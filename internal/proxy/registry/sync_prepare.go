package registry

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"

	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func (manager *Registry) prepareSyncEndpoints(
	request protocol.SyncProxies,
	reusableEndpoints map[uint16]*proxytcp.Endpoint,
	reusableUDPEndpoints map[uint16]*proxyudp.Endpoint,
) (
	map[uint16]*proxytcp.Endpoint,
	map[uint16]*proxyudp.Endpoint,
	*protocol.SyncResult,
) {
	newEndpoints := make(map[uint16]*proxytcp.Endpoint)
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP ||
			reusableEndpoints[declaration.RemotePort] != nil {
			continue
		}
		listenAddress := net.JoinHostPort(
			manager.proxyBindIP,
			strconv.Itoa(int(declaration.RemotePort)),
		)
		endpoint, err := proxytcp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_tcp"),
			listenAddress,
			manager.sourceFilter,
		)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			result := rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
			return nil, nil, &result
		}
		newEndpoints[declaration.RemotePort] = endpoint
	}

	newUDPEndpoints := make(map[uint16]*proxyudp.Endpoint)
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeUDP ||
			reusableUDPEndpoints[declaration.RemotePort] != nil {
			continue
		}
		listenAddress := net.JoinHostPort(
			manager.proxyBindIP,
			strconv.Itoa(int(declaration.RemotePort)),
		)
		endpoint, err := proxyudp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_udp"),
			listenAddress,
			manager.sourceFilter,
			manager.udpConfiguration.MaxDatagramSize,
		)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			result := rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"UDP remote port is unavailable",
			)
			return nil, nil, &result
		}
		newUDPEndpoints[declaration.RemotePort] = endpoint
	}
	return newEndpoints, newUDPEndpoints, nil
}
func newBindingID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
