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
	request SyncRequest,
	reusableEndpoints map[uint16]*proxytcp.Endpoint,
	reusableUDPEndpoints map[uint16]*proxyudp.Endpoint,
	resources *syncCandidateResources,
) *SyncResult {
	newEndpoints := resources.newEndpoints
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
			result := rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
			return &result
		}
		newEndpoints[declaration.RemotePort] = endpoint
	}

	newUDPEndpoints := resources.newUDPEndpoints
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
			result := rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declaration.Name,
				"UDP remote port is unavailable",
			)
			return &result
		}
		newUDPEndpoints[declaration.RemotePort] = endpoint
	}
	return nil
}
func newBindingID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
