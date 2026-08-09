package registry

import (
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func rollbackSyncPreparation(
	newEndpoints map[uint16]*proxytcp.Endpoint,
	newUDPEndpoints map[uint16]*proxyudp.Endpoint,
	nextUDPProxies map[string]*udpProxyBinding,
	existingUDPProxies map[string]*udpProxyBinding,
	nextHTTPProxies map[string]*httpProxyBinding,
	existingHTTPProxies map[string]*httpProxyBinding,
) {
	closeTCPEndpoints(newEndpoints)
	closeUDPEndpoints(newUDPEndpoints)
	closeUDPBindings(nextUDPProxies, existingUDPProxies)
	closeHTTPBindings(nextHTTPProxies, existingHTTPProxies)
}
