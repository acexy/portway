package registry

import (
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

// syncCandidateResources owns unpublished resources. Existing bindings are
// borrowed exclusions; rollback must never close them. Only the transaction's
// goroutine accesses this holder, and cleanup runs outside Registry locks.
type syncCandidateResources struct {
	newEndpoints        map[uint16]*proxytcp.Endpoint
	newUDPEndpoints     map[uint16]*proxyudp.Endpoint
	nextUDPProxies      map[string]*udpProxyBinding
	existingUDPProxies  map[string]*udpProxyBinding
	nextHTTPProxies     map[string]*httpProxyBinding
	existingHTTPProxies map[string]*httpProxyBinding
}

func (resources *syncCandidateResources) rollback() {
	closeTCPEndpoints(resources.newEndpoints)
	closeUDPEndpoints(resources.newUDPEndpoints)
	closeUDPBindings(resources.nextUDPProxies, resources.existingUDPProxies)
	closeHTTPBindings(resources.nextHTTPProxies, resources.existingHTTPProxies)
	resources.release()
}

// release transfers ownership to the published Registry without closing resources.
func (resources *syncCandidateResources) release() {
	*resources = syncCandidateResources{}
}
