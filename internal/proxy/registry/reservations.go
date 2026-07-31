package registry

import (
	"fmt"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

// ConfigureManagedReservations atomically validates and publishes server-owned
// public binding reservations.
func (manager *Registry) ConfigureManagedReservations(
	clients map[string]config.ManagedClientConfig,
) error {
	tcpPorts := make(map[uint16]string)
	udpPorts := make(map[uint16]string)
	httpDomains := make(map[string]string)
	for clientID, client := range clients {
		for _, proxy := range client.Configuration.Proxies {
			switch proxy.Type {
			case "tcp":
				if owner := tcpPorts[proxy.RemotePort]; owner != "" &&
					owner != clientID {
					return fmt.Errorf(
						"managed TCP remote port %q is reserved by multiple clients",
						fmt.Sprint(proxy.RemotePort),
					)
				}
				tcpPorts[proxy.RemotePort] = clientID
			case "udp":
				if owner := udpPorts[proxy.RemotePort]; owner != "" &&
					owner != clientID {
					return fmt.Errorf(
						"managed UDP remote port %q is reserved by multiple clients",
						fmt.Sprint(proxy.RemotePort),
					)
				}
				udpPorts[proxy.RemotePort] = clientID
			case "http":
				if owner := httpDomains[proxy.Domain]; owner != "" &&
					owner != clientID {
					return fmt.Errorf(
						"managed HTTP domain %q is reserved by multiple clients",
						proxy.Domain,
					)
				}
				httpDomains[proxy.Domain] = clientID
			}
		}
	}

	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	for port, clientID := range tcpPorts {
		if binding := manager.endpointBindings[port]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			return fmt.Errorf(
				"managed TCP remote port %q is already bound by another client",
				fmt.Sprint(port),
			)
		}
	}
	for port, clientID := range udpPorts {
		if binding := manager.udpEndpointBindings[port]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			return fmt.Errorf(
				"managed UDP remote port %q is already bound by another client",
				fmt.Sprint(port),
			)
		}
	}
	for domain, clientID := range httpDomains {
		if binding := manager.httpDomains[domain]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			return fmt.Errorf(
				"managed HTTP domain %q is already bound by another client",
				domain,
			)
		}
	}

	manager.managedTCPPorts = tcpPorts
	manager.managedUDPPorts = udpPorts
	manager.managedHTTPDomains = httpDomains
	return nil
}

func (manager *Registry) bindingOwnedByManagedClientLocked(
	bindingClientID string,
	reservationClientID string,
) bool {
	state := manager.clients[bindingClientID]
	return bindingClientID == reservationClientID &&
		state != nil &&
		state.authentication.Mode == authentication.ModeManaged
}

func (manager *Registry) managedReservationRejectionLocked(
	clientID string,
	mode authentication.Mode,
	request protocol.SyncProxies,
) *protocol.SyncResult {
	for _, proxy := range request.Proxies {
		var owner string
		switch proxy.Type {
		case protocol.ProxyTypeTCP:
			owner = manager.managedTCPPorts[proxy.RemotePort]
		case protocol.ProxyTypeUDP:
			owner = manager.managedUDPPorts[proxy.RemotePort]
		case protocol.ProxyTypeHTTP:
			owner = manager.managedHTTPDomains[proxy.Domain]
		}
		if owner == "" || owner == clientID && mode == authentication.ModeManaged {
			continue
		}
		result := rejectedSyncResult(
			request.Revision,
			reservationConflictCode(proxy.Type),
			proxy.Name,
			"public binding is reserved by managed configuration",
		)
		return &result
	}
	return nil
}

func reservationConflictCode(proxyType protocol.ProxyType) protocol.ProxyErrorCode {
	if proxyType == protocol.ProxyTypeHTTP {
		return protocol.ProxyErrorDomainConflict
	}
	return protocol.ProxyErrorPortConflict
}
