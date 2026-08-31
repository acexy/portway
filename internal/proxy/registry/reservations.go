package registry

import (
	"fmt"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

// ManagedReservationTransaction holds the registration barrier between final
// validation and publication so proxy synchronization cannot observe a mixed
// configuration generation.
type ManagedReservationTransaction struct {
	manager     *Registry
	tcpPorts    map[uint16]string
	udpPorts    map[uint16]string
	httpDomains map[string]string
}

// BeginManagedReservationUpdate validates a candidate while acquiring the
// registration barrier. The caller must Commit or Rollback the transaction.
func (manager *Registry) BeginManagedReservationUpdate(
	clients map[string]config.ManagedClientConfig,
) (*ManagedReservationTransaction, error) {
	tcpPorts := make(map[uint16]string)
	udpPorts := make(map[uint16]string)
	httpDomains := make(map[string]string)
	for clientID, client := range clients {
		for _, proxy := range client.Configuration.Proxies {
			switch proxy.Type {
			case protocol.ProxyTypeTCP:
				if owner := tcpPorts[proxy.Public.Port]; owner != "" &&
					owner != clientID {
					return nil, fmt.Errorf(
						"managed TCP remote port %q is reserved by multiple clients",
						fmt.Sprint(proxy.Public.Port),
					)
				}
				tcpPorts[proxy.Public.Port] = clientID
			case protocol.ProxyTypeUDP:
				if owner := udpPorts[proxy.Public.Port]; owner != "" &&
					owner != clientID {
					return nil, fmt.Errorf(
						"managed UDP remote port %q is reserved by multiple clients",
						fmt.Sprint(proxy.Public.Port),
					)
				}
				udpPorts[proxy.Public.Port] = clientID
			case protocol.ProxyTypeHTTP:
				if owner := httpDomains[proxy.Public.Domain]; owner != "" &&
					owner != clientID {
					return nil, fmt.Errorf(
						"managed HTTP domain %q is reserved by multiple clients",
						proxy.Public.Domain,
					)
				}
				httpDomains[proxy.Public.Domain] = clientID
			}
		}
	}

	manager.registrationMutex.Lock()
	manager.mutex.Lock()

	for port, clientID := range tcpPorts {
		if binding := manager.endpointBindings[port]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			manager.mutex.Unlock()
			manager.registrationMutex.Unlock()
			return nil, fmt.Errorf(
				"managed TCP remote port %q is already bound by another client",
				fmt.Sprint(port),
			)
		}
	}
	for port, clientID := range udpPorts {
		if binding := manager.udpEndpointBindings[port]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			manager.mutex.Unlock()
			manager.registrationMutex.Unlock()
			return nil, fmt.Errorf(
				"managed UDP remote port %q is already bound by another client",
				fmt.Sprint(port),
			)
		}
	}
	for domain, clientID := range httpDomains {
		if binding := manager.httpDomains[domain]; binding != nil &&
			!manager.bindingOwnedByManagedClientLocked(binding.clientID, clientID) {
			manager.mutex.Unlock()
			manager.registrationMutex.Unlock()
			return nil, fmt.Errorf(
				"managed HTTP domain %q is already bound by another client",
				domain,
			)
		}
	}

	manager.mutex.Unlock()
	return &ManagedReservationTransaction{
		manager: manager, tcpPorts: tcpPorts, udpPorts: udpPorts,
		httpDomains: httpDomains,
	}, nil
}

// Commit publishes the validated reservations and releases the barrier.
func (transaction *ManagedReservationTransaction) Commit() {
	if transaction == nil || transaction.manager == nil {
		return
	}
	manager := transaction.manager
	manager.mutex.Lock()
	manager.managedTCPPorts = transaction.tcpPorts
	manager.managedUDPPorts = transaction.udpPorts
	manager.managedHTTPDomains = transaction.httpDomains
	manager.mutex.Unlock()
	transaction.manager = nil
	manager.registrationMutex.Unlock()
}

// Rollback releases the registration barrier without publishing the candidate.
func (transaction *ManagedReservationTransaction) Rollback() {
	if transaction == nil || transaction.manager == nil {
		return
	}
	manager := transaction.manager
	transaction.manager = nil
	manager.registrationMutex.Unlock()
}

// ConfigureManagedReservations validates and immediately publishes startup reservations.
func (manager *Registry) ConfigureManagedReservations(
	clients map[string]config.ManagedClientConfig,
) error {
	transaction, err := manager.BeginManagedReservationUpdate(clients)
	if err != nil {
		return err
	}
	transaction.Commit()
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
	request SyncRequest,
) *SyncResult {
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

func reservationConflictCode(proxyType protocol.ProxyType) ErrorCode {
	if proxyType == protocol.ProxyTypeHTTP {
		return ErrorDomainConflict
	}
	return ErrorPortConflict
}
