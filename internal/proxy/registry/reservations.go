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

// ConfigureMirrorGroups publishes a prepared mirror generation while the
// transaction owns the registration barrier.
func (transaction *ManagedReservationTransaction) ConfigureMirrorGroups(
	configuration config.ProxyMirrorConfig,
) error {
	if transaction == nil || transaction.manager == nil {
		return fmt.Errorf("managed reservation transaction is inactive")
	}
	return transaction.manager.configureMirrorGroupsLocked(configuration)
}

// BeginManagedReservationUpdate validates a candidate while acquiring the
// registration barrier. The caller must Commit or Rollback the transaction.
func (manager *Registry) BeginManagedReservationUpdate(
	clients map[string]config.ManagedClientConfig,
	mirrorConfigurations ...config.ProxyMirrorConfig,
) (*ManagedReservationTransaction, error) {
	var candidateMirror config.ProxyMirrorConfig
	if len(mirrorConfigurations) != 0 {
		candidateMirror = mirrorConfigurations[0]
	}
	tcpPorts := make(map[uint16]string)
	udpPorts := make(map[uint16]string)
	httpDomains := make(map[string]string)
	for clientID, client := range clients {
		for _, proxy := range client.Configuration.Proxies {
			switch proxy.Type {
			case protocol.ProxyTypeTCP:
				if owner := tcpPorts[proxy.Public.Port]; owner != "" &&
					owner != clientID {
					allowed := mirrorConfigurationAllows(
						candidateMirror.Managed,
						protocol.ProxyTypeTCP,
						proxy.Public.Port,
						owner,
						clientID,
					)
					if len(mirrorConfigurations) == 0 {
						manager.mutex.Lock()
						group := manager.tcpMirrorGroups[proxy.Public.Port]
						allowed = group != nil &&
							group.allowsMode(owner, authentication.ModeManaged) &&
							group.allowsMode(clientID, authentication.ModeManaged)
						manager.mutex.Unlock()
					}
					if allowed {
						continue
					}
					return nil, fmt.Errorf(
						"managed TCP remote port %q is reserved by multiple clients",
						fmt.Sprint(proxy.Public.Port),
					)
				}
				tcpPorts[proxy.Public.Port] = clientID
			case protocol.ProxyTypeUDP:
				if owner := udpPorts[proxy.Public.Port]; owner != "" &&
					owner != clientID {
					allowed := mirrorConfigurationAllows(
						candidateMirror.Managed,
						protocol.ProxyTypeUDP,
						proxy.Public.Port,
						owner,
						clientID,
					)
					if len(mirrorConfigurations) == 0 {
						manager.mutex.Lock()
						group := manager.udpMirrorGroups[proxy.Public.Port]
						allowed = group != nil &&
							group.allowsMode(owner, authentication.ModeManaged) &&
							group.allowsMode(clientID, authentication.ModeManaged)
						manager.mutex.Unlock()
					}
					if allowed {
						continue
					}
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
		if proxy.Type == protocol.ProxyTypeTCP {
			if group := manager.tcpMirrorGroups[proxy.RemotePort]; group != nil &&
				group.allowsMode(clientID, mode) {
				continue
			}
		}
		if proxy.Type == protocol.ProxyTypeUDP {
			if group := manager.udpMirrorGroups[proxy.RemotePort]; group != nil &&
				group.allowsMode(clientID, mode) {
				continue
			}
		}
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

func mirrorConfigurationAllows(
	groups []config.ProxyMirrorGroupConfig,
	proxyType protocol.ProxyType,
	port uint16,
	clientIDs ...string,
) bool {
	for _, group := range groups {
		if group.Type != proxyType || !mirrorPublicIncludesPort(group.Public, port) {
			continue
		}
		for _, clientID := range clientIDs {
			allowed := false
			for _, member := range group.ClientIDs {
				if member == clientID {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
		return true
	}
	return false
}

func mirrorPublicIncludesPort(public config.ProxyMirrorPublicConfig, port uint16) bool {
	for _, portRange := range public.PortRanges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}
