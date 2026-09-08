package config

import (
	"fmt"
	"sort"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/protocol"
)

type managedBindingOwner struct {
	clientID  string
	proxyName string
}

func validateManagedClientConflicts(
	clients map[string]ManagedClientConfig,
	mirrorConfigurations ...ProxyMirrorConfig,
) error {
	var mirror ProxyMirrorConfig
	if len(mirrorConfigurations) != 0 {
		mirror = mirrorConfigurations[0]
	}
	mirrorMembers := make(map[string]map[string]struct{})
	for _, group := range mirror.Managed {
		members := make(map[string]struct{}, len(group.ClientIDs))
		for _, clientID := range group.ClientIDs {
			members[clientID] = struct{}{}
		}
		for _, port := range group.Public.Ports() {
			mirrorMembers[fmt.Sprintf("%s:%d", group.Type, port)] = members
		}
	}
	clientIDs := coll.MapKeys(clients)
	sort.Strings(clientIDs)

	tcpPorts := make(map[uint16]managedBindingOwner)
	udpPorts := make(map[uint16]managedBindingOwner)
	httpDomains := make(map[string]managedBindingOwner)
	for _, clientID := range clientIDs {
		for _, proxy := range clients[clientID].Configuration.Proxies {
			owner := managedBindingOwner{
				clientID:  clientID,
				proxyName: proxy.Name,
			}
			switch proxy.Type {
			case protocol.ProxyTypeTCP:
				if previous, exists := tcpPorts[proxy.Public.Port]; exists {
					members := mirrorMembers[fmt.Sprintf("%s:%d", proxy.Type, proxy.Public.Port)]
					_, previousAllowed := members[previous.clientID]
					_, currentAllowed := members[clientID]
					if previousAllowed && currentAllowed {
						continue
					}
					return managedBindingConflict(
						"TCP remote port",
						fmt.Sprint(proxy.Public.Port),
						previous,
						owner,
					)
				}
				tcpPorts[proxy.Public.Port] = owner
			case protocol.ProxyTypeUDP:
				if previous, exists := udpPorts[proxy.Public.Port]; exists {
					members := mirrorMembers[fmt.Sprintf("%s:%d", proxy.Type, proxy.Public.Port)]
					_, previousAllowed := members[previous.clientID]
					_, currentAllowed := members[clientID]
					if previousAllowed && currentAllowed {
						continue
					}
					return managedBindingConflict(
						"UDP remote port",
						fmt.Sprint(proxy.Public.Port),
						previous,
						owner,
					)
				}
				udpPorts[proxy.Public.Port] = owner
			case protocol.ProxyTypeHTTP:
				if previous, exists := httpDomains[proxy.Public.Domain]; exists {
					return managedBindingConflict(
						"HTTP domain",
						proxy.Public.Domain,
						previous,
						owner,
					)
				}
				httpDomains[proxy.Public.Domain] = owner
			}
		}
	}
	return nil
}

func managedBindingConflict(
	resource string,
	value string,
	first managedBindingOwner,
	second managedBindingOwner,
) error {
	return fmt.Errorf(
		"managed %s %q is configured by client %q proxy %q and client %q proxy %q",
		resource,
		value,
		first.clientID,
		first.proxyName,
		second.clientID,
		second.proxyName,
	)
}
