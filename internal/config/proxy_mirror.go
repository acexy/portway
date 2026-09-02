package config

import (
	"fmt"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

const (
	maxProxyMirrorGroups  = 128
	maxProxyMirrorMembers = 32
	maxProxyMirrorPorts   = 128
)

type proxyMirrorKey struct {
	proxyType protocol.ProxyType
	port      uint16
}

func validateProxyMirrorConfiguration(configuration ServerConfig) error {
	if len(configuration.Proxies.Mirror.Governed)+len(configuration.Proxies.Mirror.Managed) >
		maxProxyMirrorGroups {
		return fmt.Errorf("proxies.mirror may contain at most %d groups", maxProxyMirrorGroups)
	}
	names := make(map[string]struct{})
	ports := make(map[proxyMirrorKey]string)
	if err := validateProxyMirrorGroups(
		"proxies.mirror.governed",
		authentication.ModeGoverned,
		configuration.Proxies.Mirror.Governed,
		configuration,
		names,
		ports,
	); err != nil {
		return err
	}
	if err := validateProxyMirrorGroups(
		"proxies.mirror.managed",
		authentication.ModeManaged,
		configuration.Proxies.Mirror.Managed,
		configuration,
		names,
		ports,
	); err != nil {
		return err
	}
	if len(ports) > maxProxyMirrorPorts {
		return fmt.Errorf("proxies.mirror may expand to at most %d public endpoints", maxProxyMirrorPorts)
	}
	return validateManagedClientConflicts(configuration.ManagedClients, configuration.Proxies.Mirror)
}

func validateProxyMirrorGroups(
	path string,
	mode authentication.Mode,
	groups []ProxyMirrorGroupConfig,
	configuration ServerConfig,
	names map[string]struct{},
	ports map[proxyMirrorKey]string,
) error {
	for index, group := range groups {
		field := fmt.Sprintf("%s[%d]", path, index)
		if !proxyNamePattern.MatchString(group.Name) {
			return fmt.Errorf("%s.name is invalid", field)
		}
		if _, duplicate := names[group.Name]; duplicate {
			return fmt.Errorf("%s.name %q is duplicated", field, group.Name)
		}
		names[group.Name] = struct{}{}
		if group.Type != protocol.ProxyTypeTCP && group.Type != protocol.ProxyTypeUDP {
			return fmt.Errorf("%s.type must be tcp or udp", field)
		}
		if len(group.Public.PortRanges) == 0 {
			return fmt.Errorf("%s.public.port_ranges must not be empty", field)
		}
		if err := validateSortedPortRanges(field+".public.port_ranges", group.Public.PortRanges); err != nil {
			return err
		}
		groupPorts := group.Public.Ports()
		if len(groupPorts) > maxProxyMirrorPorts {
			return fmt.Errorf("%s.public.port_ranges may expand to at most %d ports", field, maxProxyMirrorPorts)
		}
		for _, port := range groupPorts {
			key := proxyMirrorKey{proxyType: group.Type, port: port}
			if owner := ports[key]; owner != "" {
				return fmt.Errorf("%s public endpoint conflicts with mirror group %q", field, owner)
			}
			ports[key] = group.Name
		}
		if group.PrimaryClientID == "" {
			return fmt.Errorf("%s.primary_client_id is required", field)
		}
		if len(group.ClientIDs) == 0 || len(group.ClientIDs) > maxProxyMirrorMembers {
			return fmt.Errorf("%s.client_ids must contain between 1 and %d entries", field, maxProxyMirrorMembers)
		}
		members := make(map[string]struct{}, len(group.ClientIDs))
		for _, clientID := range group.ClientIDs {
			if clientID == "" {
				return fmt.Errorf("%s.client_ids contains an empty ClientID", field)
			}
			if _, duplicate := members[clientID]; duplicate {
				return fmt.Errorf("%s.client_ids contains duplicate ClientID %q", field, clientID)
			}
			members[clientID] = struct{}{}
			if err := validateProxyMirrorMember(mode, clientID, group, groupPorts, configuration); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
		if _, primaryMember := members[group.PrimaryClientID]; !primaryMember {
			return fmt.Errorf("%s.primary_client_id must be present in client_ids", field)
		}
	}
	return nil
}

func validateProxyMirrorMember(
	mode authentication.Mode,
	clientID string,
	group ProxyMirrorGroupConfig,
	ports []uint16,
	configuration ServerConfig,
) error {
	switch mode {
	case authentication.ModeGoverned:
		client, exists := configuration.GovernedClients[clientID]
		if !exists {
			return fmt.Errorf("governed client_id %q does not exist", clientID)
		}
		var permission *ProxyPermission
		if group.Type == protocol.ProxyTypeTCP {
			permission = client.Permissions.Proxies.TCP
		} else {
			permission = client.Permissions.Proxies.UDP
		}
		if permission == nil {
			return fmt.Errorf("client_id %q is not permitted to use the mirror ports", clientID)
		}
		for _, port := range ports {
			if !portAllowed(port, permission.PortRanges) {
				return fmt.Errorf("client_id %q is not permitted to use mirror port %d", clientID, port)
			}
		}
	case authentication.ModeManaged:
		client, exists := configuration.ManagedClients[clientID]
		if !exists {
			return fmt.Errorf("managed client_id %q does not exist", clientID)
		}
		for _, port := range ports {
			matches := 0
			for _, proxy := range client.Configuration.Proxies {
				if proxy.Type == group.Type && proxy.Public.Port == port {
					matches++
				}
			}
			if matches != 1 {
				return fmt.Errorf("client_id %q must configure exactly one matching proxy for port %d", clientID, port)
			}
		}
	}
	return nil
}

func portAllowed(port uint16, ranges []PortRange) bool {
	for _, candidate := range ranges {
		if port >= candidate.Start && port <= candidate.End {
			return true
		}
	}
	return false
}

// ValidateProxyMirrorConfiguration validates mirror groups after authentication files load.
func ValidateProxyMirrorConfiguration(configuration ServerConfig) error {
	return validateProxyMirrorConfiguration(configuration)
}
