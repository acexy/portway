package config

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/acexy/portway/internal/protocol"
)

func validateForwards(forwards []ForwardConfig, field string) error {
	if len(forwards) > hardMaxProxiesPerClient {
		return fmt.Errorf("%s must contain at most %d entries", field, hardMaxProxiesPerClient)
	}
	names := make(map[string]struct{}, len(forwards))
	listeners := make(map[string]struct{}, len(forwards))
	for index, forward := range forwards {
		if err := ValidateProxyName(forward.Name); err != nil {
			return fmt.Errorf("%s[%d].name has an invalid format", field, index)
		}
		if _, duplicate := names[forward.Name]; duplicate {
			return fmt.Errorf("%s[%d].name is duplicated", field, index)
		}
		names[forward.Name] = struct{}{}
		switch forward.Type {
		case protocol.ForwardTypeTCP, protocol.ForwardTypeUDP:
		default:
			return fmt.Errorf("%s[%d].type must be tcp or udp", field, index)
		}
		listenAddress, err := netip.ParseAddr(forward.Listen.IP)
		if err != nil || listenAddress.String() != forward.Listen.IP {
			return fmt.Errorf("%s[%d].listen.ip must be a canonical IP address", field, index)
		}
		if forward.Listen.Port == 0 {
			return fmt.Errorf("%s[%d].listen.port must be between 1 and 65535", field, index)
		}
		targetAddress, err := netip.ParseAddr(forward.Target.IP)
		if err != nil || targetAddress.String() != forward.Target.IP {
			return fmt.Errorf("%s[%d].target.ip must be a canonical IP address", field, index)
		}
		if forward.Target.Port == 0 {
			return fmt.Errorf("%s[%d].target.port must be between 1 and 65535", field, index)
		}
		listener := fmt.Sprintf("%s/%s/%d", forward.Type, listenAddress, forward.Listen.Port)
		if _, duplicate := listeners[listener]; duplicate {
			return fmt.Errorf("%s[%d] duplicates a %s listener", field, index, forward.Type)
		}
		listeners[listener] = struct{}{}
	}
	return nil
}

func validateProxyForwardNames(proxies []ProxyConfig, forwards []ForwardConfig) error {
	names := make(map[string]struct{}, len(proxies))
	for _, proxy := range proxies {
		names[proxy.Name] = struct{}{}
	}
	for index, forward := range forwards {
		if _, duplicate := names[forward.Name]; duplicate {
			return fmt.Errorf("forwards[%d].name duplicates a proxy name", index)
		}
	}
	return nil
}

func validateForwardServerConfig(configuration ForwardServerConfig) error {
	if configuration.Configured && len(configuration.Rules) == 0 {
		return errors.New("forwards.rules must not be empty when forwards is configured")
	}
	if configuration.Enabled && len(configuration.Rules) == 0 {
		return errors.New("forwards.rules must not be empty when forwards.enabled is true")
	}
	if err := validateForwardRules("forwards.rules", configuration.Rules); err != nil {
		return err
	}
	return validateUDPConfig(EffectiveForwardUDPConfig(configuration))
}

func validateForwardRules(field string, rules []ForwardIPRule) error {
	prefixes := make([]netip.Prefix, len(rules))
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.IPRange)
		if err != nil || prefix.String() != rule.IPRange || prefix != prefix.Masked() {
			return fmt.Errorf("%s[%d].ip_range must be a canonical CIDR", field, index)
		}
		if len(rule.TCP.PortRanges) == 0 && len(rule.UDP.PortRanges) == 0 {
			return fmt.Errorf("%s[%d] must contain tcp or udp port ranges", field, index)
		}
		if err := validateSortedPortRanges(
			fmt.Sprintf("%s[%d].tcp.port_ranges", field, index),
			rule.TCP.PortRanges,
		); err != nil {
			return err
		}
		if err := validateSortedPortRanges(
			fmt.Sprintf("%s[%d].udp.port_ranges", field, index),
			rule.UDP.PortRanges,
		); err != nil {
			return err
		}
		for previousIndex, previous := range prefixes[:index] {
			if previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr()) {
				return fmt.Errorf(
					"%s[%d].ip_range overlaps %s[%d].ip_range",
					field,
					index,
					field,
					previousIndex,
				)
			}
		}
		prefixes[index] = prefix
	}
	return nil
}

func validateSortedPortRanges(field string, ranges []PortRange) error {
	var previousEnd uint16
	for index, portRange := range ranges {
		if portRange.Start == 0 || portRange.End == 0 || portRange.Start > portRange.End {
			return fmt.Errorf("%s[%d] is invalid", field, index)
		}
		if index > 0 && portRange.Start <= previousEnd {
			return fmt.Errorf("%s must be sorted and non-overlapping", field)
		}
		previousEnd = portRange.End
	}
	return nil
}

// ForwardTargetAllowed reports whether one concrete target matches one rule.
func ForwardTargetAllowed(
	rules []ForwardIPRule,
	forwardType protocol.ForwardType,
	targetIP string,
	targetPort uint16,
) bool {
	_, allowed := MatchingForwardRule(rules, forwardType, targetIP, targetPort)
	return allowed
}

// MatchingForwardRule returns the unique rule authorizing one target.
func MatchingForwardRule(
	rules []ForwardIPRule,
	forwardType protocol.ForwardType,
	targetIP string,
	targetPort uint16,
) (ForwardIPRule, bool) {
	address, err := netip.ParseAddr(targetIP)
	if err != nil || targetPort == 0 {
		return ForwardIPRule{}, false
	}
	for _, rule := range rules {
		prefix, parseError := netip.ParsePrefix(rule.IPRange)
		if parseError != nil || !prefix.Contains(address) {
			continue
		}
		var ranges []PortRange
		switch forwardType {
		case protocol.ForwardTypeTCP:
			ranges = rule.TCP.PortRanges
		case protocol.ForwardTypeUDP:
			ranges = rule.UDP.PortRanges
		default:
			return ForwardIPRule{}, false
		}
		for _, portRange := range ranges {
			if targetPort >= portRange.Start && targetPort <= portRange.End {
				return rule, true
			}
		}
		return ForwardIPRule{}, false
	}
	return ForwardIPRule{}, false
}

// ValidateForwardConfiguration validates cross-file Forward safety boundaries.
func ValidateForwardConfiguration(configuration ServerConfig) error {
	if err := validateForwardServerConfig(configuration.Forwards); err != nil {
		return err
	}
	return validateForwardConfiguration(configuration)
}

func validateForwardConfiguration(configuration ServerConfig) error {
	for clientID, client := range configuration.GovernedClients {
		if err := validateForwardRuleSubset(
			configuration.Forwards.Rules,
			client.Permissions.Forwards.Rules,
		); err != nil {
			return fmt.Errorf("governed client %q: %w", clientID, err)
		}
	}
	for clientID, client := range configuration.ManagedClients {
		if err := validateForwardRuleSubset(
			configuration.Forwards.Rules,
			client.Permissions.Forwards.Rules,
		); err != nil {
			return fmt.Errorf("managed client %q: %w", clientID, err)
		}
		effectiveRules := configuration.Forwards.Rules
		if len(client.Permissions.Forwards.Rules) != 0 {
			effectiveRules = client.Permissions.Forwards.Rules
		}
		for index, forward := range client.Configuration.Forwards {
			if !ForwardTargetAllowed(
				effectiveRules,
				forward.Type,
				forward.Target.IP,
				forward.Target.Port,
			) {
				return fmt.Errorf(
					"managed client %q configuration.forwards[%d] target is not allowed",
					clientID,
					index,
				)
			}
		}
	}
	return nil
}

func validateForwardRuleSubset(global []ForwardIPRule, child []ForwardIPRule) error {
	for childIndex, childRule := range child {
		childPrefix, _ := netip.ParsePrefix(childRule.IPRange)
		matched := false
		for _, globalRule := range global {
			globalPrefix, _ := netip.ParsePrefix(globalRule.IPRange)
			if !globalPrefix.Contains(childPrefix.Addr()) ||
				globalPrefix.Bits() > childPrefix.Bits() {
				continue
			}
			if !portRangesAreSubset(childRule.TCP.PortRanges, globalRule.TCP.PortRanges) ||
				!portRangesAreSubset(childRule.UDP.PortRanges, globalRule.UDP.PortRanges) {
				continue
			}
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf(
				"permissions.forwards.rules[%d] is not a subset of server forwards.rules",
				childIndex,
			)
		}
	}
	return nil
}

func portRangesAreSubset(child []PortRange, parent []PortRange) bool {
	for _, childRange := range child {
		contained := false
		for _, parentRange := range parent {
			if childRange.Start >= parentRange.Start && childRange.End <= parentRange.End {
				contained = true
				break
			}
		}
		if !contained {
			return false
		}
	}
	return true
}
