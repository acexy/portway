package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

// BuildAuthenticationSnapshot builds the immutable runtime authentication index.
func BuildAuthenticationSnapshot(configuration ServerConfig) (*authentication.Snapshot, error) {
	records := make(
		[]authentication.Record,
		0,
		1+len(configuration.GovernedClients)+len(configuration.ManagedClients),
	)
	sharedToken := ""
	if configuration.Authentication.SharedToken != nil {
		sharedToken = *configuration.Authentication.SharedToken
	}
	if sharedToken != "" {
		records = append(records, authentication.Record{
			Context: authentication.Context{Mode: authentication.ModeShared},
			Token:   sharedToken,
		})
	}
	for _, client := range configuration.GovernedClients {
		records = append(records, authentication.Record{
			Context: authentication.Context{
				Mode:     authentication.ModeGoverned,
				ClientID: client.Authentication.ClientID,
			},
			Token: client.Authentication.Token,
		})
	}
	for _, client := range configuration.ManagedClients {
		records = append(records, authentication.Record{
			Context: authentication.Context{
				Mode:     authentication.ModeManaged,
				ClientID: client.Authentication.ClientID,
			},
			Token: client.Authentication.Token,
		})
	}
	return authentication.NewSnapshot(records)
}

func loadServerAuthenticationFiles(configuration *ServerConfig) error {
	baseDirectory := "."
	if configuration.SourcePath != "" {
		baseDirectory = filepath.Dir(configuration.SourcePath)
	}
	governedClients, err := loadGovernedClients(
		resolveConfigurationPath(baseDirectory, configuration.Authentication.GovernedClientsPath),
	)
	if err != nil {
		return err
	}
	managedClients, err := loadManagedClients(
		resolveConfigurationPath(baseDirectory, configuration.Authentication.ManagedClientsPath),
	)
	if err != nil {
		return err
	}
	for clientID := range governedClients {
		if _, duplicate := managedClients[clientID]; duplicate {
			return fmt.Errorf("client_id %q is configured in both governed and managed modes", clientID)
		}
	}
	configuration.GovernedClients = governedClients
	configuration.ManagedClients = managedClients
	if err := validateManagedClientConflicts(managedClients, configuration.Proxies.Mirror); err != nil {
		return err
	}
	if _, err := BuildAuthenticationSnapshot(*configuration); err != nil {
		return err
	}
	return nil
}
func resolveConfigurationPath(baseDirectory string, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDirectory, path)
}

func loadGovernedClients(path string) (map[string]GovernedClientConfig, error) {
	clients := make(map[string]GovernedClientConfig)
	if path == "" {
		return clients, nil
	}
	files, err := authenticationFiles(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		client := GovernedClientConfig{
			Permissions: GovernedPermissions{
				Proxies: GovernedProxyPermissions{
					Limits: DefaultProxyPermissionLimits(),
				},
				Forwards: GovernedForwardPermissions{
					Limits: DefaultForwardPermissionLimits(),
				},
			},
		}
		if err := loadAuthenticationYAML(file, &client); err != nil {
			return nil, err
		}
		applyGovernedPermissionDefaults(&client.Permissions)
		clientID := client.Authentication.ClientID
		if err := validateAuthenticationClientFile(file, clientID, client.Authentication.Token); err != nil {
			return nil, err
		}
		if err := validateGovernedPermissions(client.Permissions); err != nil {
			return nil, fmt.Errorf("validate governed client %q: %w", clientID, err)
		}
		if _, duplicate := clients[clientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", clientID)
		}
		clients[clientID] = client
	}
	return clients, nil
}

func loadManagedClients(path string) (map[string]ManagedClientConfig, error) {
	clients := make(map[string]ManagedClientConfig)
	if path == "" {
		return clients, nil
	}
	files, err := authenticationFiles(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		var client ManagedClientConfig
		if err := loadAuthenticationYAML(file, &client); err != nil {
			return nil, err
		}
		clientID := client.Authentication.ClientID
		if err := validateAuthenticationClientFile(file, clientID, client.Authentication.Token); err != nil {
			return nil, err
		}
		if client.Configuration.Revision == 0 {
			return nil, fmt.Errorf(
				"validate managed client %q: configuration.revision must be greater than zero",
				clientID,
			)
		}
		if err := validateManagedConfiguration(client.Configuration); err != nil {
			return nil, fmt.Errorf("validate managed client %q: %w", clientID, err)
		}
		if err := validateForwardRules(
			"permissions.forwards.rules",
			client.Permissions.Forwards.Rules,
		); err != nil {
			return nil, fmt.Errorf("validate managed client %q: %w", clientID, err)
		}
		if len(client.Configuration.Forwards) == 0 &&
			len(client.Permissions.Forwards.Rules) != 0 {
			return nil, fmt.Errorf(
				"validate managed client %q: permissions.forwards.rules must be empty without configuration.forwards",
				clientID,
			)
		}
		if _, duplicate := clients[clientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", clientID)
		}
		clients[clientID] = client
	}
	return clients, nil
}

func authenticationFiles(path string) ([]string, error) {
	directoryInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect authentication directory %q: %w", path, err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, fmt.Errorf(
			"authentication directory %q must be a directory without symbolic links",
			path,
		)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read authentication directory %q: %w", path, err)
	}
	files := make([]string, 0, len(entries))
	var totalBytes int64
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf(
				"authentication file %q must be a regular file without symbolic links",
				filepath.Join(path, entry.Name()),
			)
		}
		if len(files) >= maxAuthenticationFiles {
			return nil, fmt.Errorf(
				"authentication directory %q exceeds %d YAML files",
				path,
				maxAuthenticationFiles,
			)
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect authentication file %q: %w", entry.Name(), err)
		}
		if info.Size() > maxAuthenticationFileBytes {
			return nil, fmt.Errorf(
				"authentication file %q exceeds %d bytes",
				entry.Name(),
				maxAuthenticationFileBytes,
			)
		}
		totalBytes += info.Size()
		if totalBytes > maxAuthenticationTotalBytes {
			return nil, fmt.Errorf(
				"authentication directory %q exceeds %d total bytes",
				path,
				maxAuthenticationTotalBytes,
			)
		}
		files = append(files, filepath.Join(path, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func readAuthenticationFile(path string) ([]byte, error) {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open authentication directory %q: %w", directory, err)
	}
	defer root.Close()

	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect authentication file %q: %w", path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"authentication file %q must be a regular file without symbolic links",
			path,
		)
	}
	if before.Size() > maxAuthenticationFileBytes {
		return nil, fmt.Errorf(
			"authentication file %q exceeds %d bytes",
			name,
			maxAuthenticationFileBytes,
		)
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open authentication file %q: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened authentication file %q: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("authentication file %q changed while opening", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxAuthenticationFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read authentication file %q: %w", path, err)
	}
	if len(data) > maxAuthenticationFileBytes {
		return nil, fmt.Errorf(
			"authentication file %q exceeds %d bytes",
			name,
			maxAuthenticationFileBytes,
		)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect read authentication file %q: %w", path, err)
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() ||
		!opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("authentication file %q changed while reading", path)
	}
	return data, nil
}

func validateAuthenticationClientFile(path string, clientID string, token string) error {
	if err := ValidateClientID(clientID); err != nil {
		return fmt.Errorf("validate authentication file %q: %w", path, err)
	}
	if err := validateToken(token); err != nil {
		return fmt.Errorf("authentication file %q token: %w", path, err)
	}
	return nil
}

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

func validateGovernedPermissions(permissions GovernedPermissions) error {
	proxies := permissions.Proxies
	if proxies.TCP != nil {
		if err := validateSortedPortRanges(
			"permissions.proxies.tcp.port_ranges",
			proxies.TCP.PortRanges,
		); err != nil {
			return err
		}
		if len(proxies.TCP.PortRanges) == 0 {
			return errors.New("permissions.proxies.tcp.port_ranges must not be empty")
		}
	}
	if proxies.UDP != nil {
		if err := validateSortedPortRanges(
			"permissions.proxies.udp.port_ranges",
			proxies.UDP.PortRanges,
		); err != nil {
			return err
		}
		if len(proxies.UDP.PortRanges) == 0 {
			return errors.New("permissions.proxies.udp.port_ranges must not be empty")
		}
	}
	if err := validateForwardRules("permissions.forwards.rules", permissions.Forwards.Rules); err != nil {
		return err
	}
	if proxies.HTTP == nil {
		return validateGovernedLimits(permissions)
	}
	if len(proxies.HTTP.Domains) == 0 {
		return errors.New("permissions.proxies.http.domains must not be empty")
	}
	domains := make(map[string]struct{}, len(proxies.HTTP.Domains))
	for index, domain := range proxies.HTTP.Domains {
		if strings.HasPrefix(domain, "*.") {
			if err := ValidateHTTPDomain(strings.TrimPrefix(domain, "*.")); err != nil {
				return fmt.Errorf("permissions.proxies.http.domains[%d]: invalid wildcard domain", index)
			}
		} else if err := ValidateHTTPDomain(domain); err != nil {
			return fmt.Errorf("permissions.proxies.http.domains[%d]: %w", index, err)
		}
		if _, duplicate := domains[domain]; duplicate {
			return fmt.Errorf("permissions.proxies.http.domains contains duplicate domain %q", domain)
		}
		domains[domain] = struct{}{}
	}
	if len(proxies.HTTP.PublicSchemes) > 0 {
		if err := validateHTTPPublicSchemes(
			proxies.HTTP.PublicSchemes,
			"permissions.proxies.http.public_schemes",
		); err != nil {
			return err
		}
	}
	return validateGovernedLimits(permissions)
}

func validateGovernedLimits(permissions GovernedPermissions) error {
	proxyLimits := permissions.Proxies.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_total", proxyLimits.MaxTotal, hardMaxProxiesPerClient},
		{"max_tcp", proxyLimits.MaxTCP, hardMaxProxiesPerClient},
		{"max_udp", proxyLimits.MaxUDP, hardMaxProxiesPerClient},
		{"max_http", proxyLimits.MaxHTTP, hardMaxProxiesPerClient},
		{"max_active_links", proxyLimits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.proxies.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if proxyLimits.MaxTCP > proxyLimits.MaxTotal || proxyLimits.MaxUDP > proxyLimits.MaxTotal ||
		proxyLimits.MaxHTTP > proxyLimits.MaxTotal {
		return errors.New("permissions.proxies per-type limits must not exceed max_total")
	}
	forwardLimits := permissions.Forwards.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_total", forwardLimits.MaxTotal, hardMaxProxiesPerClient},
		{"max_tcp", forwardLimits.MaxTCP, hardMaxProxiesPerClient},
		{"max_udp", forwardLimits.MaxUDP, hardMaxProxiesPerClient},
		{"max_active_links", forwardLimits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.forwards.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if forwardLimits.MaxTCP > forwardLimits.MaxTotal || forwardLimits.MaxUDP > forwardLimits.MaxTotal {
		return errors.New("permissions.forwards per-type limits must not exceed max_total")
	}
	return nil
}

func applyGovernedPermissionDefaults(permissions *GovernedPermissions) {
	if permissions.Proxies.HTTP == nil || len(permissions.Proxies.HTTP.PublicSchemes) != 0 {
		return
	}
	permissions.Proxies.HTTP.PublicSchemes = []protocol.HTTPPublicScheme{
		protocol.HTTPPublicSchemeHTTP,
	}
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
