package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
				ClientID: client.ClientID,
			},
			Token: client.Token,
		})
	}
	for _, client := range configuration.ManagedClients {
		records = append(records, authentication.Record{
			Context: authentication.Context{
				Mode:     authentication.ModeManaged,
				ClientID: client.ClientID,
			},
			Token: client.Token,
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
				Limits: DefaultPermissionLimits(),
			},
		}
		if err := loadAuthenticationYAML(file, &client); err != nil {
			return nil, err
		}
		applyGovernedPermissionDefaults(&client.Permissions)
		if err := validateAuthenticationClientFile(file, client.ClientID, client.Token); err != nil {
			return nil, err
		}
		if err := validateGovernedPermissions(client.Permissions); err != nil {
			return nil, fmt.Errorf("validate governed client %q: %w", client.ClientID, err)
		}
		if _, duplicate := clients[client.ClientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", client.ClientID)
		}
		clients[client.ClientID] = client
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
		if err := validateAuthenticationClientFile(file, client.ClientID, client.Token); err != nil {
			return nil, err
		}
		if client.Configuration.Revision == 0 {
			return nil, fmt.Errorf(
				"validate managed client %q: configuration.revision must be greater than zero",
				client.ClientID,
			)
		}
		if err := validateManagedProxies(client.Configuration.Proxies); err != nil {
			return nil, fmt.Errorf("validate managed client %q: %w", client.ClientID, err)
		}
		if _, duplicate := clients[client.ClientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", client.ClientID)
		}
		clients[client.ClientID] = client
	}
	if err := validateManagedClientConflicts(clients); err != nil {
		return nil, err
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
	if len(token) < generatedTokenBytes {
		return fmt.Errorf(
			"authentication file %q token must contain at least %d bytes",
			path,
			generatedTokenBytes,
		)
	}
	return nil
}

type managedBindingOwner struct {
	clientID  string
	proxyName string
}

func validateManagedClientConflicts(clients map[string]ManagedClientConfig) error {
	clientIDs := make([]string, 0, len(clients))
	for clientID := range clients {
		clientIDs = append(clientIDs, clientID)
	}
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
				if previous, exists := tcpPorts[proxy.RemotePort]; exists {
					return managedBindingConflict(
						"TCP remote port",
						fmt.Sprint(proxy.RemotePort),
						previous,
						owner,
					)
				}
				tcpPorts[proxy.RemotePort] = owner
			case protocol.ProxyTypeUDP:
				if previous, exists := udpPorts[proxy.RemotePort]; exists {
					return managedBindingConflict(
						"UDP remote port",
						fmt.Sprint(proxy.RemotePort),
						previous,
						owner,
					)
				}
				udpPorts[proxy.RemotePort] = owner
			case protocol.ProxyTypeHTTP:
				if previous, exists := httpDomains[proxy.Domain]; exists {
					return managedBindingConflict(
						"HTTP domain",
						proxy.Domain,
						previous,
						owner,
					)
				}
				httpDomains[proxy.Domain] = owner
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
	types := make(map[protocol.ProxyType]struct{}, len(permissions.ProxyTypes))
	for _, proxyType := range permissions.ProxyTypes {
		switch proxyType {
		case protocol.ProxyTypeTCP, protocol.ProxyTypeUDP, protocol.ProxyTypeHTTP:
		default:
			return fmt.Errorf("permissions.proxy_types contains unsupported type %q", proxyType)
		}
		if _, duplicate := types[proxyType]; duplicate {
			return fmt.Errorf("permissions.proxy_types contains duplicate type %q", proxyType)
		}
		types[proxyType] = struct{}{}
	}
	if err := validatePortRanges("permissions.tcp.remote_port_ranges", permissions.TCP.RemotePortRanges); err != nil {
		return err
	}
	if err := validatePortRanges("permissions.udp.remote_port_ranges", permissions.UDP.RemotePortRanges); err != nil {
		return err
	}
	domains := make(map[string]struct{}, len(permissions.HTTP.Domains))
	for index, domain := range permissions.HTTP.Domains {
		if strings.HasPrefix(domain, "*.") {
			if err := ValidateHTTPDomain(strings.TrimPrefix(domain, "*.")); err != nil {
				return fmt.Errorf("permissions.http.domains[%d]: invalid wildcard domain", index)
			}
		} else if err := ValidateHTTPDomain(domain); err != nil {
			return fmt.Errorf("permissions.http.domains[%d]: %w", index, err)
		}
		if _, duplicate := domains[domain]; duplicate {
			return fmt.Errorf("permissions.http.domains contains duplicate domain %q", domain)
		}
		domains[domain] = struct{}{}
	}
	if len(permissions.HTTP.PublicSchemes) > 0 {
		if err := validateHTTPPublicSchemes(
			permissions.HTTP.PublicSchemes,
			"permissions.http.public_schemes",
		); err != nil {
			return err
		}
	}
	limits := permissions.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_proxies", limits.MaxProxies, hardMaxProxiesPerClient},
		{"max_tcp_proxies", limits.MaxTCPProxies, hardMaxProxiesPerClient},
		{"max_udp_proxies", limits.MaxUDPProxies, hardMaxProxiesPerClient},
		{"max_http_proxies", limits.MaxHTTPProxies, hardMaxProxiesPerClient},
		{"max_active_links", limits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if limits.MaxTCPProxies > limits.MaxProxies ||
		limits.MaxUDPProxies > limits.MaxProxies ||
		limits.MaxHTTPProxies > limits.MaxProxies {
		return errors.New(
			"permissions per-type proxy limits must not exceed max_proxies",
		)
	}
	if err := validateGovernedRulePresence(
		protocol.ProxyTypeTCP,
		types,
		len(permissions.TCP.RemotePortRanges),
		"permissions.tcp.remote_port_ranges",
	); err != nil {
		return err
	}
	if err := validateGovernedRulePresence(
		protocol.ProxyTypeUDP,
		types,
		len(permissions.UDP.RemotePortRanges),
		"permissions.udp.remote_port_ranges",
	); err != nil {
		return err
	}
	if err := validateGovernedRulePresence(
		protocol.ProxyTypeHTTP,
		types,
		len(permissions.HTTP.Domains),
		"permissions.http.domains",
	); err != nil {
		return err
	}
	if _, httpAllowed := types[protocol.ProxyTypeHTTP]; !httpAllowed &&
		len(permissions.HTTP.PublicSchemes) != 0 {
		return errors.New(
			"permissions.http.public_schemes must be empty when http is not allowed",
		)
	}
	return nil
}

func applyGovernedPermissionDefaults(permissions *GovernedPermissions) {
	if len(permissions.HTTP.PublicSchemes) != 0 {
		return
	}
	for _, proxyType := range permissions.ProxyTypes {
		if proxyType == protocol.ProxyTypeHTTP {
			permissions.HTTP.PublicSchemes = []protocol.HTTPPublicScheme{
				protocol.HTTPPublicSchemeHTTP,
			}
			return
		}
	}
}

func validateGovernedRulePresence(
	proxyType protocol.ProxyType,
	allowedTypes map[protocol.ProxyType]struct{},
	ruleCount int,
	field string,
) error {
	_, allowed := allowedTypes[proxyType]
	if allowed && ruleCount == 0 {
		return fmt.Errorf("%s must not be empty when %s is allowed", field, proxyType)
	}
	if !allowed && ruleCount != 0 {
		return fmt.Errorf("%s must be empty when %s is not allowed", field, proxyType)
	}
	return nil
}

func validatePortRanges(field string, ranges []PortRange) error {
	sortedRanges := append([]PortRange(nil), ranges...)
	sort.Slice(sortedRanges, func(left int, right int) bool {
		return sortedRanges[left].Start < sortedRanges[right].Start
	})
	var previousEnd uint16
	for index, portRange := range sortedRanges {
		if portRange.Start == 0 || portRange.End == 0 || portRange.Start > portRange.End {
			return fmt.Errorf("%s[%d] is invalid", field, index)
		}
		if index > 0 && portRange.Start <= previousEnd {
			return fmt.Errorf("%s contains overlapping ranges", field)
		}
		previousEnd = portRange.End
	}
	return nil
}
