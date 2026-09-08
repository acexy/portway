package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/acexy/portway/internal/authentication"
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
