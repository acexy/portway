package server

import (
	"sync"

	"github.com/acexy/portway/internal/config"
)

// configurationManager owns the currently published immutable server snapshot.
type configurationManager struct {
	mutex   sync.RWMutex
	current config.ServerConfig
}

func newConfigurationManager(configuration config.ServerConfig) *configurationManager {
	return &configurationManager{current: configuration}
}

func (manager *configurationManager) snapshot() config.ServerConfig {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()
	return manager.current
}

func (manager *configurationManager) publish(configuration config.ServerConfig) {
	manager.mutex.Lock()
	manager.current = configuration
	manager.mutex.Unlock()
}

func (manager *configurationManager) updateSourceDigest(digest string) {
	manager.mutex.Lock()
	manager.current.SourceDigest = digest
	manager.mutex.Unlock()
}

func (manager *configurationManager) governedClient(
	clientID string,
) (config.GovernedClientConfig, bool) {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()
	client, exists := manager.current.GovernedClients[clientID]
	return client, exists
}

func (manager *configurationManager) managedClient(
	clientID string,
) (config.ManagedClientConfig, bool) {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()
	client, exists := manager.current.ManagedClients[clientID]
	return client, exists
}
