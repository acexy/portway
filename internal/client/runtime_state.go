package client

import "github.com/acexy/portway/internal/config"

func (s *Service) runtimeIdentity() string {
	s.runtimeMutex.RLock()
	defer s.runtimeMutex.RUnlock()
	return s.runtimeClientID
}
func (s *Service) setRuntimeClientID(clientID string) {
	s.runtimeMutex.Lock()
	s.runtimeClientID = clientID
	s.runtimeMutex.Unlock()
}

func (s *Service) runtimeProxySnapshot() []config.ProxyConfig {
	s.runtimeMutex.RLock()
	defer s.runtimeMutex.RUnlock()
	return append([]config.ProxyConfig(nil), s.runtimeProxies...)
}

func (s *Service) setRuntimeProxies(proxies []config.ProxyConfig) {
	s.runtimeMutex.Lock()
	s.runtimeProxies = append([]config.ProxyConfig(nil), proxies...)
	s.runtimeMutex.Unlock()
}
