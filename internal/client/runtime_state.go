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

func (s *Service) runtimeForwardSnapshot() []config.ForwardConfig {
	s.runtimeMutex.RLock()
	defer s.runtimeMutex.RUnlock()
	return append([]config.ForwardConfig(nil), s.runtimeForwards...)
}

func (s *Service) setRuntimeForwards(forwards []config.ForwardConfig) {
	s.runtimeMutex.Lock()
	s.runtimeForwards = append([]config.ForwardConfig(nil), forwards...)
	s.runtimeMutex.Unlock()
}
