package config

import "github.com/acexy/portway/internal/protocol"

// ProxyDeclaration converts public Proxy settings without sharing the scheme slice.
func ProxyDeclaration(configuration ProxyConfig) protocol.ProxyDeclaration {
	return protocol.ProxyDeclaration{
		Name:          configuration.Name,
		Type:          configuration.Type,
		RemotePort:    configuration.Public.Port,
		Domain:        configuration.Public.Domain,
		PublicSchemes: append([]protocol.HTTPPublicScheme(nil), configuration.Public.Schemes...),
	}
}

// ForwardDeclaration converts the server-side target of a Forward configuration.
func ForwardDeclaration(configuration ForwardConfig) protocol.ForwardDeclaration {
	return protocol.ForwardDeclaration{
		Name:       configuration.Name,
		Type:       configuration.Type,
		TargetIP:   configuration.Target.IP,
		TargetPort: configuration.Target.Port,
	}
}
