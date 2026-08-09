package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/acexy/portway/internal/transport"
)

// EnsureClientID generates a process-scoped client ID when none is configured.
func EnsureClientID(configuration *ClientConfig) (string, bool, error) {
	if configuration.ClientID != "" {
		return configuration.ClientID, false, nil
	}

	randomBytes := make([]byte, generatedClientIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", false, fmt.Errorf("generate client ID: %w", err)
	}

	clientID := "pw_c_" + base64.RawURLEncoding.EncodeToString(randomBytes)
	configuration.ClientID = clientID
	return clientID, true, nil
}

// DefaultClient returns the client configuration used when no file exists.
func DefaultClient() ClientConfig {
	return ClientConfig{
		Transport: ClientTransportConfig{
			Type:          transport.TypeTCP,
			ServerAddress: "127.0.0.1:7000",
		},
		LogLevel: LogLevelInfo,
	}
}

// DefaultServer returns the server configuration used when no file exists.
func DefaultServer() ServerConfig {
	return ServerConfig{
		Transport: ServerTransportConfig{
			Type:          transport.TypeTCP,
			ListenAddress: "0.0.0.0:7000",
		},
		Tunnel: TunnelConfig{
			BindIP: "0.0.0.0",
		},
		LogLevel: LogLevelInfo,
		HTTP: HTTPConfig{
			ReadHeaderTimeout:              httpDefaultReadHeaderTimeout,
			GracefulShutdownTimeout:        httpDefaultGracefulShutdownTimeout,
			MaxHeaderBytes:                 httpDefaultMaxHeaderBytes,
			MaxConcurrentRequests:          httpDefaultMaxConcurrentRequests,
			MaxConcurrentRequestsPerClient: httpDefaultMaxConcurrentRequestsPerClient,
			MaxConcurrentRequestsPerDomain: httpDefaultMaxConcurrentRequestsPerDomain,
			MaxIdleConnections:             httpDefaultMaxIdleConnections,
			MaxIdleConnectionsPerDomain:    httpDefaultMaxIdleConnectionsPerDomain,
			MaxUpgradeConnections:          httpDefaultMaxUpgradeConnections,
			MaxUpgradeConnectionsPerClient: httpDefaultMaxUpgradeConnectionsPerClient,
			MaxUpgradeConnectionsPerDomain: httpDefaultMaxUpgradeConnectionsPerDomain,
			MaxConcurrentHTTP2Streams:      httpDefaultMaxConcurrentHTTP2Streams,
		},
		UDP: DefaultUDPConfig(),
	}
}

// EnsureServerToken generates a token when token mode has no configured value.
func EnsureServerToken(configuration *ServerConfig) (string, bool, error) {
	if configuration.Authentication.SharedToken != nil {
		if *configuration.Authentication.SharedToken != "" {
			return *configuration.Authentication.SharedToken, false, nil
		}
		token, err := generateToken()
		if err != nil {
			return "", false, err
		}
		configuration.Authentication.SharedToken = &token
		configuration.SharedTokenGenerated = true
		return token, true, nil
	}
	if configuration.Authentication.GovernedClientsPath != "" ||
		configuration.Authentication.ManagedClientsPath != "" {
		return "", false, nil
	}

	token, err := generateToken()
	if err != nil {
		return "", false, err
	}
	configuration.Authentication.SharedToken = &token
	configuration.SharedTokenGenerated = true
	return token, true, nil
}

func generateToken() (string, error) {
	randomBytes := make([]byte, generatedTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate server token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
