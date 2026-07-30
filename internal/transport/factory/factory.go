// Package factory creates concrete transport implementations from application configuration.
package factory

import (
	"context"
	"fmt"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/transport"
	transportquic "github.com/acexy/portway/internal/transport/quic"
	transporttoken "github.com/acexy/portway/internal/transport/tcp/token"
)

// NewClient creates the configured client transport.
func NewClient(configuration config.ClientConfig) (transport.Client, error) {
	switch configuration.Transport.Type {
	case transport.TypeTCP:
		return transporttoken.NewClient(
			configuration.Transport.ServerAddress,
			configuration.Authentication.Token,
		), nil
	case transport.TypeQUIC:
		return transportquic.NewClient(transportquic.ClientConfig{
			Address:    configuration.Transport.ServerAddress,
			ServerName: configuration.Transport.QUIC.ServerName,
			CAFile:     configuration.Transport.QUIC.CAFile,
			Token:      configuration.Authentication.Token,
		})
	default:
		return nil, fmt.Errorf(
			"unsupported client transport type %q",
			configuration.Transport.Type,
		)
	}
}

// NewServer creates and starts the configured server transport.
func NewServer(
	ctx context.Context,
	configuration config.ServerConfig,
	credentials *authentication.Store,
	maxConcurrentConnections int,
	sourceFilter *ipfilter.Filter,
) (transport.Server, error) {
	switch configuration.Transport.Type {
	case transport.TypeTCP:
		return transporttoken.NewServer(
			ctx,
			configuration.Transport.ListenAddress,
			credentials,
			maxConcurrentConnections,
			sourceFilter,
		)
	case transport.TypeQUIC:
		return transportquic.NewServer(
			ctx,
			transportquic.ServerConfig{
				Address:     configuration.Transport.ListenAddress,
				CertFile:    configuration.Transport.QUIC.CertFile,
				KeyFile:     configuration.Transport.QUIC.KeyFile,
				Credentials: credentials,
			},
			maxConcurrentConnections,
			sourceFilter,
		)
	default:
		return nil, fmt.Errorf(
			"unsupported server transport type %q",
			configuration.Transport.Type,
		)
	}
}
