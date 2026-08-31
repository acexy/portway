// Package client provides the Portway client runtime.
package client

import (
	"errors"
	"fmt"
	"sync"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type remoteSessionError struct {
	code      protocol.SessionErrorCode
	message   string
	retryable bool
}

type proxyRegistrationError struct {
	code      protocol.ProxyErrorCode
	proxyName string
	message   string
	retryable bool
}

type reconnectPhase string

const (
	reconnectPhaseRegistration reconnectPhase = "registration"
	reconnectPhaseRecovery     reconnectPhase = "session_recovery"
)

var errManagedLocalProxies = errors.New(
	"managed clients cannot configure local proxies or forwards",
)

var errClientDeclaredProxiesRequired = errors.New(
	"shared and governed clients require at least one local proxy or forward",
)

var errReconnectPeriodExceeded = errors.New(
	"control connection retry period exceeded 8 hours",
)

func (registrationError *proxyRegistrationError) Error() string {
	return fmt.Sprintf(
		"proxy registration rejected: proxy=%q code=%s message=%s",
		registrationError.proxyName,
		registrationError.code,
		registrationError.message,
	)
}

func (sessionError *remoteSessionError) Error() string {
	return fmt.Sprintf("server rejected control session: %s: %s", sessionError.code, sessionError.message)
}

// Service manages the client process lifecycle.
//
// It owns the control connection, reconnect lifecycle, proxy registration,
// and session-scoped TCP links.
type Service struct {
	logger          *logging.Logger
	configuration   config.ClientConfig
	transport       transport.Client
	identification  protocol.ClientIdentification
	runtimeMutex    sync.RWMutex
	runtimeClientID string
	runtimeProxies  []config.ProxyConfig
	runtimeForwards []config.ForwardConfig
	managedMutex    sync.RWMutex
	managedStatus   protocol.ManagedConfigStatus
}

// NewService creates a client service.
func NewService(logger *logging.Logger, configuration config.ClientConfig) *Service {
	return &Service{
		logger:          logger.WithField("client_id", configuration.Authentication.ClientID),
		configuration:   configuration,
		runtimeClientID: configuration.Authentication.ClientID,
		runtimeProxies:  append([]config.ProxyConfig(nil), configuration.Proxies...),
		runtimeForwards: append([]config.ForwardConfig(nil), configuration.Forwards...),
	}
}

// Run runs the client until the parent context is canceled.
