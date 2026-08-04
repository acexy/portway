// Package session owns authenticated client session state and recovery.
package session

import (
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

type clientRecord struct {
	clientID          string
	sessionID         string
	previousSessionID string
	state             state
	connection        net.Conn
	lastHeartbeatAt       time.Time
	lastHeartbeatSequence uint64
	suspendedAt           time.Time
	authentication        authentication.Context
}

// ExpiredClient identifies a session whose recovery window elapsed.
type ExpiredClient struct {
	ClientID       string
	SessionID      string
	Connection     net.Conn
	Authentication authentication.Context
}

// Client identifies one current client session.
type Client struct {
	ClientID  string
	SessionID string
}

// Registry owns the current session record for every ClientID.
type Registry struct {
	mutex   sync.Mutex
	clients map[string]*clientRecord
}

// NewRegistry creates an empty session registry.
func NewRegistry() *Registry {
	return &Registry{
		clients: make(map[string]*clientRecord),
	}
}

func (registry *Registry) Register(
	clientID string,
	resumeSessionID string,
	sessionID string,
	connection net.Conn,
	now time.Time,
) (resumed bool, created bool, previousConnection net.Conn, sessionError *protocol.SessionError) {
	return registry.RegisterAuthenticated(
		clientID,
		resumeSessionID,
		sessionID,
		connection,
		now,
		authentication.Context{Mode: authentication.ModeShared},
	)
}

// RegisterAuthenticated registers a Session and binds its transport authentication record.
func (registry *Registry) RegisterAuthenticated(
	clientID string,
	resumeSessionID string,
	sessionID string,
	connection net.Conn,
	now time.Time,
	authenticationContext authentication.Context,
) (resumed bool, created bool, previousConnection net.Conn, sessionError *protocol.SessionError) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists {
		if resumeSessionID != "" {
			return false, false, nil, &protocol.SessionError{
				Code:      protocol.SessionErrorSessionExpired,
				Message:   "recoverable client session no longer exists",
				Retryable: true,
			}
		}
		registry.clients[clientID] = &clientRecord{
			clientID:        clientID,
			sessionID:       sessionID,
			state:           stateInitializing,
			connection:      connection,
			lastHeartbeatAt: now,
			authentication:  authenticationContext,
		}
		return false, true, nil, nil
	}

	if record.state == stateInitializing {
		if resumeSessionID == "" ||
			resumeSessionID == record.sessionID ||
			resumeSessionID == record.previousSessionID {
			return false, false, nil, &protocol.SessionError{
				Code:      protocol.SessionErrorClientIDRecoveryPending,
				Message:   "client session initialization is still in progress",
				Retryable: true,
			}
		}
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorClientIDAlreadyOnline,
			Message:   "client ID is already online",
			Retryable: false,
		}
	}
	if record.state == stateActive {
		if resumeSessionID != "" && resumeSessionID == record.sessionID {
			return false, false, nil, &protocol.SessionError{
				Code:      protocol.SessionErrorClientIDRecoveryPending,
				Message:   "client session is still active and waiting to become recoverable",
				Retryable: true,
			}
		}
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorClientIDAlreadyOnline,
			Message:   "client ID is already online",
			Retryable: false,
		}
	}
	if resumeSessionID == "" {
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorClientIDRecoveryPending,
			Message:   "client ID is waiting for its recovery window to expire",
			Retryable: true,
		}
	}
	if resumeSessionID != record.sessionID && resumeSessionID != record.previousSessionID {
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorResumeSessionMismatch,
			Message:   "resume session ID does not match the suspended client",
			Retryable: false,
		}
	}

	previousConnection = record.connection
	record.previousSessionID = record.sessionID
	record.sessionID = sessionID
	record.state = stateInitializing
	record.connection = connection
	record.lastHeartbeatAt = now
	record.lastHeartbeatSequence = 0
	record.suspendedAt = time.Time{}
	record.authentication = authenticationContext
	return true, false, previousConnection, nil
}

// Activate publishes a fully initialized Session as active.
func (registry *Registry) Activate(clientID string, sessionID string, now time.Time) bool {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID || record.state != stateInitializing {
		return false
	}
	record.state = stateActive
	record.lastHeartbeatAt = now
	record.lastHeartbeatSequence = 0
	return true
}

// RevokeAuthentication removes sessions authenticated by the specified records.
func (registry *Registry) RevokeAuthentication(
	contexts []authentication.Context,
) []ExpiredClient {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	type revokedRecord struct {
		credentialID [32]byte
		generation   uint64
	}
	revokedCredentials := make(map[revokedRecord]struct{}, len(contexts))
	for _, context := range contexts {
		revokedCredentials[revokedRecord{
			credentialID: context.CredentialID,
			generation:   context.Generation,
		}] = struct{}{}
	}
	revoked := make([]ExpiredClient, 0)
	for clientID, record := range registry.clients {
		if _, exists := revokedCredentials[revokedRecord{
			credentialID: record.authentication.CredentialID,
			generation:   record.authentication.Generation,
		}]; !exists {
			continue
		}
		revoked = append(revoked, ExpiredClient{
			ClientID:       clientID,
			SessionID:      record.sessionID,
			Connection:     record.connection,
			Authentication: record.authentication,
		})
		delete(registry.clients, clientID)
	}
	return revoked
}

func (registry *Registry) Heartbeat(
	clientID string,
	sessionID string,
	sequence uint64,
	now time.Time,
) (accepted bool, reactivated bool) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID ||
		record.state == stateInitializing ||
		sequence == 0 || sequence <= record.lastHeartbeatSequence {
		return false, false
	}
	reactivated = record.state == stateSuspended
	record.state = stateActive
	record.lastHeartbeatAt = now
	record.lastHeartbeatSequence = sequence
	record.suspendedAt = time.Time{}
	return true, reactivated
}

// Active reports whether the specified Session is currently active.
func (registry *Registry) Active(clientID string, sessionID string) bool {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	return exists && record.sessionID == sessionID && record.state == stateActive
}

func (registry *Registry) Disconnect(clientID string, sessionID string, now time.Time) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID {
		return
	}
	if record.state != stateSuspended {
		record.state = stateSuspended
		record.suspendedAt = now
	}
}

func (registry *Registry) Remove(clientID string, sessionID string) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if exists && record.sessionID == sessionID {
		delete(registry.clients, clientID)
	}
}

func (registry *Registry) Sweep(
	now time.Time,
	heartbeatTimeout time.Duration,
	recoveryWindow time.Duration,
) (suspendedClients []Client, expiredClients []ExpiredClient) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	for clientID, record := range registry.clients {
		if record.state == stateActive && now.Sub(record.lastHeartbeatAt) >= heartbeatTimeout {
			record.state = stateSuspended
			record.suspendedAt = now
			suspendedClients = append(suspendedClients, Client{
				ClientID:  clientID,
				SessionID: record.sessionID,
			})
			continue
		}
		if record.state == stateSuspended && now.Sub(record.suspendedAt) >= recoveryWindow {
			delete(registry.clients, clientID)
			expiredClients = append(expiredClients, ExpiredClient{
				ClientID:       clientID,
				SessionID:      record.sessionID,
				Connection:     record.connection,
				Authentication: record.authentication,
			})
		}
	}
	return suspendedClients, expiredClients
}
