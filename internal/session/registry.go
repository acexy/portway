// Package session owns authenticated client session state and recovery.
package session

import (
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

type clientRecord struct {
	clientID          string
	sessionID         string
	previousSessionID string
	state             state
	connection        net.Conn
	lastHeartbeatAt   time.Time
	suspendedAt       time.Time
}

// ExpiredClient identifies a session whose recovery window elapsed.
type ExpiredClient struct {
	ClientID   string
	SessionID  string
	Connection net.Conn
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
			state:           stateActive,
			connection:      connection,
			lastHeartbeatAt: now,
		}
		return false, true, nil, nil
	}

	if record.state == stateActive {
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorClientIDAlreadyOnline,
			Message:   "client ID is already online",
			Retryable: true,
		}
	}
	if resumeSessionID == "" {
		return false, false, nil, &protocol.SessionError{
			Code:      protocol.SessionErrorClientIDAlreadyOnline,
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
	record.state = stateActive
	record.connection = connection
	record.lastHeartbeatAt = now
	record.suspendedAt = time.Time{}
	return true, false, previousConnection, nil
}

func (registry *Registry) Heartbeat(clientID string, sessionID string, now time.Time) bool {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID {
		return false
	}
	record.state = stateActive
	record.lastHeartbeatAt = now
	record.suspendedAt = time.Time{}
	return true
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
				ClientID:   clientID,
				SessionID:  record.sessionID,
				Connection: record.connection,
			})
		}
	}
	return suspendedClients, expiredClients
}
