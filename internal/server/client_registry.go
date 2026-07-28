package server

import (
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/protocol"
)

type clientRecord struct {
	clientID          string
	sessionID         string
	previousSessionID string
	state             consts.ServerClientState
	connection        net.Conn
	lastHeartbeatAt   time.Time
	suspendedAt       time.Time
}

type expiredClient struct {
	clientID   string
	sessionID  string
	connection net.Conn
}

type clientSession struct {
	clientID  string
	sessionID string
}

type clientRegistry struct {
	mutex   sync.Mutex
	clients map[string]*clientRecord
}

func newClientRegistry() *clientRegistry {
	return &clientRegistry{
		clients: make(map[string]*clientRecord),
	}
}

func (registry *clientRegistry) register(
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
			state:           consts.ServerClientStateActive,
			connection:      connection,
			lastHeartbeatAt: now,
		}
		return false, true, nil, nil
	}

	if record.state == consts.ServerClientStateActive {
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
	record.state = consts.ServerClientStateActive
	record.connection = connection
	record.lastHeartbeatAt = now
	record.suspendedAt = time.Time{}
	return true, false, previousConnection, nil
}

func (registry *clientRegistry) heartbeat(clientID string, sessionID string, now time.Time) bool {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID {
		return false
	}
	record.state = consts.ServerClientStateActive
	record.lastHeartbeatAt = now
	record.suspendedAt = time.Time{}
	return true
}

func (registry *clientRegistry) disconnect(clientID string, sessionID string, now time.Time) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if !exists || record.sessionID != sessionID {
		return
	}
	if record.state != consts.ServerClientStateSuspended {
		record.state = consts.ServerClientStateSuspended
		record.suspendedAt = now
	}
}

func (registry *clientRegistry) remove(clientID string, sessionID string) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	record, exists := registry.clients[clientID]
	if exists && record.sessionID == sessionID {
		delete(registry.clients, clientID)
	}
}

func (registry *clientRegistry) sweep(
	now time.Time,
	heartbeatTimeout time.Duration,
	recoveryWindow time.Duration,
) (suspendedClients []clientSession, expiredClients []expiredClient) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	for clientID, record := range registry.clients {
		if record.state == consts.ServerClientStateActive && now.Sub(record.lastHeartbeatAt) >= heartbeatTimeout {
			record.state = consts.ServerClientStateSuspended
			record.suspendedAt = now
			suspendedClients = append(suspendedClients, clientSession{
				clientID:  clientID,
				sessionID: record.sessionID,
			})
			continue
		}
		if record.state == consts.ServerClientStateSuspended && now.Sub(record.suspendedAt) >= recoveryWindow {
			delete(registry.clients, clientID)
			expiredClients = append(expiredClients, expiredClient{
				clientID:   clientID,
				sessionID:  record.sessionID,
				connection: record.connection,
			})
		}
	}
	return suspendedClients, expiredClients
}
