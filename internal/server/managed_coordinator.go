package server

import (
	"net"
	"sync"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

type managedSession struct {
	sessionID  string
	connection net.Conn
	writer     *control.Writer
	prepared   chan protocol.ManagedConfigStatus
	applied    chan protocol.ManagedConfigStatus
	mutex      sync.Mutex
}

// managedCoordinator owns the online managed-session index and status delivery.
type managedCoordinator struct {
	mutex    sync.RWMutex
	sessions map[string]*managedSession
}

func newManagedCoordinator() *managedCoordinator {
	return &managedCoordinator{sessions: make(map[string]*managedSession)}
}

func (coordinator *managedCoordinator) register(
	clientID string,
	session *managedSession,
) {
	coordinator.mutex.Lock()
	coordinator.sessions[clientID] = session
	coordinator.mutex.Unlock()
}

func (coordinator *managedCoordinator) unregister(clientID string, sessionID string) {
	coordinator.mutex.Lock()
	current := coordinator.sessions[clientID]
	if current != nil && current.sessionID == sessionID {
		delete(coordinator.sessions, clientID)
	}
	coordinator.mutex.Unlock()
}

func (coordinator *managedCoordinator) get(clientID string) *managedSession {
	coordinator.mutex.RLock()
	defer coordinator.mutex.RUnlock()
	return coordinator.sessions[clientID]
}

func (coordinator *managedCoordinator) publish(
	clientID string,
	sessionID string,
	messageType protocol.MessageType,
	status protocol.ManagedConfigStatus,
) bool {
	current := coordinator.get(clientID)
	if current == nil || current.sessionID != sessionID {
		return false
	}
	var destination chan protocol.ManagedConfigStatus
	switch messageType {
	case protocol.MessageManagedConfigPrepared:
		destination = current.prepared
	case protocol.MessageManagedConfigApplied:
		destination = current.applied
	default:
		return false
	}
	select {
	case destination <- status:
		return true
	default:
		return false
	}
}
