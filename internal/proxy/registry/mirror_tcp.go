package registry

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

const (
	mirrorTCPChunkSize           = 32 * 1024
	mirrorTCPQueueDepth          = 32
	mirrorTCPRetryInterval       = time.Second
	mirrorTCPMaxRetryInterval    = 5 * time.Second
	mirrorTCPWriteTimeout        = 5 * time.Second
	mirrorTCPCloseGracePeriod    = 5 * time.Second
	mirrorTCPMaxSessions         = 4096
	mirrorTCPMaxSessionsPerGroup = 256
)

type mirrorTCPTarget struct {
	binding *tcpProxyBinding
	target  link.Target
	primary bool
}

type mirrorTCPMember struct {
	target       mirrorTCPTarget
	connection   net.Conn
	queue        chan []byte
	done         chan struct{}
	responseDone chan struct{}
	closeOnce    sync.Once
	stopped      chan struct{}
}

// Each worker owns at most one pending or active link for a member generation.
type mirrorTCPWorker struct {
	target      mirrorTCPTarget
	context     context.Context
	cancel      context.CancelFunc
	initialDone chan struct{}
	done        chan struct{}
}

// mirrorTCPSession owns one Visitor connection and its dynamically changing
// set of best-effort mirror copies.
type mirrorTCPSession struct {
	context         context.Context
	cancel          context.CancelFunc
	manager         *Registry
	group           *mirrorGroup
	visitor         net.Conn
	mutex           sync.Mutex
	closed          bool
	members         map[string]*mirrorTCPMember
	workers         map[string]*mirrorTCPWorker
	inputDone       chan struct{}
	waitGroup       sync.WaitGroup
	responseMutex   sync.Mutex
	primaryClientID atomic.Pointer[string]
}

type mirrorTCPJoin struct {
	session *mirrorTCPSession
	target  mirrorTCPTarget
}

func (manager *Registry) openMirrorVisitor(group *mirrorGroup, visitor net.Conn) {
	defer visitor.Close()
	ctx, cancel := context.WithCancel(manager.context)
	session := &mirrorTCPSession{
		context:   ctx,
		cancel:    cancel,
		manager:   manager,
		group:     group,
		visitor:   visitor,
		members:   make(map[string]*mirrorTCPMember),
		workers:   make(map[string]*mirrorTCPWorker),
		inputDone: make(chan struct{}),
	}
	if !manager.addMirrorTCPSession(group, session) {
		cancel()
		return
	}
	defer manager.removeMirrorTCPSession(group, session)
	stopVisitor := context.AfterFunc(ctx, func() { _ = visitor.Close() })
	defer stopVisitor()
	defer func() {
		session.closeInput()
		cancel()
		session.waitGroup.Wait()
	}()

	// Register before taking the snapshot so a concurrent activation cannot
	// fall between the initial snapshot and the live-session join notification.
	targets := manager.snapshotMirrorTCPTargets(group)
	initial := make([]<-chan struct{}, 0, len(targets))
	for _, target := range targets {
		initial = append(initial, session.addTarget(target))
	}
	for _, ready := range initial {
		select {
		case <-ready:
		case <-ctx.Done():
			return
		}
	}

	buffer := make([]byte, mirrorTCPChunkSize)
	for {
		length, err := visitor.Read(buffer)
		if length != 0 {
			for _, member := range session.snapshotMembers() {
				payload := append([]byte(nil), buffer[:length]...)
				select {
				case member.queue <- payload:
				default:
					member.close()
				}
			}
		}
		if err != nil {
			break
		}
	}
	members := session.closeInput()
	for _, member := range members {
		close(member.queue)
	}
	finished := make(chan struct{})
	go func() {
		session.waitGroup.Wait()
		close(finished)
	}()
	timer := time.NewTimer(mirrorTCPCloseGracePeriod)
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
	case <-ctx.Done():
	}
}

func (manager *Registry) addMirrorTCPSession(group *mirrorGroup, session *mirrorTCPSession) bool {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.closed || manager.tcpMirrorGroups[group.port] != group ||
		len(group.tcpSessions) >= mirrorTCPMaxSessionsPerGroup {
		return false
	}
	count := 0
	for _, current := range manager.tcpMirrorGroups {
		count += len(current.tcpSessions)
	}
	if count >= mirrorTCPMaxSessions {
		return false
	}
	primary := group.configuration.PrimaryClientID
	session.primaryClientID.Store(&primary)
	group.tcpSessions[session] = struct{}{}
	return true
}

func (manager *Registry) removeMirrorTCPSession(group *mirrorGroup, session *mirrorTCPSession) {
	manager.mutex.Lock()
	delete(group.tcpSessions, session)
	manager.mutex.Unlock()
}

func (manager *Registry) mirrorTCPJoinsLocked(clientID string, state *clientState) []mirrorTCPJoin {
	joins := make([]mirrorTCPJoin, 0)
	for _, binding := range state.tcpProxies {
		group := manager.tcpMirrorGroups[binding.declaration.RemotePort]
		if group == nil || !group.allows(clientID, state) || group.tcpMembers[clientID] != binding {
			continue
		}
		target := mirrorTCPTarget{
			binding: binding,
			primary: clientID == group.configuration.PrimaryClientID,
			target: link.Target{
				ClientID: clientID, SessionID: state.sessionID,
				ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
				BindingID: binding.bindingID, Writer: state.writer,
				Authentication: state.authentication, MaxActiveLinks: state.maxActiveLinks,
			},
		}
		for session := range group.tcpSessions {
			joins = append(joins, mirrorTCPJoin{session: session, target: target})
		}
	}
	return joins
}

func (session *mirrorTCPSession) addTarget(target mirrorTCPTarget) <-chan struct{} {
	session.manager.mutex.Lock()
	defer session.manager.mutex.Unlock()
	if !session.targetCurrentLocked(target) {
		done := make(chan struct{})
		close(done)
		return done
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	previous := session.workers[target.target.ClientID]
	if previous != nil && previous.target.binding == target.binding &&
		previous.target.target.SessionID == target.target.SessionID &&
		previous.target.target.Writer == target.target.Writer {
		return previous.initialDone
	}
	ctx, cancel := context.WithCancel(session.context)
	worker := &mirrorTCPWorker{
		target: target, context: ctx, cancel: cancel,
		initialDone: make(chan struct{}), done: make(chan struct{}),
	}
	if session.closed || session.context.Err() != nil {
		cancel()
		close(worker.initialDone)
		return worker.initialDone
	}
	session.workers[target.target.ClientID] = worker
	if previous != nil {
		previous.cancel()
	}
	session.waitGroup.Go(func() { session.runWorker(worker, previous) })
	return worker.initialDone
}

func (session *mirrorTCPSession) runWorker(worker, previous *mirrorTCPWorker) {
	var initialOnce sync.Once
	initialDone := func() { initialOnce.Do(func() { close(worker.initialDone) }) }
	defer initialDone()
	defer close(worker.done)
	defer worker.cancel()
	defer func() {
		session.mutex.Lock()
		if session.workers[worker.target.target.ClientID] == worker {
			delete(session.workers, worker.target.target.ClientID)
		}
		session.mutex.Unlock()
	}()
	if previous != nil {
		select {
		case <-previous.done:
		case <-worker.context.Done():
			return
		}
	}
	delay := mirrorTCPRetryInterval
	for {
		manager := session.manager
		manager.mutex.Lock()
		valid := session.targetCurrentLocked(worker.target)
		if !valid {
			session.mutex.Lock()
			if session.workers[worker.target.target.ClientID] == worker {
				delete(session.workers, worker.target.target.ClientID)
			}
			session.mutex.Unlock()
		}
		manager.mutex.Unlock()
		if !valid || worker.context.Err() != nil {
			return
		}
		select {
		case <-session.inputDone:
			return
		default:
		}
		connection, err := manager.linkBroker.OpenStream(worker.context, worker.target.target)
		var member *mirrorTCPMember
		if err == nil {
			manager.mutex.Lock()
			if session.targetCurrentLocked(worker.target) && worker.context.Err() == nil {
				member = session.addConnection(worker.target, connection)
			}
			manager.mutex.Unlock()
			if member == nil {
				_ = connection.Close()
			}
		}
		initialDone()
		if member != nil {
			delay = mirrorTCPRetryInterval
			stopClose := context.AfterFunc(worker.context, member.close)
			select {
			case <-member.stopped:
			case <-worker.context.Done():
			case <-session.inputDone:
				<-member.done
				// Primary may change while this link remains alive. The session's
				// bounded drain window owns termination of every response reader.
				<-member.responseDone
			}
			member.close()
			stopClose()
			<-member.done
			<-member.responseDone
			session.mutex.Lock()
			if session.members[worker.target.target.ClientID] == member {
				delete(session.members, worker.target.target.ClientID)
			}
			session.mutex.Unlock()
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-worker.context.Done():
			timer.Stop()
			return
		case <-session.inputDone:
			timer.Stop()
			return
		}
		delay = min(delay*2, mirrorTCPMaxRetryInterval)
	}
}

// The registry lock makes authorization validation and publication atomic.
func (session *mirrorTCPSession) targetCurrentLocked(target mirrorTCPTarget) bool {
	manager := session.manager
	state := manager.clients[target.target.ClientID]
	return !manager.closed && manager.tcpMirrorGroups[session.group.port] == session.group &&
		state != nil && state.active && state.sessionID == target.target.SessionID &&
		state.writer == target.target.Writer &&
		session.group.tcpMembers[target.target.ClientID] == target.binding &&
		state.tcpProxies[target.target.ProxyName] == target.binding
}

func (session *mirrorTCPSession) addConnection(
	target mirrorTCPTarget,
	connection net.Conn,
) *mirrorTCPMember {
	member := &mirrorTCPMember{
		target: target, connection: connection,
		queue:        make(chan []byte, mirrorTCPQueueDepth),
		done:         make(chan struct{}),
		responseDone: make(chan struct{}),
		stopped:      make(chan struct{}),
	}
	session.mutex.Lock()
	if session.closed {
		session.mutex.Unlock()
		return nil
	}
	previous := session.members[target.target.ClientID]
	session.members[target.target.ClientID] = member
	session.mutex.Unlock()
	if previous != nil {
		previous.close()
	}
	go member.writeLoop(session.context)
	go func() {
		defer close(member.responseDone)
		defer func() {
			session.mutex.Lock()
			closed := session.closed
			session.mutex.Unlock()
			if !closed {
				member.close()
			}
		}()
		if session.visitor != nil {
			session.copyResponse(member)
			return
		}
		_, _ = io.Copy(io.Discard, connection)
	}()
	return member
}

// A failed local Primary must not irreversibly half-close the visitor. Only
// visitor input EOF ends recovery; responses from successive links are serialized.
func (session *mirrorTCPSession) copyResponse(member *mirrorTCPMember) {
	buffer := make([]byte, mirrorTCPChunkSize)
	for {
		length, readError := member.connection.Read(buffer)
		if length != 0 {
			session.responseMutex.Lock()
			if !session.currentMember(member) {
				session.responseMutex.Unlock()
				return
			}
			primary := session.primaryClientID.Load()
			if primary == nil || member.target.target.ClientID != *primary {
				session.responseMutex.Unlock()
				if readError != nil {
					return
				}
				continue
			}
			err := session.visitor.SetWriteDeadline(time.Now().Add(mirrorTCPWriteTimeout))
			if err == nil {
				var written int
				written, err = session.visitor.Write(buffer[:length])
				if err == nil && written != length {
					err = io.ErrShortWrite
				}
			}
			session.responseMutex.Unlock()
			if err != nil {
				session.cancel()
				return
			}
		}
		if readError != nil {
			return
		}
	}
}

func (session *mirrorTCPSession) currentMember(member *mirrorTCPMember) bool {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.members[member.target.target.ClientID] == member
}

func (session *mirrorTCPSession) snapshotMembers() []*mirrorTCPMember {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	members := make([]*mirrorTCPMember, 0, len(session.members))
	for _, member := range session.members {
		members = append(members, member)
	}
	return members
}

func (session *mirrorTCPSession) closeInput() []*mirrorTCPMember {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	close(session.inputDone)
	members := make([]*mirrorTCPMember, 0, len(session.members))
	for _, member := range session.members {
		members = append(members, member)
	}
	return members
}

func (manager *Registry) snapshotMirrorTCPTargets(group *mirrorGroup) []mirrorTCPTarget {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.tcpMirrorGroups[group.port] != group {
		return nil
	}
	targets := make([]mirrorTCPTarget, 0, len(group.tcpMembers))
	for clientID, binding := range group.tcpMembers {
		state := manager.clients[clientID]
		if state == nil || !state.active || state.sessionID != binding.sessionID ||
			state.tcpProxies[binding.declaration.Name] != binding || state.writer == nil {
			continue
		}
		targets = append(targets, mirrorTCPTarget{
			binding: binding,
			primary: clientID == group.configuration.PrimaryClientID,
			target: link.Target{
				ClientID: clientID, SessionID: state.sessionID,
				ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
				BindingID: binding.bindingID, Writer: state.writer,
				Authentication: state.authentication, MaxActiveLinks: state.maxActiveLinks,
			},
		})
	}
	return targets
}

func (member *mirrorTCPMember) writeLoop(ctx context.Context) {
	defer close(member.done)
	for {
		select {
		case <-member.stopped:
			return
		case <-ctx.Done():
			member.close()
			return
		case payload, open := <-member.queue:
			if !open {
				closeWrite(member.connection)
				return
			}
			if err := member.connection.SetWriteDeadline(time.Now().Add(mirrorTCPWriteTimeout)); err != nil {
				member.close()
				return
			}
			if written, err := member.connection.Write(payload); err != nil || written != len(payload) {
				member.close()
				return
			}
		}
	}
}

func (member *mirrorTCPMember) close() {
	member.closeOnce.Do(func() {
		close(member.stopped)
		_ = member.connection.Close()
	})
}

func closeWrite(connection net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if candidate, ok := connection.(closeWriter); ok {
		_ = candidate.CloseWrite()
	}
}
