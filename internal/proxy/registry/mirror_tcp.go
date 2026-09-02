package registry

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

const (
	mirrorTCPChunkSize  = 32 * 1024
	mirrorTCPQueueDepth = 32
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
}

// mirrorTCPSession owns one Visitor connection and its dynamically changing
// set of best-effort mirror copies.
type mirrorTCPSession struct {
	context context.Context
	cancel  context.CancelFunc
	manager *Registry
	group   *mirrorGroup
	visitor net.Conn
	mutex   sync.Mutex
	closed  bool
	members map[string]*mirrorTCPMember
}

type mirrorTCPJoin struct {
	session *mirrorTCPSession
	target  mirrorTCPTarget
}

func (manager *Registry) openMirrorVisitor(group *mirrorGroup, visitor net.Conn) {
	defer visitor.Close()
	targets := manager.snapshotMirrorTCPTargets(group)
	if len(targets) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(manager.context)
	session := &mirrorTCPSession{
		context: ctx,
		cancel:  cancel,
		manager: manager,
		group:   group,
		visitor: visitor,
		members: make(map[string]*mirrorTCPMember),
	}
	if !manager.addMirrorTCPSession(group, session) {
		cancel()
		return
	}
	defer cancel()
	defer manager.removeMirrorTCPSession(group, session)

	type openResult struct {
		target     mirrorTCPTarget
		connection net.Conn
		err        error
	}
	opened := make(chan openResult, len(targets))
	for _, target := range targets {
		targetSnapshot := target
		go func() {
			connection, err := manager.linkBroker.OpenStream(ctx, targetSnapshot.target)
			opened <- openResult{target: targetSnapshot, connection: connection, err: err}
		}()
	}
	members := make([]*mirrorTCPMember, 0, len(targets))
	for range targets {
		result := <-opened
		if result.err != nil {
			continue
		}
		if member := session.addConnection(result.target, result.connection); member != nil {
			members = append(members, member)
		}
	}
	if len(members) == 0 {
		return
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
	members = session.closeInput()
	for _, member := range members {
		close(member.queue)
	}
	for _, member := range members {
		<-member.done
		if member.target.primary {
			<-member.responseDone
		} else {
			member.close()
		}
	}
}

func (manager *Registry) addMirrorTCPSession(group *mirrorGroup, session *mirrorTCPSession) bool {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.tcpMirrorGroups[group.port] != group {
		return false
	}
	group.tcpSessions[session] = struct{}{}
	return true
}

func (manager *Registry) removeMirrorTCPSession(group *mirrorGroup, session *mirrorTCPSession) {
	manager.mutex.Lock()
	if manager.tcpMirrorGroups[group.port] == group {
		delete(group.tcpSessions, session)
	}
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

func (session *mirrorTCPSession) addTarget(target mirrorTCPTarget) {
	go func() {
		connection, err := session.manager.linkBroker.OpenStream(session.context, target.target)
		if err != nil {
			return
		}
		if session.addConnection(target, connection) == nil {
			_ = connection.Close()
		}
	}()
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
		if target.primary && session.visitor != nil {
			_, _ = io.Copy(session.visitor, connection)
			if session.currentMember(member) {
				closeWrite(session.visitor)
			}
			return
		}
		_, _ = io.Copy(io.Discard, connection)
	}()
	return member
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
		case <-ctx.Done():
			member.close()
			return
		case payload, open := <-member.queue:
			if !open {
				closeWrite(member.connection)
				return
			}
			if _, err := member.connection.Write(payload); err != nil {
				member.close()
				return
			}
		}
	}
}

func (member *mirrorTCPMember) close() {
	member.closeOnce.Do(func() { _ = member.connection.Close() })
}

func closeWrite(connection net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if candidate, ok := connection.(closeWriter); ok {
		_ = candidate.CloseWrite()
	}
}
