package registry

import (
	"net"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/proxy/mirror"
)

const (
	mirrorTCPMaxSessions         = 4096
	mirrorTCPMaxSessionsPerGroup = 256
)

type mirrorTCPJoin struct {
	session *mirror.TCPSession
	target  link.Target
}

// mirrorTargetGuard keeps target validation and runtime publication in the same
// registration critical section without exposing Registry to the data plane.
type mirrorTargetGuard struct {
	manager *Registry
	group   *mirrorGroup
}

func (guard mirrorTargetGuard) Lock()   { guard.manager.mutex.Lock() }
func (guard mirrorTargetGuard) Unlock() { guard.manager.mutex.Unlock() }

func (guard mirrorTargetGuard) IsCurrent(target link.Target) bool {
	manager := guard.manager
	state := manager.clients[target.ClientID]
	binding := guard.group.tcpMembers[target.ClientID]
	return !manager.closed && manager.tcpMirrorGroups[guard.group.port] == guard.group &&
		state != nil && state.active && state.sessionID == target.SessionID &&
		state.writer == target.Writer && binding != nil && binding.bindingID == target.BindingID &&
		state.tcpProxies[target.ProxyName] == binding
}

func (manager *Registry) openMirrorVisitor(group *mirrorGroup, visitor net.Conn) {
	session := mirror.NewTCPSession(manager.context, visitor,
		mirrorTargetGuard{manager: manager, group: group}, manager.linkBroker.OpenStream)
	if !manager.addMirrorTCPSession(group, session) {
		session.Cancel()
		_ = visitor.Close()
		return
	}
	defer manager.removeMirrorTCPSession(group, session)
	// Register before taking the snapshot so concurrent activation cannot fall
	// between the snapshot and notification of existing visitor sessions.
	session.Serve(manager.snapshotMirrorTCPTargets(group))
}

func (manager *Registry) addMirrorTCPSession(group *mirrorGroup, session *mirror.TCPSession) bool {
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
	session.SetPrimary(group.configuration.PrimaryClientID)
	group.tcpSessions[session] = struct{}{}
	return true
}

func (manager *Registry) removeMirrorTCPSession(group *mirrorGroup, session *mirror.TCPSession) {
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
		target := mirrorTCPLinkTarget(clientID, state, binding)
		for session := range group.tcpSessions {
			joins = append(joins, mirrorTCPJoin{session: session, target: target})
		}
	}
	return joins
}

func (manager *Registry) snapshotMirrorTCPTargets(group *mirrorGroup) []link.Target {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.tcpMirrorGroups[group.port] != group {
		return nil
	}
	targets := make([]link.Target, 0, len(group.tcpMembers))
	for clientID, binding := range group.tcpMembers {
		state := manager.clients[clientID]
		if state == nil || !state.active || state.sessionID != binding.sessionID ||
			state.tcpProxies[binding.declaration.Name] != binding || state.writer == nil {
			continue
		}
		targets = append(targets, mirrorTCPLinkTarget(clientID, state, binding))
	}
	return targets
}

func mirrorTCPLinkTarget(clientID string, state *clientState, binding *tcpProxyBinding) link.Target {
	return link.Target{
		ClientID: clientID, SessionID: state.sessionID,
		ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
		BindingID: binding.bindingID, Writer: state.writer,
		Authentication: state.authentication, MaxActiveLinks: state.maxActiveLinks,
	}
}
