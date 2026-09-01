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

func (manager *Registry) openMirrorVisitor(group *mirrorGroup, visitor net.Conn) {
	defer visitor.Close()
	targets := manager.snapshotMirrorTCPTargets(group)
	if len(targets) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(manager.context)
	defer cancel()

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
		member := &mirrorTCPMember{
			target: result.target, connection: result.connection,
			queue:        make(chan []byte, mirrorTCPQueueDepth),
			done:         make(chan struct{}),
			responseDone: make(chan struct{}),
		}
		members = append(members, member)
		go member.writeLoop(ctx)
		if result.target.primary {
			go func() {
				defer close(member.responseDone)
				_, _ = io.Copy(visitor, result.connection)
				closeWrite(visitor)
			}()
		} else {
			go func() {
				defer close(member.responseDone)
				_, _ = io.Copy(io.Discard, result.connection)
			}()
		}
	}
	if len(members) == 0 {
		return
	}

	buffer := make([]byte, mirrorTCPChunkSize)
	for {
		length, err := visitor.Read(buffer)
		if length != 0 {
			for _, member := range members {
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

func (manager *Registry) snapshotMirrorTCPTargets(group *mirrorGroup) []mirrorTCPTarget {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.tcpMirrorGroups[group.configuration.Public.Port] != group {
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
