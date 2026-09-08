package mirror

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/link"
)

type tcpMember struct {
	target       link.Target
	connection   net.Conn
	queue        chan []byte
	done         chan struct{}
	responseDone chan struct{}
	closeOnce    sync.Once
	stopped      chan struct{}
}

func (session *TCPSession) addConnection(
	target link.Target,
	connection net.Conn,
) *tcpMember {
	member := &tcpMember{
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
	previous := session.members[target.ClientID]
	session.members[target.ClientID] = member
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
func (session *TCPSession) copyResponse(member *tcpMember) {
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
			if primary == nil || member.target.ClientID != *primary {
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

func (session *TCPSession) currentMember(member *tcpMember) bool {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.members[member.target.ClientID] == member
}

func (member *tcpMember) writeLoop(ctx context.Context) {
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

func (member *tcpMember) close() {
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
