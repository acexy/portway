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
	session      *TCPSession
	drainTimer   *time.Timer
}

func (session *TCPSession) addConnection(
	target link.Target,
	connection net.Conn,
) *tcpMember {
	member := &tcpMember{
		target: target, connection: connection, session: session,
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
	session.memberReadyOnce.Do(func() { close(session.memberReady) })
	session.mutex.Unlock()
	if previous != nil {
		previous.close()
	}
	go member.writeLoop(session.context)
	go func() {
		defer close(member.responseDone)
		if session.visitor != nil && session.copyResponse(member) {
			// A clean Primary EOF ends only its response direction. Keep the
			// request writer alive until Visitor EOF or cancellation.
			return
		}
		member.close()
	}()
	return member
}

// copyResponse returns true only after forwarding a clean Primary half-close.
// Replica readers never wait for the Primary's potentially blocked visitor write.
func (session *TCPSession) copyResponse(member *tcpMember) bool {
	buffer := make([]byte, mirrorTCPChunkSize)
	for {
		length, readError := member.connection.Read(buffer)
		if length != 0 && session.isPrimary(member) {
			if !session.acquireResponse() {
				return false
			}
			session.mutex.Lock()
			eligible := session.responseEligibleLocked(member)
			var err error
			if eligible {
				if session.responseClosed {
					err = io.ErrClosedPipe
				} else {
					session.responseWriter = member
					err = session.visitor.SetWriteDeadline(time.Time{})
				}
			}
			session.mutex.Unlock()
			if eligible && err == nil {
				var written int
				written, err = session.visitor.Write(buffer[:length])
				if err == nil && written != length {
					err = io.ErrShortWrite
				}
			}
			session.mutex.Lock()
			session.responseWriter = nil
			if err != nil {
				session.cancel()
			}
			session.mutex.Unlock()
			<-session.responseGate
			if err != nil {
				return false
			}
		}
		if readError != nil {
			if readError == io.EOF && session.isPrimary(member) {
				if !session.acquireResponse() {
					return false
				}
				session.mutex.Lock()
				eligible := session.responseEligibleLocked(member)
				if eligible {
					session.responseClosed = true
				}
				session.mutex.Unlock()
				if eligible {
					if err := closeWrite(session.visitor); err != nil {
						session.cancel()
					}
				}
				<-session.responseGate
				return eligible
			}
			return false
		}
	}
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
				if err := closeWrite(member.connection); err != nil {
					member.close()
				}
				return
			}
			if err := member.setWriteDeadline(); err != nil {
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

func (member *tcpMember) setWriteDeadline() error {
	deadline := time.Now().Add(mirrorTCPWriteTimeout)
	if member.session != nil {
		member.session.mutex.Lock()
		defer member.session.mutex.Unlock()
		if member.session.isPrimary(member) {
			deadline = time.Time{}
		}
	}
	return member.connection.SetWriteDeadline(deadline)
}

func closeWrite(connection net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if candidate, ok := connection.(closeWriter); ok {
		return candidate.CloseWrite()
	}
	return io.ErrClosedPipe
}

// The session mutex protects generation and responder eligibility checks.
func (session *TCPSession) responseEligibleLocked(member *tcpMember) bool {
	if session.context.Err() != nil || session.members[member.target.ClientID] != member || !session.isPrimary(member) {
		return false
	}
	select {
	case <-member.stopped:
		return false
	default:
		return true
	}
}
