// Package mirror owns best-effort mirror data-plane sessions.
package mirror

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/link"
)

const (
	mirrorTCPChunkSize        = 32 * 1024
	mirrorTCPQueueDepth       = 32
	mirrorTCPRetryInterval    = time.Second
	mirrorTCPMaxRetryInterval = 5 * time.Second
	mirrorTCPWriteTimeout     = 5 * time.Second
	mirrorTCPCloseGracePeriod = 5 * time.Second
)

// Each worker owns at most one pending or active link for a member generation.
type tcpWorker struct {
	target      link.Target
	context     context.Context
	cancel      context.CancelFunc
	initialDone chan struct{}
	done        chan struct{}
}

// TCPSession owns one Visitor connection and its dynamically changing
// set of best-effort mirror copies.
type TCPSession struct {
	context         context.Context
	cancel          context.CancelFunc
	guard           TargetGuard
	open            OpenStream
	visitor         net.Conn
	mutex           sync.Mutex
	closed          bool
	members         map[string]*tcpMember
	workers         map[string]*tcpWorker
	inputDone       chan struct{}
	waitGroup       sync.WaitGroup
	responseMutex   sync.Mutex
	primaryClientID atomic.Pointer[string]
}

// TargetGuard serializes target-generation validation with local publication.
// Lock ordering is guard before session. IsCurrent requires the guard lock;
// implementations must not perform I/O, callbacks, or task waits while locked.
type TargetGuard interface {
	Lock()
	Unlock()
	IsCurrent(link.Target) bool
}

// OpenStream prepares one authenticated link outside the target guard lock.
type OpenStream func(context.Context, link.Target) (net.Conn, error)

// NewTCPSession creates a visitor owner. Register it before taking the target
// snapshot, then call Serve exactly once; AddTarget may run concurrently.
func NewTCPSession(ctx context.Context, visitor net.Conn, guard TargetGuard, open OpenStream) *TCPSession {
	sessionContext, cancel := context.WithCancel(ctx)
	return &TCPSession{
		context: sessionContext, cancel: cancel, visitor: visitor,
		guard: guard, open: open,
		members: make(map[string]*tcpMember), workers: make(map[string]*tcpWorker),
		inputDone: make(chan struct{}),
	}
}

// Cancel requests termination; Serve waits for all member workers before returning.
func (session *TCPSession) Cancel() { session.cancel() }

// SetPrimary changes response eligibility without waiting for a blocked writer.
func (session *TCPSession) SetPrimary(clientID string) { session.primaryClientID.Store(&clientID) }

// Serve consumes visitor input and owns the bounded response-drain window.
func (session *TCPSession) Serve(targets []link.Target) {
	visitor := session.visitor
	ctx := session.context
	defer visitor.Close()
	stopVisitor := context.AfterFunc(ctx, func() { _ = visitor.Close() })
	defer stopVisitor()
	defer func() {
		session.closeInput()
		session.cancel()
		session.waitGroup.Wait()
	}()

	initial := make([]<-chan struct{}, 0, len(targets))
	for _, target := range targets {
		initial = append(initial, session.AddTarget(target))
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

// AddTarget starts or replaces one authorized member generation. The returned
// channel closes after its first link attempt or rejection.
func (session *TCPSession) AddTarget(target link.Target) <-chan struct{} {
	session.guard.Lock()
	defer session.guard.Unlock()
	if !session.guard.IsCurrent(target) {
		done := make(chan struct{})
		close(done)
		return done
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	previous := session.workers[target.ClientID]
	if previous != nil && previous.target.BindingID == target.BindingID &&
		previous.target.SessionID == target.SessionID &&
		previous.target.Writer == target.Writer {
		return previous.initialDone
	}
	ctx, cancel := context.WithCancel(session.context)
	worker := &tcpWorker{
		target: target, context: ctx, cancel: cancel,
		initialDone: make(chan struct{}), done: make(chan struct{}),
	}
	if session.closed || session.context.Err() != nil {
		cancel()
		close(worker.initialDone)
		return worker.initialDone
	}
	session.workers[target.ClientID] = worker
	if previous != nil {
		previous.cancel()
	}
	session.waitGroup.Go(func() { session.runWorker(worker, previous) })
	return worker.initialDone
}

func (session *TCPSession) runWorker(worker, previous *tcpWorker) {
	var initialOnce sync.Once
	initialDone := func() { initialOnce.Do(func() { close(worker.initialDone) }) }
	defer initialDone()
	defer close(worker.done)
	defer worker.cancel()
	defer func() {
		session.mutex.Lock()
		if session.workers[worker.target.ClientID] == worker {
			delete(session.workers, worker.target.ClientID)
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
		session.guard.Lock()
		valid := session.guard.IsCurrent(worker.target)
		if !valid {
			session.mutex.Lock()
			if session.workers[worker.target.ClientID] == worker {
				delete(session.workers, worker.target.ClientID)
			}
			session.mutex.Unlock()
		}
		session.guard.Unlock()
		if !valid || worker.context.Err() != nil {
			return
		}
		select {
		case <-session.inputDone:
			return
		default:
		}
		connection, err := session.open(worker.context, worker.target)
		var member *tcpMember
		if err == nil {
			session.guard.Lock()
			if session.guard.IsCurrent(worker.target) && worker.context.Err() == nil {
				member = session.addConnection(worker.target, connection)
			}
			session.guard.Unlock()
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
			if session.members[worker.target.ClientID] == member {
				delete(session.members, worker.target.ClientID)
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

func (session *TCPSession) snapshotMembers() []*tcpMember {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	members := make([]*tcpMember, 0, len(session.members))
	for _, member := range session.members {
		members = append(members, member)
	}
	return members
}

func (session *TCPSession) closeInput() []*tcpMember {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	close(session.inputDone)
	members := make([]*tcpMember, 0, len(session.members))
	for _, member := range session.members {
		members = append(members, member)
	}
	return members
}
