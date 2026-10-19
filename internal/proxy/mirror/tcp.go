// Package mirror owns best-effort mirror data-plane sessions.
package mirror

import (
	"context"
	"errors"
	"io"
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
	mirrorTCPWriteTimeout     = 15 * time.Second
	mirrorTCPCloseGracePeriod = 15 * time.Second
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
	inputContext    context.Context
	inputCancel     context.CancelFunc
	memberReady     chan struct{}
	memberReadyOnce sync.Once
	waitGroup       sync.WaitGroup
	responseGate    chan struct{}
	responseWriter  *tcpMember
	responseClosed  bool
	primaryChanged  chan struct{}
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
	inputContext, inputCancel := context.WithCancel(sessionContext)
	return &TCPSession{
		context: sessionContext, cancel: cancel, visitor: visitor,
		inputContext: inputContext, inputCancel: inputCancel,
		guard: guard, open: open,
		members: make(map[string]*tcpMember), workers: make(map[string]*tcpWorker),
		inputDone:      make(chan struct{}),
		memberReady:    make(chan struct{}),
		primaryChanged: make(chan struct{}),
		responseGate:   make(chan struct{}, 1),
	}
}

// Cancel requests termination; Serve waits for all member workers before returning.
func (session *TCPSession) Cancel() { session.cancel() }

// SetPrimary changes response eligibility without waiting for a blocked writer.
func (session *TCPSession) SetPrimary(clientID string) {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	previous := session.primaryClientID.Load()
	if previous != nil && *previous == clientID {
		return
	}
	session.primaryClientID.Store(&clientID)
	close(session.primaryChanged)
	session.primaryChanged = make(chan struct{})
	for _, member := range session.members {
		session.updateMemberRoleLocked(member)
	}
	// A previously admitted response write may finish, but cannot block a
	// responder switch forever. Its failure cancels the complete visitor.
	if session.responseWriter != nil {
		deadline := time.Time{}
		if session.responseWriter.target.ClientID != clientID {
			deadline = time.Now().Add(mirrorTCPWriteTimeout)
		}
		if err := session.visitor.SetWriteDeadline(deadline); err != nil {
			session.cancel()
		}
	}
	if session.responseClosed {
		session.cancel()
	}
}

// Serve consumes visitor input and drains the Primary independently of replicas.
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
waitInitial:
	for _, ready := range initial {
		select {
		case <-ready:
		case <-session.memberReady:
			break waitInitial
		case <-ctx.Done():
			return
		}
	}

	buffer := make([]byte, mirrorTCPChunkSize)
	for {
		length, err := visitor.Read(buffer)
		if length != 0 {
			members := session.snapshotMembers()
			var payload []byte
			if len(members) != 0 {
				// Queues share immutable storage, independent of the next read.
				payload = append([]byte(nil), buffer[:length]...)
			}
			for _, member := range members {
				session.enqueue(member, payload)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return
			}
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
	select {
	case <-finished:
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
		openContext, cancelOpen := context.WithCancel(worker.context)
		stopInputCancel := context.AfterFunc(session.inputContext, cancelOpen)
		connection, err := session.open(openContext, worker.target)
		stopInputCancel()
		cancelOpen()
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
				select {
				case <-member.done:
					select {
					case <-member.responseDone:
					case <-member.stopped:
					case <-worker.context.Done():
					}
				case <-member.stopped:
				case <-worker.context.Done():
				}
			}
			member.close()
			session.mutex.Lock()
			// A failed member cannot retain an unbounded visitor write while
			// its owner waits for cleanup or starts a replacement generation.
			if session.responseWriter == member {
				session.cancel()
			}
			session.mutex.Unlock()
			stopClose()
			<-member.done
			<-member.responseDone
			session.mutex.Lock()
			if member.drainTimer != nil {
				member.drainTimer.Stop()
			}
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
	session.inputCancel()
	members := make([]*tcpMember, 0, len(session.members))
	for _, member := range session.members {
		session.updateMemberRoleLocked(member)
		members = append(members, member)
	}
	return members
}

// enqueue keeps one bounded input block while a healthy Primary applies backpressure.
func (session *TCPSession) enqueue(member *tcpMember, payload []byte) {
	for {
		session.mutex.Lock()
		primary := session.isPrimary(member)
		changed := session.primaryChanged
		if !primary {
			select {
			case member.queue <- payload:
			default:
				member.close()
			}
			session.mutex.Unlock()
			return
		}
		session.mutex.Unlock()
		select {
		case member.queue <- payload:
			return
		case <-member.stopped:
			return
		case <-session.context.Done():
			return
		case <-changed:
		}
	}
}

func (session *TCPSession) isPrimary(member *tcpMember) bool {
	primary := session.primaryClientID.Load()
	return primary != nil && member.target.ClientID == *primary
}

// The session mutex serializes role changes with deadline and drain ownership.
func (session *TCPSession) updateMemberRoleLocked(member *tcpMember) {
	deadline := time.Time{}
	if !session.isPrimary(member) {
		deadline = time.Now().Add(mirrorTCPWriteTimeout)
	}
	if err := member.connection.SetWriteDeadline(deadline); err != nil {
		member.close()
	}
	if member.drainTimer != nil {
		member.drainTimer.Stop()
		member.drainTimer = nil
	}
	if session.closed && !session.isPrimary(member) {
		var timer *time.Timer
		timer = time.AfterFunc(mirrorTCPCloseGracePeriod, func() {
			session.mutex.Lock()
			defer session.mutex.Unlock()
			if member.drainTimer == timer && !session.isPrimary(member) {
				member.close()
			}
		})
		member.drainTimer = timer
	}
}

func (session *TCPSession) acquireResponse() bool {
	select {
	case session.responseGate <- struct{}{}:
		return true
	case <-session.context.Done():
		return false
	}
}
