package mirror

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acexy/portway/internal/link"
)

// integritySession publishes every supplied member before consuming visitor input.
func integritySession(t *testing.T, visitor net.Conn, connections map[string]net.Conn) (*TCPSession, <-chan struct{}) {
	t.Helper()
	guard := &testTargetGuard{targets: make(map[string]link.Target)}
	for client := range connections {
		guard.targets[client] = link.Target{ClientID: client, SessionID: client, BindingID: client}
	}
	var connectionsMutex sync.Mutex
	session := NewTCPSession(context.Background(), visitor, guard,
		func(ctx context.Context, target link.Target) (net.Conn, error) {
			// Each test exercises the first link only. Failed replicas may retry,
			// but must not reuse a closed connection.
			connectionsMutex.Lock()
			connection := connections[target.ClientID]
			delete(connections, target.ClientID)
			connectionsMutex.Unlock()
			if connection == nil {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return connection, nil
		})
	session.SetPrimary("primary")
	for _, target := range guard.targets {
		<-session.AddTarget(target)
	}
	done := make(chan struct{})
	go func() { defer close(done); session.Serve(nil) }()
	t.Cleanup(func() { session.Cancel(); <-done })
	return session, done
}

func TestPrimaryBackpressurePreservesBurstAndCancellation(t *testing.T) {
	for _, cancelBlocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "cancel"}[cancelBlocked], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				visitor, peer := net.Pipe()
				stream, backend := net.Pipe()
				defer peer.Close()
				defer backend.Close()
				session, done := integritySession(t, visitor, map[string]net.Conn{"primary": stream})
				payload := bytes.Repeat([]byte("ordered-request"), 200000)
				written := make(chan error, 1)
				go func() { _, err := peer.Write(payload); written <- err }()
				synctest.Wait()
				// Exceed the old five-second write deadline while the queue is full.
				time.Sleep(6 * time.Second)
				select {
				case err := <-written:
					t.Fatalf("input did not apply backpressure: %v", err)
				default:
				}
				if cancelBlocked {
					session.Cancel()
					<-done
					if err := <-written; err == nil {
						t.Fatal("blocked visitor survived cancellation")
					}
					return
				}
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(backend, received); err != nil || !bytes.Equal(received, payload) {
					t.Fatalf("Primary request corrupted: %v", err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestBlockedPrimaryResponseDoesNotBlockReplicaConsumption(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := net.Pipe()
		primary, backend := net.Pipe()
		replica, shadow := net.Pipe()
		defer peer.Close()
		defer backend.Close()
		defer shadow.Close()
		integritySession(t, visitor, map[string]net.Conn{"primary": primary, "replica": replica})
		payload := bytes.Repeat([]byte("response"), 10000)
		written := make(chan error, 1)
		go func() { _, err := backend.Write(payload); written <- err }()
		synctest.Wait()
		time.Sleep(6 * time.Second)
		// More than one reader buffer proves the discard loop keeps reading.
		if _, err := shadow.Write(bytes.Repeat([]byte("discard"), 10000)); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, received); err != nil || !bytes.Equal(received, payload) {
			t.Fatalf("Primary response corrupted: %v", err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	})
}

func TestReplicaWriteTimeoutIsFifteenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connection, peer := net.Pipe()
		defer peer.Close()
		member := &tcpMember{connection: connection, queue: make(chan []byte, 1),
			done: make(chan struct{}), stopped: make(chan struct{})}
		member.queue <- []byte("blocked")
		go member.writeLoop(context.Background())
		synctest.Wait()
		time.Sleep(14 * time.Second)
		select {
		case <-member.done:
			t.Fatal("replica was closed before fifteen seconds")
		default:
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-member.done:
		default:
			t.Fatal("replica retained its blocked write after fifteen seconds")
		}
	})
}

// halfPipe keeps request and response EOF independent without real-time sleeps.
type halfPipe struct {
	net.Conn
	reader *io.PipeReader
	writer *io.PipeWriter
}

func newHalfPipe() (*halfPipe, *halfPipe) {
	leftReader, leftWriter := io.Pipe()
	rightReader, rightWriter := io.Pipe()
	return &halfPipe{reader: leftReader, writer: rightWriter}, &halfPipe{reader: rightReader, writer: leftWriter}
}

func (pipe *halfPipe) Read(buffer []byte) (int, error)  { return pipe.reader.Read(buffer) }
func (pipe *halfPipe) Write(buffer []byte) (int, error) { return pipe.writer.Write(buffer) }
func (pipe *halfPipe) CloseWrite() error                { return pipe.writer.Close() }
func (pipe *halfPipe) Close() error                     { return errors.Join(pipe.reader.Close(), pipe.writer.Close()) }
func (pipe *halfPipe) SetWriteDeadline(time.Time) error { return nil }

func TestPrimaryHalfClosePreservesDelayedResponseAndReplicaDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := newHalfPipe()
		primary, backend := newHalfPipe()
		replica, shadow := newHalfPipe()
		defer peer.Close()
		defer backend.Close()
		defer shadow.Close()
		session, done := integritySession(t, visitor, map[string]net.Conn{"primary": primary, "replica": replica})
		peer.CloseWrite()
		if _, err := backend.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("request half-close: %v", err)
		}
		// The replica never completes its response. Its drain deadline must not
		// end the Primary, even after the new fifteen-second grace period.
		time.Sleep(16 * time.Second)
		synctest.Wait()
		session.mutex.Lock()
		_, replicaExists := session.members["replica"]
		session.mutex.Unlock()
		if replicaExists {
			t.Fatal("replica drain did not finish")
		}
		for range 2 {
			go func() { _, _ = backend.Write([]byte("response")) }()
			payload := make([]byte, 8)
			if _, err := io.ReadFull(peer, payload); err != nil || string(payload) != "response" {
				t.Fatalf("response truncated: %q, %v", payload, err)
			}
			time.Sleep(6 * time.Second)
		}
		backend.CloseWrite()
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("response half-close: %v", err)
		}
		<-done
	})
}

func TestPrimaryResponseEOFKeepsRequestDirectionAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := newHalfPipe()
		primary, backend := newHalfPipe()
		defer peer.Close()
		defer backend.Close()
		_, done := integritySession(t, visitor, map[string]net.Conn{"primary": primary})
		backend.CloseWrite()
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("response EOF not forwarded: %v", err)
		}
		go func() { _, _ = peer.Write([]byte("remaining")); peer.CloseWrite() }()
		payload, err := io.ReadAll(backend)
		if err != nil || string(payload) != "remaining" {
			t.Fatalf("request direction closed prematurely: %q, %v", payload, err)
		}
		<-done
	})
}

func TestPrimarySwitchBoundsBlockedOldResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := net.Pipe()
		primary, backend := net.Pipe()
		replica, shadow := net.Pipe()
		defer peer.Close()
		defer backend.Close()
		defer shadow.Close()
		session, done := integritySession(t, visitor, map[string]net.Conn{"primary": primary, "replica": replica})
		go func() { _, _ = backend.Write([]byte("blocked")) }()
		synctest.Wait()
		session.SetPrimary("replica")
		go func() { _, _ = shadow.Write([]byte("new response")) }()
		time.Sleep(15 * time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("responder switch retained blocked visitor")
		}
	})
}

func TestReplicaOverflowDoesNotLosePrimaryTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := net.Pipe()
		primary, backend := net.Pipe()
		replica, shadow := net.Pipe()
		defer peer.Close()
		defer backend.Close()
		defer shadow.Close()
		integritySession(t, visitor, map[string]net.Conn{"primary": primary, "replica": replica})
		payload := bytes.Repeat([]byte("request"), 200000)
		written := make(chan error, 1)
		go func() { _, err := peer.Write(payload); written <- err }()
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(backend, received); err != nil || !bytes.Equal(received, payload) {
			t.Fatalf("slow replica affected Primary request: %v", err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if _, err := shadow.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("overflowed replica survived: %v", err)
		}
		go func() { _, err := backend.Write([]byte("complete")); written <- err }()
		response := make([]byte, 8)
		if _, err := io.ReadFull(peer, response); err != nil || string(response) != "complete" {
			t.Fatalf("slow replica affected Primary response: %q, %v", response, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrimaryFailureReleasesBlockedResponseAfterInputEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := newHalfPipe()
		primary, backend := newHalfPipe()
		defer peer.Close()
		defer backend.Close()
		session, done := integritySession(t, visitor, map[string]net.Conn{"primary": primary})
		peer.CloseWrite()
		if _, err := backend.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal(err)
		}
		go func() { _, _ = backend.Write([]byte("blocked response")) }()
		synctest.Wait()
		session.mutex.Lock()
		member := session.members["primary"]
		session.mutex.Unlock()
		member.close()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("failed Primary retained blocked response task")
		}
	})
}

func TestInputEOFCancelsPendingMemberOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := newHalfPipe()
		primary, backend := newHalfPipe()
		defer peer.Close()
		defer backend.Close()
		targets := []link.Target{{ClientID: "primary", BindingID: "primary"}, {ClientID: "pending", BindingID: "pending"}}
		guard := &testTargetGuard{targets: map[string]link.Target{"primary": targets[0], "pending": targets[1]}}
		pending := make(chan struct{})
		cancelled := make(chan struct{})
		session := NewTCPSession(context.Background(), visitor, guard, func(ctx context.Context, target link.Target) (net.Conn, error) {
			if target.ClientID == "primary" {
				return primary, nil
			}
			close(pending)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		})
		defer session.Cancel()
		session.SetPrimary("primary")
		done := make(chan struct{})
		go func() { defer close(done); session.Serve(targets) }()
		<-pending
		peer.CloseWrite()
		<-cancelled
		backend.CloseWrite()
		<-done
	})
}

func TestPrimaryReadFailureRecoversWithoutReplayingInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, peer := newHalfPipe()
		first, firstBackend := newHalfPipe()
		second, secondBackend := newHalfPipe()
		defer peer.Close()
		defer firstBackend.Close()
		defer secondBackend.Close()
		target := link.Target{ClientID: "primary", BindingID: "primary"}
		guard := &testTargetGuard{targets: map[string]link.Target{"primary": target}}
		recovered := make(chan struct{})
		attempts := 0
		session := NewTCPSession(context.Background(), visitor, guard, func(ctx context.Context, _ link.Target) (net.Conn, error) {
			attempts++
			if attempts == 1 {
				return first, nil
			}
			if attempts == 2 {
				close(recovered)
				return second, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		session.SetPrimary("primary")
		<-session.AddTarget(target)
		done := make(chan struct{})
		go func() { defer close(done); session.Serve(nil) }()
		defer func() { session.Cancel(); <-done }()
		firstBackend.writer.CloseWithError(errors.New("injected connection reset"))
		synctest.Wait()
		if _, err := peer.Write([]byte("outage")); err != nil {
			t.Fatal(err)
		}
		<-recovered
		synctest.Wait()
		go func() { _, _ = peer.Write([]byte("fresh")) }()
		request := make([]byte, 5)
		if _, err := io.ReadFull(secondBackend, request); err != nil || string(request) != "fresh" {
			t.Fatalf("recovery replayed input or lost new request: %q, %v", request, err)
		}
		go func() { _, _ = secondBackend.Write([]byte("reply")) }()
		response := make([]byte, 5)
		if _, err := io.ReadFull(peer, response); err != nil || string(response) != "reply" {
			t.Fatalf("recovered Primary did not reply: %q, %v", response, err)
		}
	})
}
