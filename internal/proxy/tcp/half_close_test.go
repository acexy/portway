package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

type duplexPipe struct {
	net.Conn
	reader *io.PipeReader
	writer *io.PipeWriter
}

func newDuplexPipe() (*duplexPipe, *duplexPipe) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &duplexPipe{reader: ar, writer: bw}, &duplexPipe{reader: br, writer: aw}
}
func (p *duplexPipe) Read(b []byte) (int, error)  { return p.reader.Read(b) }
func (p *duplexPipe) Write(b []byte) (int, error) { return p.writer.Write(b) }
func (p *duplexPipe) CloseWrite() error           { return p.writer.Close() }
func (p *duplexPipe) Close() error                { return errors.Join(p.reader.Close(), p.writer.Close()) }

func TestForwardHalfCloseAllowsDelayedAndLongResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, left := newDuplexPipe()
		right, backend := newDuplexPipe()
		defer visitor.Close()
		defer backend.Close()
		done := make(chan error, 1)
		go func() { _, err := Forward(context.Background(), left, right); done <- err }()
		visitor.CloseWrite()
		if _, err := backend.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("half close: %v", err)
		}
		for range 2 {
			time.Sleep(6 * time.Second)
			select {
			case err := <-done:
				t.Fatalf("response truncated: %v", err)
			default:
			}
			go func() { _, _ = backend.Write([]byte("response")) }()
			payload := make([]byte, 8)
			if _, err := io.ReadFull(visitor, payload); err != nil {
				t.Fatal(err)
			}
		}
		backend.CloseWrite()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestForwardReadFailureImmediatelyClosesOtherDirection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		visitor, left := newDuplexPipe()
		right, backend := newDuplexPipe()
		defer visitor.Close()
		defer backend.Close()
		done := make(chan error, 1)
		failure := errors.New("injected read failure")
		go func() { _, err := Forward(context.Background(), left, right); done <- err }()
		visitor.writer.CloseWithError(failure)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, failure) {
				t.Fatal(err)
			}
		default:
			t.Fatal("copy task still blocked after read failure")
		}
	})
}
