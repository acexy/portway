package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestCloseAcknowledgmentSurvivesReaderTermination(t *testing.T) {
	for _, expired := range []bool{false, true} {
		for range 100 {
			messages := make(chan protocol.Envelope, 2)
			readErrors := make(chan error, 1)
			messages <- protocol.Envelope{Type: protocol.MessagePing}
			messages <- protocol.Envelope{Type: protocol.MessageCloseAck, Payload: []byte(`{"session_id":"session-one"}`)}
			readErrors <- io.EOF
			close(messages)
			deadline := time.Now().Add(time.Second)
			if expired {
				deadline = time.Now().Add(-time.Second)
			}
			envelope, err := waitCloseAcknowledgment(messages, readErrors, deadline)
			if err != nil || envelope.Type != protocol.MessageCloseAck {
				t.Fatalf("queued acknowledgment lost: expired=%v type=%s error=%v", expired, envelope.Type, err)
			}
		}
	}
}

func TestCloseAcknowledgmentPreservesReadFailure(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		messages := make(chan protocol.Envelope, 1)
		readErrors := make(chan error, 1)
		failure := errors.New("QUIC connection closed before acknowledgment")
		readErrors <- failure
		if stopped {
			close(messages)
		}
		if _, err := waitCloseAcknowledgment(messages, readErrors, time.Now().Add(time.Second)); !errors.Is(err, failure) {
			t.Fatalf("lost concrete read error: %v", err)
		}
	}
}

func TestCloseAcknowledgmentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		messages := make(chan protocol.Envelope, 1)
		messages <- protocol.Envelope{Type: protocol.MessagePing}
		_, err := waitCloseAcknowledgment(messages, make(chan error), started.Add(gracefulCloseTimeout))
		if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(started) != gracefulCloseTimeout {
			t.Fatalf("close wait was not bounded: duration=%v error=%v", time.Since(started), err)
		}
	})
}

func TestControlReaderQueuesAcknowledgmentBeforeEOF(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	messages := make(chan protocol.Envelope, 1)
	readErrors := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readControlMessages(context.Background(), local, messages, readErrors, newHeartbeatState(time.Now()))
	}()
	if err := protocol.WriteControl(remote, protocol.MessageCloseAck, protocol.CloseAck{SessionID: "session-one"}); err != nil {
		t.Fatal(err)
	}
	remote.Close()
	<-done
	envelope, err := waitCloseAcknowledgment(messages, readErrors, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var acknowledgment protocol.CloseAck
	if err := protocol.DecodePayload(envelope, &acknowledgment); err != nil || acknowledgment.SessionID != "session-one" {
		t.Fatalf("acknowledgment changed: %+v, %v", acknowledgment, err)
	}
}
