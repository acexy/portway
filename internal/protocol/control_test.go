package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestControlFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	expected := Heartbeat{Sequence: 42}
	if err := WriteControl(&buffer, MessagePing, expected); err != nil {
		t.Fatalf("write control frame: %v", err)
	}

	envelope, err := ReadControl(&buffer)
	if err != nil {
		t.Fatalf("read control frame: %v", err)
	}
	if envelope.Type != MessagePing {
		t.Fatalf("unexpected message type: %s", envelope.Type)
	}

	var actual Heartbeat
	if err := DecodePayload(envelope, &actual); err != nil {
		t.Fatalf("decode heartbeat: %v", err)
	}
	if actual != expected {
		t.Fatalf("unexpected heartbeat: %#v", actual)
	}
}

func TestDecodePayloadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	envelope := Envelope{
		Type:    MessagePing,
		Payload: []byte(`{"sequence":1,"unexpected":true}`),
	}
	var heartbeat Heartbeat
	err := DecodePayload(envelope, &heartbeat)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
	if !errors.Is(err, ErrInvalidControlMessage) {
		t.Fatalf("error = %v, want ErrInvalidControlMessage", err)
	}
}

func TestReadControlClassifiesInvalidFrame(t *testing.T) {
	t.Parallel()

	frame := make([]byte, controlHeaderSize)
	copy(frame, "NOPE")
	if _, err := ReadControl(bytes.NewReader(frame)); !errors.Is(
		err,
		ErrInvalidControlMessage,
	) {
		t.Fatalf("ReadControl() error = %v, want ErrInvalidControlMessage", err)
	}
}

func TestRequestIDValidationBoundsReplayCacheKeys(t *testing.T) {
	valid := strings.Repeat("a", maxRequestIDBytes)
	if err := ValidateRequestID(valid); err != nil {
		t.Fatalf("valid request ID rejected: %v", err)
	}
	for _, invalid := range []string{"", valid + "a", "has space", "padded="} {
		if err := ValidateRequestID(invalid); err == nil {
			t.Fatalf("invalid request ID %q was accepted", invalid)
		}
	}
	var buffer bytes.Buffer
	if err := WriteControlWithRequestID(
		&buffer,
		MessagePing,
		strings.Repeat("x", maxRequestIDBytes+1),
		Heartbeat{},
	); err == nil {
		t.Fatal("oversized request ID was written")
	}
}

func TestCloseSessionFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	expected := CloseSession{
		SessionID: "current-session",
		Reason:    CloseReasonClientShutdown,
	}
	if err := WriteControl(&buffer, MessageCloseSession, expected); err != nil {
		t.Fatalf("write close session frame: %v", err)
	}

	envelope, err := ReadControl(&buffer)
	if err != nil {
		t.Fatalf("read close session frame: %v", err)
	}
	if envelope.Type != MessageCloseSession {
		t.Fatalf("unexpected message type: %s", envelope.Type)
	}

	var actual CloseSession
	if err := DecodePayload(envelope, &actual); err != nil {
		t.Fatalf("decode close session: %v", err)
	}
	if actual != expected {
		t.Fatalf("unexpected close session: %#v", actual)
	}
}

func TestManagedConfigurationDigestIsStableAndSensitive(t *testing.T) {
	proxies := []ManagedProxy{{
		Name:       "ssh",
		Type:       ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  22,
		RemotePort: 22022,
	}}
	first, err := ManagedConfigurationDigest(proxies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ManagedConfigurationDigest(append([]ManagedProxy(nil), proxies...))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("equivalent managed configurations produced different digests")
	}
	proxies[0].RemotePort++
	changed, err := ManagedConfigurationDigest(proxies)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("changed managed configuration retained the previous digest")
	}
}
