package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	controlHeaderSize      = 12
	controlEncodingJSON    = 1
	maxControlPayloadBytes = 1024 * 1024
	maxRequestIDBytes      = 128
)

// ErrInvalidControlMessage indicates malformed framing or message content from
// a peer. I/O failures are not wrapped with this error.
var ErrInvalidControlMessage = errors.New("invalid control message")

// MessageType identifies a control protocol message.
type MessageType string

// Capability identifies one negotiated control or proxy capability.
type Capability string

const (
	CapabilityTCP         Capability = "tcp"
	CapabilityUDP         Capability = "udp"
	CapabilityHTTP        Capability = "http"
	CapabilityJSONControl Capability = "json-control"
	CapabilityTCPForward  Capability = "tcp_forward"
	CapabilityUDPForward  Capability = "udp_forward"
)

// ManagementMode identifies who owns a client's proxy configuration.
type ManagementMode string

const (
	ManagementModeShared   ManagementMode = "shared_token"
	ManagementModeGoverned ManagementMode = "governed"
	ManagementModeManaged  ManagementMode = "managed"
)

const (
	// MessageClientHello starts control protocol negotiation.
	MessageClientHello MessageType = "client_hello"
	// MessageServerHello confirms control protocol negotiation.
	MessageServerHello MessageType = "server_hello"
	// MessageServerIdentification declares the server product and version.
	MessageServerIdentification MessageType = "server_identification"
	// MessageClientIdentification declares the client product and runtime environment.
	MessageClientIdentification MessageType = "client_identification"
	// MessagePing checks that a control session remains responsive.
	MessagePing MessageType = "ping"
	// MessagePong acknowledges a ping.
	MessagePong MessageType = "pong"
	// MessageSessionError reports a session registration or recovery rejection.
	MessageSessionError MessageType = "session_error"
	// MessageCloseSession requests immediate removal of an established client session.
	MessageCloseSession MessageType = "close_session"
	// MessageCloseAck confirms that a client session was removed.
	MessageCloseAck MessageType = "close_ack"
	// MessageSyncProxies atomically declares a client's complete proxy set.
	MessageSyncProxies MessageType = "sync_proxies"
	// MessageSyncResult reports an atomic proxy declaration result.
	MessageSyncResult MessageType = "sync_result"
	// MessageOpenLink asks a client to establish one proxy data link.
	MessageOpenLink MessageType = "open_link"
	// MessageCancelLink cancels a pending data link.
	MessageCancelLink MessageType = "cancel_link"
	// MessageLinkFailed reports a client-side link setup failure.
	MessageLinkFailed MessageType = "link_failed"
	// MessageBindLink binds a RoleData connection to one pending link.
	MessageBindLink MessageType = "bind_link"
	// MessageBindResult reports a RoleData binding result.
	MessageBindResult MessageType = "bind_result"
	// MessageManagedConfigPrepare stages one complete server-owned configuration.
	MessageManagedConfigPrepare MessageType = "managed_config_prepare"
	// MessageManagedConfigPrepared confirms that a managed configuration is valid.
	MessageManagedConfigPrepared MessageType = "managed_config_prepared"
	// MessageManagedConfigActivate activates one prepared managed configuration.
	MessageManagedConfigActivate MessageType = "managed_config_activate"
	// MessageManagedConfigApplied confirms activation of a managed configuration.
	MessageManagedConfigApplied MessageType = "managed_config_applied"
	// MessageSyncConfiguration atomically declares complete Proxy and Forward sets.
	MessageSyncConfiguration MessageType = "sync_configuration"
	// MessageSyncConfigurationResult reports a complete configuration result.
	MessageSyncConfigurationResult MessageType = "sync_configuration_result"
	// MessageRequestForwardLink asks the server to prepare one Forward Link.
	MessageRequestForwardLink MessageType = "request_forward_link"
	// MessageForwardLinkOffer returns an authorized one-time Forward Ticket.
	MessageForwardLinkOffer MessageType = "forward_link_offer"
	// MessageCancelForwardLink cancels a pending Forward Link.
	MessageCancelForwardLink MessageType = "cancel_forward_link"
	// MessageForwardLinkFailed reports Forward Link setup failure.
	MessageForwardLinkFailed MessageType = "forward_link_failed"
	// MessageForwardBindingRevoked deactivates one Forward Binding after reload.
	MessageForwardBindingRevoked MessageType = "forward_binding_revoked"
	// MessageForwardBindingActivated restores one dormant Forward Binding after reload.
	MessageForwardBindingActivated MessageType = "forward_binding_activated"
)

// SessionErrorCode identifies a stable session registration or recovery failure.
type SessionErrorCode string

const (
	// SessionErrorClientIDAlreadyOnline indicates an active duplicate client ID.
	SessionErrorClientIDAlreadyOnline SessionErrorCode = "client_id_already_online"
	// SessionErrorClientIDRecoveryPending indicates that registration or recovery is waiting for the current Session lifecycle transition.
	SessionErrorClientIDRecoveryPending SessionErrorCode = "client_id_recovery_pending"
	// SessionErrorResumeSessionMismatch indicates an invalid recovery session ID.
	SessionErrorResumeSessionMismatch SessionErrorCode = "resume_session_mismatch"
	// SessionErrorSessionExpired indicates that recoverable state no longer exists.
	SessionErrorSessionExpired SessionErrorCode = "session_expired"
	// SessionErrorInvalidClientID indicates an invalid client identifier.
	SessionErrorInvalidClientID SessionErrorCode = "invalid_client_id"
	// SessionErrorAuthenticationFailed hides credential and identity failure details.
	SessionErrorAuthenticationFailed SessionErrorCode = "authentication_failed"
	// SessionErrorServerCapacityReached indicates that the server cannot admit another control Session.
	SessionErrorServerCapacityReached SessionErrorCode = "server_capacity_reached"
)

// Envelope is the common control message container.
type Envelope struct {
	Type      MessageType     `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// ClientHello advertises capabilities supported by the client.
type ClientHello struct {
	ClientID        string       `json:"client_id"`
	ResumeSessionID string       `json:"resume_session_id,omitempty"`
	Capabilities    []Capability `json:"capabilities"`
}

// ServerHello confirms the session and negotiated capabilities.
type ServerHello struct {
	ClientID       string         `json:"client_id"`
	ManagementMode ManagementMode `json:"management_mode"`
	SessionID      string         `json:"session_id"`
	Resumed        bool           `json:"resumed"`
	Capabilities   []Capability   `json:"capabilities"`
}

// Heartbeat carries a monotonically increasing session sequence.
type Heartbeat struct {
	Sequence uint64 `json:"sequence"`
}

// SessionError describes a client registration or recovery rejection.
type SessionError struct {
	Code      SessionErrorCode `json:"code"`
	Message   string           `json:"message"`
	Retryable bool             `json:"retryable"`
}

// CloseReason identifies why an endpoint is intentionally closing a session.
type CloseReason string

const (
	// CloseReasonClientShutdown indicates an intentional client process shutdown.
	CloseReasonClientShutdown CloseReason = "client_shutdown"
)

// CloseSession requests graceful termination of the current control session.
type CloseSession struct {
	SessionID string      `json:"session_id"`
	Reason    CloseReason `json:"reason"`
}

// CloseAck confirms graceful termination of a control session.
type CloseAck struct {
	SessionID string `json:"session_id"`
}

// WriteControl writes one length-limited JSON control frame.
func WriteControl(writer io.Writer, messageType MessageType, payload any) error {
	return WriteControlWithRequestID(writer, messageType, "", payload)
}

// WriteControlWithRequestID writes one control frame with a correlation identifier.
func WriteControlWithRequestID(
	writer io.Writer,
	messageType MessageType,
	requestID string,
	payload any,
) error {
	if requestID != "" {
		if err := ValidateRequestID(requestID); err != nil {
			return err
		}
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode control payload: %w", err)
	}
	envelopeBytes, err := json.Marshal(Envelope{
		Type:      messageType,
		RequestID: requestID,
		Payload:   payloadBytes,
	})
	if err != nil {
		return fmt.Errorf("encode control envelope: %w", err)
	}
	if len(envelopeBytes) > maxControlPayloadBytes {
		return fmt.Errorf("control payload exceeds %d bytes", maxControlPayloadBytes)
	}

	header := make([]byte, controlHeaderSize)
	copy(header, Magic)
	header[4] = CoreVersion
	header[5] = controlEncodingJSON
	binary.BigEndian.PutUint32(header[8:], uint32(len(envelopeBytes)))
	if err := writeAll(writer, header); err != nil {
		return fmt.Errorf("write control header: %w", err)
	}
	if err := writeAll(writer, envelopeBytes); err != nil {
		return fmt.Errorf("write control payload: %w", err)
	}
	return nil
}

// ReadControl reads and validates one JSON control frame.
func ReadControl(reader io.Reader) (Envelope, error) {
	header := make([]byte, controlHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Envelope{}, err
	}
	if string(header[:4]) != Magic {
		return Envelope{}, fmt.Errorf("%w: invalid control frame magic", ErrInvalidControlMessage)
	}
	if header[4] != CoreVersion {
		return Envelope{}, fmt.Errorf(
			"%w: unsupported control protocol version %d",
			ErrInvalidControlMessage,
			header[4],
		)
	}
	if header[5] != controlEncodingJSON {
		return Envelope{}, fmt.Errorf(
			"%w: unsupported control encoding %d",
			ErrInvalidControlMessage,
			header[5],
		)
	}
	if binary.BigEndian.Uint16(header[6:8]) != 0 {
		return Envelope{}, fmt.Errorf(
			"%w: unsupported control frame flags",
			ErrInvalidControlMessage,
		)
	}

	payloadLength := binary.BigEndian.Uint32(header[8:])
	if payloadLength == 0 || payloadLength > maxControlPayloadBytes {
		return Envelope{}, fmt.Errorf(
			"%w: invalid control payload length %d",
			ErrInvalidControlMessage,
			payloadLength,
		)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Envelope{}, err
	}

	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf(
			"%w: decode control envelope: %v",
			ErrInvalidControlMessage,
			err,
		)
	}
	var trailingValue any
	if err := decoder.Decode(&trailingValue); !errors.Is(err, io.EOF) {
		if err == nil {
			return Envelope{}, fmt.Errorf(
				"%w: decode control envelope: trailing JSON value",
				ErrInvalidControlMessage,
			)
		}
		return Envelope{}, fmt.Errorf(
			"%w: decode control envelope: %v",
			ErrInvalidControlMessage,
			err,
		)
	}
	if envelope.Type == "" {
		return Envelope{}, fmt.Errorf(
			"%w: control message type is required",
			ErrInvalidControlMessage,
		)
	}
	if envelope.RequestID != "" {
		if err := ValidateRequestID(envelope.RequestID); err != nil {
			return Envelope{}, fmt.Errorf("%w: %v", ErrInvalidControlMessage, err)
		}
	}
	return envelope, nil
}

// ValidateRequestID rejects correlation identifiers that could amplify the
// bounded replay cache or make operator-visible identifiers ambiguous.
func ValidateRequestID(requestID string) error {
	if requestID == "" {
		return errors.New("request ID is required")
	}
	if len(requestID) > maxRequestIDBytes {
		return fmt.Errorf("request ID exceeds %d bytes", maxRequestIDBytes)
	}
	for index := range len(requestID) {
		character := requestID[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' {
			continue
		}
		return errors.New("request ID must use Base64URL characters without padding")
	}
	return nil
}

// DecodePayload strictly decodes a control message payload.
func DecodePayload(envelope Envelope, destination any) error {
	if len(envelope.Payload) == 0 {
		return fmt.Errorf(
			"%w: control message payload is required",
			ErrInvalidControlMessage,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf(
			"%w: decode %s payload: %v",
			ErrInvalidControlMessage,
			envelope.Type,
			err,
		)
	}
	var trailingValue any
	if err := decoder.Decode(&trailingValue); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf(
				"%w: decode %s payload: trailing JSON value",
				ErrInvalidControlMessage,
				envelope.Type,
			)
		}
		return fmt.Errorf(
			"%w: decode %s payload: %v",
			ErrInvalidControlMessage,
			envelope.Type,
			err,
		)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
