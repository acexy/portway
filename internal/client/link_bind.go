package client

import (
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

// completeLinkBinding validates an already classified BindResult and clears the
// deadline only after acceptance. The caller retains stream ownership.
func completeLinkBinding(dataConnection transport.Stream, envelope protocol.Envelope, linkID string) protocol.LinkErrorCode {
	var result protocol.BindResult
	if err := protocol.DecodePayload(envelope, &result); err != nil ||
		result.LinkID != linkID {
		return protocol.LinkErrorInvalidBinding
	}
	if result.Status != protocol.LinkStatusAccepted {
		if result.Error != nil {
			return *result.Error
		}
		return protocol.LinkErrorInvalidBinding
	}
	if err := dataConnection.SetDeadline(time.Time{}); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	return ""
}
