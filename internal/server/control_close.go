package server

import (
	"fmt"
	"io"
	"time"

	"github.com/acexy/portway/internal/transport"
)

const controlCloseDeliveryTimeout = 2 * time.Second

// finishControlSession preserves delivery of the already-written close_ack.
// The connection owner still performs the full Close when this bounded wait ends.
func finishControlSession(connection transport.Stream) error {
	if err := connection.SetReadDeadline(time.Now().Add(controlCloseDeliveryTimeout)); err != nil {
		return fmt.Errorf("set control close delivery deadline: %w", err)
	}
	if err := connection.CloseWrite(); err != nil {
		return fmt.Errorf("finish close acknowledgment stream: %w", err)
	}
	// Peer closure, cancellation, or the deadline ends the delivery opportunity.
	// No further business messages are dispatched or retained during shutdown.
	_, _ = io.Copy(io.Discard, connection)
	return nil
}
