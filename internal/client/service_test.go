package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/protocol"
)

func TestReconnectDelayWithJitterStaysWithinConfiguredRange(t *testing.T) {
	t.Parallel()

	baseDelay := 20 * time.Second
	minimumDelay := baseDelay * (100 - consts.ClientReconnectJitterPercent) / 100
	maximumDelay := baseDelay * (100 + consts.ClientReconnectJitterPercent) / 100

	for range 100 {
		delay := reconnectDelayWithJitter(baseDelay)
		if delay < minimumDelay || delay > maximumDelay {
			t.Fatalf(
				"jittered delay %s is outside range %s to %s",
				delay,
				minimumDelay,
				maximumDelay,
			)
		}
	}
}

func TestClassifyLinkDialFailure(t *testing.T) {
	t.Parallel()

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name           string
		ctx            context.Context
		transportError error
		localError     error
		expected       protocol.LinkErrorCode
	}{
		{
			name:     "session cancelled",
			ctx:      cancelledContext,
			expected: protocol.LinkErrorCancelled,
		},
		{
			name:           "transport failed and local dial was cancelled",
			ctx:            context.Background(),
			transportError: errors.New("transport unavailable"),
			localError:     context.Canceled,
			expected:       protocol.LinkErrorTransportFailed,
		},
		{
			name:           "local failed and transport dial was cancelled",
			ctx:            context.Background(),
			transportError: context.Canceled,
			localError:     errors.New("connection refused"),
			expected:       protocol.LinkErrorLocalDialFailed,
		},
		{
			name:       "local dial timed out",
			ctx:        context.Background(),
			localError: context.DeadlineExceeded,
			expected:   protocol.LinkErrorLocalDialFailed,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actual := classifyLinkDialFailure(
				test.ctx,
				test.transportError,
				test.localError,
			)
			if actual != test.expected {
				t.Fatalf("expected %s, got %s", test.expected, actual)
			}
		})
	}
}
