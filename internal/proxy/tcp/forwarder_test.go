package tcp

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestForwardResultPreservesDirection(t *testing.T) {
	result := forwardResult(
		copyResult{leftToRight: false, bytes: 23},
		copyResult{leftToRight: true, bytes: 17},
	)
	if result.LeftToRightBytes != 17 || result.RightToLeftBytes != 23 {
		t.Fatalf("unexpected forward result: %+v", result)
	}
}

func TestCloseReasonClassifiesExpectedNetworkErrors(t *testing.T) {
	testCases := []struct {
		name   string
		ctx    context.Context
		err    error
		reason string
	}{
		{name: "reset", ctx: context.Background(), err: syscall.ECONNRESET, reason: "connection_reset"},
		{name: "broken pipe", ctx: context.Background(), err: syscall.EPIPE, reason: "broken_pipe"},
		{name: "unknown", ctx: context.Background(), err: errors.New("unknown"), reason: "stream_error"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	testCases = append(testCases, struct {
		name   string
		ctx    context.Context
		err    error
		reason string
	}{name: "cancelled", ctx: ctx, err: context.Canceled, reason: "link_cancelled"})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if reason := CloseReason(testCase.ctx, testCase.err); reason != testCase.reason {
				t.Fatalf("expected %q, got %q", testCase.reason, reason)
			}
		})
	}
}
