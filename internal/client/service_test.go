package client

import (
	"testing"
	"time"

	"github.com/acexy/portway/internal/consts"
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
