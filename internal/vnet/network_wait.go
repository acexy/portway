package vnet

import (
	"context"
	"errors"
	"time"
)

const networkCleanupTimeout = 10 * time.Second
const networkInspectionInterval = 50 * time.Millisecond

// waitForNetworkCondition checks state immediately and bounds every subsequent
// observation by the caller's context. It never changes foreign resources.
func waitForNetworkCondition(ctx context.Context, check func() (bool, error)) error {
	ticker := time.NewTicker(networkInspectionInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := check()
		if err != nil || ready {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// A disappearing route is not proof of ownership. Wait for conflict-free state
// rather than deleting a route or accepting a still-conflicting configuration.
func waitForNetworkConflicts(ctx context.Context, check func(context.Context) error) error {
	waitContext, cancel := context.WithTimeout(ctx, networkCleanupTimeout)
	defer cancel()
	var conflict error
	err := waitForNetworkCondition(waitContext, func() (bool, error) {
		err := check(waitContext)
		if errors.Is(err, ErrForeignResource) {
			conflict = err
			return false, nil
		}
		return err == nil, err
	})
	if ctx.Err() == nil && errors.Is(waitContext.Err(), context.DeadlineExceeded) {
		return errors.Join(conflict, waitContext.Err(), err)
	}
	return err
}
