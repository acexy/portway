package system

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkConflictWaitRechecksUntilClear(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	err := waitForNetworkConflicts(ctx, func(context.Context) error {
		calls++
		if calls == 1 {
			return ErrForeignResource
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestNetworkConflictWaitStopsOnInspectionFailure(t *testing.T) {
	failure := errors.New("route snapshot failed")
	calls := 0
	err := waitForNetworkConflicts(context.Background(), func(context.Context) error {
		calls++
		return failure
	})
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestNetworkConflictWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := waitForNetworkConflicts(ctx, func(context.Context) error {
		calls++
		cancel()
		return ErrForeignResource
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestNetworkConditionDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := waitForNetworkCondition(ctx, func() (bool, error) { return false, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("persistent state escaped deadline: %v", err)
	}
}

func TestNetworkConflictWaitPreservesPersistentConflict(t *testing.T) {
	calls := 0
	err := waitForNetworkConflicts(context.Background(), func(ctx context.Context) error {
		calls++
		if calls == 1 {
			return ErrForeignResource
		}
		// A canceled platform command may report a process error rather than ctx.Err().
		<-ctx.Done()
		return errors.New("route inspection process terminated")
	})
	if !errors.Is(err, ErrForeignResource) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("persistent conflict lost its category or deadline: %v", err)
	}
}

func TestNetworkConfigurationWaitRecovers(t *testing.T) {
	calls := 0
	err := waitForNetworkConfiguration(context.Background(), func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("inspection has no deadline")
		}
		calls++
		if calls == 1 {
			return errors.New("address is not ready")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestNetworkConfigurationWaitTimeoutPreservesCause(t *testing.T) {
	failure := errors.New("address cannot be bound")
	err := waitForNetworkConfiguration(context.Background(), func(ctx context.Context) error {
		<-ctx.Done()
		return failure
	})
	if !errors.Is(err, ErrNetworkNotReady) || !errors.Is(err, context.DeadlineExceeded) ||
		!errors.Is(err, failure) || errors.Is(err, ErrStateMismatch) {
		t.Fatalf("unexpected timeout classification: %v", err)
	}
}

func TestNetworkConfigurationWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := waitForNetworkConfiguration(ctx, func(context.Context) error {
		cancel()
		return errors.New("inspection canceled")
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrNetworkNotReady) {
		t.Fatalf("unexpected cancellation classification: %v", err)
	}
}
