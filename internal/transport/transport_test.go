package transport

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsPermanent(t *testing.T) {
	t.Parallel()

	networkError := errors.New("network unavailable")
	testCases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{name: "authentication", err: ErrAuthentication, permanent: true},
		{name: "protocol", err: ErrProtocol, permanent: true},
		{
			name:      "implementation specific",
			err:       Permanent(networkError),
			permanent: true,
		},
		{
			name:      "wrapped protocol",
			err:       fmt.Errorf("connect: %w", ErrProtocol),
			permanent: true,
		},
		{name: "network", err: networkError, permanent: false},
		{name: "nil", err: nil, permanent: false},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if actual := IsPermanent(testCase.err); actual != testCase.permanent {
				t.Fatalf(
					"IsPermanent(%v) = %t, want %t",
					testCase.err,
					actual,
					testCase.permanent,
				)
			}
		})
	}
}

func TestPermanentPreservesCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("certificate rejected")
	err := Permanent(cause)
	if !errors.Is(err, ErrPermanent) {
		t.Fatal("Permanent() result does not contain ErrPermanent")
	}
	if !errors.Is(err, cause) {
		t.Fatal("Permanent() result does not preserve its cause")
	}
}
