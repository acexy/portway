package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestReconnectDelayWithJitterStaysWithinConfiguredRange(t *testing.T) {
	t.Parallel()

	baseDelay := 20 * time.Second
	minimumDelay := baseDelay * (100 - reconnectJitterPercent) / 100
	maximumDelay := baseDelay * (100 + reconnectJitterPercent) / 100

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

func TestReconnectPeriodIsBoundedToEightHours(t *testing.T) {
	startedAt := time.Unix(100, 0)
	delay, available := boundedReconnectDelay(
		startedAt,
		startedAt.Add(maximumReconnectPeriod-5*time.Second),
		maximumReconnectDelay,
	)
	if !available || delay != 5*time.Second {
		t.Fatalf("bounded delay = %s, available=%t", delay, available)
	}
	if !reconnectPeriodExceeded(
		startedAt,
		startedAt.Add(maximumReconnectPeriod),
	) {
		t.Fatal("eight-hour reconnect period did not expire")
	}
	if _, available := boundedReconnectDelay(
		startedAt,
		startedAt.Add(maximumReconnectPeriod),
		time.Second,
	); available {
		t.Fatal("delay remained available after reconnect period expired")
	}
}

func TestClassifyControlProtocolError(t *testing.T) {
	t.Parallel()

	invalidMessage := fmt.Errorf(
		"%w: unsupported control version",
		protocol.ErrInvalidControlMessage,
	)
	classified := classifyControlProtocolError(invalidMessage)
	if !errors.Is(classified, transport.ErrProtocol) {
		t.Fatalf("classified error = %v, want transport.ErrProtocol", classified)
	}

	networkError := errors.New("network unavailable")
	if classified := classifyControlProtocolError(networkError); classified != networkError {
		t.Fatalf("network error changed to %v", classified)
	}
}

func TestManagedLocalProxyConfigurationIsPermanent(t *testing.T) {
	err := transport.Permanent(errManagedLocalProxies)
	if !transport.IsPermanent(err) || !errors.Is(err, errManagedLocalProxies) {
		t.Fatalf("managed local proxy error is not permanent: %v", err)
	}
}

func TestLocalProxyRequirementsFollowAuthenticatedManagementMode(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		proxyCount int
		wantError  error
	}{
		{name: "shared empty", mode: "shared_token", wantError: errClientDeclaredProxiesRequired},
		{name: "governed empty", mode: "governed", wantError: errClientDeclaredProxiesRequired},
		{name: "shared configured", mode: "shared_token", proxyCount: 1},
		{name: "governed configured", mode: "governed", proxyCount: 1},
		{name: "managed empty", mode: "managed"},
		{name: "managed configured", mode: "managed", proxyCount: 1, wantError: errManagedLocalProxies},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateLocalProxiesForManagementMode(testCase.mode, testCase.proxyCount)
			if testCase.wantError == nil {
				if err != nil {
					t.Fatalf("valid mode configuration was rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, testCase.wantError) || !transport.IsPermanent(err) {
				t.Fatalf("error = %v, want permanent %v", err, testCase.wantError)
			}
		})
	}
}

func TestDecodeAuthenticationFailureHidesSessionDetails(t *testing.T) {
	payload, err := json.Marshal(protocol.SessionError{
		Code:      protocol.SessionErrorAuthenticationFailed,
		Message:   "credential or client identity mismatch",
		Retryable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = decodeRemoteSessionError(protocol.Envelope{
		Type:    protocol.MessageSessionError,
		Payload: payload,
	})
	if !errors.Is(err, transport.ErrAuthentication) ||
		err.Error() != "authentication failed" {
		t.Fatalf("authentication details were exposed: %v", err)
	}
}

func TestKnownSessionErrorsRejectContradictoryRetryableValue(t *testing.T) {
	testCases := []protocol.SessionError{
		{Code: protocol.SessionErrorAuthenticationFailed, Retryable: true},
		{Code: protocol.SessionErrorInvalidClientID, Retryable: true},
		{Code: protocol.SessionErrorClientIDAlreadyOnline, Retryable: true},
		{Code: protocol.SessionErrorResumeSessionMismatch, Retryable: true},
		{Code: protocol.SessionErrorClientIDRecoveryPending, Retryable: false},
		{Code: protocol.SessionErrorSessionExpired, Retryable: false},
	}
	for _, testCase := range testCases {
		if err := validateSessionErrorRetryable(testCase); !errors.Is(
			err,
			transport.ErrProtocol,
		) {
			t.Fatalf("error %q contradiction was accepted: %v", testCase.Code, err)
		}
	}
}

func TestValidateManagedPreparationVerifiesDigest(t *testing.T) {
	proxies := []protocol.ManagedProxy{}
	digest := sha256.Sum256([]byte("[]"))
	preparation := protocol.ManagedConfigPrepare{
		Revision: 1,
		Digest:   hex.EncodeToString(digest[:]),
		Proxies:  proxies,
	}
	if _, _, err := validateManagedPreparation(preparation); err != nil {
		t.Fatalf("valid managed preparation was rejected: %v", err)
	}
	preparation.Digest = hex.EncodeToString(make([]byte, sha256.Size))
	if _, _, err := validateManagedPreparation(preparation); err == nil {
		t.Fatal("managed preparation with invalid digest was accepted")
	}
}

func TestValidateManagedPreparationRejectsInvalidProxyPermanently(t *testing.T) {
	proxies := []protocol.ManagedProxy{{
		Name:      "invalid",
		Type:      protocol.ProxyTypeTCP,
		LocalIP:   "127.0.0.1",
		LocalPort: 0,
	}}
	digest, err := protocol.ManagedConfigurationDigest(proxies)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = validateManagedPreparation(protocol.ManagedConfigPrepare{
		Revision: 1,
		Digest:   digest,
		Proxies:  proxies,
	})
	if !errors.Is(err, transport.ErrProtocol) {
		t.Fatalf("invalid managed configuration was not permanent: %v", err)
	}
}

func TestRuntimeIdentityAndProxiesDoNotMutateStartupConfiguration(t *testing.T) {
	configuration := config.DefaultClient()
	configuration.ClientID = "startup-client"
	configuration.Proxies = []config.ProxyConfig{{
		Name:      "startup",
		Type:      "tcp",
		LocalIP:   "127.0.0.1",
		LocalPort: 1,
	}}
	service := NewService(logging.New("test"), configuration)
	service.setRuntimeClientID("authenticated-client")
	service.setRuntimeProxies([]config.ProxyConfig{{
		Name:      "managed",
		Type:      "tcp",
		LocalIP:   "127.0.0.1",
		LocalPort: 2,
	}})

	if service.configuration.ClientID != "startup-client" ||
		len(service.configuration.Proxies) != 1 ||
		service.configuration.Proxies[0].Name != "startup" {
		t.Fatalf("runtime state mutated startup configuration: %+v", service.configuration)
	}
	if service.runtimeIdentity() != "authenticated-client" ||
		service.runtimeProxySnapshot()[0].Name != "managed" {
		t.Fatal("runtime identity or proxy snapshot was not updated")
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
