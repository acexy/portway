package client

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	transportfactory "github.com/acexy/portway/internal/transport/factory"
)

// Run runs the client until the parent context is canceled or a permanent failure occurs.
func (s *Service) Run(ctx context.Context) error {
	defer s.closeVNetManager()
	defer s.vnetPeerRuntime.close()
	identification, err := currentClientIdentification()
	if err != nil {
		return err
	}
	s.identification = identification

	transportClient, err := transportfactory.NewClient(s.configuration)
	if err != nil {
		return err
	}
	s.transport = transportClient
	s.logger.InfoWithFields("client started", map[string]any{
		"event":          "client_started",
		"server_address": s.configuration.Transport.ServerAddress,
	})
	defer s.logger.InfoWithField("client stopped", "event", "client_stopped")

	backoff := reconnectBackoff{delay: initialRegistrationReconnectDelay}
	sessionID := ""
	var disconnectedAt time.Time

	for {
		if sessionID != "" &&
			!disconnectedAt.IsZero() &&
			time.Since(disconnectedAt) >= sessionRecoveryWindow {
			s.logger.InfoWithField("client session recovery window expired", "session_id", sessionID)
			sessionID = ""
			disconnectedAt = time.Time{}
			backoff.delay = max(backoff.delay, initialRegistrationReconnectDelay)
		}
		attemptLogger := s.logger
		if sessionID != "" {
			attemptLogger = attemptLogger.WithField("session_id", sessionID)
		}
		attemptLogger.TraceWithField(
			"starting control connection attempt",
			"resume",
			sessionID != "",
		)

		var recoveryDeadline time.Time
		if !disconnectedAt.IsZero() {
			recoveryDeadline = disconnectedAt.Add(sessionRecoveryWindow)
		}
		establishedSessionID, established, stable, err := s.runControlSession(ctx, sessionID, recoveryDeadline)
		if ctx.Err() != nil {
			return nil
		}
		if transport.IsPermanent(err) {
			return err
		}
		var configurationError *configurationRegistrationError
		if errors.As(err, &configurationError) && !configurationError.retryable {
			return err
		}
		if establishedSessionID != "" {
			sessionID = establishedSessionID
			if disconnectedAt.IsZero() {
				disconnectedAt = time.Now()
			}
		}
		if established {
			disconnectedAt = time.Now()
			backoff.sessionEstablished(stable)
		}

		var sessionError *remoteSessionError
		if errors.As(err, &sessionError) {
			switch sessionError.code {
			case protocol.SessionErrorSessionExpired:
				sessionID = ""
				disconnectedAt = time.Time{}
				backoff.delay = max(backoff.delay, initialRegistrationReconnectDelay)
				continue
			case protocol.SessionErrorClientIDRecoveryPending:
			case protocol.SessionErrorResumeSessionMismatch,
				protocol.SessionErrorInvalidClientID,
				protocol.SessionErrorClientIDAlreadyOnline:
				return err
			}
			if !sessionError.retryable {
				return err
			}
		}
		attemptLogger.WarnWithFields(
			"control session disconnected; recovery scheduled",
			err,
			map[string]any{
				"event":      "control_session_disconnected",
				"stage":      controlFailureStage(established),
				"reason":     "recoverable_error",
				"error_code": controlFailureCode(err),
				"retryable":  true,
			},
		)

		phase := reconnectPhaseForSession(sessionID)
		if phase == reconnectPhaseRecovery {
			backoff.delay = min(backoff.delay, maximumRecoveryReconnectDelay)
		}
		backoff.attempt++
		actualReconnectDelay := reconnectDelayWithJitter(backoff.delay)
		if !disconnectedAt.IsZero() {
			remaining := time.Until(disconnectedAt.Add(sessionRecoveryWindow))
			actualReconnectDelay = min(actualReconnectDelay, max(remaining, 0))
		}
		attemptLogger.TraceWithField(
			"waiting before control connection retry",
			"delay",
			actualReconnectDelay,
		)
		attemptLogger.InfoWithFields("session reconnect scheduled", map[string]any{
			"event":          "session_reconnect_scheduled",
			"retry_delay_ms": actualReconnectDelay.Milliseconds(),
			"retry_attempt":  backoff.attempt,
			"retry_phase":    phase,
			"resume":         sessionID != "",
		})
		if !waitForRetry(ctx, actualReconnectDelay) {
			return nil
		}
		backoff.delay = nextReconnectDelay(backoff.delay, phase)
	}
}

func controlFailureStage(established bool) string {
	if established {
		return "control_loop"
	}
	return "session_setup"
}

func controlFailureCode(err error) string {
	var sessionError *remoteSessionError
	if errors.As(err, &sessionError) {
		return string(sessionError.code)
	}
	var configurationError *configurationRegistrationError
	if errors.As(err, &configurationError) {
		return string(configurationError.code)
	}
	if errors.Is(err, transport.ErrAuthentication) {
		return "authentication_failed"
	}
	if errors.Is(err, transport.ErrProtocol) {
		return "protocol_error"
	}
	return "transport_error"
}

func reconnectPhaseForSession(sessionID string) reconnectPhase {
	if sessionID != "" {
		return reconnectPhaseRecovery
	}
	return reconnectPhaseRegistration
}

func nextReconnectDelay(current time.Duration, phase reconnectPhase) time.Duration {
	if phase == reconnectPhaseRecovery {
		return min(current*2, maximumRecoveryReconnectDelay)
	}
	if current >= 8*time.Second && current < 15*time.Second {
		return 15 * time.Second
	}
	return min(current*2, maximumRegistrationReconnectDelay)
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func reconnectDelayWithJitter(delay time.Duration) time.Duration {
	var randomByte [1]byte
	if _, err := rand.Read(randomByte[:]); err != nil {
		return delay
	}

	jitterRange := 2*reconnectJitterPercent + 1
	jitterPercent := int(randomByte[0])%jitterRange - reconnectJitterPercent
	return delay + delay*time.Duration(jitterPercent)/100
}

// reconnectBackoff survives short sessions. Only the first established session
// or confirmed stable operation starts a new fast recovery cycle.
type reconnectBackoff struct {
	delay          time.Duration
	attempt        uint64
	hasEstablished bool
}

func (backoff *reconnectBackoff) sessionEstablished(stable bool) {
	if !backoff.hasEstablished || stable {
		backoff.delay = initialRecoveryReconnectDelay
		backoff.attempt = 0
	}
	backoff.hasEstablished = true
}
