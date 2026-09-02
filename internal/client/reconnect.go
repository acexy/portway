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

func (s *Service) Run(ctx context.Context) error {
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
	defer s.logger.Info("client stopped")

	reconnectDelay := initialRegistrationReconnectDelay
	var reconnectAttempt uint64
	var reconnectStartedAt time.Time
	sessionID := ""
	var disconnectedAt time.Time

	for {
		if reconnectPeriodExceeded(reconnectStartedAt, time.Now()) {
			return errReconnectPeriodExceeded
		}
		if sessionID != "" &&
			!disconnectedAt.IsZero() &&
			time.Since(disconnectedAt) >= sessionRecoveryWindow {
			s.logger.InfoWithField("client session recovery window expired", "session_id", sessionID)
			sessionID = ""
			disconnectedAt = time.Time{}
			reconnectDelay = initialRegistrationReconnectDelay
			reconnectAttempt = 0
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

		establishedSessionID, established, err := s.runControlSession(ctx, sessionID)
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
		if established {
			sessionID = establishedSessionID
			disconnectedAt = time.Now()
			reconnectDelay = initialRecoveryReconnectDelay
			reconnectAttempt = 0
			reconnectStartedAt = time.Now()
		} else if reconnectStartedAt.IsZero() {
			reconnectStartedAt = time.Now()
		}

		var sessionError *remoteSessionError
		if errors.As(err, &sessionError) {
			switch sessionError.code {
			case protocol.SessionErrorSessionExpired:
				sessionID = ""
				disconnectedAt = time.Time{}
				reconnectDelay = initialRegistrationReconnectDelay
				reconnectAttempt = 0
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
				"event":  "control_session_disconnected",
				"reason": "recoverable_error",
			},
		)

		phase := reconnectPhaseForSession(sessionID)
		reconnectAttempt++
		actualReconnectDelay := reconnectDelayWithJitter(reconnectDelay)
		actualReconnectDelay, available := boundedReconnectDelay(
			reconnectStartedAt,
			time.Now(),
			actualReconnectDelay,
		)
		if !available {
			return errReconnectPeriodExceeded
		}
		attemptLogger.TraceWithField(
			"waiting before control connection retry",
			"delay",
			actualReconnectDelay,
		)
		attemptLogger.InfoWithFields("session reconnect scheduled", map[string]any{
			"event":          "session_reconnect_scheduled",
			"retry_delay_ms": actualReconnectDelay.Milliseconds(),
			"retry_attempt":  reconnectAttempt,
			"retry_phase":    phase,
			"resume":         sessionID != "",
		})
		if !waitForRetry(ctx, actualReconnectDelay) {
			return nil
		}
		reconnectDelay = nextReconnectDelay(reconnectDelay, phase)
	}
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

func reconnectPeriodExceeded(startedAt time.Time, now time.Time) bool {
	return !startedAt.IsZero() && now.Sub(startedAt) >= maximumReconnectPeriod
}

func boundedReconnectDelay(
	startedAt time.Time,
	now time.Time,
	delay time.Duration,
) (time.Duration, bool) {
	remaining := maximumReconnectPeriod - now.Sub(startedAt)
	if remaining <= 0 {
		return 0, false
	}
	return min(delay, remaining), true
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
