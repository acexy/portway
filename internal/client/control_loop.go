package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func (s *Service) runControlLoop(
	ctx context.Context,
	connection net.Conn,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	transportSession transport.ClientSession,
	managementMode protocol.ManagementMode,
	forwardRuntimes ...*forwardManager,
) error {
	var forwardRuntime *forwardManager
	if len(forwardRuntimes) != 0 {
		forwardRuntime = forwardRuntimes[0]
	}
	sessionContext, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	// The reader remains available during the bounded graceful-close window
	// after the process context is canceled so it can deliver close_ack.
	readerContext, cancelReader := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelReader()
	// Keep one decoded control message ready so a Pong that has already arrived
	// is not hidden behind reader scheduling when the watchdog checks liveness.
	messages := make(chan protocol.Envelope, 1)
	readErrors := make(chan error, 1)
	go readControlMessages(readerContext, connection, messages, readErrors)
	linkManager := newLinkManager(
		sessionContext,
		sessionLogger,
		s.runtimeIdentity(),
		s.runtimeProxySnapshot(),
		sessionID,
		writer,
		transportSession,
	)
	defer linkManager.close()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	watchdogTicker := time.NewTicker(heartbeatCheckInterval)
	defer watchdogTicker.Stop()

	lastPongAt := time.Now()
	var sentSequence uint64
	var acknowledgedSequence uint64
	var pendingManagedProxies []config.ProxyConfig
	var pendingManagedForwardRuntime *forwardManager
	var pendingManagedStatus *protocol.ManagedConfigStatus
	for {
		select {
		case <-ctx.Done():
			if pendingManagedForwardRuntime != nil {
				pendingManagedForwardRuntime.close()
			}
			linkManager.close()
			s.closeControlSession(
				connection,
				messages,
				readErrors,
				sessionID,
				sessionLogger,
				writer,
			)
			return nil
		case err := <-readErrors:
			return err
		case envelope, ok := <-messages:
			if !ok {
				return errors.New("control message reader stopped")
			}
			switch envelope.Type {
			case protocol.MessageForwardLinkOffer:
				if forwardRuntime == nil {
					return fmt.Errorf("%w: unexpected Forward Link offer", transport.ErrProtocol)
				}
				var offer protocol.ForwardLinkOffer
				if err := protocol.DecodePayload(envelope, &offer); err != nil {
					return classifyControlProtocolError(err)
				}
				forwardRuntime.deliverOffer(offer)
			case protocol.MessageForwardBindingRevoked:
				if forwardRuntime == nil {
					return fmt.Errorf("%w: unexpected Forward revocation", transport.ErrProtocol)
				}
				var revocation protocol.ForwardBindingRevoked
				if err := protocol.DecodePayload(envelope, &revocation); err != nil {
					return classifyControlProtocolError(err)
				}
				forwardRuntime.revoke(revocation)
			case protocol.MessageCancelForwardLink:
				if forwardRuntime == nil {
					return fmt.Errorf("%w: unexpected Forward cancellation", transport.ErrProtocol)
				}
				var cancellation protocol.CancelForwardLink
				if err := protocol.DecodePayload(envelope, &cancellation); err != nil {
					return classifyControlProtocolError(err)
				}
				forwardRuntime.cancelLink(cancellation.LinkID)
			case protocol.MessagePong:
				var heartbeat protocol.Heartbeat
				if err := protocol.DecodePayload(envelope, &heartbeat); err != nil {
					return classifyControlProtocolError(err)
				}
				if heartbeat.Sequence <= acknowledgedSequence || heartbeat.Sequence > sentSequence {
					return fmt.Errorf(
						"%w: unexpected heartbeat sequence %d",
						transport.ErrProtocol,
						heartbeat.Sequence,
					)
				}
				acknowledgedSequence = heartbeat.Sequence
				lastPongAt = time.Now()
				sessionLogger.TraceWithField(
					"heartbeat pong received",
					"sequence",
					heartbeat.Sequence,
				)
			case protocol.MessageSessionError:
				return decodeRemoteSessionError(envelope)
			case protocol.MessageOpenLink:
				var request protocol.OpenLink
				if err := protocol.DecodePayload(envelope, &request); err != nil {
					return classifyControlProtocolError(err)
				}
				linkManager.open(request)
				sessionLogger.WithField("link_id", request.LinkID).Trace(
					"open link received",
				)
			case protocol.MessageCancelLink:
				var cancellation protocol.CancelLink
				if err := protocol.DecodePayload(envelope, &cancellation); err != nil {
					return classifyControlProtocolError(err)
				}
				linkManager.cancelLink(cancellation.LinkID)
			case protocol.MessageManagedConfigPrepare:
				if managementMode != protocol.ManagementModeManaged {
					return fmt.Errorf(
						"%w: unmanaged session received managed configuration",
						transport.ErrProtocol,
					)
				}
				var preparation protocol.ManagedConfigPrepare
				if err := protocol.DecodePayload(envelope, &preparation); err != nil {
					return classifyControlProtocolError(err)
				}
				proxies, status, err := validateManagedPreparation(preparation)
				if err != nil {
					return err
				}
				forwards, err := managedForwardConfigurations(preparation.Forwards)
				if err != nil {
					return err
				}
				if pendingManagedStatus != nil {
					if status != *pendingManagedStatus {
						return fmt.Errorf(
							"%w: conflicting managed configuration rollout is pending",
							transport.ErrProtocol,
						)
					}
					if err := writer.Write(
						protocol.MessageManagedConfigPrepared,
						status,
					); err != nil {
						return err
					}
					continue
				}
				s.managedMutex.RLock()
				currentStatus := s.managedStatus
				s.managedMutex.RUnlock()
				if status.Revision < currentStatus.Revision ||
					(status.Revision == currentStatus.Revision &&
						status.Digest != currentStatus.Digest) {
					return fmt.Errorf(
						"%w: stale or conflicting managed configuration revision",
						transport.ErrProtocol,
					)
				}
				pendingManagedProxies = proxies
				pendingManagedForwardRuntime, err = newForwardManager(
					sessionContext, sessionLogger, s.runtimeIdentity(), sessionID,
					writer, transportSession, forwards,
				)
				if err != nil {
					return transport.Permanent(err)
				}
				pendingManagedStatus = &status
				if err := writer.Write(
					protocol.MessageManagedConfigPrepared,
					status,
				); err != nil {
					return err
				}
			case protocol.MessageManagedConfigActivate:
				var activation protocol.ManagedConfigActivate
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if pendingManagedStatus == nil {
					s.managedMutex.RLock()
					currentStatus := s.managedStatus
					s.managedMutex.RUnlock()
					if activation.Revision != currentStatus.Revision || activation.Digest != currentStatus.Digest {
						return fmt.Errorf(
							"%w: managed configuration activation has no preparation",
							transport.ErrProtocol,
						)
					}
					if err := writer.Write(
						protocol.MessageManagedConfigApplied,
						currentStatus,
					); err != nil {
						return err
					}
					continue
				}
				if activation.Revision != pendingManagedStatus.Revision || activation.Digest != pendingManagedStatus.Digest {
					return fmt.Errorf(
						"%w: managed configuration activation mismatch",
						transport.ErrProtocol,
					)
				}
				s.setRuntimeProxies(pendingManagedProxies)
				linkManager.updateProxies(pendingManagedProxies)
				if err := pendingManagedForwardRuntime.applyBindings(activation.Forwards); err != nil {
					return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
				}
				pendingManagedForwardRuntime.start()
				if forwardRuntime != nil {
					forwardRuntime.close()
				}
				forwardRuntime = pendingManagedForwardRuntime
				s.managedMutex.Lock()
				s.managedStatus = protocol.ManagedConfigStatus{Revision: activation.Revision, Digest: activation.Digest}
				s.managedMutex.Unlock()
				if err := writer.Write(
					protocol.MessageManagedConfigApplied,
					s.managedStatus,
				); err != nil {
					return err
				}
				pendingManagedProxies = nil
				pendingManagedForwardRuntime = nil
				pendingManagedStatus = nil
				sessionLogger.InfoWithField(
					"managed configuration applied",
					"revision",
					activation.Revision,
				)
			default:
				return fmt.Errorf(
					"%w: unsupported control message %q",
					transport.ErrProtocol,
					envelope.Type,
				)
			}
		case <-heartbeatTicker.C:
			if sentSequence == math.MaxUint64 {
				return errors.New("heartbeat sequence exhausted")
			}
			sentSequence++
			if err := writer.Write(protocol.MessagePing, protocol.Heartbeat{
				Sequence: sentSequence,
			}); err != nil {
				return err
			}
			sessionLogger.TraceWithField("heartbeat ping sent", "sequence", sentSequence)
		case <-watchdogTicker.C:
			if len(messages) != 0 {
				continue
			}
			if time.Since(lastPongAt) >= heartbeatTimeout {
				return fmt.Errorf(
					"server heartbeat timed out after %s",
					heartbeatTimeout,
				)
			}
		}
	}
}
func (s *Service) closeControlSession(
	connection net.Conn,
	messages <-chan protocol.Envelope,
	readErrors <-chan error,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
) {
	if err := connection.SetDeadline(time.Now().Add(gracefulCloseTimeout)); err != nil {
		sessionLogger.Error("failed to set graceful close deadline", err)
		return
	}
	if err := writer.Write(protocol.MessageCloseSession, protocol.CloseSession{
		SessionID: sessionID,
		Reason:    protocol.CloseReasonClientShutdown,
	}); err != nil {
		sessionLogger.Error("failed to send close session", err)
		return
	}
	sessionLogger.Trace("close session sent")

	timer := time.NewTimer(gracefulCloseTimeout)
	defer timer.Stop()
	for {
		select {
		case envelope, ok := <-messages:
			if !ok {
				return
			}
			if envelope.Type != protocol.MessageCloseAck {
				continue
			}
			var acknowledgment protocol.CloseAck
			if err := protocol.DecodePayload(envelope, &acknowledgment); err != nil {
				sessionLogger.Error("failed to decode close acknowledgment", err)
				return
			}
			if acknowledgment.SessionID != sessionID {
				sessionLogger.Error(
					"close acknowledgment contained an unexpected session ID",
					errors.New("session ID mismatch"),
				)
			}
			sessionLogger.Trace("close acknowledgment received")
			return
		case <-readErrors:
			return
		case <-timer.C:
			return
		}
	}
}

func readControlMessages(
	ctx context.Context,
	connection net.Conn,
	messages chan<- protocol.Envelope,
	readErrors chan<- error,
) {
	defer close(messages)

	for {
		envelope, err := protocol.ReadControl(connection)
		if err != nil {
			select {
			case readErrors <- classifyControlProtocolError(err):
			case <-ctx.Done():
			}
			return
		}
		select {
		case messages <- envelope:
		case <-ctx.Done():
			return
		}
	}
}
