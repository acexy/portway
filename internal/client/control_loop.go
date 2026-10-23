package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet/system"
)

func (s *Service) runControlLoop(
	ctx context.Context,
	connection net.Conn,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	transportSession transport.ClientSession,
	managementMode protocol.ManagementMode,
	vnetNegotiated bool,
	vnetPeerNegotiated bool,
	activeForwardManager *forwardManager,
	heartbeat *heartbeatState,
) error {
	sessionContext, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	// The reader remains available during the bounded graceful-close window
	// after the process context is canceled so it can deliver close_ack.
	readerContext, cancelReader := context.WithCancel(context.WithoutCancel(ctx))
	// Business dispatch has one bounded slot; Pong updates bypass this queue.
	messages := make(chan protocol.Envelope, 1)
	readErrors := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		readControlMessages(readerContext, connection, messages, readErrors, heartbeat)
	}()
	defer func() { cancelReader(); _ = connection.Close(); <-readerDone }()
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		if err := runHeartbeat(sessionContext, writer, heartbeat, sessionLogger); err != nil {
			select {
			case readErrors <- err:
			default:
			}
			cancelSession()
			_ = connection.Close()
		}
	}()
	defer func() { cancelSession(); <-heartbeatDone }()
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
	if !vnetNegotiated || !vnetPeerNegotiated || managementMode != protocol.ManagementModeManaged {
		s.closeVNetManager()
		s.vnetPeerRuntime.close()
	}
	var vnetManager *clientVNetManager
	if vnetNegotiated && managementMode == protocol.ManagementModeManaged {
		vnetManager = s.attachVNetManager(
			ctx, s.logger.WithComponent("vnet"), s.runtimeIdentity(),
			sessionID, writer, transportSession, s.configuration.Transport.ServerAddress,
		)
		defer vnetManager.detachSession()
	}

	var pendingManaged *pendingManagedConfiguration
	defer func() {
		if pendingManaged != nil {
			pendingManaged.close()
		}
		if activeForwardManager != nil {
			activeForwardManager.close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			cancelSession()
			<-heartbeatDone
			if pendingManaged != nil {
				pendingManaged.close()
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
		case err := <-vnetFailures(vnetManager):
			if errors.Is(err, system.ErrElevationRequired) {
				cancelSession()
				<-heartbeatDone
				if pendingManaged != nil {
					pendingManaged.close()
				}
				linkManager.close()
				s.closeControlSession(connection, messages, readErrors, sessionID, sessionLogger, writer)
			}
			return err
		case err := <-readErrors:
			return err
		case envelope, ok := <-messages:
			if !ok {
				select {
				case err := <-readErrors:
					return err
				default:
				}
				return errors.New("control message reader stopped")
			}
			switch envelope.Type {
			case protocol.MessageForwardLinkOffer:
				if activeForwardManager == nil {
					return fmt.Errorf("%w: unexpected Forward Link offer", transport.ErrProtocol)
				}
				var offer protocol.ForwardLinkOffer
				if err := protocol.DecodePayload(envelope, &offer); err != nil {
					return classifyControlProtocolError(err)
				}
				activeForwardManager.deliverOffer(offer)
			case protocol.MessageVNetAssignment:
				if vnetManager == nil {
					return fmt.Errorf("%w: unexpected VNet assignment", transport.ErrProtocol)
				}
				var assignment protocol.VNetAssignment
				if err := protocol.DecodePayload(envelope, &assignment); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.applyAssignment(assignment); err != nil {
					return err
				}
			case protocol.MessageVNetActivate:
				if vnetManager == nil {
					return fmt.Errorf("%w: unexpected VNet activation", transport.ErrProtocol)
				}
				var activation protocol.VNetActivate
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.activate(activation); err != nil {
					return err
				}
			case protocol.MessageOpenVNetChannel:
				if vnetManager == nil {
					return fmt.Errorf("%w: unexpected VNet channel offer", transport.ErrProtocol)
				}
				var offer protocol.OpenVNetChannel
				if err := protocol.DecodePayload(envelope, &offer); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.offer(offer); err != nil {
					return err
				}
			case protocol.MessageVNetDeactivate:
				if vnetManager == nil {
					return fmt.Errorf("%w: unexpected VNet deactivation", transport.ErrProtocol)
				}
				var deactivation protocol.VNetDeactivate
				if err := protocol.DecodePayload(envelope, &deactivation); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.deactivate(deactivation); err != nil {
					return err
				}
			case protocol.MessageVNetPeerOffer:
				if vnetManager == nil || !vnetPeerNegotiated {
					return fmt.Errorf("%w: unexpected VNet peer offer", transport.ErrProtocol)
				}
				var offer protocol.VNetPeerOffer
				if err := protocol.DecodePayload(envelope, &offer); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.peerOffer(offer); err != nil {
					return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
				}
			case protocol.MessageVNetPeerActivate:
				if vnetManager == nil || !vnetPeerNegotiated {
					return fmt.Errorf("%w: unexpected VNet peer activation", transport.ErrProtocol)
				}
				var activation protocol.VNetPeerActivate
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := vnetManager.peerActivate(activation); err != nil {
					return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
				}
			case protocol.MessageVNetPeerRevoke:
				if vnetManager == nil || !vnetPeerNegotiated {
					return fmt.Errorf("%w: unexpected VNet peer revocation", transport.ErrProtocol)
				}
				var revocation protocol.VNetPeerRevoke
				if err := protocol.DecodePayload(envelope, &revocation); err != nil {
					return classifyControlProtocolError(err)
				}
				vnetManager.peerRevoke(revocation)
			case protocol.MessageForwardBindingRevoked:
				if activeForwardManager == nil {
					return fmt.Errorf("%w: unexpected Forward revocation", transport.ErrProtocol)
				}
				var revocation protocol.ForwardBindingRevoked
				if err := protocol.DecodePayload(envelope, &revocation); err != nil {
					return classifyControlProtocolError(err)
				}
				activeForwardManager.revoke(revocation)
			case protocol.MessageForwardBindingActivated:
				if activeForwardManager == nil {
					return fmt.Errorf("%w: unexpected Forward activation", transport.ErrProtocol)
				}
				var activation protocol.ForwardBindingActivated
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if err := activeForwardManager.activate(activation); err != nil {
					return fmt.Errorf("activate Forward: %w", err)
				}
			case protocol.MessageCancelForwardLink:
				if activeForwardManager == nil {
					return fmt.Errorf("%w: unexpected Forward cancellation", transport.ErrProtocol)
				}
				var cancellation protocol.CancelForwardLink
				if err := protocol.DecodePayload(envelope, &cancellation); err != nil {
					return classifyControlProtocolError(err)
				}
				activeForwardManager.cancelLink(cancellation.LinkID)
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
				candidate, err := s.prepareManagedConfiguration(
					sessionContext, sessionLogger, sessionID, writer, transportSession,
					preparation, pendingManaged,
				)
				if err != nil {
					return err
				}
				pendingManaged = candidate
				if err := writer.Write(protocol.MessageManagedConfigPrepared, candidate.status); err != nil {
					return err
				}
			case protocol.MessageManagedConfigActivate:
				var activation protocol.ManagedConfigActivate
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if pendingManaged == nil {
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
				nextForwardManager, err := pendingManaged.activate(s, activeForwardManager, linkManager, activation)
				activeForwardManager = nextForwardManager
				if err != nil {
					return err
				}
				if err := writer.Write(protocol.MessageManagedConfigApplied, pendingManaged.status); err != nil {
					return err
				}
				pendingManaged = nil
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
		}
	}
}

func vnetFailures(manager *clientVNetManager) <-chan error {
	if manager == nil {
		return nil
	}
	return manager.failures
}

func (s *Service) closeControlSession(
	connection net.Conn,
	messages <-chan protocol.Envelope,
	readErrors <-chan error,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
) {
	deadline := time.Now().Add(gracefulCloseTimeout)
	if err := connection.SetDeadline(deadline); err != nil {
		sessionLogger.Error("failed to set graceful close deadline", err)
		return
	}
	if err := writer.WriteUntil(deadline, protocol.MessageCloseSession, protocol.CloseSession{
		SessionID: sessionID,
		Reason:    protocol.CloseReasonClientShutdown,
	}); err != nil {
		sessionLogger.Error("failed to send close session", err)
		return
	}
	sessionLogger.Trace("close session sent")

	envelope, err := waitCloseAcknowledgment(messages, readErrors, deadline)
	if err != nil {
		reason := "read_failed"
		if errors.Is(err, os.ErrDeadlineExceeded) {
			reason = "timeout"
		}
		sessionLogger.WarnWithFields("control session close unconfirmed", err, map[string]any{"reason": reason})
		return
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
		return
	}
	sessionLogger.Info("control session close acknowledged")
}

func waitCloseAcknowledgment(
	messages <-chan protocol.Envelope,
	readErrors <-chan error,
	deadline time.Time,
) (protocol.Envelope, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	// The sole reader publishes messages before its terminal error. Drain only
	// the current queue snapshot so unrelated traffic cannot extend the deadline.
	queuedAcknowledgment := func() (protocol.Envelope, bool) {
		for range len(messages) {
			envelope := <-messages
			if envelope.Type == protocol.MessageCloseAck {
				return envelope, true
			}
		}
		return protocol.Envelope{}, false
	}
	for {
		select {
		case envelope, ok := <-messages:
			if !ok {
				select {
				case err := <-readErrors:
					return protocol.Envelope{}, err
				default:
					return protocol.Envelope{}, io.EOF
				}
			}
			if envelope.Type == protocol.MessageCloseAck {
				return envelope, nil
			}
		case err := <-readErrors:
			if envelope, ok := queuedAcknowledgment(); ok {
				return envelope, nil
			}
			return protocol.Envelope{}, err
		case <-timer.C:
			if envelope, ok := queuedAcknowledgment(); ok {
				return envelope, nil
			}
			return protocol.Envelope{}, os.ErrDeadlineExceeded
		}
	}
}

func readControlMessages(
	ctx context.Context,
	connection net.Conn,
	messages chan<- protocol.Envelope,
	readErrors chan<- error,
	heartbeat *heartbeatState,
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
		if envelope.Type == protocol.MessagePong {
			if err := heartbeat.accept(envelope, time.Now()); err != nil {
				select {
				case readErrors <- err:
				case <-ctx.Done():
				}
				return
			}
			continue
		}
		select {
		case messages <- envelope:
		case <-ctx.Done():
			return
		}
	}
}
