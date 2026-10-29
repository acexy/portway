package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

func (manager *clientVNetManager) activate(activation protocol.VNetActivate) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.device == nil || manager.assignment.State != protocol.VNetStateEnabled ||
		activation.PoolGeneration != manager.assignment.PoolGeneration ||
		activation.ConfigGeneration != manager.assignment.ConfigGeneration {
		return fmt.Errorf("%w: invalid VNet activation", transport.ErrProtocol)
	}
	manager.activated = true
	return nil
}

func (manager *clientVNetManager) offer(offer protocol.OpenVNetChannel) error {
	manager.mutex.Lock()
	assignment := manager.assignment
	if assignment.State != protocol.VNetStateEnabled || manager.device == nil || !manager.activated {
		manager.mutex.Unlock()
		return nil
	}
	if offer.PoolGeneration != assignment.PoolGeneration ||
		offer.ChannelCount != assignment.PacketChannels ||
		offer.ChannelIndex >= offer.ChannelCount || offer.ExpiresAtUnixMS <= time.Now().UnixMilli() {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: invalid VNet channel offer", transport.ErrProtocol)
	}
	if _, duplicate := manager.offers[offer.ChannelIndex]; duplicate {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: duplicate VNet channel offer", transport.ErrProtocol)
	}
	manager.offers[offer.ChannelIndex] = offer
	complete := len(manager.offers) == int(assignment.PacketChannels)
	manager.mutex.Unlock()
	if complete {
		manager.waitGroup.Go(func() { manager.openPool(assignment) })
	}
	return nil
}

func (manager *clientVNetManager) openPool(assignment protocol.VNetAssignment) {
	manager.mutex.Lock()
	sessionContext := manager.sessionContext
	if sessionContext == nil && manager.writer != nil {
		sessionContext = manager.context
	}
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || !manager.activated ||
		sessionContext == nil || manager.transport == nil {
		manager.mutex.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(sessionContext)
	manager.poolCancel = cancel
	transportSession := manager.transport
	sessionID := manager.sessionID
	offers := make(map[uint8]protocol.OpenVNetChannel, len(manager.offers))
	for index, offer := range manager.offers {
		offers[index] = offer
	}
	manager.mutex.Unlock()
	channels := make([]clientVNetChannel, int(assignment.PacketChannels))
	for index := range channels {
		offer := offers[uint8(index)]
		stream, err := transportSession.OpenDataStream(ctx)
		var stopCancel func() bool
		if err == nil {
			stopCancel = context.AfterFunc(ctx, func() { _ = stream.Close() })
			err = stream.SetDeadline(time.UnixMilli(offer.ExpiresAtUnixMS))
		}
		if err == nil {
			err = protocol.WriteControl(stream, protocol.MessageBindVNetChannel, protocol.BindVNetChannel{
				ClientID: manager.clientID, SessionID: sessionID,
				TransportGeneration: assignment.TransportGeneration, VirtualIP: assignment.ClientIP,
				PoolGeneration: offer.PoolGeneration, ChannelIndex: offer.ChannelIndex,
				ChannelCount: offer.ChannelCount, Ticket: offer.Ticket,
			})
		}
		if err == nil {
			var envelope protocol.Envelope
			envelope, err = protocol.ReadControl(stream)
			if err == nil && envelope.Type != protocol.MessageVNetBindResult {
				err = errors.New("unexpected VNet bind response")
			}
			if err == nil {
				var result protocol.VNetBindResult
				err = protocol.DecodePayload(envelope, &result)
				if err == nil && (result.Status != protocol.LinkStatusAccepted ||
					result.PoolGeneration != offer.PoolGeneration || result.ChannelIndex != offer.ChannelIndex) {
					err = errors.New("VNet channel binding was rejected")
				}
			}
		}
		if stopCancel != nil {
			stopCancel()
		}
		if err != nil {
			cancel()
			if stream != nil {
				stream.Close()
			}
			closeVNetChannels(channels)
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "channel_bind_failed")
			return
		}
		_ = stream.SetDeadline(time.Time{})
		channels[index] = clientVNetChannel{
			stream: stream,
			writer: vnet.NewPacketWriter(ctx, stream, assignment.MTU, clientVNetChannelWriteTimeout),
		}
	}
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || ctx.Err() != nil || !manager.activated || manager.device == nil {
		manager.mutex.Unlock()
		closeVNetChannels(channels)
		return
	}
	manager.channels = channels
	if !manager.recoveryStarted.IsZero() {
		manager.lastRecovery = time.Since(manager.recoveryStarted)
		manager.recoveries++
		manager.recoveryStarted = time.Time{}
	}
	device := manager.device
	manager.mutex.Unlock()
	if err := manager.reportAssignmentStatus(assignment, protocol.VNetStateActive, ""); err != nil {
		manager.failPool(assignment.PoolGeneration, vnetFailureStatusReportFailed)
		return
	}
	manager.logger.InfoWithFields("VNet is active", map[string]any{
		"event":          "vnet_active",
		"interface_name": device.Name(),
		"virtual_ip":     assignment.ClientIP,
		"cidr":           assignment.CIDR,
		"channel_count":  len(channels),
	})
	for _, channel := range channels {
		manager.waitGroup.Go(func() { manager.readChannel(device, assignment, channel.stream) })
	}
}
