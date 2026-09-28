package client

import (
	"errors"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func (manager *clientVNetManager) preparePeerEndpoint(assignment protocol.VNetAssignment) error {
	manager.mutex.Lock()
	existing := manager.peerEndpoint
	previous := manager.assignment
	var stale *vnet.PeerEndpoint
	if existing != nil && (previous.ClientIP != assignment.ClientIP || previous.MTU != assignment.MTU) {
		stale = existing
		manager.peerEndpoint = nil
		existing = nil
	}
	manager.mutex.Unlock()
	if stale != nil {
		_ = stale.Close()
	}
	if existing == nil {
		bindAddress, err := vnet.PeerUDPAddress(manager.serverAddress, true)
		if err != nil {
			return err
		}
		newEndpoint := vnet.NewPeerEndpoint
		if manager.peerRuntime != nil {
			newEndpoint = manager.peerRuntime.newEndpoint
		}
		manager.mutex.Lock()
		sessionContext, sessionID := manager.sessionContext, manager.sessionID
		if sessionContext == nil && manager.writer != nil {
			sessionContext = manager.context
		}
		manager.mutex.Unlock()
		if sessionContext == nil {
			return errors.New("VNet control session is unavailable")
		}
		endpoint, err := newEndpoint(
			sessionContext, bindAddress, manager.clientID, sessionID,
			assignment.ClientIP, assignment.MTU,
			func(status protocol.VNetPeerStatus) error {
				return manager.writePeerControl(protocol.MessageVNetPeerStatus, status)
			},
			manager.deliverPeerPacket,
		)
		if err != nil {
			return err
		}
		endpoint.SetFlowOpener(func(generation uint64, peerClientID string, flow vnet.Flow) error {
			return manager.writePeerControl(protocol.MessageVNetPeerFlowOpen, protocol.VNetPeerFlowOpen{
				PeerGeneration: generation, PeerClientID: peerClientID, Protocol: flow.Protocol,
				SourceIP: flow.SourceIP.String(), SourcePort: flow.SourcePort,
				DestinationIP: flow.DestinationIP.String(), DestinationPort: flow.DestinationPort,
				TCPFlags: flow.TCPFlags,
			})
		})
		manager.mutex.Lock()
		if manager.peerEndpoint == nil {
			manager.peerEndpoint = endpoint
			existing = endpoint
		} else {
			existing = manager.peerEndpoint
		}
		manager.mutex.Unlock()
		if existing != endpoint {
			_ = endpoint.Close()
		}
	}
	serverAddress, err := vnet.PeerUDPAddress(manager.serverAddress, false)
	if err != nil {
		return err
	}
	if err := existing.Register(serverAddress, assignment.PeerRegistrationTicket); err != nil {
		manager.logger.WarnWithFields("VNet P2P registration could not be sent; relay remains active", err, map[string]any{
			"event": "vnet_p2p_registration_failed",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerOffer(offer protocol.VNetPeerOffer) error {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint == nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: offer.PeerGeneration, PeerClientID: offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "peer_unavailable",
		})
	}
	if err := endpoint.ApplyOffer(offer); err != nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: offer.PeerGeneration, PeerClientID: offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "offer_rejected",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerActivate(activation protocol.VNetPeerActivate) error {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint == nil {
		return nil
	}
	if err := endpoint.Activate(activation); err != nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: activation.PeerGeneration, PeerClientID: activation.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "activation_unavailable",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerRevoke(revocation protocol.VNetPeerRevoke) {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint != nil {
		endpoint.Revoke(revocation)
	}
}

func (manager *clientVNetManager) deliverPeerPacket(packet []byte) error {
	manager.mutex.Lock()
	device := manager.device
	userspaceTCP := manager.userspaceTCP
	manager.mutex.Unlock()
	if device == nil {
		return errors.New("VNet device is unavailable")
	}
	if userspaceTCP != nil && userspaceTCP.Handle(packet) {
		return nil
	}
	manager.deviceWrite.Lock()
	written, err := device.WritePacket(packet)
	manager.deviceWrite.Unlock()
	if err == nil && written != len(packet) {
		return errors.New("short VNet peer device write")
	}
	return err
}

// Peer control work must not indefinitely block device or datagram readers.
func (manager *clientVNetManager) writePeerControl(message protocol.MessageType, payload any) error {
	manager.mutex.Lock()
	writer := manager.writer
	manager.mutex.Unlock()
	if writer == nil {
		return errors.New("VNet control session is unavailable")
	}
	err := writer.WriteUntil(time.Now().Add(clientVNetChannelWriteTimeout), message, payload)
	if err != nil {
		_ = writer.Close()
	}
	return err
}
