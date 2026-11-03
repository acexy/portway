package server

import (
	"errors"
	"time"

	"github.com/acexy/portway/internal/vnet"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
	"github.com/acexy/portway/internal/vnet/system"
	"github.com/acexy/portway/internal/vnet/userspace"
)

func (runtime *serverVNetRuntime) routeClientPacket(clientID string, packet []byte) error {
	destination, err := runtime.router.RouteClientPacket(clientID, packet, time.Now())
	if err != nil {
		if errors.Is(err, packetdata.ErrInvalidPacket) {
			return err
		}
		return nil
	}
	if destination.Kind == vnet.DestinationClient && destination.ClientID != clientID {
		runtime.offerPeer(clientID, destination.ClientID)
	}
	// Destination failure must never tear down the source pool.
	_ = runtime.dispatch(destination, packet)
	return nil
}

func (runtime *serverVNetRuntime) readDevice(device system.Device) {
	buffer := make([]byte, vnetMTU)
	for {
		length, err := device.ReadPacket(buffer)
		if err != nil {
			if runtime.context.Err() == nil {
				runtime.logger.Error("VNet device reader stopped", err)
			}
			runtime.mutex.Lock()
			var userspaceTCP *userspace.UserspaceTCP
			if runtime.device == device {
				runtime.device = nil
				userspaceTCP = runtime.userspaceTCP
				runtime.userspaceTCP = nil
			}
			runtime.mutex.Unlock()
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
			}
			_ = device.Close()
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		runtime.mutex.RLock()
		userspaceTCP := runtime.userspaceTCP
		runtime.mutex.RUnlock()
		if userspaceTCP != nil && !userspaceTCP.ObserveHostPacket(packet) {
			continue
		}
		destination, err := runtime.router.RouteServerPacket(packet, time.Now())
		if err == nil {
			_ = runtime.dispatch(destination, packet)
		}
	}
}

func (runtime *serverVNetRuntime) dispatch(destination vnet.Destination, packet []byte) error {
	if !runtime.router.IsCurrent(destination) {
		return vnet.ErrFlowRejected
	}
	if destination.Kind == vnet.DestinationServer {
		runtime.mutex.RLock()
		userspaceTCP := runtime.userspaceTCP
		runtime.mutex.RUnlock()
		if userspaceTCP != nil && userspaceTCP.Handle(packet) {
			return nil
		}
		runtime.deviceWrite.Lock()
		defer runtime.deviceWrite.Unlock()
		runtime.mutex.RLock()
		device := runtime.device
		runtime.mutex.RUnlock()
		if device == nil {
			return vnet.ErrTargetUnavailable
		}
		written, err := device.WritePacket(packet)
		if err == nil && written != len(packet) {
			err = errors.New("short VNet device write")
		}
		return err
	}
	pool, exists := runtime.broker.Active(destination.ClientID)
	if !exists {
		return vnet.ErrTargetUnavailable
	}
	return pool.Enqueue(packet, destination.ChannelIndex, func() bool {
		runtime.mutex.RLock()
		session := runtime.sessions[destination.ClientID]
		current := pool.MatchesSession(session.sessionID, session.poolGeneration)
		runtime.mutex.RUnlock()
		return current && runtime.router.IsCurrent(destination)
	})
}
