package server

import (
	"context"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/vnet"
)

func serverNetworkSpec(configuration config.VirtualNetworkConfig) vnet.NetworkSpec {
	return vnet.NetworkSpec{
		Role: vnet.NetworkRoleServer, CIDR: configuration.CIDR,
		LocalIP: configuration.ServerIP, ServerIP: configuration.ServerIP,
		MTU: vnetMTU, OwnerUID: -1,
	}
}

func (runtime *serverVNetRuntime) migrateRuntimeDevice(
	device vnet.Device,
	previous, configuration config.VirtualNetworkConfig,
) bool {
	if !runtime.preparingDevice.CompareAndSwap(false, true) {
		return false
	}
	ctx, cancel := context.WithCancel(runtime.context)
	runtime.mutex.Lock()
	runtime.prepareCancel = cancel
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() {
		startReader := false
		defer func() {
			cancel()
			runtime.preparingDevice.Store(false)
			runtime.mutex.RLock()
			latest := runtime.configuration
			retry := runtime.context.Err() == nil && latest.Enabled && runtime.device == nil
			runtime.mutex.RUnlock()
			if retry {
				runtime.prepareRuntimeDevice(latest)
			}
		}()
		err := vnet.MigrateNetworkContext(
			ctx,
			device,
			serverNetworkSpec(previous),
			serverNetworkSpec(configuration),
		)
		if err != nil {
			runtime.logger.Warn("failed to migrate VNet network; recreating the device", err)
			_ = device.Close()
			if ctx.Err() != nil {
				return
			}
			device, err = runtime.prepareNetwork(ctx, serverNetworkSpec(configuration))
			if err != nil {
				if ctx.Err() == nil {
					runtime.logger.Warn("VNet network installation did not activate the network", err)
				}
				return
			}
			startReader = true
		}
		runtime.mutex.Lock()
		if ctx.Err() != nil || runtime.device != nil || !runtime.configuration.Enabled ||
			runtime.configuration.CIDR != configuration.CIDR ||
			runtime.configuration.ServerIP != configuration.ServerIP {
			runtime.mutex.Unlock()
			_ = device.Close()
			return
		}
		runtime.device = device
		runtime.prepareUserspaceTCPLocked(configuration)
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.Unlock()
		if startReader {
			runtime.waitGroup.Go(func() { runtime.readDevice(device) })
		}
		for index, session := range sessions {
			_ = runtime.assign(clientIDs[index], session.sessionID)
		}
	})
	return true
}

func (runtime *serverVNetRuntime) prepareRuntimeDevice(configuration config.VirtualNetworkConfig) {
	if !runtime.preparingDevice.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithCancel(runtime.context)
	runtime.mutex.Lock()
	if runtime.device != nil || !runtime.configuration.Enabled ||
		runtime.configuration.CIDR != configuration.CIDR || runtime.configuration.ServerIP != configuration.ServerIP {
		runtime.mutex.Unlock()
		cancel()
		runtime.preparingDevice.Store(false)
		return
	}
	runtime.prepareCancel = cancel
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() {
		defer func() {
			cancel()
			runtime.preparingDevice.Store(false)
			runtime.mutex.RLock()
			latest := runtime.configuration
			replaced := latest.CIDR != configuration.CIDR || latest.ServerIP != configuration.ServerIP
			retry := runtime.context.Err() == nil && latest.Enabled && runtime.device == nil && replaced
			runtime.mutex.RUnlock()
			if retry {
				runtime.prepareRuntimeDevice(latest)
			}
		}()
		device, err := runtime.prepareNetwork(ctx, serverNetworkSpec(configuration))
		if err != nil {
			if ctx.Err() == nil {
				runtime.logger.Warn("VNet network installation did not activate the network", err)
			}
			return
		}
		runtime.mutex.Lock()
		if ctx.Err() != nil || runtime.device != nil || !runtime.configuration.Enabled ||
			runtime.configuration.CIDR != configuration.CIDR ||
			runtime.configuration.ServerIP != configuration.ServerIP {
			runtime.mutex.Unlock()
			_ = device.Close()
			return
		}
		runtime.device = device
		runtime.prepareUserspaceTCPLocked(configuration)
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.Unlock()
		runtime.waitGroup.Go(func() { runtime.readDevice(device) })
		for index, session := range sessions {
			_ = runtime.assign(clientIDs[index], session.sessionID)
		}
	})
}

func (runtime *serverVNetRuntime) activateInstalledDevice(configuration config.VirtualNetworkConfig) bool {
	if runtime.preparingDevice.Load() {
		return false
	}
	runtime.mutex.RLock()
	ready := runtime.device != nil
	runtime.mutex.RUnlock()
	if ready {
		return true
	}
	status, err := vnet.InspectNetwork()
	if err != nil || !status.Installed || status.CIDR != configuration.CIDR || status.LocalIP != configuration.ServerIP {
		return false
	}
	device, err := vnet.OpenInstalledNetwork()
	if err != nil {
		return false
	}
	runtime.mutex.Lock()
	if runtime.device != nil || !runtime.configuration.Enabled {
		runtime.mutex.Unlock()
		_ = device.Close()
		return false
	}
	if runtime.configuration.CIDR != configuration.CIDR || runtime.configuration.ServerIP != configuration.ServerIP {
		runtime.mutex.Unlock()
		_ = device.Close()
		return false
	}
	runtime.device = device
	runtime.prepareUserspaceTCPLocked(configuration)
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() { runtime.readDevice(device) })
	return true
}

func (runtime *serverVNetRuntime) reconcileDevice() {
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-runtime.context.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		runtime.mutex.RLock()
		configuration := runtime.configuration
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.RUnlock()
		if configuration.Enabled && runtime.deviceReady() {
			delay = time.Second
			continue
		}
		if configuration.Enabled && runtime.activateInstalledDevice(configuration) {
			for index, session := range sessions {
				_ = runtime.assign(clientIDs[index], session.sessionID)
			}
			delay = time.Second
			continue
		}
		if configuration.Enabled && vnet.RuntimeReprepareSupported() {
			runtime.prepareRuntimeDevice(configuration)
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (runtime *serverVNetRuntime) deviceReady() bool {
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	return runtime.device != nil
}
