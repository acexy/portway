package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet/system"
	"github.com/acexy/portway/internal/vnet/userspace"
)

func (manager *clientVNetManager) prepareDevice(ctx context.Context, assignment protocol.VNetAssignment) {
	preparedDevice, err := manager.prepareNetwork(ctx, clientNetworkSpec(assignment))
	if ctx.Err() != nil {
		if preparedDevice != nil {
			_ = preparedDevice.Close()
		}
		return
	}
	if err != nil {
		if errors.Is(err, system.ErrElevationRequired) {
			// Return to the CLI only after runtime cleanup; UAC must not run
			// while an unprivileged copy still owns the control session.
			select {
			case manager.failures <- transport.Permanent(err):
			default:
			}
			return
		}
		if errors.Is(err, system.ErrNetworkNotReady) {
			manager.logger.WarnWithFields("VNet network is not ready; requesting assignment retry", err, map[string]any{
				"event": "vnet_network_not_ready", "vnet_cidr": assignment.CIDR,
			})
			// Failed status reuses server-coordinated recovery without terminating
			// the control session or misreporting a permanent network conflict.
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "device_unavailable")
			return
		}
		if errors.Is(err, system.ErrForeignResource) || errors.Is(err, system.ErrStateMismatch) {
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "network_conflict")
			if !manager.exitOnConflict {
				manager.logger.WarnWithFields("VNet network conflicts with existing resources", err, map[string]any{
					"event": "vnet_network_conflict", "vnet_cidr": assignment.CIDR,
				})
			}
			if manager.exitOnConflict {
				manager.logger.WarnWithFields(
					"VNet network conflict requires operator action; client is exiting. Stop other Portway processes, run 'portway vnetwork uninstall' as administrator, resolve any address or route overlap with the assigned VNet CIDR, then restart the client",
					err,
					map[string]any{
						"event":     "vnet_network_conflict",
						"vnet_cidr": assignment.CIDR,
					},
				)
				select {
				case manager.failures <- transport.Permanent(fmt.Errorf("Windows VNet network conflict: %w", err)):
				default:
				}
			}
			return
		}
		manager.logger.WarnWithFields("VNet network installation is required", err, map[string]any{
			"event": "vnet_installation_required",
		})
		_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateInstallationRequired, "device_unavailable")
		return
	}
	manager.activatePreparedDevice(ctx, assignment, preparedDevice, true)
}

func clientNetworkSpec(assignment protocol.VNetAssignment) system.NetworkSpec {
	return system.NetworkSpec{
		Role: system.NetworkRoleClient, CIDR: assignment.CIDR, LocalIP: assignment.ClientIP,
		ServerIP: assignment.ServerIP, MTU: assignment.MTU, OwnerUID: -1,
	}
}

func (manager *clientVNetManager) activatePreparedDevice(
	ctx context.Context,
	assignment protocol.VNetAssignment,
	device system.Device,
	startReader bool,
) {
	var userspaceTCP *userspace.UserspaceTCP
	if assignment.NetworkMode == protocol.VNetNetworkModeLoopback {
		prefix, _ := netip.ParsePrefix(assignment.CIDR)
		var userspaceError error
		userspaceTCP, userspaceError = userspace.NewUserspaceTCP(
			manager.context, netip.MustParseAddr(assignment.ClientIP), prefix.Bits(), assignment.MTU,
			manager.sendUserspaceTCPPacket,
		)
		if userspaceError != nil {
			_ = device.Close()
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "userspace_stack_unavailable")
			return
		}
	}
	manager.mutex.Lock()
	if ctx.Err() != nil || manager.assignment.PoolGeneration != assignment.PoolGeneration {
		manager.mutex.Unlock()
		if userspaceTCP != nil {
			_ = userspaceTCP.Close()
		}
		_ = device.Close()
		return
	}
	manager.device = device
	manager.migratingDevice = nil
	manager.userspaceTCP = userspaceTCP
	if startReader {
		manager.waitGroup.Go(func() { manager.readDevice(device, assignment) })
	}
	manager.mutex.Unlock()
	manager.logger.DebugWithFields("VNet network is ready", map[string]any{
		"event":          "vnet_network_ready",
		"interface_name": device.Name(),
		"virtual_ip":     assignment.ClientIP,
		"cidr":           assignment.CIDR,
	})
	_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateReady, "")
}
