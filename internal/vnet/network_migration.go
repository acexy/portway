package vnet

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// networkMigrationOperations isolates privileged effects from the rollback transaction.
type networkMigrationOperations struct {
	removeAddress func(context.Context, NetworkSpec) error
	addAddress    func(context.Context, NetworkSpec) error
	setIdentity   func(context.Context, NetworkSpec, string) error
	store         func(context.Context, NetworkSpec, string) error
}

func migrateNetworkInstallation(ctx context.Context, manifest ownershipManifest, spec NetworkSpec, operations networkMigrationOperations) (result error) {
	previous := NetworkSpec{Role: manifest.Role, CIDR: manifest.CIDR, LocalIP: manifest.LocalIP,
		ServerIP: manifest.ServerIP, MTU: manifest.MTU, OwnerUID: spec.OwnerUID}
	addressChanged := previous.CIDR != spec.CIDR || previous.LocalIP != spec.LocalIP
	if addressChanged {
		if err := operations.removeAddress(ctx, previous); err != nil {
			return fmt.Errorf("remove previous VNet address: %w", err)
		}
	}
	newAddressAdded := false
	defer func() {
		if result == nil {
			return
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var rollbackError error
		if newAddressAdded {
			rollbackError = operations.removeAddress(rollbackContext, spec)
		}
		if addressChanged {
			rollbackError = errors.Join(rollbackError, operations.addAddress(rollbackContext, previous))
		}
		rollbackError = errors.Join(rollbackError, operations.setIdentity(rollbackContext, previous, manifest.InstallationID))
		if rollbackError == nil {
			rollbackError = operations.store(rollbackContext, previous, manifest.InstallationID)
		}
		if rollbackError != nil {
			result = errors.Join(result, fmt.Errorf("restore previous VNet installation: %w", rollbackError))
		}
	}()
	if addressChanged {
		if err := operations.addAddress(ctx, spec); err != nil {
			return err
		}
		newAddressAdded = true
	}
	if err := operations.setIdentity(ctx, spec, manifest.InstallationID); err != nil {
		return err
	}
	return operations.store(ctx, spec, manifest.InstallationID)
}
