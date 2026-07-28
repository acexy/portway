// Package lifecycle provides process lifecycle management.
package lifecycle

import (
	"context"

	"github.com/acexy/golang-toolkit/sys"
)

// Component represents a component managed by the process lifecycle.
type Component interface {
	Run(context.Context) error
}

// Run starts a component and cancels its context when an interrupt is received.
func Run(component Component) error {

	ctx, stop := sys.ShutdownContext(context.Background())
	defer stop()

	return component.Run(ctx)
}
