package link

import (
	"time"

	systemlimits "github.com/acexy/portway/internal/limits"
)

const (
	pendingTimeout      = 10 * time.Second
	maxPending          = 1024
	maxPendingPerClient = 128
	maxPendingPerProxy  = 64
	maxActive           = 4096
	maxActivePerClient  = systemlimits.HardMaxActiveLinksPerClient
	maxActivePerProxy   = 256
)
