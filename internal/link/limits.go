package link

import "time"

const (
	pendingTimeout           = 10 * time.Second
	maxPending               = 1024
	maxPendingPerClient      = 128
	maxPendingPerProxy       = 64
	maxActive                = 4096
	maxActivePerClient       = 512
	maxActivePerProxy        = 256
)
