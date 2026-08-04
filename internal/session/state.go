package session

type state string

const (
	stateInitializing state = "initializing"
	stateActive    state = "active"
	stateSuspended state = "suspended"
)
