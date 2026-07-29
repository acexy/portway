package session

type state string

const (
	stateActive    state = "active"
	stateSuspended state = "suspended"
)
