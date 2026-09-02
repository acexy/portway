package registry

import (
	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

// SyncTransaction owns a prepared Forward generation. Commit revalidates the
// observed generation under the Registry publication barrier; Rollback only
// discards the unpublished candidate. Both operations are idempotent.
type SyncTransaction struct {
	registry  *Registry
	clientID  string
	sessionID string
	next      map[string]*binding
	previous  []*binding
	results   []protocol.ForwardResult
}

// BeginSync validates and prepares a complete Forward generation without
// changing the currently published Bindings.
func (registry *Registry) BeginSync(
	clientID string,
	sessionID string,
	writer *control.Writer,
	authenticationContext authentication.Context,
	maxActiveLinks int,
	declarations []protocol.ForwardDeclaration,
) (*SyncTransaction, *protocol.ForwardError) {
	if validationError := registry.Validate(authenticationContext, declarations); validationError != nil {
		return nil, validationError
	}

	registry.mutex.Lock()
	if registry.closed {
		registry.mutex.Unlock()
		return nil, forwardError(protocol.ForwardErrorSessionInactive, "", "Forward Registry is closed")
	}

	transaction := &SyncTransaction{
		registry:  registry,
		clientID:  clientID,
		sessionID: sessionID,
		next:      make(map[string]*binding, len(declarations)),
		results:   make([]protocol.ForwardResult, 0, len(declarations)),
	}
	for _, existing := range registry.bindings {
		if existing.clientID == clientID && existing.sessionID == sessionID {
			transaction.previous = append(transaction.previous, existing)
		}
	}
	for _, declaration := range declarations {
		bindingID, err := newBindingID()
		if err != nil {
			registry.mutex.Unlock()
			transaction.registry = nil
			return nil, forwardError(
				protocol.ForwardErrorInvalidRequest,
				declaration.Name,
				"generate Forward Binding",
			)
		}
		_, active := registry.policy(authenticationContext, declaration)
		current := &binding{
			clientID: clientID, sessionID: sessionID, bindingID: bindingID,
			declaration: declaration, writer: writer,
			authentication: authenticationContext, maxActiveLinks: maxActiveLinks, active: active,
		}
		transaction.next[bindingKey(clientID, sessionID, declaration.Name)] = current
		result := protocol.ForwardResult{
			Name: declaration.Name, Type: declaration.Type, BindingID: bindingID, Active: active,
		}
		if declaration.Type == protocol.ForwardTypeUDP {
			result.UDP = protocolUDPConfig(registry.udpConfig())
		}
		transaction.results = append(transaction.results, result)
	}
	registry.mutex.Unlock()
	return transaction, nil
}

// Results returns the prepared wire results. The caller must not mutate them.
func (transaction *SyncTransaction) Results() []protocol.ForwardResult {
	if transaction == nil {
		return nil
	}
	return transaction.results
}

// Commit atomically publishes the prepared Forward generation if the observed
// Session generation and current policy still match.
func (transaction *SyncTransaction) Commit() bool {
	if transaction == nil || transaction.registry == nil {
		return false
	}
	registry := transaction.registry
	registry.mutex.Lock()
	if registry.closed || !transaction.matchesPreviousLocked() {
		transaction.registry = nil
		registry.mutex.Unlock()
		return false
	}
	for _, current := range transaction.next {
		configured, active := registry.policy(current.authentication, current.declaration)
		if !configured {
			transaction.registry = nil
			registry.mutex.Unlock()
			return false
		}
		current.active = active
	}
	for key, existing := range registry.bindings {
		if existing.clientID == transaction.clientID && existing.sessionID == transaction.sessionID {
			delete(registry.bindings, key)
		}
	}
	for key, current := range transaction.next {
		registry.bindings[key] = current
	}
	transaction.registry = nil
	registry.mutex.Unlock()
	for _, previous := range transaction.previous {
		registry.broker.CancelBinding(previous.bindingID)
	}
	return true
}

func (transaction *SyncTransaction) matchesPreviousLocked() bool {
	previous := make(map[*binding]struct{}, len(transaction.previous))
	for _, current := range transaction.previous {
		previous[current] = struct{}{}
	}
	matched := 0
	for _, current := range transaction.registry.bindings {
		if current.clientID != transaction.clientID || current.sessionID != transaction.sessionID {
			continue
		}
		if _, exists := previous[current]; !exists {
			return false
		}
		matched++
	}
	return matched == len(previous)
}

// Rollback discards the unpublished generation.
func (transaction *SyncTransaction) Rollback() {
	if transaction == nil || transaction.registry == nil {
		return
	}
	transaction.registry = nil
}
