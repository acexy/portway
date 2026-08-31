package registry

import (
	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

// SyncTransaction owns a prepared Forward generation while holding the
// Registry publication barrier. Commit and Rollback are idempotent.
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
	return transaction, nil
}

// Results returns the prepared wire results. The caller must not mutate them.
func (transaction *SyncTransaction) Results() []protocol.ForwardResult {
	if transaction == nil {
		return nil
	}
	return transaction.results
}

// Commit atomically publishes the prepared Forward generation.
func (transaction *SyncTransaction) Commit() {
	if transaction == nil || transaction.registry == nil {
		return
	}
	registry := transaction.registry
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
}

// Rollback discards the prepared generation and releases the publication barrier.
func (transaction *SyncTransaction) Rollback() {
	if transaction == nil || transaction.registry == nil {
		return
	}
	registry := transaction.registry
	transaction.registry = nil
	registry.mutex.Unlock()
}
