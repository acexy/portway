package client

import (
	"context"
	"fmt"
	"net"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

// pendingManagedConfiguration owns candidate resources until activation succeeds.
// The control loop remains responsible for acknowledgments and session shutdown.
type pendingManagedConfiguration struct {
	proxies  []config.ProxyConfig
	forwards *forwardManager
	status   protocol.ManagedConfigStatus
}

func (s *Service) prepareManagedConfiguration(
	ctx context.Context,
	logger *logging.Logger,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
	preparation protocol.ManagedConfigPrepare,
	pending *pendingManagedConfiguration,
) (*pendingManagedConfiguration, error) {
	proxies, status, err := validateManagedPreparation(preparation)
	if err != nil {
		return nil, err
	}
	forwards, err := managedForwardConfigurations(preparation.Forwards)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		if status != pending.status {
			return nil, fmt.Errorf("%w: conflicting managed configuration rollout is pending", transport.ErrProtocol)
		}
		return pending, nil
	}
	s.managedMutex.RLock()
	currentStatus := s.managedStatus
	s.managedMutex.RUnlock()
	if status.Revision < currentStatus.Revision ||
		(status.Revision == currentStatus.Revision && status.Digest != currentStatus.Digest) {
		return nil, fmt.Errorf("%w: stale or conflicting managed configuration revision", transport.ErrProtocol)
	}
	return &pendingManagedConfiguration{
		proxies: proxies,
		forwards: newForwardManager(
			ctx, logger, s.runtimeIdentity(), sessionID, writer, transportSession, forwards,
		),
		status: status,
	}, nil
}

func (pending *pendingManagedConfiguration) activate(
	service *Service,
	current *forwardManager,
	links *linkManager,
	activation protocol.ManagedConfigActivate,
) (*forwardManager, error) {
	if activation.Revision != pending.status.Revision || activation.Digest != pending.status.Digest {
		return current, fmt.Errorf("%w: managed configuration activation mismatch", transport.ErrProtocol)
	}
	next, err := replaceManagedForwardRuntime(current, pending.forwards, activation.Forwards)
	if err != nil {
		return next, err
	}
	service.setRuntimeProxies(pending.proxies)
	links.updateProxies(pending.proxies)
	service.managedMutex.Lock()
	service.managedStatus = pending.status
	service.managedMutex.Unlock()
	// The caller now owns the active manager, including acknowledgment failures.
	pending.forwards = nil
	return next, nil
}

func (pending *pendingManagedConfiguration) close() {
	if pending.forwards != nil {
		pending.forwards.close()
		pending.forwards = nil
	}
}

func replaceManagedForwardRuntime(
	current *forwardManager,
	candidate *forwardManager,
	bindings []protocol.ForwardResult,
) (*forwardManager, error) {
	if err := candidate.applyBindings(bindings); err != nil {
		return current, fmt.Errorf("%w: %v", transport.ErrProtocol, err)
	}
	// The old listeners must release unchanged addresses before the candidate
	// generation can bind them. From this point, failures are fail-closed and
	// the control session reconnects to converge on the desired generation.
	if current != nil {
		current.close()
	}
	if err := candidate.start(); err != nil {
		candidate.close()
		return nil, err
	}
	return candidate, nil
}

func (s *Service) receiveManagedConfiguration(
	ctx context.Context,
	connection net.Conn,
	writer *control.Writer,
	clientID string,
	sessionID string,
	transportSession transport.ClientSession,
) (*forwardManager, error) {
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return nil, classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigPrepare {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigPrepare,
			envelope.Type,
		)
	}
	var preparation protocol.ManagedConfigPrepare
	if err := protocol.DecodePayload(envelope, &preparation); err != nil {
		return nil, classifyControlProtocolError(err)
	}
	proxies, status, err := validateManagedPreparation(preparation)
	if err != nil {
		return nil, err
	}
	forwards, err := managedForwardConfigurations(preparation.Forwards)
	if err != nil {
		return nil, err
	}
	forwardRuntime := newForwardManager(ctx, s.logger, clientID, sessionID, writer, transportSession, forwards)
	preparedRuntime := false
	defer func() {
		if !preparedRuntime {
			forwardRuntime.close()
		}
	}()
	if err := writer.Write(protocol.MessageManagedConfigPrepared, status); err != nil {
		return nil, err
	}
	envelope, err = protocol.ReadControl(connection)
	if err != nil {
		return nil, classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigActivate {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigActivate,
			envelope.Type,
		)
	}
	var activation protocol.ManagedConfigActivate
	if err := protocol.DecodePayload(envelope, &activation); err != nil {
		return nil, classifyControlProtocolError(err)
	}
	if activation.Revision != status.Revision || activation.Digest != status.Digest {
		return nil, fmt.Errorf("%w: managed configuration activation mismatch", transport.ErrProtocol)
	}
	if err := forwardRuntime.applyBindings(activation.Forwards); err != nil {
		return nil, fmt.Errorf("%w: %v", transport.ErrProtocol, err)
	}
	if err := forwardRuntime.start(); err != nil {
		return nil, err
	}
	s.setRuntimeProxies(proxies)
	s.managedMutex.Lock()
	s.managedStatus = status
	s.managedMutex.Unlock()
	if err := writer.Write(protocol.MessageManagedConfigApplied, status); err != nil {
		return nil, err
	}
	s.logger.InfoWithField("managed configuration applied", "revision", status.Revision)
	preparedRuntime = true
	return forwardRuntime, nil
}
func validateManagedPreparation(
	preparation protocol.ManagedConfigPrepare,
) ([]config.ProxyConfig, protocol.ManagedConfigStatus, error) {
	if preparation.Revision == 0 || preparation.Digest == "" {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: invalid managed configuration generation",
			transport.ErrProtocol,
		)
	}
	var digest string
	var err error
	if preparation.Forwards == nil {
		digest, err = protocol.ManagedConfigurationDigest(preparation.Proxies)
	} else {
		digest, err = protocol.ManagedConfigurationDigest(preparation.Proxies, preparation.Forwards)
	}
	if err != nil {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"encode managed configuration: %w",
			err,
		)
	}
	if digest != preparation.Digest {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: managed configuration digest mismatch",
			transport.ErrProtocol,
		)
	}
	proxies := coll.SliceCollect(preparation.Proxies, func(managedProxy protocol.ManagedProxy) config.ProxyConfig {
		return config.ProxyConfig{
			Name:  managedProxy.Name,
			Type:  managedProxy.Type,
			Local: config.EndpointConfig{IP: managedProxy.LocalIP, Port: managedProxy.LocalPort},
			Public: config.ProxyPublicConfig{
				Port: managedProxy.RemotePort, Domain: managedProxy.Domain,
				Schemes: append([]protocol.HTTPPublicScheme(nil), managedProxy.PublicSchemes...),
			},
		}
	})
	if proxies == nil {
		proxies = []config.ProxyConfig{}
	}
	if err := config.ValidateManagedProxies(proxies); err != nil {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: validate managed configuration: %v",
			transport.ErrProtocol,
			err,
		)
	}
	status := protocol.ManagedConfigStatus{
		Revision: preparation.Revision,
		Digest:   preparation.Digest,
	}
	return proxies, status, nil
}

func managedForwardConfigurations(forwards []protocol.ManagedForward) ([]config.ForwardConfig, error) {
	configurations := coll.SliceCollect(forwards, func(forward protocol.ManagedForward) config.ForwardConfig {
		return config.ForwardConfig{
			Name: forward.Name, Type: forward.Type,
			Listen: config.EndpointConfig{IP: forward.ListenIP, Port: forward.ListenPort},
			Target: config.EndpointConfig{IP: forward.TargetIP, Port: forward.TargetPort},
		}
	})
	if configurations == nil {
		configurations = []config.ForwardConfig{}
	}
	if err := config.ValidateManagedForwards(configurations); err != nil {
		return nil, fmt.Errorf("%w: validate managed Forward configuration: %v", transport.ErrProtocol, err)
	}
	return configurations, nil
}
