package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func (s *Service) applyManagedConfiguration(
	ctx context.Context,
	connection net.Conn,
	clientID string,
	sessionID string,
	writer *control.Writer,
	clientConfiguration config.ManagedClientConfig,
	authenticationContext authentication.Context,
) error {
	preparation, declarations, err := managedConfigurationPayload(clientConfiguration)
	if err != nil {
		return fmt.Errorf("build managed configuration: %w", err)
	}
	return s.applyManagedGeneration(
		ctx,
		clientID,
		sessionID,
		preparation,
		declarations,
		authenticationContext,
		initialManagedExchange{connection: connection, writer: writer},
		false,
	)
}

func expectManagedStatus(
	connection net.Conn,
	messageType protocol.MessageType,
	expected protocol.ManagedConfigStatus,
) error {
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	if envelope.Type != messageType {
		return fmt.Errorf("expected %s, got %s", messageType, envelope.Type)
	}
	var actual protocol.ManagedConfigStatus
	if err := protocol.DecodePayload(envelope, &actual); err != nil {
		return err
	}
	if actual != expected {
		return errors.New("managed configuration status does not match")
	}
	return nil
}

func (s *Service) registerManagedSession(
	clientID string,
	sessionID string,
	connection net.Conn,
	writer *control.Writer,
	authenticationContexts ...authentication.Context,
) {
	authenticationContext := authentication.Context{Mode: authentication.ModeManaged, ClientID: clientID}
	if len(authenticationContexts) != 0 {
		authenticationContext = authenticationContexts[0]
	}
	s.managed.register(clientID, &managedSession{
		sessionID:      sessionID,
		connection:     connection,
		writer:         writer,
		prepared:       make(chan protocol.ManagedConfigStatus, 1),
		applied:        make(chan protocol.ManagedConfigStatus, 1),
		authentication: authenticationContext,
	})
}

func (s *Service) unregisterManagedSession(clientID string, sessionID string) {
	s.managed.unregister(clientID, sessionID)
}

func (s *Service) publishManagedStatus(
	clientID string,
	sessionID string,
	messageType protocol.MessageType,
	status protocol.ManagedConfigStatus,
) bool {
	return s.managed.publish(clientID, sessionID, messageType, status)
}

func managedConfigurationPayload(
	clientConfiguration config.ManagedClientConfig,
) (protocol.ManagedConfigPrepare, protocol.SyncConfiguration, error) {
	managedProxies := coll.SliceCollect(clientConfiguration.Configuration.Proxies, func(proxyConfiguration config.ProxyConfig) protocol.ManagedProxy {
		return protocol.ManagedProxy{
			Name:       proxyConfiguration.Name,
			Type:       proxyConfiguration.Type,
			LocalIP:    proxyConfiguration.Local.IP,
			LocalPort:  proxyConfiguration.Local.Port,
			RemotePort: proxyConfiguration.Public.Port,
			Domain:     proxyConfiguration.Public.Domain,
			PublicSchemes: append(
				[]protocol.HTTPPublicScheme(nil),
				proxyConfiguration.Public.Schemes...,
			),
		}
	})
	declarations := coll.SliceCollect(clientConfiguration.Configuration.Proxies, func(proxyConfiguration config.ProxyConfig) protocol.ProxyDeclaration {
		return protocol.ProxyDeclaration{
			Name:       proxyConfiguration.Name,
			Type:       proxyConfiguration.Type,
			RemotePort: proxyConfiguration.Public.Port,
			Domain:     proxyConfiguration.Public.Domain,
			PublicSchemes: append(
				[]protocol.HTTPPublicScheme(nil),
				proxyConfiguration.Public.Schemes...,
			),
		}
	})
	managedForwards := coll.SliceCollect(clientConfiguration.Configuration.Forwards, func(forward config.ForwardConfig) protocol.ManagedForward {
		return protocol.ManagedForward{
			Name: forward.Name, Type: forward.Type,
			ListenIP: forward.Listen.IP, ListenPort: forward.Listen.Port,
			TargetIP: forward.Target.IP, TargetPort: forward.Target.Port,
		}
	})
	forwardDeclarations := coll.SliceCollect(clientConfiguration.Configuration.Forwards, func(forward config.ForwardConfig) protocol.ForwardDeclaration {
		return protocol.ForwardDeclaration{Name: forward.Name, Type: forward.Type,
			TargetIP: forward.Target.IP, TargetPort: forward.Target.Port}
	})
	if managedProxies == nil {
		managedProxies = []protocol.ManagedProxy{}
		declarations = []protocol.ProxyDeclaration{}
	}
	if managedForwards == nil {
		managedForwards = []protocol.ManagedForward{}
		forwardDeclarations = []protocol.ForwardDeclaration{}
	}
	digest, err := protocol.ManagedConfigurationDigest(managedProxies, managedForwards)
	if err != nil {
		return protocol.ManagedConfigPrepare{}, protocol.SyncConfiguration{}, err
	}
	return protocol.ManagedConfigPrepare{
			Revision: clientConfiguration.Configuration.Revision,
			Digest:   digest,
			Proxies:  managedProxies,
			Forwards: managedForwards,
		}, protocol.SyncConfiguration{
			Revision: clientConfiguration.Configuration.Revision,
			Proxies:  declarations,
			Forwards: forwardDeclarations,
		}, nil
}

func (s *Service) rolloutManagedConfiguration(
	ctx context.Context,
	clientID string,
	configuration config.ManagedClientConfig,
) error {
	current := s.managed.get(clientID)
	if current == nil {
		return nil
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()

	preparation, declarations, err := managedConfigurationPayload(configuration)
	if err != nil {
		return fmt.Errorf("build managed rollout: %w", err)
	}
	rolloutContext, cancel := context.WithTimeout(ctx, managedRolloutTimeout)
	defer cancel()
	return s.applyManagedGeneration(
		rolloutContext,
		clientID,
		current.sessionID,
		preparation,
		declarations,
		current.authentication,
		onlineManagedExchange{session: current},
		true,
	)
}

func drainManagedStatus(statuses chan protocol.ManagedConfigStatus) {
	for {
		select {
		case <-statuses:
		default:
			return
		}
	}
}
func waitManagedStatus(
	ctx context.Context,
	statuses <-chan protocol.ManagedConfigStatus,
	expected protocol.ManagedConfigStatus,
) error {
	select {
	case actual := <-statuses:
		if actual != expected {
			return errors.New("managed configuration status does not match")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
