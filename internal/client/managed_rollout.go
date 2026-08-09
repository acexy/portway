package client

import (
	"fmt"
	"net"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func (s *Service) receiveManagedConfiguration(
	connection net.Conn,
	writer *control.Writer,
) error {
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigPrepare {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigPrepare,
			envelope.Type,
		)
	}
	var preparation protocol.ManagedConfigPrepare
	if err := protocol.DecodePayload(envelope, &preparation); err != nil {
		return classifyControlProtocolError(err)
	}
	proxies, status, err := validateManagedPreparation(preparation)
	if err != nil {
		return err
	}
	if err := writer.Write(protocol.MessageManagedConfigPrepared, status); err != nil {
		return err
	}
	envelope, err = protocol.ReadControl(connection)
	if err != nil {
		return classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigActivate {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigActivate,
			envelope.Type,
		)
	}
	var activation protocol.ManagedConfigStatus
	if err := protocol.DecodePayload(envelope, &activation); err != nil {
		return classifyControlProtocolError(err)
	}
	if activation != status {
		return fmt.Errorf("%w: managed configuration activation mismatch", transport.ErrProtocol)
	}
	s.setRuntimeProxies(proxies)
	s.managedMutex.Lock()
	s.managedStatus = status
	s.managedMutex.Unlock()
	if err := writer.Write(protocol.MessageManagedConfigApplied, status); err != nil {
		return err
	}
	s.logger.InfoWithField("managed configuration applied", "revision", status.Revision)
	return nil
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
	digest, err := protocol.ManagedConfigurationDigest(preparation.Proxies)
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
	proxies := make([]config.ProxyConfig, 0, len(preparation.Proxies))
	for _, managedProxy := range preparation.Proxies {
		proxies = append(proxies, config.ProxyConfig{
			Name:       managedProxy.Name,
			Type:       managedProxy.Type,
			LocalIP:    managedProxy.LocalIP,
			LocalPort:  managedProxy.LocalPort,
			RemotePort: managedProxy.RemotePort,
			Domain:     managedProxy.Domain,
			PublicSchemes: append(
				[]protocol.HTTPPublicScheme(nil),
				managedProxy.PublicSchemes...,
			),
		})
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
