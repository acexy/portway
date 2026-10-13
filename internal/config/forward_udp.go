package config

import "github.com/acexy/portway/internal/protocol"

// ForwardUDPProtocolConfig maps shared UDP limits to their Forward wire names.
func ForwardUDPProtocolConfig(configuration UDPConfig) *protocol.ForwardUDPConfig {
	return &protocol.ForwardUDPConfig{
		AssociationIdleTimeout:                configuration.AssociationIdleTimeout,
		LinkWriteTimeout:                      configuration.LinkWriteTimeout,
		MaxDatagramSize:                       configuration.MaxDatagramSize,
		MaxAssociations:                       configuration.MaxAssociations,
		MaxAssociationsPerClient:              configuration.MaxAssociationsPerClient,
		MaxAssociationsPerForward:             configuration.MaxAssociationsPerProxy,
		MaxAssociationsPerSourceIP:            configuration.MaxAssociationsPerSourceIP,
		MaxPendingAssociations:                configuration.MaxPendingAssociations,
		MaxPendingAssociationsPerClient:       configuration.MaxPendingAssociationsPerClient,
		MaxPendingAssociationsPerForward:      configuration.MaxPendingAssociationsPerProxy,
		MaxNewAssociationsPerSecond:           configuration.MaxNewAssociationsPerSecond,
		MaxNewAssociationsPerSecondPerClient:  configuration.MaxNewAssociationsPerSecondPerClient,
		MaxNewAssociationsPerSecondPerForward: configuration.MaxNewAssociationsPerSecondPerProxy,
		MaxQueuedDatagramsPerAssociation:      configuration.MaxQueuedDatagramsPerAssociation,
		MaxQueuedBytesPerAssociation:          configuration.MaxQueuedBytesPerAssociation,
		MaxQueuedBytes:                        configuration.MaxQueuedBytes,
	}
}

// ForwardUDPConfigFromProtocol maps Forward wire limits to shared runtime limits.
// Validation remains the caller's responsibility.
func ForwardUDPConfigFromProtocol(configuration protocol.ForwardUDPConfig) UDPConfig {
	return UDPConfig{
		AssociationIdleTimeout:               configuration.AssociationIdleTimeout,
		LinkWriteTimeout:                     configuration.LinkWriteTimeout,
		MaxDatagramSize:                      configuration.MaxDatagramSize,
		MaxAssociations:                      configuration.MaxAssociations,
		MaxAssociationsPerClient:             configuration.MaxAssociationsPerClient,
		MaxAssociationsPerProxy:              configuration.MaxAssociationsPerForward,
		MaxAssociationsPerSourceIP:           configuration.MaxAssociationsPerSourceIP,
		MaxPendingAssociations:               configuration.MaxPendingAssociations,
		MaxPendingAssociationsPerClient:      configuration.MaxPendingAssociationsPerClient,
		MaxPendingAssociationsPerProxy:       configuration.MaxPendingAssociationsPerForward,
		MaxNewAssociationsPerSecond:          configuration.MaxNewAssociationsPerSecond,
		MaxNewAssociationsPerSecondPerClient: configuration.MaxNewAssociationsPerSecondPerClient,
		MaxNewAssociationsPerSecondPerProxy:  configuration.MaxNewAssociationsPerSecondPerForward,
		MaxQueuedDatagramsPerAssociation:     configuration.MaxQueuedDatagramsPerAssociation,
		MaxQueuedBytesPerAssociation:         configuration.MaxQueuedBytesPerAssociation,
		MaxQueuedBytes:                       configuration.MaxQueuedBytes,
	}
}
