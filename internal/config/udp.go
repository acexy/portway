package config

import (
	"errors"
	"fmt"
	"reflect"
	"time"
)

// EffectiveForwardUDPConfig supplies defaults for programmatic Forward configurations.
func EffectiveForwardUDPConfig(configuration ForwardServerConfig) UDPConfig {
	if reflect.DeepEqual(configuration.UDP, UDPConfig{}) {
		return DefaultUDPConfig()
	}
	return configuration.UDP
}

const (
	udpDefaultAssociationIdleTimeout               = 60 * time.Second
	udpDefaultLinkWriteTimeout                     = 3 * time.Second
	udpDefaultMaxDatagramSize                      = 8 * 1024
	udpDefaultMaxAssociations                      = 4096
	udpDefaultMaxAssociationsPerClient             = 512
	udpDefaultMaxAssociationsPerProxy              = 256
	udpDefaultMaxAssociationsPerSourceIP           = 64
	udpDefaultMaxPendingAssociations               = 1024
	udpDefaultMaxPendingAssociationsPerClient      = 128
	udpDefaultMaxPendingAssociationsPerProxy       = 64
	udpDefaultMaxNewAssociationsPerSecond          = 1000
	udpDefaultMaxNewAssociationsPerSecondPerClient = 200
	udpDefaultMaxNewAssociationsPerSecondPerProxy  = 100
	udpDefaultMaxQueuedDatagramsPerAssociation     = 32
	udpDefaultMaxQueuedBytesPerAssociation         = 256 * 1024
	udpDefaultMaxQueuedBytes                       = 64 * 1024 * 1024

	udpMinAssociationIdleTimeout                = 5 * time.Second
	udpMaxAssociationIdleTimeout                = 10 * time.Minute
	udpMinLinkWriteTimeout                      = 100 * time.Millisecond
	udpMaxLinkWriteTimeout                      = 30 * time.Second
	udpHardMaxDatagramSize                      = 65507
	udpHardMaxAssociations                      = 4096
	udpHardMaxAssociationsPerClient             = 512
	udpHardMaxAssociationsPerProxy              = 256
	udpHardMaxAssociationsPerSourceIP           = 1024
	udpHardMaxPendingAssociations               = 1024
	udpHardMaxPendingAssociationsPerClient      = 128
	udpHardMaxPendingAssociationsPerProxy       = 64
	udpHardMaxNewAssociationsPerSecond          = 10000
	udpHardMaxNewAssociationsPerSecondPerClient = 2000
	udpHardMaxNewAssociationsPerSecondPerProxy  = 1000
	udpHardMaxQueuedDatagramsPerAssociation     = 256
	udpHardMaxQueuedBytesPerAssociation         = 4 * 1024 * 1024
	udpHardMaxQueuedBytes                       = 512 * 1024 * 1024
)

// UDPConfig configures bounded server-side UDP proxy resources.
type UDPConfig struct {
	AssociationIdleTimeout               time.Duration `yaml:"association_idle_timeout"`
	LinkWriteTimeout                     time.Duration `yaml:"link_write_timeout"`
	MaxDatagramSize                      int           `yaml:"max_datagram_size"`
	MaxAssociations                      int           `yaml:"max_associations"`
	MaxAssociationsPerClient             int           `yaml:"max_associations_per_client"`
	MaxAssociationsPerProxy              int           `yaml:"max_associations_per_proxy"`
	MaxAssociationsPerSourceIP           int           `yaml:"max_associations_per_source_ip"`
	MaxPendingAssociations               int           `yaml:"max_pending_associations"`
	MaxPendingAssociationsPerClient      int           `yaml:"max_pending_associations_per_client"`
	MaxPendingAssociationsPerProxy       int           `yaml:"max_pending_associations_per_proxy"`
	MaxNewAssociationsPerSecond          int           `yaml:"max_new_associations_per_second"`
	MaxNewAssociationsPerSecondPerClient int           `yaml:"max_new_associations_per_second_per_client"`
	MaxNewAssociationsPerSecondPerProxy  int           `yaml:"max_new_associations_per_second_per_proxy"`
	MaxQueuedDatagramsPerAssociation     int           `yaml:"max_queued_datagrams_per_association"`
	MaxQueuedBytesPerAssociation         int           `yaml:"max_queued_bytes_per_association"`
	MaxQueuedBytes                       int           `yaml:"max_queued_bytes"`
}

// DefaultUDPConfig returns production-safe UDP resource defaults.
func DefaultUDPConfig() UDPConfig {
	return UDPConfig{
		AssociationIdleTimeout:               udpDefaultAssociationIdleTimeout,
		LinkWriteTimeout:                     udpDefaultLinkWriteTimeout,
		MaxDatagramSize:                      udpDefaultMaxDatagramSize,
		MaxAssociations:                      udpDefaultMaxAssociations,
		MaxAssociationsPerClient:             udpDefaultMaxAssociationsPerClient,
		MaxAssociationsPerProxy:              udpDefaultMaxAssociationsPerProxy,
		MaxAssociationsPerSourceIP:           udpDefaultMaxAssociationsPerSourceIP,
		MaxPendingAssociations:               udpDefaultMaxPendingAssociations,
		MaxPendingAssociationsPerClient:      udpDefaultMaxPendingAssociationsPerClient,
		MaxPendingAssociationsPerProxy:       udpDefaultMaxPendingAssociationsPerProxy,
		MaxNewAssociationsPerSecond:          udpDefaultMaxNewAssociationsPerSecond,
		MaxNewAssociationsPerSecondPerClient: udpDefaultMaxNewAssociationsPerSecondPerClient,
		MaxNewAssociationsPerSecondPerProxy:  udpDefaultMaxNewAssociationsPerSecondPerProxy,
		MaxQueuedDatagramsPerAssociation:     udpDefaultMaxQueuedDatagramsPerAssociation,
		MaxQueuedBytesPerAssociation:         udpDefaultMaxQueuedBytesPerAssociation,
		MaxQueuedBytes:                       udpDefaultMaxQueuedBytes,
	}
}

func validateUDPConfig(configuration UDPConfig) error {
	if configuration.AssociationIdleTimeout < udpMinAssociationIdleTimeout ||
		configuration.AssociationIdleTimeout > udpMaxAssociationIdleTimeout {
		return fmt.Errorf(
			"udp.association_idle_timeout must be between %s and %s",
			udpMinAssociationIdleTimeout,
			udpMaxAssociationIdleTimeout,
		)
	}
	if configuration.LinkWriteTimeout < udpMinLinkWriteTimeout ||
		configuration.LinkWriteTimeout > udpMaxLinkWriteTimeout {
		return fmt.Errorf(
			"udp.link_write_timeout must be between %s and %s",
			udpMinLinkWriteTimeout,
			udpMaxLinkWriteTimeout,
		)
	}
	limits := []struct {
		name  string
		value int
		min   int
		max   int
	}{
		{"max_datagram_size", configuration.MaxDatagramSize, 1, udpHardMaxDatagramSize},
		{"max_associations", configuration.MaxAssociations, 1, udpHardMaxAssociations},
		{"max_associations_per_client", configuration.MaxAssociationsPerClient, 1, udpHardMaxAssociationsPerClient},
		{"max_associations_per_proxy", configuration.MaxAssociationsPerProxy, 1, udpHardMaxAssociationsPerProxy},
		{"max_associations_per_source_ip", configuration.MaxAssociationsPerSourceIP, 1, udpHardMaxAssociationsPerSourceIP},
		{"max_pending_associations", configuration.MaxPendingAssociations, 1, udpHardMaxPendingAssociations},
		{"max_pending_associations_per_client", configuration.MaxPendingAssociationsPerClient, 1, udpHardMaxPendingAssociationsPerClient},
		{"max_pending_associations_per_proxy", configuration.MaxPendingAssociationsPerProxy, 1, udpHardMaxPendingAssociationsPerProxy},
		{"max_new_associations_per_second", configuration.MaxNewAssociationsPerSecond, 1, udpHardMaxNewAssociationsPerSecond},
		{"max_new_associations_per_second_per_client", configuration.MaxNewAssociationsPerSecondPerClient, 1, udpHardMaxNewAssociationsPerSecondPerClient},
		{"max_new_associations_per_second_per_proxy", configuration.MaxNewAssociationsPerSecondPerProxy, 1, udpHardMaxNewAssociationsPerSecondPerProxy},
		{"max_queued_datagrams_per_association", configuration.MaxQueuedDatagramsPerAssociation, 1, udpHardMaxQueuedDatagramsPerAssociation},
		{"max_queued_bytes_per_association", configuration.MaxQueuedBytesPerAssociation, udpHardMaxDatagramSize, udpHardMaxQueuedBytesPerAssociation},
		{"max_queued_bytes", configuration.MaxQueuedBytes, udpHardMaxDatagramSize, udpHardMaxQueuedBytes},
	}
	for _, limit := range limits {
		if limit.value < limit.min || limit.value > limit.max {
			return fmt.Errorf(
				"udp.%s must be between %d and %d",
				limit.name,
				limit.min,
				limit.max,
			)
		}
	}
	platformMaximum, err := platformUDPMaxDatagramSize()
	if err != nil {
		return fmt.Errorf("determine platform UDP datagram limit: %w", err)
	}
	if configuration.MaxDatagramSize > platformMaximum {
		return fmt.Errorf(
			"udp.max_datagram_size %d exceeds platform UDP datagram limit %d",
			configuration.MaxDatagramSize,
			platformMaximum,
		)
	}
	if configuration.MaxAssociationsPerClient > configuration.MaxAssociations ||
		configuration.MaxAssociationsPerProxy > configuration.MaxAssociations ||
		configuration.MaxAssociationsPerSourceIP > configuration.MaxAssociations {
		return errors.New("udp association sub-limits must not exceed max_associations")
	}
	if configuration.MaxPendingAssociationsPerClient > configuration.MaxPendingAssociations ||
		configuration.MaxPendingAssociationsPerProxy > configuration.MaxPendingAssociations {
		return errors.New("udp pending association sub-limits must not exceed max_pending_associations")
	}
	if configuration.MaxNewAssociationsPerSecondPerClient > configuration.MaxNewAssociationsPerSecond ||
		configuration.MaxNewAssociationsPerSecondPerProxy > configuration.MaxNewAssociationsPerSecond {
		return errors.New("udp association rate sub-limits must not exceed max_new_associations_per_second")
	}
	if configuration.MaxQueuedBytesPerAssociation > configuration.MaxQueuedBytes {
		return errors.New("udp.max_queued_bytes_per_association must not exceed udp.max_queued_bytes")
	}
	return nil
}

// ValidateUDPConfig validates externally supplied UDP runtime limits.
func ValidateUDPConfig(configuration UDPConfig) error {
	return validateUDPConfig(configuration)
}
