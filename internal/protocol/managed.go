package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ManagedProxy contains the complete server-owned client proxy configuration.
type ManagedProxy struct {
	Name          string             `json:"name"`
	Type          ProxyType          `json:"type"`
	LocalIP       string             `json:"local_ip"`
	LocalPort     uint16             `json:"local_port"`
	RemotePort    uint16             `json:"remote_port,omitempty"`
	Domain        string             `json:"domain,omitempty"`
	PublicSchemes []HTTPPublicScheme `json:"public_schemes,omitempty"`
}

// ManagedForward contains one complete server-owned Forward configuration.
type ManagedForward struct {
	Name       string      `json:"name"`
	Type       ForwardType `json:"type"`
	ListenIP   string      `json:"listen_ip"`
	ListenPort uint16      `json:"listen_port"`
	TargetIP   string      `json:"target_ip"`
	TargetPort uint16      `json:"target_port"`
}

// ManagedConfigPrepare stages one complete managed configuration generation.
type ManagedConfigPrepare struct {
	Revision uint64           `json:"revision"`
	Digest   string           `json:"digest"`
	Proxies  []ManagedProxy   `json:"proxies"`
	Forwards []ManagedForward `json:"forwards"`
}

// ManagedConfigStatus acknowledges one managed configuration phase.
type ManagedConfigStatus struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

// ManagedConfigActivate activates one prepared generation and its server Binding IDs.
type ManagedConfigActivate struct {
	Revision uint64          `json:"revision"`
	Digest   string          `json:"digest"`
	Forwards []ForwardResult `json:"forwards"`
}

// ManagedConfigurationDigest returns the canonical digest used by both peers.
func ManagedConfigurationDigest(
	proxies []ManagedProxy,
	forwardSets ...[]ManagedForward,
) (string, error) {
	if len(forwardSets) == 0 {
		encoded, err := json.Marshal(proxies)
		if err != nil {
			return "", fmt.Errorf("encode managed configuration: %w", err)
		}
		digest := sha256.Sum256(encoded)
		return hex.EncodeToString(digest[:]), nil
	}
	forwards := []ManagedForward{}
	if len(forwardSets) != 0 && forwardSets[0] != nil {
		forwards = forwardSets[0]
	}
	encoded, err := json.Marshal(struct {
		Proxies  []ManagedProxy   `json:"proxies"`
		Forwards []ManagedForward `json:"forwards"`
	}{Proxies: proxies, Forwards: forwards})
	if err != nil {
		return "", fmt.Errorf("encode managed configuration: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
