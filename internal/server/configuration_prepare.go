package server

import (
	"fmt"
	"reflect"

	"github.com/acexy/portway/internal/config"
)

// preparedConfiguration owns candidate values only; publication and resource
// retirement remain in applyConfigurationCandidateContext.
type preparedConfiguration struct {
	configuration     config.ServerConfig
	changes           configurationChanges
	httpsCertificates *httpsCertificateSnapshot
	httpsDigest       string
}

type configurationChanges struct {
	authentication    bool
	governedClients   bool
	managedClients    bool
	forwards          bool
	virtualNetwork    bool
	mirror            bool
	httpsCertificates bool
	logLevel          bool
}

func (changes configurationChanges) authenticationChanged() bool {
	return changes.authentication || changes.governedClients || changes.managedClients
}

func (changes configurationChanges) forwardPolicyChanged() bool {
	return changes.forwards || changes.governedClients || changes.managedClients
}

func (changes configurationChanges) any() bool {
	return changes.authenticationChanged() || changes.forwards || changes.virtualNetwork ||
		changes.mirror || changes.httpsCertificates || changes.logLevel
}

// prepareConfigurationCandidate requires the caller to hold authenticationBarrier.
// Preserve validation order so rejected candidates report the same first error.
func (s *Service) prepareConfigurationCandidate(
	current config.ServerConfig,
	candidate config.ServerConfig,
) (*preparedConfiguration, error) {
	prepared := &preparedConfiguration{}
	if err := config.ValidateForwardConfiguration(candidate); err != nil {
		return nil, err
	}
	if err := config.ValidateProxyMirrorConfiguration(candidate); err != nil {
		return nil, err
	}
	if err := s.validateVNetConfigurationTransition(current.VirtualNetwork, candidate.VirtualNetwork); err != nil {
		return nil, err
	}

	if serverTokenRequiresGeneration(candidate) &&
		current.Authentication.SharedToken != nil {
		if !current.SharedTokenGenerated {
			return nil, restartRequiredError{field: "authentication.shared_token"}
		}
		sharedToken := *current.Authentication.SharedToken
		candidate.Authentication.SharedToken = &sharedToken
		candidate.SharedTokenGenerated = true
	}
	if _, _, err := config.EnsureServerToken(&candidate); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(candidate.Transport, current.Transport) {
		return nil, restartRequiredError{
			field: changedYAMLField("transport", current.Transport, candidate.Transport),
		}
	}
	if candidate.Proxies.BindIP != current.Proxies.BindIP {
		return nil, restartRequiredError{
			field: "proxies.bind_ip",
		}
	}
	if candidate.Proxies.HTTP.ListenAddress != current.Proxies.HTTP.ListenAddress {
		return nil, restartRequiredError{field: "proxies.http.listen_address"}
	}
	if candidate.Proxies.HTTPS.ListenAddress != current.Proxies.HTTPS.ListenAddress {
		return nil, restartRequiredError{field: "proxies.https.listen_address"}
	}
	if !reflect.DeepEqual(candidate.Proxies.HTTP.HTTPConfig, current.Proxies.HTTP.HTTPConfig) {
		return nil, restartRequiredError{
			field: changedYAMLField(
				"proxies.http",
				current.Proxies.HTTP.HTTPConfig,
				candidate.Proxies.HTTP.HTTPConfig,
			),
		}
	}
	prepared.changes.httpsCertificates = !reflect.DeepEqual(
		candidate.Proxies.HTTPS.Certificates,
		current.Proxies.HTTPS.Certificates,
	)
	if prepared.changes.httpsCertificates {
		if s.httpsCertificates == nil {
			return nil, restartRequiredError{
				field: "proxies.https.certificates",
			}
		}
		var err error
		prepared.httpsCertificates, prepared.httpsDigest, err = loadHTTPSCertificates(candidate.Proxies.HTTPS)
		if err != nil {
			return nil, fmt.Errorf("reload HTTPS certificate: %w", err)
		}
	}
	if !reflect.DeepEqual(candidate.Proxies.UDP, current.Proxies.UDP) {
		return nil, restartRequiredError{
			field: changedYAMLField("proxies.udp", current.Proxies.UDP, candidate.Proxies.UDP),
		}
	}
	if !reflect.DeepEqual(candidate.Security, current.Security) {
		return nil, restartRequiredError{
			field: changedYAMLField("security", current.Security, candidate.Security),
		}
	}
	if !reflect.DeepEqual(candidate.Operations, current.Operations) {
		return nil, restartRequiredError{
			field: changedYAMLField("operations", current.Operations, candidate.Operations),
		}
	}
	if err := validateManagedRevisionTransitions(current, candidate); err != nil {
		return nil, err
	}
	prepared.configuration = candidate
	prepared.changes.authentication = !reflect.DeepEqual(candidate.Authentication, current.Authentication)
	prepared.changes.governedClients = !reflect.DeepEqual(candidate.GovernedClients, current.GovernedClients)
	prepared.changes.managedClients = !reflect.DeepEqual(candidate.ManagedClients, current.ManagedClients)
	prepared.changes.forwards = !reflect.DeepEqual(candidate.Forwards, current.Forwards)
	prepared.changes.virtualNetwork = !reflect.DeepEqual(candidate.VirtualNetwork, current.VirtualNetwork)
	prepared.changes.mirror = !reflect.DeepEqual(candidate.Proxies.Mirror, current.Proxies.Mirror)
	prepared.changes.logLevel = candidate.LogLevel != current.LogLevel
	return prepared, nil
}
