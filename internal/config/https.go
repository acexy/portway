package config

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maximumHTTPSCertificates          = 256
	maximumHTTPSDomainsPerCertificate = 128
)

// ValidateHTTPSConfig validates the bounded public HTTPS SNI certificate mapping.
func ValidateHTTPSConfig(configuration HTTPSConfig) error {
	if len(configuration.Certificates) > maximumHTTPSCertificates {
		return fmt.Errorf(
			"https.certificates must contain at most %d entries",
			maximumHTTPSCertificates,
		)
	}
	configuredDomains := make(map[string]struct{})
	for certificateIndex, certificate := range configuration.Certificates {
		field := fmt.Sprintf("https.certificates[%d]", certificateIndex)
		if len(certificate.Domains) == 0 {
			return fmt.Errorf("%s.domains must not be empty", field)
		}
		if len(certificate.Domains) > maximumHTTPSDomainsPerCertificate {
			return fmt.Errorf(
				"%s.domains must contain at most %d entries",
				field,
				maximumHTTPSDomainsPerCertificate,
			)
		}
		if certificate.CertFile == "" {
			return fmt.Errorf("%s.cert_file is required", field)
		}
		if certificate.KeyFile == "" {
			return fmt.Errorf("%s.key_file is required", field)
		}
		for domainIndex, domain := range certificate.Domains {
			if err := validateHTTPSDomainPattern(domain); err != nil {
				return fmt.Errorf("%s.domains[%d]: %w", field, domainIndex, err)
			}
			if _, duplicate := configuredDomains[domain]; duplicate {
				return fmt.Errorf("HTTPS domain %q is configured more than once", domain)
			}
			configuredDomains[domain] = struct{}{}
		}
	}
	return nil
}

func validateHTTPSDomainPattern(domain string) error {
	if strings.HasPrefix(domain, "*.") {
		if err := ValidateHTTPDomain(strings.TrimPrefix(domain, "*.")); err != nil {
			return errors.New("must be a canonical single-label wildcard DNS name")
		}
		return nil
	}
	if err := ValidateHTTPDomain(domain); err != nil {
		return fmt.Errorf("must be a canonical DNS name: %w", err)
	}
	return nil
}
