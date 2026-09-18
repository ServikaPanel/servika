//go:build !windows

package platform

import "servika/internal/provisioner"

// unixProvider is a THIN bridge onto the existing provisioner.
//
// THERE IS NO LOGIC HERE AND THERE WILL BE NONE. This file only delegates, so
// the behaviour change is zero: every function it calls is one the panel
// already uses today. Logic added here would break the rule this package exists
// to keep - a mistake in the bridge would hit both platforms at once.
//
// The build tag is `!windows` rather than `linux` because the panel is compiled
// on macOS as a quick correctness check; a `linux` tag would leave that build
// with no provider at all.
type unixProvider struct{}

var activeProvider Provider = unixProvider{}

func (unixProvider) Name() string { return "linux" }

func (unixProvider) Capabilities() Capability {
	return CapSite | CapSSL | CapIsolation | CapQuota | CapMail | CapPHPVersion | CapMandatoryAccess
}

// Verify does nothing here. The Linux environment is already checked by the
// installer gate, and checking it again would create a second source of truth
// that can disagree with the first.
func (unixProvider) Verify() error { return nil }

func (unixProvider) CreateSite(req SiteRequest) (SiteResult, error) {
	r, err := provisioner.Provision(req.Domain, req.PHPVersion)
	if err != nil {
		return SiteResult{}, err
	}
	return SiteResult{
		SystemUser: r.SystemUser,
		WebRoot:    r.WebRoot,
		FTPHost:    r.FTPHost,
		PHPVersion: r.PHPVersion,
		PHPSocket:  r.PHPSocket,
	}, nil
}

func (unixProvider) DeleteSite(id SiteID) error {
	return provisioner.Deprovision(id.Domain, id.SystemUser)
}

// IssueSSL drops the provisioner's IssueOutcome on purpose: it describes a
// Linux-only path (which SAN names were skipped, whether a valid certificate
// was reused) and has no meaning in a cross-platform contract. A caller that
// needs it calls the provisioner directly, which is what the panel does today.
func (unixProvider) IssueSSL(req SSLRequest) (Certificate, error) {
	cert, key, _, err := provisioner.EnableLetsEncrypt(req.Domain, req.SystemUser, req.PHPVersion, req.Backend)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{CertPath: cert, KeyPath: key}, nil
}
