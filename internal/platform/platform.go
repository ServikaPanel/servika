// Package platform names the host operations that are not the same on every
// operating system, so a second platform can be added without rewriting the
// code that asks for them.
//
// The panel manages AlmaLinux directly today. A Windows host does the same work
// through entirely different tools: IIS instead of nginx, an application pool
// instead of a PHP-FPM pool, a local account instead of a tenant Linux user.
// This package is where that difference is expressed once.
//
// The contract is deliberately SMALL. The provisioner is ~9.000 lines and
// abstracting all of it would mean rewriting Linux behaviour that works, which
// is the one risk this package exists to avoid. Only the core of the site
// lifecycle lives here; everything else stays platform-specific and moves in
// later, one verified piece at a time.
package platform

import "errors"

// ErrUnsupported is what a provider returns for a capability it does not have.
// It is a distinct error so a caller can tell "this platform cannot do it" from
// "it failed", which are different answers for an operator.
var ErrUnsupported = errors.New("this platform does not support that capability")

// ErrInvalidRequest is what a provider returns for a request it refuses to act
// on, such as a malformed domain name.
var ErrInvalidRequest = errors.New("invalid request")

// Capability is the set of things a platform can do.
//
// A new platform starts with every capability off, so a missing implementation
// reads as absent rather than as broken.
//
// THE ORDER IS PART OF THE CONTRACT. These bits are stored as a NUMBER, in the
// panel database and in what an agent reports. The order of the existing lines
// never changes and a new capability is only ever appended, because one line
// inserted in the middle silently shifts every value already recorded.
type Capability uint32

const (
	CapSite            Capability = 1 << iota // the basic site lifecycle
	CapSSL                                    // issuing and renewing certificates
	CapIsolation                              // tenant isolation (systemd slice / application pool)
	CapQuota                                  // disk quota
	CapMail                                   // mail server
	CapPHPVersion                             // a PHP version per site
	CapMandatoryAccess                        // mandatory access control (SELinux and the like)
	CapEventLog                               // the operating system event log
	CapScheduledTask                          // scheduled tasks
	CapMSSQL                                  // Microsoft SQL Server
	CapFTP                                    // FTP server
	CapDNS                                    // DNS server role
	CapDotNet                                 // the ASP.NET Core hosting bundle
	CapMySQL                                  // MySQL or MariaDB
	CapPostgreSQL                             // PostgreSQL
)

// Has reports whether the set carries the given capability.
func (c Capability) Has(want Capability) bool { return c&want != 0 }

// SiteRequest is the least a platform needs to open a site.
type SiteRequest struct {
	Domain     string
	PHPVersion string // ignored by a platform without CapPHPVersion
}

// SiteID points at a site that already exists.
type SiteID struct {
	Domain     string
	SystemUser string
}

// SiteResult is the platform-independent output of opening a site.
//
// The field names deliberately match provisioner.Result one for one, so the
// Linux adapter is a straight copy and cannot introduce a translation error.
type SiteResult struct {
	SystemUser string
	WebRoot    string
	FTPHost    string
	PHPVersion string
	PHPSocket  string // empty on Windows: IIS uses an application pool
}

// Certificate is where an issued certificate landed on disk.
type Certificate struct {
	CertPath string
	KeyPath  string
}

// SSLRequest asks for a certificate.
//
// PHPVersion and Backend are not invented: the Linux call is
// EnableLetsEncrypt(domain, systemUser, phpVersion, backend) and both are
// needed to rewrite the vhost. Windows ignores them.
type SSLRequest struct {
	SiteID
	PHPVersion string
	Backend    string
}

// Provider is what a platform implements.
type Provider interface {
	Name() string
	Capabilities() Capability

	// Verify reports whether the host is ready for this provider: the services
	// and paths it needs. The panel calls it at startup and REPORTS what is
	// missing rather than continuing quietly.
	Verify() error

	CreateSite(SiteRequest) (SiteResult, error)
	DeleteSite(SiteID) error
	IssueSSL(SSLRequest) (Certificate, error)
}

// Active is the provider of the platform this binary was built for.
//
// Each operating system file sets its own activeProvider, so the choice is made
// at COMPILE time, not at run time, and the wrong platform's code never enters
// the binary at all.
func Active() Provider { return activeProvider }
