//go:build windows

package platform

// Day-to-day operation of a site that already exists: reading its detail,
// driving its application pool, changing its bindings, and asking win-acme for
// a certificate. windows.go holds the site LIFECYCLE; this holds everything
// after it.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// output runs a command and returns its combined text with the error. run
// throws the output away and only reports failure; parsing an appcmd listing
// needs the text.
func output(name string, arg ...string) (string, error) {
	out, err := exec.Command(name, arg...).CombinedOutput()
	return string(out), err
}

// SiteList returns every IIS site with its state and bindings.
func SiteList() ([]SiteSummary, error) {
	out, err := output(appcmdPath(), "list", "site")
	if err != nil {
		return nil, fmt.Errorf("could not list the sites: %v - %s", err, strings.TrimSpace(out))
	}
	return parseSiteList(out), nil
}

// ReadSiteDetail gathers one site's state, physical path, pool and bindings
// from four appcmd queries.
//
// A malformed domain is an invalid request, which a caller turns into a 400. A
// site that is simply not there is an operational failure, which is a different
// answer for an operator.
func ReadSiteDetail(domain string) (SiteDetail, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return SiteDetail{}, fmt.Errorf("invalid domain %q: %w", domain, ErrInvalidRequest)
	}
	appcmd := appcmdPath()

	out, err := output(appcmd, "list", "site", "/name:"+domain)
	m := firstMatch(out, siteLinePattern)
	if m == nil {
		if err != nil {
			return SiteDetail{}, fmt.Errorf("could not query the site %q: %v - %s", domain, err, strings.TrimSpace(out))
		}
		return SiteDetail{}, fmt.Errorf("site %q: %w", domain, ErrNotFound)
	}
	detail := SiteDetail{Name: m[1], State: m[4], Bindings: parseBindings(m[3])}

	// The root application names the pool it runs in.
	if appOut, _ := output(appcmd, "list", "app", "/site.name:"+domain); appOut != "" {
		if m := firstMatch(appOut, appLinePattern); m != nil {
			detail.Pool.Name = m[2]
		}
	}
	// The root virtual directory names the physical path.
	if vdirOut, _ := output(appcmd, "list", "vdir", "/app.name:"+domain+"/"); vdirOut != "" {
		if m := firstMatch(vdirOut, vdirLinePattern); m != nil {
			detail.PhysicalPath = m[2]
		}
	}
	readPool(appcmd, &detail)
	return detail, nil
}

// readPool fills in the pool's state and runtime version.
//
// The pool is queried POSITIONALLY. `list site /name:` is proven, but for a
// pool it is unclear whether appcmd wants /name: or /apppool.name:, and a
// positional identifier works for every appcmd object type.
func readPool(appcmd string, detail *SiteDetail) {
	if detail.Pool.Name == "" {
		return
	}
	out, _ := output(appcmd, "list", "apppool", detail.Pool.Name)
	if out == "" {
		return
	}
	if m := firstMatch(out, poolLinePattern); m != nil {
		detail.Pool.RuntimeVersion = m[2]
		detail.Pool.State = m[4]
	}
}

// PoolAction starts, stops or recycles an application pool.
func PoolAction(pool, action string) error {
	pool, err := validatePoolName(pool)
	if err != nil {
		return err
	}
	verb, err := poolVerb(action)
	if err != nil {
		return err
	}
	return run(appcmdPath(), verb, "apppool", "/apppool.name:"+pool)
}

// PoolRuntime sets an application pool's managed .NET version.
func PoolRuntime(pool, version string) error {
	pool, err := validatePoolName(pool)
	if err != nil {
		return err
	}
	if err := validateRuntime(version); err != nil {
		return err
	}
	return run(appcmdPath(), "set", "apppool", pool, "/managedRuntimeVersion:"+version)
}

// bindingChange adds or removes a binding. The sign is appcmd's own: `/+` adds
// to a collection and `/-` removes from it.
func bindingChange(sign, site, protocol, port, host string) error {
	site = strings.ToLower(strings.TrimSpace(site))
	if !domainPattern.MatchString(site) {
		return fmt.Errorf("invalid site %q: %w", site, ErrInvalidRequest)
	}
	b, err := validateBinding(protocol, port, host)
	if err != nil {
		return err
	}
	return run(appcmdPath(), "set", "site", "/site.name:"+site,
		fmt.Sprintf("/%sbindings.[protocol='%s',bindingInformation='*:%d:%s']", sign, b.Protocol, b.Port, b.Host))
}

// AddBinding adds a binding to a site.
func AddBinding(site, protocol, port, host string) error {
	return bindingChange("+", site, protocol, port, host)
}

// RemoveBinding takes a binding off a site.
func RemoveBinding(site, protocol, port, host string) error {
	return bindingChange("-", site, protocol, port, host)
}

const (
	// wacsPath is where the catalog installs win-acme. Without it there is
	// nothing to run and the attempt is refused rather than started.
	wacsPath = `C:\Program Files\Servika\win-acme\wacs.exe`

	// acmeEmailEnv names the operator's ACME registration address. There is NO
	// default: Let's Encrypt registers this address and it belongs to whoever
	// runs the host, not to whoever wrote the code. A shipped default would put
	// one address on every installation.
	acmeEmailEnv = "SERVIKA_ACME_EMAIL"

	// acmeTimeout bounds one issuance. wacs performs an ACME validation and an
	// IIS installation; three minutes is generous for a real domain and stops
	// a stuck run from waiting for ever.
	acmeTimeout = 180 * time.Second

	// acmeNote is appended to a successful answer. A certificate needs real DNS
	// and reachable ports 80 and 443, so on a .invalid or private-network test
	// host this command FAILS and that is expected. Saying so is the difference
	// between an operator debugging their setup and an operator debugging
	// nothing.
	acmeNote = "note: a certificate is only issued for a real domain reachable from outside on ports 80 and 443; " +
		"on a .invalid or private-network test host this command FAILS, which is expected."
)

// IssueSiteCertificate runs win-acme against a site in IIS mode.
//
// A precondition failure (bad name, win-acme absent, no email configured, site
// not found) is an error before anything runs. Once wacs actually runs, a
// non-zero exit or a timeout is ALSO an error: answering success with the
// failure buried in the text would report a certificate that does not exist.
// The honest wacs output is carried inside the error either way.
func IssueSiteCertificate(site string) (string, error) {
	site = strings.ToLower(strings.TrimSpace(site))
	if !domainPattern.MatchString(site) {
		return "", fmt.Errorf("invalid site %q: %w", site, ErrInvalidRequest)
	}
	email := strings.TrimSpace(os.Getenv(acmeEmailEnv))
	if email == "" {
		return "", fmt.Errorf("set %s to the operator's ACME registration address first: %w", acmeEmailEnv, ErrInvalidRequest)
	}
	if _, err := os.Stat(wacsPath); err != nil {
		return "", fmt.Errorf("win-acme is not installed at %s; install it from the catalog first", wacsPath)
	}
	// wacs wants the NUMERIC site id, which only the listing carries.
	id, err := siteID(site)
	if err != nil {
		return "", err
	}
	return runWacs(id, email)
}

// runWacs performs the issuance and reports what happened.
func runWacs(id, email string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, wacsPath,
		"--target", "iis",
		"--siteid", id,
		"--installation", "iis",
		"--accepttos",
		"--emailaddress", email,
	).CombinedOutput()

	text := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("the certificate request timed out after %s and wacs was stopped:\n%s", acmeTimeout, text)
	}
	if err != nil {
		return "", fmt.Errorf("the certificate was not issued (%v):\n%s", err, text)
	}
	if text != "" {
		text += "\n\n"
	}
	return text + acmeNote, nil
}

// siteID resolves a site name to its numeric IIS id.
func siteID(site string) (string, error) {
	out, _ := output(appcmdPath(), "list", "site", "/name:"+site)
	if m := firstMatch(out, siteLinePattern); m != nil {
		return m[2], nil
	}
	return "", fmt.Errorf("site %q: %w - %s", site, ErrNotFound, strings.TrimSpace(out))
}
