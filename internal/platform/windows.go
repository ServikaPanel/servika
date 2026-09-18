//go:build windows

package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// windowsProvider runs the site lifecycle on IIS and NTFS.
//
// CapSite is NOT on by default. It turns on only after `servika-agent selftest`
// has run and passed ON THIS MACHINE, which is what the seal file below
// records. That makes the rule "a capability is announced only once it is
// proven" mechanical per host rather than a promise on paper: an untested host
// never receives a site request.
//
// IssueSSL still returns ErrUnsupported on purpose. Certificate issuance on
// Windows is a separate step.
type windowsProvider struct{}

var activeProvider Provider = windowsProvider{}

// selftestSeal is what the selftest writes. It holds the version that passed,
// so an upgraded agent finds a seal from the OLD version and CapSite closes
// again: every new agent version proves itself once more.
const selftestSeal = `C:\ProgramData\servika\selftest.ok`

// rootDir is where tenant directories live.
const rootDir = `C:\inetpub\servika`

func (windowsProvider) Name() string { return "windows" }

func (windowsProvider) Capabilities() Capability {
	var c Capability
	// The seal rule is absolute: CapSite opens only when the seal matches THIS
	// version. A wider discovery pass must not loosen the site gate.
	b, err := os.ReadFile(selftestSeal)
	if err == nil && strings.TrimSpace(string(b)) == Version {
		c |= CapSite
	}
	// The event log and the task scheduler are part of Windows itself, on every
	// host and independent of IIS, so they need no seal.
	c |= CapEventLog | CapScheduledTask
	return c | discoveredCapabilities()
}

// capabilityCache holds the discovery result for a minute.
//
// The panel can probe /health every few seconds and every probe calls
// Capabilities(). Opening a new powershell.exe each time is a process storm:
// one to two seconds and a child process per call. A minute of staleness costs
// nothing, because installing a service on a server takes minutes anyway and
// the next window picks it up on its own.
var capabilityCache struct {
	sync.Mutex
	value Capability
	at    time.Time
}

const capabilityCacheLife = 60 * time.Second

// discoveredCapabilities derives capabilities from installed services and from
// what is on disk.
func discoveredCapabilities() Capability {
	capabilityCache.Lock()
	defer capabilityCache.Unlock()
	if !capabilityCache.at.IsZero() && time.Since(capabilityCache.at) < capabilityCacheLife {
		return capabilityCache.value
	}

	var c Capability
	// Every candidate service is asked for in ONE PowerShell call. ConvertTo-Json
	// is required: Get-Service's table output is LOCALISED, so the headers and
	// the state text change on a non-English install while the JSON field names
	// do not. The arguments are passed separately, never joined into a shell
	// string.
	//
	// `; exit 0` is also required. Names that do not exist on this host
	// (MSSQLSERVER and the like) are suppressed by SilentlyContinue, but
	// powershell -Command still exits 1, and Output() then treats a perfectly
	// good JSON answer as a failure. That is how an installed FTP service failed
	// to light its capability bit on a real host.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-Service -Name 'MSSQLSERVER','MSSQL$*','ftpsvc','DNS','MySQL*','postgresql*' -ErrorAction SilentlyContinue | Select-Object -Property Name | ConvertTo-Json -Compress; exit 0`,
	).Output()
	if err == nil {
		c |= capabilitiesFromServices(serviceNames(out))
	}
	// The ASP.NET Core hosting bundle installs its IIS module at this fixed
	// path, so the directory is a reliable sign and no registry scan is needed.
	if fi, err := os.Stat(`C:\Program Files\IIS\Asp.Net Core Module\V2`); err == nil && fi.IsDir() {
		c |= CapDotNet
	}

	// The failure case is cached too. Re-running every few seconds against a
	// broken PowerShell would bring back exactly the process storm the cache
	// exists to prevent.
	capabilityCache.value = c
	capabilityCache.at = time.Now()
	return c
}

// Verify reports every missing piece rather than the first, so an operator does
// not fix one thing and discover the next on the following run.
func (windowsProvider) Verify() error {
	var missing []string
	if _, err := os.Stat(appcmdPath()); err != nil {
		missing = append(missing, "IIS not found at "+appcmdPath()+"; the Web Server (IIS) role must be installed")
	}
	if _, err := exec.LookPath("icacls"); err != nil {
		missing = append(missing, "icacls is not on PATH")
	}
	// The classic administrator test: `net session` only succeeds in an
	// elevated session.
	if err := exec.Command("net", "session").Run(); err != nil {
		missing = append(missing, "the agent is not elevated; install it as a service running as LocalSystem")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the host is not ready: %s", strings.Join(missing, "; "))
	}
	return nil
}

func appcmdPath() string {
	dir := os.Getenv("WINDIR")
	if dir == "" {
		dir = `C:\Windows`
	}
	return filepath.Join(dir, "System32", "inetsrv", "appcmd.exe")
}

// ownerMarkerPath records which domain a tenant directory belongs to. It sits
// in the tenant root, OUTSIDE httpdocs, so it is never served over the web.
func ownerMarkerPath(user string) string {
	return filepath.Join(rootDir, user, ".servika-owner")
}

func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// The Windows password policy wants complexity: upper, lower, digit, symbol.
	return "Sv!" + hex.EncodeToString(b) + "Z", nil
}

// run executes a command and reports its output with the failure, because the
// exit code alone never says what went wrong.
func run(name string, arg ...string) error {
	out, err := exec.Command(name, arg...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v - %s", name, strings.Join(arg, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (w windowsProvider) CreateSite(req SiteRequest) (SiteResult, error) {
	if !w.Capabilities().Has(CapSite) {
		return SiteResult{}, fmt.Errorf("CreateSite: this host is not proven yet, run `servika-agent selftest` first: %w", ErrUnsupported)
	}
	return createSite(req)
}

// checkOwner refuses to take over a directory that belongs to another domain.
// The decision itself is ownerConflict, which is tested; this only reads the
// marker off disk. An unreadable marker means there is nothing to conflict with.
func checkOwner(user, domain, webRoot string) error {
	marker, err := os.ReadFile(ownerMarkerPath(user))
	if err != nil || !ownerConflict(marker, domain) {
		return nil
	}
	return fmt.Errorf("account name collision: %s already belongs to %q (user=%s); this domain could not be mapped to its own account, please report it",
		filepath.Dir(webRoot), strings.TrimSpace(string(marker)), user)
}

// createSite is the core path, independent of the capability gate, and it is
// what the selftest runs too. A selftest that took a shortcut would prove
// nothing about the production path.
func createSite(req SiteRequest) (SiteResult, error) {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !domainPattern.MatchString(domain) {
		return SiteResult{}, fmt.Errorf("invalid domain %q: %w", req.Domain, ErrInvalidRequest)
	}
	user := systemUserFor(domain)
	webRoot := filepath.Join(rootDir, user, "httpdocs")
	if err := checkOwner(user, domain, webRoot); err != nil {
		return SiteResult{}, err
	}
	if err := os.MkdirAll(webRoot, 0o755); err != nil {
		return SiteResult{}, fmt.Errorf("could not create the web root: %w", err)
	}
	if err := os.WriteFile(ownerMarkerPath(user), []byte(domain+"\n"), 0o644); err != nil {
		return SiteResult{}, fmt.Errorf("could not write the owner marker: %w", err)
	}
	if err := buildSite(domain, user, webRoot); err != nil {
		return SiteResult{}, err
	}
	return SiteResult{
		SystemUser: user,
		WebRoot:    webRoot,
		FTPHost:    domain,
		// Windows has no per-site PHP version yet (CapPHPVersion is off), so
		// the request is NOT echoed back. An empty field tells the truth.
		PHPVersion: "",
		PHPSocket:  "",
	}, nil
}

// buildSite creates the account, the pool, the ACLs and the IIS site, undoing
// what it made if a step fails. A half-built site (account exists, site does
// not) locks the next attempt out as well.
func buildSite(domain, user, webRoot string) error {
	appcmd := appcmdPath()
	var undo []func()
	rollback := func() {
		// Undone in reverse: the site has to go before the pool it binds to,
		// and the pool before the account it runs as.
		for _, step := range slices.Backward(undo) {
			step()
		}
	}

	password, err := randomPassword()
	if err != nil {
		return err
	}
	if err := run("net", "user", user, password, "/add", "/expires:never", "/y"); err != nil {
		return fmt.Errorf("local account: %w", err)
	}
	undo = append(undo, func() { _ = run("net", "user", user, "/delete") })

	// ORDER MATTERS: the pool first, then the ACL. The `IIS AppPool\<name>`
	// virtual account does not exist until the pool does, and icacls answers
	// 1332 ("No mapping between account names and security IDs") if the ACL is
	// tried first.
	if err := run(appcmd, "add", "apppool", "/name:"+user); err != nil {
		rollback()
		return fmt.Errorf("application pool: %w", err)
	}
	undo = append(undo, func() { _ = run(appcmd, "delete", "apppool", "/apppool.name:"+user) })

	// NTFS: Modify for the site account (for FTP and deployment), ReadExecute
	// for the application pool identity.
	if err := run("icacls", webRoot, "/inheritance:e",
		"/grant", user+":(OI)(CI)M",
		"/grant", `IIS AppPool\`+user+":(OI)(CI)RX"); err != nil {
		rollback()
		return fmt.Errorf("NTFS ACL: %w", err)
	}

	if err := run(appcmd, "add", "site", "/name:"+domain,
		"/bindings:http/*:80:"+domain, "/physicalPath:"+webRoot); err != nil {
		rollback()
		return fmt.Errorf("IIS site: %w", err)
	}
	undo = append(undo, func() { _ = run(appcmd, "delete", "site", "/site.name:"+domain) })

	if err := run(appcmd, "set", "app", domain+"/", "/applicationPool:"+user); err != nil {
		rollback()
		return fmt.Errorf("binding the pool: %w", err)
	}
	return nil
}

// DeleteSite removes the IIS objects and the account. THE WEB ROOT STAYS.
// Deleting a customer's files is the one step with no way back, so it is left
// to an explicit operator decision, the same discipline the Linux side applies
// to backups.
func (w windowsProvider) DeleteSite(id SiteID) error {
	if !w.Capabilities().Has(CapSite) {
		return fmt.Errorf("DeleteSite: this host is not proven yet: %w", ErrUnsupported)
	}
	return deleteSite(id)
}

// resolveUser finds the account a domain runs as.
//
// The caller's value wins; then the pool name IIS actually has; and only as a
// last resort the derivation is run again. Recomputing alone would be wrong if
// systemUserFor ever changes between versions: it would produce a name that
// never existed and leave the real account orphaned.
func resolveUser(id SiteID, domain string) string {
	if id.SystemUser != "" {
		return id.SystemUser
	}
	if user := poolNameFromIIS(domain); user != "" {
		return user
	}
	return systemUserFor(domain)
}

func deleteSite(id SiteID) error {
	domain := strings.ToLower(strings.TrimSpace(id.Domain))
	if !domainPattern.MatchString(domain) {
		return fmt.Errorf("invalid domain %q: %w", id.Domain, ErrInvalidRequest)
	}
	appcmd := appcmdPath()
	user := resolveUser(id, domain)
	var failures []string
	if err := run(appcmd, "delete", "site", "/site.name:"+domain); err != nil {
		failures = append(failures, err.Error())
	}
	// The web root is kept, so the deleted account's and pool's entries must be
	// stripped from it: otherwise they pile up as orphaned SIDs and a colliding
	// reuse would inherit the old rights. The order matters - after the site is
	// gone (no window where a live site serves 403) but before the pool and the
	// account are, while the names still resolve.
	webRoot := filepath.Join(rootDir, user, "httpdocs")
	if _, err := os.Stat(webRoot); err == nil {
		_ = run("icacls", webRoot, "/remove:g", user, "/remove:g", `IIS AppPool\`+user, "/T", "/C", "/Q")
	}
	if err := run(appcmd, "delete", "apppool", "/apppool.name:"+user); err != nil {
		failures = append(failures, err.Error())
	}
	if err := run("net", "user", user, "/delete"); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("partial delete: %s", strings.Join(failures, " | "))
	}
	return nil
}

// poolNameFromIIS reads the application pool bound to a domain. An unexpected
// answer (empty, or several lines) is refused rather than used.
func poolNameFromIIS(domain string) string {
	out, err := exec.Command(appcmdPath(), "list", "app", domain+"/", "/text:applicationPool").Output()
	if err != nil {
		return ""
	}
	user := strings.TrimSpace(string(out))
	if strings.HasPrefix(user, userPrefix) && !strings.ContainsAny(user, " \r\n") {
		return user
	}
	return ""
}

func (windowsProvider) IssueSSL(req SSLRequest) (Certificate, error) {
	return Certificate{}, fmt.Errorf("IssueSSL(%s): certificate issuance on Windows is a later step: %w", req.Domain, ErrUnsupported)
}

// SelfTest proves the host by running the REAL production path: it opens a test
// site, sees it in appcmd's listing, deletes it, and writes the seal if all of
// that worked.
//
// The `.invalid` TLD is chosen on purpose (RFC 2606): the test domain can never
// resolve in real DNS.
func SelfTest() error {
	var w windowsProvider
	if err := w.Verify(); err != nil {
		return err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	domain := "servika-selftest-" + hex.EncodeToString(suffix) + ".invalid"
	result, err := createSite(SiteRequest{Domain: domain})
	if err != nil {
		return fmt.Errorf("could not open the test site: %w", err)
	}
	id := SiteID{Domain: domain, SystemUser: result.SystemUser}
	out, err := exec.Command(appcmdPath(), "list", "site", "/name:"+domain).CombinedOutput()
	if err != nil || !strings.Contains(string(out), domain) {
		_ = deleteSite(id)
		return fmt.Errorf("the site was created but appcmd does not list it; IIS state is inconsistent: %s", strings.TrimSpace(string(out)))
	}
	if err := deleteSite(id); err != nil {
		return fmt.Errorf("could not delete the test site: %w", err)
	}
	_ = os.RemoveAll(filepath.Join(rootDir, result.SystemUser))
	if err := os.MkdirAll(filepath.Dir(selftestSeal), 0o755); err != nil {
		return err
	}
	return os.WriteFile(selftestSeal, []byte(Version+"\n"), 0o644)
}

// ReadEvents returns the newest records of one log.
//
// The log name comes from the allowlist only. It becomes a wevtutil argument
// directly, and free text would be both an argument injection and a way to read
// any log on the host.
func ReadEvents(log string, count int) ([]EventRecord, error) {
	if !eventLogs[log] {
		return nil, fmt.Errorf("unknown log %q, expected System, Application or Security: %w", log, ErrInvalidRequest)
	}
	// /rd:true reads backwards from the newest record; /f:RenderedXml brings the
	// resolved message along.
	out, err := exec.Command("wevtutil", "qe", log,
		"/c:"+strconv.Itoa(boundedCount(count)), "/rd:true", "/f:RenderedXml").Output()
	if err != nil {
		return nil, commandError("wevtutil "+log, err)
	}
	return parseEvents(log, out)
}

// ReadTasks returns the scheduled tasks. With all unset, the hundreds of
// operating system tasks under \Microsoft\ are dropped, leaving what an
// operator actually put there.
func ReadTasks(all bool) ([]TaskRecord, error) {
	// The PSCustomObject field names match the Go field names one for one, so no
	// mapping layer is needed. The date format is fixed on the PowerShell side
	// so a locale setting cannot leak into the JSON. Only single quotes appear
	// inside the command and it is passed as a separate argument; nothing is
	// joined into a shell string.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-ScheduledTask | ForEach-Object { $i = $_ | Get-ScheduledTaskInfo; [PSCustomObject]@{ Name = ($_.TaskPath + $_.TaskName); State = [string]$_.State; LastRun = if ($i.LastRunTime) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }; NextRun = if ($i.NextRunTime) { $i.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }; LastResult = $i.LastTaskResult } } | ConvertTo-Json -Compress; exit 0`,
	).Output()
	if err != nil {
		return nil, commandError("the task list", err)
	}
	return parseTasks(out, all)
}

// commandError carries a failed command's stderr into the message, because the
// exit code on its own tells an operator nothing.
func commandError(what string, err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(exit.Stderr) > 0 {
		return fmt.Errorf("%s: %v - %s", what, err, strings.TrimSpace(string(exit.Stderr)))
	}
	return fmt.Errorf("%s: %w", what, err)
}
