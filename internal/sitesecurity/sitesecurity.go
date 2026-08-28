// Package sitesecurity reports known vulnerabilities in what a tenant's site
// actually runs: its WordPress plugins and themes, its npm dependencies and its
// Composer dependencies.
//
// The panel could already see three neighbouring things and not this one.
// internal/system/cve.go covers the SERVER's own packages through dnf,
// internal/antivirus looks for malware, and internal/wordpress/checksums.go
// checks core integrity. An outdated plugin with a published CVE fell between
// them, and that is where most real compromises come from.
//
// Everything here is ADVISORY. Version matching against a third-party feed is
// not exact, so nothing in this package may suspend an account, delete a file
// or bill anybody. A wrong row is a support call; a wrong suspension is an
// outage.
package sitesecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"servika/internal/files"
	"servika/internal/wordpress"
)

// App types, matching the security_findings ENUM exactly.
const (
	AppWordPress = "wordpress"
	AppNodeJS    = "nodejs"
	AppComposer  = "php-composer"
)

// Scan states, matching the security_scan_status ENUM exactly.
const (
	StateIdle     = "idle"
	StateRunning  = "running"
	StateFinished = "finished"
	StateFailed   = "failed"
)

const (
	// scanBudget bounds one whole sweep. A server with hundreds of sites and a
	// slow feed must not leave the scan marked running for a day.
	scanBudget = 45 * time.Minute

	// startupDelay lets the panel finish booting before the first sweep. The
	// same shape as internal/mailreport's collector.
	startupDelay = 5 * time.Minute

	// scanInterval is how often the sweep runs unattended.
	scanInterval = 6 * time.Hour

	// domainWorkers is how many domains are inspected at once. Each one runs
	// wp-cli, which loads a whole WordPress site to answer.
	domainWorkers = 3
)

// ErrScanRunning is what a second request gets while a sweep is in progress.
var ErrScanRunning = errors.New("a scan is already running")

// ErrDomainNotFound is what a single-domain scan gets for an id that is not a
// top-level tenant domain (an addon, a subdomain, a non-tenant, or nothing).
var ErrDomainNotFound = errors.New("no such top-level tenant domain")

// Collector owns one panel's scanning.
type Collector struct {
	DB     *sql.DB
	client *http.Client

	// Feed endpoints, copied from the constants. A test replaces them, and
	// the client with them, because netguard.DialControl refuses the loopback
	// address an httptest server listens on.
	osvQueryURL      string
	osvQueryBatchURL string
	wpFeedBase       string

	// running is the in-process half of the single-scan rule. The database
	// half survives a restart; this one stops two requests in the same process
	// from both passing the database check before either wrote it.
	//
	// scanning names the domains the current run covers, so the monitor can draw
	// a live "scanning" badge per domain. An empty set with running true means
	// the whole server is being swept; a populated set is a single-domain scan.
	mu       sync.Mutex
	running  bool
	scanning map[int64]bool
}

// New builds a Collector.
func New(db *sql.DB) *Collector {
	return &Collector{
		DB:               db,
		client:           newFeedClient(),
		osvQueryURL:      defaultOSVQueryURL,
		osvQueryBatchURL: defaultOSVQueryBatchURL,
		wpFeedBase:       defaultWPFeedBase,
	}
}

// HealRunningScans clears a state left behind by a panel that was killed
// mid-sweep.
//
// The in-process lock lives only in memory, so without this a crash during a
// scan leaves the row saying "running" and every later request, manual or
// scheduled, refuses for good.
func HealRunningScans(db *sql.DB) {
	if _, err := db.Exec(
		`UPDATE security_scan_status SET state='failed',
		        last_error='the panel restarted while this scan was running'
		  WHERE state='running'`); err != nil {
		log.Printf("site security: could not clear a stale scan state: %v", err)
	}
}

// StartCollector runs the sweep on a timer.
func StartCollector(db *sql.DB) {
	collector := New(db)
	go func() {
		time.Sleep(startupDelay)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
			if err := collector.ScanAll(ctx); err != nil && !errors.Is(err, ErrScanRunning) {
				log.Printf("site security scan: %v", err)
			}
			cancel()
			time.Sleep(scanInterval)
		}
	}()
}

// findingKey is the merge key for one finding.
//
// It is hashed here rather than indexed as the natural key because that key is
// 831 characters, over InnoDB's 3072-byte index limit in utf8mb4. The separator
// is a NUL byte, which cannot appear in any of the four values, so no two
// different tuples can produce one key by running together.
func findingKey(domainID int64, installPath, packageName, cveID string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d\x00%s\x00%s\x00%s",
		domainID, installPath, packageName, cveID))
	return hex.EncodeToString(sum[:])
}

// tally is what one sweep counts.
type tally struct {
	domains  int
	packages int
	unparsed int
	findings int
}

// ScanAll sweeps every tenant domain.
//
// It refuses to start a second sweep, in this process and across a restart. A
// sweep that runs out of its budget is written as FAILED and keeps what it
// found: a partial sweep presented as a clean one is the worst answer this
// screen can give, and that is the same rule internal/antivirus follows.
func (c *Collector) ScanAll(ctx context.Context) error {
	if err := c.begin(ctx); err != nil {
		return err
	}
	counts, scanErr := c.scan(ctx)
	c.finish(counts, scanErr)
	return scanErr
}

// acquireSlot takes the in-memory half of the single-scan lock and records
// which domains the run covers. An empty list is a whole-server sweep; a
// non-empty one is a single-domain scan. It is shared by both so a sweep and a
// single-domain scan in the same process can never overlap.
func (c *Collector) acquireSlot(domainIDs []int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrScanRunning
	}
	c.running = true
	c.scanning = make(map[int64]bool, len(domainIDs))
	for _, id := range domainIDs {
		if id > 0 {
			c.scanning[id] = true
		}
	}
	return nil
}

// ScanStatus reports whether a scan is running and which domains it covers. An
// empty set with running true means the whole server is being swept. The map is
// a copy, so the caller cannot mutate the collector's state.
func (c *Collector) ScanStatus() (bool, map[int64]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[int64]bool, len(c.scanning))
	for id := range c.scanning {
		out[id] = true
	}
	return c.running, out
}

// begin takes both halves of the single-scan lock for a whole-server sweep.
func (c *Collector) begin(ctx context.Context) error {
	if err := c.acquireSlot(nil); err != nil {
		return err
	}

	// The database half is a conditional update, so two panels pointed at one
	// database cannot both start. RowsAffected of 0 means somebody else won.
	result, err := c.DB.ExecContext(ctx,
		`UPDATE security_scan_status
		    SET state='running', started_at=NOW(), finished_at=NULL, last_error='',
		        scanned_domains=0, scanned_packages=0, unparsed_packages=0, finding_count=0
		  WHERE id=1 AND state<>'running'`)
	if err != nil {
		c.release()
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		c.release()
		return err
	}
	if affected == 0 {
		c.release()
		return ErrScanRunning
	}
	return nil
}

func (c *Collector) release() {
	c.mu.Lock()
	c.running = false
	c.scanning = nil
	c.mu.Unlock()
}

// finish records the outcome. It runs on its OWN context, because the sweep's
// budget may already have expired and the row must still be corrected.
func (c *Collector) finish(counts tally, scanErr error) {
	defer c.release()

	state := StateFinished
	message := ""
	if scanErr != nil {
		state = StateFailed
		message = scanErr.Error()
		if len(message) > 512 {
			message = message[:512]
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// last_success is stamped only on a whole-server sweep that finished
	// cleanly, and finish runs only for such a sweep (a single-domain scan
	// releases the slot without touching this row). It is what separates "no
	// supported app was found" from "this domain has never been scanned", so a
	// failed sweep must leave it exactly as the last good sweep left it.
	if _, err := c.DB.ExecContext(ctx,
		`UPDATE security_scan_status
		    SET state=?, finished_at=NOW(), last_success=IF(?, NOW(), last_success),
		        last_error=?,
		        scanned_domains=?, scanned_packages=?, unparsed_packages=?, finding_count=?
		  WHERE id=1`,
		state, scanErr == nil, message,
		counts.domains, counts.packages, counts.unparsed, counts.findings); err != nil {
		log.Printf("site security: could not record the scan outcome: %v", err)
	}
}

// target is one domain to inspect.
type target struct {
	id         int64
	name       string
	systemUser string
}

// lookupTarget reads one top-level tenant domain by id, using the same WHERE the
// sweep uses so a single-domain scan can never walk an addon's parent tree or a
// non-tenant row. A missing row answers ErrDomainNotFound.
func (c *Collector) lookupTarget(ctx context.Context, domainID int64) (target, error) {
	var item target
	err := c.DB.QueryRowContext(ctx,
		`SELECT id, domain_name, system_user FROM domains
		  WHERE id=? AND parent_domain_id IS NULL AND system_user LIKE 'c\_%'`,
		domainID).Scan(&item.id, &item.name, &item.systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, ErrDomainNotFound
	}
	return item, err
}

// BeginOne resolves one domain and takes the scan slot for it, synchronously, so
// a refusal is answered as a refusal rather than reported as a start that did
// nothing. On success the caller MUST run RunOne (in a goroutine) to release the
// slot. It does NOT touch security_scan_status: a single-domain scan is not a
// sweep, so it must not overwrite the sweep summary or its last_success stamp.
func (c *Collector) BeginOne(ctx context.Context, domainID int64) (target, error) {
	item, err := c.lookupTarget(ctx, domainID)
	if err != nil {
		return target{}, err
	}
	if err := c.acquireSlot([]int64{domainID}); err != nil {
		return target{}, err
	}
	return item, nil
}

// RunOne inspects the one domain BeginOne resolved and releases the slot. Call
// it in a goroutine on its OWN context: a single-domain scan still reaches the
// feeds and can take longer than the request that asked for it.
func (c *Collector) RunOne(ctx context.Context, item target) error {
	defer c.release()
	_, err := c.scanDomain(ctx, item)
	return err
}

// scan does the work. It returns what it counted even when it fails, so a
// partial sweep is reported as partial rather than lost.
func (c *Collector) scan(ctx context.Context) (tally, error) {
	var counts tally

	rows, err := c.DB.QueryContext(ctx,
		`SELECT id, domain_name, system_user FROM domains
		  WHERE parent_domain_id IS NULL AND system_user LIKE 'c\\_%'
		  ORDER BY id`)
	if err != nil {
		return counts, err
	}
	var targets []target
	for rows.Next() {
		var item target
		if err := rows.Scan(&item.id, &item.name, &item.systemUser); err != nil {
			_ = rows.Close()
			return counts, err
		}
		targets = append(targets, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return counts, err
	}
	_ = rows.Close()

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
	)
	slots := make(chan struct{}, domainWorkers)
	for _, item := range targets {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(item target) {
			defer wg.Done()
			defer func() { <-slots }()
			partial, err := c.scanDomain(ctx, item)
			mu.Lock()
			counts.domains++
			counts.packages += partial.packages
			counts.unparsed += partial.unparsed
			counts.findings += partial.findings
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(item)
	}
	wg.Wait()

	// A sweep that ran out of its budget is FAILED, whatever it managed to
	// write. The alternative reports a partial pass as a clean one.
	if ctx.Err() != nil {
		return counts, fmt.Errorf("the scan ran out of its budget after %d domain(s)", counts.domains)
	}
	return counts, firstErr
}

// scanResult is what one source produced for one domain: what it counted, the
// vulnerabilities it found, and the installations it looked at. The last is
// returned even when the first two are empty, because "this was inspected and
// is clean" is the answer the inventory exists to give.
type scanResult struct {
	counts   tally
	findings []Finding
	apps     []Inventory
}

// scanDomain inspects one domain and writes what it finds.
//
// A failure in one of the three sources does not stop the other two: a broken
// WordPress installation must not hide a vulnerable npm dependency in the same
// home.
func (c *Collector) scanDomain(ctx context.Context, item target) (tally, error) {
	var counts tally
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	seen := map[string]bool{}
	// perInstall counts DISTINCT findings per installation, off the same merge
	// key the total uses, so an advisory reported by both feeds is counted once
	// in the inventory row and once in the sweep total rather than twice in one
	// and once in the other.
	perInstall := map[string]int{}
	record := func(findings []Finding) {
		for _, finding := range findings {
			key, err := c.upsert(ctx, item.id, finding)
			if err != nil {
				note(err)
				continue
			}
			if !seen[key] {
				seen[key] = true
				counts.findings++
				perInstall[installKey(finding.AppType, finding.InstallPath)]++
			}
		}
	}

	var apps []Inventory

	wp, err := c.scanWordPress(ctx, item)
	note(err)
	counts.packages += wp.counts.packages
	counts.unparsed += wp.counts.unparsed
	apps = append(apps, wp.apps...)
	record(wp.findings)

	locks, err := c.scanLockfiles(ctx, item)
	note(err)
	counts.packages += locks.counts.packages
	counts.unparsed += locks.counts.unparsed
	apps = append(apps, locks.apps...)
	record(locks.findings)

	for i := range apps {
		apps[i].Findings = perInstall[installKey(apps[i].AppType, apps[i].InstallPath)]
	}
	// The inventory is written LAST, so its finding counts are the ones this
	// pass actually recorded, and the prune only runs when nothing above it
	// failed. A write failure here is surfaced rather than logged and dropped:
	// an inventory nobody could write is the state this feature exists to make
	// visible, so it must not itself go missing quietly.
	note(c.recordInventory(ctx, item.id, apps, firstErr == nil))

	return counts, firstErr
}

// Finding is one row about to be written.
type Finding struct {
	AppType     string
	InstallPath string
	Package     string
	Installed   string
	Advisory    Advisory
}

// upsert writes one finding and returns its merge key.
//
// first_seen is deliberately NOT touched on the update, so a finding that has
// been present for months reads differently from one that appeared today.
func (c *Collector) upsert(ctx context.Context, domainID int64, finding Finding) (string, error) {
	key := findingKey(domainID, finding.InstallPath, finding.Package, finding.Advisory.ID)
	var cvss any
	if finding.Advisory.CVSS > 0 {
		cvss = finding.Advisory.CVSS
	}
	_, err := c.DB.ExecContext(ctx,
		`INSERT INTO security_findings
		   (finding_key, domain_id, app_type, install_path, package_name,
		    installed_version, cve_id, severity, cvss, title, fixed_in, source)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		   installed_version=VALUES(installed_version), severity=VALUES(severity),
		   cvss=VALUES(cvss), title=VALUES(title), fixed_in=VALUES(fixed_in),
		   source=VALUES(source), last_seen=NOW()`,
		key, domainID, finding.AppType, truncate(finding.InstallPath, 512),
		truncate(finding.Package, 255), truncate(finding.Installed, 64),
		truncate(finding.Advisory.ID, 64), truncate(finding.Advisory.Severity, 16),
		cvss, truncate(finding.Advisory.Title, 512),
		truncate(finding.Advisory.FixedIn, 64), truncate(finding.Advisory.Source, 255))
	return key, err
}

// truncate bounds a value to its column. A feed that grows a longer field must
// not fail the whole write.
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// scanWordPress inspects every WordPress installation of one tenant.
func (c *Collector) scanWordPress(ctx context.Context, item target) (scanResult, error) {
	var result scanResult
	var firstErr error

	for _, install := range wordpress.Discover(item.systemUser) {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// The installation is recorded whether or not its version can be read
		// and whether or not anything is found in it: wp-config.php is there, so
		// this is a WordPress site the sweep looked at.
		entry := Inventory{AppType: AppWordPress, InstallPath: install.Rel}

		if version, err := wordpress.CoreVersion(item.systemUser, install.Dir); err == nil && version != "" {
			entry.Version = version
			entry.Packages++
			result.counts.packages++
			advisories, judged, err := c.WordPressAdvisories(ctx, "core", version, version)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if !judged {
				result.counts.unparsed++
			}
			for _, advisory := range advisories {
				result.findings = append(result.findings, Finding{
					AppType: AppWordPress, InstallPath: install.Rel,
					Package: "wordpress", Installed: version, Advisory: advisory,
				})
			}
		}

		for _, kind := range []string{"plugin", "theme"} {
			components, err := wordpress.Components(ctx, item.systemUser, install.Dir, kind)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s list for %s: %w", kind, item.name, err)
				}
				continue
			}
			for _, component := range components {
				if ctx.Err() != nil {
					result.apps = append(result.apps, entry)
					return result, ctx.Err()
				}
				entry.Packages++
				result.counts.packages++
				advisories, judged, err := c.WordPressAdvisories(ctx, kind, component.Name, component.Version)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				if !judged {
					result.counts.unparsed++
				}
				for _, advisory := range advisories {
					result.findings = append(result.findings, Finding{
						AppType:     AppWordPress,
						InstallPath: install.Rel,
						Package:     kind + ":" + component.Name,
						Installed:   component.Version,
						Advisory:    advisory,
					})
				}
			}
		}
		result.apps = append(result.apps, entry)
	}
	return result, firstErr
}

// lockfileSources are the dependency lists this reads, relative to the tenant
// home. The depth matches the WordPress discovery: the document root and one
// directory below it.
var lockfileSources = []struct {
	file      string
	ecosystem string
	appType   string
	parse     func([]byte) ([]Package, error)
}{
	{"package-lock.json", ecosystemNPM, AppNodeJS, ParseNPMLock},
	{"composer.lock", ecosystemPackagist, AppComposer, ParseComposerLock},
}

// scanLockfiles inspects the npm and Composer dependency lists of one tenant.
//
// The files belong to the tenant, so every read goes through files.OpenBeneath
// semantics (openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS): a link planted
// anywhere in the path cannot redirect this root-privileged read at a file
// outside the home.
func (c *Collector) scanLockfiles(ctx context.Context, item target) (scanResult, error) {
	var result scanResult
	var firstErr error

	home := "/home/" + item.systemUser
	directories := []string{"public_html"}
	names, err := files.ListNamesBeneath(home, "public_html")
	if err != nil {
		firstErr = err
	}
	for _, name := range names {
		directories = append(directories, "public_html/"+name)
	}

	for _, dir := range directories {
		for _, source := range lockfileSources {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			body, err := files.ReadFileBeneath(home, dir+"/"+source.file, maxLockfileBytes)
			if err != nil {
				// An absent lockfile is the normal case for most sites, so it
				// is not an error worth reporting.
				continue
			}
			packages, err := source.parse(body)
			if err != nil {
				// A malformed lockfile drops that INSTALLATION, never the
				// sweep. It is the tenant's file and they can break it. No
				// inventory row is written either: the dependency list could
				// not be read, so claiming the installation was inspected would
				// be the false reassurance this record exists to prevent, and
				// the error above stops the prune from removing what was known.
				if firstErr == nil {
					firstErr = fmt.Errorf("%s under %s: %w", source.file, item.name, err)
				}
				continue
			}
			result.counts.packages += len(packages)
			rel := strings.TrimPrefix(dir, "public_html")
			if rel == "" {
				rel = "/"
			}
			result.apps = append(result.apps, Inventory{
				AppType: source.appType, InstallPath: rel, Packages: len(packages),
			})

			affected, err := c.AffectedPackages(ctx, source.ecosystem, packages)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for _, pkg := range affected {
				advisories, err := c.Advisories(ctx, source.ecosystem, pkg)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				for _, advisory := range advisories {
					result.findings = append(result.findings, Finding{
						AppType:     source.appType,
						InstallPath: rel,
						Package:     pkg.Name,
						Installed:   pkg.Version,
						Advisory:    advisory,
					})
				}
			}
		}
	}
	return result, firstErr
}
