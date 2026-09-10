package backups

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// A domain's home directory and its schemas are what every backup and every
// restore mutates. Two rsync passes, or a tar reading a tree an rsync --delete
// is rewriting, leave the document root and the database in an undefined mixed
// state while both operations report success.
func TestOneDomainIsHeldByOneOperation(t *testing.T) {
	const domain = int64(4242)

	release, ok := lockDomain(domain)
	if !ok {
		t.Fatal("the first claim was refused on a free domain")
	}
	if _, second := lockDomain(domain); second {
		t.Fatal("a second operation claimed a domain that is already held")
	}
	if !domainLocked(domain) {
		t.Fatal("the domain does not report itself held")
	}

	release()
	if domainLocked(domain) {
		t.Fatal("the domain is still held after its release")
	}
	release2, ok := lockDomain(domain)
	if !ok {
		t.Fatal("a released domain could not be claimed again")
	}
	release2()
}

// Two domains are two trees, so one must not block the other.
func TestTheLockIsPerDomain(t *testing.T) {
	first, ok := lockDomain(1)
	if !ok {
		t.Fatal("domain 1 was refused")
	}
	t.Cleanup(first)
	second, ok := lockDomain(2)
	if !ok {
		t.Fatal("domain 2 was refused while domain 1 was held")
	}
	t.Cleanup(second)
}

// The claim decides and stores in ONE step. The guard it replaces was a check
// followed by a separate write, which two callers arriving together can both
// pass. Run with -race.
func TestExactlyOneOfManyConcurrentClaimsWins(t *testing.T) {
	const domain = int64(99)
	var mu sync.Mutex
	won := 0
	var releases []func()

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if release, ok := lockDomain(domain); ok {
				mu.Lock()
				won++
				releases = append(releases, release)
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if won != 1 {
		t.Fatalf("%d of 32 concurrent claims won, want exactly 1", won)
	}
	for _, release := range releases {
		release()
	}
}

// Releasing twice must not free a claim a LATER operation now holds.
func TestAReleaseIsIdempotent(t *testing.T) {
	const domain = int64(7)
	release, ok := lockDomain(domain)
	if !ok {
		t.Fatal("the claim was refused")
	}
	release()

	next, ok := lockDomain(domain)
	if !ok {
		t.Fatal("the domain could not be claimed after its release")
	}
	t.Cleanup(next)

	release() // the first holder's stale release
	if !domainLocked(domain) {
		t.Fatal("a stale release freed a claim the next operation holds")
	}
}

// The lock has to sit at the chokepoints every producer goes through, or a path
// added later is uncovered. backupOneDomain is reached by the manual handler's
// siblings, the bulk job and the scheduler; restoreCore by the bulk restore job.
func TestEveryMutatingPathClaimsTheDomain(t *testing.T) {
	jobs := readSource(t, "jobs.go")

	for _, function := range []string{"func backupOneDomain(", "func restoreCore("} {
		body := functionSource(t, jobs, function)
		if !strings.Contains(body, "lockDomain(domainID)") {
			t.Errorf("%s does not claim the domain it mutates", function)
		}
		if !strings.Contains(body, "defer release()") {
			t.Errorf("%s does not release its claim", function)
		}
	}

	// The two HTTP handlers do not go through those chokepoints, so they claim
	// for themselves.
	if !strings.Contains(readSource(t, "restore.go"), "lockDomain(id)") {
		t.Error("the single-domain restore endpoint does not claim the domain")
	}
	if !strings.Contains(readSource(t, "backups.go"), "lockDomain(id)") {
		t.Error("the manual backup endpoint does not claim the domain")
	}
}

// The guard this replaces excluded only another BACKUP, so a backup could start
// while a restore was rewriting the same tree. Nothing may reintroduce it.
func TestTheBackupOnlyGuardIsGone(t *testing.T) {
	for _, name := range []string{"backups.go", "jobs.go", "restore.go", "schedule.go"} {
		if strings.Contains(readSource(t, name), "backupInProgress") {
			t.Errorf("%s still uses the backup-only guard", name)
		}
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// functionSource returns one function's body, from its signature to the closing
// brace in the first column.
func functionSource(t *testing.T, source, signature string) string {
	t.Helper()
	at := strings.Index(source, signature)
	if at < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}

// A busy domain is reported as busy rather than as a generic failure, so an
// operator reading a partial bulk job knows why a domain was skipped.
func TestABusyDomainIsNamedAsBusy(t *testing.T) {
	if !regexp.MustCompile(`already running for this domain`).MatchString(ErrDomainBusy.Error()) {
		t.Fatalf("ErrDomainBusy says %q", ErrDomainBusy.Error())
	}
}
