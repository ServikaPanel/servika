package mtasts

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

// The enforce lock is the one control in the panel that can stop mail being
// delivered, so every test here uses a database that CANNOT answer. A gate that
// still refuses under those conditions has been proved to refuse without asking
// anything, and a gate that reaches the soak query proves it ran the checks
// ahead of it first.

var errDBUnavailable = errors.New("connection refused")

type failingConnector struct{}

func (failingConnector) Open(string) (driver.Conn, error) { return nil, errDBUnavailable }

func init() { sql.Register("mtasts_failing_db", failingConnector{}) }

func failingDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mtasts_failing_db", "")
	if err != nil {
		t.Fatalf("open the failing database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// stubMXCert replaces the certificate check for one test.
func stubMXCert(t *testing.T, covers bool) {
	t.Helper()
	original := mxCertCovers
	mxCertCovers = func(string) bool { return covers }
	t.Cleanup(func() { mxCertCovers = original })
}

// A domain that has not reached testing cannot jump to enforce. The sequence is
// what proves the policy is fetchable at all.
func TestEnforceIsRefusedBeforeTesting(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModePendingDNS, ModePendingCert, ModeWithdrawing} {
		stubMXCert(t, true)
		blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
			domainRow{domainName: "example.com", mode: mode}, []string{"mail.example.com"})
		if !blocked || reason != ReasonNotTesting {
			t.Errorf("%s: blocked=%v reason=%q, want blocked with %s", mode, blocked, reason, ReasonNotTesting)
		}
	}
}

// A policy that names no MX host rejects every message in enforce mode, so it
// must never be reachable.
func TestEnforceIsRefusedWithNoMXHost(t *testing.T) {
	stubMXCert(t, true)
	blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
		domainRow{domainName: "example.com", mode: ModeTesting}, nil)
	if !blocked || reason != ReasonMXCertUnset {
		t.Fatalf("blocked=%v reason=%q, want blocked with %s", blocked, reason, ReasonMXCertUnset)
	}
}

// THE security proof. A sender honouring an enforce policy against a mismatched
// MX certificate does not deliver and does not bounce, so the lock has to hold
// on the certificate alone.
//
// The database cannot answer, so reaching the soak query would surface as
// ReasonSoak. Getting ReasonMXCertUnset proves the certificate was checked
// FIRST and that no database answer can unlock it.
func TestEnforceIsRefusedWhenTheCertificateOmitsAnMXHost(t *testing.T) {
	stubMXCert(t, false)
	blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
		domainRow{domainName: "example.com", mode: ModeTesting}, []string{"mail.example.com"})
	if !blocked {
		t.Fatal("enforce was allowed with a certificate that does not name the MX host")
	}
	if reason != ReasonMXCertUnset {
		t.Fatalf("reason = %q, want %s", reason, ReasonMXCertUnset)
	}
}

// One uncovered host among several is still a refusal: a sender picks any MX in
// the policy, so the weakest one decides.
func TestOneUncoveredMXHostRefusesTheWholePolicy(t *testing.T) {
	original := mxCertCovers
	mxCertCovers = func(host string) bool { return host != "backup.example.com" }
	t.Cleanup(func() { mxCertCovers = original })

	blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
		domainRow{domainName: "example.com", mode: ModeTesting},
		[]string{"mail.example.com", "backup.example.com"})
	if !blocked || reason != ReasonMXCertUnset {
		t.Fatalf("blocked=%v reason=%q, want blocked with %s", blocked, reason, ReasonMXCertUnset)
	}
}

// Fail-closed. An unreadable soak timestamp must not unlock enforce.
func TestAnUnreadableSoakRefusesEnforce(t *testing.T) {
	stubMXCert(t, true)
	blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
		domainRow{domainName: "example.com", mode: ModeTesting}, []string{"mail.example.com"})
	if !blocked {
		t.Fatal("enforce was allowed while the soak could not be read")
	}
	if reason != ReasonSoak {
		t.Fatalf("reason = %q, want %s", reason, ReasonSoak)
	}
}

// The certificate gate is non-vacuous in BOTH directions. The two tests above
// share every input except what mxCertCovers answers, and they produce different
// reasons, so the gate is what decided each of them rather than something
// upstream refusing everything.
func TestTheCertificateGateDecidesRatherThanRefusingEverything(t *testing.T) {
	row := domainRow{domainName: "example.com", mode: ModeTesting}
	hosts := []string{"mail.example.com"}

	stubMXCert(t, false)
	_, refusedReason := enforceLock(context.Background(), failingDB(t), 1, row, hosts)

	stubMXCert(t, true)
	_, passedReason := enforceLock(context.Background(), failingDB(t), 1, row, hosts)

	if refusedReason == passedReason {
		t.Fatalf("the gate returned %q either way, so it decides nothing", refusedReason)
	}
	if refusedReason != ReasonMXCertUnset || passedReason != ReasonSoak {
		t.Fatalf("refused=%q passed=%q, want %s then %s",
			refusedReason, passedReason, ReasonMXCertUnset, ReasonSoak)
	}
}

// A domain already in enforce is not asked to soak again, or a certificate
// renewal would read as a fresh publication and lock the control it is already
// past.
func TestADomainAlreadyEnforcingIsNotBlocked(t *testing.T) {
	stubMXCert(t, true)
	blocked, reason := enforceLock(context.Background(), failingDB(t), 1,
		domainRow{domainName: "example.com", mode: ModeEnforce}, []string{"mail.example.com"})
	if blocked {
		t.Fatalf("a domain already in enforce was blocked with %s", reason)
	}
}

// describe never lets a database value reach a log line unchecked.
func TestDescribeRefusesAnUnknownMode(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModePendingDNS, ModePendingCert, ModeTesting, ModeEnforce, ModeWithdrawing} {
		if describe(mode) != string(mode) {
			t.Errorf("%s was not described as itself", mode)
		}
	}
	if got := describe(Mode("testing\ninjected: line")); got == "testing\ninjected: line" {
		t.Errorf("an unknown mode reached the log verbatim: %q", got)
	}
}
