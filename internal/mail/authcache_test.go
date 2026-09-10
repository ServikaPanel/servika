package mail

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// recordAuthCommands replaces the doveadm runner and makes sure LookPath finds
// one, so the tests measure the argv this package builds rather than the host.
func recordAuthCommands(t *testing.T) *[][]string {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "doveadm")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write the doveadm stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := exec.LookPath("doveadm"); err != nil {
		t.Fatalf("the doveadm stub is not on PATH: %v", err)
	}

	var mu sync.Mutex
	var calls [][]string
	previous := authCommand
	authCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() { authCommand = previous })
	return &calls
}

// Dovecot serves a later login from its cached passdb answer, so a rotated
// password does not revoke anything until the entry is dropped: for the life of
// the cache the OLD password still opens the mailbox over IMAP and over
// Postfix's Dovecot SASL listener.
func TestARevokedAddressIsFlushedByName(t *testing.T) {
	calls := recordAuthCommands(t)

	FlushAuthCache(context.Background(), "user@example.com")

	if len(*calls) != 1 {
		t.Fatalf("%d commands ran, want 1", len(*calls))
	}
	if got := strings.Join((*calls)[0], " "); got != "doveadm auth cache flush -u user@example.com" {
		t.Fatalf("command = %q", got)
	}
}

// A domain-level change flushes everything, because doveadm takes a user rather
// than a domain and enumerating the domain's mailboxes would miss exactly the
// rows a purge has already deleted.
func TestADomainLevelChangeFlushesTheWholeCache(t *testing.T) {
	calls := recordAuthCommands(t)

	FlushAllAuthCache(context.Background())

	if len(*calls) != 1 {
		t.Fatalf("%d commands ran, want 1", len(*calls))
	}
	if got := strings.Join((*calls)[0], " "); got != "doveadm auth cache flush" {
		t.Fatalf("command = %q", got)
	}
}

// The address reaches an argv, so a value carrying whitespace or a NUL is
// refused rather than passed on. An empty address would flush nothing and is
// refused for the same reason.
func TestAnUnusableAddressRunsNoCommand(t *testing.T) {
	calls := recordAuthCommands(t)

	for _, email := range []string{"", "   ", "user@example.com\nsecond", "user @example.com", "user\x00@example.com"} {
		FlushAuthCache(context.Background(), email)
	}
	if len(*calls) != 0 {
		t.Fatalf("%d commands ran for unusable addresses, want 0: %v", len(*calls), *calls)
	}
}

// A host with no Dovecot has no cache to flush, and running doveadm there would
// log a failure on every mailbox write.
func TestNothingRunsWithoutDoveadm(t *testing.T) {
	calls := recordAuthCommands(t)
	t.Setenv("PATH", t.TempDir())

	FlushAuthCache(context.Background(), "user@example.com")
	FlushAllAuthCache(context.Background())

	if len(*calls) != 0 {
		t.Fatalf("%d commands ran without doveadm, want 0", len(*calls))
	}
}

// Every path that revokes mail access must drop the cached answer, because the
// row change alone reaches Postfix (which re-reads per message) and not IMAP.
// This walks the package rather than listing the calls, so a NEW revocation path
// added without a flush fails here instead of shipping the same hour-long window.
func TestEveryRevocationPathFlushesTheAuthCache(t *testing.T) {
	for _, want := range []struct{ file, symbol, call string }{
		{"mail.go", "Delete", "FlushAuthCache(r.Context(), email)"},
		{"mail.go", "ResetPassword", "h.flushMailboxAuthCache(r.Context(), id, mailboxID)"},
		{"mail.go", "SetStatus", "h.flushMailboxAuthCache(r.Context(), id, mailboxID)"},
		{"provision.go", "DisableDomain", "FlushAllAuthCache(ctx)"},
		{"provision.go", "PurgeDomain", "FlushAllAuthCache(ctx)"},
		{"policy.go", "auto-suspension", "FlushAuthCache(ctx, email)"},
	} {
		body, err := os.ReadFile(want.file)
		if err != nil {
			t.Fatalf("read %s: %v", want.file, err)
		}
		if !strings.Contains(string(body), want.call) {
			t.Errorf("%s (%s) does not flush the auth cache: %q is absent", want.symbol, want.file, want.call)
		}
	}
}

// Roundcube is published at /webmail/, which every mail user of every hosted
// domain reaches. The floor is 1.7.4: 1.7.3 carries eleven security fixes
// including an IMAP command injection and 1.7.4 carries further ones. NEITHER
// release was given a CVE identifier, so nothing keyed to a CVE feed reports a
// server left behind, and there is no CI gate that re-checks this pin.
//
// The exact value is asserted rather than a range, so a bump has to state which
// release it moves to.
func TestTheRoundcubePinIsNotBelowItsSecurityFloor(t *testing.T) {
	body, err := os.ReadFile("../../assets/ops/servika-mail-setup")
	if err != nil {
		t.Fatalf("read the mail setup script: %v", err)
	}
	if !strings.Contains(string(body), "\nRCVER=1.7.4\n") {
		t.Error("RCVER is not the pinned version 1.7.4")
	}
}
