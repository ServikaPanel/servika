package datamigrate

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"servika/internal/git"
	"servika/internal/secret"
)

// The webhook backfill seals a delivery token that was written in the clear and
// fills the digest the delivery path looks the row up by. It runs at EVERY
// boot, so a converged database must be left alone, and a row it cannot open
// must be left as it is rather than half written.

// A cleartext token is sealed against its OWN domain and its digest is written
// beside it, so a ciphertext lifted from one repository does not open in
// another's row.
func TestACleartextWebhookTokenIsSealedAgainstItsOwnDomain(t *testing.T) {
	initSecret(t)
	captureLog(t)
	script := &backfillScript{rows: [][]driver.Value{{int64(4), int64(7), "0123456789abcdef0123", ""}}}

	SealGitWebhookSecrets(context.Background(), backfillDB(t, script))

	got := script.argsOf(t, 0)
	if len(got) != 4 || got[2] != int64(4) || got[3] != "0123456789abcdef0123" {
		t.Fatalf("write args = %v, want the old value matched on repository 4", got)
	}
	sealed, _ := got[0].(string)
	if !secret.IsEncrypted(sealed) {
		t.Fatalf("the written value is not sealed: %q", sealed)
	}
	if back, err := git.OpenWebhookSecret(sealed, 7); err != nil || back != "0123456789abcdef0123" {
		t.Errorf("open on its own domain = %q, %v", back, err)
	}
	if _, err := git.OpenWebhookSecret(sealed, 8); err == nil {
		t.Error("the ciphertext opened under another domain")
	}
	if got[1] != git.WebhookSecretHash("0123456789abcdef0123") {
		t.Errorf("digest = %v, want the digest of the token", got[1])
	}
}

// A row that is already sealed AND already carries its digest is left alone, so
// the pass costs one query on every boot after it converges.
func TestAConvergedWebhookRowIsLeftAlone(t *testing.T) {
	initSecret(t)
	captureLog(t)
	sealed, err := git.SealWebhookSecret("0123456789abcdef0123", 7)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	script := &backfillScript{rows: [][]driver.Value{
		{int64(4), int64(7), sealed, git.WebhookSecretHash("0123456789abcdef0123")},
	}}

	SealGitWebhookSecrets(context.Background(), backfillDB(t, script))

	if len(script.execs) != 0 {
		t.Errorf("a converged row was rewritten: %v", script.execs)
	}
}

// A row sealed for ANOTHER domain cannot be opened, so it is left as it is. A
// token the panel can no longer open is worse than one still in the clear: the
// hook registered at the remote keeps delivering to a URL nothing matches.
func TestAWebhookRowThatCannotBeOpenedIsLeftAsItIs(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	elsewhere, err := git.SealWebhookSecret("0123456789abcdef0123", 99)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	script := &backfillScript{rows: [][]driver.Value{{int64(4), int64(7), elsewhere, ""}}}

	SealGitWebhookSecrets(context.Background(), backfillDB(t, script))

	if len(script.execs) != 0 {
		t.Errorf("an unopenable row was written: %v", script.execs)
	}
	if !strings.Contains(logged.String(), "could not open the token of repository 4") {
		t.Errorf("the refusal was not reported: %s", logged)
	}
}

// A pass that could not read the whole list says so, because the count it logs
// would otherwise read as a complete conversion.
func TestAShortWebhookListIsReported(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{
		rows:   [][]driver.Value{{int64(4), int64(7), "0123456789abcdef0123", ""}},
		rowErr: errors.New("connection lost"),
	}

	SealGitWebhookSecrets(context.Background(), backfillDB(t, script))

	if !strings.Contains(logged.String(), "could not read the whole list") {
		t.Errorf("a truncated list was not reported: %s", logged)
	}
}

// A table that cannot be read at all stops the pass rather than reporting a
// conversion that never ran.
func TestAnUnreadableWebhookTableStopsThePass(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{queryErr: errors.New("no such column")}

	SealGitWebhookSecrets(context.Background(), backfillDB(t, script))

	if len(script.execs) != 0 {
		t.Errorf("a write ran although the table could not be read: %v", script.execs)
	}
	if !strings.Contains(logged.String(), "could not read git_repos") {
		t.Errorf("the read failure was not reported: %s", logged)
	}
}
