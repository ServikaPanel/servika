package git

import (
	"context"
	"database/sql/driver"
	"errors"
	"net/http"
	"strings"
	"testing"

	"servika/internal/secret"
)

// The delivery token is stored sealed and looked up by its digest. These tests
// pin the three properties that makes worth having: the column no longer holds
// the token, the seal does not open on another domain's row, and the delivery
// path matches the digest rather than the token.

// A sealed token opens again, and does not survive a move to another row. The
// AAD carries the domain id, so a ciphertext copied from one repository to
// another is refused rather than opened.
func TestASealedTokenDoesNotOpenUnderAnotherDomain(t *testing.T) {
	sealingKey(t)

	sealed, err := SealWebhookSecret("0123456789abcdef0123", 7)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !secret.IsEncrypted(sealed) {
		t.Fatalf("the sealed value is not sealed: %q", sealed)
	}
	if token, err := OpenWebhookSecret(sealed, 7); err != nil || token != "0123456789abcdef0123" {
		t.Errorf("open on its own row = %q, %v", token, err)
	}
	if _, err := OpenWebhookSecret(sealed, 8); err == nil {
		t.Error("a token sealed for domain 7 opened under domain 8")
	}
}

// A row written before the seal existed carries no prefix and comes back
// unchanged, so a delivery keeps working until the backfill reaches it.
func TestALegacyPlaintextTokenIsReturnedUnchanged(t *testing.T) {
	sealingKey(t)

	token, err := OpenWebhookSecret("the token", 7)
	if err != nil || token != "the token" {
		t.Errorf("open a legacy value = %q, %v", token, err)
	}
}

// The delivery path resolves the repository by the digest of the token in the
// URL. Matching the sealed column instead cannot work: the seal is
// non-deterministic, so the same token seals to a different value every time.
func TestADeliveryLooksTheRepositoryUpByTheDigest(t *testing.T) {
	sealingKey(t)
	script := newScript()
	connectedRepo(script, webhookKey)
	(&pulled{}).install(t)

	recorder := signedPush(t, &Handlers{DB: scriptDB(t, script)})

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	args := queryArgs(t, script, repoLookup)
	if len(args) != 1 || args[0] != WebhookSecretHash(webhookToken) {
		t.Errorf("the repository was looked up with %v, want the digest of the token", args)
	}
	if args[0] == webhookToken {
		t.Error("the delivery matched the token itself")
	}
}

// queryArgs returns the arguments of the one query carrying fragment.
func queryArgs(t *testing.T, script *sqlScript, fragment string) []driver.Value {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, q := range script.queries {
		if strings.Contains(q.query, fragment) {
			return q.args
		}
	}
	t.Fatalf("no query carrying %q ran: %v", fragment, script.steps)
	return nil
}

// StoredWebhookToken answers empty rather than a wrong value when the row is
// missing or its seal cannot be opened, because the caller then generates a
// fresh token and re-registers the hook.
func TestAnUnreadableStoredTokenAnswersEmpty(t *testing.T) {
	sealingKey(t)

	cases := []struct {
		name  string
		rows  [][]driver.Value
		fails error
	}{
		{name: "no row", rows: nil},
		{name: "an empty column", rows: [][]driver.Value{{""}}},
		{name: "a seal that does not open", rows: [][]driver.Value{{"enc:v1:not-a-real-ciphertext"}}},
		{name: "a query that fails", fails: errors.New("gone")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			script := newScript()
			const lookup = "SELECT COALESCE(webhook_secret,'') FROM git_repos WHERE domain_id=?"
			script.rows[lookup] = testCase.rows
			if testCase.fails != nil {
				script.fail[lookup] = testCase.fails
			}

			if token := StoredWebhookToken(context.Background(), scriptDB(t, script), 7); token != "" {
				t.Errorf("token = %q, want empty", token)
			}
		})
	}
}
