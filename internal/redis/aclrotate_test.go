package redis

import (
	"os"
	"strings"
	"testing"
)

// ACL SETUSER MERGES into the existing rule set, and the `>` verb ADDS a
// password to the user's list rather than replacing it. Without resetpass every
// password ever issued to a tenant's ACL user stays valid, while the panel
// stores only the newest one: re-issuing looked like a rotation and revoked
// nothing.
//
// That matters because the credential lives in cleartext in the tenant's
// wp-config.php, one of the most commonly disclosed files on a compromised
// WordPress site. After a disclosure there was no way to invalidate the leaked
// value short of deleting the ACL user, which takes the object cache down.
//
// Measured against Valkey 8: two SETUSER calls without resetpass leave two
// hashes in ACL GETUSER and both authenticate; with resetpass exactly one
// remains, the earlier ones answer WRONGPASS, and the key and channel scopes
// are unchanged.
func TestTheACLCommandRevokesEveryEarlierPassword(t *testing.T) {
	body := readRedisSource(t, "redis.go")
	enable := redisFunction(t, body, "func enableUser(")

	if !strings.Contains(enable, `"resetpass"`) {
		t.Fatal("the ACL command does not clear the password list, so every password ever issued stays valid")
	}
	// Before the new password: resetpass after `>` would clear the one just set.
	reset := strings.Index(enable, `"resetpass"`)
	add := strings.Index(enable, `">" + password`)
	if add < 0 {
		t.Fatal("the ACL command no longer sets a password; this test is out of date")
	}
	if reset > add {
		t.Error("resetpass runs after the new password, so it clears the password it just set")
	}
	// The scopes still reset too, or this change traded one unbounded list for
	// another.
	for _, verb := range []string{`"resetkeys"`, `"resetchannels"`} {
		if !strings.Contains(enable, verb) {
			t.Errorf("the ACL command no longer carries %s", verb)
		}
	}
}

// The ops script builds the same command and is re-run by an operator repairing
// a site, so it has to carry the same verb.
func TestTheOpsScriptAlsoRevokesEveryEarlierPassword(t *testing.T) {
	body, err := os.ReadFile("../../assets/ops/servika-wp-redis.sh")
	if err != nil {
		t.Fatalf("read the ops script: %v", err)
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		if !strings.Contains(line, "ACL SETUSER") {
			continue
		}
		if !strings.Contains(line, "resetpass") {
			t.Errorf("the ops script re-issues a password without revoking the earlier ones: %s",
				strings.TrimSpace(line))
		}
		if strings.Index(line, "resetpass") > strings.Index(line, ">$PASS") {
			t.Error("resetpass runs after the new password in the ops script")
		}
	}
}

func readRedisSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// redisFunction returns one function's body, from its signature to the closing
// brace in the first column.
func redisFunction(t *testing.T, source, signature string) string {
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
