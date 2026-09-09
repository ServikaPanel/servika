package redis

import (
	"regexp"
	"strings"
	"testing"

	"servika/internal/secret"
)

func TestGenPass(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{36}$`)
	a, b := genPass(), genPass()
	if !re.MatchString(a) {
		t.Fatalf("genPass() = %q, want 36 lowercase hex chars", a)
	}
	if a == b {
		t.Fatalf("genPass() returned identical values %q", a)
	}
}

func TestSystemUserPattern(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "c_acme", want: true},
		{in: "abc_123", want: true},
		{in: "C_Acme", want: false},
		{in: "", want: false},
		{in: "has-dash", want: false},
		{in: "a.b", want: false},
	}
	for _, test := range tests {
		if got := systemUserPattern.MatchString(test.in); got != test.want {
			t.Fatalf("systemUserPattern.MatchString(%q) = %t, want %t", test.in, got, test.want)
		}
	}
}

func TestWPSnippet(t *testing.T) {
	got := wpSnippet("c_acme", "secret")
	for _, want := range []string{
		"define( 'WP_REDIS_PASSWORD', array( 'c_acme', 'secret' ) );",
		"define( 'WP_REDIS_PREFIX', 'c_acme:' );",
		"define( 'WP_REDIS_HOST', '127.0.0.1' );",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("wpSnippet() missing %q in:\n%s", want, got)
		}
	}
}

// The stored password is sealed against the row's OWN system_user, so a
// ciphertext lifted out of one tenant's row must not open in another's. That
// binding is the whole reason Password reads system_user back from the row
// instead of taking it from its caller.
func TestTheStoredPasswordIsBoundToItsOwnTenant(t *testing.T) {
	if err := secret.Init([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	const password = "0123456789abcdef0123456789abcdef1234"
	sealed, err := secret.EncryptWith(password, "c_alice")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == password {
		t.Fatal("the value was stored in the clear")
	}
	back, err := secret.DecryptWith(sealed, "c_alice")
	if err != nil || back != password {
		t.Fatalf("the owning tenant could not read it back: %q, %v", back, err)
	}
	if _, err := secret.DecryptWith(sealed, "c_bob"); err == nil {
		t.Error("another tenant's system_user opened the value")
	}
}

// A row written before encryption existed carries no prefix, and secret returns
// it unchanged. Without that an install predating this change would answer its
// tenants with an unusable password.
func TestALegacyPlaintextRowStillReadsBack(t *testing.T) {
	if err := secret.Init([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	const legacy = "0123456789abcdef0123456789abcdef1234"
	back, err := secret.DecryptWith(legacy, "c_alice")
	if err != nil || back != legacy {
		t.Fatalf("a legacy plaintext row did not read back: %q, %v", back, err)
	}
}

// SavePassword is the only writer of this column outside the handler, so it is
// what stops a caller from recording an unsealed value or an unvalidated name.
func TestSavePasswordRefusesAnInvalidTenantOrAnEmptyPassword(t *testing.T) {
	if err := secret.Init([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	for _, systemUser := range []string{"", "c_alice; DROP", "../c_alice", strings.Repeat("c", 64)} {
		if err := SavePassword(t.Context(), nil, 1, systemUser, "pw"); err == nil {
			t.Errorf("SavePassword accepted the system user %q", systemUser)
		}
	}
	if err := SavePassword(t.Context(), nil, 1, "c_alice", ""); err == nil {
		t.Error("SavePassword accepted an empty password")
	}
}
