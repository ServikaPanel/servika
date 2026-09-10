package auth

import (
	"strings"
	"testing"

	"servika/internal/secret"
)

func initSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// A seed is all that is needed to generate valid codes indefinitely, so a
// database read must not yield one. Every other stored credential in the panel
// is sealed under SERVIKA_SECRET_KEY; this one was not.
func TestTheStoredSeedIsNotTheSeed(t *testing.T) {
	initSecret(t)
	const seed = "JBSWY3DPEHPK3PXP"

	sealed, err := SealTOTPSecret(seed, 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	if strings.Contains(sealed, seed) {
		t.Fatalf("the sealed value still carries the seed: %q", sealed)
	}
	if !secret.IsEncrypted(sealed) {
		t.Fatalf("the sealed value is not encrypted: %q", sealed)
	}

	opened, err := OpenTOTPSecret(sealed, 7)
	if err != nil {
		t.Fatalf("OpenTOTPSecret: %v", err)
	}
	if opened != seed {
		t.Fatalf("OpenTOTPSecret() = %q, want the seed back", opened)
	}
}

// The AAD binds the seal to one users row. Without it a ciphertext could be
// copied from one row into another, and whoever holds the source account's
// authenticator would then satisfy the target account's second factor.
func TestASealedSeedDoesNotOpenForAnotherUser(t *testing.T) {
	initSecret(t)

	sealed, err := SealTOTPSecret("JBSWY3DPEHPK3PXP", 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}

	if _, err := OpenTOTPSecret(sealed, 8); err == nil {
		t.Fatal("a seed sealed for user 7 opened for user 8")
	}
}

// The seal was introduced after seeds already existed. A value with no
// encryption prefix has to stay usable, or every account that enabled 2FA before
// this change is locked out of its own second factor until the backfill runs.
func TestALegacyCleartextSeedStaysUsable(t *testing.T) {
	initSecret(t)
	const seed = "JBSWY3DPEHPK3PXP"

	opened, err := OpenTOTPSecret(seed, 7)
	if err != nil {
		t.Fatalf("OpenTOTPSecret on a legacy value: %v", err)
	}
	if opened != seed {
		t.Fatalf("OpenTOTPSecret() = %q, want the legacy value unchanged", opened)
	}
}

// A ciphertext that does not open is an error rather than a value, so a caller
// denies instead of verifying a code against something it could not read.
func TestADamagedSealIsAnErrorNotAValue(t *testing.T) {
	initSecret(t)

	if _, err := OpenTOTPSecret("enc:v1:not-base64-at-all!!", 7); err == nil {
		t.Fatal("a damaged seal was accepted")
	}
}

// The sealed form is about 87 characters for a 32-character seed. The column was
// varchar(64), which would truncate it, and a truncated ciphertext never opens
// again.
func TestTheSealedFormFitsTheWidenedColumn(t *testing.T) {
	initSecret(t)

	// The longest seed this panel issues, at the base32 length TOTPGenerateSecret
	// produces, plus headroom.
	sealed, err := SealTOTPSecret(strings.Repeat("A", 64), 999999)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	if len(sealed) > 255 {
		t.Fatalf("the sealed value is %d characters, past the column's 255", len(sealed))
	}
	if len(sealed) <= 64 {
		t.Fatalf("the sealed value is %d characters, so the widening was not needed after all", len(sealed))
	}
}
