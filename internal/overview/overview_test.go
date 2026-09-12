package overview

import (
	"strings"
	"testing"

	"servika/internal/secret"
)

// The server-wide database list hands out passwords, so revealDBPass has to be
// right in BOTH directions: it must open a row the caller is entitled to, and
// it must produce nothing at all for a row it cannot open. Passing the stored
// value through on failure would publish the ciphertext of a live credential.
func TestRevealDBPass(t *testing.T) {
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}

	const (
		dbUser    = "shop_main"
		plaintext = "S3cret-Passw0rd"
	)
	sealed, err := secret.EncryptWith(plaintext, dbUser)
	if err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}

	t.Run("opens a row under its own database user", func(t *testing.T) {
		if got := revealDBPass(dbUser, sealed); got != plaintext {
			t.Fatalf("revealDBPass = %q, want %q", got, plaintext)
		}
	})

	// The database user is the AEAD associated data, so a ciphertext copied into
	// another account's row will not open. That row must come back blank.
	t.Run("reports blank and leaks nothing under a foreign database user", func(t *testing.T) {
		got := revealDBPass("blog_main", sealed)
		if got != "" {
			t.Fatalf("revealDBPass = %q, want empty", got)
		}
		if strings.Contains(got, sealed) || strings.Contains(got, plaintext) {
			t.Fatalf("revealDBPass leaked the stored value: %q", got)
		}
	})

	t.Run("reports blank for a corrupted stored value", func(t *testing.T) {
		if got := revealDBPass(dbUser, sealed[:len(sealed)-4]+"AAAA"); got != "" {
			t.Fatalf("revealDBPass = %q, want empty", got)
		}
	})

	// Rows written before encryption carry no prefix and are returned unchanged,
	// so an install mid-backfill keeps working.
	t.Run("passes a legacy plaintext row through", func(t *testing.T) {
		if got := revealDBPass(dbUser, "legacy-plaintext"); got != "legacy-plaintext" {
			t.Fatalf("revealDBPass = %q, want the legacy value", got)
		}
	})
}

// assertSizes checks the parsed rows against what the output states.
func assertSizes(t *testing.T, got map[string]int64, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("size mismatch: got %d rows, want %d (%v)", len(got), len(want), got)
	}
	for name, size := range want {
		if got[name] != size {
			t.Errorf("%q = %d, want %d", name, got[name], size)
		}
	}
}

func TestParseDBSizes(t *testing.T) {
	t.Run("well-formed multi-line output", func(t *testing.T) {
		raw := []byte("panel\t512\ntenant_shop\t10240\ntenant_blog\t0\n")
		assertSizes(t, parseDBSizes(raw),
			map[string]int64{"panel": 512, "tenant_shop": 10240, "tenant_blog": 0})
	})

	t.Run("skips malformed lines without dropping valid ones", func(t *testing.T) {
		// A blank line, a line with no tab, a 3-field line, and a non-numeric
		// size must all be skipped while the two valid rows survive.
		raw := []byte("panel\t512\n\nnotabhere\ntoo\tmany\tfields\ntenant\tNaN\ngood\t42")
		assertSizes(t, parseDBSizes(raw), map[string]int64{"panel": 512, "good": 42})
	})

	t.Run("empty output yields empty non-nil map", func(t *testing.T) {
		got := parseDBSizes([]byte("   \n  "))
		if got == nil {
			t.Fatal("map must be non-nil")
		}
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})

	t.Run("trims surrounding whitespace on both fields", func(t *testing.T) {
		got := parseDBSizes([]byte("  spaced_db \t  99  "))
		if got["spaced_db"] != 99 {
			t.Errorf("spaced_db = %d, want 99 (map: %v)", got["spaced_db"], got)
		}
	})
}
