package laravel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The editor reads the .env, the operator edits it and the answer replaces the
// file through tee. The read stopped at two megabytes and returned what fit
// with no signal, so a normal read-modify-write in the UI dropped everything
// past that point and the panel reported success.

// envFile writes a .env of n bytes and returns its directory.
func envFile(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	body := []byte(strings.Repeat("A", n))
	if err := os.WriteFile(filepath.Join(dir, ".env"), body, 0o600); err != nil {
		t.Fatalf("write the .env: %v", err)
	}
	return dir
}

// A file at the cap still opens; the cap is a ceiling, not a barrier.
func TestAnEnvAtTheCapIsReadWhole(t *testing.T) {
	content, err := readEnvFile(envFile(t, maxEnvBytes))
	if err != nil {
		t.Fatalf("a .env at the cap was refused: %v", err)
	}
	if len(content) != maxEnvBytes {
		t.Errorf("read %d bytes, want %d", len(content), maxEnvBytes)
	}
}

// One byte more is refused rather than cut, which is what stops the save from
// destroying the rest of the file.
func TestAnOversizedEnvIsRefusedRatherThanTruncated(t *testing.T) {
	content, err := readEnvFile(envFile(t, maxEnvBytes+1))
	if !errors.Is(err, errEnvTooLarge) {
		t.Fatalf("err = %v, want errEnvTooLarge", err)
	}
	if content != "" {
		t.Errorf("the truncated content was returned anyway: %d bytes", len(content))
	}
}

// The write bound is the read bound. A file the panel accepts has to be a file
// it can show whole again, or saving once makes the .env uneditable for good.
func TestTheWriteBoundMatchesTheReadBound(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvFile("nobody", dir, strings.Repeat("A", maxEnvBytes+1)); !errors.Is(err, errEnvTooLarge) {
		t.Errorf("err = %v, want errEnvTooLarge", err)
	}
}
