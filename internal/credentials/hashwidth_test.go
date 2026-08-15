package credentials

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestFTPPasswordHashFitsItsColumn is the regression guard for a defect that
// made FTP unusable on every domain: password_md5 was created VARCHAR(64) when
// the column really held an MD5, and the panel now writes a 106-character
// SHA-512-crypt hash into it. Every INSERT failed with "Error 1406: Data too
// long", and the caller only logged it, so domains were created and handed the
// user an FTP password for an account that did not exist.
//
// The check is against the migrations rather than a live schema, so it fails on
// a laptop before it can reach a server.
func TestFTPPasswordHashFitsItsColumn(t *testing.T) {
	hash, err := HashPassword("a-representative-password")
	if err != nil {
		t.Skipf("openssl is unavailable: %v", err)
	}
	if !IsHashed(hash) {
		t.Fatalf("HashPassword produced %q, which is not a $6$ hash", hash)
	}

	width := columnWidth(t, "ftp_accounts", "password_md5")
	if width < len(hash) {
		t.Fatalf("password_md5 is VARCHAR(%d) but the hash the panel writes is %d characters (%q); "+
			"every FTP account INSERT fails or is silently truncated", width, len(hash), hash)
	}
}

// TestPanelPasswordHashFitsItsColumn covers the same class for the panel login
// hash, which is bcrypt rather than SHA-512-crypt.
func TestPanelPasswordHashFitsItsColumn(t *testing.T) {
	const bcryptLength = 60 // $2a$<cost>$<22-char salt><31-char digest>
	if width := columnWidth(t, "users", "password_hash"); width < bcryptLength {
		t.Fatalf("users.password_hash is VARCHAR(%d) but a bcrypt hash is %d characters", width, bcryptLength)
	}
}

// columnWidth returns the VARCHAR width a column has after all migrations, which
// is the width declared by the LAST migration that mentions it.
func columnWidth(t *testing.T, table, column string) int {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	// Migrations are numbered and applied in name order, so the last file that
	// declares the column is the one that decides its width.
	sort.Strings(names)

	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(column) + `\s+VARCHAR\((\d+)\)`)
	width := 0
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- repository-local migrations directory.
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// A migration that only mentions the column in a comment must not count,
		// so only statement lines are considered.
		for line := range strings.SplitSeq(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			if match := pattern.FindStringSubmatch(line); match != nil {
				parsed, convErr := strconv.Atoi(match[1])
				if convErr == nil {
					width = parsed
				}
			}
		}
	}
	if width == 0 {
		t.Fatalf("no VARCHAR declaration for %s.%s was found in migrations/", table, column)
	}
	return width
}
