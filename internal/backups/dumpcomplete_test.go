package backups

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDump(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.sql")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	return p
}

// A dump is trusted only when it ends with mysqldump's completion marker, so a
// truncated dump (killed client, full disk) is rejected even though it has
// bytes.
func TestDumpCompleteRequiresTheMarker(t *testing.T) {
	full := "CREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\n-- Dump completed on 2026-08-26 12:00:00\n"
	if !dumpComplete(writeDump(t, full)) {
		t.Error("a complete dump was rejected")
	}
	truncated := "CREATE TABLE t (id INT);\nINSERT INTO t VALUES (1),(2),(3" // cut off mid-statement
	if dumpComplete(writeDump(t, truncated)) {
		t.Error("a truncated dump was accepted")
	}
	if dumpComplete(writeDump(t, "")) {
		t.Error("an empty dump was accepted")
	}
	// The marker must be found even when it sits far past a 512-byte tail window's
	// start, so a large dump is still recognized.
	big := strings.Repeat("INSERT INTO t VALUES (1);\n", 2000) + "-- Dump completed on 2026-08-26 12:00:00\n"
	if !dumpComplete(writeDump(t, big)) {
		t.Error("a large complete dump was rejected")
	}
}
