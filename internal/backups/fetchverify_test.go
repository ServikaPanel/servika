package backups

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArchive lays down a file and returns its path and sha256.
func writeArchive(t *testing.T, body string) (path, digest string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the archive: %v", err)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("hash the archive: %v", err)
	}
	return path, digest
}

// The fetch path accepted an archive on its byte count alone. The destination is
// a third-party host the customer or operator configured, an FTP destination
// runs plaintext and unauthenticated on the wire, and padding a substituted
// archive to the recorded size is trivial. What arrives is extracted as root,
// rsynced into the tenant's home and imported as SQL.
func TestASubstitutedArchiveOfTheRightSizeIsRefused(t *testing.T) {
	path, digest := writeArchive(t, "the real archive bytes")

	// Same length, different content: the size check cannot tell them apart.
	substituted := "THE FAKE ARCHIVE BYTES"
	if len(substituted) != len("the real archive bytes") {
		t.Fatalf("the test's substitute is %d bytes, not %d", len(substituted), len("the real archive bytes"))
	}
	if err := os.WriteFile(path, []byte(substituted), 0o600); err != nil {
		t.Fatalf("write the substitute: %v", err)
	}

	if err := verifyDownloaded(path, int64(len(substituted))); err != nil {
		t.Fatalf("the size check refused a file of the recorded size: %v", err)
	}
	err := verifyFetched(path, int64(len(substituted)), digest)
	if err == nil {
		t.Fatal("a substituted archive of the recorded size was accepted")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("the refusal does not name the digest: %v", err)
	}
	// A refused archive is removed, or the next read path finds it on disk and
	// skips the fetch entirely.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("the refused archive was left on disk")
	}
}

// The genuine archive still passes, so the check is not simply refusing
// everything.
func TestTheRecordedArchiveIsAccepted(t *testing.T) {
	path, digest := writeArchive(t, "the real archive bytes")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := verifyFetched(path, info.Size(), digest); err != nil {
		t.Fatalf("the recorded archive was refused: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("an accepted archive was removed")
	}
}

// A row written before the column existed carries no digest. It keeps the size
// check it always had rather than becoming unrestorable.
func TestARowWithNoRecordedDigestKeepsTheSizeCheck(t *testing.T) {
	path, _ := writeArchive(t, "legacy archive")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := verifyFetched(path, info.Size(), ""); err != nil {
		t.Fatalf("a legacy row was refused: %v", err)
	}
	// The size check still bites.
	if err := verifyFetched(path, info.Size()+1, ""); err == nil {
		t.Fatal("a truncated legacy archive was accepted")
	}
}

// The size check runs first, so a truncated transfer is reported as truncated
// rather than as a digest mismatch: the two say different things to an operator.
func TestATruncatedTransferIsReportedAsIncomplete(t *testing.T) {
	path, digest := writeArchive(t, "short")

	err := verifyFetched(path, 4096, digest)
	if err == nil {
		t.Fatal("a truncated archive was accepted")
	}
	if strings.Contains(err.Error(), "sha256") {
		t.Fatalf("a truncated transfer was reported as a digest mismatch: %v", err)
	}
}

// Every read path passes through ensureLocalArchive, so the digest has to be
// applied to BOTH destinations it can fetch from.
func TestBothFetchBranchesVerifyTheDigest(t *testing.T) {
	body := readSource(t, "destination.go")
	fetch := functionSource(t, body, "func ensureLocalArchive(")

	if !strings.Contains(fetch, "expectedBackupDigest(") {
		t.Fatal("the fetch path never reads the recorded digest")
	}
	if got := strings.Count(fetch, "verifyFetched(abs, expected, digest)"); got != 2 {
		t.Fatalf("%d of the two fetch branches verify the digest, want both", got)
	}
	// The weaker check must not remain as a branch's own gate.
	if strings.Contains(fetch, "verifyDownloaded(abs, expected) == nil") {
		t.Fatal("a fetch branch still accepts an archive on its size alone")
	}
}

// The integrity scan already hashed the archive and recorded that it does not
// match, and raised a critical notification about it. Applying it over a live
// site anyway ignores the panel's own evidence.
func TestARestoreFromACorruptArchiveNeedsAnOverride(t *testing.T) {
	restore := functionSource(t, readSource(t, "restore.go"), "func (h *Handlers) Restore(")
	if !strings.Contains(restore, `verification == "corrupt"`) {
		t.Fatal("the restore endpoint does not consult the recorded verification")
	}
	if !strings.Contains(restore, "req.AllowCorrupt") {
		t.Fatal("the restore endpoint has no explicit override")
	}

	// A bulk job carries no per-item confirmation, so it refuses outright.
	bulk := functionSource(t, readSource(t, "jobs.go"), "func restoreCore(")
	if !strings.Contains(bulk, `verification == "corrupt"`) {
		t.Fatal("the bulk restore path does not consult the recorded verification")
	}
	if strings.Contains(bulk, "AllowCorrupt") {
		t.Fatal("the bulk restore path carries an override it cannot have confirmed")
	}
}
