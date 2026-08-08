package mailreport

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// maildirWith builds a Maildir holding one message per body.
func maildirWith(t *testing.T, names []string, bodies []string) string {
	t.Helper()
	root := t.TempDir()
	for _, sub := range []string{"new", "cur", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for i, name := range names {
		path := filepath.Join(root, "new", name)
		if err := os.WriteFile(path, []byte(bodies[i]), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// snapshot records every file under a Maildir with its size, so a test can
// prove nothing was written, renamed or removed.
func snapshot(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, relative+":"+info.ModTime().UTC().String()+":"+
			string(rune('0'+info.Size()%10)))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	slices.Sort(out)
	return out
}

// The panel does not own postmaster@. Reading a report must not delete, move or
// re-flag a message, because people write to that address and the mailbox is
// the customer's.
func TestCollectingDoesNotTouchTheMailbox(t *testing.T) {
	fixedNow(t)
	message := reportMessage(t, aggregateXML("192.0.2.1", "5", "google.com"))
	root := maildirWith(t, []string{"1770000100.abc.host"}, []string{message})

	before := snapshot(t, root)
	names, _, err := newMessages(root, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("names = %d, want 1", len(names))
	}
	raw, err := readMessage(names[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(Attachments(raw)) == 0 {
		t.Fatal("the report attachment was not found")
	}
	if after := snapshot(t, root); !slices.Equal(before, after) {
		t.Errorf("the mailbox changed:\nbefore %v\nafter  %v", before, after)
	}
}

// The Maildir belongs to the tenant, so root must not follow a link planted in
// it out of the tree.
func TestAPlantedSymlinkIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ")
	}
	root := maildirWith(t, nil, nil)
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$hash"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(root, "new", "1770000200.evil.host")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readMessage(link); err == nil {
		t.Fatal("a planted symlink was followed")
	}
}

// The cursor advances only as far as what was read, so a message older than the
// cursor is skipped and one newer is picked up.
func TestTheCursorSkipsWhatWasAlreadySeen(t *testing.T) {
	root := maildirWith(t,
		[]string{"1770000100.old.host", "1770000300.new.host"},
		[]string{"old", "new"})

	names, newest, err := newMessages(root, 1770000200)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 || !strings.HasSuffix(names[0], "1770000300.new.host") {
		t.Errorf("names = %v, want only the newer message", names)
	}
	if newest != 1770000300 {
		t.Errorf("newest = %d, want 1770000300", newest)
	}
}

// A name that carries no epoch is always eligible: being read twice costs a
// duplicate-key no-op, while skipping it would lose a report for good.
func TestAMessageWithoutAnEpochIsStillRead(t *testing.T) {
	root := maildirWith(t, []string{"not-a-maildir-name"}, []string{"body"})
	names, _, err := newMessages(root, 1770000000)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 {
		t.Errorf("names = %v, want the unparseable name to be read", names)
	}
}

// A flag change renames a Maildir file and moves it from new to cur. The
// leading epoch survives both, which is the whole reason the cursor uses it.
func TestReadingAMessageDoesNotChangeItsEpoch(t *testing.T) {
	root := maildirWith(t, []string{"1770000400.abc.host"}, []string{"body"})
	if err := os.Rename(
		filepath.Join(root, "new", "1770000400.abc.host"),
		filepath.Join(root, "cur", "1770000400.abc.host:2,S")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	names, newest, err := newMessages(root, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 || newest != 1770000400 {
		t.Errorf("names = %v newest = %d, want the read message still found at its epoch", names, newest)
	}
}

// reportMessage wraps a document as a base64 attachment inside a multipart
// message, which is how every real reporter sends one.
func reportMessage(t *testing.T, document string) string {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	var wrapped strings.Builder
	for len(encoded) > 76 {
		wrapped.WriteString(encoded[:76])
		wrapped.WriteString("\r\n")
		encoded = encoded[76:]
	}
	wrapped.WriteString(encoded)

	return strings.Join([]string{
		"From: noreply-dmarc-support@google.com",
		"To: postmaster@example.com",
		"Subject: Report domain: example.com",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="BOUND"`,
		"",
		"--BOUND",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"This is an aggregate report.",
		"",
		"--BOUND",
		`Content-Type: application/xml; name="report.xml"`,
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="report.xml"`,
		"",
		wrapped.String(),
		"",
		"--BOUND--",
		"",
	}, "\r\n")
}

// A base64 attachment must be decoded before it reaches Unpack, or an archive's
// magic bytes are never seen and every real report is silently skipped.
func TestABase64AttachmentIsDecoded(t *testing.T) {
	fixedNow(t)
	raw := reportMessage(t, aggregateXML("198.51.100.9", "12", "microsoft.com"))
	documents := Attachments([]byte(raw))
	if len(documents) == 0 {
		t.Fatal("no attachment was found")
	}
	var found bool
	for _, document := range documents {
		report, err := ParseAggregate(document)
		if err != nil {
			continue
		}
		found = true
		if report.Rows[0].SourceIP != "198.51.100.9" || report.Rows[0].MessageCount != 12 {
			t.Errorf("row = %+v", report.Rows[0])
		}
	}
	if !found {
		t.Error("the attachment did not parse as a report")
	}
}
