package antivirus

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file past its read limit used to be skipped by the content layer entirely,
// which made the limit an escape rather than a budget: an attacker padded a
// webshell past 3 MiB and stepped around every content rule at once, while the
// file was still recorded as scanned.
func TestPaddingAFilePastTheReadLimitNoLongerHidesIt(t *testing.T) {
	root := t.TempDir()
	shell := []byte("<?php system($_GET['cmd']); ?>\n")
	padding := bytes.Repeat([]byte("// filler comment line\n"), 200000) // ~4.4 MB

	// The payload at the END, which is the ordinary shape of an infection: an
	// attacker appends to a file that is already there.
	tail := filepath.Join(root, "appended.php")
	if err := os.WriteFile(tail, append(append([]byte("<?php\n"), padding...), shell...), 0o600); err != nil {
		t.Fatal(err)
	}
	// And the payload at the START, which the head read has always covered.
	head := filepath.Join(root, "prepended.php")
	if err := os.WriteFile(head, append(append([]byte{}, shell...), padding...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{tail, head} {
		if fi, err := os.Stat(p); err != nil || fi.Size() <= phpReadLimit {
			t.Fatalf("%s is not over the read limit, so this test proves nothing", p)
		}
	}

	_, findings, _ := runScan(context.Background(), root, DefaultRequest(root))
	found := map[string]bool{}
	for _, f := range findings {
		found[filepath.Base(f.File)] = true
		if f.Level != LevelCritical {
			t.Errorf("%s was reported %s, want critical", f.File, f.Level)
		}
	}
	if !found["appended.php"] {
		t.Error("a webshell appended past the read limit is still invisible to the scan")
	}
	if !found["prepended.php"] {
		t.Error("a webshell at the start of an oversized file is no longer found")
	}
}

// Joining two distant parts of a file invents adjacency that is not in it. A
// head ending in `system(` beside a tail starting with `$_GET[` would otherwise
// be reported as a webshell nobody wrote, and on a large legitimate file that
// is a finding an operator cannot act on.
func TestNoRuleMatchesAcrossTheJoinBetweenHeadAndTail(t *testing.T) {
	root := t.TempDir()
	// Newline-broken padding on purpose: an unbroken run of alphabet characters
	// is itself a weak signal (PHP.Obf.LongBase64Block), and a fixture that
	// trips a rule inside the padding proves nothing about the seam.
	line := []byte("// ordinary comment line, nothing to see here\n")
	pad := func(n int) []byte {
		b := bytes.Repeat(line, n/len(line)+1)
		return b[:n]
	}

	// The file is laid out so the head ends with the opening half and the tail
	// BEGINS with the closing half, which is the only arrangement in which the
	// join could fabricate a match.
	const opener = "system("
	const closer = "$_GET['cmd']);\n"
	const middle = 100 << 10

	var body []byte
	body = append(body, []byte("<?php\n")...)
	body = append(body, pad(phpReadLimit-len("<?php\n")-len(opener))...)
	body = append(body, []byte(opener)...) // ends exactly at phpReadLimit
	body = append(body, pad(middle)...)
	body = append(body, []byte(closer)...) // first bytes of the last tailReadLimit
	body = append(body, pad(tailReadLimit-len(closer))...)

	path := filepath.Join(root, "seam.php")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readForScan(path, phpReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture only proves something if the two halves really did land on
	// either side of the join.
	if !bytes.HasSuffix(b[:phpReadLimit], []byte(opener)) {
		t.Fatal("the head does not end with the opening half; the fixture is wrong")
	}
	if !bytes.HasPrefix(b[phpReadLimit+len(seam):], []byte(closer)) {
		t.Fatal("the tail does not start with the closing half; the fixture is wrong")
	}
	if matches := evaluate(".php", b); len(matches) > 0 {
		var names []string
		for _, m := range matches {
			names = append(names, m.name)
		}
		t.Errorf("a rule matched across the seam: %s", strings.Join(names, ", "))
	}
}

// The ordinary case is unchanged: a file at or under its limit is read once and
// no seam is inserted, so nothing about a normal scan moved.
func TestAFileWithinItsLimitIsReadWholeAndUnjoined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.php")
	body := []byte("<?php echo 1;\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readForScan(path, phpReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, body) {
		t.Errorf("a small file was not read verbatim: %q", b)
	}
}
