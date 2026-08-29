package transfers

import (
	"strings"
	"testing"
)

// The mailbox listing is untrusted source input. Only valid local parts survive;
// a name carrying a path, a shell metacharacter or whitespace is dropped rather
// than trusted, because it later builds an rsync remote path.
func TestParseMailboxListKeepsOnlyValidLocalParts(t *testing.T) {
	out := strings.Join([]string{
		"info",
		"John.Doe", // upper-cased on the source, normalized here
		"",         // blank line
		"*",        // catch-all marker, not a mailbox
		"info",     // duplicate
		"../etc/passwd",
		"a;rm -rf /",
		"has space",
		".hidden", // must start alphanumeric
		"sales",
	}, "\n")

	got := parseMailboxList(out)
	want := []string{"info", "john.doe", "sales"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: got %q, want %q (full %v)", i, got[i], w, got)
		}
	}
}

func TestParseMailboxListRejectsInjectionAttempts(t *testing.T) {
	for _, bad := range []string{
		"../../root", "a`whoami`", "a$(id)", "a|b", "a&b", "a b", "a/b", "a:b",
	} {
		if got := parseMailboxList(bad); len(got) != 0 {
			t.Errorf("%q survived validation as %v", bad, got)
		}
	}
}

func TestMaildirSourcePathPerVendor(t *testing.T) {
	cases := []struct{ vendor, want string }{
		{"cpanel", "/home/acme/mail/example.com/info/"},
		{"plesk", "/var/qmail/mailnames/example.com/info/Maildir/"},
		{"directadmin", "/home/acme/imap/example.com/info/Maildir/"},
		{"unknown", ""},
	}
	for _, c := range cases {
		got := maildirSourcePath(c.vendor, "acme", "example.com", "info")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.vendor, got, c.want)
		}
		// A non-empty source path must end in a slash so rsync copies the
		// contents (cur/new/tmp) rather than the directory itself.
		if got != "" && !strings.HasSuffix(got, "/") {
			t.Errorf("%s: %q does not end in a slash", c.vendor, got)
		}
	}
}

func TestMailboxCommandCoversTheSupportedVendors(t *testing.T) {
	for _, v := range []string{"cpanel", "plesk", "directadmin"} {
		cmd, ok := mailboxCommand(v, "acme", "example.com")
		if !ok || cmd == "" {
			t.Errorf("%s: no mailbox command", v)
		}
		if !strings.Contains(cmd, "example.com") {
			t.Errorf("%s: command does not scope to the domain: %s", v, cmd)
		}
	}
	if _, ok := mailboxCommand("unknown", "acme", "example.com"); ok {
		t.Error("an unknown vendor reported a mailbox command")
	}
}

// The forwarder parser is shared with the cpmove import. In the live migration
// the source and target domain are the same, so a destination keeps its domain,
// and a pipe/include destination is dropped because Servika cannot host it.
func TestParseAliasBodyRewritesAndDropsUnhostable(t *testing.T) {
	body := []byte(strings.Join([]string{
		"sales: sales@example.com",
		"team: a@example.com,b@example.com",
		"pipe: |/usr/bin/procmail",
		"inc: :include:/etc/list",
		"", // blank
	}, "\n"))

	got := parseAliasBody(body, "example.com", "example.com")
	byLocal := map[string]string{}
	for _, a := range got {
		byLocal[a.Local] = a.Destination
	}
	if byLocal["sales"] != "sales@example.com" {
		t.Errorf("sales forwarder wrong: %q", byLocal["sales"])
	}
	if byLocal["team"] != "a@example.com,b@example.com" {
		t.Errorf("team forwarder wrong: %q", byLocal["team"])
	}
	if _, ok := byLocal["pipe"]; ok {
		t.Error("a pipe destination was kept")
	}
	if _, ok := byLocal["inc"]; ok {
		t.Error("an :include: destination was kept")
	}
}
