package mail

import (
	"strings"
	"testing"
)

// The Maildir root belongs to the SYSTEM USER while uniqueness on mailboxes is
// (domain_id, local_part), and an addon domain carries its parent's system_user.
// Keyed on the local part alone, info@parent.com and info@addon.com were two
// rows with two passwords and two quotas that resolved to one directory: either
// password read and deleted the other account's mail.
func TestMaildirOfTwoDomainsOnOneSystemUserDoNotCollide(t *testing.T) {
	const root = "/home/c_parent/mail"
	parent := mailboxMaildir(root, "parent.com", "info")
	addon := mailboxMaildir(root, "addon.com", "info")
	if parent == addon {
		t.Fatalf("both mail domains resolve to %q", parent)
	}
	for _, path := range []string{parent, addon} {
		if !strings.HasPrefix(path, root+"/") {
			t.Errorf("%q is outside the tenant Maildir root", path)
		}
		// Dovecot and Postfix both read the path as a Maildir, which the trailing
		// slash is what marks.
		if !strings.HasSuffix(path, "/") {
			t.Errorf("%q does not end in a slash, so it is not read as a Maildir", path)
		}
	}
	if parent != root+"/parent.com/info/" {
		t.Errorf("maildir = %q, want the domain between the root and the local part", parent)
	}
}

// createMaildir writes as root inside a home the tenant owns, so it must refuse
// a path it cannot prove is under that home rather than following it.
func TestCreateMaildirRefusesAPathOutsideTheTenantHome(t *testing.T) {
	for _, maildir := range []string{"/etc/cron.d/", "/home/c_other/mail/info/", "/home/c_site"} {
		if err := createMaildir("c_site", maildir); err == nil {
			t.Errorf("createMaildir() accepted %q, which is outside /home/c_site", maildir)
		}
	}
}

// Dovecot reads the letters after ":2," on sight, so getting them wrong makes a
// migrated mailbox come back entirely unread, which is what the customer notices
// first.
func TestMaildirInfoCarriesTheFlagsDovecotReads(t *testing.T) {
	cases := []struct {
		flags []string
		want  string
	}{
		{nil, ":2,"},
		{[]string{"\\Seen"}, ":2,S"},
		{[]string{"\\Seen", "\\Answered"}, ":2,RS"},
		{[]string{"\\Answered", "\\Seen"}, ":2,RS"},
		{[]string{"\\Flagged", "\\Draft", "\\Seen"}, ":2,DFS"},
		{[]string{"\\Seen", "\\Seen"}, ":2,S"},
		{[]string{"\\Recent", "$Label1"}, ":2,"},
	}
	for _, test := range cases {
		if got := maildirInfo(test.flags); got != test.want {
			t.Errorf("maildirInfo(%v) = %q, want %q", test.flags, got, test.want)
		}
	}
}

// INBOX is the Maildir root itself, and every other folder is a dot-prefixed
// sibling with the hierarchy flattened onto dots.
func TestFolderNamesMapOntoTheMaildirLayout(t *testing.T) {
	cases := []struct {
		folder    string
		delimiter rune
		want      string
	}{
		{"INBOX", '/', ""},
		{"inbox", '.', ""},
		{"Sent", '/', ".Sent"},
		{"INBOX/Sent", '/', ".Sent"},
		{"INBOX.Sent", '.', ".Sent"},
		{"Projects/2025/Notes", '/', ".Projects.2025.Notes"},
		{"Archive.Old", '.', ".Archive.Old"},
	}
	for _, test := range cases {
		if got := maildirSubdir(test.folder, test.delimiter); got != test.want {
			t.Errorf("maildirSubdir(%q, %q) = %q, want %q", test.folder, string(test.delimiter), got, test.want)
		}
	}
}

// The folder name is whatever the remote server sends, so a name carrying a
// slash, a dot or a newline must not be able to place a directory outside the
// mailbox or split the flattened path.
func TestHostileFolderNamesCannotLeaveTheMaildir(t *testing.T) {
	cases := map[rune]string{
		'/': "../../etc",
		'|': "a/b",
	}
	for delimiter, folder := range cases {
		got := maildirSubdir(folder, delimiter)
		if strings.Contains(got, "..") || strings.Contains(got, "/") {
			t.Errorf("maildirSubdir(%q, %q) = %q, which escapes the mailbox", folder, string(delimiter), got)
		}
	}

	if got := maildirSubdir("Inject\r\nX", '/'); strings.ContainsAny(got, "\r\n") {
		t.Errorf("maildirSubdir kept a line break: %q", got)
	}
	// A name that is nothing but separators has no directory to make, and the
	// message belongs in the root rather than in a directory called "."
	if got := maildirSubdir("///", '/'); got != "" {
		t.Errorf("maildirSubdir(%q) = %q, want the root", "///", got)
	}
}

// A sanitised part is a single directory name: never a dot, which would name a
// parent, and never a slash, which would be a path.
func TestSanitizedFolderPartsAreASingleName(t *testing.T) {
	for _, part := range []string{".", "..", "", "   ", "\x00", "/", "a/b", "a.b", "..\\..", "ok"} {
		got := sanitizeFolderPart(part)
		if strings.ContainsAny(got, "./\x00\r\n") {
			t.Errorf("sanitizeFolderPart(%q) = %q, which is not a single name", part, got)
		}
	}
	// A name with nothing left in it after sanitising leaves nothing to create.
	for _, part := range []string{"", "   ", "\x00", "\x01\x02"} {
		if got := sanitizeFolderPart(part); got != "" {
			t.Errorf("sanitizeFolderPart(%q) = %q, want nothing", part, got)
		}
	}
	// A folder the server calls ".." keeps its messages under a harmless name
	// rather than being dropped.
	if got := sanitizeFolderPart(".."); got == "" {
		t.Error("a folder named \"..\" was dropped, taking its messages with it")
	}
	// And an ordinary name survives, or the refusals above would be free.
	if got := sanitizeFolderPart("Faturalar 2025"); got != "Faturalar 2025" {
		t.Errorf("an ordinary folder name was mangled: %q", got)
	}
}

// Only this file's own callers name a progress column, but the guard is what
// keeps that true if one ever comes from somewhere else.
func TestOnlyProgressColumnsAreWritable(t *testing.T) {
	for _, column := range []string{"folders_done", "messages_done", "bytes_done"} {
		if !isProgressColumn(column) {
			t.Errorf("%q was refused", column)
		}
	}
	for _, column := range []string{"status", "remote_user", "id", "", "folders_done=1;DROP TABLE"} {
		if isProgressColumn(column) {
			t.Errorf("%q was accepted as a progress column", column)
		}
	}
}
