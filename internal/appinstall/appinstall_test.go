package appinstall

import "testing"

// The subdirectory becomes one path segment under the document root. Anything
// that could carry a separator would put the installation somewhere else, and
// a leading dot would hide it from the customer who asked for it.
func TestOnlyOnePathSegmentIsAcceptedAsASubdirectory(t *testing.T) {
	for _, good := range []string{"", "shop", "wiki2", "my-site", "a_b"} {
		if !ValidSubdirectory(good) {
			t.Errorf("%q was refused", good)
		}
	}
	for _, bad := range []string{
		"..", "../etc", "a/b", "/abs", ".hidden", "-lead", "A", "a b", "a?b",
		"a/../b", "\\b",
	} {
		if ValidSubdirectory(bad) {
			t.Errorf("%q was accepted as a subdirectory", bad)
		}
	}
}

// The archive name is joined onto the panel's temporary directory. It is a
// NAME: a separator or a dot segment in it would write outside that directory.
func TestTheArchiveNameCannotLeaveTheTemporaryDirectory(t *testing.T) {
	for _, good := range []string{"drupal.tar.gz", "grav.zip", "x.tar.bz2", "y.tgz"} {
		if !validArchiveName(good) {
			t.Errorf("%q was refused", good)
		}
	}
	for _, bad := range []string{
		"", "noextension", "../escape.zip", "a/b.zip", "a\\b.zip",
		"..zip", "x.tar.gz.exe", "x.php",
	} {
		if validArchiveName(bad) {
			t.Errorf("%q was accepted as an archive name", bad)
		}
	}
}

// A catalog entry an administrator can edit still has to be usable. The https
// requirement is the one that matters: over plain http the bytes and any
// checksum served beside them are both rewritable by anybody on the path.
func TestACatalogEntryIsCheckedBeforeItIsStored(t *testing.T) {
	base := Entry{
		Code: "joomla", Name: "Joomla", Version: "6.1.2",
		DownloadURL: "https://example.test/joomla.tar.gz",
		SHA256:      "ba184026652260816dd826ac08fc95fd710888877824e2396a85e64d6e983325",
		ArchiveName: "joomla.tar.gz", StripComponents: 0,
	}
	if field, ok := ValidEntry(base); !ok {
		t.Fatalf("a valid entry was refused on %q", field)
	}

	cases := []struct {
		field string
		edit  func(*Entry)
	}{
		{"download_url", func(e *Entry) { e.DownloadURL = "http://example.test/x.tar.gz" }},
		{"download_url", func(e *Entry) { e.DownloadURL = "ftp://example.test/x.tar.gz" }},
		{"code", func(e *Entry) { e.Code = "Joomla" }},
		{"code", func(e *Entry) { e.Code = "a" }},
		{"name", func(e *Entry) { e.Name = "" }},
		{"version", func(e *Entry) { e.Version = "" }},
		{"sha256", func(e *Entry) { e.SHA256 = "not-a-digest" }},
		{"sha256", func(e *Entry) { e.SHA256 = "BA184026652260816DD826AC08FC95FD710888877824E2396A85E64D6E983325" }},
		{"archive_name", func(e *Entry) { e.ArchiveName = "../x.zip" }},
		{"strip_components", func(e *Entry) { e.StripComponents = 9 }},
		{"strip_components", func(e *Entry) { e.StripComponents = -1 }},
	}
	for _, testCase := range cases {
		entry := base
		testCase.edit(&entry)
		field, ok := ValidEntry(entry)
		if ok {
			t.Errorf("an entry with a bad %s was accepted", testCase.field)
			continue
		}
		if field != testCase.field {
			t.Errorf("the refusal named %q, want %q", field, testCase.field)
		}
	}
}

// An EMPTY checksum is allowed in the table so an administrator can enter a new
// version's URL and fill in the digest afterwards. LookupEntry is what refuses
// to install it, and that separation is what these two assertions pin.
func TestAnEmptyChecksumIsStorableButNotInstallable(t *testing.T) {
	entry := Entry{
		Code: "drupal", Name: "Drupal", Version: "11.4.5",
		DownloadURL: "https://example.test/drupal.tar.gz",
		SHA256:      "", ArchiveName: "drupal.tar.gz",
	}
	if field, ok := ValidEntry(entry); !ok {
		t.Errorf("an entry with no checksum could not be stored, refused on %q", field)
	}
	if sha256Pattern.MatchString(entry.SHA256) {
		t.Error("an empty checksum matched the digest pattern, so LookupEntry would install it unverified")
	}
}

// The reason code is what the screen matches on, so it has to survive being
// wrapped and has to be absent from anything that is not a refusal.
func TestTheReasonCodeSurvivesWrapping(t *testing.T) {
	err := refuse(ReasonChecksum, nil)
	if ReasonOf(err) != ReasonChecksum {
		t.Errorf("ReasonOf gave %q, want %q", ReasonOf(err), ReasonChecksum)
	}
	if ReasonOf(nil) != "" {
		t.Error("ReasonOf named a code for no error")
	}
}
