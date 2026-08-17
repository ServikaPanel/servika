package hostapps

import (
	"runtime"
	"strings"
	"testing"
)

func sampleEntry() Entry {
	return Entry{
		Code: "grafana", Name: "Grafana", Version: "13.1.3",
		URLAMD64:    "https://example.invalid/grafana-amd64.tar.gz",
		SHA256AMD64: strings.Repeat("a", 64),
		URLARM64:    "https://example.invalid/grafana-arm64.tar.gz",
		SHA256ARM64: strings.Repeat("b", 64),
		ArchiveKind: "tar.gz", StripComponents: 1, BinaryPath: "bin/grafana",
		StartArgs: "server", PortEnvName: "GF_SERVER_HTTP_PORT",
		TakesPort: true, DefaultPort: 3001, NeedsDataDir: true, Enabled: true,
	}
}

// A project that publishes no build for this architecture is refused BEFORE
// anything is downloaded, with its own reason code. TeamSpeak has no arm64 Linux
// server at all, so on an arm64 host the honest answer is that it cannot be
// installed; failing halfway through a download instead leaves an account, a
// directory and a unit behind for an application that was never going to run.
func TestAnArchitectureWithNoBuildIsRefusedUpFront(t *testing.T) {
	entry := sampleEntry()
	switch runtime.GOARCH {
	case "amd64":
		entry.URLAMD64 = ""
	case "arm64":
		entry.URLARM64 = ""
	default:
		t.Skipf("this panel does not ship for %s", runtime.GOARCH)
	}
	_, _, err := Download(entry)
	if got := ReasonOf(err); got != ReasonNoBuild {
		t.Errorf("refused as %q, want %q", got, ReasonNoBuild)
	}
}

// An archive with no recorded checksum is refused at install time. The download
// becomes a program this server executes as its own account, so "we could not
// check it" has to stop the install rather than annotate it.
func TestAnUncheckedArchiveIsRefused(t *testing.T) {
	entry := sampleEntry()
	entry.SHA256AMD64, entry.SHA256ARM64 = "", ""
	_, _, err := Download(entry)
	if got := ReasonOf(err); got != ReasonNoChecksum {
		t.Errorf("refused as %q, want %q", got, ReasonNoChecksum)
	}
	// A malformed one is refused the same way, or a truncated paste would be
	// stored and then never match anything.
	entry.SHA256AMD64, entry.SHA256ARM64 = "abc", "abc"
	if _, _, err := Download(entry); ReasonOf(err) != ReasonNoChecksum {
		t.Errorf("a short digest was accepted as a checksum")
	}
}

// The architecture that IS published resolves, or every test above proves
// nothing.
func TestThePublishedArchitectureResolves(t *testing.T) {
	url, digest, err := Download(sampleEntry())
	if err != nil {
		t.Fatalf("the catalog covers this architecture but was refused: %v", err)
	}
	if url == "" || len(digest) != 64 {
		t.Errorf("resolved to %q / %q", url, digest)
	}
}

// start_args reaches an ExecStart line. The raw string is checked BEFORE it is
// split, because strings.Fields treats a newline as whitespace and a per-token
// check can never see one: a second directive would then be appended to the unit
// as though the catalog had asked for it.
func TestALineBreakInTheArgumentsIsRefusedBeforeSplitting(t *testing.T) {
	for _, args := range []string{
		"server\nExecStartPost=/bin/sh -c id",
		"server\rrun",
		"server\x00run",
	} {
		entry := sampleEntry()
		entry.StartArgs = args
		if got := ReasonOf(mustFail(t, entry)); got != ReasonBadArgs {
			t.Errorf("%q refused as %q, want %q", args, got, ReasonBadArgs)
		}
	}
}

// systemd expands % as a specifier, so a token carrying one does not reach the
// unit as the text the catalog holds.
func TestASpecifierIsRefused(t *testing.T) {
	entry := sampleEntry()
	entry.StartArgs = "server --config=%h/x"
	if got := ReasonOf(mustFail(t, entry)); got != ReasonBadArgs {
		t.Errorf("refused as %q, want %q", got, ReasonBadArgs)
	}
}

func mustFail(t *testing.T, entry Entry) error {
	t.Helper()
	_, err := BuildArgv(entry, "/opt/servika-apps/grafana/data", 31000)
	if err == nil {
		t.Fatalf("%q was accepted", entry.StartArgs)
	}
	return err
}

// The two placeholders are what let a catalog row name the port and the data
// directory the PANEL chose, without this package having to understand each
// product's flag syntax.
func TestThePlaceholdersAreSubstituted(t *testing.T) {
	entry := sampleEntry()
	entry.StartArgs = "--storage.tsdb.path={data} --web.listen-address=:{port}"
	argv, err := BuildArgv(entry, "/opt/servika-apps/prometheus/data", 31007)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--storage.tsdb.path=/opt/servika-apps/prometheus/data",
		"--web.listen-address=:31007",
	}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for index := range want {
		if argv[index] != want[index] {
			t.Errorf("argv[%d] = %q, want %q", index, argv[index], want[index])
		}
	}
}

// Every port handed out belongs to this package's range. A port outside it would
// sit above a range drop that does not cover it, so the firewall accept written
// for it would open a port belonging to something else.
func TestEveryAllocatedPortIsInsideTheRange(t *testing.T) {
	taken := map[int]bool{}
	previous := 0
	for range 50 {
		port, err := NextPort(taken, previous)
		if err != nil {
			t.Fatal(err)
		}
		if !InRange(port) {
			t.Fatalf("allocated %d, outside %d-%d", port, PortMin, PortMax)
		}
		if taken[port] {
			t.Fatalf("allocated %d twice", port)
		}
		taken[port] = true
		previous = port
	}
}

// A freed port is not handed straight to the next application. A bookmark or an
// open tab still pointing at it would otherwise land on a different application
// entirely, which for something like a MinIO console is worse than a refusal.
func TestAFreedPortIsNotHandedStraightBack(t *testing.T) {
	taken := map[int]bool{PortMin: true, PortMin + 1: true}
	delete(taken, PortMin) // the first application was removed
	port, err := NextPort(taken, PortMin+1)
	if err != nil {
		t.Fatal(err)
	}
	if port == PortMin {
		t.Errorf("the just-freed port %d was handed out again", port)
	}
}

// A full range is REFUSED rather than wrapped onto something outside it.
func TestAFullRangeIsRefused(t *testing.T) {
	taken := map[int]bool{}
	for port := PortMin; port <= PortMax; port++ {
		taken[port] = true
	}
	if _, err := NextPort(taken, PortMax); ReasonOf(err) != ReasonNoPort {
		t.Errorf("a full range was not refused with %q", ReasonNoPort)
	}
}

// The removal path deletes a Linux account and a directory tree BY NAME, so the
// name it accepts is the whole boundary. A tenant account must never pass it:
// deleting c_example takes a customer's home with it.
func TestOnlyThisPackagesOwnAccountsCanBeRemoved(t *testing.T) {
	for _, name := range []string{"svk_gitea", "svk_grafana", "svk_minio"} {
		if !ValidSystemUser(name) {
			t.Errorf("%q is a name this hands out but was refused", name)
		}
	}
	for _, name := range []string{
		"", "root", "mysql", "nginx", "c_example", "svk_", "svk_A", "svk_x y",
		"svk_../root", "SVK_gitea", "svk_gitea ", "s",
	} {
		if ValidSystemUser(name) {
			t.Errorf("%q was accepted as one of this package's accounts", name)
		}
	}
}

// binary_path is joined onto a directory the panel created and the result is
// then made executable, so anything that escapes the tree reaches a chmod on a
// file this package does not own.
func TestTheBinaryPathCannotLeaveTheArchive(t *testing.T) {
	for _, path := range []string{"gitea", "bin/grafana", "usr/local/bin/x"} {
		if !validRelPath(path) {
			t.Errorf("%q is an ordinary archive path but was refused", path)
		}
	}
	for _, path := range []string{
		"", "/usr/bin/id", "../../etc/passwd", "bin/../../x", "bin/x;id",
		"bin/$(id)", "bin/x y", "bin/x\ny",
	} {
		if validRelPath(path) {
			t.Errorf("%q was accepted as an archive path", path)
		}
	}
}

// The catalog is admin-editable, so every field is checked again on the install
// path. The field NAME is returned because a refusal that only says "invalid"
// leaves an operator reading ten columns.
func TestAnInvalidCatalogRowNamesTheFieldThatIsWrong(t *testing.T) {
	cases := map[string]func(*Entry){
		"code":             func(e *Entry) { e.Code = "Grafana!" },
		"archive_kind":     func(e *Entry) { e.ArchiveKind = "rar" },
		"strip_components": func(e *Entry) { e.StripComponents = 9 },
		"binary_path":      func(e *Entry) { e.BinaryPath = "/usr/bin/id" },
		"port_env_name":    func(e *Entry) { e.PortEnvName = "gf port" },
		"url_amd64":        func(e *Entry) { e.URLAMD64 = "http://example.invalid/x" },
		"sha256_arm64":     func(e *Entry) { e.SHA256ARM64 = "zz" },
		"start_args":       func(e *Entry) { e.StartArgs = "server\nExecStop=/bin/sh" },
	}
	for want, mutate := range cases {
		entry := sampleEntry()
		mutate(&entry)
		field, err := ValidEntry(entry)
		if err == nil {
			t.Errorf("%s: the row was accepted", want)
			continue
		}
		if field != want {
			t.Errorf("the refusal named %q, want %q", field, want)
		}
	}
	if field, err := ValidEntry(sampleEntry()); err != nil {
		t.Errorf("a good row was refused (%s): %v", field, err)
	}
}
