package backups

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"servika/internal/secret"
)

const (
	sizeQuery         = "SELECT size_b FROM backups WHERE id=? AND domain_id=?"
	digestQuery       = "SELECT COALESCE(sha256,'') FROM backups WHERE id=? AND domain_id=?"
	remoteStatusQuery = "SELECT remote_status FROM backups WHERE id=? AND domain_id=?"
	destinationQuery  = "FROM backup_destinations WHERE domain_id=?"
	settingsQuery     = "FROM backup_settings WHERE id=1"
	archiveBody       = "the real archive bytes"
)

// domainDestinationRow is an SFTP destination with a pinned key, in SELECT order.
func domainDestinationRow() []driver.Value {
	return []driver.Value{int64(1), "sftp", "203.0.113.10", int64(22), "backup", "secret-pass", "/backups",
		"203.0.113.10 ssh-ed25519 AAAAkey", "", "", "", int64(0), int64(1), nil, "", ""}
}

// settingsRow is the system-wide settings singleton, in SELECT order.
func settingsRow(remoteEnabled bool, minFreeGB int64, password string) []driver.Value {
	return []driver.Value{int64(1), minFreeGB, int64(0), boolValue(remoteEnabled), "sftp", "203.0.113.20", int64(22),
		"offsite", password, "/gpanel", "203.0.113.20 ssh-ed25519 AAAAkey", int64(0), nil, "", ""}
}

func boolValue(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// lftpFetches answers `lftp -c <script>`: a get from a directory named in bodies
// writes that body to the -o target, and a get from any other directory fails.
func lftpFetches(t *testing.T, bodies map[string]string) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		if !hasArgvPrefix(argv, []string{"lftp", "-c"}) {
			return "", 0
		}
		dir := between(argv[2], `cd "`, `"`)
		body, ok := bodies[dir]
		if !ok {
			return "get: Access failed: No such file", 1
		}
		if err := os.WriteFile(between(argv[2], `-o "`, `"`), []byte(body), 0o600); err != nil {
			return err.Error(), 2
		}
		return "", 0
	})
}

// between returns the text after the first open and before the next close.
func between(s, open, close string) string {
	_, rest, _ := strings.Cut(s, open)
	value, _, _ := strings.Cut(rest, close)
	return value
}

type localArchive struct {
	root, abs string
	digest    string
	script    *sqlScript
}

// newLocalArchive answers the size, digest and remote status of backup 9 of
// domain 5; the archive itself is not written.
func newLocalArchive(t *testing.T, remoteStatus string, settings []driver.Value) *localArchive {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SERVIKA_BACKUP_ROOT", root)
	_, digest := writeArchive(t, archiveBody)
	rows := map[string][][]driver.Value{
		sizeQuery:         {{int64(len(archiveBody))}},
		digestQuery:       {{digest}},
		remoteStatusQuery: {{remoteStatus}},
		destinationQuery:  {domainDestinationRow()},
		settingsQuery:     {},
	}
	if settings != nil {
		rows[settingsQuery] = [][]driver.Value{settings}
	}
	return &localArchive{
		root: root, abs: filepath.Join(root, "c_example", archiveName), digest: digest,
		script: &sqlScript{rows: rows},
	}
}

func (l *localArchive) ensure(t *testing.T) error {
	t.Helper()
	return ensureLocalArchive(context.Background(), scriptDB(t, l.script), 5, 9, "c_example", archiveName)
}

func TestEnsureLocalArchiveRefusesAnInvalidName(t *testing.T) {
	for _, c := range []struct{ user, file string }{
		{"root", archiveName}, {"c_example", ""}, {"c_example", "x/" + archiveName},
		{"c_example", ".."}, {"c_example", "."},
	} {
		err := ensureLocalArchive(context.Background(), nil, 5, 9, c.user, c.file)
		if err == nil || err.Error() != "invalid backup file" {
			t.Errorf("(%q, %q): %v, want the name refused", c.user, c.file, err)
		}
	}
}

// A local copy of the recorded size, or of an unrecorded size, is used as it is.
func TestEnsureLocalArchiveKeepsACompleteLocalCopy(t *testing.T) {
	for _, recorded := range [][][]driver.Value{{{int64(len(archiveBody))}}, {}} {
		l := newLocalArchive(t, "successful", nil)
		l.script.rows[sizeQuery] = recorded
		writeFixtureFile(t, l.abs, archiveBody)
		commands := lftpFetches(t, nil)

		if err := l.ensure(t); err != nil {
			t.Fatalf("a complete local copy was refused: %v", err)
		}
		if len(commands.argvs()) != 0 {
			t.Errorf("a complete local copy was fetched again: %v", commands.argvs())
		}
	}
}

// A truncated local copy is replaced by the domain destination's copy, which is
// written beside the archive and moved into place only once it is whole.
func TestEnsureLocalArchiveFetchesFromTheDomainDestination(t *testing.T) {
	l := newLocalArchive(t, "successful", nil)
	writeFixtureFile(t, l.abs, "trunc")
	commands := lftpFetches(t, map[string]string{"/backups": archiveBody})

	if err := l.ensure(t); err != nil {
		t.Fatalf("the fetch was refused: %v", err)
	}
	if got, _ := os.ReadFile(l.abs); string(got) != archiveBody {
		t.Errorf("the archive holds %q", got)
	}
	argvs := commands.argvs()
	if len(argvs) != 1 {
		t.Fatalf("lftp ran %d times: %v", len(argvs), argvs)
	}
	script := argvs[0][2]
	for _, want := range []string{
		`open -u "backup" --env-password "sftp://203.0.113.10:22"`,
		`cd "/backups"; get "` + archiveName + `" -o "` + l.abs + `.downloading"; bye`,
		"UserKnownHostsFile=",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the fetch script lacks %q: %s", want, script)
		}
	}
}

// A fetched copy that does not match the recorded digest is removed, and with no
// system destination the backup is reported missing.
func TestEnsureLocalArchiveRefusesAFetchedCopyThatDoesNotMatch(t *testing.T) {
	l := newLocalArchive(t, "successful", nil)
	lftpFetches(t, map[string]string{"/backups": strings.ToUpper(archiveBody)})

	if err := l.ensure(t); err == nil || err.Error() != "backup file is missing on disk" {
		t.Fatalf("ensureLocalArchive = %v, want the backup reported missing", err)
	}
	if _, err := os.Stat(l.abs); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused copy was left in place: %v", err)
	}
}

// Without a successful per-domain upload, or when the domain destination cannot
// be read or answer, the system destination is tried: the dated directory first,
// then the base directory.
func TestEnsureLocalArchiveFallsBackToTheSystemDestination(t *testing.T) {
	cases := []struct {
		name  string
		setup func(l *localArchive)
		runs  int
	}{
		{name: "no per-domain upload", setup: func(l *localArchive) { l.script.rows[remoteStatusQuery] = [][]driver.Value{{"failed"}} }, runs: 2},
		{name: "the destination cannot be read", setup: func(l *localArchive) {
			delete(l.script.rows, destinationQuery)
			l.script.fail = map[string]error{destinationQuery: errors.New("lost")}
		}, runs: 2},
		{name: "the domain destination has no copy", setup: func(*localArchive) {}, runs: 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLocalArchive(t, "successful", settingsRow(true, 0, "pw"))
			c.setup(l)
			commands := lftpFetches(t, map[string]string{"/gpanel": archiveBody})

			if err := l.ensure(t); err != nil {
				t.Fatalf("the system destination was not used: %v", err)
			}
			var dirs []string
			for _, argv := range commands.argvs() {
				dirs = append(dirs, between(argv[2], `cd "`, `"`))
			}
			want := []string{"/gpanel/2026-01-01", "/gpanel"}
			if c.runs == 3 {
				want = append([]string{"/backups"}, want...)
			}
			if !slices.Equal(dirs, want) {
				t.Errorf("fetched from %v, want %v", dirs, want)
			}
		})
	}
}

func TestEnsureLocalArchiveReportsWhyTheSystemDestinationCannotHelp(t *testing.T) {
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		settings   []driver.Value
		bodies     map[string]string
		wantPrefix string
	}{
		{name: "the password cannot be opened", settings: settingsRow(true, 0, "enc:v1:not-a-sealed-value"),
			wantPrefix: "the stored off-site password could not be decrypted (SERVIKA_SECRET_KEY may have changed): "},
		{name: "the disk is too full to fetch", settings: settingsRow(true, 1_000_000_000, "pw"),
			wantPrefix: "the backup is off-site but there is not enough disk to fetch it"},
		{name: "neither directory has a copy", settings: settingsRow(true, 0, "pw"),
			wantPrefix: "backup file is missing on disk"},
		{name: "the copy does not match", settings: settingsRow(true, 0, "pw"),
			bodies:     map[string]string{"/gpanel/2026-01-01": strings.ToUpper(archiveBody)},
			wantPrefix: "backup file is missing on disk"},
		{name: "the system destination is off", settings: settingsRow(false, 0, "pw"),
			wantPrefix: "backup file is missing on disk"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLocalArchive(t, "", c.settings)
			commands := lftpFetches(t, c.bodies)

			err := l.ensure(t)

			if err == nil || !strings.HasPrefix(err.Error(), c.wantPrefix) {
				t.Fatalf("ensureLocalArchive = %v, want it to start with %q", err, c.wantPrefix)
			}
			if c.bodies == nil && strings.HasPrefix(c.wantPrefix, "the ") && len(commands.argvs()) != 0 {
				t.Errorf("a fetch ran although it could not succeed: %v", commands.argvs())
			}
		})
	}
}
