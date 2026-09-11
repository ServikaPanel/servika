package archivex

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// extraction records what the extractor would have been asked to run.
type extraction struct {
	user    string
	args    []string
	started bool
}

// scriptedExtractor records the argv the package builds and answers with a
// shell script, so the command matrix can be read without an extractor and
// without runuser.
func scriptedExtractor(t *testing.T, script string) *extraction {
	t.Helper()
	record := &extraction{}
	setForTest(t, &extractCommand, func(ctx context.Context, systemUser string, arguments ...string) *exec.Cmd {
		record.user = systemUser
		record.args = arguments
		record.started = true
		return exec.CommandContext(ctx, "sh", "-c", script)
	})
	return record
}

// countedMembers replaces the pre-extraction scan with a fixed member count, so
// the command matrix does not need a real archive of every format.
func countedMembers(t *testing.T, members int) *bool {
	t.Helper()
	scanned := false
	setForTest(t, &scanArchive, func(_ context.Context, _ string, _ Type, _ Limits, collect func(string, int64)) error {
		scanned = true
		for range members {
			collect("member", 1)
		}
		return nil
	})
	return &scanned
}

// The extractor and its flags are the whole of what runs as the tenant, so the
// argv is pinned per format: a wrong flag either drops the container directory
// that should stay or keeps the one that should go.
func TestExtractStripBuildsTheCommandForEachFormat(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.bin")
	if err := os.WriteFile(archivePath, []byte("archive"), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	const destination = "/home/c_site/public_html"

	cases := []struct {
		name        string
		archiveType Type
		strip       int
		verbose     bool
		rar         string
		hasBSDTar   bool
		want        []string
		wantErr     error
	}{
		{name: "a ZIP is unzipped quietly", archiveType: TypeZIP,
			want: []string{"unzip", "-o", "-q", archivePath, "-d", destination}},
		{name: "a ZIP with progress keeps every line", archiveType: TypeZIP, verbose: true,
			want: []string{"unzip", "-o", archivePath, "-d", destination}},
		{name: "a ZIP that skips a directory goes through bsdtar", archiveType: TypeZIP, strip: 1, hasBSDTar: true,
			want: []string{"bsdtar", "-x", "--strip-components=1", "-f", archivePath, "-C", destination}},
		{name: "a ZIP that skips a directory with progress", archiveType: TypeZIP, strip: 1, verbose: true, hasBSDTar: true,
			want: []string{"bsdtar", "-xv", "--strip-components=1", "-f", archivePath, "-C", destination}},
		{name: "a ZIP that skips a directory without bsdtar", archiveType: TypeZIP, strip: 1,
			wantErr: ErrStripUnsupported},
		{name: "a RAR through bsdtar", archiveType: TypeRAR, rar: "bsdtar",
			want: []string{"bsdtar", "-x", "-f", archivePath, "-C", destination}},
		{name: "a RAR through bsdtar skipping two directories", archiveType: TypeRAR, rar: "bsdtar", strip: 2, verbose: true,
			want: []string{"bsdtar", "-xv", "--strip-components=2", "-f", archivePath, "-C", destination}},
		{name: "a RAR through unar", archiveType: TypeRAR, rar: "unar",
			want: []string{"unar", "-f", "-D", "-o", destination, archivePath}},
		{name: "a RAR through unar cannot skip a directory", archiveType: TypeRAR, rar: "unar", strip: 1,
			wantErr: ErrStripUnsupported},
		{name: "a RAR with no tool installed", archiveType: TypeRAR,
			wantErr: ErrRARUnavailable},
		{name: "a plain TAR", archiveType: TypeTAR,
			want: []string{"tar", "-x", "-f", "-", "-C", destination}},
		{name: "a gzip TAR with progress", archiveType: TypeTARGzip, verbose: true,
			want: []string{"tar", "-xzv", "-f", "-", "-C", destination}},
		{name: "a bzip2 TAR skipping three directories", archiveType: TypeTARBzip2, strip: 3,
			want: []string{"tar", "-xj", "--strip-components=3", "-f", "-", "-C", destination}},
		{name: "an xz TAR", archiveType: TypeTARXz,
			want: []string{"tar", "-xJ", "-f", "-", "-C", destination}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			countedMembers(t, 2)
			setForTest(t, &rarTool, func() (string, bool) { return tc.rar, tc.rar != "" })
			setForTest(t, &lookPath, func(string) (string, error) {
				if tc.hasBSDTar {
					return "/usr/bin/bsdtar", nil
				}
				return "", errors.New("not installed")
			})
			record := scriptedExtractor(t, "exit 0")
			var prog *progressCounter
			if tc.verbose {
				prog = &progressCounter{onLine: func(int) {}}
			}

			_, err := extractStrip(context.Background(), archivePath, tc.archiveType,
				destination, "c_site", tc.strip, Limits{}, prog, nil)

			if tc.wantErr != nil {
				assertRefused(t, err, tc.wantErr, record)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgv(t, record, tc.want)
		})
	}
}

// assertRefused checks a format this server cannot handle: the reason reaches
// the caller and no extractor runs.
func assertRefused(t *testing.T, err, want error, record *extraction) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if record.started {
		t.Errorf("an extractor ran anyway: %v", record.args)
	}
}

// assertArgv checks the tenant an extraction runs as and the argv it built.
func assertArgv(t *testing.T, record *extraction, want []string) {
	t.Helper()
	if record.user != "c_site" {
		t.Errorf("tenant = %q, want c_site", record.user)
	}
	if strings.Join(record.args, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", record.args, want)
	}
}

// The tenant name reaches runuser, so it is validated before anything is read
// or started, not after.
func TestExtractStripRefusesATenantItDoesNotManage(t *testing.T) {
	for _, user := range []string{"", "c_", "root", "postgres", "c_site;rm -rf /", "c_site/../root", "C_Site "} {
		t.Run(user, func(t *testing.T) {
			scanned := countedMembers(t, 1)
			record := scriptedExtractor(t, "exit 0")

			_, err := extractStrip(context.Background(), "/srv/archive.tar", TypeTAR,
				"/home/c_site/public_html", user, 0, Limits{}, nil, nil)

			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("error = %v, want ErrInvalidTenant", err)
			}
			if *scanned {
				t.Error("the archive was read before the tenant was judged")
			}
			if record.started {
				t.Error("an extractor ran for a tenant this panel does not manage")
			}
		})
	}
}

// Nothing is extracted from an archive that failed validation, and the reason
// the scan gave is the reason the caller gets.
func TestExtractStripStopsWhenTheArchiveFailsValidation(t *testing.T) {
	setForTest(t, &scanArchive, func(context.Context, string, Type, Limits, func(string, int64)) error {
		return ErrUnsafePath
	})
	record := scriptedExtractor(t, "exit 0")

	_, err := extractStrip(context.Background(), "/srv/archive.tar", TypeTAR,
		"/home/c_site/public_html", "c_site", 0, Limits{}, nil, nil)

	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error = %v, want ErrUnsafePath", err)
	}
	if record.started {
		t.Error("an extractor ran for an archive the scan refused")
	}
}

// The TAR family is fed through standard input, so the archive is opened here
// and a file that cannot be opened names itself.
func TestExtractStripReportsTheArchiveItCannotOpen(t *testing.T) {
	countedMembers(t, 1)
	record := scriptedExtractor(t, "exit 0")

	_, err := extractStrip(context.Background(), filepath.Join(t.TempDir(), "missing.tar"),
		TypeTAR, "/home/c_site/public_html", "c_site", 0, Limits{}, nil, nil)

	if err == nil || !strings.Contains(err.Error(), "open archive:") {
		t.Fatalf("error = %v, want one naming the archive", err)
	}
	if record.started {
		t.Error("an extractor ran without an archive to feed it")
	}
}

// A failing extractor reports its own output with the failure: that output is
// the only thing that says why it failed.
func TestExtractStripReturnsTheExtractorOutputOnFailure(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(archivePath, []byte("archive"), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	countedMembers(t, 1)
	scriptedExtractor(t, "echo 'tar: permission denied'; exit 2")

	output, err := extractStrip(context.Background(), archivePath, TypeTAR,
		"/home/c_site/public_html", "c_site", 0, Limits{}, nil, nil)

	if err == nil || !strings.Contains(err.Error(), "extract archive as tenant:") {
		t.Fatalf("error = %v, want one naming the tenant extraction", err)
	}
	if !strings.Contains(output, "permission denied") {
		t.Errorf("output = %q, want the extractor's own message", output)
	}
}

// A verbose extraction reports the same failure, and the tail it kept is what
// the caller shows: with progress wired up there is no combined output to
// return instead.
func TestExtractStripReturnsTheProgressTailOnFailure(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(archivePath, []byte("archive"), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	countedMembers(t, 1)
	scriptedExtractor(t, "echo 'tar: cannot write'; exit 2")

	prog := &progressCounter{onLine: func(int) {}}
	tail, err := extractStrip(context.Background(), archivePath, TypeTAR,
		"/home/c_site/public_html", "c_site", 0, Limits{}, prog, nil)

	if err == nil || !strings.Contains(err.Error(), "extract archive as tenant:") {
		t.Fatalf("error = %v, want one naming the tenant extraction", err)
	}
	if !strings.Contains(tail, "cannot write") {
		t.Errorf("tail = %q, want the extractor's own message", tail)
	}
}

// Progress is counted from the lines a verbose extractor prints, and the total
// comes from the scan that runs before it.
func TestExtractStripCountsTheLinesAVerboseExtractorPrints(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(archivePath, []byte("archive"), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	countedMembers(t, 3)
	scriptedExtractor(t, "printf 'one\\ntwo\\nthree\\n'")

	extracted, total := 0, 0
	prog := &progressCounter{onLine: func(delta int) { extracted += delta }}
	tail, err := extractStrip(context.Background(), archivePath, TypeTAR,
		"/home/c_site/public_html", "c_site", 0, Limits{}, prog, func(members int) { total = members })

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 3 || extracted != 3 {
		t.Errorf("reported %d of %d members, want 3 of 3", extracted, total)
	}
	if !strings.Contains(tail, "three") {
		t.Errorf("tail = %q, want the extractor's own output", tail)
	}
}
