package archivex

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// setForTest replaces a package variable for one test. It is shared by the
// characterization tests in this package.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// regularMember describes one ordinary file inside a test archive.
func regularMember(name string) tar.Header {
	return tar.Header{Name: name, Mode: 0644, Size: int64(len("content")), Typeflag: tar.TypeReg}
}

// tarArchiveBytes builds a TAR archive in memory.
func tarArchiveBytes(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatalf("write TAR header: %v", err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte("content")); err != nil {
				t.Fatalf("write TAR member: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close TAR writer: %v", err)
	}
	return buffer.Bytes()
}

// archiveFile writes archive bytes where a scan can open them.
func archiveFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return path
}

// compress pipes data through a real compressor. The test is skipped when the
// tool is absent, because the branch under test is the decompression one and
// not the tool itself.
func compress(t *testing.T, tool string, data []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s is not installed", tool)
	}
	command := exec.Command(tool, "-c")
	command.Stdin = bytes.NewReader(data)
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		t.Fatalf("compress with %s: %v", tool, err)
	}
	return output.Bytes()
}

// damagedHeader breaks the checksum field of the first TAR header, which is
// what a corrupted upload looks like to the reader.
func damagedHeader(archive []byte) []byte {
	damaged := bytes.Clone(archive)
	copy(damaged[148:156], []byte("garbage "))
	return damaged
}

// collectNames records every member a scan accepted, in order.
func collectNames(names *[]string) func(string, int64) {
	return func(name string, _ int64) { *names = append(*names, name) }
}

// Each compressed form of a TAR reaches the same reader through a different
// decompressor, so every one of them has to report the same members.
func TestScanTARReadsEveryCompressedForm(t *testing.T) {
	plain := tarArchiveBytes(t, regularMember("public_html/index.html"), regularMember("public_html/style.css"))
	cases := []struct {
		name        string
		archiveType Type
		data        []byte
	}{
		{name: "plain", archiveType: TypeTAR, data: plain},
		{name: "gzip", archiveType: TypeTARGzip, data: compress(t, "gzip", plain)},
		{name: "bzip2", archiveType: TypeTARBzip2, data: compress(t, "bzip2", plain)},
		{name: "xz", archiveType: TypeTARXz, data: compress(t, "xz", plain)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var names []string
			err := scan(context.Background(), archiveFile(t, tc.data), tc.archiveType, Limits{}, collectNames(&names))
			if err != nil {
				t.Fatalf("scan() error = %v", err)
			}
			if strings.Join(names, ",") != "public_html/index.html,public_html/style.css" {
				t.Errorf("members = %v, want both files of the plain archive", names)
			}
		})
	}
}

// A stream that cannot be read is refused with the reason. Reporting it as an
// empty archive would let a corrupt upload extract into nothing and look like a
// success.
func TestScanTARNamesTheStreamItCannotRead(t *testing.T) {
	plain := tarArchiveBytes(t, regularMember("public_html/index.html"))
	cases := []struct {
		name        string
		archiveType Type
		data        []byte
		want        string
	}{
		{name: "a plain TAR declared as gzip", archiveType: TypeTARGzip, data: plain,
			want: "open gzip stream:"},
		{name: "a TAR with a damaged header", archiveType: TypeTAR, data: damagedHeader(plain),
			want: "read TAR archive:"},
		{name: "an xz stream with trailing garbage", archiveType: TypeTARXz,
			data: append(compress(t, "xz", plain), []byte("trailing garbage")...),
			want: "decompress xz archive:"},
		{name: "an xz stream carrying a damaged TAR", archiveType: TypeTARXz,
			data: compress(t, "xz", damagedHeader(plain)),
			want: "read TAR archive:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := scan(context.Background(), archiveFile(t, tc.data), tc.archiveType, Limits{}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("scan() error = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// An archive that is not there names the failure rather than reporting an
// archive with no members.
func TestScanReportsTheArchiveItCannotOpen(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.bin")
	for _, tc := range []struct {
		archiveType Type
		want        string
	}{
		{archiveType: TypeTAR, want: "open archive:"},
		{archiveType: TypeZIP, want: "open ZIP archive:"},
	} {
		err := Scan(context.Background(), missing, tc.archiveType, Limits{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Scan() error = %v, want one naming %q", err, tc.want)
		}
	}
}

// A large archive is walked member by member, so a cancelled request stops the
// walk instead of reading the whole thing.
func TestScanStopsWhenTheRequestIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tarPath := archiveFile(t, tarArchiveBytes(t, regularMember("public_html/index.html")))
	if err := Scan(ctx, tarPath, TypeTAR, Limits{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Scan() TAR error = %v, want context.Canceled", err)
	}
	if err := Scan(ctx, writeZIPMembers(t, 2, 1), TypeZIP, Limits{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Scan() ZIP error = %v, want context.Canceled", err)
	}
}

// A ZIP inventory rides on the same walk as its validation, so the collector
// sees every member with the size the archive declares for it.
func TestScanZIPReportsEachMemberToTheCollector(t *testing.T) {
	var names []string
	var total int64
	err := scan(context.Background(), writeZIPMembers(t, 2, 5), TypeZIP, Limits{},
		func(name string, size int64) {
			names = append(names, name)
			total += size
		})
	if err != nil {
		t.Fatalf("scan() error = %v", err)
	}
	if len(names) != 2 || total != 10 {
		t.Errorf("collected %v totalling %d, want both members totalling 10", names, total)
	}
}

// xz is an external tool. A host without it refuses the archive and names the
// tool, rather than reading the stream as an archive with no members.
func TestScanTARReportsAMissingDecompressor(t *testing.T) {
	path := archiveFile(t, compress(t, "xz", tarArchiveBytes(t, regularMember("public_html/index.html"))))
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))

	err := scan(context.Background(), path, TypeTARXz, Limits{}, nil)
	if err == nil || !strings.Contains(err.Error(), "start xz:") {
		t.Fatalf("scan() error = %v, want one naming xz", err)
	}
}

// The RAR listing carries the member count and the sizes, so both the limit and
// the inventory are read from it.
func TestValidateLSARListingCountsMembersAndReportsSizes(t *testing.T) {
	listing := []byte(`{"lsarContents":[` +
		`{"XADFileName":"site/index.html","XADFileType":"Regular","XADFileSize":10},` +
		`{"XADFileName":"site/app.css","XADFileType":"Regular","XADFileSize":20}]}`)

	if err := validateLSARListing(listing, Limits{MaxMembers: 1}, nil); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("validateLSARListing() error = %v, want ErrTooManyMembers", err)
	}

	var names []string
	var total int64
	err := validateLSARListing(listing, Limits{}, func(name string, size int64) {
		names = append(names, name)
		total += size
	})
	if err != nil {
		t.Fatalf("validateLSARListing() error = %v", err)
	}
	if strings.Join(names, ",") != "site/index.html,site/app.css" || total != 30 {
		t.Errorf("collected %v totalling %d, want both members totalling 30", names, total)
	}
}

// The archive root entry is not a member. Counting it would report one member
// more than the archive holds and add "." as a root, which would then look like
// a container directory.
func TestSummarizeSkipsTheArchiveRootEntry(t *testing.T) {
	path := archiveFile(t, tarArchiveBytes(t,
		tar.Header{Name: "./", Mode: 0755, Typeflag: tar.TypeDir},
		regularMember("./public_html/index.html")))

	summary, err := Summarize(context.Background(), path, TypeTAR, Limits{}, nil)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Members != 1 {
		t.Errorf("members = %d, want only the file", summary.Members)
	}
	if strings.Join(summary.Roots, ",") != "public_html" {
		t.Errorf("roots = %v, want only public_html", summary.Roots)
	}
}
