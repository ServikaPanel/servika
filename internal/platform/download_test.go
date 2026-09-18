package platform

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// payload is the body every download test serves.
var payload = []byte(strings.Repeat("servika-installer-bytes|", 512))

// payloadSum is its SHA-256.
func payloadSum() string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// newJob returns one a download can write into.
func newJob() *Job { return &Job{ID: "d", state: JobRunning} }

// pin makes url carry an expected checksum for the duration of one test.
func pin(t *testing.T, url, sum string) {
	t.Helper()
	downloadSums[url] = sum
	t.Cleanup(func() { delete(downloadSums, url) })
}

// serveBytes answers GET with the payload, honouring a Range request.
func serveBytes(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func TestAVerifiedDownloadLandsAtTheTargetPath(t *testing.T) {
	url := serveBytes(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	pin(t, url, payloadSum())

	target := filepath.Join(t.TempDir(), "sub", "installer.msi")
	if err := download(newJob(), url, target); err != nil {
		t.Fatalf("the download failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the target is not there: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the target holds different bytes")
	}
	if _, err := os.Stat(target + ".part"); !os.IsNotExist(err) {
		t.Fatal("the temporary file was left behind")
	}
}

func TestAWrongChecksumNeverReachesTheTargetPath(t *testing.T) {
	// Every byte here is about to run as SYSTEM, so a file that does not match
	// its pin must not exist at the path the installer runs.
	var served int
	url := serveBytes(t, func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte("this is not the installer"))
	})
	pin(t, url, payloadSum())

	target := filepath.Join(t.TempDir(), "installer.msi")
	err := download(newJob(), url, target)
	if err == nil {
		t.Fatal("a file that failed its checksum was accepted")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("the failure did not name the checksum: %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("the unverified file reached the target path")
	}
	if _, statErr := os.Stat(target + ".part"); !os.IsNotExist(statErr) {
		t.Fatal("the corrupt temporary file was left on disk")
	}
	if served != downloadAttempts {
		t.Fatalf("a checksum mismatch was retried %d times, expected %d", served, downloadAttempts)
	}
}

func TestAMissingFileIsNotRetried(t *testing.T) {
	// 404, 403 and 410 all mean the file is not there, and waiting does not put
	// it back.
	var served int
	url := serveBytes(t, func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusNotFound)
	})
	target := filepath.Join(t.TempDir(), "installer.msi")
	err := download(newJob(), url, target)
	if !errors.Is(err, errPermanentDownload) {
		t.Fatalf("a 404 was not treated as permanent: %v", err)
	}
	if served != 1 {
		t.Fatalf("a 404 was fetched %d times", served)
	}
}

func TestATemporaryFailureIsRetriedAndCanSucceed(t *testing.T) {
	var served int
	url := serveBytes(t, func(w http.ResponseWriter, _ *http.Request) {
		served++
		if served < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(payload)
	})
	pin(t, url, payloadSum())

	target := filepath.Join(t.TempDir(), "installer.msi")
	start := time.Now()
	if err := download(newJob(), url, target); err != nil {
		t.Fatalf("a recoverable download failed: %v", err)
	}
	if served != 3 {
		t.Fatalf("the download was attempted %d times", served)
	}
	// 2s then 4s of backoff; a run much faster than that means the wait is gone.
	if elapsed := time.Since(start); elapsed < 6*time.Second {
		t.Fatalf("the retries waited only %v, so the backoff is not applied", elapsed)
	}
}

func TestACutDownloadResumesFromWhatArrived(t *testing.T) {
	// Without a resume a connection that drops near the end of a gigabyte
	// installer starts the whole fetch again.
	var ranges []string
	url := serveBytes(t, func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Range")
		ranges = append(ranges, header)
		if header == "" {
			// First attempt: send half and cut the connection.
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			_, _ = w.Write(payload[:len(payload)/2])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler) // drops the connection mid-body
		}
		var from int
		if _, err := fmt.Sscanf(header, "bytes=%d-", &from); err != nil || from <= 0 {
			t.Errorf("the resume asked for %q", header)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(payload)-1, len(payload)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[from:])
	})
	pin(t, url, payloadSum())

	target := filepath.Join(t.TempDir(), "installer.msi")
	if err := download(newJob(), url, target); err != nil {
		t.Fatalf("the resumed download failed: %v", err)
	}
	if len(ranges) < 2 || ranges[1] == "" {
		t.Fatalf("the second attempt did not ask to resume: %v", ranges)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("the resumed file does not match the original")
	}
}

func TestWithoutAChecksumTheDownloadNeverResumes(t *testing.T) {
	// A redirecting address can serve different bytes on the second attempt, and
	// the two halves would be stitched into a file nothing detects as wrong
	// before it runs as SYSTEM.
	dir := t.TempDir()
	target := filepath.Join(dir, "installer.msi")
	if err := os.WriteFile(target+".part", []byte("half of yesterday's file"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ranges []string
	url := serveBytes(t, func(w http.ResponseWriter, r *http.Request) {
		ranges = append(ranges, r.Header.Get("Range"))
		_, _ = w.Write(payload)
	})
	// No pin for this URL on purpose.
	if err := download(newJob(), url, target); err != nil {
		t.Fatalf("the unpinned download failed: %v", err)
	}
	if ranges[0] != "" {
		t.Fatalf("an unpinned download asked to resume: %q", ranges[0])
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, payload) {
		t.Fatal("the stale partial file was stitched into the result")
	}
}

func TestAnUnpinnedDownloadSaysSoInTheLog(t *testing.T) {
	// Passing over a missing checksum quietly would read as "verified".
	url := serveBytes(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	job := newJob()
	if err := download(job, url, filepath.Join(t.TempDir(), "x.msi")); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(job.view().Log, "\n")
	if !strings.Contains(log, "NO checksum pinned") {
		t.Fatalf("the missing checksum was not reported:\n%s", log)
	}
}

func TestEveryPinnedAddressIsVersionLocked(t *testing.T) {
	// An address that redirects to "the current release" serves different bytes
	// over time, so pinning it would fail every installation the day the vendor
	// publishes an update.
	for url := range downloadSums {
		for _, redirector := range []string{"aka.ms", "go.microsoft.com/fwlink"} {
			if strings.Contains(url, redirector) {
				t.Errorf("the redirecting address %q carries a checksum pin", url)
			}
		}
	}
	for _, url := range []string{dotnetHostingURL, mssqlURL} {
		if _, pinned := downloadSums[url]; pinned {
			t.Errorf("%q is a redirect and must not be pinned", url)
		}
	}
}

func TestTheProgressStaysUnknownWhileTheSizeIs(t *testing.T) {
	// A server that sends no length genuinely does not say how much is coming.
	reader := &progressReader{read: 1000, size: 0, startedAt: time.Now().Add(-time.Second)}
	got := reader.snapshot(time.Now())
	if got.Percent != -1 || got.SecondsLeft != -1 {
		t.Fatalf("an unknown size produced %+v", got)
	}
	if got.BytesPerSec <= 0 {
		t.Fatal("the speed is not reported even though bytes arrived")
	}
}

func TestTheEstimateCountsOnlyTheBytesThisAttemptFetched(t *testing.T) {
	// A resumed download starts with megabytes already on disk. Counting those
	// towards the speed would report a rate the line never reached.
	reader := &progressReader{
		read: 3 << 20, startByte: 2 << 20, size: 4 << 20,
		startedAt: time.Now().Add(-time.Second),
	}
	got := reader.snapshot(time.Now())
	if got.BytesPerSec > (1<<20)+(1<<18) {
		t.Fatalf("the resumed offset was counted as speed: %d B/s", got.BytesPerSec)
	}
	if got.Percent != 75 {
		t.Fatalf("the percentage read %d, expected 75", got.Percent)
	}
	if got.SecondsLeft != 1 {
		t.Fatalf("the estimate read %d seconds, expected 1", got.SecondsLeft)
	}
}

func TestThePercentageNeverPassesOneHundred(t *testing.T) {
	// A server that understates its length must not make the bar overflow.
	reader := &progressReader{read: 500, size: 100, startedAt: time.Now().Add(-time.Second)}
	if got := reader.snapshot(time.Now()); got.Percent != 100 {
		t.Fatalf("the percentage read %d", got.Percent)
	}
}

func TestAResumedSizeAddsTheOffsetBack(t *testing.T) {
	// On a 206 the content length is what REMAINS, not the whole file.
	resp := &http.Response{ContentLength: 600}
	if got := fullSize(resp, 400, true); got != 1000 {
		t.Fatalf("the resumed size read %d, expected 1000", got)
	}
	if got := fullSize(resp, 400, false); got != 600 {
		t.Fatalf("a fresh download read %d, expected 600", got)
	}
	if got := fullSize(&http.Response{ContentLength: -1}, 0, false); got != 0 {
		t.Fatalf("an unknown length read %d, expected 0", got)
	}
}

// makeZip writes an archive with the given entry names.
func makeZip(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, name := range names {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("content of " + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAZipEntryCannotWriteOutsideTheTargetDirectory(t *testing.T) {
	// "..\..\x.exe" would land somewhere the installer then runs as SYSTEM.
	dir := t.TempDir()
	for _, name := range []string{
		"../escaped.exe", "../../escaped.exe", "sub/../../escaped.exe",
	} {
		if _, err := entryTarget(name, dir); err == nil {
			t.Errorf("the entry %q was allowed out of the target directory", name)
		}
	}
	for _, name := range []string{"tool.exe", "sub/tool.exe", "a/b/../c.exe"} {
		if _, err := entryTarget(name, dir); err != nil {
			t.Errorf("the ordinary entry %q was refused: %v", name, err)
		}
	}
}

func TestOneEscapingEntryRejectsTheWholeArchive(t *testing.T) {
	// Half an archive on disk is worse than none: the operator sees files and
	// assumes the rest arrived.
	dir := t.TempDir()
	archive := makeZip(t, "good.exe", "../escaped.exe")
	err := unzip(newJob(), archive, dir)
	if err == nil {
		t.Fatal("an archive holding an escaping entry was accepted")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("the failure did not say the archive was rejected: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "escaped.exe")); statErr == nil {
		t.Fatal("a file was written outside the target directory")
	}
}

func TestAnOrdinaryArchiveUnpacks(t *testing.T) {
	dir := t.TempDir()
	archive := makeZip(t, "tool.exe", "sub/data.txt")
	if err := unzip(newJob(), archive, dir); err != nil {
		t.Fatalf("an ordinary archive failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "sub", "data.txt"))
	if err != nil || string(got) != "content of sub/data.txt" {
		t.Fatalf("the nested entry read as %q (%v)", got, err)
	}
}
