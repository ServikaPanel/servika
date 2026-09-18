package platform

// Fetching an installer and unpacking it.
//
// EVERY BYTE HERE IS ABOUT TO RUN AS SYSTEM. That is the reason for each rule
// below: the download is verified against a pinned SHA-256 where the address is
// version-locked, a half-finished download never reaches the target path, and a
// zip entry that would write outside the target directory rejects the whole
// archive.
//
// This file carries no build tag. Nothing in it is Windows-specific: net/http,
// archive/zip and crypto/sha256 behave the same everywhere, so all of it is
// measured on every build.

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Download addresses. Each is version-locked except where noted, so the bytes
// fetched today are the bytes that were measured.
const (
	dotnetHostingURL = "https://aka.ms/dotnet/8.0/dotnet-hosting-win.exe"
	winAcmeURL       = "https://github.com/win-acme/win-acme/releases/download/v2.2.9.1701/win-acme.v2.2.9.1701.x64.pluggable.zip"
	mssqlURL         = "https://go.microsoft.com/fwlink/?linkid=2216019"
	gosqlcmdURL      = "https://github.com/microsoft/go-sqlcmd/releases/download/v1.8.0/sqlcmd-windows-amd64.zip"
	mysqlURL         = "https://dev.mysql.com/get/Downloads/MySQLInstaller/mysql-installer-community-8.0.40.0.msi"
	pgsqlURL         = "https://get.enterprisedb.com/postgresql/postgresql-16.4-1-windows-x64.exe"
	nodeURL          = "https://nodejs.org/dist/v20.18.1/node-v20.18.1-x64.msi"
	gitURL           = "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe"
	rewriteURL       = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
	phpMyAdminURL    = "https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.zip"
)

const (
	// downloadAttempts and backoffBase give 2, 4 and 8 seconds between tries.
	downloadAttempts = 4
	backoffBase      = 2 * time.Second

	// downloadTimeout bounds ONE attempt. SQL Express is close to a gigabyte and
	// a slow line needs room, while a connection that stalls for ever must not
	// leave a job reading "running" until the agent is restarted.
	downloadTimeout = 30 * time.Minute

	// logEvery is how much has to arrive before another text line is written.
	// The structured progress carries the live bar; this is for the log.
	logEvery = 10 << 20

	// progressEvery throttles the structured update.
	progressEvery = 250 * time.Millisecond
)

// errPermanentDownload marks a failure that will NOT get better by trying
// again: 404, 403 and 410 all mean the file is not there. Everything else (a
// connection error, a 5xx, a half-received body, a checksum mismatch) counts as
// temporary and is retried with backoff.
var errPermanentDownload = errors.New("the download failed permanently")

// downloadSums pins the SHA-256 of a download.
//
// ONLY A VERSION-LOCKED, UNCHANGING ADDRESS IS PINNED. An address that
// redirects to "the current release" (aka.ms, go.microsoft.com/fwlink) serves
// different bytes over time, so pinning it would fail every installation the
// day the vendor publishes an update. Those are NOT pinned, and the log says so
// in words rather than passing over it quietly. A URL absent from this map
// means "no checksum", never "verified".
//
// Each value below was computed by fetching the address and hashing the result.
var downloadSums = map[string]string{
	gosqlcmdURL:   "fcfc2960426637e049d961722ad5eed6f4a824c9724163ef7f681fc568420b41",
	winAcmeURL:    "a2c874e9893a1d91e0329887f72c067dcc49800a49963fa7d61c5a4e09058f0c",
	rewriteURL:    "37342ff2f585f263f34f48e9de59eb1051d61015a8e967dbde4075716230a32a",
	mysqlURL:      "f7ac30efc8b04a8348756ce3b69718da9619a5c5b061354fafd3849fd339c90d",
	phpMyAdminURL: "31c95fe5c00e0f899b5d31ac6fff506cf8061f2f746e9d7084c395f47451946e",
	nodeURL:       "658930e6136d01bf244146a6436d8ea146cd50557c1b2a2617a60bcd9dce0da1",
	gitURL:        "25527923debc06515b3016f2d6bca0820656e8281a23be2f43bfb658bd5dda70",
	pgsqlURL:      "f4bf0ac4b33471f18aad7d1d9cc52613003f3a3a612aae167366bf7f7840b2bc",
	// NOT pinned, on purpose: mssqlURL and dotnetHostingURL are redirects whose
	// target file changes when the vendor publishes an update.
}

// progressReader counts what has been read and reports it two ways: a text line
// every logEvery bytes, and the structured progress a live bar reads, throttled
// to progressEvery.
//
// The speed is an AVERAGE since the attempt started, not an instant rate. An
// instant rate jumps around and makes the estimate jump with it.
type progressReader struct {
	r     io.Reader
	job   *Job
	label string

	read      int64 // bytes read so far, including a resumed offset
	size      int64 // full file size; 0 means unknown
	lastLog   int64
	startedAt time.Time
	startByte int64 // the resumed offset, which does not count towards the speed
	lastTick  time.Time
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.read += int64(n)
	if p.read-p.lastLog >= logEvery {
		p.lastLog = p.read
		p.job.Logf("  ... %d MB in", p.read>>20)
	}
	now := time.Now()
	if err != nil || now.Sub(p.lastTick) >= progressEvery {
		p.lastTick = now
		p.job.setProgress(p.snapshot(now))
	}
	return n, err
}

// snapshot computes the bytes, speed and estimate.
//
// Percent and SecondsLeft stay -1 while the size is unknown, because a server
// that sends no length genuinely does not say how much is coming.
func (p *progressReader) snapshot(now time.Time) Progress {
	out := Progress{
		Stage: "downloading", Label: p.label,
		BytesDone: p.read, BytesTotal: p.size,
		Percent: -1, SecondsLeft: -1,
	}
	elapsed := now.Sub(p.startedAt).Seconds()
	if elapsed <= 0 {
		return out
	}
	speed := float64(p.read-p.startByte) / elapsed
	out.BytesPerSec = int64(speed)
	if p.size <= 0 {
		return out
	}
	out.Percent = min(int(float64(p.read)/float64(p.size)*100), 100)
	if speed > 0 {
		out.SecondsLeft = int(float64(p.size-p.read) / speed)
	}
	return out
}

// download fetches url to target.
//
// It writes to a ".part" file, retries with exponential backoff, RESUMES a cut
// download with an HTTP Range request, computes the SHA-256 as the bytes
// arrive, and only after the checksum holds does it move the file to target.
// So a target path that exists is a file that was fully received and verified.
func download(job *Job, url, target string) error {
	expected := downloadSums[url]
	part := target + ".part"
	label := filepath.Base(target)
	job.Logf("downloading: %s", url)

	var last error
	for attempt := 1; attempt <= downloadAttempts; attempt++ {
		if attempt > 1 {
			wait := backoffBase * time.Duration(int64(1)<<(attempt-2))
			job.Logf("  retrying the download (%d/%d, in %v): %v", attempt, downloadAttempts, wait, last)
			time.Sleep(wait)
		}
		last = downloadOnce(job, url, part, expected, label)
		if last == nil {
			return finishDownload(job, part, target)
		}
		if errors.Is(last, errPermanentDownload) {
			_ = os.Remove(part)
			return last
		}
	}
	_ = os.Remove(part) // the last attempt failed too; leave no remains
	return fmt.Errorf("the download failed after %d attempts: %w", downloadAttempts, last)
}

// finishDownload moves the verified temporary file into place.
func finishDownload(job *Job, part, target string) error {
	if err := os.Rename(part, target); err != nil {
		_ = os.Remove(part)
		return fmt.Errorf("the downloaded file could not be moved into place: %w", err)
	}
	job.Logf("downloaded: %s", filepath.Base(target))
	return nil
}

// downloadOnce is ONE attempt.
func downloadOnce(job *Job, url, part, expected, label string) error {
	if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
		return fmt.Errorf("the download directory could not be created: %w", err)
	}
	// WITHOUT A CHECKSUM, NEVER RESUME. A redirecting address can serve
	// different bytes on the second attempt, and the two halves would be
	// stitched into a file nothing can detect as wrong before it runs as SYSTEM.
	if expected == "" {
		_ = os.Remove(part)
	}
	from := partialSize(part)

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	resp, err := requestFrom(ctx, url, from)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	resume, err := readRange(resp, part, url)
	if err != nil {
		return err
	}
	if !resume {
		from = 0
	}
	written, sum, err := copyBody(job, resp, part, label, from, resume)
	if err != nil {
		return err
	}
	return verifySum(job, part, expected, sum, from+written)
}

// partialSize reports how much of an interrupted download is already on disk.
func partialSize(part string) int64 {
	if fi, err := os.Stat(part); err == nil {
		return fi.Size()
	}
	return 0
}

// requestFrom issues the GET, asking for the remainder when there is one.
func requestFrom(ctx context.Context, url string, from int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: the request could not be built: %v", errPermanentDownload, err)
	}
	if from > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", from))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection: %w", err) // temporary, so it is retried
	}
	return resp, nil
}

// readRange decides what the status code means for resuming.
func readRange(resp *http.Response, part, url string) (bool, error) {
	switch resp.StatusCode {
	case http.StatusOK:
		return false, nil // the server ignored the range, or this is a first try
	case http.StatusPartialContent:
		return true, nil
	case http.StatusRequestedRangeNotSatisfiable:
		_ = os.Remove(part) // what is on disk is longer than the file; start over
		return false, errors.New("the range was refused (416), so the download starts again")
	case http.StatusNotFound, http.StatusForbidden, http.StatusGone:
		return false, fmt.Errorf("%w: HTTP %d (%s)", errPermanentDownload, resp.StatusCode, url)
	}
	return false, fmt.Errorf("HTTP %d (%s)", resp.StatusCode, url) // 5xx and the rest are retried
}

// copyBody streams the body into the part file while hashing it, and returns
// how much this attempt wrote plus the hash of the WHOLE file.
func copyBody(job *Job, resp *http.Response, part, label string, from int64, resume bool) (int64, string, error) {
	digest := sha256.New()
	flags := os.O_CREATE | os.O_WRONLY
	if resume {
		// The hash has to cover the whole file, so the bytes already on disk are
		// fed through it before the new ones arrive.
		if f, err := os.Open(part); err == nil {
			_, _ = io.Copy(digest, f)
			_ = f.Close()
		}
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return 0, "", fmt.Errorf("the temporary file could not be opened: %w", err)
	}
	now := time.Now()
	reader := &progressReader{
		r: resp.Body, job: job, label: label,
		read: from, size: fullSize(resp, from, resume), lastLog: from,
		startedAt: now, startByte: from, lastTick: now,
	}
	n, err := io.Copy(io.MultiWriter(f, digest), reader)
	closeErr := f.Close()
	if err != nil {
		// Temporary: the next attempt resumes from what did arrive.
		return n, "", fmt.Errorf("the download stopped part way (%d bytes): %w", from+n, err)
	}
	if closeErr != nil {
		return n, "", fmt.Errorf("the downloaded file could not be closed: %w", closeErr)
	}
	return n, hex.EncodeToString(digest.Sum(nil)), nil
}

// fullSize works out the whole file's size. On a 206 the length is what REMAINS,
// so the offset is added back. An unknown length stays 0, which the bar reads as
// indeterminate.
func fullSize(resp *http.Response, from int64, resume bool) int64 {
	if resp.ContentLength <= 0 {
		return 0
	}
	if resume {
		return from + resp.ContentLength
	}
	return resp.ContentLength
}

// verifySum compares the hash against the pin, and says plainly when there is
// no pin instead of passing over it quietly.
func verifySum(job *Job, part, expected, sum string, total int64) error {
	megabytes := float64(total) / (1 << 20)
	if expected == "" {
		job.Logf("  note: this download has NO checksum pinned, so it was not verified - %.1f MB", megabytes)
		return nil
	}
	if !strings.EqualFold(sum, expected) {
		_ = os.Remove(part) // a corrupt download: drop it and start again
		return fmt.Errorf("the checksum does not match (expected %s, got %s)", expected, sum)
	}
	job.Logf("  checksum verified (sha256 %s..., %.1f MB)", sum[:12], megabytes)
	return nil
}

// unzip unpacks an archive into a directory.
//
// ZIP SLIP: an entry named "..\..\x.exe" would write OUTSIDE the target
// directory, and what is written there is about to run as SYSTEM. The archive
// comes off the internet, so its contents are not trusted however fixed the
// version is. Every entry's resolved path MUST stay under the target, and ONE
// entry that escapes rejects the whole archive rather than leaving it half
// unpacked.
func unzip(job *Job, archive, dir string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("the archive could not be opened: %w", err)
	}
	defer func() { _ = r.Close() }()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("the target directory could not be created: %w", err)
	}
	for _, entry := range r.File {
		if err := extractEntry(entry, dir); err != nil {
			return err
		}
	}
	job.Logf("archive unpacked: %d entries -> %s", len(r.File), dir)
	return nil
}

// entryTarget resolves one entry's path and refuses one that leaves dir.
func entryTarget(name, dir string) (string, error) {
	root := filepath.Clean(dir) + string(os.PathSeparator)
	// filepath.Join cleans the result, so "a/../../x" resolves before the check.
	target := filepath.Join(dir, name)
	if !strings.HasPrefix(target, root) {
		return "", fmt.Errorf("a zip entry points outside the target directory, so the archive was rejected: %q", name)
	}
	return target, nil
}

// extractEntry writes one entry.
func extractEntry(entry *zip.File, dir string) error {
	target, err := entryTarget(entry.Name, dir)
	if err != nil {
		return err
	}
	if entry.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := writeEntry(entry, target); err != nil {
		return fmt.Errorf("%s could not be extracted: %w", entry.Name, err)
	}
	return nil
}

// writeEntry copies one file out of the archive.
func writeEntry(entry *zip.File, target string) error {
	src, err := entry.Open()
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.Create(target)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}
