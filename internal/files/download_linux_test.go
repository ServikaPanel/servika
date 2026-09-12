//go:build linux

package files

// Download against a real tenant tree. Linux-only because openReadBeneath is:
// the darwin stub refuses every path, so a test there would prove nothing.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// download runs one request for a home-relative path.
func download(t *testing.T, rel string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, homeScript())}).
		Download(recorder, filesRequest(http.MethodGet, "/files/7/download?path="+rel, ""))
	return recorder
}

// A tenant holds a shell as their own c_* account, so they can mkfifo inside
// their home. Before this, the open succeeded (a fifo is not a directory), the
// stat reported size 0, and the io.Copy waited on the pipe for as long as the
// tenant kept a writer open, holding a goroutine and a connection for the whole
// 30-minute deadline this handler grants itself.
func TestANamedPipeCannotBeDownloaded(t *testing.T) {
	home := tenantHome(t)
	pipe := filepath.Join(home, "trap")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("mkfifo is not available here: %v", err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- download(t, "trap") }()

	select {
	case recorder := <-done:
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the download blocked on the pipe instead of refusing it")
	}
}

// A directory keeps its own answer: it is a different mistake and the message
// an operator reads should say which one they made.
func TestADirectoryStillReportsThatItIsADirectory(t *testing.T) {
	home := tenantHome(t)
	if err := os.Mkdir(filepath.Join(home, "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}

	recorder := download(t, "public_html")

	assertResponse(t, recorder, http.StatusBadRequest, "directories cannot be downloaded")
}

// The regular case must keep working, or the guard has replaced one failure
// with another.
func TestARegularFileIsStillServedWithItsLength(t *testing.T) {
	home := tenantHome(t)
	const body = "hello from the tenant"
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	recorder := download(t, "notes.txt")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != body {
		t.Errorf("body = %q, want %q", recorder.Body.String(), body)
	}
	if got := recorder.Header().Get("Content-Length"); got != "21" {
		t.Errorf("Content-Length = %q, want 21", got)
	}
}
