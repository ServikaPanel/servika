package wpchecksums

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A body that is not the answer wordpress.org publishes is a failure, never an
// answer. These pin the two decode refusals apart from the "nothing published"
// case, which is remembered while a failure is not.

// answeringWith starts a server that answers every request with one body, and
// points the package at it.
func answeringWith(t *testing.T, body string) {
	t.Helper()
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	swapEndpoint(t, server.URL)
}

// A truncated or non-JSON body is a failure, so the next check asks again.
func TestABodyThatIsNotJSONIsAFailure(t *testing.T) {
	answeringWith(t, "<html>proxy error</html>")

	_, err := Table(context.Background(), Details{Version: "7.1"})

	if err == nil {
		t.Fatal("a body that is not JSON was accepted")
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Errorf("err = %v, want a failure rather than the unpublished answer", err)
	}
}

// A checksums field that is present but is not a table of strings is the same
// case: it is not the answer, and it is not a version nobody published.
func TestATableOfTheWrongShapeIsAFailure(t *testing.T) {
	answeringWith(t, `{"checksums":{"wp-admin/index.php":123}}`)

	_, err := Table(context.Background(), Details{Version: "7.1"})

	if err == nil {
		t.Fatal("a table of numbers was accepted")
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Errorf("err = %v, want a failure rather than the unpublished answer", err)
	}
}

// The answer is bounded while it is read, so a body that never ends cannot be
// held in memory in full.
func TestAnEndlessBodyIsRefused(t *testing.T) {
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"checksums":{`)
		for range 4096 {
			_, _ = io.WriteString(w, `"`+strings.Repeat("a", 1024)+`":"x",`)
		}
	}))
	defer server.Close()
	swapEndpoint(t, server.URL)

	if _, err := Table(context.Background(), Details{Version: "7.1"}); err == nil {
		t.Fatal("an endless body was accepted")
	}
}
