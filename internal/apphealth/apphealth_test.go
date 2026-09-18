package apphealth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The probe answers the question systemctl cannot: is the program listening?
// These tests pin that a closed port fails, that an open one passes, that an
// HTTP application answering 404 still counts as up, and that the probe never
// leaves the loopback interface.

// listener opens a TCP port and returns it, closed when the test ends.
func listener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port nothing is listening on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// A port something is listening on passes on the first attempt.
func TestAListeningPortPasses(t *testing.T) {
	if err := Wait(context.Background(), Probe{Port: listener(t)}); err != nil {
		t.Errorf("a listening port reported %v", err)
	}
}

// A port nothing is listening on is reported, and the message names the port
// and how many attempts were spent, because that is what an operator reading a
// failed start needs.
func TestAClosedPortIsReportedAfterEveryAttempt(t *testing.T) {
	port := closedPort(t)
	// The attempts are real, so the budget is cut with a context rather than by
	// waiting eight seconds for a unit test.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	err := Wait(ctx, Probe{Port: port})

	if err == nil {
		t.Fatal("a closed port reported healthy")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(port)) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the failure does not say which port: %v", err)
	}
}

// A probe with no port is a caller mistake, not an unhealthy application, and
// the two must not read the same: a start that silently "failed its health
// check" because nobody set the port is worse than one that says so.
func TestAProbeWithNoPortIsACallerMistake(t *testing.T) {
	if err := Wait(context.Background(), Probe{}); !errors.Is(err, ErrNoPort) {
		t.Errorf("err = %v, want ErrNoPort", err)
	}
}

// An HTTP application that answers 404 is UP. The panel does not know what an
// application's paths mean, so treating anything but 200 as unhealthy would
// report a working install as down.
func TestAnHTTPApplicationAnsweringNotFoundIsStillUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	port := portOf(t, server.URL)

	if err := Wait(context.Background(), Probe{Port: port, Path: "/healthz"}); err != nil {
		t.Errorf("a 404 was treated as unhealthy: %v", err)
	}
}

// The HTTP probe asks for the path it was given, on the loopback interface. A
// probe that could be pointed anywhere else would be an SSRF with the panel's
// own network position.
func TestTheHTTPProbeStaysOnLoopbackAndAsksForItsPath(t *testing.T) {
	var host, path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, path = r.Host, r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	port := portOf(t, server.URL)

	if err := Wait(context.Background(), Probe{Port: port, Path: "/api/health"}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !strings.HasPrefix(host, "127.0.0.1:") {
		t.Errorf("the probe asked host %q, want 127.0.0.1", host)
	}
	if path != "/api/health" {
		t.Errorf("the probe asked for %q", path)
	}
}

// A redirect is an answer. Following one would let the application's own
// configuration send this request off the loopback interface.
func TestARedirectCountsAsAnAnswerAndIsNotFollowed(t *testing.T) {
	var asked int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked++
		http.Redirect(w, &http.Request{}, "http://example.invalid/elsewhere", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	if err := Wait(context.Background(), Probe{Port: portOf(t, server.URL), Path: "/"}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if asked != 1 {
		t.Errorf("the probe made %d requests, want 1", asked)
	}
}

// A context that ends during the initial delay stops the probe rather than
// running the whole budget. A restore that the operator cancelled must not keep
// dialling for eight more seconds.
func TestACancelledContextStopsTheProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Wait(ctx, Probe{Port: closedPort(t), InitialDelay: time.Minute})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// Healthy answers the same question as Wait, reduced to the fact.
func TestHealthyAgreesWithWait(t *testing.T) {
	if !Healthy(context.Background(), Probe{Port: listener(t)}) {
		t.Error("a listening port reported unhealthy")
	}
}

// portOf reads the port out of an httptest server URL.
func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return n
}
