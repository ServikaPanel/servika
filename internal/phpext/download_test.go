package phpext

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// trusting returns a client with the redirect policy under test and the test
// server's certificate accepted, so the measurement is about the policy rather
// than about the certificate.
func trusting(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	client := loaderClient()
	client.Transport = server.Client().Transport
	return client
}

// http.DefaultClient followed https to plain http silently. Measured with a real
// Go client against a TLS server redirecting to a plain one: the request started
// at https, ended at http, and the body came back over the plaintext hop. These
// bytes become a zend_extension loaded into every PHP process on the server, so
// the address being https has to mean something.
func TestARedirectOutOfTLSIsRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "payload from the plaintext hop")
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()

	resp, err := trusting(t, secure).Get(secure.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("the downgrade was followed and ended at %s", resp.Request.URL)
	}
	if !strings.Contains(err.Error(), "refusing a redirect from https") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The guard is not vacuous: a redirect that stays on TLS is still followed, so
// a publisher moving the archive to another https path keeps working.
func TestARedirectThatStaysOnTLSIsFollowed(t *testing.T) {
	const body = "payload from the second TLS hop"
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer second.Close()

	first := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL, http.StatusFound)
	}))
	// Both servers share one certificate authority so a single client trusts the
	// whole chain; otherwise the second hop would fail on the certificate and the
	// test would pass for the wrong reason.
	first.TLS = &tls.Config{Certificates: second.TLS.Certificates} // #nosec G402 -- test server, no MinVersion needed
	first.StartTLS()
	defer first.Close()

	client := loaderClient()
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: second.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}, // #nosec G402 -- test roots
	}

	resp, err := client.Get(first.URL)
	if err != nil {
		t.Fatalf("an https to https redirect was refused: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("body %q, want %q", got, body)
	}
	if resp.Request.URL.Scheme != "https" {
		t.Errorf("ended on %s, want https", resp.Request.URL.Scheme)
	}
}

// A redirect loop must end in an error rather than in a request that never
// returns. The policy replaces Go's default entirely, so it has to count.
func TestARedirectLoopIsBounded(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/again", http.StatusFound)
	}))
	defer server.Close()

	resp, err := loaderClient().Get(server.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatal("a redirect loop returned a response")
	}
	if !strings.Contains(err.Error(), "stopped after") {
		t.Errorf("the loop ended for the wrong reason: %v", err)
	}
}
