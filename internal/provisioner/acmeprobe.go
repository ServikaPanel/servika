package provisioner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/logx"
	"servika/internal/netguard"
)

// Let's Encrypt fails the WHOLE order when any one name in it fails validation,
// so a name that cannot answer http-01 does not merely miss out, it takes the
// apex down with it. DNS resolving here is not proof that it can answer: a CDN
// may sit in front, port 80 may be filtered, or another vhost may already claim
// the name.
//
// So each name is measured before it enters the SAN: write a random token under
// the ACME webroot and read it back over HTTP. Only an exact match counts.

const (
	challengeTimeout = 15 * time.Second
	challengeMaxBody = 512
)

// acmeWebrootDir is the directory nginx serves /.well-known/acme-challenge/ from
// on every vhost, including the port-80 catch-all. It is a variable so a test can
// point it at a temporary directory.
var acmeWebrootDir = "/var/www/_acme"

// challengeReason is a stable code the caller can hand to a UI, which then
// translates it. The API is English and the interface ships twelve languages, so
// a sentence built here could not be translated.
type challengeReason string

const (
	reasonUnreachable    challengeReason = "challenge_unreachable"
	reasonWrongStatus    challengeReason = "challenge_status"
	reasonWrongContent   challengeReason = "challenge_mismatch"
	reasonWebrootUnwrite challengeReason = "challenge_webroot_unwritable"
)

// challengeProbe is a seam: tests drive the HTTP side without a network.
var challengeProbe = fetchChallenge

// challengeReachable reports whether host would pass an http-01 validation right
// now. It returns one of the reason codes above when it would not.
func challengeReachable(host string) (challengeReason, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return reasonWebrootUnwrite, fmt.Errorf("could not generate a challenge token: %w", err)
	}
	token := "servika-preflight-" + hex.EncodeToString(raw)
	// The body is deliberately not the token alone: a server that echoes the
	// request path back would otherwise look like a pass.
	body := token + "." + hex.EncodeToString(raw)

	dir := filepath.Join(acmeWebrootDir, ".well-known", "acme-challenge")
	// #nosec G301 -- the ACME webroot is served by nginx and holds only short-lived public challenge tokens.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return reasonWebrootUnwrite, err
	}
	path := filepath.Join(dir, token)
	// #nosec G306 -- a challenge token is public by definition; the CA fetches it over plain HTTP.
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return reasonWebrootUnwrite, err
	}
	defer func() { _ = os.Remove(path) }()
	_, _ = tenantCommand("restorecon", "-R", acmeWebrootDir).CombinedOutput()

	status, got, err := challengeProbe("http://" + host + "/.well-known/acme-challenge/" + token)
	switch {
	case err != nil:
		return reasonUnreachable, err
	case status != http.StatusOK:
		return reasonWrongStatus, fmt.Errorf("challenge path answered HTTP %d", status)
	case strings.TrimSpace(got) != body:
		return reasonWrongContent, fmt.Errorf("challenge path is served by something else")
	}
	return "", nil
}

// fetchChallenge performs the plain-HTTP read of the challenge path.
//
// Redirects are NOT followed: the CA reads the challenge at that exact URL, so a
// redirect means the name does not answer, however friendly the destination is.
// The dialer goes through netguard so a hostname pointing at an internal address
// cannot turn this into a probe of the panel's own network.
func fetchChallenge(url string) (int, string, error) {
	client := &http.Client{
		Timeout: challengeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: challengeTimeout,
				Control: netguard.DialControl,
			}).DialContext,
		},
	}
	resp, err := client.Get(url) // #nosec G107 -- the URL is built here from a validated hostname, and the dialer refuses internal addresses.
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, challengeMaxBody))
	return resp.StatusCode, string(body), nil
}

// validatedSANHosts filters hosts down to the ones that can answer http-01 now,
// and reports why each of the others was dropped.
//
// The apex is never dropped silently: when it fails, the caller must refuse
// issuance rather than order a certificate that cannot be validated, because a
// failed order spends one of the five validation failures Let's Encrypt allows
// per hostname per hour.
func validatedSANHosts(hosts []string) (kept []string, dropped map[string]challengeReason) {
	dropped = map[string]challengeReason{}
	for _, host := range hosts {
		reason, err := challengeReachable(host)
		if reason == "" {
			kept = append(kept, host)
			continue
		}
		dropped[host] = reason
		logChallengeDrop(host, reason, err)
	}
	return kept, dropped
}

// logChallengeDrop records why a name will not be asked for, so an operator
// reading the log can tell "DNS is wrong" from "something else answers this
// name" without reproducing the probe.
func logChallengeDrop(host string, reason challengeReason, err error) {
	if err != nil {
		logx.Warnf("acme preflight: %s dropped from the certificate (%s): %v", host, reason, err)
		return
	}
	logx.Warnf("acme preflight: %s dropped from the certificate (%s)", host, reason)
}
