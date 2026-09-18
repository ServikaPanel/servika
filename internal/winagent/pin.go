// Package winagent registers the Windows agents this panel talks to.
//
// The panel itself runs on AlmaLinux and manages that host directly. A Windows
// host cannot be managed that way, so it runs a small agent and the panel
// reaches it over HTTPS. This package holds the registry and the transport.
//
// Three decisions carry the security of that link:
//
//   - The token is sealed at rest with the agent's own address as AAD, so a
//     ciphertext lifted from one row cannot be replayed from another.
//   - The agent presents a self-signed certificate, so the panel pins it. The
//     SHA-256 of the leaf is learned on first contact (trust on first use) and
//     enforced on every later call. A changed certificate FAILS the call and is
//     recorded as its own state; the pin is never refreshed silently, because a
//     silent refresh is exactly what an interception would need.
//   - The address must be loopback or private even though the link is TLS. The
//     encryption protects the token in flight; the address gate keeps the
//     management plane off the public internet. They are separate defenses and
//     both stay.
package winagent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// tokenHeader carries the shared token to the agent. The agent compares it
	// in constant time and answers 401 when it does not match.
	tokenHeader = "X-Servika-Token"

	// dialTimeout bounds the certificate read, callTimeout every later call.
	// An unreachable agent must not hold a panel request open.
	dialTimeout = 5 * time.Second
	callTimeout = 5 * time.Second

	// allowPublicEnv opens the address gate deliberately, for an operator whose
	// Windows host has no private network to the panel. It is OFF unless the
	// value is exactly "1", and it never disables the pin.
	allowPublicEnv = "SERVIKA_WINAGENT_ALLOW_PUBLIC"
)

// ErrFingerprint means the certificate the agent presented is not the one the
// panel pinned.
//
// This is NOT a condition to repair silently. It is either an interception or
// an agent that was reinstalled without telling the panel, and the operator has
// to tell the two apart. The fix is a deliberate re-registration.
var ErrFingerprint = errors.New("the agent's certificate changed - re-register it")

// shortFingerprint is the prefix shown in an answer. The full value stays in
// the database; a prefix is enough for an operator to compare against what the
// agent printed at startup.
func shortFingerprint(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

// validAddress checks the "host:port" form and the private-network rule.
//
// Only a literal IP is accepted. A hostname resolves differently on every
// lookup, which is how DNS rebinding turns an allowed address into a public
// one between the check and the call.
func validAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("address must be host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("only a literal IP address is accepted, not a hostname")
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	if os.Getenv(allowPublicEnv) == "1" {
		return nil
	}
	return fmt.Errorf("the agent address must be loopback or private (%s is public); set %s=1 to allow it deliberately", host, allowPublicEnv)
}

// readFingerprint reads the SHA-256 of the leaf certificate the address serves.
// This is the first-look half of trust on first use.
//
// InsecureSkipVerify is deliberate and harmless here: this connection exists
// only to READ the certificate and carries no request and no token. The call
// that carries the token is made immediately afterwards, pinned to exactly this
// fingerprint.
func readFingerprint(address string) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: this connection only READS the certificate; no token or request travels over it.
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", fmt.Errorf("could not reach the agent over TLS: %w", err)
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the agent presented no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// matchesPin compares one raw certificate against the pin.
func matchesPin(raw []byte, fingerprint string) error {
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return ErrFingerprint
	}
	return nil
}

// pinnedClient answers only to the server holding the given fingerprint.
//
// InsecureSkipVerify and the two verify hooks go together on purpose: the agent
// is self-signed, so chain validation would fail by definition. Skipping the
// chain and comparing the leaf digest replaces it with a stricter rule, and the
// handshake fails BEFORE the token is written.
//
// Both hooks are installed, and session resumption is turned off, because an
// abbreviated handshake does not re-present the certificate. VerifyConnection
// runs on every connection including a resumed one; VerifyPeerCertificate does
// not. Disabling tickets removes the case entirely, and the second hook stays
// as the belt to that braces.
func pinnedClient(fingerprint string) *http.Client {
	return &http.Client{
		Timeout: callTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // G402: deliberate certificate pinning against a self-signed agent; the leaf digest is compared below and a mismatch aborts the handshake before the token is sent.
				MinVersion:         tls.VersionTLS12,

				SessionTicketsDisabled: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("the agent presented no certificate")
					}
					return matchesPin(cs.PeerCertificates[0].Raw, fingerprint)
				},
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("the agent presented no certificate")
					}
					return matchesPin(rawCerts[0], fingerprint)
				},
			},
		},
	}
}

// isFingerprintError reports whether a client error came from the pin.
// The HTTP client wraps a handshake failure in url.Error and sometimes in
// OpError, so errors.Is is tried first and the text comparison is the fallback
// for a wrapper that drops the cause.
func isFingerprintError(err error) bool {
	return errors.Is(err, ErrFingerprint) || strings.Contains(err.Error(), ErrFingerprint.Error())
}

// health is what the agent answers on /health.
type health struct {
	Platform     string `json:"platform"`
	Version      string `json:"version"`
	Channel      string `json:"channel"`
	Capabilities uint32 `json:"capabilities"`
	EnvError     string `json:"env_error"`
}

// probe asks the agent for its health over a client pinned to fingerprint.
func probe(address, token, fingerprint string) (*health, error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+address+"/health", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(tokenHeader, token)
	resp, err := pinnedClient(fingerprint).Do(req)
	if err != nil {
		if isFingerprintError(err) {
			return nil, ErrFingerprint
		}
		return nil, fmt.Errorf("could not reach the agent: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the agent rejected the token (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the agent answered %d", resp.StatusCode)
	}
	var h health
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, fmt.Errorf("could not read the health answer: %w", err)
	}
	if h.Platform != "windows" {
		return nil, fmt.Errorf("expected platform windows, got %q", h.Platform)
	}
	return &h, nil
}
