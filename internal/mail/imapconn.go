package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"

	"servika/internal/netguard"
)

// How the panel talks to the remote server. These are the values
// mail_migration_jobs.remote_security stores.
const (
	SecuritySSL      = "ssl"      // implicit TLS, conventionally port 993
	SecuritySTARTTLS = "starttls" // upgrade an unencrypted 143 session
	SecurityPlain    = "plain"    // no encryption at all
)

// Stable reason codes. The API is English and the panel ships twelve languages,
// so a screen renders these, never a sentence built here.
const (
	ReasonUnreachable = "unreachable"
	ReasonTLSFailed   = "tls_failed"
	ReasonBlockedHost = "blocked_host"
	ReasonBadSecurity = "bad_security"
)

// imapDialTimeout bounds one connection attempt. Discovery probes several
// candidates, so a host that accepts the TCP connection and then says nothing
// must not hold the whole sweep open.
const imapDialTimeout = 10 * time.Second

// ReasonError carries a stable code alongside the underlying failure.
//
// The code is what the API returns and the interface translates; the wrapped
// error stays for the log, where the operator can see what actually happened.
type ReasonError struct {
	Code string
	Err  error
}

func (e *ReasonError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *ReasonError) Unwrap() error { return e.Err }

func reasonFor(err error) string {
	if reason, ok := errors.AsType[*ReasonError](err); ok {
		return reason.Code
	}
	return ReasonUnreachable
}

// dialIMAP opens a client to a customer-named server.
//
// Every connection this package makes goes through here, because the host comes
// from a form: netguard.DialControl runs after resolution with the concrete
// address, so it refuses loopback, private and link-local targets and, unlike a
// check performed before dialling, also refuses a name that resolves to a public
// address once and a private one on the next lookup.
//
// Certificates are verified. The panel is carrying the customer's password for
// another provider over this connection, so a server whose certificate cannot be
// checked is refused with tls_failed rather than trusted anyway.
func dialIMAP(ctx context.Context, host string, port int, security string) (*imapclient.Client, error) {
	switch security {
	case SecuritySSL, SecuritySTARTTLS, SecurityPlain:
	default:
		return nil, &ReasonError{Code: ReasonBadSecurity, Err: fmt.Errorf("unknown security %q", security)}
	}

	dialer := &net.Dialer{Timeout: imapDialTimeout, Control: netguard.DialControl}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if errors.Is(err, netguard.ErrBlockedTarget) {
			return nil, &ReasonError{Code: ReasonBlockedHost, Err: err}
		}
		return nil, &ReasonError{Code: ReasonUnreachable, Err: err}
	}

	settings := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	if security == SecuritySTARTTLS {
		// NewStartTLS is used rather than a hand-rolled upgrade because it also
		// refuses a server that answers PREAUTH before the session is encrypted,
		// which would otherwise hand the connection over unprotected.
		client, err := imapclient.NewStartTLS(conn, &imapclient.Options{TLSConfig: settings})
		if err != nil {
			return nil, &ReasonError{Code: ReasonTLSFailed, Err: err}
		}
		return client, nil
	}

	if security == SecuritySSL {
		secure := tls.Client(conn, settings)
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, &ReasonError{Code: ReasonTLSFailed, Err: err}
		}
		conn = secure
	}

	client := imapclient.New(conn, nil)
	if err := client.WaitGreeting(); err != nil {
		_ = client.Close()
		return nil, &ReasonError{Code: ReasonUnreachable, Err: err}
	}
	return client, nil
}
