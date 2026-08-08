// Package mtasts publishes an MTA-STS policy (RFC 8461) and the TLS-RPT record
// that reports on it (RFC 8460).
//
// MTA-STS tells a sending server that this domain's mail must be delivered over
// authenticated TLS. That makes it the one mail setting in the panel that can
// lose mail: a sender honouring a policy in `enforce` mode will REFUSE to
// deliver, and not bounce, when the MX certificate does not match. Every rule
// here exists to keep that from happening by accident.
package mtasts

import (
	"errors"
	"fmt"
	"strings"
)

// Mode is where a domain is in the publication sequence.
//
// It is a sequence rather than a switch because publishing needs a DNS record,
// then a certificate that covers mta-sts.<domain>, then the vhost and the TXT
// record, and each step waits on the world rather than on the panel.
type Mode string

const (
	// ModeOff means no policy is published and none is cached anywhere.
	ModeOff Mode = "off"
	// ModePendingDNS means the records are written and DNS has not caught up.
	ModePendingDNS Mode = "pending_dns"
	// ModePendingCert means DNS resolves and the certificate does not yet name
	// mta-sts.<domain>.
	ModePendingCert Mode = "pending_cert"
	// ModeTesting publishes a policy senders REPORT on but do not enforce, so a
	// mismatch shows up in TLS-RPT instead of losing mail.
	ModeTesting Mode = "testing"
	// ModeEnforce publishes a policy senders refuse to deliver against when it
	// does not match.
	ModeEnforce Mode = "enforce"
	// ModeWithdrawing publishes `mode: none` while the previous policy ages out
	// of sender caches. Removing the record instead leaves senders applying a
	// cached enforce policy against a server that no longer proves it.
	ModeWithdrawing Mode = "withdrawing"
)

// maxAge values, in seconds.
//
// A sender caches the policy for max_age, so this number is also how long a
// withdrawal takes. Testing publishes a day, which keeps a mistake cheap.
// Enforce publishes a week, which is what RFC 8461 asks for and what makes the
// protection worth having; by then the panel has proved the certificate.
const (
	MaxAgeTesting = 86400
	MaxAgeEnforce = 604800
)

// TestingSoakDays is how long a policy must have been published in testing
// before enforce may be selected.
//
// The wait is the point. TLS-RPT reports arrive daily, so a shorter soak would
// unlock enforce before the first report saying whether senders can actually
// complete a TLS session with this server has been read.
const TestingSoakDays = 7

// ErrNotPublished is returned when a policy is asked for and none is published.
var ErrNotPublished = errors.New("no MTA-STS policy is published for this domain")

// ValidMode reports whether a value is a mode an operator may SELECT. The
// intermediate states are reached by the panel, never chosen.
func ValidMode(value string) bool {
	return Mode(value) == ModeTesting || Mode(value) == ModeEnforce
}

// Published reports whether a mode serves a policy file at all.
func Published(mode Mode) bool {
	switch mode {
	case ModeTesting, ModeEnforce, ModeWithdrawing:
		return true
	default:
		return false
	}
}

// PolicyFile renders the document served at
// https://mta-sts.<domain>/.well-known/mta-sts.txt.
//
// The line ending is CRLF because RFC 8461 section 3.2 says so, and a sender
// that parses strictly will reject the file otherwise.
func PolicyFile(mode Mode, mxHosts []string) (string, error) {
	if !Published(mode) {
		return "", ErrNotPublished
	}
	published := string(mode)
	maxAge := MaxAgeTesting
	switch mode {
	case ModeEnforce:
		maxAge = MaxAgeEnforce
	case ModeWithdrawing:
		// `none` is how a policy is retired: it stays fetchable so a sender
		// holding the old one replaces it instead of keeping it until it
		// expires. A withdrawal that simply stopped answering would leave the
		// cached policy in force for its whole max_age.
		published = "none"
	}
	if published != "none" && len(mxHosts) == 0 {
		// A policy with no mx line matches no server, so in enforce mode it
		// rejects every message. Refusing to render it is the only safe answer.
		return "", errors.New("the policy names no MX host")
	}

	var body strings.Builder
	body.WriteString("version: STSv1\r\n")
	fmt.Fprintf(&body, "mode: %s\r\n", published)
	for _, host := range mxHosts {
		fmt.Fprintf(&body, "mx: %s\r\n", host)
	}
	fmt.Fprintf(&body, "max_age: %d\r\n", maxAge)
	return body.String(), nil
}

// PolicyTXT is the value of the _mta-sts.<domain> TXT record.
//
// A sender caches the policy against this id and only refetches when it
// changes, so the id has to be regenerated whenever the policy does or the
// change is never noticed.
func PolicyTXT(id string) string { return "v=STSv1; id=" + id }

// ReportTXT is the value of the _smtp._tls.<domain> TXT record, which asks for
// TLS-RPT reports at the same address the DMARC record already names.
func ReportTXT(address string) string { return "v=TLSRPTv1; rua=mailto:" + address }
