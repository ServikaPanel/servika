// Package autoconfig answers the two endpoints mail clients probe before asking
// a person for server names and ports.
//
// Thunderbird fetches /.well-known/autoconfig/mail/config-v1.1.xml and Outlook
// POSTs to /autodiscover/autodiscover.xml. Both are served from the domain's OWN
// vhost rather than an autoconfig.<domain> or autodiscover.<domain> host, for
// the same reason webmail is: a subdomain needs an extra A record and an extra
// name on the certificate for every domain, and a client that reaches either one
// over a certificate that does not cover it shows a warning at exactly the
// moment it is about to be handed a password. The domain's existing certificate
// already covers this path.
//
// The trade-off is the older Thunderbird releases that only tried
// autoconfig.<domain>. They fall back to guessing, which reaches the same
// servers because the discovery A records exist.
//
// Neither endpoint can require authentication: a mail client has no panel
// session. They therefore return only what the MX record already reveals, which
// is that this host handles mail for the domain, plus the ports and encryption a
// client would otherwise be told by hand.
package autoconfig

import (
	"context"
	"database/sql"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"
)

// Handlers serves both endpoints.
type Handlers struct{ DB *sql.DB }

// The ports and encryption below are what this server actually runs, taken from
// assets/mail/dovecot (protocols = imap lmtp, no POP3), assets/mail/postfix
// (submission on 587 with smtpd_tls_security_level=encrypt), and the firewall
// openings in servika-mail-setup (25, 587, 143). Announcing anything else
// produces an account that configures itself and then cannot connect.
const (
	imapPort       = 143
	submissionPort = 587
	// socketTypeSTARTTLS is the encryption both ports negotiate. Postfix runs
	// submission with smtpd_tls_security_level=encrypt, so the upgrade is not
	// optional even though the port is the plaintext one.
	socketTypeSTARTTLS = "STARTTLS"
	// Dovecot's userdb matches on the full address (`WHERE m.email='%u'`), so a
	// bare local part cannot log in.
	usernameIsFullAddress = "%EMAILADDRESS%"
)

// maxAutodiscoverBody bounds the POST Outlook sends. The real request is well
// under a kilobyte; anything larger is not a mail client.
const maxAutodiscoverBody = 8 << 10

// ErrNoMailHost is returned when no hostname can be announced yet, because none
// of the candidates is covered by an active certificate.
var ErrNoMailHost = errors.New("no mail hostname with a valid certificate")

// ClientSettings is everything a mail client needs to configure one account.
//
// It exists so the panel's own connection card and the two discovery endpoints
// cannot disagree: a card that printed 993 while Dovecot listens on 143 would
// produce an account that configures itself and then cannot connect, which is
// the exact failure this package was written to avoid.
type ClientSettings struct {
	Hostname       string `json:"hostname"`
	IMAPPort       int    `json:"imap_port"`
	SubmissionPort int    `json:"submission_port"`
	// Security is what both ports negotiate. Implicit TLS is not offered because
	// neither 993 nor 465 is opened by servika-mail-setup.
	Security string `json:"security"`
	// Covered is every name the domain's installed mail certificate carries. It
	// is reported so a screen can explain a hostname that is still pending
	// instead of only stating that there is none: a certificate covering smtp.
	// and imap. but not mail. is a DNS problem, and an empty list is an issuance
	// problem.
	Covered []string `json:"covered,omitempty"`
}

// SettingsFor returns the settings announced for a domain.
//
// The hostname is measured, never assumed, exactly as the discovery endpoints
// measure it: a name no certificate covers walks the client into a warning at
// the moment it is about to be handed a password. When there is no such name yet
// it returns ErrNoMailHost, which is a state the caller can report rather than
// an error to log.
func SettingsFor(ctx context.Context, db *sql.DB, domain string) (ClientSettings, error) {
	host, covered, err := announceableHost(ctx, db, domain)
	if err != nil {
		// Covered is carried out with the error on purpose: the caller reports
		// ErrNoMailHost as a state rather than a failure, and the list is what
		// tells the reader whether the certificate exists at all.
		return ClientSettings{Covered: covered}, err
	}
	return ClientSettings{
		Hostname:       host,
		IMAPPort:       imapPort,
		SubmissionPort: submissionPort,
		Security:       socketTypeSTARTTLS,
		Covered:        covered,
	}, nil
}

// Thunderbird answers GET /.well-known/autoconfig/mail/config-v1.1.xml.
//
// The email address Thunderbird appends as a query parameter is ignored: the
// response uses %EMAILADDRESS%, a placeholder the client substitutes itself, so
// no client-supplied text is echoed back at all.
func (h *Handlers) Thunderbird(w http.ResponseWriter, r *http.Request) {
	domain, mailHost, ok := h.resolve(w, r)
	if !ok {
		return
	}

	config := clientConfig{
		Version: "1.1",
		Provider: emailProvider{
			ID:               domain,
			Domain:           domain,
			DisplayName:      domain,
			DisplayShortName: domain,
			Incoming: []serverConfig{{
				Type:           "imap",
				Hostname:       mailHost,
				Port:           imapPort,
				SocketType:     "STARTTLS",
				Username:       usernameIsFullAddress,
				Authentication: "password-cleartext",
			}},
			Outgoing: []serverConfig{{
				Type:           "smtp",
				Hostname:       mailHost,
				Port:           submissionPort,
				SocketType:     "STARTTLS",
				Username:       usernameIsFullAddress,
				Authentication: "password-cleartext",
			}},
		},
	}
	writeXML(w, config)
}

// Outlook answers POST /autodiscover/autodiscover.xml.
//
// Outlook has no username placeholder, so the address it posts has to come back
// in LoginName. It is parsed and checked against the domain being asked about
// before it is used, and the response is produced by the XML encoder rather than
// by pasting strings together, so a crafted address cannot break out of the
// element it belongs in.
func (h *Handlers) Outlook(w http.ResponseWriter, r *http.Request) {
	domain, mailHost, ok := h.resolve(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAutodiscoverBody))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "request body could not be read")
		return
	}
	address, err := requestedAddress(body)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "the request did not carry a usable email address")
		return
	}
	// The address decides which mailbox the client will try to log in as. If its
	// domain is not the one this vhost serves, answering would hand out settings
	// for somebody else's domain under this domain's name.
	if !strings.EqualFold(addressDomain(address), domain) {
		httpx.WriteError(w, http.StatusNotFound, "this host does not serve that address")
		return
	}

	response := autodiscoverResponse{
		XMLName: xml.Name{Local: "Autodiscover"},
		Xmlns:   autodiscoverResponseNS,
		Response: autodiscoverBody{
			Xmlns: autodiscoverPayloadNS,
			Account: autodiscoverAccount{
				AccountType: "email",
				Action:      "settings",
				Protocols: []autodiscoverProtocol{
					{
						Type: "IMAP", Server: mailHost, Port: imapPort,
						SSL: "on", SPA: "off", AuthRequired: "on", LoginName: address,
					},
					{
						Type: "SMTP", Server: mailHost, Port: submissionPort,
						SSL: "on", SPA: "off", AuthRequired: "on", LoginName: address,
					},
				},
			},
		},
	}
	writeXML(w, response)
}

// resolve turns the requested host into the domain this vhost serves and the
// mail hostname it is safe to announce, or writes the response and reports
// false.
func (h *Handlers) resolve(w http.ResponseWriter, r *http.Request) (domain, mailHost string, ok bool) {
	requested := normalizeHost(r.Host)
	if requested == "" {
		httpx.WriteError(w, http.StatusNotFound, "unknown host")
		return "", "", false
	}
	domain, hosted, err := h.hostedDomainFor(r, requested)
	if err != nil {
		// #nosec G706 -- requested came through normalizeHost, which accepts only the hostname alphabet, so it cannot carry CR/LF or control characters; err is a database driver error.
		httpx.LogR(r, "autoconfig lookup for %s: %v", requested, err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "mail settings are temporarily unavailable")
		return "", "", false
	}
	if !hosted {
		httpx.WriteError(w, http.StatusNotFound, "this host does not serve mail")
		return "", "", false
	}
	mailHost, _, err = announceableHost(r.Context(), h.DB, domain)
	if err != nil {
		// Not an error the client can act on, and not one worth a 500: there is
		// simply no name that would survive the client's certificate check yet.
		httpx.WriteError(w, http.StatusNotFound, "no mail hostname is ready to be announced")
		return "", "", false
	}
	return domain, mailHost, true
}

// hostsMail reports whether the domain has active mail service here. A domain
// that merely exists in the panel is not enough: answering for it would send a
// client at a mailbox that cannot be created.
// hostedDomainFor maps the requested host onto the domain whose mail settings
// answer for it.
//
// Thunderbird asks autoconfig.<domain> and Outlook asks autodiscover.<domain>,
// so those two hosts stand for the domain underneath them. The literal host is
// tried FIRST: a customer may legitimately host a domain that is itself called
// autoconfig.example.com, and that domain's own settings must win over the
// settings of example.com.
func (h *Handlers) hostedDomainFor(r *http.Request, requested string) (domain string, hosted bool, err error) {
	found, err := h.hostsMail(r, requested)
	if err != nil {
		return "", false, err
	}
	if found {
		return requested, true, nil
	}
	for _, prefix := range []string{"autoconfig.", "autodiscover."} {
		if !strings.HasPrefix(requested, prefix) {
			continue
		}
		parent := strings.TrimPrefix(requested, prefix)
		if parent == "" {
			continue
		}
		found, err := h.hostsMail(r, parent)
		if err != nil {
			return "", false, err
		}
		if found {
			return parent, true, nil
		}
	}
	return "", false, nil
}

func (h *Handlers) hostsMail(r *http.Request, domain string) (bool, error) {
	var count int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM mail_domains WHERE domain_name = ? AND status = 'active'`, domain).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// mailHostPreference is the order in which a covered name is announced.
//
// One hostname is announced for both IMAP and submission, and all three names
// sit in the same certificate, so the order only has to be deterministic and
// defensible: mail. is the MX target, and imap. is the server a client is
// configured with first.
var mailHostPreference = []string{"mail.", "imap.", "smtp."}

// announceableHost returns the hostname to put in the settings, along with every
// name the domain's certificate covers.
//
// It is MEASURED, never assumed. The ACME pre-flight DROPS a name that cannot
// answer a challenge (provisioner.validatedSANHosts), so a domain whose mail.
// label has no A record is issued a certificate covering smtp. and imap. and
// nothing else. Testing only mail. would throw that working certificate away and
// fall through to the panel, so every candidate is measured in turn.
//
// The covered list is returned even alongside an error: a screen explaining why
// no hostname is ready needs to say whether the certificate carries other names
// or none at all, and reading the certificate twice for that would be waste.
func announceableHost(ctx context.Context, db *sql.DB, domain string) (string, []string, error) {
	covered, _ := provisioner.MailCertificateStatus(domain)
	for _, prefix := range mailHostPreference {
		want := prefix + domain
		for _, name := range covered {
			if strings.EqualFold(name, want) {
				return want, covered, nil
			}
		}
	}

	var panelDomain sql.NullString
	var sslStatus string
	err := db.QueryRowContext(ctx,
		`SELECT custom_domain, ssl_status FROM panel_settings WHERE id = 1`).Scan(&panelDomain, &sslStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", covered, err
	}
	// An active web certificate is not enough for the panel's own name to be an
	// answer here. The mail SNI map is built from the per-domain mail chains
	// alone, so a panel domain carrying only a web certificate would send the
	// client to a port that answers with the server-wide default certificate:
	// the exact warning this function exists to prevent.
	host := strings.ToLower(strings.TrimSpace(panelDomain.String))
	if host != "" && sslStatus == "active" && provisioner.MailSNICovers(host) {
		return host, covered, nil
	}
	return "", covered, ErrNoMailHost
}

// normalizeHost turns the Host header into the domain the vhost serves: no port,
// lower case, and without the www. label, which is the same site.
//
// The result is then checked against the hostname alphabet rather than merely
// having a few dangerous characters removed. The Host header is client-supplied
// and this value goes into a query, a log line and the response body, so the
// only safe rule is an allowlist: anything that is not a hostname is not a
// hostname, and "" makes every caller answer 404.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	host = strings.Trim(host, ".")
	host = strings.TrimPrefix(host, "www.")
	if !isHostname(host) {
		return ""
	}
	return host
}

// isHostname reports whether the value is a plausible DNS name: labels of
// letters, digits and hyphens separated by dots, and nothing else. It is
// deliberately stricter than DNS allows, because everything this panel hosts is
// a name ValidateDomain already accepted.
func isHostname(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if !isLabel(label) {
			return false
		}
	}
	return true
}

// isLabel reports whether one dot-separated part of a name is usable.
func isLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

func addressDomain(address string) string {
	if idx := strings.LastIndex(address, "@"); idx != -1 {
		return strings.ToLower(address[idx+1:])
	}
	return ""
}

func writeXML(w http.ResponseWriter, payload any) {
	body, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("autoconfig: encode the response: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "mail settings could not be produced")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	// The answer depends only on the host and is fine to cache briefly, but not
	// long enough to outlive a certificate being issued, which changes which
	// hostname is announced.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return
	}
	if _, err := w.Write(body); err != nil {
		log.Printf("autoconfig: write the response: %v", err)
	}
}
