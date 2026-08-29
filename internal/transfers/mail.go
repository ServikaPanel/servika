package transfers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/mail"
)

// migrateMail provisions the domain's mail infrastructure, recreates each
// discovered mailbox with a FRESH password, rsyncs its Maildir from the source,
// and recreates forwarders.
//
// The source password is never reused, mirroring the cpmove importMail policy:
// the panel stores a SHA512-CRYPT hash and the vendors disagree on their own
// hash scheme, so a fresh password sidesteps the whole compatibility question
// and the new credentials are reported for the operator to hand out.
//
// Everything the source host returns is untrusted, so a discovered local part is
// validated with localPartRE before it reaches an rsync path or the mail handler.
func (h *Handlers) migrateMail(ctx context.Context, source *RemoteSource, account RemoteAccount, domainID int64, systemUser string, logf func(string, ...any)) (int, []MailCredential, []string, error) {
	if h.Mail == nil {
		return 0, nil, nil, errors.New("mail provider is not ready")
	}
	warnings := []string{}
	locals, aliases, err := h.discoverMail(ctx, source, account, logf)
	if err != nil {
		return 0, nil, warnings, err
	}
	if len(locals) == 0 && len(aliases) == 0 {
		return 0, nil, warnings, nil
	}
	if err := mail.EnableDomain(ctx, h.DB, domainID); err != nil {
		return 0, nil, warnings, err
	}

	creds := []MailCredential{}
	provisioned := make([]string, 0, len(locals))
	for _, local := range locals {
		created, cred, err := h.provisionMailbox(ctx, domainID, local, account.DomainName, logf)
		if err != nil {
			return len(provisioned), creds, warnings, err
		}
		if cred != nil {
			creds = append(creds, *cred)
		}
		if created {
			provisioned = append(provisioned, local)
		}
	}

	warnings = append(warnings, h.copyMaildirs(ctx, source, account, systemUser, provisioned, logf)...)
	warnings = append(warnings, h.provisionAliases(ctx, domainID, aliases)...)
	return len(provisioned), creds, warnings, nil
}

// provisionMailbox creates one mailbox through the in-process mail handler. A
// 201 returns fresh credentials; a 409 means the box already exists and its data
// is still copied, so both report the box as present.
func (h *Handlers) provisionMailbox(ctx context.Context, domainID int64, local, domainName string, logf func(string, ...any)) (bool, *MailCredential, error) {
	body, _ := json.Marshal(map[string]string{"local_part": local})
	rr := httptest.NewRecorder()
	h.Mail.Create(rr, mailRequest(ctx, http.MethodPost, "/mail", domainID, bytes.NewReader(body)))
	switch rr.Code {
	case http.StatusCreated:
		var result MailCredential
		_ = json.Unmarshal(rr.Body.Bytes(), &result)
		return true, &result, nil
	case http.StatusConflict:
		logf("Mail: %s already exists, keeping it", local+"@"+domainName)
		return true, nil, nil
	default:
		return false, nil, fmt.Errorf("mailbox %s: %s", local, strings.TrimSpace(rr.Body.String()))
	}
}

// copyMaildirs rsyncs each provisioned mailbox's Maildir from the source into the
// target's mail tree, then fixes ownership and SELinux context once. A mailbox
// with no Maildir on the source is a warning, never a step failure.
func (h *Handlers) copyMaildirs(ctx context.Context, source *RemoteSource, account RemoteAccount, systemUser string, provisioned []string, logf func(string, ...any)) []string {
	warnings := []string{}
	if len(provisioned) == 0 {
		return warnings
	}
	mailRoot := "/home/" + systemUser + "/mail"
	for _, local := range provisioned {
		src := maildirSourcePath(source.Type, account.SourceAccount, account.DomainName, local)
		if src == "" {
			continue
		}
		dst := mailRoot + "/" + local + "/"
		if _, err := source.RsyncPull(ctx, src, dst, "--exclude=dovecot*", "--exclude=maildirsize"); err != nil {
			warnings = append(warnings, "mail data for "+local+" could not be copied")
			logf("Mail: %s data could not be copied: %v", local, err)
		}
	}
	// #nosec G204 -- fixed binary with separate args; systemUser is a validated identifier.
	_, _ = newTransferCommand(ctx, "chown", "-R", systemUser+":"+systemUser, mailRoot).CombinedOutput()
	// #nosec G204 -- fixed binary with separate args; systemUser is a validated identifier.
	_, _ = newTransferCommand(ctx, "restorecon", "-RF", mailRoot).CombinedOutput()
	return warnings
}

// provisionAliases recreates each forwarder through the in-process mail handler.
// An alias failure is a warning, not a step failure: a lost forwarder is a
// smaller loss than a whole mail migration reported as broken.
func (h *Handlers) provisionAliases(ctx context.Context, domainID int64, aliases []aliasImport) []string {
	warnings := []string{}
	for _, a := range aliases {
		body, _ := json.Marshal(map[string]string{"local_part": a.Local, "destination": a.Destination})
		rr := httptest.NewRecorder()
		h.Mail.CreateAlias(rr, mailRequest(ctx, http.MethodPost, "/mail/aliases", domainID, bytes.NewReader(body)))
		if rr.Code != http.StatusCreated && rr.Code != http.StatusConflict {
			label := a.Local
			if label == "" {
				label = "catch-all"
			}
			warnings = append(warnings, "mail forwarder "+label+" could not be created")
		}
	}
	return warnings
}

// discoverMail lists the source domain's mailboxes and forwarders over SSH. The
// domain and account name are validated before they enter a remote command, and
// every discovered local part is validated before it is returned.
func (h *Handlers) discoverMail(ctx context.Context, source *RemoteSource, account RemoteAccount, logf func(string, ...any)) ([]string, []aliasImport, error) {
	domain := strings.ToLower(strings.TrimSpace(account.DomainName))
	user := strings.TrimSpace(account.SourceAccount)
	if !reRemoteDomain.MatchString(domain) {
		return nil, nil, fmt.Errorf("invalid source domain")
	}
	// cPanel and DirectAdmin build filesystem paths from the account name; Plesk
	// reads its own database and does not use it.
	if source.Type != "plesk" && !reRemoteAccount.MatchString(user) {
		return nil, nil, fmt.Errorf("invalid source account")
	}

	cmd, ok := mailboxCommand(source.Type, user, domain)
	if !ok {
		return nil, nil, fmt.Errorf("mail migration is not supported for %q", source.Type)
	}
	out, err := source.Run(ctx, cmd)
	if err != nil {
		return nil, nil, err
	}
	locals := parseMailboxList(out)

	// Forwarder discovery is best effort: a source that keeps them in a form this
	// migration does not read costs the mailboxes nothing.
	var aliases []aliasImport
	if aliasCmd := aliasCommand(source.Type, domain); aliasCmd != "" {
		if body, aerr := source.Run(ctx, aliasCmd); aerr == nil {
			aliases = parseAliasBody([]byte(body), domain, domain)
		} else {
			logf("Mail: forwarders could not be read, migrate them by hand: %v", aerr)
		}
	} else if source.Type == "plesk" {
		logf("Mail: Plesk forwarders are not migrated automatically, recreate them by hand")
	}
	return locals, aliases, nil
}

// mailboxCommand returns the remote command that lists a domain's mailbox local
// parts. The domain and user are already validated by the caller.
func mailboxCommand(vendor, user, domain string) (string, bool) {
	switch vendor {
	case "cpanel":
		return "{ cat /home/" + user + "/etc/" + domain + "/shadow 2>/dev/null || cat /home/" + user + "/etc/" + domain + "/passwd 2>/dev/null; } | cut -d: -f1", true
	case "plesk":
		return `plesk db -Ne "SELECT m.mail_name FROM mail m JOIN domains d ON m.dom_id=d.id WHERE d.name='` + domain + `' AND m.postbox='true'"`, true
	case "directadmin":
		return "cut -d: -f1 /etc/virtual/" + domain + "/passwd 2>/dev/null", true
	}
	return "", false
}

// aliasCommand returns the remote command that lists a domain's forwarders, or
// an empty string when the vendor's layout is not read automatically.
func aliasCommand(vendor, domain string) string {
	switch vendor {
	case "cpanel":
		return "cat /etc/valias/" + domain + " 2>/dev/null"
	case "directadmin":
		return "cat /etc/virtual/" + domain + "/aliases 2>/dev/null"
	}
	return ""
}

// parseMailboxList turns a mailbox listing (one local part per line) into a
// validated, deduplicated slice. Every name is untrusted source input, so a name
// that is not a valid local part is dropped rather than trusted.
func parseMailboxList(out string) []string {
	seen := make(map[string]bool)
	locals := []string{}
	for line := range strings.SplitSeq(out, "\n") {
		local := strings.ToLower(strings.TrimSpace(line))
		if local == "" || local == "*" || seen[local] {
			continue
		}
		if !localPartRE.MatchString(local) {
			continue
		}
		seen[local] = true
		locals = append(locals, local)
	}
	return locals
}

// maildirSourcePath returns the remote directory whose contents (cur/new/tmp)
// hold one mailbox's messages, with a trailing slash so rsync copies the
// contents rather than the directory itself. The caller has validated every
// component.
func maildirSourcePath(vendor, user, domain, local string) string {
	switch vendor {
	case "cpanel":
		return "/home/" + user + "/mail/" + domain + "/" + local + "/"
	case "plesk":
		return "/var/qmail/mailnames/" + domain + "/" + local + "/Maildir/"
	case "directadmin":
		return "/home/" + user + "/imap/" + domain + "/" + local + "/Maildir/"
	}
	return ""
}

// mailRequest builds an in-process request carrying the chi URL param `id` that
// the mail handlers read to resolve the target domain. It mirrors domainRequest
// but starts from a context rather than a parent request, because the live
// migration runs from MigrateAccount, which has no *http.Request.
func mailRequest(ctx context.Context, method, url string, domainID int64, body *bytes.Reader) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", strconv.FormatInt(domainID, 10))
	reqCtx := context.WithValue(ctx, chi.RouteCtxKey, rc)
	req := httptest.NewRequest(method, url, body).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")
	return req
}
