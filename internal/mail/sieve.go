package mail

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/files"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

type Autoresponder struct {
	MailboxID    int64  `json:"mailbox_id"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	IntervalDays int    `json:"interval_days"`
}

type MailFilter struct {
	ID          int64  `json:"id"`
	MailboxID   int64  `json:"mailbox_id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	MatchField  string `json:"match_field"`
	MatchValue  string `json:"match_value"`
	ActionType  string `json:"action_type"`
	ActionValue string `json:"action_value"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

var sieveFolderPattern = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,64}$`)

// AutoresponderGet returns a mailbox vacation responder. GET /domains/{id}/mail/{mid}/autoresponder
func (h *Handlers) AutoresponderGet(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mid, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var a Autoresponder
	var enabled int
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT m.id, m.email, a.enabled, a.subject_text, a.body_text, a.interval_days
		FROM mailboxes m LEFT JOIN mail_autoresponders a ON a.mailbox_id=m.id
		WHERE m.id=? AND m.domain_id=?`, mid, id).
		Scan(&a.MailboxID, &a.Email, &enabled, &a.Subject, &a.Body, &a.IntervalDays)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if err != nil {
		// A LEFT JOIN NULL means the mailbox exists but has no responder yet.
		var email string
		if e := h.DB.QueryRowContext(r.Context(),
			`SELECT email FROM mailboxes WHERE id=? AND domain_id=?`, mid, id).Scan(&email); e == nil {
			httpx.WriteJSON(w, http.StatusOK, Autoresponder{MailboxID: mid, Email: email, IntervalDays: 7})
			return
		}
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	a.Enabled = enabled == 1
	httpx.WriteJSON(w, http.StatusOK, a)
}

// AutoresponderPut saves and compiles a mailbox vacation responder. PUT /domains/{id}/mail/{mid}/autoresponder
func (h *Handlers) AutoresponderPut(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	mid, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var req Autoresponder
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.Body = strings.TrimSpace(req.Body)
	if req.Subject == "" || req.Body == "" || len(req.Subject) > 255 || len(req.Body) > 10000 {
		httpx.WriteError(w, http.StatusBadRequest, "subject and a message up to 10,000 characters are required")
		return
	}
	if req.IntervalDays < 1 || req.IntervalDays > 30 {
		httpx.WriteError(w, http.StatusBadRequest, "reply interval must be 1-30 days")
		return
	}
	if !h.mailboxBelongs(r.Context(), id, mid) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	var oldEnabled int
	var oldSubject, oldBody string
	var oldDays int
	oldErr := h.DB.QueryRowContext(r.Context(), `SELECT enabled,subject_text,body_text,interval_days
		FROM mail_autoresponders WHERE mailbox_id=?`, mid).
		Scan(&oldEnabled, &oldSubject, &oldBody, &oldDays)
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO mail_autoresponders(mailbox_id, domain_id, enabled, subject_text, body_text, interval_days)
		VALUES(?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), subject_text=VALUES(subject_text),
		  body_text=VALUES(body_text), interval_days=VALUES(interval_days)`,
		mid, id, req.Enabled, req.Subject, req.Body, req.IntervalDays)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save autoresponder")
		return
	}
	if err := ApplyMailboxSieve(r.Context(), h.DB, mid); err != nil {
		if oldErr == nil {
			_, _ = h.DB.Exec(`UPDATE mail_autoresponders SET enabled=?,subject_text=?,body_text=?,
				interval_days=? WHERE mailbox_id=?`, oldEnabled, oldSubject, oldBody, oldDays, mid)
		} else {
			_, _ = h.DB.Exec(`DELETE FROM mail_autoresponders WHERE mailbox_id=?`, mid)
		}
		writeApplyFailure(w, "apply sieve mailbox", mid, "could not apply the mail rules", err)
		return
	}
	h.audit(r, "mail.autoresponder.update", strconv.FormatInt(mid, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// AutoresponderDelete removes a mailbox vacation responder. DELETE /domains/{id}/mail/{mid}/autoresponder
func (h *Handlers) AutoresponderDelete(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	mid, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	if !h.mailboxBelongs(r.Context(), id, mid) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM mail_autoresponders WHERE mailbox_id=?`, mid); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete autoresponder")
		return
	}
	if err := ApplyMailboxSieve(r.Context(), h.DB, mid); err != nil {
		writeApplyFailure(w, "apply sieve mailbox", mid, "could not apply the mail rules", err)
		return
	}
	h.audit(r, "mail.autoresponder.delete", strconv.FormatInt(mid, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// FilterList returns domain mailbox filters. GET /domains/{id}/mail/filters
func (h *Handlers) FilterList(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT f.id, f.mailbox_id, m.email, f.name, f.match_field, f.match_value,
		       f.action_type, f.action_value, f.priority_n, f.enabled
		FROM mail_filters f JOIN mailboxes m ON m.id=f.mailbox_id
		WHERE f.domain_id=? ORDER BY m.email, f.priority_n, f.id`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mail filters")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]MailFilter, 0)
	for rows.Next() {
		var f MailFilter
		var enabled int
		if err := rows.Scan(&f.ID, &f.MailboxID, &f.Email, &f.Name, &f.MatchField, &f.MatchValue,
			&f.ActionType, &f.ActionValue, &f.Priority, &enabled); err == nil {
			f.Enabled = enabled == 1
			out = append(out, f)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mail filters")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// FilterCreate creates and compiles a mailbox filter. POST /domains/{id}/mail/filters
func (h *Handlers) FilterCreate(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	var req MailFilter
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.MatchValue = strings.TrimSpace(req.MatchValue)
	req.ActionValue = strings.TrimSpace(req.ActionValue)
	if !h.mailboxBelongs(r.Context(), id, req.MailboxID) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if err := validateFilter(req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	res, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO mail_filters(mailbox_id, domain_id, name, match_field, match_value,
		  action_type, action_value, priority_n, enabled) VALUES(?,?,?,?,?,?,?,?,?)`,
		req.MailboxID, id, req.Name, req.MatchField, req.MatchValue,
		req.ActionType, req.ActionValue, req.Priority, req.Enabled)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save mail filter")
		return
	}
	fid, _ := res.LastInsertId()
	if err := ApplyMailboxSieve(r.Context(), h.DB, req.MailboxID); err != nil {
		_, _ = h.DB.Exec(`DELETE FROM mail_filters WHERE id=?`, fid)
		writeApplyFailure(w, "apply sieve mailbox", req.MailboxID, "could not apply the mail rules", err)
		return
	}
	h.audit(r, "mail.filter.create", strconv.FormatInt(fid, 10), true)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": fid})
}

// FilterDelete removes and recompiles a mailbox filter. DELETE /domains/{id}/mail/filters/{fid}
func (h *Handlers) FilterDelete(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	fid, _ := strconv.ParseInt(chi.URLParam(r, "fid"), 10, 64)
	var mid int64
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT mailbox_id FROM mail_filters WHERE id=? AND domain_id=?`, fid, id).Scan(&mid); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "mail filter not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM mail_filters WHERE id=?`, fid); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete mail filter")
		return
	}
	if err := ApplyMailboxSieve(r.Context(), h.DB, mid); err != nil {
		writeApplyFailure(w, "apply sieve mailbox", mid, "could not apply the mail rules", err)
		return
	}
	h.audit(r, "mail.filter.delete", strconv.FormatInt(fid, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validateFilter(f MailFilter) error {
	if f.Name == "" || len(f.Name) > 128 || f.MatchValue == "" || len(f.MatchValue) > 255 {
		return errors.New("filter name and match value are required")
	}
	if f.MatchField != "from" && f.MatchField != "to" && f.MatchField != "subject" {
		return errors.New("invalid match field")
	}
	switch f.ActionType {
	case "move":
		if !sieveFolderPattern.MatchString(f.ActionValue) {
			return errors.New("invalid target folder")
		}
	case "redirect":
		if !destinationEmailPattern.MatchString(strings.ToLower(f.ActionValue)) {
			return errors.New("invalid redirect address")
		}
	case "discard":
	default:
		return errors.New("invalid filter action")
	}
	return nil
}

func (h *Handlers) mailboxBelongs(ctx context.Context, domainID, mailboxID int64) bool {
	var n int
	_ = h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mailboxes WHERE id=? AND domain_id=?`, mailboxID, domainID).Scan(&n)
	return n == 1
}

// ErrSieveUnavailable says the host has no Sieve compiler. It is the one apply
// failure whose text is safe to hand to the mailbox owner, so it is a sentinel
// rather than an ad-hoc string.
var ErrSieveUnavailable = errors.New("dovecot-pigeonhole is not installed")

// ApplyMailboxSieve regenerates and compiles the mailbox's ~/.dovecot.sieve script
// from its enabled filters and autoresponder, then activates the compiled binary.
func ApplyMailboxSieve(ctx context.Context, db *sql.DB, mailboxID int64) error {
	if _, err := exec.LookPath("sievec"); err != nil {
		return ErrSieveUnavailable
	}
	var maildir, email, systemUser string
	if err := db.QueryRowContext(ctx, `
		SELECT TRIM(TRAILING '/' FROM m.maildir), m.email, md.system_user
		FROM mailboxes m JOIN mail_domains md ON md.id=m.mail_domain_id WHERE m.id=?`, mailboxID).
		Scan(&maildir, &email, &systemUser); err != nil {
		return err
	}
	home, rel, err := maildirJail(systemUser, maildir)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	out.WriteString(`require ["fileinto", "vacation", "mailbox"];

# Move mail flagged by Rspamd into Junk.
if header :contains "X-Spam" "Yes" {
  fileinto :create "Junk";
  stop;
}
`)
	rows, err := db.QueryContext(ctx, `
		SELECT match_field, match_value, action_type, action_value
		FROM mail_filters WHERE mailbox_id=? AND enabled=1 ORDER BY priority_n,id`, mailboxID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var field, value, action, actionValue string
		if err := rows.Scan(&field, &value, &action, &actionValue); err != nil {
			_ = rows.Close()
			return err
		}
		header := map[string]string{"from": "From", "to": "To", "subject": "Subject"}[field]
		fmt.Fprintf(&out, "\nif header :contains %s %s {\n", sieveQuote(header), sieveQuote(value))
		switch action {
		case "move":
			fmt.Fprintf(&out, "  fileinto :create %s;\n", sieveQuote(actionValue))
		case "redirect":
			fmt.Fprintf(&out, "  redirect %s;\n", sieveQuote(actionValue))
		case "discard":
			out.WriteString("  discard;\n")
		}
		out.WriteString("  stop;\n}\n")
	}
	if err := rows.Err(); err != nil {
		// The scan path above already fails the write. A query that broke half way
		// is the same defect: the generated script would silently drop a filter the
		// mailbox owner saved, so it must not be written at all.
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	// Forwarding comes after the filters, so a filter that files a message and
	// stops still wins, and before the vacation reply, which is not a delivery.
	forwarding, err := readForwarding(ctx, db, mailboxID)
	if err != nil {
		return err
	}
	if forwarding.Enabled {
		out.WriteString("\n# Forwarding.\n")
		for _, destination := range forwarding.Destinations {
			fmt.Fprintf(&out, "redirect %s;\n", sieveQuote(destination))
		}
		if !forwarding.KeepCopy {
			// Without this Sieve still delivers locally, so "do not keep a copy"
			// has to be said explicitly or the mailbox keeps filling up.
			out.WriteString("discard;\n")
		}
	}

	var enabled int
	var subject, body string
	var days int
	err = db.QueryRowContext(ctx, `SELECT enabled, subject_text, body_text, interval_days
		FROM mail_autoresponders WHERE mailbox_id=?`, mailboxID).
		Scan(&enabled, &subject, &body, &days)
	if err == nil && enabled == 1 {
		fmt.Fprintf(&out, "\nvacation :days %d :subject %s text:\n%s\n.\n;\n",
			days, sieveQuote(subject), sieveMultiline(body))
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	return compileSieve(ctx, home, rel, out.Bytes(), systemUser)
}

// maildirJail splits a stored mailbox directory into the tenant home that
// confines it and the path relative to that home.
//
// Every write below is made through openat2 relative to the home, so the
// relative half is what keeps a planted symlink from sending a root write
// somewhere else. A directory that is not under /home/<system_user>/ is REFUSED
// rather than written by absolute path, because a row edited outside the panel
// would otherwise re-open exactly the hole this confinement closes.
func maildirJail(systemUser, maildir string) (home, rel string, err error) {
	if systemUser == "" || strings.ContainsRune(systemUser, filepath.Separator) ||
		systemUser == "." || systemUser == ".." {
		return "", "", fmt.Errorf("invalid system user %q", systemUser)
	}
	home = filepath.Join("/home", systemUser)
	rel, err = filepath.Rel(home, filepath.Clean(maildir))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("mailbox directory %q is not under %s", maildir, home)
	}
	return home, rel, nil
}

// compileSieve compiles the script in a root-owned staging directory and then
// publishes the source and the compiled binary into the mailbox through openat2.
//
// sievec is never pointed at a path inside the tenant's tree: it runs as root and
// resolves what it is given, so a symlink standing where the script belongs would
// make it read and write outside the mailbox. Staging also keeps the compiler's
// output naming exactly as before, since the staged file carries the same base
// name the mailbox copy does.
func compileSieve(ctx context.Context, home, rel string, script []byte, systemUser string) error {
	stage, err := os.MkdirTemp("", "servika-sieve-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	staged := filepath.Join(stage, ".dovecot.sieve.new")
	if err := os.WriteFile(staged, script, 0o600); err != nil {
		return err
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the argument is a root-owned staging path.
	cmd := exec.CommandContext(ctx, "sievec", staged)
	cmd.Env = subprocessEnv
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sievec: %s", strings.TrimSpace(string(output)))
	}

	if err := files.MkdirAllBeneath(home, rel, systemUser); err != nil {
		return err
	}
	if err := publishSieveFile(home, rel, ".dovecot.sieve", script, systemUser); err != nil {
		return err
	}
	compiled, err := os.ReadFile(staged + ".svbin")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return publishSieveFile(home, rel, ".dovecot.sieve.svbin", compiled, systemUser)
}

// publishSieveFile stages the bytes beside their target and renames them into
// place, so Dovecot never reads a half-written script.
func publishSieveFile(home, rel, name string, data []byte, systemUser string) error {
	tmpRel := rel + "/" + name + ".new"
	if err := files.WriteFileBeneath(home, tmpRel, data, 0o600, systemUser); err != nil {
		return err
	}
	return files.RenameBeneath(home, tmpRel, rel+"/"+name, systemUser)
}

func sieveMultiline(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, ".") {
			lines[i] = "." + line
		}
	}
	return strings.Join(lines, "\n")
}

// sieveQuote escapes a value as a Sieve quoted-string (RFC 5228 §2.4.2).
//
// Newlines are folded to a space: a quoted-string has NO escape that represents
// a line break — a backslash only takes the following character literally, so
// `\n` means "n". The previously emitted `\n` silently turned a multi-line match
// value into "…n…".
func sieveQuote(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
