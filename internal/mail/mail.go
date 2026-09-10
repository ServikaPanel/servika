package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"servika/internal/auth"
	"servika/internal/credentials"
	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/quota"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB *sql.DB
}

type Mailbox struct {
	ID        int64  `json:"id"`
	LocalPart string `json:"local_part"`
	Email     string `json:"email"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	// QuotaBytes is the limit and UsedBytes the last measurement of it. Zero
	// quota means no limit, not a full mailbox, so a screen has to read them
	// together. UsageCheckedAt is empty until a measurement has ever run, which
	// keeps "never measured" apart from "measured, and it was empty".
	QuotaBytes     int64  `json:"quota_bytes"`
	UsedBytes      int64  `json:"used_bytes"`
	UsageCheckedAt string `json:"usage_checked_at,omitempty"`
}

type Status struct {
	Enabled      bool   `json:"enabled"`
	DKIMSelector string `json:"dkim_selector,omitempty"`
	// InfrastructureMissing names the mail services that are not running on this
	// server, empty when the stack is ready. It is data rather than a sentence so
	// the interface can disable the enable button and explain why in its own
	// language, instead of letting the customer click and collect an error.
	InfrastructureMissing []string `json:"infrastructure_missing,omitempty"`
}

var localPartPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

func (h *Handlers) domain(r *http.Request) (id int64, systemUser string, demo, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(is_demo,0) FROM domains WHERE id=?`, id).
		Scan(&systemUser, &isDemo); err != nil {
		return id, "", false, false
	}
	return id, systemUser, isDemo == 1, true
}

func (h *Handlers) audit(r *http.Request, action, target string, ok bool) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		return
	}
	auth.WriteAudit(h.DB, claims.UserID, claims.Username, httpx.AuditIP(r), action, target, ok)
}

// MailStatus reports whether native mail hosting is enabled for a domain.
func (h *Handlers) MailStatus(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var status, selector string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT status, dkim_selector FROM mail_domains WHERE domain_id=?`, id).Scan(&status, &selector)
	// Reported in both states. A domain that has never enabled mail needs it to
	// know the button will not work; a domain that already has mailboxes needs it
	// more, because there the stack going down means delivery has stopped.
	httpx.WriteJSON(w, http.StatusOK, Status{
		Enabled:               err == nil && status == "active",
		DKIMSelector:          selector,
		InfrastructureMissing: MissingMailServices(r.Context()),
	})
}

// Enable enables native mail hosting for a domain.
func (h *Handlers) Enable(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	// Stop here rather than after the fact. EnableDomain publishes MX, SPF, DKIM
	// and DMARC, so letting it run against a dead stack tells the world this
	// server accepts the domain's mail while nothing is listening.
	//
	// The interface disables the button from the status response, so a customer
	// should never reach this; it is the backstop for a stale tab. The names go to
	// the log rather than the response because the response is English and the
	// interface ships twelve languages.
	if missing := MissingMailServices(r.Context()); len(missing) > 0 {
		// #nosec G706 -- missing is a subset of the requiredMailServices literals ("postfix", "dovecot"); no request data reaches this line.
		log.Printf("enable mail domain=%d: refused, services not running: %s", id, strings.Join(missing, ", "))
		httpx.WriteError(w, http.StatusServiceUnavailable, "mail infrastructure is not running on this server")
		return
	}
	if err := EnableDomain(r.Context(), h.DB, id); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("enable mail domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not enable mail")
		return
	}
	h.audit(r, "mail.enable", strconv.FormatInt(id, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Disable disables native mail hosting for a domain without deleting mailboxes.
func (h *Handlers) Disable(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	if err := DisableDomain(r.Context(), h.DB, id); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("disable mail domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not disable mail")
		return
	}
	h.audit(r, "mail.disable", strconv.FormatInt(id, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Purge removes mail hosting for a domain outright, mailboxes and stored
// messages included. Unlike Disable this cannot be undone, which is why it has a
// route of its own instead of a flag on that one: an accidental call must not be
// reachable from the reversible path.
func (h *Handlers) Purge(w http.ResponseWriter, r *http.Request) {
	id, systemUser, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	if systemUser == "" {
		// Without it the Maildir root cannot be located, and deleting the database
		// rows alone would strand the files with nothing left pointing at them.
		httpx.WriteError(w, http.StatusInternalServerError, "domain record is incomplete")
		return
	}
	diskFailed, err := PurgeDomain(r.Context(), h.DB, id, systemUser)
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("purge mail domain=%d: %v", id, err)
		h.audit(r, "mail.purge", strconv.FormatInt(id, 10), false)
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove mail hosting")
		return
	}
	h.audit(r, "mail.purge", strconv.FormatInt(id, 10), true)
	if diskFailed {
		// 200 because the service really is gone; the warning is a stable CODE the
		// interface translates, not a sentence, and it is not hidden: the files
		// still occupy the customer's disk.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "warning": "mail_files_not_removed"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// List returns mailboxes for a domain.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, local_part, email, status, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i'),
		        quota_bytes, used_bytes,
		        COALESCE(DATE_FORMAT(usage_checked_at,'%Y-%m-%dT%H:%i:%sZ'),'')
		   FROM mailboxes WHERE domain_id=? ORDER BY local_part`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mailboxes")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Mailbox, 0)
	for rows.Next() {
		var mailbox Mailbox
		if err := rows.Scan(&mailbox.ID, &mailbox.LocalPart, &mailbox.Email, &mailbox.Status, &mailbox.CreatedAt,
			&mailbox.QuotaBytes, &mailbox.UsedBytes, &mailbox.UsageCheckedAt); err == nil {
			out = append(out, mailbox)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mailboxes")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Create creates a mailbox for a domain.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	var req struct {
		LocalPart string `json:"local_part"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	localPart := strings.ToLower(strings.TrimSpace(req.LocalPart))
	if !localPartPattern.MatchString(localPart) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid mailbox name")
		return
	}
	if req.Password == "" {
		req.Password = credentials.RandomPassword(20)
	}
	if !credentials.ValidPassword(req.Password) {
		httpx.WriteError(w, http.StatusBadRequest, "password contains invalid characters")
		return
	}

	var mailDomainID int64
	var domainName, maildirRoot, systemUser string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, domain_name, maildir_root, system_user FROM mail_domains WHERE domain_id=? AND status='active'`, id).
		Scan(&mailDomainID, &domainName, &maildirRoot, &systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusBadRequest, "enable mail for this domain first")
		return
	}
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("read mail domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read mail domain")
		return
	}
	// The plan gate is a COUNT followed by a separate INSERT, and the unique key
	// on mailboxes constrains the address rather than the per-customer count, so
	// concurrent requests all read the same total and all insert. This is the lock
	// quota documents for exactly that race; it was wired only into the two
	// database-creation paths.
	//
	// Released as soon as the row exists, not at the end of the handler: a
	// concurrent request counting it from then on sees the true total.
	unlock := sync.OnceFunc(quota.LockCustomerForDomain(r.Context(), h.DB, id))
	defer unlock()
	if err := quota.CheckMailboxAllowed(r.Context(), h.DB, id); err != nil {
		if le, ok := errors.AsType[*quota.LimitError](err); ok {
			httpx.WriteError(w, http.StatusForbidden, le.Message)
			return
		}
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("mailbox quota check for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify plan limit")
		return
	}

	email := localPart + "@" + domainName
	hash, err := HashPassword(req.Password)
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("hash mailbox password domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not prepare mailbox password")
		return
	}
	maildir := mailboxMaildir(maildirRoot, domainName, localPart)
	if err := createMaildir(systemUser, maildir); err != nil {
		// #nosec G706 -- logged values are a filepath.Join of a template-derived root, a validated domain name and a validated local part, plus an error string; no raw tenant string with CR/LF reaches the log.
		log.Printf("create Maildir %q: %v", maildir, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not create mailbox storage")
		return
	}

	// The plan's mail limits are applied at creation. Dovecot reads the quota
	// through its userdb query and the policy server reads the send limits from
	// the same row, so a mailbox created without them is genuinely unlimited no
	// matter what the plan says. A send limit the plan leaves at zero keeps the
	// column default rather than becoming unlimited.
	limits := planLimitsOrDefault(r.Context(), h.DB, id)
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO mailboxes(domain_id, mail_domain_id, local_part, email, password_hash, maildir, quota_bytes,
		   send_limit_hour, send_limit_day)
		 VALUES(?,?,?,?,?,?,?,
		   IF(? > 0, ?, DEFAULT(send_limit_hour)),
		   IF(? > 0, ?, DEFAULT(send_limit_day)))`,
		id, mailDomainID, localPart, email, hash, maildir, limits.QuotaBytes,
		limits.SendLimitHour, limits.SendLimitHour,
		limits.SendLimitDay, limits.SendLimitDay)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "mailbox already exists or could not be created")
		return
	}
	unlock()
	mailboxID, _ := res.LastInsertId()
	h.audit(r, "mail.create", email, true)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": mailboxID, "email": email, "password": req.Password})
}

// Delete removes a mailbox row while preserving its Maildir data on disk.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	mailboxID, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var email string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT email FROM mailboxes WHERE id=? AND domain_id=?`, mailboxID, id).Scan(&email); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM mailboxes WHERE id=? AND domain_id=?`, mailboxID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete mailbox")
		return
	}
	// The passdb answer is cached, so the deleted mailbox keeps authenticating
	// until the entry expires; its Maildir is deliberately preserved on disk.
	FlushAuthCache(r.Context(), email)
	h.audit(r, "mail.delete", email, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ResetPassword updates a mailbox password or generates a new one.
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	mailboxID, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Password == "" {
		req.Password = credentials.RandomPassword(20)
	}
	if !credentials.ValidPassword(req.Password) {
		httpx.WriteError(w, http.StatusBadRequest, "password contains invalid characters")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("hash mailbox password domain=%d mailbox=%d: %v", id, mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not prepare mailbox password")
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE mailboxes SET password_hash=? WHERE id=? AND domain_id=?`, hash, mailboxID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update mailbox")
		return
	}
	if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	// Without this the OLD password still opens the mailbox over IMAP and SASL
	// for the life of the cache entry, which is the window a rotation closes.
	h.flushMailboxAuthCache(r.Context(), id, mailboxID)
	h.audit(r, "mail.password", strconv.FormatInt(mailboxID, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "password": req.Password})
}

// SetStatus changes a mailbox status.
func (h *Handlers) SetStatus(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	mailboxID, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Status != "active" && req.Status != "suspended") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid status")
		return
	}
	// mailboxes.status carries two independent authorities: the owner's own on/off
	// switch, and the containment the spam policy applies when a mailbox passes its
	// send limit (internal/mail/policy.go stamps spam_suspended_at with it). Only
	// spam_suspended_at tells them apart, so a customer resuming a mailbox could
	// undo the panel's only automatic answer to an abusive mailbox and erase the
	// evidence in the same statement.
	//
	// The guard sits in the WHERE clause, not in a separate read, so the policy
	// server cannot contain the mailbox between a check and the write.
	operator := isMailOperator(r)
	liftsContainment := operator && req.Status == "active"
	guard := ""
	if req.Status == "active" && !operator {
		guard = " AND spam_suspended_at IS NULL"
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE mailboxes SET status=?,
		   spam_suspended_at=IF(?='active',NULL,spam_suspended_at)
		 WHERE id=? AND domain_id=?`+guard, req.Status, req.Status, mailboxID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update mailbox")
		return
	}
	if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
		status, message := h.statusRefusal(r.Context(), id, mailboxID)
		httpx.WriteError(w, status, message)
		return
	}
	// mailboxes.status is an input to the cached passdb answer, so a suspension
	// reaches IMAP only once the entry is dropped.
	h.flushMailboxAuthCache(r.Context(), id, mailboxID)
	action := "mail.status"
	if liftsContainment {
		// Naming the lift separately is the point of reserving it: an operator
		// undoing a spam containment leaves a line an operator can find later,
		// rather than one indistinguishable from an ordinary resume.
		action = "mail.status.spam_resume"
	}
	h.audit(r, action, strconv.FormatInt(mailboxID, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// statusRefusal explains why a status update matched no row. The update itself
// carries the guard, so this only has to name which of the two reasons applied:
// the mailbox is gone, or the spam policy holds it and the caller is its owner.
//
// It fails closed. A row it cannot read is not evidence the containment is gone.
func (h *Handlers) statusRefusal(ctx context.Context, domainID, mailboxID int64) (int, string) {
	// Reading the predicate rather than the timestamp keeps the answer independent
	// of whether the DSN parses DATETIME into time.Time.
	var contained bool
	err := h.DB.QueryRowContext(ctx,
		`SELECT spam_suspended_at IS NOT NULL FROM mailboxes WHERE id=? AND domain_id=?`,
		mailboxID, domainID).Scan(&contained)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return http.StatusNotFound, "mailbox not found"
	case err != nil:
		return http.StatusInternalServerError, "could not update mailbox"
	case contained:
		return http.StatusForbidden, "the spam protection suspended this mailbox; an operator has to resume it"
	default:
		return http.StatusNotFound, "mailbox not found"
	}
}

// planLimitsOrDefault reads the domain plan's mail limits for a mailbox that is
// about to be created.
//
// A read failure yields the zero value rather than an arbitrary limit: inventing
// a quota is worse than the plan not being applied, and a zero send limit leaves
// the column default in place instead of removing the spam protection. The
// failure is logged, so it is not lost.
func planLimitsOrDefault(ctx context.Context, db *sql.DB, domainID int64) PlanMailLimits {
	limits, err := planLimitsFor(ctx, db, domainID)
	if err != nil {
		// #nosec G706 -- the operands are an integer domain ID and a database
		// driver error; no client-controlled string reaches the log line.
		log.Printf("mail plan limit lookup for domain %d: %v", domainID, err)
		return PlanMailLimits{}
	}
	return limits
}

// quotaBytesFromMB converts the plan's megabyte figure into the byte count the
// mailbox row and Dovecot's quota_rule both speak. A plan value of 0 (or a
// negative one an operator managed to store) means no limit, and Dovecot reads
// that as "no quota_rule", not as "zero bytes allowed".
func quotaBytesFromMB(quotaMB int64) int64 {
	if quotaMB <= 0 {
		return 0
	}
	return quotaMB * 1024 * 1024
}
