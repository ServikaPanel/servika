package mail

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

type SendLimits struct {
	MailboxID       int64  `json:"mailbox_id"`
	Email           string `json:"email"`
	HourLimit       int    `json:"hour_limit"`
	DayLimit        int    `json:"day_limit"`
	SentHour        int    `json:"sent_hour"`
	SentDay         int    `json:"sent_day"`
	SpamSuspendedAt string `json:"spam_suspended_at,omitempty"`
}

// StartPolicyServer runs the Postfix policy delegation service used by
// smtpd_end_of_data_restrictions to enforce per-account send limits.
func StartPolicyServer(db *sql.DB, address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		logx.Errorf("mail policy could not listen (%s): %v", address, err)
		return
	}
	logx.Infof("mail send policy service on %s", address)
	go func() {
		defer func() { _ = listener.Close() }()
		// An unconditional `continue` on an Accept error spins the CPU forever
		// when the listener breaks permanently (a closed fd). A close is
		// permanent → return; on a transient error (fd/memory pressure) back off
		// briefly and retry, doubling the wait on consecutive failures.
		wait := 5 * time.Millisecond
		const maxWait = time.Second
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logx.Errorf("mail policy listener closed: %v", err)
					return
				}
				logx.Errorf("mail policy accept: %v", err)
				time.Sleep(wait)
				if wait < maxWait {
					wait *= 2
				}
				continue
			}
			wait = 5 * time.Millisecond
			go handlePolicyConnection(db, conn)
		}
	}()
	go pruneSendLog(db)
}

// pruneSendLog trims mail_send_log: it gains one row per outgoing message and,
// left unbounded, climbs to millions of rows over months. The policy server runs
// two SUMs over this table on every mail, so its cost feeds straight into send
// latency. The limit windows are 1 hour and 1 day, so a 2-day retention is more
// than enough (the same pattern as the 30-day git_webhook_deliveries prune).
func pruneSendLog(db *sql.DB) {
	const batch = 50000
	for {
		// A single DELETE of millions of rows means a long InnoDB lock; delete in
		// batches and fully drain any accumulated backlog on the first pass.
		for range 200 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			res, err := db.ExecContext(ctx,
				`DELETE FROM mail_send_log WHERE ts < NOW()-INTERVAL 2 DAY LIMIT ?`, batch)
			cancel()
			if err != nil {
				logx.Errorf("mail_send_log prune: %v", err)
				break
			}
			if n, err := res.RowsAffected(); err != nil || n < batch {
				break
			}
		}
		time.Sleep(time.Hour)
	}
}

func handlePolicyConnection(db *sql.DB, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	scanner := bufio.NewScanner(conn)
	attrs := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			action := evaluateSendPolicy(db, attrs)
			_, _ = fmt.Fprintf(conn, "action=%s\n\n", action)
			attrs = map[string]string{}
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			attrs[key] = value
		}
	}
	reportUnansweredPolicyRequest(attrs, scanner.Err())
}

// reportUnansweredPolicyRequest names the two ways this connection can end
// without having answered the request it received.
//
// Postfix is configured with `smtpd_policy_service_default_action=DUNNO`, so a
// request that goes unanswered is not refused: the send limit simply does not
// apply to that mail, and the next restriction runs as if this service had no
// opinion. Discarding the error therefore turns a ceiling that has stopped
// working into something with no trace anywhere, which is the one outcome a
// rate limit must not have.
//
// A non-empty attribute map means the peer sent attributes and the connection
// ended before the blank line that asks for a verdict. The read error is
// reported separately because it also fires when nothing was pending, and
// `os.ErrDeadlineExceeded` is excluded because the 15-second deadline above
// closes every connection, healthy ones included.
func reportUnansweredPolicyRequest(attrs map[string]string, err error) {
	if len(attrs) > 0 {
		logx.Errorf("mail policy: connection ended with %d attributes and no verdict; the send limit did not apply to that mail", len(attrs))
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		logx.Errorf("mail policy read: %v", err)
	}
}

func evaluateSendPolicy(db *sql.DB, attrs map[string]string) string {
	request, ok := readPolicyRequest(attrs)
	if !ok {
		return "DUNNO"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "DUNNO"
	}
	defer func() { _ = tx.Rollback() }()
	sender, verdict := lockSendingMailbox(ctx, tx, request.email)
	if verdict != "" {
		return verdict
	}
	if verdict := sender.readSentCounts(ctx, tx); verdict != "" {
		return verdict
	}
	// Server-wide ceilings sit above the per-mailbox ones. They are read inside
	// the same transaction as the counts, so a limit an operator has just lowered
	// takes effect on the very next message rather than after a restart.
	server, serverErr := ReadServerSettings(ctx, db)
	if serverErr != nil {
		// Failing open here would let a compromised account through exactly when
		// the database is unhealthy, which is not when to relax a ceiling.
		logx.Errorf("mail policy could not read the server settings: %v", serverErr)
		return "DEFER_IF_PERMIT 4.7.1 Send policy is temporarily unavailable"
	}
	if verdict := serverCeilingVerdict(ctx, tx, server, sender, request); verdict != "" {
		return verdict
	}
	if sender.exceeds(request.recipients) {
		return suspendForSendLimit(ctx, tx, sender, request)
	}
	return recordAcceptedSend(ctx, tx, sender, request)
}

// policyRequest is what Postfix asked about one message.
type policyRequest struct {
	email      string
	recipients int
	clientIP   string
}

// readPolicyRequest reads the sender, the recipient count and the client
// address, and reports false when there is no authenticated sender to judge.
func readPolicyRequest(attrs map[string]string) (policyRequest, bool) {
	email := strings.ToLower(strings.TrimSpace(attrs["sasl_username"]))
	if email == "" {
		return policyRequest{}, false
	}
	recipients, _ := strconv.Atoi(attrs["recipient_count"])
	if recipients < 1 {
		recipients = 1
	}
	// Postfix gives the address the mail came from. It is recorded so the
	// per-client ceiling has something to count, and bounded because it is
	// written into a column and read back into a query.
	clientIP := strings.TrimSpace(attrs["client_address"])
	if len(clientIP) > 45 || net.ParseIP(clientIP) == nil {
		clientIP = ""
	}
	return policyRequest{email: email, recipients: recipients, clientIP: clientIP}, true
}

// policySender is the mailbox a message is sent from, as its row and its send
// log stand inside the policy transaction.
type policySender struct {
	mailboxID, domainID int64
	status              string
	hourLimit, dayLimit int
	sentHour, sentDay   int
}

// lockSendingMailbox reads the sending mailbox FOR UPDATE and returns the verdict
// when it may not send at all.
func lockSendingMailbox(ctx context.Context, tx *sql.Tx, email string) (policySender, string) {
	var sender policySender
	err := tx.QueryRowContext(ctx, `SELECT id, domain_id, status, send_limit_hour, send_limit_day
		FROM mailboxes WHERE email=? FOR UPDATE`, email).
		Scan(&sender.mailboxID, &sender.domainID, &sender.status, &sender.hourLimit, &sender.dayLimit)
	if err != nil {
		return sender, "DUNNO"
	}
	if sender.status != "active" {
		return sender, "REJECT 5.7.1 Mail account is not active"
	}
	return sender, ""
}

// readSentCounts reads the mailbox's own hourly and daily totals.
//
// The per-mailbox counts DEFER on a read failure, for the same reason the
// server-settings read below does and ceilingCount does. Discarded, both
// totals stayed at 0, the exceeded test could never be true, and the mailbox
// was never suspended: the one layer meant to catch a compromised account was
// off for as long as mail_send_log could not be read, which is exactly the
// state a mass-mailing burst against that table produces.
func (sender *policySender) readSentCounts(ctx context.Context, tx *sql.Tx) string {
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		WHERE mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`, sender.mailboxID).Scan(&sender.sentHour); err != nil {
		// #nosec G706 -- the logged values are a validated mailbox id and an error string; no raw tenant string with CR/LF reaches the log.
		logx.Errorf("mail policy could not read the hourly send count for mailbox %d: %v", sender.mailboxID, err)
		return "DEFER_IF_PERMIT 4.7.1 Send policy is temporarily unavailable"
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		WHERE mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 DAY`, sender.mailboxID).Scan(&sender.sentDay); err != nil {
		// #nosec G706 -- the logged values are a validated mailbox id and an error string; no raw tenant string with CR/LF reaches the log.
		logx.Errorf("mail policy could not read the daily send count for mailbox %d: %v", sender.mailboxID, err)
		return "DEFER_IF_PERMIT 4.7.1 Send policy is temporarily unavailable"
	}
	return ""
}

// serverCeilingVerdict applies the server-wide hourly ceilings for the domain
// and for the sending connection.
func serverCeilingVerdict(ctx context.Context, tx *sql.Tx, server ServerSettings, sender policySender, request policyRequest) string {
	domainSent := ceilingCount(ctx, tx,
		`SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		  WHERE domain_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`,
		server.DomainSendLimitHour, sender.domainID)
	clientSent := 0
	if request.clientIP != "" {
		clientSent = ceilingCount(ctx, tx,
			`SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
			  WHERE client_ip=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`,
			server.ClientSendLimitHour, request.clientIP)
	}
	if server.DomainSendLimitHour > 0 && domainSent+request.recipients > server.DomainSendLimitHour {
		// The domain ceiling is a rate limit on the whole domain, not a signal
		// that one mailbox was taken over, so nothing is suspended: the sender is
		// told to come back rather than locked out.
		return "DEFER_IF_PERMIT 4.7.1 Domain hourly send limit reached; try again later"
	}
	if server.ClientSendLimitHour > 0 && clientSent+request.recipients > server.ClientSendLimitHour {
		return "DEFER_IF_PERMIT 4.7.1 Hourly send limit for this connection reached; try again later"
	}
	return ""
}

// exceeds reports whether the message passes the mailbox's hourly or daily
// limit.
func (sender policySender) exceeds(recipients int) bool {
	return (sender.hourLimit > 0 && sender.sentHour+recipients > sender.hourLimit) ||
		(sender.dayLimit > 0 && sender.sentDay+recipients > sender.dayLimit)
}

// suspendForSendLimit suspends a mailbox that passed its own limit, logs the
// refused message and commits.
func suspendForSendLimit(ctx context.Context, tx *sql.Tx, sender policySender, request policyRequest) string {
	email := request.email
	_, _ = tx.ExecContext(ctx, `UPDATE mailboxes
			SET status='suspended', spam_suspended_at=NOW() WHERE id=?`, sender.mailboxID)
	_, _ = tx.ExecContext(ctx, `INSERT INTO mail_send_log(mailbox_id,domain_id,ok,recipient_count,client_ip)
			VALUES(?,?,0,?,?)`, sender.mailboxID, sender.domainID, request.recipients, request.clientIP)
	_ = tx.Commit()
	// The suspension reaches Postfix immediately (this server re-reads the
	// row per message) but not IMAP, whose passdb answer is cached.
	FlushAuthCache(ctx, email)
	logx.Warnf("mail spam protection: %s auto-suspended (hour=%d/%d day=%d/%d)",
		email, sender.sentHour, sender.hourLimit, sender.sentDay, sender.dayLimit)
	return "REJECT 5.7.1 Send limit exceeded; account suspended for security"
}

// recordAcceptedSend logs a message the mailbox may send and commits.
func recordAcceptedSend(ctx context.Context, tx *sql.Tx, sender policySender, request policyRequest) string {
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_send_log(mailbox_id,domain_id,ok,recipient_count,client_ip)
		VALUES(?,?,1,?,?)`, sender.mailboxID, sender.domainID, request.recipients, request.clientIP); err != nil {
		return "DUNNO"
	}
	if err := tx.Commit(); err != nil {
		return "DUNNO"
	}
	return "DUNNO"
}

// SendLimitsGet returns a mailbox's send limits and usage. GET /domains/{id}/mail/{mid}/send-limits
func (h *Handlers) SendLimitsGet(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mid, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var s SendLimits
	var suspended sql.NullString
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT m.id,m.email,m.send_limit_hour,m.send_limit_day,
		  (SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log l WHERE l.mailbox_id=m.id AND l.ok=1 AND l.ts>=NOW()-INTERVAL 1 HOUR),
		  (SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log l WHERE l.mailbox_id=m.id AND l.ok=1 AND l.ts>=NOW()-INTERVAL 1 DAY),
		  DATE_FORMAT(m.spam_suspended_at,'%Y-%m-%d %H:%i')
		FROM mailboxes m WHERE m.id=? AND m.domain_id=?`, mid, id).
		Scan(&s.MailboxID, &s.Email, &s.HourLimit, &s.DayLimit, &s.SentHour, &s.SentDay, &suspended)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if suspended.Valid {
		s.SpamSuspendedAt = suspended.String
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

// isMailOperator reports whether the caller acts on a mailbox as an operator
// rather than as its owner. Every mail route is mounted under CustomerScope, so
// an admin and a reseller reach them too; the decisions reserved for them are
// writing a send limit the plan does not allow, and lifting a suspension the
// spam policy applied.
func isMailOperator(r *http.Request) bool {
	c := middleware.ClaimsFrom(r)
	return c != nil && (c.Role == middleware.RoleAdmin || c.Role == middleware.RoleReseller)
}

// refuseAbovePlan reads the domain's plan and reports why a customer's send
// limits are not acceptable, or an empty reason when they are.
func (h *Handlers) refuseAbovePlan(ctx context.Context, domainID int64, req SendLimits) (string, error) {
	plan, err := planLimitsFor(ctx, h.DB, domainID)
	if err != nil {
		return "", err
	}
	return refusalAgainstPlan(plan, req), nil
}

// refusalAgainstPlan judges the request against the plan's ceiling.
//
// 0 is refused outright: the policy server reads a stored 0 as UNLIMITED
// (`hourLimit > 0 && ...`), so on a mailbox row it is not "no override", it is
// the removal of the ceiling. A PLAN value of 0 is the opposite: it means the
// plan sets no override, so it is not a ceiling to hold anybody to.
func refusalAgainstPlan(plan PlanMailLimits, req SendLimits) string {
	if req.HourLimit == 0 || req.DayLimit == 0 {
		return "a send limit of 0 means unlimited and cannot be set on this subscription"
	}
	if plan.SendLimitHour > 0 && req.HourLimit > plan.SendLimitHour {
		return "the hourly send limit exceeds the plan's ceiling"
	}
	if plan.SendLimitDay > 0 && req.DayLimit > plan.SendLimitDay {
		return "the daily send limit exceeds the plan's ceiling"
	}
	return ""
}

// SendLimitsPut saves a mailbox's send limits. PUT /domains/{id}/mail/{mid}/send-limits
func (h *Handlers) SendLimitsPut(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mid, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var req SendLimits
	if json.NewDecoder(r.Body).Decode(&req) != nil || invalidSendLimits(req) {
		httpx.WriteError(w, http.StatusBadRequest, "limits must be 0-100000; the hourly limit may not exceed the daily limit")
		return
	}
	if !h.mailboxBelongs(r.Context(), id, mid) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	// A customer may lower its own limits, never raise them past the plan and
	// never to 0, which the policy server reads as unlimited.
	operator := isMailOperator(r)
	if !operator && !h.sendLimitsWithinPlan(w, r, id, req) {
		return
	}
	// send_limits_manual is what stops the next plan change from undoing this,
	// because the plan realignment skips a mailbox somebody has tuned by hand.
	// Only an OPERATOR may set it: a customer who could would make their own
	// value survive every later plan change, which is the whole point of the
	// ceiling they are being held to.
	manual := 0
	if operator {
		manual = 1
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE mailboxes
		SET send_limit_hour=?,send_limit_day=?,send_limits_manual=? WHERE id=? AND domain_id=?`,
		req.HourLimit, req.DayLimit, manual, mid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save send limits")
		return
	}
	h.audit(r, "mail.send_limits.update", strconv.FormatInt(mid, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// invalidSendLimits reports a limit outside 0-100000, or an hourly limit above
// the daily one.
func invalidSendLimits(req SendLimits) bool {
	return req.HourLimit < 0 || req.HourLimit > 100000 ||
		req.DayLimit < 0 || req.DayLimit > 100000 ||
		(req.HourLimit > 0 && req.DayLimit > 0 && req.HourLimit > req.DayLimit)
}

// sendLimitsWithinPlan refuses a customer's limits the plan does not allow. It
// writes the refusal and reports false when the request must stop.
func (h *Handlers) sendLimitsWithinPlan(w http.ResponseWriter, r *http.Request, domainID int64, req SendLimits) bool {
	reason, err := h.refuseAbovePlan(r.Context(), domainID, req)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the plan's mail limits")
		return false
	}
	if reason != "" {
		httpx.WriteError(w, http.StatusForbidden, reason)
		return false
	}
	return true
}

// ceilingCount runs a counting query only when the ceiling it feeds is actually
// set. Every outgoing message goes through here, so a query for a limit nobody
// configured is pure latency on the send path.
//
// A failed count returns the ceiling itself, which trips the limit. Returning 0
// would let mail through precisely when the database cannot be read, and a
// deferral an operator can see beats a ceiling that quietly stops applying.
func ceilingCount(ctx context.Context, tx *sql.Tx, query string, ceiling int, arg any) int {
	if ceiling <= 0 {
		return 0
	}
	var count int
	if err := tx.QueryRowContext(ctx, query, arg).Scan(&count); err != nil {
		logx.Errorf("mail policy ceiling count: %v", err)
		return ceiling
	}
	return count
}
