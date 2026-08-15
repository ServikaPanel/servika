package mail

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"

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
		log.Printf("mail policy could not listen (%s): %v", address, err)
		return
	}
	log.Printf("mail send policy service on %s", address)
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
					log.Printf("mail policy listener closed: %v", err)
					return
				}
				log.Printf("mail policy accept: %v", err)
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
				log.Printf("mail_send_log prune: %v", err)
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
		log.Printf("mail policy: connection ended with %d attributes and no verdict; the send limit did not apply to that mail", len(attrs))
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		log.Printf("mail policy read: %v", err)
	}
}

func evaluateSendPolicy(db *sql.DB, attrs map[string]string) string {
	email := strings.ToLower(strings.TrimSpace(attrs["sasl_username"]))
	if email == "" {
		return "DUNNO"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "DUNNO"
	}
	defer func() { _ = tx.Rollback() }()
	var mailboxID, domainID int64
	var status string
	var hourLimit, dayLimit int
	err = tx.QueryRowContext(ctx, `SELECT id, domain_id, status, send_limit_hour, send_limit_day
		FROM mailboxes WHERE email=? FOR UPDATE`, email).
		Scan(&mailboxID, &domainID, &status, &hourLimit, &dayLimit)
	if err != nil {
		return "DUNNO"
	}
	if status != "active" {
		return "REJECT 5.7.1 Mail account is not active"
	}
	var sentHour, sentDay int
	_ = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		WHERE mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`, mailboxID).Scan(&sentHour)
	_ = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		WHERE mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 DAY`, mailboxID).Scan(&sentDay)
	// Server-wide ceilings sit above the per-mailbox ones. They are read inside
	// the same transaction as the counts, so a limit an operator has just lowered
	// takes effect on the very next message rather than after a restart.
	server, serverErr := ReadServerSettings(ctx, db)
	if serverErr != nil {
		// Failing open here would let a compromised account through exactly when
		// the database is unhealthy, which is not when to relax a ceiling.
		log.Printf("mail policy could not read the server settings: %v", serverErr)
		return "DEFER_IF_PERMIT 4.7.1 Send policy is temporarily unavailable"
	}
	domainSent := ceilingCount(ctx, tx,
		`SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
		  WHERE domain_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`,
		server.DomainSendLimitHour, domainID)
	clientSent := 0
	if clientIP != "" {
		clientSent = ceilingCount(ctx, tx,
			`SELECT COALESCE(SUM(recipient_count),0) FROM mail_send_log
			  WHERE client_ip=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR`,
			server.ClientSendLimitHour, clientIP)
	}
	if server.DomainSendLimitHour > 0 && domainSent+recipients > server.DomainSendLimitHour {
		// The domain ceiling is a rate limit on the whole domain, not a signal
		// that one mailbox was taken over, so nothing is suspended: the sender is
		// told to come back rather than locked out.
		return "DEFER_IF_PERMIT 4.7.1 Domain hourly send limit reached; try again later"
	}
	if server.ClientSendLimitHour > 0 && clientSent+recipients > server.ClientSendLimitHour {
		return "DEFER_IF_PERMIT 4.7.1 Hourly send limit for this connection reached; try again later"
	}

	exceeded := (hourLimit > 0 && sentHour+recipients > hourLimit) ||
		(dayLimit > 0 && sentDay+recipients > dayLimit)
	if exceeded {
		_, _ = tx.ExecContext(ctx, `UPDATE mailboxes
			SET status='suspended', spam_suspended_at=NOW() WHERE id=?`, mailboxID)
		_, _ = tx.ExecContext(ctx, `INSERT INTO mail_send_log(mailbox_id,domain_id,ok,recipient_count,client_ip)
			VALUES(?,?,0,?,?)`, mailboxID, domainID, recipients, clientIP)
		_ = tx.Commit()
		log.Printf("mail spam protection: %s auto-suspended (hour=%d/%d day=%d/%d)",
			email, sentHour, hourLimit, sentDay, dayLimit)
		return "REJECT 5.7.1 Send limit exceeded; account suspended for security"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_send_log(mailbox_id,domain_id,ok,recipient_count,client_ip)
		VALUES(?,?,1,?,?)`, mailboxID, domainID, recipients, clientIP); err != nil {
		return "DUNNO"
	}
	if err := tx.Commit(); err != nil {
		return "DUNNO"
	}
	return "DUNNO"
}

// SendLimitsGet returns a mailbox's send limits and usage. GET /domains/{id}/mail/{mid}/send-limits
func (h *Handlers) SendLimitsGet(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
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

// SendLimitsPut saves a mailbox's send limits. PUT /domains/{id}/mail/{mid}/send-limits
func (h *Handlers) SendLimitsPut(w http.ResponseWriter, r *http.Request) {
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
	var req SendLimits
	if json.NewDecoder(r.Body).Decode(&req) != nil ||
		req.HourLimit < 0 || req.HourLimit > 100000 ||
		req.DayLimit < 0 || req.DayLimit > 100000 ||
		(req.HourLimit > 0 && req.DayLimit > 0 && req.HourLimit > req.DayLimit) {
		httpx.WriteError(w, http.StatusBadRequest, "limits must be 0-100000; the hourly limit may not exceed the daily limit")
		return
	}
	if !h.mailboxBelongs(r.Context(), id, mid) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	// send_limits_manual is what stops the next plan change from undoing this.
	// The plan realignment skips a mailbox somebody has tuned by hand, so the
	// flag has to be set in the same statement as the values it protects.
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE mailboxes
		SET send_limit_hour=?,send_limit_day=?,send_limits_manual=1 WHERE id=? AND domain_id=?`,
		req.HourLimit, req.DayLimit, mid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save send limits")
		return
	}
	h.audit(r, "mail.send_limits.update", strconv.FormatInt(mid, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
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
		log.Printf("mail policy ceiling count: %v", err)
		return ceiling
	}
	return count
}
