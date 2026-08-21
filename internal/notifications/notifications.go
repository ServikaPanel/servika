// Package notifications is the panel's own alert stream.
//
// Nothing here delivers anything outside the panel. A notification is a row a
// signed-in person sees in the top bar, and that is the whole contract: an
// operator or a customer who never signs in still learns nothing, which is why
// this is a screen rather than a channel.
//
// Two rules shape everything below and neither is visible from the schema.
//
// A notification with a NULL domain_id is PANEL-WIDE and belongs to admins
// alone. No ownership condition can express that, so the visibility test is
// that rule ANDed with middleware.ScopeCondition rather than a bare ScopeSQL
// call, and every query here goes through the same visibility() so a rule
// honoured on the read path and forgotten on the write path is impossible.
//
// The read flag is NOT a column on the notification. One domain notification
// has up to three viewers: the customer, the reseller who owns them, and an
// admin. A single flag means whoever opens it first marks it read for everyone,
// so an admin dismissing a notice hides it from the customer who has to act on
// it.
package notifications

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Levels a notification can carry. They are the screen's tone, not a policy:
// nothing in the panel acts on a notification.
const (
	LevelInfo     = "info"
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// maxRows bounds one page. The bell shows a recent list rather than an archive,
// and an unbounded list on a server that has been running for a year is a
// response nobody reads and a query nobody notices getting slower.
const maxRows = 100

// retention is how long a notification is kept. Without it the table grows for
// the life of the installation, and this one has a writer that fires on every
// real-time detection.
const retention = 90 * 24 * time.Hour

type Handlers struct{ DB *sql.DB }

// Notification is one row as the screen reads it.
type Notification struct {
	ID        int64  `json:"id"`
	Level     string `json:"level"`
	Category  string `json:"category"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	DomainID  *int64 `json:"domain_id"`
	Domain    string `json:"domain"`
	RefType   string `json:"ref_type"`
	RefID     int64  `json:"ref_id"`
	Read      bool   `json:"read"`
	CreatedAt string `json:"created_at"`
}

// Write records one notification.
//
// domainID nil means panel-wide, which only admins see. The error is RETURNED
// rather than logged and discarded: a notification that was never written reads
// exactly like one that was delivered, and the caller is the only code that
// knows whether losing it matters.
func Write(ctx context.Context, db *sql.DB, level, category, title, message string, domainID *int64, refType string, refID int64) error {
	if db == nil {
		return fmt.Errorf("notifications: no database")
	}
	var domain any
	if domainID != nil {
		domain = *domainID
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO notifications (level, category, title, message, domain_id, ref_type, ref_id)
		 VALUES (?,?,?,?,?,?,?)`,
		level, category, truncate(title, 200), message, domain, refType, refID)
	if err != nil {
		return fmt.Errorf("notifications: the notification could not be written: %w", err)
	}
	return nil
}

// visibility answers which notifications this request may see, as a condition
// over the aliases `n` (notifications) and `d` (the LEFT JOINed domain).
//
// An admin sees everything, panel-wide rows included. Everybody else sees only
// rows that name a domain they own: a NULL domain_id is the panel's own
// business and there is no ownership chain to narrow it by.
func visibility(r *http.Request) (string, []any) {
	cond, args, unrestricted := middleware.ScopeCondition(r, "d")
	if unrestricted {
		return "1 = 1", nil
	}
	return "n.domain_id IS NOT NULL AND " + cond, args
}

// reader is the signed-in user id, which is what a read is recorded against.
func reader(r *http.Request) (int64, bool) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		return 0, false
	}
	return c.UserID, true
}

// List answers GET /notifications.
//
// It carries the unread count beside the rows, because the bell draws a badge
// and a second round trip for one integer is a request per poll per open tab.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := reader(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	cond, args := visibility(r)

	// The reader's own read state is resolved by the JOIN, so two people looking
	// at the same notification see their own answer.
	// #nosec G202 G701 -- cond comes from visibility(), which is either the literal "1 = 1" or a literal prefix plus a middleware.ScopeCondition fragment built from literals and the literal alias "d"; no request text reaches the statement and every value is bound.
	query := `SELECT n.id, n.level, n.category, n.title, n.message, n.domain_id,
	                 COALESCE(d.domain_name, ''), n.ref_type, n.ref_id,
	                 (nr.user_id IS NOT NULL),
	                 DATE_FORMAT(n.created_at, '%Y-%m-%d %H:%i:%s')
	            FROM notifications n
	            LEFT JOIN domains d ON d.id = n.domain_id
	            LEFT JOIN notification_reads nr
	                   ON nr.notification_id = n.id AND nr.user_id = ?
	           WHERE ` + cond + ` ORDER BY n.id DESC LIMIT ` + strconv.Itoa(maxRows)

	// #nosec G202 G701 -- see the annotation on the query above.
	rows, err := h.DB.QueryContext(r.Context(), query, append([]any{userID}, args...)...)
	if err != nil {
		log.Printf("notifications: the list could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the notifications could not be read")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []Notification{}
	for rows.Next() {
		var item Notification
		var domainID sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Level, &item.Category, &item.Title, &item.Message,
			&domainID, &item.Domain, &item.RefType, &item.RefID, &item.Read, &item.CreatedAt); err != nil {
			log.Printf("notifications: a row could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the notifications could not be read")
			return
		}
		if domainID.Valid {
			value := domainID.Int64
			item.DomainID = &value
		}
		out = append(out, item)
	}
	// A query that broke half way would otherwise answer 200 with a short list,
	// and "fewer alerts than expected" is exactly the reading this exists to
	// prevent.
	if err := rows.Err(); err != nil {
		log.Printf("notifications: the list ended early: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the notifications could not be read")
		return
	}

	unread, err := h.unreadCount(r.Context(), userID, cond, args)
	if err != nil {
		// A failed count rendered as zero is a badge saying there is nothing to
		// look at, which is the one answer this must never invent.
		log.Printf("notifications: the unread count could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the notifications could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"notifications": out, "unread": unread})
}

func (h *Handlers) unreadCount(ctx context.Context, userID int64, cond string, args []any) (int, error) {
	// #nosec G202 G701 -- cond comes from visibility(); it carries no request text and every value is bound.
	query := `SELECT COUNT(*) FROM notifications n
	            LEFT JOIN domains d ON d.id = n.domain_id
	            LEFT JOIN notification_reads nr
	                   ON nr.notification_id = n.id AND nr.user_id = ?
	           WHERE ` + cond + ` AND nr.user_id IS NULL`
	var unread int
	// #nosec G202 G701 -- see the annotation on the query above.
	err := h.DB.QueryRowContext(ctx, query, append([]any{userID}, args...)...).Scan(&unread)
	return unread, err
}

// MarkRead answers POST /notifications/{id}/read and POST /notifications/read-all.
//
// Both go through ONE statement whose SELECT carries the same visibility test as
// the list, so "mark everything read" can only reach rows this request can
// actually see. There is no read-modify-write, so two tabs marking the same row
// cannot race, and INSERT IGNORE makes a repeated call a no-op rather than an
// error the screen has to explain.
func (h *Handlers) MarkRead(w http.ResponseWriter, r *http.Request) {
	userID, ok := reader(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	cond, args := visibility(r)

	params := append([]any{userID}, args...)
	single := ""
	if raw := chi.URLParam(r, "id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid notification id")
			return
		}
		single = " AND n.id = ?"
		params = append(params, id)
	}

	// #nosec G202 G701 -- cond comes from visibility() and `single` is one of two literals; the notification id is bound through params, never interpolated.
	statement := `INSERT IGNORE INTO notification_reads (notification_id, user_id)
	              SELECT n.id, ? FROM notifications n
	              LEFT JOIN domains d ON d.id = n.domain_id
	              WHERE ` + cond + single
	// #nosec G202 G701 -- see the annotation on the statement above.
	result, err := h.DB.ExecContext(r.Context(), statement, params...)
	if err != nil {
		log.Printf("notifications: a read could not be recorded: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the notification could not be marked read")
		return
	}
	marked, err := result.RowsAffected()
	if err != nil {
		log.Printf("notifications: the affected count could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the notification could not be marked read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "marked": marked})
}

// StartPrune removes notifications past the retention window once a day.
//
// The read rows go with them through the foreign key. A first pass runs at
// startup so an installation that is restarted more often than it is left
// running still prunes.
func StartPrune(ctx context.Context, db *sql.DB) {
	go func() {
		prune(ctx, db)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune(ctx, db)
			}
		}
	}()
}

func prune(ctx context.Context, db *sql.DB) {
	// The cutoff is computed by the DATABASE clock. The driver writes a Go
	// time.Time as UTC while the server answers in the session timezone, so a
	// Go-side timestamp on one side of the comparison is wrong by the offset
	// between them.
	days := int(retention / (24 * time.Hour))
	if _, err := db.ExecContext(ctx,
		`DELETE FROM notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`, days); err != nil {
		log.Printf("notifications: the retention pass failed: %v", err)
	}
}

// truncate cuts to n RUNES, never bytes. The column is utf8mb4 and a byte cut
// through a multi-byte rune stores text the database has to reject or mangle.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
