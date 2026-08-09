package slowquery

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Stable reason codes. The API is English and the panel renders twelve
// languages, so a screen maps the CODE to a sentence rather than showing the
// message.
const (
	reasonThresholdInvalid = "slow_log_threshold_invalid"
	reasonApplyFailed      = "slow_log_apply_failed"
)

// Handlers serves the slow query surface.
type Handlers struct {
	DB *sql.DB
}

// Row is one aggregated shape as a screen reads it.
type Row struct {
	DomainID     *int64 `json:"domain_id,omitempty"`
	DomainName   string `json:"domain_name,omitempty"`
	DBUser       string `json:"db_user"`
	Schema       string `json:"schema_name"`
	Digest       string `json:"digest"`
	SQL          string `json:"normalized_sql"`
	Calls        int64  `json:"calls"`
	TotalMS      int64  `json:"total_time_ms"`
	AvgMS        int64  `json:"avg_time_ms"`
	MaxMS        int64  `json:"max_time_ms"`
	LockMS       int64  `json:"lock_time_ms"`
	RowsSent     int64  `json:"rows_sent"`
	RowsExamined int64  `json:"rows_examined"`
	FullScans    int64  `json:"full_scan_calls"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
}

// Status describes the feature itself, so a screen can say why a table is empty
// instead of showing nothing and implying the server is healthy.
type Status struct {
	Enabled     bool    `json:"enabled"`
	Seconds     float64 `json:"seconds"`
	LogPath     string  `json:"log_path"`
	LogSizeKB   int64   `json:"log_size_kb"`
	LogPresent  bool    `json:"log_present"`
	CollectedAt string  `json:"collected_at,omitempty"`
	LastError   string  `json:"last_error,omitempty"`
	MinSeconds  float64 `json:"min_seconds"`
	MaxSeconds  float64 `json:"max_seconds"`
	Retention   int     `json:"retention_days"`
}

// The window a screen may ask for. A day is the default because that is the
// question support actually asks; a week is the ceiling because the rows are
// hourly and a longer window is a report, not a screen.
const (
	defaultHours = 24
	maxHours     = 24 * 7
	defaultLimit = 50
	maxLimit     = 200
)

// List answers the server-wide view. Admin only: it names every tenant.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.query(r.Context(), 0, hoursParam(r), limitParam(r))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the slow query statistics")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
}

// ListForDomain answers one domain's view. Mounted under CustomerScope, so the
// caller already owns the domain; the query is narrowed by domain_id anyway,
// because a row-by-row check cannot secure a list.
func (h *Handlers) ListForDomain(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	rows, err := h.query(r.Context(), domainID, hoursParam(r), limitParam(r))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the slow query statistics")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
}

// query reads the aggregated rows. domainID 0 means the whole server.
//
// The ordering is by TOTAL time rather than by the longest single execution:
// what costs a shared server is the shape that spends the most time in total,
// which is usually a short query running constantly rather than one slow one.
func (h *Handlers) query(ctx context.Context, domainID int64, hours, limit int) ([]Row, error) {
	statement := "SELECT s.domain_id, COALESCE(d.domain_name,''), s.db_user, s.schema_name," +
		" s.digest, s.normalized_sql," +
		" SUM(s.calls), SUM(s.total_time_ms), MAX(s.max_time_ms), SUM(s.lock_time_ms)," +
		" SUM(s.rows_sent), SUM(s.rows_examined), SUM(s.full_scan_calls)," +
		" MIN(s.bucket_hour), MAX(s.bucket_hour)" +
		" FROM slow_query_stats s" +
		" LEFT JOIN domains d ON d.id = s.domain_id" +
		" WHERE s.bucket_hour >= NOW() - INTERVAL ? HOUR"
	args := []any{hours}
	if domainID > 0 {
		statement += " AND s.domain_id = ?"
		args = append(args, domainID)
	}
	statement += " GROUP BY s.domain_id, s.db_user, s.schema_name, s.digest, s.normalized_sql, d.domain_name" +
		" ORDER BY SUM(s.total_time_ms) DESC LIMIT ?"
	args = append(args, limit)

	result, err := h.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = result.Close() }()

	rows := []Row{}
	for result.Next() {
		var row Row
		var owner sql.NullInt64
		var first, last sql.NullString
		if err := result.Scan(&owner, &row.DomainName, &row.DBUser, &row.Schema,
			&row.Digest, &row.SQL, &row.Calls, &row.TotalMS, &row.MaxMS, &row.LockMS,
			&row.RowsSent, &row.RowsExamined, &row.FullScans, &first, &last); err != nil {
			return nil, err
		}
		if owner.Valid {
			value := owner.Int64
			row.DomainID = &value
		}
		if row.Calls > 0 {
			row.AvgMS = row.TotalMS / row.Calls
		}
		row.FirstSeen = first.String
		row.LastSeen = last.String
		rows = append(rows, row)
	}
	return rows, result.Err()
}

// Status answers what the feature itself is doing.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	status := Status{
		LogPath:    config.MariaDBSlowLog(),
		MinSeconds: minThresholdSeconds,
		MaxSeconds: maxThresholdSeconds,
		Retention:  retentionDays,
	}
	var seconds sql.NullFloat64
	var enabled int
	var collectedAt sql.NullString
	var lastError sql.NullString
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(slow_query_enabled,0), slow_query_seconds,
		        DATE_FORMAT(slow_query_collected_at, '%Y-%m-%d %H:%i:%s'),
		        COALESCE(slow_query_last_error,'')
		   FROM panel_settings WHERE id=1`).Scan(&enabled, &seconds, &collectedAt, &lastError)
	if err != nil && err != sql.ErrNoRows {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the slow query settings")
		return
	}
	status.Enabled = enabled == 1
	status.Seconds = defaultThresholdSeconds
	if seconds.Valid {
		status.Seconds = seconds.Float64
	}
	status.CollectedAt = collectedAt.String
	status.LastError = lastError.String

	if info, statErr := os.Stat(status.LogPath); statErr == nil {
		status.LogPresent = true
		status.LogSizeKB = info.Size() / 1024
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

type settingsRequest struct {
	Enabled *bool    `json:"enabled"`
	Seconds *float64 `json:"seconds"`
}

// Save stores the switch and the threshold and applies them to MariaDB.
//
// The threshold is validated HERE, on the write path, not only where the screen
// draws the field: the value is rendered into MariaDB's own configuration file,
// and a file MariaDB refuses stops it from starting on the next restart.
func (h *Handlers) Save(w http.ResponseWriter, r *http.Request) {
	var request settingsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	enabled, seconds, err := h.currentSetting(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the slow query settings")
		return
	}
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	if request.Seconds != nil {
		if !ValidThreshold(*request.Seconds) {
			writeReason(w, http.StatusBadRequest,
				"the threshold must be between 0.1 and 60 seconds", reasonThresholdInvalid)
			return
		}
		seconds = *request.Seconds
	}

	// MariaDB first. Storing a setting the server refused would leave the screen
	// reporting a threshold nothing is enforcing.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Apply(ctx, enabled, seconds); err != nil {
		writeReason(w, http.StatusInternalServerError,
			"MariaDB did not accept the slow query settings", reasonApplyFailed)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET slow_query_enabled=?, slow_query_seconds=? WHERE id=1`,
		boolToInt(enabled), seconds); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the slow query settings")
		return
	}
	h.Status(w, r)
}

func (h *Handlers) currentSetting(ctx context.Context) (bool, float64, error) {
	var enabled int
	var seconds float64
	err := h.DB.QueryRowContext(ctx,
		`SELECT COALESCE(slow_query_enabled,0), COALESCE(slow_query_seconds,?)
		   FROM panel_settings WHERE id=1`, defaultThresholdSeconds).Scan(&enabled, &seconds)
	if err == sql.ErrNoRows {
		return false, defaultThresholdSeconds, nil
	}
	if err != nil {
		return false, defaultThresholdSeconds, err
	}
	return enabled == 1, seconds, nil
}

// writeReason answers with the panel's error shape plus a stable reason CODE.
func writeReason(w http.ResponseWriter, status int, message, reason string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func hoursParam(r *http.Request) int {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 {
		return defaultHours
	}
	return min(hours, maxHours)
}

func limitParam(r *http.Request) int {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		return defaultLimit
	}
	return min(limit, maxLimit)
}
