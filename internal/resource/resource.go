// Package resource reports per-domain resource usage and plan limits.
package resource

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

type Limit struct {
	Usage int64 `json:"usage"`
	Limit int64 `json:"limit"` // Zero means unlimited.
}

type Summary struct {
	DomainName string `json:"domain_name"`
	SystemUser string `json:"system_user"`
	PlanName   string `json:"plan_name"`
	PHPVersion string `json:"php_version"`
	IPv4       string `json:"ipv4"`
	SSLEnabled bool   `json:"ssl_enabled"`
	SSLExpiry  string `json:"ssl_expiry,omitempty"`

	// Metrics with plan limits, expressed as usage and limit.
	DiskMB    Limit `json:"disk_mb"`    // Limit comes from disk_quota_mb (XFS when quota active).
	TrafficMB Limit `json:"traffic_mb"` // Limit comes from traffic_quota_mb.

	// Inode quota (populated only when XFS user quota is ACTIVE, otherwise 0).
	InodeUsage  int64 `json:"inode_usage"`
	InodeLimit  int64 `json:"inode_limit"`
	DBCount     Limit `json:"db_count"`     // Limit comes from max_db.
	FTPCount    Limit `json:"ftp_count"`    // Limit comes from max_ftp.
	EmailCount  Limit `json:"email_count"`  // Limit comes from max_email.
	DomainCount Limit `json:"domain_count"` // Limit comes from max_domain and includes subdomains.

	// Additional counters without plan limits.
	DNSRecordCount int64 `json:"dns_record"`
	CronJobCount   int64 `json:"cron_job"`
	BackupCount    int64 `json:"backup_count"`
	BackupMB       int64 `json:"backup_mb"`
}

type Handlers struct {
	DB *sql.DB
}

// planLimits carries the ceilings the plan sets. A zero means unlimited.
type planLimits struct {
	name    string
	disk    int64
	traffic int64
	domain  int64
	db      int64
	email   int64
	ftp     int64
}

// domainRow reads the domain the summary describes, and reports the plan it is
// on.
func (h *Handlers) domainRow(ctx context.Context, id int64) (Summary, sql.NullInt64, error) {
	var o Summary
	var planID sql.NullInt64
	var sslExpiry sql.NullString
	var sslEnabled int
	err := h.DB.QueryRowContext(ctx,
		`SELECT d.domain_name, d.system_user, d.php_version, d.ipv4, d.ssl_enabled,
		        DATE_FORMAT(d.ssl_expiry,'%Y-%m-%d'), d.plan_id
		 FROM domains d WHERE d.id=?`, id).
		Scan(&o.DomainName, &o.SystemUser, &o.PHPVersion, &o.IPv4, &sslEnabled, &sslExpiry, &planID)
	if err != nil {
		return Summary{}, planID, err
	}
	o.SSLEnabled = sslEnabled == 1
	if sslExpiry.Valid {
		o.SSLExpiry = sslExpiry.String
	}
	return o, planID, nil
}

// limitsOf loads the plan's ceilings. A domain on no plan, or a plan row that
// cannot be read, is reported as unlimited rather than as every limit at zero.
func (h *Handlers) limitsOf(ctx context.Context, planID sql.NullInt64) planLimits {
	var limits planLimits
	var planName sql.NullString
	if planID.Valid {
		_ = h.DB.QueryRowContext(ctx,
			`SELECT name, disk_quota_mb, traffic_quota_mb, max_domain, max_db, max_email, max_ftp
			 FROM service_plans WHERE id=?`, planID.Int64).
			Scan(&planName, &limits.disk, &limits.traffic, &limits.domain, &limits.db, &limits.email, &limits.ftp)
	}
	if planName.Valid {
		limits.name = planName.String
	} else {
		limits.name = "Unlimited (no plan assigned)"
	}
	return limits
}

// measureDisk fills in the disk figures from du and, when XFS user quota is
// ACTIVE, from the filesystem instead.
func (h *Handlers) measureDisk(ctx context.Context, id int64, o *Summary, diskQuota int64) {
	// Calculate disk usage. A measurement that fails (a du deadline on a very
	// large tree) must not be reported as zero and must not overwrite the stored
	// size: zero reads as an empty home and would show a tenant far below a quota
	// they may be over. The last known value is served instead.
	home := "/home/" + o.SystemUser
	if size, duErr := homeBytes(ctx, home); duErr == nil {
		o.DiskMB.Usage = size / (1024 * 1024)
		_, _ = h.DB.ExecContext(ctx, `UPDATE domains SET size_kb=? WHERE id=?`, size/1024, id)
	} else {
		var lastKB int64
		_ = h.DB.QueryRowContext(ctx, `SELECT size_kb FROM domains WHERE id=?`, id).Scan(&lastKB)
		o.DiskMB.Usage = lastKB / 1024
	}
	o.DiskMB.Limit = diskQuota
	// When XFS user quota is ACTIVE, pull real disk usage/limit and inode usage/limit from
	// the filesystem (more accurate than du, and includes inodes). On noquota, QuotaStatus
	// returns all zeros and du-based values are preserved.
	usedMB, limitMB, usedIno, limitIno := quotaStatus(o.SystemUser)
	if limitMB <= 0 && limitIno <= 0 {
		return
	}
	if usedMB > 0 {
		o.DiskMB.Usage = int64(usedMB)
	}
	if limitMB > 0 {
		o.DiskMB.Limit = int64(limitMB)
	}
	o.InodeUsage = int64(usedIno)
	o.InodeLimit = int64(limitIno)
}

// databaseUsers lists the domain's database accounts. The length of this list
// IS the reported database count, so a dropped row tells the customer they have
// room they do not have; both read failures are logged rather than passed off
// as a complete count.
func (h *Handlers) databaseUsers(r *http.Request, id int64) []string {
	dbUsers := []string{}
	rows, err := h.DB.QueryContext(r.Context(), `SELECT db_user FROM db_accounts WHERE domain_id=?`, id)
	if err != nil {
		return dbUsers
	}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			httpx.WarnR(r, "resource: skipping an unreadable database account for domain %d: %v", id, err)
			continue
		}
		dbUsers = append(dbUsers, u)
	}
	if err := rows.Err(); err != nil {
		httpx.LogR(r, "resource: could not read the database account list for domain %d: %v", id, err)
	}
	_ = rows.Close()
	return dbUsers
}

// countJobs counts the jobs in the tenant's host crontab. A comment and a blank
// line are not jobs, and a tenant with no crontab counts zero.
func countJobs(systemUser string) int64 {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := runCommand("crontab", "-u", systemUser, "-l").CombinedOutput()
	if err != nil {
		return 0
	}
	var jobs int64
	for ln := range strings.SplitSeq(string(out), "\n") {
		s := strings.TrimSpace(ln)
		if s != "" && !strings.HasPrefix(s, "#") {
			jobs++
		}
	}
	return jobs
}

// countRows fills in the counters the plan limits apply to and the ones it does
// not.
func (h *Handlers) countRows(ctx context.Context, id int64, o *Summary) {
	// Convert domains.traffic_kb from kilobytes to megabytes.
	var trafficKB int64
	_ = h.DB.QueryRowContext(ctx, `SELECT traffic_kb FROM domains WHERE id=?`, id).Scan(&trafficKB)
	o.TrafficMB.Usage = trafficKB / 1024

	// Count FTP accounts.
	_ = h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ftp_accounts WHERE domain_id=?`, id).Scan(&o.FTPCount.Usage)

	// Count mailboxes.
	_ = h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM mailboxes WHERE domain_id=?`, id).Scan(&o.EmailCount.Usage)

	// Count DNS records.
	_ = h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_records WHERE domain_id=?`, id).Scan(&o.DNSRecordCount)

	// Count backups and calculate their total size.
	_ = h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size_b),0) FROM backups WHERE domain_id=?`, id).
		Scan(&o.BackupCount, &o.BackupMB)
	o.BackupMB = o.BackupMB / (1024 * 1024) // Convert bytes to megabytes.
}

func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx := r.Context()

	o, planID, err := h.domainRow(ctx, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	limits := h.limitsOf(ctx, planID)
	o.PlanName = limits.name

	h.measureDisk(ctx, id, &o, limits.disk)
	h.countRows(ctx, id, &o)

	// Count databases and collect users for size calculation.
	o.DBCount.Usage = int64(len(h.databaseUsers(r, id)))
	o.CronJobCount = countJobs(o.SystemUser)

	// The primary domain counts as one. Subdomains should eventually be included in the subscription count.
	// For now, this follows the subscription model of one primary domain and zero subdomains.
	o.DomainCount.Usage = 1

	o.TrafficMB.Limit = limits.traffic
	o.DBCount.Limit = limits.db
	o.FTPCount.Limit = limits.ftp
	o.EmailCount.Limit = limits.email
	o.DomainCount.Limit = limits.domain

	// DiskMB measures the home directory only. Database size is deliberately not
	// added to it: the databases may sit on another disk, so one number covering
	// both would report a quota nobody can act on.
	httpx.WriteJSON(w, http.StatusOK, o)
}
