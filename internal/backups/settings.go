// System-wide backup settings: the master switch, the disk guard, and ONE
// off-site destination every domain's backup is copied to.
//
// backup_destinations is per domain, so none of these could be expressed before:
// there was no way to turn every automatic backup off at once, no free-space
// check before writing (backups could fill the root disk and take the panel and
// every site down), and no single off-site destination with an option to delete
// the local copy once the off-site copy is verified.
package backups

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"servika/internal/netguard"
	"servika/internal/notifications"
	"servika/internal/secret"
)

// dateStamp matches the "-YYYYMMDD-HHMMSS" stamp in a backup file name.
var dateStamp = regexp.MustCompile(`-(\d{8})-\d{6}`)

// movedOffSiteMark is appended to a backup's notes when its local copy was
// deleted after a verified off-site upload, so the list still shows the operator
// what they have and the fetch path knows where to look.
const movedOffSiteMark = "[moved off-site]"

// BackupSettings is the backup_settings singleton row (id=1).
type BackupSettings struct {
	Enabled        bool   `json:"enabled"`
	MinFreeGB      int    `json:"min_free_gb"`
	MaxStoreGB     int    `json:"max_store_gb"` // 0 = unlimited
	RemoteEnabled  bool   `json:"remote_enabled"`
	RemoteType     string `json:"remote_type"`
	RemoteHost     string `json:"remote_host"`
	RemotePort     int    `json:"remote_port"`
	RemoteUsername string `json:"remote_username"`
	RemotePassword string `json:"remote_password,omitempty"` // write-only: GET returns empty
	RemoteDir      string `json:"remote_dir"`
	RemoteHostKey  string `json:"-"` // pinned SFTP host key; never leaves the server
	DeleteLocal    bool   `json:"delete_local"`
	LastUpload     string `json:"last_upload,omitempty"`
	LastStatus     string `json:"last_status,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	// Read-only live measurements for the UI.
	FreeGB  float64 `json:"free_gb"`
	StoreGB float64 `json:"store_gb"`
}

// defaultBackupSettings is what a host with no row yet behaves as: automatic
// backups on, a 10 GB free-space floor, no off-site destination.
func defaultBackupSettings() *BackupSettings {
	return &BackupSettings{Enabled: true, MinFreeGB: 10, RemoteType: "sftp", RemotePort: 22, RemoteDir: "/"}
}

// readBackupSettings returns the singleton row. A missing table or row is NOT an
// error: on an installation where the migration has not run yet the scheduler
// must keep working, so it falls back to the safe default.
func readBackupSettings(ctx context.Context, db *sql.DB) *BackupSettings {
	s := defaultBackupSettings()
	var enabled, remoteEnabled, deleteLocal int
	var lastUpload sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT enabled, min_free_gb, max_store_gb, remote_enabled, remote_type, remote_host,
		        remote_port, remote_username, remote_password, remote_dir, remote_host_key, delete_local,
		        DATE_FORMAT(last_upload,'%Y-%m-%d %H:%i'), last_status, last_error
		 FROM backup_settings WHERE id=1`).
		Scan(&enabled, &s.MinFreeGB, &s.MaxStoreGB, &remoteEnabled, &s.RemoteType, &s.RemoteHost,
			&s.RemotePort, &s.RemoteUsername, &s.RemotePassword, &s.RemoteDir, &s.RemoteHostKey, &deleteLocal,
			&lastUpload, &s.LastStatus, &s.LastError)
	if err != nil {
		return defaultBackupSettings()
	}
	s.Enabled = enabled == 1
	s.RemoteEnabled = remoteEnabled == 1
	s.DeleteLocal = deleteLocal == 1
	s.LastUpload = lastUpload.String
	// The stored password is encrypted at rest; decrypt so runtime consumers
	// receive the usable plaintext. A legacy plaintext value passes through, and an
	// empty password is left as-is without touching the cipher.
	if s.RemotePassword != "" {
		if pw, e := secret.Decrypt(s.RemotePassword); e == nil {
			s.RemotePassword = pw
		}
	}
	return s
}

// writeBackupSettings updates the singleton row. An empty RemotePassword PRESERVES
// the stored one, because the field is write-only and the UI never reads it back,
// so a save must not blank it.
func writeBackupSettings(ctx context.Context, db *sql.DB, s *BackupSettings) error {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	if _, err := db.ExecContext(ctx, `INSERT IGNORE INTO backup_settings (id) VALUES (1)`); err != nil {
		return err
	}
	if s.RemotePassword == "" {
		_, err := db.ExecContext(ctx,
			`UPDATE backup_settings SET enabled=?, min_free_gb=?, max_store_gb=?, remote_enabled=?,
			 remote_type=?, remote_host=?, remote_port=?, remote_username=?, remote_dir=?, delete_local=?
			 WHERE id=1`,
			b(s.Enabled), s.MinFreeGB, s.MaxStoreGB, b(s.RemoteEnabled),
			s.RemoteType, s.RemoteHost, s.RemotePort, s.RemoteUsername, s.RemoteDir, b(s.DeleteLocal))
		return err
	}
	enc, err := secret.Encrypt(s.RemotePassword)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`UPDATE backup_settings SET enabled=?, min_free_gb=?, max_store_gb=?, remote_enabled=?,
		 remote_type=?, remote_host=?, remote_port=?, remote_username=?, remote_password=?, remote_dir=?,
		 delete_local=? WHERE id=1`,
		b(s.Enabled), s.MinFreeGB, s.MaxStoreGB, b(s.RemoteEnabled),
		s.RemoteType, s.RemoteHost, s.RemotePort, s.RemoteUsername, enc, s.RemoteDir, b(s.DeleteLocal))
	return err
}

// destination converts the system-wide settings into a per-domain Destination
// so the existing lftp/S3-free upload, download, size-check and connection-test
// code is reused unchanged. DomainID stays 0, which marks it as the singleton.
func (s *BackupSettings) destination() *Destination {
	return &Destination{
		Type: s.RemoteType, Host: s.RemoteHost, Port: s.RemotePort,
		Username: s.RemoteUsername, Password: s.RemotePassword,
		RemoteDir: s.RemoteDir, HostKey: s.RemoteHostKey, Enabled: s.RemoteEnabled,
	}
}

// ensureGlobalHostKey pins the SFTP host key of the system-wide destination on
// first use and stores it in the singleton row, because that row has no
// per-domain Destination to carry it. ensureHostKey does not persist a key for a
// DomainID of 0, so the singleton needs its own trust-on-first-use.
func ensureGlobalHostKey(ctx context.Context, db *sql.DB, s *BackupSettings) error {
	if s.RemoteType != "sftp" || strings.TrimSpace(s.RemoteHostKey) != "" {
		return nil
	}
	if err := netguard.CheckHost(s.RemoteHost); err != nil {
		return fmt.Errorf("destination host not permitted: %w", err)
	}
	key, err := scanHostKey(ctx, s.RemoteHost, s.RemotePort)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE backup_settings SET remote_host_key=? WHERE id=1 AND remote_host_key=''`, key); err != nil {
		return fmt.Errorf("the host key could not be stored: %w", err)
	}
	s.RemoteHostKey = key
	return nil
}

// diskFreeGB returns the writable free space (GB) on the filesystem holding path.
// Bavail excludes the blocks reserved for root, so it is what a non-root writer
// actually has.
func diskFreeGB(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1024 * 1024 * 1024), nil
}

// storeUsageGB returns the total size (GB) of everything under the backup root.
func storeUsageGB() float64 {
	var total int64
	// #nosec G703 -- backupRoot() is a fixed, config-derived server path, not tenant input.
	_ = filepath.Walk(backupRoot(), func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // an unreadable directory must not stop the walk
		}
		if fi != nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return float64(total) / (1024 * 1024 * 1024)
}

// diskGate is called BEFORE a backup is written. It returns "" when writing is
// allowed, or the reason it is refused.
func diskGate(s *BackupSettings) string {
	if s.MinFreeGB > 0 {
		if free, err := diskFreeGB(backupRoot()); err == nil && free < float64(s.MinFreeGB) {
			return fmt.Sprintf("free space %.1f GB < threshold %d GB", free, s.MinFreeGB)
		}
	}
	if s.MaxStoreGB > 0 {
		if used := storeUsageGB(); used > float64(s.MaxStoreGB) {
			return fmt.Sprintf("backup store %.1f GB > ceiling %d GB", used, s.MaxStoreGB)
		}
	}
	return ""
}

// diskGateTitle is the stable English title the daily-once dedup keys on.
const diskGateTitle = "Backups stopped: disk guard"

// notifyDiskGate writes one panel-wide critical notification per day for the same
// cause, so an hourly scheduler that keeps hitting a full disk does not flood the
// bell. The alert is panel-wide (no domain), so admins alone see it.
func notifyDiskGate(db *sql.DB, reason string) {
	var n int
	_ = db.QueryRow(
		`SELECT COUNT(*) FROM notifications
		 WHERE category=? AND title=? AND created_at > NOW()-INTERVAL 1 DAY`,
		backupNotifyCategory, diskGateTitle).Scan(&n)
	if n > 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	event := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: backupNotifyCategory,
		Title:    diskGateTitle,
		Message:  "Automatic backups were skipped by the disk guard (" + reason + "). Clean up old backups, lower retention, or set an off-site destination and enable delete-local.",
		Key:      "backup.diskGate",
		Params:   map[string]any{"reason": reason},
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		// #nosec G706 -- logged value is a template-derived reason; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup disk guard: alert could not be written: %v", err)
	}
	// #nosec G706 -- logged value is a template-derived reason; no raw tenant string with CR/LF reaches the log.
	log.Printf("backup disk guard: %s", reason)
}

// remoteDateDir derives a UTC date folder from the backup file name's stamp, so
// every tenant's backups do not pile into one directory. A name whose stamp
// cannot be read returns "", and the file goes to the base directory.
//
//	"c_site-20260826-233538.tar.gz" -> "2026-08-26"
func remoteDateDir(fileName string) string {
	m := dateStamp.FindStringSubmatch(fileName)
	if len(m) != 2 {
		return ""
	}
	d := m[1] // YYYYMMDD
	return d[0:4] + "-" + d[4:6] + "-" + d[6:8]
}

// joinRemotePath joins a base remote directory with a subdirectory, returning the
// base alone when the subdirectory is empty.
func joinRemotePath(base, sub string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "/"
	}
	if sub == "" {
		return base
	}
	if base == "/" {
		return "/" + sub
	}
	return base + "/" + sub
}

// markGlobalStatus records the last off-site result on the singleton row.
func markGlobalStatus(db *sql.DB, status, errText string) {
	_, _ = db.Exec(`UPDATE backup_settings SET last_status=?, last_error=?, last_upload=NOW() WHERE id=1`,
		status, errText)
}

// pushGlobalAsync uploads a backup to the SYSTEM-WIDE destination, independent of
// the domain's own destination, and deletes the local copy afterwards when
// delete-local is on and the off-site copy is verified.
//
// The remote path carries a date subdirectory. The upload is verified against
// the local size (remoteSize), and the local copy is deleted ONLY when that
// check passes, so a truncated off-site copy can never take the last copy with
// it. A failure keeps the local copy and writes a domain-scoped critical alert,
// because the last_status field is one row that parallel uploads overwrite.
func pushGlobalAsync(db *sql.DB, domainID, backupID int64, localPath, fileName string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		s := readBackupSettings(ctx, db)
		if !s.RemoteEnabled || strings.TrimSpace(s.RemoteHost) == "" {
			return
		}
		if err := ensureGlobalHostKey(ctx, db, s); err != nil {
			short := truncateError(err.Error())
			markGlobalStatus(db, "failed", short)
			notifyUploadFailed(ctx, db, domainID, backupID, short)
			return
		}
		d := s.destination()
		d.RemoteDir = joinRemotePath(s.RemoteDir, remoteDateDir(fileName))
		if err := uploadToRemote(ctx, db, d, localPath, fileName); err != nil {
			short := truncateError(err.Error())
			markGlobalStatus(db, "failed", short)
			notifyUploadFailed(ctx, db, domainID, backupID, short)
			// #nosec G706 -- logged values are integer IDs and error output; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup global upload domain=%d: %v", domainID, err)
			return
		}
		localSize := int64(-1)
		// #nosec G703 -- localPath is an internal backup archive path under BackupRoot derived from a validSystemUser-checked identifier.
		if fi, e := os.Stat(localPath); e == nil {
			localSize = fi.Size()
		}
		rs := remoteSize(ctx, db, d, fileName)
		if localSize > 0 && rs > 0 && rs != localSize {
			msg := fmt.Sprintf("remote size mismatch (local=%d remote=%d): the upload was incomplete", localSize, rs)
			markGlobalStatus(db, "failed", msg)
			notifyUploadFailed(ctx, db, domainID, backupID, msg)
			// #nosec G706 -- logged values are integer IDs and a template-derived size message; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup global upload domain=%d: %s", domainID, msg)
			return
		}
		markGlobalStatus(db, "successful", "")
		// Delete the local copy only when it is verified off-site (rs > 0). The DB
		// row stays, so the operator still sees which backup they have.
		if s.DeleteLocal && backupID > 0 && rs > 0 {
			// #nosec G703 -- localPath is an internal backup archive path under BackupRoot derived from a validSystemUser-checked identifier.
			if err := os.Remove(localPath); err == nil {
				_, _ = db.Exec(`UPDATE backups SET notes=CONCAT(notes,' `+movedOffSiteMark+`') WHERE id=?`, backupID)
				// #nosec G706 -- logged values are template-derived names; no raw tenant string with CR/LF reaches the log.
				log.Printf("backup global: %s moved off-site, local copy removed", fileName)
			}
		}
	}()
}

// truncateError bounds an error string stored in a VARCHAR(512) column.
func truncateError(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

// fetchGlobalRemote downloads a backup from the SYSTEM-WIDE destination into
// localPath. It looks in the date subdirectory first, then the base directory,
// so a backup uploaded before the date-directory layout existed is still found.
func fetchGlobalRemote(ctx context.Context, db *sql.DB, s *BackupSettings, fileName, localPath string) error {
	if err := ensureGlobalHostKey(ctx, db, s); err != nil {
		return err
	}
	dirs := []string{joinRemotePath(s.RemoteDir, remoteDateDir(fileName))}
	if base := joinRemotePath(s.RemoteDir, ""); base != dirs[0] {
		dirs = append(dirs, base)
	}
	var last error
	for _, dir := range dirs {
		d := s.destination()
		d.RemoteDir = dir
		if err := downloadFromRemote(ctx, db, d, fileName, localPath); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last == nil {
		last = fmt.Errorf("the backup could not be fetched from the off-site destination")
	}
	return last
}
