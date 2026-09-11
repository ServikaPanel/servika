package mail

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"servika/internal/httpx"
)

const rspamdSettingsPath = "/etc/rspamd/local.d/settings.conf"

var rspamdApplyMu sync.Mutex

type SpamSettings struct {
	Enabled        bool    `json:"enabled"`
	GreylistScore  float64 `json:"greylist_score"`
	AddHeaderScore float64 `json:"add_header_score"`
	RejectScore    float64 `json:"reject_score"`
}

func defaultSpamSettings() SpamSettings {
	return SpamSettings{Enabled: true, GreylistScore: 4, AddHeaderScore: 6, RejectScore: 15}
}

// SpamGet returns the domain's spam policy. GET /domains/{id}/mail/spam
func (h *Handlers) SpamGet(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	s, found, err := readSpamSettings(r.Context(), h.DB, id)
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("read spam settings domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read spam settings")
		return
	}
	if !found {
		s = defaultSpamSettings()
	}
	_, rspamdErr := exec.LookPath("rspamadm")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"settings": s,
		"rspamd":   rspamdErr == nil,
	})
}

// SpamPut saves and applies the domain's spam policy. PUT /domains/{id}/mail/spam
func (h *Handlers) SpamPut(w http.ResponseWriter, r *http.Request) {
	id, _, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "mail is unavailable for demo subscriptions")
		return
	}
	var req SpamSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateSpamSettings(req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	old, oldFound, err := readSpamSettings(r.Context(), h.DB, id)
	if err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("read spam settings domain=%d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read spam settings")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO mail_spam_settings(domain_id, enabled, greylist_score, add_header_score, reject_score)
		 VALUES(?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), greylist_score=VALUES(greylist_score),
		   add_header_score=VALUES(add_header_score), reject_score=VALUES(reject_score)`,
		id, req.Enabled, req.GreylistScore, req.AddHeaderScore, req.RejectScore); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save spam settings")
		return
	}
	if err := ApplyRspamdSettings(h.DB); err != nil {
		if oldFound {
			_, _ = h.DB.Exec(`UPDATE mail_spam_settings SET enabled=?, greylist_score=?,
				add_header_score=?, reject_score=? WHERE domain_id=?`,
				old.Enabled, old.GreylistScore, old.AddHeaderScore, old.RejectScore, id)
		} else {
			_, _ = h.DB.Exec(`DELETE FROM mail_spam_settings WHERE domain_id=?`, id)
		}
		_ = ApplyRspamdSettings(h.DB)
		writeApplyFailure(w, "apply rspamd policy domain", id, "could not apply the spam policy", err)
		return
	}
	h.audit(r, "mail.spam.update", strconv.FormatInt(id, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": req})
}

func validateSpamSettings(s SpamSettings) error {
	if s.GreylistScore < 0 || s.RejectScore > 50 ||
		s.GreylistScore > s.AddHeaderScore || s.AddHeaderScore > s.RejectScore {
		return errors.New("scores must be within 0-50 and ordered greylist <= add header <= reject")
	}
	return nil
}

func readSpamSettings(ctx context.Context, db *sql.DB, domainID int64) (SpamSettings, bool, error) {
	var s SpamSettings
	var enabled int
	err := db.QueryRowContext(ctx, `SELECT enabled, greylist_score, add_header_score, reject_score
		FROM mail_spam_settings WHERE domain_id=?`, domainID).
		Scan(&enabled, &s.GreylistScore, &s.AddHeaderScore, &s.RejectScore)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	s.Enabled = enabled == 1
	return s, err == nil, err
}

// ErrRspamdUnavailable says the host has no Rspamd. It is the one apply failure
// whose text is safe to hand to the domain owner, so it is a sentinel rather
// than an ad-hoc string.
var ErrRspamdUnavailable = errors.New("rspamadm is not installed")

// ApplyRspamdSettings atomically regenerates the settings module configuration.
// The previous file remains in place when rspamadm rejects the candidate.
func ApplyRspamdSettings(db *sql.DB) error {
	rspamdApplyMu.Lock()
	defer rspamdApplyMu.Unlock()
	if _, err := exec.LookPath("rspamadm"); err != nil {
		return ErrRspamdUnavailable
	}
	rows, err := db.Query(`
		SELECT s.domain_id, d.domain_name, s.greylist_score, s.add_header_score, s.reject_score
		FROM mail_spam_settings s
		JOIN domains d ON d.id=s.domain_id
		JOIN mail_domains md ON md.domain_id=d.id
		WHERE s.enabled=1 AND md.status='active'
		ORDER BY s.domain_id`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var out bytes.Buffer
	out.WriteString("# Generated by Servika; edit from the panel.\n")
	for rows.Next() {
		var id int64
		var domain string
		var grey, header, reject float64
		if err := rows.Scan(&id, &domain, &grey, &header, &reject); err != nil {
			return err
		}
		if strings.ContainsAny(domain, "\"{};\r\n") {
			return fmt.Errorf("invalid domain: %q", domain)
		}
		fmt.Fprintf(&out, `
domain_%d {
  priority = high;
  rcpt = "@%s";
  apply {
    actions {
      greylist = %.2f;
      "add header" = %.2f;
      reject = %.2f;
    }
  }
}
`, id, domain, grey, header, reject)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return writeRspamdSettings(out.Bytes())
}

// writeRspamdSettings atomically installs the candidate config, validates it with
// rspamadm, reloads the service, and rolls back to the previous file on any failure.
func writeRspamdSettings(content []byte) error {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll("/etc/rspamd/local.d", 0o755); err != nil {
		return err
	}
	tmp := rspamdSettingsPath + ".new"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(tmp, content, 0o640); err != nil {
		return err
	}
	previous, previousErr := os.ReadFile(rspamdSettingsPath)
	if err := os.Rename(tmp, rspamdSettingsPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	rollback := func() {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if previousErr == nil {
			// #nosec G306 G703 -- root-owned rspamd config file its daemon must read; fixed system path, no tenant input, no secret.
			_ = os.WriteFile(rspamdSettingsPath, previous, 0o644)
		} else {
			_ = os.Remove(rspamdSettingsPath)
		}
	}
	// The Rspamd systemd unit reads the configuration as an unprivileged user.
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(rspamdSettingsPath, 0o644); err != nil {
		rollback()
		return err
	}
	if output, err := exec.Command("rspamadm", "configtest").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("configtest: %s", strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command("systemctl", "reload", "rspamd").CombinedOutput(); err != nil {
		rollback()
		_, _ = exec.Command("systemctl", "reload", "rspamd").CombinedOutput()
		return fmt.Errorf("reload: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
