// Package plans provides service-plan CRUD, seed data, and resource-limit fields.
package plans

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/mail"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// Plan describes a service plan and its resource limits.
type Plan struct {
	ID                   int64  `json:"id"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	DiskQuotaMB          int    `json:"disk_quota_mb"` // Zero means unlimited.
	TrafficQuotaMB       int    `json:"traffic_quota_mb"`
	MaxDomain            int    `json:"max_domain"`
	MaxDB                int    `json:"max_db"`
	MaxEmail             int    `json:"max_email"`
	MailboxQuotaMB       int    `json:"mailbox_quota_mb"`     // storage per mailbox, 0 = unlimited
	MailSendLimitHour    int    `json:"mail_send_limit_hour"` // 0 keeps the built-in per-mailbox default
	MailSendLimitDay     int    `json:"mail_send_limit_day"`  // 0 keeps the built-in per-mailbox default
	MaxFTP               int    `json:"max_ftp"`
	MaxApp               int    `json:"max_app"`     // Node/Python applications, 0 = unlimited.
	CPUPercent           int    `json:"cpu_percent"` // 100 equals one CPU core.
	RAMMB                int    `json:"ram_mb"`      // Hard limit in MB.
	MaxProcess           int    `json:"max_process"` // systemd TasksMax.
	InodeQuota           int    `json:"inode_quota"`
	IOWeight             int    `json:"io_weight"` // systemd IOWeight from 1 to 1000.
	MySQLMaxConnections  int    `json:"mysql_max_connections"`
	PMMaxChildren        int    `json:"pm_max_children"`         // Zero derives the limit from plan memory.
	IOReadMBps           int    `json:"io_read_mbps"`            // Zero means unlimited.
	IOWriteMBps          int    `json:"io_write_mbps"`           // Zero means unlimited.
	IOReadIOPS           int    `json:"io_read_iops"`            // Zero means unlimited.
	IOWriteIOPS          int    `json:"io_write_iops"`           // Zero means unlimited.
	DBMaxQueriesPerHour  int    `json:"db_max_queries_per_hour"` // Zero means unlimited.
	DBMaxUpdatesPerHour  int    `json:"db_max_updates_per_hour"` // Zero means unlimited.
	DBMaxQuerySeconds    int    `json:"db_max_query_seconds"`    // Zero disables query termination.
	PHPVersion           string `json:"php_version"`
	FastCGICache         bool   `json:"fastcgi_cache"`
	ClientMaxBodyMB      int    `json:"client_max_body_mb"`
	NginxExtraDirectives string `json:"nginx_extra_directives"`
	// WAF (ModSecurity + OWASP CRS) plan defaults — domains in this plan inherit these values.
	WAFEnabled  bool   `json:"waf_enabled"`
	WAFMode     string `json:"waf_mode"`     // "on" (block) | "detect" (log only) | "off"
	WAFParanoia int    `json:"waf_paranoia"` // CRS paranoia 1..4
	IsDefault   bool   `json:"is_default"`
	CreatedAt   string `json:"created_at"`
}

// Handlers provides service plan HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

const selectAll = `SELECT id, name, description, disk_quota_mb, traffic_quota_mb,
  max_domain, max_db, max_email, COALESCE(mailbox_quota_mb,0),
  COALESCE(mail_send_limit_hour,0), COALESCE(mail_send_limit_day,0), max_ftp,
  COALESCE(max_app,0),
  cpu_percent, ram_mb, max_process, inode_quota, io_weight, mysql_max_connections,
  COALESCE(pm_max_children,0),
  COALESCE(io_read_mbps,0), COALESCE(io_write_mbps,0),
  COALESCE(io_read_iops,0), COALESCE(io_write_iops,0),
  COALESCE(db_max_queries_per_hour,0), COALESCE(db_max_updates_per_hour,0),
  COALESCE(db_max_query_seconds,0),
  php_version, fastcgi_cache, client_max_body_mb, COALESCE(nginx_extra_directives,''),
  COALESCE(waf_enabled,0), COALESCE(waf_mode,'on'), COALESCE(waf_paranoia,1),
  is_default, DATE_FORMAT(created_at,'%Y-%m-%d') FROM service_plans`

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scan(rs interface{ Scan(...any) error }) (Plan, error) {
	var p Plan
	var vars, fc, wafEn int
	err := rs.Scan(&p.ID, &p.Name, &p.Description, &p.DiskQuotaMB, &p.TrafficQuotaMB,
		&p.MaxDomain, &p.MaxDB, &p.MaxEmail, &p.MailboxQuotaMB,
		&p.MailSendLimitHour, &p.MailSendLimitDay, &p.MaxFTP, &p.MaxApp,
		&p.CPUPercent, &p.RAMMB, &p.MaxProcess, &p.InodeQuota, &p.IOWeight, &p.MySQLMaxConnections,
		&p.PMMaxChildren,
		&p.IOReadMBps, &p.IOWriteMBps, &p.IOReadIOPS, &p.IOWriteIOPS,
		&p.DBMaxQueriesPerHour, &p.DBMaxUpdatesPerHour, &p.DBMaxQuerySeconds,
		&p.PHPVersion, &fc, &p.ClientMaxBodyMB, &p.NginxExtraDirectives,
		&wafEn, &p.WAFMode, &p.WAFParanoia,
		&vars, &p.CreatedAt)
	p.IsDefault = vars == 1
	p.FastCGICache = fc == 1
	p.WAFEnabled = wafEn == 1
	return p, err
}

// List returns all service plans.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), selectAll+" ORDER BY is_default DESC, id ASC")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Plan, 0)
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Get returns a service plan and its assigned domain count.
func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE id=?", id)
	p, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "plan not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	// Count domains using the plan.
	var dCount int
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domains WHERE plan_id=?`, id).Scan(&dCount)
	resp := map[string]any{
		"plan":         p,
		"domain_count": dCount,
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func fillDefaults(p *Plan) {
	if p.CPUPercent == 0 {
		p.CPUPercent = 100
	}
	if p.RAMMB == 0 {
		p.RAMMB = 512
	}
	if p.MaxProcess == 0 {
		p.MaxProcess = 50
	}
	if p.InodeQuota == 0 {
		p.InodeQuota = 50000
	}
	if p.IOWeight == 0 {
		p.IOWeight = 100
	}
	if p.MySQLMaxConnections == 0 {
		p.MySQLMaxConnections = 25
	}
	if strings.TrimSpace(p.PHPVersion) == "" {
		p.PHPVersion = "8.3"
	}
	if p.ClientMaxBodyMB == 0 {
		p.ClientMaxBodyMB = 64
	}
	// WAF defaults
	switch strings.ToLower(strings.TrimSpace(p.WAFMode)) {
	case "on", "detect", "off":
		p.WAFMode = strings.ToLower(strings.TrimSpace(p.WAFMode))
	default:
		p.WAFMode = "on"
	}
	if p.WAFParanoia < 1 || p.WAFParanoia > 4 {
		p.WAFParanoia = 1
	}
}

// Create creates a service plan.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	var p Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan name is required")
		return
	}
	fillDefaults(&p)
	if name := provisioner.DangerousNginxDirective(p.NginxExtraDirectives); name != "" {
		httpx.WriteError(w, http.StatusBadRequest, "nginx directive '"+name+"' is not allowed at plan level")
		return
	}
	if err := provisioner.ValidateNginxDirectives(p.NginxExtraDirectives); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid nginx directives")
		return
	}
	v := 0
	if p.IsDefault {
		v = 1
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE service_plans SET is_default=0`)
	}
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO service_plans(name, description, disk_quota_mb, traffic_quota_mb,
		   max_domain, max_db, max_email, mailbox_quota_mb, mail_send_limit_hour, mail_send_limit_day, max_ftp,
		   max_app,
		   cpu_percent, ram_mb, max_process, inode_quota, io_weight, mysql_max_connections,
		   pm_max_children, io_read_mbps, io_write_mbps, io_read_iops, io_write_iops,
		   db_max_queries_per_hour, db_max_updates_per_hour, db_max_query_seconds,
		   php_version, fastcgi_cache, client_max_body_mb, nginx_extra_directives,
		   waf_enabled, waf_mode, waf_paranoia, is_default)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.Name, p.Description, p.DiskQuotaMB, p.TrafficQuotaMB,
		p.MaxDomain, p.MaxDB, p.MaxEmail, p.MailboxQuotaMB, p.MailSendLimitHour, p.MailSendLimitDay, p.MaxFTP,
		p.MaxApp,
		p.CPUPercent, p.RAMMB, p.MaxProcess, p.InodeQuota, p.IOWeight, p.MySQLMaxConnections,
		p.PMMaxChildren, p.IOReadMBps, p.IOWriteMBps, p.IOReadIOPS, p.IOWriteIOPS,
		p.DBMaxQueriesPerHour, p.DBMaxUpdatesPerHour, p.DBMaxQuerySeconds,
		p.PHPVersion, b01(p.FastCGICache), p.ClientMaxBodyMB, p.NginxExtraDirectives,
		b01(p.WAFEnabled), p.WAFMode, p.WAFParanoia, v)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	id, _ := res.LastInsertId()
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE id=?", id)
	// WAF plan default may have changed — re-render vhosts for domains in this plan
	// whose WAF override is set to inherit. Runs in the background.
	go h.wafPlanReapply(id)

	saved, _ := scan(row)
	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// Update updates a service plan.
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var p Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "plan name is required")
		return
	}
	fillDefaults(&p)
	if name := provisioner.DangerousNginxDirective(p.NginxExtraDirectives); name != "" {
		httpx.WriteError(w, http.StatusBadRequest, "nginx directive '"+name+"' is not allowed at plan level")
		return
	}
	if err := provisioner.ValidateNginxDirectives(p.NginxExtraDirectives); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid nginx directives")
		return
	}
	v := 0
	if p.IsDefault {
		v = 1
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE service_plans SET is_default=0 WHERE id<>?`, id)
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE service_plans SET name=?, description=?, disk_quota_mb=?, traffic_quota_mb=?,
		   max_domain=?, max_db=?, max_email=?, mailbox_quota_mb=?,
		   mail_send_limit_hour=?, mail_send_limit_day=?, max_ftp=?, max_app=?,
		   cpu_percent=?, ram_mb=?, max_process=?, inode_quota=?, io_weight=?, mysql_max_connections=?,
		   pm_max_children=?, io_read_mbps=?, io_write_mbps=?, io_read_iops=?, io_write_iops=?,
		   db_max_queries_per_hour=?, db_max_updates_per_hour=?, db_max_query_seconds=?,
		   php_version=?, fastcgi_cache=?, client_max_body_mb=?, nginx_extra_directives=?, waf_enabled=?, waf_mode=?, waf_paranoia=?, is_default=?
		 WHERE id=?`,
		p.Name, p.Description, p.DiskQuotaMB, p.TrafficQuotaMB,
		p.MaxDomain, p.MaxDB, p.MaxEmail, p.MailboxQuotaMB, p.MailSendLimitHour, p.MailSendLimitDay, p.MaxFTP,
		p.MaxApp,
		p.CPUPercent, p.RAMMB, p.MaxProcess, p.InodeQuota, p.IOWeight, p.MySQLMaxConnections,
		p.PMMaxChildren, p.IOReadMBps, p.IOWriteMBps, p.IOReadIOPS, p.IOWriteIOPS,
		p.DBMaxQueriesPerHour, p.DBMaxUpdatesPerHour, p.DBMaxQuerySeconds,
		p.PHPVersion, b01(p.FastCGICache), p.ClientMaxBodyMB, p.NginxExtraDirectives, b01(p.WAFEnabled), p.WAFMode, p.WAFParanoia, v, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE id=?", id)
	// WAF plan default may have changed — re-render vhosts for domains in this plan
	// whose WAF override is set to inherit. Runs in the background.
	go h.wafPlanReapply(id)
	// The mail limits may have changed too. Without this the new values would
	// apply only to mailboxes created from now on, so the same plan would mean
	// two different things depending on when a customer signed up.
	// #nosec G118 -- the goroutine deliberately builds its own context; the request context dies with the response and would abort the realignment half way through.
	go h.mailLimitReapply(id)

	saved, _ := scan(row)
	httpx.WriteJSON(w, http.StatusOK, saved)
}

// mailLimitReapply pushes the plan's mail limits onto the mailboxes of every
// domain on it. Runs in a background goroutine with its own context, because the
// request context is cancelled as soon as the response is written.
func (h *Handlers) mailLimitReapply(planID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	changed, err := mail.ApplyPlanLimitsToPlan(ctx, h.DB, planID)
	if err != nil {
		log.Printf("mail limit reapply for plan %d: %v", planID, err)
		return
	}
	if changed > 0 {
		log.Printf("mail limit reapply for plan %d: %d mailbox rows updated", planID, changed)
	}
}

// wafPlanReapply re-applies the WAF settings (including plan-default inheritors)
// for all domains in this plan. Runs in a background goroutine.
func (h *Handlers) wafPlanReapply(planID int64) {
	rows, err := h.DB.Query(`SELECT id FROM domains WHERE plan_id=?`, planID)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var did int64
		if rows.Scan(&did) == nil {
			ids = append(ids, did)
		}
	}
	_ = rows.Close()
	for _, did := range ids {
		if err := provisioner.WAFApply(h.DB, did); err != nil {
			log.Printf("waf plan reapply domain=%d: %v", did, err)
		}
	}
}

// Delete deletes an unused service plan.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var n int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domains WHERE plan_id=?`, id).Scan(&n); err != nil {
		// FAIL-CLOSED: a count error must not bypass the "plan in use" guard and
		// delete a plan that live subscriptions still reference.
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	} else if n > 0 {
		httpx.WriteError(w, http.StatusConflict,
			"this plan cannot be deleted because it is used by "+strconv.Itoa(n)+" subscriptions")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM service_plans WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// SearchDomains returns domains assigned to a plan.
func (h *Handlers) SearchDomains(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain_name, system_user, status, DATE_FORMAT(created_at,'%Y-%m-%d')
		 FROM domains WHERE plan_id=? ORDER BY id`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan operation failed")
		return
	}
	defer func() { _ = rows.Close() }()
	type dom struct {
		ID         int64  `json:"id"`
		DomainName string `json:"domain_name"`
		SK         string `json:"system_user"`
		Status     string `json:"status"`
		CreatedAt  string `json:"created_at"`
	}
	out := make([]dom, 0)
	for rows.Next() {
		var d dom
		if err := rows.Scan(&d.ID, &d.DomainName, &d.SK, &d.Status, &d.CreatedAt); err == nil {
			out = append(out, d)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type seedTier struct {
	Name, Description                                        string
	Disk, Traffic, MaxDomain, MaxDB, MaxMail, MaxFTP, MaxApp int
	CPU, RAM, Process, Inode, IO, MySQL, PMMax               int
	Default                                                  int
}

// panelLang reads panel_settings.default_lang, which decides the language of the
// seeded plan names and descriptions (the language chosen at install). English is
// the primary language; anything unreadable or not "tr" falls back to it.
func panelLang(ctx context.Context, db *sql.DB) string {
	var lang string
	_ = db.QueryRowContext(ctx, `SELECT default_lang FROM panel_settings WHERE id=1`).Scan(&lang)
	return config.NormalizeLang(lang)
}

// planText holds the localized display strings for the three default tiers. Only
// the display text differs by language; every resource limit is identical.
type planText struct{ starterName, starterDesc, standardName, standardDesc, proName, proDesc string }

// planTexts maps a supported language code to its tier display strings. English is
// the fallback for any code missing here.
var planTexts = map[string]planText{
	"en":    {"Starter", "One site for a small project", "Standard", "Multiple projects and email", "Professional", "High traffic and large sites"},
	"tr":    {"Başlangıç", "Küçük bir proje için tek site", "Standart", "Birden çok proje ve e-posta", "Profesyonel", "Yüksek trafik ve büyük siteler"},
	"de":    {"Einsteiger", "Eine Website für ein kleines Projekt", "Standard", "Mehrere Projekte und E-Mail", "Professionell", "Hoher Traffic und große Websites"},
	"fr":    {"Débutant", "Un site pour un petit projet", "Standard", "Plusieurs projets et e-mail", "Professionnel", "Trafic élevé et grands sites"},
	"it":    {"Base", "Un sito per un piccolo progetto", "Standard", "Più progetti ed e-mail", "Professionale", "Traffico elevato e siti grandi"},
	"pt":    {"Inicial", "Um site para um pequeno projeto", "Padrão", "Vários projetos e e-mail", "Profissional", "Tráfego elevado e sites grandes"},
	"pt-BR": {"Inicial", "Um site para um projeto pequeno", "Padrão", "Vários projetos e e-mail", "Profissional", "Tráfego alto e sites grandes"},
	"es":    {"Inicial", "Un sitio para un proyecto pequeño", "Estándar", "Varios proyectos y correo", "Profesional", "Alto tráfico y sitios grandes"},
	"cs":    {"Začátečník", "Jeden web pro malý projekt", "Standard", "Více projektů a e-mail", "Profesionální", "Vysoký provoz a velké weby"},
	"ro":    {"Start", "Un site pentru un proiect mic", "Standard", "Mai multe proiecte și e-mail", "Profesional", "Trafic ridicat și site-uri mari"},
	"ja":    {"スターター", "小規模プロジェクト向けの1サイト", "スタンダード", "複数のプロジェクトとメール", "プロフェッショナル", "高トラフィックと大規模サイト"},
	"zh":    {"入门版", "适合小型项目的单个站点", "标准版", "多个项目和电子邮件", "专业版", "高流量和大型站点"},
}

// seedPlans returns the three default tiers with localized name/description.
func seedPlans(lang string) []seedTier {
	tx, ok := planTexts[lang]
	if !ok {
		tx = planTexts["en"]
	}
	// The application counts are deliberate rather than left at the column's
	// "0 = unlimited" default: an app is a process that stays resident, so a tier
	// capped at one domain and two FTP accounts must not also allow an unbounded
	// number of them.
	return []seedTier{
		{tx.starterName, tx.starterDesc, 1024, 5120, 1, 1, 5, 2, 1,
			50, 256, 30, 100000, 100, 15, 4, 1},
		{tx.standardName, tx.standardDesc, 10240, 51200, 5, 10, 25, 10, 5,
			100, 512, 60, 250000, 100, 30, 8, 0},
		{tx.proName, tx.proDesc, 51200, 204800, 25, 50, 100, 50, 25,
			200, 2048, 150, 500000, 200, 100, 32, 0},
	}
}

// SeedIfEmpty creates three default plans with resource limits when none exist.
func SeedIfEmpty(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_plans`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	log.Printf("seed: adding 3 default plans")
	for _, p := range seedPlans(panelLang(ctx, db)) {
		_, err := db.ExecContext(ctx,
			`INSERT INTO service_plans(name, description, disk_quota_mb, traffic_quota_mb,
			   max_domain, max_db, max_email, max_ftp, max_app,
			   cpu_percent, ram_mb, max_process, inode_quota, io_weight, mysql_max_connections,
			   pm_max_children, is_default)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.Name, p.Description, p.Disk, p.Traffic, p.MaxDomain, p.MaxDB, p.MaxMail, p.MaxFTP, p.MaxApp,
			p.CPU, p.RAM, p.Process, p.Inode, p.IO, p.MySQL, p.PMMax, p.Default)
		if err != nil {
			log.Printf("seed plan %s: %v", p.Name, err)
		}
	}
	return nil
}

// SeedSync inserts missing standard plans without modifying existing plans.
func SeedSync(ctx context.Context, db *sql.DB) error {
	for _, p := range seedPlans(panelLang(ctx, db)) {
		_, err := db.ExecContext(ctx,
			`INSERT INTO service_plans(name, description, disk_quota_mb, traffic_quota_mb,
			   max_domain, max_db, max_email, max_ftp, max_app,
			   cpu_percent, ram_mb, max_process, inode_quota, io_weight, mysql_max_connections,
			   pm_max_children, is_default)
			 SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0
			 FROM DUAL
			 WHERE NOT EXISTS (SELECT 1 FROM service_plans WHERE name=?)`,
			p.Name, p.Description, p.Disk, p.Traffic, p.MaxDomain, p.MaxDB, p.MaxMail, p.MaxFTP, p.MaxApp,
			p.CPU, p.RAM, p.Process, p.Inode, p.IO, p.MySQL, p.PMMax, p.Name)
		if err != nil {
			log.Printf("seed sync plan %s: %v", p.Name, err)
		}
	}
	return nil
}
