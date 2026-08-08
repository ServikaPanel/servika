// template.go provides the server-wide DNS template and DKIM key generation.
//
// Placeholders: {DOMAIN} domain name, {IP} domain IPv4, {SELECTOR} DKIM
// selector, {DKIM} DKIM public TXT, {NS1}/{NS2} the shared nameserver pair
// (see nameserver.go).
package dns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"servika/internal/httpx"
)

var (
	dkimSelectorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
	dkimDomainPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// TemplateRow describes one row in the server-wide DNS template.
type TemplateRow struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	TTL       int    `json:"ttl"`
	Priority  int    `json:"priority"`
	SortOrder int    `json:"sort_order"`
	Enabled   bool   `json:"enabled"`
}

// TemplateMeta contains the SOA and DKIM settings shared by the DNS template.
type TemplateMeta struct {
	SOARefresh   int    `json:"soa_refresh"`
	SOARetry     int    `json:"soa_retry"`
	SOAExpire    int    `json:"soa_expire"`
	SOAMinimum   int    `json:"soa_minimum"`
	SOATTL       int    `json:"soa_ttl"`
	DKIMSelector string `json:"dkim_selector"`
	DKIMEnabled  bool   `json:"dkim_enabled"`
}

func builtinDefaults() []TemplateRow {
	rows := []TemplateRow{
		{Name: "@", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 10, Enabled: true},
		{Name: "@", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 11, Enabled: true},
		{Name: "www", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 20, Enabled: true},
		{Name: "www", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 21, Enabled: true},
		{Name: "mail", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 30, Enabled: true},
		{Name: "mail", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 35, Enabled: true},
		{Name: "@", Type: "MX", Value: "mail.{DOMAIN}", TTL: 3600, Priority: 10, SortOrder: 40, Enabled: true},
		{Name: "@", Type: "TXT", Value: "v=spf1 a mx ip4:{IP} ip6:{IP6} ~all", TTL: 3600, SortOrder: 50, Enabled: true},
		{Name: "_dmarc", Type: "TXT", Value: "v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}; ruf=mailto:postmaster@{DOMAIN}; fo=1; adkim=r; aspf=r", TTL: 3600, SortOrder: 60, Enabled: true},
		{Name: "{SELECTOR}._domainkey", Type: "TXT", Value: "{DKIM}", TTL: 3600, SortOrder: 70, Enabled: true},
		// The NS records name the SHARED nameserver pair. No ns1/ns2 A record is
		// placed under the customer's domain: the nameserver lives in the
		// provider's (or reseller's) own domain, where glue is needed once
		// instead of once per customer domain. See nameserver.go.
		{Name: "@", Type: "NS", Value: "{NS1}", TTL: 86400, SortOrder: 100, Enabled: true},
		{Name: "@", Type: "NS", Value: "{NS2}", TTL: 86400, SortOrder: 110, Enabled: true},
	}
	return append(rows, MailDiscoveryRows()...)
}

// MailDiscoveryRows are the records a mail client needs to find and trust the
// server.
//
// The A records exist because people type smtp./imap. into a mail client out of
// habit; without them those names do not resolve at all, and the mail
// certificate cannot cover a name that does not exist. The SRV records are the
// standard way (RFC 6186) for a client to discover the ports without being told.
//
// The ports here are the ones this server actually serves, not the ones a
// hosting panel usually advertises: assets/mail/dovecot runs `protocols = imap
// lmtp` and servika-mail-setup opens 25, 587 and 143 in the firewall. So there
// is no POP3 service and no implicit-TLS listener to point a client at, and
// _imap._tcp/143 with STARTTLS is what a client can actually reach.
//
// autoconfig and autodiscover are here because each client looks there FIRST or
// SECOND depending on which one it is: Thunderbird probes autoconfig.<domain>
// before the domain's own /.well-known path, and Outlook probes the domain
// before autodiscover.<domain>. Covering both means either client succeeds on
// its first attempt, and it is the only route that works at all when the apex
// resolves to another server while mail is hosted here.
//
// _autodiscover._tcp is still deliberately absent: it exists solely to point
// Outlook at a DIFFERENT host, which makes it show a redirect warning, and the
// host it would name is one Outlook now reaches directly.
func MailDiscoveryRows() []TemplateRow {
	return []TemplateRow{
		{Name: "smtp", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 31, Enabled: true},
		{Name: "smtp", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 36, Enabled: true},
		{Name: "imap", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 32, Enabled: true},
		{Name: "imap", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 37, Enabled: true},
		{Name: "autoconfig", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 33, Enabled: true},
		{Name: "autoconfig", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 38, Enabled: true},
		{Name: "autodiscover", Type: "A", Value: "{IP}", TTL: 3600, SortOrder: 34, Enabled: true},
		{Name: "autodiscover", Type: "AAAA", Value: "{IP6}", TTL: 3600, SortOrder: 39, Enabled: true},
		// SRV value is "weight port target"; the priority lives in its own column.
		{Name: "_imap._tcp", Type: "SRV", Value: "1 143 mail.{DOMAIN}", TTL: 3600, Priority: 10, SortOrder: 120, Enabled: true},
		{Name: "_submission._tcp", Type: "SRV", Value: "1 587 mail.{DOMAIN}", TTL: 3600, Priority: 10, SortOrder: 122, Enabled: true},
	}
}

// SeedTemplateIfEmpty inserts the built-in template only when no custom template exists.
func SeedTemplateIfEmpty(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_template`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, row := range builtinDefaults() {
		enabled := 0
		if row.Enabled {
			enabled = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO dns_template(name,type,value,ttl,priority,sort_order,enabled) VALUES(?,?,?,?,?,?,?)`,
			row.Name, row.Type, row.Value, row.TTL, row.Priority, row.SortOrder, enabled); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadTemplate returns every DNS template row in configured order.
func LoadTemplate(ctx context.Context, db *sql.DB) ([]TemplateRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, type, value, ttl, priority, sort_order, enabled FROM dns_template ORDER BY sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]TemplateRow, 0)
	for rows.Next() {
		var row TemplateRow
		var enabled int
		if err := rows.Scan(&row.ID, &row.Name, &row.Type, &row.Value, &row.TTL, &row.Priority, &row.SortOrder, &enabled); err != nil {
			return nil, err
		}
		row.Enabled = enabled == 1
		out = append(out, row)
	}
	return out, rows.Err()
}

// LoadTemplateMeta returns the shared SOA and DKIM settings or safe defaults.
func LoadTemplateMeta(ctx context.Context, db *sql.DB) TemplateMeta {
	meta := TemplateMeta{SOARefresh: 3600, SOARetry: 900, SOAExpire: 1209600, SOAMinimum: 3600, SOATTL: 3600, DKIMSelector: "default", DKIMEnabled: true}
	var dkimEnabled int
	if err := db.QueryRowContext(ctx,
		`SELECT soa_refresh, soa_retry, soa_expire, soa_minimum, soa_ttl, dkim_selector, dkim_enabled
		 FROM dns_template_meta WHERE id=1`).
		Scan(&meta.SOARefresh, &meta.SOARetry, &meta.SOAExpire, &meta.SOAMinimum, &meta.SOATTL, &meta.DKIMSelector, &dkimEnabled); err == nil {
		meta.DKIMEnabled = dkimEnabled == 1
	}
	if !dkimSelectorPattern.MatchString(meta.DKIMSelector) {
		meta.DKIMSelector = "default"
	}
	return meta
}

func substituteTemplate(value, domainName, ipv4, ipv6, selector, dkim, ns1, ns2 string) string {
	// The IPv6 term goes first and, with no address, takes its whole mechanism
	// with it. See dropIPv6Mechanisms.
	if ipv6 == "" {
		value = dropIPv6Mechanisms(value)
	}
	value = strings.ReplaceAll(value, "{DOMAIN}", domainName)
	value = strings.ReplaceAll(value, "{IP6}", ipv6)
	value = strings.ReplaceAll(value, "{IP}", ipv4)
	value = strings.ReplaceAll(value, "{SELECTOR}", selector)
	value = strings.ReplaceAll(value, "{DKIM}", dkim)
	value = strings.ReplaceAll(value, "{NS1}", ns1)
	return strings.ReplaceAll(value, "{NS2}", ns2)
}

// dropIPv6Mechanisms removes any SPF term built around the IPv6 placeholder.
//
// Leaving `ip6:` with an empty value is not a harmless blank: it is an invalid
// SPF term, and a receiver that cannot parse a policy returns permerror for the
// WHOLE record rather than skipping the bad term. That takes SPF down for the
// domain, and DMARC with it, on a domain that simply has no IPv6. So the term
// is removed entirely, and the surrounding spacing is normalized so the record
// does not end up with a double space a strict parser could trip on.
func dropIPv6Mechanisms(value string) string {
	if !strings.Contains(value, "{IP6}") {
		return value
	}
	fields := strings.Fields(value)
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.Contains(field, "{IP6}") {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

// EnsureDKIM returns a domain's existing DKIM public record or creates a 2048-bit key pair.
func EnsureDKIM(ctx context.Context, db *sql.DB, domainID int64, domainName, selector string) (string, error) {
	if !dkimSelectorPattern.MatchString(selector) {
		return "", errors.New("invalid DKIM selector")
	}
	if !dkimDomainPattern.MatchString(domainName) {
		return "", errors.New("invalid DKIM domain")
	}
	var privateKey, publicKey string
	err := db.QueryRowContext(ctx,
		`SELECT private_key, public_key FROM dkim_keys WHERE domain_id=? AND selector=?`,
		domainID, selector).Scan(&privateKey, &publicKey)
	if err == nil && publicKey != "" {
		syncOpenDKIM(domainName, selector, privateKey, publicKey)
		return dkimTXT(publicKey), nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	privateDER := x509.MarshalPKCS1PrivateKey(key)
	privatePEM := "-----BEGIN RSA PRIVATE KEY-----\n" + chunk64(base64.StdEncoding.EncodeToString(privateDER)) + "-----END RSA PRIVATE KEY-----\n"
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	publicKey = base64.StdEncoding.EncodeToString(publicDER)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO dkim_keys(domain_id, selector, private_key, public_key) VALUES(?,?,?,?)
		 ON DUPLICATE KEY UPDATE private_key=VALUES(private_key), public_key=VALUES(public_key)`,
		domainID, selector, privatePEM, publicKey); err != nil {
		return "", err
	}
	syncOpenDKIM(domainName, selector, privatePEM, publicKey)
	return dkimTXT(publicKey), nil
}

func dkimTXT(publicKey string) string {
	return "v=DKIM1; k=rsa; p=" + publicKey
}

func chunk64(value string) string {
	var out strings.Builder
	for len(value) > 64 {
		out.WriteString(value[:64])
		out.WriteByte('\n')
		value = value[64:]
	}
	if value != "" {
		out.WriteString(value)
		out.WriteByte('\n')
	}
	return out.String()
}

func syncOpenDKIM(domainName, selector, privatePEM, publicKey string) {
	base := "/etc/opendkim"
	if _, err := os.Stat(base); err != nil {
		return
	}
	keyDir := filepath.Join(base, "keys", domainName)
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return
	}
	privatePath := filepath.Join(keyDir, selector+".private")
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.WriteFile(privatePath, []byte(privatePEM), 0600); err != nil {
		return
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.Chmod(privatePath, 0600); err != nil {
		return
	}
	txtPath := filepath.Join(keyDir, selector+".txt")
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	_ = os.WriteFile(txtPath, []byte(selector+"._domainkey."+domainName+" IN TXT ( "+txtQuote(dkimTXT(publicKey))+" )\n"), 0644)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("chown", "-R", "opendkim:opendkim", keyDir).CombinedOutput()
	appendUnique(filepath.Join(base, "KeyTable"), selector+"._domainkey."+domainName+" "+domainName+":"+selector+":"+privatePath)
	appendUnique(filepath.Join(base, "SigningTable"), "*@"+domainName+" "+selector+"._domainkey."+domainName)
	_ = exec.Command("systemctl", "reload", "opendkim").Run()
}

func appendUnique(path, line string) {
	key, _, _ := strings.Cut(line, " ")
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	body, _ := os.ReadFile(path)
	for existing := range strings.SplitSeq(string(body), "\n") {
		if eKey, _, _ := strings.Cut(existing, " "); eKey == key {
			return
		}
	}
	// #nosec G302 G304 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	_, _ = file.WriteString(line + "\n")
}

// GetTemplate returns the server-wide DNS template and metadata.
func (h *Handlers) GetTemplate(w http.ResponseWriter, r *http.Request) {
	records, err := LoadTemplate(r.Context(), h.DB)
	if err != nil {
		log.Printf("load DNS template: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not load DNS template")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"records": records, "meta": LoadTemplateMeta(r.Context(), h.DB)})
}

// PutTemplate replaces the server-wide DNS template and metadata atomically.
func (h *Handlers) PutTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Records []TemplateRow `json:"records"`
		Meta    TemplateMeta  `json:"meta"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !dkimSelectorPattern.MatchString(req.Meta.DKIMSelector) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid DKIM selector")
		return
	}
	for i := range req.Records {
		record := &req.Records[i]
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		record.Name = strings.TrimSpace(record.Name)
		if record.Name == "" {
			record.Name = "@"
		}
		if !validRecordFields(record.Name, record.Value) || !validType(record.Type) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid DNS template record")
			return
		}
		if record.TTL <= 0 {
			record.TTL = 3600
		}
		if record.SortOrder == 0 {
			record.SortOrder = (i + 1) * 10
		}
		record.Priority = normalizePriority(record.Type, record.Priority)
	}
	setTemplateMetaDefaults(&req.Meta)

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("begin DNS template update: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update DNS template")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM dns_template`); err != nil {
		log.Printf("clear DNS template: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update DNS template")
		return
	}
	for _, record := range req.Records {
		enabled := 0
		if record.Enabled {
			enabled = 1
		}
		if _, err := tx.ExecContext(r.Context(),
			`INSERT INTO dns_template(name,type,value,ttl,priority,sort_order,enabled) VALUES(?,?,?,?,?,?,?)`,
			record.Name, record.Type, record.Value, record.TTL, record.Priority, record.SortOrder, enabled); err != nil {
			log.Printf("insert DNS template record: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not update DNS template")
			return
		}
	}
	dkimEnabled := 0
	if req.Meta.DKIMEnabled {
		dkimEnabled = 1
	}
	if _, err := tx.ExecContext(r.Context(),
		`INSERT INTO dns_template_meta(id, soa_refresh, soa_retry, soa_expire, soa_minimum, soa_ttl, dkim_selector, dkim_enabled)
		 VALUES(1,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE soa_refresh=VALUES(soa_refresh), soa_retry=VALUES(soa_retry),
		 soa_expire=VALUES(soa_expire), soa_minimum=VALUES(soa_minimum), soa_ttl=VALUES(soa_ttl),
		 dkim_selector=VALUES(dkim_selector), dkim_enabled=VALUES(dkim_enabled)`,
		req.Meta.SOARefresh, req.Meta.SOARetry, req.Meta.SOAExpire, req.Meta.SOAMinimum, req.Meta.SOATTL, req.Meta.DKIMSelector, dkimEnabled); err != nil {
		log.Printf("update DNS template metadata: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update DNS template")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit DNS template update: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update DNS template")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func setTemplateMetaDefaults(meta *TemplateMeta) {
	if meta.SOARefresh <= 0 {
		meta.SOARefresh = 3600
	}
	if meta.SOARetry <= 0 {
		meta.SOARetry = 900
	}
	if meta.SOAExpire <= 0 {
		meta.SOAExpire = 1209600
	}
	if meta.SOAMinimum <= 0 {
		meta.SOAMinimum = 3600
	}
	if meta.SOATTL <= 0 {
		meta.SOATTL = 3600
	}
}
