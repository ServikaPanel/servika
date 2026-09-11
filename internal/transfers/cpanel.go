// Package transfers implements provider-neutral hosting account discovery.
// The first adapter understands cPanel full-account (cpmove) tar archives.
package transfers

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	maxArchiveEntries = 1_000_000
	maxExpandedBytes  = int64(100 << 30) // inventory guard; no data is extracted here
	maxMetadataBytes  = int64(2 << 20)
)

var domainRE = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,63}$`)
var localPartRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
var cronEnvRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

var (
	ErrNotCPanel       = errors.New("the archive was not recognized as a cPanel full-account backup")
	ErrUnsafeArchive   = errors.New("security: the archive contains an unsafe member")
	ErrArchiveTooLarge = errors.New("security: the archive exceeds the inventory limit")
)

type Inventory struct {
	Provider      string    `json:"provider"`
	Username      string    `json:"username"`
	PrimaryDomain string    `json:"primary_domain"`
	ArchiveRoot   string    `json:"archive_root"`
	EntryCount    int       `json:"entry_count"`
	ExpandedBytes int64     `json:"expanded_bytes"`
	WebFiles      int       `json:"web_files"`
	WebBytes      int64     `json:"web_bytes"`
	Databases     []string  `json:"databases"`
	DNSZones      []string  `json:"dns_zones"`
	MailFiles     int       `json:"mail_files"`
	Mailboxes     []string  `json:"mailboxes"`
	AliasCount    int       `json:"alias_count"`
	CronPresent   bool      `json:"cron_present"`
	CronJobs      []CronJob `json:"cron_jobs"`
	SSLCerts      int       `json:"ssl_certs"`
	Warnings      []string  `json:"warnings"`
}

type CronJob struct {
	Minute  string `json:"minute"`
	Hour    string `json:"hour"`
	Day     string `json:"day"`
	Month   string `json:"month"`
	Weekday string `json:"weekday"`
	Command string `json:"command"`
	Comment string `json:"comment,omitempty"`
}

// AnalyzeCPanel reads a gzip-compressed cPanel full backup without extracting it.
func AnalyzeCPanel(src io.Reader) (Inventory, error) {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return Inventory{}, fmt.Errorf("could not open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	s := &cpanelScan{
		inv:    Inventory{Provider: "cpanel", Databases: []string{}, DNSZones: []string{}, Mailboxes: []string{}, CronJobs: []CronJob{}, Warnings: []string{}},
		dbSet:  map[string]bool{},
		dnsSet: map[string]bool{},
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Inventory{}, fmt.Errorf("could not read tar stream: %w", err)
		}
		if err := s.member(tr, h); err != nil {
			return Inventory{}, err
		}
	}
	if !s.seenCPanel {
		return Inventory{}, ErrNotCPanel
	}
	s.finish()
	return s.inv, nil
}

// cpanelScan is the state one pass over a cPanel archive builds up.
type cpanelScan struct {
	inv        Inventory
	dbSet      map[string]bool
	dnsSet     map[string]bool
	seenCPanel bool
	cronBody   string
}

// member takes one archive member into the inventory: it enforces the size and
// safety limits, counts what the member is, and reads the metadata it carries.
func (s *cpanelScan) member(tr *tar.Reader, h *tar.Header) error {
	s.inv.EntryCount++
	if s.inv.EntryCount > maxArchiveEntries || h.Size < 0 || s.inv.ExpandedBytes > maxExpandedBytes-h.Size {
		return ErrArchiveTooLarge
	}
	s.inv.ExpandedBytes += h.Size
	if unsafeMember(h) {
		return fmt.Errorf("%w: %q", ErrUnsafeArchive, h.Name)
	}

	rel := s.place(h.Name)
	s.count(rel, h)
	if h.Typeflag == tar.TypeReg && h.Size <= maxMetadataBytes {
		s.readMetadata(tr, rel)
	}
	return nil
}

// place returns a member's path below the archive root, recording the root and
// whether the member marks a cPanel backup.
func (s *cpanelScan) place(name string) string {
	root, rel := splitArchiveRoot(cleanMember(name))
	if s.inv.ArchiveRoot == "" && root != "" {
		s.inv.ArchiveRoot = root
	}
	if strings.HasPrefix(rel, "cp/") || rel == "cp" || strings.HasPrefix(rel, "homedir/") {
		s.seenCPanel = true
	}
	return rel
}

// count adds a member to the web, mail, cron or certificate total it belongs to,
// and hands any other member to countNamed.
func (s *cpanelScan) count(rel string, h *tar.Header) {
	regular := h.Typeflag == tar.TypeReg
	switch {
	case strings.HasPrefix(rel, "homedir/public_html/") && regular:
		s.inv.WebFiles++
		s.inv.WebBytes += h.Size
	case strings.HasPrefix(rel, "homedir/mail/") && regular:
		s.inv.MailFiles++
	case rel == "cron" || strings.HasPrefix(rel, "cron/"):
		s.inv.CronPresent = true
	case isSSLCertificateMember(rel) && regular:
		s.inv.SSLCerts++
	default:
		s.countNamed(rel, regular)
	}
}

// countNamed adds a database dump or a DNS zone the first time its name is seen.
func (s *cpanelScan) countNamed(rel string, regular bool) {
	switch {
	case strings.HasPrefix(rel, "mysql/") && strings.HasSuffix(strings.ToLower(rel), ".sql"):
		name := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
		if name != "" && !s.dbSet[name] {
			s.dbSet[name] = true
			s.inv.Databases = append(s.inv.Databases, name)
		}
	case strings.HasPrefix(rel, "dnszones/") && regular:
		name := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
		if domainRE.MatchString(name) && !s.dnsSet[name] {
			s.dnsSet[name] = true
			s.inv.DNSZones = append(s.inv.DNSZones, strings.ToLower(name))
		}
	}
}

// readMetadata reads a small metadata member's body into the inventory.
func (s *cpanelScan) readMetadata(tr *tar.Reader, rel string) {
	apply := s.metadataReader(rel)
	if apply == nil {
		return
	}
	if b, e := io.ReadAll(io.LimitReader(tr, maxMetadataBytes)); e == nil {
		apply(string(b))
	}
}

// metadataReader returns what a metadata member's body sets: the account name,
// the main domain, the mailbox list, the forwarder count or the crontab. It
// returns nil for a member that carries no metadata.
func (s *cpanelScan) metadataReader(rel string) func(body string) {
	switch {
	case rel == "cp/backup_user" || rel == "cp/username":
		return func(body string) { s.inv.Username = strings.TrimSpace(body) }
	case strings.HasPrefix(rel, "cp/userdata/") && strings.HasSuffix(rel, "/main"):
		return func(body string) { parseMainMetadata(&s.inv, body, rel) }
	case strings.HasPrefix(rel, "homedir/etc/") && strings.HasSuffix(rel, "/shadow"):
		return func(body string) { parseMailboxNames(&s.inv, body) }
	case strings.HasPrefix(rel, "va/"):
		return func(body string) { s.inv.AliasCount += countAliases(body) }
	case rel == "cron":
		return func(body string) { s.cronBody = body }
	}
	return nil
}

// finish adds the warnings a completed scan calls for, parses the crontab and
// sorts the lists.
func (s *cpanelScan) finish() {
	inv := &s.inv
	if inv.PrimaryDomain == "" && len(inv.DNSZones) > 0 {
		inv.PrimaryDomain = inv.DNSZones[0]
		inv.Warnings = append(inv.Warnings, "Primary domain was inferred from a DNS zone rather than account metadata.")
	}
	if inv.PrimaryDomain == "" {
		inv.Warnings = append(inv.Warnings, "Primary domain could not be determined automatically; it must be chosen before import.")
	}
	if inv.WebFiles == 0 {
		inv.Warnings = append(inv.Warnings, "No web files were found under public_html.")
	}
	if s.cronBody != "" {
		var skipped int
		inv.CronJobs, skipped = parseCronJobs(s.cronBody)
		if skipped > 0 {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%d cron line(s) are unsupported and will not be transferred.", skipped))
		}
	}
	sort.Strings(inv.Databases)
	sort.Strings(inv.DNSZones)
	sort.Strings(inv.Mailboxes)
}

// isSSLCertificateMember reports whether a member is a source SSL certificate.
// cPanel stores them under sslcerts/ or the account home's ssl/ tree; only .crt
// members are counted so keys and bundles are not double-counted.
func isSSLCertificateMember(rel string) bool {
	low := strings.ToLower(rel)
	if !strings.HasSuffix(low, ".crt") {
		return false
	}
	return strings.HasPrefix(low, "sslcerts/") ||
		strings.HasPrefix(low, "homedir/ssl/certs/") ||
		(strings.HasPrefix(low, "homedir/ssl/") && strings.Count(low, "/") == 2)
}

// parseCronJobs parses a cPanel crontab dump into standard five-field jobs,
// carrying a preceding comment onto each job. Environment assignments and
// non-standard schedules (@reboot etc.) are unsupported and counted as skipped;
// the job list is capped at 100 entries.
func parseCronJobs(body string) ([]CronJob, int) {
	out := make([]CronJob, 0)
	skipped := 0
	comment := ""
	for raw := range strings.SplitSeq(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			comment = ""
			continue
		}
		if after, ok := strings.CutPrefix(line, "#"); ok {
			comment = strings.TrimSpace(after)
			if len(comment) > 200 {
				comment = comment[:200]
			}
			continue
		}
		if cronEnvRE.MatchString(line) || strings.HasPrefix(line, "@") {
			skipped++
			comment = ""
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || len(out) >= 100 {
			skipped++
			comment = ""
			continue
		}
		out = append(out, CronJob{
			Minute: fields[0], Hour: fields[1], Day: fields[2],
			Month: fields[3], Weekday: fields[4],
			Command: strings.Join(fields[5:], " "), Comment: comment,
		})
		comment = ""
	}
	return out, skipped
}

func unsafeMember(h *tar.Header) bool {
	n := strings.ReplaceAll(h.Name, "\\", "/")
	if strings.HasPrefix(n, "/") {
		return true
	}
	if slices.Contains(strings.Split(n, "/"), "..") {
		return true
	}
	switch h.Typeflag {
	case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return true
	}
	return false
}

func cleanMember(name string) string {
	return strings.TrimPrefix(path.Clean(strings.ReplaceAll(name, "\\", "/")), "./")
}

func splitArchiveRoot(name string) (root, rel string) {
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 && (strings.HasPrefix(parts[0], "backup-") || strings.HasPrefix(parts[0], "cpmove-")) {
		return parts[0], parts[1]
	}
	return "", name
}

func parseMainMetadata(inv *Inventory, body, rel string) {
	parts := strings.Split(rel, "/")
	if inv.Username == "" && len(parts) >= 4 {
		inv.Username = parts[2]
	}
	for line := range strings.SplitSeq(body, "\n") {
		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(p[0]))
		value := strings.Trim(strings.TrimSpace(p[1]), `"'`)
		if (key == "main_domain" || key == "domain") && domainRE.MatchString(value) {
			inv.PrimaryDomain = strings.ToLower(value)
			return
		}
	}
}

// parseMailboxNames extracts mailbox local parts from a cPanel per-domain
// shadow file (homedir/etc/<domain>/shadow), skipping cPanel-internal accounts.
func parseMailboxNames(inv *Inventory, body string) {
	seen := make(map[string]bool, len(inv.Mailboxes))
	for _, v := range inv.Mailboxes {
		seen[v] = true
	}
	for line := range strings.SplitSeq(body, "\n") {
		p := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(p) != 2 {
			continue
		}
		local := strings.ToLower(strings.TrimSpace(p[0]))
		if !localPartRE.MatchString(local) || strings.HasPrefix(local, "__cpanel") || seen[local] {
			continue
		}
		seen[local] = true
		inv.Mailboxes = append(inv.Mailboxes, local)
	}
}

// countAliases counts forwarder entries in a cPanel valias file (va/<domain>).
func countAliases(body string) int {
	n := 0
	for line := range strings.SplitSeq(body, "\n") {
		p := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(p) == 2 && strings.TrimSpace(p[0]) != "" && strings.TrimSpace(p[1]) != "" {
			n++
		}
	}
	return n
}
