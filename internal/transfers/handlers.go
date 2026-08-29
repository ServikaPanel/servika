package transfers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"

	"servika/internal/archivex"
	"servika/internal/credentials"
	"servika/internal/cron"
	"servika/internal/domains"
	"servika/internal/httpx"
	"servika/internal/mail"
	"servika/internal/provisioner"
	"servika/internal/sqlimport"

	"github.com/go-chi/chi/v5"
)

const MaxUploadBytes = int64(20 << 30)

// commandPath mirrors the restore path; transfer subprocesses run with an
// explicit, minimal environment so panel secrets from os.Environ() are never
// inherited by mysql/tar/find.
const commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func newTransferCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=" + commandPath, "HOME=/root"}
	return command
}

type Handlers struct {
	DB      *sql.DB
	Domains *domains.Handlers
	Mail    *mail.Handlers
	Cron    *cron.Handlers
}

// Analyze accepts a cPanel full backup and returns an inventory. It never
// extracts or persists archive contents.
func (h *Handlers) Analyze(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, httpx.LargeTransferDeadline); err != nil {
		log.Printf("transfer analyze: could not extend the socket deadline: %v", err)
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	// The inventory scan reads the archive strictly front-to-back, so there is no
	// need to spool the upload to disk: ParseMultipartForm would copy a file of up
	// to 20 GiB into the temp dir. MultipartReader streams the body directly.
	mr, err := r.MultipartReader()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a multipart body is required")
		return
	}
	var f *multipart.Part
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "could not read the upload or the size limit was exceeded")
			return
		}
		if part.FormName() == "archive" {
			f = part
			break
		}
		_ = part.Close()
	}
	if f == nil {
		httpx.WriteError(w, http.StatusBadRequest, "a cPanel .tar.gz backup is required in the archive field")
		return
	}
	defer func() { _ = f.Close() }()
	low := strings.ToLower(f.FileName())
	if !strings.HasSuffix(low, ".tar.gz") && !strings.HasSuffix(low, ".tgz") {
		httpx.WriteError(w, http.StatusBadRequest, "the first release only supports cPanel .tar.gz/.tgz full backups")
		return
	}
	inv, err := AnalyzeCPanel(f)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrArchiveTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		httpx.WriteError(w, status, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, inv)
}

type importResponse struct {
	OK          bool             `json:"ok"`
	DomainID    int64            `json:"domain_id"`
	Domain      string           `json:"domain"`
	SystemUser  string           `json:"system_user"`
	WebFiles    int              `json:"web_files"`
	Databases   []DBMap          `json:"databases"`
	Mailboxes   []MailCredential `json:"mailboxes"`
	Aliases     int              `json:"aliases"`
	CronJobs    int              `json:"cron_jobs"`
	SSLImported bool             `json:"ssl_imported"`
	SSLExpires  string           `json:"ssl_expires,omitempty"`
	Skipped     []string         `json:"skipped"`
	Source      Inventory        `json:"source"`
}

// MailCredential carries a newly provisioned mailbox address and its one-time
// password back to the client; the source cPanel password hash is never reused.
type MailCredential struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DBMap struct {
	Source string `json:"source"`
	Target string `json:"target"`
	User   string `json:"user"`
}

// Import creates a new Servika domain and restores the web root plus the
// cPanel databases. Additional databases share the domain's default DB user,
// matching Servika's supported one-user-to-many-databases model.
func (h *Handlers) Import(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, httpx.LargeTransferDeadline); err != nil {
		log.Printf("transfer import: could not extend the socket deadline: %v", err)
	}

	if h.Domains == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain provider is not ready")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	// #nosec G120 -- body is bounded by MaxBytesReader above, so parsing cannot exhaust memory.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read the upload or the size limit was exceeded")
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	f, _, err := r.FormFile("archive")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "the archive field is required")
		return
	}
	defer func() { _ = f.Close() }()

	tmp, err := os.CreateTemp("", "servika-cpanel-*.tar.gz")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create a temporary archive")
		return
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	_, copyErr := io.Copy(tmp, f)
	closeErr := tmp.Close() // close on the error path too, or the fd leaks
	if copyErr != nil || closeErr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not save the archive")
		return
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	src, err := os.Open(tmpPath)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not open the archive")
		return
	}
	inv, err := AnalyzeCPanel(src)
	_ = src.Close()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, ok := h.provisionDomain(w, r, inv)
	if !ok {
		return
	}
	committed := false
	defer func() {
		if !committed {
			h.rollbackDomain(r, created.ID)
		}
	}()

	// Read the archive's small helper members (the SSL pair plus the alias table)
	// in a single pass; none of the steps below rescan the archive.
	extras, err := readArchiveExtras(tmpPath, inv)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read archive helper files: "+err.Error())
		return
	}

	if err := h.restoreWeb(r.Context(), tmpPath, inv.ArchiveRoot, created.SystemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not transfer web files: "+err.Error())
		return
	}
	dbMaps := databaseMappings(inv.Databases, created.SystemUser, created.DBName, created.DBUser)
	for i, m := range dbMaps {
		// The first database reuses the domain's default DB (created by
		// domains.Create); each additional one is created and attached to the
		// same DB user, so rollback via domains.Delete drops them all.
		if i > 0 {
			if err := credentials.MySQLCreateDBForUser(h.DB, created.ID, m.Target, created.DBUser); err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "could not create the additional database: "+err.Error())
				return
			}
		}
	}
	// Import every dump in a SINGLE archive pass; a per-dump pass meant one full
	// gzip decompress per database (gzip has no random access).
	if err := h.restoreDatabases(r.Context(), tmpPath, inv.ArchiveRoot, dbMaps); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not transfer the database: "+err.Error())
		return
	}
	mailCreds, aliasCount, err := h.importMail(r, tmpPath, extras, inv, created.ID, created.DomainName, created.SystemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not transfer email: "+err.Error())
		return
	}
	cronCount, err := h.importCron(r, inv, created.ID, created.SystemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not transfer cron jobs: "+err.Error())
		return
	}
	sslImported, sslExpires, sslWarning, err := h.importSSL(r, extras, inv, created.ID, created.DomainName)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not transfer the SSL certificate: "+err.Error())
		return
	}
	skipped := []string{}
	if sslWarning != "" {
		skipped = append(skipped, sslWarning)
	}
	committed = true
	httpx.WriteJSON(w, http.StatusCreated, importResponse{
		OK: true, DomainID: created.ID, Domain: created.DomainName,
		SystemUser: created.SystemUser, WebFiles: inv.WebFiles,
		Databases: dbMaps, Mailboxes: mailCreds, Aliases: aliasCount, CronJobs: cronCount,
		SSLImported: sslImported, SSLExpires: sslExpires, Source: inv, Skipped: skipped,
	})
}

// importSSL installs the source account's leaf certificate (plus CA bundle when
// present) for the primary domain, validated against the target domain. A
// mismatched or unusable certificate is skipped with a warning rather than
// failing the whole transfer; only unexpected I/O errors abort the import.
func (h *Handlers) importSSL(r *http.Request, extras archiveExtras, inv Inventory, domainID int64, targetDomain string) (bool, string, string, error) {
	if inv.SSLCerts == 0 {
		return false, "", "", nil
	}
	certPEM, keyPEM, err := extras.sslPair()
	if errors.Is(err, errMemberNotFound) {
		return false, "", "No matching private key was found for the source SSL certificate; SSL was not transferred.", nil
	}
	if err != nil {
		return false, "", "", err
	}
	certPath, keyPath, expires, err := provisioner.InstallImportedSSL(targetDomain, certPEM, keyPEM)
	if errors.Is(err, provisioner.ErrImportedSSLInvalid) {
		return false, "", err.Error() + "; SSL was not transferred.", nil
	}
	if err != nil {
		return false, "", "", err
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET ssl_enabled=1, ssl_source='imported', cert_path=?, key_path=?, ssl_expiry=? WHERE id=?`,
		certPath, keyPath, expires, domainID); err != nil {
		return false, "", "", err
	}
	if err := provisioner.RerenderVhost(h.DB, domainID); err != nil {
		return false, "", "", err
	}
	return true, expires.UTC().Format("2006-01-02"), "", nil
}

// archiveExtras holds the archive's small helper members (the SSL pair and the
// alias table) across the layouts cPanel uses. Every member is read in a single
// pass; see readSmallTarMembers.
type archiveExtras struct {
	certCandidates   []string
	keyCandidates    []string
	bundleCandidates []string
	aliasMember      string
	members          map[string][]byte
}

// readArchiveExtras collects the SSL certificate/key/bundle candidates and the
// alias table for the primary domain in one archive pass.
func readArchiveExtras(archivePath string, inv Inventory) (archiveExtras, error) {
	e := archiveExtras{members: map[string][]byte{}}
	root, domain := inv.ArchiveRoot, inv.PrimaryDomain
	if domain == "" {
		return e, nil
	}
	e.certCandidates = []string{
		root + "/sslcerts/" + domain + ".crt",
		root + "/homedir/ssl/certs/" + domain + ".crt",
		root + "/homedir/ssl/" + domain + ".crt",
	}
	e.keyCandidates = []string{
		root + "/sslkeys/" + domain + ".key",
		root + "/homedir/ssl/private/" + domain + ".key",
		root + "/homedir/ssl/" + domain + ".key",
	}
	e.bundleCandidates = []string{
		root + "/sslcerts/" + domain + ".cabundle",
		root + "/homedir/ssl/certs/" + domain + ".cabundle",
		root + "/homedir/ssl/" + domain + ".cabundle",
	}
	e.aliasMember = root + "/va/" + domain

	wants := append([]string{}, e.certCandidates...)
	wants = append(wants, e.keyCandidates...)
	wants = append(wants, e.bundleCandidates...)
	wants = append(wants, e.aliasMember)
	members, err := readSmallTarMembers(archivePath, wants)
	if err != nil {
		return e, err
	}
	e.members = members
	return e, nil
}

// first returns the body of the first candidate present in the collected members.
func (e archiveExtras) first(candidates []string) ([]byte, bool) {
	for _, c := range candidates {
		if body, ok := e.members[c]; ok && len(body) > 0 {
			return body, true
		}
	}
	return nil, false
}

// sslPair returns the leaf certificate (with the CA bundle appended when present)
// and its private key, or errMemberNotFound when either is missing.
func (e archiveExtras) sslPair() ([]byte, []byte, error) {
	certPEM, ok := e.first(e.certCandidates)
	if !ok {
		return nil, nil, errMemberNotFound
	}
	keyPEM, ok := e.first(e.keyCandidates)
	if !ok {
		return nil, nil, errMemberNotFound
	}
	if bundle, ok := e.first(e.bundleCandidates); ok {
		certPEM = append(append(append([]byte{}, certPEM...), '\n'), bundle...)
	}
	return certPEM, keyPEM, nil
}

// importCron recreates each supported cPanel cron job through the panel's own
// create path, rewriting the source home prefix onto the target tenant's home.
// It runs after the web/database/mail restore so a failure still rolls the whole
// domain back via the caller's deferred rollbackDomain.
func (h *Handlers) importCron(r *http.Request, inv Inventory, domainID int64, targetUser string) (int, error) {
	if len(inv.CronJobs) == 0 {
		return 0, nil
	}
	if h.Cron == nil {
		return 0, errors.New("cron provider is not ready")
	}
	created := 0
	for _, job := range inv.CronJobs {
		command := job.Command
		if inv.Username != "" {
			command = strings.ReplaceAll(command, "/home/"+inv.Username+"/", "/home/"+targetUser+"/")
		}
		body, _ := json.Marshal(map[string]string{
			"minute": job.Minute, "hour": job.Hour, "day": job.Day,
			"month": job.Month, "week": job.Weekday,
			"command": command, "comment": job.Comment,
		})
		req := domainRequest(r, http.MethodPost, "/cron", domainID, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.Cron.Create(rr, req)
		if rr.Code != http.StatusCreated {
			return 0, fmt.Errorf("job %d: %s", created+1, strings.TrimSpace(rr.Body.String()))
		}
		created++
	}
	return created, nil
}

type createdDomain struct {
	ID         int64  `json:"id"`
	DomainName string `json:"domain_name"`
	SystemUser string `json:"system_user"`
	DBName     string `json:"db_name"`
	DBUser     string `json:"db_user"`
}

// databaseMappings maps each source cPanel database name to a Servika target.
// The first source reuses the domain's default database; each additional source
// is namespaced as "<system_user>_<sanitized-suffix>", truncated to MySQL's
// 64-char identifier limit and de-duplicated with a numeric tail.
func databaseMappings(sources []string, sk, defaultDB, dbUser string) []DBMap {
	out := make([]DBMap, 0, len(sources))
	used := map[string]bool{defaultDB: true}
	for i, source := range sources {
		target := defaultDB
		if i > 0 {
			suffix := dbSuffix(source)
			maxSuffix := max(64-len(sk)-1, 1)
			if len(suffix) > maxSuffix {
				suffix = suffix[:maxSuffix]
			}
			target = sk + "_" + suffix
			base := target
			for n := 2; used[target]; n++ {
				tail := "_" + strconv.Itoa(n)
				limit := 64 - len(tail)
				if len(base) > limit {
					base = base[:limit]
				}
				target = base + tail
			}
		}
		used[target] = true
		out = append(out, DBMap{Source: source, Target: target, User: dbUser})
	}
	return out
}

func dbSuffix(source string) string {
	s := strings.ToLower(source)
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	s = strings.Trim(b.String(), "_")
	if s == "" {
		return "db"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.TrimRight(s, "_")
}

// provisionDomain drives domains.Create in-process so the full provisioning
// side effects (system user, vhost, FTP, database, php-fpm pool) are reused.
// On any non-201 it copies domains.Create's own error response to the client
// and returns ok=false.
func (h *Handlers) provisionDomain(w http.ResponseWriter, r *http.Request, inv Inventory) (createdDomain, bool) {
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if domain == "" {
		domain = inv.PrimaryDomain
	}
	if domain == "" {
		httpx.WriteError(w, http.StatusBadRequest, "the primary domain could not be determined")
		return createdDomain{}, false
	}
	customerID, err := requiredInt64(r.FormValue("customer_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "customer_id is required")
		return createdDomain{}, false
	}
	phpVersion := strings.TrimSpace(r.FormValue("php_version"))
	if phpVersion == "" {
		phpVersion = "8.3"
	}
	var planID *int64
	if s := strings.TrimSpace(r.FormValue("plan_id")); s != "" {
		v, e := requiredInt64(s)
		if e != nil {
			httpx.WriteError(w, http.StatusBadRequest, "plan_id is invalid")
			return createdDomain{}, false
		}
		planID = &v
	}

	createBody, _ := json.Marshal(map[string]any{
		"domain_name": domain, "php_version": phpVersion,
		"customer_id": customerID, "plan_id": planID,
	})
	cr := httptest.NewRequest(http.MethodPost, "/api/v1/domains", bytes.NewReader(createBody)).
		WithContext(r.Context())
	cr.Header.Set("Content-Type", "application/json")
	cw := httptest.NewRecorder()
	h.Domains.Create(cw, cr)
	if cw.Code != http.StatusCreated {
		copyRecorded(w, cw)
		return createdDomain{}, false
	}
	var created createdDomain
	if err := json.Unmarshal(cw.Body.Bytes(), &created); err != nil || created.ID <= 0 {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the created domain response")
		return createdDomain{}, false
	}
	return created, true
}

func requiredInt64(s string) (int64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("invalid number")
	}
	return v, nil
}

func copyRecorded(w http.ResponseWriter, rr *httptest.ResponseRecorder) {
	for k, values := range rr.Header() {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rr.Code)
	_, _ = w.Write(rr.Body.Bytes())
}

func (h *Handlers) rollbackDomain(r *http.Request, id int64) {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", strconv.FormatInt(id, 10))
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+strconv.FormatInt(id, 10), nil).
		WithContext(ctx)
	h.Domains.Delete(httptest.NewRecorder(), req)
}

// restoreWeb extracts the archive's public_html subtree into the freshly
// provisioned tenant home as root, then fixes ownership and SELinux context —
// the same canonical pattern backups.Restore uses. Subprocesses run with a
// minimal environment (no inherited panel secrets).
func (h *Handlers) restoreWeb(ctx context.Context, archivePath, root, sk string) error {
	if !strings.HasPrefix(sk, "c_") || root == "" {
		return errors.New("unsafe target")
	}
	// The extraction below hands the untrusted cPanel archive to the system tar,
	// which honors symlink/hardlink members and ".." paths — a member could escape
	// the tenant public_html or clobber a file through a planted symlink. Pre-scan
	// with archivex first (rejects symlink/hardlink/device/fifo members and unsafe
	// paths) so a malicious archive is refused before any file is written. The
	// upload is already capped at MaxUploadBytes, so no decompression-bomb limits
	// are needed here (zero-value Limits = unbounded).
	if err := archivex.Scan(ctx, archivePath, archivex.TypeTARGzip, archivex.Limits{}); err != nil {
		return fmt.Errorf("unsafe archive: %w", err)
	}
	target := "/home/" + sk + "/public_html"
	if out, err := newTransferCommand(ctx, "find", target, "-mindepth", "1", "-delete").CombinedOutput(); err != nil {
		return fmt.Errorf("clearing target: %s", strings.TrimSpace(string(out)))
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	member := root + "/homedir/public_html"
	cmd := newTransferCommand(ctx, "tar", "-xz", "-f", "-", "-C", target, "--strip-components=3", member)
	cmd.Stdin = f
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar: %s", strings.TrimSpace(string(out)))
	}
	if out, err := newTransferCommand(ctx, "chown", "-R", sk+":"+sk, target).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %s", strings.TrimSpace(string(out)))
	}
	_, _ = newTransferCommand(ctx, "restorecon", "-RF", target).CombinedOutput()
	return nil
}

// restoreDatabases imports every SQL dump in a SINGLE archive pass, dropping each
// dump's CREATE DATABASE / USE statements so it lands in Servika's own database
// rather than the source's. A per-dump pass meant one full gzip decompress per
// database (gzip has no random access). The archive is read sequentially; each
// member is routed to its mapped target as it is reached. mysql runs with a
// minimal environment.
func (h *Handlers) restoreDatabases(ctx context.Context, archivePath, root string, maps []DBMap) error {
	targets := make(map[string]string, len(maps)) // archive member -> target DB
	for _, m := range maps {
		targets[path.Clean(root+"/mysql/"+m.Source+".sql")] = m.Target
	}
	if len(targets) == 0 {
		return nil
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	remaining := len(targets)
	for remaining > 0 {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		targetDB, ok := targets[path.Clean(hdr.Name)]
		if !ok || hdr.Typeflag != tar.TypeReg {
			continue
		}
		delete(targets, path.Clean(hdr.Name))
		remaining--
		if err := pipeDumpToMySQL(ctx, tr, targetDB); err != nil {
			return err
		}
	}
	if remaining > 0 {
		missing := make([]string, 0, remaining)
		for _, targetDB := range targets {
			missing = append(missing, targetDB)
		}
		sort.Strings(missing)
		return fmt.Errorf("the SQL dump was not found in the archive: %s", strings.Join(missing, ", "))
	}
	return nil
}

// pipeDumpToMySQL imports one SQL dump out of a cPanel archive into targetDB.
//
// The dump was produced on somebody else's server and is hostile input, the
// same as everything else this package ingests. It used to run on the panel's
// own root MariaDB connection, where `mysql <db>` sets a DEFAULT schema and
// imposes no privilege boundary at all, guarded only by a line filter that
// dropped `USE ` and `CREATE DATABASE `. That filter never saw
// `/*!50000 USE mysql */`, so an archive carrying a GRANT could take the whole
// database server, with every other tenant's data on it. internal/sqlimport
// imports as an account privileged on targetDB alone and lets MariaDB draw the
// line instead; it still drops the schema-selection lines, now openly as a
// compatibility measure rather than as a defence.
func pipeDumpToMySQL(ctx context.Context, dump io.Reader, targetDB string) error {
	return sqlimport.Import(ctx, targetDB, dump)
}

// importMail provisions the domain's mail infrastructure, recreates each source
// mailbox with a fresh password (the cPanel hash is never reused), restores its
// Maildir, and recreates forwarders. It runs after the web/database restore so a
// mail failure still rolls the whole domain back via the caller's deferred
// rollbackDomain.
func (h *Handlers) importMail(r *http.Request, archivePath string, extras archiveExtras, inv Inventory, domainID int64, targetDomain, sk string) ([]MailCredential, int, error) {
	if len(inv.Mailboxes) == 0 && inv.AliasCount == 0 && inv.MailFiles == 0 {
		return []MailCredential{}, 0, nil
	}
	if h.Mail == nil {
		return nil, 0, errors.New("mail provider is not ready")
	}
	if err := mail.EnableDomain(r.Context(), h.DB, domainID); err != nil {
		return nil, 0, err
	}
	creds := make([]MailCredential, 0, len(inv.Mailboxes))
	locals := make([]string, 0, len(inv.Mailboxes))
	for _, local := range inv.Mailboxes {
		body, _ := json.Marshal(map[string]string{"local_part": local})
		req := domainRequest(r, http.MethodPost, "/mail", domainID, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.Mail.Create(rr, req)
		if rr.Code != http.StatusCreated {
			return nil, 0, fmt.Errorf("mailbox %s: %s", local, strings.TrimSpace(rr.Body.String()))
		}
		var result struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			return nil, 0, err
		}
		creds = append(creds, MailCredential{Email: result.Email, Password: result.Password})
		locals = append(locals, local)
	}
	if inv.PrimaryDomain != "" && len(locals) > 0 {
		if err := h.restoreMailboxes(r.Context(), archivePath, inv.ArchiveRoot, inv.PrimaryDomain, locals, sk); err != nil {
			return nil, 0, fmt.Errorf("mailbox messages: %w", err)
		}
	}

	aliases := readAliases(extras, inv.PrimaryDomain, targetDomain)
	created := 0
	for _, a := range aliases {
		body, _ := json.Marshal(map[string]string{"local_part": a.Local, "destination": a.Destination})
		req := domainRequest(r, http.MethodPost, "/mail/aliases", domainID, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.Mail.CreateAlias(rr, req)
		if rr.Code == http.StatusCreated {
			created++
			continue
		}
		return nil, 0, fmt.Errorf("alias %s: %s", a.Local, strings.TrimSpace(rr.Body.String()))
	}
	return creds, created, nil
}

// domainRequest builds an in-process request carrying the chi URL param `id`
// that the mail handlers read to resolve the target domain.
func domainRequest(parent *http.Request, method, url string, domainID int64, body io.Reader) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", strconv.FormatInt(domainID, 10))
	ctx := context.WithValue(parent.Context(), chi.RouteCtxKey, rc)
	req := httptest.NewRequest(method, url, body).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// restoreMailboxes extracts every source Maildir in a SINGLE tar call, then fixes
// ownership and SELinux context. A per-box call reopened the (up to 20 GiB)
// archive once per mailbox. The member path is
// root/homedir/mail/<source-domain>/<local>, so stripping 4 components and
// targeting /home/<sk>/mail drops each box into its own directory. Subprocesses
// run with a minimal environment.
func (h *Handlers) restoreMailboxes(ctx context.Context, archivePath, root, sourceDomain string, locals []string, sk string) error {
	if !strings.HasPrefix(sk, "c_") || root == "" {
		return errors.New("unsafe target")
	}
	// Same pre-scan restoreWeb performs, for the same reason: the system tar below
	// honors symlink/hardlink members and ".." paths, so an untrusted cPanel archive
	// could escape /home/<sk>/mail. This path is reached independently of the web
	// restore, so it cannot rely on that call having scanned the archive.
	if err := archivex.Scan(ctx, archivePath, archivex.TypeTARGzip, archivex.Limits{}); err != nil {
		return fmt.Errorf("unsafe archive: %w", err)
	}
	target := "/home/" + sk + "/mail"
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	args := []string{"tar", "-xz", "-f", "-", "-C", target, "--strip-components=4"}
	for _, local := range locals {
		args = append(args, root+"/homedir/mail/"+sourceDomain+"/"+local)
	}
	cmd := newTransferCommand(ctx, args[0], args[1:]...)
	cmd.Stdin = f
	if out, err := cmd.CombinedOutput(); err != nil {
		// A mailbox present only in metadata may have no Maildir in the archive;
		// tar does not treat that as fatal but does taint the exit code. The other
		// boxes were still extracted, so fix context and report success.
		if strings.Contains(string(out), "Not found in archive") || strings.Contains(string(out), "Not found") {
			_, _ = newTransferCommand(ctx, "chown", "-R", sk+":"+sk, target).CombinedOutput()
			_, _ = newTransferCommand(ctx, "restorecon", "-RF", target).CombinedOutput()
			return nil
		}
		return fmt.Errorf("tar: %s", strings.TrimSpace(string(out)))
	}
	if out, err := newTransferCommand(ctx, "chown", "-R", sk+":"+sk, target).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %s", strings.TrimSpace(string(out)))
	}
	_, _ = newTransferCommand(ctx, "restorecon", "-RF", target).CombinedOutput()
	return nil
}

type aliasImport struct {
	Local       string
	Destination string
}

// readAliases parses the source valias file and rewrites each forwarder onto the
// target domain, dropping pipe/include destinations that Servika cannot host.
func readAliases(extras archiveExtras, sourceDomain, targetDomain string) []aliasImport {
	if sourceDomain == "" {
		return []aliasImport{}
	}
	body, ok := extras.members[extras.aliasMember]
	if !ok {
		return []aliasImport{}
	}
	return parseAliasBody(body, sourceDomain, targetDomain)
}

// parseAliasBody parses a source alias file (`local: dest[,dest2]` per line),
// rewrites each forwarder onto the target domain, and drops pipe/include
// destinations that Servika cannot host. It is shared by the cpmove archive
// import and the live SSH migration.
func parseAliasBody(body []byte, sourceDomain, targetDomain string) []aliasImport {
	out := []aliasImport{}
	for line := range strings.SplitSeq(string(body), "\n") {
		p := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(p) != 2 {
			continue
		}
		source := strings.TrimSpace(p[0])
		destRaw := strings.TrimSpace(p[1])
		if source == "" || destRaw == "" || strings.HasPrefix(destRaw, ":") || strings.HasPrefix(destRaw, "|") {
			continue
		}
		local := strings.TrimSuffix(strings.ToLower(source), "@"+strings.ToLower(sourceDomain))
		if local == "*" {
			local = ""
		}
		if local != "" && !localPartRE.MatchString(local) {
			continue
		}
		var dests []string
		for d := range strings.SplitSeq(destRaw, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if !strings.Contains(d, "@") && localPartRE.MatchString(d) {
				d += "@" + targetDomain
			}
			d = strings.ReplaceAll(d, "@"+strings.ToLower(sourceDomain), "@"+targetDomain)
			if strings.Contains(d, "@") {
				dests = append(dests, d)
			}
		}
		if len(dests) > 0 {
			out = append(out, aliasImport{Local: local, Destination: strings.Join(dests, ",")})
		}
	}
	return out
}

var errMemberNotFound = errors.New("archive member not found")

// readSmallTarMembers collects the requested small members in a SINGLE archive
// pass.
//
// WHY BATCHED: the archive is gzip, i.e. no random access — every seek reopens
// and re-decompresses the whole file. A per-member call pushed a 20 GiB cPanel
// backup's transfer into hours (9 SSL candidates × a full decompress on their
// own). Members that are absent simply never appear in the result map.
func readSmallTarMembers(archivePath string, wants []string) (map[string][]byte, error) {
	wanted := make(map[string]string, len(wants)) // cleaned name -> original request
	for _, w := range wants {
		if w != "" {
			wanted[path.Clean(w)] = w
		}
	}
	found := make(map[string][]byte, len(wanted))
	if len(wanted) == 0 {
		return found, nil
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for len(found) < len(wanted) {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		req, ok := wanted[path.Clean(hdr.Name)]
		if !ok || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > maxMetadataBytes {
			return nil, ErrArchiveTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxMetadataBytes))
		if err != nil {
			return nil, err
		}
		found[req] = body
	}
	return found, nil
}
