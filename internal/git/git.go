// Package git provides per-domain Git deployment with deploy keys, repositories, and webhook auto-pull.
package git

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/netguard"
	"servika/internal/secret"

	"github.com/go-chi/chi/v5"
)

type Repo struct {
	ID           int64  `json:"id"`
	DomainID     int64  `json:"domain_id"`
	RepoURL      string `json:"repo_url"`
	Branch       string `json:"branch"`
	TargetDir    string `json:"target_dir"`
	DeployKeyPub string `json:"deploy_key_pub"`
	// WebhookSecret is the URL path token. It only LOCATES the repository and is
	// not a credential: nginx records the full request line for every delivery.
	WebhookSecret string `json:"webhook_secret"`
	// WebhookSigningKey is the HMAC-SHA256 key. It must never equal
	// WebhookSecret, or the signature proves nothing beyond the URL it exists to
	// backstop.
	WebhookSigningKey string `json:"webhook_signing_key"`
	LastSync          string `json:"last_sync,omitempty"`
	LastCommit        string `json:"last_commit,omitempty"`
	LastStatus        string `json:"last_status"`
	CreatedAt         string `json:"created_at"`
}

type Handlers struct {
	DB *sql.DB
}

const selectAll = `SELECT id, domain_id, repo_url, branch, target_dir,
  deploy_key_pub, webhook_secret, webhook_signing_key,
  COALESCE(DATE_FORMAT(last_sync,'%Y-%m-%d %H:%i'),''),
  last_commit, last_status,
  DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
  FROM git_repos`

func scan(rs interface{ Scan(...any) error }) (Repo, error) {
	var r Repo
	err := rs.Scan(&r.ID, &r.DomainID, &r.RepoURL, &r.Branch, &r.TargetDir,
		&r.DeployKeyPub, &r.WebhookSecret, &r.WebhookSigningKey,
		&r.LastSync, &r.LastCommit, &r.LastStatus, &r.CreatedAt)
	// Redact any embedded credentials (e.g. a GitHub PAT in https://<pat>@github.com/...)
	// before the Repo is serialized to an API response. The DB keeps the full URL for
	// cloning; only the response value is scrubbed.
	r.RepoURL = redactURLCredentials(r.RepoURL)
	return r, err
}

// redactURLCredentials removes the userinfo component from an http(s) or ssh URL so a
// stored access token is never returned in an API response. Non-URL forms (git@host:path)
// and plain URLs are returned unchanged.
func redactURLCredentials(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

func (h *Handlers) lookupDomain(r *http.Request) (id int64, systemUser string, err error) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser)
	return
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	targetDirPattern = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	branchPattern    = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
)

func validTargetDir(targetDir string) bool {
	return targetDir != "" && targetDir == strings.TrimSpace(targetDir) && len(targetDir) <= 128 &&
		!filepath.IsAbs(targetDir) && filepath.Clean(targetDir) != "." &&
		!strings.Contains(targetDir, "..") && targetDirPattern.MatchString(targetDir)
}

func validBranch(branch string) bool {
	return branch != "" && branch == strings.TrimSpace(branch) && len(branch) <= 128 &&
		!strings.HasPrefix(branch, "-") && !strings.Contains(branch, "..") &&
		branchPattern.MatchString(branch)
}

func validRepoURL(repoURL string) bool {
	if repoURL != strings.TrimSpace(repoURL) || len(repoURL) == 0 || len(repoURL) > 2048 {
		return false
	}
	if !strings.HasPrefix(repoURL, "https://") &&
		!strings.HasPrefix(repoURL, "ssh://") &&
		!strings.HasPrefix(repoURL, "git@") {
		return false
	}
	return !strings.ContainsAny(repoURL, " \t\r\n;&|`$(){}[]<>\\\"'")
}

// clearDirectoryContents empties the deploy target before a clone, leaving the
// directory itself in place. targetDir is chosen by the tenant and this runs as
// root, so every component is resolved with openat2(RESOLVE_BENEATH|
// RESOLVE_NO_SYMLINKS) instead of by path.
//
// Resolving by path was an escape. validTargetDir allows a separator, so
// `target_dir = "pwn/cron.d"` with a tenant symlink at ~/pwn pointing to /etc
// made os.Lstat check only the last component, os.ReadDir list /etc/cron.d and
// os.RemoveAll delete every file in it as root. The os.MkdirAll and chown that
// followed then handed the tenant ownership of that directory, which is a root
// cron job away from running code as root.
func clearDirectoryContents(home, targetDir string) error {
	return files.ClearBeneath(home, targetDir)
}

// deployKeyMaxBytes bounds a public key read back from the tenant's tree. An
// Ed25519 public key line is about 100 bytes; this leaves room for a comment
// while refusing to hold whatever a tenant put there instead.
const deployKeyMaxBytes = 64 << 10

// generateDeployKey creates a passphrase-free Ed25519 key under
// /home/<systemUser>/.ssh/.
//
// Every step goes through the safeio primitives, because this runs as ROOT
// against a directory the TENANT owns. Resolving by path was the escape the
// clone path above already closed: os.MkdirAll accepts an existing symlink,
// ssh-keygen -f writes through whatever the path resolves to, os.WriteFile
// follows a symlink at the final component, and `chown` without -h dereferences
// its operand and hands the tenant ownership of the resolved target. Planting
// ~/.ssh, or ~/.ssh/config, as a symlink therefore made root write a
// fixed-content file anywhere and give it to the tenant, which is a root cron
// drop-in away from code execution as root.
//
// ssh-keygen still writes by path, so it writes into a ROOT-OWNED staging
// directory and the result is published beneath the home afterwards. That is the
// same staging rule the rest of the tree follows for an external tool.
func generateDeployKey(systemUser string) (pubKey string, err error) {
	home := "/home/" + systemUser
	const (
		relDir  = ".ssh"
		relPriv = ".ssh/servika_deploy"
		relPub  = ".ssh/servika_deploy.pub"
	)
	if err := files.MkdirAllBeneath(home, relDir, systemUser); err != nil {
		return "", fmt.Errorf("prepare the deploy key directory: %w", err)
	}
	// Before the early return below, so a tenant who already has a deploy key
	// still gets the pinned host keys. A host installed before this change would
	// otherwise keep the configuration that disabled verification.
	if err := writeSSHTrust(home, systemUser); err != nil {
		return "", err
	}
	if existing, err := files.ReadFileBeneath(home, relPub, deployKeyMaxBytes); err == nil {
		files.RestoreconBeneath(home, relDir)
		return strings.TrimSpace(string(existing)), nil // Reuse the current key.
	}

	stage, err := os.MkdirTemp("", "servika-deploy-key-")
	if err != nil {
		return "", fmt.Errorf("stage the deploy key: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	stagedPriv := filepath.Join(stage, "servika_deploy")
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the only variable is a validated system user in a comment, and the path is this process's own temp directory.
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "deploy@servika/"+systemUser, "-f", stagedPriv).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	privateKey, err := os.ReadFile(stagedPriv)
	if err != nil {
		return "", fmt.Errorf("read the staged deploy key: %w", err)
	}
	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	publicKey, err := os.ReadFile(stagedPriv + ".pub")
	if err != nil {
		return "", fmt.Errorf("read the staged deploy key: %w", err)
	}

	if err := files.WriteFileBeneath(home, relPriv, privateKey, 0o600, systemUser); err != nil {
		return "", fmt.Errorf("install the deploy key: %w", err)
	}
	if err := files.WriteFileBeneath(home, relPub, publicKey, 0o644, systemUser); err != nil {
		return "", fmt.Errorf("install the deploy key: %w", err)
	}
	files.RestoreconBeneath(home, relDir)
	return strings.TrimSpace(string(publicKey)), nil
}

// runAsUserArgs executes a command without a shell as the system user.
// askpassPath is the GIT_ASKPASS helper. It contains NO secret: it echoes the
// username for a "Username" prompt and the SERVIKA_GH_TOKEN env value otherwise.
const askpassPath = "/usr/local/bin/servika-git-askpass" // #nosec G101 -- filesystem path, not a credential

// ensureGitAskpass writes the GIT_ASKPASS helper once (idempotent). The token is
// supplied through the environment at call time, so the file itself is safe to
// keep on disk world-readable.
func ensureGitAskpass() error {
	const script = "#!/bin/sh\n" +
		"# Servika GIT_ASKPASS helper. Reads the token from SERVIKA_GH_TOKEN.\n" +
		"case \"$1\" in\n" +
		"*sername*) echo \"x-access-token\" ;;\n" +
		"*) printf '%s' \"$SERVIKA_GH_TOKEN\" ;;\n" +
		"esac\n"
	if b, err := os.ReadFile(askpassPath); err == nil && string(b) == script {
		return nil
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	return os.WriteFile(askpassPath, []byte(script), 0o755)
}

// gitAuthEnv returns the extra environment that authenticates HTTPS git
// operations with a GitHub token. Empty token => no auth env (deploy-key or
// public repository path). GIT_TERMINAL_PROMPT=0 prevents an interactive hang.
func gitAuthEnv(token string) ([]string, error) {
	if token == "" {
		return nil, nil
	}
	if err := ensureGitAskpass(); err != nil {
		return nil, err
	}
	return []string{
		"GIT_ASKPASS=" + askpassPath,
		"SERVIKA_GH_TOKEN=" + token,
		"GIT_TERMINAL_PROMPT=0",
	}, nil
}

// githubTokenFor returns the decrypted GitHub PAT for a domain, or "" when no
// connection/token exists (public repo or deploy-key flow).
func githubTokenFor(db *sql.DB, domainID int64) string {
	var enc string
	if err := db.QueryRow(`SELECT pat FROM github_connections WHERE domain_id=?`, domainID).Scan(&enc); err != nil {
		return ""
	}
	plain, err := secret.Decrypt(enc)
	if err != nil {
		return ""
	}
	return plain
}

// runAsUserArgs runs a command as the tenant system user. extraEnv holds
// additional KEY=VALUE pairs (for example GIT_ASKPASS and SERVIKA_GH_TOKEN);
// values are passed via the child environment, never on the command line, so a
// token is not exposed in the process listing. sudo needs --preserve-env for the
// specific keys so it forwards them across the privilege drop.
func runAsUserArgs(systemUser, cwd string, extraEnv []string, name string, commandArgs ...string) (string, error) {
	return runAsUserArgsCtx(context.Background(), systemUser, cwd, extraEnv, name, commandArgs...)
}

// runAsUserArgsCtx is runAsUserArgs with a deadline, for the git operations that
// talk to a remote host. Those are the only ones that can block indefinitely: an
// unreachable or deliberately slow remote leaves a git process running for the
// life of the panel, and the request that started it is long gone.
//
// The deadline deliberately does NOT hang off the HTTP request. A clone clears the
// document root before it starts, so cancelling on client disconnect would leave a
// tenant serving a half-written tree; the goal here is only that the process
// cannot run forever.
func runAsUserArgsCtx(ctx context.Context, systemUser, cwd string, extraEnv []string, name string, commandArgs ...string) (string, error) {
	if !strings.HasPrefix(systemUser, "c_") {
		return "", errors.New("invalid system user")
	}
	environment := []string{
		"HOME=/home/" + systemUser,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	environment = append(environment, extraEnv...)
	preserve := ""
	for _, kv := range extraEnv {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if preserve != "" {
				preserve += ","
			}
			preserve += k
		}
	}
	sudoArgs := []string{"-u", systemUser, "-H"}
	if preserve != "" {
		sudoArgs = append(sudoArgs, "--preserve-env="+preserve)
	}
	sudoArgs = append(append(sudoArgs, "--", name), commandArgs...)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.CommandContext(ctx, "sudo", sudoArgs...)
	cmd.Dir = cwd
	cmd.Env = environment
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		runuserArgs := append([]string{"-u", systemUser, "--", name}, commandArgs...)
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		cmd = exec.CommandContext(ctx, "runuser", runuserArgs...)
		cmd.Dir = cwd
		cmd.Env = environment
		out, err = cmd.CombinedOutput()
	}
	return string(out), err
}

// gitNetworkTimeout bounds the two git operations that contact a remote (clone and
// fetch). It sits above the router's own 300-second request timeout on purpose: the
// request already gives up before this, and shortening the subprocess to match
// would abandon large shallow clones that land today. The point is that the process
// cannot outlive the panel, not that it finishes while the caller is still waiting.
const gitNetworkTimeout = 10 * time.Minute

// gitResolveArgs vets the remote and, for an HTTPS remote, pins the address git
// will connect to.
//
// netguard.CheckGitURL resolves the host and hands the URL onward unchanged; git
// then resolves the same name again when it connects. A low-TTL record under the
// customer's control can answer with a public address for the check and an
// internal one for the connection, so the panel issues a request to an address
// it never approved.
//
// http.curloptResolve maps the NAME to the vetted address inside libcurl. The
// URL keeps the hostname, so TLS still validates the certificate against it:
// rewriting the URL to the address would have traded the rebind for a broken
// certificate check.
//
// An ssh:// or git@ remote gets nothing here. That path currently disables host
// key verification for github.com, so there is no pin for an alias to preserve;
// it is pinned once that is fixed.
func gitResolveArgs(repoURL string) ([]string, error) {
	if err := netguard.CheckGitURL(repoURL); err != nil {
		return nil, fmt.Errorf("repository host not permitted: %w", err)
	}
	if !strings.HasPrefix(repoURL, "https://") {
		return nil, nil
	}
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid repository URL")
	}
	// An address literal is already the thing that would be dialed, so there is
	// no second resolution to pin.
	if net.ParseIP(parsed.Hostname()) != nil {
		return nil, nil
	}
	address, err := netguard.ResolveAllowed(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("repository host not permitted: %w", err)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	// curl's RESOLVE syntax brackets an IPv6 address.
	if strings.Contains(address, ":") {
		address = "[" + address + "]"
	}
	return []string{"-c", "http.curloptResolve=" + parsed.Hostname() + ":" + port + ":" + address}, nil
}

// gitClone performs the initial clone and replaces an existing target directory.
// token authenticates a private HTTPS repository (empty => public/deploy-key).
func gitClone(systemUser, repoURL, branch, targetDir, token string) (sha string, log string, err error) {
	if !validRepoURL(repoURL) {
		return "", "", errors.New("invalid repository URL")
	}
	resolveArgs, err := gitResolveArgs(repoURL)
	if err != nil {
		return "", "", err
	}
	if !validBranch(branch) {
		return "", "", errors.New("invalid branch")
	}
	if !validTargetDir(targetDir) {
		return "", "", errors.New("invalid target directory")
	}
	home := "/home/" + systemUser
	dst := filepath.Join(home, targetDir)
	// Clear the target. Existing public_html content is lost, as warned in the UI.
	if err := clearDirectoryContents(home, targetDir); err != nil {
		return "", "", fmt.Errorf("target directory could not be cleared: %w", err)
	}
	// Symlink-safe mkdir -p: os.MkdirAll follows a tenant symlink at any
	// component and would create the tree outside the home, as root. This also
	// chowns each directory it creates through its own fd, so the recursive
	// chown by path that used to follow is gone with it.
	if err := files.MkdirAllBeneath(home, targetDir, systemUser); err != nil {
		return "", "", fmt.Errorf("target directory is not safe: %w", err)
	}

	authEnv, err := gitAuthEnv(token)
	if err != nil {
		return "", "", errors.New("could not prepare git credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitNetworkTimeout)
	defer cancel()
	cloneArgs := append(append([]string{}, resolveArgs...),
		"clone", "--depth", "1", "--branch", branch, "--", repoURL, dst)
	out, err := runAsUserArgsCtx(ctx, systemUser, home, authEnv, "git", cloneArgs...)
	log = out
	if err != nil {
		return "", out, err
	}
	shaOut, _ := runAsUserArgs(systemUser, dst, nil, "git", "-C", dst, "rev-parse", "HEAD")
	sha = strings.TrimSpace(shaOut)
	files.RestoreconBeneath(home, targetDir)
	return sha, log, nil
}

// gitPull updates an existing repository.
// token authenticates a private HTTPS repository (empty => public/deploy-key).
func gitPull(systemUser, repoURL, targetDir, branch, token string) (sha string, log string, err error) {
	if !validTargetDir(targetDir) {
		return "", "", errors.New("invalid target directory")
	}
	if !validBranch(branch) {
		return "", "", errors.New("invalid branch")
	}
	// The fetch reaches the SAME remote the clone did, so it needs the same pin.
	// The URL comes from the stored row rather than from the repository's own
	// config, which the tenant owns and can rewrite.
	if !validRepoURL(repoURL) {
		return "", "", errors.New("invalid repository URL")
	}
	resolveArgs, err := resolveArgsFor(repoURL)
	if err != nil {
		return "", "", err
	}
	home := filepath.Join(tenantHomeRoot, systemUser)
	dst := filepath.Join(home, targetDir)
	// Resolve the target through openat2 before touching it. git itself runs as
	// the tenant, so DAC already bounds the damage, but a symlinked component
	// would silently point the pull at an unrelated directory; refusing here
	// tells the operator why instead.
	if isDir, err := files.IsDirBeneath(home, targetDir); err != nil || !isDir {
		return "", "", errors.New("target directory is not safe; re-create it and clone again")
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(filepath.Join(dst, ".git")); err != nil {
		return "", "", errors.New("target directory is not a Git repository; clone it first")
	}
	authEnv, err := gitAuthEnv(token)
	if err != nil {
		return "", "", errors.New("could not prepare git credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitNetworkTimeout)
	defer cancel()
	fetchArgs := append([]string{"-C", dst}, resolveArgs...)
	fetchArgs = append(fetchArgs, "fetch", "origin", branch)
	out, err := runUserCtx(ctx, systemUser, dst, authEnv, "git", fetchArgs...)
	if err == nil {
		resetOutput, resetErr := runUser(systemUser, dst, nil, "git", "-C", dst, "reset", "--hard", "origin/"+branch)
		out += resetOutput
		err = resetErr
	}
	log = out
	if err != nil {
		return "", out, err
	}
	shaOut, _ := runUser(systemUser, dst, nil, "git", "-C", dst, "rev-parse", "HEAD")
	sha = strings.TrimSpace(shaOut)
	files.RestoreconBeneath(home, targetDir)
	return sha, log, nil
}

// ----- HTTP handlers -----

type connectRequest struct {
	RepoURL   string `json:"repo_url"`
	Branch    string `json:"branch"`
	TargetDir string `json:"target_dir"`
}

func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE domain_id=? LIMIT 1", id)
	repo, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteJSON(w, http.StatusOK, nil)
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, repo)
}

// Connect creates a deploy key and stores the repository URL without cloning.
func (h *Handlers) Connect(w http.ResponseWriter, r *http.Request) {
	id, systemUser, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	var req connectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.RepoURL = strings.TrimSpace(req.RepoURL)
	req.Branch = strings.TrimSpace(req.Branch)
	req.TargetDir = strings.TrimSpace(req.TargetDir)
	if req.Branch == "" {
		req.Branch = "main"
	}
	if req.TargetDir == "" {
		req.TargetDir = "public_html"
	}
	if !validRepoURL(req.RepoURL) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid repo_url")
		return
	}
	if err := checkGitURL(req.RepoURL); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "repository host is not permitted")
		return
	}
	if !validBranch(req.Branch) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid branch")
		return
	}
	if !validTargetDir(req.TargetDir) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid target_dir")
		return
	}
	pub, err := deployKeyFor(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// Two INDEPENDENT values. The path token only locates the repository and is
	// written to the nginx access log on every delivery; the signing key is the
	// credential that proves the body came from the configured remote. Deriving
	// one from the other, or reusing one for both, makes the signature prove
	// nothing beyond the URL.
	secret := randomHex(20)
	signingKey := randomHex(32)
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO git_repos(domain_id, repo_url, branch, target_dir, deploy_key_pub, webhook_secret, webhook_signing_key, last_status)
		 VALUES(?,?,?,?,?,?,?, 'pending')
		 ON DUPLICATE KEY UPDATE repo_url=VALUES(repo_url), branch=VALUES(branch),
		   target_dir=VALUES(target_dir), deploy_key_pub=VALUES(deploy_key_pub)`,
		id, req.RepoURL, req.Branch, req.TargetDir, pub, secret, signingKey)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	gid, _ := res.LastInsertId()
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE id=?", gid)
	repo, _ := scan(row)
	httpx.WriteJSON(w, http.StatusCreated, repo)
}

// Clone performs the initial clone.
func (h *Handlers) Clone(w http.ResponseWriter, r *http.Request) {
	id, systemUser, err := h.lookupDomain(r)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, "permission denied")
		return
	}
	var repoURL, branch, targetDir string
	var gid int64
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT id, repo_url, branch, target_dir FROM git_repos WHERE domain_id=? LIMIT 1`, id).
		Scan(&gid, &repoURL, &branch, &targetDir)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusBadRequest, "connect a repository first")
		return
	}
	sha, log, err := gitClone(systemUser, repoURL, branch, targetDir, githubTokenFor(h.DB, id))
	status := "successful"
	if err != nil {
		status = "error"
	}
	_, _ = h.DB.ExecContext(r.Context(),
		`UPDATE git_repos SET last_sync=NOW(), last_commit=?, last_status=? WHERE id=?`,
		sha, status, gid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "commit": sha, "log": log,
	})
}

// Pull updates an existing repository.
func (h *Handlers) Pull(w http.ResponseWriter, r *http.Request) {
	id, systemUser, err := h.lookupDomain(r)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, "permission denied")
		return
	}
	var repoURL, branch, targetDir string
	var gid int64
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT id, repo_url, branch, target_dir FROM git_repos WHERE domain_id=? LIMIT 1`, id).
		Scan(&gid, &repoURL, &branch, &targetDir)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusBadRequest, "repository not found")
		return
	}
	sha, log, err := gitPull(systemUser, repoURL, targetDir, branch, githubTokenFor(h.DB, id))
	status := "successful"
	if err != nil {
		status = "error"
	}
	_, _ = h.DB.ExecContext(r.Context(),
		`UPDATE git_repos SET last_sync=NOW(), last_commit=?, last_status=? WHERE id=?`,
		sha, status, gid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "commit": sha, "log": log,
	})
}

// Delete removes the repository record but leaves the deploy key on disk.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM git_repos WHERE domain_id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete repository connection")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Webhook validates a GitHub push event secret and pulls the repository.
// URL: POST /api/v1/git-webhook/:secret
// Authentication is not required because the secret is in the URL. Only that secret is matched.
func (h *Handlers) Webhook(w http.ResponseWriter, r *http.Request) {
	secret := chi.URLParam(r, "secret")
	if len(secret) < 16 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid secret")
		return
	}
	var gid, domainID int64
	var systemUser, repoURL, branch, targetDir, signingKey string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT g.id, g.domain_id, d.system_user, g.repo_url, g.branch, g.target_dir, g.webhook_signing_key
		 FROM git_repos g JOIN domains d ON d.id=g.domain_id
		 WHERE g.webhook_secret=? LIMIT 1`, secret).Scan(&gid, &domainID, &systemUser, &repoURL, &branch, &targetDir, &signingKey)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "secret did not match")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}

	// Verify the HMAC-SHA256 signature before running any pull. The URL token
	// only locates the repository; the signature proves the body came from the
	// configured remote.
	//
	// The key is a SEPARATE column from the path token. They used to be one
	// value, which meant anyone who learned the URL could forge a signature for
	// any body, and the URL is written to the nginx access log on every
	// delivery. An empty key is refused rather than falling back to the token:
	// a fallback would restore exactly the property this separation removes.
	if signingKey == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable,
			"this repository has no webhook signing key; reconnect it from the panel")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // webhook body over 1MB is abuse
	body, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	sig := r.Header.Get("X-Hub-Signature-256")
	if sig == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "signature required")
		return
	}
	if !validGitHubSignature(signingKey, body, sig) {
		httpx.WriteError(w, http.StatusUnauthorized, "signature verification failed")
		return
	}

	event := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	delivery := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if delivery == "" || len(delivery) > 128 {
		httpx.WriteError(w, http.StatusBadRequest, "delivery id missing or invalid")
		return
	}
	// GitHub assigns each delivery a unique id. INSERT IGNORE against the UNIQUE
	// primary key atomically rejects a replay of the same signed request, whether
	// it arrives over the wire twice or is deliberately resent.
	res, derr := h.DB.ExecContext(r.Context(),
		`INSERT IGNORE INTO git_webhook_deliveries(delivery_id, git_repo_id, event)
		 VALUES(?,?,?)`, delivery, gid, event)
	if derr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record webhook delivery")
		return
	}
	if affected, aerr := res.RowsAffected(); aerr != nil || affected != 1 {
		httpx.WriteError(w, http.StatusConflict, "webhook delivery already processed")
		return
	}
	_, _ = h.DB.ExecContext(r.Context(),
		`DELETE FROM git_webhook_deliveries WHERE received_at < NOW() - INTERVAL 30 DAY`)

	if event == "ping" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "pong": true})
		return
	}
	if event != "push" {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported webhook event")
		return
	}

	sha, _, perr := pullRepository(systemUser, repoURL, targetDir, branch, githubTokenFor(h.DB, domainID))
	status := "successful"
	if perr != nil {
		status = "error-webhook"
	}
	_, _ = h.DB.ExecContext(r.Context(),
		`UPDATE git_repos SET last_sync=NOW(), last_commit=?, last_status=? WHERE id=?`,
		sha, status, gid)
	if perr != nil {
		// GitHub retries transient failures with the same delivery id. Drop the
		// replay row on failure so a legitimate retry is not rejected as a replay.
		_, _ = h.DB.ExecContext(r.Context(),
			`DELETE FROM git_webhook_deliveries WHERE delivery_id=?`, delivery)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "commit": sha,
	})
}

// validGitHubSignature reports whether sig is the GitHub HMAC-SHA256 signature
// ("sha256=<hex>") of body under secret, compared in constant time.
func validGitHubSignature(secret string, body []byte, sig string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
