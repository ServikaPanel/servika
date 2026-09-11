// Package github provides GitHub connections through Personal Access Tokens,
// repository and branch listing, and automatic webhook setup.
package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/secret"

	"github.com/go-chi/chi/v5"
)

func apiBase() string { return config.GitHubAPI() }

type Handlers struct {
	DB *sql.DB
	// WebhookBase is the IP-based public URL prefix, for example "https://203.0.113.10:8443".
	// It is retained for reference only; webhook registration uses trustedWebhookBase,
	// which requires a panel domain with a valid TLS certificate.
	WebhookBase string
}

// trustedWebhookBase returns the HTTPS base URL for webhook delivery only when
// the panel is served on a custom domain with an active (Let's Encrypt) TLS
// certificate. GitHub verifies the certificate on delivery, so an IP-based or
// self-signed endpoint is not trusted and (base, false) is returned.
func (h *Handlers) trustedWebhookBase(ctx context.Context) (string, bool) {
	var domain, sslStatus sql.NullString
	err := h.DB.QueryRowContext(ctx,
		`SELECT custom_domain, ssl_status FROM panel_settings WHERE id=1`).Scan(&domain, &sslStatus)
	if err != nil {
		return "", false
	}
	if strings.TrimSpace(domain.String) == "" || sslStatus.String != "active" {
		return "", false
	}
	return "https://" + strings.TrimSpace(domain.String), true
}

type Connection struct {
	ID             int64  `json:"id"`
	DomainID       int64  `json:"domain_id"`
	Login          string `json:"login"`
	FullName       string `json:"full_name"`
	AvatarURL      string `json:"avatar_url"`
	SelectedRepo   string `json:"selected_repo,omitempty"`
	SelectedBranch string `json:"selected_branch,omitempty"`
	WebhookID      int64  `json:"webhook_id,omitempty"`
	WebhookURL     string `json:"webhook_url,omitempty"`
}

type ghUser struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type ghRepo struct {
	FullName      string `json:"full_name"` // owner/name
	Name          string `json:"name"`
	Description   string `json:"description"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	UpdatedAt     string `json:"updated_at"`
}

type ghBranch struct {
	Name string `json:"name"`
}

type ghHook struct {
	ID     int64    `json:"id,omitempty"`
	Name   string   `json:"name"`
	Active bool     `json:"active"`
	Events []string `json:"events"`
	Config struct {
		URL         string `json:"url"`
		ContentType string `json:"content_type"`
		Secret      string `json:"secret,omitempty"`
		InsecureSSL string `json:"insecure_ssl"`
	} `json:"config"`
}

func ghCall(ctx context.Context, method, path, token string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	// #nosec G704 -- host is the fixed SERVIKA_GITHUB_API operator config (default api.github.com); path is internal, not tenant input.
	req, err := http.NewRequestWithContext(ctx, method, apiBase()+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Servika/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cli := &http.Client{Timeout: 15 * time.Second}
	// #nosec G704 -- request target is the fixed operator GitHub API base, not tenant input.
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

func patErrorMessage(status int, b []byte) string {
	if status == 401 {
		return "The token is invalid or lacks permission (401)"
	}
	if status == 403 {
		return "Rate limit or permission error (403)"
	}
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &e)
	if e.Message != "" {
		return fmt.Sprintf("GitHub: %s (HTTP %d)", e.Message, status)
	}
	return fmt.Sprintf("GitHub HTTP %d", status)
}

func (h *Handlers) lookupDomain(r *http.Request) (id int64, systemUser string, err error) {
	idStr := chi.URLParam(r, "id")
	_, _ = fmt.Sscanf(idStr, "%d", &id)
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).
		Scan(&systemUser)
	return
}

// POST /domains/{id}/github/connect — body: { token }
func (h *Handlers) Connect(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "token is required")
		return
	}
	req.Token = strings.TrimSpace(req.Token)

	// Validate the token and retrieve user information.
	b, st, err := ghCall(r.Context(), "GET", "/user", req.Token, nil)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "upstream service request failed")
		return
	}
	if st != 200 {
		httpx.WriteError(w, http.StatusBadRequest, patErrorMessage(st, b))
		return
	}
	var u ghUser
	if err := json.Unmarshal(b, &u); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "response could not be decoded")
		return
	}

	encToken, err := secret.Encrypt(req.Token)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO github_connections(domain_id, pat, login, full_name, avatar_url)
		 VALUES(?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE pat=VALUES(pat), login=VALUES(login),
		   full_name=VALUES(full_name), avatar_url=VALUES(avatar_url)`,
		id, encToken, u.Login, u.Name, u.AvatarURL)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}

	c, _ := h.readConnection(r.Context(), id)
	httpx.WriteJSON(w, http.StatusOK, c)
}

// GET /domains/{id}/github
func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	c, err := h.readConnection(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if c == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"missing": true})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

// DELETE /domains/{id}/github
func (h *Handlers) Disconnect(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// Remove the existing webhook on a best-effort basis.
	var pat, repo string
	var hookID int64
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT pat, selected_repo, webhook_id FROM github_connections WHERE domain_id=?`, id).
		Scan(&pat, &repo, &hookID)
	if plain, derr := secret.Decrypt(pat); derr == nil {
		pat = plain
	} else {
		pat = ""
	}
	if pat != "" && repo != "" && hookID > 0 {
		_, _, _ = ghCall(r.Context(), "DELETE", fmt.Sprintf("/repos/%s/hooks/%d", repo, hookID), pat, nil)
	}
	_, _ = h.DB.ExecContext(r.Context(), `DELETE FROM github_connections WHERE domain_id=?`, id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GET /domains/{id}/github/repos
func (h *Handlers) ListRepos(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.lookupDomain(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	pat := h.tokenOf(r.Context(), id)
	if pat == "" {
		httpx.WriteError(w, http.StatusBadRequest, "connect with a token first")
		return
	}
	b, st, err := ghCall(r.Context(), "GET", "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member", pat, nil)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "upstream service request failed")
		return
	}
	if st != 200 {
		httpx.WriteError(w, http.StatusBadGateway, patErrorMessage(st, b))
		return
	}
	var repos []ghRepo
	if err := json.Unmarshal(b, &repos); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not parse repository list from GitHub")
		return
	}
	out := make([]map[string]any, 0, len(repos))
	for _, rp := range repos {
		out = append(out, map[string]any{
			"full_name":      rp.FullName,
			"name":           rp.Name,
			"description":    rp.Description,
			"private":        rp.Private,
			"default_branch": rp.DefaultBranch,
			"clone_url":      rp.CloneURL,
			"html_url":       rp.HTMLURL,
			"updated_at":     rp.UpdatedAt,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// GET /domains/{id}/github/branches?repo=owner/name
func (h *Handlers) ListBranches(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.lookupDomain(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	repo := r.URL.Query().Get("repo")
	if repo == "" || !strings.Contains(repo, "/") {
		httpx.WriteError(w, http.StatusBadRequest, "the repo=owner/name parameter is required")
		return
	}
	pat := h.tokenOf(r.Context(), id)
	if pat == "" {
		httpx.WriteError(w, http.StatusBadRequest, "connect with a token first")
		return
	}
	b, st, err := ghCall(r.Context(), "GET", "/repos/"+repo+"/branches?per_page=100", pat, nil)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "upstream service request failed")
		return
	}
	if st != 200 {
		httpx.WriteError(w, http.StatusBadGateway, patErrorMessage(st, b))
		return
	}
	var brs []ghBranch
	if err := json.Unmarshal(b, &brs); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not parse branch list from GitHub")
		return
	}
	names := make([]string, 0, len(brs))
	for _, br := range brs {
		names = append(names, br.Name)
	}
	httpx.WriteJSON(w, http.StatusOK, names)
}

// POST /domains/{id}/github/use — body: { repo, branch, target_dir, auto_deploy }
// Use stores the selected repository in git_repos and creates a GitHub webhook when auto_deploy is true.
func (h *Handlers) Use(w http.ResponseWriter, r *http.Request) {
	id, systemUser, err := h.lookupDomain(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	var req struct {
		Repo       string `json:"repo"` // owner/name
		Branch     string `json:"branch"`
		TargetDir  string `json:"target_dir"`
		AutoDeploy bool   `json:"auto_deploy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.Repo == "" || !strings.Contains(req.Repo, "/") {
		httpx.WriteError(w, http.StatusBadRequest, "repo (owner/name) and branch are required")
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}
	if req.TargetDir == "" {
		req.TargetDir = "public_html"
	}
	_ = systemUser

	pat := h.tokenOf(r.Context(), id)
	if pat == "" {
		httpx.WriteError(w, http.StatusBadRequest, "connect with a token first")
		return
	}

	// Store the repo URL without the token; the token is supplied at git time via
	// GIT_ASKPASS (see internal/git), so it never lands in .git/config.
	cloneURL := fmt.Sprintf("https://github.com/%s.git", req.Repo)

	// Create or update the git_repos record.
	// The URL path token and the HMAC key are two INDEPENDENT values. They used
	// to be one column, which meant anyone who learned the delivery URL also
	// held the signing key and could forge a valid signature for any body; the
	// URL is written to the nginx access log on every delivery, so it is not a
	// secret in practice.
	//
	// A row that still carries the pre-separation pair (the migration backfilled
	// the key from the token so no configured webhook broke) gets a fresh
	// independent key HERE, because this call re-registers the hook at GitHub in
	// the same request and can therefore rotate without leaving a delivery
	// signing with a value the panel no longer accepts.
	var existingSecret, existingKey string
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(webhook_secret,''), COALESCE(webhook_signing_key,'') FROM git_repos WHERE domain_id=?`,
		id).Scan(&existingSecret, &existingKey)
	secret := existingSecret
	if secret == "" {
		secret = randomHex(20)
	}
	signingKey := existingKey
	if signingKey == "" || signingKey == secret {
		signingKey = randomHex(32)
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO git_repos(domain_id, repo_url, branch, target_dir, deploy_key_pub, webhook_secret, webhook_signing_key, last_status)
		 VALUES(?,?,?,?, '', ?,?, 'pending')
		 ON DUPLICATE KEY UPDATE repo_url=VALUES(repo_url), branch=VALUES(branch),
		   target_dir=VALUES(target_dir), webhook_secret=VALUES(webhook_secret),
		   webhook_signing_key=VALUES(webhook_signing_key)`,
		id, cloneURL, req.Branch, req.TargetDir, secret, signingKey); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}

	// Update the connection state.
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE github_connections SET selected_repo=?, selected_branch=? WHERE domain_id=?`,
		req.Repo, req.Branch, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}

	// Configure the automatic webhook.
	resp := map[string]any{"ok": true, "repo": req.Repo, "branch": req.Branch, "auto_deploy": req.AutoDeploy}
	webhookBase, trusted := h.trustedWebhookBase(r.Context())
	if req.AutoDeploy && !trusted {
		// GitHub verifies the panel TLS certificate on delivery. The default
		// IP-based endpoint cannot obtain a trusted certificate, so refuse to
		// register an insecure webhook and tell the operator how to enable it.
		resp["webhook_ok"] = false
		resp["webhook_error"] = "configure a panel domain with a valid TLS certificate before enabling auto-deploy"
	} else if req.AutoDeploy {
		hookURL := strings.TrimRight(webhookBase, "/") + "/api/v1/git-webhook/" + secret
		// Remove the previous webhook first.
		var oldID int64
		_ = h.DB.QueryRowContext(r.Context(),
			`SELECT webhook_id FROM github_connections WHERE domain_id=?`, id).Scan(&oldID)
		if oldID > 0 {
			_, _, _ = ghCall(r.Context(), "DELETE",
				fmt.Sprintf("/repos/%s/hooks/%d", req.Repo, oldID), pat, nil)
		}
		hook := ghHook{Name: "web", Active: true, Events: []string{"push"}}
		hook.Config.URL = hookURL
		hook.Config.ContentType = "json"
		// NOT `secret`: that value is the URL path segment, which GitHub sends in
		// the clear on every delivery and nginx writes to its access log.
		hook.Config.Secret = signingKey
		hook.Config.InsecureSSL = "0" // Require GitHub to verify the panel TLS certificate.
		body, st, err := ghCall(r.Context(), "POST", "/repos/"+req.Repo+"/hooks", pat, hook)
		if err != nil || (st != 201 && st != 200) {
			resp["webhook_ok"] = false
			resp["webhook_error"] = patErrorMessage(st, body)
		} else {
			var created ghHook
			if err := json.Unmarshal(body, &created); err != nil {
				resp["webhook_ok"] = false
				resp["webhook_error"] = "could not parse webhook response from GitHub"
			} else {
				_, _ = h.DB.ExecContext(r.Context(),
					`UPDATE github_connections SET webhook_id=?, webhook_url=? WHERE domain_id=?`,
					created.ID, hookURL, id)
				resp["webhook_ok"] = true
				resp["webhook_id"] = created.ID
				resp["webhook_url"] = hookURL
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handlers) readConnection(ctx context.Context, domainID int64) (*Connection, error) {
	c := &Connection{DomainID: domainID}
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, login, full_name, avatar_url, selected_repo, selected_branch, webhook_id, webhook_url
		 FROM github_connections WHERE domain_id=?`, domainID).
		Scan(&c.ID, &c.Login, &c.FullName, &c.AvatarURL, &c.SelectedRepo, &c.SelectedBranch, &c.WebhookID, &c.WebhookURL)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (h *Handlers) tokenOf(ctx context.Context, domainID int64) string {
	var pat string
	_ = h.DB.QueryRowContext(ctx, `SELECT pat FROM github_connections WHERE domain_id=?`, domainID).Scan(&pat)
	plain, err := secret.Decrypt(pat)
	if err != nil {
		return ""
	}
	return plain
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
