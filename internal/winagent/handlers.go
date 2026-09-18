package winagent

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/secret"
)

// Agent states. A fingerprint mismatch is kept apart from an unreachable agent
// on purpose: one is a network problem and the other is a security event, and
// an operator must not read them as the same row.
const (
	stateHealthy     = "healthy"
	stateUnreachable = "unreachable"
	stateMismatch    = "fingerprint-mismatch"
)

// maxBody bounds the registration body, proxyLimit the answer this package
// copies back from an agent. Event messages can be long, so the proxy limit is
// generous but finite.
const (
	maxBody    = 8 << 10
	proxyLimit = 1 << 20
)

type Handlers struct{ DB *sql.DB }

func New(db *sql.DB) *Handlers { return &Handlers{DB: db} }

// Agent is one registered Windows host as the panel answers it.
type Agent struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Address          string `json:"address"`
	Version          string `json:"version"`
	Channel          string `json:"channel"`
	Capabilities     uint32 `json:"capabilities"`
	State            string `json:"state"`
	LastSeen         string `json:"last_seen"`
	FingerprintShort string `json:"fingerprint_short"`
}

// List answers every registered agent.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id, name, address, version, channel, capabilities, state, fingerprint,
		       COALESCE(DATE_FORMAT(last_seen, '%Y-%m-%d %H:%i:%s'), '')
		  FROM windows_agents ORDER BY name`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the agents")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []Agent{}
	for rows.Next() {
		var a Agent
		var fingerprint string
		if err := rows.Scan(&a.ID, &a.Name, &a.Address, &a.Version, &a.Channel,
			&a.Capabilities, &a.State, &fingerprint, &a.LastSeen); err != nil {
			continue
		}
		a.FingerprintShort = shortFingerprint(fingerprint)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the agent list ended early")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"agents": out})
}

// addRequest is the registration body.
type addRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Token   string `json:"token"`
}

// readAddRequest decodes and validates the registration body.
func readAddRequest(w http.ResponseWriter, r *http.Request) (addRequest, bool) {
	var req addRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read the request body")
		return req, false
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Address = strings.TrimSpace(req.Address)
	switch {
	case req.Name == "" || len(req.Name) > 64:
		httpx.WriteError(w, http.StatusBadRequest, "name must be 1 to 64 characters")
	case req.Token == "":
		httpx.WriteError(w, http.StatusBadRequest, "token cannot be empty")
	default:
		if err := validAddress(req.Address); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return req, false
		}
		return req, true
	}
	return req, false
}

// Add registers an agent, but only after talking to it.
//
// The certificate is read first and the health call is pinned to it, so an
// agent that is unreachable or rejects the token is never written. A dead row
// in the list reads as "might work" and costs an operator a real diagnosis.
//
// Trust on first use cannot catch an interception that is already in place at
// this exact moment. The operator closes that by comparing the returned
// fingerprint prefix with the one the agent printed at startup. Every later
// call is locked to it.
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	req, ok := readAddRequest(w, r)
	if !ok {
		return
	}
	fingerprint, err := readFingerprint(req.Address)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	answer, err := probe(req.Address, req.Token, fingerprint)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	sealed, err := secret.EncryptWith(req.Token, req.Address)
	if err != nil {
		httpx.LogR(r, "winagent: could not seal the token: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not store the token")
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO windows_agents (name, address, token_encrypted, fingerprint, version, channel, capabilities, state, last_seen)
		VALUES (?,?,?,?,?,?,?,?,NOW())`,
		req.Name, req.Address, sealed, fingerprint, answer.Version, answer.Channel, answer.Capabilities, stateHealthy)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			httpx.WriteError(w, http.StatusConflict, "that address is already registered")
			return
		}
		httpx.LogR(r, "winagent: could not insert the agent: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not register the agent")
		return
	}
	id, _ := res.LastInsertId()
	middleware.RecordAudit(h.DB, r, "winagent.add", req.Name, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "version": answer.Version, "capabilities": answer.Capabilities,
		"env_error": answer.EnvError, "fingerprint_short": shortFingerprint(fingerprint),
	})
}

// connection is the triple needed to call one agent.
type connection struct {
	address     string
	token       string
	fingerprint string
}

// load reads and unseals one agent's connection.
func (h *Handlers) load(r *http.Request, id string) (connection, error) {
	var c connection
	var sealed string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT address, token_encrypted, fingerprint FROM windows_agents WHERE id=?`, id).
		Scan(&c.address, &sealed, &c.fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return c, errors.New("agent not found")
	}
	if err != nil {
		return c, errors.New("could not read the agent")
	}
	if c.token, err = secret.DecryptWith(sealed, c.address); err != nil {
		return c, errors.New("could not open the stored token")
	}
	return c, nil
}

// mark records a state change. A failure here only makes the list stale, so it
// is logged rather than returned over the failure the caller is already
// reporting.
func (h *Handlers) mark(r *http.Request, id, state string) {
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE windows_agents SET state=? WHERE id=?`, state, id); err != nil {
		httpx.WarnR(r, "winagent: could not mark agent %s as %s: %v", id, state, err)
	}
}

// Probe re-reads one agent's health and refreshes the row.
//
// The call is pinned to the stored fingerprint. A row written before the pin
// existed carries an empty fingerprint; it learns one here, once, and is locked
// from then on.
func (h *Handlers) Probe(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := h.load(r, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	if c.fingerprint == "" {
		if c.fingerprint, err = readFingerprint(c.address); err != nil {
			h.mark(r, id, stateUnreachable)
			httpx.WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	answer, err := probe(c.address, c.token, c.fingerprint)
	if err != nil {
		state := stateUnreachable
		if errors.Is(err, ErrFingerprint) {
			state = stateMismatch
		}
		h.mark(r, id, state)
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `
		UPDATE windows_agents SET version=?, channel=?, capabilities=?, fingerprint=?, state=?, last_seen=NOW()
		 WHERE id=?`,
		answer.Version, answer.Channel, answer.Capabilities, c.fingerprint, stateHealthy, id); err != nil {
		httpx.WarnR(r, "winagent: could not refresh agent %s: %v", id, err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": answer.Version, "capabilities": answer.Capabilities,
		"env_error": answer.EnvError, "fingerprint_short": shortFingerprint(c.fingerprint),
	})
}

// Delete removes one agent.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var name string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT name FROM windows_agents WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the agent")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM windows_agents WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the agent")
		return
	}
	middleware.RecordAudit(h.DB, r, "winagent.delete", name, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// forward proxies one read-only agent path over the pinned client and copies
// the answer back.
//
// Nothing is cached. An event log read from a cache diagnoses the wrong
// incident, so every call goes to the agent.
func (h *Handlers) forward(w http.ResponseWriter, r *http.Request, pathAndQuery string) {
	id := chi.URLParam(r, "id")
	c, err := h.load(r, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	if c.fingerprint == "" {
		// A row with no pin predates it. Connecting without one would defeat
		// the whole model, so the operator runs Probe first and learns it there.
		httpx.WriteError(w, http.StatusConflict, "this agent has no pinned certificate - probe it first")
		return
	}
	// #nosec G704 -- the address is not request data: it comes from the
	// windows_agents row an admin wrote, the route is AdminOnly, and the
	// client below refuses any host whose leaf certificate does not match the
	// pin recorded for that row. pathAndQuery is a caller constant.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://"+c.address+pathAndQuery, nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not build the request")
		return
	}
	req.Header.Set(tokenHeader, c.token)
	// #nosec G704 -- same request as above; the pin is the boundary.
	resp, err := pinnedClient(c.fingerprint).Do(req)
	if err != nil {
		if isFingerprintError(err) {
			h.mark(r, id, stateMismatch)
			httpx.WriteError(w, http.StatusBadGateway, ErrFingerprint.Error())
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, "could not reach the agent: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, proxyLimit))
}

// eventLogs is the set of Windows logs this proxy will ask for.
var eventLogs = map[string]bool{"System": true, "Application": true, "Security": true}

// Events proxies the agent's event log.
//
// The log name and the count are validated here as well as on the agent. The
// agent already checks them; the panel checks too so this endpoint cannot
// become a carrier for an arbitrary query.
func (h *Handlers) Events(w http.ResponseWriter, r *http.Request) {
	log := r.URL.Query().Get("log")
	if log == "" {
		log = "System"
	}
	if !eventLogs[log] {
		httpx.WriteError(w, http.StatusBadRequest, "log must be System, Application or Security")
		return
	}
	count := r.URL.Query().Get("count")
	if count == "" {
		count = "50"
	}
	if !digitsOnly(count) {
		httpx.WriteError(w, http.StatusBadRequest, "count must be a number")
		return
	}
	h.forward(w, r, "/events?log="+log+"&count="+count)
}

// digitsOnly reports whether value is a non-empty run of decimal digits.
func digitsOnly(value string) bool {
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return value != ""
}

// Tasks proxies the agent's scheduled tasks.
func (h *Handlers) Tasks(w http.ResponseWriter, r *http.Request) {
	all := "0"
	if r.URL.Query().Get("all") == "1" {
		all = "1"
	}
	h.forward(w, r, "/tasks?all="+all)
}
