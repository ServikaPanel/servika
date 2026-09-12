// Package waf provides the per-domain WAF (ModSecurity + OWASP CRS) settings API.
//
// GET/PUT /domains/{id}/waf reads/writes the domain WAF mode (inherit/off/block/detect)
// and paranoia level. On write, provisioner.WAFApply refreshes the per-domain modsec conf
// and re-renders the vhost (nginx -t gate + rollback). When the module is not loaded the
// setting is still persisted but the render gracefully skips WAF — the response includes
// a module_loaded flag.
package waf

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB *sql.DB
}

// Settings represents the domain-level WAF override.
//
//	mode: "inherit" (from plan) | "off" | "block" (On) | "detect" (DetectionOnly)
//	paranoia: 0 = inherit, 1..4 = override
type Settings struct {
	Mode     string `json:"mode"`
	Paranoia int    `json:"paranoia"`
}

type planInfo struct {
	Active   bool   `json:"active"`
	Mode     string `json:"mode"`
	Paranoia int    `json:"paranoia"`
	Name     string `json:"name,omitempty"`
}

type effectiveInfo struct {
	Active   bool   `json:"active"`
	Engine   string `json:"engine"`
	Paranoia int    `json:"paranoia"`
}

// mapWAFMode maps an API mode string to the (waf_enabled, waf_mode) column values.
// A nil pair means NULL (inherit from plan). ok is false for an unrecognized mode.
func mapWAFMode(mode string) (enabled, wafMode any, ok bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "inherit", "":
		return nil, nil, true
	case "off":
		return 0, "off", true
	case "block":
		return 1, "on", true
	case "detect":
		return 1, "detect", true
	default:
		return nil, nil, false
	}
}

// mapWAFParanoia clamps a paranoia level to the persisted column value.
// Levels 1..4 are kept; anything else becomes nil (NULL = inherit from plan).
func mapWAFParanoia(paranoia int) any {
	if paranoia >= 1 && paranoia <= 4 {
		return paranoia
	}
	return nil
}

// detects reports whether a stored waf_mode column names detection-only.
func detects(mode sql.NullString) bool {
	return mode.Valid && strings.ToLower(strings.TrimSpace(mode.String)) == "detect"
}

// overrideOf maps the domain's own columns to the API settings. An unset
// override is "inherit", which is not the same answer as "off".
func overrideOf(enabled sql.NullInt64, mode sql.NullString, paranoia sql.NullInt64) Settings {
	s := Settings{Mode: "inherit", Paranoia: 0}
	if enabled.Valid {
		switch {
		case int(enabled.Int64) != 1:
			s.Mode = "off"
		case detects(mode):
			s.Mode = "detect"
		default:
			s.Mode = "block"
		}
	}
	if paranoia.Valid && paranoia.Int64 > 0 {
		s.Paranoia = int(paranoia.Int64)
	}
	return s
}

// planDefault maps the plan columns to the informational plan block. A domain
// on no plan reports the resolver's own default rather than an empty plan.
func planDefault(enabled sql.NullInt64, mode sql.NullString, paranoia sql.NullInt64, name sql.NullString) planInfo {
	plan := planInfo{Active: false, Mode: "off", Paranoia: 1}
	if name.Valid {
		plan.Name = name.String
	}
	if paranoia.Valid && paranoia.Int64 > 0 {
		plan.Paranoia = int(paranoia.Int64)
	}
	if enabled.Valid && enabled.Int64 == 1 {
		plan.Active = true
		plan.Mode = "block"
		if detects(mode) {
			plan.Mode = "detect"
		}
	}
	return plan
}

// GET /domains/{id}/waf
func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, sk string
	var dEn, dPL sql.NullInt64
	var dMode sql.NullString
	var pEn sql.NullInt64
	var pMode sql.NullString
	var pPL sql.NullInt64
	var pName sql.NullString
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.domain_name, d.system_user, d.waf_enabled, d.waf_mode, d.waf_paranoia,
		        p.waf_enabled, p.waf_mode, p.waf_paranoia, p.name
		 FROM domains d LEFT JOIN service_plans p ON p.id = d.plan_id
		 WHERE d.id = ?`, id).
		Scan(&domainName, &sk, &dEn, &dMode, &dPL, &pEn, &pMode, &pPL, &pName)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read WAF settings")
		return
	}

	s := overrideOf(dEn, dMode, dPL)
	plan := planDefault(pEn, pMode, pPL, pName)

	// Effective (same resolver as provisioner — no drift)
	efActive, efEngine, efPL := wafEffective(h.DB, sk)
	ef := effectiveInfo{Active: efActive, Engine: efEngine, Paranoia: efPL}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"domain_name":   domainName,
		"settings":      s,
		"plan":          plan,
		"effective":     ef,
		"module_loaded": wafModuleLoaded(),
	})
}

// PUT /domains/{id}/waf   body: {"settings": {"mode":"block","paranoia":1}}
func (h *Handlers) Save(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req struct {
		Settings Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}

	var sk string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&sk); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
		} else {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to read domain")
		}
		return
	}

	// mode → (waf_enabled, waf_mode); nil = NULL = inherit from plan
	enVal, modeVal, ok := mapWAFMode(req.Settings.Mode)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid mode (inherit|off|block|detect)")
		return
	}
	plVal := mapWAFParanoia(req.Settings.Paranoia)

	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET waf_enabled=?, waf_mode=?, waf_paranoia=? WHERE id=?`,
		enVal, modeVal, plVal, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save WAF settings")
		return
	}

	// Re-render vhost — nginx -t gate + rollback protects. Gracefully skipped when module absent.
	if err := provisioner.WAFApply(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError,
			"WAF settings saved but vhost render failed (nginx unchanged)")
		return
	}

	efActive, efEngine, efPL := wafEffective(h.DB, sk)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"effective":     effectiveInfo{Active: efActive, Engine: efEngine, Paranoia: efPL},
		"module_loaded": wafModuleLoaded(),
	})
}
