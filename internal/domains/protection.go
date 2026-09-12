package domains

import (
	"encoding/json"
	"net/http"

	"servika/internal/geoip"
	"servika/internal/httpx"
	"servika/internal/provisioner"
)

// Country rules and the request rate limit for one domain.
//
// Both live beside the IP access rules because they answer the same question
// from different angles, and both re-render the vhost the same way: the setting
// is stored once and the render reads it back, because roughly thirty unrelated
// call sites rewrite a vhost without knowing these settings exist.

// maxDomainCountries bounds one domain's country list.
//
// Every country a domain names lands in the shared nginx include, which nginx
// parses on every reload for every domain on the server. A single customer
// selecting most of the world would make that everyone else's problem.
const maxDomainCountries = 40

var validGeoModes = map[string]bool{"off": true, "allow": true, "deny": true}

type geoSettings struct {
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
}

// GetGeo returns the domain's country policy and the state of the database
// behind it.
//
// The database state travels with the policy rather than being fetched
// separately, so the screen can disable the control and say why in the reader's
// own language instead of letting the customer save a rule that refuses nobody.
func (h *Handlers) GetGeo(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var mode string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(geo_mode,'off') FROM domains WHERE id=?`, id).Scan(&mode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be read")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT country_code FROM domain_geo_rules WHERE domain_id=? ORDER BY country_code`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be read")
		return
	}
	defer func() { _ = rows.Close() }()
	countries := make([]string, 0)
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			// A dropped country is one the operator saved and can no longer see or
			// remove, while the rule it belongs to keeps being enforced.
			httpx.WarnR(r, "country rules: skipping an unreadable code: %v", err)
			continue
		}
		countries = append(countries, code)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be read")
		return
	}

	status, err := geoip.ReadStatus(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be read")
		return
	}
	// The account id belongs to the operator, not to a customer looking at
	// their own site, so only the state a customer can act on is returned.
	status.AccountID = ""
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"mode":      mode,
		"countries": countries,
		"database":  status,
	})
}

// SetGeo replaces the domain's country policy.
func (h *Handlers) SetGeo(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var request geoSettings
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validGeoModes[request.Mode] {
		httpx.WriteError(w, http.StatusBadRequest, "mode must be off, allow or deny")
		return
	}

	countries, ok := geoCountries(w, request.Countries)
	if !ok {
		return
	}
	if request.Mode != "off" && !geoPolicyEnforceable(w, countries) {
		return
	}
	if !h.storeGeoPolicy(w, r, id, request.Mode, countries) {
		return
	}

	if err := rerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rules saved but virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// geoCountries normalises the requested country codes and keeps each once. It
// refuses a value that is not a code and a list past maxDomainCountries.
func geoCountries(w http.ResponseWriter, requested []string) ([]string, bool) {
	countries := make([]string, 0, len(requested))
	seen := map[string]bool{}
	for _, raw := range requested {
		code := geoip.NormalizeCountry(raw)
		if code == "" {
			writeReason(w, http.StatusBadRequest, "that is not a country code", geoip.ReasonCountryUnknown)
			return nil, false
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		countries = append(countries, code)
	}
	if len(countries) > maxDomainCountries {
		writeReason(w, http.StatusBadRequest, "too many countries", geoip.ReasonTooManyCountries)
		return nil, false
	}
	return countries, true
}

// geoPolicyEnforceable checks that a policy that is switched on can be
// enforced, and answers the request when it cannot.
//
// FAIL-CLOSED on the WRITE path. Without ranges a deny list refuses
// nobody and an allow list would refuse everybody, so the policy is not
// stored at all rather than stored and silently not enforced.
func geoPolicyEnforceable(w http.ResponseWriter, countries []string) bool {
	if !geoDatabaseAvailable() {
		writeReason(w, http.StatusConflict,
			"no country database has been downloaded", geoip.ReasonUnavailable)
		return false
	}
	if len(countries) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "select at least one country")
		return false
	}
	for _, code := range countries {
		if !geoKnownCountry(code) {
			writeReason(w, http.StatusBadRequest,
				"the country database does not carry that country", geoip.ReasonCountryUnknown)
			return false
		}
	}
	return true
}

// storeGeoPolicy replaces the stored mode and country list in one transaction,
// and answers the request when it cannot.
func (h *Handlers) storeGeoPolicy(w http.ResponseWriter, r *http.Request, id int64, mode string, countries []string) bool {
	transaction, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be saved")
		return false
	}
	defer func() { _ = transaction.Rollback() }()

	if _, err := transaction.ExecContext(r.Context(),
		`UPDATE domains SET geo_mode=? WHERE id=?`, mode, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be saved")
		return false
	}
	if _, err := transaction.ExecContext(r.Context(),
		`DELETE FROM domain_geo_rules WHERE domain_id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be saved")
		return false
	}
	for _, code := range countries {
		if _, err := transaction.ExecContext(r.Context(),
			`INSERT INTO domain_geo_rules(domain_id, country_code) VALUES(?,?)`, id, code); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be saved")
			return false
		}
	}
	if err := transaction.Commit(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country rules could not be saved")
		return false
	}
	return true
}

type rateLimitSettings struct {
	RPS int `json:"rps"`
}

// GetRateLimit returns the domain's request ceiling and the rates it may pick.
func (h *Handlers) GetRateLimit(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var rps int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(rate_limit_rps,0) FROM domains WHERE id=?`, id).Scan(&rps); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the rate limit could not be read")
		return
	}
	// The ladder is served rather than duplicated on the screen, because the
	// rates that exist are the ones nginx has zones for.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"rps":    rps,
		"ladder": provisioner.RateLadder(),
	})
}

// SetRateLimit stores the domain's request ceiling.
func (h *Handlers) SetRateLimit(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var request rateLimitSettings
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// A rate off the ladder has no zone, and a vhost naming a zone nginx does
	// not declare fails the configuration test for the whole server.
	if !provisioner.ValidRate(request.RPS) {
		writeReason(w, http.StatusBadRequest, "that request rate is not available", geoip.ReasonRateNotAllowed)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET rate_limit_rps=? WHERE id=?`, request.RPS, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the rate limit could not be saved")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the rate limit was saved but virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// writeReason answers with the panel's error shape plus a stable reason CODE.
//
// The message is English because the API is; the code is what the screen maps
// to a sentence in the reader's own language.
func writeReason(w http.ResponseWriter, status int, message, reason string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}
