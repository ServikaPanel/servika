package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"servika/internal/geoip"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Server-wide country blocking.
//
// This is the operator's control, not a customer's. It drops at the packet
// level, so it covers every port rather than only the web server, and that is
// exactly why it cannot be per-domain: nftables never sees a Host header.
//
// The element lists live in their own file, included from inside the table
// block. A country runs to thousands of intervals, and keeping them out of
// buildRuleset leaves that function small enough to assert the ORDER of the
// base rules, which is the part that decides whether the block can be bypassed.
const geoIncludeFile = "/etc/nftables/servika-geo.nft"

const (
	geoSetV4 = "servika_geo4"
	geoSetV6 = "servika_geo6"
)

// buildGeoSets renders the element file.
//
// An empty set is still DECLARED. The table body references @servika_geo4
// unconditionally, and nft rejects a rule naming a set that does not exist, so
// dropping the declaration when no country is blocked would fail the whole
// ruleset rather than block nothing.
func buildGeoSets(ranges geoip.Ranges) []byte {
	var body strings.Builder
	body.WriteString("\tset " + geoSetV4 + " {\n\t\ttype ipv4_addr\n\t\tflags interval\n")
	if len(ranges.V4) > 0 {
		body.WriteString("\t\telements = {\n")
		for index, network := range ranges.V4 {
			separator := ",\n"
			if index == len(ranges.V4)-1 {
				separator = "\n"
			}
			fmt.Fprintf(&body, "\t\t\t%s%s", network.CIDR, separator)
		}
		body.WriteString("\t\t}\n")
	}
	body.WriteString("\t}\n")

	body.WriteString("\tset " + geoSetV6 + " {\n\t\ttype ipv6_addr\n\t\tflags interval\n")
	if len(ranges.V6) > 0 {
		body.WriteString("\t\telements = {\n")
		for index, network := range ranges.V6 {
			separator := ",\n"
			if index == len(ranges.V6)-1 {
				separator = "\n"
			}
			fmt.Fprintf(&body, "\t\t\t%s%s", network.CIDR, separator)
		}
		body.WriteString("\t\t}\n")
	}
	body.WriteString("\t}\n")
	return []byte(body.String())
}

// blockedCountries reads the operator's country list.
func blockedCountries(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT country_code FROM firewall_geo_rules WHERE enabled=1 ORDER BY country_code`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	codes := make([]string, 0)
	for rows.Next() {
		var code string
		if rows.Scan(&code) == nil {
			if normalized := geoip.NormalizeCountry(code); normalized != "" {
				codes = append(codes, normalized)
			}
		}
	}
	return codes, rows.Err()
}

// writeGeoSets regenerates the element file from the stored country list.
func writeGeoSets(ctx context.Context, db *sql.DB) error {
	codes, err := blockedCountries(ctx, db)
	if err != nil {
		return err
	}
	var ranges geoip.Ranges
	if len(codes) > 0 && geoip.Available() {
		if found, lookupErr := geoip.Lookup(codes); lookupErr == nil {
			ranges = found
		} else {
			// A country the operator asked to block whose ranges cannot be read
			// is a silent hole, so it is reported rather than treated as empty.
			return fmt.Errorf("read the country ranges: %w", lookupErr)
		}
	}
	// #nosec G301 -- root-owned nftables configuration directory; it holds public address ranges, not secrets.
	if err := os.MkdirAll("/etc/nftables", 0o755); err != nil {
		return fmt.Errorf("create the nftables directory: %w", err)
	}
	// #nosec G306 -- root-owned nftables configuration file the nft tool must read; it carries public address ranges, not secrets.
	return os.WriteFile(geoIncludeFile, buildGeoSets(ranges), 0o644)
}

// Handlers for the operator's country list live on the firewall handler so the
// rebuild is the same one every other rule change goes through.

// ListGeo returns the blocked countries and the database behind them.
func (h *Handlers) ListGeo(w http.ResponseWriter, r *http.Request) {
	codes, err := blockedCountries(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country blocks could not be read")
		return
	}
	status, err := geoip.ReadStatus(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "country blocks could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"countries": codes,
		"database":  status,
	})
}

// AddGeo blocks a country for the whole server.
func (h *Handlers) AddGeo(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	code := geoip.NormalizeCountry(request.Country)
	if code == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "that is not a country code", "reason": geoip.ReasonCountryUnknown})
		return
	}
	// Without ranges the rule would be stored and enforce nothing, which is
	// worse on this screen than on a customer's: the operator would believe the
	// whole server was closed to that country.
	if !geoip.Available() {
		httpx.WriteJSON(w, http.StatusConflict, map[string]string{
			"error": "no country database has been downloaded", "reason": geoip.ReasonUnavailable})
		return
	}
	if !geoip.KnownCountry(code) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "the country database does not carry that country", "reason": geoip.ReasonCountryUnknown})
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT IGNORE INTO firewall_geo_rules(country_code) VALUES(?)`, code); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the country block could not be saved")
		return
	}
	if err := h.rebuild(); err != nil {
		log.Printf("firewall: apply the country block: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the country block was saved but the firewall was not updated")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

// DeleteGeo unblocks a country.
func (h *Handlers) DeleteGeo(w http.ResponseWriter, r *http.Request) {
	code := geoip.NormalizeCountry(chi.URLParam(r, "code"))
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "that is not a country code")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM firewall_geo_rules WHERE country_code=?`, code); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the country block could not be removed")
		return
	}
	if err := h.rebuild(); err != nil {
		log.Printf("firewall: remove the country block: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the block was removed but the firewall was not updated")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
