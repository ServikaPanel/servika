package domainblock

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/provisioner"
)

// maxEntriesPerRequest bounds one paste. The list is written by hand, so a
// request carrying more than this is a mistake rather than a bulk import, and
// the ceiling keeps a single request from holding the table open.
const maxEntriesPerRequest = 500

type Handlers struct {
	DB *sql.DB
}

// item is one row as the screen sees it.
type item struct {
	Domain          string `json:"domain"`
	Description     string `json:"description"`
	MatchSubdomains bool   `json:"match_subdomains"`
	CreatedBy       string `json:"created_by"`
	CreatedAt       string `json:"created_at"`
}

// writeResult reports a bulk write as what it was.
//
// A paste of forty names where six were already listed and two were malformed
// is not "done": the operator has to see which two never made it, or they will
// believe a name is banned when it is not.
type writeResult struct {
	Applied  int      `json:"applied"`
	Skipped  int      `json:"skipped"`
	Rejected []string `json:"rejected"`
}

// GET /admin/banned-domains
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT b.domain, b.description, b.match_subdomains,
		        COALESCE(u.username,''), DATE_FORMAT(b.created_at,'%Y-%m-%d %H:%i')
		   FROM banned_domains b
		   LEFT JOIN users u ON u.id = b.created_by
		  ORDER BY b.domain`)
	if err != nil {
		log.Printf("banned domain list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	out := make([]item, 0)
	for rows.Next() {
		var it item
		var match int
		if err := rows.Scan(&it.Domain, &it.Description, &match, &it.CreatedBy, &it.CreatedAt); err != nil {
			log.Printf("banned domain list scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		it.MatchSubdomains = match != 0
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		log.Printf("banned domain list rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// parseEntries turns one pasted blob into candidate hostnames.
//
// Operators paste from a report, one name per line or comma separated, so the
// separators are whatever whitespace and punctuation came with it. Nothing else
// is rewritten: a name that does not survive ValidateDomain is REPORTED back
// rather than repaired, because guessing what somebody meant is how a ban ends
// up covering a name they never wrote.
func parseEntries(blob string) []string {
	fields := strings.FieldsFunc(blob, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		name := Normalize(field)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

type writeReq struct {
	Domains         string `json:"domains"`
	Description     string `json:"description"`
	MatchSubdomains *bool  `json:"match_subdomains"`
}

// POST /admin/banned-domains adds one name or a pasted list.
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	var req writeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entries := parseEntries(req.Domains)
	if len(entries) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no domain name was given")
		return
	}
	if len(entries) > maxEntriesPerRequest {
		httpx.WriteError(w, http.StatusBadRequest, "too many domain names in one request")
		return
	}
	// The default is subdomains included, because a phisher hides the brand one
	// label down. The field is a pointer so an explicit false is told apart from
	// a body that never mentioned it.
	match := 1
	if req.MatchSubdomains != nil && !*req.MatchSubdomains {
		match = 0
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > 255 {
		description = description[:255]
	}

	var createdBy any
	if claims := middleware.ClaimsFrom(r); claims != nil && claims.UserID > 0 {
		createdBy = claims.UserID
	}

	result := writeResult{Rejected: []string{}}
	for _, name := range entries {
		if provisioner.ValidateDomain(name) != nil {
			result.Rejected = append(result.Rejected, name)
			continue
		}
		res, err := h.DB.ExecContext(r.Context(),
			`INSERT INTO banned_domains(domain, description, match_subdomains, created_by)
			 VALUES(?,?,?,?)
			 ON DUPLICATE KEY UPDATE description=VALUES(description), match_subdomains=VALUES(match_subdomains)`,
			name, description, match, createdBy)
		if err != nil {
			log.Printf("banned domain insert: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the list could not be written")
			return
		}
		// MariaDB answers 1 for an insert and 2 for a replaced row; both mean
		// the name is now banned as asked, and 0 means the row was already
		// exactly this.
		if affected, err := res.RowsAffected(); err == nil && affected == 0 {
			result.Skipped++
			continue
		}
		result.Applied++
	}
	Invalidate()
	httpx.WriteJSON(w, http.StatusOK, result)
}

type removeReq struct {
	Domains string `json:"domains"`
}

// POST /admin/banned-domains/remove lifts one name or a pasted list.
//
// It is a POST rather than a DELETE with the name in the path because a
// hostname in a URL segment has to survive percent-encoding on the way through
// nginx and the router, and one bulk shape serves both cases.
func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	var req removeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entries := parseEntries(req.Domains)
	if len(entries) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no domain name was given")
		return
	}
	if len(entries) > maxEntriesPerRequest {
		httpx.WriteError(w, http.StatusBadRequest, "too many domain names in one request")
		return
	}

	result := writeResult{Rejected: []string{}}
	for _, name := range entries {
		res, err := h.DB.ExecContext(r.Context(), `DELETE FROM banned_domains WHERE domain=?`, name)
		if err != nil {
			log.Printf("banned domain delete: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the list could not be written")
			return
		}
		affected, err := res.RowsAffected()
		if err != nil {
			log.Printf("banned domain delete count: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the list could not be written")
			return
		}
		if affected == 0 {
			result.Skipped++
			continue
		}
		result.Applied++
	}
	Invalidate()
	httpx.WriteJSON(w, http.StatusOK, result)
}
