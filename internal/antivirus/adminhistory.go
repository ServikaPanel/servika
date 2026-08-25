package antivirus

// What this server has ever found, across every scan and every domain.
//
// Three screens existed and none of them answered that question. The per-sweep
// detail answers "what did THIS sweep find", so a detection is only reachable
// through the run that produced it. The quarantine list answers "what is being
// HELD", so it says nothing at all about a finding nobody contained: a
// suspicious verdict, a WordPress core file the automatic pass deliberately
// skipped, a containment that failed. Those are exactly the findings somebody
// has to act on, and they were visible nowhere but inside one sweep's detail.
//
// The containment state is DERIVED from av_quarantine rather than read from a
// column, because that is where it lives. av_findings.quarantined says a file
// was taken at the moment the row was written and is never updated afterwards,
// so a file taken and then restored still reads as held. The join answers what
// is true now: no row means nothing was done, a row still open means the file
// is held, and a row with restored_at means it was put back.

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// HistoryEntry is one detection with what became of it.
type HistoryEntry struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	DomainID  int64  `json:"domain_id"`
	Domain    string `json:"domain"`
	File      string `json:"file"`
	Signature string `json:"signature"`
	Engine    string `json:"engine"`
	Score     int    `json:"score"`
	Level     string `json:"level"`
	Rules     string `json:"rules"`
	// State is what became of the file: "none", "quarantined" or "restored".
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// AdminHistory answers GET /admin/antivirus/history (ResellerOrAbove).
//
// The narrowing is in the QUERY and not in a middleware tier, because a
// row-by-row ownership check does not work on a list endpoint: the rows a
// reseller may not see would already have been read and counted.
//
// ScopeSQL cannot express it. A finding with a NULL domain_id sits outside every
// tenant home, belongs to no customer, and is the server operator's alone; that
// is a rule about a nullable column rather than a step in the ownership chain,
// and ScopeSQL returns its own leading WHERE with no room for one beside it.
// ScopeCondition returns the bare condition, which is the shape internal/
// notifications already uses for the same reason.
func (h *Handlers) AdminHistory(w http.ResponseWriter, r *http.Request) {
	condition, args, unrestricted := middleware.ScopeCondition(r, "d")
	// LEFT JOIN on domains, because a finding outside every tenant home has no
	// domain row at all and an inner join would drop it silently. LEFT JOIN on
	// av_quarantine for the same reason in the other direction: most findings
	// were never contained, and those are the ones this screen exists for.
	query := `SELECT f.id, f.scan_id, COALESCE(f.domain_id, 0), COALESCE(d.domain_name, ''),
	                 f.file, f.signature, f.engine, f.score, f.level, COALESCE(f.rules, ''),
	                 q.id, q.restored_at, f.created_at
	            FROM av_findings f
	            LEFT JOIN domains d ON d.id = f.domain_id
	            LEFT JOIN av_quarantine q ON q.finding_id = f.id`
	if !unrestricted {
		// This is also what keeps a NULL domain_id out of a reseller's list, and
		// the mechanism is worth naming because it is not a clause. The condition
		// is an EXISTS over customers keyed on d.customer_id, and the LEFT JOIN
		// leaves that column NULL for a finding with no domain, so the subquery
		// matches nothing and the row is dropped. An admin is unrestricted and
		// never reaches this branch, which is why such a finding is theirs alone.
		query += ` WHERE ` + condition
	}
	// id descending beside the timestamp, because created_at is a second-
	// resolution TIMESTAMP and one sweep writes many findings inside one second.
	// #nosec G202 -- adminMaxRows is a package constant, never caller text.
	query += ` ORDER BY f.created_at DESC, f.id DESC LIMIT ` + strconv.Itoa(adminMaxRows)

	// #nosec G202 G701 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		log.Printf("antivirus: the finding history could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the finding history")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []HistoryEntry{}
	for rows.Next() {
		var entry HistoryEntry
		var quarantineID sql.NullInt64
		var restored sql.NullString
		if err := rows.Scan(&entry.ID, &entry.ScanID, &entry.DomainID, &entry.Domain,
			&entry.File, &entry.Signature, &entry.Engine, &entry.Score, &entry.Level,
			&entry.Rules, &quarantineID, &restored, &entry.CreatedAt); err != nil {
			// A failed row is REPORTED, never skipped. A short list here reads as
			// a server that has found less than it has, which is the one answer
			// this screen must not invent.
			log.Printf("antivirus: a finding row could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the finding history")
			return
		}
		entry.State = quarantineState(quarantineID, restored)
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		log.Printf("antivirus: the finding history read ended early: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the finding history")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// quarantineState turns the join's two columns into what became of the file.
func quarantineState(quarantineID sql.NullInt64, restored sql.NullString) string {
	switch {
	case !quarantineID.Valid:
		return "none"
	case restored.Valid:
		return "restored"
	default:
		return "quarantined"
	}
}
