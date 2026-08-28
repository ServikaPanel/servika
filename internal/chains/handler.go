package chains

// The attack-chain list endpoint. It is the data source for the live-attack
// screen: the most recent chains a caller is entitled to see, each with the
// timeline of events that formed it.
//
// Scope is resolved through the ownership chain, never a reseller_id column
// (av_chains carries none, by design). middleware.ScopeCondition narrows the
// query: an admin is unrestricted and sees the panel-wide (NULL domain_id)
// chains too; a reseller or customer sees only chains whose domain they own,
// and the LEFT JOIN leaves a NULL-domain chain's ownership NULL so their EXISTS
// never matches it. This is the same shape the antivirus finding-history
// endpoint uses.

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

type Handlers struct{ DB *sql.DB }

// EventDTO is one event on a chain's timeline.
type EventDTO struct {
	Source    string `json:"source"`
	Stage     string `json:"stage"`
	StageName string `json:"stage_name"`
	Level     string `json:"level"`
	Summary   string `json:"summary"`
	Time      string `json:"time"`
}

// ChainDTO is one attack chain with its stages and event timeline.
type ChainDTO struct {
	ID         int64      `json:"id"`
	DomainID   *int64     `json:"domain_id"`
	Domain     string     `json:"domain"`
	Stages     []string   `json:"stages"`
	StageNames []string   `json:"stage_names"`
	Confidence int        `json:"confidence"`
	Level      string     `json:"level"`
	Time       string     `json:"time"`
	Events     []EventDTO `json:"events"`
}

// chainListLimit bounds the live screen to the most recent chains.
const chainListLimit = 50

// List answers GET /antivirus/chains with the caller's most recent chains,
// each with its event timeline. The rows are ordered newest first.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	cond, args, _ := middleware.ScopeCondition(r, "d")

	// An entry (Initial Access) event is a login attack on an ACCOUNT, so a
	// customer never sees it, only an admin or the owning reseller. A customer
	// caller resolves no entry owners, so the entry branch of the timeline query
	// matches nothing for them.
	entryVisible := false
	if c := middleware.ClaimsFrom(r); c != nil && c.Role != middleware.RoleUser {
		entryVisible = true
	}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	// #nosec G202 G701 -- cond is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(ctx,
		`SELECT z.id, z.domain_id, COALESCE(d.domain_name,''), z.stages, z.confidence, z.level,
		        DATE_FORMAT(z.created_at,'%Y-%m-%d %H:%i:%s')
		 FROM av_chains z LEFT JOIN domains d ON d.id = z.domain_id
		 WHERE `+cond+`
		 ORDER BY z.created_at DESC LIMIT ?`, append(args, chainListLimit)...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "attack chains could not be read")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []ChainDTO{}
	for rows.Next() {
		var c ChainDTO
		var dom sql.NullInt64
		var stageStr string
		if err := rows.Scan(&c.ID, &dom, &c.Domain, &stageStr, &c.Confidence, &c.Level, &c.Time); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "an attack chain could not be read")
			return
		}
		if dom.Valid {
			c.DomainID = &dom.Int64
		}
		c.Stages = strings.Split(stageStr, ">")
		c.StageNames = make([]string, 0, len(c.Stages))
		for _, s := range c.Stages {
			c.StageNames = append(c.StageNames, StageName(s))
		}
		if dom.Valid {
			reseller, user := int64(-1), int64(-1)
			if entryVisible {
				reseller, user = domainOwners(ctx, h.DB, dom.Int64)
			}
			c.Events = h.chainEvents(ctx, dom.Int64, c.Time, cond, args, reseller, user)
		}
		out = append(out, c)
	}
	// A query that broke halfway would otherwise answer 200 with a short list,
	// and a screen that reports attacks must not under-report them.
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "attack chains could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"chains": out})
}

// chainEvents reads the timeline for one chain's domain: the events in the
// correlation window ending at the chain's time. The domain events are scoped by
// the CALLER's own condition, not only by the chain's stored domain_id, so it
// cannot be trusted to leak: the outer query already hides a chain whose domain
// the caller no longer owns (scope is resolved live from the ownership chain),
// but scoping the events query too keeps it self-securing if the outer query is
// ever changed. The entry (Initial Access) event has its OWN scope, the actor
// match: it is a NULL-domain login event that the domain-branch cond can never
// pass, and the entryReseller/entryUser owners (already -1 for a customer caller)
// decide who sees it. It is best-effort: a read error leaves the chain without a
// timeline rather than failing the whole list.
func (h *Handlers) chainEvents(ctx context.Context, domID int64, at, cond string, condArgs []any, entryReseller, entryUser int64) []EventDTO {
	args := []any{domID}
	args = append(args, condArgs...)
	args = append(args, entryReseller, entryUser, at, at, windowMin, eventLimit)
	// #nosec G202 G701 -- cond is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(ctx,
		`SELECT e.source, e.stage, e.level, e.summary, DATE_FORMAT(e.created_at,'%Y-%m-%d %H:%i:%s')
		 FROM av_events e LEFT JOIN domains d ON d.id = e.domain_id
		 WHERE ((e.domain_id = ? AND `+cond+`)
		        OR (e.domain_id IS NULL AND e.stage='entry' AND e.actor_user_id IN (?,?)))
		   AND e.created_at <= ? AND e.created_at >= (? - INTERVAL ? MINUTE)
		 ORDER BY e.created_at LIMIT ?`, args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []EventDTO
	for rows.Next() {
		var e EventDTO
		if err := rows.Scan(&e.Source, &e.Stage, &e.Level, &e.Summary, &e.Time); err != nil {
			return out
		}
		e.StageName = StageName(e.Stage)
		out = append(out, e)
	}
	return out
}
