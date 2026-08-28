// Package chains is the attack-chain correlator (EDR Phase 2).
//
// The file scan and the process watcher each produce a SINGLE signal. An attack
// is a CHAIN: a webshell is written, a web process execs a shell, a payload is
// fetched, a cron line is added. Reporting each signal on its own is an
// antivirus; joining a tenant's signals inside a time window into "attack chain,
// confidence X%" is what moves the product toward EDR.
//
// FP-LAUNDERING GATE: purely temporal correlation (tenant + window) would
// launder two INDEPENDENT false positives into one critical chain. So CAUSALITY
// (the same full path, meaning a dropped file was executed, or the same pid) and
// TIME-ORDER weight the confidence, and a chain escalates to critical ONLY with
// a causal link or three-plus ordered stages. Two independent weak signals stay
// a warning. Same-DIRECTORY is deliberately not causal: a tenant document root
// holds many files, so two unrelated detections would share it.
//
// Both detectors write a stage-classified row to av_events (WriteEvent). This
// correlator runs on a ticker in the panel, groups a tenant's recent events, and
// declares a chain (an av_chains row plus one scoped notification) when at least
// two DISTINCT kill-chain stages appear. A single stage is NOT a chain.
package chains

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"servika/internal/notifications"
)

const (
	windowMin     = 15 // correlation window (minutes)
	tickSeconds   = 20 // how often a correlation round runs
	rededupeMin   = 30 // do not re-report the same chain signature within this
	domainCoolMin = 30 // per-domain cooldown window (signature-independent)
	domainMax     = 3  // most chains reported per domain inside the cooldown
	eventLimit    = 500
	retentionDays = 7  // prune av_events / av_chains older than this
	cleanupMin    = 60 // how often the retention job runs
	// notifyCategory groups these with the other antivirus alerts in the bell.
	// It is the literal antivirus uses; a shared const would need a leaf package,
	// and antivirus imports THIS package (never the reverse), so the string is
	// duplicated deliberately.
	notifyCategory = "antivirus"
	// insertDedupeSec suppresses a duplicate event (same domain, stage, path)
	// within this many seconds, so a detector firing in a loop cannot flood
	// av_events.
	insertDedupeSec = 30
	// queryTimeout bounds every correlation query.
	queryTimeout = 5 * time.Second
	// entryRededupMin is the window in which a second entry event for the same
	// account is suppressed. It is SMALLER than windowMin, so during a sustained
	// attack the entry event is re-emitted before the previous one leaves the
	// correlation window, leaving no blind gap in which a chain would miss it.
	entryRededupMin = 10
)

var (
	stageOrder = map[string]int{"entry": 0, "file_write": 1, "execution": 2, "c2": 3, "persistence": 4}
	stageName  = map[string]string{
		"entry": "Initial Access", "file_write": "File Write", "execution": "Execution",
		"c2": "C2", "persistence": "Persistence",
	}
)

// Event is one av_events row used for scoring. Path and Pid carry the causal
// evidence; Time is the row's created_at (parseTime=true makes it a time.Time),
// used only to order two events of THIS table against each other, never against
// SQL NOW().
type Event struct {
	Stage string
	Level string
	Path  string
	Pid   int
	Time  time.Time
}

// Result is a scored chain.
type Result struct {
	Confidence int
	Stages     []string
	Level      string
	Causal     bool
	Enough     bool
}

// ── Pure core (testable without a database) ─────────────────────────────────

// ChainScore turns a tenant's windowed events into a scored chain. It requires
// at least TWO distinct kill-chain stages, because a single signal is not a
// chain. Confidence is 40 + (distinct-1)*15, plus 25 for a causal link, plus 5
// when the stages are time-ordered, clamped to 99. The level is critical only
// with a causal link or three-plus ordered stages; otherwise a warning, which is
// what stops two independent weak signals from laundering into a critical alert.
func ChainScore(events []Event) Result {
	present := map[string]bool{}
	for _, e := range events {
		if _, ok := stageOrder[e.Stage]; ok {
			present[e.Stage] = true
		}
	}
	if len(present) < 2 {
		return Result{}
	}
	stages := make([]string, 0, len(present))
	for s := range present {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool { return stageOrder[stages[i]] < stageOrder[stages[j]] })

	distinct := len(present)
	causal := causalLink(events)
	ordered := timeOrdered(events, stages)

	confidence := 40 + (distinct-1)*15
	if causal {
		confidence += 25
	}
	if ordered {
		confidence += 5
	}
	if confidence > 99 {
		confidence = 99
	}
	level := notifications.LevelWarning
	if causal || (distinct >= 3 && ordered) {
		level = notifications.LevelCritical
	}
	return Result{Confidence: confidence, Stages: stages, Level: level, Causal: causal, Enough: true}
}

// causalLink reports whether two events of DIFFERENT stages are causally linked:
// the same pid (one process), or the same full path (a dropped file was run).
func causalLink(events []Event) bool {
	for i := range events {
		for j := i + 1; j < len(events); j++ {
			if events[i].Stage == events[j].Stage {
				continue
			}
			if events[i].Pid > 0 && events[i].Pid == events[j].Pid {
				return true
			}
			if pathLinked(events[i].Path, events[j].Path) {
				return true
			}
		}
	}
	return false
}

// pathLinked is true ONLY for the same full path (a dropped file was executed).
// Same-directory is deliberately not linked: a document root holds many files,
// so two unrelated detections would share it and reopen the FP-laundering.
func pathLinked(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return filepath.ToSlash(a) == filepath.ToSlash(b)
}

// timeOrdered reports whether each stage's FIRST occurrence follows kill-chain
// order in time. A zero/invalid time means not ordered, so the bonus is not
// given on incomplete data.
func timeOrdered(events []Event, stages []string) bool {
	first := map[string]time.Time{}
	for _, e := range events {
		if e.Time.IsZero() {
			return false
		}
		if t, ok := first[e.Stage]; !ok || e.Time.Before(t) {
			first[e.Stage] = e.Time
		}
	}
	for i := 1; i < len(stages); i++ {
		if first[stages[i]].Before(first[stages[i-1]]) {
			return false
		}
	}
	return true
}

// ChainSignature is the dedup key: the domain plus the ordered stage sequence.
func ChainSignature(domainID int64, stages []string) string {
	h := sha256.Sum256([]byte(strconv.FormatInt(domainID, 10) + "|" + strings.Join(stages, ">")))
	return hex.EncodeToString(h[:])[:32]
}

// StageName is the display name of one kill-chain stage ("File Write"), or the
// raw stage when it is unknown. The names are technical kill-chain terms and
// stay in English; the list endpoint sends them so the frontend does not carry a
// second copy of the mapping.
func StageName(stage string) string {
	if n := stageName[stage]; n != "" {
		return n
	}
	return stage
}

// StageSummary is the human-readable chain ("File Write → Execution").
func StageSummary(stages []string) string {
	names := make([]string, 0, len(stages))
	for _, s := range stages {
		if n := stageName[s]; n != "" {
			names = append(names, n)
		}
	}
	return strings.Join(names, " → ")
}

// ── DB-driven correlation ───────────────────────────────────────────────────

// WriteEvent records one stage-classified event. It is the ONE entry the
// detectors call, and it never fails the detection it describes: a write error
// is logged, not returned. An insert-dedup drops a repeat of the same
// (domain, stage, path) within insertDedupeSec, so a detector firing in a loop
// cannot flood av_events.
func WriteEvent(db *sql.DB, domainID int64, source, stage, level, summary, path string, pid int, refType string, refID int64) {
	if db == nil || domainID <= 0 {
		return
	}
	var seen int
	if db.QueryRow(
		`SELECT 1 FROM av_events WHERE domain_id=? AND stage=? AND path=?
		 AND created_at >= (NOW() - INTERVAL ? SECOND) LIMIT 1`,
		domainID, stage, truncate(path, 500), insertDedupeSec).Scan(&seen) == nil {
		return
	}
	_, err := db.Exec(
		`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid, ref_type, ref_id)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		domainID, source, stage, level, truncate(summary, 250), truncate(path, 500), pid, refType, refID)
	if err != nil {
		log.Printf("attack chain: the event could not be recorded: %v", err)
	}
}

// Start runs the correlation loop; call it as `go chains.Start(db)`. Each tick is
// wrapped in a recover so a correlation panic cannot crash the whole panel, and
// the retention job runs on its own slower cadence.
func Start(db *sql.DB) {
	if db == nil {
		return
	}
	t := time.NewTicker(tickSeconds * time.Second)
	defer t.Stop()
	lastCleanup := time.Now()
	for range t.C {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("attack chain correlation panicked (recovered): %v", r)
				}
			}()
			apiScan(db) // detect a panel brute-force success and record the entry stage
			if err := Run(db); err != nil {
				log.Printf("attack chain correlation: %v", err)
			}
		}()
		if time.Since(lastCleanup) > cleanupMin*time.Minute {
			prune(db)
			lastCleanup = time.Now()
		}
	}
}

// Run is one correlation round: for each tenant with an event in the window,
// score the chain and, when it is sufficient and neither the signature nor the
// domain is over its limit, write it and notify.
func Run(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	domains, err := windowedDomains(ctx, db)
	if err != nil {
		return err
	}
	for _, domainID := range domains {
		events, err := domainEvents(db, domainID)
		if err != nil || len(events) < 2 {
			continue
		}
		result := ChainScore(events)
		if !result.Enough {
			continue
		}
		signature := ChainSignature(domainID, result.Stages)
		if reportedRecently(db, signature) || domainSaturated(db, domainID) {
			continue
		}
		writeChain(db, domainID, result, len(events), signature)
	}
	return nil
}

// windowedDomains lists the tenants with at least one event in the window.
func windowedDomains(ctx context.Context, db *sql.DB) ([]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT domain_id FROM av_events
		WHERE domain_id IS NOT NULL AND created_at >= (NOW() - INTERVAL ? MINUTE)`, windowMin)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var d int64
		if rows.Scan(&d) == nil && d > 0 {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// domainEvents reads one tenant's windowed events, bounded by eventLimit and a
// timeout so a flood cannot exhaust memory or hang the round.
// domainOwners resolves a domain to the two accounts that own it: the reseller
// (customers.owner_user_id) and the customer user (customers.user_id). Either
// may be absent. A missing or unreadable owner is returned as the sentinel -1,
// which matches no account, so a failed lookup links no entry event rather than
// falling back to a real account.
func domainOwners(ctx context.Context, db *sql.DB, domainID int64) (reseller, user int64) {
	reseller, user = -1, -1
	var r, u sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT c.owner_user_id, c.user_id FROM domains d
		 JOIN customers c ON c.id = d.customer_id WHERE d.id = ?`, domainID).Scan(&r, &u)
	if err != nil {
		return -1, -1
	}
	if r.Valid && r.Int64 > 0 {
		reseller = r.Int64
	}
	if u.Valid && u.Int64 > 0 {
		user = u.Int64
	}
	return reseller, user
}

func domainEvents(db *sql.DB, domainID int64) ([]Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	// An entry (Initial Access) event has a NULL domain_id and is keyed to the
	// brute-forced account. Pull it into this domain's chain when its account
	// OWNS the domain, resolved live from the ownership chain. A failed lookup
	// yields a sentinel that matches no account, never a fallback that would link
	// an unrelated login (the isolation rule).
	reseller, user := domainOwners(ctx, db, domainID)
	rows, err := db.QueryContext(ctx, `SELECT stage, level, path, pid, created_at FROM av_events
		WHERE (domain_id=? OR (domain_id IS NULL AND stage='entry' AND actor_user_id IN (?,?)))
		  AND created_at >= (NOW() - INTERVAL ? MINUTE)
		ORDER BY created_at LIMIT ?`, domainID, reseller, user, windowMin, eventLimit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		var path sql.NullString
		var pid sql.NullInt64
		var ts sql.NullTime // parseTime=true makes a TIMESTAMP a time.Time, not a string
		if rows.Scan(&e.Stage, &e.Level, &path, &pid, &ts) == nil {
			e.Path = path.String
			e.Pid = int(pid.Int64)
			e.Time = ts.Time
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// reportedRecently reports whether a chain of this signature was written within
// the re-dedup window. It FAILS CLOSED (true) on a query error, so a transient
// database problem skips the alert rather than repeating it.
func reportedRecently(db *sql.DB, signature string) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_chains
		WHERE signature=? AND created_at >= (NOW() - INTERVAL ? MINUTE)`, signature, rededupeMin).Scan(&n); err != nil {
		log.Printf("attack chain: the dedup query failed: %v", err)
		return true
	}
	return n > 0
}

// domainSaturated caps the chains reported per domain in the cooldown window,
// independent of the signature, so a shifting subset of stages cannot spam the
// bell. It FAILS CLOSED on a query error.
func domainSaturated(db *sql.DB, domainID int64) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_chains
		WHERE domain_id=? AND created_at >= (NOW() - INTERVAL ? MINUTE)`, domainID, domainCoolMin).Scan(&n); err != nil {
		return true
	}
	return n >= domainMax
}

// writeChain records the chain and sends one scoped notification.
func writeChain(db *sql.DB, domainID int64, r Result, eventCount int, signature string) {
	res, err := db.Exec(`INSERT INTO av_chains
		(domain_id, stages, confidence, level, event_count, signature)
		VALUES (?,?,?,?,?,?)`, domainID, strings.Join(r.Stages, ">"), r.Confidence, r.Level, eventCount, signature)
	if err != nil {
		log.Printf("attack chain: the chain could not be recorded: %v", err)
		return
	}
	chainID, _ := res.LastInsertId()
	notify(db, domainID, chainID, r)
	log.Printf("ATTACK CHAIN [%s confidence %d causal=%v] domain=%d: %s",
		r.Level, r.Confidence, r.Causal, domainID, StageSummary(r.Stages))
}

// notify writes one scoped alert. It carries the domain, the kill-chain stage
// summary and the confidence, never a tenant path: the paths belong to the
// underlying findings on the antivirus page. The level (warning vs critical)
// already conveys whether a causal link was found.
func notify(db *sql.DB, domainID, chainID int64, r Result) {
	ctx := context.Background()
	name := domainName(ctx, db, domainID)
	summary := StageSummary(r.Stages)
	event := notifications.Event{
		Level:    r.Level,
		Category: notifyCategory,
		Title:    "Attack chain detected",
		Message:  fmt.Sprintf("Attack chain detected on %s: %s — confidence %d%%.", name, summary, r.Confidence),
		Key:      "chain.detected",
		Params:   map[string]any{"domain": name, "stages": summary, "confidence": r.Confidence},
		DomainID: &domainID,
		RefType:  "av_chain",
		RefID:    chainID,
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		log.Printf("attack chain: the alert for domain %d could not be written: %v", domainID, err)
	}
}

// prune drops rows past the retention, in bounded batches so one DELETE cannot
// lock the table, on its own timeout.
func prune(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, table := range []string{"av_events", "av_chains"} {
		for range 20 { // at most 20 x 5000 rows per table per run
			// #nosec G202 -- table is a hardcoded literal from the loop above, never user input
			r, err := db.ExecContext(ctx,
				"DELETE FROM "+table+" WHERE created_at < (NOW() - INTERVAL ? DAY) LIMIT 5000", retentionDays)
			if err != nil {
				log.Printf("attack chain: pruning %s failed: %v", table, err)
				break
			}
			if n, _ := r.RowsAffected(); n < 5000 {
				break
			}
		}
	}
}

// domainName resolves a domain id to its name for the alert text.
func domainName(ctx context.Context, db *sql.DB, id int64) string {
	var name string
	if err := db.QueryRowContext(ctx, `SELECT domain_name FROM domains WHERE id=?`, id).Scan(&name); err != nil {
		return ""
	}
	return name
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
