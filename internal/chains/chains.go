// Package chains is the attack-chain correlator (EDR Phase 2).
//
// The file scan and the process watcher each produce a SINGLE signal. An attack
// is a CHAIN: a webshell is written, a web process execs a shell, a payload is
// fetched, a cron line is added. Reporting each signal on its own is an
// antivirus; joining a tenant's signals inside a time window into "attack chain,
// confidence X%" is what moves the product toward EDR.
//
// Both detectors write a stage-classified row to av_events (WriteEvent). This
// correlator runs on a ticker in the panel: it groups a tenant's recent events,
// and when at least two DISTINCT kill-chain stages appear it declares a chain
// (an av_chains row plus one scoped notification). A single stage is NOT a
// chain, which is what keeps a lone detection from raising a chain alert.
package chains

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
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
	retentionDays = 7  // prune av_events older than this
	// confidenceCritical is the confidence at or above which the notification is
	// raised to critical rather than a warning.
	confidenceCritical = 80
	// notifyCategory groups these with the other antivirus alerts in the bell.
	// It is the literal antivirus uses; a shared const would need a leaf package,
	// and antivirus imports THIS package (never the reverse), so the string is
	// duplicated deliberately.
	notifyCategory = "antivirus"
)

// stageOrder is the kill-chain order the stages are sorted into. stageName is
// the human-readable label; the labels are kill-chain terms and stay in English
// (a technical term is never translated), so they travel as a notification
// parameter rather than a localized string.
var (
	stageOrder = map[string]int{"entry": 0, "file_write": 1, "execution": 2, "c2": 3, "persistence": 4}
	stageName  = map[string]string{
		"entry": "Initial Access", "file_write": "File Write", "execution": "Execution",
		"c2": "C2", "persistence": "Persistence",
	}
)

// Event is a simplified av_events row used for scoring. It deliberately carries
// no timestamp: the window is enforced in SQL, and the score uses only the
// stage and the level, so a Go-side time never has to agree with SQL NOW().
type Event struct {
	Stage string
	Level string
}

// ── Pure core (testable without a database) ─────────────────────────────────

// ChainScore turns a tenant's windowed events into a confidence score and the
// ordered stage sequence. It requires at least TWO distinct kill-chain stages,
// because a single signal is not a chain and folding one into a chain would turn
// every lone detection into a chain alert.
//
// Confidence is 40 + (distinct-1)*20 (two stages 60, three 80, four 100), plus 5
// when any event is critical, plus 5 for the classic file_write+execution pair,
// clamped to 99.
func ChainScore(events []Event) (confidence int, stages []string, enough bool) {
	present := map[string]bool{}
	critical := false
	for _, e := range events {
		if _, ok := stageOrder[e.Stage]; !ok {
			continue // an unknown stage is ignored
		}
		present[e.Stage] = true
		if e.Level == "critical" {
			critical = true
		}
	}
	if len(present) < 2 {
		return 0, nil, false
	}
	for s := range present {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool { return stageOrder[stages[i]] < stageOrder[stages[j]] })

	confidence = 40 + (len(present)-1)*20
	if critical {
		confidence += 5
	}
	if present["file_write"] && present["execution"] {
		confidence += 5 // the strongest chain core: something written, then run
	}
	if confidence > 99 {
		confidence = 99
	}
	return confidence, stages, true
}

// ChainSignature is the dedup key: the domain plus the ordered stage sequence,
// so the same chain is not reported over and over.
func ChainSignature(domainID int64, stages []string) string {
	h := sha256.Sum256([]byte(strconv.FormatInt(domainID, 10) + "|" + strings.Join(stages, ">")))
	return hex.EncodeToString(h[:])[:32]
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
// is logged, not returned, so a scan or a watch cannot break because the event
// could not be recorded.
func WriteEvent(db *sql.DB, domainID int64, source, stage, level, summary, refType string, refID int64) {
	if db == nil || domainID <= 0 {
		return
	}
	_, err := db.Exec(
		`INSERT INTO av_events (domain_id, source, stage, level, summary, ref_type, ref_id)
		 VALUES (?,?,?,?,?,?,?)`,
		domainID, source, stage, level, truncate(summary, 250), refType, refID)
	if err != nil {
		log.Printf("attack chain: the event could not be recorded: %v", err)
	}
}

// Start runs the correlation loop; call it as `go chains.Start(db)`. The tick is
// cheap when idle: with no events in the window the first query returns nothing.
func Start(db *sql.DB) {
	if db == nil {
		return
	}
	t := time.NewTicker(tickSeconds * time.Second)
	defer t.Stop()
	for range t.C {
		if err := Run(db); err != nil {
			log.Printf("attack chain correlation: %v", err)
		}
	}
}

// Run is one correlation round: for each tenant with an event in the window,
// score the chain and, when it is sufficient and its signature was not reported
// recently, write it and notify. It then prunes events past the retention.
func Run(db *sql.DB) error {
	domains, err := windowedDomains(db)
	if err != nil {
		return err
	}
	for _, domainID := range domains {
		events, err := domainEvents(db, domainID)
		if err != nil || len(events) < 2 {
			continue
		}
		confidence, stages, ok := ChainScore(events)
		if !ok {
			continue
		}
		signature := ChainSignature(domainID, stages)
		if reportedRecently(db, signature) {
			continue
		}
		writeChain(db, domainID, stages, confidence, len(events), signature)
	}
	pruneEvents(db)
	return nil
}

// windowedDomains lists the tenants with at least one event in the window.
func windowedDomains(db *sql.DB) ([]int64, error) {
	rows, err := db.Query(`SELECT DISTINCT domain_id FROM av_events
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

// domainEvents reads one tenant's windowed events.
func domainEvents(db *sql.DB, domainID int64) ([]Event, error) {
	rows, err := db.Query(`SELECT stage, level FROM av_events
		WHERE domain_id=? AND created_at >= (NOW() - INTERVAL ? MINUTE)
		ORDER BY created_at`, domainID, windowMin)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		if rows.Scan(&e.Stage, &e.Level) == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// reportedRecently reports whether a chain of this signature was written within
// the re-dedup window.
func reportedRecently(db *sql.DB, signature string) bool {
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM av_chains
		WHERE signature=? AND created_at >= (NOW() - INTERVAL ? MINUTE)`, signature, rededupeMin).Scan(&n)
	return n > 0
}

// writeChain records the chain and sends one scoped notification.
func writeChain(db *sql.DB, domainID int64, stages []string, confidence, eventCount int, signature string) {
	res, err := db.Exec(`INSERT INTO av_chains
		(domain_id, stages, confidence, event_count, signature)
		VALUES (?,?,?,?,?)`, domainID, strings.Join(stages, ">"), confidence, eventCount, signature)
	if err != nil {
		log.Printf("attack chain: the chain could not be recorded: %v", err)
		return
	}
	chainID, _ := res.LastInsertId()
	notify(db, domainID, chainID, stages, confidence)
	log.Printf("ATTACK CHAIN [confidence %d] domain=%d: %s", confidence, domainID, StageSummary(stages))
}

// notify writes one scoped alert. It carries the domain, the kill-chain stage
// summary and the confidence, never a tenant path: the paths belong to the
// underlying findings on the antivirus page.
func notify(db *sql.DB, domainID, chainID int64, stages []string, confidence int) {
	ctx := context.Background()
	name := domainName(ctx, db, domainID)
	summary := StageSummary(stages)
	level := notifications.LevelWarning
	if confidence >= confidenceCritical {
		level = notifications.LevelCritical
	}
	event := notifications.Event{
		Level:    level,
		Category: notifyCategory,
		Title:    "Attack chain detected",
		Message:  fmt.Sprintf("Attack chain detected on %s: %s — confidence %d%%.", name, summary, confidence),
		Key:      "chain.detected",
		Params:   map[string]any{"domain": name, "stages": summary, "confidence": confidence},
		DomainID: &domainID,
		RefType:  "av_chain",
		RefID:    chainID,
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		log.Printf("attack chain: the alert for domain %d could not be written: %v", domainID, err)
	}
}

// pruneEvents drops events past the retention. The window only ever reads the
// last windowMin minutes, so nothing older is needed for correlation; the
// retention leaves recent history for a future screen while bounding the table.
func pruneEvents(db *sql.DB) {
	if _, err := db.Exec(
		`DELETE FROM av_events WHERE created_at < (NOW() - INTERVAL ? DAY)`, retentionDays); err != nil {
		log.Printf("attack chain: old events could not be pruned: %v", err)
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
