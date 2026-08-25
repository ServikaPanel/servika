package antivirus

// Containing a critical finding without being asked to, once the operator has
// asked to be asked no longer.
//
// The switch defaults to off and that is not a statement about readiness. Moving
// a customer's file is the one action here that a wrong verdict makes expensive,
// so an operator turns it on once they have watched the engine behave on their
// own server. The same reason panel_settings.host_apps_enabled and
// session_idle_minutes default to off: a panel update must not start doing
// something an installation has never done.
//
// Only CRITICAL findings are taken. A suspicious one is, by construction, two
// signals neither of which convicts on its own, and the weighing exists exactly
// so that such a file is reported to a person rather than acted on.

import (
	"context"
	"database/sql"
	"log"
)

// autoQuarantineOutcome is what one automatic pass did. Both halves are
// reported: a run that left files behind is not a finished cleanup, and
// reporting only the successes hides the one case that matters.
type autoQuarantineOutcome struct {
	Taken  int
	Failed int
	// CoreSkipped counts the WordPress core files that were reported and
	// deliberately left in place. It is neither a success nor a failure, and
	// folding it into either would say something untrue about the pass.
	CoreSkipped int
}

// autoQuarantine contains the critical findings of one scan.
//
// It reads the findings back from the database rather than taking the in-memory
// list, because containment needs the row id it was written with, and because a
// finding that failed to insert must not be reported as one that was contained.
func (h *Handlers) autoQuarantine(ctx context.Context, scanID int64) autoQuarantineOutcome {
	var out autoQuarantineOutcome

	type target struct {
		findingID  int64
		domainID   int64
		systemUser string
		file       string
		signature  string
	}
	var targets []target

	// The join is what restricts this to a tenant's own tree: a finding with no
	// domain has nowhere to be contained into, and one whose domain has been
	// deleted since the scan has no home directory left either.
	//
	// The engine test excludes a finding whose subject is not a file. Selecting
	// it and letting the containment refuse would count the refusal in
	// auto_quarantine_failed, which sends an operator after a fault that is not
	// there; the narrowing is in the QUERY so the count is right by construction
	// rather than by a branch further down.
	rows, err := h.DB.QueryContext(ctx,
		`SELECT f.id, f.domain_id, d.system_user, f.file, f.signature
		   FROM av_findings f JOIN domains d ON d.id = f.domain_id
		  WHERE f.scan_id=? AND f.level=? AND f.quarantined=0 AND f.engine <> ?`,
		scanID, LevelCritical, EngineDatabase)
	if err != nil {
		// #nosec G706 -- logged values are an integer scan id and a database error; no raw tenant string with CR/LF reaches the log.
		log.Printf("antivirus: automatic containment could not read the findings of scan %d: %v", scanID, err)
		return out
	}
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.findingID, &t.domainID, &t.systemUser, &t.file, &t.signature); err != nil {
			continue
		}
		targets = append(targets, t)
	}
	closeErr := rows.Err()
	_ = rows.Close()
	if closeErr != nil {
		// A short list here would silently leave files behind while reporting a
		// completed pass, so the ones that were read are still contained and the
		// rest are counted as failures rather than forgotten.
		// #nosec G706 -- logged values are an integer scan id and a database error; no raw tenant string with CR/LF reaches the log.
		log.Printf("antivirus: the finding list for scan %d was cut short: %v", scanID, closeErr)
		out.Failed++
	}

	// The containment runs OUTSIDE the rows loop. quarantineFinding issues
	// several statements of its own, and holding a result set open across them
	// on a single connection is what turns one slow containment into a stalled
	// pass.
	for _, t := range targets {
		// A WordPress core file is reported and left alone. It is counted
		// separately rather than as a failure, because nothing went wrong and a
		// figure in the failed column would send an operator looking for a fault
		// that is not there.
		if CoreFileProtected(t.file, t.signature) {
			out.CoreSkipped++
			continue
		}
		if reason := h.quarantineFinding(t.domainID, t.systemUser, t.findingID); reason != "" {
			// #nosec G706 -- logged values are integer ids and a fixed reason code from this package; no raw tenant string reaches the log.
			log.Printf("antivirus: finding %d could not be contained automatically: %s", t.findingID, reason)
			out.Failed++
			continue
		}
		out.Taken++
	}
	return out
}

// recordAutoQuarantine writes what the pass did beside the scan.
func recordAutoQuarantine(db *sql.DB, scanID int64, out autoQuarantineOutcome) {
	if _, err := db.Exec(
		`UPDATE av_scans SET auto_quarantined=?, auto_quarantine_failed=?, auto_quarantine_core_skipped=? WHERE id=?`,
		out.Taken, out.Failed, out.CoreSkipped, scanID); err != nil {
		// #nosec G706 -- logged values are an integer scan id and a database error; no raw tenant string with CR/LF reaches the log.
		log.Printf("antivirus: what automatic containment did to scan %d could not be recorded: %v", scanID, err)
	}
}
