package antivirus

// Telling somebody a scan found something.
//
// The unit is the SCAN, never the finding. Upstream's version writes one
// notification per finding, so a sweep that turns up three hundred infected
// files writes three hundred rows and buries every other alert on the server
// under them. What an operator acts on is "this site is infected", once, with
// the count.
//
// Nothing here carries a tenant PATH. A notification is drawn on a screen and
// the file names come from a tenant's own tree, so the message is the domain
// name and three numbers; the paths are on the antivirus page, behind the
// ownership check that page already has.
//
// A failure to write is LOGGED and never returned upward. The scan itself
// succeeded and its findings are in the database; failing the scan because the
// alert about it could not be written would throw away the measurement to
// report the failure to tell somebody about it.

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"servika/internal/notifications"
)

// notifyCategory groups these on the screen and in the category filter.
const notifyCategory = "antivirus"

// notifySweep writes one alert per affected domain plus one panel-wide summary.
//
// The panel-wide row is not a duplicate of the per-domain ones: an operator
// watching a hundred sites needs "the sweep found seven files across three
// sites" in one line, and cannot see the per-domain rows for a customer they do
// not own anyway.
func notifySweep(ctx context.Context, db *sql.DB, scanID int64, perDomain map[int64]int, unowned int) {
	total := unowned
	for _, count := range perDomain {
		total += count
	}
	if total == 0 {
		// A clean sweep is not an event. Writing one would make the bell a
		// nightly heartbeat, and a badge that is always lit is a badge nobody
		// reads.
		return
	}

	for domainID, count := range perDomain {
		id := domainID
		name := domainName(ctx, db, id)
		event := notifications.Event{
			Level:    notifications.LevelCritical,
			Category: notifyCategory,
			Title:    "Malware found",
			Message:  fmt.Sprintf("The server sweep found %d infected file(s) on %s.", count, name),
			Key:      "antivirus.sweepDomain",
			Params:   map[string]any{"count": count, "domain": name},
			DomainID: &id,
			RefType:  "av_scan",
			RefID:    scanID,
		}
		if err := notifications.Write(ctx, db, event); err != nil {
			log.Printf("antivirus: the sweep alert for domain %d could not be written: %v", id, err)
		}
	}

	summary := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: notifyCategory,
		Title:    "Malware found by the server sweep",
		Message: fmt.Sprintf("The server sweep found %d infected file(s) across %d site(s).",
			total, len(perDomain)),
		Key: "antivirus.sweepServer",
		Params: map[string]any{
			"count": total, "sites": len(perDomain), "unowned": unowned,
		},
		RefType: "av_scan",
		RefID:   scanID,
	}
	if err := notifications.Write(ctx, db, summary); err != nil {
		log.Printf("antivirus: the sweep summary alert could not be written: %v", err)
	}
}

// notifyRealtime writes one alert for one file the watcher caught.
//
// Here the finding IS the unit: a real-time detection is one file, and the
// whole point of watching is that somebody hears about it now rather than at
// the next sweep.
func notifyRealtime(ctx context.Context, db *sql.DB, scanID int64, domainID sql.NullInt64, contained bool) {
	event := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: notifyCategory,
		Title:    "Malware caught as it was written",
		Key:      "antivirus.realtimeDetected",
		RefType:  "av_scan",
		RefID:    scanID,
	}
	name := ""
	if domainID.Valid {
		id := domainID.Int64
		event.DomainID = &id
		name = domainName(ctx, db, id)
	}
	event.Params = map[string]any{"domain": name, "contained": contained}
	if contained {
		event.Key = "antivirus.realtimeContained"
		event.Message = fmt.Sprintf("A file written on %s was found infected and moved to quarantine.", name)
	} else {
		event.Message = fmt.Sprintf("A file written on %s was found infected. It is still in place.", name)
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		log.Printf("antivirus: the real-time alert for scan %d could not be written: %v", scanID, err)
	}
}

// domainName reads a domain's name for the alert text.
//
// An unreadable name answers empty rather than failing the alert: the reader
// resolves the sentence from the message key and the domain id is on the row
// either way, so a missing name costs a word and losing the alert costs the
// event.
func domainName(ctx context.Context, db *sql.DB, id int64) string {
	var name string
	if err := db.QueryRowContext(ctx, `SELECT domain_name FROM domains WHERE id=?`, id).Scan(&name); err != nil {
		return ""
	}
	return name
}
