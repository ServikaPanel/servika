package antivirus

// The sweep as its own process, so a systemd timer can start one.
//
// It answers "-av-sweep" on this same binary, for the reason the scan worker
// and the watcher do: a second binary would carry a second copy of the rule set
// and an update that installed one and failed on the other would leave a sweep
// enforcing rules the panel no longer ships.
//
// Like the watcher and unlike the scan worker it DOES open the database, and
// for the same reason: the worker hands its findings to a parent through a
// file, while this has no parent to hand anything to. It then calls exactly the
// runSweep the handler and the in-process scheduler call, so a switch honoured
// on one path is honoured on all three.
//
// What it deliberately does NOT re-check is the HOUR. The timer's OnCalendar is
// what decides when this runs, and refusing here when the drop-in and the
// database disagree would mean no sweep at all rather than a sweep at the old
// hour. A sweep at the wrong hour is worth having; servika-verify reports the
// disagreement itself.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"servika/internal/avsettings"
	"servika/internal/db"
)

const sweepFlag = "av-sweep"

// RunSweepIfAsked answers "-av-sweep" and reports whether it did.
func RunSweepIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-"+sweepFlag && os.Args[1] != "--"+sweepFlag) {
		return false
	}
	if err := runSweepProcess(); err != nil {
		fmt.Fprintf(os.Stderr, "antivirus sweep: %v\n", err)
		os.Exit(1)
	}
	return true
}

// errSweepNotDue ends the process with a zero exit status.
//
// A timer unit that exits non-zero is recorded as `failed`, and `failed` is the
// one state a screen reads as broken. None of the reasons a sweep is skipped
// are failures: the operator switched the feature off, every detection layer is
// off, or one already ran. Each is reported on stdout, which the journal keeps.
var errSweepNotDue = errors.New("not due")

func runSweepProcess() error {
	dsn := strings.TrimSpace(os.Getenv("SERVIKA_DB_DSN"))
	if dsn == "" {
		return errors.New("SERVIKA_DB_DSN is required")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = handle.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
	defer cancel()

	if err := sweepNow(ctx, handle); err != nil {
		if errors.Is(err, errSweepNotDue) {
			return nil
		}
		return err
	}
	return nil
}

// sweepNow performs the checks that are still this process's to make, then runs
// the sweep. It is separate from runSweepProcess so a test can drive it with a
// database and without a flag.
func sweepNow(ctx context.Context, handle *sql.DB) error {
	settings, err := avsettings.Read(ctx, handle)
	if err != nil {
		return fmt.Errorf("the antivirus settings could not be read: %w", err)
	}
	// The timer can outlive the setting: `systemctl disable` may have failed,
	// or an operator may have enabled the unit by hand. The setting is what the
	// operator asked for, so it is checked here as well as where the timer is
	// written.
	if !settings.ScheduledScan {
		log.Print("antivirus: the scheduled sweep is switched off, doing nothing")
		return errSweepNotDue
	}
	if !settings.RuleEngine && !settings.LocationHeuristics {
		// A sweep with every layer off records a finished scan with no
		// findings, which reads exactly like a clean server. Both other paths
		// refuse this too.
		log.Print("antivirus: every detection layer is switched off, so a sweep would inspect nothing")
		return errSweepNotDue
	}
	// This is what stops a sweep the panel already ran by hand from being
	// repeated an hour later, and it is a cross-process check because it asks
	// the database rather than this process's memory.
	if recent, err := sweptRecently(ctx, handle, time.Now()); err != nil {
		// A failed read is NOT "no sweep yet". That direction sweeps the whole
		// filesystem on every timer firing for as long as the database is
		// unwell, which is the worst time to be adding load.
		return fmt.Errorf("whether a sweep is already due could not be read: %w", err)
	} else if recent {
		log.Print("antivirus: a sweep already ran inside the gap, doing nothing")
		return errSweepNotDue
	}

	slot, err := takeScanSlot(ctx, handle)
	if err != nil {
		// Not a failure either: the panel is running a scan right now. The next
		// firing will find it recorded and skip for the right reason.
		log.Print("antivirus: another scan is in progress, doing nothing")
		return errSweepNotDue
	}
	defer slot.Release()

	req := sweepRequest(settings)
	res, err := handle.ExecContext(ctx,
		`INSERT INTO av_scans (domain_id, scope, status, engine) VALUES (NULL,?,?,?)`,
		settings.Scope, "running", engineName())
	if err != nil {
		return fmt.Errorf("the sweep could not be recorded: %w", err)
	}
	sid, _ := res.LastInsertId()
	// #nosec G706 -- sid is an integer and req.Roots is one of two compiled-in literals ("/" or "/home"), chosen by a scope the write path validates against two constants. No tenant text reaches this line.
	log.Printf("antivirus: timed sweep %d starting over %v", sid, req.Roots)
	runSweep(ctx, handle, sid, req)
	return nil
}
