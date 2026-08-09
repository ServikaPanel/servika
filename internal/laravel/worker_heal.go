package laravel

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"regexp"
	"strconv"

	"servika/internal/config"
)

// reWorkerUnitFile matches a template this package owns, so healing never
// touches a unit somebody else put in the same directory.
var reWorkerUnitFile = regexp.MustCompile(`^servika-laravel-queue-([0-9]+)@\.service$`)

// reLegacyQueueUnit matches the single-worker unit this package used to write,
// one per DOMAIN and with no instance. Nothing produces it any more, so any
// that survive an upgrade are removed: they run against a schema that is gone.
var reLegacyQueueUnit = regexp.MustCompile(`^servika-laravel-queue-([0-9]+)\.service$`)

// reScheduleCron matches the schedule entry, which is named after the domain.
var reScheduleCron = regexp.MustCompile(`^servika-laravel-([0-9]+)$`)

// TeardownForDomain removes everything the toolkit put on the host for one
// domain.
//
// This has to be called from the domain delete path. Nothing else reaches these
// files, so without it the unit keeps running as a login userdel just removed
// and the cron entry keeps trying to run a scheduler in a directory that is
// gone. Every step is best effort so a missing piece does not strand the rest.
func TeardownForDomain(ctx context.Context, db *sql.DB, domainID int64) {
	workers, err := WorkersForDomain(ctx, db, domainID)
	if err != nil {
		// The rows cannot be read, so the ids are unknown. Say so rather than
		// return quietly: what is left behind is a running process.
		log.Printf("laravel: read the workers of domain %d for teardown: %v", domainID, err)
	}
	for _, worker := range workers {
		TeardownWorker(worker.ID)
	}
	// The schedule and the legacy single worker are named after the DOMAIN, so
	// they are removed whether or not any worker row was readable.
	_ = os.Remove(cronPath(domainID))
	stopInstance(legacyQueueUnit(domainID))
	_ = os.Remove(legacyQueueUnitPath(domainID))
	_, _ = workerCommand("systemctl", "daemon-reload").CombinedOutput()
}

func legacyQueueUnit(domainID int64) string {
	return "servika-laravel-queue-" + strconv.FormatInt(domainID, 10) + ".service"
}

func legacyQueueUnitPath(domainID int64) string {
	return unitDir + "/" + legacyQueueUnit(domainID)
}

// HealOnStartup brings the host back in line with the database.
//
// Three things drift. A unit can be missing after a restore that brought the
// database back but not /etc. An enabled worker can be down after a reboot that
// raced its dependencies. And a unit can outlive its row when a delete only half
// completed, which matters most: that worker still processes jobs under a name
// the panel can no longer show, let alone stop.
func HealOnStartup(db *sql.DB) {
	ctx := context.Background()
	workers, err := AllWorkers(ctx, db)
	if err != nil {
		log.Printf("laravel: startup heal could not read the workers: %v", err)
		return
	}
	known := make(map[int64]bool, len(workers))
	for _, worker := range workers {
		known[worker.ID] = true
		healWorker(ctx, db, worker)
	}
	removeOrphanWorkerUnits(ctx, db, known)
}

// healWorker repairs one worker's presence on the host.
func healWorker(ctx context.Context, db *sql.DB, worker Worker) {
	var systemUser, phpVersion, appRoot string
	if err := db.QueryRowContext(ctx,
		`SELECT d.system_user, COALESCE(d.php_version,'8.3'), COALESCE(a.app_root,'public_html')
		   FROM domains d
		   LEFT JOIN cp_laravel_apps a ON a.domain_id = d.id
		  WHERE d.id=?`, worker.DomainID).Scan(&systemUser, &phpVersion, &appRoot); err != nil {
		log.Printf("laravel: heal worker %d: read its domain: %v", worker.ID, err)
		return
	}
	appDir, err := safeAppDir(systemUser, appRoot)
	if err != nil {
		log.Printf("laravel: heal worker %d: %v", worker.ID, err)
		return
	}

	want := RenderWorkerUnit(worker, worker.DomainID, systemUser, appDir, phpBin(phpVersion))
	// #nosec G304 -- a fixed path this package owns, named after a row id.
	have, readErr := os.ReadFile(UnitTemplatePath(worker.ID))
	status := ReadWorkerStatus(worker)

	// Re-apply when the unit drifted, when an enabled worker is short of the
	// processes it asked for, or when a stopped one is still running. The last
	// case is not hypothetical: Restart=always brings back a process killed by
	// anything other than systemd.
	drifted := readErr != nil || string(have) != want
	shortOfProcesses := worker.Enabled && status.Running < worker.Processes
	runningWhenStopped := !worker.Enabled && status.Running > 0
	if !drifted && !shortOfProcesses && !runningWhenStopped {
		return
	}
	if err := ApplyWorker(worker, worker.DomainID, systemUser, appDir, phpBin(phpVersion)); err != nil {
		log.Printf("laravel: heal worker %d: %v", worker.ID, err)
		return
	}
	log.Printf("laravel: reapplied worker %d of domain %d", worker.ID, worker.DomainID)
}

// removeOrphanWorkerUnits tears down units and cron entries whose row is gone.
func removeOrphanWorkerUnits(ctx context.Context, db *sql.DB, known map[int64]bool) {
	entries, err := os.ReadDir(unitDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if match := reWorkerUnitFile.FindStringSubmatch(name); match != nil {
			id, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil || known[id] {
				continue
			}
			log.Printf("laravel: removing %s, which has no worker row", name)
			TeardownWorker(id)
			continue
		}
		// The legacy per-domain unit is removed unconditionally: this package
		// no longer produces that shape, so one surviving an upgrade is running
		// against a schema that was dropped.
		if match := reLegacyQueueUnit.FindStringSubmatch(name); match != nil {
			log.Printf("laravel: removing %s, which predates the worker definitions", name)
			stopInstance(name)
			_ = os.Remove(unitDir + "/" + name)
			_, _ = workerCommand("systemctl", "daemon-reload").CombinedOutput()
		}
	}
	removeOrphanScheduleCrons(ctx, db)
	removeOrphanWorkerLogs(known)
}

// removeOrphanScheduleCrons drops a schedule entry whose domain is gone.
//
// The check is fail-CLOSED in the direction that matters: only sql.ErrNoRows,
// which is the database positively saying the domain does not exist, removes a
// file. Any other error leaves it alone, because deleting on an unreadable
// database would take out the scheduler of every live domain at once.
func removeOrphanScheduleCrons(ctx context.Context, db *sql.DB) {
	entries, err := os.ReadDir(cronDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		match := reScheduleCron.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		id, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			continue
		}
		var exists int
		err = db.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE id=?`, id).Scan(&exists)
		if !errors.Is(err, sql.ErrNoRows) {
			continue
		}
		log.Printf("laravel: removing the schedule of domain %d, which no longer exists", id)
		_ = os.Remove(cronDir + "/" + entry.Name())
	}
}

// removeOrphanWorkerLogs drops the log of a worker that no longer exists.
func removeOrphanWorkerLogs(known map[int64]bool) {
	entries, err := os.ReadDir(config.LaravelLogDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		match := reWorkerLog.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		id, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || known[id] {
			continue
		}
		_ = os.Remove(config.LaravelLogDir() + "/" + name)
	}
}

var reWorkerLog = regexp.MustCompile(`^queue-([0-9]+)\.log$`)
