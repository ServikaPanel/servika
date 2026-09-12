package laravel

import (
	"context"
	"database/sql"
	"time"

	"servika/internal/bgjob"
	"servika/internal/logx"
)

const reconcileJobName = "laravel: job reconciler"

// jobReconcileGrace is how long a job may sit in a non-terminal state before the
// reconciler is allowed to finalize it. It prevents finalizing a just-started job
// before its detached systemd unit has registered as active.
const jobReconcileGrace = 120 * time.Second

// StartJobReconciler runs a background loop that finalizes Laravel install/deploy
// jobs whose detached unit has stopped but whose DB row is still non-terminal
// because no client polled the status endpoint. This makes job completion
// independent of browser polling.
func StartJobReconciler(db *sql.DB, interval time.Duration) {
	go func() {
		time.Sleep(90 * time.Second) // warmup: let startup healing settle first
		// Each pass is guarded on its own: an unrecovered panic here would take
		// the whole panel process down, and recovering only at the loop's exit
		// would leave the reconciler silent until the next restart.
		bgjob.Guard(reconcileJobName, func() { reconcileOnce(db) })
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			bgjob.Guard(reconcileJobName, func() { reconcileOnce(db) })
		}
	}()
}

// reconcileOnce finalizes every stuck job past the grace period in one pass.
func reconcileOnce(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rows, err := db.QueryContext(ctx,
		`SELECT d.id, d.system_user
		 FROM domains d JOIN cp_laravel_apps a ON a.domain_id=d.id
		 WHERE a.last_deploy_status IN ('running','installing')
		   AND a.updated_at < (NOW() - INTERVAL ? SECOND)`,
		int(jobReconcileGrace.Seconds()))
	if err != nil {
		logx.Errorf("laravel job reconciler query: %v", err)
		return
	}
	type stuck struct {
		id         int64
		systemUser string
	}
	var jobs []stuck
	for rows.Next() {
		var s stuck
		if err := rows.Scan(&s.id, &s.systemUser); err != nil {
			logx.Errorf("laravel job reconciler scan: %v", err)
			continue
		}
		jobs = append(jobs, s)
	}
	if err := rows.Err(); err != nil {
		// A job missing from this list stays marked running for good, because the
		// reconciler is what closes a row a restart left behind.
		logx.Errorf("laravel job reconciler: could not read the stuck job list: %v", err)
	}
	_ = rows.Close()

	h := &Handlers{DB: db}
	for _, s := range jobs {
		func() {
			defer lockDomain(s.id)() // serialize against a concurrent Deploy/Install
			rec := h.getRecord(ctx, s.id)
			switch rec.LastDeployStatus {
			case "running":
				h.finalizeDeploy(ctx, s.id, s.systemUser, rec)
			case "installing":
				h.finalizeInstall(ctx, s.id, s.systemUser, rec)
			}
		}()
	}
}
