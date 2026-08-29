// Backup / restore progress tracking, so the customer sees WHAT is happening.
//
// A single-domain backup or restore takes minutes on a large tenant. The page
// showed only "Backing up…" for the whole time, with no way to tell which stage
// it was in or whether it was moving at all. This records a per-domain stage,
// percent, elapsed time and final result that one endpoint reports.
//
// The record lives in memory and there is one per domain (a single-flight lock
// already holds). It is not removed the moment work finishes: it lingers briefly
// so the client can read the result.
package backups

import (
	"database/sql"
	"os"
	"sync"
	"time"
)

// progressRetention is how long a finished record stays readable. The client
// polls every 1.5s, so two minutes is plenty for the last result to be seen even
// after a page reload.
const progressRetention = 2 * time.Minute

// Stage keys the frontend translates. The backend emits a stable key rather than
// a sentence, because the panel renders twelve languages.
const (
	stagePreparing     = "preparing"
	stageDumpingDBs    = "dumping_databases"
	stageArchiving     = "archiving_files"
	stageVerifying     = "verifying_integrity"
	stageUploading     = "uploading_offsite"
	stageDownloading   = "downloading_offsite"
	stageExtracting    = "extracting_archive"
	stageRestoringHome = "restoring_files"
	stageImportingDB   = "importing_database"
)

// Progress is the status the client polls. Active=false means no record.
type Progress struct {
	Active   bool   `json:"active"` // a record exists (running OR just finished)
	Done     bool   `json:"done"`   // the work finished
	Op       string `json:"op"`     // "backup" | "restore"
	Stage    string `json:"stage"`  // stage key the frontend translates
	DoneB    int64  `json:"done_bytes"`
	TotalB   int64  `json:"total_bytes"` // 0 = unknown (no percent)
	Percent  int    `json:"percent"`     // 0-99 while running, 100 when done
	ElapsedS int    `json:"elapsed_s"`
	Result   string `json:"result,omitempty"` // success message
	Error    string `json:"error,omitempty"`  // failure message
}

type progressRecord struct {
	mu         sync.Mutex
	op         string
	stage      string
	done       int64
	total      int64
	started    time.Time
	finished   bool
	finishedAt time.Time
	result     string
	errText    string
	stop       chan struct{}
}

var progressByDomain sync.Map // domainID (int64) -> *progressRecord

func progressRecordFor(domainID int64) *progressRecord {
	if v, ok := progressByDomain.Load(domainID); ok {
		if r, isRec := v.(*progressRecord); isRec {
			return r
		}
	}
	return nil
}

// progressActive reports whether a RUNNING (not yet finished) job holds a domain.
func progressActive(domainID int64) bool {
	r := progressRecordFor(domainID)
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.finished
}

// progressStart begins tracking a new job. total=0 hides the percent.
func progressStart(domainID int64, op, stage string, total int64) {
	progressStopFile(domainID)
	progressByDomain.Store(domainID, &progressRecord{
		op:      op,
		stage:   stage,
		total:   total,
		started: time.Now(),
	})
}

// progressStage moves to a new stage and resets the byte counter (each stage
// measures its own progress). total=0 keeps the previous total.
func progressStage(domainID int64, stage string, total int64) {
	progressStopFile(domainID)
	if r := progressRecordFor(domainID); r != nil {
		r.mu.Lock()
		r.stage = stage
		r.done = 0
		if total != 0 {
			r.total = total
		}
		r.mu.Unlock()
	}
}

// progressWatchFile samples a file's growing size once a second into "done".
// tar/gzip/lftp are separate processes, so the target file's size is the most
// direct measure of progress available.
func progressWatchFile(domainID int64, path string) {
	r := progressRecordFor(domainID)
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.stop != nil {
		close(r.stop)
	}
	stop := make(chan struct{})
	r.stop = stop
	r.mu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// #nosec G703 -- path is an internal backup archive path under BackupRoot supplied by buildArchive (validSystemUser-checked); this is never reached with tenant path input.
				if fi, err := os.Stat(path); err == nil {
					r.mu.Lock()
					r.done = fi.Size()
					r.mu.Unlock()
				}
			}
		}
	}()
}

// progressStopFile stops the file sampler.
func progressStopFile(domainID int64) {
	if r := progressRecordFor(domainID); r != nil {
		r.mu.Lock()
		if r.stop != nil {
			close(r.stop)
			r.stop = nil
		}
		r.mu.Unlock()
	}
}

// progressFinish ends the job and keeps the RESULT readable for progressRetention,
// then removes the record.
func progressFinish(domainID int64, result string, err error) {
	progressStopFile(domainID)
	r := progressRecordFor(domainID)
	if r == nil {
		return
	}
	r.mu.Lock()
	r.finished = true
	r.finishedAt = time.Now()
	if err != nil {
		r.errText = err.Error()
	} else {
		r.result = result
	}
	r.mu.Unlock()

	go func() {
		time.Sleep(progressRetention)
		if rr := progressRecordFor(domainID); rr != nil {
			rr.mu.Lock()
			stale := rr.finished && time.Since(rr.finishedAt) >= progressRetention
			rr.mu.Unlock()
			if stale {
				progressByDomain.Delete(domainID)
			}
		}
	}()
}

// progressRead returns the current status. Active=false means no record.
func progressRead(domainID int64) Progress {
	r := progressRecordFor(domainID)
	if r == nil {
		return Progress{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := Progress{
		Active:   true,
		Done:     r.finished,
		Op:       r.op,
		Stage:    r.stage,
		DoneB:    r.done,
		TotalB:   r.total,
		ElapsedS: int(time.Since(r.started).Seconds()),
		Result:   r.result,
		Error:    r.errText,
	}
	if r.finished {
		p.Percent = 100
		return p
	}
	// Held at 99% while running: archiving may finish but verification, checksum
	// and upload remain. An early "100%" reads as done and the customer closes the
	// page mid-operation.
	if r.total > 0 && r.done > 0 {
		p.Percent = min(int(r.done*100/r.total), 99)
	}
	return p
}

// previousBackupSize is the size of this domain's most recent backup, used to
// ESTIMATE the percent while a new one is written. Backup sizes change little day
// to day, so it is a good estimate (off on the first backup after a big change,
// then it settles).
func previousBackupSize(db *sql.DB, domainID int64) int64 {
	var b int64
	_ = db.QueryRow(`SELECT size_b FROM backups WHERE domain_id=? AND size_b>0 ORDER BY id DESC LIMIT 1`,
		domainID).Scan(&b)
	return b
}
