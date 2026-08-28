package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"servika/internal/archivex"
)

// extractJobTimeout bounds one extraction. It is long because a multi-gigabyte
// archive on a busy tenant can take many minutes, and the tenant's own cgroup is
// the real resource limit; this only stops a wedged extractor from holding its
// descriptors for ever.
const extractJobTimeout = 30 * time.Minute

// Asynchronous archive extraction.
//
// A large archive takes longer than the router's 300-second request timeout, so
// the connection is cut while the extractor is still running and the caller
// never learns the result. Extraction therefore runs in a goroutine and the
// handler returns a job id at once; the page polls a progress endpoint. The job
// store lives only in memory: a restart loses it, which leaves a
// partly-extracted directory the same way any interrupted file operation does,
// so there is nothing to heal in a database.
//
// The pinned archive and target descriptors (the openat2 fds behind the
// /proc/self/fd paths) are handed to the goroutine, which closes them when the
// extraction finishes. The handler must NOT close them, or the pinned paths go
// stale before the extractor reads them.

type extractState string

const (
	extractRunning extractState = "running"
	extractDone    extractState = "done"
	extractFailed  extractState = "failed"
)

// extractJob tracks one running extraction. total is 0 until the member count is
// known; done grows as members are extracted. The counters are atomic because
// the extractor goroutine writes them while the poll goroutine reads them.
type extractJob struct {
	systemUser string // the tenant this job belongs to, so a poll is scoped
	total      atomic.Int64
	done       atomic.Int64

	mu    sync.Mutex
	state extractState
	code  string // a reason code when state is failed
}

func (j *extractJob) setTotal(n int) { j.total.Store(int64(n)) }
func (j *extractJob) addDone(n int)  { j.done.Add(int64(n)) }

func (j *extractJob) finish() {
	j.mu.Lock()
	j.state = extractDone
	j.mu.Unlock()
}

func (j *extractJob) fail(code string) {
	j.mu.Lock()
	j.state = extractFailed
	j.code = code
	j.mu.Unlock()
}

func (j *extractJob) snapshot() (total, done int64, state extractState, code string) {
	j.mu.Lock()
	state, code = j.state, j.code
	j.mu.Unlock()
	return j.total.Load(), j.done.Load(), state, code
}

// extractJobs maps an unguessable id to its job. A finished job is left in the
// map so a late poll still reads the final state; it is pruned by the poll that
// observes a terminal state.
var extractJobs sync.Map // id -> *extractJob

func newExtractJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// runExtractJob extracts the archive as the tenant, feeding progress into job,
// then relabels the target. It OWNS the two pinned descriptors and closes them
// when it returns, because the /proc/self/fd paths built from them must stay
// valid until the extractor has read them. It uses a background context, never
// the request's, which is cancelled when the handler returns the job id.
func runExtractJob(job *extractJob, archiveFd, targetFd *os.File, archivePinned, targetPinned, systemUser string, limits archivex.Limits) {
	defer func() {
		_ = archiveFd.Close()
		_ = targetFd.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), extractJobTimeout)
	defer cancel()

	if _, err := archivex.ExtractProgress(ctx, archivePinned, targetPinned, systemUser, limits,
		func(total int) { job.setTotal(total) },
		func(delta int) { job.addDone(delta) }); err != nil {
		job.fail(extractFailureCode(err))
		return
	}
	// Relabel SELinux contexts on the pinned target path (kernel-resolved, under home).
	if _, err := newFileCommand(ctx, "restorecon", "-R", targetPinned).CombinedOutput(); err != nil {
		job.fail("relabel_failed")
		return
	}
	job.finish()
}

// extractFailureCode maps an extraction error to a stable reason code the page
// localises, keeping the same two outcomes the synchronous path reported.
func extractFailureCode(err error) string {
	if errors.Is(err, archivex.ErrArchiveTooLarge) || errors.Is(err, archivex.ErrTooManyMembers) {
		return "archive_too_large"
	}
	return "invalid_archive"
}
