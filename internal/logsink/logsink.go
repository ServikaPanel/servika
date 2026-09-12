// Package logsink writes the panel's log rows without making anybody wait.
//
// Three tables are fed from here: request_logs from the HTTP middleware,
// app_logs from logx, and (through the caller's own statement) audit_log. The
// first two are written on paths that must not slow down or fail because the
// database is busy, so a row is handed to a buffered channel and a single
// goroutine writes the batches.
//
// A full channel DROPS the row. Blocking would put the database's slowest moment
// in front of every request the panel serves, which is the opposite of what a
// log is for. The drops are counted and reported, so a silent gap in the table
// is never mistaken for a quiet period.
package logsink

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"servika/internal/bgjob"
	"servika/internal/logx"
)

// bufferSize is how many rows may wait to be written.
//
// It is deliberately larger than a burst and much smaller than a memory
// problem: 4096 rows of a few hundred bytes is a couple of megabytes at worst,
// and a panel that is more than 4096 requests behind on its logging has a
// database problem the log cannot fix.
const bufferSize = 4096

// flushInterval bounds how long a row waits when the buffer is not filling.
const flushInterval = 2 * time.Second

// batchSize bounds one INSERT. A larger statement holds the table's lock for
// longer, and this table is on the same server as the customer sites.
const batchSize = 256

// complainInterval throttles the dropped-row report. The drops happen in bursts
// by definition, so one line per drop would be the flood the drop prevented.
const complainInterval = time.Minute

// now is a seam so a test can move time without sleeping.
var now = time.Now

// Sink accepts rows and writes them in batches.
type Sink[T any] struct {
	rows    chan T
	dropped atomic.Int64

	complainMu    sync.Mutex
	lastComplaint time.Time

	name  string
	write func(context.Context, *sql.DB, []T)
}

// newSink builds a sink. write receives one batch and must never panic the
// caller: it is run under bgjob.Guard.
func newSink[T any](name string, write func(context.Context, *sql.DB, []T)) *Sink[T] {
	return &Sink[T]{rows: make(chan T, bufferSize), name: name, write: write}
}

// Send queues a row, or drops it when the buffer is full.
//
// It never blocks and never returns an error, because every caller is on a path
// where the log is not the work.
func (s *Sink[T]) Send(row T) {
	select {
	case s.rows <- row:
	default:
		s.dropped.Add(1)
		s.complain()
	}
}

// complain reports the dropped rows at most once per complainInterval.
func (s *Sink[T]) complain() {
	s.complainMu.Lock()
	defer s.complainMu.Unlock()
	if now().Sub(s.lastComplaint) < complainInterval {
		return
	}
	s.lastComplaint = now()
	logx.Warnf("%s: the write buffer is full, %d row(s) dropped so far", s.name, s.dropped.Load())
}

// Dropped reports how many rows this sink has thrown away.
func (s *Sink[T]) Dropped() int64 { return s.dropped.Load() }

// run consumes the channel until ctx ends, then writes what is left.
func (s *Sink[T]) run(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]T, 0, batchSize)

	for {
		select {
		case row := <-s.rows:
			batch = append(batch, row)
			if len(batch) >= batchSize {
				batch = s.flush(ctx, db, batch)
			}
		case <-ticker.C:
			batch = s.flush(ctx, db, batch)
		case <-ctx.Done():
			s.drain(db, batch)
			return
		}
	}
}

// flush writes the batch and returns an empty one.
func (s *Sink[T]) flush(ctx context.Context, db *sql.DB, batch []T) []T {
	if len(batch) == 0 {
		return batch
	}
	// A panic in the write must not end the writer goroutine: the panel would
	// then log nothing at all for the rest of its life, silently.
	bgjob.Guard(s.name, func() { s.write(ctx, db, batch) })
	return batch[:0]
}

// drain writes what is buffered at shutdown, under its own deadline.
//
// The caller's context is already cancelled by the time this runs, so it cannot
// be reused: the write would be refused before it started.
func (s *Sink[T]) drain(db *sql.DB, batch []T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case row := <-s.rows:
			batch = append(batch, row)
			if len(batch) < batchSize {
				continue
			}
		default:
		}
		if len(batch) == 0 {
			return
		}
		bgjob.Guard(s.name, func() { s.write(ctx, db, batch) })
		batch = batch[:0]
		if len(s.rows) == 0 {
			return
		}
	}
}

// Start runs the sink's writer until ctx ends.
func (s *Sink[T]) Start(ctx context.Context, db *sql.DB) {
	bgjob.Go(s.name, nil, func() { s.run(ctx, db) })
}
