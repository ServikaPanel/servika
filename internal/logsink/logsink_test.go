package logsink

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"
)

// collector records the batches a sink hands its writer.
type collector struct {
	mu      sync.Mutex
	batches [][]int
	done    chan struct{}
	want    int
}

func newCollector(want int) *collector {
	return &collector{done: make(chan struct{}), want: want}
}

func (c *collector) write(_ context.Context, _ *sql.DB, batch []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The sink reuses its slice, so the batch must be copied before it is kept.
	kept := make([]int, len(batch))
	copy(kept, batch)
	c.batches = append(c.batches, kept)
	if c.rowsLocked() >= c.want {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
}

func (c *collector) rowsLocked() int {
	total := 0
	for _, batch := range c.batches {
		total += len(batch)
	}
	return total
}

func (c *collector) rows() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rowsLocked()
}

// waitForRows blocks until the collector has the rows it was told to expect.
func (c *collector) waitForRows(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("only %d of %d row(s) reached the writer", c.rows(), c.want)
	}
}

// A row handed to the sink reaches the writer without the caller waiting.
func TestAQueuedRowReachesTheWriter(t *testing.T) {
	got := newCollector(3)
	sink := newSink("test", got.write)
	sink.Start(t.Context(), nil)

	for i := range 3 {
		sink.Send(i)
	}

	got.waitForRows(t)
	if sink.Dropped() != 0 {
		t.Errorf("%d row(s) were dropped with an empty buffer", sink.Dropped())
	}
}

// The whole point of the buffer: Send never waits for the database.
//
// Nothing consumes this sink, so every call after the buffer fills takes the
// drop path. A blocking Send would hang here rather than fail the assertion.
func TestSendNeverBlocks(t *testing.T) {
	sink := newSink("test", func(context.Context, *sql.DB, []int) {})

	finished := make(chan struct{})
	go func() {
		for i := range bufferSize + 100 {
			sink.Send(i)
		}
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Send blocked once the buffer was full, so a slow database would stall every request")
	}
	if sink.Dropped() != 100 {
		t.Errorf("%d row(s) were dropped, expected exactly 100", sink.Dropped())
	}
}

// A batch is written when it is full, without waiting for the flush interval.
func TestAFullBatchIsWrittenAtOnce(t *testing.T) {
	got := newCollector(batchSize)
	sink := newSink("test", got.write)
	sink.Start(t.Context(), nil)

	start := time.Now()
	for i := range batchSize {
		sink.Send(i)
	}
	got.waitForRows(t)

	if elapsed := time.Since(start); elapsed >= flushInterval {
		t.Errorf("a full batch waited %s for the ticker, expected an immediate write", elapsed)
	}
}

// A writer that panics must not end the goroutine, or the panel logs nothing at
// all for the rest of its life and nothing says so.
func TestAPanickingWriterDoesNotStopTheSink(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	survived := make(chan struct{})
	sink := newSink("test", func(_ context.Context, _ *sql.DB, batch []int) {
		mu.Lock()
		calls++
		current := calls
		mu.Unlock()
		if current == 1 {
			panic("the database went away")
		}
		close(survived)
	})
	sink.Start(t.Context(), nil)

	sink.Send(1)
	time.Sleep(flushInterval + 500*time.Millisecond)
	sink.Send(2)

	select {
	case <-survived:
	case <-time.After(10 * time.Second):
		t.Fatal("the writer never ran again after a panic")
	}
}

// A nil database is the state during startup and in every unit test that does
// not open one. It must be a silent no-op, not a crash.
func TestANilDatabaseWritesNothing(t *testing.T) {
	writeRequests(context.Background(), nil, []RequestRow{{Method: "GET", Endpoint: "/x"}})
	writeApp(context.Background(), nil, []AppRow{{Level: "INFO", Message: "x"}})
}

// A value longer than its column would make MariaDB refuse the whole batch
// under a strict sql_mode, so one oversized user agent would drop 255 unrelated
// rows.
func TestAnOversizedValueIsShortenedToItsColumn(t *testing.T) {
	long := ""
	for range maxUserAgent + 50 {
		long += "a"
	}
	if got := clip(long, maxUserAgent); len(got) != maxUserAgent {
		t.Errorf("the value is %d bytes, want %d", len(got), maxUserAgent)
	}
	// A multi-byte character must not be cut in half, because the column's
	// collation refuses the broken byte and the batch fails anyway.
	multi := ""
	for range 200 {
		multi += "ş"
	}
	got := clip(multi, 255)
	if len(got) > 255 {
		t.Errorf("the value is %d bytes, past the 255 limit", len(got))
	}
	for _, r := range got {
		if r == '�' {
			t.Error("a character was cut in half")
		}
	}
}

// An empty JSON column is stored as NULL: MariaDB refuses "" for a JSON column.
func TestAnEmptyJSONValueBecomesNull(t *testing.T) {
	if nullString("") != nil {
		t.Error("an empty value would be written as a string, which the JSON column refuses")
	}
	if nullString(`{"a":1}`) == nil {
		t.Error("a real value was turned into NULL")
	}
}
