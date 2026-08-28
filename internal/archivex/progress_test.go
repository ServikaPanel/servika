package archivex

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestCountReportsMemberCount checks that Count returns the number of members,
// which is the total a progress bar divides by. It rides on the same validation
// scan Extract uses, so it counts exactly what will be extracted.
func TestCountReportsMemberCount(t *testing.T) {
	path := writeTarGz(t, "a.txt", "dir/b.txt", "dir/c.txt")
	n, err := Count(context.Background(), path, TypeTARGzip, Limits{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 3 {
		t.Errorf("Count = %d, want 3", n)
	}
}

// TestProgressCounterCountsLinesAndKeepsTail proves the writer reports one unit
// per newline (a verbose extractor prints one line per member) and keeps only
// the tail of the output for the error message.
func TestProgressCounterCountsLinesAndKeepsTail(t *testing.T) {
	var mu sync.Mutex
	total := 0
	pc := &progressCounter{onLine: func(delta int) { mu.Lock(); total += delta; mu.Unlock() }}

	_, _ = pc.Write([]byte("one\ntwo\n"))
	_, _ = pc.Write([]byte("three\n"))
	_, _ = pc.Write([]byte("no newline here"))

	mu.Lock()
	got := total
	mu.Unlock()
	if got != 3 {
		t.Errorf("counted %d lines, want 3", got)
	}

	// The tail is bounded, so a huge output cannot grow the buffer without limit.
	big := strings.Repeat("x", progressTailMax*2)
	_, _ = pc.Write([]byte(big))
	if len(pc.tailString()) > progressTailMax {
		t.Errorf("tail length %d exceeds the cap %d", len(pc.tailString()), progressTailMax)
	}
}
