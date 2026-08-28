package files

import (
	"fmt"
	"testing"

	"servika/internal/archivex"
)

// TestExtractJobTracksProgressAndState checks the counters and the terminal
// states a poll reads back.
func TestExtractJobTracksProgressAndState(t *testing.T) {
	job := &extractJob{systemUser: "c_test", state: extractRunning}
	job.setTotal(10)
	job.addDone(3)
	job.addDone(2)

	total, done, state, code := job.snapshot()
	if total != 10 || done != 5 || state != extractRunning || code != "" {
		t.Fatalf("snapshot = (%d,%d,%q,%q), want (10,5,running,)", total, done, state, code)
	}

	job.fail("archive_too_large")
	if _, _, state, code := job.snapshot(); state != extractFailed || code != "archive_too_large" {
		t.Errorf("after fail: state=%q code=%q, want failed/archive_too_large", state, code)
	}

	done2 := &extractJob{state: extractRunning}
	done2.finish()
	if _, _, state, _ := done2.snapshot(); state != extractDone {
		t.Errorf("after finish: state=%q, want done", state)
	}
}

// TestExtractFailureCode keeps the two outcomes the synchronous path reported.
func TestExtractFailureCode(t *testing.T) {
	if got := extractFailureCode(archivex.ErrArchiveTooLarge); got != "archive_too_large" {
		t.Errorf("too-large = %q, want archive_too_large", got)
	}
	if got := extractFailureCode(archivex.ErrTooManyMembers); got != "archive_too_large" {
		t.Errorf("too-many = %q, want archive_too_large", got)
	}
	if got := extractFailureCode(fmt.Errorf("some other failure")); got != "invalid_archive" {
		t.Errorf("other = %q, want invalid_archive", got)
	}
}

// TestNewExtractJobIDIsUniqueAndUnguessable checks the id is a 32-hex-character
// random token, so it is not enumerable across tenants.
func TestNewExtractJobIDIsUniqueAndUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := newExtractJobID()
		if err != nil {
			t.Fatalf("newExtractJobID: %v", err)
		}
		if len(id) != 32 {
			t.Fatalf("id %q is %d chars, want 32", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
