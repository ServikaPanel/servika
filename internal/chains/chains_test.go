package chains

import (
	"strings"
	"testing"
)

// A single signal is NOT a chain: folding one detection into a chain would raise
// a chain alert on every lone finding.
func TestChainScoreNeedsTwoDistinctStages(t *testing.T) {
	one := []Event{{Stage: "file_write", Level: "critical"}, {Stage: "file_write", Level: "critical"}}
	if _, _, ok := ChainScore(one); ok {
		t.Fatal("a single distinct stage was reported as a chain")
	}
	if _, _, ok := ChainScore(nil); ok {
		t.Fatal("no events was reported as a chain")
	}
}

// The classic file_write + execution chain: base 60, +5 critical, +5 for the
// write+execute pair = 70. This is the measured live case.
func TestChainScoreWriteThenExecute(t *testing.T) {
	c, stages, ok := ChainScore([]Event{
		{Stage: "file_write", Level: "critical"},
		{Stage: "execution", Level: "critical"},
	})
	if !ok {
		t.Fatal("write+execute was not reported as a chain")
	}
	if c != 70 {
		t.Fatalf("write+execute confidence = %d, want 70 (60 + 5 critical + 5 pair)", c)
	}
	// Stages come back in kill-chain order.
	if strings.Join(stages, ">") != "file_write>execution" {
		t.Fatalf("stage order: %v", stages)
	}
}

// The write+execute bonus is real: a non-adjacent pair of the same size scores
// 5 less.
func TestChainScoreWriteExecuteBonus(t *testing.T) {
	withPair, _, _ := ChainScore([]Event{{Stage: "file_write"}, {Stage: "execution"}})
	noPair, _, _ := ChainScore([]Event{{Stage: "file_write"}, {Stage: "c2"}})
	if withPair != 65 {
		t.Fatalf("file_write+execution (no critical) = %d, want 65", withPair)
	}
	if noPair != 60 {
		t.Fatalf("file_write+c2 (no critical, no pair) = %d, want 60", noPair)
	}
	if withPair-noPair != 5 {
		t.Fatalf("the write+execute bonus should be 5, got %d", withPair-noPair)
	}
}

// Confidence grows with stage diversity and clamps at 99.
func TestChainScoreDiversityAndClamp(t *testing.T) {
	three, _, _ := ChainScore([]Event{{Stage: "file_write"}, {Stage: "execution"}, {Stage: "c2"}})
	if three != 85 {
		t.Fatalf("three stages (with write+exec pair) = %d, want 85 (80 + 5 pair)", three)
	}
	all := ChainStages("entry", "file_write", "execution", "c2", "persistence")
	c, _, _ := ChainScore(all)
	if c != 99 {
		t.Fatalf("five critical stages should clamp to 99, got %d", c)
	}
}

// An unknown stage is ignored, so it cannot inflate the count.
func TestChainScoreIgnoresUnknownStage(t *testing.T) {
	if _, _, ok := ChainScore([]Event{{Stage: "file_write"}, {Stage: "not_a_stage"}}); ok {
		t.Fatal("an unknown stage was counted toward the chain")
	}
}

// The signature is stable and domain-scoped: the same domain and stages hash the
// same, a different domain does not.
func TestChainSignatureStableAndScoped(t *testing.T) {
	a := ChainSignature(7, []string{"file_write", "execution"})
	b := ChainSignature(7, []string{"file_write", "execution"})
	c := ChainSignature(8, []string{"file_write", "execution"})
	if a != b {
		t.Fatal("the same domain and stages produced different signatures")
	}
	if a == c {
		t.Fatal("two domains produced the same signature")
	}
	if len(a) != 32 {
		t.Fatalf("signature length = %d, want 32", len(a))
	}
}

func TestStageSummary(t *testing.T) {
	if got := StageSummary([]string{"file_write", "execution"}); got != "File Write → Execution" {
		t.Fatalf("summary = %q", got)
	}
}

// ChainStages is a test helper: build a critical Event per stage name.
func ChainStages(stages ...string) []Event {
	out := make([]Event, 0, len(stages))
	for _, s := range stages {
		out = append(out, Event{Stage: s, Level: "critical"})
	}
	return out
}
