package chains

import (
	"testing"
	"time"

	"servika/internal/notifications"
)

var (
	t1 = time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 1, 1, 10, 1, 0, 0, time.UTC)
)

// A single signal is NOT a chain.
func TestChainScoreNeedsTwoDistinctStages(t *testing.T) {
	one := []Event{{Stage: "file_write", Level: "critical", Time: t1}, {Stage: "file_write", Time: t2}}
	if ChainScore(one).Enough {
		t.Fatal("a single distinct stage was reported as a chain")
	}
	if ChainScore(nil).Enough {
		t.Fatal("no events was reported as a chain")
	}
}

// Two independent signals (different paths, no shared pid) stay a WARNING, even
// though they form two stages. This is the FP-laundering gate: base 55, ordered
// +5 = 60, but not critical.
func TestChainScoreIndependentSignalsStayWarning(t *testing.T) {
	r := ChainScore([]Event{
		{Stage: "file_write", Level: "critical", Path: "/home/c_x/public_html/a.php", Time: t1},
		{Stage: "execution", Level: "critical", Path: "/usr/sbin/php-fpm", Pid: 5, Time: t2},
	})
	if !r.Enough {
		t.Fatal("two stages were not reported as a chain")
	}
	if r.Causal {
		t.Fatal("unrelated events were judged causal")
	}
	if r.Level != notifications.LevelWarning {
		t.Fatalf("independent signals should be a warning, got %q", r.Level)
	}
	if r.Confidence != 60 {
		t.Fatalf("confidence = %d, want 60 (55 + 5 ordered)", r.Confidence)
	}
}

// A dropped file executed from the SAME path is causal, so it escalates to
// critical: base 55, +25 causal, +5 ordered = 85.
func TestChainScoreSamePathIsCausalCritical(t *testing.T) {
	dropped := "/home/c_x/public_html/.x"
	r := ChainScore([]Event{
		{Stage: "file_write", Level: "critical", Path: dropped, Time: t1},
		{Stage: "execution", Level: "critical", Path: dropped, Pid: 9, Time: t2},
	})
	if !r.Causal {
		t.Fatal("same-path events were not judged causal")
	}
	if r.Level != notifications.LevelCritical {
		t.Fatalf("a causal chain should be critical, got %q", r.Level)
	}
	if r.Confidence != 85 {
		t.Fatalf("confidence = %d, want 85 (55 + 25 causal + 5 ordered)", r.Confidence)
	}
}

// A shared pid is causal even when the paths differ.
func TestChainScoreSamePidIsCausal(t *testing.T) {
	r := ChainScore([]Event{
		{Stage: "execution", Path: "/a", Pid: 42, Time: t1},
		{Stage: "c2", Path: "/b", Pid: 42, Time: t2},
	})
	if !r.Causal || r.Level != notifications.LevelCritical {
		t.Fatalf("a shared pid should be a causal critical chain: %+v", r)
	}
}

// Same-DIRECTORY is deliberately NOT causal: a document root holds many files.
func TestPathLinkedOnlySameFullPath(t *testing.T) {
	if pathLinked("/home/c_x/public_html/a.php", "/home/c_x/public_html/b.php") {
		t.Fatal("same directory was judged a causal link")
	}
	if !pathLinked("/home/c_x/public_html/a.php", "/home/c_x/public_html/a.php") {
		t.Fatal("the same full path was not judged linked")
	}
	if pathLinked("", "/x") || pathLinked("/x", "") {
		t.Fatal("an empty path was judged linked")
	}
}

// Reverse-order events (execution before the file was written) are not ordered,
// so the ordered bonus is withheld.
func TestChainScoreReverseOrderNotOrdered(t *testing.T) {
	forward := timeOrdered([]Event{{Stage: "file_write", Time: t1}, {Stage: "execution", Time: t2}},
		[]string{"file_write", "execution"})
	reverse := timeOrdered([]Event{{Stage: "file_write", Time: t2}, {Stage: "execution", Time: t1}},
		[]string{"file_write", "execution"})
	if !forward {
		t.Fatal("in-order events were not judged ordered")
	}
	if reverse {
		t.Fatal("reverse-order events were judged ordered")
	}
}

// A zero timestamp withholds the ordered bonus rather than guessing.
func TestChainScoreZeroTimeNotOrdered(t *testing.T) {
	if timeOrdered([]Event{{Stage: "file_write"}, {Stage: "execution", Time: t2}}, []string{"file_write", "execution"}) {
		t.Fatal("a zero timestamp was treated as ordered")
	}
}

// Three ordered stages with no causal link still reach critical (a full ordered
// kill-chain is strong on its own): base 70, +5 ordered = 75, critical.
func TestChainScoreThreeOrderedStagesCritical(t *testing.T) {
	r := ChainScore([]Event{
		{Stage: "file_write", Path: "/a", Time: t1},
		{Stage: "execution", Path: "/b", Time: t2},
		{Stage: "c2", Path: "/c", Time: t2.Add(time.Minute)},
	})
	if r.Causal {
		t.Fatal("distinct paths were judged causal")
	}
	if r.Level != notifications.LevelCritical {
		t.Fatalf("three ordered stages should be critical, got %q", r.Level)
	}
	if r.Confidence != 75 {
		t.Fatalf("confidence = %d, want 75 (70 + 5 ordered)", r.Confidence)
	}
}

// Confidence clamps at 99.
func TestChainScoreClampsAt99(t *testing.T) {
	r := ChainScore([]Event{
		{Stage: "entry", Path: "/a", Pid: 1, Time: t1},
		{Stage: "file_write", Path: "/a", Pid: 1, Time: t1},
		{Stage: "execution", Path: "/a", Pid: 1, Time: t2},
		{Stage: "c2", Path: "/a", Pid: 1, Time: t2},
		{Stage: "persistence", Path: "/a", Pid: 1, Time: t2},
	})
	if r.Confidence != 99 {
		t.Fatalf("five causal ordered stages should clamp to 99, got %d", r.Confidence)
	}
}

// An unknown stage is ignored.
func TestChainScoreIgnoresUnknownStage(t *testing.T) {
	if ChainScore([]Event{{Stage: "file_write", Time: t1}, {Stage: "not_a_stage", Time: t2}}).Enough {
		t.Fatal("an unknown stage was counted toward the chain")
	}
}

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
