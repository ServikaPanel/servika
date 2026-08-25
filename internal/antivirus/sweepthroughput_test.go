package antivirus

import (
	"testing"

	"servika/internal/avsettings"
)

// The sweep is the scan the worker pool and the file-rate ceiling were added
// for: it walks every tenant home on the server. It reached neither, so a sweep
// ran on one worker with no disk ceiling while a scan of ONE site got both.

func TestTheSweepCarriesTheOperatorsThroughputSettings(t *testing.T) {
	s := avsettings.Settings{
		RuleEngine:     true,
		ScanWorkers:    7,
		FileRatePerSec: 250,
	}
	req := sweepRequest(s)
	if req.Workers != 7 {
		t.Fatalf("the sweep asked for %d workers, not the 7 the operator set", req.Workers)
	}
	if req.FileRatePerSec != 250 {
		t.Fatalf("the sweep asked for a file rate of %d, not the 250 the operator set", req.FileRatePerSec)
	}
}

func TestASweepNeverAsksForZeroWorkers(t *testing.T) {
	// Zero means automatic on the screen, and Resolve turns it into a real
	// number. A request carrying 0 is clamped to one worker downstream, so the
	// defect this guards is silent: the sweep simply runs single-threaded.
	req := sweepRequest(avsettings.Settings{RuleEngine: true})
	if req.Workers < 1 {
		t.Fatalf("an automatic worker count reached the request as %d", req.Workers)
	}
	// The resolved value is what the slice file is written from, so the two
	// cannot disagree about what "automatic" means.
	want := avsettings.Settings{RuleEngine: true}.Resolve(avsettings.ServerCapacity()).ScanWorkers
	if req.Workers != want {
		t.Fatalf("the sweep resolved %d workers where the slice resolves %d", req.Workers, want)
	}
}
