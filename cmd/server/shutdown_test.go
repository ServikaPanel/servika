package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"servika/internal/httpx"
)

// The drain window and the unit's stop timeout are two halves of one decision,
// written in two files that nothing else connects. A drain shorter than the
// deadline the panel hands out kills the work it promised to finish, and a
// TimeoutStopSec below the drain lets systemd SIGKILL the process while it is
// still draining, which puts the panel back where it was.
func TestTheUnitLetsTheDrainFinish(t *testing.T) {
	if shutdownGrace < httpx.LargeTransferDeadline {
		t.Errorf("the drain window is %s, shorter than the %s the transfer endpoints are granted",
			shutdownGrace, httpx.LargeTransferDeadline)
	}
	stop := unitStopTimeout(t)
	if stop < shutdownGrace {
		t.Errorf("TimeoutStopSec is %s, below the %s drain window; systemd kills the process first",
			stop, shutdownGrace)
	}
}

// unitStopTimeout reads TimeoutStopSec from the shipped unit, in seconds.
func unitStopTimeout(t *testing.T) time.Duration {
	t.Helper()
	const unit = "../../assets/systemd/servika.service"
	source, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(source), "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), "TimeoutStopSec=")
		if !found {
			continue
		}
		seconds, convErr := strconv.Atoi(value)
		if convErr != nil {
			t.Fatalf("TimeoutStopSec=%s is not a plain number of seconds", value)
		}
		return time.Duration(seconds) * time.Second
	}
	t.Fatalf("%s declares no TimeoutStopSec, so systemd uses its 90-second default", unit)
	return 0
}
