package bgjob

import (
	"errors"
	"io"
	"log"
	"testing"
	"time"
)

// quietLogs silences the panic log lines so a passing run does not print stacks.
func quietLogs(t *testing.T) {
	t.Helper()
	out := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(out) })
}

func TestGuardSwallowsPanicAndLetsTheCallerContinue(t *testing.T) {
	quietLogs(t)
	reached := false
	Guard("test", func() { panic("boom") })
	reached = true
	if !reached {
		t.Fatal("Guard() did not return after the panic")
	}
}

func TestGuardRunsFunctionThatDoesNotPanic(t *testing.T) {
	calls := 0
	Guard("test", func() { calls++ })
	if calls != 1 {
		t.Fatalf("fn ran %d times, want 1", calls)
	}
}

// A scheduler wraps one tick, so a tick that panics must not stop the ones after it.
func TestGuardKeepsALoopAliveAcrossAPanickingTick(t *testing.T) {
	quietLogs(t)
	ticks := 0
	for i := range 3 {
		Guard("test", func() {
			ticks++
			if i == 1 {
				panic("bad tick")
			}
		})
	}
	if ticks != 3 {
		t.Fatalf("%d ticks ran, want 3: a panicking tick stopped the loop", ticks)
	}
}

func TestGoReportsAPanicThroughOnPanic(t *testing.T) {
	quietLogs(t)
	got := make(chan error, 1)
	Go("test", func(err error) { got <- err }, func() { panic("boom") })
	select {
	case err := <-got:
		if !errors.Is(err, ErrPanic) {
			t.Fatalf("onPanic received %v, want ErrPanic", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onPanic was never called for a panicking job")
	}
}

func TestGoLeavesOnPanicUncalledWhenTheJobSucceeds(t *testing.T) {
	done := make(chan struct{})
	failed := make(chan error, 1)
	Go("test", func(err error) { failed <- err }, func() { close(done) })
	<-done
	select {
	case err := <-failed:
		t.Fatalf("onPanic was called with %v for a job that did not panic", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestGoSurvivesANilOnPanic(t *testing.T) {
	quietLogs(t)
	started := make(chan struct{})
	Go("test", nil, func() { close(started); panic("boom") })
	<-started
	// A panic in the recorder path would take the process down, so reaching here
	// at all is the assertion; give the goroutine a moment to unwind first.
	time.Sleep(200 * time.Millisecond)
}

// The recorder writes to the database, so its own panic must not escape either.
func TestGoGuardsAPanickingOnPanic(t *testing.T) {
	quietLogs(t)
	called := make(chan struct{})
	Go("test", func(error) { close(called); panic("recorder boom") }, func() { panic("boom") })
	select {
	case <-called:
		time.Sleep(200 * time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("onPanic was never called")
	}
}
