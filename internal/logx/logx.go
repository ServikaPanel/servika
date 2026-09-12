// Package logx writes the panel's log lines with a syslog severity, so an
// operator can ask the journal for the failures instead of reading every line
// the panel has ever written.
//
// The panel logs through the standard library and ships no structured-logging
// dependency. That choice does not prevent severities: systemd reads a leading
// `<N>` on a line as its syslog priority (SyslogLevelPrefix defaults to yes),
// so a one-token prefix is all journald needs for `journalctl -p err -u
// servika` to select the errors. Nothing else about a line changes, and a line
// read outside journald simply carries a visible `<3>`.
//
// Every line still goes through the standard logger, so a caller that swapped
// log.SetOutput (every test that reads what was logged) keeps working, and the
// panel keeps ONE output.
package logx

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
)

// sink is an optional SECOND destination for every line, set once at startup.
//
// journald stays the first destination and is never conditional on it: the sink
// writes to the panel's own database, which is down during startup, during a
// migration and during exactly the incident an operator is trying to read about.
// A line reaches journald whether or not the sink is set, and whether or not it
// works.
//
// It is an atomic pointer rather than a plain variable because the panel logs
// from every goroutine it has, and the sink is installed while some of them are
// already running.
var sink atomic.Pointer[func(level, message string)]

// SetSink installs the second destination. Passing nil removes it.
//
// The function it takes MUST NOT log: it is called from inside every logx call,
// so a line it writes would call it again.
func SetSink(fn func(level, message string)) {
	if fn == nil {
		sink.Store(nil)
		return
	}
	sink.Store(&fn)
}

// fanOut hands one line to the sink, if there is one.
//
// A panic inside the sink is contained here. logx is called from every path the
// panel has, including the ones that are already failing, so a broken second
// destination must not take down the caller that was only reporting a problem.
// The recover reports to stderr directly: routing it back through logx would
// call the same sink again.
func fanOut(level, message string) {
	fn := sink.Load()
	if fn == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(os.Stderr, "logx: the log sink panicked: %v\n", recovered)
		}
	}()
	(*fn)(level, message)
}

// The three priorities the panel distinguishes, in syslog numbers: 3 is err,
// 4 is warning and 6 is informational. Debug (7) is deliberately absent: the
// panel has no verbosity setting to turn it on with, and a level nobody can
// select is a level that only makes the classification harder.
const (
	levelError = "<3>"
	levelWarn  = "<4>"
	levelInfo  = "<6>"
)

// Which level a line takes:
//
//   - Errorf: the operation FAILED. Something the panel was asked to do did not
//     happen, and an operator has to know.
//   - Warnf: the panel CONTINUED, but not as intended: a step was skipped, a
//     stale value was kept, a retry was needed, a limit was hit.
//   - Infof: routine progress. What the panel did, in the ordinary case.
//
// The prefix marks the FIRST line only, so a multi-line message (a command's
// output, a rendered file) carries its severity on the first line and lands at
// the unit's default priority for the rest. Keep the first line the one that
// says what happened.

// Errorf logs a failure.
func Errorf(format string, args ...any) { write(levelError, fmt.Sprintf(format, args...)) }

// Warnf logs a degraded path the panel continued through.
func Warnf(format string, args ...any) { write(levelWarn, fmt.Sprintf(format, args...)) }

// Infof logs routine progress.
func Infof(format string, args ...any) { write(levelInfo, fmt.Sprintf(format, args...)) }

// Error logs a failure that needs no formatting.
func Error(message string) { write(levelError, message) }

// Warn logs a degraded path that needs no formatting.
func Warn(message string) { write(levelWarn, message) }

// Info logs routine progress that needs no formatting.
func Info(message string) { write(levelInfo, message) }

// write sends one line to journald and then to the sink.
//
// journald FIRST, always. The sink writes to the panel's own database, and the
// line must survive that database being down, which is exactly when the
// interesting lines are written.
func write(level, message string) {
	log.Print(level + message)
	fanOut(level, message)
}

// Fatalf logs a failure the process cannot continue past, and exits 1, exactly
// like log.Fatalf. It is for startup only: a request path must never take the
// panel down.
//
// It does NOT wait for the sink to write: this runs when the panel cannot
// start, so the database it would write to is usually the reason. journald has
// the line already.
func Fatalf(format string, args ...any) {
	write(levelError, fmt.Sprintf(format, args...))
	os.Exit(1)
}
