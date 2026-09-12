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
	"log"
	"os"
)

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
func Errorf(format string, args ...any) { log.Printf(levelError+format, args...) }

// Warnf logs a degraded path the panel continued through.
func Warnf(format string, args ...any) { log.Printf(levelWarn+format, args...) }

// Infof logs routine progress.
func Infof(format string, args ...any) { log.Printf(levelInfo+format, args...) }

// Error logs a failure that needs no formatting.
func Error(message string) { log.Print(levelError + message) }

// Warn logs a degraded path that needs no formatting.
func Warn(message string) { log.Print(levelWarn + message) }

// Info logs routine progress that needs no formatting.
func Info(message string) { log.Print(levelInfo + message) }

// Fatalf logs a failure the process cannot continue past, and exits 1, exactly
// like log.Fatalf. It is for startup only: a request path must never take the
// panel down.
func Fatalf(format string, args ...any) {
	log.Printf(levelError+format, args...)
	os.Exit(1)
}
