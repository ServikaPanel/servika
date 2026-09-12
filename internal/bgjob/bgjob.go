// Package bgjob runs detached background work with panic recovery.
//
// The panel starts every long operation in a goroutine detached from the
// request. chi's Recoverer wraps only the HTTP handler goroutine, so a panic in
// one of these takes the WHOLE servika-server process down and with it the API,
// /healthz, every scheduler and every other tenant's in-flight job. Systemd
// restarts the unit, but the startup heals then mark every interrupted job
// failed, so one panic destroys work that had nothing to do with it.
//
// Go turns that into a single failed job. Guard turns a bad scheduler tick into
// one skipped tick instead of a timer that is silent for the process's life.
package bgjob

import (
	"errors"
	"runtime/debug"

	"servika/internal/logx"
)

// ErrPanic is the error handed to a Go caller's onPanic. It carries no detail on
// purpose: the panic value can hold an internal path, and the job row onPanic
// writes is rendered to the customer. The value and its stack go to the log.
var ErrPanic = errors.New("internal error")

// Guard runs fn on the CALLING goroutine and recovers a panic inside it.
//
// A scheduler wraps one tick with this rather than the whole loop, because
// recovering at the loop's exit would leave the ticker dead until the next
// restart. name identifies the work in the log line.
func Guard(name string, fn func()) {
	_ = guarded(name, fn)
}

// Go runs fn in a new goroutine under Guard.
//
// onPanic may be nil. When it is not, it runs only on the panic path and is
// responsible for moving the job row to a terminal state, so a crashed job shows
// as failed instead of running for ever.
func Go(name string, onPanic func(error), fn func()) {
	go func() {
		if guarded(name, fn) && onPanic != nil {
			// The recorder is guarded as well: it writes to the database, and a
			// panic there would defeat the whole point of this package.
			Guard(name+" (panic recorder)", func() { onPanic(ErrPanic) })
		}
	}()
}

// guarded runs fn and reports whether it panicked.
func guarded(name string, fn func()) (panicked bool) {
	defer func() {
		if p := recover(); p != nil {
			panicked = true
			// #nosec G706 -- name is a caller-supplied literal and the stack is runtime-generated; no tenant string reaches the log.
			logx.Errorf("%s: panicked: %v\n%s", name, p, debug.Stack())
		}
	}()
	fn()
	return false
}
