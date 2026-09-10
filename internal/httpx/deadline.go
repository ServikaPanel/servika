package httpx

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// ErrHandlerTimeout is the cancellation cause a request context carries when its
// handler ran past the budget the router gave it.
var ErrHandlerTimeout = errors.New("handler timeout")

// ErrNoHandlerTimeout reports that the request carries no extendable timeout, so
// the handler half of ExtendDeadline had nothing to lift.
var ErrNoHandlerTimeout = errors.New("request carries no extendable handler timeout")

type handlerTimeoutKey struct{}

// handlerTimeout is a request budget that can be LENGTHENED after the request
// has already started.
//
// context.WithTimeout cannot do that: a derived context never outlives its
// parent's deadline, so the router's own budget always wins and an endpoint that
// asks for thirty minutes still dies at the default. A timer can be reset, so the
// context is cancellable rather than deadline-bound and the timer decides when it
// fires. The parent is still the request context, so a client that goes away
// cancels the work exactly as before.
type handlerTimeout struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel context.CancelCauseFunc
	fired  bool
}

// extend lengthens the budget to d measured from now. It reports false once the
// timer has already fired, because a request that was cancelled is not one an
// extension can bring back.
func (t *handlerTimeout) extend(d time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fired {
		return false
	}
	t.timer.Stop()
	t.timer.Reset(d)
	return true
}

func (t *handlerTimeout) fire() {
	t.mu.Lock()
	t.fired = true
	t.mu.Unlock()
	t.cancel(ErrHandlerTimeout)
}

func (t *handlerTimeout) timedOut() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fired
}

// WithHandlerTimeout gives ctx a budget of d that ExtendDeadline can lengthen.
//
// The returned function stops the timer and releases the context. Call it when
// the handler returns, or the timer holds the context alive for the whole budget
// after the response has already been written.
func WithHandlerTimeout(ctx context.Context, d time.Duration) (context.Context, func()) {
	inner, cancel := context.WithCancelCause(ctx)
	budget := &handlerTimeout{cancel: cancel}
	budget.timer = time.AfterFunc(d, budget.fire)
	return context.WithValue(inner, handlerTimeoutKey{}, budget), func() {
		budget.timer.Stop()
		cancel(nil)
	}
}

// HandlerTimedOut reports whether the request's budget ran out. A middleware uses
// it to decide whether an empty response should become a 504.
func HandlerTimedOut(ctx context.Context) bool {
	budget, ok := ctx.Value(handlerTimeoutKey{}).(*handlerTimeout)
	return ok && budget.timedOut()
}

// LargeTransferDeadline is the socket read/write budget an endpoint that moves
// gigabytes lifts itself to.
//
// The server's own ReadTimeout and WriteTimeout are deliberately short, because
// they apply to EVERY endpoint and a client dribbling one byte a second would
// otherwise hold a connection, and its file descriptor, for as long as they
// like. The few endpoints that really do take minutes lift the limit for their
// own request only.
const LargeTransferDeadline = 30 * time.Minute

// cappedExtension bounds how much one request may buy itself, so no caller can
// ask for a handler that never ends.
func cappedExtension(d time.Duration) time.Duration {
	if d > LargeTransferDeadline {
		return LargeTransferDeadline
	}
	return d
}

// ExtendDeadline lengthens BOTH budgets of ONE request: the socket read and
// write deadlines, and the handler timeout that bounds r.Context().
//
// Lifting only the socket half is what this used to do, and it left the contract
// true on paper while every context-bound piece of work still stopped at the
// router's default: a multi-gigabyte SQL import died with a killed mysql child
// and a partly written database. d is capped at LargeTransferDeadline, so no
// caller can ask for an unbounded handler.
//
// It reports whether both extensions reached their target. A silent failure would
// be worse than none, so every caller logs what it gets back.
func ExtendDeadline(w http.ResponseWriter, r *http.Request, d time.Duration) error {
	d = cappedExtension(d)
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(d)
	if err := controller.SetReadDeadline(deadline); err != nil {
		return err
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return err
	}
	budget, ok := r.Context().Value(handlerTimeoutKey{}).(*handlerTimeout)
	if !ok || !budget.extend(d) {
		return ErrNoHandlerTimeout
	}
	return nil
}
