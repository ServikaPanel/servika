package middleware

import (
	"net/http"
	"time"

	"servika/internal/httpx"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Timeout bounds how long a handler may run, and unlike chimw.Timeout the bound
// can be LIFTED by the handler itself through httpx.ExtendDeadline.
//
// chi derives the request context with context.WithTimeout, and a derived
// context never outlives its parent's deadline. The endpoints that move
// gigabytes therefore kept the router's default however far they lifted their
// socket deadline, so a multi-gigabyte SQL import had its mysql child killed
// part way through. httpx.WithHandlerTimeout uses a resettable timer instead.
//
// The 504 is written only when the budget ran out AND the handler wrote nothing.
// chi writes it unconditionally from a defer, which lands on top of a response a
// long-running handler had already completed.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, release := httpx.WithHandlerTimeout(r.Context(), d)
			defer release()

			// WrapResponseWriter is what accesslog and metrics already use here.
			// It forwards Unwrap, so httpx.ExtendDeadline's ResponseController
			// still reaches the connection through it.
			recorder := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(recorder, r.WithContext(ctx))

			if recorder.Status() == 0 && httpx.HandlerTimedOut(ctx) {
				recorder.WriteHeader(http.StatusGatewayTimeout)
			}
		})
	}
}
