package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// The server's read and write timeouts are short, and the large-transfer
// endpoints rely on ExtendDeadline to lift them. If the response writers the
// panel wraps a request in do not forward SetReadDeadline, the lift silently
// does nothing and a multi-gigabyte upload dies at the server default with no
// explanation. This runs the call through the same wrapper types the router
// installs: chi's compressor and the WrapResponseWriter that both the access log
// and the metrics collector use.
func TestExtendDeadlineReachesTheConnectionThroughTheWrappers(t *testing.T) {
	var extendErr error
	var extended bool

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extendErr = ExtendDeadline(w, r, LargeTransferDeadline)
		extended = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := chimw.Compress(5)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, release := WithHandlerTimeout(r.Context(), time.Minute)
		defer release()
		metricsWriter := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		accessLogWriter := chimw.NewWrapResponseWriter(metricsWriter, r.ProtoMajor)
		inner.ServeHTTP(accessLogWriter, r.WithContext(ctx))
	}))

	server := httptest.NewServer(wrapped)
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	if !extended {
		t.Fatal("the handler never ran")
	}
	if extendErr != nil {
		t.Errorf("ExtendDeadline through the wrappers: %v", extendErr)
	}
}

// A writer with no route to the connection has to report that, so a caller logs
// it instead of believing the deadline was lifted.
func TestExtendDeadlineReportsAWriterItCannotReach(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ExtendDeadline(httptest.NewRecorder(), request, time.Minute); err == nil {
		t.Error("a writer with no connection behind it reported success")
	}
}

// The handler half has to report a failure of its own. A request that carries no
// extendable budget means the router's default still bounds every piece of
// context-bound work, which is exactly the state that killed a mysql import part
// way through, so it must not read as a successful lift.
func TestExtendDeadlineReportsARequestWithNoExtendableBudget(t *testing.T) {
	served := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served <- ExtendDeadline(w, r, LargeTransferDeadline)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = response.Body.Close()

	if err := <-served; !errors.Is(err, ErrNoHandlerTimeout) {
		t.Errorf("want ErrNoHandlerTimeout, got %v", err)
	}
}

// An extension may not buy more than the large-transfer budget, so a later caller
// cannot ask for a handler that never ends.
func TestExtendDeadlineIsCappedAtTheLargeTransferBudget(t *testing.T) {
	ctx, release := WithHandlerTimeout(context.Background(), time.Hour)
	defer release()
	budget, ok := ctx.Value(handlerTimeoutKey{}).(*handlerTimeout)
	if !ok {
		t.Fatal("the context carries no budget")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	_ = ExtendDeadline(httptest.NewRecorder(), request, 100*time.Hour)

	// The recorder cannot carry a socket deadline, so the call returns early and
	// the budget is untouched. Extending it directly is what the cap guards.
	if !budget.extend(100 * time.Hour) {
		t.Fatal("the budget refused an extension")
	}
	if got := cappedExtension(100 * time.Hour); got != LargeTransferDeadline {
		t.Errorf("cap: want %v, got %v", LargeTransferDeadline, got)
	}
}

// A handler that lifts its budget runs past the router default, and the 504 the
// middleware writes for a timed-out request must not land on its response.
func TestALiftedBudgetOutlivesTheRouterDefault(t *testing.T) {
	const short = 40 * time.Millisecond
	ctx, release := WithHandlerTimeout(context.Background(), short)
	defer release()

	budget, _ := ctx.Value(handlerTimeoutKey{}).(*handlerTimeout)
	if !budget.extend(2 * time.Second) {
		t.Fatal("the budget refused an extension")
	}

	time.Sleep(4 * short)
	if HandlerTimedOut(ctx) {
		t.Error("the budget fired at the router default even though it was lifted")
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("the context was cancelled: %v", err)
	}
}

// Without a lift the budget still fires, so the default is a real bound rather
// than one the resettable timer quietly removed.
func TestAnUnliftedBudgetStillFires(t *testing.T) {
	const short = 40 * time.Millisecond
	ctx, release := WithHandlerTimeout(context.Background(), short)
	defer release()

	<-ctx.Done()
	if !HandlerTimedOut(ctx) {
		t.Error("the context ended without the budget reporting a timeout")
	}
	if !errors.Is(context.Cause(ctx), ErrHandlerTimeout) {
		t.Errorf("cause: want ErrHandlerTimeout, got %v", context.Cause(ctx))
	}
}
