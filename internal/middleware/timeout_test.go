package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"servika/internal/httpx"
)

const shortBudget = 40 * time.Millisecond

// A handler that ignores its budget and writes nothing must still answer 504, so
// replacing chimw.Timeout did not drop the bound it enforced.
func TestAHandlerThatRunsPastItsBudgetAnswers504(t *testing.T) {
	handler := Timeout(shortBudget)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusGatewayTimeout {
		t.Errorf("status: want 504, got %d", recorder.Code)
	}
}

// A handler that lifts its budget runs past the router default and keeps its own
// status. chimw.Timeout wrote 504 from a defer whatever the handler had already
// sent, which is what put a gateway timeout on top of a finished response.
func TestALiftedBudgetKeepsTheHandlersOwnStatus(t *testing.T) {
	var extendErr error
	handler := Timeout(shortBudget)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extendErr = httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline)
		time.Sleep(4 * shortBudget)
		if r.Context().Err() != nil {
			t.Error("the lifted budget was cancelled at the router default")
		}
		w.WriteHeader(http.StatusCreated)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = response.Body.Close()

	if extendErr != nil {
		t.Errorf("ExtendDeadline through the middleware: %v", extendErr)
	}
	if response.StatusCode != http.StatusCreated {
		t.Errorf("status: want 201, got %d", response.StatusCode)
	}
}

// A handler that answered before its budget ran out keeps that answer. Nothing
// may append a 504 to a response that already went out.
func TestAnAnsweredRequestIsNotOverwrittenBy504(t *testing.T) {
	handler := Timeout(shortBudget)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		time.Sleep(4 * shortBudget)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusAccepted {
		t.Errorf("status: want 202, got %d", recorder.Code)
	}
}
