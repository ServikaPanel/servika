package optimize

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// revertRequest asks for change 5 to be put back through the scripted database.
func revertRequest(t *testing.T, script *sqlScript) (*Handlers, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "5")
	r := httptest.NewRequest(http.MethodPost, "/system/optimize/history/5/revert", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	return &Handlers{DB: scriptDB(t, script)}, httptest.NewRecorder(), r
}

// An internal fault carries the driver's own text, which names the table and the
// column. The reason-code branch is what puts an operator-actionable message on
// the screen; everything else belongs in the log.
func TestAFailedRevertDoesNotSurfaceTheUnderlyingError(t *testing.T) {
	script := newScript()
	script.fail["FROM optimize_backups WHERE id=?"] =
		errors.New("Error 1146 (42S02): Table 'panel.optimize_backups' doesn't exist")

	handlers, recorder, request := revertRequest(t, script)
	handlers.RevertChange(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusInternalServerError, recorder.Body)
	}
	for _, leaked := range []string{"optimize_backups", "42S02", "Table"} {
		if strings.Contains(recorder.Body.String(), leaked) {
			t.Errorf("the response names %q: %s", leaked, recorder.Body)
		}
	}
	if !strings.Contains(recorder.Body.String(), "the change could not be reverted") {
		t.Errorf("the generic message is missing: %s", recorder.Body)
	}
}

// A refusal is different: its reason code and message are written for the
// operator, and the screen renders them in twelve languages.
func TestARefusedRevertKeepsItsReasonCode(t *testing.T) {
	script := newScript()
	script.rows["FROM optimize_backups WHERE id=?"] = nil // no such row

	handlers, recorder, request := revertRequest(t, script)
	handlers.RevertChange(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusConflict, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), ReasonUnknownBackup) {
		t.Errorf("the reason code is missing: %s", recorder.Body)
	}
}
