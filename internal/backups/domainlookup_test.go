package backups

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// lookupQuery is the read every per-domain backup handler starts with.
const lookupQuery = "SELECT domain_name, system_user FROM domains WHERE id=?"

// domainRequest builds a request with its route parameters set the way chi hands
// them to a handler. params alternates names and values.
func domainRequest(method, target, body string, params ...string) *http.Request {
	route := chi.NewRouteContext()
	for i := 0; i+1 < len(params); i += 2 {
		route.URLParams.Add(params[i], params[i+1])
	}
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
}

// existingDomain answers the lookup for domain 5 with the two columns it selects.
func existingDomain() map[string][][]driver.Value {
	return map[string][][]driver.Value{lookupQuery: {{"example.com", "c_example"}}}
}

// The lookup still scanned a third destination after the read-only column left
// its SELECT, and database/sql refuses a scan whose destinations outnumber the
// columns. Every existing domain then answered 500 on its schedule, its
// destination and its manual backup.
func TestAnExistingDomainReadsItsBackupSchedule(t *testing.T) {
	rows := existingDomain()
	rows["COALESCE(backup_freq,'none'), COALESCE(backup_hour,3)"] = [][]driver.Value{{"daily", int64(4), int64(7), nil}}
	h := &Handlers{DB: scriptDB(t, &sqlScript{rows: rows})}

	w := httptest.NewRecorder()
	h.GetSchedule(w, domainRequest(http.MethodGet, "/domains/5/backups/schedule", "", "id", "5"))
	if w.Code != http.StatusOK {
		t.Fatalf("the schedule read answered %d: %s", w.Code, w.Body.String())
	}
	var got Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != (Schedule{Frequency: "daily", Hour: 4, Retention: 7}) {
		t.Fatalf("schedule = %+v", got)
	}
}

func TestAnExistingDomainSavesItsBackupSchedule(t *testing.T) {
	script := &sqlScript{rows: existingDomain()}
	h := &Handlers{DB: scriptDB(t, script)}

	w := httptest.NewRecorder()
	h.SetSchedule(w, domainRequest(http.MethodPut, "/domains/5/backups/schedule",
		`{"frequency":"weekly","hour":2,"retention":120}`, "id", "5"))
	if w.Code != http.StatusOK {
		t.Fatalf("the schedule save answered %d: %s", w.Code, w.Body.String())
	}
	updates := script.execsContaining("UPDATE domains SET backup_freq=?")
	if len(updates) != 1 {
		t.Fatalf("%d schedule updates ran, want 1", len(updates))
	}
	// The retention is clamped to 90 before it is stored.
	if want := []driver.Value{"weekly", int64(2), int64(90), int64(5)}; !slices.Equal(updates[0].args, want) {
		t.Fatalf("the update bound %v, want %v", updates[0].args, want)
	}
}

func TestAnExistingDomainDeletesItsBackupDestination(t *testing.T) {
	script := &sqlScript{rows: existingDomain()}
	h := &Handlers{DB: scriptDB(t, script)}

	w := httptest.NewRecorder()
	h.DeleteDestination(w, domainRequest(http.MethodDelete, "/domains/5/backups/destination", "", "id", "5"))
	if w.Code != http.StatusOK {
		t.Fatalf("the destination delete answered %d: %s", w.Code, w.Body.String())
	}
	deletes := script.execsContaining("DELETE FROM backup_destinations WHERE domain_id=?")
	if len(deletes) != 1 || !slices.Equal(deletes[0].args, []driver.Value{int64(5)}) {
		t.Fatalf("the delete ran as %+v", deletes)
	}
}
