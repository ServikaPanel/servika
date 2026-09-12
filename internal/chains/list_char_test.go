package chains

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// The live-attack screen. Two properties matter more than the shape of the
// answer: a caller never sees a chain on a domain they do not own, and an entry
// event (a login attack on an ACCOUNT) is never shown to a customer. A list
// that under-reports is also a failure here, so a query that breaks halfway is
// an error rather than a short list.

// listScript answers the two queries the endpoint makes, keyed by table.
type listScript struct {
	chains, events [][]driver.Value
	chainsErr      error
	eventsErr      error
	chainsRowErr   error
	eventsRowErr   error
	queries        []string
	args           [][]driver.Value
}

type listConn struct{ script *listScript }

func (c listConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c listConn) Driver() driver.Driver                        { return listDriver{} }
func (c listConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c listConn) Close() error                                 { return nil }
func (c listConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c listConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	c.script.queries = append(c.script.queries, query)
	c.script.args = append(c.script.args, plain)

	if strings.Contains(query, "FROM av_chains") {
		if c.script.chainsErr != nil {
			return nil, c.script.chainsErr
		}
		return &listRows{rows: c.script.chains, columns: 7, rowErr: c.script.chainsRowErr}, nil
	}
	if c.script.eventsErr != nil {
		return nil, c.script.eventsErr
	}
	return &listRows{rows: c.script.events, columns: 5, rowErr: c.script.eventsRowErr}, nil
}

type listRows struct {
	rows    [][]driver.Value
	columns int
	rowErr  error
	at      int
}

func (r *listRows) Columns() []string { return make([]string, r.columns) }
func (r *listRows) Close() error      { return nil }
func (r *listRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		if r.rowErr != nil {
			return r.rowErr
		}
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type listDriver struct{}

func (listDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func listDB(t *testing.T, script *listScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(listConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// chainRow is one av_chains row in SELECT order.
func chainRow(id int64, domain driver.Value, name, stages string, confidence int64, level string) []driver.Value {
	return []driver.Value{id, domain, name, stages, confidence, level, "2026-01-02 03:04:05"}
}

// listChains calls the endpoint as one role and returns its status and body.
func listChains(t *testing.T, h *Handlers, role string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/antivirus/chains", nil)
	if role != "" {
		claims := &auth.Claims{UserID: 5, Role: role}
		request = request.WithContext(auth.WithClaims(request.Context(), claims))
	}
	recorder := httptest.NewRecorder()
	h.List(recorder, request)

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %s", recorder.Body.String())
	}
	return recorder.Code, body
}

// chainsOf returns the decoded chain list.
func chainsOf(t *testing.T, body map[string]any) []any {
	t.Helper()
	list, ok := body["chains"].([]any)
	if !ok {
		t.Fatalf("the answer carries no chain list: %v", body)
	}
	return list
}

// assertStages checks that a chain carries exactly these stages, each with the
// name the screen prints.
func assertStages(t *testing.T, chain map[string]any, want ...string) {
	t.Helper()
	stages, _ := chain["stages"].([]any)
	names, _ := chain["stage_names"].([]any)
	if len(stages) != len(want) || len(names) != len(want) {
		t.Fatalf("stages = %v, names = %v, want %v", stages, names, want)
	}
	for i, stage := range want {
		if stages[i] != stage {
			t.Errorf("stage %d = %v, want %q", i, stages[i], stage)
		}
		if names[i] != StageName(stage) {
			t.Errorf("stage name %d = %v, want %q", i, names[i], StageName(stage))
		}
	}
}

// A chain is returned with its stages split, each stage named, and the timeline
// of its domain's events.
func TestAChainIsReturnedWithItsStagesAndTimeline(t *testing.T) {
	script := &listScript{
		chains: [][]driver.Value{chainRow(1, int64(9), "example.com", "entry>persist", 85, "critical")},
		events: [][]driver.Value{
			{"login", "entry", "warning", "a failed login", "2026-01-02 03:00:00"},
			{"avscan", "persist", "critical", "a web shell", "2026-01-02 03:04:00"},
		},
	}
	h := &Handlers{DB: listDB(t, script)}

	status, body := listChains(t, h, middleware.RoleAdmin)

	if status != http.StatusOK {
		t.Fatalf("status %d (%v)", status, body)
	}
	list := chainsOf(t, body)
	if len(list) != 1 {
		t.Fatalf("chains = %v, want one", list)
	}
	chain, _ := list[0].(map[string]any)
	assertStages(t, chain, "entry", "persist")
	events, _ := chain["events"].([]any)
	if len(events) != 2 {
		t.Errorf("events = %v, want the two in the window", events)
	}
	if chain["confidence"] != float64(85) || chain["level"] != "critical" {
		t.Errorf("chain = %v", chain)
	}
}

// A panel-wide chain has no domain, so there is no domain timeline to read and
// no second query is made.
func TestAPanelWideChainCarriesNoTimeline(t *testing.T) {
	script := &listScript{chains: [][]driver.Value{chainRow(1, nil, "", "entry>persist", 60, "warning")}}
	h := &Handlers{DB: listDB(t, script)}

	status, body := listChains(t, h, middleware.RoleAdmin)

	if status != http.StatusOK {
		t.Fatalf("status %d (%v)", status, body)
	}
	chain, _ := chainsOf(t, body)[0].(map[string]any)
	if chain["domain_id"] != nil {
		t.Errorf("domain_id = %v, want null", chain["domain_id"])
	}
	if len(script.queries) != 1 {
		t.Errorf("ran %d queries, want only the chain list", len(script.queries))
	}
}

// An entry event is a login attack on an ACCOUNT, so its owners are resolved
// only for a caller who may see one. A customer resolves none, and the query
// carries the two impossible owner ids that make the entry branch match
// nothing.
func TestACustomerNeverResolvesTheEntryEventOwners(t *testing.T) {
	for _, tc := range []struct {
		role        string
		wantOwnerID driver.Value
		wantQueries int
	}{
		{role: middleware.RoleUser, wantOwnerID: int64(-1), wantQueries: 2},
		{role: middleware.RoleAdmin, wantQueries: 3},
	} {
		t.Run(tc.role, func(t *testing.T) {
			script := &listScript{
				chains: [][]driver.Value{chainRow(1, int64(9), "example.com", "entry>persist", 85, "critical")},
			}
			h := &Handlers{DB: listDB(t, script)}

			if status, body := listChains(t, h, tc.role); status != http.StatusOK {
				t.Fatalf("status %d (%v)", status, body)
			}
			// An admin resolves the owners with an extra query first; a customer
			// does not ask at all.
			if len(script.queries) != tc.wantQueries {
				t.Fatalf("ran %d queries, want %d: %v", len(script.queries), tc.wantQueries, script.queries)
			}
			if tc.wantOwnerID == nil {
				return
			}
			// The event query binds the domain id, then the scope arguments, then
			// the two owner ids, then the window. Measured for a customer: the
			// scope contributes one argument, so the owners are the third and
			// fourth.
			eventArgs := script.args[len(script.args)-1]
			if eventArgs[2] != tc.wantOwnerID || eventArgs[3] != tc.wantOwnerID {
				t.Errorf("event query owners = %v, want two %v", eventArgs, tc.wantOwnerID)
			}
		})
	}
}

// A screen that reports attacks must not under-report them, so a list that
// broke halfway is an error rather than a short answer.
func TestAListThatBreaksHalfwayIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  *listScript
		message string
	}{
		{
			name:    "the chain query fails",
			script:  &listScript{chainsErr: errors.New("lost connection")},
			message: "attack chains could not be read",
		},
		{
			name: "a chain row cannot be read",
			script: &listScript{chains: [][]driver.Value{
				{nil, int64(9), "example.com", "entry>persist", int64(85), "critical", "2026-01-02 03:04:05"},
			}},
			message: "an attack chain could not be read",
		},
		{
			name: "the list ends early",
			script: &listScript{
				chains:       [][]driver.Value{chainRow(1, nil, "", "entry>persist", 60, "warning")},
				chainsRowErr: errors.New("lost connection"),
			},
			message: "attack chains could not be read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{DB: listDB(t, tc.script)}

			status, body := listChains(t, h, middleware.RoleAdmin)

			if status != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500 (%v)", status, body)
			}
			if got, _ := body["error"].(string); got != tc.message {
				t.Errorf("message %q, want %q", got, tc.message)
			}
		})
	}
}

// A timeline that cannot be read leaves the chain without one rather than
// failing the whole list: a chain with no events is still a chain worth
// showing.
func TestATimelineThatCannotBeReadDoesNotFailTheList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script *listScript
	}{
		{
			name: "the event query fails",
			script: &listScript{
				chains:    [][]driver.Value{chainRow(1, int64(9), "example.com", "entry>persist", 85, "critical")},
				eventsErr: errors.New("lost connection"),
			},
		},
		{
			name: "the event list ends early",
			script: &listScript{
				chains: [][]driver.Value{chainRow(1, int64(9), "example.com", "entry>persist", 85, "critical")},
				events: [][]driver.Value{
					{"avscan", "persist", "critical", "a web shell", "2026-01-02 03:04:00"},
				},
				eventsRowErr: errors.New("lost connection"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logged)
			t.Cleanup(func() { log.SetOutput(previous) })
			h := &Handlers{DB: listDB(t, tc.script)}

			status, body := listChains(t, h, middleware.RoleUser)

			if status != http.StatusOK {
				t.Fatalf("status %d, want the chain without its timeline (%v)", status, body)
			}
			chain, _ := chainsOf(t, body)[0].(map[string]any)
			if events, _ := chain["events"].([]any); len(events) != 0 {
				t.Errorf("events = %v, want none rather than a partial timeline", events)
			}
		})
	}
}

// The list is bounded, because the screen shows the most recent chains and an
// unbounded query is the whole table on every poll.
func TestTheListIsBounded(t *testing.T) {
	script := &listScript{}
	h := &Handlers{DB: listDB(t, script)}

	if status, body := listChains(t, h, middleware.RoleAdmin); status != http.StatusOK {
		t.Fatalf("status %d (%v)", status, body)
	}
	if !strings.Contains(script.queries[0], "ORDER BY z.created_at DESC LIMIT ?") {
		t.Errorf("the chain query is not ordered and bounded: %s", script.queries[0])
	}
	last := script.args[0][len(script.args[0])-1]
	if last != int64(chainListLimit) {
		t.Errorf("the bound is %v, want %d", last, chainListLimit)
	}
}
