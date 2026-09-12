package firewall

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rule screen writes the whole packet filter of the server. Nothing below
// the pure buildRuleset was reachable in a test: a rebuild runs nft twice and
// writes two files under /etc/nftables, and adding a rule refuses eight ways
// before it gets there. The three seams (rulesFile, geoIncludeFile, and the two
// nft calls) carry that, so these tests measure the DECISIONS: what is refused,
// what a failed apply leaves behind, and what reaches the ruleset.

// fwScript answers the six reads a rebuild makes and records what ran.
type fwScript struct {
	// rules are the firewall_rules rows, as type, ip, port and protocol.
	rules [][]driver.Value
	// countries are the blocked country codes.
	countries [][]driver.Value
	// remoteEnabled is panel_settings.db_remote_enabled.
	remoteEnabled int64
	// remoteHosts are the allowed remote database sources.
	remoteHosts [][]driver.Value
	// hostApps is how many server applications are installed, and openPorts the
	// ports the operator opened.
	hostApps  int64
	openPorts [][]driver.Value
	// templateCount is what a template's duplicate check reads back.
	templateCount int64
	queryErr      map[string]error
	execErr       map[string]error
	execs         []string
	execArgs      [][]driver.Value
	lastInsert    int64
}

// ranStatement returns the arguments of the first executed statement carrying
// the fragment, and whether it ran.
func (s *fwScript) ranStatement(fragment string) ([]driver.Value, bool) {
	for i, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return s.execArgs[i], true
		}
	}
	return nil, false
}

type fwConn struct{ script *fwScript }

func (c fwConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c fwConn) Driver() driver.Driver                        { return fwDriver{} }
func (c fwConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c fwConn) Close() error                                 { return nil }
func (c fwConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func fwFailure(table map[string]error, query string) error {
	for fragment, err := range table {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

type fwResult struct{ id int64 }

func (r fwResult) LastInsertId() (int64, error) { return r.id, nil }
func (r fwResult) RowsAffected() (int64, error) { return 1, nil }

func (c fwConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	c.script.execs = append(c.script.execs, query)
	c.script.execArgs = append(c.script.execArgs, plain)
	if err := fwFailure(c.script.execErr, query); err != nil {
		return nil, err
	}
	return fwResult{id: c.script.lastInsert}, nil
}

func (c fwConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if err := fwFailure(c.script.queryErr, query); err != nil {
		return nil, err
	}
	switch {
	// Before the rule listing below: a template's duplicate check reads a single
	// count out of the same table, and answering it with rule rows would fail
	// the scan rather than the check.
	case strings.Contains(query, "SELECT COUNT(*) FROM firewall_rules"):
		return &fwRows{columns: 1, rows: [][]driver.Value{{c.script.templateCount}}}, nil
	case strings.Contains(query, "FROM firewall_rules"):
		return &fwRows{columns: 4, rows: c.script.rules}, nil
	case strings.Contains(query, "FROM firewall_geo_rules"):
		return &fwRows{columns: 1, rows: c.script.countries}, nil
	case strings.Contains(query, "db_remote_enabled"):
		return &fwRows{columns: 1, rows: [][]driver.Value{{c.script.remoteEnabled}}}, nil
	case strings.Contains(query, "FROM db_remote_hosts"):
		return &fwRows{columns: 1, rows: c.script.remoteHosts}, nil
	case strings.Contains(query, "FROM host_apps"):
		return &fwRows{columns: 1, rows: [][]driver.Value{{c.script.hostApps}}}, nil
	case strings.Contains(query, "FROM host_app_ports"):
		return &fwRows{columns: 1, rows: c.script.openPorts}, nil
	}
	return &fwRows{columns: 1}, nil
}

type fwRows struct {
	columns int
	rows    [][]driver.Value
	at      int
}

func (r *fwRows) Columns() []string { return make([]string, r.columns) }
func (r *fwRows) Close() error      { return nil }
func (r *fwRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type fwDriver struct{}

func (fwDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// nftCalls records what the two nft steps were given.
type nftCalls struct {
	checked  []string
	applied  []string
	checkErr error
	applyErr error
}

// fakeHost points the two written files at a temporary directory and stands in
// for both nft calls, so a rebuild can run on a laptop.
func fakeHost(t *testing.T) (*nftCalls, string) {
	t.Helper()
	dir := t.TempDir()
	previousRules, previousGeo := rulesFile, geoIncludeFile
	previousCheck, previousApply := nftCheck, nftApply
	t.Cleanup(func() {
		rulesFile, geoIncludeFile = previousRules, previousGeo
		nftCheck, nftApply = previousCheck, previousApply
	})
	rulesFile = filepath.Join(dir, "servika_fw.nft")
	geoIncludeFile = filepath.Join(dir, "servika-geo.nft")

	calls := &nftCalls{}
	nftCheck = func(ruleset []byte) (string, error) {
		calls.checked = append(calls.checked, string(ruleset))
		if calls.checkErr != nil {
			return "the ruleset is not valid", calls.checkErr
		}
		return "", nil
	}
	nftApply = func(ruleset []byte) (string, error) {
		calls.applied = append(calls.applied, string(ruleset))
		if calls.applyErr != nil {
			return "the ruleset could not be applied", calls.applyErr
		}
		return "", nil
	}
	return calls, dir
}

func fwDB(t *testing.T, script *fwScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(fwConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// addRule posts one rule and returns the response.
func addRule(h *Handlers, body string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	h.Add(response, httptest.NewRequest(http.MethodPost, "/firewall", strings.NewReader(body)))
	return response
}

// errorOf reads the message out of a refusal.
func errorOf(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer is not JSON: %s", response.Body.String())
	}
	message, _ := body["error"].(string)
	return message
}

// A rule that would lock somebody out, or that nft could not render, is refused
// before it reaches the table.
func TestARuleIsRefusedBeforeItIsStored(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{8080, 8443})
	for _, tc := range []struct {
		name    string
		body    string
		message string
	}{
		{name: "not JSON", body: "{", message: "invalid request body"},
		{
			name:    "a protocol nft does not filter here",
			body:    `{"type":"close","protocol":"icmp","port":25}`,
			message: "protocol must be tcp or udp",
		},
		{
			name:    "a port that does not exist",
			body:    `{"type":"close","port":70000}`,
			message: "invalid port (0-65535)",
		},
		{
			name:    "a ban on something that is not an address",
			body:    `{"type":"banned","ip":"garbage"}`,
			message: "enter a valid IP address or CIDR (for example, 1.2.3.4 or 1.2.3.0/24)",
		},
		{
			name:    "an allowlist entry that is not an address",
			body:    `{"type":"whitelist","ip":""}`,
			message: "enter a valid IP address or CIDR (for example, 1.2.3.4 or 1.2.3.0/24)",
		},
		{
			name:    "closing everything",
			body:    `{"type":"close","port":0}`,
			message: "specify a port to close",
		},
		{
			name:    "closing the port the panel is on",
			body:    `{"type":"close","port":8443}`,
			message: "port 8443 is critical for SSH, web, panel, or DNS access and cannot be closed",
		},
		{
			name:    "closing the port sshd serves",
			body:    `{"type":"close","port":22}`,
			message: "port 22 is critical for SSH, web, panel, or DNS access and cannot be closed",
		},
		{
			name:    "a kind of rule the renderer has no line for",
			body:    `{"type":"quarantine","ip":"203.0.113.7"}`,
			message: "type must be banned, whitelist, or closed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = fakeHost(t)
			script := &fwScript{}
			h := &Handlers{DB: fwDB(t, script)}

			response := addRule(h, tc.body)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body)
			}
			if got := errorOf(t, response); got != tc.message {
				t.Errorf("message = %q, want %q", got, tc.message)
			}
			if _, stored := script.ranStatement("INSERT INTO firewall_rules"); stored {
				t.Error("the refused rule was stored anyway")
			}
		})
	}
}

// A rule with no protocol is tcp, and closing a port blocks everybody, so the
// address is cleared rather than kept.
func TestAStoredRuleCarriesTheDefaultsTheRendererExpects(t *testing.T) {
	stubSSHPorts(t, []int{22})
	_, _ = fakeHost(t)
	script := &fwScript{lastInsert: 12}
	h := &Handlers{DB: fwDB(t, script)}

	response := addRule(h, `{"type":"close","port":3306,"ip":"203.0.113.7","description":"MySQL"}`)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body)
	}
	args, stored := script.ranStatement("INSERT INTO firewall_rules")
	if !stored {
		t.Fatal("the rule was not stored")
	}
	if args[0] != "close" || args[1] != "" || args[2] != int64(3306) || args[3] != "tcp" {
		t.Errorf("stored %v, want a tcp close with no address", args)
	}
}

// A rule that cannot be applied is REMOVED again, and the firewall is rebuilt
// from the rows that are left: a stored rule the packet filter never received
// would show the operator a protection that does not exist.
func TestARuleThatCannotBeAppliedIsTakenBackOut(t *testing.T) {
	stubSSHPorts(t, []int{22})
	calls, _ := fakeHost(t)
	calls.checkErr = errors.New("exit status 1")
	script := &fwScript{lastInsert: 12}
	h := &Handlers{DB: fwDB(t, script)}

	response := addRule(h, `{"type":"close","port":3306}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := errorOf(t, response); got != "firewall rules could not be applied" {
		t.Errorf("message = %q", got)
	}
	args, removed := script.ranStatement("DELETE FROM firewall_rules")
	if !removed {
		t.Fatal("the rule that could not be applied is still in the table")
	}
	if args[0] != int64(12) {
		t.Errorf("removed %v, want the row just inserted", args)
	}
	// The second rebuild is what puts the packet filter back to the rows that
	// are left; without it the host keeps whatever the failed attempt left.
	if len(calls.checked) != 2 {
		t.Errorf("nft was asked to validate %d times, want the attempt and the rollback", len(calls.checked))
	}
}

// A rule the table would not take is reported rather than answered as stored.
func TestARuleTheTableRefusesIsReported(t *testing.T) {
	stubSSHPorts(t, []int{22})
	_, _ = fakeHost(t)
	script := &fwScript{execErr: map[string]error{
		"INSERT INTO firewall_rules": errors.New("read-only server"),
	}}
	h := &Handlers{DB: fwDB(t, script)}

	response := addRule(h, `{"type":"banned","ip":"203.0.113.7"}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := errorOf(t, response); got != "rule could not be added" {
		t.Errorf("message = %q", got)
	}
}

// The rendered ruleset carries each kind of rule in the order the chain needs,
// and a port-specific allowlist entry brings its own drop with it: without that
// drop the accept grants nothing that was not already allowed.
func TestEachKindOfRuleReachesTheRulesetInOrder(t *testing.T) {
	calls, _ := fakeHost(t)
	script := &fwScript{rules: [][]driver.Value{
		{"whitelist", "203.0.113.7", int64(3306), "tcp"},
		{"close", "", int64(21), "tcp"},
		{"banned", "198.51.100.9", int64(0), "tcp"},
	}}
	h := &Handlers{DB: fwDB(t, script)}

	if err := h.rebuild(); err != nil {
		t.Fatalf("rebuild() = %v", err)
	}
	if len(calls.applied) != 1 {
		t.Fatalf("nft applied %d rulesets, want one", len(calls.applied))
	}
	ruleset := calls.applied[0]
	accept := at(ruleset, "ip saddr 203.0.113.7 tcp dport 3306 accept")
	restrict := at(ruleset, "tcp dport 3306 drop")
	closed := at(ruleset, "tcp dport 21 drop")
	banned := at(ruleset, "ip saddr 198.51.100.9 drop")
	if accept < 0 || restrict < 0 || closed < 0 || banned < 0 {
		t.Fatalf("a line is missing (accept=%d restrict=%d close=%d ban=%d):\n%s",
			accept, restrict, closed, banned, ruleset)
	}
	if accept >= restrict || restrict >= closed || closed >= banned {
		t.Errorf("the order is accept=%d restrict=%d close=%d ban=%d:\n%s",
			accept, restrict, closed, banned, ruleset)
	}
}

// A row that cannot be read is skipped rather than failing the rebuild, and the
// rules around it still reach the host: one unreadable row must not take the
// whole packet filter down with it.
func TestAnUnreadableRuleIsSkippedAndTheRestStillApply(t *testing.T) {
	calls, _ := fakeHost(t)
	script := &fwScript{rules: [][]driver.Value{
		{nil, "", int64(21), "tcp"},
		{"close", "", int64(23), "tcp"},
	}}
	h := &Handlers{DB: fwDB(t, script)}

	if err := h.rebuild(); err != nil {
		t.Fatalf("rebuild() = %v", err)
	}
	ruleset := calls.applied[0]
	if strings.Contains(ruleset, "dport 21 drop") {
		t.Error("an unreadable row was rendered anyway")
	}
	if !strings.Contains(ruleset, "dport 23 drop") {
		t.Errorf("the readable rule did not reach the host:\n%s", ruleset)
	}
}

// The applied ruleset is persisted, so panel startup can put it back after a
// reboot, and the country element file is written first: nft validates the
// include as part of the document, so a stale file would be what gets checked.
func TestTheAppliedRulesetIsPersistedAlongsideTheCountryFile(t *testing.T) {
	calls, dir := fakeHost(t)
	h := &Handlers{DB: fwDB(t, &fwScript{})}

	if err := h.rebuild(); err != nil {
		t.Fatalf("rebuild() = %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "servika_fw.nft"))
	if err != nil {
		t.Fatalf("the ruleset was not persisted: %v", err)
	}
	if string(stored) != calls.applied[0] {
		t.Error("the persisted ruleset is not the one that was applied")
	}
	info, err := os.Stat(filepath.Join(dir, "servika-geo.nft"))
	if err != nil {
		t.Fatalf("the country element file was not written: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("the country file is %v, want 0644 so nft can read it", info.Mode().Perm())
	}
}

// Every read a rebuild makes can fail, and each one aborts it: a ruleset built
// from a half-read database is a firewall with the drops of one state and the
// accepts of another.
func TestAReadThatFailsAbortsTheWholeRebuild(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fragment string
		want     string
	}{
		{name: "the rules", fragment: "FROM firewall_rules", want: "lost connection"},
		{name: "the countries", fragment: "FROM firewall_geo_rules", want: "lost connection"},
		{name: "the database switch", fragment: "db_remote_enabled", want: "remote database switch"},
		{name: "the database allowlist", fragment: "FROM db_remote_hosts", want: "remote database hosts"},
		{name: "the applications", fragment: "FROM host_apps", want: "server applications"},
		{name: "the application ports", fragment: "FROM host_app_ports", want: "server application ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, _ := fakeHost(t)
			script := &fwScript{
				remoteEnabled: 1,
				hostApps:      1,
				queryErr:      map[string]error{tc.fragment: errors.New("lost connection")},
			}
			h := &Handlers{DB: fwDB(t, script)}

			err := h.rebuild()

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rebuild() = %v, want %q", err, tc.want)
			}
			if len(calls.applied) != 0 {
				t.Error("a ruleset was applied although the database could not be read")
			}
		})
	}
}

// An invalid ruleset is never applied, and a failed apply is reported rather
// than persisted: the file on disk is what the next boot restores.
func TestANftFailureNeitherAppliesNorPersists(t *testing.T) {
	for _, tc := range []struct {
		name    string
		check   error
		apply   error
		message string
	}{
		{name: "the ruleset is invalid", check: errors.New("exit status 1"), message: "nft validation failed"},
		{name: "the apply failed", apply: errors.New("exit status 1"), message: "nft apply failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, dir := fakeHost(t)
			calls.checkErr, calls.applyErr = tc.check, tc.apply
			h := &Handlers{DB: fwDB(t, &fwScript{})}

			err := h.rebuild()

			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("rebuild() = %v, want %q", err, tc.message)
			}
			if tc.check != nil && len(calls.applied) != 0 {
				t.Error("an invalid ruleset was applied")
			}
			if _, statErr := os.Stat(filepath.Join(dir, "servika_fw.nft")); statErr == nil {
				t.Error("a ruleset that never applied was persisted, so the next boot restores it")
			}
		})
	}
}

// The country element file cannot be written where there is no directory, and
// that stops the rebuild rather than checking a stale file.
func TestACountryFileThatCannotBeWrittenStopsTheRebuild(t *testing.T) {
	calls, dir := fakeHost(t)
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	geoIncludeFile = filepath.Join(blocked, "servika-geo.nft")
	h := &Handlers{DB: fwDB(t, &fwScript{})}

	if err := h.rebuild(); err == nil {
		t.Fatal("rebuild() = nil, want the write failure")
	}
	if len(calls.checked) != 0 {
		t.Error("nft was asked to validate a document whose include could not be written")
	}
}
