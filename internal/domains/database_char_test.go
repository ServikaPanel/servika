package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/credentials"
	"servika/internal/quota"
)

// databaseFakes stands in for the MariaDB account calls CreateDatabase makes.
type databaseFakes struct {
	hostCalls
	quotaErr   error
	forUserErr error
	createErr  error
	decryptErr error
	limitsErr  error
	limits     chan int64
	password   string
}

func newDatabaseFakes(t *testing.T) *databaseFakes {
	t.Helper()
	f := &databaseFakes{limits: make(chan int64, 1)}
	setForTest(t, &lockCustomerForDomain, f.lock)
	setForTest(t, &checkDatabaseAllowed, f.quota)
	setForTest(t, &mysqlCreateDBForUser, f.forUser)
	setForTest(t, &mysqlCreateDB, f.create)
	setForTest(t, &decryptDBPass, f.decrypt)
	setForTest(t, &applyResourceLimits, f.resourceLimits)
	return f
}

func (f *databaseFakes) lock(_ context.Context, _ *sql.DB, id int64) func() {
	f.record("lock %d", id)
	return func() { f.record("unlock") }
}

func (f *databaseFakes) quota(_ context.Context, _ *sql.DB, id int64) error {
	f.record("database quota %d", id)
	return f.quotaErr
}

func (f *databaseFakes) forUser(_ *sql.DB, id int64, name, user string) error {
	f.record("create %s for existing %s", name, user)
	return f.forUserErr
}

func (f *databaseFakes) create(_ *sql.DB, id int64, name, user, password string) error {
	f.record("create %s with new %s", name, user)
	f.password = password
	return f.createErr
}

func (f *databaseFakes) decrypt(user, stored string) (string, error) {
	f.record("decrypt %s %s", user, stored)
	return "stored-password", f.decryptErr
}

func (f *databaseFakes) resourceLimits(_ context.Context, _ *sql.DB, id int64) error {
	f.limits <- id
	return f.limitsErr
}

type databaseCase struct {
	name    string
	body    string
	script  func(*sqlScript)
	fakes   func(*databaseFakes)
	status  int
	message string
	steps   []string
	limits  bool
}

// databaseScript answers for domain 7 owned by c_example, with no database of
// the requested name.
func databaseScript() *sqlScript {
	s := newScript()
	s.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{"c_example"}}
	s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_name=?"] = [][]driver.Value{{int64(0)}}
	return s
}

func runCreateDatabase(t *testing.T, tc databaseCase) (*httptest.ResponseRecorder, *databaseFakes) {
	t.Helper()
	script := databaseScript()
	fakes := newDatabaseFakes(t)
	if tc.script != nil {
		tc.script(script)
	}
	if tc.fakes != nil {
		tc.fakes(fakes)
	}
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).CreateDatabase(recorder,
		requestWithParams(http.MethodPost, tc.body, map[string]string{"id": "7"}))
	if tc.limits {
		waitForID(t, fakes.limits, 7)
	}
	return recorder, fakes
}

// createdDatabase decodes a successful CreateDatabase answer.
func createdDatabase(t *testing.T, recorder *httptest.ResponseRecorder) (name, user, password string) {
	t.Helper()
	var body struct {
		OK       bool   `json:"ok"`
		DomainID int64  `json:"domain_id"`
		DBName   string `json:"db_name"`
		DBUser   string `json:"db_user"`
		DBPass   string `json:"db_pass"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	if !body.OK || body.DomainID != 7 {
		t.Errorf("body = %+v, want ok for domain 7", body)
	}
	return body.DBName, body.DBUser, body.DBPass
}

const (
	stepLock   = "lock 7"
	stepQuota  = "database quota 7"
	stepUnlock = "unlock"
	longUser   = "c_abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
)

func TestCreateDatabaseRefusesWhatItCannotCreate(t *testing.T) {
	existing := `{"db_suffix":"shop","user_mode":"existing","existing_user":"c_example_app"}`
	newUser := `{"db_suffix":"shop","user_mode":"new","user_suffix":"app"}`
	longDomain := func(s *sqlScript) {
		s.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{longUser}}
	}
	cases := []databaseCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "a domain that does not exist", body: `{}`,
			script: func(s *sqlScript) { s.rows["SELECT system_user FROM domains WHERE id=?"] = nil },
			status: http.StatusNotFound, message: "domain not found"},
		{name: "a domain that cannot be read", body: `{}`,
			script: func(s *sqlScript) { s.fail["SELECT system_user FROM domains WHERE id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "domain query failed"},
		{name: "a plan at its database limit", body: `{}`,
			fakes:  func(f *databaseFakes) { f.quotaErr = &quota.LimitError{Message: "database limit reached"} },
			status: http.StatusForbidden, message: "database limit reached", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a plan limit that cannot be read", body: `{}`,
			fakes:  func(f *databaseFakes) { f.quotaErr = errScripted },
			status: http.StatusInternalServerError, message: "could not verify plan limit", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "no database suffix", body: `{"user_suffix":"app"}`,
			status: http.StatusBadRequest, message: "database name suffix is required", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "an invalid database suffix", body: `{"db_suffix":"Shop!"}`,
			status: http.StatusBadRequest, message: "invalid database suffix (lowercase letters, digits, underscore only; 1-32 characters)",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a database name past 64 characters", body: `{"db_suffix":"abcdefghijklmnopqrstuvwxyzabcdef"}`, script: longDomain,
			status: http.StatusBadRequest, message: "database name too long (prefix + suffix must be at most 64 characters)",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "an existing user outside the prefix", body: `{"db_suffix":"shop","user_mode":"existing","existing_user":"c_other_app"}`,
			status: http.StatusBadRequest, message: "invalid existing user", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "an existing user this domain does not hold", body: existing,
			script: func(s *sqlScript) {
				s.rows["db_accounts WHERE domain_id=? AND db_user=?"] = [][]driver.Value{{int64(0)}}
			},
			status: http.StatusBadRequest, message: "selected user does not belong to this domain", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "no user suffix", body: `{"db_suffix":"shop","user_mode":"new"}`,
			status: http.StatusBadRequest, message: "user name suffix is required", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "an invalid user suffix", body: `{"db_suffix":"shop","user_mode":"new","user_suffix":"App!"}`,
			status: http.StatusBadRequest, message: "invalid user suffix (lowercase letters, digits, underscore only; 1-32 characters)",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a user name past 64 characters", body: `{"db_suffix":"shop","user_mode":"new","user_suffix":"abcdefghijklmnopqrstuvwxyzabcdef"}`,
			script: longDomain,
			status: http.StatusBadRequest, message: "user name too long (prefix + suffix must be at most 64 characters)",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a user name lookup that fails", body: newUser,
			script: func(s *sqlScript) { s.fail["SELECT COUNT(*) FROM db_accounts WHERE db_user=?"] = errScripted },
			status: http.StatusInternalServerError, message: "database creation failed", steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a user name already taken", body: newUser,
			script: func(s *sqlScript) {
				s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_user=?"] = [][]driver.Value{{int64(1)}}
			},
			status: http.StatusConflict, message: "A database user with this name already exists: c_example_app",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a weak password", body: `{"db_suffix":"shop","user_mode":"new","user_suffix":"app","password":"short"}`,
			script: freeUserName, status: http.StatusBadRequest, steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "a database name already taken", body: `{}`,
			script: func(s *sqlScript) {
				s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_name=?"] = [][]driver.Value{{int64(1)}}
			},
			status: http.StatusConflict, message: "A database with this name already exists: c_example_db7",
			steps: []string{stepLock, stepQuota, stepUnlock}},
		{name: "an existing user MariaDB refuses", body: existing, script: ownedExistingUser,
			fakes:  func(f *databaseFakes) { f.forUserErr = credentials.ErrInvalidMySQLCredentials },
			status: http.StatusBadRequest, message: "invalid database name or user",
			steps: []string{stepLock, stepQuota, "create c_example_shop for existing c_example_app", stepUnlock}},
		{name: "an existing user whose database cannot be created", body: existing, script: ownedExistingUser,
			fakes:  func(f *databaseFakes) { f.forUserErr = errScripted },
			status: http.StatusInternalServerError, message: "database creation failed",
			steps: []string{stepLock, stepQuota, "create c_example_shop for existing c_example_app", stepUnlock}},
		{name: "a new user another domain owns", body: `{}`,
			fakes:  func(f *databaseFakes) { f.createErr = credentials.ErrDBUserOwnedByAnotherDomain },
			status: http.StatusConflict, message: "A database user with this name already exists: c_example_db7",
			steps: []string{stepLock, stepQuota, "create c_example_db7 with new c_example_db7", stepUnlock}},
		{name: "a new user MariaDB refuses", body: `{}`,
			fakes:  func(f *databaseFakes) { f.createErr = credentials.ErrInvalidMySQLCredentials },
			status: http.StatusBadRequest, message: "invalid database name or user",
			steps: []string{stepLock, stepQuota, "create c_example_db7 with new c_example_db7", stepUnlock}},
		{name: "a new user whose database cannot be created", body: `{}`,
			fakes:  func(f *databaseFakes) { f.createErr = errScripted },
			status: http.StatusInternalServerError, message: "database creation failed",
			steps: []string{stepLock, stepQuota, "create c_example_db7 with new c_example_db7", stepUnlock}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, fakes := runCreateDatabase(t, tc)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// freeUserName answers that no account holds the requested user name.
func freeUserName(s *sqlScript) {
	s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_user=?"] = [][]driver.Value{{int64(0)}}
}

// ownedExistingUser answers that domain 7 holds c_example_app.
func ownedExistingUser(s *sqlScript) {
	s.rows["db_accounts WHERE domain_id=? AND db_user=?"] = [][]driver.Value{{int64(1)}}
}

// An empty body generates the name, the user and the password. The resource
// limits that follow are best-effort, so their failure changes nothing here.
func TestCreateDatabaseGeneratesEverythingForAnEmptyBody(t *testing.T) {
	recorder, fakes := runCreateDatabase(t, databaseCase{body: `{}`, limits: true,
		fakes: func(f *databaseFakes) { f.limitsErr = errScripted }})
	assertOutcome(t, recorder, http.StatusCreated, "")
	assertSteps(t, &fakes.hostCalls, stepLock, stepQuota, "create c_example_db7 with new c_example_db7", stepUnlock)
	name, user, password := createdDatabase(t, recorder)
	if name != "c_example_db7" || user != "c_example_db7" || password == "" || password != fakes.password {
		t.Errorf("created %q %q %q, the account got %q", name, user, password, fakes.password)
	}
}

// A new user takes the password the customer chose, or a generated one.
func TestCreateDatabaseOpensANewUser(t *testing.T) {
	for _, tc := range []struct {
		name, password string
	}{
		{name: "a chosen password", password: "Aa1!aaaaaaaaaaaa"},
		{name: "a generated password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"db_suffix":"shop","user_mode":"new","user_suffix":"app","password":"` + tc.password + `"}`
			recorder, fakes := runCreateDatabase(t, databaseCase{body: body, script: freeUserName, limits: true})
			assertOutcome(t, recorder, http.StatusCreated, "")
			assertSteps(t, &fakes.hostCalls, stepLock, stepQuota, "create c_example_shop with new c_example_app", stepUnlock)
			name, user, password := createdDatabase(t, recorder)
			assertNewUserPassword(t, name, user, password, tc.password, fakes.password)
		})
	}
}

func assertNewUserPassword(t *testing.T, name, user, password, chosen, created string) {
	t.Helper()
	if name != "c_example_shop" || user != "c_example_app" || password != created {
		t.Errorf("created %q %q %q, the account got %q", name, user, password, created)
	}
	if chosen != "" && password != chosen {
		t.Errorf("password = %q, want the chosen %q", password, chosen)
	}
	if chosen == "" && password == "" {
		t.Error("no password was generated")
	}
}

// An existing user keeps its password, which is read back and returned; a
// password that cannot be read or opened comes back empty.
func TestCreateDatabaseSharesAnExistingUser(t *testing.T) {
	const body = `{"db_suffix":"shop","user_mode":"existing","existing_user":"c_example_app"}`
	for _, tc := range []struct {
		name     string
		script   func(*sqlScript)
		fakes    func(*databaseFakes)
		steps    []string
		password string
	}{
		{name: "a stored password", script: withStoredPassword,
			steps:    []string{"decrypt c_example_app enc:v1:sealed"},
			password: "stored-password"},
		{name: "a stored password that cannot be opened", script: withStoredPassword,
			fakes: func(f *databaseFakes) { f.decryptErr = errScripted },
			steps: []string{"decrypt c_example_app enc:v1:sealed"}},
		{name: "no stored password", script: func(s *sqlScript) {
			ownedExistingUser(s)
			s.rows["SELECT db_pass_plain FROM db_accounts"] = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder, fakes := runCreateDatabase(t, databaseCase{body: body, script: tc.script, fakes: tc.fakes, limits: true})
			assertOutcome(t, recorder, http.StatusCreated, "")
			assertSteps(t, &fakes.hostCalls, joinSteps(
				[]string{stepLock, stepQuota, "create c_example_shop for existing c_example_app"}, tc.steps, []string{stepUnlock})...)
			if _, _, password := createdDatabase(t, recorder); password != tc.password {
				t.Errorf("password = %q, want %q", password, tc.password)
			}
		})
	}
}

func withStoredPassword(s *sqlScript) {
	ownedExistingUser(s)
	s.rows["SELECT db_pass_plain FROM db_accounts"] = [][]driver.Value{{"enc:v1:sealed"}}
}

// A weak password is refused with the strength check's own reason.
func TestCreateDatabaseNamesWhyAPasswordIsWeak(t *testing.T) {
	recorder, _ := runCreateDatabase(t, databaseCase{
		body:   `{"db_suffix":"shop","user_mode":"new","user_suffix":"app","password":"short"}`,
		script: freeUserName,
	})
	_, reason := credentials.StrongPassword("short")
	assertOutcome(t, recorder, http.StatusBadRequest, reason)
	if reason == "" || strings.Contains(recorder.Body.String(), "short\"") {
		t.Errorf("the refusal carries no reason or echoes the password: %s", recorder.Body.String())
	}
}

// passwordFakes stands in for the MariaDB account calls SetDatabasePassword
// makes.
type passwordFakes struct {
	hostCalls
	addErr     error
	encryptErr error
	changeErr  error
	password   string
}

func newPasswordFakes(t *testing.T) *passwordFakes {
	t.Helper()
	f := &passwordFakes{}
	setForTest(t, &mysqlAddUser, f.add)
	setForTest(t, &encryptDBPass, f.encrypt)
	setForTest(t, &mysqlChangePassword, f.change)
	return f
}

func (f *passwordFakes) add(name, user, password string) error {
	f.record("add %s to %s", user, name)
	f.password = password
	return f.addErr
}

func (f *passwordFakes) encrypt(user, password string) (string, error) {
	f.record("encrypt for %s", user)
	return "enc:v1:sealed", f.encryptErr
}

func (f *passwordFakes) change(_ *sql.DB, user, password string) error {
	f.record("change %s", user)
	f.password = password
	return f.changeErr
}

type passwordCase struct {
	name    string
	body    string
	script  func(*sqlScript)
	fakes   func(*passwordFakes)
	status  int
	message string
	steps   []string
}

// passwordScript answers for database 3, c_example_shop, with no user yet.
func passwordScript() *sqlScript {
	s := newScript()
	s.rows["FROM db_accounts db JOIN domains d"] = [][]driver.Value{{"c_example_shop", ""}}
	s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_user=? AND id<>?"] = [][]driver.Value{{int64(0)}}
	return s
}

func runSetDatabasePassword(t *testing.T, tc passwordCase) (*httptest.ResponseRecorder, *sqlScript, *passwordFakes) {
	t.Helper()
	script := passwordScript()
	fakes := newPasswordFakes(t)
	if tc.script != nil {
		tc.script(script)
	}
	if tc.fakes != nil {
		tc.fakes(fakes)
	}
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).SetDatabasePassword(recorder,
		requestWithParams(http.MethodPut, tc.body, map[string]string{"dbid": "3"}))
	return recorder, script, fakes
}

func TestSetDatabasePasswordRefusesWhatItCannotSet(t *testing.T) {
	const withUser = `{"password":"secret-pass","user":"c_example_app"}`
	cases := []passwordCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "a password that is already ciphertext", body: `{"password":"enc:v1:abc"}`,
			status: http.StatusBadRequest, message: "invalid password"},
		{name: "a short password", body: `{"password":"five5"}`,
			status: http.StatusBadRequest, message: "password must be at least 6 characters"},
		{name: "a database that does not exist", body: withUser,
			script: func(s *sqlScript) { s.rows["FROM db_accounts db JOIN domains d"] = nil },
			status: http.StatusNotFound, message: "database record not found"},
		{name: "a database that cannot be read", body: withUser,
			script: func(s *sqlScript) { s.fail["FROM db_accounts db JOIN domains d"] = errScripted },
			status: http.StatusInternalServerError, message: "database read failed"},
		{name: "a database with no user and no name for one", body: `{"password":"secret-pass"}`,
			status: http.StatusBadRequest, message: "this database has no user — send a user name to create one"},
		{name: "an invalid user name", body: `{"password":"secret-pass","user":"bad user"}`,
			status: http.StatusBadRequest, message: "invalid user name"},
		{name: "a user name another database holds", body: withUser,
			script: func(s *sqlScript) {
				s.rows["SELECT COUNT(*) FROM db_accounts WHERE db_user=? AND id<>?"] = [][]driver.Value{{int64(1)}}
			},
			status: http.StatusConflict, message: "this user name is already used by another database"},
		{name: "a user name lookup that fails", body: withUser,
			script: func(s *sqlScript) { s.fail["SELECT COUNT(*) FROM db_accounts WHERE db_user=? AND id<>?"] = errScripted },
			status: http.StatusConflict, message: "this user name is already used by another database"},
		{name: "a user MariaDB will not create", body: withUser,
			fakes:  func(f *passwordFakes) { f.addErr = errScripted },
			status: http.StatusInternalServerError, message: "user could not be created", steps: []string{"add c_example_app to c_example_shop"}},
		{name: "a password that cannot be sealed", body: withUser,
			fakes:  func(f *passwordFakes) { f.encryptErr = errScripted },
			status: http.StatusInternalServerError, message: "user could not be created",
			steps: []string{"add c_example_app to c_example_shop", "encrypt for c_example_app"}},
		{name: "a record that cannot be updated", body: withUser,
			script: func(s *sqlScript) { s.fail["UPDATE db_accounts SET db_user=?"] = errScripted },
			status: http.StatusInternalServerError, message: "database record could not be updated",
			steps: []string{"add c_example_app to c_example_shop", "encrypt for c_example_app"}},
		{name: "a password MariaDB will not change", body: `{"password":"secret-pass"}`,
			script: func(s *sqlScript) {
				s.rows["FROM db_accounts db JOIN domains d"] = [][]driver.Value{{"c_example_shop", "c_example_app"}}
			},
			fakes:  func(f *passwordFakes) { f.changeErr = errScripted },
			status: http.StatusInternalServerError, message: "password change failed", steps: []string{"change c_example_app"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, _, fakes := runSetDatabasePassword(t, tc)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// A database restored without its account gets one under the name sent, and the
// sealed password is stored against it.
func TestSetDatabasePasswordCreatesTheMissingUser(t *testing.T) {
	recorder, script, fakes := runSetDatabasePassword(t, passwordCase{body: `{"password":"secret-pass","user":" c_example_app "}`})
	assertOutcome(t, recorder, http.StatusOK, "")
	assertSteps(t, &fakes.hostCalls, "add c_example_app to c_example_shop", "encrypt for c_example_app")
	assertExecArgs(t, script, "UPDATE db_accounts SET db_user=?", []driver.Value{"c_example_app", "enc:v1:sealed", int64(3)})
	assertPasswordAnswer(t, recorder, "c_example_app", "secret-pass")
}

// An existing user has its password changed; an empty body generates one.
func TestSetDatabasePasswordChangesAnExistingUser(t *testing.T) {
	recorder, _, fakes := runSetDatabasePassword(t, passwordCase{
		body: `{}`,
		script: func(s *sqlScript) {
			s.rows["FROM db_accounts db JOIN domains d"] = [][]driver.Value{{"c_example_shop", "c_example_app"}}
		},
	})
	assertOutcome(t, recorder, http.StatusOK, "")
	assertSteps(t, &fakes.hostCalls, "change c_example_app")
	if fakes.password == "" {
		t.Fatal("no password was generated")
	}
	assertPasswordAnswer(t, recorder, "c_example_app", fakes.password)
}

func assertPasswordAnswer(t *testing.T, recorder *httptest.ResponseRecorder, user, password string) {
	t.Helper()
	var body struct {
		OK     bool   `json:"ok"`
		DBID   int64  `json:"dbid"`
		DBName string `json:"db_name"`
		DBUser string `json:"db_user"`
		DBPass string `json:"db_pass"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := body
	want.OK, want.DBID, want.DBName, want.DBUser, want.DBPass = true, 3, "c_example_shop", user, password
	if body != want {
		t.Errorf("body = %+v, want %+v", body, want)
	}
}
