package wordpress

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// runUserPassword drives the password reset endpoint.
func runUserPassword(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &Handlers{DB: scriptDB(t, s)}
	recorder := httptest.NewRecorder()
	h.UserPassword(recorder, wpRequest(http.MethodPost, "/domains/1/wordpress/user-password", body))
	return recorder
}

func TestUserPasswordRefusesARequestItCannotAct(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	recordWP(t, nil)

	refusals := []struct {
		name     string
		user     string
		body     string
		status   int
		fragment string
	}{
		{"a body that is not JSON", "c_test", "{", http.StatusBadRequest, "invalid request body"},
		{"an unknown domain", "", `{"dir":"/blog","user_id":1}`, http.StatusNotFound, "domain not found"},
		{"a directory with no WordPress in it", "c_test", `{"dir":"/other","user_id":1}`,
			http.StatusBadRequest, "invalid request"},
		{"a user id of zero", "c_test", `{"dir":"/blog","user_id":0}`, http.StatusBadRequest, "invalid user"},
		{"a password under eight characters", "c_test", `{"dir":"/blog","user_id":1,"password":"short"}`,
			http.StatusBadRequest, "8 to 100 characters"},
		{"a password over a hundred characters", "c_test",
			`{"dir":"/blog","user_id":1,"password":"` + strings.Repeat("x", 101) + `"}`,
			http.StatusBadRequest, "8 to 100 characters"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := newScript()
			if tc.user != "" {
				s = domainScript(tc.user)
			} else {
				s.rows[domainLookup] = [][]driver.Value{}
			}
			assertStatus(t, runUserPassword(t, s, tc.body), tc.status, tc.fragment)
		})
	}
}

// A user id that names nobody must not be reported as a completed change, and
// the login is read before the update for exactly that reason.
func TestUserPasswordStopsAtAnAccountItCannotRead(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	cases := []struct {
		name   string
		answer wpAnswer
	}{
		{"the lookup fails", wpAnswer{out: "Error: Invalid user ID", err: errors.New("exit 1")}},
		{"the lookup returns nothing", wpAnswer{out: "  \n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := recordWP(t, map[string]wpAnswer{"user get": tc.answer})

			assertStatus(t, runUserPassword(t, domainScript("c_test"), `{"dir":"/blog","user_id":9}`),
				http.StatusNotFound, "user not found")
			for _, key := range rec.keys() {
				if key == "user update" {
					t.Fatal("the password was changed for an account that was not read")
				}
			}
		})
	}
}

func TestUserPasswordReportsAChangeItCouldNotFinish(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	cases := []struct {
		name     string
		answers  map[string]wpAnswer
		fragment string
	}{
		{"the update command fails", map[string]wpAnswer{
			"user get":    {out: "admin"},
			"user update": {out: "Error: could not update", err: errors.New("exit 1")}},
			"operation failed"},
		{"the new password does not work afterwards", map[string]wpAnswer{
			"user get":            {out: "admin"},
			"eval check-password": {out: "MISMATCH"}},
			"the password change could not be confirmed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recordWP(t, tc.answers)

			assertStatus(t, runUserPassword(t, domainScript("c_test"), `{"dir":"/blog","user_id":9}`),
				http.StatusInternalServerError, tc.fragment)
		})
	}
}

func TestUserPasswordGeneratesAPasswordAndKeepsItOffTheCommandLine(t *testing.T) {
	root := tenantRoot(t)
	target := filepath.Join(root, "blog")
	wpConfig(t, target, "<?php")
	rec := recordWP(t, map[string]wpAnswer{"user get": {out: "admin\n"}})

	recorder := runUserPassword(t, domainScript("c_test"), `{"dir":"/blog","user_id":9}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var got struct {
		OK       bool   `json:"ok"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if !got.OK || got.Username != "admin" {
		t.Errorf("response = %+v, want the login the lookup returned", got)
	}
	if got.Password != rec.userPass || got.Password == "" {
		t.Errorf("password = %q, want the value that went in on stdin (%q)", got.Password, rec.userPass)
	}
	for _, call := range rec.calls {
		for _, arg := range call.args {
			if strings.Contains(arg, got.Password) {
				t.Fatalf("the password is in argv: %q", arg)
			}
		}
	}
	assertArgvHolds(t, rec.argvFor("user update"), "user", "update", "9", "--skip-email",
		"--path="+target, "--quiet", "--prompt=user_pass")
}

// A password the customer chose is used as given, and still verified.
func TestUserPasswordKeepsTheChosenPassword(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	rec := recordWP(t, map[string]wpAnswer{"user get": {out: "admin"}})

	recorder := runUserPassword(t, domainScript("c_test"),
		`{"dir":"/blog","user_id":9,"password":"  chosenPassword  "}`)
	assertStatus(t, recorder, http.StatusOK, `"password":"chosenPassword"`)
	if rec.userPass != "chosenPassword" {
		t.Fatalf("stdin carried %q, want the trimmed password the customer chose", rec.userPass)
	}
}
