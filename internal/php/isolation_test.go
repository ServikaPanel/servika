package php

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// Every ini key the panel refuses in the free-text box and ALSO exposes as a
// dedicated field must be role-gated. The two paths used to contradict each
// other: a directive line overriding open_basedir was refused, while the same
// value sent as the open_basedir field of the same request was accepted and
// rendered into the pool as a php_admin_value.
//
// This compares the two lists rather than naming the fields twice, so adding a
// key to one and forgetting the other fails here.
func TestEveryProhibitedKeyWithAFieldIsRoleGated(t *testing.T) {
	gated := map[string]bool{}
	for _, field := range isolationFields {
		gated[field.iniKey] = true
		if !prohibitedExtraDirectives[field.iniKey] {
			t.Errorf("%s is role-gated as a field but allowed as an extra directive", field.iniKey)
		}
	}

	// The reverse direction is read from the RENDERER rather than guessed from
	// field names: any prohibited ini key the pool template fills from a
	// Settings field is reachable through the request body, so it has to be
	// gated. Deriving it from the template is what keeps this honest when a
	// field name and its ini key differ, as session_save_path and
	// session.save_path do.
	for key := range prohibitedExtraDirectives {
		if !templateFillsFromSettings(poolTmpl.Root.String(), key) || gated[key] {
			continue
		}
		t.Errorf("%s is refused as an extra directive but the pool takes it from a settings field any caller may send",
			key)
	}
}

// templateFillsFromSettings reports whether the pool template renders key from a
// Settings field, rather than from a fixed value or the system user.
func templateFillsFromSettings(template, key string) bool {
	for line := range strings.SplitSeq(template, "\n") {
		prefix := "php_admin_value[" + key + "]"
		if !strings.HasPrefix(strings.TrimSpace(line), prefix) &&
			!strings.HasPrefix(strings.TrimSpace(line), "{{if .S.") {
			continue
		}
		if strings.Contains(line, prefix) && strings.Contains(line, "{{") && strings.Contains(line, ".S.") {
			return true
		}
	}
	return false
}

// A customer's values are discarded and the stored ones put back.
func TestACustomerCannotWidenTheJail(t *testing.T) {
	stored := map[string]string{
		"disable_functions":           "exec,system",
		"open_basedir":                "/home/c_tenant/:/tmp/",
		"include_path":                ".:/usr/share/php",
		"session_save_path":           "/home/c_tenant/tmp",
		"mail_force_extra_parameters": "",
	}
	db := storedSettingsDB(t, stored)
	sent := Settings{
		DisableFunctions:         "",
		OpenBasedir:              "/",
		IncludePath:              "/etc",
		SessionSavePath:          "/tmp",
		MailForceExtraParameters: "-X/tmp/mail.log",
	}

	keepIsolationFields(context.Background(), db, requestAs(middleware.RoleUser), 7, 0, &sent)

	for _, field := range isolationFields {
		if got := field.get(&sent); got != stored[field.column] {
			t.Errorf("%s = %q, want the stored %q", field.iniKey, got, stored[field.column])
		}
	}
}

// And an administrator's values pass through, or the guard would make the
// setting unchangeable by anyone.
func TestAnAdministratorStillSetsTheIsolationFields(t *testing.T) {
	db := storedSettingsDB(t, map[string]string{"open_basedir": "/home/c_tenant/"})
	sent := Settings{OpenBasedir: "/srv/shared/"}

	keepIsolationFields(context.Background(), db, requestAs(middleware.RoleAdmin), 7, 0, &sent)

	if sent.OpenBasedir != "/srv/shared/" {
		t.Errorf("OpenBasedir = %q, want the administrator's value", sent.OpenBasedir)
	}
}

// A request with no claim at all is treated as non-admin: the guard fails
// closed.
func TestAnUnauthenticatedRequestIsTreatedAsNonAdmin(t *testing.T) {
	db := storedSettingsDB(t, map[string]string{"open_basedir": "/home/c_tenant/"})
	sent := Settings{OpenBasedir: "/"}

	keepIsolationFields(context.Background(), db, httptest.NewRequest(http.MethodPut, "/x", nil), 7, 0, &sent)

	if sent.OpenBasedir != "/home/c_tenant/" {
		t.Errorf("OpenBasedir = %q, want the stored value", sent.OpenBasedir)
	}
}

// With no stored row the hardened defaults are used, not the caller's values.
func TestWithNoStoredRowTheDefaultsAreUsed(t *testing.T) {
	db := storedSettingsDB(t, nil)
	sent := Settings{DisableFunctions: "", OpenBasedir: "/"}

	keepIsolationFields(context.Background(), db, requestAs(middleware.RoleUser), 7, 0, &sent)

	defaults := Defaults()
	if sent.DisableFunctions != defaults.DisableFunctions {
		t.Errorf("DisableFunctions = %q, want the hardened default", sent.DisableFunctions)
	}
	if sent.OpenBasedir != defaults.OpenBasedir {
		t.Errorf("OpenBasedir = %q, want the default", sent.OpenBasedir)
	}
}

func requestAs(role string) *http.Request {
	request := httptest.NewRequest(http.MethodPut, "/domains/7/php-settings", nil)
	claims := &auth.Claims{UserID: 3, Username: "tenant", Role: role}
	return request.WithContext(auth.WithClaims(request.Context(), claims))
}

// storedSettingsDB answers each single-column SELECT with the stored value for
// that column, or no row when the column is absent from the map.
func storedSettingsDB(t *testing.T, stored map[string]string) *sql.DB {
	t.Helper()
	db := sql.OpenDB(settingsConn{stored: stored})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type settingsConn struct{ stored map[string]string }

func (c settingsConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c settingsConn) Driver() driver.Driver                        { return settingsDriver{} }
func (c settingsConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c settingsConn) Close() error                                 { return nil }
func (c settingsConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c settingsConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	for column, value := range c.stored {
		if strings.Contains(query, "SELECT "+column+" FROM php_settings") {
			return &settingsRows{value: value}, nil
		}
	}
	return &settingsRows{empty: true}, nil
}

type settingsRows struct {
	value string
	empty bool
	done  bool
}

func (r *settingsRows) Columns() []string { return []string{"value"} }
func (r *settingsRows) Close() error      { return nil }
func (r *settingsRows) Next(dest []driver.Value) error {
	if r.empty || r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

type settingsDriver struct{}

func (settingsDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }
