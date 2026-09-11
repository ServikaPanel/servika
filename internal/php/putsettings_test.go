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

	"github.com/go-chi/chi/v5"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// A PHP settings save read the domain a second time with a SELECT whose column
// list was left empty when the read-only column was dropped. MariaDB refuses that
// statement with ERROR 1064, so every save answered 404 "domain not found" for a
// domain the scope lookup had just resolved. The fake refuses every query it was
// not told about, which is what that statement meets on a real server.
func TestAResolvedDomainReachesTheSettingsValidation(t *testing.T) {
	db := sql.OpenDB(domainOnlyConn{})
	t.Cleanup(func() { _ = db.Close() })

	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	body := strings.NewReader(`{"settings":{"memory_limit":"lots","post_max_size":"lots","upload_max_filesize":"lots"}}`)
	r := httptest.NewRequest(http.MethodPut, "/domains/7/php-settings", body)
	ctx := auth.WithClaims(r.Context(), &auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin})
	ctx = context.WithValue(ctx, chi.RouteCtxKey, route)

	w := httptest.NewRecorder()
	(&Handlers{DB: db}).PutSettings(w, r.WithContext(ctx))

	// The size values are refused by validation, which runs after the domain is
	// resolved and before anything is written, so the answer proves the save got
	// past the domain read without touching the host.
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), reasonInvalidSize) {
		t.Fatalf("the save answered %d: %s", w.Code, w.Body.String())
	}
}

// domainOnlyConn answers the scope lookup for domain 7 and refuses every other
// statement.
type domainOnlyConn struct{}

const scopeQuery = "SELECT domain_name, system_user, php_version FROM domains WHERE id=?"

func (c domainOnlyConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c domainOnlyConn) Driver() driver.Driver                        { return settingsDriver{} }
func (c domainOnlyConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c domainOnlyConn) Close() error                                 { return nil }
func (c domainOnlyConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c domainOnlyConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if query != scopeQuery {
		return nil, errors.New("unexpected query: " + query)
	}
	return &domainRow{}, nil
}

type domainRow struct{ done bool }

func (r *domainRow) Columns() []string { return []string{"domain_name", "system_user", "php_version"} }
func (r *domainRow) Close() error      { return nil }
func (r *domainRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0], dest[1], dest[2] = "example.com", "c_example", "8.3"
	return nil
}
