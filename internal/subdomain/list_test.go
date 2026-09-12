package subdomain

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
)

// domainRequest builds a request carrying the {id} route parameter every
// handler in this package reads.
func domainRequest(t *testing.T, method string, domainID int64) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "/domains/"+strconv.FormatInt(domainID, 10)+"/subdomain", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", strconv.FormatInt(domainID, 10))
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))
}

// parentDomain scripts the lookup every handler opens with.
func parentDomain(script *sqlScript, systemUser, domainName, phpVersion string) {
	script.rows["FROM domains WHERE id=?"] = [][]driver.Value{
		{systemUser, domainName, phpVersion},
	}
}

// The list is the screen. A row the scan drops is a subdomain the tenant
// created, is being served, and cannot see or manage, so the columns the query
// asks for and the fields the scan fills must stay in step.
func TestEverySubdomainRowReachesTheList(t *testing.T) {
	script := newScript()
	parentDomain(script, "c_acme", "acme.test", "8.3")
	script.rows["FROM subdomains WHERE domain_id=?"] = [][]driver.Value{
		{int64(7), "shop", "shop.acme.test", "8.2", "2026-01-02 03:04"},
		{int64(9), "blog", "blog.acme.test", "8.3", "2026-01-03 05:06"},
	}
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.List(recorder, domainRequest(t, http.MethodGet, 4))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var out []Sub
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("the list carries %d of the 2 rows: %s", len(out), recorder.Body)
	}
	if out[0].Subdomain != "shop" || out[0].FQDN != "shop.acme.test" {
		t.Errorf("first row = %+v", out[0])
	}
	if out[0].PHPVersion != "8.2" {
		t.Errorf("php_version = %q, want the version the row carries", out[0].PHPVersion)
	}
	if out[0].CreatedAt != "2026-01-02 03:04" {
		t.Errorf("created_at = %q, want the formatted timestamp", out[0].CreatedAt)
	}
	if out[0].DocRoot != "/home/c_acme/subdomains/shop.acme.test" {
		t.Errorf("docroot = %q", out[0].DocRoot)
	}
}

// A domain nobody owns is a 404, and nothing is listed for it.
func TestListingAnUnknownDomainIsRefused(t *testing.T) {
	script := newScript()
	script.rows["FROM domains WHERE id=?"] = nil
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.List(recorder, domainRequest(t, http.MethodGet, 4))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}
