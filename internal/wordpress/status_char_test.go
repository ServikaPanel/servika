package wordpress

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// runStatus drives the status endpoint.
func runStatus(t *testing.T, s *sqlScript, query string) *httptest.ResponseRecorder {
	t.Helper()
	h := &Handlers{DB: scriptDB(t, s)}
	recorder := httptest.NewRecorder()
	h.Status(recorder, wpRequest(http.MethodGet, "/domains/1/wordpress/status"+query, ""))
	return recorder
}

func TestStatusRefusesARequestItCannotAct(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	recordWP(t, nil)

	t.Run("an unknown domain", func(t *testing.T) {
		s := newScript()
		s.rows[domainLookup] = [][]driver.Value{}
		assertStatus(t, runStatus(t, s, "?dir=/blog"), http.StatusNotFound, "domain not found")
	})
	t.Run("a directory with no WordPress in it", func(t *testing.T) {
		assertStatus(t, runStatus(t, domainScript("c_test"), "?dir=/other"),
			http.StatusBadRequest, "invalid request")
	})
}

func TestStatusReportsEveryValueItCollected(t *testing.T) {
	root := tenantRoot(t)
	target := filepath.Join(root, "blog")
	wpConfig(t, target, "<?php")
	if err := os.MkdirAll(filepath.Join(target, "wp-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "wp-content", ".servika-maintenance"), []byte("back soon"), 0o600); err != nil {
		t.Fatal(err)
	}
	recordWP(t, map[string]wpAnswer{
		"core version":           {out: "7.0\n"},
		"core check-update":      {out: `[{"version":"7.1"}]`},
		"eval echo PHP_VERSION;": {out: "8.3.6\n"},
		"db size":                {out: "12.5\n"},
	})

	recorder := runStatus(t, domainScript("c_test"), "?dir=/blog")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	want := map[string]any{"version": "7.0", "update_available": true, "target_version": "7.1",
		"php": "8.3.6", "db_mb": "12.5", "maintenance": true}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}
}

// A wp-cli call that fails leaves its own value at the default rather than
// failing the whole report.
func TestStatusReportsDefaultsForTheCallsThatFailed(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	recordWP(t, map[string]wpAnswer{
		"core version":           {out: "7.1\n"},
		"core check-update":      {out: "Error: could not reach wordpress.org", err: errors.New("exit 1")},
		"eval echo PHP_VERSION;": {err: errors.New("exit 1")},
		"db size":                {err: errors.New("exit 1")},
	})

	recorder := runStatus(t, domainScript("c_test"), "?dir=/blog")
	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	want := map[string]any{"version": "7.1", "update_available": false, "target_version": "",
		"php": "", "db_mb": "", "maintenance": false}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}
}

// An empty update list is a current site, not an unknown one.
func TestStatusReadsAnEmptyUpdateListAsCurrent(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	recordWP(t, map[string]wpAnswer{"core check-update": {out: "[]"}})

	recorder := runStatus(t, domainScript("c_test"), "?dir=/blog")
	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if got["update_available"] != false || got["target_version"] != "" {
		t.Fatalf("response = %v, want no update", got)
	}
}

// With no dir parameter the status is read from the document root.
func TestStatusDefaultsToTheDocumentRoot(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, root, "<?php")
	rec := recordWP(t, nil)

	if code := runStatus(t, domainScript("c_test"), "").Code; code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	assertArgvHolds(t, rec.argvFor("core version"), "core", "version", "--path="+root)
}
