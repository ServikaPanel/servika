package wordpress

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// runDelete drives the delete endpoint against a scripted database.
func runDelete(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &Handlers{DB: scriptDB(t, s)}
	recorder := httptest.NewRecorder()
	h.Delete(recorder, wpRequest(http.MethodDelete, "/domains/1/wordpress", body))
	return recorder
}

func TestDeleteRefusesARequestItCannotAct(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	recordHost(t)

	refusals := []struct {
		name     string
		user     string
		body     string
		status   int
		fragment string
	}{
		{"an unknown domain", "", `{"dir":"/blog"}`, http.StatusNotFound, "domain not found"},
		{"a domain with no tenant user", "root", `{"dir":"/blog"}`, http.StatusBadRequest, "invalid user"},
		{"a body that is not JSON", "c_test", "{", http.StatusBadRequest, "invalid request body"},
		{"a directory with no WordPress in it", "c_test", `{"dir":"/other"}`, http.StatusBadRequest, "invalid request"},
		{"a directory outside the document root", "c_test", `{"dir":"../../etc"}`, http.StatusBadRequest, "invalid request"},
		{"a directory name carrying a line break", "c_test", `{"dir":"/blog\ninjected"}`, http.StatusBadRequest, "invalid request"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := newScript()
			if tc.user != "" {
				s = domainScript(tc.user)
			} else {
				s.rows[domainLookup] = [][]driver.Value{}
			}
			assertStatus(t, runDelete(t, s, tc.body), tc.status, tc.fragment)
		})
	}
}

// Deleting the document root would delete the whole site, so the panel refuses
// it rather than doing what was asked.
func TestDeleteRefusesTheDocumentRoot(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, root, "<?php")
	host := recordHost(t)

	assertStatus(t, runDelete(t, domainScript("c_test"), `{"dir":"/ (root)"}`),
		http.StatusBadRequest, "cannot be removed from the panel")
	if len(host.removed) != 0 {
		t.Fatalf("the document root was removed: %v", host.removed)
	}
}

func TestDeleteRemovesTheDirectoryAndItsOwnDatabase(t *testing.T) {
	root := tenantRoot(t)
	target := filepath.Join(root, "blog")
	wpConfig(t, target, `<?php define('DB_NAME', 'wp_deadbeef');`)
	host := recordHost(t)
	s := domainScript("c_test")
	s.rows[dbOwnerLookup] = [][]driver.Value{{int64(1)}}

	assertStatus(t, runDelete(t, s, `{"dir":"/blog","delete_db":true}`), http.StatusOK, `"ok":true`)
	if len(host.dropped) != 1 || host.dropped[0] != "wp_deadbeef/wpu_deadbeef" {
		t.Errorf("dropped = %v, want the paired account of the managed database", host.dropped)
	}
	if len(host.removed) != 1 || host.removed[0] != target {
		t.Errorf("removed = %v, want %q", host.removed, target)
	}
}

// A delete_db request names the database indirectly, through the wp-config.php
// in the directory. A name that is not this domain's must not be dropped.
func TestDeleteDropsNoDatabaseItCannotProve(t *testing.T) {
	root := tenantRoot(t)
	cases := []struct {
		name    string
		config  string
		ownedBy int64
	}{
		{"a database of another domain", `<?php define('DB_NAME', 'wp_deadbeef');`, 0},
		{"a database without the managed prefix", `<?php define('DB_NAME', 'other_db');`, 1},
		{"a name that is not an identifier", "<?php define('DB_NAME', 'wp_x`;DROP');", 1},
		{"a wp-config.php with no database name", "<?php", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(root, "blog")
			wpConfig(t, target, tc.config)
			host := recordHost(t)
			s := domainScript("c_test")
			s.rows[dbOwnerLookup] = [][]driver.Value{{tc.ownedBy}}

			assertStatus(t, runDelete(t, s, `{"dir":"/blog","delete_db":true}`), http.StatusOK, `"ok":true`)
			if len(host.dropped) != 0 {
				t.Errorf("dropped = %v, want nothing", host.dropped)
			}
			if len(host.removed) != 1 {
				t.Errorf("removed = %v, want the directory itself", host.removed)
			}
		})
	}
}

// Without delete_db the database is left alone, even though wp-config.php names
// one this domain owns.
func TestDeleteKeepsTheDatabaseWhenItWasNotAsked(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), `<?php define('DB_NAME', 'wp_deadbeef');`)
	host := recordHost(t)
	s := domainScript("c_test")
	s.rows[dbOwnerLookup] = [][]driver.Value{{int64(1)}}

	assertStatus(t, runDelete(t, s, `{"dir":"/blog"}`), http.StatusOK, `"ok":true`)
	if len(host.dropped) != 0 {
		t.Fatalf("dropped = %v, want nothing", host.dropped)
	}
}

func TestDeleteReportsADirectoryItCouldNotRemove(t *testing.T) {
	root := tenantRoot(t)
	wpConfig(t, filepath.Join(root, "blog"), "<?php")
	host := recordHost(t)
	host.removeErr = errors.New("permission denied")

	assertStatus(t, runDelete(t, domainScript("c_test"), `{"dir":"/blog"}`),
		http.StatusInternalServerError, "could not delete record")
}
