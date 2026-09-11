package mail

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"servika/internal/middleware"
)

const deliveryRead = "FROM mail_delivery_log WHERE domain_id = ?"

func deliveryScript() *sqlScript {
	s := handlerScript()
	s.rows[deliveryRead] = [][]driver.Value{{"2026-08-06 07:12:33", "out", "a@example.com", "b@example.net", "sent", "250 OK"}}
	return s
}

func readDeliveryLog(t *testing.T, s *sqlScript, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodGet, "/domains/1/mail/delivery-log?"+query, "", middleware.RoleUser,
		map[string]string{"id": "1"})
	(&Handlers{DB: scriptDB(t, s)}).DeliveryLog(recorder, request)
	return recorder
}

// Every refusal the delivery log gives, with the status and the text a caller
// sees.
func TestDeliveryLogRefusals(t *testing.T) {
	const unreadable = "could not read the delivery log"
	const limit = "limit must be between 1 and 200"
	cases := []struct {
		name, query string
		setup       func(*sqlScript)
		status      int
		text        string
	}{
		{"an unknown domain", "", func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"an unknown status", "status=softbounce", noSetup, http.StatusBadRequest, "unknown status filter"},
		{"an unknown direction", "direction=sideways", noSetup, http.StatusBadRequest, "direction must be in or out"},
		{"a search longer than an address", "search=" + strings.Repeat("a", maxAddressLen+1), noSetup, http.StatusBadRequest, "search term is too long"},
		{"a limit that is not a number", "limit=many", noSetup, http.StatusBadRequest, limit},
		{"a zero limit", "limit=0", noSetup, http.StatusBadRequest, limit},
		{"a limit past one page", "limit=201", noSetup, http.StatusBadRequest, limit},
		{"a read that fails", "", func(s *sqlScript) { s.fail[deliveryRead] = errScripted }, http.StatusInternalServerError, unreadable},
		{"a row that does not scan", "", func(s *sqlScript) { s.rows[deliveryRead] = [][]driver.Value{{"one column"}} }, http.StatusInternalServerError, unreadable},
		{"a read that ends early", "", func(s *sqlScript) { s.endWith[deliveryRead] = errScripted }, http.StatusInternalServerError, unreadable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := deliveryScript()
			c.setup(script)
			assertAnswer(t, readDeliveryLog(t, script, c.query), c.status, c.text)
		})
	}
}

// Each filter narrows the domain-scoped query with a bound value, and a LIKE
// wildcard in the search is matched literally.
func TestDeliveryLogNarrowsTheScopedQuery(t *testing.T) {
	script := deliveryScript()
	recorder := readDeliveryLog(t, script, "status=rejected&direction=in&search=a%25_b&limit=5")
	assertAnswer(t, recorder, http.StatusOK, `"recipient":"b@example.net"`)

	read := script.onlyRead(t, deliveryRead)
	for _, clause := range []string{" AND status = ?", " AND direction = ?",
		` AND (sender LIKE ? ESCAPE '\\' OR recipient LIKE ? ESCAPE '\\')`, ` ORDER BY ts DESC, id DESC LIMIT ?`} {
		if !strings.Contains(read.query, clause) {
			t.Errorf("the query lacks %q:\n%s", clause, read.query)
		}
	}
	want := []driver.Value{int64(1), "rejected", "in", `%a\%\_b%`, `%a\%\_b%`, int64(5)}
	if !slices.Equal(read.args, want) {
		t.Fatalf("bound values = %#v, want %#v", read.args, want)
	}
	var entries []DeliveryEntry
	if err := json.Unmarshal(recorder.Body.Bytes(), &entries); err != nil || len(entries) != 1 || entries[0].Reason != "250 OK" {
		t.Fatalf("entries = %+v (%v)", entries, err)
	}
}

// Without a limit the answer is one page.
func TestDeliveryLogDefaultsToOnePage(t *testing.T) {
	script := deliveryScript()
	assertAnswer(t, readDeliveryLog(t, script, ""), http.StatusOK, `"status":"sent"`)
	read := script.onlyRead(t, deliveryRead)
	if want := []driver.Value{int64(1), int64(deliveryPageSize)}; !slices.Equal(read.args, want) {
		t.Fatalf("bound values = %#v, want %#v", read.args, want)
	}
}
