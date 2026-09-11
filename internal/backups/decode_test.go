package backups

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bodyRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
}

// An empty body is the deliberately tolerated case: both endpoints document a
// default for it.
func TestAnEmptyBodyIsTolerated(t *testing.T) {
	var target struct {
		Mode string `json:"mode"`
	}
	if err := decodeOptionalBody(bodyRequest(""), &target); err != nil {
		t.Errorf("an empty body was refused: %v", err)
	}
	if target.Mode != "" {
		t.Errorf("an empty body set a field: %q", target.Mode)
	}
}

// A malformed body must not fall through to the defaults, because on both of
// these endpoints the default is the WIDEST operation available: a full restore
// over the live site and every schema, and a backup of every domain on the
// server.
func TestAMalformedBodyIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"mode": "files"`,       // truncated
		`{"mode": 7}`,            // wrong type
		`{"domain_ids": "all"}`,  // wrong type
		`not json at all`,        //
		`{"mode":"files"} extra`, // trailing junk in the first value's stream
	} {
		var target struct {
			Mode      string  `json:"mode"`
			DomainIDs []int64 `json:"domain_ids"`
		}
		err := decodeOptionalBody(bodyRequest(body), &target)
		if body == `{"mode":"files"} extra` {
			// Decode reads ONE value and stops, so trailing junk is not an
			// error. Recorded rather than asserted, so the boundary is written
			// down instead of discovered.
			continue
		}
		if err == nil {
			t.Errorf("a malformed body was accepted: %s", body)
		}
	}
}

// A well-formed body still decodes.
func TestAWellFormedBodyDecodes(t *testing.T) {
	var target struct {
		Mode      string  `json:"mode"`
		DomainIDs []int64 `json:"domain_ids"`
	}
	if err := decodeOptionalBody(bodyRequest(`{"mode":"files","domain_ids":[3,4]}`), &target); err != nil {
		t.Fatalf("a valid body was refused: %v", err)
	}
	if target.Mode != "files" || len(target.DomainIDs) != 2 {
		t.Errorf("the body did not decode: %+v", target)
	}
}

// And the two handlers actually use it, before the defaults are applied.
func TestBothWideningHandlersRefuseAMalformedBody(t *testing.T) {
	for _, c := range []struct{ file, handler, widening string }{
		{"restore.go", "func (h *Handlers) Restore(", `req.Mode = "full"`},
		{"jobs.go", "func (h *Handlers) StartBackupJob(", "h.scopedDomains(r, req.DomainIDs)"},
	} {
		body := backupsFunction(t, readBackupsSource(t, c.file), c.handler)
		decode := strings.Index(body, "decodeOptionalBody(r, &req)")
		widen := strings.Index(body, c.widening)
		if decode < 0 {
			t.Errorf("%s does not check its request body", c.handler)
			continue
		}
		if strings.Contains(body, "_ = json.NewDecoder(r.Body).Decode(&req)") {
			t.Errorf("%s still discards the decode error", c.handler)
		}
		if widen >= 0 && decode > widen {
			t.Errorf("%s applies its widening default before checking the body", c.handler)
		}
	}
}
