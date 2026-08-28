package transfers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"servika/internal/secret"
)

// sealForHost is the single point where a stored credential is encrypted. Two
// properties must hold: an empty value stays NULL (so credentials_stored reads
// false), and a sealed value round-trips ONLY under the same host, because the
// host is the AES-GCM AAD. A blob copied to another host must not decrypt.
func TestSealForHostIsHostBound(t *testing.T) {
	if err := secret.Init([]byte("test-key-that-is-long-enough-32b!")); err != nil {
		t.Fatalf("secret init: %v", err)
	}

	empty, err := sealForHost("", "src.example.com")
	if err != nil {
		t.Fatalf("seal empty: %v", err)
	}
	if empty.Valid {
		t.Fatalf("an empty secret must stay NULL, got %q", empty.String)
	}

	sealed, err := sealForHost("s3cret-pw", "src.example.com")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !sealed.Valid || sealed.String == "" {
		t.Fatalf("a non-empty secret must be stored")
	}
	if strings.Contains(sealed.String, "s3cret-pw") {
		t.Fatalf("the plaintext survived in the sealed value: %q", sealed.String)
	}

	back, err := secret.DecryptWith(sealed.String, "src.example.com")
	if err != nil || back != "s3cret-pw" {
		t.Fatalf("same-host decrypt failed: %q err=%v", back, err)
	}
	if _, err := secret.DecryptWith(sealed.String, "other.example.com"); err == nil {
		t.Fatalf("a blob decrypted under a DIFFERENT host; the AAD is not bound")
	}
}

// ---------------------------------------------------------------------------
// A recording driver, in the repository's own style (no sqlmock dependency).
// The QUERY TEXT decides the outcome, so a test catches a dropped WHERE clause.
// ---------------------------------------------------------------------------

type sessRecorder struct {
	mu      sync.Mutex
	queries []string
	// The sealed blobs a real row would hold. They are returned ONLY for the
	// credential-load query, never for the list or get, so a leak is visible.
	sealedPass string
}

func (r *sessRecorder) saw(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.queries {
		if strings.Contains(q, fragment) {
			return true
		}
	}
	return false
}

var (
	sessStateMu sync.Mutex
	sessState   = map[string]*sessRecorder{}
	sessOnce    sync.Once
)

type sessDriver struct{}

func (sessDriver) Open(name string) (driver.Conn, error) {
	sessStateMu.Lock()
	defer sessStateMu.Unlock()
	rec, ok := sessState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &sessConn{rec: rec}, nil
}

type sessConn struct{ rec *sessRecorder }

func (c *sessConn) Prepare(query string) (driver.Stmt, error) {
	c.rec.mu.Lock()
	c.rec.queries = append(c.rec.queries, query)
	c.rec.mu.Unlock()
	return &sessStmt{rec: c.rec, query: query}, nil
}
func (c *sessConn) Close() error              { return nil }
func (c *sessConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type sessStmt struct {
	rec   *sessRecorder
	query string
}

func (s *sessStmt) Close() error  { return nil }
func (s *sessStmt) NumInput() int { return -1 }
func (s *sessStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *sessStmt) Query(args []driver.Value) (driver.Rows, error) {
	switch {
	case strings.Contains(s.query, "FROM migration_sessions") &&
		strings.Contains(s.query, "ORDER BY last_used"):
		// SessionList: id, type, host, port, user, credentials_stored, last_used.
		return &sessRows{
			columns: []string{"id", "source_type", "source_host", "source_port", "source_user", "cs", "last_used"},
			values: [][]driver.Value{
				{int64(7), "cpanel", "src.example.com", int64(22), "root", int64(1), "2026-08-28 10:00:00"},
			},
		}, nil
	case strings.Contains(s.query, "FROM migration_sessions") &&
		strings.Contains(s.query, "discovery_json"):
		// SessionGet: type, host, port, user, discovery_json, hasPass, hasKey.
		return &sessRows{
			columns: []string{"source_type", "source_host", "source_port", "source_user", "discovery_json", "hp", "hk"},
			values: [][]driver.Value{
				{"cpanel", "src.example.com", int64(22), "root", `[{"domain_name":"a.com"}]`, int64(1), int64(0)},
			},
		}, nil
	case strings.Contains(s.query, "source_password, source_key FROM migration_sessions"):
		// loadSessionCredentials: the sealed blobs.
		return &sessRows{
			columns: []string{"source_password", "source_key"},
			values:  [][]driver.Value{{s.rec.sealedPass, nil}},
		}, nil
	}
	return &sessRows{columns: []string{"x"}}, nil
}

type sessRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *sessRows) Columns() []string { return r.columns }
func (r *sessRows) Close() error      { return nil }
func (r *sessRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func sessDB(t *testing.T, rec *sessRecorder) *sql.DB {
	t.Helper()
	sessOnce.Do(func() { sql.Register("transfers-sess", sessDriver{}) })
	name := t.Name()
	sessStateMu.Lock()
	sessState[name] = rec
	sessStateMu.Unlock()
	t.Cleanup(func() {
		sessStateMu.Lock()
		delete(sessState, name)
		sessStateMu.Unlock()
	})
	db, err := sql.Open("transfers-sess", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// SessionList must filter by expires_at and must never return a secret: the
// only credential fact in the response is credentials_stored.
func TestSessionListHidesSecretsAndFiltersExpired(t *testing.T) {
	rec := &sessRecorder{sealedPass: "ENC:should-never-appear"}
	h := &Handlers{DB: sessDB(t, rec)}

	w := httptest.NewRecorder()
	h.SessionList(w, httptest.NewRequest(http.MethodGet, "/admin/migrations/sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "ENC:should-never-appear") || strings.Contains(body, "source_password") {
		t.Fatalf("the list leaked a secret: %s", body)
	}
	if !strings.Contains(body, `"credentials_stored":true`) {
		t.Fatalf("credentials_stored was not reported: %s", body)
	}
	if !rec.saw("expires_at > NOW()") {
		t.Fatalf("the list query did not filter expired sessions")
	}
}

// SessionGet restores the form and the discovery result, again with no secret.
func TestSessionGetHidesSecrets(t *testing.T) {
	rec := &sessRecorder{sealedPass: "ENC:should-never-appear"}
	h := &Handlers{DB: sessDB(t, rec)}

	r := httptest.NewRequest(http.MethodGet, "/admin/migrations/sessions/7", nil)
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", "7")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

	w := httptest.NewRecorder()
	h.SessionGet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["credentials_stored"] != true {
		t.Fatalf("credentials_stored not true: %v", got)
	}
	if strings.Contains(w.Body.String(), "ENC:should-never-appear") {
		t.Fatalf("SessionGet leaked a secret: %s", w.Body.String())
	}
	if !rec.saw("expires_at > NOW()") {
		t.Fatalf("SessionGet did not filter expired sessions")
	}
}

// saveSession keeps ONE fresh session per source: it deletes the earlier row
// for the same host+user before inserting.
func TestSaveSessionKeepsOnePerSource(t *testing.T) {
	if err := secret.Init([]byte("test-key-that-is-long-enough-32b!")); err != nil {
		t.Fatalf("secret init: %v", err)
	}
	rec := &sessRecorder{}
	h := &Handlers{DB: sessDB(t, rec)}
	src := &RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, User: "root", Password: "pw"}
	_ = h.saveSession(src, []byte(`[]`), "admin")
	if !rec.saw("DELETE FROM migration_sessions WHERE source_host=? AND source_user=?") {
		t.Fatalf("saveSession did not drop the earlier session for the same source")
	}
}
