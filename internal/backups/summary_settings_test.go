package backups

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"servika/internal/auth"
	"servika/internal/middleware"
)

const summaryQuery = "COALESCE(d.backup_freq,'none'), COALESCE(d.backup_hour,3), COALESCE(d.backup_retention,7)"

func summaryRequest(claims *auth.Claims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/backups/summary", nil)
	return r.WithContext(auth.WithClaims(r.Context(), claims))
}

// The summary counts every archive on disk per domain and reports the schedule
// the domains really carry.
func TestSummaryReportsWhatIsOnDisk(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_BACKUP_ROOT", root)
	newest := time.Date(2026, 1, 2, 3, 4, 0, 0, time.Local)
	for name, spec := range map[string]struct {
		body string
		at   time.Time
	}{
		"a.tar.gz":  {"0123456789", newest},
		"b.tar.gz":  {"01234", newest.Add(-24 * time.Hour)},
		"notes.txt": {"ignored", newest.Add(time.Hour)},
	} {
		path := filepath.Join(root, "c_example", name)
		writeFixtureFile(t, path, spec.body)
		if err := os.Chtimes(path, spec.at, spec.at); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "c_example", "dir.tar.gz"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := &sqlScript{rows: map[string][][]driver.Value{
		summaryQuery: {
			{int64(5), "example.com", "c_example", "daily", int64(3), int64(7)},
			{int64(6), "empty.com", "c_empty", "none", int64(21), int64(90)},
			{"not a number", "x.com", "c_x", "daily", int64(3), int64(7)},
		},
		"SELECT COUNT(*) FROM backup_destinations WHERE enabled=1": {{int64(2)}},
	}}
	admin := &auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin}

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).Summary(w, summaryRequest(admin))

	want := map[string]any{
		"domains": []any{
			map[string]any{"domain_id": float64(5), "domain_name": "example.com", "count": float64(2), "total_bytes": float64(15), "last_backup": "2026-01-02 03:04"},
			map[string]any{"domain_id": float64(6), "domain_name": "empty.com", "count": float64(0), "total_bytes": float64(0), "last_backup": ""},
		},
		"total_size_bytes": float64(15), "total_backups": float64(2), "destination_count": float64(2),
		"automatic_domains": float64(1), "schedule_hour": float64(3), "retention_min": float64(7), "retention_max": float64(7),
	}
	if got := responseBody(t, w); w.Code != http.StatusOK || !reflect.DeepEqual(got, want) {
		t.Fatalf("answered %d %v, want %v", w.Code, got, want)
	}
}

func TestSummaryNarrowsAResellerAndReportsAFailedList(t *testing.T) {
	reseller := &auth.Claims{UserID: 7, Username: "agency", Role: middleware.RoleReseller}
	script := &sqlScript{fail: map[string]error{summaryQuery: errors.New("lost")}}

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).Summary(w, summaryRequest(reseller))

	assertRefusal(t, w, http.StatusInternalServerError, "could not list backups")
	want := " WHERE EXISTS (SELECT 1 FROM customers sc WHERE sc.id = d.customer_id AND sc.owner_user_id = ?) ORDER BY d.domain_name"
	if script.queriesContaining(want) != 1 {
		t.Errorf("the summary was not narrowed to the reseller: %v", script.queries)
	}
}

func TestSetScheduleRefusesAnInvalidSchedule(t *testing.T) {
	cases := []struct {
		name    string
		script  *sqlScript
		body    string
		status  int
		message string
	}{
		{"an unknown domain", &sqlScript{rows: map[string][][]driver.Value{lookupQuery: {}}}, `{}`, http.StatusNotFound, "domain not found"},
		{"a failed lookup", &sqlScript{fail: map[string]error{lookupQuery: errors.New("lost")}}, `{}`, http.StatusInternalServerError, "internal server error"},
		{"a malformed body", &sqlScript{rows: existingDomain()}, `{`, http.StatusBadRequest, "invalid request body"},
		{"an unknown frequency", &sqlScript{rows: existingDomain()}, `{"frequency":"hourly"}`, http.StatusBadRequest, "frequency must be none, daily, or weekly"},
		{"an hour past the day", &sqlScript{rows: existingDomain()}, `{"frequency":"daily","hour":24}`, http.StatusBadRequest, "hour: 0-23"},
		{"a negative hour", &sqlScript{rows: existingDomain()}, `{"frequency":"daily","hour":-1}`, http.StatusBadRequest, "hour: 0-23"},
		{"the update fails", &sqlScript{rows: existingDomain(), fail: map[string]error{"UPDATE domains SET backup_freq=?": errors.New("read-only")}},
			`{"frequency":"daily","hour":1}`, http.StatusInternalServerError, "could not update backup schedule"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, c.script)}).SetSchedule(w, domainRequest(http.MethodPut, "/domains/5/backups/schedule", c.body, "id", "5"))
			assertRefusal(t, w, c.status, c.message)
		})
	}
}

func TestSetScheduleRaisesARetentionBelowOne(t *testing.T) {
	script := &sqlScript{rows: existingDomain()}
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).SetSchedule(w, domainRequest(http.MethodPut, "/domains/5/backups/schedule", `{"frequency":"none","hour":0,"retention":-3}`, "id", "5"))

	updates := script.execsContaining("UPDATE domains SET backup_freq=?")
	if w.Code != http.StatusOK || len(updates) != 1 || !slices.Equal(updates[0].args, []driver.Value{"none", int64(0), int64(1), int64(5)}) {
		t.Fatalf("answered %d, update %+v", w.Code, updates)
	}
}

func TestValidateBackupSettingsNamesEachRemoteField(t *testing.T) {
	remote := func(mutate func(s *BackupSettings)) *BackupSettings {
		s := &BackupSettings{RemoteEnabled: true, RemoteType: "ftp", RemoteHost: "backup.example.com", RemotePort: 21, RemoteUsername: "u", RemoteDir: "/"}
		mutate(s)
		return s
	}
	cases := []struct {
		settings *BackupSettings
		want     string
	}{
		{&BackupSettings{MinFreeGB: 10001}, "min_free_gb must be between 0 and 10000"},
		{&BackupSettings{MaxStoreGB: -1}, "max_store_gb must be between 0 and 1000000"},
		{remote(func(s *BackupSettings) { s.RemotePort = 65536 }), "remote_port must be between 1 and 65535"},
		{remote(func(s *BackupSettings) { s.RemoteUsername = " " }), "remote_username cannot be empty"},
		{remote(func(s *BackupSettings) { s.RemotePassword = "a\x00b" }), "the fields cannot contain a line break or control character"},
		{remote(func(s *BackupSettings) { s.RemoteDir = "/a\rb" }), "the fields cannot contain a line break or control character"},
		{remote(func(*BackupSettings) {}), ""},
	}
	for _, c := range cases {
		if got := validateBackupSettings(c.settings); got != c.want {
			t.Errorf("validateBackupSettings(%+v) = %q, want %q", c.settings, got, c.want)
		}
	}
}

func TestS3EndpointNormalisesAndRefuses(t *testing.T) {
	cases := []struct {
		destination Destination
		want        string
		wantErr     string
	}{
		{destination: Destination{Type: "s3"}, want: "https://s3.amazonaws.com"},
		{destination: Destination{Type: "s3", Region: "us-east-1"}, want: "https://s3.amazonaws.com"},
		{destination: Destination{Type: "s3", Region: "eu-west-1"}, want: "https://s3.eu-west-1.amazonaws.com"},
		{destination: Destination{Type: "b2"}, wantErr: "a Backblaze S3 endpoint is required"},
		{destination: Destination{Type: "s3", Endpoint: "  https://s3.example.com/  "}, want: "https://s3.example.com"},
		{destination: Destination{Type: "s3", Endpoint: "https://s3.example.com/base/"}, want: "https://s3.example.com/base"},
		{destination: Destination{Type: "s3", Endpoint: "https://s3.example.com#frag"}, wantErr: "the endpoint cannot contain a query or fragment"},
		{destination: Destination{Type: "s3", Endpoint: "https:///path"}, wantErr: "the endpoint must be a valid HTTPS address"},
		{destination: Destination{Type: "s3", Endpoint: "https://%zz"}, wantErr: "the endpoint must be a valid HTTPS address"},
	}
	for _, c := range cases {
		u, err := s3Endpoint(&c.destination)
		switch {
		case c.wantErr != "":
			if err == nil || err.Error() != c.wantErr {
				t.Errorf("%+v: s3Endpoint = (%v, %v), want %q", c.destination, u, err, c.wantErr)
			}
		case err != nil || u.String() != c.want:
			t.Errorf("%+v: s3Endpoint = (%v, %v), want %q", c.destination, u, err, c.want)
		}
	}
}
