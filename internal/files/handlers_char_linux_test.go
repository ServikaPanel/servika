//go:build linux

package files

// Characterization of the four file-manager handlers that walk a tenant tree:
// Upload, Extract, Archive and Search. They are Linux-only because every path
// they take goes through the openat2 helpers, which exist only there.

import (
	"bytes"
	"context"
	"database/sql/driver"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"servika/internal/archivex"

	"github.com/go-chi/chi/v5"
)

const systemUserQuery = "SELECT system_user FROM domains WHERE id=?"

// tenantHome points the package at a temporary home root and returns the
// tenant's own home inside it.
func tenantHome(t *testing.T) string {
	t.Helper()
	// The path is resolved first: the safeio helpers compare against the
	// resolved form, and a temporary directory sits under a symlinked /var on
	// some hosts.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "c_test")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &homeRoot, root)
	return home
}

// homeScript answers the one lookup every file handler makes.
func homeScript() *sqlScript {
	s := newScript()
	s.rows[systemUserQuery] = [][]driver.Value{{"c_test"}}
	return s
}

// filesRequest builds a request whose chi route carries domain 7.
func filesRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}

func assertResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if recorder.Code != status {
		t.Errorf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), fragment) {
		t.Errorf("body = %s, want it to hold %q", recorder.Body.String(), fragment)
	}
}

// recordedCommand is one external tool a handler ran.
type recordedCommand struct {
	name       string
	args       []string
	systemUser string
}

// commandLog stands in for the two command seams and records what each handler
// would have run on the host.
type commandLog struct {
	mu     sync.Mutex
	calls  []recordedCommand
	fail   map[string]bool
	output func(name string, args []string) string
}

func (c *commandLog) record(name, systemUser string, args []string) *exec.Cmd {
	c.mu.Lock()
	c.calls = append(c.calls, recordedCommand{name: name, args: args, systemUser: systemUser})
	failing := c.fail[name]
	c.mu.Unlock()
	if failing {
		return exec.Command("false")
	}
	if c.output != nil {
		if out := c.output(name, args); out != "" {
			return exec.Command("printf", "%s", out)
		}
	}
	return exec.Command("true")
}

func (c *commandLog) file(_ context.Context, name string, args ...string) *exec.Cmd {
	return c.record(name, "", args)
}

func (c *commandLog) tenant(_ context.Context, systemUser, name string, args ...string) *exec.Cmd {
	return c.record(name, systemUser, args)
}

// install replaces both command seams for one test.
func (c *commandLog) install(t *testing.T) *commandLog {
	t.Helper()
	if c.fail == nil {
		c.fail = map[string]bool{}
	}
	setForTest(t, &fileCommand, c.file)
	setForTest(t, &tenantCommand, c.tenant)
	return c
}

// ran returns the arguments of the first recorded call to name.
func (c *commandLog) ran(name string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, call := range c.calls {
		if call.name == name {
			return call.args, true
		}
	}
	return nil, false
}

// ----- Upload -----

// multipartBody builds an upload with one file field.
func multipartBody(t *testing.T, field, name, content string) (body, contentType string) {
	t.Helper()
	var buffer bytes.Buffer
	form := multipart.NewWriter(&buffer)
	part, err := form.CreateFormFile(field, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.String(), form.FormDataContentType()
}

func TestUploadRefusesBeforeItWrites(t *testing.T) {
	upload, uploadType := multipartBody(t, "file", "index.html", "<h1>hello</h1>")
	wrongField, wrongFieldType := multipartBody(t, "archive", "index.html", "x")
	cases := []struct {
		name        string
		body        string
		contentType string
		path        string
		script      func(s *sqlScript)
		noSpace     bool
		noQuota     bool
		status      int
		want        string
	}{
		{name: "a domain that is not there", body: upload, contentType: uploadType,
			script: func(s *sqlScript) { s.rows[systemUserQuery] = nil },
			status: http.StatusNotFound, want: "not found"},
		{name: "a host with no room left", body: upload, contentType: uploadType, noSpace: true,
			status: http.StatusInsufficientStorage, want: "server disk space is temporarily low"},
		{name: "a body that is not multipart", body: "plain", contentType: "multipart/form-data; boundary=x",
			status: http.StatusBadRequest, want: "invalid request"},
		{name: "an upload under the wrong field name", body: wrongField, contentType: wrongFieldType,
			status: http.StatusBadRequest, want: "invalid request"},
		{name: "a tenant over their quota", body: upload, contentType: uploadType, noQuota: true,
			status: http.StatusInsufficientStorage, want: "disk quota exceeded"},
		{name: "a destination that is a symlink", body: upload, contentType: uploadType, path: "link",
			status: http.StatusInternalServerError, want: "operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := tenantHome(t)
			if err := os.Symlink(t.TempDir(), filepath.Join(home, "link")); err != nil {
				t.Fatal(err)
			}
			installUploadSeams(t, !tc.noSpace, !tc.noQuota)
			script := homeScript()
			if tc.script != nil {
				tc.script(script)
			}
			recorder := serveUpload(t, script, tc.body, tc.contentType, tc.path)
			assertResponse(t, recorder, tc.status, tc.want)
		})
	}
}

// installUploadSeams replaces the disk and quota gates for one test.
func installUploadSeams(t *testing.T, hasSpace, hasQuota bool) {
	t.Helper()
	setForTest(t, &reserveSpace, func() bool { return hasSpace })
	setForTest(t, &releaseSpace, func() {})
	setForTest(t, &quotaAvailable, func(string, int64) bool { return hasQuota })
}

func serveUpload(t *testing.T, script *sqlScript, body, contentType, path string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/domains/7/files/upload"
	if path != "" {
		target += "?path=" + path
	}
	request := filesRequest(http.MethodPost, target, body)
	request.Header.Set("Content-Type", contentType)
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Upload(recorder, request)
	return recorder
}

// The upload lands in the tenant's own tree, under the name the browser sent.
func TestUploadWritesTheFileItWasSent(t *testing.T) {
	home := tenantHome(t)
	if err := os.MkdirAll(filepath.Join(home, docrootRel), 0o755); err != nil {
		t.Fatal(err)
	}
	body, contentType := multipartBody(t, "file", "index.html", "<h1>hello</h1>")
	installUploadSeams(t, true, true)
	recorder := serveUpload(t, homeScript(), body, contentType, docrootRel)
	assertResponse(t, recorder, http.StatusCreated, `"name":"index.html"`)
	assertFileHolds(t, filepath.Join(home, docrootRel, "index.html"), "<h1>hello</h1>")
}

// ----- Extract -----

func serveExtract(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Extract(recorder, filesRequest(http.MethodPost, "/api/v1/domains/7/files/extract", body))
	return recorder
}

func TestExtractRefusesWhatItCannotUnpack(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		script func(s *sqlScript)
		status int
		want   string
	}{
		{name: "a domain that is not there", body: `{"path":"archive.zip"}`,
			script: func(s *sqlScript) { s.rows[systemUserQuery] = nil },
			status: http.StatusNotFound, want: "operation failed"},
		{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"},
		{name: "an archive that is not there", body: `{"path":"missing.zip"}`,
			status: http.StatusNotFound, want: "operation failed"},
		{name: "a directory", body: `{"path":"` + docrootRel + `"}`,
			status: http.StatusBadRequest, want: "path is not a regular file"},
		{name: "a format the panel cannot unpack", body: `{"path":"` + docrootRel + `/notes.txt"}`,
			status: http.StatusBadRequest, want: "unsupported format"},
		{name: "a target whose parent is a symlink", body: `{"path":"` + docrootRel + `/site.zip","target":"link/inside"}`,
			status: http.StatusInternalServerError, want: "operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := tenantHome(t)
			writeUnder(t, home, docrootRel+"/notes.txt", "plain")
			writeUnder(t, home, docrootRel+"/site.zip", "PK\x03\x04")
			if err := os.Symlink(t.TempDir(), filepath.Join(home, "link")); err != nil {
				t.Fatal(err)
			}
			(&commandLog{}).install(t)
			script := homeScript()
			if tc.script != nil {
				tc.script(script)
			}
			assertResponse(t, serveExtract(t, script, tc.body), tc.status, tc.want)
		})
	}
}

// A plain .gz file is decompressed inside the request, beside itself, and the
// target is relabelled afterwards.
func TestExtractDecompressesAGzipFileInTheRequest(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/dump.sql.gz", "not really gzip")
	commands := (&commandLog{output: func(name string, _ []string) string {
		if name == "gunzip" {
			return "SELECT 1;\n"
		}
		return ""
	}}).install(t)

	assertResponse(t, serveExtract(t, homeScript(), `{"path":"`+docrootRel+`/dump.sql.gz"}`),
		http.StatusOK, `"ok":true`)
	assertFileHolds(t, filepath.Join(home, docrootRel, "dump.sql"), "SELECT 1;\n")
	if _, ok := commands.ran("restorecon"); !ok {
		t.Errorf("the target was not relabelled: %+v", commands.calls)
	}
}

// A gzip file the tool refuses leaves nothing behind: a half-written output is
// worse than none, because the page would offer it as a file.
func TestExtractRemovesTheOutputOfAFailedGzip(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/dump.sql.gz", "not really gzip")
	(&commandLog{fail: map[string]bool{"gunzip": true}}).install(t)

	assertResponse(t, serveExtract(t, homeScript(), `{"path":"`+docrootRel+`/dump.sql.gz"}`),
		http.StatusBadRequest, "invalid gzip file")
	if _, err := os.Lstat(filepath.Join(home, docrootRel, "dump.sql")); !os.IsNotExist(err) {
		t.Errorf("the partial output survived: %v", err)
	}
}

// A relabel the host refuses is a server fault: the file is already written, but
// nginx cannot read what it cannot label.
func TestExtractReportsAFailedRelabel(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/dump.sql.gz", "not really gzip")
	(&commandLog{fail: map[string]bool{"restorecon": true}}).install(t)

	assertResponse(t, serveExtract(t, homeScript(), `{"path":"`+docrootRel+`/dump.sql.gz"}`),
		http.StatusInternalServerError, "operation failed")
}

// extractStart is what the job seam was handed.
type extractStart struct {
	systemUser    string
	archiveType   archivex.Type
	archivePinned string
	targetPinned  string
}

// An output the panel cannot create is a server fault: the archive is the
// tenant's, but the failure is not theirs to fix.
func TestExtractReportsAnOutputItCannotCreate(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/dump.sql.gz", "not really gzip")
	// A directory of that name is already where the decompressed file goes.
	if err := os.Mkdir(filepath.Join(home, docrootRel, "dump.sql"), 0o755); err != nil {
		t.Fatal(err)
	}
	(&commandLog{}).install(t)

	assertResponse(t, serveExtract(t, homeScript(), `{"path":"`+docrootRel+`/dump.sql.gz"}`),
		http.StatusInternalServerError, "operation failed")
}

// An archive is handed to a job rather than unpacked in the request, because a
// large one outlasts the router's timeout. The job gets the PINNED descriptors,
// not the paths the caller named, and owns them from there.
func TestExtractStartsAJobForAnArchive(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/site.zip", "PK\x03\x04")
	(&commandLog{}).install(t)
	started := make(chan extractStart, 1)
	setForTest(t, &startExtractJob, func(job *extractJob, archiveFd, targetFd *os.File,
		archivePinned, targetPinned, systemUser string, archiveType archivex.Type, _ archivex.Limits) {
		defer func() {
			_ = archiveFd.Close()
			_ = targetFd.Close()
		}()
		job.finish()
		started <- extractStart{systemUser: systemUser, archiveType: archiveType,
			archivePinned: archivePinned, targetPinned: targetPinned}
	})

	recorder := serveExtract(t, homeScript(), `{"path":"`+docrootRel+`/site.zip"}`)
	assertResponse(t, recorder, http.StatusAccepted, `"job_id"`)
	select {
	case call := <-started:
		if call.systemUser != "c_test" || call.archiveType != archivex.TypeZIP {
			t.Errorf("the job was started for %q with type %v, want c_test and a zip", call.systemUser, call.archiveType)
		}
		if !strings.HasPrefix(call.archivePinned, "/proc/self/fd/") ||
			!strings.HasPrefix(call.targetPinned, "/proc/self/fd/") {
			t.Errorf("the job was given %q and %q, want pinned descriptors", call.archivePinned, call.targetPinned)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no extraction job was started")
	}
}

// ----- Archive -----

func serveArchive(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Archive(recorder, filesRequest(http.MethodPost, "/api/v1/domains/7/files/archive", body))
	return recorder
}

func TestArchiveRefusesWhatItCannotPack(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		script func(s *sqlScript)
		fail   map[string]bool
		status int
		want   string
	}{
		{name: "a domain that is not there", body: `{"resources":["` + docrootRel + `"],"output_path":"out.zip"}`,
			script: func(s *sqlScript) { s.rows[systemUserQuery] = nil },
			status: http.StatusNotFound, want: "operation failed"},
		{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"},
		{name: "no source at all", body: `{"output_path":"out.zip"}`,
			status: http.StatusBadRequest, want: "source missing"},
		{name: "a source that is a symlink", body: `{"resources":["link"],"output_path":"out.zip"}`,
			status: http.StatusBadRequest, want: "invalid request"},
		{name: "an output inside a symlinked directory",
			body:   `{"resources":["` + docrootRel + `"],"output_path":"link/out.zip"}`,
			status: http.StatusBadRequest, want: "invalid request"},
		{name: "a tool that fails", body: `{"resources":["` + docrootRel + `"],"output_path":"out.zip"}`,
			fail:   map[string]bool{"zip": true},
			status: http.StatusInternalServerError, want: "operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := tenantHome(t)
			writeUnder(t, home, docrootRel+"/index.html", "<h1>hello</h1>")
			if err := os.Symlink(t.TempDir(), filepath.Join(home, "link")); err != nil {
				t.Fatal(err)
			}
			(&commandLog{fail: tc.fail}).install(t)
			script := homeScript()
			if tc.script != nil {
				tc.script(script)
			}
			assertResponse(t, serveArchive(t, script, tc.body), tc.status, tc.want)
		})
	}
}

// The tool runs as the tenant, with the resolved paths, and the size comes from
// the archive it wrote.
func TestArchiveRunsTheToolAsTheTenant(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/index.html", "<h1>hello</h1>")
	writeUnder(t, home, "out.zip", "PK\x03\x04")
	commands := (&commandLog{}).install(t)

	body := `{"resources":["` + docrootRel + `"],"output_path":"out.zip","format":"zip"}`
	assertResponse(t, serveArchive(t, homeScript(), body), http.StatusOK, `"size":4`)
	args, ok := commands.ran("zip")
	if !ok {
		t.Fatalf("zip did not run: %+v", commands.calls)
	}
	if args[0] != "-r" || args[3] != filepath.Join(home, "out.zip") {
		t.Errorf("zip arguments = %q", args)
	}
	if args[len(args)-1] != filepath.Join(home, docrootRel) {
		t.Errorf("the source is not the resolved path: %q", args)
	}
	if commands.calls[0].systemUser != "c_test" {
		t.Errorf("the tool ran as %q, want c_test", commands.calls[0].systemUser)
	}
}

// An archive whose size cannot be read is still reported as created, without a
// size: zero would read as an empty archive.
func TestArchiveOmitsTheSizeItCouldNotRead(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/index.html", "<h1>hello</h1>")
	(&commandLog{}).install(t)

	body := `{"resources":["` + docrootRel + `"],"output_path":"out.zip"}`
	recorder := serveArchive(t, homeScript(), body)
	assertResponse(t, recorder, http.StatusOK, `"output_path":"out.zip"`)
	if strings.Contains(recorder.Body.String(), `"size"`) {
		t.Errorf("body = %s, want no size for an archive that is not there", recorder.Body.String())
	}
}

// ----- Search -----

func serveSearch(t *testing.T, script *sqlScript, query string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Search(recorder, filesRequest(http.MethodGet, "/api/v1/domains/7/files/search?"+query, ""))
	return recorder
}

func TestSearchAnswersWithoutWalkingWhenItCan(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		script func(s *sqlScript)
		status int
		want   string
	}{
		{name: "a domain that is not there", query: "q=index",
			script: func(s *sqlScript) { s.rows[systemUserQuery] = nil },
			status: http.StatusNotFound, want: "operation failed"},
		{name: "an empty pattern", query: "q=%20",
			status: http.StatusOK, want: `"total":0`},
		{name: "a base that is a symlink", query: "q=index&path=link",
			status: http.StatusBadRequest, want: "invalid request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := tenantHome(t)
			if err := os.Symlink(t.TempDir(), filepath.Join(home, "link")); err != nil {
				t.Fatal(err)
			}
			(&commandLog{}).install(t)
			script := homeScript()
			if tc.script != nil {
				tc.script(script)
			}
			assertResponse(t, serveSearch(t, script, tc.query), tc.status, tc.want)
		})
	}
}

// What find prints is rebased onto home-relative paths, and the pattern reaches
// it with the wildcards a caller typed removed.
func TestSearchRebasesWhatFindPrinted(t *testing.T) {
	home := tenantHome(t)
	writeUnder(t, home, docrootRel+"/index.html", "<h1>hello</h1>")
	if err := os.Mkdir(filepath.Join(home, docrootRel, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	commands := (&commandLog{output: func(name string, args []string) string {
		if name != "find" {
			return ""
		}
		base := args[1]
		// The last three lines are what a walk can also print: a link, a size
		// that is not a number, and a line with fewer fields than the format.
		return strings.Join([]string{
			base + "/" + docrootRel + "/index.html\t14\tf\t1700000000",
			base + "/" + docrootRel + "/cache\t4096\td\t1700000000",
			base + "/" + docrootRel + "/link\tx14\tl\t1700000000",
			base,
			"",
		}, "\n")
	}}).install(t)

	recorder := serveSearch(t, homeScript(), "q=*ind?ex*")
	assertResponse(t, recorder, http.StatusOK, `"total":3`)
	body := recorder.Body.String()
	for _, want := range []string{`"path":"/` + docrootRel + `/index.html"`, `"type":"folder"`,
		`"type":"symlink"`, `"q":"index"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body = %s, want it to hold %q", body, want)
		}
	}
	args, _ := commands.ran("find")
	if args[3] != "*index*" {
		t.Errorf("find pattern = %q, want *index*", args[3])
	}
}

// A walk that finds more than the page can hold is cut: the whole array is
// rendered on the panel's heap, which every customer shares.
func TestSearchStopsAtFiveHundredResults(t *testing.T) {
	tenantHome(t)
	(&commandLog{output: func(name string, args []string) string {
		if name != "find" {
			return ""
		}
		lines := make([]string, 600)
		for i := range lines {
			lines[i] = args[1] + "/file.txt\t10\tf\t1700000000"
		}
		return strings.Join(lines, "\n")
	}}).install(t)

	assertResponse(t, serveSearch(t, homeScript(), "q=file"), http.StatusOK, `"total":500`)
}
