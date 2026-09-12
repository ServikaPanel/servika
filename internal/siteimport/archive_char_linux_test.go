package siteimport

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"servika/internal/archivex"

	"github.com/go-chi/chi/v5"
)

// Every path this package resolves goes through the openat2 helpers, which are
// Linux-only, so these cases build against Linux. seams.go carries the tenant
// home root, the two host commands, the extractor and the dump importer, none
// of which exist in a test.

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// tenantHome points the home root at a temporary tree and creates the tenant's
// own home inside it.
func tenantHome(t *testing.T, systemUser string) string {
	t.Helper()
	root := t.TempDir()
	setForTest(t, &tenantHomeRoot, root)
	home := filepath.Join(root, systemUser)
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	return home
}

// ownedDomain scripts the domain lookup every handler opens with.
func ownedDomain(script *sqlScript, systemUser string) {
	script.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{systemUser}}
}

// importRequest carries the {id} route parameter and a body.
func importRequest(t *testing.T, method, contentType string, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "/domains/4/import", bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "4")
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))
}

// multipartBody builds a body from ordered name/value pairs. A name ending in
// ":<file name>" becomes a file part.
func multipartBody(t *testing.T, pairs ...string) (string, []byte) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("multipartBody wants name/value pairs, got %d values", len(pairs))
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < len(pairs); i += 2 {
		name, value := pairs[i], pairs[i+1]
		field, fileName, isFile := strings.Cut(name, ":")
		var (
			part interface{ Write([]byte) (int, error) }
			err  error
		)
		if isFile {
			part, err = writer.CreateFormFile(field, fileName)
		} else {
			part, err = writer.CreateFormField(field)
		}
		if err != nil {
			t.Fatalf("build the %s part: %v", field, err)
		}
		if _, err := part.Write([]byte(value)); err != nil {
			t.Fatalf("write the %s part: %v", field, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the multipart body: %v", err)
	}
	return writer.FormDataContentType(), body.Bytes()
}

// zipArchive builds a zip carrying each path/content pair.
func zipArchive(t *testing.T, entries ...string) string {
	t.Helper()
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	for i := 0; i < len(entries); i += 2 {
		part, err := writer.Create(entries[i])
		if err != nil {
			t.Fatalf("add %s: %v", entries[i], err)
		}
		if _, err := part.Write([]byte(entries[i+1])); err != nil {
			t.Fatalf("write %s: %v", entries[i], err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}
	return body.String()
}

// uploadArchive posts a multipart body to the handler.
func uploadArchive(t *testing.T, handlers *Handlers, pairs ...string) *httptest.ResponseRecorder {
	t.Helper()
	contentType, body := multipartBody(t, pairs...)
	recorder := httptest.NewRecorder()
	handlers.UploadArchive(recorder, importRequest(t, http.MethodPost, contentType, body))
	return recorder
}

// assertRefusal checks the status and the message a refusal answers with.
func assertRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), message) {
		t.Errorf("body = %s, want it to carry %q", recorder.Body, message)
	}
}

// stagedNames lists what is in the tenant's import work area.
func stagedNames(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, stagingDir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read the staging directory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// The upload stages the archive and inventories it WITHOUT extracting, because
// the caller has to confirm the destination and the archive must not be
// uploaded twice to do that.
func TestAnUploadedArchiveIsStagedAndInventoried(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := uploadArchive(t, handlers,
		"archive:site.zip", zipArchive(t, "site/wp-config.php", "<?php\n", "site/index.php", "<?php\n"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	answer := decodeSummary(t, recorder)
	if answer.FileName != "site.zip" {
		t.Errorf("file_name = %q", answer.FileName)
	}
	// The staging id is generated, never taken from the upload.
	if answer.StageID == "site.zip" || !strings.HasSuffix(answer.StageID, ".zip") {
		t.Errorf("stage_id = %q, want a generated name keeping the extension", answer.StageID)
	}
	if answer.App != "wordpress" {
		t.Errorf("app = %q, want the marker file's application", answer.App)
	}
	// Measured: the zip extractor cannot drop a leading path component, so an
	// archive that HAS a container directory is still reported as one this panel
	// cannot skip, with the reason.
	if answer.CanSkipRoot {
		t.Error("can_skip_root = true for a format whose extractor cannot strip")
	}
	assertWarnings(t, answer, "strip_unavailable")
	// The archive itself is on disk under the generated name, in the tenant's
	// own quota.
	if names := stagedNames(t, home); len(names) != 1 || names[0] != answer.StageID {
		t.Errorf("staged = %v, want the one archive named %q", names, answer.StageID)
	}
}

// decodeSummary reads the inventory an upload answered with.
func decodeSummary(t *testing.T, recorder *httptest.ResponseRecorder) ArchiveSummary {
	t.Helper()
	var answer ArchiveSummary
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	return answer
}

// assertWarnings checks the exact set of warnings an inventory carries.
func assertWarnings(t *testing.T, answer ArchiveSummary, want ...string) {
	t.Helper()
	if len(answer.Warnings) != len(want) {
		t.Fatalf("warnings = %v, want %v", answer.Warnings, want)
	}
	for i, warning := range want {
		if answer.Warnings[i] != warning {
			t.Errorf("warnings = %v, want %v", answer.Warnings, want)
		}
	}
}

// An archive the reader cannot open is refused AND removed: a staged file
// nothing can read is a file the tenant cannot see and cannot delete.
func TestAnArchiveThatCannotBeReadIsRemoved(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := uploadArchive(t, handlers, "archive:site.zip", "this is not a zip file")

	assertRefusal(t, recorder, http.StatusBadRequest, "the archive could not be read")
	if names := stagedNames(t, home); len(names) != 0 {
		t.Errorf("staged = %v, want the unreadable archive removed", names)
	}
}

// An archive with nothing in it is staged and reported, not refused: the caller
// decides what to do with it.
func TestAnEmptyArchiveIsReportedRatherThanRefused(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := uploadArchive(t, handlers, "archive:site.zip", zipArchive(t))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	assertWarnings(t, decodeSummary(t, recorder), "empty")
}

// An archive with several top-level entries has no container directory to skip,
// and the caller is told so rather than being offered the choice.
func TestAnArchiveWithNoContainerRootIsReported(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := uploadArchive(t, handlers, "archive:site.zip",
		zipArchive(t, "index.php", "<?php\n", "assets/app.css", "body{}"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	answer := decodeSummary(t, recorder)
	if answer.CanSkipRoot {
		t.Error("can_skip_root = true for an archive with no container directory")
	}
	assertWarnings(t, answer, "no_container_root")
}

func TestAnUploadRefusesWhatItCannotStage(t *testing.T) {
	cases := []struct {
		name    string
		script  func(*sqlScript)
		pairs   []string
		status  int
		message string
	}{
		{
			name:    "a domain that is not there",
			script:  func(s *sqlScript) { s.rows["SELECT system_user FROM domains WHERE id=?"] = nil },
			pairs:   []string{"archive:site.zip", "PK"},
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name:    "a domain with no tenant account",
			script:  func(s *sqlScript) { ownedDomain(s, "root") },
			pairs:   []string{"archive:site.zip", "PK"},
			status:  http.StatusBadRequest,
			message: "the domain has no valid system user",
		},
		{
			name:    "a body with no archive field",
			script:  func(s *sqlScript) { ownedDomain(s, "c_acme") },
			pairs:   []string{"notes", "hello"},
			status:  http.StatusBadRequest,
			message: "the archive field is required",
		},
		{
			name:    "a format the extractors do not read",
			script:  func(s *sqlScript) { ownedDomain(s, "c_acme") },
			pairs:   []string{"archive:site.7z", "anything"},
			status:  http.StatusBadRequest,
			message: "unsupported format",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			home := tenantHome(t, "c_acme")
			script := newScript()
			testCase.script(script)
			handlers := &Handlers{DB: scriptDB(t, script)}

			assertRefusal(t, uploadArchive(t, handlers, testCase.pairs...), testCase.status, testCase.message)
			if names := stagedNames(t, home); len(names) != 0 {
				t.Errorf("staged = %v, want nothing", names)
			}
		})
	}
}

// A request that is not multipart at all is refused before anything is read.
func TestAnUploadWithoutAMultipartBodyIsRefused(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.UploadArchive(recorder, importRequest(t, http.MethodPost, "application/json", []byte(`{}`)))

	assertRefusal(t, recorder, http.StatusBadRequest, "a multipart body is required")
}

// A body that claims to be multipart and is not is refused while it is being
// read, rather than treated as an upload with no fields.
func TestAnUploadThatCannotBeReadIsRefused(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.UploadArchive(recorder, importRequest(t, http.MethodPost,
		`multipart/form-data; boundary=abc`, []byte("--abc\r\nthis is not a part\r\n")))

	assertRefusal(t, recorder, http.StatusBadRequest, "the upload could not be read")
}

// A home the work area cannot be created beneath stops the upload before a byte
// of it is stored.
func TestAWorkAreaThatCannotBeCreatedIsReported(t *testing.T) {
	root := t.TempDir()
	setForTest(t, &tenantHomeRoot, root)
	// The tenant home is a FILE, so openat2 has nothing to create beneath.
	if err := os.WriteFile(filepath.Join(root, "c_acme"), []byte("not a home"), 0o600); err != nil {
		t.Fatalf("write the home: %v", err)
	}
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := uploadArchive(t, handlers, "archive:site.zip", zipArchive(t, "a.php", "<?php\n"))

	assertRefusal(t, recorder, http.StatusInternalServerError, "the import work area could not be created")
}

// stageArchive puts an archive in the work area and returns its id, which is
// what an apply addresses it by.
func stageArchive(t *testing.T, handlers *Handlers, name, content string) string {
	t.Helper()
	recorder := uploadArchive(t, handlers, "archive:"+name, content)
	if recorder.Code != http.StatusOK {
		t.Fatalf("staging failed: %d %s", recorder.Code, recorder.Body)
	}
	return decodeSummary(t, recorder).StageID
}

// extractCall records what the extractor was asked to do.
type extractCall struct {
	destination string
	systemUser  string
	strip       int
}

// recordExtraction installs the extractor seam and returns where its calls land.
func recordExtraction(t *testing.T, err error) *[]extractCall {
	t.Helper()
	calls := []extractCall{}
	setForTest(t, &extractArchive, func(_ context.Context, _ string, _ archivex.Type,
		destination, systemUser string, strip int, _ archivex.Limits) (string, error) {
		calls = append(calls, extractCall{destination: destination, systemUser: systemUser, strip: strip})
		return "", err
	})
	setForTest(t, &runCommand, func(string, ...string) error { return nil })
	setForTest(t, &lookPath, func(string) (string, error) { return "", errors.New("not installed") })
	return &calls
}

// applyArchive posts an apply body to the handler.
func applyArchive(t *testing.T, handlers *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handlers.ApplyArchive(recorder, importRequest(t, http.MethodPost, "application/json", []byte(body)))
	return recorder
}

func TestApplyExtractsIntoTheChosenDirectoryAndDropsTheStagedCopy(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
	calls := recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`","target":"public_html/new"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if len(*calls) != 1 {
		t.Fatalf("extractor calls = %v, want one", *calls)
	}
	call := (*calls)[0]
	if call.destination != filepath.Join(home, "public_html/new") {
		t.Errorf("destination = %q", call.destination)
	}
	if call.systemUser != "c_acme" || call.strip != 0 {
		t.Errorf("call = %+v, want the tenant and no strip", call)
	}
	// The destination was created before the extractor ran.
	if info, err := os.Stat(filepath.Join(home, "public_html/new")); err != nil || !info.IsDir() {
		t.Errorf("the destination was not prepared: %v", err)
	}
	// The staged copy should not keep sitting in the tenant's quota.
	if names := stagedNames(t, home); len(names) != 0 {
		t.Errorf("staged = %v, want the copy removed after the extraction", names)
	}
}

// Skipping the container directory is offered only when there is one, and it
// reaches the extractor as a strip level rather than a path.
func TestApplySkipsTheContainerDirectory(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
	calls := recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`","skip_root":true}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if len(*calls) != 1 || (*calls)[0].strip != 1 {
		t.Fatalf("extractor calls = %v, want one with strip 1", *calls)
	}
	var answer applyArchiveResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if answer.SkippedRoot != "site" {
		t.Errorf("skipped_root = %q, want the container directory", answer.SkippedRoot)
	}
	if answer.Target != "public_html" {
		t.Errorf("target = %q, want the default destination", answer.Target)
	}
}

// Emptying the destination is what the caller asked for, and it happens before
// the extractor runs.
func TestApplyEmptiesTheDestinationWhenAsked(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatalf("create the destination: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "public_html", "old.php"), []byte("<?php\n"), 0o640); err != nil {
		t.Fatalf("write the old site: %v", err)
	}
	recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`","clean_dest":true}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if _, err := os.Stat(filepath.Join(home, "public_html", "old.php")); !os.IsNotExist(err) {
		t.Errorf("the previous site survived the clean: %v", err)
	}
}

func TestApplyRefusesWhatItCannotExtract(t *testing.T) {
	cases := []struct {
		name       string
		body       func(stageID string) string
		extractErr error
		status     int
		message    string
	}{
		{
			name:    "an upload id nothing staged",
			body:    func(string) string { return `{"stage_id":"deadbeef.zip"}` },
			status:  http.StatusNotFound,
			message: "invalid upload id",
		},
		{
			name:    "a body that is not JSON",
			body:    func(string) string { return `{` },
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
		{
			name:    "the work area as the destination",
			body:    func(id string) string { return `{"stage_id":"` + id + `","target":"` + stagingDir + `"}` },
			status:  http.StatusBadRequest,
			message: "the import work area cannot be the destination",
		},
		{
			name:    "the home itself as the destination",
			body:    func(id string) string { return `{"stage_id":"` + id + `","target":"/"}` },
			status:  http.StatusBadRequest,
			message: "the destination cannot be the home directory itself",
		},
		{
			name:       "an extractor that refused",
			body:       func(id string) string { return `{"stage_id":"` + id + `"}` },
			extractErr: archivex.ErrUnsafePath,
			status:     http.StatusBadRequest,
			message:    "extraction failed",
		},
		{
			name:       "an archive whose format cannot be stripped",
			body:       func(id string) string { return `{"stage_id":"` + id + `","skip_root":true}` },
			extractErr: archivex.ErrStripUnsupported,
			status:     http.StatusNotImplemented,
			message:    "extraction failed",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			home := tenantHome(t, "c_acme")
			script := newScript()
			ownedDomain(script, "c_acme")
			handlers := &Handlers{DB: scriptDB(t, script)}
			stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
			recordExtraction(t, testCase.extractErr)

			assertRefusal(t, applyArchive(t, handlers, testCase.body(stageID)), testCase.status, testCase.message)
			// A refused apply leaves the staged copy where it is, so the caller can
			// try again without uploading it a second time.
			if names := stagedNames(t, home); len(names) != 1 {
				t.Errorf("staged = %v, want the archive kept for another attempt", names)
			}
		})
	}
}

// An archive with several top-level entries has nothing to skip, and saying so
// is better than dropping an arbitrary one of them.
func TestApplyRefusesToSkipARootThatIsNotThere(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip",
		zipArchive(t, "index.php", "<?php\n", "assets/app.css", "body{}"))
	calls := recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`","skip_root":true}`)

	assertRefusal(t, recorder, http.StatusBadRequest, "no single container directory")
	if len(*calls) != 0 {
		t.Errorf("the extractor ran anyway: %v", *calls)
	}
}

// A destination that cannot be prepared stops the apply: the extractor must
// never be pointed at a path this package could not create itself.
func TestApplyReportsADestinationItCannotPrepare(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
	// A FILE where the destination directory must go.
	if err := os.WriteFile(filepath.Join(home, "public_html"), []byte("not a directory"), 0o640); err != nil {
		t.Fatalf("block the destination: %v", err)
	}
	calls := recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`"}`)

	assertRefusal(t, recorder, http.StatusBadRequest, "the destination could not be prepared")
	if len(*calls) != 0 {
		t.Errorf("the extractor ran against a destination that was not prepared: %v", *calls)
	}
}

// The apply reads the staged archive through the descriptor it pinned, and an
// archive it cannot read is refused rather than extracted blind.
func TestApplyReportsAnArchiveItCannotSummarize(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageID := stageArchive(t, handlers, "site.zip", zipArchive(t, "site/index.php", "<?php\n"))
	// The tenant owns the staged file and can replace its content.
	if err := os.WriteFile(filepath.Join(home, stagingDir, stageID), []byte("not a zip"), 0o640); err != nil {
		t.Fatalf("replace the staged archive: %v", err)
	}
	calls := recordExtraction(t, nil)

	recorder := applyArchive(t, handlers, `{"stage_id":"`+stageID+`","skip_root":true}`)

	assertRefusal(t, recorder, http.StatusBadRequest, "the archive could not be read")
	if len(*calls) != 0 {
		t.Errorf("the extractor ran against an unreadable archive: %v", *calls)
	}
}

// An apply for a domain that is not there is a 404, like every other call.
func TestApplyRefusesADomainThatIsNotThere(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	script.rows["SELECT system_user FROM domains WHERE id=?"] = nil
	handlers := &Handlers{DB: scriptDB(t, script)}
	calls := recordExtraction(t, nil)

	assertRefusal(t, applyArchive(t, handlers, `{"stage_id":"x.zip"}`), http.StatusNotFound, "domain not found")
	if len(*calls) != 0 {
		t.Errorf("the extractor ran for an unknown domain: %v", *calls)
	}
}

// A staging id is generated by this package, so anything else is refused before
// it reaches the filesystem.
func TestAStagingIdThisPackageDidNotGenerateIsRefused(t *testing.T) {
	tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recordExtraction(t, nil)

	for _, id := range []string{"../../etc/passwd", "not-hex.zip", strings.Repeat("a", 32) + ".7z"} {
		body, err := json.Marshal(map[string]string{"stage_id": id})
		if err != nil {
			t.Fatalf("build the body: %v", err)
		}
		assertRefusal(t, applyArchive(t, handlers, string(body)), http.StatusNotFound, "invalid upload id")
	}
}

// stageIDOf is the generated name of the one staged archive.
func stageIDOf(t *testing.T, home string) string {
	t.Helper()
	names := stagedNames(t, home)
	if len(names) != 1 {
		t.Fatalf("staged = %v, want exactly one", names)
	}
	return names[0]
}

// An upload older than the staging lifetime is swept on the next upload, so an
// abandoned transfer cannot sit in a tenant's quota forever.
func TestAnAbandonedUploadIsSweptByTheNextOne(t *testing.T) {
	home := tenantHome(t, "c_acme")
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}
	stageArchive(t, handlers, "old.zip", zipArchive(t, "site/index.php", "<?php\n"))
	abandoned := stageIDOf(t, home)
	old := time.Now().Add(-stagingLifetime - time.Hour)
	if err := os.Chtimes(filepath.Join(home, stagingDir, abandoned), old, old); err != nil {
		t.Fatalf("age the staged archive: %v", err)
	}

	stageArchive(t, handlers, "new.zip", zipArchive(t, "site/index.php", "<?php\n"))

	for _, name := range stagedNames(t, home) {
		if name == abandoned {
			t.Errorf("the abandoned upload %q survived the sweep", name)
		}
	}
}
