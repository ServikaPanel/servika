package phpext

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The extension list and the toggle read and rename files in the directory the
// whole PHP version shares, and a rename that the master will not accept has to
// go back. The tests below pin the naming rules, the refusals and the rollback.

// setForTest points a package variable somewhere else for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// iniDir points the version list at a temporary extension directory holding the
// named files, and returns that directory.
func iniDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("extension=x.so\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	setForTest(t, &installedVersions, func() []Version {
		return []Version{{Version: "8.3", IniDir: dir, Service: "php-fpm", PHPBin: "/usr/bin/php"}}
	})
	return dir
}

// listed asks the handler for one version's extensions.
func listed(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	(&Handlers{}).List(recorder, httptest.NewRequest(http.MethodGet, "/php-extensions"+query, nil))
	return recorder
}

// extensionsIn decodes the answer's extension list.
func extensionsIn(t *testing.T, recorder *httptest.ResponseRecorder) []Extension {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var answer struct {
		Total   int         `json:"total"`
		Content []Extension `json:"content"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if answer.Total != len(answer.Content) {
		t.Errorf("total = %d, content = %d", answer.Total, len(answer.Content))
	}
	return answer.Content
}

// The name shown to the operator is the extension's own, with the load-order
// prefix and both suffixes taken off, and a disabled file still appears.
func TestTheListNamesEachExtensionWithoutItsLoadOrderPrefix(t *testing.T) {
	iniDir(t, "20-soap.ini", "40-opcache.ini.disabled", "curl.ini", "1234-notaprefix.ini", "README")

	extensions := extensionsIn(t, listed(t, "?version=8.3"))

	want := []Extension{
		{Name: "1234-notaprefix", Enabled: true, INIFile: "1234-notaprefix.ini"},
		{Name: "curl", Enabled: true, INIFile: "curl.ini"},
		{Name: "opcache", Enabled: false, INIFile: "40-opcache.ini.disabled"},
		{Name: "soap", Enabled: true, INIFile: "20-soap.ini"},
	}
	if len(extensions) != len(want) {
		t.Fatalf("extensions = %+v, want %d entries", extensions, len(want))
	}
	for i, extension := range extensions {
		if extension != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, extension, want[i])
		}
	}
}

// Without a version the list answers for the default one, so the page loads
// before the operator has chosen anything.
func TestTheListDefaultsToTheBaseVersion(t *testing.T) {
	iniDir(t, "20-soap.ini")

	if extensions := extensionsIn(t, listed(t, "")); len(extensions) != 1 {
		t.Errorf("extensions = %+v, want the default version's one entry", extensions)
	}
}

func TestTheListRefusesAVersionItCannotServe(t *testing.T) {
	iniDir(t)

	recorder := listed(t, "?version=5.6")

	if recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "unsupported version") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

// A directory that is not there is an installation problem, not an empty list,
// so it is reported rather than answered with zero extensions.
func TestTheListReportsADirectoryItCannotRead(t *testing.T) {
	dir := iniDir(t)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	recorder := listed(t, "?version=8.3")

	if recorder.Code != http.StatusInternalServerError ||
		!strings.Contains(recorder.Body.String(), "failed to read extension directory") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

// toggled sends a toggle request.
func toggled(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	(&Handlers{}).Toggle(recorder, httptest.NewRequest(http.MethodPost, "/php-extensions/toggle", strings.NewReader(body)))
	return recorder
}

// recordReloads answers every host command and counts the tenant reloads.
func recordReloads(t *testing.T, failWith error) (*[]string, *int) {
	t.Helper()
	var ran []string
	reloads := 0
	setForTest(t, &runCommand, func(name string, args ...string) ([]byte, error) {
		ran = append(ran, strings.Join(append([]string{name}, args...), " "))
		return nil, failWith
	})
	setForTest(t, &reloadTenantMasters, func() { reloads++ })
	return &ran, &reloads
}

// Disabling renames the file out of the way and reloads both the shared master
// and every tenant's own, or the change stays invisible to a running site.
func TestDisablingRenamesTheFileAndReloadsEveryMaster(t *testing.T) {
	dir := iniDir(t, "20-soap.ini")
	ran, reloads := recordReloads(t, nil)

	recorder := toggled(t, `{"version":"8.3","ini_file":"20-soap.ini","active":false}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), `"file":"20-soap.ini.disabled"`) {
		t.Errorf("body = %s", recorder.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-soap.ini")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the enabled name is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-soap.ini.disabled")); err != nil {
		t.Errorf("the disabled name was not written: %v", err)
	}
	if len(*ran) != 1 || (*ran)[0] != "systemctl reload-or-restart php-fpm" {
		t.Errorf("commands = %v", *ran)
	}
	if *reloads != 1 {
		t.Errorf("tenant reloads = %d, want 1", *reloads)
	}
}

func TestEnablingPutsTheFileBackUnderItsLoadingName(t *testing.T) {
	dir := iniDir(t, "20-soap.ini.disabled")
	recordReloads(t, nil)

	recorder := toggled(t, `{"version":"8.3","ini_file":"20-soap.ini.disabled","active":true}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-soap.ini")); err != nil {
		t.Errorf("the enabled name was not written: %v", err)
	}
}

// A master that will not reload leaves the file under the name it had, or the
// directory says one thing and the running master another.
func TestAFailedReloadPutsTheNameBack(t *testing.T) {
	dir := iniDir(t, "20-soap.ini")
	_, reloads := recordReloads(t, errors.New("exit status 1"))

	recorder := toggled(t, `{"version":"8.3","ini_file":"20-soap.ini","active":false}`)

	if recorder.Code != http.StatusInternalServerError ||
		!strings.Contains(recorder.Body.String(), "failed to reload PHP-FPM") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-soap.ini")); err != nil {
		t.Errorf("the original name was not put back: %v", err)
	}
	if *reloads != 0 {
		t.Errorf("tenant reloads = %d, want none", *reloads)
	}
}

// Asking for the state a file is already in is not an error and does not touch
// the master.
func TestAToggleToTheCurrentStateChangesNothing(t *testing.T) {
	for _, testCase := range []struct {
		name, file, body, message string
	}{
		{
			name:    "already enabled",
			file:    "20-soap.ini",
			body:    `{"version":"8.3","ini_file":"20-soap.ini","active":true}`,
			message: "already enabled",
		},
		{
			name:    "already disabled",
			file:    "20-soap.ini.disabled",
			body:    `{"version":"8.3","ini_file":"20-soap.ini.disabled","active":false}`,
			message: "already disabled",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			iniDir(t, testCase.file)
			ran, _ := recordReloads(t, nil)

			recorder := toggled(t, testCase.body)

			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), testCase.message) {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}
			if len(*ran) != 0 {
				t.Errorf("commands = %v, want none", *ran)
			}
		})
	}
}

func TestAToggleRefusesWhatItMustNotRename(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		status  int
		message string
	}{
		{
			name:    "a path rather than a file name",
			body:    `{"version":"8.3","ini_file":"../../etc/php.d/20-soap.ini","active":false}`,
			status:  http.StatusBadRequest,
			message: "invalid file name",
		},
		{
			name:    "a name that is not an ini file",
			body:    `{"version":"8.3","ini_file":"soap.conf","active":false}`,
			status:  http.StatusBadRequest,
			message: "invalid file name",
		},
		{
			name:    "a version that is not installed",
			body:    `{"version":"5.6","ini_file":"20-soap.ini","active":false}`,
			status:  http.StatusBadRequest,
			message: "unsupported version",
		},
		{
			name:    "a file that is not there",
			body:    `{"version":"8.3","ini_file":"20-gone.ini","active":false}`,
			status:  http.StatusNotFound,
			message: "file not found",
		},
		{
			name:    "a body that is not JSON",
			body:    `{"version":`,
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			iniDir(t, "20-soap.ini")
			ran, _ := recordReloads(t, nil)

			recorder := toggled(t, testCase.body)

			if recorder.Code != testCase.status ||
				!strings.Contains(recorder.Body.String(), testCase.message) {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}
			if len(*ran) != 0 {
				t.Errorf("commands = %v, want none", *ran)
			}
		})
	}
}

// safeName decides what reaches pecl as a package name, so it is pinned on its
// own rather than through a handler.
func TestSafeNameAcceptsOnlyAPackageName(t *testing.T) {
	for _, accepted := range []string{"redis", "imagick", "pdo_mysql", "ssh2-1", "A0"} {
		if !safeName(accepted) {
			t.Errorf("%q was refused", accepted)
		}
	}
	for _, refused := range []string{
		"", "redis;rm -rf /", "redis package", "../redis", "redis/1", "redİs",
		strings.Repeat("a", 65),
	} {
		if safeName(refused) {
			t.Errorf("%q was accepted", refused)
		}
	}
}
