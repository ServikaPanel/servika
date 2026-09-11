package laravel

import (
	"os"
	"path/filepath"
	"testing"
)

// tenantHome points the package at a temporary tenant home and returns that
// home together with the tenant's public_html, which already exists.
func tenantHome(t *testing.T) (home, publicHTML string) {
	t.Helper()
	// The path is resolved first: safeAppDir compares against the resolved form,
	// and a temporary directory sits under a symlinked /var on some hosts.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publicHTML = filepath.Join(home, "c_test", "public_html")
	if err := os.MkdirAll(publicHTML, 0o750); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &homeRoot, home)
	return home, publicHTML
}

// Everything the toolkit runs for a tenant runs in the directory this function
// returns, so a path that leaves public_html is a path the panel would execute
// composer, npm and git in.
func TestSafeAppDirKeepsAnApplicationInsidePublicHTML(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		appRoot string
		setup   func(t *testing.T, publicHTML string)
		rel     string
		wantErr string
	}{
		{name: "a user that is not a tenant", user: "root", appRoot: "public_html",
			wantErr: "invalid system user"},
		{name: "no directory at all", user: "c_test"},
		{name: "a parent reference", user: "c_test", appRoot: "public_html/../etc",
			wantErr: "invalid application directory"},
		{name: "a character the shell reads", user: "c_test", appRoot: "public_html/a b",
			wantErr: "invalid application directory"},
		{name: "a directory outside public_html", user: "c_test", appRoot: "etc",
			wantErr: "application directory must be under public_html"},
		{name: "a subdirectory", user: "c_test", appRoot: "public_html/app", rel: "app"},
		{name: "a subdirectory that does not exist yet", user: "c_test", appRoot: "public_html/a/b/c", rel: "a/b/c"},
		{name: "a symlink that leaves the home", user: "c_test", appRoot: "public_html/link",
			setup: func(t *testing.T, publicHTML string) {
				if err := os.Symlink(t.TempDir(), filepath.Join(publicHTML, "link")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "application directory cannot leave public_html through a symlink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, publicHTML := tenantHome(t)
			if tc.setup != nil {
				tc.setup(t, publicHTML)
			}
			got, err := safeAppDir(tc.user, tc.appRoot)
			assertAppDir(t, got, err, wantedPath(publicHTML, tc.rel, tc.wantErr), tc.wantErr)
		})
	}
}

// wantedPath is the directory a case expects, or empty when it expects an error.
func wantedPath(publicHTML, rel, wantErr string) string {
	switch {
	case wantErr != "":
		return ""
	case rel == "":
		return publicHTML
	default:
		return filepath.Join(publicHTML, rel)
	}
}

func assertAppDir(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()
	text := ""
	if err != nil {
		text = err.Error()
	}
	if text != wantErr {
		t.Fatalf("err = %q, want %q", text, wantErr)
	}
	if got != want {
		t.Errorf("directory = %q, want %q", got, want)
	}
}

// A directory that is not there yet still resolves: the symlink walk climbs to
// the tenant's public_html and stops, because an install creates the directory
// after this answer.
func TestSafeAppDirAcceptsADirectoryThatIsNotThereYet(t *testing.T) {
	home, _ := tenantHome(t)
	got, err := safeAppDir("c_other", "public_html")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if want := filepath.Join(home, "c_other", "public_html"); got != want {
		t.Errorf("directory = %q, want %q", got, want)
	}
}

// Every field of a worker definition reaches a systemd unit file, and an
// out-of-range value is refused rather than clamped: a screen that asked for
// twelve processes and silently got ten tells the operator something untrue.
func TestValidateWorkerRefusesEveryFieldItCannotRender(t *testing.T) {
	cases := []struct {
		name   string
		change func(w *Worker)
		want   string
	}{
		{name: "a definition that is already usable"},
		{name: "an empty name", change: func(w *Worker) { w.Name = "" }, want: reasonWorkerName},
		{name: "a name with a space", change: func(w *Worker) { w.Name = "my worker" }, want: reasonWorkerName},
		{name: "an empty connection", change: func(w *Worker) { w.Connection = "  " }},
		{name: "a connection with a directive character",
			change: func(w *Worker) { w.Connection = "data base!" }, want: reasonWorkerConnection},
		{name: "a queue list with a newline",
			change: func(w *Worker) { w.Queues = "high\nExecStartPre=/bin/sh" }, want: reasonWorkerQueues},
		{name: "no process at all", change: func(w *Worker) { w.Processes = 0 }, want: reasonWorkerRange},
		{name: "more processes than the sweep walks",
			change: func(w *Worker) { w.Processes = maxWorkerProcesses + 1 }, want: reasonWorkerRange},
		{name: "no try", change: func(w *Worker) { w.Tries = 0 }, want: reasonWorkerRange},
		{name: "a timeout below the floor", change: func(w *Worker) { w.Timeout = 4 }, want: reasonWorkerRange},
		{name: "a sleep above the ceiling", change: func(w *Worker) { w.Sleep = 61 }, want: reasonWorkerRange},
		{name: "a memory ceiling below the floor",
			change: func(w *Worker) { w.MemoryMB = 32 }, want: reasonWorkerRange},
		{name: "a job ceiling nobody can reach",
			change: func(w *Worker) { w.MaxJobs = 5 }, want: reasonWorkerRange},
		{name: "a job ceiling above the ceiling",
			change: func(w *Worker) { w.MaxJobs = 100001 }, want: reasonWorkerRange},
		{name: "no job ceiling", change: func(w *Worker) { w.MaxJobs = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			worker := baseWorker()
			if tc.change != nil {
				tc.change(&worker)
			}
			if got := ValidateWorker(&worker); got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

// An empty connection takes the default rather than reaching a unit file empty.
func TestValidateWorkerNamesTheDefaultConnection(t *testing.T) {
	worker := baseWorker()
	worker.Connection = "   "
	if reason := ValidateWorker(&worker); reason != "" {
		t.Fatalf("reason = %q, want none", reason)
	}
	if worker.Connection != "database" {
		t.Errorf("connection = %q, want database", worker.Connection)
	}
}
