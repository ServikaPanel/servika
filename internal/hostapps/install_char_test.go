package hostapps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An install adds a Linux user, writes into the install directory and installs a
// systemd unit. The tests below pin the order of those steps and the point each
// failure stops at, and pin the unpack shape rules that decide what lands in the
// install directory.

// setForTest points a package variable somewhere else for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// installSteps records the order of an install and fails one named step.
type installSteps struct {
	done     []string
	failAt   string
	failWith error
}

// step records one step and returns its scripted failure.
func (s *installSteps) step(name string) error {
	s.done = append(s.done, name)
	if name == s.failAt {
		if s.failWith != nil {
			return s.failWith
		}
		return errors.New(name + " failed")
	}
	return nil
}

// install points every host step at the recorder.
func (s *installSteps) install(t *testing.T) {
	t.Helper()
	setForTest(t, &downloadFor, func(Entry) (string, string, error) {
		return "https://example.test/app.tar.gz", "", s.step("download")
	})
	setForTest(t, &ensureUser, func(string) (string, error) { return "svc_gitea", s.step("user") })
	setForTest(t, &prepareDirectories, func(string, string) error { return s.step("directories") })
	setForTest(t, &fetchArchive, func(context.Context, string, string, string) error { return s.step("fetch") })
	setForTest(t, &unpackArchive, func(context.Context, Entry, string, string) error { return s.step("unpack") })
	setForTest(t, &verifyBinary, func(string, string) (string, error) {
		return "/opt/servika-apps/gitea/gitea", s.step("binary")
	})
	setForTest(t, &buildArgv, func(Entry, string, int) ([]string, error) {
		return []string{"web"}, s.step("argv")
	})
	setForTest(t, &writeEnvFile, func(Entry, int, map[string]string) error { return s.step("env") })
	setForTest(t, &ensureLogFile, func(string) error { return s.step("log") })
	setForTest(t, &installUnit, func(string, string) error { return s.step("unit") })
	setForTest(t, &enableUnit, func(string) error { return s.step("enable") })
}

// installEntry is a catalog row the steps above accept.
func installEntry() (Entry, App) {
	entry := Entry{
		Code: "gitea", Name: "Gitea", Version: "1.22.0",
		ArchiveKind: "binary", BinaryPath: "gitea", PortEnvName: "GITEA_PORT",
		URLAMD64: "https://example.test/app", DefaultPort: 3000,
	}
	return entry, App{ID: 1, Code: "gitea", InstallDir: "/opt/servika-apps/gitea", DataDir: "/opt/servika-apps/gitea/data", Port: 3000}
}

// The steps run in one order, and the ownership pass runs a second time after
// the unpack because the files that just landed belong to root.
func TestAnInstallRunsItsStepsInOrder(t *testing.T) {
	recorder := &installSteps{}
	recorder.install(t)
	entry, app := installEntry()

	if err := install(context.Background(), entry, app); err != nil {
		t.Fatalf("install: %v", err)
	}

	want := "download,user,directories,fetch,unpack,binary,directories,argv,env,log,unit,enable"
	if got := strings.Join(recorder.done, ","); got != want {
		t.Errorf("steps = %s\nwant  = %s", got, want)
	}
}

// A failing step stops the install there, so nothing later runs against a host
// the previous step left half-prepared.
func TestAFailingStepStopsTheInstall(t *testing.T) {
	for _, step := range []string{
		"download", "user", "directories", "fetch", "unpack", "binary",
		"argv", "env", "log", "unit", "enable",
	} {
		t.Run(step, func(t *testing.T) {
			recorder := &installSteps{failAt: step}
			recorder.install(t)
			entry, app := installEntry()

			err := install(context.Background(), entry, app)

			if err == nil || !strings.Contains(err.Error(), step+" failed") {
				t.Fatalf("err = %v, want the %s failure", err, step)
			}
			if last := recorder.done[len(recorder.done)-1]; last != step {
				t.Errorf("the install went on to %s after %s failed: %v", last, step, recorder.done)
			}
		})
	}
}

// unpackRecorder answers the unpacking tools and records what they were asked to
// run, laying out whatever tree the test wants in the staging directory.
func unpackRecorder(t *testing.T, lay func(staging string), failWith error) *[]string {
	t.Helper()
	var ran []string
	setForTest(t, &unpackWith, func(_ context.Context, name string, arguments ...string) error {
		ran = append(ran, strings.Join(append([]string{name}, arguments...), " "))
		if failWith != nil {
			return failWith
		}
		// The staging directory is the argument after -d or -C.
		staging := arguments[len(arguments)-1]
		for i, argument := range arguments {
			if argument == "-d" || argument == "-C" {
				staging = arguments[i+1]
			}
		}
		if lay != nil {
			lay(staging)
		}
		return nil
	})
	return &ran
}

// plant writes a file, creating the directories above it.
func plant(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A tar archive is extracted into staging and the level the catalog names is
// promoted into the install directory, so the binary lands where the unit will
// look for it.
func TestATarArchiveIsPromotedFromTheLevelTheCatalogNames(t *testing.T) {
	installDir := t.TempDir()
	ran := unpackRecorder(t, func(staging string) {
		plant(t, filepath.Join(staging, "gitea-1.22.0", "gitea"), "the program")
		plant(t, filepath.Join(staging, "gitea-1.22.0", "public", "index.html"), "a page")
	}, nil)
	entry := Entry{Code: "gitea", ArchiveKind: "tar.gz", BinaryPath: "gitea", StripComponents: 1}

	if err := Unpack(context.Background(), entry, "/tmp/download", installDir); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if len(*ran) != 1 || !strings.HasPrefix((*ran)[0], "tar -xzf /tmp/download -C ") ||
		!strings.HasSuffix((*ran)[0], "--no-same-owner") {
		t.Errorf("commands = %v", *ran)
	}
	for _, rel := range []string{"gitea", "public/index.html"} {
		if _, err := os.Stat(filepath.Join(installDir, rel)); err != nil {
			t.Errorf("%s did not land: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(installDir, ".staging")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staging directory survived: %v", err)
	}
}

// A single-file download is copied to the path the catalog names rather than
// handed to an unpacking tool.
func TestABinaryDownloadIsCopiedIntoPlace(t *testing.T) {
	installDir := t.TempDir()
	download := filepath.Join(t.TempDir(), "download")
	plant(t, download, "the program")
	ran := unpackRecorder(t, nil, nil)
	entry := Entry{Code: "gitea", ArchiveKind: "binary", BinaryPath: "bin/gitea"}

	if err := Unpack(context.Background(), entry, download, installDir); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if len(*ran) != 0 {
		t.Errorf("commands = %v, want none", *ran)
	}
	body, err := os.ReadFile(filepath.Join(installDir, "bin", "gitea"))
	if err != nil || string(body) != "the program" {
		t.Errorf("the binary did not land: %v %q", err, body)
	}
}

// A zip goes to unzip, with the archive and the staging directory it must not
// write outside of.
func TestAZipArchiveGoesToUnzip(t *testing.T) {
	installDir := t.TempDir()
	ran := unpackRecorder(t, func(staging string) {
		plant(t, filepath.Join(staging, "app"), "the program")
	}, nil)
	entry := Entry{Code: "app", ArchiveKind: "zip", BinaryPath: "app"}

	if err := Unpack(context.Background(), entry, "/tmp/download", installDir); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if len(*ran) != 1 || !strings.HasPrefix((*ran)[0], "unzip -q -o /tmp/download -d ") {
		t.Errorf("commands = %v", *ran)
	}
}

// An archive whose layout changed between versions is refused with its own
// message, rather than producing a tree whose binary is one level too deep.
func TestAnArchiveWithoutTheExpectedTopDirectoryIsRefused(t *testing.T) {
	installDir := t.TempDir()
	unpackRecorder(t, func(staging string) {
		plant(t, filepath.Join(staging, "gitea"), "the program")
		plant(t, filepath.Join(staging, "README"), "loose")
	}, nil)
	entry := Entry{Code: "gitea", ArchiveKind: "tar.gz", BinaryPath: "gitea", StripComponents: 1}

	err := Unpack(context.Background(), entry, "/tmp/download", installDir)

	if err == nil || !strings.Contains(err.Error(), "single top directory") {
		t.Fatalf("err = %v, want the shape refusal", err)
	}
}

// A symlink where the top directory belongs is not that directory, so the
// promote cannot be redirected out of the staging tree. Measured: the entry-type
// test refuses it first, under the shape message, and the O_NOFOLLOW open below
// it is the second defence rather than the one that answers.
func TestASymlinkedTopEntryIsRefused(t *testing.T) {
	installDir := t.TempDir()
	outside := t.TempDir()
	unpackRecorder(t, func(staging string) {
		if err := os.Symlink(outside, filepath.Join(staging, "gitea-1.22.0")); err != nil {
			t.Fatal(err)
		}
	}, nil)
	entry := Entry{Code: "gitea", ArchiveKind: "tar.gz", BinaryPath: "gitea", StripComponents: 1}

	err := Unpack(context.Background(), entry, "/tmp/download", installDir)

	if err == nil || !strings.Contains(err.Error(), "single top directory") {
		t.Fatalf("err = %v, want the symlink refusal", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "..")); err != nil {
		t.Errorf("the directory the symlink pointed at is gone: %v", err)
	}
}

func TestAnArchiveKindTheUnpackerDoesNotKnowIsRefused(t *testing.T) {
	ran := unpackRecorder(t, nil, nil)
	entry := Entry{Code: "app", ArchiveKind: "7z", BinaryPath: "app"}

	err := Unpack(context.Background(), entry, "/tmp/download", t.TempDir())

	if err == nil || !strings.Contains(err.Error(), "not an archive kind this understands") {
		t.Fatalf("err = %v, want the kind refusal", err)
	}
	if len(*ran) != 0 {
		t.Errorf("commands = %v, want none", *ran)
	}
}

// A tool that fails takes the install with it, and its own output is what the
// operator is shown.
func TestAFailingUnpackToolStopsTheUnpack(t *testing.T) {
	unpackRecorder(t, nil, errors.New("tar: unexpected end of file"))
	entry := Entry{Code: "app", ArchiveKind: "tar.xz", BinaryPath: "app"}

	err := Unpack(context.Background(), entry, "/tmp/download", t.TempDir())

	if err == nil || !strings.Contains(err.Error(), "unexpected end of file") {
		t.Fatalf("err = %v, want the tool failure", err)
	}
}
