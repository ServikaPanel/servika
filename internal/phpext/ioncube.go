// IonCube Loader installation and removal downloads the commercial loader from ioncube.com.
package phpext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
)

func ionCubeURL() string { return config.IonCubeURL() }

type ioncubeReq struct {
	Version string `json:"version"`
}

// ionCubeInstallFlag is the subcommand that installs the loader for ONE version
// on this same binary. A PHP install started from the panel appends a call to it
// (see IonCubeInstallShell), so the loader is ready within the same detached job
// that installed the interpreter. It runs the hardened Go path below rather than
// a raw shell curl+tar, and re-invoking the binary avoids the import cycle that a
// direct call from internal/phpversion (which this package imports) would close.
const ionCubeInstallFlag = "ioncube-install"

// errLoaderArtifact marks a download that is present but not the object it
// claims to be (a non-plain member, or an ELF this interpreter cannot load). It
// separates a bad artefact (answered 502) from a local failure (500) and from a
// version the archive simply does not carry (errMemberMissing, answered 400).
var errLoaderArtifact = errors.New("the downloaded IonCube archive is not a usable loader")

// ionCubeStage downloads the loader archive once and extracts it, returning the
// directory that holds the extracted ioncube/ tree and a cleanup to remove it.
// The startup heal and the per-version install both stage once and install for
// every version from the same extracted copy, so the archive is fetched once.
func ionCubeStage(ctx context.Context) (stageDir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "ioncube-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create a temporary directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmpDir) }
	tarPath := filepath.Join(tmpDir, "ioncube.tar.gz")
	if derr := download(ctx, ionCubeURL(), tarPath); derr != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("download the IonCube Loader: %w", derr)
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); paths are this package's own temp files.
	if out, terr := exec.CommandContext(ctx, "tar", "xzf", tarPath, "-C", tmpDir).CombinedOutput(); terr != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("extract the IonCube archive: %w: %s", terr, strings.TrimSpace(string(out)))
	}
	return tmpDir, cleanup, nil
}

// installIonCubeForVersion copies the loader for one PHP version out of an
// already-extracted stage directory, verifies it is an object this interpreter
// can load, writes the zend_extension .ini and reloads PHP-FPM. It carries no
// HTTP concern so the handler, the startup heal and the CLI mode share it.
func installIonCubeForVersion(ctx context.Context, s Version, stageDir string) (soDst, iniPath string, loaded bool, err error) {
	// 1. Read the PHP extension_dir.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the version was matched against the whitelist.
	extOut, err := exec.CommandContext(ctx, s.PHPBin, "-r", "echo ini_get('extension_dir');").Output()
	if err != nil {
		return "", "", false, fmt.Errorf("read the PHP extension directory: %w", err)
	}
	extDir := strings.TrimSpace(string(extOut))
	if extDir == "" {
		return "", "", false, errors.New("the PHP extension directory is empty")
	}

	// 2. Select the shared object matching the PHP version. The member is opened
	// rather than stat'ed, because os.Stat FOLLOWS a symlink and a symlink is the
	// one member kind extraction still creates freely (see loaderfile.go).
	soSrc := filepath.Join(stageDir, "ioncube", "ioncube_loader_lin_"+s.Version+".so")
	member, err := openArchiveMember(soSrc)
	if err != nil {
		if errors.Is(err, errMemberMissing) {
			return "", "", false, errMemberMissing
		}
		return "", "", false, fmt.Errorf("%w: %v", errLoaderArtifact, err)
	}
	defer func() { _ = member.Close() }()

	// 3. Prove the member is an object this interpreter can load, BEFORE it is
	// copied into extension_dir. The publisher gives no checksum and no signature,
	// so this establishes that the file is even an object, and it is the only way
	// to notice a wrong architecture: the two archives use identical member names.
	if verr := verifyLoaderELF(member); verr != nil {
		return "", "", false, fmt.Errorf("%w: %v", errLoaderArtifact, verr)
	}

	// 4. Copy the loader into extension_dir from the checked descriptor, so
	// nothing can be swapped in between the check and the copy.
	soDst = filepath.Join(extDir, "ioncube_loader_lin_"+s.Version+".so")
	if cerr := copyFromMember(member, soDst); cerr != nil {
		return "", "", false, fmt.Errorf("copy the IonCube Loader: %w", cerr)
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(soDst, 0644)

	// 5. Write an .ini that loads the extension before OPcache through the 00 prefix.
	iniPath = filepath.Join(s.IniDir, "00-ioncube.ini")
	iniContent := "; IonCube Loader must load before OPcache\nzend_extension = " + soDst + "\n"
	// #nosec G306 -- root-owned system integration file its daemon must read; no secret stored here (secrets use 0600/0640).
	if werr := os.WriteFile(iniPath, []byte(iniContent), 0644); werr != nil {
		return "", "", false, fmt.Errorf("write the IonCube Loader configuration: %w", werr)
	}

	// 6. Reload PHP-FPM.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the service name comes from the version metadata.
	if out, rerr := exec.CommandContext(ctx, "systemctl", "reload-or-restart", s.Service).CombinedOutput(); rerr != nil {
		return "", "", false, fmt.Errorf("reload PHP-FPM: %w: %s", rerr, strings.TrimSpace(string(out)))
	}

	// 7. Verify that php -m reports IonCube.
	verifyCtx, vc := context.WithTimeout(ctx, 5*time.Second)
	defer vc()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the version was matched against the whitelist.
	mOut, _ := exec.CommandContext(verifyCtx, s.PHPBin, "-m").Output()
	loaded = strings.Contains(strings.ToLower(string(mOut)), "ioncube")
	return soDst, iniPath, loaded, nil
}

// ionCubeLoaderPresent reports whether the version already carries the loader
// .ini. The startup heal skips a version that has it, so a healthy server never
// downloads the archive or reloads a pool. It tests the .ini rather than the .so
// in extension_dir, because the latter needs a php exec per version on every
// boot, the exact cost internal/phpversion's cache exists to avoid; the manual
// button re-installs a version whose extension_dir moved under it.
func ionCubeLoaderPresent(s Version) bool {
	_, err := os.Stat(filepath.Join(s.IniDir, "00-ioncube.ini"))
	return err == nil
}

// IonCubeInstall installs the IonCube zend_extension for a PHP version.
func (h *Handlers) IonCubeInstall(w http.ResponseWriter, r *http.Request) {
	var req ioncubeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s, ok := versionByID(req.Version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	stageDir, cleanup, err := ionCubeStage(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to prepare the IonCube Loader")
		return
	}
	defer cleanup()

	soDst, iniPath, loaded, err := installIonCubeForVersion(ctx, s, stageDir)
	if err != nil {
		switch {
		case errors.Is(err, errMemberMissing):
			httpx.WriteError(w, http.StatusBadRequest, "IonCube Loader is unavailable for PHP "+req.Version)
		case errors.Is(err, errLoaderArtifact):
			httpx.WriteError(w, http.StatusBadGateway, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to install the IonCube Loader")
		}
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok":            true,
		"version":       req.Version,
		"shared_object": soDst,
		"ini":           iniPath,
		"loaded":        loaded,
	})
}

// IonCubeRemove deletes the .ini and shared object, then reloads PHP-FPM.
func (h *Handlers) IonCubeRemove(w http.ResponseWriter, r *http.Request) {
	var req ioncubeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s, ok := versionByID(req.Version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}
	iniPath := filepath.Join(s.IniDir, "00-ioncube.ini")
	_ = os.Remove(iniPath)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	extOut, _ := exec.Command(s.PHPBin, "-r", "echo ini_get('extension_dir');").Output()
	extDir := strings.TrimSpace(string(extOut))
	if extDir != "" {
		_ = os.Remove(filepath.Join(extDir, "ioncube_loader_lin_"+req.Version+".so"))
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("systemctl", "reload-or-restart", s.Service).CombinedOutput()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "version": req.Version})
}

// HealIonCube installs the IonCube Loader for every installed PHP version that
// lacks it, so a fresh install and every existing one end up with the loader on
// each server start. It first lists the versions that are missing it and returns
// without downloading the archive when none are, so a healthy fleet pays only a
// few os.Stat calls. Each version is installed fail-soft: a version that cannot
// take the loader logs a line and the rest still get theirs.
func HealIonCube(ctx context.Context) {
	var missing []Version
	for _, s := range Versions() {
		if !ionCubeLoaderPresent(s) {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	stageDir, cleanup, err := ionCubeStage(ctx)
	if err != nil {
		log.Printf("ioncube heal: %v", err)
		return
	}
	defer cleanup()
	for _, s := range missing {
		if _, _, _, ierr := installIonCubeForVersion(ctx, s, stageDir); ierr != nil {
			log.Printf("ioncube heal: PHP %s: %v", s.Version, ierr)
			continue
		}
		log.Printf("ioncube heal: installed the loader for PHP %s", s.Version)
	}
}

// RunIonCubeInstallIfAsked answers "-ioncube-install <version>" on this binary
// and reports whether it did. A PHP install job appends this call so the loader
// is ready within the same detached job. It answers before config.Load for the
// reason the antivirus workers do: installing the loader needs the archive URL
// and the interpreter path, not the JWT secret or a database connection.
func RunIonCubeInstallIfAsked() bool {
	if len(os.Args) < 3 || (os.Args[1] != "-"+ionCubeInstallFlag && os.Args[1] != "--"+ionCubeInstallFlag) {
		return false
	}
	version := os.Args[2]
	s, ok := versionByID(version)
	if !ok {
		fmt.Fprintf(os.Stderr, "ioncube: PHP %s is not installed\n", version)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	stageDir, cleanup, err := ionCubeStage(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ioncube: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	if _, _, _, ierr := installIonCubeForVersion(ctx, s, stageDir); ierr != nil {
		fmt.Fprintf(os.Stderr, "ioncube: %v\n", ierr)
		os.Exit(1)
	}
	fmt.Printf("ioncube: installed the loader for PHP %s\n", version)
	return true
}

// IonCubeInstallShell returns the shell that installs the loader for a freshly
// installed PHP version, by re-invoking this same binary in its hardened
// -ioncube-install mode. It is wired into phpversion.IonCubePostInstall from
// main, so internal/phpversion appends it to the install job without importing
// this package. A failure is a WARNING, not a failed PHP install: the loader is
// optional and both the startup heal and the manual button retry it. An empty
// return (the binary path could not be resolved) injects nothing.
func IonCubeInstallShell(version string) string {
	self, err := os.Executable()
	if err != nil || strings.TrimSpace(self) == "" {
		return ""
	}
	return "\n" + ionCubeShellQuote(self) + " -" + ionCubeInstallFlag + " " + ionCubeShellQuote(version) +
		` || echo "WARNING: the IonCube Loader was not installed for PHP ` + version + `"` + "\n"
}

// ionCubeShellQuote renders a value as a single-quoted shell word.
func ionCubeShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// maxLoaderRedirects bounds the redirect chain. Go's own default is 10; the
// number is written out here because the policy below replaces the default
// entirely and a policy that forgets to count is a policy that loops.
const maxLoaderRedirects = 5

// loaderClient refuses a redirect that leaves TLS.
//
// http.DefaultClient follows a redirect from https to plain http without a
// word. Measured with a real Go client against a TLS server redirecting to a
// plain one: the request started at https, ended at http, and the body came
// back over the plaintext hop. So the shipped https:// address proves nothing
// on its own about how the bytes arrived, and these bytes become a
// zend_extension loaded into every PHP process on the server.
//
// The test is against the FIRST request rather than the previous hop, so a
// chain cannot step down through an intermediate. A download that started on
// plain http is left alone: SERVIKA_IONCUBE_URL accepts one deliberately
// (config.EnvURL allows http), and refusing there would break an operator's
// internal mirror rather than close anything.
func loaderClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxLoaderRedirects {
				return fmt.Errorf("stopped after %d redirects", maxLoaderRedirects)
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing a redirect from https to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

func download(ctx context.Context, url, destination string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := loaderClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}
