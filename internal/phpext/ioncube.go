// IonCube Loader installation and removal downloads the commercial loader from ioncube.com.
package phpext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// 1. Read PHP extension_dir.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	extOut, err := exec.CommandContext(ctx, s.PHPBin, "-r", "echo ini_get('extension_dir');").Output()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read PHP extension directory")
		return
	}
	extDir := strings.TrimSpace(string(extOut))
	if extDir == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "pHP extension directory is empty")
		return
	}

	// 2. Create a temporary directory and download the archive.
	tmpDir, err := os.MkdirTemp("", "ioncube-*")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create temporary directory")
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tarPath := filepath.Join(tmpDir, "ioncube.tar.gz")
	if err := download(ctx, ionCubeURL(), tarPath); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to download IonCube Loader")
		return
	}

	// 3. Extract the archive.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(ctx, "tar", "xzf", tarPath, "-C", tmpDir).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to extract IonCube Loader archive")
		return
	}

	// 4. Select the shared object matching the PHP version.
	//
	// The member is opened rather than stat'ed, because os.Stat FOLLOWS a
	// symlink and a symlink is the one member kind extraction still creates
	// freely. See internal/phpext/loaderfile.go for the measurement.
	soSrc := filepath.Join(tmpDir, "ioncube", "ioncube_loader_lin_"+req.Version+".so")
	member, err := openArchiveMember(soSrc)
	if err != nil {
		if errors.Is(err, errMemberMissing) {
			// A missing non-thread-safe loader means the version is unavailable.
			httpx.WriteError(w, http.StatusBadRequest,
				"IonCube Loader is unavailable for PHP "+req.Version)
			return
		}
		httpx.WriteError(w, http.StatusBadGateway,
			"the downloaded IonCube archive does not carry a plain file for PHP "+req.Version)
		return
	}
	defer func() { _ = member.Close() }()

	// 5. Copy the loader into extension_dir, from the descriptor that was
	// checked rather than from the path, so nothing can be swapped in between.
	soDst := filepath.Join(extDir, "ioncube_loader_lin_"+req.Version+".so")
	if err := copyFromMember(member, soDst); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to copy IonCube Loader")
		return
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(soDst, 0644)

	// 6. Write an .ini file that loads the extension before OPcache through the 00 prefix.
	iniPath := filepath.Join(s.IniDir, "00-ioncube.ini")
	iniContent := "; IonCube Loader must load before OPcache\nzend_extension = " + soDst + "\n"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(iniPath, []byte(iniContent), 0644); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to write IonCube Loader configuration")
		return
	}

	// 7. Reload PHP-FPM.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(ctx, "systemctl", "reload-or-restart", s.Service).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError,
			"failed to reload PHP-FPM")
		return
	}

	// 8. Verify that php -m reports IonCube.
	verifyCtx, vc := context.WithTimeout(r.Context(), 5*time.Second)
	defer vc()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	mOut, _ := exec.CommandContext(verifyCtx, s.PHPBin, "-m").Output()
	loaded := strings.Contains(strings.ToLower(string(mOut)), "ioncube")

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
