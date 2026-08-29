package phpext

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Asynchronous PECL extension installation.
//
// A PECL build compiles from source and first installs PEAR plus the development
// toolchain (gcc/make/autoconf), which takes minutes, so a synchronous request
// hangs past the router's timeout and the operator sees nothing. The install runs
// in a goroutine and the handler returns a job id at once; the page polls a status
// endpoint for the live step, percent and combined output. The job store lives only
// in memory: a restart loses it, which at worst leaves a half-built extension the
// operator can reinstall, so there is nothing to heal in a database.

type peclState string

const (
	peclRunning peclState = "running"
	peclDone    peclState = "done"
	peclFailed  peclState = "failed"
)

// peclJob tracks one running install. Every field is read by the poll goroutine
// while the worker writes it, so all access is under mu. step and errMsg are stable
// CODES the frontend localizes, never English sentences, because the extensions
// screen renders twelve languages; the raw tool output stays in log for detail.
type peclJob struct {
	mu      sync.Mutex
	state   peclState
	step    string // a stable step code (see the step codes below)
	percent int
	method  string // "dnf" | "pecl"
	errMsg  string // a stable error code, empty until a failure
	log     string // the tail of the combined output, capped
	ended   time.Time
}

const peclLogLimit = 8192

func (j *peclJob) setStep(step string, percent int) {
	j.mu.Lock()
	j.step = step
	j.percent = percent
	j.mu.Unlock()
}

func (j *peclJob) setMethod(method string) {
	j.mu.Lock()
	j.method = method
	j.mu.Unlock()
}

func (j *peclJob) appendLog(b []byte) {
	j.mu.Lock()
	j.log += string(b)
	if len(j.log) > peclLogLimit {
		j.log = j.log[len(j.log)-peclLogLimit:]
	}
	j.mu.Unlock()
}

func (j *peclJob) fail(msg string) {
	j.mu.Lock()
	j.state = peclFailed
	j.errMsg = msg
	j.ended = time.Now()
	j.mu.Unlock()
}

func (j *peclJob) finish(step string) {
	j.mu.Lock()
	j.state = peclDone
	j.step = step
	j.percent = 100
	j.ended = time.Now()
	j.mu.Unlock()
}

func (j *peclJob) snapshot() (state peclState, step string, percent int, method, errMsg, logs string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state, j.step, j.percent, j.method, j.errMsg, j.log
}

// peclJobs maps an unguessable id to its job. A finished job is left in the map so
// a late poll still reads the final state; prunePECLJobs drops terminal jobs older
// than ten minutes.
var peclJobs sync.Map // id -> *peclJob

func newPECLJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func prunePECLJobs() {
	cutoff := time.Now().Add(-10 * time.Minute)
	peclJobs.Range(func(key, value any) bool {
		job := value.(*peclJob)
		job.mu.Lock()
		terminal := job.state != peclRunning && !job.ended.IsZero() && job.ended.Before(cutoff)
		job.mu.Unlock()
		if terminal {
			peclJobs.Delete(key)
		}
		return true
	})
}

// peclPrefix returns the package-name prefix for the version: "php82" on Remi,
// "php" on the AppStream build.
func peclPrefix(s Version) string {
	if strings.HasPrefix(s.Service, "php") && strings.Contains(s.Service, "-php-fpm") && s.Service != "php-fpm" {
		return strings.Split(s.Service, "-")[0]
	}
	return "php"
}

// peclCandidates lists the prebuilt DNF package names to probe, most likely first.
//
// Two classes of extension ship as a prebuilt package. A BUNDLED extension
// (gmp, imap, mbstring, gd, intl, bcmath) comes with the PHP source tree and is
// packaged as "<prefix>-php-<name>" with no "pecl" segment; it is NOT in the
// PECL repository, so a `pecl install` of it fails. A PECL extension (redis,
// mongodb, imagick) is packaged as "<prefix>-php-pecl-<name>". The bundled name
// is probed FIRST, because that is the only way a bundled extension installs
// without a doomed compile.
func peclCandidates(prefix, pkg string) []string {
	if prefix == "php" {
		return []string{
			"php-" + pkg, // bundled (AppStream): php-gmp, php-imap
			"php-pecl-" + pkg,
			"php-pecl-" + pkg + "6",
			"php-pecl-" + pkg + "5",
			"php-pecl-" + pkg + "3",
		}
	}
	return []string{
		prefix + "-php-" + pkg,               // bundled: php83-php-gmp, php83-php-imap
		prefix + "-php-pecl-" + pkg,          // base name
		prefix + "-php-pecl-" + pkg + "-im7", // im7 suffix for imagick
		prefix + "-php-pecl-" + pkg + "6",    // version suffix (redis6, mongodb1)
		prefix + "-php-pecl-" + pkg + "5",    // redis5 legacy
		prefix + "-php-pecl-" + pkg + "3",    // xdebug3
	}
}

// runPECLInstall installs one extension for one version, feeding progress into
// job. It recovers from a panic, because this runs in a bare goroutine where an
// unrecovered panic would take the whole panel process down. It uses a background
// context with its own timeout, never a request context, which is cancelled when
// the handler returns the job id.
func runPECLInstall(job *peclJob, s Version, pkg string) {
	defer func() {
		if p := recover(); p != nil {
			job.fail("internal")
			log.Printf("phpext: PECL install job panicked: %v", p)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), extensionInstallTimeout)
	defer cancel()

	prefix := peclPrefix(s)

	// 1. Try a prebuilt DNF package first: the fast path, no compile.
	job.setStep("probing", 10)
	dnfPkg := ""
	for _, name := range peclCandidates(prefix, pkg) {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); the package name is built from a validated identifier (safeName).
		if exec.CommandContext(ctx, "dnf", "info", "--quiet", name).Run() == nil {
			dnfPkg = name
			break
		}
	}
	if dnfPkg != "" {
		job.setMethod("dnf")
		if !peclInstallDNF(ctx, job, dnfPkg) {
			return
		}
		reloadFPM(ctx, job, s)
		job.finish("done")
		return
	}

	// 2. PECL build path. Auto-install PEAR and the build toolchain when missing,
	// instead of failing with "manual install required".
	job.setMethod("pecl")
	if !peclEnsureToolchain(ctx, job, s, prefix) {
		return
	}
	if !peclBuild(ctx, job, s, pkg) {
		return
	}
	if !peclWriteINI(job, s, pkg) {
		return
	}
	reloadFPM(ctx, job, s)
	job.finish("done")
}

// peclInstallDNF installs the prebuilt package; it reports false on failure.
func peclInstallDNF(ctx context.Context, job *peclJob, dnfPkg string) bool {
	job.setStep("installing_dnf", 55)
	job.appendLog([]byte("dnf install " + dnfPkg + "\n")) // the resolved name goes in the log, not the localizable step
	// #nosec G204 G702 -- fixed binary with separate args (no shell); dnfPkg is one of the validated candidate names.
	out, err := exec.CommandContext(ctx, "dnf", "install", "-y", dnfPkg).CombinedOutput()
	job.appendLog(out)
	if err != nil {
		job.fail("dnf_install_failed")
		return false
	}
	return true
}

// peclEnsureToolchain installs PEAR (when pecl is missing) and the build tools; it
// reports false on failure.
func peclEnsureToolchain(ctx context.Context, job *peclJob, s Version, prefix string) bool {
	if _, err := os.Stat(s.PECLBin); err != nil {
		job.setStep("installing_pear", 25)
		// #nosec G204 G702 -- fixed binary with separate args (no shell); prefix is derived from the installed service name, never request input.
		out, err := exec.CommandContext(ctx, "dnf", "install", "-y", prefix+"-php-pear").CombinedOutput()
		job.appendLog(out)
		if err != nil {
			job.fail("pear_failed")
			return false
		}
		if _, err := os.Stat(s.PECLBin); err != nil {
			job.fail("pear_missing")
			return false
		}
	}
	// pecl install compiles from source, so php-devel plus gcc/make/autoconf are required.
	job.setStep("toolchain", 40)
	devel := prefix + "-php-devel"
	if prefix == "php" {
		devel = "php-devel"
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); devel is derived from the installed service name.
	out, err := exec.CommandContext(ctx, "dnf", "install", "-y", devel, "gcc", "make", "autoconf").CombinedOutput()
	job.appendLog(out)
	if err != nil {
		job.fail("toolchain_failed")
		return false
	}
	return true
}

// peclBuild runs the source build; it reports false on failure.
func peclBuild(ctx context.Context, job *peclJob, s Version, pkg string) bool {
	job.setStep("compiling", 60)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); pkg is a validated identifier (safeName).
	cmd := exec.CommandContext(ctx, s.PECLBin, "install", "-f", pkg)
	cmd.Env = peclEnvironment(s.PHPBin)
	out, err := cmd.CombinedOutput()
	job.appendLog(out)
	if err != nil {
		job.fail("build_failed")
		return false
	}
	return true
}

// peclWriteINI writes the extension's ini file when it is missing; it reports false
// on failure, because a swallowed write error would report a successful install
// while the extension never loads.
func peclWriteINI(job *peclJob, s Version, pkg string) bool {
	job.setStep("writing_ini", 85)
	iniPath := filepath.Join(s.IniDir, "50-"+pkg+".ini")
	if _, err := os.Stat(iniPath); err == nil {
		return true
	}
	// #nosec G306 -- root-owned system integration file its daemon must read; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(iniPath, []byte("extension="+pkg+".so\n"), 0644); err != nil {
		job.fail("ini_failed")
		return false
	}
	return true
}

// reloadFPM reloads the version's PHP-FPM service. A failure is logged and recorded
// in the job log but is not fatal: the extension loads on the next restart.
func reloadFPM(ctx context.Context, job *peclJob, s Version) {
	job.setStep("restarting", 92)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the service name comes from the installed version, never request input.
	out, err := exec.CommandContext(ctx, "systemctl", "reload-or-restart", s.Service).CombinedOutput()
	job.appendLog(out)
	if err != nil {
		log.Printf("phpext: php-fpm reload after PECL install failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
}
