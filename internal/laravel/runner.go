// Package laravel provides per-domain Laravel Toolkit operations.
package laravel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"servika/internal/config"
)

const (
	outputLimit  = 64 << 10
	shortTimeout = 120 * time.Second
	systemPath   = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	cronDir      = "/etc/cron.d"
	unitDir      = "/etc/systemd/system"
	logSubdir    = "logs"
)

func composerBin() string { return config.ComposerBin() }
func logRootDir() string  { return config.LaravelLogDir() }

const badURLChars = "\"'`$();|&<>\\"

// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
func ensureLogRoot() { _ = os.MkdirAll(logRootDir(), 0755) }

var execSem sync.Map

func execGate(systemUser string) func() {
	v, _ := execSem.LoadOrStore(systemUser, make(chan struct{}, 3))
	c := v.(chan struct{})
	c <- struct{}{}
	return func() { <-c }
}

var domainLocks sync.Map

func lockDomain(id int64) func() {
	v, _ := domainLocks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

var (
	reArg         = regexp.MustCompile(`^[A-Za-z0-9:_.,=/@-]+$`)
	reComposerPkg = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*)/[a-z0-9]([a-z0-9._-]*)(:[\^~<>=0-9.* |,-]+)?$`)
	reNodeVersion = regexp.MustCompile(`^[0-9]{1,2}(\.[0-9]{1,3}){0,2}$`)
	reANSI        = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")

	// Queue worker fields. Each of these reaches a systemd unit file, so the
	// character classes are the boundary rather than a tidiness rule.
	reWorkerName       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reWorkerConnection = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	// The first character must be alphanumeric. A leading dash reads as a FLAG
	// to Laravel's argument parser, so "--daemon" in the queue list would pass
	// an arbitrary artisan option the panel never offered.
	reQueueName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

func validSystemUser(systemUser string) bool {
	return strings.HasPrefix(systemUser, "c_") && len(systemUser) > 2
}

func cleanANSI(s string) string { return reANSI.ReplaceAllString(s, "") }

func phpBin(version string) string {
	code := strings.ReplaceAll(strings.TrimSpace(version), ".", "")
	if code != "" {
		candidate := "/usr/bin/php" + code
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/usr/bin/php"
}

func safeAppDir(systemUser, appRoot string) (string, error) {
	if !validSystemUser(systemUser) {
		return "", fmt.Errorf("invalid system user")
	}
	rel := strings.Trim(strings.TrimSpace(appRoot), "/")
	if rel == "" {
		rel = "public_html"
	}
	if strings.Contains(rel, "..") || !regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(rel) {
		return "", fmt.Errorf("invalid application directory")
	}
	if rel != "public_html" && !strings.HasPrefix(rel, "public_html/") {
		return "", fmt.Errorf("application directory must be under public_html")
	}
	base := "/home/" + systemUser + "/public_html"
	abs := filepath.Clean("/home/" + systemUser + "/" + rel)
	if abs != base && !strings.HasPrefix(abs, base+"/") {
		return "", fmt.Errorf("application directory cannot leave public_html")
	}
	check := abs
	for check == base || strings.HasPrefix(check, base+"/") {
		if real, err := filepath.EvalSymlinks(check); err == nil {
			if real != base && !strings.HasPrefix(real, base+"/") {
				return "", fmt.Errorf("application directory cannot leave public_html through a symlink")
			}
			break
		}
		if check == base {
			break
		}
		check = filepath.Dir(check)
	}
	return abs, nil
}

func tenantEnv(systemUser string) []string {
	return []string{
		"HOME=/home/" + systemUser,
		"USER=" + systemUser,
		"LOGNAME=" + systemUser,
		"PATH=" + systemPath,
		"COMPOSER_HOME=/home/" + systemUser + "/.composer",
		"COMPOSER_ALLOW_SUPERUSER=0",
		"NPM_CONFIG_CACHE=/home/" + systemUser + "/.npm",
		"LANG=C.UTF-8",
	}
}

func TenantExec(ctx context.Context, systemUser, cwd, bin string, args ...string) (string, bool) {
	return tenantExecEnv(ctx, systemUser, cwd, tenantEnv(systemUser), bin, args...)
}

func tenantExecEnv(ctx context.Context, systemUser, cwd string, env []string, bin string, args ...string) (string, bool) {
	if !validSystemUser(systemUser) {
		return "invalid system user", false
	}
	real, err := filepath.EvalSymlinks(cwd)
	if err != nil || (real != "/home/"+systemUser && !strings.HasPrefix(real, "/home/"+systemUser+"/")) {
		return "working directory is outside the tenant home", false
	}
	release := execGate(systemUser)
	defer release()
	ctx, cancel := context.WithTimeout(ctx, shortTimeout)
	defer cancel()
	argv := append([]string{"-u", systemUser, "--", bin}, args...)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.CommandContext(ctx, "runuser", argv...)
	cmd.Dir = real
	cmd.Env = env
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	runErr := cmd.Run()
	out := cleanANSI(buf.String())
	if len(out) > outputLimit {
		out = out[len(out)-outputLimit:]
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out + "\n\n[timeout: command did not finish within 120 seconds and was terminated]", false
	}
	return out, runErr == nil
}

func systemdRunDetached(systemUser, cwd, unit, logPath string, argv ...string) error {
	if !validSystemUser(systemUser) {
		return fmt.Errorf("invalid system user")
	}
	real, err := filepath.EvalSymlinks(cwd)
	if err != nil || (real != "/home/"+systemUser && !strings.HasPrefix(real, "/home/"+systemUser+"/")) {
		return fmt.Errorf("working directory is outside the tenant home")
	}
	ensureLogRoot()
	_ = os.Remove(logPath)
	args := []string{
		"--unit=" + unit,
		"--uid=" + systemUser, "--gid=" + systemUser,
		"--working-directory=" + real,
		"--slice=servika-" + systemUser + ".slice",
		"-p", "RuntimeMaxSec=1800",
		"-p", "StandardOutput=append:" + logPath,
		"-p", "StandardError=append:" + logPath,
		"-E", "HOME=/home/" + systemUser,
		"-E", "PATH=" + systemPath,
		"-E", "COMPOSER_HOME=/home/" + systemUser + "/.composer",
		"-E", "COMPOSER_ALLOW_SUPERUSER=0",
		"-E", "NPM_CONFIG_CACHE=/home/" + systemUser + "/.npm",
		"-E", "LANG=C.UTF-8",
		"--",
	}
	args = append(args, argv...)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if err := exec.Command("systemd-run", args...).Run(); err != nil {
		return fmt.Errorf("detached command start failed")
	}
	return nil
}

func unitStatus(unit string) string {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, _ := exec.Command("systemctl", "show", "-p", "ActiveState", "--value", unit).Output()
	return strings.TrimSpace(string(out))
}

func fileTail(path string, max int64) string {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if fi.Size() > max {
		_, _ = f.Seek(-max, io.SeekEnd)
	}
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return cleanANSI(string(b))
}

func validRepoURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" || len(u) > 512 {
		return false
	}
	for _, c := range u {
		if c <= ' ' || strings.ContainsRune(badURLChars, c) {
			return false
		}
	}
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "git@") || strings.HasPrefix(u, "ssh://")
}

func readEnvFile(appDir string) (string, error) {
	path := filepath.Join(appDir, ".env")
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf(".env is not a regular file")
	}
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeEnvFile(systemUser, appDir, content string) error {
	if len(content) > 5<<20 {
		return fmt.Errorf(".env is too large")
	}
	dst := filepath.Join(appDir, ".env")
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("runuser", "-u", systemUser, "--", "/usr/bin/tee", dst)
	cmd.Env = tenantEnv(systemUser)
	cmd.Stdin = strings.NewReader(content)
	var errBuf bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf(".env write failed")
	}
	return nil
}
