package hostapps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"servika/internal/config"
)

// maxArchiveBytes bounds what a download may write to disk.
//
// The archive is third-party input arriving over the network, so the ceiling is
// enforced while STREAMING rather than read off Content-Length, which the server
// supplies and can simply be wrong. The value clears the largest product in the
// catalog (Grafana, measured at about 120 MB) with room to spare.
const maxArchiveBytes = 1 << 30

const downloadTimeout = 20 * time.Minute

// Fetch downloads a release archive and verifies it against the catalog digest.
//
// The digest is checked BEFORE the file is used for anything, and a mismatch
// deletes the download. The archive becomes a program this server executes, so
// an unverified copy is not kept around for a later attempt to pick up.
//
// The client is deliberately NOT wrapped in netguard. That guard exists for a
// host a CUSTOMER named; this URL comes from the admin-only catalog, and an
// operator serving these archives from an internal mirror on a private address
// is a supported installation rather than an attack.
func Fetch(ctx context.Context, url, digest, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return refuse(ReasonDownload, "the download URL could not be used: %v", err)
	}
	client := &http.Client{Timeout: downloadTimeout}
	response, err := client.Do(request)
	if err != nil {
		return refuse(ReasonDownload, "the download failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return refuse(ReasonDownload, "the download answered %s", response.Status)
	}

	// #nosec G304 -- dest is built by this package from TMPDIR and a validated code.
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create the download file: %w", err)
	}
	sum := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, sum), io.LimitReader(response.Body, maxArchiveBytes+1))
	closeErr := file.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(dest)
		return refuse(ReasonDownload, "the download was interrupted: %v", copyErr)
	case closeErr != nil:
		_ = os.Remove(dest)
		return fmt.Errorf("close the download file: %w", closeErr)
	case written > maxArchiveBytes:
		_ = os.Remove(dest)
		return refuse(ReasonDownload, "the download is larger than this installs")
	}

	got := hex.EncodeToString(sum.Sum(nil))
	if got != digest {
		_ = os.Remove(dest)
		return refuse(ReasonChecksum,
			"the download does not match the recorded checksum, so it was discarded")
	}
	return nil
}

// Unpack lays a downloaded archive out under the install directory.
//
// Extraction goes into a STAGING directory and the wanted level is then promoted
// into place, rather than trusting an unpacker's own strip option. That gives
// one code path for every archive kind and makes the shape assumption explicit:
// an archive whose layout changed between versions is refused here, with its own
// message, instead of silently producing a tree whose binary is one level deeper
// than the catalog says.
//
// GNU tar 1.35 on AlmaLinux 10 refuses a member whose name contains "..", writes
// nothing for it and exits 2, and strips a leading "/" (measured), so extraction
// itself cannot reach outside the staging directory. What it DOES create is a
// symlink member pointing anywhere, which is why the binary is later opened
// O_NOFOLLOW and why the ownership pass runs with -h.
func Unpack(ctx context.Context, entry Entry, archive, installDir string) error {
	staging := filepath.Join(installDir, ".staging")
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("clear the staging directory: %w", err)
	}
	// #nosec G301 -- root-owned; the tree is handed to the service account afterwards.
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return fmt.Errorf("create the staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	switch entry.ArchiveKind {
	case "binary":
		target := filepath.Join(staging, entry.BinaryPath)
		// #nosec G301 -- root-owned; the tree is handed to the service account afterwards.
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create the binary directory: %w", err)
		}
		if err := copyFile(archive, target); err != nil {
			return err
		}
	case "zip":
		if err := runTool(ctx, "unzip", "-q", "-o", archive, "-d", staging); err != nil {
			return err
		}
	default:
		flag := map[string]string{"tar.gz": "-xzf", "tar.xz": "-xJf", "tar.bz2": "-xjf"}[entry.ArchiveKind]
		if flag == "" {
			return refuse(ReasonUnpack, "%q is not an archive kind this understands", entry.ArchiveKind)
		}
		if err := runTool(ctx, "tar", flag, archive, "-C", staging, "--no-same-owner"); err != nil {
			return err
		}
	}

	source, err := descend(staging, entry.StripComponents)
	if err != nil {
		return err
	}
	return promote(source, installDir)
}

// descend walks the requested number of levels into the unpacked tree, refusing
// any level that does not hold exactly one directory. Each step opens with
// O_NOFOLLOW and asserts IsDir() on the DESCRIPTOR, so a symlink member cannot
// stand in for the level it names.
func descend(root string, levels int) (string, error) {
	current := root
	for range levels {
		names, err := os.ReadDir(current)
		if err != nil {
			return "", fmt.Errorf("read the unpacked tree: %w", err)
		}
		if len(names) != 1 || !names[0].IsDir() {
			return "", refuse(ReasonUnpack,
				"the archive does not have the single top directory the catalog expects")
		}
		next := filepath.Join(current, names[0].Name())
		// #nosec G304 -- a path this package built inside its own staging directory.
		handle, err := os.OpenFile(next, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", refuse(ReasonUnpack, "the archive's top entry is not a plain directory")
		}
		info, statErr := handle.Stat()
		_ = handle.Close()
		if statErr != nil || !info.IsDir() {
			return "", refuse(ReasonUnpack, "the archive's top entry is not a plain directory")
		}
		current = next
	}
	return current, nil
}

// promote moves the unpacked content into place. A rename within one filesystem
// is atomic per entry, and staging is a subdirectory of the destination, so this
// never crosses a device.
func promote(source, installDir string) error {
	names, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read the unpacked tree: %w", err)
	}
	for _, name := range names {
		target := filepath.Join(installDir, name.Name())
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("clear %s: %w", name.Name(), err)
		}
		if err := os.Rename(filepath.Join(source, name.Name()), target); err != nil {
			return fmt.Errorf("install %s: %w", name.Name(), err)
		}
	}
	return nil
}

func copyFile(source, target string) error {
	// #nosec G304 -- both paths are built by this package.
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open the download: %w", err)
	}
	defer func() { _ = in.Close() }()
	// 0750 rather than 0755: the tenants share this host, and there is no reason
	// for a customer account to be able to execute the operator's own programs.
	// The tree is handed to the service account by PrepareDirectories afterwards.
	// #nosec G302 G304 -- an executable this server runs; the world bit is already off and both paths are built by this package.
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o750)
	if err != nil {
		return fmt.Errorf("create the binary: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("write the binary: %w", err)
	}
	return out.Close()
}

// runTool runs an unpacking tool under the caller's deadline. The archive was
// written by a remote server, so a tool that never returns must not hold the
// install job open for good.
func runTool(ctx context.Context, name string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(ctx, unpackTimeout)
	defer cancel()
	output, err := systemCommandContext(ctx, name, arguments...).CombinedOutput()
	if err != nil {
		return refuse(ReasonUnpack, "%s failed: %s", name, tail(string(output), 400))
	}
	return nil
}

const unpackTimeout = 15 * time.Minute

func tail(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) > limit {
		return text[len(text)-limit:]
	}
	return text
}

// EnsureUser creates the application's own Linux account.
//
// It is a system account with no password, no shell and no /home entry: the
// account exists to own a directory and run one process, and nothing on this
// server should be able to log in as it.
func EnsureUser(code string) (string, error) {
	name := SystemUser(code)
	if !ValidSystemUser(name) {
		return "", refuse(ReasonBadEntry, "%q is not a name this hands out", name)
	}
	if _, err := systemCommand("id", "-u", name).Output(); err == nil {
		return name, nil
	}
	output, err := systemCommand("useradd",
		"--system", "--no-create-home", "--shell", "/sbin/nologin",
		"--home-dir", InstallDir(code), name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("create the account %s: %s: %w", name, tail(string(output), 200), err)
	}
	return name, nil
}

// RemoveUser deletes the application's account.
//
// The name is checked against this package's own prefix first, because the call
// deletes a Linux account by name and the tenant accounts share the host.
func RemoveUser(name string) error {
	if !ValidSystemUser(name) {
		return refuse(ReasonBadEntry, "%q is not a name this package hands out", name)
	}
	// A missing account is not an error: the removal path must be able to finish
	// a half-completed install.
	if _, err := systemCommand("id", "-u", name).Output(); err != nil {
		return nil
	}
	if output, err := systemCommand("userdel", name).CombinedOutput(); err != nil {
		return fmt.Errorf("remove the account %s: %s: %w", name, tail(string(output), 200), err)
	}
	return nil
}

// PrepareDirectories creates the install and data directories and hands them to
// the application's account.
//
// The ownership pass runs with -h so a symlink member that survived extraction
// is re-owned as the LINK rather than dereferenced. Measured on AlmaLinux 10,
// plain `chown -R` already leaves the target of a link alone (coreutils treats
// -R as -P), and -h additionally fixes the link node itself.
func PrepareDirectories(code, systemUser string) error {
	installDir := InstallDir(code)
	// #nosec G301 -- root-owned parent; the application's own tree is chowned below.
	if err := os.MkdirAll(DataDir(code), 0o755); err != nil {
		return fmt.Errorf("create the application directories: %w", err)
	}
	if output, err := systemCommand("chown", "-h", "-R",
		systemUser+":"+systemUser, installDir).CombinedOutput(); err != nil {
		return fmt.Errorf("hand over the directory: %s: %w", tail(string(output), 200), err)
	}
	return nil
}

// VerifyBinary asserts that the catalog's binary really landed, as a regular
// file, and makes it executable.
//
// The open is O_NOFOLLOW with IsRegular() asserted on the DESCRIPTOR rather than
// on a separate stat of the path: a symlink member is the one thing extraction
// still creates freely, and chmod through a link would change the mode of
// whatever it points at.
func VerifyBinary(code, binaryPath string) (string, error) {
	if !validRelPath(binaryPath) {
		return "", refuse(ReasonBadEntry, "the binary path is not a relative path inside the archive")
	}
	full := filepath.Join(InstallDir(code), binaryPath)
	// #nosec G304 -- built from a validated code and a validated relative path.
	handle, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", refuse(ReasonBinaryMissing,
			"the archive does not contain %s where the catalog says it does", binaryPath)
	}
	defer func() { _ = handle.Close() }()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", refuse(ReasonBinaryMissing, "%s is not a plain file", binaryPath)
	}
	// 0750 for the same reason as the copy above: executable by the application's
	// own account and by nothing else on this host.
	if err := handle.Chmod(0o750); err != nil {
		return "", fmt.Errorf("make %s executable: %w", binaryPath, err)
	}
	return full, nil
}

// BackupData archives the data directory before a removal takes it away.
//
// Removal is the one operation here that cannot be undone, and the contents
// belong to the operator rather than to the panel: a Gitea removal takes every
// repository with it. The archive lands OUTSIDE the tree the removal deletes.
// A failure is reported to the caller rather than swallowed, because a removal
// that quietly kept no copy is worse than one that refused.
func BackupData(ctx context.Context, code string) (string, int64, error) {
	dataDir := DataDir(code)
	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		return "", 0, nil
	}
	// #nosec G301 -- root-owned backup directory holding operator data.
	if err := os.MkdirAll(config.HostAppBackupDir(), 0o700); err != nil {
		return "", 0, fmt.Errorf("create the backup directory: %w", err)
	}
	name := fmt.Sprintf("%s-%s.tar.gz", code, time.Now().UTC().Format("20060102-150405"))
	target := filepath.Join(config.HostAppBackupDir(), name)
	if err := runTool(ctx, "tar", "-czf", target, "-C", InstallDir(code), "data"); err != nil {
		return "", 0, err
	}
	stat, err := os.Stat(target)
	if err != nil {
		return "", 0, fmt.Errorf("read the archive back: %w", err)
	}
	return target, stat.Size(), nil
}

// TeardownFiles removes everything one application left on the host. It is best
// effort per step so a missing piece does not strand the rest.
func TeardownFiles(code string) {
	_, _ = systemCommand("systemctl", "disable", "--now", UnitName(code)).CombinedOutput()
	_ = os.Remove(UnitPath(code))
	_, _ = systemCommand("systemctl", "daemon-reload").CombinedOutput()
	_, _ = systemCommand("systemctl", "reset-failed", UnitName(code)).CombinedOutput()
	_ = os.Remove(EnvPath(code))
	_ = os.Remove(LogPath(code))
	_ = os.RemoveAll(InstallDir(code))
}
