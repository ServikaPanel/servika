// Package appbackup archives and restores the tree one application runs from.
//
// Both application kinds the panel manages need the same five steps and none of
// them is obvious: the unit is stopped first so nothing writes into the tree
// while tar reads it, the archive is written to a .part file and renamed only
// once its digest is taken, the restore keeps a copy of what it is about to
// replace, and a restore that leaves the application not answering is rolled
// back rather than reported as done.
//
// What differs between the two kinds is the unit control and the paths, so both
// arrive as a Target rather than being imported: internal/apps and
// internal/hostapps each name their own systemd helpers, and importing either
// from here would close an import cycle.
package appbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/apphealth"
	"servika/internal/logx"
)

const (
	// KeepDefault is how many archives one application keeps. The caller runs
	// the rotation, because the list lives in its own table.
	KeepDefault = 5
	// MaxSize refuses an archive that would fill the disk. A Gitea instance with
	// every repository in it is the largest thing measured here, and 20 GB is
	// well past it.
	MaxSize = 20 << 30

	createTimeout  = 10 * time.Minute
	restoreTimeout = 15 * time.Minute
	unitTimeout    = 20 * time.Second

	// The probe budget after a restore. apphealth's own budget is about eight
	// seconds; this bounds the whole wait including the delay.
	healthBudget = 25 * time.Second
	healthDelay  = 2 * time.Second
)

// ErrCorrupt reports an archive whose contents no longer match the digest taken
// when it was written. It is returned BEFORE anything is stopped or deleted.
var ErrCorrupt = errors.New("appbackup: the archive does not match its recorded digest")

// Target is one application to archive or restore.
type Target struct {
	// Dir is where this application's archives live. One directory per
	// application, so a rotation cannot reach another application's files.
	Dir string
	// Root is the directory a restore REPLACES. It is archived whole.
	Root string
	// Extra are further absolute paths to put in the archive: the unit file and
	// the EnvironmentFile. A missing one is skipped rather than refused, because
	// an application that has no env file is not a broken application.
	Extra []string
	// Port is probed after a restore. Zero skips the probe, which is all that
	// can be done for an application that binds nothing.
	Port int

	// Stop and Start control the unit. They are fields rather than package
	// functions because the two callers name different helpers.
	Stop  func(context.Context) error
	Start func(context.Context) error
}

// Archive is one file this package wrote.
type Archive struct {
	Path   string `json:"path"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

// command is a variable so a test can run the tar calls against a temporary
// tree. It is not operator configuration.
var command = exec.CommandContext

// Create stops the application, archives its tree and starts it again.
//
// The application is started again whatever happens, including on a failed tar:
// a backup that left the service down would be worse than no backup at all.
func Create(ctx context.Context, t Target) (Archive, error) {
	if err := t.validate(); err != nil {
		return Archive{}, err
	}
	// #nosec G301 -- root-owned; the archives carry the application's env file.
	if err := os.MkdirAll(t.Dir, 0o700); err != nil {
		return Archive{}, fmt.Errorf("create the backup directory: %w", err)
	}
	if err := t.stop(ctx); err != nil {
		return Archive{}, err
	}
	defer t.restart()

	stamp := time.Now().UTC().Format("20060102-150405")
	// The archive is written to .part and renamed only after its digest is
	// taken, so a run that dies mid-tar cannot leave a truncated file that looks
	// like a backup.
	temporary := filepath.Join(t.Dir, stamp+".tar.gz.part")
	final := filepath.Join(t.Dir, stamp+".tar.gz")
	kept := false
	defer func() {
		if !kept {
			_ = os.Remove(temporary)
		}
	}()

	if err := writeArchive(ctx, t, temporary); err != nil {
		return Archive{}, err
	}
	archive, err := sealArchive(temporary, final)
	if err != nil {
		return Archive{}, err
	}
	kept = true
	return archive, nil
}

// Restore puts an archive back and proves the application still answers.
//
// The digest is checked FIRST, before the unit is stopped and before anything is
// deleted: a corrupt archive must cost nothing.
func Restore(ctx context.Context, t Target, archive Archive) error {
	if err := t.validate(); err != nil {
		return err
	}
	if err := verify(archive); err != nil {
		return err
	}
	if err := t.stop(ctx); err != nil {
		return err
	}
	rollback, err := takeRollback(ctx, t)
	if err != nil {
		return err
	}
	if err := swapIn(ctx, t, archive.Path); err != nil {
		undo(t, rollback, err.Error())
		return err
	}
	if err := t.startAndProbe(ctx); err != nil {
		undo(t, rollback, err.Error())
		return fmt.Errorf("%w; the previous tree was put back", err)
	}
	_ = os.Remove(rollback)
	return nil
}

// Remove deletes one archive.
//
// The path comes out of a database row, and the row was written by this panel,
// but a delete that takes an absolute path is worth refusing on its own terms:
// only a normalised file sitting directly under dir is accepted.
func Remove(dir, path string) error {
	if path == "" || filepath.Clean(path) != path || filepath.Dir(path) != filepath.Clean(dir) {
		return fmt.Errorf("appbackup: %q is not an archive under %s", path, dir)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Digest is the SHA-256 of a file, hex encoded.
func Digest(path string) (string, error) {
	// #nosec G304 -- a path this package wrote, under the caller's own backup directory.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (t Target) validate() error {
	if !filepath.IsAbs(t.Dir) || !filepath.IsAbs(t.Root) {
		return fmt.Errorf("appbackup: the backup directory and the application root must be absolute")
	}
	if t.Stop == nil || t.Start == nil {
		return fmt.Errorf("appbackup: the target carries no unit control")
	}
	for _, path := range t.Extra {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("appbackup: %q is not an absolute path", path)
		}
	}
	return nil
}

// stop takes the application down for the duration.
//
// The context is detached from the caller's: a browser tab closed mid-backup
// must not cancel the stop and leave tar reading a tree that is being written.
func (t Target) stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unitTimeout)
	defer cancel()
	if err := t.Stop(ctx); err != nil {
		return fmt.Errorf("stop the application: %w", err)
	}
	return nil
}

// restart puts the application back. A failure here is reported rather than
// returned: the caller is already on its way out and the archive, if one was
// written, is still valid.
func (t Target) restart() {
	ctx, cancel := context.WithTimeout(context.Background(), unitTimeout)
	defer cancel()
	if err := t.Start(ctx); err != nil {
		logx.Errorf("appbackup: the application did not start again after the archive: %v", err)
	}
}

// startAndProbe starts the application and waits for it to answer.
//
// systemctl returning 0 says the unit was accepted, not that the restored tree
// works. Without the probe a restore of a corrupt archive reports success.
func (t Target) startAndProbe(ctx context.Context) error {
	startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unitTimeout)
	defer cancel()
	if err := t.Start(startCtx); err != nil {
		return fmt.Errorf("start the application: %w", err)
	}
	if t.Port <= 0 {
		return nil
	}
	probeCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), healthBudget)
	defer stop()
	return apphealth.Wait(probeCtx, apphealth.Probe{Port: t.Port, InitialDelay: healthDelay})
}

// writeArchive runs the tar that produces the archive.
//
// Every member is stored RELATIVE to /, so an extract with -C / puts each file
// back exactly where it came from and the restore needs no path rewriting.
func writeArchive(ctx context.Context, t Target, target string) error {
	arguments := []string{"-czf", target, "-C", "/"}
	const fixed = 4
	for _, path := range append([]string{t.Root}, t.Extra...) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		arguments = append(arguments, strings.TrimPrefix(path, "/"))
	}
	if len(arguments) == fixed {
		return fmt.Errorf("appbackup: there is nothing to archive under %s", t.Root)
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()
	if output, err := command(ctx, "tar", arguments...).CombinedOutput(); err != nil {
		return fmt.Errorf("archive the application: %s: %w", tail(string(output)), err)
	}
	return nil
}

// sealArchive measures the finished file and moves it into place.
func sealArchive(temporary, final string) (Archive, error) {
	info, err := os.Stat(temporary)
	if err != nil {
		return Archive{}, fmt.Errorf("read the archive back: %w", err)
	}
	if info.Size() > MaxSize {
		return Archive{}, fmt.Errorf("appbackup: the archive is %d bytes, over the %d byte ceiling",
			info.Size(), int64(MaxSize))
	}
	digest, err := Digest(temporary)
	if err != nil {
		return Archive{}, fmt.Errorf("take the archive digest: %w", err)
	}
	if err := os.Rename(temporary, final); err != nil {
		return Archive{}, fmt.Errorf("move the archive into place: %w", err)
	}
	// 0600: an archive carries the application's own EnvironmentFile, and that
	// file carries whatever token the application was installed with.
	if err := os.Chmod(final, 0o600); err != nil {
		return Archive{}, fmt.Errorf("close the archive to other accounts: %w", err)
	}
	return Archive{Path: final, Size: info.Size(), SHA256: digest}, nil
}

func verify(archive Archive) error {
	digest, err := Digest(archive.Path)
	if err != nil {
		return fmt.Errorf("read the archive: %w", err)
	}
	if digest != archive.SHA256 {
		return fmt.Errorf("%w: %s", ErrCorrupt, archive.Path)
	}
	return nil
}

// takeRollback copies the tree the restore is about to replace.
//
// It lands in the backup directory rather than beside the tree, because the
// next step deletes that tree whole.
func takeRollback(ctx context.Context, t Target) (string, error) {
	path := filepath.Join(t.Dir, "pre-restore.tar.gz")
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()
	output, err := command(ctx, "tar", "-czf", path, "-C", "/",
		strings.TrimPrefix(t.Root, "/")).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("archive the current tree before replacing it: %s: %w",
			tail(string(output)), err)
	}
	return path, nil
}

func swapIn(ctx context.Context, t Target, archive string) error {
	if err := os.RemoveAll(t.Root); err != nil {
		return fmt.Errorf("clear the current tree: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, restoreTimeout)
	defer cancel()
	if output, err := command(ctx, "tar", "-xzf", archive, "-C", "/").CombinedOutput(); err != nil {
		return fmt.Errorf("unpack the archive: %s: %w", tail(string(output)), err)
	}
	return nil
}

// undo puts the replaced tree back and starts the application again.
//
// The rollback archive is deliberately LEFT on disk here. A restore that broke
// the application and then deleted the only copy of what it replaced leaves the
// operator nothing; the file staying is what makes a manual recovery possible.
func undo(t Target, rollback, reason string) {
	logx.Warnf("appbackup: the restore failed (%s); putting the previous tree back", reason)
	ctx, cancel := context.WithTimeout(context.Background(), restoreTimeout)
	defer cancel()
	_ = os.RemoveAll(t.Root)
	if output, err := command(ctx, "tar", "-xzf", rollback, "-C", "/").CombinedOutput(); err != nil {
		logx.Errorf("appbackup: the rollback failed as well: %s: %v; the copy is kept at %s",
			tail(string(output)), err, rollback)
		return
	}
	startCtx, stop := context.WithTimeout(context.Background(), unitTimeout)
	defer stop()
	if err := t.Start(startCtx); err != nil {
		logx.Errorf("appbackup: the application did not start after the rollback: %v", err)
	}
}

func tail(text string) string {
	const limit = 400
	text = strings.TrimSpace(text)
	if len(text) > limit {
		return text[len(text)-limit:]
	}
	return text
}
