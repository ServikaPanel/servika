//go:build linux

package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/files"
)

// generateDeployKey runs as ROOT against /home/<system_user>/.ssh, a directory
// the TENANT owns. Resolving by path was an escape in every step: os.MkdirAll
// accepts an existing symlink, ssh-keygen -f writes through whatever the path
// resolves to, os.WriteFile follows a symlink at the final component, and chown
// without -h dereferences its operand.
//
// These exercise the primitives the function now uses, against a home with the
// attack planted. They are Linux-only because safeio is openat2.

// A tenant who replaces ~/.ssh with a symlink must not make a root-privileged
// write land outside their own tree.
func TestAPlantedDirectorySymlinkCannotRedirectTheWrite(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".ssh")); err != nil {
		t.Fatalf("plant the directory symlink: %v", err)
	}

	// MkdirAllBeneath refuses the planted link rather than creating through it.
	if err := files.MkdirAllBeneath(home, ".ssh", ""); err == nil {
		if _, err := os.Stat(filepath.Join(outside, "servika_deploy")); err == nil {
			t.Fatal("a file was created through the planted directory symlink")
		}
	}
	if err := files.WriteFileBeneath(home, ".ssh/config", []byte("x"), 0o600, ""); err == nil {
		t.Fatal("the ssh config was written through the planted directory symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "config")); err == nil {
		t.Fatal("the ssh config landed outside the home")
	}
}

// A tenant who replaces the LEAF with a symlink must not have root write through
// it either: os.WriteFile follows a link at the final component.
func TestAPlantedLeafSymlinkIsNotWrittenThrough(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write the victim file: %v", err)
	}
	if err := files.MkdirAllBeneath(home, ".ssh", ""); err != nil {
		t.Fatalf("create the ssh directory: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".ssh", "config")); err != nil {
		t.Fatalf("plant the leaf symlink: %v", err)
	}

	_ = files.WriteFileBeneath(home, ".ssh/config", []byte("Host github.com\n"), 0o600, "")

	body, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read the victim file: %v", err)
	}
	if string(body) != "original\n" {
		t.Fatalf("the victim file was overwritten through the planted link: %q", body)
	}
}

// The key generation itself must not resolve a tenant path by string any more.
func TestTheDeployKeyPathIsNotResolvedByString(t *testing.T) {
	body, err := os.ReadFile("git.go")
	if err != nil {
		t.Fatalf("read git.go: %v", err)
	}
	// The ssh config and known_hosts writes live in githubhostkeys.go, which
	// generateDeployKey calls on every run, so both files are read here.
	trust, err := os.ReadFile("githubhostkeys.go")
	if err != nil {
		t.Fatalf("read githubhostkeys.go: %v", err)
	}
	source := string(body) + string(trust)

	for _, gone := range []string{
		`os.MkdirAll(dir, 0700)`,
		`exec.Command("chown", "-R", systemUser+":"+systemUser, dir)`,
		`exec.Command("chown", systemUser+":"+systemUser, cfg)`,
		`os.WriteFile(cfg,`,
	} {
		if strings.Contains(source, gone) {
			t.Errorf("the deploy key path is still resolved by string: %s", gone)
		}
	}
	for _, want := range []string{
		`files.MkdirAllBeneath(home, relDir, systemUser)`,
		`files.WriteFileBeneath(home, relPriv,`,
		`files.WriteFileBeneath(home, relSSHConfig,`,
		`files.RestoreconBeneath(home, relDir)`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("%s is missing from the deploy key path", want)
		}
	}
	// ssh-keygen writes by path, so it must write into a ROOT-OWNED staging
	// directory rather than into the tenant's tree.
	if !strings.Contains(source, `os.MkdirTemp("", "servika-deploy-key-")`) {
		t.Error("ssh-keygen is not staged outside the tenant home")
	}
	if !strings.Contains(source, `"-f", stagedPriv`) {
		t.Error("ssh-keygen still writes into the tenant tree")
	}
}
