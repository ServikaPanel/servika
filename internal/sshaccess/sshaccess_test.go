package sshaccess

import (
	"bytes"
	"os"
	"testing"
)

// Every path this package writes to sits under /home/<system_user>, a tree the
// tenant owns and can replace an entry of. A root-privileged write that resolves
// such a path by name follows a planted symlink, which is how a tenant reached
// /root/.ssh/authorized_keys through the AdminOnly key endpoint. Writes must go
// through the files.*Beneath primitives, which pin every component with openat2.
func TestNoPathResolvingWritesUnderTenantHome(t *testing.T) {
	src, err := os.ReadFile("sshaccess.go")
	if err != nil {
		t.Fatalf("read package source: %v", err)
	}
	// EnsureInfra writes /usr/local/bin and /etc/ssh, which are root-only and not
	// reachable by a tenant, so the scan is limited to the two handlers that touch
	// the home.
	for _, fn := range []string{"func (h *Handlers) SaveKey(", "func (h *Handlers) Configure(", "func prepareSSHDir("} {
		body := functionBody(t, src, fn)
		for _, banned := range []string{"os.MkdirAll(", "os.WriteFile(", "os.Create(", "os.Remove(", "os.OpenFile("} {
			if bytes.Contains(body, []byte(banned)) {
				t.Fatalf("%s uses %s on a tenant path; use the files.*Beneath primitives instead", fn, banned)
			}
		}
	}
	for _, want := range []string{"files.MkdirAllBeneath(", "files.WriteFileBeneath("} {
		if !bytes.Contains(src, []byte(want)) {
			t.Fatalf("package no longer calls %s, so the SSH directory is not pinned beneath the tenant home", want)
		}
	}
}

// functionBody returns the source of the function whose declaration starts with
// header, up to the next top-level declaration.
func functionBody(t *testing.T, src []byte, header string) []byte {
	t.Helper()
	start := bytes.Index(src, []byte(header))
	if start < 0 {
		t.Fatalf("function %q not found in the package source", header)
	}
	body, _, _ := bytes.Cut(src[start+len(header):], []byte("\nfunc "))
	return body
}

func TestValidSystemUser(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "valid tenant", in: "c_acme", want: true},
		{name: "short valid", in: "c_ab", want: true},
		{name: "too short", in: "c_", want: false},
		{name: "no prefix", in: "root", want: false},
		{name: "dot injection", in: "c_a.b", want: false},
		{name: "semicolon injection", in: "c_a;b", want: false},
		{name: "space", in: "c_a b", want: false},
		{name: "backtick", in: "c_a`b", want: false},
		{name: "newline", in: "c_a\nb", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validSystemUser(test.in); got != test.want {
				t.Fatalf("validSystemUser(%q) = %t, want %t", test.in, got, test.want)
			}
		})
	}
}

func TestBoolToInt(t *testing.T) {
	if got := boolToInt(true); got != 1 {
		t.Fatalf("boolToInt(true) = %d, want 1", got)
	}
	if got := boolToInt(false); got != 0 {
		t.Fatalf("boolToInt(false) = %d, want 0", got)
	}
}
