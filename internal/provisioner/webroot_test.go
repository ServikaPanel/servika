package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AbsoluteWebRoot is the guard between a stored document-root choice and the
// path nginx serves. It refuses a name that is not a tenant, a path that is not
// a plain subdirectory, and a symlink that leads out of public_html.

// withTenantHome points the tenant home root at a real directory for one test.
// The temporary directory is resolved first: on macOS it sits behind the /var
// symlink, and the guard compares resolved paths against the base it builds.
func withTenantHome(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve the temporary home root: %v", err)
	}
	previous := tenantHomeRoot
	tenantHomeRoot = root
	t.Cleanup(func() { tenantHomeRoot = previous })
	return root
}

func TestAWebRootIsRefusedForAnInvalidTenantOrPath(t *testing.T) {
	withTenantHome(t)
	cases := []struct {
		name, user, subdirectory, reason string
	}{
		{"not a tenant user", "root", "", "invalid system user"},
		{"upper case in the tenant user", "c_Example", "", "invalid system user"},
		{"a parent reference", "c_example_com", "../etc", "invalid web root"},
		{"a character outside the allowed set", "c_example_com", "a b", "invalid web root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AbsoluteWebRoot(tc.user, tc.subdirectory)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("AbsoluteWebRoot() = %q, %v; want an error naming %q", got, err, tc.reason)
			}
		})
	}
}

func TestAWebRootResolvesUnderPublicHTML(t *testing.T) {
	root := withTenantHome(t)
	base := filepath.Join(root, "c_example_com", "public_html")
	if err := os.MkdirAll(filepath.Join(base, "blog"), 0o755); err != nil {
		t.Fatalf("create public_html: %v", err)
	}
	if err := os.Symlink(filepath.Join(base, "blog"), filepath.Join(base, "alias")); err != nil {
		t.Fatalf("create the inside symlink: %v", err)
	}
	cases := []struct {
		name, subdirectory, want string
	}{
		{"no subdirectory", "", base},
		{"a lone slash", "/", base},
		{"a dot", ".", base},
		{"an existing subdirectory with slashes around it", "/blog/", filepath.Join(base, "blog")},
		{"a subdirectory that does not exist yet", "blog/app", filepath.Join(base, "blog", "app")},
		{"a symlink that stays inside", "alias", filepath.Join(base, "alias")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AbsoluteWebRoot("c_example_com", tc.subdirectory)
			if err != nil || got != tc.want {
				t.Fatalf("AbsoluteWebRoot() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// A symlink inside public_html that points outside it is refused, including
// when the requested path continues below the link.
func TestAWebRootCannotLeavePublicHTMLThroughASymlink(t *testing.T) {
	root := withTenantHome(t)
	base := filepath.Join(root, "c_example_com", "public_html")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("create public_html: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "escape")); err != nil {
		t.Fatalf("create the escaping symlink: %v", err)
	}
	for _, subdirectory := range []string{"escape", "escape/deeper/still"} {
		got, err := AbsoluteWebRoot("c_example_com", subdirectory)
		if err == nil || !strings.Contains(err.Error(), "through a symlink") {
			t.Errorf("AbsoluteWebRoot(%q) = %q, %v; want the symlink refusal", subdirectory, got, err)
		}
	}
}

// A web root is computed even before the tenant's home exists, so it can be
// chosen for a tenant whose home is created afterwards.
func TestAWebRootForAHomeThatDoesNotExistYetIsComputed(t *testing.T) {
	root := withTenantHome(t)
	want := filepath.Join(root, "c_new_tenant", "public_html", "site")
	got, err := AbsoluteWebRoot("c_new_tenant", "site")
	if err != nil || got != want {
		t.Fatalf("AbsoluteWebRoot() = %q, %v; want %q", got, err, want)
	}
}
