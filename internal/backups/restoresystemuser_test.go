package backups

import (
	"strings"
	"testing"
)

// restoreHome and restoreSelectedFiles build "/home/<systemUser>" and hand it to
// a root rsync, chown and restorecon, or to the *Beneath primitives as the root
// they pin. Every caller checks the name, so the gate here protects against a
// database value that was tampered with. It runs BEFORE anything reads the disk,
// so a refused name reaches no command.
func TestRestoreRefusesASystemUserThatCouldLeaveTheHome(t *testing.T) {
	refused := []string{"", "..", "../root", "c_site/../../etc", "c_site x", "root", "c_site\n", "c_site;id"}
	for _, name := range refused {
		if err := restoreHome(t.Context(), t.TempDir(), name, false); err == nil {
			t.Errorf("restoreHome(%q) = nil, want a refusal", name)
		}
		if _, _, err := restoreSelected(t.Context(), t.TempDir(), name, []string{"public_html"}, "copy"); err == nil {
			t.Errorf("restoreSelectedFiles(%q) = nil, want a refusal", name)
		}
	}
}

// The negative half proves nothing alone: a gate that refused every name would
// pass it while breaking every restore. A valid name gets past the gate, where
// restoreHome then finds no extracted home and returns nil without running a
// command.
func TestRestoreHomeAcceptsAValidSystemUser(t *testing.T) {
	if err := restoreHome(t.Context(), t.TempDir(), "c_example_com", false); err != nil {
		t.Fatalf("restoreHome with a valid name = %v, want nil", err)
	}
}

// validSystemUser is the gate both functions call.
func TestValidSystemUserRefusesASeparator(t *testing.T) {
	if validSystemUser("c_site/..") || validSystemUser(strings.Repeat("c_", 1)+"a b") {
		t.Fatal("validSystemUser accepted a name carrying a separator or a space")
	}
	if !validSystemUser("c_example_com") {
		t.Fatal("validSystemUser refused a name the provisioner produces")
	}
}
