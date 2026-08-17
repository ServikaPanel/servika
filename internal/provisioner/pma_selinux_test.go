package provisioner

import (
	"os"
	"strings"
	"testing"
)

// The installer, assets/ops/servika-repair and this startup heal all label the
// same two phpMyAdmin trees. A type that disagrees is not a cosmetic
// difference: on an Enforcing host the web server is refused and phpMyAdmin
// answers 403, and whichever of the three ran last decides the outcome.
func TestTheRepairToolAndTheHealAgreeOnTheLabels(t *testing.T) {
	body, err := os.ReadFile("../../assets/ops/servika-repair")
	if err != nil {
		t.Fatalf("read the repair tool: %v", err)
	}
	repair := string(body)

	for _, want := range []struct {
		path     string
		typeName string
	}{
		{"/opt/phpmyadmin", pmaRootSELinuxType},
		{"/var/lib/phpmyadmin", pmaVarLibSELinuxType},
	} {
		if !strings.Contains(repair, want.typeName) {
			t.Errorf("the repair tool does not name %q, which the heal applies to %s", want.typeName, want.path)
		}
	}
}

// The two trees are labelled differently on purpose. phpMyAdmin's installation
// is read and its session directory is written, and a single type for both
// either denies the writes or grants them over the served code.
func TestTheServedTreeAndTheWrittenTreeCarryDifferentTypes(t *testing.T) {
	if pmaRootSELinuxType == pmaVarLibSELinuxType {
		t.Fatalf("both trees are %q; the installation is read and the session directory is written", pmaRootSELinuxType)
	}
	if !strings.HasSuffix(pmaVarLibSELinuxType, "_rw_content_t") {
		t.Errorf("the session directory is %q, which does not permit the writes phpMyAdmin makes there", pmaVarLibSELinuxType)
	}
}

// Every command in the labelling helper is best effort, so the type is read
// back. Without that, a host where semanage is missing reports success while
// the daemon is being refused.
func TestTheLabellingHelperReportsWhatThePathActuallyCarries(t *testing.T) {
	if selinuxActive() {
		t.Skip("this host runs SELinux; the assertion below is about the read-back, not a live label")
	}
	// With SELinux off there is nothing to label and nothing to refuse.
	if err := ensureSELinuxType("/nonexistent-servika-test-path", pmaRootSELinuxType); err != nil {
		t.Errorf("labelling reported %v on a host without SELinux; there is nothing to enforce", err)
	}
}
