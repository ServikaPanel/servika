package provisioner

import (
	"fmt"
	"os/exec"
	"strings"
)

// ensureSELinuxType gives a path the file context type its daemon needs, and
// reports what the path actually carries afterwards.
//
// Two things make this more than a `restorecon` call. A path the distribution
// does not know inherits the default for its parent, so a directory under /var
// comes out `var_log_t` or `var_lib_t` and the web server is not allowed to
// create anything in it. And `restorecon` only applies the rules that exist:
// without a `semanage fcontext` entry it restores the same wrong default, and
// the next full relabel undoes any `chcon` that was applied by hand.
//
// The label is READ BACK because every command here is best effort. On an
// Enforcing host a wrong type is not a degraded feature, it is the daemon being
// refused, so the caller has to be able to tell the difference between a
// directory it can use and one it cannot.
func ensureSELinuxType(path, wantType string) error {
	if !selinuxActive() {
		return nil
	}
	spec := path + "(/.*)?"
	if _, err := exec.LookPath("semanage"); err == nil {
		output, _ := tenantCommand("semanage", "fcontext", "-l").CombinedOutput()
		if !strings.Contains(string(output), spec) {
			_, _ = tenantCommand("semanage", "fcontext", "-a", "-t", wantType, spec).CombinedOutput()
		}
		_, _ = tenantCommand("restorecon", "-R", path).CombinedOutput()
	} else {
		// Without semanage the rule cannot be persisted, so this holds only until
		// the next full relabel. It still beats leaving the path unusable.
		_, _ = tenantCommand("chcon", "-R", "-t", wantType, path).CombinedOutput()
	}
	if got := selinuxType(path); got != wantType {
		return fmt.Errorf("%s is labelled %q, not %q", path, got, wantType)
	}
	return nil
}
