package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A unit that restarts but carries no StartLimit keys never reaches `failed`,
// which is the one state a screen, `systemctl --failed` and an OnFailure= hook
// read as broken. The defaults are a ten-second window and a burst of five, so
// any RestartSec of 3 or more fits at most four starts in that window and the
// burst is never reached: the unit stays in `activating (auto-restart)` for
// ever.
//
// The panel's own unit was the one left without them, and that state is
// reachable by design rather than only by accident: a migration failure, an
// unreadable secret and a listen failure all exit the process on purpose.
//
// Measured against systemd 257 on AlmaLinux 10, with a unit of exactly the
// panel's shape: without the keys it was still `activating` after 40 seconds
// and 12 restarts and `systemctl --failed` was empty; with them it reached
// `failed` after 5 restarts, about 16 seconds in, and appeared there.
func TestEveryRestartingUnitReachesAFailedState(t *testing.T) {
	for _, unit := range shippedUnits(t) {
		body := readScript(t, unit)
		if !strings.Contains(body, "Restart=") || strings.Contains(body, "Restart=no") {
			continue
		}
		name := filepath.Base(unit)
		for _, key := range []string{"StartLimitIntervalSec=", "StartLimitBurst="} {
			if !strings.Contains(body, key) {
				t.Errorf("%s restarts but carries no %s, so it loops without ever reaching failed", name, key)
			}
		}
		// Both keys belong in [Unit]. systemd answers "Unknown key
		// 'StartLimitIntervalSec' in section [Service], ignoring." while
		// silently accepting StartLimitBurst there, which would leave the burst
		// counting against the default ten-second window.
		// On the section HEADER, not on the first mention: these files explain
		// the rule in a comment that names "[Service]", and splitting on that
		// puts the whole [Unit] section on the wrong side.
		unitSection, serviceSection, found := strings.Cut(body, "\n[Service]\n")
		if !found {
			continue
		}
		for _, key := range []string{"StartLimitIntervalSec=", "StartLimitBurst="} {
			if strings.Contains(serviceSection, key) {
				t.Errorf("%s declares %s in [Service], where systemd ignores or misapplies it", name, key)
			}
			if !strings.Contains(unitSection, key) {
				t.Errorf("%s does not declare %s in [Unit]", name, key)
			}
		}
	}
}

// A unit file marked executable makes systemd print "Configuration file ... is
// marked executable. Please remove executable permission bits." on every verify.
func TestNoShippedUnitIsExecutable(t *testing.T) {
	for _, unit := range shippedUnits(t) {
		info, err := os.Stat(unit)
		if err != nil {
			t.Fatalf("stat %s: %v", unit, err)
		}
		if info.Mode().Perm()&0o111 != 0 {
			t.Errorf("%s is mode %04o; a unit file is configuration, not a program",
				filepath.Base(unit), info.Mode().Perm())
		}
	}
}

func shippedUnits(t *testing.T) []string {
	t.Helper()
	units, err := filepath.Glob("../../assets/systemd/*.service")
	if err != nil {
		t.Fatalf("list the shipped units: %v", err)
	}
	if len(units) < 4 {
		t.Fatalf("only %d units were found; the assets layout changed and this test is not reading it", len(units))
	}
	return units
}
