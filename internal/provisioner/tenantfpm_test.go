package provisioner

// What the per-tenant PHP-FPM unit must say about restarting.
//
// Every assertion here reads the RENDERED unit rather than the template string,
// so a change that moves a key between sections is caught even when the same
// text is still present somewhere in the file.

import (
	"strings"
	"testing"
)

// sectionOf returns the [Section] a key was rendered into, or "" when the unit
// does not carry that key at all.
//
// The whole point of these tests is WHERE a key sits, so a plain
// strings.Contains would pass on exactly the placement being guarded against.
func sectionOf(unit, key string) string {
	section := ""
	for line := range strings.SplitSeq(unit, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed
			continue
		}
		if name, _, found := strings.Cut(trimmed, "="); found && name == key {
			return section
		}
	}
	return ""
}

// The StartLimit keys belong to [Unit]. systemd answers `Unknown key
// 'StartLimitIntervalSec' in section [Service], ignoring.` while silently
// ACCEPTING StartLimitBurst there, so the wrong section is not a failure that
// anything reports: the burst simply counts against the default ten-second
// window and the unit behaves as though the keys were never written.
func TestTheStartLimitKeysAreInTheUnitSection(t *testing.T) {
	unit := renderTenantUnit("c_tenant", "/usr/sbin/php-fpm")

	for _, key := range []string{"StartLimitIntervalSec", "StartLimitBurst"} {
		switch section := sectionOf(unit, key); section {
		case "[Unit]":
		case "":
			t.Errorf("%s is missing, so the unit runs on systemd's default window", key)
		default:
			t.Errorf("%s is in %s; systemd ignores it there", key, section)
		}
	}
}

// The reason the absence mattered rather than merely being inconsistent: with no
// keys systemd uses 10 seconds and 5 starts, and RestartSec=2 puts starts at
// t=0,2,4,6,8, exactly on that boundary. A window shorter than the restart
// spacing times the burst puts the unit back in that position, so the two values
// are asserted together rather than each on its own.
func TestTheRestartWindowIsWiderThanTheBurstCanFill(t *testing.T) {
	unit := renderTenantUnit("c_tenant", "/usr/sbin/php-fpm")

	interval := valueOf(t, unit, "StartLimitIntervalSec")
	burst := valueOf(t, unit, "StartLimitBurst")
	spacing := valueOf(t, unit, "RestartSec")
	if spacing == 0 {
		t.Fatal("the unit sets no RestartSec, so this test measures nothing")
	}
	// burst starts spaced `spacing` apart span (burst-1)*spacing seconds. The
	// window has to be wider than that, or the limit is never reached and the
	// master restarts for as long as it keeps failing.
	span := (burst - 1) * spacing
	if interval <= span {
		t.Errorf("StartLimitIntervalSec=%d cannot hold %d starts spaced %ds apart (%ds)",
			interval, burst, spacing, span)
	}
}

// Restart=on-failure without a start limit is the shape that loops. The unit
// keeps on-failure deliberately (a clean stop must not be restarted), so the
// limit is what bounds it.
func TestTheUnitStillRestartsOnFailure(t *testing.T) {
	unit := renderTenantUnit("c_tenant", "/usr/sbin/php-fpm")
	if sectionOf(unit, "Restart") != "[Service]" {
		t.Error("Restart is not in [Service]")
	}
	if !strings.Contains(unit, "Restart=on-failure") {
		t.Error("the unit no longer restarts a failed master at all")
	}
}

// The change reaches EXISTING tenants through a heal that already exists.
//
// HealTenantFPMLogs runs from provisioner.Init at every startup, is not
// sentinel-gated, renders the wanted unit and rewrites the installed one on any
// difference (fpmlog.go). So a unit written before this change differs from the
// current rendering, which is what makes the heal fire for it.
func TestAUnitWrittenBeforeTheStartLimitDiffersFromTheCurrentOne(t *testing.T) {
	current := renderTenantUnit("c_tenant", "/usr/sbin/php-fpm")

	// What the previous template produced: the same file with the two keys
	// removed. Built by removal rather than by a second copy of the template, so
	// this test cannot drift away from what is actually rendered.
	var previous strings.Builder
	for line := range strings.SplitSeq(current, "\n") {
		if strings.HasPrefix(line, "StartLimitIntervalSec=") || strings.HasPrefix(line, "StartLimitBurst=") {
			continue
		}
		previous.WriteString(line)
		previous.WriteString("\n")
	}
	old := strings.TrimSuffix(previous.String(), "\n")
	if old == current {
		t.Fatal("removing the keys changed nothing, so this test measures nothing")
	}
	if old == strings.TrimSuffix(current, "\n") {
		t.Error("the heal's comparison would not fire, so no existing tenant receives the change")
	}
}

// valueOf reads one integer directive out of a rendered unit.
func valueOf(t *testing.T, unit, key string) int {
	t.Helper()
	for line := range strings.SplitSeq(unit, "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || name != key {
			continue
		}
		total := 0
		for _, r := range value {
			if r < '0' || r > '9' {
				t.Fatalf("%s=%q is not a plain number", key, value)
			}
			total = total*10 + int(r-'0')
		}
		return total
	}
	t.Fatalf("the unit carries no %s", key)
	return 0
}

// A php_settings row with an EMPTY disable_functions means the operator allowed
// every function (the panel's shell-execution toggle is on). It must be kept as
// empty, not re-hardened, or the tenant's own PHP-FPM master blocks PHP while the
// panel toggle reads as on. Only a control-character injection falls back.
func TestAnEmptyDisableFunctionsIsKeptAsAllowAll(t *testing.T) {
	if got := tenantDisableFunctions(""); got != "" {
		t.Errorf("empty = %q, want it kept empty (operator allowed all)", got)
	}
	if got := tenantDisableFunctions("   "); got != "" {
		t.Errorf("whitespace-only = %q, want empty", got)
	}
	if got := tenantDisableFunctions("exec,system"); got != "exec,system" {
		t.Errorf("a set value = %q, want it preserved", got)
	}
	if got := tenantDisableFunctions("exec\nsystem"); got != hardenedDisableFunctions {
		t.Errorf("a control-character injection = %q, want the hardened default", got)
	}
}
