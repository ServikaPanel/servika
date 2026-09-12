package plans

import "testing"

// A plan's zero is not a limit of zero, it is "the operator left this field
// alone". Every one of these numbers reaches a cgroup, an FPM pool or an nginx
// directive, so a zero that survived would be a tenant with no processes, no
// memory and a 0 MB upload ceiling rather than a tenant on the defaults.

// A field left empty takes the default the panel documents.
func TestAnEmptyFieldTakesItsDefault(t *testing.T) {
	var plan Plan
	fillDefaults(&plan)

	for _, tc := range []struct {
		field string
		got   int
		want  int
	}{
		{field: "cpu percent", got: plan.CPUPercent, want: 100},
		{field: "memory", got: plan.RAMMB, want: 512},
		{field: "processes", got: plan.MaxProcess, want: 50},
		{field: "inodes", got: plan.InodeQuota, want: 50000},
		{field: "io weight", got: plan.IOWeight, want: 100},
		{field: "database connections", got: plan.MySQLMaxConnections, want: 25},
		{field: "upload ceiling", got: plan.ClientMaxBodyMB, want: 64},
		{field: "waf paranoia", got: plan.WAFParanoia, want: 1},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.field, tc.got, tc.want)
		}
	}
	if plan.PHPVersion != "8.3" {
		t.Errorf("php version = %q, want 8.3", plan.PHPVersion)
	}
	if plan.WAFMode != "on" {
		t.Errorf("waf mode = %q, want on", plan.WAFMode)
	}
}

// A field the operator did set is left alone, or the defaults would be a
// ceiling rather than a starting point.
func TestASetFieldIsNotOverwritten(t *testing.T) {
	plan := Plan{
		CPUPercent: 25, RAMMB: 128, MaxProcess: 10, InodeQuota: 1000,
		IOWeight: 10, MySQLMaxConnections: 5, ClientMaxBodyMB: 8,
		PHPVersion: "8.1", WAFMode: "off", WAFParanoia: 3,
	}
	before := plan

	fillDefaults(&plan)

	if plan != before {
		t.Errorf("fillDefaults changed a plan the operator filled in:\n got %+v\nwant %+v", plan, before)
	}
}

// The WAF mode reaches a rendered nginx directive, so it is folded to one of
// the three the renderer knows and anything else becomes the safe one.
func TestTheWAFModeIsFoldedToWhatTheRendererKnows(t *testing.T) {
	for given, want := range map[string]string{
		"ON":         "on",
		"  Detect ":  "detect",
		"off":        "off",
		"":           "on",
		"monitoring": "on",
	} {
		plan := Plan{WAFMode: given}
		fillDefaults(&plan)
		if plan.WAFMode != want {
			t.Errorf("waf mode %q became %q, want %q", given, plan.WAFMode, want)
		}
	}
}

// A paranoia level outside the four the rule set defines would render a
// configuration nginx refuses, which takes every site down rather than one.
func TestAParanoiaLevelOutsideTheRangeIsReset(t *testing.T) {
	for _, given := range []int{-1, 0, 5, 99} {
		plan := Plan{WAFParanoia: given}
		fillDefaults(&plan)
		if plan.WAFParanoia != 1 {
			t.Errorf("paranoia %d became %d, want 1", given, plan.WAFParanoia)
		}
	}
	for _, given := range []int{1, 2, 3, 4} {
		plan := Plan{WAFParanoia: given}
		fillDefaults(&plan)
		if plan.WAFParanoia != given {
			t.Errorf("paranoia %d became %d, want it kept", given, plan.WAFParanoia)
		}
	}
}

// A PHP version of spaces is not a version: it would reach a socket path and an
// FPM pool name.
func TestAPHPVersionOfSpacesTakesTheDefault(t *testing.T) {
	plan := Plan{PHPVersion: "   "}
	fillDefaults(&plan)
	if plan.PHPVersion != "8.3" {
		t.Errorf("php version = %q, want 8.3", plan.PHPVersion)
	}
}
