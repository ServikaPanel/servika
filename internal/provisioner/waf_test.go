package provisioner

import (
	"database/sql/driver"
	"errors"
	"testing"
)

// WAFEffective decides whether a vhost carries "modsecurity on", in which mode,
// and at which paranoia level. The domain's own value wins over the plan's, and
// every state that cannot be read resolves to off at paranoia 1.

const wafQuery = "LEFT JOIN service_plans p"

// wafRow is one answer in SELECT order: the domain's three nullable overrides,
// then the plan's three defaults.
func wafRow(domainEnabled, domainMode, domainParanoia driver.Value, planEnabled int64, planMode string, planParanoia int64) [][]driver.Value {
	return [][]driver.Value{{domainEnabled, domainMode, domainParanoia, planEnabled, planMode, planParanoia}}
}

func TestTheWAFSettingIsTheDomainOverrideOverThePlanDefault(t *testing.T) {
	cases := []struct {
		name     string
		row      [][]driver.Value
		active   bool
		engine   string
		paranoia int
	}{
		{"the plan default applies", wafRow(nil, nil, nil, 1, "on", 2), true, "On", 2},
		{"the domain turns it off", wafRow(int64(0), nil, nil, 1, "on", 2), false, "", 2},
		{"the domain turns it on over a plan without it", wafRow(int64(1), nil, nil, 0, "on", 1), true, "On", 1},
		{"the domain asks for detection", wafRow(nil, "detect", nil, 1, "on", 1), true, "DetectionOnly", 1},
		{"DetectionOnly spelled out", wafRow(nil, "DetectionOnly", nil, 1, "on", 1), true, "DetectionOnly", 1},
		{"a blank domain mode keeps the plan's", wafRow(nil, "  ", nil, 1, "detect", 1), true, "DetectionOnly", 1},
		{"mode off", wafRow(nil, "off", nil, 1, "on", 3), false, "", 3},
		{"an empty plan mode is off", wafRow(nil, nil, nil, 1, "", 1), false, "", 1},
		{"a mode that is not detection blocks", wafRow(nil, "block", nil, 1, "on", 1), true, "On", 1},
		{"the domain paranoia wins", wafRow(nil, nil, int64(3), 1, "on", 1), true, "On", 3},
		{"a zero domain paranoia keeps the plan's", wafRow(nil, nil, int64(0), 1, "on", 2), true, "On", 2},
		{"paranoia above four is clamped", wafRow(nil, nil, int64(9), 1, "on", 1), true, "On", 4},
		{"paranoia below one is clamped", wafRow(nil, nil, nil, 1, "on", 0), true, "On", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := withScript(t, &sqlScript{rows: map[string][][]driver.Value{wafQuery: tc.row}})
			active, engine, paranoia := WAFEffective(db, "c_example_com")
			if active != tc.active || engine != tc.engine || paranoia != tc.paranoia {
				t.Errorf("WAFEffective() = %v, %q, %d; want %v, %q, %d",
					active, engine, paranoia, tc.active, tc.engine, tc.paranoia)
			}
		})
	}
}

func TestAnUnreadableWAFSettingIsOff(t *testing.T) {
	if active, engine, paranoia := WAFEffective(nil, "c_example_com"); active || engine != "" || paranoia != 1 {
		t.Errorf("no database: WAFEffective() = %v, %q, %d; want off at paranoia 1", active, engine, paranoia)
	}
	cases := map[string]*sqlScript{
		"the query fails": {fail: map[string]error{wafQuery: errors.New(lostConnectionTo)}},
		// An addon domain or an unknown system user answers no row.
		"no top-level domain": {rows: map[string][][]driver.Value{wafQuery: {}}},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			db := withScript(t, script)
			if active, engine, paranoia := WAFEffective(db, "c_example_com"); active || engine != "" || paranoia != 1 {
				t.Errorf("WAFEffective() = %v, %q, %d; want off at paranoia 1", active, engine, paranoia)
			}
		})
	}
}
