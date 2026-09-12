package domains

import (
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
)

// A lift clears the switch first, because the renderer reads it back from the
// row, and clears the deadline last. A panel that stops between the two leaves
// the domain with maintenance_enabled=0, the deadline still set and the 503
// fragment still rendered. The due query required maintenance_enabled = 1, so
// nothing ever revisited that domain: the site stayed fully unavailable while
// every panel screen reported it as open, until somebody toggled the mode by
// hand. The deadline is now the only condition, and the write path clears the
// deadline together with the switch, so a past deadline means an unfinished
// lift and nothing else.

// liftFakes records the renders one tick makes.
type liftFakes struct {
	hostCalls
	renderErr error
}

func newLiftFakes(t *testing.T) *liftFakes {
	t.Helper()
	f := &liftFakes{}
	setForTest(t, &rerenderVhost, f.render)
	return f
}

func (f *liftFakes) render(_ *sql.DB, id int64) error {
	f.record("render %d", id)
	return f.renderErr
}

// dueScript answers the scheduler's due query with one domain.
func dueScript() *sqlScript {
	s := newScript()
	s.rows["FROM domains"] = [][]driver.Value{{int64(7)}}
	return s
}

// tick runs one pass and returns the fakes and the script it ran against.
func tick(t *testing.T, script *sqlScript, renderErr error) *liftFakes {
	t.Helper()
	fakes := newLiftFakes(t)
	fakes.renderErr = renderErr
	MaintenanceTickOnce(scriptDB(t, script))
	return fakes
}

// A domain whose lift was interrupted still reaches the scheduler. The switch
// is already 0 there, so only the deadline can carry the fact that the vhost
// was never re-rendered.
func TestTheDueQueryDoesNotRequireTheSwitchToBeStillOn(t *testing.T) {
	script := dueScript()

	fakes := tick(t, script, nil)

	for _, step := range script.stepsSnapshot() {
		if !strings.Contains(step, "SELECT id FROM domains") {
			continue
		}
		if strings.Contains(step, "maintenance_enabled") {
			t.Errorf("the due query still filters on the switch, so an interrupted lift is never retried:\n%s", step)
		}
		if !strings.Contains(step, "maintenance_until <= NOW()") {
			t.Errorf("the due query does not compare the deadline in SQL:\n%s", step)
		}
	}
	assertSteps(t, &fakes.hostCalls, "render 7")
}

// The order the lift writes in: the switch before the render, the deadline
// after it. Anything else either renders the 503 fragment again or drops the
// only record that the lift is unfinished.
func TestTheDeadlineIsClearedOnlyAfterTheRenderSucceeded(t *testing.T) {
	script := dueScript()

	tick(t, script, nil)

	var order []string
	for _, step := range script.stepsSnapshot() {
		switch {
		case strings.Contains(step, "maintenance_enabled=0"):
			order = append(order, "switch")
		case strings.Contains(step, "maintenance_until=NULL"):
			order = append(order, "deadline")
		}
	}
	if len(order) != 2 || order[0] != "switch" || order[1] != "deadline" {
		t.Errorf("the lift wrote %v, want the switch then the deadline", order)
	}
}

// A render that fails leaves the deadline set, so the next tick tries again,
// and puts the switch back, so the panel does not report the site as open while
// nginx still answers 503.
func TestAFailedRenderLeavesTheDeadlineAndRestoresTheSwitch(t *testing.T) {
	script := dueScript()

	tick(t, script, errScripted)

	if len(script.execsContaining("maintenance_until=NULL")) != 0 {
		t.Error("a failed render cleared the deadline, so the domain is no longer due")
	}
	if len(script.execsContaining("maintenance_enabled=1")) != 1 {
		t.Error("a failed render did not put the switch back, so the panel reports the site as open")
	}
}
