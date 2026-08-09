package domains

import (
	"os"
	"strings"
	"testing"
	"time"
)

// THE timezone rule for this column. The driver writes a Go time.Time as UTC
// while MySQL's NOW() answers in the session timezone, so a deadline written by
// one clock and compared by the other is wrong by the offset between them. The
// write applies a DURATION with DATE_ADD(NOW(), ...), which makes both sides the
// same clock, and the scheduler compares it in SQL for the same reason.
func TestTheDeadlineIsComputedByTheDatabaseClock(t *testing.T) {
	source := readSource(t, "maintenance.go")

	if !strings.Contains(source, "DATE_ADD(NOW(), INTERVAL ? MINUTE)") {
		t.Error("the deadline is not computed with DATE_ADD(NOW(), ...)")
	}
	// No Go-side clock may reach this column. time.Now() anywhere in the file
	// would mean some path writes a driver-formatted timestamp instead.
	if strings.Contains(source, "time.Now()") {
		t.Error("a Go clock value is used where the database clock is required")
	}
}

// Both refused shapes render a vhost the fragment never reaches: a custom vhost
// is written out verbatim and a redirect-only domain uses a different template.
// Storing the switch for either would leave the screen saying the site is
// closed while every visitor still got through.
func TestTheTwoUnrenderableShapesHaveTheirOwnReasonCodes(t *testing.T) {
	if reasonMaintenanceCustomVhost == reasonMaintenanceRedirectOnly {
		t.Fatal("the two shapes share one code, so the screen cannot tell them apart")
	}
	for _, code := range []string{
		reasonMaintenanceCustomVhost, reasonMaintenanceRedirectOnly,
		reasonMaintenanceBadAddress, reasonMaintenanceTooManyIPs,
	} {
		if code == "" || strings.ContainsAny(code, " .") || strings.ToLower(code) != code {
			t.Errorf("%q is not a stable reason code", code)
		}
		if maintenanceUnavailableMessage(code) == "" {
			t.Errorf("%q has no English message beside it", code)
		}
	}
	// Each refused shape gets its own sentence, or the code would be the only
	// thing distinguishing them and a client without the mapping sees one
	// message for two different problems.
	if maintenanceUnavailableMessage(reasonMaintenanceCustomVhost) ==
		maintenanceUnavailableMessage(reasonMaintenanceRedirectOnly) {
		t.Error("the two shapes share one message")
	}
}

// The refusal happens on the WRITE path, not only where the screen draws the
// switch: a client calling the API directly must get the same answer.
func TestTheWritePathChecksTheShapeItself(t *testing.T) {
	source := readSource(t, "maintenance.go")
	save := source[strings.Index(source, "func (h *Handlers) MaintenanceSave"):]
	save = save[:strings.Index(save, "\nfunc ")]

	if !strings.Contains(save, "maintenanceUnavailable(") {
		t.Error("MaintenanceSave does not check whether the shape can carry the fragment")
	}
	// The page file is written before the vhost points at it. The other order
	// leaves a window in which nginx serves a location whose file is absent.
	//
	// Matched on the CALL form, not the bare name: a comment mentioning
	// WriteMaintenancePage appears earlier in the function and would satisfy a
	// name-only search whatever the real order was.
	write := strings.Index(save, "provisioner.WriteMaintenancePage(")
	render := strings.Index(save, "provisioner.RerenderVhost(")
	if write < 0 || render < 0 || write > render {
		t.Error("the vhost is rendered before the page file exists")
	}
}

// Field ceilings cut by RUNE, never by byte: the columns are utf8mb4 and a byte
// cut lands mid-character, storing a broken one.
func TestFieldsAreCutByRuneNotByte(t *testing.T) {
	long := strings.Repeat("ş", maxMaintenanceTitle+40)
	got := sanitizeLine(long, maxMaintenanceTitle)
	if count := len([]rune(got)); count != maxMaintenanceTitle {
		t.Errorf("kept %d runes, want %d", count, maxMaintenanceTitle)
	}
	if !strings.HasSuffix(got, "ş") {
		t.Errorf("the value was cut mid-character: %q", got[len(got)-4:])
	}
}

// A single-line field loses its line breaks and control characters; the message
// keeps line breaks because the page renders them.
func TestControlCharactersAreStrippedFromTheFields(t *testing.T) {
	if got := sanitizeLine("one\r\ntwo\x00three\t", 100); got != "onetwothree" {
		t.Errorf("sanitizeLine kept control characters: %q", got)
	}
	got := sanitizeText("first\r\nsecond\x00\tthird", 100)
	if got != "first\nsecond third" && got != "first\nsecondthird" {
		t.Errorf("sanitizeText = %q", got)
	}
	if !strings.Contains(got, "\n") {
		t.Errorf("sanitizeText dropped the line break the page renders: %q", got)
	}
	if strings.ContainsAny(got, "\x00\r\t") {
		t.Errorf("sanitizeText kept a control character: %q", got)
	}
}

// readSource returns one file of this package so a rule about HOW something is
// written can be asserted. The alternative is a live MariaDB, which no unit
// test here has.
func readSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// The scheduler compares the deadline in SQL, not against a Go clock.
//
// maintenance_until was written with DATE_ADD(NOW(), ...), so the clock that
// set it must be the clock that reads it. A Go comparison here would put back
// exactly the timezone difference the write path exists to avoid.
func TestTheSchedulerComparesTheDeadlineInSQL(t *testing.T) {
	source := readSource(t, "maintenance_scheduler.go")

	if !strings.Contains(source, "maintenance_until <= NOW()") {
		t.Error("the scheduler does not compare the deadline in SQL")
	}
	if strings.Contains(source, "time.Now()") {
		t.Error("the scheduler compares the deadline with a Go clock value")
	}
}

// A domain whose vhost could not be re-rendered stays due, so the next tick
// tries again. Clearing the row anyway would leave the panel reporting the site
// as open while nginx still answered 503 to every visitor, with nothing left to
// notice it.
func TestAFailedRenderLeavesTheDomainDue(t *testing.T) {
	source := readSource(t, "maintenance_scheduler.go")
	lift := source[strings.Index(source, "func liftMaintenance"):]

	render := strings.Index(lift, "provisioner.RerenderVhost(")
	clearDeadline := strings.Index(lift, "maintenance_until=NULL")
	if render < 0 || clearDeadline < 0 {
		t.Fatalf("unexpected shape:\n%s", lift)
	}
	if clearDeadline < render {
		t.Error("the deadline is cleared before the vhost is known to have changed")
	}
	// The failure branch puts the switch back rather than leaving the domain
	// half-open.
	if !strings.Contains(lift, "maintenance_enabled=1 WHERE id=?") {
		t.Error("a failed render does not restore the switch, so the retry never happens")
	}
}

// The pass runs under its own deadline, shorter than the interval, so a slow
// pass cannot overlap the next one. main hands this package a context that
// never cancels, so inheriting one would mean no deadline at all.
func TestTheSchedulerPassHasItsOwnDeadline(t *testing.T) {
	source := readSource(t, "maintenance_scheduler.go")
	if !strings.Contains(source, "context.WithTimeout(context.Background()") {
		t.Error("the pass does not set its own deadline")
	}
	if !strings.Contains(source, "maintenanceTick-") {
		t.Error("the deadline is not derived from the tick interval, so it can exceed it")
	}
	if maintenanceTick <= 0 {
		t.Fatal("the tick interval is not positive")
	}
	if maintenanceTick > time.Minute {
		t.Errorf("the tick is %v; a customer's stated reopening time would be missed by that much", maintenanceTick)
	}
}
