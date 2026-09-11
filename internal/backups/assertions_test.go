package backups

import (
	"database/sql/driver"
	"slices"
	"testing"
)

// assertExecs fails unless the statements holding fragment ran with exactly the
// given argument lists, in order.
func assertExecs(t *testing.T, script *sqlScript, fragment string, want ...[]driver.Value) {
	t.Helper()
	got := script.execsContaining(fragment)
	if len(got) != len(want) {
		t.Errorf("%d statements holding %q ran, want %d: %+v", len(got), fragment, len(want), got)
		return
	}
	for i := range want {
		if !slices.Equal(got[i].args, want[i]) {
			t.Errorf("statement %d holding %q bound %v, want %v", i, fragment, got[i].args, want[i])
		}
	}
}

// alert is the message key and the domain of one notification.
type alert struct {
	key    string
	domain driver.Value
}

// assertAlerts fails unless exactly these notifications were written, in order.
func assertAlerts(t *testing.T, script *sqlScript, want ...alert) {
	t.Helper()
	written := script.execsContaining(notificationInsert)
	got := make([]alert, 0, len(written))
	for _, statement := range written {
		key, _ := statement.args[4].(string)
		got = append(got, alert{key: key, domain: statement.args[6]})
	}
	if !slices.Equal(got, want) {
		t.Errorf("alerts = %+v, want %+v", got, want)
	}
}

// assertOutcome fails unless a call returned want, or failed with wantErr when
// that is set.
func assertOutcome(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil || err.Error() != wantErr {
			t.Fatalf("got (%q, %v), want the error %q", got, err, wantErr)
		}
		return
	}
	if err != nil || got != want {
		t.Fatalf("got (%q, %v), want %q", got, err, want)
	}
}
