package config

import "testing"

// The range has to stay below the kernel's default ephemeral range, or an
// outgoing connection can take a port an application is meant to hold. That
// application then fails to bind at its next restart, and the failure looks
// like the application's own, at a moment nobody connected to the machine.
func TestTheApplicationRangeStaysBelowTheEphemeralRange(t *testing.T) {
	if AppPortMin > AppPortMax {
		t.Fatalf("the application range is inverted: %d-%d", AppPortMin, AppPortMax)
	}
	if AppPortMax >= EphemeralPortMin {
		t.Errorf("the application range ends at %d, inside the ephemeral range that starts at %d",
			AppPortMax, EphemeralPortMin)
	}
	if AppPortMin < 1024 {
		t.Errorf("the application range starts at %d, in the privileged ports", AppPortMin)
	}
}
