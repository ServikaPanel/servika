package config

import (
	"runtime"
	"strconv"
	"testing"
)

// The panel shares one MariaDB with every tenant site. AlmaLinux 10 ships
// max_connections at 151 and servika-optimize raises it to 200, so a panel pool
// that could grow past the cap would starve the sites the server exists to host.
func TestThePoolNeverGrowsPastWhatTheServerCanShare(t *testing.T) {
	if DBMaxOpenConnsCap >= 151 {
		t.Fatalf("cap %d is at or above the stock MariaDB max_connections of 151", DBMaxOpenConnsCap)
	}
	n, override := DBMaxOpenConns()
	if override != "" {
		t.Fatalf("no override was set, got %q", override)
	}
	if n > DBMaxOpenConnsCap {
		t.Fatalf("default pool %d exceeds the cap %d", n, DBMaxOpenConnsCap)
	}
}

// The previous fixed value was 16. A host must not come out of this change with
// fewer connections than it had.
func TestNoHostLosesCapacity(t *testing.T) {
	n, _ := DBMaxOpenConns()
	if n < 16 {
		t.Fatalf("pool %d is below the 16 this replaced (NumCPU=%d)", n, runtime.NumCPU())
	}
}

// An override outside the bounds is reported and NOT applied: a pool of one
// deadlocks the panel, and a pool wider than the server's own max_connections
// fails at the point of use, in the middle of somebody's request.
func TestAnOutOfRangeOverrideIsReportedAndNotApplied(t *testing.T) {
	fallback, _ := DBMaxOpenConns()

	refused := []struct {
		name  string
		value string
	}{
		{"far below the floor", "1"},
		{"just below the floor", strconv.Itoa(DBMinOpenConns - 1)},
		{"just above the cap", strconv.Itoa(DBMaxOpenConnsCap + 1)},
		{"far above the cap", "5000"},
		{"negative", "-8"},
		{"zero", "0"},
		{"not a number", "many"},
		{"a float", "32.5"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SERVIKA_DB_MAX_CONNS", tc.value)
			n, override := DBMaxOpenConns()
			if override == "" {
				t.Fatalf("%q was accepted silently", tc.value)
			}
			if n != fallback {
				t.Fatalf("refused value still changed the pool: got %d, want the default %d", n, fallback)
			}
		})
	}
}

// A value inside the bounds is what the operator gets, or the variable is
// decoration.
func TestAnOverrideInsideTheBoundsIsApplied(t *testing.T) {
	for _, value := range []int{DBMinOpenConns, 20, 32, DBMaxOpenConnsCap} {
		t.Run(strconv.Itoa(value), func(t *testing.T) {
			t.Setenv("SERVIKA_DB_MAX_CONNS", strconv.Itoa(value))
			n, override := DBMaxOpenConns()
			if override != "" {
				t.Fatalf("in-range %d was reported as a problem: %s", value, override)
			}
			if n != value {
				t.Fatalf("pool is %d, want the requested %d", n, value)
			}
		})
	}
}

// Whitespace around an otherwise valid value is the shape an environment file
// produces, and an unset variable must not be read as a refused one.
func TestSurroundingWhitespaceAndAnEmptyValueAreNotErrors(t *testing.T) {
	t.Setenv("SERVIKA_DB_MAX_CONNS", "  32  ")
	if n, override := DBMaxOpenConns(); override != "" || n != 32 {
		t.Fatalf("padded value gave %d, %q", n, override)
	}
	t.Setenv("SERVIKA_DB_MAX_CONNS", "")
	fallback := min(max(runtime.NumCPU()*4, DBMinOpenConns), DBMaxOpenConnsCap)
	if n, override := DBMaxOpenConns(); override != "" || n != fallback {
		t.Fatalf("empty value gave %d, %q, want the default %d", n, override, fallback)
	}
}
