package sitesecurity

import "testing"

func TestOrderingIsSegmentBySegmentAndNumeric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0", "1.0.0", 0},    // a missing segment is zero
		{"1.2", "1.10", -1},    // numeric, not lexical: 2 < 10
		{"1.10", "1.2", 1},     //
		{"5.3.1", "5.3.2", -1}, // the real Contact Form 7 case
		{"5.3.2", "5.3.2", 0},
		{"5.4", "5.3.2", 1},
		{"v4.17.15", "4.17.21", -1},   // npm writes the leading v
		{"1.2.3+build.5", "1.2.3", 0}, // SemVer build metadata carries no order
		{"0.0.1", "0.0.0", 1},
	}
	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q, %q) could not judge", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The whole point of the second return value: a version this cannot order must
// produce NO ANSWER. Guessing high invents a finding on a site that is fine,
// guessing low hides a real one, and pre-release ordering differs between
// SemVer, PHP and the plugin repository, so there is no rule that is right for
// all three.
func TestAVersionItCannotOrderIsRefusedRatherThanGuessed(t *testing.T) {
	for _, version := range []string{
		"1.0.0-rc.2",
		"1.0.0-beta",
		"2.5.x",
		"latest",
		"",
		"   ",
		"1..2",
		"-1.0",
		"1.0.0a",
	} {
		if _, ok := Compare(version, "1.0.0"); ok {
			t.Errorf("Compare judged %q, which it cannot order", version)
		}
		if _, ok := Compare("1.0.0", version); ok {
			t.Errorf("Compare judged %q on the right, which it cannot order", version)
		}
	}
}

// The real record shape from wpvulnerability: Contact Form 7 < 5.3.2.
func TestTheUpperBoundOnlyRangeMatchesWhatItShould(t *testing.T) {
	for _, c := range []struct {
		installed string
		want      bool
	}{
		{"5.3.1", true},
		{"5.0", true},
		{"5.3.2", false},
		{"5.9.1", false},
	} {
		got, judged := InRange(c.installed, "", "", "5.3.2", "lt")
		if !judged {
			t.Fatalf("the range could not be judged for %q", c.installed)
		}
		if got != c.want {
			t.Errorf("InRange(%q, <5.3.2) = %v, want %v", c.installed, got, c.want)
		}
	}
}

// Both bounds present is a window, and a version outside either end is out.
func TestATwoSidedRangeExcludesBothEnds(t *testing.T) {
	for _, c := range []struct {
		installed string
		want      bool
	}{
		{"1.5", true},
		{"1.0", true},
		{"2.0", true},
		{"0.9", false},
		{"2.1", false},
	} {
		got, judged := InRange(c.installed, "1.0", "ge", "2.0", "le")
		if !judged {
			t.Fatalf("the range could not be judged for %q", c.installed)
		}
		if got != c.want {
			t.Errorf("InRange(%q, 1.0..2.0) = %v, want %v", c.installed, got, c.want)
		}
	}
}

// An operator the feed adds later must REFUSE, not fall through as "no bound".
// Treating an unknown bound as absent turns a narrow range into every version
// ever released, which is a finding on every site running the package.
func TestAnUnknownOperatorIsRefusedRatherThanIgnored(t *testing.T) {
	if _, judged := InRange("1.0", "", "", "2.0", "approximately"); judged {
		t.Error("an unknown maximum operator was judged")
	}
	if _, judged := InRange("1.0", "0.5", "roughly", "", ""); judged {
		t.Error("an unknown minimum operator was judged")
	}
	// An EMPTY operator beside a real bound is the same mistake: the feed said
	// there is a bound and did not say which way it points.
	if _, judged := InRange("1.0", "", "", "2.0", ""); judged {
		t.Error("a bound with no operator was judged")
	}
}

// A record with no bounds at all is what "the whole package is vulnerable and
// unfixed" looks like in this feed. It is reported rather than dropped.
func TestARecordWithNoBoundsClaimsEveryVersion(t *testing.T) {
	got, judged := InRange("9.9.9", "", "", "", "")
	if !judged {
		t.Fatal("an unbounded record could not be judged")
	}
	if !got {
		t.Error("an unbounded record matched nothing")
	}
}

// An installed version the comparison cannot order stops the record from being
// judged, so no row is written for it.
func TestAnUnorderableInstalledVersionStopsTheRange(t *testing.T) {
	if _, judged := InRange("1.0.0-rc.1", "", "", "2.0", "lt"); judged {
		t.Error("a pre-release version was judged against a range")
	}
}
