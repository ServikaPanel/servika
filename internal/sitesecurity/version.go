package sitesecurity

import (
	"strconv"
	"strings"
)

// Compare orders two package version strings, and reports whether it could.
//
// The second return value is the point of this function. Every caller here is
// deciding whether to write a row that says a customer's site is vulnerable, so
// a version it cannot understand must produce NO ANSWER rather than a guess.
// Guessing high invents a finding on a site that is fine; guessing low hides a
// real one. The scan counts what it could not judge and reports that number
// beside the findings, which is the only honest thing to do with it.
//
// The comparison is numeric segment by numeric segment, which is what plugin,
// npm and Composer versions overwhelmingly are. A segment that is not a plain
// decimal number gives up: pre-release ordering ("1.0.0-rc.2" before "1.0.0")
// differs between SemVer, PHP and the WordPress plugin repository, and a rule
// that is right for one is wrong for the others.
//
// A leading "v" is dropped because both npm and Composer write it, and a
// trailing build tag after "+" is dropped because SemVer defines it as carrying
// no ordering at all.
func Compare(a, b string) (int, bool) {
	left, leftOK := versionFields(a)
	right, rightOK := versionFields(b)
	if !leftOK || !rightOK {
		return 0, false
	}
	for i := 0; i < len(left) || i < len(right); i++ {
		// A missing segment is zero, so 1.2 and 1.2.0 are the same version.
		// Both spellings appear in the same feed for the same release.
		var l, r int64
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		switch {
		case l < r:
			return -1, true
		case l > r:
			return 1, true
		}
	}
	return 0, true
}

// versionFields splits a version into its numeric segments, or reports that it
// is not a shape this can order.
func versionFields(version string) ([]int64, bool) {
	v := strings.TrimSpace(version)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// SemVer build metadata is explicitly not ordered, so it is removed rather
	// than refused: "1.2.3+build.5" and "1.2.3" are the same release.
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	fields := make([]int64, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n < 0 {
			return nil, false
		}
		fields = append(fields, n)
	}
	return fields, true
}

// InRange reports whether installed falls inside the range a wpvulnerability
// record describes, and whether the record could be judged at all.
//
// The operators are the feed's own words. An operator this does not know is
// REFUSED rather than assumed: the feed can add one, and treating an unknown
// bound as "no bound" turns a narrow range into every version ever released.
func InRange(installed, minVersion, minOperator, maxVersion, maxOperator string) (bool, bool) {
	if minVersion != "" {
		ok, judged := satisfies(installed, minOperator, minVersion)
		if !judged {
			return false, false
		}
		if !ok {
			return false, true
		}
	}
	if maxVersion != "" {
		ok, judged := satisfies(installed, maxOperator, maxVersion)
		if !judged {
			return false, false
		}
		if !ok {
			return false, true
		}
	}
	// A record with no bound at all claims every version. That is what "the
	// whole plugin is vulnerable and unfixed" looks like in this feed, so it is
	// reported rather than dropped.
	return true, true
}

// satisfies applies one of the feed's comparison operators.
func satisfies(installed, operator, bound string) (bool, bool) {
	order, ok := Compare(installed, bound)
	if !ok {
		return false, false
	}
	switch operator {
	case "lt":
		return order < 0, true
	case "le":
		return order <= 0, true
	case "gt":
		return order > 0, true
	case "ge":
		return order >= 0, true
	case "eq":
		return order == 0, true
	default:
		return false, false
	}
}
