package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// routeTable is main.go, which IS the route table: every endpoint and its
// middleware tier is declared there. main() opens a database and provisions the
// host, so the wiring cannot be exercised here; the declaration is what these
// assertions read.
func routeTable(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

// routeGuard returns the middleware a route is mounted with.
func routeGuard(t *testing.T, method, path string) string {
	t.Helper()
	// The guard must sit immediately before the mount. Allowing anything between
	// them let the regex pair a route with the PREVIOUS line's guard.
	pattern := regexp.MustCompile(
		`middleware\.(\w+)\)\.` + method + `\("` + regexp.QuoteMeta(path) + `"`)
	match := pattern.FindStringSubmatch(routeTable(t))
	if match == nil {
		t.Fatalf("%s %s is not mounted with a middleware.* guard in main.go", method, path)
	}
	return match[1]
}

// The metrics endpoint reports request counts and latency by method, route
// pattern and status across the WHOLE server: every reseller's and every
// customer's traffic, how often admin-only routes are exercised, and the global
// error rate. A reseller's scope is its own customers, and metrics.Handler's own
// comment states it is admin-gated at the route layer.
//
// The neighbouring /system/usage and /system/services are deliberately
// reseller-visible so a reseller can offer support; they describe the HOST, not
// other tenants' traffic. This asserts the two decisions stay apart.
func TestTheMetricsEndpointIsAdminOnly(t *testing.T) {
	if guard := routeGuard(t, "Get", "/system/metrics"); guard != "AdminOnly" {
		t.Errorf("/system/metrics is mounted with middleware.%s, want AdminOnly", guard)
	}
}

func TestHostStatusStaysVisibleToAReseller(t *testing.T) {
	for _, path := range []string{"/system/usage", "/system/services"} {
		if guard := routeGuard(t, "Get", path); guard != "ResellerOrAbove" {
			t.Errorf("%s is mounted with middleware.%s, want ResellerOrAbove", path, guard)
		}
	}
}

// A guard that no longer exists would make every assertion above vacuous.
func TestTheGuardNamesUsedByTheseAssertionsExist(t *testing.T) {
	table := routeTable(t)
	for _, guard := range []string{"middleware.AdminOnly", "middleware.ResellerOrAbove"} {
		if !strings.Contains(table, guard) {
			t.Errorf("%s is not used anywhere in the route table", guard)
		}
	}
}
