package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"

	"github.com/go-chi/chi/v5"
)

func TestRequireAuthRejectsOversizedTokenBeforeParsing(t *testing.T) {
	nextCalled := false
	handler := RequireAuth([]byte("01234567890123456789012345678901"))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 8193))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("RequireAuth() status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if nextCalled {
		t.Fatal("RequireAuth() called the protected handler for an oversized token")
	}
}

// Suspension is enforced through EnforceCustomerNotSuspended (the pma-token path
// uses it directly; CustomerScope shares the same suspendedDomainLookup seam).
// Only end customers (role=user) are gated; admin and reseller bypass it.
func TestEnforceCustomerNotSuspendedBlocksSuspendedCustomer(t *testing.T) {
	originalLookup := suspendedDomainLookup
	t.Cleanup(func() { suspendedDomainLookup = originalLookup })
	suspendedDomainLookup = func(context.Context, int64) (bool, error) { return true, nil }

	response := httptest.NewRecorder()
	if EnforceCustomerNotSuspended(response, reqRole(RoleUser, 5), 42) {
		t.Fatal("EnforceCustomerNotSuspended() allowed a suspended customer")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if !strings.Contains(response.Body.String(), "account is suspended") {
		t.Fatalf("response = %s", response.Body.String())
	}
}

func TestEnforceCustomerNotSuspendedFailsClosedWhenSuspensionCannotBeVerified(t *testing.T) {
	originalLookup := suspendedDomainLookup
	t.Cleanup(func() { suspendedDomainLookup = originalLookup })
	suspendedDomainLookup = func(context.Context, int64) (bool, error) { return false, context.Canceled }

	response := httptest.NewRecorder()
	if EnforceCustomerNotSuspended(response, reqRole(RoleUser, 5), 42) {
		t.Fatal("EnforceCustomerNotSuspended() allowed access without verifying suspension state")
	}
	// Denied, and the status says why: the panel could not check, which is a
	// "come back" rather than "your request was wrong".
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

// Regression guard for the single-token model: every identity now carries
// auth.Claims, so a bare "ClaimsFrom(r) != nil" bypass would let a suspended
// customer through. Admin and reseller must bypass; a customer must be gated;
// an anonymous request must be rejected.
func TestEnforceCustomerNotSuspendedRoleBehaviour(t *testing.T) {
	originalLookup := suspendedDomainLookup
	t.Cleanup(func() { suspendedDomainLookup = originalLookup })
	suspendedDomainLookup = func(context.Context, int64) (bool, error) { return true, nil }

	for _, role := range []string{RoleAdmin, RoleReseller} {
		rec := httptest.NewRecorder()
		if !EnforceCustomerNotSuspended(rec, reqRole(role, 1), 42) {
			t.Fatalf("%s must bypass end-customer suspension, code=%d", role, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	if EnforceCustomerNotSuspended(rec, httptest.NewRequest(http.MethodGet, "/", nil), 42) {
		t.Fatal("anonymous request must be rejected")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDomainOwnedByEnforcesCustomerDomain(t *testing.T) {
	tests := []struct {
		name     string
		context  context.Context
		domainID int64
		allowed  bool
	}{
		{name: "administrator may access any domain", context: auth.WithClaims(context.Background(), &auth.Claims{Role: RoleAdmin}), domainID: 42, allowed: true},
		{name: "customer without a DB is denied (fail-closed)", context: auth.WithClaims(context.Background(), &auth.Claims{Role: RoleUser, UserID: 3}), domainID: 42, allowed: false},
		{name: "missing identity is denied", context: context.Background(), domainID: 42, allowed: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", nil).WithContext(test.context)
			if got := DomainOwnedBy(request, test.domainID); got != test.allowed {
				t.Fatalf("DomainOwnedBy() = %t, want %t", got, test.allowed)
			}
		})
	}
}

// reqRole builds a request carrying a session token (auth.Claims) of the given role.
func reqRole(role string, uid int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: uid, Username: "t", Role: role}))
}

func TestAdminOnly(t *testing.T) {
	run := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, r)
		return rec.Code
	}

	if code := run(reqRole(RoleAdmin, 1)); code != http.StatusOK {
		t.Errorf("admin should pass, code=%d", code)
	}
	// The real regression: a reseller token carries auth.Claims; without the
	// role check it was treated as admin.
	if code := run(reqRole(RoleReseller, 2)); code != http.StatusForbidden {
		t.Errorf("reseller should get 403, code=%d", code)
	}
	if code := run(reqRole(RoleUser, 3)); code != http.StatusForbidden {
		t.Errorf("user role should get 403, code=%d", code)
	}
	if code := run(httptest.NewRequest(http.MethodGet, "/", nil)); code != http.StatusForbidden {
		t.Errorf("anonymous should get 403, code=%d", code)
	}
}

func TestResellerOrAbove(t *testing.T) {
	run := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		ResellerOrAbove(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, r)
		return rec.Code
	}

	if code := run(reqRole(RoleAdmin, 1)); code != http.StatusOK {
		t.Errorf("admin should pass, code=%d", code)
	}
	if code := run(reqRole(RoleReseller, 2)); code != http.StatusOK {
		t.Errorf("reseller should pass, code=%d", code)
	}
	if code := run(reqRole(RoleUser, 3)); code != http.StatusForbidden {
		t.Errorf("user role should get 403, code=%d", code)
	}
}

func TestScopeSQL(t *testing.T) {
	// Admin: no narrowing.
	if cond, arg := ScopeSQL(reqRole(RoleAdmin, 1), "d"); cond != "" || arg != nil {
		t.Errorf("admin must not be narrowed, cond=%q arg=%v", cond, arg)
	}

	// Reseller: EXISTS over the ownership chain + its own user id.
	cond, arg := ScopeSQL(reqRole(RoleReseller, 7), "d")
	if cond == "" || len(arg) != 1 || arg[0] != int64(7) {
		t.Errorf("reseller scope wrong: cond=%q arg=%v", cond, arg)
	}
	if !strings.Contains(cond, "owner_user_id") {
		t.Errorf("reseller scope must match owner_user_id, cond=%q", cond)
	}

	// Customer (role=user): the regression this fixes — the old switch had no
	// RoleUser branch and fell through to WHERE 1 = 0, so every scoped list
	// returned empty for a customer. It must now narrow over customers.user_id.
	cond, arg = ScopeSQL(reqRole(RoleUser, 42), "d")
	if cond == "" || len(arg) != 1 || arg[0] != int64(42) {
		t.Errorf("customer scope wrong: cond=%q arg=%v", cond, arg)
	}
	if !strings.Contains(cond, "sc.user_id") || strings.Contains(cond, "1 = 0") {
		t.Errorf("customer scope must match user_id, not fail-closed, cond=%q", cond)
	}

	// Anonymous: fail-closed — no row must match.
	cond, _ = ScopeSQL(httptest.NewRequest(http.MethodGet, "/", nil), "d")
	if cond != " WHERE 1 = 0" {
		t.Errorf("anonymous request must be fail-closed, cond=%q", cond)
	}
}

// ScopeSQL is now built on ScopeCondition, so the two must say the same thing
// for every role. A table that cannot use ScopeSQL (a notification with a NULL
// domain_id is panel-wide and belongs to admins alone, which no ownership
// condition expresses) ANDs the condition into its own clause, and a second
// hand-written copy of the ownership chain is how the two drift apart.
func TestTheComposableConditionSaysTheSameThingAsScopeSQL(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"admin", reqRole(RoleAdmin, 1)},
		{"reseller", reqRole(RoleReseller, 7)},
		{"customer", reqRole(RoleUser, 42)},
		{"anonymous", httptest.NewRequest(http.MethodGet, "/", nil)},
	} {
		clause, clauseArgs := ScopeSQL(tc.req, "d")
		cond, condArgs, unrestricted := ScopeCondition(tc.req, "d")

		want := ""
		if !unrestricted {
			want = " WHERE " + cond
		}
		if clause != want {
			t.Errorf("%s: ScopeSQL answered %q while the condition builds %q", tc.name, clause, want)
		}
		if len(clauseArgs) != len(condArgs) {
			t.Errorf("%s: the two disagree on argument count: %v vs %v", tc.name, clauseArgs, condArgs)
		}
		// Only an admin is unrestricted, and an admin is the only one ScopeSQL
		// answers with no clause at all.
		if unrestricted != (tc.name == "admin") {
			t.Errorf("%s: unrestricted=%v", tc.name, unrestricted)
		}
		// The condition never carries the leading keyword, or ANDing it into
		// another clause produces a syntax error rather than a narrowed query.
		if strings.HasPrefix(strings.TrimSpace(cond), "WHERE") {
			t.Errorf("%s: the condition still carries its own WHERE: %q", tc.name, cond)
		}
	}
}

func TestDomainOwnedByFailsClosed(t *testing.T) {
	// scopeDB is nil (no DB in this test) → a reseller's ownership cannot be
	// verified, so access must be DENIED. If it failed open, a DB error would
	// grant the reseller access to every domain.
	if DomainOwnedBy(reqRole(RoleReseller, 2), 99) {
		t.Error("reseller access must be denied without a DB (fail-closed)")
	}
	// Admin passes without touching the DB.
	if !DomainOwnedBy(reqRole(RoleAdmin, 1), 99) {
		t.Error("admin should access every domain")
	}
	// Customer (role=user) resolves ownership from the chain, which cannot be read
	// without a DB, so it must be denied (fail-closed) rather than pass open.
	if DomainOwnedBy(reqRole(RoleUser, 3), 99) {
		t.Error("customer access must be denied without a DB (fail-closed)")
	}
}

func TestCustomerScopeResellerWithoutScopeCannotPass(t *testing.T) {
	// scopeDB is nil → ResellerOwnsDomain is false → the reseller must get 403.
	// Regression guard: the old code passed resellers straight through because
	// ClaimsFrom != nil.
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "42")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, routeContext)
	ctx = auth.WithClaims(ctx, &auth.Claims{UserID: 2, Role: RoleReseller})
	request := httptest.NewRequest(http.MethodGet, "/domains/42", nil).WithContext(ctx)

	rec := httptest.NewRecorder()
	CustomerScope(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, request)

	if rec.Code != http.StatusForbidden {
		t.Errorf("reseller whose scope cannot be verified should get 403, code=%d", rec.Code)
	}
}
