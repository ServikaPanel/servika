package accounts

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// Creating a customer decides two things the rest of the panel depends on: the
// reseller that owns the row, and whether the reseller had room for it. Only the
// plan check was pinned, so these tests cover the rest before the handler is
// split.

// resellerRequest is a create request from a reseller with the given user id.
func resellerRequest(userID int64, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/customers", strings.NewReader(body))
	ctx := auth.WithClaims(request.Context(),
		&auth.Claims{UserID: userID, Username: "reseller", Role: middleware.RoleReseller})
	return request.WithContext(ctx)
}

// create runs the handler with the given request and script.
func create(t *testing.T, script *accountScript, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(accountConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).CreateCustomer(recorder, request)
	return recorder
}

// A body the handler cannot read, and a body with no name or no email, are both
// refused before any statement runs.
func TestAnIncompleteCreateRequestIsRefusedBeforeTheWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "not json", body: `{`, want: "invalid request body"},
		{name: "no name", body: `{"email":"a@b.c"}`, want: "name and email are required"},
		{name: "no email", body: `{"name":"Acme"}`, want: "name and email are required"},
		{name: "both blank", body: `{"name":"","email":""}`, want: "name and email are required"},
	} {
		script := &accountScript{}

		recorder := create(t, script, adminRequest(http.MethodPost, "/customers", tc.body))

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", tc.name, recorder.Code, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Errorf("%s: message = %s, want %q", tc.name, recorder.Body, tc.want)
		}
		if script.wrote("INSERT INTO customers") {
			t.Errorf("%s: a customer row was written", tc.name)
		}
	}
}

// A customer with no status is active. A blank status would reach every screen
// that groups customers by it.
func TestACustomerWithNoStatusIsActive(t *testing.T) {
	script := &accountScript{}

	recorder := create(t, script, adminRequest(http.MethodPost, "/customers", `{"name":"Acme","email":"a@b.c"}`))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	args := script.argsOf("INSERT INTO customers")
	if len(args) != 6 {
		t.Fatalf("insert arguments = %v", args)
	}
	if args[3] != "active" {
		t.Errorf("status = %v, want active", args[3])
	}
	if !strings.Contains(recorder.Body.String(), `"id":7`) {
		t.Errorf("the answer does not carry the new id: %s", recorder.Body)
	}
}

// A status the operator did set is kept.
func TestAGivenStatusIsKept(t *testing.T) {
	script := &accountScript{}

	create(t, script, adminRequest(http.MethodPost, "/customers", `{"name":"Acme","email":"a@b.c","status":"suspended"}`))

	if args := script.argsOf("INSERT INTO customers"); len(args) != 6 || args[3] != "suspended" {
		t.Errorf("insert arguments = %v, want the given status", args)
	}
}

// A customer an admin creates belongs to no reseller. A reseller's own customer
// is bound to it, because every list and every ownership check reads that column.
func TestTheOwnerIsTheResellerAndNobodyForAnAdmin(t *testing.T) {
	adminScript := &accountScript{}
	create(t, adminScript, adminRequest(http.MethodPost, "/customers", `{"name":"Acme","email":"a@b.c"}`))
	if args := adminScript.argsOf("INSERT INTO customers"); len(args) != 6 || args[5] != nil {
		t.Errorf("an admin's customer has owner %v, want none", args)
	}

	resellerScript := &accountScript{
		rows: map[string][]driver.Value{
			"FROM reseller_limits":                 {int64(5)},
			"FROM customers WHERE owner_user_id=?": {int64(1)},
		},
	}
	recorder := create(t, resellerScript, resellerRequest(42, `{"name":"Acme","email":"a@b.c"}`))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if args := resellerScript.argsOf("INSERT INTO customers"); len(args) != 6 || args[5] != int64(42) {
		t.Errorf("a reseller's customer has owner %v, want 42", args)
	}
}

// A reseller at its ceiling is refused with the limit message, and no row is
// written. The gate runs at creation time only, so a row past it stays.
func TestAResellerAtItsCeilingIsRefused(t *testing.T) {
	script := &accountScript{
		rows: map[string][]driver.Value{
			"FROM reseller_limits":                 {int64(2)},
			"FROM customers WHERE owner_user_id=?": {int64(2)},
		},
	}

	recorder := create(t, script, resellerRequest(42, `{"name":"Acme","email":"a@b.c"}`))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "reseller limit reached: at most 2 customers") {
		t.Errorf("message = %s", recorder.Body)
	}
	if script.wrote("INSERT INTO customers") {
		t.Fatal("a customer was written past the reseller ceiling")
	}
}

// A limit the handler cannot read is not proof of room.
func TestAnUnreadableResellerLimitRefusesTheWrite(t *testing.T) {
	script := &accountScript{}

	recorder := create(t, script, resellerRequest(42, `{"name":"Acme","email":"a@b.c"}`))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "could not verify reseller limit") {
		t.Errorf("message = %s", recorder.Body)
	}
	if script.wrote("INSERT INTO customers") {
		t.Fatal("a customer was written although the limit could not be read")
	}
}

// A reseller with no limits row has no ceiling, so the create goes through
// without a count.
func TestAResellerWithNoLimitsRowHasNoCeiling(t *testing.T) {
	script := &accountScript{noRows: map[string]bool{"FROM reseller_limits": true}}

	recorder := create(t, script, resellerRequest(42, `{"name":"Acme","email":"a@b.c"}`))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
}

// A write that fails is reported rather than answered as a created customer.
func TestAFailedInsertIsReported(t *testing.T) {
	script := &accountScript{
		execErr: map[string]error{"INSERT INTO customers": errors.New("write failed")},
	}

	recorder := create(t, script, adminRequest(http.MethodPost, "/customers", `{"name":"Acme","email":"a@b.c"}`))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "customer could not be created") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// A caller with no claims is treated as an admin creating an unowned customer,
// not as a reseller with no limit.
func TestARequestWithNoClaimsCreatesAnUnownedCustomer(t *testing.T) {
	script := &accountScript{}
	request := httptest.NewRequest(http.MethodPost, "/customers",
		strings.NewReader(`{"name":"Acme","email":"a@b.c"}`))

	recorder := create(t, script, request.WithContext(context.Background()))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if args := script.argsOf("INSERT INTO customers"); len(args) != 6 || args[5] != nil {
		t.Errorf("owner = %v, want none", args)
	}
}
