package mail

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

func limitRequest(role string) *http.Request {
	request := httptest.NewRequest(http.MethodPut, "/domains/1/mail/2/send-limits", nil)
	if role == "" {
		return request
	}
	claims := &auth.Claims{UserID: 1, Username: "actor", Role: role}
	return request.WithContext(auth.WithClaims(request.Context(), claims))
}

// send_limits_manual is what makes a value survive every later plan change, so a
// customer who could set it would make their own ceiling permanent. Only an
// operator may.
func TestOnlyAnOperatorMaySetALimitByHand(t *testing.T) {
	for role, want := range map[string]bool{
		middleware.RoleAdmin:    true,
		middleware.RoleReseller: true,
		middleware.RoleUser:     false,
		"":                      false,
	} {
		if got := isMailOperator(limitRequest(role)); got != want {
			t.Errorf("role %q: operator = %v, want %v", role, got, want)
		}
	}
}

// A stored 0 is UNLIMITED to the policy server, not "no override", so a customer
// setting it removes the outbound ceiling entirely. On a stock installation the
// two server-wide backstops are off, so nothing else would hold them.
func TestACustomerCannotSetAnUnlimitedSendLimit(t *testing.T) {
	plan := PlanMailLimits{SendLimitHour: 100, SendLimitDay: 1000}
	for _, req := range []SendLimits{
		{HourLimit: 0, DayLimit: 500},
		{HourLimit: 50, DayLimit: 0},
		{HourLimit: 0, DayLimit: 0},
	} {
		if reason := refusalAgainstPlan(plan, req); reason == "" {
			t.Errorf("%+v was accepted, want a refusal", req)
		}
	}
}

// The plan's ceiling is the whole point: a customer may lower its own limits and
// never raise them past what the subscription allows.
func TestACustomerCannotExceedThePlansCeiling(t *testing.T) {
	plan := PlanMailLimits{SendLimitHour: 100, SendLimitDay: 1000}

	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 101, DayLimit: 1000}); reason == "" {
		t.Error("an hourly limit above the plan was accepted")
	}
	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 100, DayLimit: 1001}); reason == "" {
		t.Error("a daily limit above the plan was accepted")
	}
	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 10, DayLimit: 100}); reason != "" {
		t.Errorf("lowering below the plan was refused: %s", reason)
	}
	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 100, DayLimit: 1000}); reason != "" {
		t.Errorf("the plan's own values were refused: %s", reason)
	}
}

// A plan value of 0 means the plan sets NO override, so it is not a ceiling to
// hold anybody to. Reading it as "unlimited is the ceiling" would refuse every
// value on a plan that simply does not configure mail limits.
func TestAPlanWithoutMailLimitsImposesNoCeiling(t *testing.T) {
	plan := PlanMailLimits{}
	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 100000, DayLimit: 100000}); reason != "" {
		t.Errorf("a plan that sets no mail limits refused a value: %s", reason)
	}
	// Zero is still refused, because it is unlimited rather than a high number.
	if reason := refusalAgainstPlan(plan, SendLimits{HourLimit: 0, DayLimit: 0}); reason == "" {
		t.Error("unlimited was accepted on a plan that sets no mail limits")
	}
}
