package backups

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

func jobRequest(claims *auth.Claims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/backups/jobs", nil)
	if claims == nil {
		return r
	}
	return r.WithContext(auth.WithClaims(r.Context(), claims))
}

// The job list is mounted under ResellerOrAbove and backup_jobs carries no owner
// column, so an unnarrowed query handed every reseller the other resellers' jobs,
// including the domain each run was working on.
func TestTheJobListIsNarrowedForEveryoneButAnAdmin(t *testing.T) {
	admin := jobRequest(&auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin})
	if filter, args := jobScopeFilter(admin, "j"); filter != "" || args != nil {
		t.Fatalf("an admin was narrowed: %q %v", filter, args)
	}

	reseller := jobRequest(&auth.Claims{UserID: 7, Username: "agency", Role: middleware.RoleReseller})
	filter, args := jobScopeFilter(reseller, "j")
	if filter == "" {
		t.Fatal("a reseller reads every job on the server")
	}
	// The two ways a job may be theirs: it produced one of their archives, or
	// they started it. Both have to be present, or one class of job disappears.
	if !strings.Contains(filter, "EXISTS") || !strings.Contains(filter, "b.job_id=j.id") {
		t.Fatalf("the filter does not reach the job's own archives: %q", filter)
	}
	if !strings.Contains(filter, "j.started_by=?") {
		t.Fatalf("the filter drops the caller's own jobs: %q", filter)
	}
	// Every value is bound: the reseller's user id from ScopeSQL, then the name.
	if len(args) != 2 || args[0] != int64(7) || args[1] != "agency" {
		t.Fatalf("bound values are %v", args)
	}
	if strings.Contains(filter, "agency") {
		t.Fatalf("the username was interpolated into the SQL: %q", filter)
	}
}

// Fail closed. actorName answers "system" with no claims, which is the nightly
// job's own started_by, so an unauthenticated caller falling through to the
// started_by branch would read exactly the job that covers every domain.
func TestAnUnauthenticatedCallerMatchesNoJob(t *testing.T) {
	filter, args := jobScopeFilter(jobRequest(nil), "j")
	if strings.TrimSpace(filter) != "1 = 0" {
		t.Fatalf("an anonymous caller got the filter %q", filter)
	}
	if args != nil {
		t.Fatalf("an anonymous caller bound %v", args)
	}
}

// Visibility and content are separate questions: a reseller sees the nightly job
// because it backed up one of their domains, but active_domain names whichever
// domain that run is on right now, which is usually somebody else's.
func TestAVisibleJobStillHidesAnotherOperatorsNames(t *testing.T) {
	reseller := jobRequest(&auth.Claims{UserID: 7, Username: "agency", Role: middleware.RoleReseller})

	nightly := Job{ActiveDomain: "rival-customer.com", StartedBy: "system"}
	redactJobForScope(reseller, &nightly)
	if nightly.ActiveDomain != "" {
		t.Fatalf("another customer's domain survived: %q", nightly.ActiveDomain)
	}
	if nightly.StartedBy != "system" {
		t.Fatalf("the scheduler's own name was hidden: %q", nightly.StartedBy)
	}

	other := Job{ActiveDomain: "rival-customer.com", StartedBy: "rival-agency"}
	redactJobForScope(reseller, &other)
	if other.ActiveDomain != "" || other.StartedBy != "" {
		t.Fatalf("another operator's job leaked %q / %q", other.ActiveDomain, other.StartedBy)
	}

	// Their own job is theirs to read in full, or the progress line the page
	// exists to show goes blank for the person who started the work.
	mine := Job{ActiveDomain: "my-customer.com", StartedBy: "agency"}
	redactJobForScope(reseller, &mine)
	if mine.ActiveDomain != "my-customer.com" || mine.StartedBy != "agency" {
		t.Fatalf("the caller's own job was redacted: %q / %q", mine.ActiveDomain, mine.StartedBy)
	}
}

// An admin operates the server and the progress line is the whole point of the
// page, so redaction must not reach them.
func TestAnAdminReadsEveryJobUnredacted(t *testing.T) {
	admin := jobRequest(&auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin})
	j := Job{ActiveDomain: "any-customer.com", StartedBy: "agency"}
	redactJobForScope(admin, &j)
	if j.ActiveDomain != "any-customer.com" || j.StartedBy != "agency" {
		t.Fatalf("an admin was redacted: %q / %q", j.ActiveDomain, j.StartedBy)
	}
}

// A request that carries no identity at all must lose both fields, not keep them
// because the role check found nothing to compare.
func TestAnUnauthenticatedCallerReadsNoNames(t *testing.T) {
	j := Job{ActiveDomain: "any-customer.com", StartedBy: "agency"}
	redactJobForScope(jobRequest(nil), &j)
	if j.ActiveDomain != "" || j.StartedBy != "" {
		t.Fatalf("an anonymous caller read %q / %q", j.ActiveDomain, j.StartedBy)
	}
}
