package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func plans(t *testing.T) PlanStore {
	t.Helper()
	return PlanStore{Path: filepath.Join(t.TempDir(), "plans.json")}
}

func savePlan(t *testing.T, s PlanStore, p Plan) {
	t.Helper()
	if err := s.Save(p); err != nil {
		t.Fatalf("could not save the plan %q: %v", p.Name, err)
	}
}

func TestAHostWithNoPlanFileStartsEmpty(t *testing.T) {
	s := plans(t)
	status, err := s.Status(false)
	if err != nil {
		t.Fatalf("an absent file was read as a failure: %v", err)
	}
	if len(status.Plans) != 0 || len(status.Assignments) != 0 {
		t.Fatalf("an absent file produced %+v", status)
	}
}

func TestACorruptPlanFileIsReportedNotIgnored(t *testing.T) {
	s := plans(t)
	if err := os.WriteFile(s.Path, []byte("[broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Status(false); err == nil {
		t.Fatal("a corrupt file was read as an empty store; every plan on the host would silently vanish")
	}
}

func TestSavingTheSameNameReplacesRatherThanDuplicates(t *testing.T) {
	s := plans(t)
	savePlan(t, s, Plan{Name: "Basic", DiskQuotaMB: 1000})
	savePlan(t, s, Plan{Name: "basic", DiskQuotaMB: 2000})
	status, err := s.Status(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Plans) != 1 {
		t.Fatalf("saving the same name twice left %d plans", len(status.Plans))
	}
	if status.Plans[0].DiskQuotaMB != 2000 {
		t.Fatalf("the plan was not replaced: %+v", status.Plans[0])
	}
}

func TestAPlanNameOutsideThePatternIsRefused(t *testing.T) {
	s := plans(t)
	for _, name := range []string{"", strings.Repeat("a", 41), "quote\"name", "new\nline", "semi;colon", "brace{}"} {
		if err := s.Save(Plan{Name: name}); err == nil {
			t.Fatalf("plan name %q was accepted", name)
		}
	}
	for _, name := range []string{"Basic", "Gelişmiş Paket", "plan_1", "plan-2"} {
		if err := s.Save(Plan{Name: name}); err != nil {
			t.Fatalf("plan name %q was refused: %v", name, err)
		}
	}
}

func TestANegativeOrImpossibleLimitIsRefused(t *testing.T) {
	s := plans(t)
	bad := []Plan{
		{Name: "p", DiskQuotaMB: -1},
		{Name: "p", MaxConns: -1},
		{Name: "p", MaxBandwidth: -1},
		{Name: "p", MemoryMB: -1},
		{Name: "p", CPUPercent: -1},
		{Name: "p", CPUPercent: 101},
	}
	for _, p := range bad {
		if err := s.Save(p); err == nil {
			t.Fatalf("the plan %+v was accepted", p)
		}
	}
}

func TestAPlanStillAssignedToASiteIsNotDeleted(t *testing.T) {
	// Deleting it would leave that site pointing at a plan that does not exist.
	s := plans(t)
	savePlan(t, s, Plan{Name: "Basic"})
	if err := s.Assign("shop.example.com", "Basic"); err != nil {
		t.Fatal(err)
	}
	err := s.Delete("Basic")
	if err == nil {
		t.Fatal("a plan was deleted while a site still carried it")
	}
	if !strings.Contains(err.Error(), "shop.example.com") {
		t.Fatalf("the refusal does not name the site holding it: %v", err)
	}
	if err := s.Unassign("shop.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("Basic"); err != nil {
		t.Fatalf("the plan was still refused after its last site let go: %v", err)
	}
}

func TestADeletedSiteDoesNotLockItsPlanForever(t *testing.T) {
	// Without Forget the assignment is orphaned, and Delete then refuses the
	// plan because it is assigned to a site that no longer exists. The plan
	// could never be deleted again.
	s := plans(t)
	savePlan(t, s, Plan{Name: "Basic"})
	if err := s.Assign("gone.example.com", "Basic"); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget("gone.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("Basic"); err != nil {
		t.Fatalf("the plan is still locked by a site that no longer exists: %v", err)
	}
}

func TestForgettingASiteThatCarriesNoPlanIsNotAFailure(t *testing.T) {
	// It runs on every site deletion, including sites that never had a plan.
	s := plans(t)
	if err := s.Forget("never.example.com"); err != nil {
		t.Fatalf("forgetting an unassigned site failed: %v", err)
	}
}

func TestUnassigningASiteThatCarriesNoPlanIsReported(t *testing.T) {
	// Unlike Forget, this is an operator action, so answering success for no
	// work done would be a lie.
	s := plans(t)
	if err := s.Unassign("never.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unassigning an unassigned site answered %v", err)
	}
}

func TestAPlanThatIsNotThereIsReportedAsNotFound(t *testing.T) {
	s := plans(t)
	if _, err := s.Find("nothing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finding an absent plan answered %v", err)
	}
	if err := s.Delete("nothing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting an absent plan answered %v", err)
	}
}

func TestAnAssignedSiteIsFoundWhateverCaseItWasWrittenIn(t *testing.T) {
	s := plans(t)
	savePlan(t, s, Plan{Name: "Basic"})
	if err := s.Assign("SHOP.Example.COM", "Basic"); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Assignments["shop.example.com"] != "Basic" {
		t.Fatalf("the assignment was stored as %+v", status.Assignments)
	}
	if err := s.Unassign("shop.example.com"); err != nil {
		t.Fatalf("the assignment could not be removed under its lowercased name: %v", err)
	}
}

func TestZeroMeansUnlimitedInEveryLimit(t *testing.T) {
	// A plan leaving a limit at 0 must turn the limit OFF, not set it to zero.
	// A connection limit of literally zero would take the site down.
	if got := connectionLimit(0); got != iisUnlimited {
		t.Fatalf("a connection limit of 0 became %d, want the IIS maximum", got)
	}
	if got := bandwidthBytes(0); got != iisUnlimited {
		t.Fatalf("a bandwidth of 0 became %d, want the IIS maximum", got)
	}
	if limit, action := cpuThrottle(0); limit != 0 || action != "NoAction" {
		t.Fatalf("a CPU limit of 0 became %d/%s, want 0/NoAction", limit, action)
	}
	if got := memoryKB(0); got != 0 {
		t.Fatalf("a memory limit of 0 became %d, want the recycle turned off", got)
	}
}

func TestBandwidthIsConvertedFromKilobytesToBytes(t *testing.T) {
	// The plan holds KB per second and IIS wants BYTES per second. Passing the
	// plan's number through unchanged would throttle a site to a thousandth of
	// what the operator set.
	if got := bandwidthBytes(100); got != 100*1024 {
		t.Fatalf("100 KB/s became %d bytes/s, want %d", got, 100*1024)
	}
}

func TestALimitOverWhatIISAcceptsIsClampedNotRefused(t *testing.T) {
	// appcmd answers a hard error on an out-of-range number, which would fail
	// the whole assignment over a value the operator meant as "very large".
	if got := connectionLimit(iisUnlimited + 1); got != iisUnlimited {
		t.Fatalf("an oversized connection limit became %d", got)
	}
	if got := bandwidthBytes(iisUnlimited); got != iisUnlimited {
		t.Fatalf("an oversized bandwidth became %d", got)
	}
}

func TestTheCPULimitIsExpressedInThousandthsOfAPercent(t *testing.T) {
	// appcmd's unit is a thousandth of a percent. Passing 20 instead of 20000
	// would throttle the pool to 0.02%.
	limit, action := cpuThrottle(20)
	if limit != 20000 || action != "Throttle" {
		t.Fatalf("20%% became %d/%s, want 20000/Throttle", limit, action)
	}
}

func TestTheMemoryLimitIsConvertedToKilobytes(t *testing.T) {
	if got := memoryKB(512); got != 512*1024 {
		t.Fatalf("512 MB became %d KB, want %d", got, 512*1024)
	}
}

func TestTheQuotaEngineStateIsReportedAsItWasMeasured(t *testing.T) {
	// The panel has to be able to say "no quota is being enforced". Reporting
	// otherwise is a false assurance an operator would size a disk against.
	s := plans(t)
	for _, installed := range []bool{true, false} {
		status, err := s.Status(installed)
		if err != nil {
			t.Fatal(err)
		}
		if status.QuotaEngine != installed {
			t.Fatalf("a quota engine measured as %v was reported as %v", installed, status.QuotaEngine)
		}
	}
}
