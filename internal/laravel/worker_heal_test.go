package laravel

import (
	"os"
	"strings"
	"testing"
)

// The domain delete path is the only thing that reaches these files. Without a
// call there the unit keeps running as a login userdel has just removed and the
// cron entry keeps trying to run a scheduler in a directory that is gone.
func TestTheDomainDeletePathTearsDownTheToolkit(t *testing.T) {
	source, err := os.ReadFile("../domains/handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "laravel.TeardownForDomain(r.Context(), h.DB, id)") {
		t.Error("deleting a domain no longer tears the Laravel toolkit down")
	}
}

// Teardown must reach the schedule cron and the pre-worker unit as well as the
// workers, because both are named after the DOMAIN and survive a worker table
// that cannot be read at all.
func TestTeardownReachesEveryArtefactNamedAfterTheDomain(t *testing.T) {
	body := sourceOf(t, "worker_heal.go")
	for _, want := range []string{
		"os.Remove(cronPath(domainID))",
		"stopInstance(legacyQueueUnit(domainID))",
		"os.Remove(legacyQueueUnitPath(domainID))",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("teardown no longer performs %s", want)
		}
	}
	// The domain-named artefacts must be removed OUTSIDE the loop over worker
	// rows, or a domain whose worker table cannot be read at all keeps its
	// scheduler. The loop BODY is what is examined: a position check against
	// the loop's opening line passes either way, since inside the loop is also
	// textually after it.
	loop := strings.Index(body, "for _, worker := range workers {")
	if loop < 0 {
		t.Fatal("the worker loop moved; this test has to follow it")
	}
	end := strings.Index(body[loop:], "\n\t}")
	if end < 0 {
		t.Fatal("the worker loop has no closing brace at function indentation")
	}
	if strings.Contains(body[loop:loop+end], "cronPath") {
		t.Error("the schedule removal sits inside the worker loop, so an unreadable worker table strands it")
	}
}

// The teardown sweep and the instance sweep must both walk to the fixed ceiling.
// Walking to a stored process count misses exactly the instances a half-applied
// write left behind.
func TestTheInstanceSweepWalksToTheFixedCeiling(t *testing.T) {
	body := sourceOf(t, "worker_systemd.go")
	teardown := body[strings.Index(body, "func TeardownWorker("):]
	if !strings.Contains(teardown, "index <= maxWorkerProcesses") {
		t.Error("teardown no longer walks every instance the ceiling allows")
	}
	apply := body[strings.Index(body, "func ApplyWorker("):]
	if !strings.Contains(apply, "for index := wanted + 1; index <= maxWorkerProcesses; index++") {
		t.Error("reducing the process count no longer stops the instances above it")
	}
}

// A schedule cron is removed only when the database positively says the domain
// is gone. Removing on any other error would take out the scheduler of every
// live domain the moment the database is briefly unreadable.
func TestAnUnreadableDatabaseKeepsEveryScheduleInPlace(t *testing.T) {
	body := sourceOf(t, "worker_heal.go")
	if !strings.Contains(body, "if !errors.Is(err, sql.ErrNoRows) {") {
		t.Error("the schedule sweep no longer requires a positive answer before removing a file")
	}
}

// The pre-worker unit shape is removed unconditionally: nothing produces it any
// more, so one surviving an upgrade runs against columns that were dropped.
func TestTheUnitShapeThatPredatesWorkerRowsIsAlwaysRemoved(t *testing.T) {
	if !reLegacyQueueUnit.MatchString("servika-laravel-queue-12.service") {
		t.Error("the pre-worker unit name is no longer recognised")
	}
	// The template and its instances must NOT match that pattern, or healing
	// would tear down every live worker it walks past.
	for _, name := range []string{
		"servika-laravel-queue-12@.service",
		"servika-laravel-queue-12@3.service",
	} {
		if reLegacyQueueUnit.MatchString(name) {
			t.Errorf("%s is treated as a pre-worker unit and would be removed", name)
		}
	}
	if !reWorkerUnitFile.MatchString("servika-laravel-queue-12@.service") {
		t.Error("the template unit is no longer recognised")
	}
	// Healing must not touch a unit another package owns.
	for _, name := range []string{"servika-app-12.service", "servika-laravel-deploy-12.service"} {
		if reWorkerUnitFile.MatchString(name) || reLegacyQueueUnit.MatchString(name) {
			t.Errorf("%s would be torn down by the Laravel heal", name)
		}
	}
}

func sourceOf(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
