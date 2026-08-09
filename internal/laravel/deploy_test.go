package laravel

import (
	"strings"
	"testing"
)

// A PHP worker loads the application once and keeps it in memory, so a deploy
// that does not restart it leaves the OLD code processing jobs until --max-time
// expires, which is up to an hour after a deploy the customer watched succeed.
func TestADeployMovesTheWorkersOntoTheNewCode(t *testing.T) {
	body := sourceOf(t, "deploy.go")
	if !strings.Contains(body, "h.restartWorkersAfterDeploy(ctx, id)") {
		t.Fatal("a finished deploy no longer restarts the workers")
	}
}

// The restart sits in the branch that WON the conditional update, so a deploy
// restarts its workers exactly once however many callers poll the status
// endpoint and however often the background reconciler runs.
func TestTheDeployRestartHappensExactlyOnce(t *testing.T) {
	body := sourceOf(t, "deploy.go")
	winner := strings.Index(body, "if affected, _ := result.RowsAffected(); affected == 1 {")
	if winner < 0 {
		t.Fatal("the single-winner branch moved; this test has to follow it")
	}
	end := strings.Index(body[winner:], "\n\t}")
	if end < 0 {
		t.Fatal("the single-winner branch has no closing brace at function indentation")
	}
	if !strings.Contains(body[winner:winner+end], "restartWorkersAfterDeploy") {
		t.Error("the restart sits outside the single-winner branch, so every poll of the status endpoint restarts the workers again")
	}
}

// `artisan queue:restart` writes a cache key the worker polls, so an
// application whose cache driver is misconfigured loses the signal silently,
// which is exactly the state somebody is most likely deploying to fix. The
// panel restarts through systemd instead, which depends on nothing the tenant
// configured.
func TestTheDeployDoesNotRelyOnTheApplicationsOwnCache(t *testing.T) {
	body := sourceOf(t, "deploy.go")
	// Only the script builder is examined. The command box still offers
	// queue:restart as something a customer can run by hand, and the comment
	// explaining this decision names it too.
	script := strings.Index(body, "func deployScript(")
	if script < 0 {
		t.Fatal("deployScript was renamed; this test has to follow it")
	}
	end := strings.Index(body[script:], "\n}")
	if end < 0 {
		t.Fatal("deployScript has no closing brace")
	}
	if strings.Contains(body[script:script+end], "queue:restart") {
		t.Error("the deploy script signals the workers through the application cache, which a broken cache driver swallows")
	}
}
