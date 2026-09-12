package provisioner

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// About 26 request handlers reach renderAndReload. `nginx -t` reads the whole
// configuration tree and `systemctl reload nginx` waits behind any other
// systemd job, and neither observed a deadline: the handler timeout cancels
// r.Context() and does not touch a child process, so a command that never
// returned held the handler, its goroutine and the connection until the socket
// write deadline dropped the client with no HTTP response at all. The render
// now ends in an ordinary error, and rolls the vhost back like any other
// validation failure.
func TestARenderThatCannotValidateGivesUpAndRollsBack(t *testing.T) {
	f := withRenderSequence(t)
	reloaded := hangingNginx(t)

	body, err := f.render(t, exampleVhost())

	if err == nil {
		t.Fatal("renderAndReload() returned no error while nginx -t never finished")
	}
	if !strings.Contains(err.Error(), "did not finish within") {
		t.Errorf("renderAndReload() error = %v, want it to name the budget", err)
	}
	if body != "" {
		t.Errorf("the vhost was left on disk after the validation gave up:\n%s", body)
	}
	if *reloaded {
		t.Error("nginx was reloaded although the configuration was never validated")
	}
}

// hangingNginx makes `nginx -t` sit there under a budget short enough for a
// test, and reports whether a reload was attempted after it.
func hangingNginx(t *testing.T) *bool {
	t.Helper()
	reloaded := false
	previousCommand, previousBudget := systemCommand, nginxBudget
	t.Cleanup(func() { systemCommand, nginxBudget = previousCommand, previousBudget })
	nginxBudget = 100 * time.Millisecond
	systemCommand = func(name string, _ ...string) *exec.Cmd {
		if name != "nginx" {
			reloaded = reloaded || name == "systemctl"
			return exec.Command("/bin/sh", "-c", "exit 0")
		}
		return exec.Command("/bin/sh", "-c", "sleep 30")
	}
	return &reloaded
}
