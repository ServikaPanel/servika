package laravel

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// baseWorker is a definition every field of which is already inside its range,
// so a test can change exactly one thing.
func baseWorker() Worker {
	return Worker{
		ID: 7, DomainID: 3, Name: "default", Connection: "database",
		Processes: 2, Tries: 3, Timeout: 60, Sleep: 3, MaxJobs: 1000, MemoryMB: 128,
		Enabled: true,
	}
}

// The queue list lands on an ExecStart line, so a newline in it is a second
// systemd directive running as the tenant. strings.Split leaves the newline
// sitting inside a token, which is why the raw string is checked before it is
// split rather than each token afterwards.
func TestAQueueNameCannotIntroduceASecondDirective(t *testing.T) {
	refused := []string{
		"high\nExecStartPre=/bin/sh -c id",
		"high\rdefault",
		"high\x00default",
		// systemd expands % as a specifier in ExecStart, so a queue named %h
		// would run against a path nobody wrote.
		"%h",
		"high,%n",
		"high default", // a space is another argument, not another queue
		"--daemon",     // a flag smuggled in through the queue list
		"high;touch /tmp/x",
		// TrimSpace would quietly drop this newline and leave a list that
		// looks fine. Refusing is the point: input carrying a line break is
		// not what the customer typed into a one-line field, and silently
		// rewriting it hides that from them.
		"high,\ndefault",
	}
	for _, raw := range refused {
		if _, ok := NormalizeQueues(raw); ok {
			t.Errorf("%q was accepted as a queue list", raw)
		}
	}

	accepted := map[string]string{
		"":                    "",
		"high":                "high",
		"high,default":        "high,default",
		" high , default ":    "high,default",
		"emails.v2,reports-1": "emails.v2,reports-1",
	}
	for raw, want := range accepted {
		got, ok := NormalizeQueues(raw)
		if !ok {
			t.Errorf("%q was refused", raw)
			continue
		}
		if got != want {
			t.Errorf("%q normalized to %q, want %q", raw, got, want)
		}
	}
}

// A value outside its range is refused with a reason code, never clamped. A
// screen that asked for twelve processes and silently got ten is telling the
// operator something untrue about their own server.
func TestAnOutOfRangeValueIsRefusedRatherThanClamped(t *testing.T) {
	cases := map[string]func(*Worker){
		"processes above the ceiling": func(w *Worker) { w.Processes = maxWorkerProcesses + 1 },
		"processes below one":         func(w *Worker) { w.Processes = 0 },
		"timeout above the ceiling":   func(w *Worker) { w.Timeout = 601 },
		"timeout below the floor":     func(w *Worker) { w.Timeout = 1 },
		"tries above the ceiling":     func(w *Worker) { w.Tries = 11 },
		"sleep above the ceiling":     func(w *Worker) { w.Sleep = 61 },
		"memory below the floor":      func(w *Worker) { w.MemoryMB = 32 },
		"memory above the ceiling":    func(w *Worker) { w.MemoryMB = 2048 },
		"max jobs below the floor":    func(w *Worker) { w.MaxJobs = 5 },
	}
	for name, mutate := range cases {
		worker := baseWorker()
		mutate(&worker)
		reason := ValidateWorker(&worker)
		if reason != reasonWorkerRange {
			t.Errorf("%s: reason = %q, want %q", name, reason, reasonWorkerRange)
		}
	}

	// Zero max_jobs means no ceiling and must stay accepted, or the guard above
	// is over-broad and refuses a definition it was never meant to touch.
	worker := baseWorker()
	worker.MaxJobs = 0
	if reason := ValidateWorker(&worker); reason != "" {
		t.Errorf("max_jobs=0 was refused with %q", reason)
	}
}

// A name reaches the unit Description and the unique key, so it is checked too.
func TestAWorkerNameIsCheckedBeforeItReachesAUnit(t *testing.T) {
	for _, name := range []string{"", "Default", "a b", "x\ny", "-lead", strings.Repeat("a", 33)} {
		worker := baseWorker()
		worker.Name = name
		if reason := ValidateWorker(&worker); reason != reasonWorkerName {
			t.Errorf("name %q gave reason %q, want %q", name, reason, reasonWorkerName)
		}
	}
	for _, name := range []string{"default", "high-priority", "emails_v2", "a"} {
		worker := baseWorker()
		worker.Name = name
		if reason := ValidateWorker(&worker); reason != "" {
			t.Errorf("name %q was refused with %q", name, reason)
		}
	}
}

// The restart rate limit only applies from [Unit]. In [Service] systemd 257
// ignores StartLimitIntervalSec and silently accepts StartLimitBurst, so the
// burst counts against the default ten-second window that RestartSec=5 can
// never fill, and a worker that cannot start restarts every five seconds for
// good instead of reaching failed.
func TestTheRestartRateLimitIsDeclaredWhereSystemdReadsIt(t *testing.T) {
	unit := RenderWorkerUnit(baseWorker(), 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")

	service := strings.Index(unit, "\n[Service]")
	if service < 0 {
		t.Fatal("the unit has no [Service] section")
	}
	for _, key := range []string{"StartLimitIntervalSec=300", "StartLimitBurst=5"} {
		at := strings.Index(unit, key)
		switch {
		case at < 0:
			t.Errorf("the unit no longer declares %s", key)
		case at > service:
			t.Errorf("%s sits in [Service], where systemd ignores it", key)
		}
	}
}

// systemd sends SIGTERM on a stop and Laravel finishes the job in hand. A stop
// timeout at or below the job timeout turns every restart into a SIGKILL
// mid-job, which loses the job or replays it with its side effects.
func TestTheStopTimeoutOutlastsTheJobTimeout(t *testing.T) {
	for _, timeout := range []int{5, 60, 600} {
		worker := baseWorker()
		worker.Timeout = timeout
		unit := RenderWorkerUnit(worker, 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
		want := "TimeoutStopSec=" + strconv.Itoa(timeout+30)
		if !strings.Contains(unit, want) {
			t.Errorf("timeout %d: the unit is missing %q", timeout, want)
		}
	}
}

// The worker runs as the tenant, so without these two the process reads every
// other tenant's home with its own user's permissions.
func TestAWorkerCannotSeeAnotherTenantsHome(t *testing.T) {
	unit := RenderWorkerUnit(baseWorker(), 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
	for _, want := range []string{"ProtectHome=tmpfs", "BindPaths=/home/c_example", "ReadWritePaths=/home/c_example"} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit is missing %q", want)
		}
	}
}

// A cgroup ceiling calls in the OOM killer and loses the job in flight, while
// Laravel's own --memory tells the worker to exit cleanly after finishing it.
func TestTheMemoryCeilingLetsTheJobFinish(t *testing.T) {
	unit := RenderWorkerUnit(baseWorker(), 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
	if !strings.Contains(unit, "--memory=128") {
		t.Error("the worker is not given Laravel's own memory ceiling")
	}
	if strings.Contains(unit, "MemoryMax=") {
		t.Error("the unit sets a cgroup memory ceiling, which kills the job in flight")
	}
}

// systemd opens an append: target with O_APPEND|O_CREAT and follows a symlink,
// so a log inside the tenant's own home lets a planted link redirect a
// root-opened descriptor.
func TestTheLogTargetIsNotInsideATenantHome(t *testing.T) {
	path := WorkerLogPath(7)
	if strings.HasPrefix(path, "/home/") {
		t.Errorf("the log target is inside a tenant-writable tree: %s", path)
	}
	unit := RenderWorkerUnit(baseWorker(), 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
	if !strings.Contains(unit, "StandardOutput=append:"+path) {
		t.Errorf("the unit does not append to %s", path)
	}
}

// An empty queue list means the connection's own default queue, so the flag is
// left off entirely rather than passed empty, which Laravel reads as a queue
// literally named "".
func TestAnEmptyQueueListLeavesTheFlagOff(t *testing.T) {
	worker := baseWorker()
	worker.Queues = ""
	unit := RenderWorkerUnit(worker, 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
	if strings.Contains(unit, "--queue") {
		t.Error("an empty queue list still rendered a --queue flag")
	}

	worker.Queues = "high,default"
	unit = RenderWorkerUnit(worker, 3, "c_example", "/home/c_example/public_html", "/usr/bin/php83")
	if !strings.Contains(unit, "--queue=high,default") {
		t.Error("the queue list did not reach ExecStart")
	}
}

// Instances are named after the worker row, not the domain, because a domain
// may define several workers and they would otherwise share one unit.
func TestEveryWorkerGetsItsOwnUnitName(t *testing.T) {
	if UnitTemplate(7) == UnitTemplate(8) {
		t.Error("two workers share one template")
	}
	if UnitInstance(7, 1) == UnitInstance(7, 2) {
		t.Error("two instances of one worker share a name")
	}
	if !strings.HasSuffix(UnitTemplate(7), "@.service") {
		t.Errorf("%s is not a template unit", UnitTemplate(7))
	}
}

// The log read must not follow a link the tenant planted at the log path.
func TestTheLogTailRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_LARAVEL_LOG_DIR", dir)

	secret := dir + "/secret"
	if err := os.WriteFile(secret, []byte("root:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, WorkerLogPath(7)); err != nil {
		t.Fatal(err)
	}
	if body := WorkerLogTail(7); body != "" {
		t.Errorf("the log tail followed a symlink and returned %q", body)
	}
}
