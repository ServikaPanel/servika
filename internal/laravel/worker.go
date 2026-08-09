package laravel

// Queue workers: one systemd template unit per definition, one instance per
// process.
//
// Everything a customer types here ends up on an ExecStart line, so this file is
// the validation boundary. What it lets through, systemd runs.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/config"
)

// maxWorkerProcesses bounds the instance count.
//
// It is not the resource limit: the tenant slice already carries TasksMax and
// MemoryMax from the plan, and that is what actually stops a domain from taking
// the server. This only keeps an absurd number off the screen, and it is a
// CONSTANT because the instance sweep walks up to it (see ApplyWorker).
const maxWorkerProcesses = 10

// Stable reason codes. The API is English and the panel renders twelve
// languages, so a screen maps the code, never the sentence.
const (
	reasonWorkerName       = "laravel_worker_name_invalid"
	reasonWorkerConnection = "laravel_worker_connection_invalid"
	reasonWorkerQueues     = "laravel_worker_queues_invalid"
	reasonWorkerRange      = "laravel_worker_value_out_of_range"
	reasonWorkerDuplicate  = "laravel_worker_name_taken"
	reasonWorkerUnknown    = "laravel_worker_unknown"
	reasonWorkerApplyFail  = "laravel_worker_apply_failed"
)

// Worker is one queue worker definition.
type Worker struct {
	ID         int64  `json:"id"`
	DomainID   int64  `json:"domain_id"`
	Name       string `json:"name"`
	Connection string `json:"connection"`
	// Queues is a comma separated list. Empty means the connection's own
	// default queue, and the --queue flag is left off entirely.
	Queues    string `json:"queues"`
	Processes int    `json:"processes"`
	Tries     int    `json:"tries"`
	Timeout   int    `json:"timeout_sec"`
	Sleep     int    `json:"sleep_sec"`
	MaxJobs   int    `json:"max_jobs"`
	MemoryMB  int    `json:"memory_mb"`
	Enabled   bool   `json:"enabled"`
}

// UnitTemplate is the template unit that serves every instance of one worker.
func UnitTemplate(workerID int64) string {
	return "servika-laravel-queue-" + strconv.FormatInt(workerID, 10) + "@.service"
}

// UnitInstance is one running process of a worker.
func UnitInstance(workerID int64, index int) string {
	return "servika-laravel-queue-" + strconv.FormatInt(workerID, 10) +
		"@" + strconv.Itoa(index) + ".service"
}

// UnitTemplatePath is where the template is written.
func UnitTemplatePath(workerID int64) string {
	return filepath.Join(unitDir, UnitTemplate(workerID))
}

// WorkerLogPath is where every instance of one worker appends.
//
// The directory is root-owned rather than the tenant's home: systemd opens an
// append: target with O_APPEND|O_CREAT and FOLLOWS a symlink, so a target a
// tenant can write lets a planted link redirect a root-opened descriptor.
//
// All instances share one file. Each opens its own O_APPEND descriptor, so they
// interleave at write granularity but never truncate one another, and the
// question being asked of this screen is almost always "what did this worker
// do", not "what did process three do".
func WorkerLogPath(workerID int64) string {
	return filepath.Join(config.LaravelLogDir(), "queue-"+strconv.FormatInt(workerID, 10)+".log")
}

// ValidateWorker checks every field that reaches a unit file or a database row.
// It returns a reason code, empty when the definition is usable.
//
// Out-of-range values are REFUSED rather than clamped to a default. A screen
// that asked for twelve processes and silently got ten is telling the operator
// something untrue about their own server.
func ValidateWorker(w *Worker) string {
	w.Name = strings.TrimSpace(w.Name)
	if !reWorkerName.MatchString(w.Name) {
		return reasonWorkerName
	}
	w.Connection = strings.TrimSpace(w.Connection)
	if w.Connection == "" {
		w.Connection = "database"
	}
	if !reWorkerConnection.MatchString(w.Connection) {
		return reasonWorkerConnection
	}
	queues, ok := NormalizeQueues(w.Queues)
	if !ok {
		return reasonWorkerQueues
	}
	w.Queues = queues

	for _, bound := range []struct{ value, low, high int }{
		{w.Processes, 1, maxWorkerProcesses},
		{w.Tries, 1, 10},
		{w.Timeout, 5, 600},
		{w.Sleep, 0, 60},
		{w.MemoryMB, 64, 1024},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return reasonWorkerRange
		}
	}
	// 0 is "no ceiling", which is why max_jobs is not in the table above.
	if w.MaxJobs != 0 && (w.MaxJobs < 10 || w.MaxJobs > 100000) {
		return reasonWorkerRange
	}
	return ""
}

// NormalizeQueues validates the queue list and returns it in canonical form.
//
// The raw string is checked for \r, \n and \0 BEFORE it is split: a split on
// commas leaves a newline sitting inside a token, and once that token reaches
// ExecStart it is a second systemd directive. A per-token character class would
// catch it here, but the raw check is what makes that independent of the class
// ever being loosened.
//
// A '%' is refused because systemd expands it as a specifier in ExecStart, so a
// queue named "%h" would run against a path nobody wrote.
func NormalizeQueues(raw string) (string, bool) {
	if strings.ContainsAny(raw, "\r\n\x00%") {
		return "", false
	}
	names := make([]string, 0, 8)
	for field := range strings.SplitSeq(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if !reQueueName.MatchString(field) {
			return "", false
		}
		names = append(names, field)
	}
	if len(names) > 8 {
		return "", false
	}
	return strings.Join(names, ","), true
}

// RenderWorkerUnit builds the template unit for one worker.
//
// Four lines are not obvious from the code around them:
//
// The StartLimit pair lives in [Unit]. systemd 257 answers `Unknown key
// 'StartLimitIntervalSec' in section [Service], ignoring.` while silently
// accepting StartLimitBurst there (measured with systemd-analyze verify), so the
// [Service] spelling leaves the burst counting against the default ten-second
// window, which RestartSec=5 can never fill. A worker that cannot start would
// then restart every five seconds for good instead of reaching failed, which is
// the one state the screen reads as broken.
//
// TimeoutStopSec is LARGER than the job timeout. systemd sends SIGTERM first and
// Laravel finishes the job in hand before exiting; a stop timeout below the job
// timeout turns every restart into a SIGKILL mid-job, losing the job or
// replaying it with its side effects.
//
// ProtectHome=tmpfs plus BindPaths hides every other tenant's home. Without them
// a worker reads /home/<somebody else> with its own user's permissions.
//
// The memory ceiling is Laravel's --memory, NOT systemd's MemoryMax. A cgroup
// limit calls in the OOM killer and loses the job in flight; --memory tells the
// worker to exit cleanly after finishing it, and systemd starts it again.
func RenderWorkerUnit(worker Worker, domainID int64, systemUser, appDir, php string) string {
	execStart := php + " " + appDir + "/artisan queue:work " + worker.Connection +
		fmt.Sprintf(" --sleep=%d --tries=%d --timeout=%d --memory=%d --max-time=3600",
			worker.Sleep, worker.Tries, worker.Timeout, worker.MemoryMB)
	if worker.MaxJobs > 0 {
		execStart += fmt.Sprintf(" --max-jobs=%d", worker.MaxJobs)
	}
	if worker.Queues != "" {
		execStart += " --queue=" + worker.Queues
	}
	logPath := WorkerLogPath(worker.ID)

	var body strings.Builder
	fmt.Fprintf(&body, `[Unit]
Description=Servika Laravel queue worker %%i for domain %d (%s)
After=network.target mariadb.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s
Slice=servika-%s.slice
Environment=HOME=/home/%s
ExecStart=%s
Restart=always
RestartSec=5
TimeoutStopSec=%d
StandardOutput=append:%s
StandardError=append:%s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/home/%s
ProtectHome=tmpfs
BindPaths=/home/%s
PrivateTmp=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitCORE=0

[Install]
WantedBy=multi-user.target
`,
		domainID, worker.Name,
		systemUser, systemUser,
		appDir,
		systemUser,
		systemUser,
		execStart,
		worker.Timeout+30,
		logPath, logPath,
		systemUser, systemUser)
	return body.String()
}

// EnsureWorkerLog creates the log as root-only before systemd opens it, so the
// append: target is never a name a tenant could win a race for.
//
// The worker writes through a descriptor systemd opened and passed down, never
// by opening the path, so its own user needs no permission here.
func EnsureWorkerLog(workerID int64) error {
	// #nosec G301 -- root-owned log directory the panel serves back through its own endpoint.
	if err := os.MkdirAll(config.LaravelLogDir(), 0o750); err != nil {
		return fmt.Errorf("create the log directory: %w", err)
	}
	path := WorkerLogPath(workerID)
	// #nosec G304 -- a fixed path this package owns, named after a row id.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open the log: %w", err)
	}
	return file.Close()
}
