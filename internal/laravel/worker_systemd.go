package laravel

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// WorkerStatus is what the panel can say about one worker.
type WorkerStatus struct {
	Installed bool `json:"installed"`
	// Running counts the instances systemd reports as active.
	Running int `json:"running"`
	// Failed counts the instances that gave up. A single one is worth showing:
	// the others carrying the load hides exactly the process that is not.
	Failed   int `json:"failed"`
	Restarts int `json:"restarts"`
}

// workerCommand runs a privileged tool without inheriting the panel's own
// environment, which carries the JWT and encryption secrets.
func workerCommand(name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value is validated before exec.
	command := exec.Command(name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// ReadWorkerStatus asks systemd about every instance a worker could have.
//
// It walks to maxWorkerProcesses rather than to the row's own count, so an
// instance left behind by a half-applied write is still reported instead of
// running unseen.
func ReadWorkerStatus(worker Worker) WorkerStatus {
	status := WorkerStatus{}
	if _, err := os.Stat(UnitTemplatePath(worker.ID)); err == nil {
		status.Installed = true
	}
	for index := 1; index <= maxWorkerProcesses; index++ {
		active, sub, restarts := instanceProps(UnitInstance(worker.ID, index))
		switch {
		case active == "failed" || sub == "failed":
			status.Failed++
		case active == "active" || active == "activating":
			status.Running++
		}
		status.Restarts += restarts
	}
	return status
}

// instanceProps reads one instance's state.
func instanceProps(unit string) (activeState, subState string, restarts int) {
	output, err := workerCommand("systemctl", "show",
		"-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", unit).Output()
	if err != nil {
		return "", "", 0
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "ActiveState":
			activeState = value
		case "SubState":
			subState = value
		case "NRestarts":
			count := 0
			_, _ = fmt.Sscanf(value, "%d", &count)
			restarts = count
		}
	}
	return activeState, subState, restarts
}

// ApplyWorker writes the template and brings the instance count in line.
//
// The sweep runs to maxWorkerProcesses rather than to the count previously
// stored, because that stored value is wrong exactly when it matters: after a
// write that installed instances and then failed before recording them.
func ApplyWorker(worker Worker, domainID int64, systemUser, appDir, php string) error {
	if err := EnsureWorkerLog(worker.ID); err != nil {
		return err
	}
	body := RenderWorkerUnit(worker, domainID, systemUser, appDir, php)
	// #nosec G306 -- root-owned systemd unit that PID 1 must read; it carries no secret.
	if err := os.WriteFile(UnitTemplatePath(worker.ID), []byte(body), 0o644); err != nil {
		return fmt.Errorf("write the unit: %w", err)
	}
	if output, err := workerCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("reload systemd: %s: %w", strings.TrimSpace(string(output)), err)
	}

	wanted := 0
	if worker.Enabled {
		wanted = worker.Processes
	}
	for index := 1; index <= wanted; index++ {
		unit := UnitInstance(worker.ID, index)
		// A previous run may have left this instance in failed, where systemd
		// refuses to start it again until the state is cleared.
		_, _ = workerCommand("systemctl", "reset-failed", unit).CombinedOutput()
		if output, err := workerCommand("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("start %s: %s: %w", unit, strings.TrimSpace(string(output)), err)
		}
	}
	for index := wanted + 1; index <= maxWorkerProcesses; index++ {
		stopInstance(UnitInstance(worker.ID, index))
	}
	return nil
}

// stopInstance takes one instance down for good. Stopping alone is not enough:
// the unit carries Restart=always, so a process killed by anything other than
// systemd comes straight back.
func stopInstance(unit string) {
	_, _ = workerCommand("systemctl", "disable", "--now", unit).CombinedOutput()
	_, _ = workerCommand("systemctl", "reset-failed", unit).CombinedOutput()
}

// RestartWorker restarts every running instance in place.
//
// This is graceful: systemd sends SIGTERM, Laravel finishes the job in hand, and
// TimeoutStopSec is rendered above the job timeout so it has room to.
func RestartWorker(worker Worker) error {
	var failure error
	for index := 1; index <= worker.Processes; index++ {
		unit := UnitInstance(worker.ID, index)
		if output, err := workerCommand("systemctl", "restart", unit).CombinedOutput(); err != nil && failure == nil {
			failure = fmt.Errorf("restart %s: %s: %w", unit, strings.TrimSpace(string(output)), err)
		}
	}
	return failure
}

// TeardownWorker removes everything one worker left on the host. Every step is
// best effort so a missing piece does not strand the rest.
func TeardownWorker(workerID int64) {
	for index := 1; index <= maxWorkerProcesses; index++ {
		stopInstance(UnitInstance(workerID, index))
	}
	_ = os.Remove(UnitTemplatePath(workerID))
	_, _ = workerCommand("systemctl", "daemon-reload").CombinedOutput()
	_ = os.Remove(WorkerLogPath(workerID))
}

// maxWorkerLogBytes bounds what one log poll pulls into memory.
const maxWorkerLogBytes = 60000

// WorkerLogTail returns the end of a worker's log.
//
// The open is O_NOFOLLOW with the regular-file check on the DESCRIPTOR, not on a
// separate stat of the path: the process appending to this file runs as the
// tenant, so even though the panel owns the directory the content is theirs.
// O_NONBLOCK keeps a fifo from blocking the open before any check can run.
func WorkerLogTail(workerID int64) string {
	path := WorkerLogPath(workerID)
	// #nosec G304 -- a fixed path this package owns, named after a row id.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return ""
	}
	if stat.Size() > maxWorkerLogBytes {
		if _, err := file.Seek(-maxWorkerLogBytes, io.SeekEnd); err != nil {
			return ""
		}
	}
	body, err := io.ReadAll(io.LimitReader(file, maxWorkerLogBytes))
	if err != nil {
		return ""
	}
	return cleanANSI(string(body))
}
