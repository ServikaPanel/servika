//go:build windows

package platform

// Driving a Windows service and reading the host's resource snapshot.

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// settleTimeout is how long a service is given to reach its target state.
	settleTimeout = 30 * time.Second
	// settleInterval is how often its state is re-read while waiting.
	settleInterval = 750 * time.Millisecond
)

// ListServices asks for every allowlisted service in one PowerShell call.
//
// `; exit 0` is required: names that are not installed are suppressed by
// SilentlyContinue, yet powershell still exits 1 and Output() would throw away a
// perfectly good answer. The state and start type are cast to [string] first,
// because the enums serialise as NUMBERS on PowerShell 5.1.
func ListServices() ([]ServiceView, error) {
	command := "Get-Service -Name " + quotedAllowlist() +
		" -ErrorAction SilentlyContinue | ForEach-Object { [PSCustomObject]@{ " +
		"Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.Status; " +
		"StartType = [string]$_.StartType } } | ConvertTo-Json -Compress; exit 0"

	out, err := exec.Command("powershell", "-NoProfile", "-Command", command).Output()
	if err != nil {
		return nil, commandError("the service list", err)
	}
	return parseServices(out)
}

// serviceCommand issues the request for one action. The canonical name is what
// is passed, never the caller's spelling.
func serviceCommand(name, action string) error {
	switch action {
	case "start":
		return run("sc", "start", name)
	case "stop":
		return run("sc", "stop", name)
	}
	// sc.exe has no single restart verb, and Restart-Service -Force turns the
	// dependent services with it.
	//
	// -ErrorAction Stop with try/catch is required: Restart-Service is a CMDLET
	// and does not set $LASTEXITCODE, and "it did not come back" is not a
	// terminating error by default. Without this the command always reports
	// success.
	return run("powershell", "-NoProfile", "-Command",
		"$ProgressPreference='SilentlyContinue'; try { Restart-Service -Force -Name '"+name+
			"' -ErrorAction Stop } catch { Write-Error $_; exit 1 }")
}

// ServiceAction starts, stops or restarts an allowlisted service.
//
// THE COMMAND'S EXIT CODE IS NOT THE ANSWER. `sc start` and `sc stop` are
// ASYNCHRONOUS: a zero exit means the request was accepted, not that the service
// reached the state. So the real state is polled instead. If the target is
// reached the action succeeded even when the command complained, which is the
// idempotent case of a service that was already there. If it is not reached the
// failure is reported with the state actually observed.
func ServiceAction(name, action string) error {
	canonical := canonicalService(name)
	if canonical == "" {
		return fmt.Errorf("the service %q is not one this panel manages: %w", name, ErrInvalidRequest)
	}
	target, err := targetState(action)
	if err != nil {
		return err
	}
	commandErr := serviceCommand(canonical, action)
	reached, err := waitForService(canonical, target)
	if err != nil {
		// The state could never be read at all, so nothing was measured. Say so
		// rather than guessing at an outcome.
		return err
	}
	if strings.EqualFold(reached, target) {
		return nil
	}
	if commandErr != nil {
		return fmt.Errorf("service %s: after %q the state is %q, wanted %q - %v", canonical, action, reached, target, commandErr)
	}
	return fmt.Errorf("service %s: %q was accepted but the state became %q, wanted %q", canonical, action, reached, target)
}

// waitForService polls a service until it reaches the target state, and returns
// the last state it saw. It returns an error only when the state could not be
// read at all; a state that simply never arrived is the caller's decision.
func waitForService(name, target string) (string, error) {
	last := ""
	deadline := time.Now().Add(settleTimeout)
	for {
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"$ProgressPreference='SilentlyContinue'; (Get-Service -Name '"+name+
				"' -ErrorAction SilentlyContinue).Status; exit 0").Output()
		if err == nil {
			if state := strings.TrimSpace(string(out)); state != "" {
				last = state
				if strings.EqualFold(last, target) {
					return last, nil
				}
			}
		}
		if time.Now().After(deadline) {
			if last == "" {
				return "", fmt.Errorf("the state of service %s could not be read; is it registered", name)
			}
			return last, nil
		}
		time.Sleep(settleInterval)
	}
}

// resourceScript collects CPU, memory and disk in one PowerShell call.
//
// ProgressPreference is silenced because a CIM cmdlet in a console-less context,
// which is what a service is, tries to draw a progress bar and can die with
// "Access is denied reading the console output buffer".
//
// The disk list is forced into an array with @(...), so a host with one disk
// still produces an array. -Depth 5 is needed because the nested objects would
// otherwise be cut at the default depth of 2.
const resourceScript = `$ProgressPreference='SilentlyContinue'; ` +
	`$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; ` +
	`$os=Get-CimInstance Win32_OperatingSystem; ` +
	`$totalKB=[double]$os.TotalVisibleMemorySize; $freeKB=[double]$os.FreePhysicalMemory; $usedKB=$totalKB-$freeKB; ` +
	`$disk=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { ` +
	`$t=[double]$_.Size; $f=[double]$_.FreeSpace; [PSCustomObject]@{ ` +
	`Drive=$_.DeviceID; Percent= if ($t -gt 0) { [math]::Round((($t-$f)/$t)*100,1) } else { 0 }; ` +
	`TotalGB=[math]::Round($t/1GB,1); FreeGB=[math]::Round($f/1GB,1) } }; ` +
	`[PSCustomObject]@{ ` +
	`cpu_percent= if ($cpu -ne $null) { [double]$cpu } else { 0 }; ` +
	`memory=[PSCustomObject]@{ ` +
	`percent= if ($totalKB -gt 0) { [math]::Round(($usedKB/$totalKB)*100,1) } else { 0 }; ` +
	`total_mb=[math]::Round($totalKB/1024,1); used_mb=[math]::Round($usedKB/1024,1) }; ` +
	`disks=@($disk) } | ConvertTo-Json -Compress -Depth 5`

// ReadResources returns the host's current CPU, memory and disk use.
func ReadResources() (ResourceView, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", resourceScript).Output()
	if err != nil {
		return ResourceView{}, commandError("the resource snapshot", err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return ResourceView{}, fmt.Errorf("the resource snapshot came back empty")
	}
	var view ResourceView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		return ResourceView{}, fmt.Errorf("could not decode the resource snapshot: %w", err)
	}
	if view.Disks == nil {
		view.Disks = []DiskView{}
	}
	return view, nil
}
