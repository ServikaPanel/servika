//go:build windows

package platform

// Applying a plan to a host: appcmd for the IIS limits, FSRM for the disk quota.

import (
	"fmt"
	"os/exec"
	"strings"
)

// QuotaEngineInstalled reports whether FSRM is on this host.
func QuotaEngineInstalled() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"if (Get-Command Get-FsrmQuota -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' }").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "YES")
}

// psPath embeds a path in a PowerShell single-quoted literal, doubling any
// quote. Inside a single-quoted literal $(...) and variable expansion do
// nothing, which is what makes this safe.
func psPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "''") + "'"
}

// powershell runs a script and returns its combined output with the error.
func powershell(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	return string(out), err
}

// setQuota applies a hard disk quota to a path, updating one that is there.
func setQuota(path string, mb int64) error {
	script := fmt.Sprintf(
		"$p=%s; $s=%dMB; if (Get-FsrmQuota -Path $p -ErrorAction SilentlyContinue) "+
			"{ Set-FsrmQuota -Path $p -Size $s -ErrorAction Stop } "+
			"else { New-FsrmQuota -Path $p -Size $s -ErrorAction Stop }",
		psPath(path), mb)
	if out, err := powershell(script); err != nil {
		return fmt.Errorf("%v - %s", err, strings.TrimSpace(out))
	}
	return nil
}

// clearQuota removes a path's quota when it has one.
func clearQuota(path string) error {
	p := psPath(path)
	script := fmt.Sprintf("if (Get-FsrmQuota -Path %s -ErrorAction SilentlyContinue) "+
		"{ Remove-FsrmQuota -Path %s -Confirm:$false -ErrorAction Stop }", p, p)
	if out, err := powershell(script); err != nil {
		return fmt.Errorf("%v - %s", err, strings.TrimSpace(out))
	}
	return nil
}

// InstallQuotaEngine installs the FSRM feature. It takes minutes, and the local
// panel has no write timeout, so the call is synchronous. It reports whether the
// host still needs a restart.
func InstallQuotaEngine() (restartNeeded bool, err error) {
	out, err := powershell(
		"$r = Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools; " +
			"if (-not $r.Success) { throw 'the feature could not be installed' }; " +
			"if ($r.RestartNeeded -eq 'Yes') { 'RESTART' } else { 'OK' }")
	if err != nil {
		return false, fmt.Errorf("%v - %s", err, strings.TrimSpace(out))
	}
	return strings.Contains(out, "RESTART"), nil
}

// applySiteLimits sets the connection and bandwidth limits on the site itself.
// A failure here is returned, not warned about: these are the limits IIS always
// accepts, so a failure means something is actually wrong.
func applySiteLimits(site string, p Plan) error {
	err := run(appcmdPath(), "set", "site", "/site.name:"+site,
		fmt.Sprintf("/limits.maxConnections:%d", connectionLimit(p.MaxConns)),
		fmt.Sprintf("/limits.maxBandwidth:%d", bandwidthBytes(p.MaxBandwidth)))
	if err != nil {
		return fmt.Errorf("could not apply the IIS site limits: %w", err)
	}
	return nil
}

// applyPoolLimits sets the CPU and memory limits on the application pool and
// returns what could not be applied.
//
// These are warnings rather than failures: the site limits already landed, and
// answering with a bare error would tell the operator nothing was applied when
// half of it was.
func applyPoolLimits(pool string, p Plan) []string {
	if pool == "" {
		return []string{"the site has no application pool; the CPU and memory limits were skipped"}
	}
	var warnings []string
	limit, action := cpuThrottle(p.CPUPercent)
	if err := run(appcmdPath(), "set", "apppool", "/apppool.name:"+pool,
		fmt.Sprintf("/cpu.limit:%d", limit), "/cpu.action:"+action); err != nil {
		warnings = append(warnings, "could not apply the pool CPU limit: "+err.Error())
	}
	if err := run(appcmdPath(), "set", "apppool", "/apppool.name:"+pool,
		fmt.Sprintf("/recycling.periodicRestart.privateMemory:%d", memoryKB(p.MemoryMB))); err != nil {
		warnings = append(warnings, "could not apply the pool memory limit: "+err.Error())
	}
	return warnings
}

// applyQuota applies the disk quota and says plainly what happened.
//
// When FSRM is missing the quota is NOT applied and the note says so. Answering
// "quota active" with nothing enforcing it is a false assurance an operator
// would size a disk against.
func applyQuota(path string, p Plan) (bool, string) {
	if p.DiskQuotaMB <= 0 {
		if path != "" && QuotaEngineInstalled() {
			// The plan went back to unlimited; drop any quota left from before.
			_ = clearQuota(path)
		}
		return true, "the disk quota is unlimited"
	}
	if !QuotaEngineInstalled() {
		return false, "FSRM (File Server Resource Manager) is not installed, so the disk quota was NOT applied; install the quota engine to enable it"
	}
	if path == "" {
		return false, "the site's physical path could not be found, so the quota was not applied"
	}
	if err := setQuota(path, p.DiskQuotaMB); err != nil {
		return false, "the quota could not be applied: " + err.Error()
	}
	return true, fmt.Sprintf("a %d MB quota was applied to %s", p.DiskQuotaMB, path)
}

// AssignPlan applies a plan to a site and records the assignment.
func (s PlanStore) AssignPlan(site, name string) (AssignResult, error) {
	site = strings.ToLower(strings.TrimSpace(site))
	if !domainPattern.MatchString(site) {
		return AssignResult{}, fmt.Errorf("invalid domain %q: %w", site, ErrInvalidRequest)
	}
	plan, err := s.Find(name)
	if err != nil {
		return AssignResult{}, err
	}
	detail, err := ReadSiteDetail(site)
	if err != nil {
		return AssignResult{}, err
	}
	result := AssignResult{Site: site, Plan: plan.Name}
	if err := applySiteLimits(site, plan); err != nil {
		return result, err
	}
	result.Warnings = applyPoolLimits(detail.Pool.Name, plan)
	result.LimitsSet = true
	result.QuotaSet, result.QuotaNote = applyQuota(detail.PhysicalPath, plan)
	if err := s.Assign(site, plan.Name); err != nil {
		return result, fmt.Errorf("the limits were applied but the assignment was not saved: %w", err)
	}
	return result, nil
}

// RemovePlan puts a site back to no limits and drops its assignment.
//
// Resetting the host is best-effort: the site or its pool may already be gone,
// and the assignment still has to come off the books.
func (s PlanStore) RemovePlan(site string) error {
	site = strings.ToLower(strings.TrimSpace(site))
	if !domainPattern.MatchString(site) {
		return fmt.Errorf("invalid domain %q: %w", site, ErrInvalidRequest)
	}
	detail, err := ReadSiteDetail(site)
	_ = run(appcmdPath(), "set", "site", "/site.name:"+site,
		fmt.Sprintf("/limits.maxConnections:%d", iisUnlimited),
		fmt.Sprintf("/limits.maxBandwidth:%d", iisUnlimited))
	if err == nil {
		if detail.Pool.Name != "" {
			_ = run(appcmdPath(), "set", "apppool", "/apppool.name:"+detail.Pool.Name,
				"/cpu.limit:0", "/cpu.action:NoAction", "/recycling.periodicRestart.privateMemory:0")
		}
		if detail.PhysicalPath != "" && QuotaEngineInstalled() {
			_ = clearQuota(detail.PhysicalPath)
		}
	}
	return s.Unassign(site)
}
