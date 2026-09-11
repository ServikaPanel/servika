package resourcelimit

import (
	"time"

	"servika/internal/provisioner"
)

// Seams: unexported package variables whose defaults are exactly what this
// package reads, runs and calls on a real host. A characterization test
// replaces one so a decision can be exercised without systemd, without
// xfs_quota, without MariaDB and without a tenant PHP-FPM service.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// cgroupRoot is where the kernel exposes the live cgroup of a slice.
	cgroupRoot = "/sys/fs/cgroup"
	// cutoverSettle is how long healing lets a freshly started tenant service
	// settle before it probes the site again.
	cutoverSettle = 700 * time.Millisecond
)

var (
	planLimits       = GetPlanLimits
	writeSlice       = WriteSystemdSlice
	deleteSlice      = DeleteSystemdSlice
	applyDomainQuota = DomainQuotaApply
	applyMySQLLimits = ApplyMySQLLimits
	applyAllLimits   = ApplyAll
	reassertLimits   = ReassertLimits
	probeHTTPS       = planProbeHTTPS
	serviceActive    = tenantServiceActive

	tenantFPMActive     = provisioner.TenantFPMActive
	enableTenantFPM     = provisioner.EnableTenantFPM
	rollbackToSharedFPM = provisioner.RollbackToSharedFPM

	quotaFSCompatible = QuotaFSCompatible
	quotaActive       = mountQuotaActive
	sentinelWrite     = quotaSentinelWrite
	sentinelDelete    = quotaSentinelDelete
)
