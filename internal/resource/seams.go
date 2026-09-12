package resource

import (
	"os/exec"

	"servika/internal/diskusage"
	"servika/internal/resourcelimit"
)

// The summary measures the tenant's home with du, asks xfs_quota for the live
// quota state and reads the host crontab. Each step is a variable so a test can
// run the endpoint on a machine that hosts no tenant.
var (
	homeBytes   = diskusage.Bytes
	quotaStatus = resourcelimit.QuotaStatus
	runCommand  = exec.Command
)
