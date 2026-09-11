package laravel

import (
	"os/exec"

	"servika/internal/netguard"
	"servika/internal/provisioner"
)

// Seams: unexported package variables whose defaults are exactly the calls this
// package makes on a real host. A characterization test replaces one so a
// handler can be exercised without a tenant home, systemd or the network.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// homeRoot is where tenant homes live, so a test can point safeAppDir at a
	// temporary directory.
	homeRoot = "/home"
	// runScriptDir holds the generated install and deploy scripts.
	runScriptDir = "/run"
)

var (
	laravelCommand    = exec.Command
	tenantExec        = TenantExec
	tenantExecWithEnv = tenantExecEnv
	runDetached       = systemdRunDetached
	readUnitStatus    = unitStatus
	nodeBinDirFor     = nodeBinDir
	composerBinPath   = composerBin
	absoluteWebRoot   = provisioner.AbsoluteWebRoot
	rerenderVhost     = provisioner.RerenderVhost
	checkGitURL       = netguard.CheckGitURL
)
