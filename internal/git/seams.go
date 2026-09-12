package git

import "servika/internal/netguard"

// The values below are variables only so a characterization test can point them
// somewhere other than the host. Each default is the call this package made
// before the seam existed. None of them is operator configuration: there is no
// environment variable, no paths.go entry and no README row.
var (
	// tenantHomeRoot is the parent of every tenant home.
	tenantHomeRoot = "/home"

	// resolveArgsFor pins the address git connects to for an HTTPS remote.
	resolveArgsFor = gitResolveArgs

	// runUserCtx and runUser run a command as the tenant.
	runUserCtx = runAsUserArgsCtx
	runUser    = runAsUserArgs

	// pullRepository updates a checked-out repository.
	pullRepository = gitPull

	// deployKeyFor creates the tenant's deploy key and returns its public half.
	deployKeyFor = generateDeployKey

	// checkGitURL vets the remote host before a repository is stored.
	checkGitURL = netguard.CheckGitURL
)
