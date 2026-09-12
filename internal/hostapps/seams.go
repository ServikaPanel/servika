package hostapps

// The values below are variables only so a characterization test can point them
// somewhere other than the host. Each default is the function this package
// called before the seam existed. None of them is operator configuration: there
// is no environment variable, no paths.go entry and no README row.
//
// An install adds a Linux user, writes into /opt and installs a systemd unit, so
// its ORDER is what a test can check without a host to run it on.
var (
	// unpackWith runs the unpacking tool an archive kind needs.
	unpackWith = runTool

	downloadFor        = Download
	ensureUser         = EnsureUser
	prepareDirectories = PrepareDirectories
	fetchArchive       = Fetch
	unpackArchive      = Unpack
	verifyBinary       = VerifyBinary
	buildArgv          = BuildArgv
	writeEnvFile       = WriteEnvFile
	ensureLogFile      = EnsureLogFile
	installUnit        = InstallUnit
	enableUnit         = Enable
)
