package cron

import "servika/internal/phpversion"

// Seam: an unexported package variable whose default is exactly what this
// package reads on a real host. phpBinFor asks the host which PHP versions are
// installed, which a test cannot answer, so a characterization test replaces
// this and leaves the decision code untouched.
//
// It is NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row.
var installedVersions = phpversion.AllVersions
