package panelport

// Test seams for the two host operations a port change makes: the commands it
// runs (nginx -t, systemctl, systemd-run) and the TCP probe that decides
// whether the panel came back. The file paths need no seam; each already has
// its own SERVIKA_* override, which is how the installer points them.
//
// Both are package-level variables whose default is the production value.

// runCommand runs one of this package's fixed commands.
var runCommand = run

// portAnswers reports whether something is accepting connections on a port.
var portAnswers = WaitReachable
