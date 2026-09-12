package composer

import "os/exec"

// runCommand starts the composer process. It is a variable so a test can stand
// in for runuser, which needs root and a real hosting account.
var runCommand = exec.CommandContext
