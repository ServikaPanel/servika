//go:build windows

// servika-agent is the Windows side of the panel, as a SEPARATE self-installing
// binary.
//
// WHY A SEPARATE BINARY: a Linux release must not be able to break a Windows
// host. Built into the panel binary the two would share one artifact, and every
// Linux release would carry Windows code with it. A separate binary with its
// own channel means each side changes only with its own release.
//
// TLS: the agent listens over HTTPS with its own self-signed ECDSA P-256
// certificate, generated on the first run. The panel verifies it by SHA-256
// fingerprint rather than by a CA chain, which is what `fingerprint` prints.
//
// Commands:
//
//	servika-agent install             copy into place, generate the token and
//	                                  the panel password, register the Windows
//	                                  service and the firewall rule, and start
//	servika-agent uninstall           remove the service and the firewall rule
//	                                  (the configuration and certificate STAY,
//	                                  so a reinstall keeps the same identity)
//	servika-agent selftest            prove the host by creating, checking and
//	                                  deleting a real IIS site, then seal it
//	servika-agent panel-password      generate a new local panel password and
//	                                  print it once
//	servika-agent fingerprint         print the certificate's SHA-256
//	servika-agent version             print "<version> <channel>"
//	servika-agent update <exe>        swap in a new binary, gated on its health,
//	                                  rolling back automatically when it fails
//	servika-agent clear-install-lock  clear a half-finished installation's lock
//	servika-agent                     run in the foreground (development)
//	servika-agent service             called by the service manager
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"servika/internal/logx"
	"servika/internal/platform"
)

const (
	// dataDir holds the certificate, the settings, the log and the downloads.
	// ProgramData rather than a user profile: the service runs under whatever
	// account the operator gives it and this path does not move.
	dataDir = `C:\ProgramData\servika`

	installDir  = `C:\Program Files\Servika\agent`
	exeName     = "servika-agent.exe"
	serviceName = "ServikaAgent"

	firewallRule  = "Servika Agent 8460"
	panelFirewall = "Servika Local Panel 8443"
)

// installMarker is where a running installation records itself, so an agent
// restart finds a half-finished one instead of starting a second.
func installMarker() string { return filepath.Join(dataDir, "install-active.json") }

// installer is the process-wide installation runner.
var installer = platform.NewInstaller(installMarker())

func main() {
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if handled := runCommand(command); handled {
		return
	}
	// Under the service manager? The binPath says "service", but a wrong binPath
	// must not let the service manager kill us after 30 seconds, so this is
	// detected as well as declared.
	inService, _ := svc.IsWindowsService()
	if command == "service" || inService {
		runService()
		return
	}
	runForeground()
}

// runCommand answers a one-shot command and reports whether it took the run.
func runCommand(command string) bool {
	switch command {
	case "selftest":
		exitOn(platform.SelfTest(), "the selftest FAILED")
		fmt.Println("the selftest PASSED - site management is open on this host (version " + platform.Version + ")")
	case "fingerprint":
		cert, err := loadCertificate(dataDir)
		exitOn(err, "the certificate could not be prepared")
		fmt.Println(fingerprintOf(cert))
	case "install":
		exitOn(install(), "THE INSTALLATION FAILED")
	case "uninstall":
		exitOn(uninstall(), "THE REMOVAL FAILED")
	case "panel-password":
		exitOn(resetPanelPassword(), "THE PANEL PASSWORD COULD NOT BE RESET")
	case "version":
		// A machine-readable line. The update command reads it back from the new
		// binary as proof that it actually runs.
		fmt.Println(platform.Version + " " + platform.Channel)
	case "update":
		runUpdateCommand()
	case "clear-install-lock":
		installer.LoadPending()
		installer.ClearPending()
		fmt.Println("the half-finished installation lock is cleared; installations can start again.")
	default:
		return false
	}
	return true
}

// runUpdateCommand reads the replacement path and performs the update.
func runUpdateCommand() {
	newExe := ""
	if len(os.Args) > 2 {
		newExe = os.Args[2]
	}
	if newExe == "" {
		fmt.Fprintln(os.Stderr, "usage: servika-agent update <path-to-new-exe>")
		os.Exit(1)
	}
	exitOn(update(newExe), "UPDATE")
}

// exitOn prints the failure and stops when err is not nil.
func exitOn(err error, what string) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, what+":", err)
	os.Exit(1)
}

// elevated reports whether this process can change the service and the
// firewall. `net session` fails for a non-administrator.
func elevated() bool { return exec.Command("net", "session").Run() == nil }

// runTool runs a host tool and returns its combined output.
func runTool(name string, arg ...string) (string, error) {
	out, err := exec.Command(name, arg...).CombinedOutput()
	return string(out), err
}

// install puts the agent on the host and starts it.
func install() error {
	if !elevated() {
		return fmt.Errorf("an elevated PowerShell or CMD is required (Run as administrator)")
	}
	fmt.Println("Servika Windows agent - installing (" + platform.Version + " / " + platform.Channel + ")")
	target, err := copySelf()
	if err != nil {
		return err
	}
	current, newToken, password, err := prepareSettings()
	if err != nil {
		return err
	}
	if err := lockDataDirectory(); err != nil {
		return err
	}
	if err := openFirewall(); err != nil {
		return err
	}
	if err := registerService(target); err != nil {
		return err
	}
	cert, err := loadCertificate(dataDir)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	reportInstall(target, current, cert, newToken, password)
	return nil
}

// copySelf copies the running binary into the installation directory.
func copySelf() (string, error) {
	for _, dir := range []string{installDir, dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	target := filepath.Join(installDir, exeName)
	if sameFile(self, target) {
		return target, nil
	}
	if err := copyFile(self, target); err != nil {
		return "", fmt.Errorf("the executable could not be copied: %w", err)
	}
	return target, nil
}

// prepareSettings fills in whatever is missing and saves the file.
//
// AN EXISTING TOKEN AND PASSWORD HASH ARE KEPT. A reinstall must not silently
// break the panel's registration or change a password the operator knows. Both
// have their own deliberate reset: delete the file, or run panel-password.
func prepareSettings() (settings, bool, string, error) {
	current, err := readSettings(dataDir)
	if err != nil {
		return current, false, "", err
	}
	newToken := current.Token == ""
	if newToken {
		if current.Token, err = randomToken(); err != nil {
			return current, false, "", err
		}
	}
	if current.Listen == "" {
		current.Listen = defaultListen
	}
	password := ""
	if current.PanelPasswordHash == "" {
		if password, err = randomPanelPassword(); err != nil {
			return current, false, "", err
		}
		if current.PanelPasswordHash, err = hashPanelPassword(password); err != nil {
			return current, false, "", err
		}
	}
	current.Version = platform.Version
	if err := writeSettings(dataDir, current); err != nil {
		return current, false, "", err
	}
	return current, newToken, password, nil
}

// lockDataDirectory restricts the whole data directory to SYSTEM and the local
// Administrators group.
//
// On Windows os.WriteFile's 0600 sets only the read-only bit and does NOT touch
// the ACL, so the token, the TLS PRIVATE KEY and the log would all be readable
// by Users under the ProgramData default. SIDs are used rather than group
// names, because the names are localised and the SIDs are not. (OI)(CI) makes
// files written later inherit the same restriction.
func lockDataDirectory() error {
	out, err := runTool("icacls", dataDir, "/inheritance:r",
		"/grant", "*S-1-5-18:(OI)(CI)F", "/grant", "*S-1-5-32-544:(OI)(CI)F")
	if err != nil {
		return fmt.Errorf("the data directory could not be locked down: %v - %s", err, out)
	}
	return nil
}

// openFirewall lets the panel reach the agent over the private network. The two
// ports get separate rules so the operator can close the local panel without
// closing the agent API.
func openFirewall() error {
	for _, rule := range []struct{ name, port string }{
		{firewallRule, "8460"},
		{panelFirewall, "8443"},
	} {
		// Delete first so a reinstall does not stack duplicate rules.
		_, _ = runTool("netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule.name)
		out, err := runTool("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+rule.name, "dir=in", "action=allow", "protocol=TCP", "localport="+rule.port)
		if err != nil {
			return fmt.Errorf("the firewall rule %q could not be added: %v - %s", rule.name, err, out)
		}
	}
	return nil
}

// registerService installs the Windows service and starts it.
//
// The failure actions matter: nobody logs into a hosting server to restart a
// service by hand, so a crash has to bring it back on its own.
func registerService(target string) error {
	_, _ = runTool("sc", "stop", serviceName)
	_, _ = runTool("sc", "delete", serviceName)
	time.Sleep(time.Second)
	out, err := runTool("sc", "create", serviceName,
		"binPath=", `"`+target+`" service`, "start=", "auto", "DisplayName=", "Servika Agent")
	if err != nil {
		return fmt.Errorf("the service could not be created: %v - %s", err, out)
	}
	_, _ = runTool("sc", "description", serviceName, "Servika Windows agent ("+platform.Channel+")")
	_, _ = runTool("sc", "failure", serviceName, "reset=", "86400",
		"actions=", "restart/5000/restart/5000/restart/5000")
	if out, err := runTool("sc", "start", serviceName); err != nil {
		return fmt.Errorf("the service could not be started: %v - %s", err, out)
	}
	return nil
}

// reportInstall prints what the operator has to act on.
func reportInstall(target string, current settings, cert tls.Certificate, newToken bool, password string) {
	fmt.Println()
	fmt.Println("INSTALLED")
	fmt.Println("  Service      :", serviceName, "(automatic, restarts 5 seconds after a crash)")
	fmt.Println("  Listening    :", current.Listen, "(TLS)")
	if newToken {
		fmt.Println("  TOKEN (NEW)  :", current.Token)
		fmt.Println("                 Enter this in the panel under Windows Hosts > Add Agent.")
	} else {
		fmt.Println("  Token        : the existing token was KEPT (" + settingsPath(dataDir) + ")")
	}
	fmt.Println("  Fingerprint  :", fingerprintOf(cert))
	fmt.Println("  Log          :", filepath.Join(dataDir, "agent.log"))
	if password != "" {
		fmt.Println("  PANEL LOGIN  : https://" + localAddress() + ":8443  user: admin  password: " + password)
	} else {
		fmt.Println("  Panel login  : the existing password was KEPT (reset it with: panel-password)")
	}
	fmt.Println()
	fmt.Println("NEXT:")
	fmt.Println("  1) With IIS installed, prove the host:  \"" + target + "\" selftest")
	fmt.Println("  2) Add it in the panel: Windows Hosts > Add Agent")
	fmt.Println("     (the address is this machine's PRIVATE network IP plus :8460)")
}

// uninstall removes the service and the firewall rules.
func uninstall() error {
	if !elevated() {
		return fmt.Errorf("an elevated PowerShell or CMD is required")
	}
	_, _ = runTool("sc", "stop", serviceName)
	if out, err := runTool("sc", "delete", serviceName); err != nil {
		return fmt.Errorf("the service could not be deleted: %v - %s", err, out)
	}
	for _, name := range []string{firewallRule, panelFirewall} {
		_, _ = runTool("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	}
	fmt.Println("The service and both firewall rules are removed.")
	fmt.Println("The configuration and certificate are deliberately LEFT in " + dataDir + ":")
	fmt.Println("a reinstall then keeps the same token and fingerprint, so the panel's registration holds.")
	return nil
}

// resetPanelPassword generates a new local panel password and prints it once.
//
// The settings file is read DIRECTLY rather than through loadSettings, because
// loadSettings applies the environment overrides and writing those back would
// corrupt the installed configuration. A running service needs no restart: the
// login handler reads the hash from disk on every attempt.
func resetPanelPassword() error {
	if !elevated() {
		return fmt.Errorf("an elevated PowerShell or CMD is required")
	}
	current, err := readSettings(dataDir)
	if err != nil {
		return err
	}
	if current.Token == "" {
		return fmt.Errorf("there is no configuration in %s - run `servika-agent install` first", dataDir)
	}
	password, err := randomPanelPassword()
	if err != nil {
		return err
	}
	if current.PanelPasswordHash, err = hashPanelPassword(password); err != nil {
		return err
	}
	if err := writeSettings(dataDir, current); err != nil {
		return err
	}
	fmt.Println("The local panel password is RESET:")
	fmt.Println("  user     : admin")
	fmt.Println("  password : " + password)
	fmt.Println("It takes effect immediately; no service restart is needed.")
	return nil
}

// localAddress is the address to show in the install output.
func localAddress() string {
	if ip := firstIPv4(); ip != "" {
		return ip
	}
	return "SERVER-IP"
}

// firstIPv4 returns the first global unicast IPv4 on any interface. Private
// addresses count: the management plane lives on the private network anyway.
func firstIPv4() string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addresses {
		netAddr, ok := a.(*net.IPNet)
		if !ok || !netAddr.IP.IsGlobalUnicast() {
			continue
		}
		if v4 := netAddr.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func sameFile(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

// copyFile writes source over target, stopping the service first because a
// running service holds its own executable open.
func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	_, _ = runTool("sc", "stop", serviceName)
	time.Sleep(time.Second)
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	// A failed close means the copy FAILED. Ignoring it would hide a truncated
	// executable that then fails to start with no explanation.
	return out.Close()
}

// agentService is the service manager handshake. Without it the service manager
// kills a plain console program after 30 seconds for not answering.
type agentService struct{ servers [2]*http.Server }

func (a *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	failed := make(chan error, 1)
	go func() { failed <- serve(&a.servers) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-failed:
			logx.Errorf("the server stopped: %v", err)
			status <- svc.Status{State: svc.StopPending}
			return false, 1
		case request := <-requests:
			if done, code := a.handle(request, status); done {
				return false, code
			}
		}
	}
}

// handle answers one service manager request and reports whether to stop.
func (a *agentService) handle(request svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	switch request.Cmd {
	case svc.Interrogate:
		status <- request.CurrentStatus
	case svc.Stop, svc.Shutdown:
		status <- svc.Status{State: svc.StopPending}
		for _, s := range a.servers {
			if s != nil {
				_ = s.Close()
			}
		}
		return true, 0
	}
	return false, 0
}

// runService starts under the service manager.
func runService() {
	// Standard output is discarded under the service manager, so the log goes to
	// a file. It is the only trace an operator has when something fails at boot.
	_ = os.MkdirAll(dataDir, 0o755)
	if f, err := os.OpenFile(filepath.Join(dataDir, "agent.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	if err := svc.Run(serviceName, &agentService{}); err != nil {
		logx.Fatalf("the service could not run: %v", err)
	}
}

// runForeground starts without the service manager, for development.
func runForeground() {
	var servers [2]*http.Server
	if err := serve(&servers); err != nil {
		logx.Fatalf("%v", err)
	}
}
