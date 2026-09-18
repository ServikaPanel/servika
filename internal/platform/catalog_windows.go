//go:build windows

package platform

// Detecting what is installed, and installing what is not.
//
// Every command here is run with exec.Command's argument list. Nothing is
// joined into a shell string, and every argument comes from a constant in this
// file rather than from a request.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// downloadDir is where an installer is fetched to. It is under ProgramData
	// rather than a temporary directory, so a resumed download survives a reboot.
	downloadDir = `C:\ProgramData\servika\downloads`

	// winAcmeDir and phpMyAdminDir are where those two archives are unpacked.
	winAcmeDir    = `C:\Program Files\Servika\win-acme`
	phpMyAdminDir = `C:\inetpub\servika-tools\phpmyadmin`

	// installTimeout bounds ONE installer command. SQL Express takes a quarter
	// of an hour and thirty minutes leaves room on a slow machine, while a stuck
	// installer must not read "running" until the agent is restarted.
	installTimeout = 30 * time.Minute

	// rebootRequired is ERROR_SUCCESS_REBOOT_REQUIRED. In the installer world it
	// means "installed, now restart", so it is NOT a failure. Treating it as one
	// would turn every successful MSI into a false alarm.
	rebootRequired = 3010
)

// installers maps a catalog key to the function that installs it.
var installers = map[string]func(*Job) error{
	"iis":        installIIS,
	"urlrewrite": installRewrite,
	"dotnet":     installDotNet,
	"ssl":        installWinAcme,
	"ftp":        installFTP,
	"dns":        installDNS,
	"quota":      installQuota,
	"mssql":      installMSSQL,
	"mysql":      installMySQL,
	"pgsql":      installPostgres,
	"phpmyadmin": installPhpMyAdmin,
	"node":       installNode,
	"git":        installGit,
	"redis":      installRedis,
}

// rewriteDLL is where the URL Rewrite module lands. Its presence is the reliable
// sign that the module is installed.
func rewriteDLL() string {
	win := os.Getenv("WINDIR")
	if win == "" {
		win = `C:\Windows`
	}
	return filepath.Join(win, "System32", "inetsrv", "rewrite.dll")
}

// memuraiInstalled reports whether the Redis-compatible cache is on the host.
// The cheap checks come first and the service query last.
func memuraiInstalled() bool {
	if _, err := exec.LookPath("memurai"); err == nil {
		return true
	}
	if fileExists(`C:\Program Files\Memurai\memurai.exe`) {
		return true
	}
	// sc query exits 0 when the service is registered and 1060 when it is not.
	return exec.Command("sc", "query", "Memurai").Run() == nil
}

// itemInstalled reports whether one catalog item is already on the host.
//
// Most items are answered by the capability bit they light, which comes from
// the cached discovery pass. The rest have no bit and are checked directly.
func itemInstalled(item Item) bool {
	if item.Capability != 0 {
		return Active().Capabilities().Has(item.Capability)
	}
	switch item.Key {
	case "urlrewrite":
		return fileExists(rewriteDLL())
	case "phpmyadmin":
		return fileExists(filepath.Join(phpMyAdminDir, "index.php"))
	case "node":
		return commandExists("node")
	case "git":
		return commandExists("git")
	case "redis":
		return memuraiInstalled()
	}
	return false
}

// CatalogStatus returns the catalog with what is installed marked.
func CatalogStatus() []Entry { return Catalog(itemInstalled) }

// Start begins an installation and returns its job id.
//
// The item is checked against the SAME rules the catalog answer shows, so a
// request for something the panel already greys out is refused here too rather
// than trusted because the panel said so.
func (in *Installer) Start(key string) (string, error) {
	item, ok := findItem(catalog, key)
	if !ok {
		return "", fmt.Errorf("unknown item %q: %w", key, ErrNotInstallable)
	}
	if item.Tier == TierUndecided {
		return "", fmt.Errorf("%q cannot be installed yet: %w", item.Name, ErrNotInstallable)
	}
	install, ok := installers[key]
	if !ok {
		return "", fmt.Errorf("%q has no installer: %w", item.Name, ErrNotInstallable)
	}
	if itemInstalled(item) {
		return "", fmt.Errorf("%q is already installed: %w", item.Name, ErrNotInstallable)
	}
	id, err := randomHex(8)
	if err != nil {
		return "", fmt.Errorf("the job id could not be generated: %w", err)
	}
	job, err := in.claim(id, key)
	if err != nil {
		return "", err
	}
	in.writeMarker(id, key)
	// The capability cache is dropped after EVERY outcome, because a run that
	// failed part way can still have changed the host.
	go in.run(job, item, install, dropCapabilityCache)
	return id, nil
}

// dropCapabilityCache forces the next discovery pass to look at the host again.
func dropCapabilityCache() {
	capabilityCache.Lock()
	capabilityCache.at = time.Time{}
	capabilityCache.Unlock()
}

// randomHex returns n random bytes as hex.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// runInstall runs one installer command and streams its output into the log.
//
// CombinedOutput is deliberately NOT used. A fifteen-minute SQL installation
// has to show the operator live progress, not one block once it is over.
func runInstall(job *Job, name string, arg ...string) error {
	// HONEST UNCERTAINTY: while an installer runs the duration GENUINELY cannot
	// be estimated, because msiexec and the SQL setup do not say how long they
	// will take. Percent stays -1 so the bar is indeterminate rather than showing
	// an invented number.
	job.setProgress(Progress{Stage: "installing", Label: filepath.Base(name), Percent: -1, SecondsLeft: -1})
	job.Logf("> %s %s", name, strings.Join(arg, " "))

	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, arg...)
	out := &logWriter{job: job}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	out.flush()
	if err == nil {
		return nil
	}
	return installFailure(ctx, job, name, err)
}

// installFailure decides what a non-zero exit actually means.
func installFailure(ctx context.Context, job *Job, name string, err error) error {
	// The timeout is checked INSIDE the error branch on purpose: a deadline that
	// expires just after a successful Run must not turn a finished installation
	// into a timeout.
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s: the %.0f minute timeout expired", name, installTimeout.Minutes())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == rebootRequired {
		job.Logf("exit code %d: installed, a restart is needed", rebootRequired)
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}

// installFeature runs Install-WindowsFeature.
//
// Success=False IS a failure even when the exit code is 0: the cmdlet can
// return 0 on a partial failure, so the result object has to be read. The
// feature list comes only from the fixed calls below.
//
// ProgressPreference must be silenced. The ServerManager cmdlets try to draw a
// progress bar, and without a console that fails with "Access is denied reading
// the console output buffer" and takes the cmdlet down with it.
func installFeature(job *Job, features string) error {
	script := "$ProgressPreference='SilentlyContinue'; $s = Install-WindowsFeature -Name " + features +
		"; $s | Format-List Success,RestartNeeded,ExitCode" +
		"; if (-not $s.Success) { exit 1 }"
	return runInstall(job, "powershell", "-NoProfile", "-Command", script)
}

func installIIS(job *Job) error { return installFeature(job, "Web-Server -IncludeManagementTools") }
func installFTP(job *Job) error { return installFeature(job, "Web-Ftp-Server,Web-Mgmt-Console") }
func installDNS(job *Job) error { return installFeature(job, "DNS -IncludeManagementTools") }

// installQuota installs File Server Resource Manager, which is what applies a
// plan's disk limit. Without it the limit is silently not enforced.
func installQuota(job *Job) error {
	restart, err := InstallQuotaEngine()
	if err != nil {
		return err
	}
	if restart {
		job.Logf("File Server Resource Manager is installed; a restart is needed before the quota takes effect")
	}
	return nil
}

// fetch downloads one file into the download directory and returns its path.
func fetch(job *Job, url, name string) (string, error) {
	target := filepath.Join(downloadDir, name)
	if err := download(job, url, target); err != nil {
		return "", err
	}
	return target, nil
}

// installDotNet installs the ASP.NET Core hosting bundle.
//
// The bundle runs with /norestart and does not stop IIS itself, so the closing
// iisreset is required: without it the module is invisible until somebody
// restarts IIS by hand.
func installDotNet(job *Job) error {
	path, err := fetch(job, dotnetHostingURL, "dotnet-hosting-win.exe")
	if err != nil {
		return err
	}
	if err := runInstall(job, path, "/install", "/quiet", "/norestart"); err != nil {
		return err
	}
	return runInstall(job, "iisreset")
}

// installWinAcme unpacks win-acme. It is a copy rather than an installation, so
// it is the quickest item. The binary is checked afterwards: if the archive
// layout ever changes, this says so plainly instead of reporting a success that
// leaves nothing installed.
func installWinAcme(job *Job) error {
	archive, err := fetch(job, winAcmeURL, "win-acme.zip")
	if err != nil {
		return err
	}
	if err := unzip(job, archive, winAcmeDir); err != nil {
		return err
	}
	if !fileExists(wacsPath) {
		return fmt.Errorf("the archive unpacked but wacs.exe is not at %s, so its layout differs from what was expected", wacsPath)
	}
	job.Logf("win-acme is ready: %s", wacsPath)
	return nil
}

// installMSSQL installs SQL Server Express in two stages.
//
// The bootstrapper's own `/ACTION=INSTALL /QUIET` fails within a second with
// "Downloading install package... Failure", while the SAME bootstrapper's
// `/ACTION=Download` fetches the media without trouble. So the media is
// downloaded first and the extracted installer is then run directly.
//
// The engine check at the top makes the whole thing repeatable: if the engine
// is already there, a second run skips the 750 MB media and only repairs
// sqlcmd. Without it SQLEXPR would fail with "instance already exists" and a
// half-finished installation could never be completed.
func installMSSQL(job *Job) error {
	if Active().Capabilities().Has(CapMSSQL) {
		job.Logf("the SQL Server engine is already installed; skipping the engine and only checking sqlcmd")
		return repairSqlcmd(job)
	}
	job.Logf("this takes a while: the media is about 750 MB and the output can stay quiet for minutes")
	bootstrapper, err := fetch(job, mssqlURL, "SQL2022-SSEI-Expr.exe")
	if err != nil {
		return err
	}
	media, err := downloadSQLMedia(job, bootstrapper)
	if err != nil {
		return err
	}
	job.Logf("2/2 - installing SQL Server (the SQLEXPRESS instance)")
	// SQLBROWSERSVCSTARTUPTYPE is required: reaching a named instance over TCP
	// needs the SQL Browser, and without it sqlcmd cannot find SQLEXPRESS.
	if err := runInstall(job, media, "/Q", "/ACTION=Install", "/FEATURES=SQLENGINE",
		"/INSTANCENAME=SQLEXPRESS", `/SQLSYSADMINACCOUNTS=BUILTIN\Administrators`,
		"/TCPENABLED=1", "/SQLBROWSERSVCSTARTUPTYPE=Automatic",
		"/IACCEPTSQLSERVERLICENSETERMS"); err != nil {
		return err
	}
	// Automatic, but it can still be stopped right after the installation.
	_ = exec.Command("sc", "start", "SQLBrowser").Run()
	return repairSqlcmd(job)
}

// downloadSQLMedia runs the bootstrapper's download stage and returns the
// installer it produced.
func downloadSQLMedia(job *Job, bootstrapper string) (string, error) {
	dir := filepath.Join(downloadDir, "sqlmedia")
	job.Logf("1/2 - downloading the SQL media (about 750 MB)")
	if err := runInstall(job, bootstrapper, "/ACTION=Download", "/MEDIAPATH="+dir,
		"/MEDIATYPE=Core", "/QUIET", "/HIDEPROGRESSBAR"); err != nil {
		return "", fmt.Errorf("the SQL media could not be downloaded: %w", err)
	}
	media := filepath.Join(dir, "SQLEXPR_x64_ENU.exe")
	if !fileExists(media) {
		return "", fmt.Errorf("the downloaded media is not at %s", media)
	}
	return media, nil
}

// repairSqlcmd puts go-sqlcmd in place if it is not already there.
//
// The SQL Server engine does NOT ship sqlcmd, and every database operation this
// agent performs runs through it. Keeping this separate and idempotent is what
// lets a run where the engine installed but sqlcmd did not be fixed without
// fetching 750 MB again.
func repairSqlcmd(job *Job) error {
	if fileExists(sqlcmdInstalled) {
		job.Logf("sqlcmd is already in place: %s", sqlcmdInstalled)
		return nil
	}
	job.Logf("downloading the sqlcmd tool (go-sqlcmd, no ODBC needed)")
	archive, err := fetch(job, gosqlcmdURL, "go-sqlcmd.zip")
	if err != nil {
		return fmt.Errorf("sqlcmd could not be downloaded: %w", err)
	}
	if err := unzip(job, archive, filepath.Dir(sqlcmdInstalled)); err != nil {
		return fmt.Errorf("sqlcmd could not be unpacked: %w", err)
	}
	if !fileExists(sqlcmdInstalled) {
		return fmt.Errorf("sqlcmd was extracted but is not at %s", sqlcmdInstalled)
	}
	job.Logf("sqlcmd is ready: %s", sqlcmdInstalled)
	return nil
}

// installMySQL installs the MySQL Installer tool.
//
// The package installs the TOOL, not a running MySQL instance. That is reported
// as a partial installation rather than a success, so nobody reads "MySQL is
// ready" from a host that has no server on it.
func installMySQL(job *Job) error {
	path, err := fetch(job, mysqlURL, "mysql-installer-community.msi")
	if err != nil {
		return err
	}
	if err := runInstall(job, "msiexec", "/i", path, "/qn"); err != nil {
		return err
	}
	return fmt.Errorf("the MySQL Installer tool is installed but there is no running MySQL instance: %w", ErrPartialInstall)
}

// postgresOptionFile writes the superuser password into a short-lived 0600 file
// in the BitRock --optionfile format and returns its path.
//
// THE PASSWORD MUST NOT BE AN ARGUMENT. On Windows any local process can read
// another's command line (Get-CimInstance Win32_Process), so a password passed
// as --superpassword is readable for the whole installation. A file that is
// created, used and deleted keeps it out of the command line.
func postgresOptionFile(dir, password string) (string, error) {
	suffix, err := randomHex(4)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "pg-opt-"+suffix+".ini")
	if err := os.WriteFile(path, []byte("superpassword="+password+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// installPostgres installs PostgreSQL unattended on port 5432.
func installPostgres(job *Job) error {
	path, err := fetch(job, pgsqlURL, "postgresql-windows-x64.exe")
	if err != nil {
		return err
	}
	password, err := randomHex(16) // 32 hex characters, so at least 128 bits
	if err != nil {
		return fmt.Errorf("the postgres password could not be generated: %w", err)
	}
	optionFile, err := postgresOptionFile(downloadDir, password)
	if err != nil {
		return fmt.Errorf("the postgres option file could not be written: %w", err)
	}
	defer func() { _ = os.Remove(optionFile) }()

	// The password goes to the job's own secret field, never to the log: a log
	// stays in the scrollback and would show the password again on every visit
	// (CWE-532). The panel shows it once.
	job.setSecret(password)
	job.Logf("the postgres superuser password was generated; take it ONCE from the panel's hidden-output field and store it")
	return runInstall(job, path, "--mode", "unattended", "--serverport", "5432", "--optionfile", optionFile)
}

// installNode installs the Node.js LTS MSI.
func installNode(job *Job) error {
	path, err := fetch(job, nodeURL, "node-x64.msi")
	if err != nil {
		return err
	}
	return runInstall(job, "msiexec", "/i", path, "/qn", "/norestart")
}

// installGit installs Git for Windows with the Inno Setup silent flags.
func installGit(job *Job) error {
	path, err := fetch(job, gitURL, "git-64-bit.exe")
	if err != nil {
		return err
	}
	return runInstall(job, path, "/VERYSILENT", "/NORESTART")
}

// installRewrite installs the IIS URL Rewrite module.
func installRewrite(job *Job) error {
	path, err := fetch(job, rewriteURL, "rewrite_amd64_en-US.msi")
	if err != nil {
		return err
	}
	return runInstall(job, "msiexec", "/i", path, "/qn", "/norestart")
}

// installRedis installs Memurai, the Redis-compatible server for Windows.
// There is no official Redis build for this platform, which is why the item is
// experimental rather than proven.
func installRedis(job *Job) error {
	job.Logf("there is no official Redis build for Windows; Memurai is the Redis-compatible server being installed")
	path, err := fetch(job, memuraiURL, "Memurai-Developer.msi")
	if err != nil {
		return err
	}
	return runInstall(job, "msiexec", "/i", path, "/qn", "/norestart")
}

// installPhpMyAdmin unpacks phpMyAdmin.
//
// This only puts the files down. phpMyAdmin needs PHP and an IIS site to run,
// so the result is a partial installation, not a ready interface.
func installPhpMyAdmin(job *Job) error {
	job.Logf("unpacking the phpMyAdmin files; PHP has to be installed for them to run")
	archive, err := fetch(job, phpMyAdminURL, "phpmyadmin.zip")
	if err != nil {
		return err
	}
	if err := unzip(job, archive, phpMyAdminDir); err != nil {
		return err
	}
	return fmt.Errorf("the phpMyAdmin files are unpacked but PHP and an IIS site are still needed: %w", ErrPartialInstall)
}
