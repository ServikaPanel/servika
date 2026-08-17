package hostapps

import (
	"strings"
	"testing"
)

// section returns the body of one systemd unit section, so a key can be
// asserted to be IN it rather than merely present somewhere in the file.
func section(t *testing.T, body, name string) string {
	t.Helper()
	start := strings.Index(body, "["+name+"]")
	if start < 0 {
		t.Fatalf("the unit has no [%s] section:\n%s", name, body)
	}
	rest := body[start+len(name)+2:]
	// Cut returns the whole string when the separator is absent, which is the
	// last section of the unit.
	head, _, _ := strings.Cut(rest, "\n[")
	return head
}

func renderedUnit(t *testing.T) string {
	t.Helper()
	entry := sampleEntry()
	argv, err := BuildArgv(entry, DataDir(entry.Code), 31004)
	if err != nil {
		t.Fatal(err)
	}
	return RenderUnit(entry, SystemUser(entry.Code),
		append([]string{"/opt/servika-apps/grafana/bin/grafana"}, argv...))
}

// The two StartLimit keys belong to [Unit] and nowhere else.
//
// systemd 257 answers `Unknown key 'StartLimitIntervalSec' in section [Service],
// ignoring.` while SILENTLY accepting StartLimitBurst there (measured with
// systemd-analyze verify), so the [Service] spelling leaves the burst counting
// against the default ten-second window. With RestartSec=5 only two starts fit
// it, the burst is never reached, and an application that cannot start restarts
// every five seconds for good instead of reaching failed, which is the one state
// the screen reads as broken. internal/apps and internal/laravel carry the same
// rule for the same measurement.
func TestTheStartLimitKeysAreInTheUnitSection(t *testing.T) {
	body := renderedUnit(t)
	unit, service := section(t, body, "Unit"), section(t, body, "Service")
	for _, key := range []string{"StartLimitIntervalSec=", "StartLimitBurst="} {
		if !strings.Contains(unit, key) {
			t.Errorf("%s is not in [Unit]:\n%s", key, body)
		}
		if strings.Contains(service, key) {
			t.Errorf("%s is in [Service], where systemd ignores or misreads it:\n%s", key, body)
		}
	}
}

// The environment goes in an EnvironmentFile, never Environment=. Any local
// account reads Environment= values back out of `systemctl show`, and these
// applications carry admin tokens and database passwords. The tenants share this
// host, so "local account" is not hypothetical.
func TestTheEnvironmentIsNotWrittenIntoTheUnit(t *testing.T) {
	body := renderedUnit(t)
	if !strings.Contains(body, "EnvironmentFile=") {
		t.Errorf("the unit has no EnvironmentFile:\n%s", body)
	}
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Environment=") {
			t.Errorf("the unit carries an Environment= line, readable by every local account: %q", line)
		}
	}
}

// The log target is under the panel's root-owned directory. systemd opens an
// append: target with O_APPEND|O_CREAT and FOLLOWS symlinks, so a target in a
// directory the application's own account could write would let it redirect a
// root-opened descriptor.
func TestTheLogTargetIsNotWritableByTheApplication(t *testing.T) {
	body := renderedUnit(t)
	logPath := LogPath("grafana")
	if !strings.Contains(body, "StandardOutput=append:"+logPath) {
		t.Errorf("the log target is not the panel's own path:\n%s", body)
	}
	if strings.HasPrefix(logPath, InstallDir("grafana")) {
		t.Errorf("the log lives inside the application's own tree: %s", logPath)
	}
}

// The program the service executes is read-only to the account running it: only
// the data directory is writable. That is stricter than internal/apps, which has
// to open the whole home because a tenant's files and a tenant's application are
// one tree.
func TestOnlyTheDataDirectoryIsWritable(t *testing.T) {
	body := renderedUnit(t)
	if !strings.Contains(body, "ProtectSystem=strict") {
		t.Fatalf("without ProtectSystem=strict the ReadWritePaths line means nothing:\n%s", body)
	}
	if !strings.Contains(body, "ReadWritePaths="+DataDir("grafana")+"\n") {
		t.Errorf("the data directory is not the writable path:\n%s", body)
	}
	if strings.Contains(body, "ReadWritePaths="+InstallDir("grafana")+"\n") {
		t.Errorf("the whole install directory is writable, so the program can rewrite itself:\n%s", body)
	}
}

// The port variable is written under the name the CATALOG gives, because the
// products disagree: Grafana reads GF_SERVER_HTTP_PORT and ignores PORT
// entirely. Writing PORT for it would leave Grafana on its own default, which
// the panel neither reserved nor firewalled, and the screen would report it as
// down with nothing in its log to explain it.
func TestThePortIsWrittenUnderTheProductsOwnVariable(t *testing.T) {
	entry := sampleEntry()
	body := RenderEnvFile(entry, 31004, nil)
	if !strings.Contains(body, "GF_SERVER_HTTP_PORT=31004\n") {
		t.Errorf("the port is not under the catalog's variable:\n%s", body)
	}
	if strings.Contains(body, "PORT=31004\n") && !strings.Contains(body, "GF_SERVER_HTTP_PORT=31004\n") {
		t.Errorf("the port was written under the generic name:\n%s", body)
	}
}

// A supplied value can never take the port variable's name. The panel assigns
// the port and derives the firewall rule and the screen's link from it, so a
// value that overrode it would leave all three describing a port nothing is on.
func TestASuppliedValueCannotOverrideThePort(t *testing.T) {
	entry := sampleEntry()
	body := RenderEnvFile(entry, 31004, map[string]string{
		"GF_SERVER_HTTP_PORT":        "80",
		"GF_SECURITY_ADMIN_PASSWORD": "kept",
	})
	if strings.Contains(body, "GF_SERVER_HTTP_PORT=80") {
		t.Errorf("a supplied value overrode the assigned port:\n%s", body)
	}
	if !strings.Contains(body, "GF_SERVER_HTTP_PORT=31004\n") {
		t.Errorf("the assigned port is missing:\n%s", body)
	}
	if !strings.Contains(body, "GF_SECURITY_ADMIN_PASSWORD=kept\n") {
		t.Errorf("an ordinary value was dropped:\n%s", body)
	}
}

// An application that takes its port from neither a flag nor an environment
// variable gets no variable at all. Writing PORT for it would say the panel had
// told it something it never reads, and the screen's own note about setting the
// port by hand is the honest answer.
func TestAnApplicationThatIgnoresThePortGetsNoVariable(t *testing.T) {
	entry := sampleEntry()
	entry.TakesPort = false
	body := RenderEnvFile(entry, 31004, nil)
	if strings.Contains(body, "31004") {
		t.Errorf("a port was written for an application that does not read one:\n%s", body)
	}
}

// The unit and the account are named after the catalog code, which is what makes
// them findable by an operator reading systemctl output.
func TestTheHostNamesAreDerivedFromTheCode(t *testing.T) {
	if got := UnitName("gitea"); got != "servika-hostapp-gitea.service" {
		t.Errorf("unit name = %q", got)
	}
	if got := SystemUser("gitea"); got != "svk_gitea" {
		t.Errorf("system user = %q", got)
	}
	if !strings.HasSuffix(InstallDir("gitea"), "/gitea") {
		t.Errorf("install dir = %q", InstallDir("gitea"))
	}
	if DataDir("gitea") != InstallDir("gitea")+"/data" {
		t.Errorf("data dir = %q", DataDir("gitea"))
	}
}
