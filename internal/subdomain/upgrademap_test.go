package subdomain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// applyHarness points the upgrade map at a directory the test owns and records
// the host commands instead of running them.
func applyHarness(t *testing.T) (mapPath string, ran *[]string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "00-servika-upgrade-map.conf")
	t.Setenv("SERVIKA_NGINX_UPGRADE_MAP_CONF", path)

	var commands []string
	previous := runCommand
	runCommand = func(name string, args ...string) error {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	t.Cleanup(func() { runCommand = previous })
	return path, &commands
}

// $connection_upgrade is defined by a map in http context that the DOMAIN render
// writes. A subdomain writes its own server blocks, so on a server where no
// domain-level application has ever been created the map is missing and nginx
// refuses the WHOLE configuration for an undefined variable. The application can
// then never be published, and the message names nothing an operator can act on.
func TestASubdomainVhostWritesTheUpgradeMapItReferences(t *testing.T) {
	mapPath, _ := applyHarness(t)
	vhost := filepath.Join(t.TempDir(), "sub.example.com.conf")

	body := "server {\n    proxy_set_header Connection $connection_upgrade;\n}\n"
	if err := applyVhost(vhost, body); err != nil {
		t.Fatalf("applyVhost: %v", err)
	}

	written, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatalf("the upgrade map was not written: %v", err)
	}
	if !strings.Contains(string(written), "map $http_upgrade $connection_upgrade {") {
		t.Errorf("the map does not define the variable: %q", written)
	}
}

// A vhost that names no application proxy must not write a server-global file.
func TestAVhostWithoutAProxyLeavesTheUpgradeMapAlone(t *testing.T) {
	mapPath, _ := applyHarness(t)
	vhost := filepath.Join(t.TempDir(), "sub.example.com.conf")

	if err := applyVhost(vhost, "server {\n    root /home/c_shop/public_html;\n}\n"); err != nil {
		t.Fatalf("applyVhost: %v", err)
	}

	if _, err := os.Stat(mapPath); !os.IsNotExist(err) {
		t.Errorf("a vhost with no proxy wrote the upgrade map: %v", err)
	}
}

// The map is written BEFORE the vhost is validated. nginx reads the whole
// conf.d tree, so a map written afterwards would not save the test that has
// already run.
func TestTheUpgradeMapIsWrittenBeforeTheValidation(t *testing.T) {
	mapPath, ran := applyHarness(t)
	vhost := filepath.Join(t.TempDir(), "sub.example.com.conf")

	previous := runCommand
	var mapPresentAtTest bool
	runCommand = func(name string, args ...string) error {
		if name == "nginx" {
			_, err := os.Stat(mapPath)
			mapPresentAtTest = err == nil
		}
		return previous(name, args...)
	}

	if err := applyVhost(vhost, "server { proxy_set_header Connection $connection_upgrade; }\n"); err != nil {
		t.Fatalf("applyVhost: %v", err)
	}
	if !mapPresentAtTest {
		t.Errorf("nginx -t ran before the map existed: %v", *ran)
	}
}
