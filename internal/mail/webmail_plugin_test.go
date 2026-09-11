package mail

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipped asset is what the installer drops before the panel first runs; the
// startup repair rewrites it for THIS host. They must agree on everything the
// host does not decide.
//
// The backend address is now substituted per host, because the panel's backend
// port is movable and this plugin dials it directly rather than through nginx.
// The asset therefore carries the DEFAULT address, and the comparison pins the
// environment so it measures the template rather than whatever the machine
// running the test happens to export.
func TestWebmailPluginAssetMatchesStartupRepairContent(t *testing.T) {
	t.Setenv("SERVIKA_LISTEN", "")
	asset, err := os.ReadFile("../../assets/mail/roundcube/plugins/servika_signon/servika_signon.php")
	if err != nil {
		t.Fatalf("read webmail signon plugin asset: %v", err)
	}
	if string(asset) != webmailPluginPHP() {
		t.Fatal("webmail signon plugin asset differs from startup repair content")
	}
}

// And the address actually follows the port, or the substitution is decorative.
func TestTheWebmailPluginDialsTheConfiguredBackend(t *testing.T) {
	t.Setenv("SERVIKA_LISTEN", "127.0.0.1:9443")
	php := webmailPluginPHP()
	if !strings.Contains(php, "http://127.0.0.1:9443/api/v1/internal/webmail-redeem") {
		t.Error("the plugin does not dial the configured backend port")
	}
	if strings.Contains(php, "127.0.0.1:8080") {
		t.Error("the plugin still carries the hardcoded default port")
	}
	// A wildcard listen is not an address a client can dial, so it falls back to
	// the loopback while keeping the port.
	t.Setenv("SERVIKA_LISTEN", "0.0.0.0:9443")
	if !strings.Contains(webmailPluginPHP(), "http://127.0.0.1:9443/") {
		t.Error("a wildcard listen did not fall back to the loopback address")
	}
}

func TestWebmailPluginReadsTheTokenOnlyFromThePostBody(t *testing.T) {
	php := webmailPluginPHP()
	if strings.Contains(php, "$_GET") {
		t.Fatal("the plugin reads the query string, which would put the token in browser history")
	}
	if !strings.Contains(php, "$_POST['_servika_token']") {
		t.Fatal("the plugin does not read the signon token from the POST body")
	}
	if strings.Contains(php, "{{TOKEN_PATH}}") {
		t.Fatal("the shared-secret path was not substituted")
	}
}

func TestEnableWebmailPluginKeepsTheExistingPlugins(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.inc.php"
	original := "<?php\n$config['plugins']      = ['archive', 'managesieve'];\n$config['skin'] = 'elastic';\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	changed, err := enableWebmailPlugin(path, original)
	if err != nil {
		t.Fatalf("enable the plugin: %v", err)
	}
	if !changed {
		t.Fatal("the config was reported unchanged")
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	want := "$config['plugins']      = ['archive', 'managesieve', 'servika_signon'];"
	if !strings.Contains(string(updated), want) {
		t.Fatalf("plugin list = %q, want it to contain %q", string(updated), want)
	}
	if !strings.Contains(string(updated), "$config['skin'] = 'elastic';") {
		t.Fatal("the rest of the config was lost")
	}
	// The list must be rewritten in place: a second assignment would replace the
	// first one and silently disable every plugin the operator had enabled.
	if strings.Count(string(updated), "$config['plugins']") != 1 {
		t.Fatal("a second plugin list assignment was added")
	}
}

func TestEnableWebmailPluginIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.inc.php"
	original := "<?php\n$config['plugins'] = ['archive', 'servika_signon'];\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	changed, err := enableWebmailPlugin(path, original)
	if err != nil {
		t.Fatalf("enable the plugin: %v", err)
	}
	if changed {
		t.Fatal("an already-enabled plugin was reported as a change")
	}
}

func TestEnableWebmailPluginFillsAnEmptyList(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.inc.php"
	original := "<?php\n$config['plugins'] = [];\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := enableWebmailPlugin(path, original); err != nil {
		t.Fatalf("enable the plugin: %v", err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(updated), "$config['plugins'] = ['servika_signon'];") {
		t.Fatalf("plugin list = %q", string(updated))
	}
}

func TestEnableWebmailPluginReportsAMissingList(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.inc.php"
	original := "<?php\n$config['skin'] = 'elastic';\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := enableWebmailPlugin(path, original); err == nil {
		t.Fatal("a config without a plugin list was accepted")
	}
}

func TestMasterLoginJoinsTheMailboxAndTheMasterUser(t *testing.T) {
	got := MasterLogin("info@example.com")
	want := "info@example.com*servika-webmail"
	if got != want {
		t.Fatalf("MasterLogin = %q, want %q", got, want)
	}
	// Dovecot splits on the separator, so it must be the one the drop-in sets.
	if !strings.Contains(masterConf, "auth_master_user_separator = "+masterSeparator) {
		t.Fatal("the master passdb does not declare the separator the login uses")
	}
}

func TestMasterPassdbDoesNotChainToTheMailboxPassword(t *testing.T) {
	// `pass = yes` would make Dovecot ask for the mailbox's own password as well,
	// which would defeat a sign-in the panel cannot supply that password for.
	if strings.Contains(masterConf, "pass = yes") {
		t.Fatal("the master passdb chains to the mailbox passdb")
	}
	if !strings.Contains(masterConf, "master = yes") {
		t.Fatal("the passdb is not declared as a master passdb")
	}
}

func TestSignonTokenMatchesTheFormatTheWebmailPluginAccepts(t *testing.T) {
	// The plugin rejects anything outside /^[a-f0-9]{16,128}$/ before it spends a
	// loopback request on it, so a change to the minting side that broke that
	// shape would make every sign-in fail with no server-side trace.
	accepted := regexp.MustCompile(`^[a-f0-9]{16,128}$`)
	if !strings.Contains(webmailPluginPHP(), accepted.String()) {
		t.Fatal("the plugin no longer validates the token with the expected pattern")
	}
	for range 32 {
		token, err := randomToken()
		if err != nil {
			t.Fatalf("mint a token: %v", err)
		}
		if !accepted.MatchString(token) {
			t.Fatalf("minted token %q is rejected by the webmail plugin", token)
		}
	}
}

func TestWebmailRedeemRefusesWithoutTheSharedSecret(t *testing.T) {
	// The secret file is the only thing separating the redeem endpoint from the
	// open internet, so an unreadable one must deny rather than wave the caller
	// through. The DB is nil on purpose: reaching it would already be the bug.
	t.Setenv("SERVIKA_PMA_TOKEN", filepath.Join(t.TempDir(), "absent.token"))
	handlers := &Handlers{}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/internal/webmail-redeem",
		strings.NewReader(`{"token":"deadbeefdeadbeefdeadbeef"}`))
	request.Header.Set("X-Internal-Auth", "whatever-the-caller-guessed")
	recorder := httptest.NewRecorder()
	handlers.WebmailRedeem(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestWebmailRedeemRefusesAMismatchedSharedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "internal.token")
	if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write the shared secret: %v", err)
	}
	t.Setenv("SERVIKA_PMA_TOKEN", path)
	handlers := &Handlers{}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/internal/webmail-redeem",
		strings.NewReader(`{"token":"deadbeefdeadbeefdeadbeef"}`))
	request.Header.Set("X-Internal-Auth", "0123456789abcdee")
	recorder := httptest.NewRecorder()
	handlers.WebmailRedeem(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
