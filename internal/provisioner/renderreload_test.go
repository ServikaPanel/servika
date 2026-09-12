package provisioner

import (
	"database/sql/driver"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// renderAndReload is the one sequence every vhost change goes through: it reads
// what the domain has turned on, renders the template for the domain's shape,
// writes the file, prepares the http-context files the vhost names, validates the
// whole tree, reloads, and keeps the Apache backend in step. These tests run the
// sequence in temporary directories with every command recorded, and pin the file
// it writes, the commands it runs and where each failure stops it.

const (
	suspendedQuery   = "COALESCE(suspended,0) FROM domains"
	maintenanceQuery = "maintenance_enabled"
	protectionQuery  = "COALESCE(geo_mode,'off'), COALESCE(rate_limit_rps,0)"
	hotlinkQuery     = "hotlink_enabled"
	appDomainQuery   = "SELECT id FROM domains WHERE domain_name=? LIMIT 1"
	appsQuery        = "FROM apps"
	// redirectQuery is the whole statement, because it carries appDomainQuery as
	// its subquery and no shorter fragment tells the two apart.
	redirectQuery    = "SELECT target_url, status_code FROM domain_redirects WHERE domain_id=(SELECT id FROM domains WHERE domain_name=? LIMIT 1)"
	wwwRedirectQuery = "COALESCE(www_redirect,'off')"
)

// setForTest sets *target to value for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// renderFixture runs the render sequence against temporary directories. A
// command whose argv starts with one of failing exits 1 and prints output; every
// other command succeeds silently.
type renderFixture struct {
	confDir    string
	apacheDir  string
	units      string
	cache      string
	upgradeMap string
	commands   *commandRecorder
	failing    [][]string
	output     string
}

func withRenderSequence(t *testing.T) *renderFixture {
	t.Helper()
	root := t.TempDir()
	f := &renderFixture{
		confDir:    filepath.Join(root, "conf.d"),
		apacheDir:  filepath.Join(root, "httpd"),
		cache:      filepath.Join(root, "cache", "servikacache"),
		upgradeMap: filepath.Join(root, "conf.d", "00-servika-upgrade-map.conf"),
	}
	for _, dir := range []string{f.confDir, f.apacheDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	withTenantHome(t)
	f.units = withTenantUnits(t)
	withoutDatabase(t)
	certRoot(t)
	setForTest(t, &nginxConfDir, f.confDir)
	setForTest(t, &apacheConfDir, f.apacheDir)
	setForTest(t, &nginxMainConf, filepath.Join(root, "nginx.conf"))
	setForTest(t, &nginxAccount, account.Username)
	setForTest(t, &chown, func(string, int, int) error { return nil })
	setForTest(t, &protectionConfPath, filepath.Join(f.confDir, "00-servika-geo.conf"))
	setForTest(t, &webmailInstallRoot, filepath.Join(root, "roundcube"))
	t.Setenv("SERVIKA_NGINX_CACHE_DIR", f.cache)
	t.Setenv("SERVIKA_NGINX_CACHE_CONF", filepath.Join(f.confDir, "00-servika-cache.conf"))
	t.Setenv("SERVIKA_NGINX_CACHE_TEMP_CONF", filepath.Join(root, "servikacache-temp.conf"))
	t.Setenv("SERVIKA_NGINX_CACHE_LOG_CONF", filepath.Join(f.confDir, "00-servika-cache-log.conf"))
	t.Setenv("SERVIKA_NGINX_UPGRADE_MAP_CONF", f.upgradeMap)
	t.Setenv("SERVIKA_GEOIP_DIR", filepath.Join(root, "geoip"))
	t.Setenv("SERVIKA_PUBLIC_IPV4", "203.0.113.10")
	f.commands = withCommandScript(t, func(argv []string) (string, int) {
		for _, prefix := range f.failing {
			if hasArgvPrefix(argv, prefix) {
				return f.output, 1
			}
		}
		return "", 0
	})
	return f
}

func (f *renderFixture) vhostPath() string { return filepath.Join(f.confDir, "dom_c_example_com.conf") }

func (f *renderFixture) apacheVhost() string {
	return filepath.Join(f.apacheDir, "dom_c_example_com.conf")
}

// render runs the sequence for c_example_com and returns what the default vhost
// path holds afterwards, "" when nothing is there.
func (f *renderFixture) render(t *testing.T, opts VhostOpts) (string, error) {
	t.Helper()
	err := renderAndReload(opts, "c_example_com")
	body, readErr := os.ReadFile(f.vhostPath())
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(body), err
}

func exampleVhost() VhostOpts {
	return VhostOpts{
		DomainName: "example.com",
		WebRoot:    "/home/c_example_com/public_html",
		PHPSocket:  "/run/php-fpm/c_example_com.sock",
		PHPVersion: "8.3",
	}
}

// renderScript answers every read a render makes with no row, so each test turns
// on only the state it is about.
func renderScript(rows map[string][][]driver.Value) *sqlScript {
	script := &sqlScript{rows: map[string][][]driver.Value{
		suspendedQuery: {}, wafQuery: {}, ipAccessQuery: {}, maintenanceQuery: {},
		protectionQuery: {}, hotlinkQuery: {}, appDomainQuery: {}, appsQuery: {},
		redirectQuery: {}, wwwRedirectQuery: {}, panelDomainQuery: {},
		domainGeoQuery: {}, firewallGeoQuery: {}, rateLimitQuery: {},
	}}
	maps.Copy(script.rows, rows)
	return script
}

func assertVhostCarries(t *testing.T, body string, want, absent []string) {
	t.Helper()
	for _, fragment := range want {
		if !strings.Contains(body, fragment) {
			t.Errorf("the vhost does not carry %q:\n%s", fragment, body)
		}
	}
	for _, fragment := range absent {
		if strings.Contains(body, fragment) {
			t.Errorf("the vhost carries %q:\n%s", fragment, body)
		}
	}
}

func TestARenderWritesTheVhostThenValidatesAndReloads(t *testing.T) {
	f := withRenderSequence(t)

	body, err := f.render(t, exampleVhost())

	if err != nil {
		t.Fatalf("renderAndReload() error = %v", err)
	}
	assertVhostCarries(t, body, []string{
		"server_name example.com www.example.com;",
		"# ---- Backend: nginx + PHP-FPM (default) ----",
		"fastcgi_pass unix:/run/php-fpm/c_example_com.sock;",
	}, nil)
	want := [][]string{
		{"restorecon", "-R", f.cache},
		{"restorecon", filepath.Join(f.confDir, "00-servika-cache.conf")},
		{"restorecon", filepath.Join(f.confDir, "00-servika-cache-log.conf")},
		{"nginx", "-t"},
		{"systemctl", "reload", "nginx"},
	}
	if got := f.commands.argvs(); !reflect.DeepEqual(got, want) {
		t.Errorf("ran %q\nwant %q", got, want)
	}
	if _, statErr := os.Stat(protectionConfPath); statErr != nil {
		t.Errorf("the shared protection file was not written: %v", statErr)
	}
}

func TestARenderServesATenantWithItsOwnMasterFromItsSocket(t *testing.T) {
	f := withRenderSequence(t)
	writeFixture(t, filepath.Join(f.units, tenantUnitName("c_example_com")), "[Service]\n")

	body, err := f.render(t, exampleVhost())

	if err != nil {
		t.Fatalf("renderAndReload() error = %v", err)
	}
	assertVhostCarries(t, body, []string{"fastcgi_pass unix:" + tenantSocket("c_example_com") + ";"},
		[]string{"/run/php-fpm/c_example_com.sock"})
}

func TestWhatTheDomainTurnedOnReachesTheVhost(t *testing.T) {
	cases := []struct {
		name   string
		rows   map[string][][]driver.Value
		want   []string
		absent []string
	}{
		{"a suspended domain renders the suspension page and nothing it turned on",
			map[string][][]driver.Value{suspendedQuery: {{int64(1)}}, ipAccessQuery: {{int64(9), "deny"}}, ipRuleListQuery: {{"203.0.113.7"}}},
			[]string{"# example.com suspended by Servika"}, []string{"deny 203.0.113.7;", "fastcgi_pass"}},
		{"a whole-domain redirect renders the redirect vhost",
			map[string][][]driver.Value{redirectQuery: {{"https://elsewhere.example", int64(302)}}},
			[]string{"return 302 https://elsewhere.example$request_uri;"}, []string{"fastcgi_pass"}},
		{"a canonical redirect answers the other hostname with a 301",
			map[string][][]driver.Value{wwwRedirectQuery: {{"to_www"}}},
			[]string{"server_name www.example.com;", "# example.com — redirected to the canonical hostname www.example.com",
				"return 301 http://www.example.com$request_uri;"},
			[]string{"server_name example.com www.example.com;"}},
		{"a whole-domain redirect keeps both hostnames over a canonical redirect",
			map[string][][]driver.Value{redirectQuery: {{"https://elsewhere.example", int64(301)}}, wwwRedirectQuery: {{"to_www"}}},
			[]string{"server_name example.com www.example.com;"}, []string{"redirected to the canonical hostname"}},
		{"IP rules", map[string][][]driver.Value{ipAccessQuery: {{int64(9), "deny"}}, ipRuleListQuery: {{"203.0.113.7"}}},
			[]string{"    deny 203.0.113.7;\n"}, nil},
		{"maintenance mode", map[string][][]driver.Value{maintenanceQuery: {{int64(9), int64(1)}}, "FROM domain_maintenance_ips": {}},
			[]string{"# ---- Maintenance mode, managed by Servika ----"}, nil},
		{"a rate limit", map[string][][]driver.Value{protectionQuery: {{int64(9), "off", int64(30)}}},
			[]string{"limit_req zone=servika_rl_30 burst=60 nodelay;"}, nil},
		{"hotlink protection", map[string][][]driver.Value{hotlinkQuery: {{int64(1), "cdn.example.net"}}},
			[]string{"valid_referers none blocked example.com *.example.com cdn.example.net;"}, nil},
		{"a published application", map[string][][]driver.Value{appDomainQuery: {{int64(9)}}, appsQuery: {{"api", "/api/", int64(30001)}}},
			[]string{"location ^~ /api/ {", "proxy_pass http://127.0.0.1:30001;"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			withScript(t, renderScript(tc.rows))

			body, err := f.render(t, exampleVhost())

			if err != nil {
				t.Fatalf("renderAndReload() error = %v", err)
			}
			assertVhostCarries(t, body, tc.want, tc.absent)
		})
	}
}

// The map must exist before a vhost names $connection_upgrade, and an application
// mounted at / takes the site's own location / away.
func TestAnApplicationAtTheRootGetsTheUpgradeMapAndTheRootLocation(t *testing.T) {
	f := withRenderSequence(t)
	withScript(t, renderScript(map[string][][]driver.Value{appDomainQuery: {{int64(9)}}, appsQuery: {{"api", "/", int64(30001)}}}))

	body, err := f.render(t, exampleVhost())

	if err != nil {
		t.Fatalf("renderAndReload() error = %v", err)
	}
	assertVhostCarries(t, body, []string{"location ^~ / {"}, []string{"location / { try_files"})
	if data, readErr := os.ReadFile(f.upgradeMap); readErr != nil || string(data) != upgradeMapBody() {
		t.Errorf("the upgrade map holds %q, %v; want the managed body", data, readErr)
	}
	if !f.commands.ran("restorecon", f.upgradeMap) {
		t.Errorf("the upgrade map was not relabelled, ran %q", f.commands.argvs())
	}
}

func TestACustomVhostIsWrittenAsItWasStored(t *testing.T) {
	f := withRenderSequence(t)
	withScript(t, renderScript(map[string][][]driver.Value{redirectQuery: {{"https://elsewhere.example", int64(302)}}}))
	opts := exampleVhost()
	opts.CustomVhostContent = "\n  server { listen 80; }  \n"

	body, err := f.render(t, opts)

	if err != nil || body != "server { listen 80; }\n" {
		t.Fatalf("renderAndReload() error = %v, vhost = %q", err, body)
	}
}

func TestASuspendedDomainIsNotServedFromItsCustomVhost(t *testing.T) {
	f := withRenderSequence(t)
	opts := exampleVhost()
	opts.Suspended = true
	opts.CustomVhostContent = "server { listen 80; }"

	body, err := f.render(t, opts)

	if err != nil {
		t.Fatalf("renderAndReload() error = %v", err)
	}
	assertVhostCarries(t, body, []string{"# example.com suspended by Servika"}, []string{"server { listen 80; }"})
}

func TestWebmailAndMailClientConfigurationFollowTheCertificate(t *testing.T) {
	mailNames := []string{"example.com", "www.example.com", "autoconfig.example.com", "autodiscover.example.com"}
	cases := []struct {
		name   string
		names  []string
		want   []string
		absent []string
	}{
		{"a certificate naming the discovery hosts", mailNames,
			[]string{"location ^~ /webmail/ {", "location = /.well-known/autoconfig/mail/config-v1.1.xml {",
				"server_name autoconfig.example.com autodiscover.example.com;"},
			[]string{"location = /.well-known/mta-sts.txt"}},
		{"a certificate without them keeps webmail only", []string{"example.com", "www.example.com"},
			[]string{"location ^~ /webmail/ {"}, []string{"server_name autoconfig.example.com"}},
		{"no certificate carries neither", nil,
			nil, []string{"location ^~ /webmail/", "config-v1.1.xml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			if err := os.MkdirAll(webmailInstallRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			opts := exampleVhost()
			if tc.names != nil {
				opts.CertPath, opts.KeyPath = writeSANCertificate(t, tc.names...)
			}

			body, err := f.render(t, opts)

			if err != nil {
				t.Fatalf("renderAndReload() error = %v", err)
			}
			assertVhostCarries(t, body, tc.want, tc.absent)
		})
	}
}

// A canonical redirect is emitted over TLS only when the certificate names the
// host it sends visitors to.
func TestACanonicalRedirectFollowsWhatTheCertificateNames(t *testing.T) {
	cases := []struct {
		name   string
		names  []string
		want   []string
		absent []string
	}{
		{"a certificate naming www", []string{"example.com", "www.example.com"},
			[]string{"return 301 https://www.example.com$request_uri;"}, nil},
		{"a certificate without www", []string{"example.com"},
			[]string{"server_name example.com www.example.com;"}, []string{"redirected to the canonical hostname"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			opts := exampleVhost()
			opts.WWWRedirect = "to_www"
			opts.CertPath, opts.KeyPath = writeSANCertificate(t, tc.names...)

			body, err := f.render(t, opts)

			if err != nil {
				t.Fatalf("renderAndReload() error = %v", err)
			}
			assertVhostCarries(t, body, tc.want, tc.absent)
		})
	}
}

// assertValidationRolledBack checks that the shared file holds what it held
// before the render and that nginx was not reloaded.
func assertValidationRolledBack(t *testing.T, f *renderFixture, sharedBefore string) {
	t.Helper()
	if data, err := os.ReadFile(protectionConfPath); err != nil || string(data) != sharedBefore {
		t.Errorf("the shared file holds %q, %v; want %q back", data, err, sharedBefore)
	}
	if f.commands.ran("systemctl", "reload", "nginx") {
		t.Error("nginx was reloaded after its validation failed")
	}
}

func TestAFailedValidationPutsTheVhostAndTheSharedFileBack(t *testing.T) {
	cases := []struct {
		name     string
		existed  bool
		previous string
	}{
		{"a vhost that existed is restored", true, "# the previous vhost\n"},
		{"a vhost that did not exist is removed", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			f.failing, f.output = [][]string{{"nginx", "-t"}}, "nginx: [emerg] unknown directive"
			writeFixture(t, protectionConfPath, "# the previous shared file\n")
			if tc.existed {
				writeFixture(t, f.vhostPath(), tc.previous)
			}

			body, err := f.render(t, exampleVhost())

			if err == nil || !strings.Contains(err.Error(), "nginx -t failed: nginx: [emerg] unknown directive") {
				t.Fatalf("renderAndReload() error = %v, want the validation failure", err)
			}
			if _, statErr := os.Stat(f.vhostPath()); (statErr == nil) != tc.existed || body != tc.previous {
				t.Errorf("vhost = %q (present: %v), want %q (present: %v)", body, statErr == nil, tc.previous, tc.existed)
			}
			assertValidationRolledBack(t, f, "# the previous shared file\n")
		})
	}
}

// The country include is written before the shared file that loads it. When the
// shared file then cannot be written, the include goes back to what it held, or
// the next unrelated reload would parse ranges no saved rule asked for.
func TestASharedFileThatCannotBeWrittenPutsTheCountryIncludeBack(t *testing.T) {
	f := withRenderSequence(t)
	geoDir := filepath.Join(t.TempDir(), "geoip")
	t.Setenv("SERVIKA_GEOIP_DIR", geoDir)
	if err := os.MkdirAll(geoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(geoDir, "networks-v4.csv"), "203.0.113.0/24,TR\n")
	writeFixture(t, filepath.Join(geoDir, "nginx-geo.conf"), "# the previous country include\n")
	withScript(t, renderScript(map[string][][]driver.Value{domainGeoQuery: {{"TR"}}}))
	protectionConfPath = filepath.Join(f.confDir, "missing", "00-servika-geo.conf")

	_, err := f.render(t, exampleVhost())

	if err == nil || !strings.Contains(err.Error(), "write 00-servika-geo.conf") {
		t.Fatalf("renderAndReload() error = %v, want the shared file failure", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(geoDir, "nginx-geo.conf")); readErr != nil || string(data) != "# the previous country include\n" {
		t.Errorf("the country include holds %q, %v; want the previous content back", data, readErr)
	}
}

func TestARenderStopsAtTheStepThatFails(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *renderFixture, opts *VhostOpts)
		reason  string
	}{
		{"the vhost cannot be written", func(_ *testing.T, f *renderFixture, opts *VhostOpts) {
			opts.ConfigPath = filepath.Join(f.confDir, "missing", "dom_c_example_com.conf")
		}, "write vhost"},
		{"the cache directory cannot be created", func(t *testing.T, _ *renderFixture, _ *VhostOpts) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			writeFixture(t, blocker, "not a directory")
			t.Setenv("SERVIKA_NGINX_CACHE_DIR", filepath.Join(blocker, "cache"))
		}, "create cache directory"},
		{"the upgrade map cannot be written", func(t *testing.T, f *renderFixture, _ *VhostOpts) {
			withScript(t, renderScript(map[string][][]driver.Value{appDomainQuery: {{int64(9)}}, appsQuery: {{"api", "/api/", int64(30001)}}}))
			t.Setenv("SERVIKA_NGINX_UPGRADE_MAP_CONF", filepath.Join(f.confDir, "missing", "map.conf"))
		}, "write the upgrade map"},
		{"the shared protection file cannot be written", func(_ *testing.T, f *renderFixture, _ *VhostOpts) {
			protectionConfPath = filepath.Join(f.confDir, "missing", "00-servika-geo.conf")
		}, "write 00-servika-geo.conf"},
		{"nginx cannot be reloaded", func(_ *testing.T, f *renderFixture, _ *VhostOpts) {
			f.failing, f.output = [][]string{{"systemctl", "reload", "nginx"}}, "Job for nginx.service failed"
		}, "nginx reload: Job for nginx.service failed"},
		{"httpd rejects the Apache vhost", func(_ *testing.T, f *renderFixture, opts *VhostOpts) {
			opts.Backend = "apache"
			f.failing, f.output = [][]string{{"httpd", "-t"}}, "Syntax error"
		}, "httpd -t failed: Syntax error"},
		{"httpd cannot be reloaded", func(_ *testing.T, f *renderFixture, opts *VhostOpts) {
			opts.Backend = "apache"
			f.failing, f.output = [][]string{{"systemctl", "reload-or-restart", "httpd"}}, "Job for httpd.service failed"
		}, "httpd reload: Job for httpd.service failed"},
		{"a leftover Apache vhost cannot be removed", func(t *testing.T, f *renderFixture, _ *VhostOpts) {
			// A directory that is not empty stands in for a file os.Remove refuses.
			if err := os.MkdirAll(filepath.Join(f.apacheVhost(), "not-empty"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "delete Apache vhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			opts := exampleVhost()
			tc.prepare(t, f, &opts)

			_, err := f.render(t, opts)

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("renderAndReload() error = %v, want one naming %q", err, tc.reason)
			}
		})
	}
}

// Every failure AFTER the vhost is written has to put the previous vhost back,
// not just the validation failure. The vhost on disk names the very thing the
// failed step could not write: $connection_upgrade for an application, a
// servika_rl_N zone for a rate limit. nginx keeps serving its loaded
// configuration, so the file sits there unvalidated and fails `nginx -t` for the
// WHOLE server, which makes every later unrelated render roll back its own valid
// change until an operator finds the file.
func TestAPreparationFailureAfterTheWritePutsTheVhostBack(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *renderFixture)
		reason  string
	}{
		{"the cache directory cannot be created", func(t *testing.T, _ *renderFixture) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			writeFixture(t, blocker, "not a directory")
			t.Setenv("SERVIKA_NGINX_CACHE_DIR", filepath.Join(blocker, "cache"))
		}, "create cache directory"},
		{"the upgrade map cannot be written", func(t *testing.T, f *renderFixture) {
			withScript(t, renderScript(map[string][][]driver.Value{appDomainQuery: {{int64(9)}}, appsQuery: {{"api", "/api/", int64(30001)}}}))
			t.Setenv("SERVIKA_NGINX_UPGRADE_MAP_CONF", filepath.Join(f.confDir, "missing", "map.conf"))
		}, "write the upgrade map"},
		{"the shared protection file cannot be written", func(_ *testing.T, f *renderFixture) {
			protectionConfPath = filepath.Join(f.confDir, "missing", "00-servika-geo.conf")
		}, "write 00-servika-geo.conf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			writeFixture(t, f.vhostPath(), "# the previous vhost\n")
			tc.prepare(t, f)

			body, err := f.render(t, exampleVhost())

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("renderAndReload() error = %v, want one naming %q", err, tc.reason)
			}
			if body != "# the previous vhost\n" {
				t.Errorf("the vhost holds %q, want the previous one back", body)
			}
			if f.commands.ran("nginx", "-t") {
				t.Error("the tree was validated after the preparation failed")
			}
		})
	}
}

// A render that created the vhost leaves nothing behind either: the file it
// wrote was never validated.
func TestAPreparationFailureRemovesAVhostItCreated(t *testing.T) {
	f := withRenderSequence(t)
	protectionConfPath = filepath.Join(f.confDir, "missing", "00-servika-geo.conf")

	_, err := f.render(t, exampleVhost())

	if err == nil || !strings.Contains(err.Error(), "write 00-servika-geo.conf") {
		t.Fatalf("renderAndReload() error = %v, want the shared file failure", err)
	}
	if _, statErr := os.Stat(f.vhostPath()); statErr == nil {
		t.Error("the unvalidated vhost was left in conf.d")
	}
}

func TestTheApacheVhostFollowsTheBackend(t *testing.T) {
	cases := []struct {
		name      string
		backend   string
		suspended bool
		leftOver  bool
		wantFile  bool
		wantHTTPD bool
	}{
		{"the Apache backend writes its vhost and reloads httpd", "apache", false, false, true, true},
		{"leaving Apache removes its vhost and reloads httpd", "php-fpm", false, true, false, true},
		{"a suspended Apache domain loses its Apache vhost", "apache", true, true, false, true},
		{"no Apache vhost and no Apache backend touches nothing", "", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			if tc.leftOver {
				writeFixture(t, f.apacheVhost(), "<VirtualHost 127.0.0.1:10080>\n")
			}
			opts := exampleVhost()
			opts.Backend, opts.Suspended = tc.backend, tc.suspended

			if _, err := f.render(t, opts); err != nil {
				t.Fatalf("renderAndReload() error = %v", err)
			}

			if _, statErr := os.Stat(f.apacheVhost()); (statErr == nil) != tc.wantFile {
				t.Errorf("Apache vhost present = %v, want %v", statErr == nil, tc.wantFile)
			}
			if f.commands.ran("httpd", "-t") != tc.wantHTTPD || f.commands.ran("systemctl", "reload-or-restart", "httpd") != tc.wantHTTPD {
				t.Errorf("httpd was validated and reloaded = %v, want %v; ran %q", !tc.wantHTTPD, tc.wantHTTPD, f.commands.argvs())
			}
		})
	}
}
