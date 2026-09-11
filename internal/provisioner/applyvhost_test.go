package provisioner

import (
	"database/sql/driver"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"servika/internal/phpdefaults"
)

// applyVhostForDomain turns a domain row, its nginx and PHP settings and its
// protected directories into the options the vhost is rendered from. These tests
// capture those options instead of rendering, so each stored state is pinned to
// the vhost it produces.

const (
	domainDetailsQuery = "custom_vhost_content"
	nginxSettingsQuery = "FROM nginx_settings"
	phpSettingsQuery   = "FROM php_settings"
	protectedDirsQuery = "FROM protected_directories"
)

type renderCapture struct {
	opts  []VhostOpts
	users []string
	err   error
}

// withRenderCapture records every render an SSL or vhost path asks for instead
// of writing a vhost and reloading nginx.
func withRenderCapture(t *testing.T) *renderCapture {
	t.Helper()
	capture := &renderCapture{}
	previous := renderDomainVhost
	renderDomainVhost = func(opts VhostOpts, systemUser string) error {
		capture.opts = append(capture.opts, opts)
		capture.users = append(capture.users, systemUser)
		return capture.err
	}
	t.Cleanup(func() { renderDomainVhost = previous })
	return capture
}

// withTenantUnits points the tenant unit directory at an empty temporary one, so
// no tenant runs its own PHP-FPM master unless the test installs a unit.
func withTenantUnits(t *testing.T) string {
	t.Helper()
	previous := tenantUnitDir
	tenantUnitDir = t.TempDir()
	t.Cleanup(func() { tenantUnitDir = previous })
	return tenantUnitDir
}

// domainDetails is the domain row in SELECT order.
func domainDetails(name, user, cert, key, source, backend, webRoot string, suspended, customEnabled int64, custom string, parent driver.Value) [][]driver.Value {
	return [][]driver.Value{{name, user, cert, key, source, backend, webRoot, suspended, customEnabled, custom, parent}}
}

// vhostScript answers the four reads applyVhostForDomain makes, with no nginx or
// PHP settings row and nothing protected unless the test adds them.
func vhostScript(details [][]driver.Value) *sqlScript {
	return &sqlScript{
		rows: map[string][][]driver.Value{
			domainDetailsQuery: details,
			nginxSettingsQuery: {},
			phpSettingsQuery:   {},
			protectedDirsQuery: {},
		},
		fail: map[string]error{},
	}
}

// panelDefaultVhost is what a domain with no settings rows renders as.
func panelDefaultVhost(webRoot string) VhostOpts {
	return VhostOpts{
		ConfigPath:      nginxConfDir + "/dom_c_example_com.conf",
		DomainName:      "example.com",
		WebRoot:         webRoot,
		PHPSocket:       "/run/php-fpm/c_example_com.sock",
		PHPVersion:      "8.3",
		Backend:         "php-fpm",
		HdrXContentType: true, HdrXXSS: true, HdrReferrer: true,
		HdrPermissions: true, HdrCSPUpgrade: true, HdrHSTS: true,
		HSTSMaxAge: 31536000, HSTSSubdomains: true,
		FastCgiCacheMinutes: 60,
		BrowserCache:        true,
		BrowserCacheDays:    30,
		MaxExecutionTime:    phpdefaults.MaxExecutionTime,
	}
}

func renderExampleVhost(t *testing.T, script *sqlScript, certOverride, keyOverride *string) (*renderCapture, error) {
	t.Helper()
	capture := withRenderCapture(t)
	db := withScript(t, script)
	err := applyVhostForDomain(db, 7, "/run/php-fpm/c_example_com.sock", "8.3", certOverride, keyOverride)
	return capture, err
}

func TestAVhostWithoutSettingsRowsRendersThePanelDefaults(t *testing.T) {
	root := withTenantHome(t)
	withTenantUnits(t)
	script := vhostScript(domainDetails("example.com", "c_example_com", "/pki/example.com.crt", "/pki/example.com.key",
		"letsencrypt", "php-fpm", "", 0, 0, "", nil))

	capture, err := renderExampleVhost(t, script, nil, nil)

	if err != nil {
		t.Fatalf("applyVhostForDomain() error = %v", err)
	}
	want := panelDefaultVhost(filepath.Join(root, "c_example_com", "public_html"))
	want.CertPath, want.KeyPath, want.SSLSource = "/pki/example.com.crt", "/pki/example.com.key", "letsencrypt"
	if len(capture.opts) != 1 || !reflect.DeepEqual(capture.opts[0], want) {
		t.Fatalf("rendered %+v\nwant %+v", capture.opts, want)
	}
	if capture.users[0] != "c_example_com" {
		t.Errorf("rendered for %q, want c_example_com", capture.users[0])
	}
}

func TestStoredNginxAndPHPSettingsReachTheVhost(t *testing.T) {
	root := withTenantHome(t)
	withTenantUnits(t)
	script := vhostScript(domainDetails("example.com", "c_example_com", "", "", "", "php-fpm", "", 0, 0, "", nil))
	script.rows[nginxSettingsQuery] = [][]driver.Value{{
		int64(0), int64(1), int64(0), int64(1), int64(0), int64(1), int64(600), int64(0), int64(1),
		"expires 7d;", int64(1), int64(15), int64(0), int64(3), "256m",
	}}
	script.rows[phpSettingsQuery] = [][]driver.Value{{int64(120)}}
	script.rows[protectedDirsQuery] = [][]driver.Value{{"/", "/etc/nginx/htpasswd/c_example_com_root"}}

	capture, err := renderExampleVhost(t, script, nil, nil)

	if err != nil {
		t.Fatalf("applyVhostForDomain() error = %v", err)
	}
	want := panelDefaultVhost(filepath.Join(root, "c_example_com", "public_html"))
	want.HdrXContentType, want.HdrXXSS, want.HdrReferrer = false, true, false
	want.HdrPermissions, want.HdrCSPUpgrade, want.HdrHSTS = true, false, true
	want.HSTSMaxAge, want.HSTSSubdomains, want.HSTSPreload = 600, false, true
	want.FastCgiCache, want.FastCgiCacheMinutes = true, 15
	want.BrowserCache, want.BrowserCacheDays = false, 3
	want.ClientMaxBody = "256m"
	want.MaxExecutionTime = 120
	want.ExtraDirectives = "expires 7d;\n" +
		"    auth_basic \"Authentication Required\";\n" +
		"    auth_basic_user_file /etc/nginx/htpasswd/c_example_com_root;\n"
	if len(capture.opts) != 1 || !reflect.DeepEqual(capture.opts[0], want) {
		t.Fatalf("rendered %+v\nwant %+v", capture.opts, want)
	}
}

// Without an nginx settings row the protected blocks are the whole of the extra
// directives, with no separator in front of them, and a zero execution limit
// keeps the panel default.
func TestProtectedDirectoriesAloneAndAZeroLimitRenderAsDefaults(t *testing.T) {
	root := withTenantHome(t)
	withTenantUnits(t)
	script := vhostScript(domainDetails("example.com", "c_example_com", "", "", "", "php-fpm", "", 0, 0, "", nil))
	script.rows[phpSettingsQuery] = [][]driver.Value{{int64(0)}}
	script.rows[protectedDirsQuery] = [][]driver.Value{{"/", "/etc/nginx/htpasswd/c_example_com_root"}}

	capture, err := renderExampleVhost(t, script, nil, nil)

	if err != nil {
		t.Fatalf("applyVhostForDomain() error = %v", err)
	}
	want := panelDefaultVhost(filepath.Join(root, "c_example_com", "public_html"))
	want.ExtraDirectives = "    auth_basic \"Authentication Required\";\n" +
		"    auth_basic_user_file /etc/nginx/htpasswd/c_example_com_root;\n"
	if len(capture.opts) != 1 || !reflect.DeepEqual(capture.opts[0], want) {
		t.Fatalf("rendered %+v\nwant %+v", capture.opts, want)
	}
}

func TestTheVhostFollowsTheDomainsShapeAndItsOverrides(t *testing.T) {
	overrideCert, overrideKey := "/override.crt", "/override.key"
	stored := func(name string, suspended, customEnabled int64, custom string, parent driver.Value) [][]driver.Value {
		return domainDetails(name, "c_example_com", "/stored.crt", "/stored.key", "letsencrypt", "php-fpm", "", suspended, customEnabled, custom, parent)
	}
	certificate := func(got VhostOpts) []any { return []any{got.CertPath, got.KeyPath} }
	customVhost := func(got VhostOpts) []any { return []any{got.CustomVhostContent} }
	// want is evaluated inside the subtest, after the tenant home is redirected,
	// because the addon paths are derived from it.
	cases := []struct {
		name                      string
		details                   [][]driver.Value
		certOverride, keyOverride *string
		ownMaster                 bool
		field                     func(VhostOpts) []any
		want                      func() []any
	}{
		{"both certificate overrides replace the stored paths", stored("example.com", 0, 0, "", nil), &overrideCert, &overrideKey, false,
			certificate, func() []any { return []any{overrideCert, overrideKey} }},
		{"a single override is ignored", stored("example.com", 0, 0, "", nil), &overrideCert, nil, false,
			certificate, func() []any { return []any{"/stored.crt", "/stored.key"} }},
		{"a tenant with its own master is served from its socket", stored("example.com", 0, 0, "", nil), nil, nil, true,
			func(got VhostOpts) []any { return []any{got.PHPSocket} },
			func() []any { return []any{tenantSocket("c_example_com")} }},
		{"an addon domain renders into its own file and web root", stored("addon.example", 0, 0, "", int64(3)), nil, nil, false,
			func(got VhostOpts) []any { return []any{got.ConfigPath, got.WebRoot} },
			func() []any {
				return []any{addonVhostConfigPath("c_example_com", "addon.example"), AddonWebRoot("c_example_com", "addon.example")}
			}},
		{"an enabled custom vhost is carried", stored("example.com", 0, 1, "server { }", nil), nil, nil, false,
			customVhost, func() []any { return []any{"server { }"} }},
		{"a disabled custom vhost is not", stored("example.com", 0, 0, "server { }", nil), nil, nil, false,
			customVhost, func() []any { return []any{""} }},
		{"a suspended domain renders suspended", stored("example.com", 1, 0, "", nil), nil, nil, false,
			func(got VhostOpts) []any { return []any{got.Suspended} }, func() []any { return []any{true} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTenantHome(t)
			units := withTenantUnits(t)
			if tc.ownMaster {
				writeFixture(t, filepath.Join(units, tenantUnitName("c_example_com")), "[Service]\n")
			}

			capture, err := renderExampleVhost(t, vhostScript(tc.details), tc.certOverride, tc.keyOverride)

			if err != nil || len(capture.opts) != 1 {
				t.Fatalf("applyVhostForDomain() error = %v, renders = %d", err, len(capture.opts))
			}
			if got, want := tc.field(capture.opts[0]), tc.want(); !reflect.DeepEqual(got, want) {
				t.Errorf("rendered %v, want %v", got, want)
			}
		})
	}
}

func TestAnUnreadableDomainIsNotRendered(t *testing.T) {
	withTenantHome(t)
	withTenantUnits(t)
	script := &sqlScript{fail: map[string]error{domainDetailsQuery: errors.New(lostConnectionTo)}}

	capture, err := renderExampleVhost(t, script, nil, nil)

	if err == nil || !strings.Contains(err.Error(), "read domain details") {
		t.Fatalf("applyVhostForDomain() error = %v, want the domain read to be reported", err)
	}
	if len(capture.opts) != 0 {
		t.Errorf("an unreadable domain was rendered: %+v", capture.opts)
	}
}

func TestARenderFailureIsReturned(t *testing.T) {
	withTenantHome(t)
	withTenantUnits(t)
	capture := withRenderCapture(t)
	capture.err = errors.New("nginx rejected the configuration")
	db := withScript(t, vhostScript(domainDetails("example.com", "c_example_com", "", "", "", "php-fpm", "", 0, 0, "", nil)))

	err := applyVhostForDomain(db, 7, "/run/php-fpm/c_example_com.sock", "8.3", nil, nil)

	if !errors.Is(err, capture.err) {
		t.Fatalf("applyVhostForDomain() error = %v, want the render's error", err)
	}
}
