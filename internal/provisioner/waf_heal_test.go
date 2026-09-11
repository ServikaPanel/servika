package provisioner

import (
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// HealWAFOnStartup refreshes the per-domain ModSecurity configuration of every
// active tenant whose WAF is on, and only when the module is actually loaded; a
// render would otherwise name a directive nginx cannot parse. These tests pin
// when a configuration is written and when the heal writes nothing.

const wafTenantsQuery = "SELECT DISTINCT system_user FROM domains WHERE COALESCE(suspended,0)=0"

type wafHealFixture struct {
	domains   string
	module    string
	nginxConf string
	script    *sqlScript
}

func withWAFHeal(t *testing.T) *wafHealFixture {
	t.Helper()
	root := t.TempDir()
	f := &wafHealFixture{
		domains:   filepath.Join(root, "modsec", "domains"),
		module:    filepath.Join(root, "ngx_http_modsecurity_module.so"),
		nginxConf: filepath.Join(root, "nginx.conf"),
		script: &sqlScript{
			rows: map[string][][]driver.Value{
				wafTenantsQuery: {{"c_example_com"}},
				wafQuery:        wafRow(nil, nil, nil, 1, "on", 2),
			},
			fail: map[string]error{},
		},
	}
	setForTest(t, &wafModsecDir, filepath.Join(root, "modsec"))
	setForTest(t, &wafDomainsDir, f.domains)
	setForTest(t, &wafModulePath, f.module)
	setForTest(t, &wafNginxConf, f.nginxConf)
	withScript(t, f.script)
	return f
}

func (f *wafHealFixture) loadModule(t *testing.T) {
	t.Helper()
	plantFile(t, f.module)
	writeFixture(t, f.nginxConf, "load_module modules/ngx_http_modsecurity_module.so;\n")
}

func (f *wafHealFixture) domainConf(user string) string {
	return filepath.Join(f.domains, user+".conf")
}

func TestAnActiveTenantsWAFConfigurationIsRefreshedWhenTheModuleIsLoaded(t *testing.T) {
	f := withWAFHeal(t)
	f.loadModule(t)

	HealWAFOnStartup()

	conf := readString(t, f.domainConf("c_example_com"))
	for _, want := range []string{"SecRuleEngine On", "setvar:tx.blocking_paranoia_level=2", "Include " + filepath.Join(f.domains, "c_example_com.custom.conf")} {
		if !strings.Contains(conf, want) {
			t.Errorf("the configuration does not carry %q:\n%s", want, conf)
		}
	}
	assertPathsKept(t, filepath.Join(f.domains, "c_example_com.custom.conf"))
}

func TestNoWAFConfigurationIsWrittenForATenantThatCannotUseIt(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *wafHealFixture)
	}{
		{"the module file is missing", func(t *testing.T, f *wafHealFixture) {
			writeFixture(t, f.nginxConf, "load_module modules/ngx_http_modsecurity_module.so;\n")
		}},
		{"nginx.conf is missing", func(t *testing.T, f *wafHealFixture) { plantFile(t, f.module) }},
		{"nginx.conf does not load the module", func(t *testing.T, f *wafHealFixture) {
			plantFile(t, f.module)
			writeFixture(t, f.nginxConf, "events {}\n")
		}},
		{"the tenant's WAF is off", func(t *testing.T, f *wafHealFixture) {
			f.loadModule(t)
			f.script.rows[wafQuery] = wafRow(int64(0), nil, nil, 1, "on", 2)
		}},
		{"the tenant list cannot be read", func(t *testing.T, f *wafHealFixture) {
			f.loadModule(t)
			f.script.fail[wafTenantsQuery] = errors.New(lostConnectionTo)
		}},
		{"the tenant row cannot be read", func(t *testing.T, f *wafHealFixture) {
			f.loadModule(t)
			f.script.rows[wafTenantsQuery] = [][]driver.Value{{nil}}
		}},
		{"the system user is not one a path may be built from", func(t *testing.T, f *wafHealFixture) {
			f.loadModule(t)
			f.script.rows[wafTenantsQuery] = [][]driver.Value{{"c_Example"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withWAFHeal(t)
			tc.prepare(t, f)

			HealWAFOnStartup()

			assertPathsGone(t, f.domainConf("c_example_com"), f.domainConf("c_Example"))
		})
	}
}

// A tenant list cut short still refreshes the tenants read before the error.
func TestAWAFTenantListCutShortStillRefreshesWhatArrived(t *testing.T) {
	f := withWAFHeal(t)
	f.loadModule(t)
	f.script.endWith = map[string]error{wafTenantsQuery: errors.New(lostConnectionTo)}

	HealWAFOnStartup()

	assertPathsKept(t, f.domainConf("c_example_com"))
}

func TestTheWAFHealDoesNothingWithoutADatabase(t *testing.T) {
	f := withWAFHeal(t)
	withoutDatabase(t)

	HealWAFOnStartup()

	assertPathsGone(t, f.domains)
}
