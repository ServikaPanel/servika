package provisioner

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

// healTLSVhostBlocksOnStartup re-renders only an ordinary TLS vhost that lacks a
// block it is expected to carry. These tests pin which domains reach the render
// for each vhost shape and each expectation, and that one failure does not stop
// the rest.

const domainListQuery = "FROM domains ORDER BY id"

// tlsVhost is a TLS vhost in the ordinary shape carrying the given blocks.
func tlsVhost(blocks ...string) string {
	body := "server {\n    listen 443 ssl;\n    " + normalVhostMarker + "\n"
	for _, block := range blocks {
		body += "    " + block + "\n"
	}
	return body + "}\n"
}

type blockRepair struct {
	dir      string
	rendered []int64
	fail     map[int64]error
}

// withBlockRepair points the repair at a temporary vhost directory and records
// the domains it re-renders instead of rendering them.
func withBlockRepair(t *testing.T, webmail bool) *blockRepair {
	t.Helper()
	repair := &blockRepair{dir: t.TempDir(), fail: map[int64]error{}}
	previousDir, previousRender, previousWebmail := nginxConfDir, rerenderVhost, webmailInstallRoot
	nginxConfDir = repair.dir
	rerenderVhost = func(_ *sql.DB, id int64) error {
		repair.rendered = append(repair.rendered, id)
		return repair.fail[id]
	}
	webmailInstallRoot = filepath.Join(t.TempDir(), "absent")
	if webmail {
		webmailInstallRoot = t.TempDir()
	}
	t.Cleanup(func() {
		nginxConfDir, rerenderVhost, webmailInstallRoot = previousDir, previousRender, previousWebmail
	})
	return repair
}

func (r *blockRepair) vhost(t *testing.T, systemUser, body string) {
	t.Helper()
	writeFixture(t, filepath.Join(r.dir, "dom_"+systemUser+".conf"), body)
}

// blockRow is one domain in SELECT order.
func blockRow(id driver.Value, systemUser, domainName string, parent driver.Value, cert, key string) []driver.Value {
	return []driver.Value{id, systemUser, domainName, parent, cert, key}
}

func TestOnlyAnOrdinaryTLSVhostMissingABlockIsRerendered(t *testing.T) {
	repair := withBlockRepair(t, false)
	repair.vhost(t, "c_missing", tlsVhost())
	repair.vhost(t, "c_current", tlsVhost(autoconfigMarker))
	repair.vhost(t, "c_plain", "server {\n    listen 80;\n    "+normalVhostMarker+"\n}\n")
	repair.vhost(t, "c_custom", "server {\n    listen 443 ssl;\n}\n")
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{domainListQuery: {
		blockRow(int64(1), "c_missing", "missing.example", nil, "", ""),
		blockRow(int64(2), "c_current", "current.example", nil, "", ""),
		blockRow(int64(3), "c_novhost", "novhost.example", nil, "", ""),
		blockRow(int64(4), "c_plain", "plain.example", nil, "", ""),
		blockRow(int64(5), "c_custom", "custom.example", nil, "", ""),
		// An addon domain's vhost lives under its own name, outside this directory.
		blockRow(int64(6), "c_missing", "addon.example", int64(1), "", ""),
	}}})

	healTLSVhostBlocksOnStartup()

	if !slices.Equal(repair.rendered, []int64{1}) {
		t.Errorf("re-rendered %v, want only the ordinary TLS vhost missing a block", repair.rendered)
	}
}

func TestWebmailIsRequiredOnlyWhereRoundcubeIsInstalled(t *testing.T) {
	cases := []struct {
		name      string
		installed bool
		want      []int64
	}{
		{"not installed", false, nil},
		{"installed", true, []int64{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repair := withBlockRepair(t, tc.installed)
			repair.vhost(t, "c_site", tlsVhost(autoconfigMarker))
			withScript(t, &sqlScript{rows: map[string][][]driver.Value{domainListQuery: {
				blockRow(int64(1), "c_site", "site.example", nil, "", ""),
			}}})

			healTLSVhostBlocksOnStartup()

			if !slices.Equal(repair.rendered, tc.want) {
				t.Errorf("re-rendered %v, want %v", repair.rendered, tc.want)
			}
		})
	}
}

// The discovery block is expected only where the certificate names the discovery
// hostnames; otherwise a domain would be re-rendered on every boot for nothing.
func TestTheDiscoveryBlockIsRequiredOnlyWhereTheCertificateNamesIt(t *testing.T) {
	namedCert, namedKey := writeSANCertificate(t, append([]string{"site.example"}, discoverySANHosts("site.example")...)...)
	apexCert, apexKey := writeSANCertificate(t, "site.example")
	repair := withBlockRepair(t, false)
	repair.vhost(t, "c_named", tlsVhost(autoconfigMarker))
	repair.vhost(t, "c_apex", tlsVhost(autoconfigMarker))
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{domainListQuery: {
		blockRow(int64(1), "c_named", "site.example", nil, namedCert, namedKey),
		blockRow(int64(2), "c_apex", "site.example", nil, apexCert, apexKey),
	}}})

	healTLSVhostBlocksOnStartup()

	if !slices.Equal(repair.rendered, []int64{1}) {
		t.Errorf("re-rendered %v, want only the domain whose certificate names the discovery hosts", repair.rendered)
	}
}

func TestAFailedRerenderDoesNotStopTheRest(t *testing.T) {
	repair := withBlockRepair(t, false)
	repair.fail[1] = errors.New("nginx rejected the configuration")
	repair.vhost(t, "c_first", tlsVhost())
	repair.vhost(t, "c_second", tlsVhost())
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{domainListQuery: {
		blockRow(int64(1), "c_first", "first.example", nil, "", ""),
		blockRow(int64(2), "c_second", "second.example", nil, "", ""),
	}}})

	healTLSVhostBlocksOnStartup()

	if !slices.Equal(repair.rendered, []int64{1, 2}) {
		t.Errorf("re-rendered %v, want both domains attempted", repair.rendered)
	}
}

// A domain list that cannot be read in full re-renders nothing, because a
// partial list would repair some domains and silently skip the rest.
func TestAnUnreadableDomainListRerendersNothing(t *testing.T) {
	cases := map[string]*sqlScript{
		"the query fails": {fail: map[string]error{domainListQuery: errors.New(lostConnectionTo)}},
		"the list is cut short": {
			rows: map[string][][]driver.Value{domainListQuery: {
				blockRow(int64(1), "c_site", "site.example", nil, "", ""),
			}},
			endWith: map[string]error{domainListQuery: errors.New(lostConnectionTo)},
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			repair := withBlockRepair(t, false)
			repair.vhost(t, "c_site", tlsVhost())
			withScript(t, script)

			healTLSVhostBlocksOnStartup()

			if len(repair.rendered) != 0 {
				t.Errorf("re-rendered %v from an unreadable domain list", repair.rendered)
			}
		})
	}
}

func TestAnUnreadableDomainRowIsSkipped(t *testing.T) {
	repair := withBlockRepair(t, false)
	repair.vhost(t, "c_bad", tlsVhost())
	repair.vhost(t, "c_good", tlsVhost())
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{domainListQuery: {
		blockRow(nil, "c_bad", "bad.example", nil, "", ""),
		blockRow(int64(2), "c_good", "good.example", nil, "", ""),
	}}})

	healTLSVhostBlocksOnStartup()

	if !slices.Equal(repair.rendered, []int64{2}) {
		t.Errorf("re-rendered %v, want only the readable domain", repair.rendered)
	}
}

func TestNoDatabaseRepairsNoVhostBlocks(t *testing.T) {
	repair := withBlockRepair(t, false)
	withoutDatabase(t)

	healTLSVhostBlocksOnStartup()

	if len(repair.rendered) != 0 {
		t.Errorf("re-rendered %v without a database", repair.rendered)
	}
}
