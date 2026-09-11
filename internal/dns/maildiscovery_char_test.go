package dns

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"sync"
	"testing"
)

const (
	discoveryCountQuery  = "SELECT COUNT(*) FROM dns_template WHERE name=? AND type=? AND value=?"
	discoveryInsert      = "INSERT INTO dns_template(name,type,value,ttl,priority,sort_order,enabled)"
	discoveryDomainQuery = "SELECT id, domain_name, COALESCE(ipv4,'') FROM domains ORDER BY id"
)

// discoveryScript answers an apply run whose template already holds every mail
// discovery row and whose only domain is example.com.
func discoveryScript() *sqlScript {
	s := newScript()
	s.rows[discoveryCountQuery] = [][]driver.Value{{int64(1)}}
	s.rows[discoveryDomainQuery] = [][]driver.Value{{int64(7), "example.com", "192.0.2.10"}}
	return s
}

// seedCalls records what the apply run asked the seed and the zone writer to do.
type seedCalls struct {
	mu     sync.Mutex
	seeded []int64
	zones  []int64
}

// install replaces the seed and zone writer seams for one test.
func (c *seedCalls) install(t *testing.T, added int, seedErr, zoneErr error) {
	t.Helper()
	setForTest(t, &seedDefaults, func(_ context.Context, _ *sql.DB, domainID int64, _, _ string) (int, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.seeded = append(c.seeded, domainID)
		return added, seedErr
	})
	setForTest(t, &writeZone, func(_ context.Context, _ *sql.DB, domainID int64) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.zones = append(c.zones, domainID)
		return zoneErr
	})
}

func TestApplyMailDiscoveryTopsUpTheTemplateAndEveryZone(t *testing.T) {
	oneDomain := []int64{7}
	cases := []struct {
		name    string
		script  func(s *sqlScript)
		added   int
		seedErr error
		zoneErr error
		want    MailDiscoveryResult
		wantErr error
		seeded  []int64
		zones   []int64
	}{
		{name: "a template that already holds the rows", added: 2,
			want: MailDiscoveryResult{Domains: 1, RecordsAdded: 2}, seeded: oneDomain, zones: oneDomain},
		{name: "a template missing the rows", added: 0,
			script: func(s *sqlScript) { s.rows[discoveryCountQuery] = [][]driver.Value{{int64(0)}} },
			want:   MailDiscoveryResult{TemplateAdded: len(MailDiscoveryRows()), Domains: 1}, seeded: oneDomain},
		{name: "a template row that cannot be counted",
			script:  func(s *sqlScript) { s.fail[discoveryCountQuery] = errScripted },
			wantErr: errScripted},
		{name: "a template row that cannot be added",
			script: func(s *sqlScript) {
				s.rows[discoveryCountQuery] = [][]driver.Value{{int64(0)}}
				s.fail[discoveryInsert] = errScripted
			},
			wantErr: errScripted},
		{name: "domains that cannot be listed",
			script:  func(s *sqlScript) { s.fail[discoveryDomainQuery] = errScripted },
			wantErr: errScripted},
		{name: "a domain row that cannot be read",
			script: func(s *sqlScript) {
				s.rows[discoveryDomainQuery] = [][]driver.Value{{int64(7), nil, "192.0.2.10"}}
			},
			wantErr: errAny},
		{name: "a domain list that ends in an error",
			script:  func(s *sqlScript) { s.endWith[discoveryDomainQuery] = errScripted },
			wantErr: errScripted},
		{name: "a domain whose seed fails", seedErr: errScripted,
			want: MailDiscoveryResult{Domains: 1, Failed: 1}, seeded: oneDomain},
		{name: "a domain that needed nothing", added: 0,
			want: MailDiscoveryResult{Domains: 1}, seeded: oneDomain},
		{name: "a zone that cannot be written", added: 2, zoneErr: errScripted,
			want: MailDiscoveryResult{Domains: 1, RecordsAdded: 2, Failed: 1}, seeded: oneDomain, zones: oneDomain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := discoveryScript()
			if tc.script != nil {
				tc.script(script)
			}
			calls := &seedCalls{}
			calls.install(t, tc.added, tc.seedErr, tc.zoneErr)
			result, err := ApplyMailDiscovery(context.Background(), scriptDB(t, script))
			assertDiscovery(t, result, err, tc.want, tc.wantErr)
			assertCalls(t, calls, tc.seeded, tc.zones)
		})
	}
}

func assertDiscovery(t *testing.T, got MailDiscoveryResult, err error, want MailDiscoveryResult, wantErr error) {
	t.Helper()
	if wantErr == errAny && err == nil {
		t.Error("err = nil, want an error")
	} else if wantErr != errAny && !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if wantErr == nil && !reflect.DeepEqual(got, want) {
		t.Errorf("result = %+v, want %+v", got, want)
	}
}

func assertCalls(t *testing.T, calls *seedCalls, seeded, zones []int64) {
	t.Helper()
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if !reflect.DeepEqual(calls.seeded, seeded) {
		t.Errorf("seeded domains = %v, want %v", calls.seeded, seeded)
	}
	if !reflect.DeepEqual(calls.zones, zones) {
		t.Errorf("zones written = %v, want %v", calls.zones, zones)
	}
}
