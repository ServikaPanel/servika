package performance

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The panel runs ONE Valkey instance for every tenant, isolated by an ACL key
// prefix rather than by instance, and INFO stats has no per-user breakdown.
// keyspace_hits and keyspace_misses therefore describe every site on the server.
// Reporting them as one domain's figures was wrong twice: the customer tuned
// against a number they cannot influence, and every domain owner read the
// aggregate cache traffic of their neighbours on a CustomerScope route.
// The check is on the TYPE, not on an encoded value: the field was omitempty, so
// a nil one produced the same JSON either way and a value-level assertion would
// pass against the defect it exists to catch.
func TestTheSummaryCarriesNoInstanceWideRedisCounters(t *testing.T) {
	for field := range reflect.TypeFor[Summary]().Fields() {
		if field.Name == "RedisCache" || strings.Contains(string(field.Tag), "redis_cache") {
			t.Fatalf("Summary still carries %s (%s)", field.Name, field.Tag)
		}
	}
}

// The per-domain FastCGI figures stay: nginx writes a cache-status log per
// domain, so those counters really are this domain's.
func TestTheSummaryStillCarriesThePerDomainFastCGICounters(t *testing.T) {
	encoded, err := json.Marshal(Summary{DomainName: "example.com", FastCGICache: &CacheStats{Total: 1}})
	if err != nil {
		t.Fatalf("encode the summary: %v", err)
	}
	if !strings.Contains(string(encoded), "fastcgi_cache") {
		t.Fatalf("the per-domain FastCGI figures were dropped too: %s", encoded)
	}
}

// The instance-wide read is gone from the package entirely, rather than left
// behind for a later caller to wire back up.
func TestTheInstanceWideCounterReadIsGone(t *testing.T) {
	source, err := os.ReadFile("performance.go")
	if err != nil {
		t.Fatalf("read the source: %v", err)
	}
	for _, banned := range []string{"keyspace_hits:", "keyspace_misses:", `"INFO", "stats"`} {
		if strings.Contains(string(source), banned) {
			t.Errorf("the package still reads %s, which is an instance-wide counter", banned)
		}
	}
}

// A customer reading the screen must be told why there is no hit rate, rather
// than finding a silent gap where a number used to be.
func TestTheRedisRowExplainsWhyItHasNoHitRate(t *testing.T) {
	source, err := os.ReadFile("performance.go")
	if err != nil {
		t.Fatalf("read the source: %v", err)
	}
	if !strings.Contains(string(source), "Hit rate is not shown") {
		t.Fatal("the Redis row does not say why it reports no hit rate")
	}
}
