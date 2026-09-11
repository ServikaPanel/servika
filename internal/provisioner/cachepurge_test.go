package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cache key is "$scheme$request_method$host$request_uri" with no separator, so
// the host has to be parsed out rather than searched for.
func TestTheHostIsParsedOutOfTheCacheKey(t *testing.T) {
	tests := []struct {
		key  string
		host string
		ok   bool
	}{
		{key: "httpsGETexample.com/", host: "example.com", ok: true},
		{key: "httpGETexample.com/wp-admin/index.php?a=1", host: "example.com", ok: true},
		{key: "httpsHEADwww.example.com/x", host: "www.example.com", ok: true},
		{key: "httpsPOSTshop.example.com/cart/", host: "shop.example.com", ok: true},
		// Upper case in the key's host is normalised, because the purge set is.
		{key: "httpsGETExample.COM/", host: "example.com", ok: true},
		// Nothing usable: no scheme, no method, no URI.
		{key: "ftpGETexample.com/", ok: false},
		{key: "httpsBREWexample.com/", ok: false},
		{key: "httpsGETexample.com", ok: false},
		{key: "httpsGET/", ok: false},
		{key: "", ok: false},
	}
	for _, tc := range tests {
		host, ok := cacheKeyHost(tc.key)
		if ok != tc.ok {
			t.Errorf("cacheKeyHost(%q) ok = %v, want %v", tc.key, ok, tc.ok)
			continue
		}
		if ok && host != tc.host {
			t.Errorf("cacheKeyHost(%q) = %q, want %q", tc.key, host, tc.host)
		}
	}
}

// "example.com/" is a suffix of "notexample.com/", so a substring match would
// purge a neighbouring tenant's entries. That is the whole defect in miniature.
func TestANeighbourWhoseNameEndsWithOursIsNotOurs(t *testing.T) {
	host, ok := cacheKeyHost("httpsGETnotexample.com/index.php")
	if !ok {
		t.Fatal("the neighbour's key did not parse")
	}
	if host == "example.com" {
		t.Fatal("a neighbour's host was read as ours")
	}
	if !purgeHostSet("example.com")["example.com"] {
		t.Fatal("the purge set does not name the domain itself")
	}
	if purgeHostSet("example.com")[host] {
		t.Fatalf("the purge set claims the neighbour %q", host)
	}
}

// The purge covers exactly what the vhost answers to: the domain and its www
// name, which is the same list ServerNames renders.
func TestThePurgeSetIsTheVhostsOwnNames(t *testing.T) {
	hosts := purgeHostSet("Example.COM ")
	if len(hosts) != 2 || !hosts["example.com"] || !hosts["www.example.com"] {
		t.Fatalf("purgeHostSet() = %v, want the domain and its www name", hosts)
	}
	// A www domain has no second name to cover.
	if hosts := purgeHostSet("www.example.com"); len(hosts) != 1 || !hosts["www.example.com"] {
		t.Fatalf("purgeHostSet() = %v, want only the www name", hosts)
	}
	if hosts := purgeHostSet("  "); len(hosts) != 0 {
		t.Fatalf("purgeHostSet() = %v for a blank name, want nothing", hosts)
	}
}

// nginx writes the key in plain text after its binary header. Without that the
// entry cannot be attributed at all, because the file name is the key's md5.
func TestTheKeyIsReadOutOfTheFileHeader(t *testing.T) {
	head := "\x03\x00\x00\x00binary junk\x00\x00\nKEY: httpsGETexample.com/page\n" +
		"HTTP/1.1 200 OK\r\n"
	key, ok := cacheKeyFromHead(head)
	if !ok || key != "httpsGETexample.com/page" {
		t.Fatalf("cacheKeyFromHead() = %q, %v; want the key line", key, ok)
	}

	if _, ok := cacheKeyFromHead("no key here at all"); ok {
		t.Error("a header with no key line was accepted")
	}
	// A key line cut off by the read bound is a PREFIX of the real key, so
	// accepting it could attribute the entry to the wrong host.
	if _, ok := cacheKeyFromHead("\nKEY: httpsGETexample.com/very-long"); ok {
		t.Error("an unterminated key line was accepted")
	}
}

// writeCacheEntry lays one file down in the zone's two-level hierarchy.
func writeCacheEntry(t *testing.T, root, name, key string) string {
	t.Helper()
	dir := filepath.Join(root, name[len(name)-1:], name[len(name)-3:len(name)-1])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create the cache directory: %v", err)
	}
	path := filepath.Join(dir, name)
	body := "\x03\x00\x00\x00header\x00\nKEY: " + key + "\nHTTP/1.1 200 OK\r\n\r\nbody"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the cache entry: %v", err)
	}
	return path
}

// The end-to-end shape: one tenant's re-render must leave every other tenant's
// cached pages alone. The route that reaches this is CustomerScope, so before
// this any customer could empty the whole server's page cache on demand.
func TestAPurgeLeavesEveryOtherTenantsEntriesAlone(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_NGINX_CACHE_DIR", root)

	ours := writeCacheEntry(t, root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa111", "httpsGETexample.com/")
	oursWWW := writeCacheEntry(t, root, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbb222", "httpGETwww.example.com/x")
	neighbour := writeCacheEntry(t, root, "ccccccccccccccccccccccccccccc333", "httpsGETneighbour.test/")
	lookalike := writeCacheEntry(t, root, "ddddddddddddddddddddddddddddd444", "httpsGETnotexample.com/")
	unreadable := writeCacheEntry(t, root, "eeeeeeeeeeeeeeeeeeeeeeeeeeeee555", "")

	purgeFastCGICache("example.com")

	for _, gone := range []string{ours, oursWWW} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s survived its own domain's purge", filepath.Base(gone))
		}
	}
	for _, kept := range []string{neighbour, lookalike, unreadable} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed by another domain's purge", filepath.Base(kept))
		}
	}
}

// A purge with no domain name removes nothing. Falling back to a directory sweep
// is what the old code did unconditionally.
func TestAPurgeWithNoDomainRemovesNothing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_NGINX_CACHE_DIR", root)

	entry := writeCacheEntry(t, root, "fffffffffffffffffffffffffffff666", "httpsGETexample.com/")

	purgeFastCGICache("")

	if _, err := os.Stat(entry); err != nil {
		t.Fatal("a purge with no domain name emptied the shared zone")
	}
}

// Anything that is not part of the zone's two-level hierarchy is stepped over
// rather than read as a cache entry, and the domain's own entry still goes.
func TestAPurgeStepsOverWhatIsNotACacheEntry(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_NGINX_CACHE_DIR", root)

	ours := writeCacheEntry(t, root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa777", "httpsGETexample.com/")
	topStray := filepath.Join(root, "stray-at-the-top")
	levelOneStray := filepath.Join(filepath.Dir(filepath.Dir(ours)), "stray-at-level-one")
	for _, stray := range []string{topStray, levelOneStray} {
		if err := os.WriteFile(stray, []byte("not a cache entry"), 0o600); err != nil {
			t.Fatalf("write %s: %v", filepath.Base(stray), err)
		}
	}

	purgeFastCGICache("example.com")

	if _, err := os.Stat(ours); err == nil {
		t.Error("the domain's own entry survived its purge")
	}
	for _, stray := range []string{topStray, levelOneStray} {
		if _, err := os.Stat(stray); err != nil {
			t.Errorf("%s was removed by the purge", filepath.Base(stray))
		}
	}
}

// A zone that does not exist, or that is not a directory, is a purge with
// nothing to do: nothing is created and nothing is removed.
func TestAPurgeOfAMissingOrUnreadableZoneDoesNothing(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent")
		t.Setenv("SERVIKA_NGINX_CACHE_DIR", missing)

		purgeFastCGICache("example.com")

		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Errorf("the purge created the zone directory: %v", err)
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		zone := filepath.Join(t.TempDir(), "zone")
		if err := os.WriteFile(zone, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write the zone file: %v", err)
		}
		t.Setenv("SERVIKA_NGINX_CACHE_DIR", zone)

		purgeFastCGICache("example.com")

		if content, err := os.ReadFile(zone); err != nil || string(content) != "not a directory" {
			t.Errorf("the purge touched a zone path that is a file: %q, %v", content, err)
		}
	})
}

// The zone is shared by every tenant, which is why attribution is needed at all.
func TestTheCacheZoneIsSharedByEveryVhost(t *testing.T) {
	body := cacheZoneBody()
	if !strings.Contains(body, "keys_zone="+cacheZoneName) {
		t.Fatalf("the zone is no longer defined under one shared name:\n%s", body)
	}
	if !strings.Contains(body, `fastcgi_cache_key "$scheme$request_method$host$request_uri"`) {
		t.Fatalf("the cache key changed shape; cacheKeyHost parses the old one:\n%s", body)
	}
}
