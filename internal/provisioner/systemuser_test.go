package provisioner

import (
	"errors"
	"strings"
	"testing"
)

// The premise the whole allocator rests on: two ordinary, different registrable
// domains produce ONE system user name today.
//
// Truncation is not the main reason. slugSan maps every non-alphanumeric
// character to `_`, so the first two pairs below collide without either name
// coming near the 26-character ceiling. If this ever stops being true the
// allocator is not wrong, but the reason it exists has changed and that should
// be visible.
func TestOrdinaryDomainsCollideUnderTheSlugRule(t *testing.T) {
	for _, pair := range [][2]string{
		{"blog.example.com", "blog-example.com"},
		{"my-shop.com", "my.shop.com"},
		{"bestpricesupermarketonline.com", "bestpricesupermarketonlineshop.net"},
	} {
		if got, other := SlugFromDomain(pair[0]), SlugFromDomain(pair[1]); got != other {
			t.Errorf("%q and %q no longer collide: %q vs %q", pair[0], pair[1], got, other)
		}
	}
}

// A name nobody answers to is handed back untouched, so upgrading the panel
// renames no existing tenant.
func TestAFreeNameIsReturnedUnchanged(t *testing.T) {
	free := func(string) (bool, error) { return false, nil }

	for _, domainName := range []string{"example.com", "blog.example.com", "a.co"} {
		got, err := allocateSystemUser(domainName, free)
		if err != nil {
			t.Fatalf("%s: %v", domainName, err)
		}
		if want := SlugFromDomain(domainName); got != want {
			t.Errorf("%s: allocated %q, want the unchanged slug %q", domainName, got, want)
		}
	}
}

// The second of two colliding domains gets its own name. Without this the two
// share a home directory, an FTP account and a database namespace.
func TestTheSecondCollidingDomainGetsItsOwnName(t *testing.T) {
	used := map[string]bool{SlugFromDomain("blog.example.com"): true}
	taken := func(candidate string) (bool, error) { return used[candidate], nil }

	got, err := allocateSystemUser("blog-example.com", taken)
	if err != nil {
		t.Fatal(err)
	}
	if got == SlugFromDomain("blog.example.com") {
		t.Fatalf("allocated the name already in use: %q", got)
	}
	if got != "c_blog_example_com_2" {
		t.Errorf("allocated %q, want c_blog_example_com_2", got)
	}
}

// Every candidate stays inside the length SlugFromDomain has always produced, so
// no downstream path (systemd slice, MariaDB account, socket path) meets a
// longer name than it has ever seen, and none ends in the separator.
func TestNoCandidateGrowsPastTheCeiling(t *testing.T) {
	// A domain whose body is exactly at the ceiling, so every suffix has to cut.
	longName := strings.Repeat("a", 30) + ".com"
	used := map[string]bool{}
	taken := func(candidate string) (bool, error) { return used[candidate], nil }

	for range 20 {
		got, err := allocateSystemUser(longName, taken)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > len("c_")+slugBodyMax {
			t.Errorf("candidate %q is %d characters, over the %d ceiling", got, len(got), len("c_")+slugBodyMax)
		}
		if strings.HasSuffix(got, "_") {
			t.Errorf("candidate %q ends in the separator", got)
		}
		if used[got] {
			t.Fatalf("candidate %q was handed out twice", got)
		}
		used[got] = true
	}
}

// Cutting the body to make room for the suffix can land exactly on a separator.
// The name is then trimmed, so the result never carries a doubled separator that
// reads as though the panel generated a broken name.
//
// The fixture is chosen so the cut really lands there: the sanitised body is
// `<23 a's>_example_com`, so cutting to 24 characters ends on the underscore.
func TestACutThatLandsOnTheSeparatorIsTrimmed(t *testing.T) {
	domainName := strings.Repeat("a", 23) + ".example.com"
	if body := strings.TrimPrefix(SlugFromDomain(domainName), "c_"); body[23] != '_' {
		t.Fatalf("the fixture no longer cuts on a separator: %q", body)
	}
	first := SlugFromDomain(domainName)
	taken := func(candidate string) (bool, error) { return candidate == first, nil }

	got, err := allocateSystemUser(domainName, taken)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "__") {
		t.Errorf("allocated %q, which carries a doubled separator", got)
	}
	if want := "c_" + strings.Repeat("a", 23) + "_2"; got != want {
		t.Errorf("allocated %q, want %q", got, want)
	}
}

// A lookup that fails refuses the allocation. Returning the candidate anyway is
// how two tenants end up on one identity, which is the whole thing this exists
// to prevent.
func TestALookupFailureRefusesRatherThanGuessing(t *testing.T) {
	wanted := errors.New("database is down")
	failing := func(string) (bool, error) { return false, wanted }

	got, err := allocateSystemUser("example.com", failing)
	if !errors.Is(err, wanted) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
	if got != "" {
		t.Errorf("a name was allocated despite the failed lookup: %q", got)
	}
}

// A caller that reports everything as taken gets an error, not an endless loop.
func TestAnExhaustedRangeIsReported(t *testing.T) {
	always := func(string) (bool, error) { return true, nil }

	if _, err := allocateSystemUser("example.com", always); !errors.Is(err, errSystemUserExhausted) {
		t.Errorf("err = %v, want errSystemUserExhausted", err)
	}
}
