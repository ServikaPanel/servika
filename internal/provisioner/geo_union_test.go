package provisioner

import (
	"database/sql/driver"
	"errors"
	"slices"
	"testing"
)

// usedCountriesAndRates is what the shared http-context file declares. A country
// or a rate missing from it makes every vhost that names one fail nginx -t for
// the whole server, so each source is read independently and what one source
// could not deliver does not drop the others.

const (
	domainGeoQuery   = "FROM domain_geo_rules r"
	firewallGeoQuery = "FROM firewall_geo_rules"
	rateLimitQuery   = "SELECT DISTINCT rate_limit_rps"
)

func TestTheSharedGeoFileDeclaresTheUnionInUse(t *testing.T) {
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{
		domainGeoQuery:   {{"tr"}, {" US "}, {"xyz"}, {nil}},
		firewallGeoQuery: {{"de"}, {"TR"}, {"1a"}, {nil}},
		// 7 is not on the ladder, and a repeated rate is declared once.
		rateLimitQuery: {{int64(30)}, {int64(7)}, {int64(120)}, {int64(30)}, {nil}},
	}})

	countries, rates := usedCountriesAndRates()

	if want := []string{"DE", "TR", "US"}; !slices.Equal(countries, want) {
		t.Errorf("countries = %v, want %v", countries, want)
	}
	if want := []int{30, 120}; !slices.Equal(rates, want) {
		t.Errorf("rates = %v, want %v", rates, want)
	}
}

func TestAFailedGeoSourceStillDeclaresTheRest(t *testing.T) {
	withScript(t, &sqlScript{
		fail: map[string]error{domainGeoQuery: errors.New(lostConnectionTo)},
		rows: map[string][][]driver.Value{
			firewallGeoQuery: {{"de"}},
			rateLimitQuery:   {{int64(10)}},
		},
	})

	countries, rates := usedCountriesAndRates()

	if want := []string{"DE"}; !slices.Equal(countries, want) {
		t.Errorf("countries = %v, want %v", countries, want)
	}
	if want := []int{10}; !slices.Equal(rates, want) {
		t.Errorf("rates = %v, want %v", rates, want)
	}
}

// Each result set cut short keeps the values that arrived.
func TestAGeoSourceCutShortKeepsWhatArrived(t *testing.T) {
	cut := errors.New(lostConnectionTo)
	withScript(t, &sqlScript{
		rows: map[string][][]driver.Value{
			domainGeoQuery:   {{"fr"}},
			firewallGeoQuery: {{"it"}},
			rateLimitQuery:   {{int64(5)}},
		},
		endWith: map[string]error{domainGeoQuery: cut, firewallGeoQuery: cut, rateLimitQuery: cut},
	})

	countries, rates := usedCountriesAndRates()

	if want := []string{"FR", "IT"}; !slices.Equal(countries, want) {
		t.Errorf("countries = %v, want %v", countries, want)
	}
	if want := []int{5}; !slices.Equal(rates, want) {
		t.Errorf("rates = %v, want %v", rates, want)
	}
}

func TestEveryGeoSourceFailingDeclaresNothing(t *testing.T) {
	failure := errors.New(lostConnectionTo)
	withScript(t, &sqlScript{fail: map[string]error{
		domainGeoQuery: failure, firewallGeoQuery: failure, rateLimitQuery: failure,
	}})

	countries, rates := usedCountriesAndRates()

	if len(countries) != 0 || len(rates) != 0 {
		t.Errorf("usedCountriesAndRates() = %v, %v; want nothing", countries, rates)
	}
}

func TestNoDatabaseDeclaresNoGeoUnion(t *testing.T) {
	withoutDatabase(t)
	if countries, rates := usedCountriesAndRates(); countries != nil || rates != nil {
		t.Errorf("usedCountriesAndRates() = %v, %v; want nil, nil", countries, rates)
	}
}
