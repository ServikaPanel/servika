package domainblock

import "testing"

// The rule this feature exists for: a phisher hides the brand one label down,
// so banning the registered name has to reach what is under it.
func TestASubdomainOfABannedNameIsRefused(t *testing.T) {
	rule := Rule{Domain: "example-bank.com", MatchSubdomains: true}
	for _, host := range []string{
		"example-bank.com",
		"login.example-bank.com",
		"secure.login.example-bank.com",
		"EXAMPLE-BANK.COM",
		"login.example-bank.com.",
	} {
		if !Matches(rule, Normalize(host)) {
			t.Errorf("%q was allowed", host)
		}
	}
}

// The leading dot is the whole reason the suffix test is safe. Without it a
// ban on example-bank.com would also refuse notexample-bank.com, which is a
// different registration and usually somebody else's.
func TestASuffixThatIsNotALabelBoundaryIsAllowed(t *testing.T) {
	rule := Rule{Domain: "example-bank.com", MatchSubdomains: true}
	for _, host := range []string{
		"notexample-bank.com",
		"myexample-bank.com",
		"example-bank.com.evil.test",
		"example-bank.net",
	} {
		if Matches(rule, Normalize(host)) {
			t.Errorf("%q was refused, but it is a different name", host)
		}
	}
}

// match_subdomains is a column so an operator can ban one exact host without
// banning everything under it.
func TestAnExactRuleReachesOnlyThatHost(t *testing.T) {
	rule := Rule{Domain: "example-bank.com", MatchSubdomains: false}
	if !Matches(rule, Normalize("example-bank.com")) {
		t.Error("the exact host was allowed")
	}
	if Matches(rule, Normalize("login.example-bank.com")) {
		t.Error("a subdomain was refused by a rule that does not claim subdomains")
	}
}

// An empty rule matches nothing. A row that somehow carries a blank domain
// would otherwise refuse every hostname on the server.
func TestABlankRuleRefusesNobody(t *testing.T) {
	for _, blank := range []string{"", "   ", "."} {
		if Matches(Rule{Domain: blank, MatchSubdomains: true}, "example.com") {
			t.Errorf("a rule of %q refused a hostname", blank)
		}
	}
}
