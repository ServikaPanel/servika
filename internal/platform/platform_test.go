package platform

import "testing"

// TestTheCapabilityBitsKeepTheirRecordedValues locks the numeric value of every
// capability.
//
// These bits are stored as a number, in the panel database and in what an agent
// reports over the wire. Inserting one line in the middle of the const block
// shifts every value recorded before it, and nothing else in the codebase would
// notice: the old rows would simply start meaning different capabilities. This
// test is what notices.
//
// A NEW capability is appended here with its own value. An EXISTING line is
// never changed.
func TestTheCapabilityBitsKeepTheirRecordedValues(t *testing.T) {
	want := map[string]struct {
		got  Capability
		want Capability
	}{
		"CapSite":            {CapSite, 1},
		"CapSSL":             {CapSSL, 2},
		"CapIsolation":       {CapIsolation, 4},
		"CapQuota":           {CapQuota, 8},
		"CapMail":            {CapMail, 16},
		"CapPHPVersion":      {CapPHPVersion, 32},
		"CapMandatoryAccess": {CapMandatoryAccess, 64},
		"CapEventLog":        {CapEventLog, 128},
		"CapScheduledTask":   {CapScheduledTask, 256},
		"CapMSSQL":           {CapMSSQL, 512},
		"CapFTP":             {CapFTP, 1024},
		"CapDNS":             {CapDNS, 2048},
		"CapDotNet":          {CapDotNet, 4096},
		"CapMySQL":           {CapMySQL, 8192},
		"CapPostgreSQL":      {CapPostgreSQL, 16384},
	}
	for name, c := range want {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d - a line was inserted in the middle of the const block and every stored value has shifted", name, c.got, c.want)
		}
	}
}

func TestHasFindsOnlyTheCapabilitiesInTheSet(t *testing.T) {
	set := CapSite | CapSSL
	if !set.Has(CapSite) || !set.Has(CapSSL) {
		t.Fatal("Has missed a capability that is in the set")
	}
	if set.Has(CapMail) || set.Has(CapMSSQL) {
		t.Fatal("Has reported a capability that is not in the set")
	}
	if Capability(0).Has(CapSite) {
		t.Fatal("an empty set reported a capability")
	}
}

// TestTheActiveProviderNamesItselfAndItsCapabilities keeps the compiled-in
// provider honest: a platform file that forgets to set activeProvider, or
// reports no capability at all, fails here rather than at the first call.
func TestTheActiveProviderNamesItselfAndItsCapabilities(t *testing.T) {
	p := Active()
	if p == nil {
		t.Fatal("this build has no active provider")
	}
	if p.Name() == "" {
		t.Fatal("the active provider has no name")
	}
	if p.Capabilities() == 0 {
		t.Fatal("the active provider reports no capability at all")
	}
	if !p.Capabilities().Has(CapSite) {
		t.Fatal("a provider that cannot open a site is not usable")
	}
}
