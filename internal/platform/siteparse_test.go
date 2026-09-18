package platform

import (
	"strings"
	"testing"
)

// Real appcmd output: one line per object, carriage returns and all.
const siteListing = "SITE \"Default Web Site\" (id:1,bindings:http/*:80:,state:Stopped)\r\n" +
	"SITE \"shop.example.com\" (id:2,bindings:http/*:80:shop.example.com,https/*:443:shop.example.com,state:Started)\r\n" +
	"\r\n"

func TestEverySiteLineIsRead(t *testing.T) {
	sites := parseSiteList(siteListing)
	if len(sites) != 2 {
		t.Fatalf("read %d sites from a two-site listing: %+v", len(sites), sites)
	}
	if sites[1].Name != "shop.example.com" || sites[1].State != "Started" {
		t.Fatalf("the second site read as %+v", sites[1])
	}
}

func TestALineThatDoesNotMatchIsSkippedNotGuessedAt(t *testing.T) {
	noise := "some banner text\r\nSITE \"a.com\" (id:1,bindings:http/*:80:a.com,state:Started)\r\nMicrosoft (R) blah\r\n"
	sites := parseSiteList(noise)
	if len(sites) != 1 || sites[0].Name != "a.com" {
		t.Fatalf("surrounding noise was not skipped: %+v", sites)
	}
}

func TestAnEmptyListingIsAnEmptySliceNotANilPanic(t *testing.T) {
	if sites := parseSiteList(""); len(sites) != 0 {
		t.Fatalf("an empty listing produced %+v", sites)
	}
}

func TestBindingsAreSplitIntoProtocolPortAndHost(t *testing.T) {
	list := parseBindings("http/*:80:shop.example.com,https/*:443:shop.example.com")
	if len(list) != 2 {
		t.Fatalf("read %d bindings: %+v", len(list), list)
	}
	if list[0].Protocol != "http" || list[0].Port != 80 || list[0].Host != "shop.example.com" {
		t.Fatalf("the http binding read as %+v", list[0])
	}
	if list[1].Port != 443 {
		t.Fatalf("the https port read as %d", list[1].Port)
	}
}

func TestSSLComesFromTheProtocolNotFromASeparateFlag(t *testing.T) {
	list := parseBindings("http/*:80:a.com,https/*:443:a.com")
	if list[0].SSL {
		t.Fatal("an http binding was marked as SSL")
	}
	if !list[1].SSL {
		t.Fatal("an https binding was not marked as SSL")
	}
}

func TestABindingWithNoHostIsStillRead(t *testing.T) {
	// The catch-all binding IIS creates for the Default Web Site has no host.
	list := parseBindings("http/*:80:")
	if len(list) != 1 || list[0].Port != 80 || list[0].Host != "" {
		t.Fatalf("a host-less binding read as %+v", list)
	}
}

func TestNoBindingsIsNoListNotAnEmptyEntry(t *testing.T) {
	if list := parseBindings("   "); list != nil {
		t.Fatalf("an empty bindings field produced %+v", list)
	}
}

func TestAMalformedBindingPartIsDropped(t *testing.T) {
	list := parseBindings("http/*:80:a.com,garbage,https/*:443:a.com")
	if len(list) != 2 {
		t.Fatalf("a malformed part was not dropped: %+v", list)
	}
}

func TestOnlyAPoolThisPanelCreatedCanBeActedOn(t *testing.T) {
	// The pattern keeps operations off the system pools AND keeps injection
	// characters out of an appcmd argument.
	for _, pool := range []string{"", "DefaultAppPool", ".NET v4.5", "sv_", "sv_UPPER", "sv_x y", "sv_x;stop", "other_abc123"} {
		if _, err := validatePoolName(pool); err == nil {
			t.Fatalf("pool %q was accepted", pool)
		}
	}
	if _, err := validatePoolName("sv_shop1a2b3c4d"); err != nil {
		t.Fatalf("a pool this panel created was refused: %v", err)
	}
}

func TestAPoolNameThisPanelDerivesPassesItsOwnCheck(t *testing.T) {
	// The two have to agree, or every pool the provider creates is unmanageable.
	if _, err := validatePoolName(systemUserFor("shop.example.com")); err != nil {
		t.Fatalf("the derived account name is not a manageable pool name: %v", err)
	}
}

func TestOnlyThreePoolActionsAreAccepted(t *testing.T) {
	for _, action := range []string{"", "delete", "remove", "START", "start;stop"} {
		if _, err := poolVerb(action); err == nil {
			t.Fatalf("action %q was accepted", action)
		}
	}
	for action, want := range map[string]string{"start": "start", "stop": "stop", "recycle": "recycle"} {
		got, err := poolVerb(action)
		if err != nil || got != want {
			t.Fatalf("action %q mapped to %q (%v)", action, got, err)
		}
	}
}

func TestOnlyAKnownDotNetVersionIsSet(t *testing.T) {
	// A free-form version string reaching appcmd breaks the configuration
	// quietly: the pool accepts it and then fails to start applications.
	for _, version := range []string{"v4", "4.0", "v5.0", "latest", "v4.0;x"} {
		if err := validateRuntime(version); err == nil {
			t.Fatalf("version %q was accepted", version)
		}
	}
	for _, version := range []string{"v4.0", "v2.0", ""} {
		if err := validateRuntime(version); err != nil {
			t.Fatalf("version %q was refused: %v", version, err)
		}
	}
}

func TestAnEmptyRuntimeMeansNoManagedCodeAndIsAllowed(t *testing.T) {
	if !managedRuntimes[""] {
		t.Fatal("no managed code is not an allowed runtime; a static site could not be configured")
	}
}

func TestOnlyHTTPOrHTTPSCanBeBound(t *testing.T) {
	for _, protocol := range []string{"", "ftp", "net.tcp", "HTTP", "http;x"} {
		if _, err := validateBinding(protocol, "80", ""); err == nil {
			t.Fatalf("protocol %q was accepted", protocol)
		}
	}
}

func TestAPortOutsideTheRangeIsRefused(t *testing.T) {
	for _, port := range []string{"", "0", "-1", "65536", "80a", "8 0", "80;x"} {
		if _, err := validateBinding("http", port, ""); err == nil {
			t.Fatalf("port %q was accepted", port)
		}
	}
	if _, err := validateBinding("http", "65535", ""); err != nil {
		t.Fatalf("the highest valid port was refused: %v", err)
	}
}

func TestABindingHostGoesThroughTheSameNameCheckAsADomain(t *testing.T) {
	// The host lands inside an appcmd argument, so it needs the same gate.
	for _, host := range []string{"has space", "quote'x", "semi;colon", "slash/x"} {
		if _, err := validateBinding("http", "80", host); err == nil {
			t.Fatalf("host %q was accepted", host)
		}
	}
	b, err := validateBinding("https", "443", "Shop.Example.COM")
	if err != nil {
		t.Fatalf("a valid host was refused: %v", err)
	}
	if b.Host != "shop.example.com" {
		t.Fatalf("the host was stored as %q rather than lowercased", b.Host)
	}
	if !b.SSL {
		t.Fatal("an https binding was not marked as SSL")
	}
}

func TestAnEmptyBindingHostIsAllowed(t *testing.T) {
	// A binding with no host answers every name on that port, which is a real
	// configuration an operator may want.
	if _, err := validateBinding("http", "80", ""); err != nil {
		t.Fatalf("a host-less binding was refused: %v", err)
	}
}

func TestThePoolLineYieldsItsRuntimeAndState(t *testing.T) {
	line := "APPPOOL \"sv_shop1a2b3c4d\" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)\r\n"
	m := firstMatch(line, poolLinePattern)
	if m == nil {
		t.Fatal("a real pool line did not match")
	}
	if m[2] != "v4.0" || m[4] != "Started" {
		t.Fatalf("the pool line read runtime %q state %q", m[2], m[4])
	}
}

func TestTheApplicationAndDirectoryLinesYieldThePoolAndThePath(t *testing.T) {
	app := firstMatch("APP \"shop.example.com/\" (applicationPool:sv_shop1a2b3c4d)\r\n", appLinePattern)
	if app == nil || app[2] != "sv_shop1a2b3c4d" {
		t.Fatalf("the application line read as %v", app)
	}
	vdir := firstMatch(`VDIR "shop.example.com/" (physicalPath:C:\inetpub\servika\sv_x\httpdocs)`, vdirLinePattern)
	if vdir == nil || !strings.HasSuffix(vdir[2], `httpdocs`) {
		t.Fatalf("the directory line read as %v", vdir)
	}
}

func TestTheSiteIDIsTakenFromTheListingNotGuessed(t *testing.T) {
	// win-acme wants the numeric id, which only the listing carries.
	m := firstMatch(siteListing, siteLinePattern)
	if m == nil || m[2] != "1" {
		t.Fatalf("the first site's id read as %v", m)
	}
}

func TestNoMatchIsReportedAsNoMatch(t *testing.T) {
	if m := firstMatch("nothing here", siteLinePattern); m != nil {
		t.Fatalf("a non-matching output produced %v", m)
	}
}
