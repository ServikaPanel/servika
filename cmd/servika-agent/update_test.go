package main

import "testing"

func TestAWildcardBindIsPolledOverLoopback(t *testing.T) {
	// A wildcard address is not something anything can connect TO. Polling it
	// fails on Windows, and the gate would read a healthy agent as dead and roll
	// back a perfectly good update.
	cases := map[string]string{
		"0.0.0.0:8460":   "https://127.0.0.1:8460/health",
		"[::]:8460":      "https://127.0.0.1:8460/health",
		"127.0.0.1:8460": "https://127.0.0.1:8460/health",
		"10.0.0.5:8460":  "https://10.0.0.5:8460/health",
	}
	for listen, want := range cases {
		if got := localHealthURL(listen); got != want {
			t.Errorf("%q produced %q, expected %q", listen, got, want)
		}
	}
}

func TestAnAddressThatMerelyStartsWithTheWildcardIsLeftAlone(t *testing.T) {
	// "0.0.0.09" is not a wildcard bind, and rewriting it would aim the gate at
	// the wrong host.
	if got := localHealthURL("0.0.0.0.5:8460"); got != "https://0.0.0.0.5:8460/health" {
		t.Fatalf("a non-wildcard address was rewritten to %q", got)
	}
}

func TestTheChannelIsStrippedBeforeTheVersionsAreCompared(t *testing.T) {
	// The `version` command prints "<version> <channel>" while the health answer
	// carries the version alone. Comparing the whole line would fail every
	// update and roll back a working one.
	if got := versionField("1.4.2 stable"); got != "1.4.2" {
		t.Fatalf("the version read %q", got)
	}
	if got := versionField("  1.4.2  "); got != "1.4.2" {
		t.Fatalf("a padded line read %q", got)
	}
	if got := versionField(""); got != "" {
		t.Fatalf("an empty line read %q", got)
	}
}
