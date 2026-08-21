package antivirus

// The alert a scan writes, and the unit it is written in.

import (
	"os"
	"strings"
	"testing"
)

// Upstream writes one notification per FINDING. A sweep that turns up three
// hundred infected files then writes three hundred rows and buries every other
// alert on the server under them, so the unit here is the SCAN: one row per
// affected domain plus one panel-wide summary.
func TestASweepAlertsOncePerSiteAndNotOncePerFile(t *testing.T) {
	source := read(t, "notify.go")

	// The per-domain loop walks a COUNT map, not the finding list: a loop over
	// findings is exactly the shape being avoided.
	if !strings.Contains(source, "for domainID, count := range perDomain {") {
		t.Error("the sweep alert no longer walks one entry per domain")
	}
	if strings.Contains(source, "range result.Findings") || strings.Contains(source, "range findings") {
		t.Error("the sweep alert walks the findings, so it writes one row per file")
	}
	// And the summary is written once, outside that loop.
	loop := strings.Index(source, "for domainID, count := range perDomain {")
	summary := strings.Index(source, "summary := notifications.Event{")
	if loop < 0 || summary < 0 || summary < loop {
		t.Error("the panel-wide summary is not written after the per-domain loop")
	}
}

// A clean sweep is not an event. Writing one every night makes the bell a
// heartbeat, and a badge that is always lit is a badge nobody reads.
func TestACleanSweepWritesNoAlert(t *testing.T) {
	source := read(t, "notify.go")
	if !strings.Contains(source, "if total == 0 {") {
		t.Error("a sweep that found nothing no longer returns before writing")
	}
}

// A notification is drawn on a screen. The file names come from a tenant's own
// tree, so the alert carries the domain name and numbers; the paths stay on the
// antivirus page, behind the ownership check that page already has.
func TestNoTenantPathReachesAnAlert(t *testing.T) {
	source := read(t, "notify.go")
	for _, leak := range []string{"finding.File", "f.File", ".File)", ".File,"} {
		if strings.Contains(source, leak) {
			t.Errorf("a tenant path reaches the alert text through %q", leak)
		}
	}
}

// The sentence is composed in the READER's language from a key and parameters.
// Stored English cannot be: the text is written when the event happens and read
// later by somebody whose language nothing knew at that moment. The English
// stays as the fallback, so a client that does not know the key still shows
// something.
func TestEveryAlertCarriesAMessageKeyBesideItsEnglish(t *testing.T) {
	source := read(t, "notify.go")
	events := strings.Count(source, "notifications.Event{")
	if events == 0 {
		t.Fatal("no alerts are written at all, so this proves nothing")
	}
	keys := strings.Count(source, "Key:")
	if keys < events {
		t.Errorf("%d alert(s) are written but only %d carry a message key", events, keys)
	}
	if !strings.Contains(source, "Title:") || !strings.Contains(source, "Message:") {
		t.Error("the English fallback is gone, so a client that does not know the key shows nothing")
	}
}

// The scan succeeded and its findings are in the database. Failing the scan
// because the alert about it could not be written throws away the measurement in
// order to report the failure to tell somebody about it.
func TestAFailedAlertDoesNotFailTheScan(t *testing.T) {
	source := read(t, "notify.go")
	if strings.Contains(source, "return err") || strings.Contains(source, ") error {") {
		t.Error("the alert writer returns an error upward, so a scan can fail because its alert did")
	}
	if strings.Count(source, "log.Printf") < 3 {
		t.Error("a failed alert is no longer reported at all")
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
