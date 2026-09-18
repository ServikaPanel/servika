package platform

import (
	"strings"
	"testing"
)

func TestADerivedAccountNameFitsTheSAMLimit(t *testing.T) {
	// A Windows SAM account name is at most 20 characters. A name over that is
	// not truncated by Windows, it is refused, so every site on a long domain
	// would fail to be created.
	for _, domain := range []string{
		"a.com",
		"averyverylongdomainnamethatkeepsgoing.example.com",
		"xn--nglish-8sa.example",
		strings.Repeat("z", 200) + ".com",
	} {
		user := systemUserFor(domain)
		if len(user) > 20 {
			t.Fatalf("systemUserFor(%q) = %q, %d characters, over the SAM limit of 20", domain, user, len(user))
		}
		if !strings.HasPrefix(user, userPrefix) {
			t.Fatalf("systemUserFor(%q) = %q, missing the %q prefix", domain, user, userPrefix)
		}
	}
}

func TestTwoDomainsSharingAPrefixGetDifferentAccounts(t *testing.T) {
	// The body is truncated to eight characters, so these two are told apart by
	// the hash alone. That is exactly the case the 32-bit hash exists for.
	a := systemUserFor("verylongshop.example.com")
	b := systemUserFor("verylongshop.example.net")
	if a == b {
		t.Fatalf("two different domains map to the same account %q", a)
	}
}

func TestTheAccountNameIsStableForOneDomain(t *testing.T) {
	// Deletion falls back to recomputing this name. If it were not stable, a
	// delete would name an account that never existed and orphan the real one.
	if systemUserFor("shop.example.com") != systemUserFor("SHOP.Example.COM") {
		t.Fatal("the account name changes with the case of the domain")
	}
}

func TestOnlyAPlausibleDomainIsAccepted(t *testing.T) {
	// This pattern is a CHARACTER gate, not a hostname grammar: the value
	// becomes an appcmd argument and a directory name, so what it has to keep
	// out is whitespace, quoting, path separators and shell punctuation. Whether
	// each label is a legal hostname label is the panel's own validation, which
	// runs before any of this.
	for _, bad := range []string{
		"", "-lead.com", "trailing-", "UPPER.com", "has space.com",
		"semi;colon.com", "quote\".com", "slash/path.com", "back\\slash.com",
		"pipe|.com", "amp&.com", "dollar$.com", "tick`.com", "nl\n.com",
	} {
		if domainPattern.MatchString(bad) {
			t.Fatalf("%q was accepted as a domain; it becomes an appcmd argument and a directory name", bad)
		}
	}
	for _, good := range []string{"a.com", "shop.example.com", "a-b.example.co.uk", "x1.test"} {
		if !domainPattern.MatchString(good) {
			t.Fatalf("%q was refused as a domain", good)
		}
	}
}

func TestASingleServiceComesBackAsABareObject(t *testing.T) {
	// ConvertTo-Json writes an object when there is one result and an array when
	// there are several. Reading only the array shape loses every host that has
	// exactly one of the candidate services.
	names := serviceNames([]byte(`{"Name":"DNS"}`))
	if len(names) != 1 || names[0] != "DNS" {
		t.Fatalf("a single-service answer read as %v", names)
	}
}

func TestSeveralServicesComeBackAsAnArray(t *testing.T) {
	names := serviceNames([]byte(`[{"Name":"MSSQLSERVER"},{"Name":"ftpsvc"}]`))
	if len(names) != 2 {
		t.Fatalf("a two-service answer read as %v", names)
	}
}

func TestNoServiceAtAllIsNotAFailure(t *testing.T) {
	if names := serviceNames([]byte("   \r\n ")); names != nil {
		t.Fatalf("an empty answer read as %v", names)
	}
}

func TestEachServiceLightsItsOwnCapability(t *testing.T) {
	cases := map[string]Capability{
		"MSSQLSERVER":   CapMSSQL,
		"MSSQL$SECOND":  CapMSSQL, // a named instance
		"ftpsvc":        CapFTP,
		"DNS":           CapDNS,
		"MySQL80":       CapMySQL,
		"postgresql-17": CapPostgreSQL,
	}
	for name, want := range cases {
		if got := capabilitiesFromServices([]string{name}); !got.Has(want) {
			t.Errorf("service %q did not light its capability (got %d)", name, got)
		}
	}
	if capabilitiesFromServices([]string{"Spooler", "W32Time"}) != 0 {
		t.Fatal("an unrelated service lit a capability")
	}
}

// wevtutil does not produce a single root element: the output is a run of
// <Event> nodes. Anything that calls xml.Unmarshal on this fails on the second
// one with "unexpected token".
const twoEvents = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Service Control Manager"/><EventID>7036</EventID><Level>4</Level>
  <TimeCreated SystemTime="2026-09-03T10:15:30.1234567Z"/><Channel>System</Channel></System>
  <RenderingInfo><Message>The service entered the running state.</Message></RenderingInfo>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Disk"/><EventID>11</EventID><Level>2</Level>
  <TimeCreated SystemTime="2026-09-03T10:16:00.0000000Z"/><Channel>System</Channel></System>
  <RenderingInfo><Message>A controller error.</Message></RenderingInfo>
</Event>`

func TestEveryEventInTheStreamIsRead(t *testing.T) {
	events, err := parseEvents("System", []byte(twoEvents))
	if err != nil {
		t.Fatalf("the event stream failed to parse: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("read %d events from a two-event stream", len(events))
	}
	if events[0].Source != "Service Control Manager" || events[0].ID != 7036 {
		t.Fatalf("the first event read as %+v", events[0])
	}
	if events[1].Level != "error" {
		t.Fatalf("a Level 2 event read as %q, want error", events[1].Level)
	}
}

func TestTheLevelComesFromTheNumberNotTheLocalisedText(t *testing.T) {
	// RenderingInfo/Level reads "Error" on one host and "Hata" on another, so
	// the numeric System/Level is the only stable source.
	cases := map[int]string{0: "info", 1: "error", 2: "error", 3: "warning", 4: "info", 5: "info"}
	for level, want := range cases {
		if got := eventLevel(level); got != want {
			t.Errorf("level %d read as %q, want %q", level, got, want)
		}
	}
}

func TestAnEventWithNoMessageFallsBackToItsData(t *testing.T) {
	const noMessage = `<Event><System><Provider Name="App"/><EventID>1</EventID><Level>4</Level>
	<TimeCreated SystemTime="2026-09-03T10:15:30.0000000Z"/><Channel>Application</Channel></System>
	<EventData><Data>first</Data><Data>  </Data><Data>second</Data></EventData></Event>`
	events, err := parseEvents("Application", []byte(noMessage))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if events[0].Text != "first | second" {
		t.Fatalf("the fallback text read as %q", events[0].Text)
	}
}

func TestALongMessageIsCutByRuneNotByByte(t *testing.T) {
	// A byte cut splits a multi-byte character in half and puts a broken string
	// into the JSON answer.
	long := strings.Repeat("ş", messageRunes+500)
	var ev wevtEvent
	ev.RenderingInfo.Message = long
	got := eventText(ev)
	runes := []rune(got)
	if len(runes) != messageRunes {
		t.Fatalf("the message was cut to %d runes, want %d", len(runes), messageRunes)
	}
	if !strings.HasSuffix(got, "ş") {
		t.Fatal("the cut landed inside a multi-byte character")
	}
}

func TestAnEventWithNoChannelFallsBackToTheRequestedLog(t *testing.T) {
	const noChannel = `<Event><System><Provider Name="X"/><EventID>5</EventID><Level>4</Level>
	<TimeCreated SystemTime="2026-09-03T10:15:30.0000000Z"/></System></Event>`
	events, err := parseEvents("Security", []byte(noChannel))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if events[0].Log != "Security" {
		t.Fatalf("the log read as %q, want the requested Security", events[0].Log)
	}
}

func TestBrokenBytesDoNotStopTheStream(t *testing.T) {
	// Bytes leaking from the host's code page must not stop the decoder on an
	// unrelated event.
	broken := strings.ReplaceAll(twoEvents, "A controller error.", "A controller \xff error.")
	events, err := parseEvents("System", []byte(broken))
	if err != nil {
		t.Fatalf("a broken byte stopped the stream: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("read %d events after a broken byte, want 2", len(events))
	}
}

func TestAnEmptyEventStreamIsAnEmptyListNotAnError(t *testing.T) {
	events, err := parseEvents("System", nil)
	if err != nil {
		t.Fatalf("an empty stream failed: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("an empty stream produced %d events", len(events))
	}
}

func TestASingleTaskComesBackAsABareObject(t *testing.T) {
	tasks, err := parseTasks([]byte(`{"Name":"\\Backup","State":"Ready","LastResult":0}`), false)
	if err != nil {
		t.Fatalf("a single-task answer failed: %v", err)
	}
	if len(tasks) != 1 || tasks[0].Name != `\Backup` {
		t.Fatalf("a single-task answer read as %+v", tasks)
	}
}

func TestTheOperatingSystemsOwnTasksAreDroppedUnlessAsked(t *testing.T) {
	const listing = `[{"Name":"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","State":"Ready"},
	{"Name":"\\Backup","State":"Ready"}]`
	own, err := parseTasks([]byte(listing), false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(own) != 1 || own[0].Name != `\Backup` {
		t.Fatalf("the operating system's tasks were not dropped: %+v", own)
	}
	all, err := parseTasks([]byte(listing), true)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("asking for all tasks returned %d", len(all))
	}
}

func TestTheTaskListingIsCappedSoOneAnswerStaysReadable(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := range taskLimit + 50 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"Name":"\\Task","State":"Ready"}`)
	}
	b.WriteString("]")
	tasks, err := parseTasks([]byte(b.String()), false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(tasks) != taskLimit {
		t.Fatalf("the listing returned %d tasks, want the cap of %d", len(tasks), taskLimit)
	}
}

func TestNoTaskAtAllIsAnEmptyListNotAnError(t *testing.T) {
	tasks, err := parseTasks([]byte("  "), false)
	if err != nil {
		t.Fatalf("an empty listing failed: %v", err)
	}
	if len(tasks) != 0 {
		t.Fatalf("an empty listing produced %d tasks", len(tasks))
	}
}

func TestTheEventCountIsClampedIntoARange(t *testing.T) {
	if got := boundedCount(0); got != 1 {
		t.Fatalf("a count of 0 became %d", got)
	}
	if got := boundedCount(-5); got != 1 {
		t.Fatalf("a negative count became %d", got)
	}
	if got := boundedCount(maxEvents + 1000); got != maxEvents {
		t.Fatalf("an oversized count became %d, want %d", got, maxEvents)
	}
	if got := boundedCount(50); got != 50 {
		t.Fatalf("a count inside the range became %d", got)
	}
}

func TestOnlyTheAllowedLogsCanBeRead(t *testing.T) {
	for _, name := range []string{"System", "Application", "Security"} {
		if !eventLogs[name] {
			t.Fatalf("%q is not in the allowlist", name)
		}
	}
	for _, name := range []string{"", "system", "Setup", "System /c:1", "../Security"} {
		if eventLogs[name] {
			t.Fatalf("%q is in the allowlist; it reaches wevtutil as an argument", name)
		}
	}
}

func TestADirectoryBelongingToAnotherDomainIsNotTakenOver(t *testing.T) {
	// Deleting a site keeps the web root, so a deleted domain's files stay on
	// disk. If a hash collision maps a second domain onto the same account,
	// taking the directory over would serve one tenant's files as another's.
	if !ownerConflict([]byte("first.example.com\n"), "second.example.com") {
		t.Fatal("a directory owned by another domain was accepted; that is a cross-tenant leak")
	}
}

func TestADomainReclaimsItsOwnDirectory(t *testing.T) {
	// Re-creating the same site must stay idempotent.
	if ownerConflict([]byte("shop.example.com\n"), "shop.example.com") {
		t.Fatal("a domain was refused its own directory")
	}
	if ownerConflict([]byte("shop.example.com\n"), "SHOP.Example.COM") {
		t.Fatal("the owner check is case-sensitive; the same domain was refused its own directory")
	}
}

func TestAnAbsentOrEmptyMarkerIsNotAConflict(t *testing.T) {
	// A new directory, or one made before the marker existed.
	if ownerConflict(nil, "shop.example.com") {
		t.Fatal("an absent marker was read as a conflict")
	}
	if ownerConflict([]byte("  \n"), "shop.example.com") {
		t.Fatal("an empty marker was read as a conflict")
	}
}
