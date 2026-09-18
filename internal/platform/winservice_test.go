package platform

import (
	"strings"
	"testing"
)

func TestOnlyAnAllowlistedServiceCanBeNamed(t *testing.T) {
	// Stopping an arbitrary Windows service breaks the machine. The boundary is
	// in code, not in an intention.
	for _, name := range []string{"", "RpcSs", "LSASS", "Winlogon", "Spooler", "W3SVC;stop", "W3SVC extra"} {
		if got := canonicalService(name); got != "" {
			t.Fatalf("service %q resolved to %q; it is not one this panel manages", name, got)
		}
	}
}

func TestAnAllowlistedServiceResolvesToTheListsOwnSpelling(t *testing.T) {
	// The canonical name is what reaches a command, never the caller's echo of
	// it, so a caller cannot smuggle anything in through the spelling.
	if got := canonicalService("w3svc"); got != "W3SVC" {
		t.Fatalf("w3svc resolved to %q, want the allowlist's spelling W3SVC", got)
	}
	if got := canonicalService("  MSSQLSERVER  "); got != "MSSQLSERVER" {
		t.Fatalf("a padded name resolved to %q", got)
	}
}

func TestOnlyThreeServiceActionsAreAccepted(t *testing.T) {
	for _, action := range []string{"", "delete", "disable", "START", "start;stop"} {
		if _, err := targetState(action); err == nil {
			t.Fatalf("action %q was accepted", action)
		}
	}
}

func TestEachActionNamesTheStateItHasToReach(t *testing.T) {
	// The command's exit code is not the answer: sc start and sc stop are
	// asynchronous, so the action is judged by the state that follows.
	want := map[string]string{"start": "Running", "stop": "Stopped", "restart": "Running"}
	for action, state := range want {
		got, err := targetState(action)
		if err != nil {
			t.Fatalf("action %q was refused: %v", action, err)
		}
		if got != state {
			t.Fatalf("action %q targets %q, want %q", action, got, state)
		}
	}
}

func TestTheQueryIsBuiltFromTheAllowlistItself(t *testing.T) {
	// Writing the names twice is how a query and its gate drift apart: a service
	// appears in the listing that the action then refuses, or the reverse.
	query := quotedAllowlist()
	for _, name := range serviceAllowlist {
		if !strings.Contains(query, "'"+name+"'") {
			t.Fatalf("the query does not ask for %q, which the gate allows", name)
		}
	}
	if strings.Count(query, ",") != len(serviceAllowlist)-1 {
		t.Fatalf("the query is not a plain comma-separated list: %s", query)
	}
}

func TestEveryAllowlistedNameIsSafeInsideASingleQuotedArgument(t *testing.T) {
	// The names go into a PowerShell single-quoted literal. A quote or a space
	// in one would break out of it.
	for _, name := range serviceAllowlist {
		if strings.ContainsAny(name, "' \t\r\n;$`\"") {
			t.Fatalf("the allowlisted name %q is not safe inside a quoted argument", name)
		}
	}
}

func TestASingleServiceComesBackAsABareObjectHereToo(t *testing.T) {
	list, err := parseServices([]byte(`{"Name":"W3SVC","DisplayName":"World Wide Web","State":"Running","StartType":"Automatic"}`))
	if err != nil {
		t.Fatalf("a single-service answer failed: %v", err)
	}
	if len(list) != 1 || list[0].Name != "W3SVC" || list[0].State != "Running" {
		t.Fatalf("a single-service answer read as %+v", list)
	}
}

func TestSeveralServicesComeBackAsAnArrayHereToo(t *testing.T) {
	list, err := parseServices([]byte(`[{"Name":"W3SVC","State":"Running"},{"Name":"WAS","State":"Stopped"}]`))
	if err != nil {
		t.Fatalf("a two-service answer failed: %v", err)
	}
	if len(list) != 2 || list[1].Name != "WAS" {
		t.Fatalf("a two-service answer read as %+v", list)
	}
}

func TestNoServiceInstalledIsAnEmptyListNotANilAnswer(t *testing.T) {
	// The handler ranges over this; an empty list keeps the answer an array
	// rather than JSON null.
	list, err := parseServices([]byte("  \r\n"))
	if err != nil {
		t.Fatalf("an empty answer failed: %v", err)
	}
	if list == nil || len(list) != 0 {
		t.Fatalf("an empty answer read as %v", list)
	}
}

func TestABrokenServiceAnswerIsReportedNotSwallowed(t *testing.T) {
	if _, err := parseServices([]byte("{not json")); err == nil {
		t.Fatal("a broken answer read as an empty service list")
	}
}

func TestADecodeFailureDuringCapabilityDiscoveryCostsOnlyThatAnswer(t *testing.T) {
	// Capability discovery treats an unreadable answer as "nothing proven",
	// because failing the whole probe would take the readable capabilities down
	// with it.
	if names := serviceNames([]byte("{not json")); names != nil {
		t.Fatalf("a broken answer produced %v", names)
	}
}

func TestARecordWithNoNameIsNotCountedAsAService(t *testing.T) {
	if names := serviceNames([]byte(`[{"Name":"DNS"},{"Name":""}]`)); len(names) != 1 {
		t.Fatalf("an unnamed record was counted: %v", names)
	}
}
