package main

import (
	"strings"
	"testing"
)

// main.go is the startup sequence, and the order in it is load-bearing: a
// subcommand that answers after config.Load needs secrets it has no business
// needing, a heal that runs before the migrations reads a schema that is not
// there yet, and a queue worker started before its resume takes a row the
// resume is still moving. main() opens a database and provisions the host, so
// the sequence cannot be executed here; these assertions read the declaration,
// the same way routes_test.go reads the route table.

// localFuncs maps every function declared in main.go to its body, without the
// signature line: the signature would read as a call to itself and fold the
// body in a second time.
func localFuncs(t *testing.T) map[string]string {
	t.Helper()
	bodies := map[string]string{}
	for _, part := range strings.Split(routeTable(t), "\nfunc ")[1:] {
		name, rest, named := strings.Cut(part, "(")
		_, body, opened := strings.Cut(rest, "{\n")
		body, _, closed := strings.Cut(body, "\n}\n")
		if named && opened && closed {
			bodies[strings.TrimSpace(name)] = body
		}
	}
	return bodies
}

// calledLocal names the function a line calls, when the line is one call to a
// function declared in main.go. The call may be a condition or an assignment.
func calledLocal(line string, bodies map[string]string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(line), "if ")
	if assigned := strings.Index(trimmed, ":= "); assigned >= 0 {
		trimmed = trimmed[assigned+len(":= "):]
	}
	for name := range bodies {
		if name != "main" && strings.HasPrefix(trimmed, name+"(") {
			return name
		}
	}
	return ""
}

// expandOnce replaces each call to a locally declared function with its body.
func expandOnce(sequence string, bodies map[string]string) string {
	var out strings.Builder
	for line := range strings.SplitSeq(sequence, "\n") {
		if name := calledLocal(line, bodies); name != "" {
			out.WriteString(bodies[name])
		} else {
			out.WriteString(line)
		}
		out.WriteString("\n")
	}
	return out.String()
}

// startupSequence is main's body with every step extracted out of it folded
// back in, so the order below is the order the panel boots in rather than the
// order the file happens to declare its functions in.
func startupSequence(t *testing.T) string {
	t.Helper()
	bodies := localFuncs(t)
	sequence := bodies["main"]
	for range 3 { // deeper than the extraction goes
		sequence = expandOnce(sequence, bodies)
	}
	return sequence
}

// at returns the position of a marker that must appear exactly once, so the
// order below is never decided by a second copy of the same text.
func at(t *testing.T, sequence, marker string) int {
	t.Helper()
	first := strings.Index(sequence, marker)
	if first < 0 {
		t.Fatalf("%q is not in the startup sequence", marker)
	}
	if strings.Contains(sequence[first+len(marker):], marker) {
		t.Fatalf("%q runs more than once, so its position is ambiguous", marker)
	}
	return first
}

// inOrder asserts the markers run in the given order.
func inOrder(t *testing.T, sequence string, markers ...string) {
	t.Helper()
	previous := -1
	previousMarker := ""
	for _, marker := range markers {
		position := at(t, sequence, marker)
		if position < previous {
			t.Errorf("%q runs before %q, which reverses the startup order", marker, previousMarker)
		}
		previous, previousMarker = position, marker
	}
}

// Every subcommand mode answers before config.Load, because reporting a port,
// scanning for malware or installing a loader is not a reason to need the JWT
// secret, the encryption key or a database. servika-verify has to work on an
// installation that is broken enough to be worth verifying.
func TestEverySubcommandAnswersBeforeTheConfigurationIsLoaded(t *testing.T) {
	sequence := startupSequence(t)
	load := at(t, sequence, "config.Load(")
	gates := []string{
		`fmt.Printf("backend_host=`,
		"antivirus.RunWorkerIfAsked()",
		"antivirus.PrintRuleSetIfAsked()",
		"antivirus.RunWatcherIfAsked()",
		"antivirus.RunSweepIfAsked()",
		"antivirus.RunProcWatcherIfAsked()",
		"phpext.RunIonCubeInstallIfAsked()",
	}
	for _, gate := range gates {
		if at(t, sequence, gate) > load {
			t.Errorf("%s answers after config.Load, so it needs secrets it has no reason to need", gate)
		}
	}
}

// The temp directory is pinned before anything writes a file. /tmp is tmpfs on
// AlmaLinux 10, so an import or a restore that lands there drags the server
// into OOM.
func TestTheTempDirectoryIsPinnedBeforeTheConfigurationIsLoaded(t *testing.T) {
	sequence := startupSequence(t)
	if at(t, sequence, `os.Setenv("TMPDIR"`) > at(t, sequence, "config.Load(") {
		t.Error("the temporary directory is pinned after config.Load")
	}
}

// The two Redis modes unseal a column, so they need BOTH the encryption key and
// the database, and they answer after those are ready and before the panel goes
// any further.
func TestTheRedisModesAnswerAfterTheKeyAndTheDatabase(t *testing.T) {
	inOrder(t, startupSequence(t),
		"config.Load(",
		"secret.Init(",
		"db.Open(",
		"redis.Password(",
		"redis.SavePassword(",
		"dbmigrate.Run(",
	)
}

// The migrations run before every backfill and every heal: each of them reads
// or writes columns a migration adds.
func TestTheMigrationsRunBeforeTheBackfillsAndTheHeals(t *testing.T) {
	inOrder(t, startupSequence(t),
		"dbmigrate.Run(",
		"credentials.BackfillCleartextPasswords(",
		"credentials.BackfillDBPasswords(",
		"datamigrate.EncryptStoredCredentials(",
		"datamigrate.EncryptRedisPasswords(",
		"datamigrate.EncryptTOTPSecrets(",
		"provisioner.Init(d)",
		"antivirus.HealRunningScans(d)",
		"middleware.Init(d)",
	)
}

// The DNS template backfill runs right after the seed, because the seed only
// ever writes into an EMPTY template: a server that already runs Servika would
// otherwise never receive the AAAA rows added to the built-in set.
func TestTheDNSTemplateBackfillFollowsItsSeed(t *testing.T) {
	inOrder(t, startupSequence(t),
		"dns.SeedTemplateIfEmpty(",
		"datamigrate.BackfillDNSTemplateIPv6(",
		"dns.HealZoneIncludes(",
	)
}

// The mailbox migration resume runs before the workers start. A worker starting
// first could claim a row the resume is still moving.
func TestTheMigrationResumeRunsBeforeTheQueueWorkers(t *testing.T) {
	inOrder(t, startupSequence(t),
		"mail.HealMigrationJobs(d)",
		"mail.StartMigrationQueue(",
	)
}

// The router is built after the handlers exist, the server after the router,
// and the firewall is reapplied before the listener accepts anything.
func TestTheServerIsAssembledAndGuardedBeforeItListens(t *testing.T) {
	inOrder(t, startupSequence(t),
		"chi.NewRouter()",
		"srv := &http.Server{",
		"firewall.TakeOverFirewalld()",
		"srv.ListenAndServe()",
		"signal.Notify(stop",
		"srv.Shutdown(ctx)",
	)
}
