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
//
// The file is laid out in startup order: a step extracted out of main() is
// declared in the position it runs in, so a reader follows the boot from top to
// bottom.

// at returns the position of a marker that must appear exactly once, so the
// order below is never decided by a second copy of the same text.
func at(t *testing.T, source, marker string) int {
	t.Helper()
	first := strings.Index(source, marker)
	if first < 0 {
		t.Fatalf("%q is not in main.go", marker)
	}
	if strings.Contains(source[first+len(marker):], marker) {
		t.Fatalf("%q appears more than once in main.go, so its position is ambiguous", marker)
	}
	return first
}

// inOrder asserts the markers appear in the given order.
func inOrder(t *testing.T, source string, markers ...string) {
	t.Helper()
	previous := -1
	previousMarker := ""
	for _, marker := range markers {
		position := at(t, source, marker)
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
	source := routeTable(t)
	load := at(t, source, "config.Load(")
	gates := []string{
		"if printPortsIfAsked()",
		"antivirus.RunWorkerIfAsked()",
		"antivirus.PrintRuleSetIfAsked()",
		"antivirus.RunWatcherIfAsked()",
		"antivirus.RunSweepIfAsked()",
		"antivirus.RunProcWatcherIfAsked()",
		"phpext.RunIonCubeInstallIfAsked()",
	}
	for _, gate := range gates {
		if at(t, source, gate) > load {
			t.Errorf("%s answers after config.Load, so it needs secrets it has no reason to need", gate)
		}
	}
}

// The temp directory is pinned before anything writes a file. /tmp is tmpfs on
// AlmaLinux 10, so an import or a restore that lands there drags the server
// into OOM.
func TestTheTempDirectoryIsPinnedBeforeTheConfigurationIsLoaded(t *testing.T) {
	source := routeTable(t)
	if at(t, source, "\tpinTempDir()") > at(t, source, "config.Load(") {
		t.Error("the temporary directory is pinned after config.Load")
	}
}

// The two Redis modes unseal a column, so they need BOTH the encryption key and
// the database, and they answer after those are ready and before the panel goes
// any further.
func TestTheRedisModesAnswerAfterTheKeyAndTheDatabase(t *testing.T) {
	inOrder(t, routeTable(t),
		"config.Load(",
		"secret.Init(",
		"db.Open(",
		"printRedisPasswordIfAsked(d)",
		"saveRedisPasswordIfAsked(d)",
		"runMigrations(d)",
	)
}

// The migrations run before every backfill and every heal: each of them reads
// or writes columns a migration adds.
func TestTheMigrationsRunBeforeTheBackfillsAndTheHeals(t *testing.T) {
	inOrder(t, routeTable(t),
		"runMigrations(d)",
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
	inOrder(t, routeTable(t),
		"dns.SeedTemplateIfEmpty(",
		"datamigrate.BackfillDNSTemplateIPv6(",
		"dns.HealZoneIncludes(",
	)
}

// The mailbox migration resume runs before the workers start. A worker starting
// first could claim a row the resume is still moving.
func TestTheMigrationResumeRunsBeforeTheQueueWorkers(t *testing.T) {
	inOrder(t, routeTable(t),
		"mail.HealMigrationJobs(d)",
		"mail.StartMigrationQueue(",
	)
}

// The router is built after the handlers exist, the server after the router,
// and the firewall is reapplied before the listener accepts anything.
func TestTheServerIsAssembledAndGuardedBeforeItListens(t *testing.T) {
	inOrder(t, routeTable(t),
		"chi.NewRouter()",
		"srv := &http.Server{",
		"firewall.TakeOverFirewalld()",
		"srv.ListenAndServe()",
		"signal.Notify(stop",
		"srv.Shutdown(ctx)",
	)
}
