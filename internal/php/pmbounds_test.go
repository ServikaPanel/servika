package php

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// pmSettings returns a valid settings value to vary one field of.
func pmSettings() Settings { return Defaults() }

// reasonOf returns the stable reason code of a refusal.
func reasonOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var refusal settingError
	if !errors.As(err, &refusal) {
		t.Fatalf("the refusal carries no reason code: %v", err)
	}
	return refusal.Reason
}

// The six pm.* fields are rendered verbatim into a pool file that lands in the
// directory SHARED by every tenant on that PHP version, and a plan-less domain
// has no cgroup above it either. A role=user customer reaches this endpoint.
func TestThePMStrategyIsAnAllowlist(t *testing.T) {
	for _, mode := range []string{"static", "dynamic", "ondemand"} {
		settings := pmSettings()
		settings.PMStrategy = mode
		// dynamic has its own relation, checked separately.
		if mode == "dynamic" {
			settings.PMMinSpareServers, settings.PMStartServers, settings.PMMaxSpareServers = 1, 2, 3
		}
		if _, err := sanitizeSettings(settings); err != nil {
			t.Errorf("%s was refused: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "onDemand", "static ", "anything", "dynamic; evil"} {
		settings := pmSettings()
		settings.PMStrategy = mode
		if _, err := sanitizeSettings(settings); reasonOf(t, err) != reasonInvalidPMMode {
			t.Errorf("pm_strategy %q was accepted", mode)
		}
	}
}

// php-fpm enforces min_spare <= max_spare <= max_children at STARTUP, so a group
// that breaks it is discovered only when the service refuses to come back, with
// the file already in the shared directory.
func TestAnInconsistentDynamicGroupIsRefused(t *testing.T) {
	settings := pmSettings()
	settings.PMStrategy = "dynamic"
	settings.PMMaxChildren, settings.PMStartServers = 1, 30
	settings.PMMinSpareServers, settings.PMMaxSpareServers = 20, 35

	if _, err := sanitizeSettings(settings); reasonOf(t, err) != reasonPMInconsistent {
		t.Fatalf("the reported proof-of-concept group was accepted")
	}
}

// A consistent dynamic group is the ordinary case and must pass.
func TestAConsistentDynamicGroupIsAccepted(t *testing.T) {
	settings := pmSettings()
	settings.PMStrategy = "dynamic"
	settings.PMMaxChildren, settings.PMStartServers = 20, 5
	settings.PMMinSpareServers, settings.PMMaxSpareServers = 3, 10

	if _, err := sanitizeSettings(settings); err != nil {
		t.Fatalf("a consistent group was refused: %v", err)
	}
}

// Only `dynamic` carries the relation; the other two strategies ignore the spare
// counters, so holding them to it would refuse values php-fpm accepts.
func TestTheRelationAppliesToDynamicOnly(t *testing.T) {
	for _, mode := range []string{"static", "ondemand"} {
		settings := pmSettings()
		settings.PMStrategy = mode
		settings.PMMaxChildren, settings.PMStartServers = 4, 30
		settings.PMMinSpareServers, settings.PMMaxSpareServers = 20, 35
		if _, err := sanitizeSettings(settings); err != nil {
			t.Errorf("%s was held to the dynamic relation: %v", mode, err)
		}
	}
}

// An unbounded pm.max_children on a shared-master domain has no ceiling above it
// at all, because a plan-less domain also loses its systemd slice.
func TestTheCountersAreBounded(t *testing.T) {
	for name, mutate := range map[string]func(*Settings){
		"pm_max_children zero":     func(s *Settings) { s.PMMaxChildren = 0 },
		"pm_max_children negative": func(s *Settings) { s.PMMaxChildren = -1 },
		"pm_max_children huge":     func(s *Settings) { s.PMMaxChildren = pmMaxChildrenCeiling + 1 },
		"pm_max_requests negative": func(s *Settings) { s.PMMaxRequests = -1 },
		"pm_max_requests huge":     func(s *Settings) { s.PMMaxRequests = pmMaxRequestsCeiling + 1 },
		"pm_start_servers huge":    func(s *Settings) { s.PMStartServers = pmMaxChildrenCeiling + 1 },
	} {
		settings := pmSettings()
		settings.PMStrategy = "static"
		mutate(&settings)
		if _, err := sanitizeSettings(settings); reasonOf(t, err) != reasonPMOutOfRange {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The shared pool is written into the directory every other tenant on that PHP
// version shares, so a pool php-fpm refuses fails `php-fpm -t` for the WHOLE
// version and blocks creation of every new domain on it. Both sibling writers of
// this directory already validate and roll back.
func TestTheSharedPoolWriteValidatesAndRollsBack(t *testing.T) {
	body, err := os.ReadFile("php.go")
	if err != nil {
		t.Fatalf("read php.go: %v", err)
	}
	source := string(body)

	// Both calls go through the package seams (seams.go), whose defaults are
	// provisioner.FPMBinaryFor and exec.Command. The behaviour itself is pinned by
	// TestAPoolIsWrittenTestedAndTheMasterReloaded and TestARefusedPoolIsPutBack.
	if !strings.Contains(source, `fpmBinaryFor(version)`) {
		t.Error("ApplyToFilesystem does not run php-fpm -t against the version's binary")
	}
	if !strings.Contains(source, `runCommand(fpm, "-t")`) {
		t.Error("the pool is written without a php-fpm -t gate")
	}
	// Two failure paths put the previous bytes back: the php-fpm -t refusal and
	// the reload refusal.
	if n := strings.Count(source, "restorePool()"); n != 2 {
		t.Errorf("the pool is restored on %d failure paths, want 2", n)
	}
}
