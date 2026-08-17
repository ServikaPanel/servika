package optimize

import (
	"slices"
	"testing"
)

func ids(proposals []Proposal) []string {
	out := make([]string, 0, len(proposals))
	for _, proposal := range proposals {
		out = append(out, proposal.ID)
	}
	slices.Sort(out)
	return out
}

func find(t *testing.T, proposals []Proposal, id string) Proposal {
	t.Helper()
	for _, proposal := range proposals {
		if proposal.ID == id {
			return proposal
		}
	}
	t.Fatalf("%s was not proposed; got %q", id, ids(proposals))
	return Proposal{}
}

// The rule this screen exists for. Upstream computed every value from RAM and
// CPU and wrote it whatever was there, which measurably LOWERED fs.file-max
// from 2097152 to 500000 and client_max_body_size from 10240m to 128M on
// servers that had been tuned by hand.
func TestAParameterAlreadyBetterThanTheProposalIsNotOffered(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}

	// Untouched host: fs.file-max is proposed.
	fresh := Compute(facts, map[string]string{})
	find(t, fresh, "sysctl:fs.file-max")

	// Hand-tuned host: the existing value is larger, so nothing is offered.
	// The number is deliberately above what 8192 MB computes to (2097152), or
	// the equality check alone would pass this and the guard would go untested.
	tuned := Compute(facts, map[string]string{"sysctl:fs.file-max": "4194304"})
	for _, proposal := range tuned {
		if proposal.ID == "sysctl:fs.file-max" {
			t.Errorf("fs.file-max would be lowered from 4194304 to %s", proposal.Proposed)
		}
	}
}

// The same rule with a size suffix, which is how MariaDB and php-fpm write it.
func TestTheComparisonUnderstandsSizeSuffixes(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	// 50% of 8192 MB is 4096M. A host already at 8G must not be cut in half.
	tuned := Compute(facts, map[string]string{"mariadb:innodb_buffer_pool_size": "8G"})
	for _, proposal := range tuned {
		if proposal.ID == "mariadb:innodb_buffer_pool_size" {
			t.Errorf("the buffer pool would be lowered from 8G to %s", proposal.Proposed)
		}
	}
	// A host at 1G is below the proposal, so it IS offered.
	small := Compute(facts, map[string]string{"mariadb:innodb_buffer_pool_size": "1G"})
	if got := find(t, small, "mariadb:innodb_buffer_pool_size").Proposed; got != "4096M" {
		t.Errorf("proposed %q, want 4096M", got)
	}
}

// A value in a form this does not understand is LEFT ALONE. Somebody wrote it
// deliberately, and replacing it with a computed number is the mistake the
// comparison exists to stop.
func TestAnUnparseableCurrentValueIsLeftAlone(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	for _, value := range []string{"auto", "50%", "4096MB", "-1", ""} {
		result := Compute(facts, map[string]string{"sysctl:fs.file-max": value})
		offered := false
		for _, proposal := range result {
			if proposal.ID == "sysctl:fs.file-max" {
				offered = true
			}
		}
		// The empty string is the one case that SHOULD be offered: it means the
		// parameter is not set at all, not that it is set to something odd.
		if value == "" && !offered {
			t.Error("an unset parameter was not offered")
		}
		if value != "" && offered {
			t.Errorf("a current value of %q was overwritten with a computed number", value)
		}
	}
}

// A screen listing changes that change nothing is a screen nobody reads.
func TestAParameterAlreadyAtTheProposedValueIsNotOffered(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	all := Compute(facts, map[string]string{})
	current := map[string]string{}
	for _, proposal := range all {
		current[proposal.ID] = proposal.Proposed
	}
	if again := Compute(facts, current); len(again) != 0 {
		t.Errorf("a host already at every proposed value was offered %q", ids(again))
	}
}

// The host and this package write the same number in different units. MariaDB
// reports innodb_buffer_pool_size in BYTES (measured: 10.11 answers 134217728
// for the 128M default) while the proposal is written "4096M". Comparing those
// as strings finds them different forever, so an applied parameter would be
// offered again on every visit.
func TestAValueEqualInOtherUnitsIsNotProposedAgain(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	// 50% of 8192 MB is 4096M, which is 4294967296 bytes.
	current := map[string]string{"mariadb:innodb_buffer_pool_size": "4294967296"}
	for _, proposal := range Compute(facts, current) {
		if proposal.ID == "mariadb:innodb_buffer_pool_size" {
			t.Errorf("4294967296 bytes and %s are the same value", proposal.Proposed)
		}
	}
}

// php-fpm checks its pm.* values against each other when the pool is parsed,
// and it refuses at the next START rather than at the write. Applying
// pm.max_children alone would report success and leave a service that does not
// come back.
func TestThePMValuesAreExpandedIntoTheWholeGroup(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	all := Compute(facts, map[string]string{})

	expanded := Expand(all, []string{"php-fpm:pm.max_children"})
	want := []string{
		"php-fpm:pm.max_children", "php-fpm:pm.max_spare_servers",
		"php-fpm:pm.min_spare_servers", "php-fpm:pm.start_servers",
	}
	if !slices.Equal(ids(expanded), want) {
		t.Errorf("got %q, want the whole pm group %q", ids(expanded), want)
	}
}

// The InnoDB redo log is sized from the buffer pool, so growing the pool alone
// leaves InnoDB checkpointing against a log that is now far too small for it.
// The reason differs from the pm group (nothing REFUSES this configuration),
// the requirement does not: applying half of it can leave the server slower
// than before, which is the opposite of what the operator approved.
func TestTheInnoDBValuesAreExpandedTogether(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	all := Compute(facts, map[string]string{})
	expanded := Expand(all, []string{"mariadb:innodb_buffer_pool_size"})
	want := []string{"mariadb:innodb_buffer_pool_size", "mariadb:innodb_log_file_size"}
	if !slices.Equal(ids(expanded), want) {
		t.Errorf("got %q, want %q", ids(expanded), want)
	}
}

// MariaDB 10.11 REMOVED innodb_buffer_pool_instances: it is an unknown system
// variable to a client (ERROR 1193) and mysqld answers a config file carrying
// it with "'innodb-buffer-pool-instances' was removed. It does nothing now and
// exists only for compatibility with old my.cnf files." (both measured against
// 10.11.16). Offering it would put a line in the panel's drop-in that changes
// nothing, on a screen whose entire purpose is that every row it lists is a
// real change.
func TestNoRemovedMariaDBVariableIsOffered(t *testing.T) {
	removed := []string{
		"mariadb:innodb_buffer_pool_instances",
		"mariadb:innodb_additional_mem_pool_size",
		"mariadb:query_cache_size",
	}
	all := Compute(Facts{MemoryMB: 8192, CPUs: 4}, map[string]string{})
	for _, proposal := range all {
		if slices.Contains(removed, proposal.ID) {
			t.Errorf("%s was removed from MariaDB and must not be proposed", proposal.ID)
		}
	}
}

// A parameter with no group is applied on its own.
func TestAParameterWithoutAGroupStandsAlone(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	all := Compute(facts, map[string]string{})
	expanded := Expand(all, []string{"sysctl:fs.file-max"})
	if !slices.Equal(ids(expanded), []string{"sysctl:fs.file-max"}) {
		t.Errorf("got %q, want only fs.file-max", ids(expanded))
	}
}

// Nothing is proposed from measurements that were not taken. A zero RAM figure
// means the read failed, and computing a buffer pool from it would propose 128M
// on a 64 GB server.
func TestNothingIsProposedWithoutMeasurements(t *testing.T) {
	for _, facts := range []Facts{{}, {MemoryMB: 8192}, {CPUs: 4}, {MemoryMB: -1, CPUs: 4}} {
		if got := Compute(facts, map[string]string{}); len(got) != 0 {
			t.Errorf("facts %+v produced %q", facts, ids(got))
		}
	}
}

// The pm values have to satisfy php-fpm's own ordering, or the pool it writes
// is one php-fpm refuses. Measured against the shipped AlmaLinux 10 pool with
// only pm.max_children lowered to 20:
//
//	ALERT: [pool www] pm.min_spare_servers(5) and pm.max_spare_servers(35)
//	       cannot be greater than pm.max_children(20)
//	ERROR: failed to post process the configuration
//	ERROR: FPM initialization failed
//
// The same file with all four written together passes php-fpm -t.
func TestThePMValuesSatisfyTheOrderingPHPFPMEnforces(t *testing.T) {
	for _, facts := range []Facts{{MemoryMB: 1024, CPUs: 1}, {MemoryMB: 8192, CPUs: 4}, {MemoryMB: 65536, CPUs: 16}} {
		all := Compute(facts, map[string]string{})
		value := func(id string) int64 {
			number, ok := sizeValue(find(t, all, id).Proposed)
			if !ok {
				t.Fatalf("%s is not a number", id)
			}
			return number
		}
		maxChildren := value("php-fpm:pm.max_children")
		start := value("php-fpm:pm.start_servers")
		minSpare := value("php-fpm:pm.min_spare_servers")
		maxSpare := value("php-fpm:pm.max_spare_servers")

		if minSpare > start || start > maxSpare {
			t.Errorf("%+v: start_servers %d is outside [%d, %d], which php-fpm refuses",
				facts, start, minSpare, maxSpare)
		}
		if maxSpare > maxChildren {
			t.Errorf("%+v: max_spare_servers %d is over max_children %d", facts, maxSpare, maxChildren)
		}
	}
}

// The group can still come apart, in one direction that is not obvious.
// pm.max_children is increaseOnly and the three spare values are not, so a host
// already above the computed ceiling is offered the spares WITHOUT the ceiling.
// That is only safe because every computed spare value is below the computed
// ceiling, and the ceiling is offered whenever the host is below it. If a future
// edit to specs breaks either half, this is where it shows.
func TestTheSparesNeverExceedACeilingThatIsNotOffered(t *testing.T) {
	facts := Facts{MemoryMB: 8192, CPUs: 4}
	for _, hostCeiling := range []string{"5", "50", "51", "100", "4096"} {
		current := map[string]string{"php-fpm:pm.max_children": hostCeiling}
		offered := Compute(facts, current)

		ceiling, _ := sizeValue(hostCeiling)
		for _, proposal := range offered {
			if proposal.ID == "php-fpm:pm.max_children" {
				// The ceiling itself is being raised, so the whole group is
				// written together and consistency is the group's problem.
				ceiling = 0
				break
			}
		}
		if ceiling == 0 {
			continue
		}
		for _, proposal := range offered {
			if proposal.Group != "pm" {
				continue
			}
			value, ok := sizeValue(proposal.Proposed)
			if !ok {
				t.Fatalf("%s is not a number", proposal.ID)
			}
			if value > ceiling {
				t.Errorf("host ceiling %s is kept, but %s would be set to %d, which php-fpm refuses",
					hostCeiling, proposal.ID, value)
			}
		}
	}
}
