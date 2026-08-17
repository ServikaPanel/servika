// Package optimize turns the server tuning pass into something an operator can
// read one parameter at a time, agree to one parameter at a time, and undo one
// parameter at a time.
//
// assets/ops/servika-optimize.sh already computes and applies the whole pass
// and verifies MariaDB comes back. What it cannot do is any of the above: it is
// all or nothing, and on a server somebody else configured, all is a hard sell.
//
// The computation in this file is PURE. It takes what was measured off the host
// and returns what it would change, so the two rules that matter can be tested
// without a host to break.
package optimize

import (
	"fmt"
	"strconv"
	"strings"
)

// Service names, matching the optimize_backups ENUM exactly.
const (
	ServiceMariaDB = "mariadb"
	ServiceNginx   = "nginx"
	ServicePHPFPM  = "php-fpm"
	ServiceSysctl  = "sysctl"
)

// Effect is what applying a parameter costs.
const (
	EffectNone    = "none"
	EffectReload  = "reload"
	EffectRestart = "restart"
)

// The files each service is tuned through.
//
// The MariaDB and sysctl paths are the panel's own drop-ins, named to sort
// after the installer's own files. The nginx and php-fpm paths are the
// distribution's, because the directives live there and nginx refuses a
// duplicate directive from an include.
const (
	myCnfPath   = "/etc/my.cnf.d/servika-tuning.cnf"
	sysctlPath  = "/etc/sysctl.d/90-servika.conf"
	nginxPath   = "/etc/nginx/nginx.conf"
	fpmPoolPath = "/etc/php-fpm.d/www.conf"
)

// Facts are what was measured off the host.
type Facts struct {
	// MemoryMB is total RAM.
	MemoryMB int
	// CPUs is the core count.
	CPUs int
}

// Proposal is one parameter this would change.
type Proposal struct {
	// ID is "<service>:<param>", which is what an approval names.
	ID string `json:"id"`

	Service string `json:"service"`
	Param   string `json:"param"`

	// Current is what the host has now, empty when the parameter is not set.
	Current string `json:"current"`
	// Proposed is what this would set.
	Proposed string `json:"proposed"`

	// Rationale says why, in one line, in English. The screen translates the
	// SERVICE and the effect; the rationale names a measurement.
	Rationale string `json:"rationale"`

	// File is where the value would be written. It is shown because an
	// operator who tunes by hand needs to know which file the panel owns.
	File string `json:"file"`

	// Effect is what applying costs: nothing, a reload, or a restart.
	Effect string `json:"effect"`

	// Group ties parameters that must be applied together. An empty group
	// means the parameter stands alone.
	Group string `json:"group"`

	// IncreaseOnly marks a parameter whose current value is only ever replaced
	// when the proposal is LARGER. See the rule in Compute.
	IncreaseOnly bool `json:"increase_only"`
}

// spec describes one tunable.
type spec struct {
	service      string
	param        string
	file         string
	effect       string
	group        string
	increaseOnly bool
	// compute returns the value to propose, or "" for nothing to propose.
	compute func(Facts) string
	// rationale explains the value.
	rationale func(Facts, string) string
}

// bufferPoolMB is the proposed InnoDB buffer pool, in megabytes. The log file
// size is derived from it, so both read it rather than recomputing the shape.
func bufferPoolMB(f Facts) int {
	// A quarter of RAM under 4 GB, half above it, rounded down to 256 MiB.
	percent := 25
	if f.MemoryMB >= 4096 {
		percent = 50
	}
	return max((f.MemoryMB*percent/100/256)*256, 128)
}

// specs is every parameter this screen offers.
//
// Two of the files are the panel's OWN (the MariaDB drop-in and the sysctl
// drop-in), so reverting them is a restore of a file nobody else edits. The
// other two are not: nginx.conf and the stock php-fpm pool are the
// distribution's, and the operator may be editing them by hand. That is the
// whole reason every apply copies the file first and records the copy's path in
// optimize_backups, rather than reconstructing the old content from the row.
//
// Tenant PHP-FPM pools are deliberately NOT offered here. provisioner.tenantfpm
// renders them from the customer's PLAN and rewrites them on every change, so a
// value written from this screen would survive until the next render and no
// longer. /etc/php-fpm.d/www.conf is the stock pool, which the installer wires
// in as the nginx "php-fpm" upstream (assets/nginx/php-fpm.conf), and which
// nothing in the panel rewrites.
var specs = []spec{
	{
		service: ServiceMariaDB, param: "innodb_buffer_pool_size",
		file: myCnfPath, effect: EffectNone,
		group: "innodb", increaseOnly: true,
		compute: func(f Facts) string {
			return strconv.Itoa(bufferPoolMB(f)) + "M"
		},
		rationale: func(f Facts, value string) string {
			return fmt.Sprintf("InnoDB caches pages here; %s of %d MB of RAM.", value, f.MemoryMB)
		},
	},
	{
		// Sized WITH the pool, which is the whole reason it shares the group.
		// A pool that grows while the redo log stays at the 96M default makes
		// InnoDB checkpoint more often than before, so applying the pool alone
		// can leave the server slower than it was, which is the opposite of
		// what the operator approved.
		service: ServiceMariaDB, param: "innodb_log_file_size",
		file: myCnfPath, effect: EffectNone,
		group: "innodb", increaseOnly: true,
		compute: func(f Facts) string {
			return strconv.Itoa(max(bufferPoolMB(f)/4, 96)) + "M"
		},
		rationale: func(Facts, string) string {
			return "Redo log, a quarter of the buffer pool; a small log forces constant checkpointing."
		},
	},
	{
		service: ServiceMariaDB, param: "max_connections",
		file: myCnfPath, effect: EffectNone,
		increaseOnly: true,
		compute: func(f Facts) string {
			return strconv.Itoa(min(max(f.CPUs*50, 200), 1000))
		},
		rationale: func(Facts, string) string {
			return "The stock 151 is shared by every site plus the panel's own pool."
		},
	},
	{
		service: ServiceMariaDB, param: "table_open_cache",
		file: myCnfPath, effect: EffectNone,
		increaseOnly: true,
		compute: func(f Facts) string {
			return strconv.Itoa(min(max(f.MemoryMB*2, 2000), 16000))
		},
		rationale: func(Facts, string) string {
			return "Open table handles kept cached across connections."
		},
	},
	{
		service: ServiceNginx, param: "worker_connections",
		file: nginxPath, effect: EffectReload,
		increaseOnly: true,
		compute: func(f Facts) string {
			if f.MemoryMB < 2048 {
				return "2048"
			}
			return "4096"
		},
		rationale: func(Facts, string) string {
			return "Concurrent connections one worker will accept."
		},
	},
	{
		service: ServiceSysctl, param: "fs.file-max",
		file: sysctlPath, effect: EffectNone,
		increaseOnly: true,
		compute: func(f Facts) string {
			// Roughly 256 descriptors per megabyte of RAM, which is the shape
			// the kernel's own default follows, with a floor.
			value := max(f.MemoryMB*256, 500000)
			return strconv.Itoa(value)
		},
		rationale: func(Facts, string) string {
			return "System-wide open file limit."
		},
	},
	{
		service: ServiceSysctl, param: "net.core.somaxconn",
		file: sysctlPath, effect: EffectNone,
		increaseOnly: true,
		compute:      func(Facts) string { return "4096" },
		rationale: func(Facts, string) string {
			return "Listen backlog; the default of 4096 on this kernel is already the right order, older kernels shipped 128."
		},
	},
	{
		service: ServicePHPFPM, param: "pm.max_children",
		file: fpmPoolPath, effect: EffectRestart,
		group: "pm", increaseOnly: true,
		compute: func(f Facts) string {
			// Around 40 MB per PHP worker, over a quarter of RAM.
			children := max(f.MemoryMB/4/40, 5)
			return strconv.Itoa(children)
		},
		rationale: func(f Facts, value string) string {
			return fmt.Sprintf("%s workers at roughly 40 MB each, over a quarter of %d MB.", value, f.MemoryMB)
		},
	},
	{
		service: ServicePHPFPM, param: "pm.start_servers",
		file: fpmPoolPath, effect: EffectRestart,
		group: "pm",
		compute: func(f Facts) string {
			children := max(f.MemoryMB/4/40, 5)
			return strconv.Itoa(max(children/4, 2))
		},
		rationale: func(Facts, string) string { return "A quarter of the ceiling, started up front." },
	},
	{
		service: ServicePHPFPM, param: "pm.min_spare_servers",
		file: fpmPoolPath, effect: EffectRestart,
		group: "pm",
		compute: func(f Facts) string {
			children := max(f.MemoryMB/4/40, 5)
			return strconv.Itoa(max(children/8, 1))
		},
		rationale: func(Facts, string) string { return "Idle workers kept ready." },
	},
	{
		service: ServicePHPFPM, param: "pm.max_spare_servers",
		file: fpmPoolPath, effect: EffectRestart,
		group: "pm",
		compute: func(f Facts) string {
			children := max(f.MemoryMB/4/40, 5)
			return strconv.Itoa(max(children/2, 3))
		},
		rationale: func(Facts, string) string { return "Idle workers kept before php-fpm starts reaping." },
	},
}

// Compute returns what would be changed, given what the host has now.
//
// Two rules decide what comes out, and both close a hole measured in the
// upstream this design came from.
//
//   - A parameter is NOT proposed when the host's current value is already at
//     least as good. Upstream computed every value from RAM and CPU and wrote
//     it whatever was there, which measurably LOWERED fs.file-max from 2097152
//     to 500000 and client_max_body_size from 10240m to 128M on servers that
//     had been tuned by hand. Only parameters marked IncreaseOnly are compared
//     that way; the rest are compared for equality, because a smaller value is
//     genuinely correct for some of them.
//   - A parameter that is already exactly what would be proposed is not
//     offered at all. A screen listing forty changes that change nothing is a
//     screen nobody reads.
func Compute(facts Facts, current map[string]string) []Proposal {
	if facts.MemoryMB <= 0 || facts.CPUs <= 0 {
		return nil
	}
	var out []Proposal
	for _, item := range specs {
		id := item.service + ":" + item.param
		proposed := item.compute(facts)
		if proposed == "" {
			continue
		}
		existing := strings.TrimSpace(current[id])
		if sameValue(existing, proposed) {
			continue
		}
		if item.increaseOnly && existing != "" && !isLarger(proposed, existing) {
			continue
		}
		out = append(out, Proposal{
			ID: id, Service: item.service, Param: item.param,
			Current: existing, Proposed: proposed,
			Rationale: item.rationale(facts, proposed),
			File:      item.file, Effect: item.effect,
			Group: item.group, IncreaseOnly: item.increaseOnly,
		})
	}
	return out
}

// sameValue reports whether the host is already at the proposed value.
//
// It compares NUMERICALLY when both sides parse, because the two sides are
// written in different units by different parties. MariaDB reports
// innodb_buffer_pool_size as "4294967296" while this package proposes "4096M"
// (measured: information_schema.SYSTEM_VARIABLES.GLOBAL_VALUE is always bytes).
// A string comparison would find those different forever, so every applied
// MariaDB parameter would be offered again on the next visit, which is exactly
// the screen-nobody-reads failure the equality check exists to prevent.
func sameValue(existing, proposed string) bool {
	left, leftOK := sizeValue(existing)
	right, rightOK := sizeValue(proposed)
	if leftOK && rightOK {
		return left == right
	}
	return existing == proposed
}

// isLarger compares two configuration values numerically, honouring the size
// suffixes MariaDB, nginx and php-fpm all accept.
//
// A value it cannot parse compares as NOT larger, which means the parameter is
// left alone. That is the safe direction: an unparseable current value is one
// somebody wrote deliberately in a form this does not know, and replacing it
// with a computed number is exactly the mistake this function exists to stop.
func isLarger(proposed, existing string) bool {
	left, leftOK := sizeValue(proposed)
	right, rightOK := sizeValue(existing)
	if !leftOK || !rightOK {
		return false
	}
	return left > right
}

// sizeValue parses "512M", "2G", "4096" and the lowercase forms.
func sizeValue(value string) (int64, bool) {
	text := strings.TrimSpace(strings.ToLower(value))
	if text == "" {
		return 0, false
	}
	multiplier := int64(1)
	switch text[len(text)-1] {
	case 'k':
		multiplier, text = 1<<10, text[:len(text)-1]
	case 'm':
		multiplier, text = 1<<20, text[:len(text)-1]
	case 'g':
		multiplier, text = 1<<30, text[:len(text)-1]
	}
	number, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil || number < 0 {
		return 0, false
	}
	return number * multiplier, true
}

// Expand returns the full set of proposals that must be applied for the chosen
// ones, which is the chosen ones plus everything sharing a group with them.
//
// php-fpm's pm.* values are checked against each other when the pool is
// parsed: pm.start_servers must sit between the spare bounds and none of them
// may exceed pm.max_children. Applying one alone produces a configuration
// php-fpm REFUSES, and it refuses at the next start rather than at the write,
// so the screen would report success and the service would not come back.
func Expand(proposals []Proposal, chosen []string) []Proposal {
	wanted := map[string]bool{}
	groups := map[string]bool{}
	for _, id := range chosen {
		wanted[id] = true
	}
	for _, proposal := range proposals {
		if wanted[proposal.ID] && proposal.Group != "" {
			groups[proposal.Group] = true
		}
	}
	var out []Proposal
	for _, proposal := range proposals {
		if wanted[proposal.ID] || (proposal.Group != "" && groups[proposal.Group]) {
			out = append(out, proposal)
		}
	}
	return out
}
