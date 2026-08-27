package provisioner

// Watching a tenant's PHP-FPM master AFTER it has started.
//
// EnableTenantFPM waits for the socket to appear and stops there. A master that
// starts, opens its socket and THEN dies (a SIGSYS from a sandbox directive, an
// extension that faults, an ini value php-fpm -t accepts and the interpreter
// does not) is caught by nothing: the save returns success and the site stays
// 502. Every failure branch inside EnableTenantFPM already calls
// RollbackToSharedFPM; what was missing is the window after the restart.
//
// The guard runs ASYNCHRONOUSLY and always will. The upstream design this came
// from ran the same check synchronously and measured every PHP settings save
// blocking for 15.9 seconds because of it. Nothing here is on the request path.
//
// Three facts were measured against real systemd 257 on AlmaLinux 10, and each
// one decides part of this file.
//
//   - A manual `systemctl restart` RESETS NRestarts to 0 (measured: 2 before,
//     0 immediately after). EnableTenantFPM restarts the unit itself, so the
//     baseline is zero and no reading has to be taken before the window opens.
//   - With the StartLimit keys this unit now carries, a crash-loop reaches
//     `failed` after 15 seconds with NRestarts=5. That is exactly the window
//     upstream chose, which leaves no margin at all: a poll landing a second
//     early would miss it. The window here is wider for that reason, and being
//     asynchronous it costs the operator nothing.
//   - WITHOUT those keys the same loop never reaches `failed` at all (measured:
//     ActiveState=activating, SubState=auto-restart, NRestarts=7 after 25
//     seconds), because each restart takes RestartSec plus the run, so too few
//     starts land inside systemd's default ten-second window to trip it. The
//     unit is fixed, but a host carrying an older unit file until the next heal
//     is exactly the host this guard is for, so `failed` is not the only signal.

import (
	"database/sql"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// fpmPostStartWindow is how long a freshly restarted master is watched.
	// Measured: a crash-loop reaches `failed` at 15 seconds, so this leaves ten
	// seconds of margin rather than landing on the boundary.
	fpmPostStartWindow = 25 * time.Second
	// fpmCrashLoopRestarts is how many restarts inside the window count as a
	// loop. One is a master that died and came back, which is worth a line in
	// the log and not worth taking a tenant's isolation away for; two is a
	// pattern.
	fpmCrashLoopRestarts = 2
)

// fpmPostStartPoll is a variable so a test can lower it; exercising the decision
// at the shipped interval costs a second per state and buys nothing, since what
// is being measured is which state leads to a rollback rather than how long the
// sleep is. A separate test asserts the shipped value.
var fpmPostStartPoll = time.Second

// fpmUnitState is what systemd says about a tenant master right now.
//
// Known separates "systemd answered" from "the unit is fine". A read that fails
// must never be weighed as evidence, because the only thing this file does with
// evidence is take a tenant's isolation away.
type fpmUnitState struct {
	ActiveState string
	SubState    string
	Restarts    int
	Known       bool
}

// readFPMUnitState is a variable so the decision below can be measured without a
// systemd, following internal/antivirus.reputationResolver and the injected
// dialer in internal/geoip. The parsing shape is the one internal/apps,
// internal/hostapps and internal/laravel already use.
var readFPMUnitState = func(systemUser string) fpmUnitState {
	output, err := tenantCommand("systemctl", "show",
		"-p", "ActiveState", "-p", "SubState", "-p", "NRestarts",
		tenantUnitName(systemUser)).Output()
	if err != nil {
		return fpmUnitState{}
	}
	state := fpmUnitState{Known: true}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "ActiveState":
			state.ActiveState = value
		case "SubState":
			state.SubState = value
		case "NRestarts":
			// A value systemd did not give as a number leaves the count at zero
			// rather than inventing one, because this number drives a rollback.
			if n, convErr := strconv.Atoi(value); convErr == nil {
				state.Restarts = n
			}
		}
	}
	return state
}

// crashLooping reports whether a state is evidence the master cannot stay up.
//
// `failed` is systemd having given up, which is unambiguous and the site is
// already 502. The restart count is the second signal and it is not redundant:
// measured, a unit without the StartLimit keys loops forever without ever
// reaching `failed`, so a host still carrying an older unit file would show
// nothing but `activating`.
func crashLooping(state fpmUnitState) bool {
	if !state.Known {
		return false
	}
	if state.ActiveState == "failed" {
		return true
	}
	return state.Restarts >= fpmCrashLoopRestarts
}

// rollbackTenantFPM is a variable for the same reason readFPMUnitState is: the
// real one disables a unit, deletes files under /etc and moves a pool back, so a
// test of the DECISION must not be able to reach it.
var rollbackTenantFPM = RollbackToSharedFPM

// fpmGuardActive keeps one guard per tenant. Two saves in quick succession would
// otherwise run two windows over one unit and race two rollbacks, and a rollback
// is not idempotent with an enable happening beside it.
var fpmGuardActive sync.Map

func fpmGuardStart(systemUser string) bool {
	_, loaded := fpmGuardActive.LoadOrStore(systemUser, struct{}{})
	return !loaded
}

func fpmGuardEnd(systemUser string) { fpmGuardActive.Delete(systemUser) }

// guardPostStart watches a freshly started tenant master and puts the domain
// back on the shared pool when it cannot stay up.
//
// It returns nil when the tenant is healthy or when nothing could be measured.
// An unreadable state is deliberately NOT treated as a fault, which is the
// opposite of the fail-closed rule the authorization checks follow: this is an
// automatic remediation rather than a boundary, and its failure mode is removing
// a working tenant's isolation because systemctl hiccuped once.
func guardPostStart(db *sql.DB, domainID int64, systemUser, phpVersion string, window time.Duration) error {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		time.Sleep(fpmPostStartPoll)
		state := readFPMUnitState(systemUser)
		if !crashLooping(state) {
			continue
		}
		if err := rollbackTenantFPM(db, domainID, systemUser, phpVersion); err != nil {
			// The tenant is on neither a working isolated master nor a working
			// shared pool, which is the one state an operator has to be told
			// about by name.
			log.Printf("tenant PHP-FPM %s crash-looped (%s/%s, %d restarts) and the rollback FAILED: %v",
				systemUser, state.ActiveState, state.SubState, state.Restarts, err)
			return err
		}
		log.Printf("tenant PHP-FPM %s crash-looped (%s/%s, %d restarts); the domain is back on the shared pool and has lost its isolation",
			systemUser, state.ActiveState, state.SubState, state.Restarts)
		return errFPMCrashLoop
	}
	return nil
}

// errFPMCrashLoop says the guard acted. It is never returned to an HTTP caller,
// because by the time it exists the response has long been written; it exists so
// a test can tell "rolled back" from "healthy" without reading the log.
var errFPMCrashLoop = &fpmCrashLoopError{}

type fpmCrashLoopError struct{}

func (*fpmCrashLoopError) Error() string {
	return "tenant PHP-FPM crash-looped after start and was rolled back to the shared pool"
}

// guardWanted says whether there is anything to watch FOR.
//
// The only action the guard can take is RollbackToSharedFPM, which needs both a
// database handle and a domain, so a caller without them would be watched by a
// guard that could never act. It is a function rather than an inline condition
// so the rule can be measured without reaching EnableTenantFPM, which writes
// files under /etc and runs systemctl.
func guardWanted(db *sql.DB, domainID int64) bool {
	return db != nil && domainID > 0
}

// EnableTenantFPMGuarded moves a domain to its own PHP-FPM master and then
// watches it, without making the caller wait for the watching.
//
// This is a separate function rather than a flag on EnableTenantFPM so each call
// site says what it wants. The startup and drift paths deliberately keep calling
// the plain one: a boot that starts one guard goroutine per tenant, every one of
// them able to remove a tenant's isolation, is a different thing from an
// operator saving one domain's PHP settings.
func EnableTenantFPMGuarded(db *sql.DB, domainID int64, systemUser, phpVersion string) (string, error) {
	socket, err := EnableTenantFPM(db, domainID, systemUser, phpVersion)
	if err != nil {
		return socket, err
	}
	if !guardWanted(db, domainID) {
		return socket, nil
	}
	if fpmGuardStart(systemUser) {
		go func() {
			defer fpmGuardEnd(systemUser)
			_ = guardPostStart(db, domainID, systemUser, phpVersion, fpmPostStartWindow)
		}()
	}
	return socket, nil
}
