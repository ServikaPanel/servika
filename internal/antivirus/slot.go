package antivirus

// The scan slot, held across PROCESSES.
//
// `scanning` is an atomic in this process's memory, which was the whole answer
// while every scan started inside servika-server. It stops being one the moment
// a systemd timer can run `-av-sweep` as a separate process: that process has
// its own copy of the variable, sees zero, and starts a second clamscan over
// the same trees under one CPU quota, with two av_scans rows both saying
// `running` and nothing to say which is which.
//
// The database is the only thing both processes share, so the slot lives there
// as well. MariaDB's GET_LOCK is used rather than a claim row for one measured
// property: the lock is released when the CONNECTION drops, so a sweep process
// that is killed strands nothing. A row would need a heal, and a heal that runs
// at panel startup would leave the slot held for as long as the panel is down,
// which is exactly when somebody is restarting it to get a scan going again.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

// scanSlotLock is the GET_LOCK name. It is server-wide rather than per-database
// on purpose: MariaDB's named locks are global to the instance, and two panels
// on one server would still be sharing the one ClamAV signature database and
// the one disk.
const scanSlotLock = "servika_av_scan"

// slotHold is a slot that has been taken. Release gives it back.
type slotHold struct {
	conn *sql.Conn
}

// Release hands the slot back. It is safe to call once, from a defer.
//
// The RELEASE_LOCK is issued on the SAME connection that took it, because a
// named lock belongs to a connection and releasing it from another one is a
// no-op that reports success. The connection is then closed whatever the
// release did, since closing it releases the lock anyway.
func (h *slotHold) Release() {
	if h == nil || h.conn == nil {
		return
	}
	// A background context: the caller's may already be cancelled, and the
	// point of this call is to give the slot back rather than to be prompt.
	if _, err := h.conn.ExecContext(context.Background(),
		`DO RELEASE_LOCK(?)`, scanSlotLock); err != nil {
		log.Printf("antivirus: the scan slot could not be released explicitly, "+
			"closing the connection instead: %v", err)
	}
	_ = h.conn.Close()
	h.conn = nil
	scanning.Store(0)
}

// takeScanSlot takes the one scan slot, in this process and on the server.
//
// Both halves are needed and neither replaces the other. The in-process atomic
// is what makes a second request in the same panel cheap to refuse, without a
// round trip. The database lock is what makes a scan started by the timer's own
// process visible to this one.
//
// The atomic is taken FIRST because it is free, and it is given back when the
// database lock cannot be had, or a refused attempt would leave this process
// unable to scan until it restarted.
func takeScanSlot(ctx context.Context, db *sql.DB) (*slotHold, error) {
	if !scanning.CompareAndSwap(0, 1) {
		return nil, errSlotBusy
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		scanning.Store(0)
		return nil, fmt.Errorf("the scan slot could not be reached: %w", err)
	}
	// Timeout 0, never a wait. A caller that cannot have the slot now is
	// answered now: the HTTP handlers report a conflict and the scheduler waits
	// for the next hour, and both are better than an operator watching a
	// request hang for the length of somebody else's sweep.
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		`SELECT GET_LOCK(?, 0)`, scanSlotLock).Scan(&got); err != nil {
		_ = conn.Close()
		scanning.Store(0)
		return nil, fmt.Errorf("the scan slot could not be reached: %w", err)
	}
	// GET_LOCK answers 1 when it was taken, 0 on timeout and NULL on an error.
	// A NULL is NOT treated as free: that direction runs a second scan on a
	// server whose database is already unwell.
	if !got.Valid || got.Int64 != 1 {
		_ = conn.Close()
		scanning.Store(0)
		return nil, errSlotBusy
	}
	return &slotHold{conn: conn}, nil
}

// errSlotBusy means another scan holds the slot, here or in another process.
var errSlotBusy = fmt.Errorf("another scan is in progress")
