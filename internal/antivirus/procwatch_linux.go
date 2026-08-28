//go:build linux

package antivirus

// The Linux half of the process watcher: the netlink proc-connector socket, the
// read loop, the /proc readers, and the notification. Everything a test can
// reach without a live kernel is in procwatch.go.

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"servika/internal/avsettings"
	"servika/internal/db"
	"servika/internal/notifications"

	"golang.org/x/sys/unix"
)

// procThrottleWindow is how long the same (domain, reason) alert is suppressed,
// so a burst of execs cannot flood the bell.
const procThrottleWindow = 60 * time.Second

// runProcWatcher opens the database, checks the gate, subscribes to the exec
// stream and reports suspicious chains until stopped. It ENDS with a nil error
// when the feature is off, so systemd's Restart=on-failure does not bring it
// straight back, exactly like the file watcher.
func runProcWatcher() error {
	dsn := strings.TrimSpace(os.Getenv("SERVIKA_DB_DSN"))
	if dsn == "" {
		return errors.New("SERVIKA_DB_DSN is required")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = handle.Close() }()

	settings, err := avsettings.Read(context.Background(), handle)
	if err != nil {
		return fmt.Errorf("antivirus settings: %w", err)
	}
	if !settings.ProcessMonitor {
		log.Print("process watcher: process monitoring is off in the antivirus settings")
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w (CAP_NET_ADMIN is required)", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	if err := subscribeProcConnector(fd); err != nil {
		return fmt.Errorf("PROC_CN_MCAST_LISTEN: %w", err)
	}
	log.Print("process watcher: watching the exec stream (netlink proc connector)")

	w := &procWatcher{db: handle, throttle: map[string]time.Time{}}
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("netlink read: %w", err)
		}
		for _, pid := range execPIDs(buf[:n]) {
			w.evaluate(pid)
		}
	}
}

// subscribeProcConnector sends PROC_CN_MCAST_LISTEN so the kernel starts
// delivering process events on the bound socket.
func subscribeProcConnector(fd int) error {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint32(body[0:], cnIdxProc) // id.idx
	binary.LittleEndian.PutUint32(body[4:], cnValProc) // id.val
	binary.LittleEndian.PutUint32(body[8:], 0)         // seq
	binary.LittleEndian.PutUint32(body[12:], 0)        // ack
	binary.LittleEndian.PutUint16(body[16:], 4)        // len
	binary.LittleEndian.PutUint16(body[18:], 0)        // flags
	binary.LittleEndian.PutUint32(body[20:], procCNMcastListen)
	msg := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], uint16(unix.NLMSG_DONE))
	binary.LittleEndian.PutUint16(msg[6:], 0)
	binary.LittleEndian.PutUint32(msg[8:], 0)
	binary.LittleEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	copy(msg[16:], body)
	return unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// procWatcher holds the database handle and the per-(domain, reason) throttle.
type procWatcher struct {
	db       *sql.DB
	throttle map[string]time.Time
}

// evaluate enriches one exec'd PID from /proc, scores it, and reports it when it
// is a tenant process crossing the threshold.
func (w *procWatcher) evaluate(pid int) {
	ppid, comm := procStat(pid)
	if comm == "" {
		return
	}
	parentComm := ""
	if ppid > 0 {
		_, parentComm = procStat(ppid)
	}
	uid := procUID(pid)
	finding := scoreProcess(parentComm, comm, procExe(pid), uid)
	if finding.score < procScoreSuspicious {
		return
	}

	// Only a TENANT context is reported: root and system processes opening a
	// shell is normal (cron, the panel itself). The tenant is resolved from the
	// uid, never from the process, exactly as the file scan resolves it from the
	// path.
	username := uidToUsername(uid)
	if !strings.HasPrefix(username, "c_") {
		return
	}
	domainID := w.domainForSystemUser(username)
	if domainID == 0 {
		return
	}

	key := strconv.FormatInt(domainID, 10) + ":" + finding.code
	now := time.Now()
	if last, ok := w.throttle[key]; ok && now.Sub(last) < procThrottleWindow {
		return
	}
	w.throttle[key] = now

	w.notify(domainID, finding)
}

// notify writes one alert. It carries the parent and child program names, or the
// world-writable DIRECTORY, never the full binary path: a path is a tenant path
// and belongs on the antivirus page, not in the bell, the same rule the file
// alerts follow.
func (w *procWatcher) notify(domainID int64, f procFinding) {
	ctx := context.Background()
	name := domainName(ctx, w.db, domainID)
	event := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: notifyCategory,
		Title:    "Suspicious process activity",
		Key:      "procwatch." + f.code,
		DomainID: &domainID,
		RefType:  "av_proc",
	}
	switch f.code {
	case reasonWorldWritable:
		event.Message = fmt.Sprintf("A process ran from a world-writable directory (%s) on %s.", f.dir, name)
		event.Params = map[string]any{"domain": name, "dir": f.dir}
	default:
		event.Message = fmt.Sprintf("A web process (%s) started %s on %s.", f.parent, f.child, name)
		event.Params = map[string]any{"domain": name, "parent": f.parent, "child": f.child}
	}
	log.Printf("process watcher: %s on domain %d (%s)", f.code, domainID, name)
	if err := notifications.Write(ctx, w.db, event); err != nil {
		log.Printf("process watcher: the alert for domain %d could not be written: %v", domainID, err)
	}
}

// domainForSystemUser resolves a c_<user> account to its top-level domain id,
// narrowing to parent_domain_id IS NULL because an addon or subdomain row
// repeats its parent's system user, exactly like the sweep's owner lookup.
func (w *procWatcher) domainForSystemUser(username string) int64 {
	var id int64
	err := w.db.QueryRow(
		`SELECT id FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1`, username).
		Scan(&id)
	if err != nil {
		return 0
	}
	return id
}

// ── /proc readers (root reads any process; a tenant's stat is world-readable) ──

func procStat(pid int) (ppid int, comm string) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, ""
	}
	return parseStat(string(b))
}

func procExe(pid int) string {
	target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return target
}

func procUID(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) >= 1 {
				if u, e := strconv.Atoi(fields[0]); e == nil {
					return u
				}
			}
		}
	}
	return -1
}

func uidToUsername(uid int) string {
	if uid < 0 {
		return ""
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return ""
}
