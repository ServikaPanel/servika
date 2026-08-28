//go:build linux

package antivirus

// The Linux half of the process watcher: the netlink proc-connector socket, the
// FORK/EXEC/EXIT read loop, the /proc readers, and the notification. Everything
// a test can reach without a live kernel is in procwatch.go.

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
	"servika/internal/chains"
	"servika/internal/db"
	"servika/internal/notifications"

	"golang.org/x/sys/unix"
)

const (
	// procThrottleWindow is how long the same (domain, reason) alert is
	// suppressed, so a burst of execs cannot flood the bell.
	procThrottleWindow = 60 * time.Second
	// procRecordTTL bounds how long a fork record lives, so a missed EXIT event
	// cannot grow pidTable without limit.
	procRecordTTL = 5 * time.Minute
	// procSweepInterval is how often the stale throttle and pid records are
	// dropped, which is what keeps both maps from being a memory-DoS vector.
	procSweepInterval = 30 * time.Second
	// procPidTableCap is a hard ceiling on tracked pids, a second guard beside
	// the TTL sweep.
	procPidTableCap = 200000
	// procRateBurst is the per-tenant token-bucket size and refill-per-second, so
	// one tenant's exec flood cannot drown the root agent in NSS and DB lookups.
	procRateBurst = 5
)

// runProcWatcher opens the database, checks the gate, subscribes to the exec
// stream and reports suspicious execs until stopped. It ENDS with a nil error
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
	// A larger receive buffer reduces ENOBUFS under a heavy fork/exec load.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	if err := subscribeProcConnector(fd); err != nil {
		return fmt.Errorf("PROC_CN_MCAST_LISTEN: %w", err)
	}
	log.Print("process watcher: watching the exec stream (netlink proc connector)")

	w := &procWatcher{
		db:       handle,
		throttle: map[string]time.Time{},
		pidTable: map[int]*pidRecord{},
		uidName:  map[int]string{},
		buckets:  map[int]*bucket{},
	}
	w.loop(fd)
	return nil
}

// loop reads events until an unrecoverable error. EINTR, ENOBUFS and EAGAIN are
// TRANSIENT: the watcher must never die on a single error, because a dead
// watcher is a detection layer that silently went off. Stale records are swept
// on a timer so neither map grows without bound.
func (w *procWatcher) loop(fd int) {
	buf := make([]byte, 16384)
	lastSweep := time.Now()
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				if errors.Is(err, unix.ENOBUFS) {
					log.Print("process watcher: netlink buffer overran (ENOBUFS) — events dropped, continuing")
				}
				continue
			}
			log.Printf("process watcher: netlink read stopped: %v", err)
			return
		}
		// Only KERNEL-sourced events (a netlink peer pid of 0). This rejects a
		// local process injecting a forged event on the same multicast group.
		if nl, ok := from.(*unix.SockaddrNetlink); !ok || nl.Pid != 0 {
			continue
		}
		for _, ev := range parseProcEvents(buf[:n]) {
			w.handleEvent(ev)
		}
		if time.Since(lastSweep) > procSweepInterval {
			w.sweepTables()
			lastSweep = time.Now()
		}
	}
}

// procWatcher holds the database handle and the watcher's in-memory state.
type procWatcher struct {
	db       *sql.DB
	throttle map[string]time.Time // (domain, reason) -> last alert
	pidTable map[int]*pidRecord   // pid -> fork-time ancestry
	uidName  map[int]string       // uid -> username (cache)
	buckets  map[int]*bucket      // uid -> rate-limit bucket
}

// pidRecord is what a FORK event establishes. It beats the reparent race: the
// parent identity and the web-ancestor flag are recorded at fork time, not read
// from /proc later, when a double-fork has already reparented the pid to init.
type pidRecord struct {
	parent int
	web    bool
	born   time.Time
}

// bucket is a per-uid token bucket for the exec-evaluation rate limit.
type bucket struct {
	tokens   int
	refilled time.Time
}

// handleEvent threads a FORK into the ancestry table, drops an EXIT, and
// evaluates an EXEC.
func (w *procWatcher) handleEvent(ev procEvent) {
	switch ev.kind {
	case procEventFork:
		// Compute the child's web-ancestor state at FORK time and propagate it,
		// so a later reparent cannot hide it.
		web := false
		if rec := w.pidTable[ev.parent]; rec != nil {
			web = rec.web
		} else {
			web = w.procIsWeb(ev.parent)
		}
		if len(w.pidTable) < procPidTableCap {
			w.pidTable[ev.pid] = &pidRecord{parent: ev.parent, web: web, born: time.Now()}
		}
	case procEventExit:
		delete(w.pidTable, ev.pid)
	case procEventExec:
		w.evaluate(ev.pid)
	}
}

// evaluate enriches one exec'd PID from /proc, scores it, and reports it when it
// is a tenant process crossing the threshold.
func (w *procWatcher) evaluate(pid int) {
	exe := procExe(pid)
	cmdline := procCmdline(pid)
	uid := procUID(pid)

	// If this process IS a web server, mark it web in the table so the children
	// it forks after this point inherit the web-ancestor flag, even a php-fpm
	// worker respawned mid-session.
	if _, comm := procStat(pid); isWebServer(exe, comm) {
		if rec := w.pidTable[pid]; rec != nil {
			rec.web = true
		} else if len(w.pidTable) < procPidTableCap {
			w.pidTable[pid] = &pidRecord{web: true, born: time.Now()}
		}
	}

	web := false
	if rec := w.pidTable[pid]; rec != nil {
		web = rec.web
	} else {
		web = w.ancestorHasWeb(pid)
	}

	finding := scoreProcess(web, exe, cmdline, uid)
	if finding.score < procScoreSuspicious {
		return
	}
	// Rate limit per tenant uid: an exec flood must not drown the root agent in
	// NSS and DB lookups. A refusal here silently drops the alert.
	if !w.rateAllow(uid) {
		return
	}

	// Only a TENANT context is reported: root and system processes running a
	// shell is normal (cron, the panel itself). The tenant is resolved from the
	// uid, never from the process, exactly as the file scan resolves it from the
	// path.
	username := w.usernameFor(uid)
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

	// The command line and the exe path go to the journal only. They are a
	// tenant's own text and a tenant path, so they never reach the notification.
	log.Printf("process watcher: %s on domain %d (uid %d) exe=%q cmd=%q",
		finding.code, domainID, uid, exe, cmdline)
	w.notify(domainID, finding)

	// Attack-chain event: a process detection is the Execution stage, or C2 for a
	// downloader reaching out. The exe path and the pid are the causal link: an
	// execution whose path equals a dropped file's, or sharing a pid, is a chain
	// rather than two independent signals.
	level := notifications.LevelWarning
	if finding.score >= procScoreCritical {
		level = notifications.LevelCritical
	}
	chains.WriteEvent(w.db, domainID, "process", stageForCode(finding.code), level, "", exeClean(exe), pid, "av_proc", 0)
}

// stageForCode maps a process reason code to its kill-chain stage: a downloader
// reaching a remote URL is C2, everything else is Execution.
func stageForCode(code string) string {
	if code == reasonWebDownloader {
		return "c2"
	}
	return "execution"
}

// notify writes one alert. It carries the domain and, for an untrusted-origin
// finding, the LOCATION kind, never the binary path or the command line: those
// are tenant data and belong in the journal, the same rule the file alerts
// follow.
func (w *procWatcher) notify(domainID int64, f procFinding) {
	ctx := context.Background()
	name := domainName(ctx, w.db, domainID)
	level := notifications.LevelWarning
	if f.score >= procScoreCritical {
		level = notifications.LevelCritical
	}
	event := notifications.Event{
		Level:    level,
		Category: notifyCategory,
		Title:    "Suspicious process activity",
		Key:      "procwatch." + f.code,
		DomainID: &domainID,
		RefType:  "av_proc",
	}
	switch f.code {
	case reasonUntrustedOrigin:
		event.Message = fmt.Sprintf("A process ran from an untrusted location (%s) on %s.", f.category, name)
		event.Params = map[string]any{"domain": name, "location": f.category}
	case reasonWebDownloader:
		event.Message = fmt.Sprintf("A web process started a remote download on %s.", name)
		event.Params = map[string]any{"domain": name}
	default:
		event.Message = fmt.Sprintf("A web process ran a suspicious command on %s.", name)
		event.Params = map[string]any{"domain": name}
	}
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

// procIsWeb classifies a pid from /proc for the fork-time cache fill.
func (w *procWatcher) procIsWeb(pid int) bool {
	_, comm := procStat(pid)
	return isWebServer(procExe(pid), comm)
}

// ancestorHasWeb walks a pid's ancestry (the fork-time cache first, /proc as a
// fallback) for a web server, at most 8 levels. On a reparent the cache still
// holds the fork-time parent, so the chain is not lost.
func (w *procWatcher) ancestorHasWeb(pid int) bool {
	for i := 0; i < 8 && pid > 1; i++ {
		if rec := w.pidTable[pid]; rec != nil {
			if rec.web {
				return true
			}
			pid = rec.parent
			continue
		}
		ppid, comm := procStat(pid)
		if isWebServer(procExe(pid), comm) {
			return true
		}
		if ppid <= 1 {
			break
		}
		pid = ppid
	}
	return false
}

// rateAllow is a coarse per-uid token bucket (about procRateBurst per second).
func (w *procWatcher) rateAllow(uid int) bool {
	b := w.buckets[uid]
	now := time.Now()
	if b == nil {
		b = &bucket{tokens: procRateBurst, refilled: now}
		w.buckets[uid] = b
	}
	if refill := int(now.Sub(b.refilled).Seconds()) * procRateBurst; refill > 0 {
		b.tokens += refill
		if b.tokens > procRateBurst {
			b.tokens = procRateBurst
		}
		b.refilled = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// usernameFor resolves a uid to a username through a cache.
func (w *procWatcher) usernameFor(uid int) string {
	if uid < 0 {
		return ""
	}
	if name, ok := w.uidName[uid]; ok {
		return name
	}
	name := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name = u.Username
	}
	w.uidName[uid] = name
	return name
}

// sweepTables drops stale throttle and pid records, which is what keeps both
// maps from growing without bound.
func (w *procWatcher) sweepTables() {
	now := time.Now()
	for k, t := range w.throttle {
		if now.Sub(t) > procThrottleWindow {
			delete(w.throttle, k)
		}
	}
	for pid, rec := range w.pidTable {
		if now.Sub(rec.born) > procRecordTTL {
			delete(w.pidTable, pid)
		}
	}
	// A bucket at full tokens carries no state worth keeping.
	for uid, b := range w.buckets {
		if b.tokens >= procRateBurst {
			delete(w.buckets, uid)
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

// procCmdline reads /proc/<pid>/cmdline (NUL-separated) and joins it with
// spaces for the suspicious-token scan.
func procCmdline(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(b) == 0 {
		return ""
	}
	trimmed := strings.TrimRight(string(b), "\x00")
	return strings.ReplaceAll(trimmed, "\x00", " ")
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
