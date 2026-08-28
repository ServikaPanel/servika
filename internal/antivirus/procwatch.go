package antivirus

// The process-behaviour watcher subscribes to the kernel's exec stream and
// reports a tenant process whose EXECUTION is suspicious. It is the file
// watcher's sibling and answers a question no file scan can: a webshell that
// never touches disk still has to exec something, and this is where that exec
// is seen.
//
// It is NOTIFICATION-ONLY and never kills a process: the whole panel treats
// antivirus as a reporter, and a false positive that killed a customer's own
// cron job would be worse than the thing it guards against. Killing a process
// belongs to a later phase gated on high confidence and an operator policy.
//
// The scoring model is NOT a comm denylist. The first design keyed on the
// parent's and the child's comm ("php-fpm" -> "sh"), which was both noisy and
// trivially bypassed. It was noisy because PHP mail() runs popen("/bin/sh -c
// sendmail"), so every e-mail scored as web-parent -> shell. It was bypassed
// because a comm is a name the process chooses: `cp /bin/bash .../nginx` and
// run it. The model here keys on the EXECUTED BINARY's real path and its
// command line, with the web-ancestor established at FORK time (not read from
// /proc at exec time, which a double-fork reparents away). comm is only a hint
// used to classify a web server.
//
// This file is the pure, cross-platform core: the scoring, the /proc/<pid>/stat
// parse, and the netlink message parse, all testable without a live socket. The
// socket loop and the /proc readers are Linux-only (procwatch_linux.go), because
// the netlink proc connector is a Linux facility.

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// procWatchFlag is the argv that runs `servika-server -proc-watch`.
const procWatchFlag = "proc-watch"

const (
	// procScoreSuspicious is the score at or above which a chain is reported.
	procScoreSuspicious = 30
	// procScoreCritical is a verdict of its own: an untrusted-origin execution
	// or a web process running a suspicious command. Automatic action never
	// happens (this is notification-only), so this only decides the alert level.
	procScoreCritical = 40
	// procScoreDownloader sits between the two: a real download pipe from a web
	// process is worth a warning but not a critical.
	procScoreDownloader = 35
)

// The three reason codes a finding carries. They name a frontend string
// (`notify.procwatch.<code>`) so the alert is worded in the reader's language,
// the same contract the file-scan alerts use.
const (
	// reasonUntrustedOrigin: the executed binary sits where no legitimate program
	// runs from. It ignores comm, so renaming a shell or dropping an ELF into the
	// document root does not evade it.
	reasonUntrustedOrigin = "untrustedOrigin"
	// reasonWebShellCmd: a web process ran a shell or interpreter with a command
	// line carrying a download-and-run, reverse-shell or obfuscation indicator. A
	// legitimate shell-out (sendmail, mysqldump, convert) carries none of those.
	reasonWebShellCmd = "webShellCmd"
	// reasonWebDownloader: a web process ran a downloader against a remote URL.
	reasonWebDownloader = "webDownloader"
	// reasonWebPersistence: a web process touched a persistence surface (cron, a
	// shell startup file, an SSH authorized_keys, a service enable). Legitimate
	// persistence is set up over SSH or from the panel as root, never from a
	// php-fpm child, so this is a strong signal in a web context.
	reasonWebPersistence = "webPersistence"
)

// netlink proc connector constants (linux/connector.h, linux/cn_proc.h).
const (
	cnIdxProc         = 0x1
	cnValProc         = 0x1
	procCNMcastListen = 1
	procEventFork     = 0x00000001
	procEventExec     = 0x00000002
	procEventExit     = 0x80000000
)

var (
	// procWebServers are the server processes whose descendants are watched. The
	// comm values come from /proc, which truncates to 15 characters; every name
	// here is under that, and "php-fpm: pool x" truncates to "php-fpm".
	procWebServers = []string{
		"php-fpm", "php-cgi", "lsphp", "httpd", "apache2", "apache", "nginx", "litespeed",
	}
	procShellsAndInterpreters = map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "busybox": true,
		"php": true, "php-cgi": true, "python": true, "python2": true, "python3": true,
		"perl": true, "ruby": true, "node": true, "lua": true,
	}
	procDownloaders = map[string]bool{
		"curl": true, "wget": true, "fetch": true, "aria2c": true,
		"nc": true, "ncat": true, "socat": true,
	}
	// procSuspiciousTokens are the command-line shapes of a download-and-run, a
	// reverse shell, or an obfuscation stage. A legitimate shell-out (sendmail,
	// mysqldump, tar, convert) carries none of them, which is what keeps a PHP
	// mail() from firing.
	procSuspiciousTokens = []string{
		"curl ", "wget ", "|sh", "| sh", "|bash", "| bash", "bash -i", "sh -i",
		"/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "-e /bin/", "mkfifo",
		"base64 -d", "base64 --decode", "gzip -d", "xxd -r",
		"python -c", "python3 -c", "perl -e", "perl -mio", "ruby -e", "php -r",
		"chmod +x", "chmod 777", "wget -o", "curl -o",
		"setsid", "0<&", ">&/dev/tcp", "eval(", "$(curl", "$(wget", "`curl", "`wget",
	}
	// procPersistencePaths are the FILES a persistence attempt writes to: a cron
	// spool, a shell startup file, an SSH authorized_keys, a systemd unit, a PHP
	// auto-prepend surface. crontab is NOT here, because it is a verb handled
	// separately. A php-fpm child never sets these up legitimately (that is done
	// over SSH or from the panel as root), so a web-ancestored process WRITING
	// one is a strong compromise signal. Reading one (cat, grep, tar) is not, so
	// a write operator before the path is required, see cmdlinePersistence.
	procPersistencePaths = []string{
		"/etc/cron", "/var/spool/cron", "/etc/rc.local", ".bashrc",
		".bash_profile", ".profile", "authorized_keys", "/etc/systemd/system",
		"/etc/ld.so.preload", ".user.ini", ".htaccess", "auto_prepend",
	}
)

// procFinding is one weighed exec. An empty code means nothing fired. category
// is set only for reasonUntrustedOrigin and names the LOCATION kind, never the
// binary path, because a path is a tenant path and never goes in a notification.
type procFinding struct {
	score    int
	code     string
	category string
}

// scoreProcess weighs one exec. It keys on the executed binary's real path and
// its command line, never on comm, and is pure so a test can drive every branch
// without a running kernel.
//
// R1 (untrusted origin) fires for a web-ancestored process OR any tenant
// (uid >= 1000), because a binary run from /tmp or the document root is a
// dropped payload whoever launched it. R2 and R3 need a web ancestor, because a
// tenant running a shell from their own SSH session is their own business.
func scoreProcess(web bool, exe, cmdline string, uid int) procFinding {
	if cat := originCategory(exe); cat != "" && (web || uid >= 1000) {
		return procFinding{score: procScoreCritical, code: reasonUntrustedOrigin, category: cat}
	}
	if !web {
		return procFinding{}
	}
	clean := exeClean(exe)
	if isShellOrInterpreter(clean) && cmdlineSuspicious(cmdline) {
		return procFinding{score: procScoreCritical, code: reasonWebShellCmd}
	}
	if isDownloader(clean) && cmdlineRemoteURL(cmdline) {
		return procFinding{score: procScoreDownloader, code: reasonWebDownloader}
	}
	if cmdlinePersistence(cmdline) {
		return procFinding{score: procScoreCritical, code: reasonWebPersistence}
	}
	return procFinding{}
}

// originCategory names the untrusted location a binary runs from, or "" when the
// location is legitimate. The set is narrowed for Servika: the volatile
// directories, memfd and a deleted image are ALWAYS untrusted because no
// legitimate program runs from them, but only the tenant's document root
// (`/public_html/`) counts under /home. A blanket /home rule would flag every
// panel-created Node or Python application, which runs its own binary from
// `/home/<user>/<app>/.venv/bin` or `node_modules/.bin`.
func originCategory(exe string) string {
	if exe == "" {
		return ""
	}
	if strings.HasPrefix(exe, "/memfd:") {
		return "memfd"
	}
	if strings.HasSuffix(exe, " (deleted)") {
		return "deleted"
	}
	p := filepath.ToSlash(exe)
	switch {
	case strings.HasPrefix(p, "/tmp/"):
		return "tmp"
	case strings.HasPrefix(p, "/dev/shm/"):
		return "shm"
	case strings.HasPrefix(p, "/var/tmp/"):
		return "var_tmp"
	case strings.Contains(p, "/public_html/"):
		return "public_html"
	}
	return ""
}

func isShellOrInterpreter(exe string) bool {
	return procShellsAndInterpreters[filepath.Base(exe)]
}

func isDownloader(exe string) bool {
	return procDownloaders[filepath.Base(exe)]
}

// cmdlineSuspicious reports whether the command line carries a download-and-run,
// reverse-shell or obfuscation indicator. A legitimate shell-out carries none,
// which is what stops a PHP mail() (sh -c sendmail) from firing.
func cmdlineSuspicious(cmdline string) bool {
	l := strings.ToLower(cmdline)
	for _, t := range procSuspiciousTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

func cmdlineRemoteURL(cmdline string) bool {
	l := strings.ToLower(cmdline)
	return strings.Contains(l, "http://") || strings.Contains(l, "https://") ||
		strings.Contains(l, "ftp://")
}

// cmdlinePersistence reports whether the command line ESTABLISHES persistence,
// not merely reads a persistence surface. A pure read (crontab -l, cat .bashrc,
// grep /etc/cron, tar of /var/spool/cron) is a false positive, so a WRITE is
// required: a direct persistence verb, or a write operator standing BEFORE the
// target path. A web ancestor is the caller's guard, so a tenant editing their
// own cron over SSH is their own business, but a php-fpm child is not.
func cmdlinePersistence(cmdline string) bool {
	l := strings.ToLower(cmdline)
	// Direct persistence verbs. crontab -l (list) and crontab -e (editor) are
	// reads or interactive, so they are excluded; crontab <file> and crontab -
	// install a table and are not.
	if strings.Contains(l, "systemctl enable") || strings.Contains(l, "chkconfig ") ||
		strings.Contains(l, "update-rc.d") ||
		(strings.Contains(l, "crontab") && !strings.Contains(l, "crontab -l") && !strings.Contains(l, "crontab -e")) {
		return true
	}
	// Writing a persistence file: a write operator must stand BEFORE the path, so
	// an unrelated redirect after it (`>/dev/null 2>&1`) is not counted, and a
	// read that merely names the path (cat, grep, tar) is not either.
	for _, path := range procPersistencePaths {
		before, _, found := strings.Cut(l, path)
		if !found {
			continue
		}
		if strings.Contains(before, ">>") || strings.Contains(before, ">") ||
			strings.Contains(before, "tee ") || strings.Contains(before, "install -") {
			return true
		}
	}
	return false
}

// exeClean strips the " (deleted)" suffix the kernel appends to a removed
// image's readlink, so the base-name checks see the real program name.
func exeClean(exe string) string { return strings.TrimSuffix(exe, " (deleted)") }

// isWebServer reports whether an exe path or a comm names a web server or PHP
// handler. It is the one place comm is consulted, and only to classify a
// web-ancestor, never to convict.
func isWebServer(exe, comm string) bool {
	base := filepath.Base(exeClean(exe))
	for _, w := range procWebServers {
		if base == w || comm == w {
			return true
		}
	}
	// "php-fpm: pool x" truncates to a comm of "php-fpm"; the base is "php-fpm".
	return strings.HasPrefix(comm, "php-fpm") || strings.HasPrefix(base, "php-fpm")
}

// parseStat reads (ppid, comm) from a /proc/<pid>/stat line.
//
// comm is wrapped in parentheses and MAY ITSELF contain spaces and parentheses
// (a process can call itself "(evil) x"), so it is taken from the FIRST '(' to
// the LAST ')', never by splitting on whitespace. That is the classic trap this
// parse exists to avoid; the fields after the last ')' are positional and start
// with state, then ppid.
func parseStat(s string) (ppid int, comm string) {
	a := strings.IndexByte(s, '(')
	z := strings.LastIndexByte(s, ')')
	if a < 0 || z < 0 || z <= a {
		return 0, ""
	}
	comm = s[a+1 : z]
	fields := strings.Fields(s[z+1:]) // state ppid pgrp ...
	if len(fields) >= 2 {
		ppid = atoiSafe(fields[1])
	}
	return ppid, comm
}

// procEvent is one parsed FORK, EXEC or EXIT event. parent is meaningful only
// for a FORK (the parent pid); for EXEC and EXIT it is 0.
type procEvent struct {
	kind   uint32
	pid    int
	parent int
}

// parseProcEvents extracts FORK, EXEC and EXIT events from a netlink connector
// buffer.
//
// Layout: nlmsghdr(16) + cn_msg(20) + proc_event{ what(4) cpu(4) timestamp(8) =
// 16 + event data }. The connector id (cn_msg.id.idx/val) is validated so a
// message for another connector is skipped, and control messages (NLMSG_ERROR,
// NLMSG_NOOP) are skipped. EXEC data is process_pid(4) process_tgid(4); FORK
// data is parent_pid(4) parent_tgid(4) child_pid(4) child_tgid(4); EXIT data
// starts with process_pid(4). The length is validated at every step, because
// this buffer comes from the kernel but a short or malformed message must
// advance or stop rather than read past the end.
func parseProcEvents(buf []byte) []procEvent {
	var out []procEvent
	for len(buf) >= 16 {
		nlLen := binary.LittleEndian.Uint32(buf[0:])
		if nlLen < 16 || int(nlLen) > len(buf) {
			break
		}
		nlType := binary.LittleEndian.Uint16(buf[4:])
		p := buf[16:nlLen] // cn_msg + proc_event
		if ev, ok := parseOneEvent(nlType, p); ok {
			out = append(out, ev)
		}
		adv := (nlLen + 3) &^ 3 // align to 4 bytes
		if adv == 0 || int(adv) >= len(buf) {
			break
		}
		buf = buf[adv:]
	}
	return out
}

// parseOneEvent decodes a single connector payload into a procEvent. It returns
// ok=false for a control message, a foreign connector id, a short payload, or an
// event kind this watcher does not track.
func parseOneEvent(nlType uint16, p []byte) (procEvent, bool) {
	const nlmsgError, nlmsgNoop = 0x2, 0x1
	if nlType == nlmsgError || nlType == nlmsgNoop {
		return procEvent{}, false
	}
	if len(p) < 20+16+8 {
		return procEvent{}, false
	}
	if binary.LittleEndian.Uint32(p[0:]) != cnIdxProc || binary.LittleEndian.Uint32(p[4:]) != cnValProc {
		return procEvent{}, false
	}
	what := binary.LittleEndian.Uint32(p[20:])
	data := p[20+16:] // event_data
	switch what {
	case procEventExec:
		if pid := wirePID(data[0:]); pid > 0 {
			return procEvent{kind: procEventExec, pid: pid}, true
		}
	case procEventFork:
		if len(data) >= 16 {
			parent := wirePID(data[0:]) // parent_pid
			child := wirePID(data[8:])  // child_pid
			if child > 0 {
				return procEvent{kind: procEventFork, pid: child, parent: parent}, true
			}
		}
	case procEventExit:
		if pid := wirePID(data[0:]); pid > 0 {
			return procEvent{kind: procEventExit, pid: pid}, true
		}
	}
	return procEvent{}, false
}

// wirePID reads a pid from the wire. process_pid is the kernel's signed
// __kernel_pid_t, so reinterpreting the 32-bit value as int32 is correct, not a
// truncation; callers drop any non-positive reading.
func wirePID(b []byte) int {
	// #nosec G115 -- deliberate signed reinterpretation of a kernel pid
	return int(int32(binary.LittleEndian.Uint32(b)))
}

// atoiSafe parses a base-10 int, returning 0 on any error, which is the right
// default for a missing ppid.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// RunProcWatcherIfAsked runs the process watcher when argv asks for it, exactly
// like RunWatcherIfAsked, and reports whether it handled the invocation so main
// can return.
func RunProcWatcherIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-"+procWatchFlag && os.Args[1] != "--"+procWatchFlag) {
		return false
	}
	if err := runProcWatcher(); err != nil {
		fmt.Fprintf(os.Stderr, "process watcher: %v\n", err)
		os.Exit(1)
	}
	return true
}
