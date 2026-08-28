package antivirus

// The process-behaviour watcher subscribes to the kernel's exec stream and
// reports a suspicious parent -> child chain: a web process (php-fpm, nginx,
// apache) starting a shell or a downloader, or any process running from a
// world-writable directory. It is the file watcher's sibling and answers a
// question no file scan can: a webshell that never touches disk still has to
// exec something, and this is where that exec is seen.
//
// It is NOTIFICATION-ONLY and never kills a process: the whole panel treats
// antivirus as a reporter, and a false positive that killed a customer's own
// cron job would be worse than the thing it guards against. Killing a process
// belongs to a later phase gated on high confidence and an operator policy.
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
	// procScoreSuspicious is the score at or above which a chain is reported. A
	// downloader from a web process scores below it on its own: it is real
	// signal but not, by itself, worth an alert, the same weak-evidence idea the
	// content rules follow.
	procScoreSuspicious = 30
	// procWebShellScore, procDownloaderScore and procWorldWritableScore are the
	// three signals this watcher weighs.
	procWebShellScore      = 30
	procDownloaderScore    = 20
	procWorldWritableScore = 30
)

// The three reason codes a finding carries. They name a frontend string
// (`notify.procwatch.<code>`) so the alert is worded in the reader's language,
// the same contract the file-scan alerts use.
const (
	reasonWebShell      = "webShell"
	reasonWebDownloader = "webDownloader"
	reasonWorldWritable = "worldWritable"
)

// netlink proc connector constants (linux/connector.h, linux/cn_proc.h).
const (
	cnIdxProc         = 0x1
	cnValProc         = 0x1
	procCNMcastListen = 1
	procEventExec     = 0x00000002
)

var (
	// procWebParents are the server processes that should never spawn a shell.
	// The comm values come from /proc, which truncates to 15 characters; every
	// name here is under that.
	procWebParents = map[string]bool{
		"php-fpm": true, "php": true, "php-cgi": true, "lsphp": true,
		"httpd": true, "apache2": true, "apache": true, "nginx": true, "litespeed": true,
	}
	procShells = map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	}
	procDownloaders = map[string]bool{
		"curl": true, "wget": true, "fetch": true, "python": true, "python3": true,
		"perl": true, "ruby": true, "nc": true, "ncat": true, "socat": true,
	}
	// procWorldWritableDirs are the directories a tenant can write to and then
	// execute from, which is the shape of a payload staged and run in place.
	procWorldWritableDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
)

// procFinding is one weighed exec chain. An empty code means nothing fired.
type procFinding struct {
	score  int
	code   string
	parent string
	child  string
	dir    string
}

// scoreProcess weighs a parent -> child exec chain. It is pure so a test can
// drive every branch without a running kernel.
func scoreProcess(parent, child, exePath string, uid int) procFinding {
	web := procWebParents[parent]
	switch {
	case web && procShells[child]:
		return procFinding{score: procWebShellScore, code: reasonWebShell, parent: parent, child: child}
	case web && procDownloaders[child]:
		return procFinding{score: procDownloaderScore, code: reasonWebDownloader, parent: parent, child: child}
	case worldWritable(exePath) && (web || uid >= 1000):
		return procFinding{score: procWorldWritableScore, code: reasonWorldWritable, dir: worldWritablePrefix(exePath)}
	}
	return procFinding{}
}

// worldWritable reports whether the executed binary sits in a directory a tenant
// can write to.
func worldWritable(path string) bool {
	p := filepath.ToSlash(path)
	for _, d := range procWorldWritableDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// worldWritablePrefix returns the world-writable directory a path sits under,
// so the alert names the directory (a category) rather than the full binary
// path (which is a tenant path and never goes in a notification).
func worldWritablePrefix(path string) string {
	p := filepath.ToSlash(path)
	for _, d := range procWorldWritableDirs {
		if strings.HasPrefix(p, d) {
			return strings.TrimSuffix(d, "/")
		}
	}
	return ""
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

// execPIDs extracts the PIDs of EXEC events from a netlink connector buffer.
//
// Layout: nlmsghdr(16) + cn_msg(20) + proc_event{ what(4) cpu(4) timestamp(8) =
// 16 + event data }. process_pid is the first field of the exec event data. The
// length is validated at every step, because this buffer comes from the kernel
// but a short or malformed message must advance or stop rather than read past
// the end.
func execPIDs(buf []byte) []int {
	var out []int
	for len(buf) >= 16 {
		nlLen := binary.LittleEndian.Uint32(buf[0:])
		if nlLen < 16 || int(nlLen) > len(buf) {
			break
		}
		payload := buf[16:nlLen] // cn_msg + proc_event
		if len(payload) >= 20+16+4 {
			what := binary.LittleEndian.Uint32(payload[20:])
			if what == procEventExec {
				// process_pid is the kernel's signed __kernel_pid_t on the wire, so
				// reinterpreting the 32-bit value as int32 is correct, not a
				// truncation; the pid > 0 check below drops any negative reading.
				// #nosec G115 -- deliberate signed reinterpretation of a kernel pid
				pid := int(int32(binary.LittleEndian.Uint32(payload[20+16:])))
				if pid > 0 {
					out = append(out, pid)
				}
			}
		}
		adv := (nlLen + 3) &^ 3 // align to 4 bytes
		if adv == 0 || int(adv) >= len(buf) {
			break
		}
		buf = buf[adv:]
	}
	return out
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
