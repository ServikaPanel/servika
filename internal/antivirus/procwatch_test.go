package antivirus

import (
	"encoding/binary"
	"testing"
)

func TestScoreProcessWebServerStartingAShell(t *testing.T) {
	f := scoreProcess("php-fpm", "bash", "/usr/bin/bash", 1000)
	if f.score != procWebShellScore || f.code != reasonWebShell {
		t.Fatalf("web->shell: got %+v", f)
	}
	if f.parent != "php-fpm" || f.child != "bash" {
		t.Fatalf("web->shell chain not carried: %+v", f)
	}
}

func TestScoreProcessWebServerStartingADownloader(t *testing.T) {
	f := scoreProcess("nginx", "curl", "/usr/bin/curl", 1000)
	if f.score != procDownloaderScore || f.code != reasonWebDownloader {
		t.Fatalf("web->downloader: got %+v", f)
	}
	// A downloader alone is below the reporting threshold: real signal, not an
	// alert on its own.
	if f.score >= procScoreSuspicious {
		t.Fatalf("a downloader should score below the reporting threshold, got %d", f.score)
	}
}

func TestScoreProcessWorldWritableExecutable(t *testing.T) {
	f := scoreProcess("bash", "evil", "/tmp/evil", 1000)
	if f.score != procWorldWritableScore || f.code != reasonWorldWritable {
		t.Fatalf("world-writable: got %+v", f)
	}
	if f.dir != "/tmp" {
		t.Fatalf("world-writable dir should be the category /tmp, got %q", f.dir)
	}
}

func TestScoreProcessRootShellIsNormal(t *testing.T) {
	// A shell whose parent is not a web process is ordinary (cron, an admin).
	if f := scoreProcess("cron", "bash", "/usr/bin/bash", 0); f.score != 0 {
		t.Fatalf("a non-web parent starting a shell should not fire: %+v", f)
	}
}

func TestScoreProcessLegitimateWebChildIsNormal(t *testing.T) {
	if f := scoreProcess("php-fpm", "php-fpm", "/usr/sbin/php-fpm", 1000); f.score != 0 {
		t.Fatalf("php-fpm managing its own workers should not fire: %+v", f)
	}
}

func TestScoreProcessWorldWritableNeedsTenantOrWeb(t *testing.T) {
	// A root process (uid 0) that is not a web server running from /tmp is not
	// reported: system tooling legitimately does this.
	if f := scoreProcess("systemd", "helper", "/tmp/helper", 0); f.score != 0 {
		t.Fatalf("a root /tmp exec with no web parent should not fire: %+v", f)
	}
}

func TestParseStatHandlesCommWithSpacesAndParens(t *testing.T) {
	// comm can itself contain spaces and parentheses; the fields after the LAST
	// ')' are state, ppid, ...
	ppid, comm := parseStat("1234 ((evil) proc) S 42 100 100 0 -1")
	if comm != "(evil) proc" {
		t.Fatalf("comm parse trap: got %q", comm)
	}
	if ppid != 42 {
		t.Fatalf("ppid: got %d, want 42", ppid)
	}
}

func TestParseStatSimple(t *testing.T) {
	ppid, comm := parseStat("77 (bash) R 55 77 77 0")
	if comm != "bash" || ppid != 55 {
		t.Fatalf("got comm=%q ppid=%d", comm, ppid)
	}
}

// buildExecEvent builds a netlink connector message carrying one EXEC event for
// pid. Layout: nlmsghdr(16) + cn_msg(20) + proc_event{what(4) cpu(4) ts(8) =16 +
// process_pid(4)}. `what` is at payload offset 20, process_pid at payload 36.
func buildExecEvent(pid int32, what uint32) []byte {
	const total = 64
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:], total) // nlmsg_len
	binary.LittleEndian.PutUint32(buf[16+20:], what)
	binary.LittleEndian.PutUint32(buf[16+36:], uint32(pid))
	return buf
}

func TestExecPIDsExtractsExecEvents(t *testing.T) {
	pids := execPIDs(buildExecEvent(4321, procEventExec))
	if len(pids) != 1 || pids[0] != 4321 {
		t.Fatalf("exec event pid: got %v", pids)
	}
}

func TestExecPIDsIgnoresNonExecEvents(t *testing.T) {
	// A non-EXEC event (e.g. fork = 0x1) yields no pid.
	if pids := execPIDs(buildExecEvent(4321, 0x1)); len(pids) != 0 {
		t.Fatalf("a non-exec event produced pids: %v", pids)
	}
}

func TestExecPIDsStopsOnAMalformedLength(t *testing.T) {
	buf := buildExecEvent(4321, procEventExec)
	binary.LittleEndian.PutUint32(buf[0:], 8) // nlLen < 16, must stop
	if pids := execPIDs(buf); len(pids) != 0 {
		t.Fatalf("a malformed length should yield nothing, got %v", pids)
	}
}
