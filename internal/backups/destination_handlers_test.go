package backups

import (
	"context"
	"database/sql/driver"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"servika/internal/secret"
)

const (
	existingDestinationQuery = "SELECT COALESCE(password,''), COALESCE(host,''), COALESCE(port,0), COALESCE(type,'')"
	existingPasswordQuery    = "SELECT COALESCE(password,'') FROM backup_destinations WHERE domain_id=?"
	pinnedKeyQuery           = "SELECT COALESCE(host_key,'') FROM backup_destinations WHERE domain_id=?"
	readDestinationQuery     = "SELECT id, type, host, port, username, password, remote_dir, host_key,"
	destinationUpsert        = "INSERT INTO backup_destinations(domain_id, type, host, port, username, password, remote_dir,"
	hostKeyStore             = "UPDATE backup_destinations SET host_key=? WHERE domain_id=? AND host_key=''"
	scannedKey               = "203.0.113.10 ssh-ed25519 AAAAscanned"
)

func initTestSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatal(err)
	}
}

// destinationScript answers the domain lookup for domain 5 and whatever else the
// test adds.
func destinationScript(rows map[string][][]driver.Value) *sqlScript {
	all := existingDomain()
	maps.Copy(all, rows)
	return &sqlScript{rows: all}
}

func putDestination(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).PutDestination(w,
		domainRequest(http.MethodPut, "/domains/5/backups/destination", body, "id", "5"))
	return w
}

func TestPutDestinationRefusesAnInvalidDestination(t *testing.T) {
	initTestSecret(t)
	noExisting := map[string][][]driver.Value{existingDestinationQuery: {}}
	cases := []struct {
		name    string
		script  *sqlScript
		body    string
		status  int
		message string
	}{
		{"an unknown domain", &sqlScript{rows: map[string][][]driver.Value{lookupQuery: {}}}, `{}`,
			http.StatusNotFound, "domain not found"},
		{"a failed lookup", &sqlScript{fail: map[string]error{lookupQuery: errors.New("lost")}}, `{}`,
			http.StatusInternalServerError, "internal server error"},
		{"a malformed body", destinationScript(nil), `{`, http.StatusBadRequest, "invalid request body"},
		{"an unknown type", destinationScript(nil), `{"type":"scp"}`, http.StatusBadRequest, "type must be ftp, sftp, s3 or b2"},
		{"no username", destinationScript(nil), `{"type":"sftp"}`, http.StatusBadRequest, "username / access key is required"},
		{"object storage without a bucket", destinationScript(nil), `{"type":"s3","username":"AK"}`,
			http.StatusBadRequest, "bucket is required"},
		{"an insecure endpoint", destinationScript(nil), `{"type":"s3","username":"AK","bucket":"b","endpoint":"http://s3.example.com"}`,
			http.StatusBadRequest, "the endpoint must be a valid HTTPS address"},
		{"Backblaze without an endpoint", destinationScript(nil), `{"type":"b2","username":"AK","bucket":"b"}`,
			http.StatusBadRequest, "a Backblaze S3 endpoint is required"},
		{"no host", destinationScript(nil), `{"type":"sftp","username":"u"}`, http.StatusBadRequest, "host is required"},
		{"a host with shell characters", destinationScript(nil), `{"type":"ftp","username":"u","host":"h;rm -rf"}`,
			http.StatusBadRequest, "host must be a valid hostname or IPv4/IPv6 address"},
		{"an option-injecting username", destinationScript(nil), `{"type":"sftp","username":"-oProxyCommand=x","host":"203.0.113.10"}`,
			http.StatusBadRequest, "username cannot begin with a dash (ssh option injection)"},
		{"a new destination with no password", destinationScript(noExisting), `{"type":"sftp","username":"u","host":"203.0.113.10"}`,
			http.StatusBadRequest, "password is required for a new destination"},
		{"the row cannot be written", &sqlScript{
			rows: existingDomain(),
			fail: map[string]error{destinationUpsert: errors.New("read-only")},
		}, `{"type":"sftp","username":"u","host":"203.0.113.10","password":"p"}`,
			http.StatusInternalServerError, "could not save backup destination"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertRefusal(t, putDestination(t, c.script, c.body), c.status, c.message)
		})
	}
}

// A new SFTP destination takes the default port and directory, stores the
// password sealed and answers with the stored row without the password.
func TestPutDestinationStoresANewDestination(t *testing.T) {
	initTestSecret(t)
	script := destinationScript(map[string][][]driver.Value{
		existingDestinationQuery: {},
		readDestinationQuery:     {domainDestinationRow()},
	})

	w := putDestination(t, script, `{"type":"sftp","username":"backup","host":"203.0.113.10","password":"s3cret","active":true}`)

	if w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	body := responseBody(t, w)
	if _, present := body["password"]; present || body["host"] != "203.0.113.10" || body["active"] != true {
		t.Errorf("body = %v", body)
	}
	want := []driver.Value{int64(5), "sftp", "203.0.113.10", int64(22), "backup", "sealed", "/", "", "", "", int64(0), int64(1), ""}
	if args := sealedUpsert(t, script, "s3cret"); !slices.Equal(args, want) {
		t.Errorf("upsert bound %v, want %v", args, want)
	}
	if len(script.execsContaining(pinnedKeyQuery)) != 0 {
		t.Error("a pinned key was read for a changed host")
	}
}

// sealedUpsert returns the one destination upsert's arguments with the sealed
// password replaced by "sealed", after checking that it opens to password.
func sealedUpsert(t *testing.T, script *sqlScript, password string) []driver.Value {
	t.Helper()
	upserts := script.execsContaining(destinationUpsert)
	if len(upserts) != 1 {
		t.Fatalf("upserts = %+v", upserts)
	}
	args := upserts[0].args
	sealed, _ := args[5].(string)
	if opened, err := secret.Decrypt(sealed); err != nil || opened != password || !strings.HasPrefix(sealed, "enc:v1:") {
		t.Errorf("the stored password %q opened as (%q, %v)", sealed, opened, err)
	}
	args[5] = "sealed"
	return args
}

// Saving the same host, port and type keeps the stored password and the pinned
// key, and an FTP destination takes port 21.
func TestPutDestinationKeepsThePinForTheSameHost(t *testing.T) {
	initTestSecret(t)
	script := destinationScript(map[string][][]driver.Value{
		existingDestinationQuery: {{"enc:v1:stored", "203.0.113.10", int64(21), "ftp"}},
		pinnedKeyQuery:           {{"pinned-key"}},
		readDestinationQuery:     {},
	})

	w := putDestination(t, script, `{"type":"ftp","username":"backup","host":"203.0.113.10","remote_dir":"/site"}`)

	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "null" {
		t.Fatalf("answered %d %s, want 200 null", w.Code, w.Body.String())
	}
	upserts := script.execsContaining(destinationUpsert)
	want := []driver.Value{int64(5), "ftp", "203.0.113.10", int64(21), "backup", "enc:v1:stored", "/site", "", "", "", int64(0), int64(0), "pinned-key"}
	if len(upserts) != 1 || !slices.Equal(upserts[0].args, want) {
		t.Errorf("upserts = %+v, want %v", upserts, want)
	}
}

// Object storage stores the endpoint as the host, port 443 and the default region.
func TestPutDestinationStoresObjectStorage(t *testing.T) {
	initTestSecret(t)
	script := destinationScript(map[string][][]driver.Value{existingDestinationQuery: {}, readDestinationQuery: {}})

	w := putDestination(t, script, `{"type":"s3","username":"AKID","password":"key","bucket":"backups","path_style":true}`)

	if w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	want := []driver.Value{int64(5), "s3", "", int64(443), "AKID", "sealed", "/", "backups", "us-east-1", "", int64(1), int64(0), ""}
	if args := sealedUpsert(t, script, "key"); !slices.Equal(args, want) {
		t.Errorf("upsert bound %v, want %v", args, want)
	}
}

// keyScanCommands answers ssh-keyscan with a key and sshpass and curl with the
// exit code and output given.
func keyScanCommands(t *testing.T, scanExit int, connectOutput string, connectExit int) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		switch argv[0] {
		case "ssh-keyscan":
			if scanExit != 0 {
				return "", scanExit
			}
			return "# 203.0.113.10:22 SSH-2.0\n" + scannedKey + "\n", 0
		case "sshpass", "curl":
			return connectOutput, connectExit
		}
		return "", 0
	})
}

func testDestination(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).TestDestination(w,
		domainRequest(http.MethodPost, "/domains/5/backups/destination/test", body, "id", "5"))
	return w
}

func TestTestDestinationAnswersEachCase(t *testing.T) {
	initTestSecret(t)
	cases := []struct {
		name    string
		script  *sqlScript
		body    string
		connect int
		status  int
		want    map[string]any
	}{
		{name: "an unknown domain", script: &sqlScript{rows: map[string][][]driver.Value{lookupQuery: {}}},
			status: http.StatusNotFound, want: map[string]any{"error": "domain not found"}},
		{name: "a failed lookup", script: &sqlScript{fail: map[string]error{lookupQuery: errors.New("lost")}},
			status: http.StatusInternalServerError, want: map[string]any{"error": "internal server error"}},
		{name: "a form whose stored password cannot be opened",
			script: destinationScript(map[string][][]driver.Value{existingPasswordQuery: {{"enc:v1:not-sealed"}}}),
			body:   `{"type":"sftp","host":"203.0.113.10","username":"u"}`,
			status: http.StatusInternalServerError, want: map[string]any{"error": "internal server error"}},
		{name: "a form with a host carrying shell characters", script: destinationScript(map[string][][]driver.Value{existingPasswordQuery: {}}),
			body:   `{"type":"sftp","host":"h;id","username":"u","password":"p"}`,
			status: http.StatusBadRequest, want: map[string]any{"error": "host must be a valid hostname or IPv4/IPv6 address"}},
		{name: "a form with a line break in the directory", script: destinationScript(map[string][][]driver.Value{existingPasswordQuery: {}}),
			body:   `{"type":"ftp","host":"203.0.113.10","username":"u","password":"p","remote_dir":"a\nb"}`,
			status: http.StatusBadRequest, want: map[string]any{"error": "username, password and remote directory cannot contain line breaks or control characters"}},
		{name: "a form that connects", script: destinationScript(map[string][][]driver.Value{existingPasswordQuery: {{"stored-plain"}}}),
			body:   `{"type":"sftp","host":"203.0.113.10","username":"backup"}`,
			status: http.StatusOK, want: map[string]any{"ok": true}},
		{name: "no form and no stored destination", script: destinationScript(map[string][][]driver.Value{readDestinationQuery: {}}),
			status: http.StatusBadRequest, want: map[string]any{"error": "destination is missing or request body is invalid"}},
		{name: "no form and an unreadable destination", script: &sqlScript{
			rows: existingDomain(), fail: map[string]error{readDestinationQuery: errors.New("lost")},
		}, status: http.StatusBadRequest, want: map[string]any{"error": "destination is missing or request body is invalid"}},
		{name: "a stored destination that refuses", script: destinationScript(map[string][][]driver.Value{readDestinationQuery: {domainDestinationRow()}}),
			body: `{"host":""}`, connect: 5,
			status: http.StatusOK, want: map[string]any{"ok": false, "error": "connection test failed"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keyScanCommands(t, 0, "Permission denied", c.connect)
			w := testDestination(t, c.script, c.body)
			if w.Code != c.status || !reflect.DeepEqual(responseBody(t, w), c.want) {
				t.Fatalf("answered %d %s, want %d %v", w.Code, w.Body.String(), c.status, c.want)
			}
		})
	}
}

// A form-supplied SFTP destination is pinned on the row it will be saved as and
// then tested through sshpass against the vetted address.
func TestTestDestinationPinsAndTestsAFormDestination(t *testing.T) {
	script := destinationScript(map[string][][]driver.Value{existingPasswordQuery: {{"stored-plain"}}})
	commands := keyScanCommands(t, 0, "", 0)

	w := testDestination(t, script, `{"type":"sftp","host":"203.0.113.10","username":"backup"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	if !commands.ran("ssh-keyscan", "-p", "22", "-T", "10", "203.0.113.10") {
		t.Errorf("the key was not scanned: %v", commands.argvs())
	}
	stores := script.execsContaining(hostKeyStore)
	if len(stores) != 1 || !slices.Equal(stores[0].args, []driver.Value{scannedKey, int64(5)}) {
		t.Errorf("the pin was stored as %+v", stores)
	}
	assertSSHPassArgv(t, commands, "backup")
}

func assertSSHPassArgv(t *testing.T, commands *commandRecorder, user string) {
	t.Helper()
	var sshpass []string
	for _, argv := range commands.argvs() {
		if argv[0] == "sshpass" {
			sshpass = argv
		}
	}
	want := []string{"sshpass", "-e", "ssh", "-p", "22", "-l", user,
		"-o", "ConnectTimeout=10", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
		"-o", "BatchMode=no", "-o", "HostKeyAlias=203.0.113.10", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=", "-o", "GlobalKnownHostsFile=/dev/null", "--", "203.0.113.10", "true"}
	if len(sshpass) != len(want) {
		t.Fatalf("sshpass = %v", sshpass)
	}
	if !strings.HasPrefix(sshpass[20], "UserKnownHostsFile=") || len(sshpass[20]) == len("UserKnownHostsFile=") {
		t.Errorf("the known_hosts option is %q", sshpass[20])
	}
	sshpass[20] = want[20]
	if !slices.Equal(sshpass, want) {
		t.Errorf("sshpass = %v, want %v", sshpass, want)
	}
}

// A pinned key that cannot be written where ssh reads it fails the test before
// ssh runs.
func TestTestConnectionReportsAnUnwritableKnownHostsFile(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	commands := keyScanCommands(t, 0, "", 0)
	d := &Destination{Type: "sftp", Host: "203.0.113.10", Port: 22, Username: "backup", Password: "p", HostKey: scannedKey}

	err := testConnection(context.Background(), nil, d)

	if err == nil || !strings.Contains(err.Error(), "servika-knownhosts-") {
		t.Fatalf("testConnection = %v, want the known_hosts file named", err)
	}
	if len(commands.argvs()) != 0 {
		t.Errorf("a command ran without its known_hosts file: %v", commands.argvs())
	}
}

func TestTestConnectionReportsEachFailure(t *testing.T) {
	t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "")
	sftp := func(mutate func(d *Destination)) *Destination {
		d := &Destination{Type: "sftp", Host: "203.0.113.10", Port: 22, Username: "backup", Password: "p", HostKey: scannedKey}
		mutate(d)
		return d
	}
	cases := []struct {
		name        string
		destination *Destination
		scanExit    int
		output      string
		exit        int
		want        string
	}{
		{name: "an insecure object storage endpoint", destination: &Destination{Type: "s3", Endpoint: "http://s3.example.com", Bucket: "b"},
			want: "the endpoint must be a valid HTTPS address"},
		{name: "an internal address", destination: sftp(func(d *Destination) { d.Host = "127.0.0.1" }),
			want: "destination host not permitted: target address is not permitted (internal network)"},
		{name: "a password that cannot be delivered", destination: sftp(func(d *Destination) { d.Password = "a\nb" }),
			want: "the stored destination password contains a line break or control character; save the destination again"},
		{name: "a key that cannot be scanned", destination: sftp(func(d *Destination) { d.HostKey = "" }), scanExit: 1,
			want: "the destination's SSH host key could not be read: exit status 1"},
		{name: "ssh refuses with a reason", destination: sftp(func(*Destination) {}), output: " Permission denied \n", exit: 5,
			want: "Permission denied"},
		{name: "ssh refuses silently", destination: sftp(func(*Destination) {}), exit: 255, want: "exit status 255"},
		{name: "ssh connects", destination: sftp(func(*Destination) {})},
		{name: "ftp refuses with a reason", destination: &Destination{Type: "ftp", Host: "203.0.113.10", Port: 21, Username: "u", Password: "p"},
			output: "curl: (67) Access denied", exit: 67, want: "curl: (67) Access denied"},
		{name: "ftp refuses silently", destination: &Destination{Type: "ftp", Host: "203.0.113.10", Port: 21, Username: "u", Password: "p"},
			exit: 7, want: "exit status 7"},
		{name: "ftp connects", destination: &Destination{Type: "ftp", Host: "203.0.113.10", Port: 21, Username: "u", Password: "p"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			commands := keyScanCommands(t, c.scanExit, c.output, c.exit)

			err := testConnection(context.Background(), nil, c.destination)

			if c.want == "" && err != nil || c.want != "" && (err == nil || err.Error() != c.want) {
				t.Fatalf("testConnection = %v, want %q", err, c.want)
			}
			if c.destination.Type == "ftp" {
				wantCurl := []string{"curl", "-sS", "--connect-timeout", "10", "--max-time", "15", "--config", "-",
					"--ftp-skip-pasv-ip", "--ssl-reqd", "ftp://203.0.113.10:21/"}
				if argvs := commands.argvs(); len(argvs) != 1 || !slices.Equal(argvs[0], wantCurl) {
					t.Errorf("curl ran as %v", argvs)
				}
			}
		})
	}
}
