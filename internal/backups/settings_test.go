package backups

import "testing"

// remoteDateDir derives a UTC date folder from the backup file name's stamp, so a
// name whose stamp cannot be read returns "" and the file lands in the base
// directory. Both the manual and the scheduled (-auto-) name shapes carry the
// stamp.
func TestRemoteDateDirReadsTheStamp(t *testing.T) {
	cases := map[string]string{
		"c_site-20260826-233538.tar.gz":      "2026-08-26",
		"c_site-auto-20260101-000102.tar.gz": "2026-01-01",
		"no-stamp-here.tar.gz":               "",
		"":                                   "",
		"c_site-2026082-233538.tar.gz":       "", // 7-digit date, not 8
	}
	for name, want := range cases {
		if got := remoteDateDir(name); got != want {
			t.Errorf("remoteDateDir(%q) = %q, want %q", name, got, want)
		}
	}
}

// joinRemotePath joins a base remote directory with a date subdirectory, and
// returns the base alone when the subdirectory is empty, so an unparseable stamp
// keeps the old flat layout.
func TestJoinRemotePath(t *testing.T) {
	cases := []struct {
		base, sub, want string
	}{
		{"/gpanel", "2026-08-26", "/gpanel/2026-08-26"},
		{"/gpanel/", "2026-08-26", "/gpanel/2026-08-26"},
		{"/", "2026-08-26", "/2026-08-26"},
		{"", "2026-08-26", "/2026-08-26"},
		{"/gpanel", "", "/gpanel"},
		{"/", "", "/"},
		{"  /base  ", "d", "/base/d"},
	}
	for _, c := range cases {
		if got := joinRemotePath(c.base, c.sub); got != c.want {
			t.Errorf("joinRemotePath(%q,%q) = %q, want %q", c.base, c.sub, got, c.want)
		}
	}
}

// validateBackupSettings enforces the input bounds, and a disabled remote skips
// every remote-field check so a host with no off-site destination still saves.
func TestValidateBackupSettings(t *testing.T) {
	ok := &BackupSettings{MinFreeGB: 10, MaxStoreGB: 0, RemoteEnabled: false}
	if msg := validateBackupSettings(ok); msg != "" {
		t.Errorf("a valid disabled-remote setting was refused: %s", msg)
	}
	if msg := validateBackupSettings(&BackupSettings{MinFreeGB: -1}); msg == "" {
		t.Error("a negative min_free_gb was accepted")
	}
	if msg := validateBackupSettings(&BackupSettings{MaxStoreGB: 2000000}); msg == "" {
		t.Error("an out-of-range max_store_gb was accepted")
	}
	// Remote enabled but incomplete / unsafe.
	if msg := validateBackupSettings(&BackupSettings{RemoteEnabled: true, RemoteType: "s3", RemoteHost: "h", RemotePort: 22, RemoteUsername: "u"}); msg == "" {
		t.Error("an object-storage type was accepted for the system-wide destination")
	}
	if msg := validateBackupSettings(&BackupSettings{RemoteEnabled: true, RemoteType: "sftp", RemoteHost: "", RemotePort: 22, RemoteUsername: "u"}); msg == "" {
		t.Error("an empty host was accepted")
	}
	if msg := validateBackupSettings(&BackupSettings{RemoteEnabled: true, RemoteType: "sftp", RemoteHost: "h", RemotePort: 0, RemoteUsername: "u"}); msg == "" {
		t.Error("an out-of-range port was accepted")
	}
	if msg := validateBackupSettings(&BackupSettings{RemoteEnabled: true, RemoteType: "sftp", RemoteHost: "h\nx", RemotePort: 22, RemoteUsername: "u"}); msg == "" {
		t.Error("a host carrying a line break was accepted")
	}
	good := &BackupSettings{RemoteEnabled: true, RemoteType: "sftp", RemoteHost: "backup.example.com", RemotePort: 22, RemoteUsername: "u", RemoteDir: "/x"}
	if msg := validateBackupSettings(good); msg != "" {
		t.Errorf("a valid remote setting was refused: %s", msg)
	}
}
