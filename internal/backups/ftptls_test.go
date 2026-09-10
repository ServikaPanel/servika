package backups

import (
	"strings"
	"testing"
)

// lftp defaults ftp:ssl-allow to yes, so `set ftp:ssl-allow no` actively turned
// OFF the AUTH TLS upgrade the remote server offers. The whole archive (document
// root, mail and the tenant's SQL dump) and the destination's username and
// password then crossed the public internet in cleartext, on every scheduled
// upload, every restore fetch and every size check.
func TestAnFTPDestinationRequiresTLS(t *testing.T) {
	settings := lftpTransportSettings(&Destination{Type: "ftp"})

	for _, want := range []string{
		"set ftp:ssl-allow yes;",
		"set ftp:ssl-force yes;",
		"set ftp:ssl-protect-data yes;",
		"set ssl:verify-certificate yes;",
	} {
		if !strings.Contains(settings, want) {
			t.Errorf("%q is missing from the FTP transport settings: %q", want, settings)
		}
	}
	for _, refuse := range []string{"ssl-allow no", "verify-certificate no"} {
		if strings.Contains(settings, refuse) {
			t.Errorf("the FTP transport still carries %q", refuse)
		}
	}
}

// ssl-force refuses the transfer rather than falling back to plaintext, because
// a destination that cannot do TLS is exactly the one this must not use. The
// data channel is protected too: without ssl-protect-data the control channel is
// encrypted and the archive itself still travels in the clear.
func TestTheDataChannelIsProtectedNotJustTheLogin(t *testing.T) {
	settings := lftpTransportSettings(&Destination{Type: "ftp"})
	if !strings.Contains(settings, "ssl-protect-data yes") {
		t.Fatal("only the control channel is protected; the archive would still travel in the clear")
	}
}

// SFTP runs over SSH and its host key is pinned separately by
// lftpHostKeySettings, so it needs none of this.
func TestSFTPGetsNoFTPTransportSettings(t *testing.T) {
	for _, kind := range []string{"sftp", "s3", "b2"} {
		if got := lftpTransportSettings(&Destination{Type: kind}); got != "" {
			t.Errorf("%s got FTP transport settings: %q", kind, got)
		}
	}
}

// Every lftp script must carry the settings, or one path keeps sending in the
// clear while the others do not: upload, fetch, remote size and delete.
func TestEveryLftpScriptCarriesTheTransportSettings(t *testing.T) {
	body := readBackupSource(t, "destination.go")

	if strings.Contains(body, "set ftp:ssl-allow no") {
		t.Error("a script still disables the TLS upgrade")
	}
	if n := strings.Count(body, "lftpTransportSettings(d)"); n != 4 {
		t.Errorf("%d of the 4 lftp scripts pass the transport settings", n)
	}
}

// The connection test must exercise the transport the uploads use, or it reports
// a destination as working and every later transfer to it either crosses the
// internet in cleartext or fails at 03:00 with nobody watching.
func TestTheConnectionTestRequiresTLSToo(t *testing.T) {
	if !strings.Contains(readBackupSource(t, "destination.go"), `"--ssl-reqd"`) {
		t.Error("the FTP connection test does not require TLS")
	}
}
