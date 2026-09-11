package system

import (
	"strings"
	"testing"
)

const offsiteLib = "../../assets/ops/servika-offsite-lib"

// The off-site uploader reused the pre-hardening lftp settings rather than the
// pinned form the panel's own destination handling had already moved to. All
// three of its lftp runs carried `sftp:auto-confirm yes`, which accepts whatever
// SSH host key the destination presents, on every connection, without recording
// or comparing it: the transfer had no authentication of the remote server at
// all. Anything able to answer for the destination hostname received the panel's
// entire database dump, which carries every tenant's rows, the users table and
// the encrypted credential columns, and the upload reported success.
func TestTheOffsiteUploaderNeverAcceptsAnyHostKey(t *testing.T) {
	body := readScript(t, offsiteLib)
	if strings.Contains(body, "sftp:auto-confirm yes") {
		t.Error("the uploader still accepts whatever host key the destination presents")
	}
	if !strings.Contains(body, "sftp:auto-confirm no") {
		t.Error("the uploader does not turn auto-confirm off")
	}
	for _, option := range []string{
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=",
		// Without this ssh also consults root's known_hosts, so a key trusted
		// for some unrelated purpose would satisfy the check.
		"GlobalKnownHostsFile=/dev/null",
	} {
		if !strings.Contains(body, option) {
			t.Errorf("the uploader does not pass %s to ssh", option)
		}
	}
}

// An FTP destination had the TLS upgrade disabled outright, so the dump and the
// destination credentials crossed the network in the clear.
func TestTheOffsiteUploaderRequiresTLSForFTP(t *testing.T) {
	body := readScript(t, offsiteLib)
	if strings.Contains(body, "ftp:ssl-allow no") {
		t.Error("the uploader still disables the FTP TLS upgrade")
	}
	if strings.Contains(body, "ssl:verify-certificate no") {
		t.Error("the uploader still accepts an unverified TLS certificate")
	}
	for _, setting := range []string{
		"set ftp:ssl-allow yes",
		"set ftp:ssl-force yes",
		"set ftp:ssl-protect-data yes",
		"set ssl:verify-certificate yes",
	} {
		if !strings.Contains(body, setting) {
			t.Errorf("the uploader does not set %q", setting)
		}
	}
}

// A scan that produced nothing must skip the upload, never fall back to
// accepting any key. Falling back would make the pin decorative: every
// destination an attacker can make unreachable-then-answerable would be
// accepted on the retry.
func TestAnUnreadableHostKeySkipsTheUpload(t *testing.T) {
	body := readScript(t, offsiteLib)
	pin, ok := shellFunction(body, "offsite_pin_host_key")
	if !ok {
		t.Fatal("offsite_pin_host_key is no longer defined")
	}
	if !strings.Contains(pin, "return 1") {
		t.Error("the pin helper never refuses, so a failed scan cannot stop the upload")
	}
	upload, ok := shellFunction(body, "servika_upload_offsite")
	if !ok {
		t.Fatal("servika_upload_offsite is no longer defined")
	}
	if !strings.Contains(upload, `offsite_pin_host_key "$prefix" "$host" "$port") || return 0`) {
		t.Error("the uploader does not stop when the host key cannot be pinned")
	}
}

// The alias has to be spelled exactly as ssh-keyscan wrote the pin. Measured
// against OpenSSH 10.3p1: ssh uses HostKeyAlias VERBATIM and applies no
// bracketing of its own, so a bare name against a pin written as [host]:port
// fails with "No ED25519 host key is known ... and you have requested strict
// checking" and refuses every connection to a destination on a non-default
// port.
func TestTheHostKeyAliasCarriesThePortBracketing(t *testing.T) {
	body := readScript(t, offsiteLib)
	alias, ok := shellFunction(body, "offsite_host_alias")
	if !ok {
		t.Fatal("offsite_host_alias is no longer defined")
	}
	if !strings.Contains(alias, `"22"`) {
		t.Error("the alias helper does not distinguish the default port")
	}
	if !strings.Contains(alias, `'[%s]:%s'`) {
		t.Error("the alias helper does not bracket a non-default port the way ssh-keyscan does")
	}
	if !strings.Contains(body, `alias=$(offsite_host_alias "$host" "$port")`) {
		t.Error("the uploader does not build the alias from the port")
	}
}

// shellFunction returns one shell function's body, from `name()` to the closing
// brace in the first column.
func shellFunction(source, name string) (string, bool) {
	at := strings.Index(source, "\n"+name+"() {")
	if at < 0 {
		return "", false
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	return body, found
}
