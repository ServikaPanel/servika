package backups

import (
	"strings"
	"testing"

	"servika/internal/secret"
)

// The error branch was empty, so a password that could not be decrypted stayed
// in the field as its own enc:v1: ciphertext and was handed to lftp as the
// account password. That turned a credential problem into an authentication one:
// the upload failed at the destination and the operator chased FTP credentials,
// while a restore answered "backup file is missing on disk" for an off-site copy
// that was intact.
func TestAnUnopenableStoredPasswordIsNotUsedAsThePassword(t *testing.T) {
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
	// Sealed under a DIFFERENT key, which is what a rotated SERVIKA_SECRET_KEY
	// leaves behind. There is no re-key tool, so this is a state a host reaches.
	sealed, err := secret.Encrypt("the real password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := secret.Init([]byte("a-DIFFERENT-key-that-is-long-32ch")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}

	settings := &BackupSettings{RemotePassword: sealed}
	opened, decryptErr := secret.Decrypt(settings.RemotePassword)
	if decryptErr == nil {
		t.Fatalf("the value opened under the wrong key as %q", opened)
	}

	// What readBackupSettings does with that failure.
	settings.RemotePassword = ""
	settings.PasswordErr = decryptErr

	if err := settings.usablePassword(); err == nil {
		t.Fatal("an unopenable credential reports itself as usable")
	}
	if strings.HasPrefix(settings.RemotePassword, "enc:") {
		t.Fatal("the ciphertext is still in the password field")
	}
}

// A password that opens is usable, and a row with none is not an error: an
// installation with no off-site destination configured must keep working.
func TestAnOpenableOrAbsentPasswordIsUsable(t *testing.T) {
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
	if err := (&BackupSettings{RemotePassword: "opened"}).usablePassword(); err != nil {
		t.Fatalf("an opened password reports %v", err)
	}
	if err := (&BackupSettings{}).usablePassword(); err != nil {
		t.Fatalf("an empty password reports %v", err)
	}
}

// secret.Decrypt returns a legacy plaintext value unchanged with a nil error
// before any cipher work, so the tolerant branch bought nothing: only a genuine
// failure ever reached the discarded error.
func TestALegacyPlaintextPasswordStillPassesThrough(t *testing.T) {
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
	value, err := secret.Decrypt("a legacy plaintext password")
	if err != nil {
		t.Fatalf("a legacy value reported %v", err)
	}
	if value != "a legacy plaintext password" {
		t.Fatalf("a legacy value came back as %q", value)
	}
}

// Every consumer of the credential asks first, or the ciphertext reaches lftp
// through whichever one was missed.
func TestEveryConsumerOfTheCredentialChecksItFirst(t *testing.T) {
	settings := readSource(t, "settings.go")

	// The reader records the failure instead of discarding it.
	reader := functionSource(t, settings, "func readBackupSettings(")
	if !strings.Contains(reader, "s.PasswordErr = ") {
		t.Error("readBackupSettings still discards a decryption failure")
	}
	if !strings.Contains(reader, `s.RemotePassword = ""`) {
		t.Error("readBackupSettings leaves the unopened value in the password field")
	}

	for _, consumer := range []struct{ source, function string }{
		{"settings.go", "func pushGlobalAsync("},
		{"settings.go", "func fetchGlobalRemote("},
		{"destination.go", "func ensureLocalArchive("},
		{"settings_handlers.go", "func (h *Handlers) BackupSettingsTest("},
	} {
		body := functionSource(t, readSource(t, consumer.source), consumer.function)
		if !strings.Contains(body, "usablePassword()") {
			t.Errorf("%s does not check the credential before using it", consumer.function)
		}
	}
}

// The message has to name the cause, or it is the same misdiagnosis in different
// words.
func TestTheFailureNamesTheKeyRatherThanTheDestination(t *testing.T) {
	reader := functionSource(t, readSource(t, "settings.go"), "func readBackupSettings(")
	if !strings.Contains(reader, "SERVIKA_SECRET_KEY may have changed") {
		t.Fatal("the failure does not name the key as the cause")
	}
}
