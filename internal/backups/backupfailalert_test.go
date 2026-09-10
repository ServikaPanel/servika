package backups

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Alerting was added around the periphery of a backup — where the archive is
// stored, whether the disk allowed it, whether it later rotted — but not around
// the backup itself. A scheduled run that fails every night for a permission
// problem, a corrupt file in the tree or a tenant large enough to exceed the
// archive deadline left a partial job row nobody reads and nothing else, so the
// loss surfaced when a restore was needed and the newest archive was weeks old.
func TestBothSweepsAlertWhenADomainBackupFails(t *testing.T) {
	scheduler := functionSource(t, readSource(t, "schedule.go"), "func tickOnce(")
	if !strings.Contains(scheduler, "notifyBackupFailed(") {
		t.Error("the nightly sweep does not alert on a failed domain backup")
	}

	bulk := functionSource(t, readSource(t, "jobs.go"), "func (h *Handlers) StartBackupJob(")
	if !strings.Contains(bulk, "notifyBackupFailed(") {
		t.Error("the bulk job does not alert on a failed domain backup")
	}
}

// A stop is not a failure. The operator asked for it, so it must not raise a
// critical alert per remaining domain.
func TestAStoppedSweepRaisesNoFailureAlert(t *testing.T) {
	for _, source := range []struct{ name, function string }{
		{"schedule.go", "func tickOnce("},
		{"jobs.go", "func (h *Handlers) StartBackupJob("},
	} {
		body := functionSource(t, readSource(t, source.name), source.function)
		alertAt := strings.Index(body, "notifyBackupFailed(")
		stopAt := strings.Index(body, "stopped = true")
		if alertAt < 0 || stopAt < 0 {
			t.Errorf("%s: a step is missing (alert=%d, stop=%d)", source.name, alertAt, stopAt)
			continue
		}
		// The stop branch breaks out before the counting branch the alert sits in.
		if stopAt > alertAt {
			t.Errorf("%s: the stop check runs after the alert, so a stopped run alerts per domain", source.name)
		}
	}
}

// The alert is critical and domain-scoped, like the other two backup alerts: the
// customer, the reseller who owns them and an admin all need to know there is no
// recovery point.
func TestTheFailureAlertIsCriticalAndDomainScoped(t *testing.T) {
	body := functionSource(t, readSource(t, "notify.go"), "func notifyBackupFailed(")

	for _, want := range []string{
		"notifications.LevelCritical",
		"DomainID: &id",
		`Key:      "backup.backupFailed"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the failure alert is missing %q", want)
		}
	}
	// A write failure must not stop the sweep: the alert about one domain cannot
	// be allowed to end the backup of the rest.
	if strings.Contains(body, "return err") {
		t.Error("a failed alert write is returned, which would stop the sweep")
	}
}

// The notification stores an English fallback plus a key the reader's own
// language renders, so a key with no string shows the fallback to everyone.
func TestTheFailureAlertKeyHasItsLocaleStrings(t *testing.T) {
	for _, lang := range []string{"en", "tr", "de", "fr", "es", "it", "ja", "pt", "pt-BR", "ro", "cs", "zh"} {
		path := "../../frontend/src/lib/locales/" + lang + "/TopBar.json"
		body, err := os.ReadFile(path) // #nosec G304 -- a repository path this test names.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		text, ok := nested(parsed, "notify", "backup", "backupFailed")
		if !ok {
			t.Errorf("%s has no notify.backup.backupFailed string", lang)
			continue
		}
		// Both placeholders the event carries, or the sentence loses what it is
		// about or why.
		for _, placeholder := range []string{"{{domain}}", "{{reason}}"} {
			if !strings.Contains(text, placeholder) {
				t.Errorf("%s drops %s from the failure sentence", lang, placeholder)
			}
		}
	}
}

// nested walks a decoded locale file to one string.
func nested(root map[string]any, path ...string) (string, bool) {
	var current any = root
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = object[key]
		if !ok {
			return "", false
		}
	}
	text, ok := current.(string)
	return text, ok
}
