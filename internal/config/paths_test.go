package config

import "testing"

func TestEnvStringReturnsFallbackWhenUnsetOrEmpty(t *testing.T) {
	t.Setenv("SERVIKA_TEST_VALUE", "")
	if got := EnvString("SERVIKA_TEST_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("EnvString() = %q, want fallback", got)
	}
}

func TestEnvStringReturnsTrimmedValue(t *testing.T) {
	t.Setenv("SERVIKA_TEST_VALUE", "  value  ")
	if got := EnvString("SERVIKA_TEST_VALUE", "fallback"); got != "value" {
		t.Fatalf("EnvString() = %q, want value", got)
	}
}

func TestEnvAbsPathRequiresAbsolutePath(t *testing.T) {
	t.Setenv("SERVIKA_TEST_PATH", "relative/bin")
	if _, err := EnvAbsPath("SERVIKA_TEST_PATH", "/fallback"); err == nil {
		t.Fatal("EnvAbsPath() error = nil, want error")
	}
}

func TestEnvAbsPathReturnsCleanAbsolutePath(t *testing.T) {
	t.Setenv("SERVIKA_TEST_PATH", "/opt/servika/../servika/bin")
	got, err := EnvAbsPath("SERVIKA_TEST_PATH", "/fallback")
	if err != nil {
		t.Fatalf("EnvAbsPath() error = %v", err)
	}
	if got != "/opt/servika/bin" {
		t.Fatalf("EnvAbsPath() = %q, want cleaned path", got)
	}
}

func TestEnvURLRequiresHTTPURL(t *testing.T) {
	t.Setenv("SERVIKA_TEST_URL", "file:///tmp/file")
	if _, err := EnvURL("SERVIKA_TEST_URL", "https://example.com"); err == nil {
		t.Fatal("EnvURL() error = nil, want error")
	}
}

func TestEnvURLReturnsHTTPSURL(t *testing.T) {
	t.Setenv("SERVIKA_TEST_URL", "https://example.com/path")
	got, err := EnvURL("SERVIKA_TEST_URL", "https://fallback.example")
	if err != nil {
		t.Fatalf("EnvURL() error = %v", err)
	}
	if got != "https://example.com/path" {
		t.Fatalf("EnvURL() = %q, want configured URL", got)
	}
}

func TestShellQuote(t *testing.T) {
	got := ShellQuote("/tmp/it's here")
	want := `'/tmp/it'\''s here'`
	if got != want {
		t.Fatalf("ShellQuote() = %q, want %q", got, want)
	}
}

func TestOpsToolUsesConfiguredOpsBin(t *testing.T) {
	t.Setenv("SERVIKA_OPSBIN", "/custom/bin")
	if got := OpsTool("servika-jail"); got != "/custom/bin/servika-jail" {
		t.Fatalf("OpsTool() = %q, want configured tool path", got)
	}
}

// The IonCube loader is published per architecture and the two archives carry
// IDENTICAL member names, so nothing downstream can notice that the wrong one
// was fetched. The panel ships arm64 builds and the address was x86-64 only, so
// on such a server it installed an object PHP could not load: measured, the
// interpreter prints "Failed loading ..." on stderr and CONTINUES, exit 0, and
// the install reported success.
//
// Both answers are measured on one machine, because the half that was wrong is
// exactly the half a test running on the other platform never reaches.
func TestTheIonCubeArchiveFollowsTheArchitecture(t *testing.T) {
	if got := ionCubeURLForArch("arm64"); got != DefaultIonCubeURLARM64 {
		t.Errorf("arm64 resolves to %q", got)
	}
	if got := ionCubeURLForArch("amd64"); got != DefaultIonCubeURLAMD64 {
		t.Errorf("amd64 resolves to %q", got)
	}
	if DefaultIonCubeURLAMD64 == DefaultIonCubeURLARM64 {
		t.Fatal("the two addresses are the same, so the mapping decides nothing")
	}
	// An unknown architecture keeps a usable address rather than answering
	// empty: EnvURL refuses an empty URL and the panel would not start at all
	// over a feature nobody on that platform can use. The ELF check in
	// internal/phpext is what refuses the download there.
	if got := ionCubeURLForArch("riscv64"); got != DefaultIonCubeURLAMD64 {
		t.Errorf("an unknown architecture resolved to %q, want the amd64 address", got)
	}
	if _, err := EnvURL("SERVIKA_IONCUBE_URL_UNSET_FOR_TEST", DefaultIonCubeURLForArch()); err != nil {
		t.Errorf("the resolved default is not a usable URL: %v", err)
	}
}

// An operator pointing at their own mirror keeps it, whatever this server's
// architecture is: the override is the whole point of the variable.
func TestAnOperatorMirrorOutranksTheArchitectureDefault(t *testing.T) {
	const mirror = "https://mirror.example.invalid/ioncube.tar.gz"
	t.Setenv("SERVIKA_IONCUBE_URL", mirror)
	if got := IonCubeURL(); got != mirror {
		t.Fatalf("IonCubeURL() = %q, want the operator's mirror", got)
	}
}
