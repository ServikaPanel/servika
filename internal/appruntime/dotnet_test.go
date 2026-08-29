package appruntime

import (
	"strings"
	"testing"
)

// TestDotnetComponentsReflectInstalledState proves the catalog reports each
// package's installed state from the (injected) detector rather than assuming it.
func TestDotnetComponentsReflectInstalledState(t *testing.T) {
	previous := dotnetInstalled
	dotnetInstalled = func(pkg string) bool { return pkg == "dotnet-sdk-8.0" }
	t.Cleanup(func() { dotnetInstalled = previous })

	got := DotnetComponents()
	if len(got) == 0 {
		t.Fatal("the catalog is empty")
	}
	var sawSDK8, sawOther bool
	for _, c := range got {
		if c.Package == "dotnet-sdk-8.0" {
			sawSDK8 = true
			if !c.Installed {
				t.Error("dotnet-sdk-8.0 should read as installed")
			}
		} else if c.Installed {
			sawOther = true
		}
	}
	if !sawSDK8 {
		t.Error("the catalog does not name dotnet-sdk-8.0")
	}
	if sawOther {
		t.Error("a component other than dotnet-sdk-8.0 read as installed")
	}
}

// TestDotnetPackageKnownIsTheAllowlist proves only exact catalog packages pass,
// so an arbitrary package or an injection string never reaches a dnf argument.
func TestDotnetPackageKnownIsTheAllowlist(t *testing.T) {
	for _, ok := range []string{"aspnetcore-runtime-8.0", "aspnetcore-runtime-9.0", "dotnet-sdk-8.0", "dotnet-sdk-9.0"} {
		if !dotnetPackageKnown(ok) {
			t.Errorf("catalog package %q was refused", ok)
		}
	}
	for _, bad := range []string{"", "dotnet-sdk-10.0", "bash", "dotnet-sdk-8.0; rm -rf /", "aspnetcore-runtime-8.0 ", "DOTNET-SDK-8.0"} {
		if dotnetPackageKnown(bad) {
			t.Errorf("non-catalog value %q was accepted", bad)
		}
	}
}

// TestDotnetScriptsUseDnfAndNameThePackage proves install and remove reach for
// dnf with the package quoted, and never for the Node version manager.
func TestDotnetScriptsUseDnfAndNameThePackage(t *testing.T) {
	install := dotnetInstallScript("dotnet-sdk-8.0")
	remove := dotnetRemoveScript("dotnet-sdk-8.0")
	if !strings.Contains(install, "dnf install -y 'dotnet-sdk-8.0'") {
		t.Errorf("the install script does not name the quoted package:\n%s", install)
	}
	if !strings.Contains(remove, "dnf remove -y 'dotnet-sdk-8.0'") {
		t.Errorf("the remove script does not name the quoted package:\n%s", remove)
	}
	if strings.Contains(install, "n install") {
		t.Error("the .NET installer reaches for the Node version manager")
	}
}
