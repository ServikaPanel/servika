package appruntime

// .NET Core support. Unlike Node and Python, .NET is NOT an interpreter whose
// path is written into a tenant application's ExecStart line, so it deliberately
// stays OUT of the Kind / Resolve / Installed model above: a caller never asks
// this package for a dotnet path. It is a server-wide capability the operator
// installs, so it is a curated catalog of dnf packages with rpm-based installed
// detection. It REUSES the detached-job machinery in job.go (one transient unit,
// one dnf slot, the shared Status and LogTail endpoints), so a dotnet install and
// a Node install cannot both hold the rpm lock at once.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"servika/internal/config"
	"servika/internal/httpx"
)

// DotnetComponent is one installable .NET package.
type DotnetComponent struct {
	Name        string `json:"name"`
	Package     string `json:"package"` // the dnf package name
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
}

// dotnetCatalog is the curated set of .NET packages AlmaLinux 10 AppStream ships.
// 10.0 is deliberately absent because it is not released for AlmaLinux 10, and
// offering a version dnf cannot find would draw a control whose only action fails.
func dotnetCatalog() []DotnetComponent {
	return []DotnetComponent{
		{Name: "ASP.NET Core Runtime 8.0", Package: "aspnetcore-runtime-8.0", Description: "Runs ASP.NET Core web apps (LTS)"},
		{Name: "ASP.NET Core Runtime 9.0", Package: "aspnetcore-runtime-9.0", Description: "Runs ASP.NET Core web apps (STS)"},
		{Name: ".NET SDK 8.0", Package: "dotnet-sdk-8.0", Description: "Build and develop with the dotnet CLI (LTS)"},
		{Name: ".NET SDK 9.0", Package: "dotnet-sdk-9.0", Description: "Build and develop with the dotnet CLI (STS)"},
	}
}

// dotnetInstalled reports whether a dnf package is installed. It is a variable so
// a test can drive the catalog's state without a real rpm database.
var dotnetInstalled = func(pkg string) bool {
	return systemCommandContext(context.Background(), "rpm", "-q", pkg).Run() == nil
}

// DotnetComponents returns the catalog with each component's installed state.
func DotnetComponents() []DotnetComponent {
	out := dotnetCatalog()
	for i := range out {
		out[i].Installed = dotnetInstalled(out[i].Package)
	}
	return out
}

// dotnetPackageKnown reports whether a package is exactly one the catalog names.
// It is the allowlist: only these strings ever reach a dnf argument or the script
// text, so arbitrary package install/remove is refused and no shell metacharacter
// can pass, because every catalog entry is a fixed literal.
func dotnetPackageKnown(pkg string) bool {
	for _, c := range dotnetCatalog() {
		if c.Package == pkg {
			return true
		}
	}
	return false
}

// dotnetInstallScript installs one .NET package with dnf. The package is a fixed
// catalog literal, so the echo lines interpolate it directly and the dnf argument
// is quoted for good measure.
func dotnetInstallScript(pkg string) string {
	q := config.ShellQuote(pkg)
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Installing ` + pkg + `"
if ! dnf install -y ` + q + `; then
  echo "FAILED: dnf could not install ` + pkg + `"
  exit 1
fi
echo "Done: ` + pkg + ` is installed"
`
}

func dotnetRemoveScript(pkg string) string {
	q := config.ShellQuote(pkg)
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Removing ` + pkg + `"
if ! dnf remove -y ` + q + `; then
  echo "FAILED: dnf could not remove ` + pkg + `"
  exit 1
fi
echo "Done: ` + pkg + ` is removed"
`
}

type dotnetReq struct {
	Package string `json:"package"`
}

func decodeDotnetPackage(r *http.Request) (string, bool) {
	var req dotnetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", false
	}
	return req.Package, dotnetPackageKnown(req.Package)
}

// DotnetList reports the .NET catalog with installed state.
// GET /app-runtimes/dotnet
func (h *Handlers) DotnetList(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"components": DotnetComponents()})
}

// DotnetInstall starts a detached .NET package installation.
// POST /app-runtimes/dotnet/install
func (h *Handlers) DotnetInstall(w http.ResponseWriter, r *http.Request) {
	pkg, ok := decodeDotnetPackage(r)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unknown .NET component")
		return
	}
	if dotnetInstalled(pkg) {
		httpx.WriteError(w, http.StatusConflict, "that component is already installed")
		return
	}
	// One dnf transaction at a time, shared with the Node and Python installs, so
	// two operations cannot meet over the rpm lock.
	if opRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a runtime operation is already running, try again when it finishes")
		return
	}
	descriptor := opDescriptor{Kind: "dotnet", Version: pkg, Action: "install"}
	if err := startOp(descriptor, dotnetInstallScript(pkg)); err != nil {
		log.Printf("dotnet install %s: %v", pkg, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the installation")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true, "package": pkg})
}

// DotnetRemove starts a detached .NET package removal. There is no application
// usage check as there is for Node and Python: a tenant application's runtime is
// node or python, never dotnet, so no apps row points at a .NET package.
// POST /app-runtimes/dotnet/remove
func (h *Handlers) DotnetRemove(w http.ResponseWriter, r *http.Request) {
	pkg, ok := decodeDotnetPackage(r)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unknown .NET component")
		return
	}
	if !dotnetInstalled(pkg) {
		httpx.WriteError(w, http.StatusConflict, "that component is not installed")
		return
	}
	if opRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a runtime operation is already running, try again when it finishes")
		return
	}
	descriptor := opDescriptor{Kind: "dotnet", Version: pkg, Action: "remove"}
	if err := startOp(descriptor, dotnetRemoveScript(pkg)); err != nil {
		log.Printf("dotnet remove %s: %v", pkg, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the removal")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true, "package": pkg})
}
