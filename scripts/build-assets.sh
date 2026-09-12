#!/usr/bin/env bash
# Builds Linux release binaries for amd64 and arm64.
#
#   build-assets.sh <version>   # e.g. build-assets.sh 1.0.0
#
# The version is required and embedded into the binary via ldflags. It is not
# written to version.json; update that separately when publishing a release.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  printf 'Error: version argument is required (usage: %s <version>)\n' "$(basename "$0")" >&2
  exit 1
fi

# ── vulnerability gate ───────────────────────────────────────────────────
# Fail the release before packaging if a known vulnerability is reachable from
# our code. Combined with the `go` directive in go.mod, this runs against
# the pinned patched standard library. govulncheck is pinned for reproducibility
# and invoked module-agnostically, so it does not modify go.mod/go.sum.
GOVULNCHECK_VERSION="v1.6.0"
printf 'Scanning for known vulnerabilities (govulncheck %s)...\n' "$GOVULNCHECK_VERSION"
if ! go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...; then
  printf 'Error: govulncheck reported a reachable vulnerability; refusing to build release assets.\n' >&2
  exit 1
fi
printf 'No reachable vulnerabilities found.\n\n'

export CGO_ENABLED=0
export GOOS=linux

BUILD_DATE="$(date -u +%Y-%m-%d)"
LDFLAGS="-X main.version=$VERSION -X main.buildDate=$BUILD_DATE"

# ── linux/amd64 ──────────────────────────────────────────────────────────
export GOARCH=amd64
export GOAMD64=v1

printf 'Building servika-server (linux/amd64, GOAMD64=%s, version=%s, build_date=%s)\n' "$GOAMD64" "$VERSION" "$BUILD_DATE"
mkdir -p release/linux_amd64
go build -trimpath -ldflags "$LDFLAGS" -o release/linux_amd64/servika-server ./cmd/server

printf 'Building servika-seed-admin (linux/amd64, GOAMD64=%s)\n' "$GOAMD64"
go build -trimpath -o release/linux_amd64/servika-seed-admin scripts/seed_admin.go

for binary in release/linux_amd64/servika-server release/linux_amd64/servika-seed-admin; do
  if ! go version -m "$binary" | grep -Eq '^[[:space:]]*build[[:space:]]+GOAMD64=v1$'; then
    printf 'Error: %s was not built with GOAMD64=v1\n' "$binary" >&2
    exit 1
  fi
done
printf 'Release binaries built and verified for linux/amd64 (GOAMD64=v1).\n'

# ── linux/arm64 ──────────────────────────────────────────────────────────
export GOARCH=arm64
unset GOAMD64

printf '\nBuilding servika-server (linux/arm64, version=%s, build_date=%s)\n' "$VERSION" "$BUILD_DATE"
mkdir -p release/linux_arm64
go build -trimpath -ldflags "$LDFLAGS" -o release/linux_arm64/servika-server ./cmd/server

printf 'Building servika-seed-admin (linux/arm64)\n'
go build -trimpath -o release/linux_arm64/servika-seed-admin scripts/seed_admin.go

for binary in release/linux_arm64/servika-server release/linux_arm64/servika-seed-admin; do
  if ! go version -m "$binary" | grep -Eq '^[[:space:]]*build[[:space:]]+GOARCH=arm64$'; then
    printf 'Error: %s was not built with GOARCH=arm64\n' "$binary" >&2
    exit 1
  fi
done
printf 'Release binaries built and verified for linux/arm64.\n'

echo ''
printf 'All release binaries ready: linux/amd64 + linux/arm64.\n'
