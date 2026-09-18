#!/usr/bin/env bash
# Builds the Windows agent, on its own.
#
# It is deliberately NOT part of build-assets.sh. If one script produced both
# artefacts, every panel release would also refresh the agent artefact, and
# "the agent updates independently of the panel" would be true on paper only.
# The agent is built here and nowhere else.
#
# GOAMD64=v1 for the same reason as the panel build: on an older processor a v3
# instruction does not run slowly, it does not run at all (SIGILL).
#
# The agent's version is the constant in internal/platform, NOT a -ldflags
# value: the agent reports its own version over /health and compares it during
# a self-update, so the number has to survive a build that forgot the flag.
set -euo pipefail
cd "$(dirname "$0")/.."

export CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1

out="release/servika-agent-windows-amd64.exe"
mkdir -p release

echo "== building servika-agent (windows/amd64, GOAMD64=$GOAMD64) =="
go build -trimpath -o "$out" ./cmd/servika-agent

ls -la "$out"
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$out"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$out"
fi

echo "Done. This artefact is INDEPENDENT of the panel release."
echo "Install it on the host with: servika-agent-windows-amd64.exe install"
