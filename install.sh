#!/usr/bin/env bash
# Servika one-line installation bootstrap
#   curl -fsSL https://raw.githubusercontent.com/ServikaPanel/servika/main/install.sh | bash
#
# This bootstrap downloads the latest published release bundle for the host
# architecture from GitHub Releases, then runs servika-install.sh from it.
# Set SERVIKA_RELEASE_TAG to install a specific release, e.g.
#   SERVIKA_RELEASE_TAG=v1.0.0 bash install.sh
# Any remaining arguments (such as --admin-password) are forwarded to the installer.
set -euo pipefail

# sudo builds PATH from scratch out of secure_path, which on AlmaLinux 10 is
# /sbin:/bin:/usr/sbin:/usr/bin and excludes /usr/local/bin. The ops tools and
# wp-cli install there, so without this every `command -v servika-*` guard
# reports an installed tool as absent and the step is skipped silently. This
# script execs servika-install.sh, which inherits the environment, so the fix
# has to start here.
case ":$PATH:" in
  *:/usr/local/bin:*) : ;;
  *) export PATH="/usr/local/sbin:/usr/local/bin:$PATH" ;;
esac

# Parse in the C locale. Under tr_TR.UTF-8 the ranges `a-z` and `A-Z` do NOT
# contain `i` or `I`, so every character-range parse is cut at the first one
# (measured: `grep -oE '[a-zA-Z0-9_]+'` answers `aud` for `audit_log`). The
# brand name SERVIKA carries an I, so this reaches the environment loader too.
export LC_ALL=C

REPO="ServikaPanel/servika"

c_b="\033[1;34m"; c_g="\033[32m"; c_r="\033[31m"; c_0="\033[0m"
[ -t 1 ] || { c_b=; c_g=; c_r=; c_0=; }
die(){ echo -e "${c_r}✗ $*${c_0}" >&2; exit 1; }

# download_file <url> <out>: fetch a URL to a file. Some VPS networks advertise
# IPv6 but have no working IPv6 egress, so retry with IPv4 before failing.
download_file(){
  curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" ||
    curl -4fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
}

verify_release_bundle(){
  local bundle_path="$1"
  local sums_path="$2"
  local bundle_name="$3"
  local expected actual
  expected=$(awk -v name="$bundle_name" '$2 == name {print $1; exit}' "$sums_path")
  if ! printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    die "SHA256SUMS does not contain a valid checksum for $bundle_name"
  fi
  actual=$(sha256sum "$bundle_path" | cut -d' ' -f1)
  [ "$actual" = "$expected" ] || die "checksum mismatch for $bundle_name"
}

[ "$(id -u)" = 0 ] || die "root is required:  curl ... | sudo bash"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

MACHINE=$(uname -m)
case "$MACHINE" in
  x86_64)  ARCH=linux_amd64 ;;
  aarch64) ARCH=linux_arm64 ;;
  *)       echo -e "${c_r}✗ unsupported architecture: $MACHINE (expected x86_64 or aarch64)${c_0}"; exit 1 ;;
esac

TAG="${SERVIKA_RELEASE_TAG:-}"
if [ -z "$TAG" ]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
fi
[ -n "$TAG" ] || { echo -e "${c_r}✗ could not determine the latest release tag${c_0}"; exit 1; }
VERSION="${TAG#v}"

BUNDLE="servika-${VERSION}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${BUNDLE}"
SUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
echo -e "${c_b}══ Downloading Servika ${VERSION} (${ARCH}) ══${c_0}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
download_file "$URL" "$TMP/$BUNDLE" || die "download failed: $URL"
# Verify the bundle against the release SHA256SUMS before extracting so a
# corrupted or tampered artifact is never unpacked as root.
download_file "$SUMS_URL" "$TMP/SHA256SUMS" || die "download failed: $SUMS_URL"
verify_release_bundle "$TMP/$BUNDLE" "$TMP/SHA256SUMS" "$BUNDLE"
echo -e "${c_g}✓ checksum verified${c_0}"
tar xz -C "$TMP" -f "$TMP/$BUNDLE" || die "extraction failed"

cd "$TMP"
chmod +x servika-install.sh "assets/$ARCH/servika-server" "assets/$ARCH/servika-seed-admin" assets/ops/* 2>/dev/null || true
echo -e "${c_g}✓ downloaded, starting installation${c_0}\n"
exec bash servika-install.sh "$@"
