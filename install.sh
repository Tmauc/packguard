#!/usr/bin/env bash
# PackGuard one-shot installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Tmauc/packguard/main/install.sh | sh
#
# What it does:
#   1. Detects OS + arch, picks the matching release asset from the
#      GitHub Releases page of the repo named below.
#   2. Downloads the archive + the SHA256SUMS index.
#   3. Verifies the archive's checksum. Aborts if the hash doesn't match.
#   4. Extracts the binary into $PACKGUARD_INSTALL_DIR (default
#      /usr/local/bin, falls back to ~/.local/bin when /usr/local/bin
#      isn't writable — no sudo prompts).
#
# Configurable via env:
#   PACKGUARD_REPO         owner/name on GitHub          (default: Tmauc/packguard)
#   PACKGUARD_VERSION      tag to install                 (default: latest)
#   PACKGUARD_INSTALL_DIR  where to drop the binary
#   PACKGUARD_TMPDIR       override the extraction spool  (default: mktemp)
#
# Zero-trust defaults: we always pin to the release's own SHA256SUMS,
# never to a hash baked into this script — that way the installer
# survives rotations and future releases without a rebake.

set -euo pipefail

REPO="${PACKGUARD_REPO:-Tmauc/packguard}"
VERSION="${PACKGUARD_VERSION:-latest}"
INSTALL_DIR="${PACKGUARD_INSTALL_DIR:-}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

# -- detect platform --------------------------------------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"
case "$uname_s" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  MINGW*|MSYS*|CYGWIN*) err "Windows: download the .zip from https://github.com/${REPO}/releases and extract packguard.exe onto your PATH manually (this script is POSIX-only)." ;;
  *) err "unsupported OS: $uname_s" ;;
esac
case "$uname_m" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) err "unsupported arch: $uname_m" ;;
esac
target="${arch}-${os}"
archive_ext="tar.gz"

# -- pick the install dir ---------------------------------------------
if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR"

# -- resolve version --------------------------------------------------
resolve_latest() {
  # GitHub serves `/releases/latest` as a 302 whose Location header
  # carries the real tag. Avoids hitting the JSON API (no rate-limit).
  curl -fsSI -o /dev/null -w '%{redirect_url}' \
    "https://github.com/${REPO}/releases/latest" | sed 's|.*/tag/||;s|[[:space:]]*$||'
}

if [ "$VERSION" = "latest" ]; then
  VERSION="$(resolve_latest)"
  [ -n "$VERSION" ] || err "could not resolve 'latest' release for ${REPO}. Set PACKGUARD_VERSION=vX.Y.Z explicitly."
fi
log "installing packguard ${VERSION} for ${target} -> ${INSTALL_DIR}"

asset="packguard-${VERSION}-${target}.${archive_ext}"
asset_url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
sums_url="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

# -- download + verify ------------------------------------------------
TMP="${PACKGUARD_TMPDIR:-$(mktemp -d)}"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/$asset" "$asset_url" \
  || err "download failed: $asset_url. Check that the release exists on https://github.com/${REPO}/releases/tag/${VERSION}"
curl -fsSL -o "$TMP/SHA256SUMS" "$sums_url" \
  || err "download failed: $sums_url"

expected="$(grep -F "$asset" "$TMP/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || err "no SHA256 line for ${asset} in SHA256SUMS — release may be incomplete."

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$TMP/$asset" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$TMP/$asset" | awk '{print $1}')"
else
  err "neither sha256sum nor shasum found — install one and re-run."
fi
[ "$expected" = "$actual" ] \
  || err "checksum mismatch: expected $expected, got $actual. Abort."

log "checksum verified ($actual)"

# -- extract + install ------------------------------------------------
( cd "$TMP" && tar xzf "$asset" )
stage_dir="$TMP/packguard-${VERSION}-${target}"
[ -x "$stage_dir/packguard" ] || err "packguard binary missing from archive: $stage_dir/packguard"

install -m 0755 "$stage_dir/packguard" "$INSTALL_DIR/packguard"
log "installed: $INSTALL_DIR/packguard"

# -- post-install sanity ----------------------------------------------
if ! printf '%s' ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
  warn "$INSTALL_DIR is not on your PATH. Add it:"
  # The literal '$PATH' in the hint is intentional — we want the user's
  # shell to expand it at runtime, not this installer.
  # shellcheck disable=SC2016
  printf '    export PATH="%s:$PATH"\n' "$INSTALL_DIR" >&2
fi

"$INSTALL_DIR/packguard" --version
log "done — run 'packguard init' in a repo to get started."
