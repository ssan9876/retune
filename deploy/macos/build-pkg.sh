#!/bin/sh
# Packages a built macOS agent as retune-agent.pkg. Runs on a Mac (pkgbuild,
# productsign and notarytool are Apple's).
#
#   deploy/macos/build-pkg.sh VERSION AGENT_BINARY OUT_PKG
#
# The binary should be the universal build, already code-signed if it is going
# to be, and already release-signed: signing it changes its bytes, so nothing
# here touches it.
#
# Optional, from the environment:
#   MACOS_INSTALLER_IDENTITY  a "Developer ID Installer: ..." identity in the
#                             keychain; the pkg is signed with it
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
#                             notarize and staple the signed pkg
set -eu

if [ $# -ne 3 ]; then
  echo "usage: $0 VERSION AGENT_BINARY OUT_PKG" >&2
  exit 2
fi
VERSION=$1
BINARY=$2
OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/root/usr/local/bin" "$WORK/scripts"
cp "$BINARY" "$WORK/root/usr/local/bin/retune-agent"
chmod 0755 "$WORK/root/usr/local/bin/retune-agent"
cp "$HERE/scripts/postinstall" "$WORK/scripts/postinstall"
chmod 0755 "$WORK/scripts/postinstall"

# pkg versions are dotted numbers; a prerelease keeps only its numeric core.
PKG_VERSION=$(printf '%s' "$VERSION" | sed 's/[-+].*//')

UNSIGNED="$WORK/unsigned.pkg"
pkgbuild \
  --root "$WORK/root" \
  --scripts "$WORK/scripts" \
  --identifier com.retune.agent \
  --version "$PKG_VERSION" \
  --install-location / \
  "$UNSIGNED"

if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
  productsign --sign "$MACOS_INSTALLER_IDENTITY" --timestamp "$UNSIGNED" "$OUT"
  if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    xcrun notarytool submit "$OUT" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_APP_PASSWORD" --wait
    xcrun stapler staple "$OUT"
  else
    echo "signed but not notarized: APPLE_ID, APPLE_TEAM_ID and APPLE_APP_PASSWORD are not all set"
  fi
else
  cp "$UNSIGNED" "$OUT"
  echo "unsigned: Gatekeeper will refuse a double-click install; MDM and 'sudo installer -pkg' do not care"
fi
echo "built $OUT ($PKG_VERSION)"
