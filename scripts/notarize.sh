#!/usr/bin/env bash
# Sign and submit a release candidate for Apple notarization.
#
# Requires a paid Apple Developer account ($99/yr) and, one time:
#   1. A "Developer ID Application" certificate in your keychain.
#   2. A notarytool keychain profile:
#        xcrun notarytool store-credentials yap-notary \
#          --apple-id you@example.com --team-id TEAMID --password APP_SPECIFIC_PW
#
# Then: bash scripts/notarize.sh "Developer ID Application: Your Name (TEAMID)"
set -euo pipefail

if [ "${YAP_BUILD_SIGNING_MODE:-}" = evaluation ]; then
  echo "[notarize] evaluation builds are limited to workflow evidence" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDENTITY="${1:?pass the Developer ID Application identity}"
PROFILE="${YAP_NOTARY_PROFILE:-${PARLEY_NOTARY_PROFILE:-yap-notary}}"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/app/Resources/Info.plist")"
DMG="$ROOT/dist/Yap-$VERSION.dmg"

echo "[notarize] building and Developer ID signing app with bundled Python"
YAP_BUILD_SIGNING_MODE=developer-id YAP_DEVELOPER_ID="$IDENTITY" PARLEY_BUNDLE_PYTHON=1 \
  bash "$ROOT/scripts/build_app.sh" release

echo "[notarize] packaging DMG"
# Package the previously signed bundle to retain its Developer ID signature.
bash "$ROOT/scripts/make_dmg.sh" "$VERSION" --no-build >/dev/null

# Verify the bundle that will be submitted to Apple, inside the mounted DMG.
MNT="$(mktemp -d)"
hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MNT" >/dev/null
# Detach on any exit, or a failed check leaves the volume mounted.
trap 'hdiutil detach "$MNT" >/dev/null 2>&1 || true; rmdir "$MNT" 2>/dev/null || true' EXIT
codesign --verify --deep --strict "$MNT/Yap.app" \
  || { echo "[notarize] the DMG's bundle is not validly signed — aborting" >&2; exit 1; }
# --deep --strict passes on an ad-hoc signature too, so also require that the
# identity actually made it in. That is the failure #66 was: a correctly signed
# bundle carrying the WRONG signature.
SIGNATURE="$(codesign -dvv "$MNT/Yap.app" 2>&1)"
if ! grep -q '^Authority=Developer ID Application:' <<< "$SIGNATURE"; then
  echo "[notarize] the DMG's bundle lacks a Developer ID signature" >&2
  exit 1
fi
# Detach BEFORE submitting: stapler writes the ticket into this DMG, and doing
# that under a live read-only mount of the same file is asking for trouble. The
# trap stays armed as a safety net for the failure paths above.
hdiutil detach "$MNT" >/dev/null; rmdir "$MNT" 2>/dev/null || true
trap - EXIT
echo "[notarize] DMG contents verified: Developer ID signature intact"

echo "[notarize] submitting to Apple (this can take a few minutes)"
xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait

echo "[notarize] stapling ticket"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
echo "[notarize] done -> $DMG (stapled ticket validated)"
