#!/usr/bin/env bash
# Assemble Yap.app from the SwiftPM build. Bundles the Python backend
# sources (not the venv/models — those live in Application Support).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPDIR="$ROOT/app"
CONFIG="${1:-release}"
OUT="$ROOT/dist"
DEST="$OUT/Yap.app"
SIGNING_MODE="${YAP_BUILD_SIGNING_MODE:-local}"

case "$SIGNING_MODE" in
  local)
    SIGN_ID="Yap Local Signing"
    SIGN_KC="$HOME/Library/Keychains/yap-signing.keychain-db"
    if [ ! -f "$SIGN_KC" ]; then
      echo "[build] local signing keychain is missing" >&2
      exit 1
    fi
    ;;
  evaluation)
    if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] ||
       [ -z "${YAP_EVALUATION_APPROVED_SHA:-}" ]; then
      echo "[build] evaluation signing requires an explicitly approved GitHub-hosted run" >&2
      exit 1
    fi
    case "${GITHUB_EVENT_NAME:-}" in
      workflow_dispatch|pull_request) ;;
      *) echo "[build] unsupported evaluation event" >&2; exit 1 ;;
    esac
    if [ "$(git -C "$ROOT" rev-parse HEAD)" != "$YAP_EVALUATION_APPROVED_SHA" ]; then
      echo "[build] checkout does not match the explicitly approved source SHA" >&2
      exit 1
    fi
    ;;
  developer-id)
    SIGN_ID="${YAP_DEVELOPER_ID:?Developer ID Application identity required}"
    [[ "$SIGN_ID" == "Developer ID Application: "* ]] || exit 1
    if [ "${PARLEY_BUNDLE_PYTHON:-1}" != 1 ]; then
      echo "[build] Developer ID packaging requires the bundled Python runtime" >&2
      exit 1
    fi
    ;;
  *) echo "[build] unknown signing mode: $SIGNING_MODE" >&2; exit 2 ;;
esac

echo "[build] swift build -c $CONFIG"
( cd "$APPDIR" && swift build -c "$CONFIG" --disable-automatic-resolution )
BIN="$(cd "$APPDIR" && swift build -c "$CONFIG" --disable-automatic-resolution --show-bin-path)/Yap"

mkdir -p "$OUT"
STAGE="$(mktemp -d "$OUT/.build-app.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
APP="$STAGE/Yap.app"
echo "[build] assembling $APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/repo"

cp "$BIN" "$APP/Contents/MacOS/Yap"
cp "$ROOT/app/Resources/Info.plist" "$APP/Contents/Info.plist"

# App icon (regenerate if the generator is newer than the icns).
ICON="$ROOT/app/Resources/AppIcon.icns"
if [ ! -f "$ICON" ] || [ "$ROOT/scripts/make_icon.swift" -nt "$ICON" ]; then
  echo "[build] rendering app icon"
  swift "$ROOT/scripts/make_icon.swift" "$STAGE" >/dev/null
  ICON="$STAGE/AppIcon.icns"
  iconutil -c icns "$STAGE/AppIcon.iconset" -o "$ICON"
fi
cp "$ICON" "$APP/Contents/Resources/AppIcon.icns"

# Bundle the openly-licensed HD starter voices (CMU ARCTIC) so every install
# has them out of the box; the app seeds them into Application Support on first
# run. Personal clones are NOT here (no redistribution rights).
if [ -d "$ROOT/app/Resources/hd-voices" ]; then
  mkdir -p "$APP/Contents/Resources/hd-voices"
  cp "$ROOT/app/Resources/hd-voices/"*.wav "$APP/Contents/Resources/hd-voices/" 2>/dev/null || true
fi

# Bundle backend sources + launcher so a packaged app can run self-contained.
# Copy every .py + requirements so new modules (e.g. pocket_engine) ship too.
# The Pocket installer reads requirements-pocket.txt from here, so a missing
# lock would only surface when a user clicks Install.
for lock in requirements.txt requirements-pocket.txt; do
  [ -s "$ROOT/backend/$lock" ] || { echo "[build] backend/$lock missing; run scripts/lock_python_deps.sh" >&2; exit 1; }
done
mkdir -p "$APP/Contents/Resources/repo/backend" "$APP/Contents/Resources/repo/scripts"
cp "$ROOT/backend/"*.py "$ROOT/backend/"requirements*.txt "$APP/Contents/Resources/repo/backend/"
cp "$ROOT/scripts/run_backend.sh" "$APP/Contents/Resources/repo/scripts/"
chmod +x "$APP/Contents/Resources/repo/scripts/run_backend.sh"

# The `yap` command-line client for the agent API (docs/AGENT-API.md): bash + curl,
# so it needs nothing installed. Users link it onto their PATH.
mkdir -p "$APP/Contents/Resources/bin"
cp "$ROOT/scripts/yap" "$APP/Contents/Resources/bin/yap"
chmod +x "$APP/Contents/Resources/bin/yap"

# Embed the self-contained Python runtime so the app needs no system Python.
# Built by scripts/bundle_python.sh (cached). Without it, the app falls back to
# building a venv from system Python (dev machines only).
if [ "${PARLEY_BUNDLE_PYTHON:-1}" = "1" ]; then
  # Always call it: it reuses its cache only when the Python pin and the lock
  # are the ones it was built from.
  bash "$ROOT/scripts/bundle_python.sh"
  echo "[build] embedding Python runtime"
  ditto --extattr --qtn "$ROOT/dist/python-runtime" "$APP/Contents/Resources/python"
fi

# Sign and verify the staged bundle before replacing the previous build.
case "$SIGNING_MODE" in
  local)
    # Keep the stable designated requirement for local Accessibility grants.
    security unlock-keychain -p yap-local "$SIGN_KC"
    codesign --force --deep --sign "$SIGN_ID" --keychain "$SIGN_KC" "$APP"
    ;;
  evaluation)
    echo "[build] ad-hoc signing for isolated evaluation"
    codesign --force --deep --sign - "$APP"
    ;;
  developer-id)
    find "$APP/Contents/Resources/python" -type f \( -name '*.dylib' -o -name '*.so' -o -perm -111 \) \
      -exec codesign --force --timestamp --options runtime --sign "$SIGN_ID" {} +
    codesign --force --deep --timestamp --options runtime --sign "$SIGN_ID" "$APP"
    ;;
esac
codesign --verify --deep --strict "$APP"

if [ -e "$DEST" ]; then trash "$DEST"; fi
mv "$APP" "$DEST"
echo "[build] done -> $DEST"
