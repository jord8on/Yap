#!/usr/bin/env bash
# Build-artifact inspection, not a notarization or malware-free certificate.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/dist/Yap.app"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/app/Resources/Info.plist")"
DMG="$ROOT/dist/Yap-$VERSION.dmg"
OUT="$ROOT/dist/security-audit"
mkdir -p "$OUT"
REPORT="$OUT/report.md"
echo '# Yap packaged-app security inspection' > "$REPORT"
echo >> "$REPORT"
echo "- Commit: $(git -C "$ROOT" rev-parse HEAD)" >> "$REPORT"
echo "- Runner: $(uname -s)-$(uname -m) / $(sw_vers -productVersion)" >> "$REPORT"
echo "- Package version: $VERSION" >> "$REPORT"
echo >> "$REPORT"

pass() { printf 'PASS: %s\n' "$*" | tee -a "$OUT/results.log"; printf -- '- **Passed:** %s\n' "$*" >> "$REPORT"; }
fix() { printf 'NEEDS FIXING: %s\n' "$*" | tee -a "$OUT/results.log"; printf -- '- **Needs Fixing:** %s\n' "$*" >> "$REPORT"; }
pending() { printf 'NOT YET TESTED: %s\n' "$*" | tee -a "$OUT/results.log"; printf -- '- **Not Yet Tested:** %s\n' "$*" >> "$REPORT"; }

test -d "$APP" && test -s "$DMG" || { echo 'Missing built .app or .dmg'; exit 1; }
test -x "$APP/Contents/MacOS/Yap" || { echo 'Missing Yap executable'; exit 1; }
test -x "$APP/Contents/Resources/python/bin/python3" || { echo 'Missing bundled CPython'; exit 1; }
pass "Full Yap.app, embedded CPython and DMG were created."

# Check the seal before any imports or runtime tests. A post-test failure
# means the test or app changed the signed bundle, not the signing step.
if codesign --verify --deep --strict --verbose=2 "$APP" > "$OUT/codesign-before-run.log" 2>&1; then
  pass "Signed app resource seal is valid before runtime execution."
else
  fix "App signature was already invalid before runtime execution."
fi

for name in requirements.txt requirements-pocket.txt; do
  file="$APP/Contents/Resources/repo/backend/$name"
  if test -s "$file" && grep -q -- '--hash=sha256:' "$file"; then
    pass "Packaged backend includes SHA-256-locked $name."
  else
    fix "Packaged backend missing hash-locked $name."
  fi
done
"$APP/Contents/Resources/python/bin/python3" -I -B - <<'PY'
import fastapi, kokoro_onnx, onnxruntime, soundfile, sys
assert sys.version_info[:2] == (3, 12), sys.version
print('Bundled imports passed', sys.version)
PY
pass "Packaged relocatable CPython imports TTS dependencies."

# Record the actual installed packages and exact Swift revisions in the audit
# artifact. This is an inventory, not a provenance attestation.
"$APP/Contents/Resources/python/bin/python3" -I -B -m pip inspect --local \
  > "$OUT/python-package-inventory.json"
cp "$ROOT/app/Package.resolved" "$OUT/swift-package-resolved.json"
cp "$APP/Contents/Resources/python/.yap-runtime-source" "$OUT/python-runtime-source.txt"
shasum -a 256 "$ROOT/backend/requirements.txt" "$ROOT/backend/requirements-pocket.txt" \
  "$ROOT/app/Package.resolved" > "$OUT/dependency-lock-hashes.txt"
pass "Installed Python package inventory, Swift revisions and dependency hashes were recorded."

# Exercise the actual packaged app executable, not only a SwiftPM test binary.
# This is a synthetic, isolated self-test without model downloads or user data.
if python3 - "$APP/Contents/MacOS/Yap" "$OUT" <<'PY'
import os, pathlib, subprocess, sys
exe, out = sys.argv[1:]
home = pathlib.Path(out) / "sandbox-home"
home.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env["HOME"] = str(home)
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["YAP_HISTORY_FILE"] = str(home / "history-probe.json")
with open(pathlib.Path(out) / "packaged-selftest.log", "w") as log:
    try:
        result = subprocess.run([exe, "--selftest"], env=env, stdout=log,
                                stderr=subprocess.STDOUT, timeout=100)
    except subprocess.TimeoutExpired:
        sys.exit(124)
    sys.exit(result.returncode)
PY
then
  pass "Actual packaged Yap executable completed its built-in self-test."
else
  fix "Packaged Yap --selftest failed or timed out; see packaged-selftest.log."
fi

if codesign --verify --deep --strict --verbose=2 "$APP" > "$OUT/app-codesign.log" 2>&1; then
  pass "Built app passes codesign --verify --deep --strict."
else
  fix "App fails codesign verification; see app-codesign.log."
fi
codesign -dv --verbose=4 "$APP" > "$OUT/app-signature.txt" 2>&1 || true

if /usr/libexec/PlistBuddy -c 'Print NSMicrophoneUsageDescription' "$APP/Contents/Info.plist" >/dev/null && \
   /usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$APP/Contents/Info.plist" > "$OUT/bundle-id.txt"; then
  pass "Packaged Info.plist has bundle identifier and microphone permission description."
else
  fix "Packaged Info.plist is incomplete."
fi

if grep -R -q -E 'xattr.*(-cr|-dr)|stripQuarantine' "$ROOT/app/Sources/Yap" "$ROOT/scripts/make_dmg.sh"; then
  fix "Source or DMG script still contains a quarantine-clearing operation."
else
  pass "Build source and DMG script contain no automated quarantine removal."
fi

MNT="$(mktemp -d)"
attached=0
cleanup() { if [ "$attached" = 1 ]; then hdiutil detach "$MNT" -quiet >/dev/null 2>&1 || true; fi; rmdir "$MNT" >/dev/null 2>&1 || true; }
trap cleanup EXIT
if hdiutil attach -readonly -nobrowse -quiet -mountpoint "$MNT" "$DMG" > "$OUT/mount.log" 2>&1; then
  attached=1
  if test -x "$MNT/Yap.app/Contents/MacOS/Yap" && \
    cmp -s "$APP/Contents/MacOS/Yap" "$MNT/Yap.app/Contents/MacOS/Yap"; then
    pass "Mounted DMG contains the exact inspected Yap executable."
  else
    fix "DMG contains absent or different executable."
  fi
  if codesign --verify --deep --strict --verbose=2 "$MNT/Yap.app" > "$OUT/dmg-codesign.log" 2>&1; then
    pass "Yap.app inside mounted DMG passes codesign verification."
  else
    fix "DMG app fails codesign verification."
  fi
else
  fix "DMG could not be mounted for independent inspection."
fi
printf 'DMG_SHA256 ' > "$OUT/hashes.txt"
shasum -a 256 "$DMG" >> "$OUT/hashes.txt"
printf 'YAP_EXECUTABLE_SHA256 ' >> "$OUT/hashes.txt"
shasum -a 256 "$APP/Contents/MacOS/Yap" >> "$OUT/hashes.txt"
printf 'BUNDLED_PYTHON_SHA256 ' >> "$OUT/hashes.txt"
shasum -a 256 "$APP/Contents/Resources/python/bin/python3" >> "$OUT/hashes.txt"

find "$APP/Contents/Resources/python" -type f \( -name '*.dylib' -o -name '*.so' -o -name '*.so.*' \) > "$OUT/native-library-inventory.txt" || true
find "$APP/Contents" -type l -print > "$OUT/symlink-inventory.txt"
du -sh "$APP" "$DMG" > "$OUT/artifact-sizes.txt"

pending "Developer ID signature and notarization: unavailable with free Apple account."
pending "Interactive microphone, Accessibility, clipboard permission UX: headless CI cannot grant or verify user consent."
pending "Dynamic egress/packet trace and negative exfiltration tests over full dictation/model-download flows."
pending "Native binary audit, malicious-behavior certification and provenance attestation for every vendored wheel."
pending "Long-running stability, sleep/wake, multi-instance UI use and real speech model operation."

echo >> "$REPORT"
echo 'This build is for security evaluation only. Do not install on a primary Mac or publish as a release.' >> "$REPORT"
cat "$REPORT"
# An audit receipt containing NEEDS FIXING is a failed CI validation,
# even if construction and other independent checks succeeded.
if grep -q '^NEEDS FIXING:' "$OUT/results.log"; then
  echo 'Packaged security inspection detected a blocking failure.' >&2
  exit 1
fi
