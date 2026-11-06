#!/usr/bin/env bash
# Exercise privacy controls in the compiled app using disposable app/defaults
# identities and default history storage in a private, isolated home.
set -euo pipefail
umask 077

YAP_PRIVACY_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
YAP_PRIVACY_APP="${1:-$YAP_PRIVACY_REPO/dist/Yap.app}"
YAP_PRIVACY_RECEIPTS="${2:-$YAP_PRIVACY_REPO/dist/security-audit/packaged-privacy}"
[[ "$(uname -s)" == Darwin ]] || { echo "macOS is required" >&2; exit 2; }
[[ -x "$YAP_PRIVACY_APP/Contents/MacOS/Yap" ]] || { echo "build Yap.app first" >&2; exit 2; }
[[ -x /usr/bin/sandbox-exec ]] || { echo "sandbox-exec is required to deny network egress" >&2; exit 2; }
codesign --verify --deep --strict "$YAP_PRIVACY_APP"
mkdir -p "$YAP_PRIVACY_RECEIPTS"

YAP_PRIVACY_WORK="$(mktemp -d /private/tmp/yap-privacy.XXXXXXXX)"
YAP_PRIVACY_ID="dev.yap.privacyprobe.$(uuidgen | tr '[:upper:]' '[:lower:]')"
YAP_PRIVACY_COPY="$YAP_PRIVACY_WORK/YapPrivacyProbe.app"
# Make the complete expected support path exist before Foundation normalizes it;
# existing /private/tmp aliases can otherwise differ from nonexistent descendants.
mkdir -p "$YAP_PRIVACY_WORK/home/Library/Application Support"
printf '%s' "$YAP_PRIVACY_ID" > "$YAP_PRIVACY_WORK/probe-id"
# Preserve attributes, including quarantine. Only the copied bundle's identity
# and local signature change; the source bundle remains untouched.
ditto "$YAP_PRIVACY_APP" "$YAP_PRIVACY_COPY"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $YAP_PRIVACY_ID" "$YAP_PRIVACY_COPY/Contents/Info.plist"
codesign --force --sign - "$YAP_PRIVACY_COPY"
codesign --verify --deep --strict "$YAP_PRIVACY_COPY"

# Deny IP networking while retaining the Unix-domain socket used by AgentServer.
# A broken delegation guard must not download a model or contact a sidecar.
cat > "$YAP_PRIVACY_WORK/network.sb" <<'SANDBOX'
(version 1)
(allow default)
(deny network*)
(allow network* (local unix-socket))
(allow network* (remote unix-socket))
SANDBOX

printf 'source_commit=%s\nprobe_bundle_id=%s\n' \
  "$(git -C "$YAP_PRIVACY_REPO" rev-parse HEAD)" "$YAP_PRIVACY_ID" \
  > "$YAP_PRIVACY_RECEIPTS/provenance.txt"
shasum -a 256 "$YAP_PRIVACY_APP/Contents/MacOS/Yap" >> "$YAP_PRIVACY_RECEIPTS/provenance.txt"
shasum -a 256 "$YAP_PRIVACY_COPY/Contents/MacOS/Yap" > "$YAP_PRIVACY_RECEIPTS/probe-executable-before.sha256"

set +e
python3 - "$YAP_PRIVACY_WORK" "$YAP_PRIVACY_ID" "$YAP_PRIVACY_COPY" \
  "$YAP_PRIVACY_RECEIPTS/privacy-probe.log" <<'PY'
import os
from pathlib import Path
import subprocess
import sys

probe_root, probe_id, probe_app, probe_log = sys.argv[1:]
probe_environment = os.environ.copy()
for key in ("YAP_HISTORY_FILE", "YAP_API_SOCKET"):
    probe_environment.pop(key, None)
probe_environment.update({
    "CFFIXED_USER_HOME": str(Path(probe_root) / "home"),
    "YAP_PRIVACY_TEST_ROOT": probe_root,
    "YAP_PRIVACY_TEST_ID": probe_id,
    "YAP_PRIVACY_SANDBOX_ACTIVE": "1",
})
probe_command = ["/usr/bin/sandbox-exec", "-f", str(Path(probe_root) / "network.sb"),
                 str(Path(probe_app) / "Contents/MacOS/Yap"), "--privacytest"]
with open(probe_log, "w") as receipt:
    try:
        result = subprocess.run(probe_command, env=probe_environment,
                                stdout=receipt, stderr=subprocess.STDOUT, timeout=180)
        probe_result = result.returncode
    except subprocess.TimeoutExpired:
        receipt.write("\nFAIL: privacy probe exceeded its 180-second limit\n")
        probe_result = 124
sys.exit(probe_result)
PY
YAP_PRIVACY_RESULT=$?
set -e
# Also clean up the unique test domain if a timeout prevented Swift's defer.
/usr/bin/defaults delete "$YAP_PRIVACY_ID" >/dev/null 2>&1 || true
cat "$YAP_PRIVACY_RECEIPTS/privacy-probe.log"
if [[ -f "$YAP_PRIVACY_WORK/privacy-report.json" ]]; then
  cp "$YAP_PRIVACY_WORK/privacy-report.json" "$YAP_PRIVACY_RECEIPTS/privacy-report.json"
else
  echo "privacy probe produced no report" >&2
  YAP_PRIVACY_RESULT=1
fi
codesign --verify --deep --strict "$YAP_PRIVACY_APP"
codesign --verify --deep --strict "$YAP_PRIVACY_COPY"
shasum -a 256 "$YAP_PRIVACY_COPY/Contents/MacOS/Yap" > "$YAP_PRIVACY_RECEIPTS/probe-executable-after.sha256"
cmp "$YAP_PRIVACY_RECEIPTS/probe-executable-before.sha256" "$YAP_PRIVACY_RECEIPTS/probe-executable-after.sha256"
printf 'receipts=%s\n' "$YAP_PRIVACY_RECEIPTS"
# Use the project's trash convention when available. Otherwise retain this
# uniquely named test directory for diagnosis; hosted runners discard it.
if command -v trash >/dev/null 2>&1; then
  trash "$YAP_PRIVACY_WORK"
else
  printf 'temporary_probe_directory=%s\n' "$YAP_PRIVACY_WORK"
fi
exit "$YAP_PRIVACY_RESULT"
