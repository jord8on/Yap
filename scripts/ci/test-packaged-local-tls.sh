#!/usr/bin/env bash
# Exercise the packaged Python sidecar with a synthetic identity in isolated CI.
set -euo pipefail

if [ "${YAP_BUILD_SIGNING_MODE:-}" != evaluation ] ||
   [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] ||
   [ "${GITHUB_EVENT_NAME:-}" != workflow_dispatch ]; then
  echo "Packaged TLS smoke test requires the manually dispatched hosted evaluation" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESOURCES="$ROOT/dist/Yap.app/Contents/Resources"
PY="$RESOURCES/python/bin/python3"
SERVER="$RESOURCES/repo/backend/server.py"
test -x "$PY"
test -f "$SERVER"

umask 077
SCRATCH="$(mktemp -d "${RUNNER_TEMP:?}/yap-packaged-tls.XXXXXX")"
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

unset YAP_AUTH_TOKEN
TOKEN="$SCRATCH/auth-token"
CERT="$SCRATCH/backend-tls-cert.pem"
PORT="$("$PY" -I -B - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
YAP_AUTH_TOKEN_FILE="$TOKEN" "$PY" -E -s -B "$SERVER" --no-preload \
  --port "$PORT" --models-dir "$SCRATCH/models" > "$RECEIPTS/packaged-backend.log" 2>&1 &
PID=$!
URL="https://127.0.0.1:$PORT"

https() {
  curl -q --silent --show-error --noproxy '*' --max-time 3 --cacert "$CERT" "$@"
}

ready=0
for _ in $(seq 1 100); do
  if [ -f "$CERT" ] &&
     https --fail "$URL/verify?nonce=packaged-tls-smoke" -o "$SCRATCH/proof.json" 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.15
done
if [ "$ready" != 1 ]; then
  echo "Packaged sidecar failed to start over TLS. See packaged-backend.log." >&2
  exit 1
fi

# Confirm the generated identity and prepare a private curl header file.
"$PY" -I -B - "$SCRATCH" <<'PY'
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
for name in ("auth-token", "backend-tls-cert.pem", "backend-tls-key.pem"):
    info = (root / name).lstat()
    assert stat.S_ISREG(info.st_mode), name
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(), name
token = (root / "auth-token").read_bytes().strip()
expected = hmac.new(token, b"packaged-tls-smoke", hashlib.sha256).hexdigest()
proof = json.loads((root / "proof.json").read_text())["proof"]
assert hmac.compare_digest(proof, expected), "Unexpected backend HMAC proof"
(root / "auth-header").write_bytes(b"Authorization: Bearer " + token + b"\n")
PY

status() {
  https -o /dev/null -w '%{http_code}' "$@" "$URL/health"
}
test "$(status -H "@$SCRATCH/auth-header")" = 200
test "$(status)" = 401
test "$(status -H 'Authorization: Bearer invalid-smoke-token')" = 401
test "$(status -H "@$SCRATCH/auth-header" -H 'Origin: https://example.invalid')" = 403

if plaintext="$(curl -q --silent --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$PORT/health")"; then
  echo "Unexpected plaintext HTTP response ($plaintext)" >&2
  exit 1
fi
test "$plaintext" = 000

printf '%s\n' 'Packaged sidecar passed loopback TLS, HMAC, bearer rejection, browser-origin rejection, and plaintext refusal probes.'
