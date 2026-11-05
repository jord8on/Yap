#!/usr/bin/env bash
# HTTPS smoke test against the exact Python sidecar embedded in the packaged
# .app. Runs under an isolated throwaway home/token; no speech model downloads.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/dist/Yap.app"
PY="$APP/Contents/Resources/python/bin/python3"
SERVER="$APP/Contents/Resources/repo/backend/server.py"
OUT="$ROOT/dist/security-audit"
mkdir -p "$OUT"
test -x "$PY" && test -f "$SERVER"

DIR="$(mktemp -d)"
chmod 700 "$DIR"
TOKEN="$DIR/auth-token"
# Never print credentials to Actions logs or to artifacts.
python3 - "$TOKEN" <<'PY'
import pathlib, secrets, sys
p = pathlib.Path(sys.argv[1])
p.write_text(secrets.token_urlsafe(32))
p.chmod(0o600)
PY
mkdir "$DIR/models"
PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
PYTHONNOUSERSITE=1 PYTHONPATH="" YAP_AUTH_TOKEN_FILE="$TOKEN" YAP_MODELS_DIR="$DIR/models" \
    "$PY" "$SERVER" --no-preload --port "$PORT" \
    --models-dir "$DIR/models" >"$OUT/packaged-backend.log" 2>&1 &
PID=$!
cleanup() {
  kill "$PID" >/dev/null 2>&1 || true
  wait "$PID" >/dev/null 2>&1 || true
  rm -rf "$DIR"
}
trap cleanup EXIT

CERT="$DIR/backend-tls-cert.pem"
URL="https://127.0.0.1:$PORT"
ready=0
for _ in $(seq 1 100); do
  if [ -f "$CERT" ] && curl --silent --fail --max-time 2 --cacert "$CERT" \
    "$URL/verify?nonce=packaged-tls-smoke" -o "$DIR/proof.json"; then
    ready=1
    break
  fi
  if ! kill -0 "$PID" >/dev/null 2>&1; then
    echo "Backend terminated before TLS became ready" >&2
    tail -30 "$OUT/packaged-backend.log" >&2
    exit 1
  fi
  sleep 0.15
done
if [ "$ready" != 1 ]; then echo "Backend TLS startup timeout" >&2; exit 1; fi

# /verify is proof of identity without transmitting the token.
python3 - "$TOKEN" "$DIR/proof.json" <<'PY'
import hashlib, hmac, json, pathlib, sys
token = pathlib.Path(sys.argv[1]).read_text()
proof = json.loads(pathlib.Path(sys.argv[2]).read_text())["proof"]
expected = hmac.new(token.encode(), b"packaged-tls-smoke", hashlib.sha256).hexdigest()
assert hmac.compare_digest(proof, expected), "Unexpected backend HMAC proof"
PY

health_code="$(curl --silent --max-time 5 --cacert "$CERT" \
  -H "Authorization: Bearer $(cat "$TOKEN")" \
  -o "$DIR/health.json" -w '%{http_code}' "$URL/health")"
[ "$health_code" = 200 ] || { echo "Authenticated HTTPS health returned $health_code"; exit 1; }
unauth_code="$(curl --silent --max-time 5 --cacert "$CERT" \
  -o /dev/null -w '%{http_code}' "$URL/health")"
[ "$unauth_code" = 401 ] || { echo "Unauthenticated health returned $unauth_code"; exit 1; }
bad_header="$(printf 'Authorization: Bearer %s' 'definitely-not-the-secret')"
wrong_code="$(curl --silent --max-time 5 --cacert "$CERT" \
  -H "$bad_header" \
  -o /dev/null -w '%{http_code}' "$URL/health")"
[ "$wrong_code" = 401 ] || { echo "Wrong-token health returned $wrong_code"; exit 1; }

# Cleartext HTTP on the protected port must not return a usable health reply.
if curl --silent --fail --max-time 2 "http://127.0.0.1:$PORT/health" \
      -o "$DIR/http-response.json"; then
  echo "Unsafe cleartext HTTP received a successful response" >&2
  exit 1
fi

# Ensure the keys cannot be read by another local user.
python3 - "$DIR" <<'PY'
from pathlib import Path
import stat, sys
d = Path(sys.argv[1])
for p in (d, d / "backend-tls-cert.pem", d / "backend-tls-key.pem", d / "auth-token"):
    assert not p.is_symlink(), p.name
    assert not (p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)), p.name
PY

printf 'PASS: actual packaged backend serves authenticated HTTPS, HMAC challenge, 401 for bad tokens, and rejects plaintext HTTP\n'
