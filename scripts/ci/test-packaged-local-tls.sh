#!/usr/bin/env bash
# HTTPS smoke test against the exact Python sidecar embedded in the packaged
# .app. Runs with a private throwaway token/model directory. CI can opt into
# downloading hash-pinned public Kokoro models and synthesizing test text.
# The sidecar itself must work with outbound network connections denied.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/dist/Yap.app"
PY="$APP/Contents/Resources/python/bin/python3"
SERVER="$APP/Contents/Resources/repo/backend/server.py"
OUT="$ROOT/dist/security-audit"
mkdir -p "$OUT"
test -x "$PY" && test -f "$SERVER"
[[ "$(uname -s)" == Darwin && -x /usr/bin/sandbox-exec ]] || {
  echo "macOS sandbox-exec is required for the packaged backend network check" >&2
  exit 2
}

DIR="$(mktemp -d)"
chmod 700 "$DIR"
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DIR"
}
trap cleanup EXIT

# Deny connection initiation by the backend while retaining inbound loopback
# HTTPS. Model assets are downloaded separately, never by the sandboxed sidecar.
YAP_TLS_NETWORK_PROFILE="$DIR/backend-network.sb"
cat > "$YAP_TLS_NETWORK_PROFILE" <<'SANDBOX'
(version 1)
(allow default)
(deny network-outbound)
SANDBOX
cp "$YAP_TLS_NETWORK_PROFILE" "$OUT/packaged-backend-network.sb"

# A timeout or an unreachable route is NOT evidence that the sandbox denied a
# connection. The same embedded Python and profile must produce EPERM/EACCES.
# 192.0.2.1 is a documentation address; no DNS lookup or user data is involved.
python3 - "$PY" "$YAP_TLS_NETWORK_PROFILE" "$OUT" <<'PY'
from pathlib import Path
import errno, hashlib, json, os, subprocess, sys

embedded_python, profile, output = sys.argv[1:]
probe = r'''
import errno, json, socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
    connection.settimeout(2)
    try:
        connection.connect(("192.0.2.1", 9))
    except PermissionError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
        print(json.dumps({"result": "denied", "error_type": type(error).__name__,
                          "errno": error.errno, "target": "192.0.2.1:9"}))
    else:
        raise SystemExit("FAIL: outbound connection was unexpectedly permitted")
'''
environment = os.environ.copy()
environment.update({"PYTHONNOUSERSITE": "1", "PYTHONPATH": ""})
command = ["/usr/bin/sandbox-exec", "-f", profile, embedded_python, "-B", "-c", probe]
log = Path(output, "packaged-network-canary.log")
try:
    result = subprocess.run(command, env=environment, capture_output=True,
                            text=True, timeout=15)
except subprocess.TimeoutExpired:
    log.write_text("FAIL: outbound-denial canary exceeded its 15-second limit\n")
    raise SystemExit(log.read_text())
log.write_text(result.stdout + result.stderr)
if result.returncode != 0:
    raise SystemExit("FAIL: outbound-denial canary did not report PermissionError\n" + log.read_text())
canary = json.loads(result.stdout)
assert canary["result"] == "denied" and canary["error_type"] == "PermissionError", canary
assert canary["errno"] in (errno.EPERM, errno.EACCES), canary
receipt = {
    "scope": "packaged Python sidecar; not a full-app packet trace",
    "profile_sha256": hashlib.sha256(Path(profile).read_bytes()).hexdigest(),
    "embedded_python_sha256": hashlib.sha256(Path(embedded_python).read_bytes()).hexdigest(),
    "canary": canary,
    "backend_https_checks": "not-completed",
    "kokoro_synthesis": "not-completed",
}
Path(output, "packaged-network-denial.json").write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS: same-profile outbound canary received PermissionError errno=" + str(canary["errno"]))
PY

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
    /usr/bin/sandbox-exec -f "$YAP_TLS_NETWORK_PROFILE" \
    "$PY" -B "$SERVER" --no-preload --port "$PORT" \
    --models-dir "$DIR/models" >"$OUT/packaged-backend.log" 2>&1 &
PID=$!

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

# The TLS listener must reject the protocol itself, even for unauthenticated
# requests. Merely using curl --fail would also accept a cleartext HTTP 401.
http_code="$(curl --silent --max-time 2 "http://127.0.0.1:$PORT/health" \
      -o "$DIR/http-response.json" -w '%{http_code}' || true)"
if [ "$http_code" != 000 ]; then
  echo "Unsafe cleartext HTTP received status $http_code" >&2
  exit 1
fi

# Parallel real TLS connections must all authenticate to the same per-user
# identity. Reuse neither an insecure context nor curl's connection cache.
python3 - "$CERT" "$TOKEN" "$URL" <<'PY'
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json, ssl, sys, urllib.error, urllib.request
cert, token_path, base = sys.argv[1:]
token = Path(token_path).read_text()
def health(_):
    context = ssl.create_default_context(cafile=cert)
    request = urllib.request.Request(base + "/health", headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        assert response.status == 200
        assert isinstance(json.load(response), dict)
with ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(health, range(24)))
try:
    urllib.request.urlopen(base + "/health", context=ssl.create_default_context(), timeout=5)
except urllib.error.URLError as error:
    assert isinstance(error.reason, ssl.SSLCertVerificationError), type(error.reason)
else:
    raise AssertionError("An untrusted TLS certificate was accepted")
print("PASS: 24 concurrent authenticated TLS connections; default trust rejects local certificate")
PY

# Exercise a real model through the packaged server, not a mock response. All
# input is synthetic and sent only to the pinned loopback TLS listener. Model
# downloads are public assets verified by the bundled downloader's SHA-256s.
# Only this separate downloader can use outbound networking; synthesis remains
# in the sidecar launched above with network-outbound denied.
if [ "${YAP_PACKAGE_TEST_SYNTHESIS:-0}" = 1 ]; then
  "$PY" -B "$APP/Contents/Resources/repo/backend/download_models.py" \
    --models-dir "$DIR/models" > "$OUT/packaged-model-download.log" 2>&1
  python3 - "$CERT" "$TOKEN" "$URL" "$OUT" <<'PY'
from pathlib import Path
import hashlib, io, json, ssl, sys, urllib.error, urllib.request, wave
cert, token_path, base, output = sys.argv[1:]
context = ssl.create_default_context(cafile=cert)
token = Path(token_path).read_text()
sample = ("This is synthetic speech for the Yap security integration test. "
          "It contains no private information. The next sentence checks streaming. ") * 6
payload = json.dumps({"text": sample, "voice": "af_heart"}).encode()
receipts = {}
for format_name in ("pcm", "wav"):
    request = urllib.request.Request(base + "/synthesize?format=" + format_name,
        data=payload, headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json"})
    with urllib.request.urlopen(request, context=context, timeout=120) as response:
        assert response.status == 200
        audio = response.read(24_000 * 2 * 240 + 5)
        assert len(audio) < 24_000 * 2 * 240, "Unexpectedly oversized audio response"
        if format_name == "pcm":
            assert response.headers.get("X-Stream-Footer") == "YEND"
            assert audio.endswith(b"YEND"), "Incomplete PCM stream"
            pcm = audio[:-4]
            assert len(pcm) > 4_800 and len(pcm) % 2 == 0 and any(pcm)
            frames = len(pcm) // 2
        else:
            with wave.open(io.BytesIO(audio)) as wav:
                assert (wav.getframerate(), wav.getnchannels(), wav.getsampwidth()) == (24_000, 1, 2)
                frames = wav.getnframes()
                assert frames > 2_400 and any(wav.readframes(frames))
        receipts[format_name] = {"bytes": len(audio), "frames": frames,
                                "sha256": hashlib.sha256(audio).hexdigest()}
# A browser origin cannot use even a valid credential to invoke synthesis.
blocked = urllib.request.Request(base + "/synthesize", data=payload, headers={
    "Authorization": "Bearer " + token, "Content-Type": "application/json",
    "Origin": "https://security-test.invalid"})
try:
    urllib.request.urlopen(blocked, context=context, timeout=10)
except urllib.error.HTTPError as error:
    assert error.code == 403, error.code
else:
    raise AssertionError("Browser-origin synthesis was accepted")
Path(output, "packaged-synthesis.json").write_text(json.dumps(receipts, indent=2) + "\n")
print("PASS: real hash-verified Kokoro synthesis over TLS; PCM completion footer, WAV format, browser-origin rejection")
PY
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

python3 - "$OUT/packaged-network-denial.json" "${YAP_PACKAGE_TEST_SYNTHESIS:-0}" <<'PY'
from pathlib import Path
import json, sys
receipt_path = Path(sys.argv[1])
receipt = json.loads(receipt_path.read_text())
receipt["backend_https_checks"] = "passed-with-outbound-denied"
receipt["kokoro_synthesis"] = "passed-with-outbound-denied" if sys.argv[2] == "1" else "not-requested"
receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
PY

printf 'PASS: actual packaged backend serves authenticated HTTPS, HMAC challenge, 401 for bad tokens, and rejects plaintext HTTP with outbound networking denied\n'
