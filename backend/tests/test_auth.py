"""Loopback authorization, private token handling, and evaluation routes."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import os
import re
import stat
import sys
import threading
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse

import server

TOKEN = "unit-test-secret-token"


def _request(path="/health", headers=None):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {"type": "http", "method": "GET", "path": path,
             "headers": raw, "query_string": b"", "scheme": "https",
             "server": ("127.0.0.1", 8766)}
    return Request(scope)


def _run_guard(request):
    async def call_next(_req):
        return PlainTextResponse("reached", status_code=200)
    return asyncio.run(server.auth_guard(request, call_next))


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", TOKEN)


def _auth(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_health_requires_token():
    assert _run_guard(_request()).status_code == 401


def test_health_accepts_correct_token():
    assert _run_guard(_request(headers=_auth())).status_code == 200


def test_health_rejects_wrong_token():
    assert _run_guard(_request(headers=_auth("nope"))).status_code == 401


def test_non_ascii_token_returns_401_not_500():
    # Starlette decodes the header latin-1; a non-ASCII Bearer value must yield a
    # clean 401, not a compare_digest ValueError -> 500.
    r = _run_guard(_request(headers={"Authorization": "Bearer café-Ω-\xff"}))
    assert r.status_code == 401


def test_browser_origin_rejected_even_with_token():
    r = _run_guard(_request(headers={**_auth(), "Origin": "https://evil.example"}))
    assert r.status_code == 403


def test_sec_fetch_cross_site_rejected():
    r = _run_guard(_request(headers={**_auth(), "Sec-Fetch-Site": "cross-site"}))
    assert r.status_code == 403


def test_sec_fetch_same_origin_allowed():
    r = _run_guard(_request(headers={**_auth(), "Sec-Fetch-Site": "same-origin"}))
    assert r.status_code == 200


def test_install_endpoint_csrf_blocked_without_token():
    # The no-body POST a malicious page would fire to trigger a multi-GB pip run.
    assert _run_guard(_request(path="/engines/pocket/install")).status_code == 401


def test_verify_is_auth_exempt():
    # The TLS-pinned challenge uses no Authorization header.
    assert _run_guard(_request(path="/verify")).status_code == 200


def test_verify_blocks_browser_origin():
    # A website must not be able to fingerprint the backend via /verify: the
    # Origin guard runs before the /verify exemption.
    r = _run_guard(_request(path="/verify", headers={"Origin": "https://evil.example"}))
    assert r.status_code == 403


def test_verify_returns_correct_hmac():
    nonce = "challenge-nonce-xyz"
    expected = hmac.new(TOKEN.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    assert server.verify(nonce=nonce)["proof"] == expected


def test_verify_requires_nonce():
    with pytest.raises(HTTPException) as ei:
        server.verify(nonce="")
    assert ei.value.status_code == 400


def test_verify_rejects_overlong_nonce():
    # /verify is auth-exempt; an enormous nonce must be refused (DoS bound),
    # not fed into HMAC.
    with pytest.raises(HTTPException) as ei:
        server.verify(nonce="x" * 129)
    assert ei.value.status_code == 400


def test_verify_proof_does_not_equal_token():
    # The proof is an HMAC, not the token itself.
    assert server.verify(nonce="abc")["proof"] != TOKEN


@pytest.mark.parametrize("missing", [None, ""])
def test_missing_token_fails_closed_for_all_routes(monkeypatch, missing):
    monkeypatch.setattr(server, "AUTH_TOKEN", missing)
    for path in ("/health", "/engines/pocket/install", "/verify"):
        assert _run_guard(_request(path=path, headers=_auth())).status_code == 503


def test_token_failure_prevents_startup_even_with_inline_override(monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"unchanged")
    monkeypatch.setenv("YAP_AUTH_TOKEN_FILE", str(blocker / "auth-token"))
    monkeypatch.setenv("YAP_AUTH_TOKEN", "T" * 43)
    monkeypatch.setattr(sys, "argv", ["server.py", "--no-preload"])
    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=lambda *a, **kw: pytest.fail("listener started")))
    monkeypatch.setattr(server, "ensure_identity", lambda path: pytest.fail("token failure ignored"))
    with pytest.raises(RuntimeError, match="private auth token"):
        server.main()
    assert blocker.read_bytes() == b"unchanged"


def test_main_passes_private_tls_identity_and_keeps_streams_alive(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    token_file = tmp_path / "auth-token"
    monkeypatch.setenv("YAP_AUTH_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(sys, "argv", ["server.py", "--no-preload", "--models-dir", str(tmp_path / "models")])
    monkeypatch.setattr(server, "engine", None, raising=False)
    seen = {}
    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=lambda app, **kw: seen.update(kw)))
    server.main()

    assert seen["host"] == "127.0.0.1"
    assert seen["ssl_certfile"] == str(tmp_path / "backend-tls-cert.pem")
    assert seen["ssl_keyfile"] == str(tmp_path / "backend-tls-key.pem")
    assert seen["timeout_keep_alive"] == server.KEEP_ALIVE
    assert server.AUTH_TOKEN == token_file.read_text(encoding="ascii")


@pytest.mark.parametrize("unsafe", ["symlink", "fifo", "directory", "public", "empty", "oversized", "malformed"])
def test_unsafe_token_is_refused_without_replacement(tmp_path, unsafe):
    tmp_path.chmod(0o700)
    path = tmp_path / "auth-token"
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    target.chmod(0o600)
    if unsafe == "symlink":
        path.symlink_to(target)
    elif unsafe == "fifo":
        os.mkfifo(path, 0o600)
    elif unsafe == "directory":
        path.mkdir(mode=0o700)
    else:
        path.write_bytes({
            "public": b"T" * 43, "empty": b"", "oversized": b"A" * 129, "malformed": b"Bearer invalid",
        }[unsafe])
        path.chmod(0o644 if unsafe == "public" else 0o600)

    original = path.lstat()
    with pytest.raises(RuntimeError, match="auth token"):
        server._load_or_create_token(path)
    after = path.lstat()
    assert (after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) == (
        original.st_ino, original.st_mode, original.st_size, original.st_mtime_ns,
    )
    assert target.read_bytes() == b"untouched"


def test_token_rejects_wrong_owner(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "auth-token"
    path.write_bytes(b"T" * 43)
    path.chmod(0o600)
    original_fstat = os.fstat

    def wrong_token_owner(fd):
        info = original_fstat(fd)
        if stat.S_ISREG(info.st_mode):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1)
        return info

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", wrong_token_owner)
        with pytest.raises(RuntimeError, match="user-owned"):
            server._load_or_create_token(path)


def test_token_refuses_symlink_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="auth token"):
        server._load_or_create_token(alias / "auth-token")
    assert not list(target.iterdir())


def test_concurrent_token_creation_publishes_one_complete_private_secret(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "auth-token"
    barrier = threading.Barrier(2)

    def launch():
        barrier.wait(timeout=5)
        return server._load_or_create_token(path)

    with ThreadPoolExecutor(max_workers=2) as pool:
        launches = [pool.submit(launch) for _ in range(2)]
        first, second = [launch.result(timeout=5) for launch in launches]
    info = path.lstat()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first)
    assert first == second == path.read_text(encoding="ascii")
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid()
    assert set(tmp_path.iterdir()) == {path}


def test_evaluation_pocket_routes_are_unavailable_even_with_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("YAP_POCKET_ENABLED", "1")
    monkeypatch.setenv("YAP_HD_DIR", str(tmp_path))
    monkeypatch.setenv("YAP_HD_VOICES", str(tmp_path))

    class UnexpectedPocketAccess:
        def __getattr__(self, name):
            pytest.fail(f"Pocket engine accessed via {name}")

    def unexpected(*args, **kwargs):
        pytest.fail("Pocket filesystem, installer, downloader, or synthesis was reached")

    monkeypatch.setattr(server, "pk_engine", UnexpectedPocketAccess())
    for name in ("hd_voices_dir", "pocket_install_command", "ensure_cloning_weights_stream", "_segment_synth"):
        monkeypatch.setattr(server, name, unexpected)
    monkeypatch.setattr(server, "engine", SimpleNamespace(kokoro=None, files_present=lambda: True), raising=False)

    def synth(engine, fmt):
        return server.synthesize(server.SynthReq(text="speech canary", engine=engine), format=fmt)

    for call in (
        server.install_pocket,
        server.install_cloning_weights,
        server.fetch_starter_voices,
        lambda: server.list_voices(engine_name="pocket"),
        lambda: server.warm_pocket(voice="alba"),
        lambda: server.unload_engine(name="pocket"),
        lambda: synth("pocket", "pcm"),
        lambda: synth("pocket", "wav"),
    ):
        with pytest.raises(HTTPException) as unavailable:
            call()
        assert unavailable.value.status_code == 503
        assert unavailable.value.detail == server.POCKET_UNAVAILABLE

    status = server.engines_status()
    assert status["kokoro"]["installed"] is True
    assert all(status["pocket"][key] is False for key in ("installed", "loaded", "cloning", "cloning_installed"))
    assert status["pocket"]["error"] == server.POCKET_UNAVAILABLE
    assert not list(tmp_path.iterdir())
