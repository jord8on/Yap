"""Local HTTPS listener identity: reject symlink/private-key attacks."""
import shutil
from concurrent.futures import ThreadPoolExecutor
import threading
import ssl
import stat
import subprocess

import pytest

from local_tls import ensure_identity, identity_paths


def test_identity_created_private_and_usable(tmp_path):
    tmp_path.chmod(0o700)
    token = tmp_path / "auth-token"
    token.write_text("test-secret")
    cert, key = ensure_identity(token)
    assert cert == tmp_path / "backend-tls-cert.pem"
    assert key == tmp_path / "backend-tls-key.pem"
    assert stat.S_IMODE(cert.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    original_cert, original_key = cert.read_bytes(), key.read_bytes()
    assert original_cert.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY-----" in original_key.splitlines()[0]
    assert ensure_identity(token) == (cert, key)
    assert (cert.read_bytes(), key.read_bytes()) == (original_cert, original_key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    san = subprocess.check_output(
        ["/usr/bin/openssl", "x509", "-in", str(cert), "-noout", "-text"],
        text=True,
    )
    assert "IP Address:127.0.0.1" in san


def test_identity_rejects_public_directory(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(RuntimeError, match="private"):
        ensure_identity(tmp_path / "auth-token")


def test_identity_refuses_preexisting_unrelated_certificate(tmp_path):
    tmp_path.chmod(0o700)
    cert, _ = identity_paths(tmp_path / "auth-token")
    cert.write_text("not a certificate")
    cert.chmod(0o600)
    with pytest.raises(RuntimeError, match="incomplete"):
        ensure_identity(tmp_path / "auth-token")
    assert cert.read_text() == "not a certificate"


def test_concurrent_first_launch_reuses_one_private_tls_identity(tmp_path):
    tmp_path.chmod(0o700)
    token = tmp_path / "auth-token"
    token.write_text("test-secret")
    barrier = threading.Barrier(2)

    def launch():
        barrier.wait(timeout=10)
        cert, key = ensure_identity(token)
        return cert, key, cert.read_bytes()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(launch) for _ in range(2)]
        results = [future.result(timeout=25) for future in futures]

    assert results[0] == results[1]
    cert, key, _ = results[0]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


def test_mismatched_certificate_and_key_fails_closed(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    mixed = tmp_path / "mixed"
    for d in (first, second, mixed):
        d.mkdir(mode=0o700)
    cert_a, _ = ensure_identity(first / "auth-token")
    _, key_b = ensure_identity(second / "auth-token")
    cert, key = identity_paths(mixed / "auth-token")
    shutil.copyfile(cert_a, cert)
    shutil.copyfile(key_b, key)
    cert.chmod(0o600)
    key.chmod(0o600)
    with pytest.raises(RuntimeError, match="could not be loaded as a pair"):
        ensure_identity(mixed / "auth-token")


@pytest.mark.parametrize("name", ["backend-tls-cert.pem", "backend-tls-key.pem", ".backend-tls.lock"])
def test_identity_rejects_symlink_without_creating_a_pair(tmp_path, name):
    tmp_path.chmod(0o700)
    target = tmp_path / "untouched"
    target.write_bytes(b"untouched")
    (tmp_path / name).symlink_to(target)
    with pytest.raises((OSError, RuntimeError)):
        ensure_identity(tmp_path / "auth-token")
    assert target.read_bytes() == b"untouched"
    assert (tmp_path / name).is_symlink()
    assert {entry.name for entry in tmp_path.iterdir()} <= {name, "untouched", ".backend-tls.lock"}


def test_identity_refuses_previously_public_key(tmp_path):
    tmp_path.chmod(0o700)
    cert, key = ensure_identity(tmp_path / "auth-token")
    key.chmod(0o644)
    before = cert.read_bytes()
    with pytest.raises(RuntimeError, match="private user-owned regular files"):
        ensure_identity(tmp_path / "auth-token")
    assert cert.read_bytes() == before
    assert stat.S_IMODE(key.stat().st_mode) == 0o644
