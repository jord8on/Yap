"""Private per-user TLS identity for the Yap loopback backend."""
from __future__ import annotations

import fcntl
import os
import ssl
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


def identity_paths(token_file: Path) -> tuple[Path, Path]:
    parent = token_file.parent
    return parent / "backend-tls-cert.pem", parent / "backend-tls-key.pem"


@contextmanager
def private_directory(parent: Path, *, migrate_default: bool = False):
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            raise RuntimeError("Yap identity directory must be user-owned")
        mode = stat.S_IMODE(info.st_mode)
        if migrate_default and mode == 0o755:
            # Upgrade a directory created by an earlier default Yap install.
            os.fchmod(fd, 0o700)
        elif mode != 0o700:
            raise RuntimeError("Yap identity directory must be private (0700)")
        yield fd
    finally:
        os.close(fd)


def private_regular_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def _file_present(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not private_regular_file(info):
        raise RuntimeError("Yap TLS identity files must be private user-owned regular files")
    return True


def ensure_identity(token_file: Path) -> tuple[Path, Path]:
    """Reuse one private identity across launches. Refuse unsafe or partial pairs."""
    with private_directory(token_file.parent) as directory:
        lock = os.open(".backend-tls.lock",
                       os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=directory)
        try:
            if not private_regular_file(os.fstat(lock)):
                raise RuntimeError("Yap TLS identity lock must be private")
            fcntl.flock(lock, fcntl.LOCK_EX)
            cert, key = identity_paths(token_file)
            cert_present, key_present = _file_present(cert), _file_present(key)
            if not cert_present and not key_present:
                _generate_identity(cert, key)
            elif not (cert_present and key_present):
                raise RuntimeError("Yap TLS identity is incomplete")
            _validate_pair(cert, key)
            return cert, key
        finally:
            os.close(lock)


def _validate_pair(cert: Path, key: Path) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("Yap TLS certificate and key could not be loaded as a pair") from exc


def _generate_identity(cert: Path, key: Path) -> None:
    with tempfile.TemporaryDirectory(prefix=".yap-tls-", dir=cert.parent) as temp:
        tmp = Path(temp)
        tmp_cert, tmp_key = tmp / "cert.pem", tmp / "key.pem"
        config = tmp / "openssl.cnf"
        config.write_text(
            "[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = tls\n"
            "[dn]\nCN = 127.0.0.1\n"
            "[tls]\nsubjectAltName = IP:127.0.0.1\nextendedKeyUsage = serverAuth\n",
            encoding="ascii",
        )
        # Use the system tool with a private umask and an explicit configuration.
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-nodes", "-days", "3650", "-config", str(config),
             "-keyout", str(tmp_key), "-out", str(tmp_cert)],
            check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            umask=0o077, env={"PATH": "/usr/bin:/bin"},
        )
        tmp_key.chmod(0o600)
        tmp_cert.chmod(0o600)
        if not (_file_present(tmp_cert) and _file_present(tmp_key)):
            raise RuntimeError("New Yap TLS identity is incomplete")
        _validate_pair(tmp_cert, tmp_key)
        # The lock serializes legitimate first launches. Links avoid overwriting
        # an existing destination, including a symlink.
        os.link(tmp_key, key)
        os.link(tmp_cert, cert)
