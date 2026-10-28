"""Every outbound connection goes through here. Default policy: deny. Every attempt is logged."""
import contextlib
import json
import socket
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


class NetworkDisabled(Exception):
    pass


def _log(state_dir: Path, host: str, purpose: str, allowed: bool, sent=0, received=0):
    entry = {"ts": round(time.time(), 1), "host": host, "purpose": purpose,
             "allowed": allowed, "bytes_sent": sent, "bytes_received": received}
    with open(Path(state_dir) / "network.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def check(host: str, cfg: dict, state_dir: Path, purpose: str):
    if host not in cfg["network"]["allow"]:
        _log(state_dir, host, purpose, False)
        raise NetworkDisabled(
            f"Network access to '{host}' is blocked (purpose: {purpose}). "
            f"Add it to [network].allow in .sentinel.toml if you want to permit it.")


def fetch(url: str, cfg: dict, state_dir: Path, purpose: str, data: bytes | None = None,
          headers: dict | None = None, timeout: int = 60) -> bytes:
    u = urlparse(url)
    if u.scheme != "https":
        raise NetworkDisabled("Only https URLs are allowed.")
    check(u.hostname or "", cfg, state_dir, purpose)
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 (https + allowlist enforced above)
        body = resp.read()
    _log(state_dir, u.hostname, purpose, True, sent=len(data or b""), received=len(body))
    return body


def read_log(state_dir: Path):
    p = Path(state_dir) / "network.log"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@contextlib.contextmanager
def no_network():
    """Used by `sentinel verify` and the proof tests: any socket connection attempt is counted and refused."""
    attempts = {"count": 0}
    orig = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection)

    def refuse(*a, **k):
        attempts["count"] += 1
        raise OSError("network disabled by sentinel verify")

    socket.socket.connect = refuse
    socket.socket.connect_ex = refuse
    socket.create_connection = refuse
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection = orig
