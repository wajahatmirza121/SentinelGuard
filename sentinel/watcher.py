"""Continuous watching. Polling-based on purpose: zero dependencies, identical behaviour on every OS."""
import time
from pathlib import Path

from . import notify, report, scanner
from .fingerprint import iter_files, is_scannable


def snapshot(root: Path, cfg: dict) -> dict:
    snap = {}
    for rel, size in iter_files(root, cfg):
        if is_scannable(rel):
            try:
                snap[rel] = ((Path(root) / rel).stat().st_mtime_ns, size)
            except OSError:
                pass
    return snap


def watch(root, cfg, store, state_dir, interval=2.0, max_cycles=None, out=print):
    root = Path(root)
    res = scanner.scan_project(root, cfg, store, state_dir, kind="watch")
    out(report.header(res))
    notify.dispatch(cfg, state_dir, store)
    prev, cycles = snapshot(root, cfg), 0
    while max_cycles is None or cycles < max_cycles:
        time.sleep(interval)
        cycles += 1
        cur = snapshot(root, cfg)
        changed = {p for p in cur if prev.get(p) != cur[p]} | (set(prev) - set(cur))
        prev = cur
        if not changed:
            continue
        res = scanner.scan_project(root, cfg, store, state_dir, paths=changed, kind="watch")
        out(f"[watch] {len(changed)} file(s) changed -> new: {len(res.new)}, fixed: {len(res.fixed)}")
        notify.dispatch(cfg, state_dir, store)
    return res
