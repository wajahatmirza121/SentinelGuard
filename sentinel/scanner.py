"""Incremental scanner. Opens files read-only ('rb'); never executes project code; never writes into the project."""
import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import advisory
from .fingerprint import DEP_FILES, is_scannable, iter_files, parse_dependencies, sha256_file
from .models import Finding
from .rules import generic, php
from .store import Store

PHP_EXT = {".php", ".phtml", ".inc"}
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs"}


@dataclass
class ScanResult:
    run_id: int
    scanned: int = 0
    changed: int = 0
    new: list = field(default_factory=list)
    fixed: list = field(default_factory=list)
    duration: float = 0.0
    kind: str = "scan"


def assign_fingerprints(findings: list[Finding]):
    """Stable ids: based on rule + file + code text, NOT the line number, so edits above don't make old issues look new."""
    counts: dict = {}
    for f in findings:
        norm = re.sub(r"\s+", " ", f.snippet).strip()
        key = (f.rule_id, f.path, norm)
        counts[key] = counts.get(key, 0) + 1
        f.fingerprint = hashlib.sha256(f"{f.rule_id}|{f.path}|{norm}|{counts[key]}".encode()).hexdigest()[:16]


def scan_file(root: Path, rel: str, max_bytes: int) -> list[Finding]:
    with open(Path(root) / rel, "rb") as fh:          # read-only by construction
        text = fh.read(max_bytes).decode("utf-8", errors="replace")
    ext = Path(rel).suffix.lower()
    out: list[Finding] = []
    if ext in PHP_EXT:
        out += php.scan_php(text, rel)
    elif ext in PY_EXT:
        out += generic.scan_python(text, rel)
    elif ext in JS_EXT:
        out += generic.scan_js(text, rel)
    out += generic.scan_secrets(text, rel)
    lines = text.splitlines()          # inline suppression: a line containing 'sentinel:ignore' is skipped
    out = [f for f in out if not (0 < f.line <= len(lines) and "sentinel:ignore" in lines[f.line - 1])]
    assign_fingerprints(out)
    return out


def run_sca(root: Path, cfg: dict, store: Store, state_dir: Path, run_id: int):
    deps = parse_dependencies(root, cfg)
    findings = advisory.match(deps, advisory.load_index(state_dir, cfg))
    assign_fingerprints(findings)
    store.sync_scope("deps", findings, run_id)


def scan_project(root, cfg: dict, store: Store, state_dir: Path, paths=None, full=False, kind="scan") -> ScanResult:
    t0 = time.time()
    root = Path(root)
    run_id = store.begin_run(kind)
    max_bytes = cfg["scan"]["max_file_kb"] * 1024
    all_files = list(iter_files(root, cfg))
    sizes = dict(all_files)
    scannable = {rel for rel, size in all_files if is_scannable(rel) and size <= max_bytes}
    prior = store.get_files()

    if paths is None:
        candidates, deleted = scannable, set(prior) - scannable
    else:
        paths = set(paths)
        candidates = paths & scannable
        deleted = {p for p in paths if p in prior and p not in scannable}

    changed = 0
    for rel in sorted(candidates):
        st = (root / rel).stat()
        old = prior.get(rel)
        if not full and old and old[0] == st.st_mtime_ns and old[1] == st.st_size:
            continue
        sha = sha256_file(root / rel)
        store.set_file(rel, st.st_mtime_ns, st.st_size, sha)
        if not full and old and old[2] == sha:
            continue                                   # touched but unchanged
        store.sync_scope(f"file:{rel}", scan_file(root, rel, max_bytes), run_id)
        changed += 1
    for rel in deleted:
        store.sync_scope(f"file:{rel}", [], run_id)
        store.del_file(rel)

    if paths is None or full or any(Path(p).name in DEP_FILES for p in paths):
        run_sca(root, cfg, store, state_dir, run_id)
    if paths is None:
        cfgf = generic.config_findings(root, [rel for rel, _ in all_files])
        assign_fingerprints(cfgf)
        store.sync_scope("config", cfgf, run_id)

    store.db.commit()
    dur = time.time() - t0
    store.finish_run(run_id, len(candidates), dur)
    return ScanResult(run_id=run_id, scanned=len(candidates), changed=changed,
                      new=store.new_in_run(run_id), fixed=store.fixed_in_run(run_id), duration=dur, kind=kind)


def monitor_only(root, cfg: dict, store: Store, state_dir: Path) -> ScanResult:
    """Re-check dependencies and runtime against the current advisory database (no code rescan)."""
    t0 = time.time()
    run_id = store.begin_run("monitor")
    run_sca(Path(root), cfg, store, state_dir, run_id)
    dur = time.time() - t0
    store.finish_run(run_id, 0, dur)
    return ScanResult(run_id=run_id, new=store.new_in_run(run_id), fixed=store.fixed_in_run(run_id), duration=dur, kind="monitor")
