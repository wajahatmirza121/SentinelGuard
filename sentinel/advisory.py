"""Offline advisory matching (OSV format). Matching is always local; syncing is opt-in and allowlisted."""
import io
import json
import re
import zipfile
from pathlib import Path

from . import netguard
from .models import Finding

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
ECOSYSTEMS = ["Packagist", "npm", "PyPI"]
DEMO_FILE = Path(__file__).parent / "data" / "demo_advisories.json"

# ---------- version comparison (good enough for semver / composer / PEP 440 basics) ----------
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1, "c": -1, "pre": -1,
        "patch": 1, "pl": 1, "p": 1}
_VER_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-._]?([a-zA-Z]+)[-._]?(\d*))?")


def vkey(v: str):
    v = v.strip().split("+")[0]
    m = _VER_RE.match(v)
    if not m:
        return ((0,), 0, 0)
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    suffix = (m.group(2) or "").lower()
    pre = _PRE.get(suffix, -5) if suffix else 0
    return (tuple(nums), pre, int(m.group(3) or 0))


def in_range(version: str, rng: dict):
    """OSV range semantics. Returns (affected, first_fixed_version)."""
    ver = vkey(version)

    def order(e):
        if "introduced" in e:
            return (vkey(e["introduced"]) if e["introduced"] != "0" else ((0,), -9, 0), 0)
        if "fixed" in e:
            return (vkey(e["fixed"]), 1)
        if "last_affected" in e:
            return (vkey(e["last_affected"]), 2)
        return (((0,), 0, 0), 9)

    affected, fixed = False, None
    for e in sorted(rng.get("events", []), key=order):
        if "introduced" in e:
            if e["introduced"] == "0" or ver >= vkey(e["introduced"]):
                affected = True
        elif "fixed" in e:
            if ver >= vkey(e["fixed"]):
                affected = False
            elif affected and fixed is None:
                fixed = e["fixed"]
        elif "last_affected" in e:
            if ver > vkey(e["last_affected"]):
                affected = False
    return affected, (fixed if affected else None)


def norm_name(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


# ---------- loading ----------
def advisory_dir(state_dir: Path) -> Path:
    d = Path(state_dir) / "advisories"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _entries(obj):
    return obj if isinstance(obj, list) else [obj]


def load_index(state_dir: Path, cfg: dict) -> dict:
    index: dict = {}

    def add(entry):
        if not isinstance(entry, dict) or entry.get("withdrawn"):
            return
        for aff in entry.get("affected", []) or []:
            pkg = aff.get("package") or {}
            eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
            if eco and name:
                index.setdefault((eco, norm_name(eco, name)), []).append((entry, aff))

    for p in advisory_dir(state_dir).glob("*.json"):
        try:
            for e in _entries(json.loads(p.read_text(encoding="utf-8"))):
                add(e)
        except (ValueError, OSError):
            continue
    if cfg["advisory"]["include_demo"] and DEMO_FILE.exists():
        for e in _entries(json.loads(DEMO_FILE.read_text(encoding="utf-8"))):
            add(e)
    return index


def _severity(entry: dict) -> str:
    sev = str((entry.get("database_specific") or {}).get("severity", "")).upper()
    return {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
            "LOW": "low"}.get(sev, "medium")


def match(deps, index) -> list[Finding]:
    out = []
    for d in deps:
        for entry, aff in index.get((d.ecosystem, norm_name(d.ecosystem, d.name)), []):
            hit, fixed = False, None
            if d.version in (aff.get("versions") or []):
                hit = True
            for rng in aff.get("ranges") or []:
                if rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                    h, fx = in_range(d.version, rng)
                    if h:
                        hit, fixed = True, fx
                        break
            if not hit:
                continue
            aliases = [a for a in entry.get("aliases", []) if a.startswith("CVE-")]
            ident = entry["id"] + (f" ({', '.join(aliases)})" if aliases else "")
            summary = (entry.get("summary") or entry.get("details", "") or "").strip().split("\n")[0][:200]
            kind_name = "PHP runtime" if d.ecosystem == "PHP-Runtime" else f"{d.name} {d.version}"
            out.append(Finding(
                rule_id=entry["id"], severity=_severity(entry), path=d.source, line=0, kind="dependency",
                message=f"{kind_name} is affected by {ident}: {summary}"
                        if d.ecosystem != "PHP-Runtime" else f"PHP {d.version} is affected by {ident}: {summary}",
                snippet=f"{d.name}@{d.version}", cwe="",
                fix=f"Upgrade {d.name} to {fixed} or later." if fixed else f"Check the advisory {entry['id']} for a fixed version."))
    return out


# ---------- syncing (opt-in) ----------
def import_zip(data: bytes, state_dir: Path) -> int:
    """Import OSV JSON files from a zip. Output filenames are derived from advisory ids, never from the zip."""
    n = 0
    dest = advisory_dir(state_dir)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json") or info.file_size > 5_000_000:
                continue
            try:
                entry = json.loads(zf.read(info))
            except ValueError:
                continue
            if isinstance(entry, dict) and re.fullmatch(r"[A-Za-z0-9._\-]+", str(entry.get("id", ""))):
                (dest / f"{entry['id']}.json").write_text(json.dumps(entry), encoding="utf-8")
                n += 1
    return n


def sync_online(cfg: dict, state_dir: Path, ecosystems=None) -> dict:
    result = {}
    for eco in ecosystems or ECOSYSTEMS:
        data = netguard.fetch(OSV_URL.format(eco=eco), cfg, state_dir, f"advisory sync {eco}")
        result[eco] = import_zip(data, state_dir)
    return result
