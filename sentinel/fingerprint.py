"""Project fingerprinting: file walking, stack detection, dependency parsing. Read-only."""
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

CODE_EXT = {".php", ".phtml", ".inc", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}
SECRET_EXT = CODE_EXT | {".env", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".toml", ".sh", ".xml", ".json", ".properties"}
SKIP_NAMES = {"composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
DEP_FILES = {"composer.lock", "composer.json", "package-lock.json", "package.json", "requirements.txt",
             ".php-version", ".sentinel.toml"}
MAX_JSON = 20 * 1024 * 1024


def is_scannable(rel: str) -> bool:
    p = Path(rel)
    if p.name in SKIP_NAMES:
        return False
    return p.suffix.lower() in SECRET_EXT or p.name.startswith(".env")


def iter_files(root: Path, cfg: dict):
    """Yield (relative_posix_path, size). Never follows symlinks."""
    root = Path(root)
    excl = set(cfg["scan"]["exclude"])
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in excl and not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            yield Path(full).relative_to(root).as_posix(), st.st_size


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Dep:
    ecosystem: str
    name: str
    version: str
    source: str


def _load_json(p: Path):
    if not p.is_file() or p.stat().st_size > MAX_JSON:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError):
        return None


def parse_dependencies(root: Path, cfg: dict) -> list[Dep]:
    root = Path(root)
    deps: list[Dep] = []

    lock = _load_json(root / "composer.lock")
    if isinstance(lock, dict):
        for pkg in (lock.get("packages") or []) + (lock.get("packages-dev") or []):
            if pkg.get("name") and pkg.get("version"):
                deps.append(Dep("Packagist", pkg["name"].lower(), pkg["version"].lstrip("v"), "composer.lock"))

    npm = _load_json(root / "package-lock.json")
    if isinstance(npm, dict):
        if isinstance(npm.get("packages"), dict):
            for key, meta in npm["packages"].items():
                if key and isinstance(meta, dict) and meta.get("version"):
                    deps.append(Dep("npm", key.split("node_modules/")[-1], meta["version"], "package-lock.json"))
        else:
            def walk(d):
                for name, meta in (d or {}).items():
                    if isinstance(meta, dict):
                        if meta.get("version"):
                            deps.append(Dep("npm", name, meta["version"], "package-lock.json"))
                        walk(meta.get("dependencies"))
            walk(npm.get("dependencies"))

    req = root / "requirements.txt"
    if req.is_file() and req.stat().st_size < 1_000_000:
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#")[0].split(";")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
            if m:
                deps.append(Dep("PyPI", re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2), "requirements.txt"))

    php = php_version(root, cfg)
    if php:
        deps.append(Dep("PHP-Runtime", "php", php, "runtime"))
    return deps


def php_version(root: Path, cfg: dict) -> str:
    v = (cfg["project"].get("php_version") or "").strip()
    if not v and (Path(root) / ".php-version").is_file():
        v = (Path(root) / ".php-version").read_text(errors="replace").strip()
    if not v:
        cj = _load_json(Path(root) / "composer.json")
        if isinstance(cj, dict):
            v = str(((cj.get("config") or {}).get("platform") or {}).get("php", "")).strip()
    return v if re.match(r"^\d+\.\d+(\.\d+)?", v) else ""


def detect_stack(root: Path, files: list[str]) -> dict:
    root = Path(root)
    exts: dict[str, int] = {}
    for f in files:
        e = Path(f).suffix.lower()
        exts[e] = exts.get(e, 0) + 1
    langs = []
    for label, keys in (("PHP", [".php", ".phtml", ".inc"]), ("Python", [".py"]),
                        ("JavaScript/TypeScript", [".js", ".jsx", ".ts", ".tsx", ".mjs"])):
        n = sum(exts.get(k, 0) for k in keys)
        if n:
            langs.append((label, n))
    langs.sort(key=lambda x: -x[1])

    names = set(files)
    dep_names = {d.name for d in parse_dependencies(root, {"project": {"php_version": ""}})}
    frameworks = []
    if "artisan" in names or "laravel/framework" in dep_names:
        frameworks.append("Laravel")
    if "wp-config.php" in names or any(f.startswith("wp-content/") for f in files):
        frameworks.append("WordPress")
    if any(n.startswith("symfony/") for n in dep_names):
        frameworks.append("Symfony")
    if "manage.py" in names or "django" in dep_names:
        frameworks.append("Django")
    if "flask" in dep_names:
        frameworks.append("Flask")
    if "express" in dep_names:
        frameworks.append("Express")
    if "react" in dep_names:
        frameworks.append("React")
    return {"languages": langs, "frameworks": frameworks}
