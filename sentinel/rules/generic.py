"""Language-independent checks: secrets, Python/JavaScript rule packs, project configuration checks."""
import re
from pathlib import Path

from .catalog import make

# ---------------- secrets ----------------
SECRET_PATTERNS = [
    ("SEC001", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("SEC002", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("SEC003", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("SEC004", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("SEC005", re.compile(r"\b([sr]k_live_[0-9A-Za-z]{16,})\b")),
    ("SEC006", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("SEC008", re.compile(r"define\s*\(\s*['\"][A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|SALT)[A-Z0-9_]*['\"]\s*,\s*['\"]([^'\"]{8,})['\"]")),
    ("SEC007", re.compile(r"(?i)\b(?:db_?pass(?:word)?|password|passwd|pwd|secret|api_?key|auth_?token|access_?token|private_?key)\b['\"\]\s]*(?:=>|[:=])\s*['\"]([^'\"\s]{8,})['\"]")),
]
PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|your[_\-\s].*|change.?me.*|example.*|sample.*|dummy.*|test.*|password.*|secret.*|"
    r"put your unique phrase here|<.*>|\$\{.*\}|%.*%|.*\{\{.*\}\}|.*\$\w+.*|null|none|true|false|env\(.*)$")


def mask(value: str) -> str:
    return value[:2] + "****" + value[-2:] if len(value) > 8 else "****"


def scan_secrets(text: str, path: str):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for rid, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            value = m.group(1)
            if rid in ("SEC007", "SEC008") and PLACEHOLDER.match(value):
                continue
            if rid == "SEC007" and re.search(r"getenv|environ|process\.env|config\(", line):
                continue
            snippet = line.strip().replace(value, mask(value))[:160]
            out.append(make(rid, path, n, snippet, message=f"Possible secret in code ({mask(value)})", kind="secret"))
            break
    return out


# ---------------- Python & JavaScript line rules ----------------
PY_RULES = [
    ("PY001", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(\s*(?!['\"])")),
    ("PY002", re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True")),
    ("PY003", re.compile(r"\bpickle\.loads?\(")),
    ("PY004", re.compile(r"\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe))")),
    ("PY005", re.compile(r"\bos\.system\(")),
    ("PY006", re.compile(r"verify\s*=\s*False")),
    ("PY007", re.compile(r"\bhashlib\.(?:md5|sha1)\(")),
    ("PY008", re.compile(r"\.run\([^)]*debug\s*=\s*True")),
    ("PY009", re.compile(r"\.execute\(\s*f['\"]")),
]
JS_RULES = [
    ("JS001", re.compile(r"(?<![\w.])eval\s*\(")),
    ("JS002", re.compile(r"\.innerHTML\s*=\s*(?!['\"`]\s*['\"`]\s*;?\s*$)(?!['\"`][^'\"`$]*['\"`]\s*;?\s*$)")),
    ("JS003", re.compile(r"dangerouslySetInnerHTML")),
    ("JS004", re.compile(r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_]\w*\s*[,)+]|['\"][^'\"]*['\"]\s*\+)")),
    ("JS005", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("JS007", re.compile(r"rejectUnauthorized\s*:\s*false")),
    ("JS008", re.compile(r"\bnew\s+Function\s*\(")),
]


def scan_lines(text: str, path: str, rules, comment_prefixes):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(comment_prefixes) or len(s) > 2000:
            continue
        for rid, rx in rules:
            if rx.search(line):
                out.append(make(rid, path, n, s[:160]))
    return out


def scan_python(text, path):
    return scan_lines(text, path, PY_RULES, ("#",))


def scan_js(text, path):
    return scan_lines(text, path, JS_RULES, ("//", "*", "/*"))


# ---------------- project configuration checks ----------------
BACKUP_EXT = {".sql", ".bak", ".old", ".orig", ".swp", ".zip", ".tar", ".gz", ".rar", ".7z"}
DIAG_NAMES = {"phpinfo.php", "info.php", "test.php", "phpinfo.php.txt"}


def config_findings(root: Path, files: list[str]):
    out, names = [], set(files)
    gi = root / ".gitignore"
    ignored = set()
    if gi.is_file() and gi.stat().st_size < 100_000:
        ignored = {l.strip() for l in gi.read_text(errors="replace").splitlines()}
    for f in files:
        p = Path(f)
        if p.name == ".env" and not ({".env", "/.env", ".env*", "*.env", ".env.*"} & ignored):
            out.append(make("CFG001", f, 0, f, message=".env found and not listed in .gitignore"))
        if p.name.lower() in DIAG_NAMES:
            out.append(make("CFG002", f, 0, f))
        if p.suffix.lower() in BACKUP_EXT:
            out.append(make("CFG004", f, 0, f))
        if p.suffix.lower() in (".ini",) or p.name == ".user.ini":
            try:
                t = (root / f).read_text(errors="replace")[:200_000]
            except OSError:
                continue
            for n, line in enumerate(t.splitlines(), 1):
                if re.match(r"^\s*display_errors\s*=\s*(on|1|true|stdout)\b", line, re.I):
                    out.append(make("CFG005", f, n, line.strip()))
    if "composer.json" in names and "composer.lock" not in names:
        out.append(make("CFG003", "composer.json", 0, "composer.json"))
    return out
