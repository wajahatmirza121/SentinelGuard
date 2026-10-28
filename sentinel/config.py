"""Configuration is plain TOML data. Nothing in it is ever executed."""
import copy
import hashlib
import os
import tomllib
from pathlib import Path

CONFIG_NAME = ".sentinel.toml"
MANAGED_MARK = "# sentinel-managed"

DEFAULTS = {
    "project": {"php_version": ""},
    "scan": {
        "exclude": ["vendor", "node_modules", ".git", ".svn", ".hg", "__pycache__", ".idea", ".vscode"],
        "max_file_kb": 1024,
        "fail_on": "never",
    },
    "advisory": {"include_demo": False},
    "notify": {
        "min_severity": "medium",
        "max_items": 10,
        "terminal": {"enabled": True},
        "webhook": {"enabled": False, "url": ""},
        "telegram": {"enabled": False, "token_env": "SENTINEL_TELEGRAM_TOKEN", "chat_id": ""},
        "email": {"enabled": False, "host": "", "port": 465, "user_env": "SENTINEL_SMTP_USER",
                  "pass_env": "SENTINEL_SMTP_PASS", "from": "", "to": []},
    },
    "network": {"allow": []},
    "state": {"dir": ""},
    "hook": {"strict": False},
}

TEMPLATE = MANAGED_MARK + """
# SentinelGuard configuration. Data only: no commands or scripts run from this file.

[project]
php_version = ""            # e.g. "8.1.12" (used to check the PHP runtime against advisories)

[scan]
exclude = ["vendor", "node_modules", ".git"]
max_file_kb = 1024
fail_on = "never"           # never | low | medium | high | critical

[notify]
min_severity = "medium"
max_items = 10

[notify.terminal]
enabled = true

[notify.webhook]            # Slack-compatible incoming webhook
enabled = false
url = ""

[notify.telegram]
enabled = false
token_env = "SENTINEL_TELEGRAM_TOKEN"   # the token itself is read from the environment
chat_id = ""

[network]
# Network access is OFF by default. Add hosts here ONLY if you want features that need them,
# e.g. ["osv-vulnerabilities.storage.googleapis.com", "api.telegram.org"].
allow = []

[hook]
strict = false              # true: the pre-commit hook blocks commits that add high/critical findings
"""


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        elif k in out and not isinstance(out[k], dict):
            out[k] = v          # unknown keys are ignored on purpose
    return out


def load(root: Path) -> dict:
    p = Path(root) / CONFIG_NAME
    data = {}
    if p.is_file() and p.stat().st_size <= 64 * 1024:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    cfg = _merge(DEFAULTS, data)
    if os.environ.get("SENTINEL_LOAD_DEMO") == "1":
        cfg["advisory"]["include_demo"] = True
    return cfg


def state_dir(root: Path, cfg: dict) -> Path:
    """Scan state lives OUTSIDE the project tree by default, so scanning never touches project files."""
    env = os.environ.get("SENTINEL_STATE_DIR")
    if env:
        d = Path(env)
    elif cfg["state"]["dir"]:
        d = Path(cfg["state"]["dir"]).expanduser()
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
        key = hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:12]
        d = base / "sentinel" / key
    d.mkdir(parents=True, exist_ok=True)
    return d
