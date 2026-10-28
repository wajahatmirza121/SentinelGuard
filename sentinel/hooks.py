"""Git hook and CI workflow installers. Everything we create carries a marker so uninstall is exact."""
import shutil
from pathlib import Path

from .config import CONFIG_NAME, MANAGED_MARK, TEMPLATE

HOOK_MARK = "# sentinel-managed-hook"
HOOK = f"""#!/bin/sh
{HOOK_MARK}
# Fail-open: if sentinel is not installed, or it errors, the commit proceeds.
# It only blocks when [hook] strict = true in .sentinel.toml and a new high/critical finding is staged.
if command -v sentinel >/dev/null 2>&1; then
  sentinel hook pre-commit
  exit $?
fi
exit 0
"""

WORKFLOW_MARK = "# sentinel-managed-workflow"
WORKFLOW = f"""{WORKFLOW_MARK}
name: SentinelGuard
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * *"        # daily: catches new advisories for unchanged code
permissions:
  contents: read                # read-only. No write tokens, no PR-comment permission needed.
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Pin third-party actions to a full commit SHA before using in production.
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install SentinelGuard (pin a version and verify its signature)
        run: pip install sentinelguard
      - name: Sync advisories (the only step that uses the network)
        run: sentinel sync --online || true
      - name: Scan
        run: |
          sentinel scan --full --format markdown --fail-on high | tee "$GITHUB_STEP_SUMMARY"
"""


def install_hook(root: Path) -> str:
    hooks = Path(root) / ".git" / "hooks"
    if not hooks.is_dir():
        return "no .git/hooks directory found (not a git repository?)"
    target = hooks / "pre-commit"
    if target.exists() and HOOK_MARK not in target.read_text(errors="replace"):
        return "a different pre-commit hook already exists; left untouched"
    target.write_text(HOOK)
    target.chmod(0o755)
    return "pre-commit hook installed"


def install_workflow(root: Path) -> str:
    wf = Path(root) / ".github" / "workflows" / "sentinel.yml"
    if wf.exists() and WORKFLOW_MARK not in wf.read_text(errors="replace"):
        return "a different sentinel.yml already exists; left untouched"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(WORKFLOW)
    return "GitHub workflow written to .github/workflows/sentinel.yml"


def uninstall(root: Path, state_dir: Path | None = None) -> list[str]:
    root, done = Path(root), []
    hook = root / ".git" / "hooks" / "pre-commit"
    if hook.is_file() and HOOK_MARK in hook.read_text(errors="replace"):
        hook.unlink()
        done.append("removed git hook")
    wf = root / ".github" / "workflows" / "sentinel.yml"
    if wf.is_file() and WORKFLOW_MARK in wf.read_text(errors="replace"):
        wf.unlink()
        done.append("removed workflow")
    cfg = root / CONFIG_NAME
    if cfg.is_file() and cfg.read_text(errors="replace").startswith(MANAGED_MARK):
        cfg.unlink()
        done.append(f"removed {CONFIG_NAME}")
    if state_dir and Path(state_dir).is_dir() and (Path(state_dir) / "findings.db").exists():
        shutil.rmtree(state_dir)
        done.append("deleted scan state")
    return done or ["nothing to remove"]
