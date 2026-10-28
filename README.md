# SentinelGuard

A **continuous, read-only security companion** for PHP (deep), Python and JavaScript projects. Install it once; it learns
your stack, finds vulnerable code and vulnerable dependencies, keeps watching for changes **and** for newly published
advisories, and tells you only what is new.

**Design promise:** it runs *beside* your project, never inside it. Read-only, offline by default, executes no project code,
zero third-party dependencies, and every claim is verifiable with `sentinel verify`.
It does **not** promise to find all vulnerabilities; see [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Install (Python 3.11+)
```bash
pip install .            # or: python -m sentinel ...   (no install needed)
```

## 60-second tour
```bash
cd my-php-project
sentinel init --hooks --ci      # detect stack, write .sentinel.toml, install pre-commit hook + GitHub workflow
sentinel scan                   # first run is full; later runs are incremental
sentinel scan --format markdown --lang ur --output report.md     # Urdu explanations
sentinel watch                  # live: rescans only the files you save, reports only NEW findings
sentinel monitor                # re-check dependencies/runtime against the advisory DB (run from cron/CI)
sentinel monitor --print-cron   # prints a cron line (it never edits your crontab)
sentinel dashboard              # local read-only dashboard on 127.0.0.1:8787
sentinel ignore <id> --reason "false positive: value is validated in Router::map()"
sentinel explain PHP001 --lang ur
sentinel uninstall              # removes only what init created
```

## Prove the "no added risk" claims yourself
```bash
sentinel verify                 # scans with the network blocked, then checks the project tree is byte-identical
sentinel network-report         # every network attempt ever made (default: none)
sentinel permissions            # the machine-readable permissions manifest
python -m unittest discover -s tests -v    # includes the trust tests
```

## What it detects (v0.1)
| Area | Coverage |
|---|---|
| PHP code | SQL injection, XSS, file inclusion, command injection, insecure deserialization, eval/dynamic code, unrestricted upload, unvalidated file paths/URLs, open redirect, `extract($_GET)`, weak password hashing, disabled TLS verification, weak randomness for secrets, `display_errors`, `phpinfo()` |
| Secrets | AWS, GitHub, Slack, Stripe, Google keys, private keys, hardcoded passwords (values always masked) |
| Dependencies | `composer.lock`, `package-lock.json`, pinned `requirements.txt`, PHP runtime version, matched offline against OSV-format advisories |
| Config | `.env` not ignored, backups/dumps in the project, diagnostic files, `composer.lock` missing, `display_errors` in ini files |
| Python / JS | hazardous-call rule pack (eval/exec, shell=True, pickle, innerHTML, ...) |

## Advisory data (the "world changes" half)
Matching is always local. Choose how to fill the database:
```bash
sentinel sync --zip all.zip      # offline: import an OSV ecosystem dump you downloaded yourself
# or opt in to the network:
#   .sentinel.toml ->  [network] allow = ["osv-vulnerabilities.storage.googleapis.com"]
sentinel sync --online
```
`SENTINEL_LOAD_DEMO=1` loads three clearly-labelled DEMO advisories used by the tests.

## Notifications
Terminal, Slack-compatible webhook, Telegram, email (all optional, all subject to the network allowlist). A finding is
notified **once**; messages contain `file:line` and rule only, never code or secrets. Tokens come from environment variables.

## Run it sandboxed (recommended for untrusted projects)
```bash
docker build -t sentinelguard .
docker run --rm --network none --read-only --tmpfs /home/sentinel/.local \
  -v "$PWD":/project:ro sentinelguard scan --full
```
(The Dockerfile is provided but was not run in the build environment.)

## Project layout
```
sentinel/        core package (stdlib only)
  rules/         php.py (taint tracker), generic.py (secrets, py/js, config), catalog.py (explanations, EN+UR)
tests/           26 tests incl. trust proofs; fixtures/ are deliberately vulnerable
docs/            ARCHITECTURE.md, LIMITATIONS.md
SECURITY.md  THREAT_MODEL.md  Dockerfile  .github/workflows/ci.yml
```

## Roadmap (not built yet)
Real PHP parser + inter-file taint, framework models (Laravel, WordPress), VS Code extension (LSP), PR-comment bot,
signed releases + SBOM, advisory-bundle signatures, optional local-LLM explanations, more languages, independent audit.
