"""Command-line interface. Hook mode is fail-open: errors never block a commit."""
import argparse
import json
import subprocess
import sys
import tempfile
import hashlib
import os
from pathlib import Path

from . import __version__, advisory, config, dashboard, hooks, netguard, notify, report, scanner, watcher
from .fingerprint import detect_stack, iter_files, parse_dependencies
from .models import SEVERITIES, sev_rank
from .rules.catalog import RULES, meta
from .store import Store


def _ctx(path):
    root = Path(path).resolve()
    cfg = config.load(root)
    return root, cfg, config.state_dir(root, cfg)


def _fail(findings, level):
    return level != "never" and any(sev_rank(f.severity) >= sev_rank(level) for f in findings)


def cmd_init(a):
    root, cfg, sd = _ctx(a.path)
    cfg_path = root / config.CONFIG_NAME
    if not cfg_path.exists():
        cfg_path.write_text(config.TEMPLATE)
        print(f"created {config.CONFIG_NAME}")
    files = [r for r, _ in iter_files(root, cfg)]
    st = detect_stack(root, files)
    print("Languages :", ", ".join(f"{l} ({n} files)" for l, n in st["languages"]) or "none detected")
    print("Frameworks:", ", ".join(st["frameworks"]) or "none detected")
    print("Dependencies found:", len(parse_dependencies(root, cfg)))
    if a.hooks:
        print(hooks.install_hook(root))
    if a.ci:
        print(hooks.install_workflow(root))
    print("\nNext: `sentinel scan`, then `sentinel watch` while you work. Remove everything with `sentinel uninstall`.")
    return 0


def cmd_scan(a):
    root, cfg, sd = _ctx(a.path)
    store = Store(sd)
    res = scanner.scan_project(root, cfg, store, sd, full=a.full)
    findings = store.open_findings()
    out = report.render(findings, a.format, result=res, lang=a.lang, new_ids={f.fingerprint for f in res.new})
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"report written to {a.output}")
    else:
        print(out)
    if a.notify:
        notify.dispatch(cfg, sd, store, terminal=False)
    return 1 if _fail(findings, a.fail_on or cfg["scan"]["fail_on"]) else 0


def cmd_watch(a):
    root, cfg, sd = _ctx(a.path)
    print("Watching (Ctrl+C to stop). Only NEW findings are reported.")
    try:
        watcher.watch(root, cfg, Store(sd), sd, interval=a.interval)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_monitor(a):
    root, cfg, sd = _ctx(a.path)
    if a.print_cron:
        print(f"0 */6 * * * cd {root} && sentinel sync --online >/dev/null 2>&1; sentinel monitor")
        return 0
    store = Store(sd)
    res = scanner.monitor_only(root, cfg, store, sd)
    n = notify.dispatch(cfg, sd, store)
    print(f"monitor: dependencies re-checked in {res.duration:.2f}s | new: {len(res.new)} | fixed: {len(res.fixed)} | alerts sent: {n}")
    return 0


def cmd_sync(a):
    root, cfg, sd = _ctx(a.path)
    if a.zip:
        n = advisory.import_zip(Path(a.zip).read_bytes(), sd)
        print(f"imported {n} advisories from {a.zip}")
    elif a.online:
        try:
            print("imported:", advisory.sync_online(cfg, sd))
        except netguard.NetworkDisabled as e:
            print(e)
            return 2
    else:
        print("Use --zip <osv-all.zip> (offline import) or --online (needs network allowlist).")
    return 0


def cmd_status(a):
    root, cfg, sd = _ctx(a.path)
    s = Store(sd).summary()
    print("open:", s["open"], "| ignored:", s["ignored"], "| fixed:", s["fixed"])
    return 0


def cmd_ignore(a):
    root, cfg, sd = _ctx(a.path)
    n = Store(sd).ignore(a.fingerprint, a.reason)
    print(f"ignored {n} finding(s)")
    return 0 if n else 1


def cmd_explain(a):
    if a.rule not in RULES:
        print("unknown rule; try `sentinel rules`")
        return 1
    m = meta(a.rule)
    print(f"{m['id']}  {m['title']}  [{m['severity']}]  {m['cwe']}\n\nWhy it matters:\n  {m['why']}\n\nHow to fix:\n  {m['fix']}")
    if a.lang == "ur" and m["ur"]:
        print(f"\nاردو:\n  {m['ur']}")
    return 0


def cmd_rules(a):
    for rid, m in RULES.items():
        print(f"{rid:8} {m['severity']:9} {m['title']}")
    return 0


def cmd_network_report(a):
    root, cfg, sd = _ctx(a.path)
    log = netguard.read_log(sd)
    print(f"Allowed hosts in config: {cfg['network']['allow'] or 'none (network disabled)'}")
    if not log:
        print("No network connection has ever been attempted by SentinelGuard for this project.")
    for e in log:
        print(e)
    return 0


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for dp, dn, fn in os.walk(root, followlinks=False):
        dn.sort()
        for f in sorted(fn):
            p = Path(dp) / f
            if p.is_symlink():
                continue
            h.update(p.relative_to(root).as_posix().encode())
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def cmd_verify(a):
    """Prove it: scan with the network blocked and a throwaway state dir, then check nothing in the project changed."""
    root = Path(a.path).resolve()
    cfg = config.load(root)
    before = tree_hash(root)
    with tempfile.TemporaryDirectory() as tmp, netguard.no_network() as net:
        store = Store(Path(tmp))
        scanner.scan_project(root, cfg, store, Path(tmp), full=True, kind="verify")
        scanner.monitor_only(root, cfg, store, Path(tmp))
        store.close()
    after = tree_hash(root)
    ok_files, ok_net = before == after, net["count"] == 0
    print(f"[{'PASS' if ok_files else 'FAIL'}] project files unchanged by the scan")
    print(f"[{'PASS' if ok_net else 'FAIL'}] no network connection attempted ({net['count']} attempts)")
    return 0 if ok_files and ok_net else 1


def cmd_permissions(a):
    print((Path(__file__).parent / "data" / "permissions.json").read_text())
    return 0


def cmd_dashboard(a):
    root, cfg, sd = _ctx(a.path)
    Store(sd).close()
    dashboard.serve(sd, port=a.port)
    return 0


def cmd_uninstall(a):
    root, cfg, sd = _ctx(a.path)
    for line in hooks.uninstall(root, sd if a.purge_state else None):
        print(line)
    return 0


def cmd_hook(a):
    """pre-commit: fail-open. Blocks only when strict mode is on AND a new high/critical finding is staged."""
    try:
        root, cfg, sd = _ctx(".")
        staged = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                                cwd=root, capture_output=True, text=True, timeout=20).stdout.split()
        if not staged:
            return 0
        store = Store(sd)
        res = scanner.scan_project(root, cfg, store, sd, paths=staged, kind="hook")
        bad = [f for f in res.new if sev_rank(f.severity) >= sev_rank("medium")]
        for f in bad:
            print(f"[sentinel] {f.severity.upper()} {f.rule_id} {f.path}:{f.line} {f.message}")
        if cfg["hook"]["strict"] and any(sev_rank(f.severity) >= sev_rank("high") for f in bad):
            print("[sentinel] commit blocked (strict mode). Fix the issue or run `sentinel ignore <id> --reason ...`.")
            return 1
    except Exception as exc:                         # noqa: BLE001  (fail-open by design)
        print(f"[sentinel] skipped ({exc})")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="sentinel", description="Continuous, read-only security companion.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("path", nargs="?", default=".")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("init", cmd_init, "detect the stack and create .sentinel.toml")
    sp.add_argument("--hooks", action="store_true", help="install the git pre-commit hook")
    sp.add_argument("--ci", action="store_true", help="write the GitHub Actions workflow")
    sp = add("scan", cmd_scan, "incremental scan (first run is full)")
    sp.add_argument("--full", action="store_true")
    sp.add_argument("--format", choices=["text", "markdown", "json", "sarif"], default="text")
    sp.add_argument("--lang", choices=["en", "ur"], default="en")
    sp.add_argument("--fail-on", choices=["never"] + SEVERITIES[1:], default=None)
    sp.add_argument("--output")
    sp.add_argument("--notify", action="store_true", help="send to webhook/telegram/email channels")
    sp = add("watch", cmd_watch, "watch for changes and report new findings")
    sp.add_argument("--interval", type=float, default=2.0)
    sp = add("monitor", cmd_monitor, "re-check dependencies against current advisories (cron-friendly)")
    sp.add_argument("--print-cron", action="store_true")
    sp = add("sync", cmd_sync, "update the local advisory database (opt-in)")
    sp.add_argument("--zip")
    sp.add_argument("--online", action="store_true")
    add("status", cmd_status, "show counts")
    sp = add("ignore", cmd_ignore, "ignore a finding with a reason")
    sp.add_argument("fingerprint")
    sp.add_argument("--reason", required=True)
    sp = sub.add_parser("explain", help="explain a rule")
    sp.add_argument("rule")
    sp.add_argument("--lang", choices=["en", "ur"], default="en")
    sp.set_defaults(fn=cmd_explain)
    sub.add_parser("rules", help="list rules").set_defaults(fn=cmd_rules)
    add("network-report", cmd_network_report, "show every network attempt ever made")
    add("verify", cmd_verify, "prove: project unchanged and no network used")
    sub.add_parser("permissions", help="print the permissions manifest").set_defaults(fn=cmd_permissions)
    sp = add("dashboard", cmd_dashboard, "local read-only dashboard")
    sp.add_argument("--port", type=int, default=8787)
    sp = add("uninstall", cmd_uninstall, "remove hooks, workflow and config created by init")
    sp.add_argument("--purge-state", action="store_true")
    hp = sub.add_parser("hook", help="internal: git hook entry point")
    hp.add_argument("name", choices=["pre-commit"])
    hp.set_defaults(fn=cmd_hook)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.fn(a)
