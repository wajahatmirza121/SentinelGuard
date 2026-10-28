"""Notifications. Only NEW findings above the threshold are sent, once. Messages contain locations, never code or secrets."""
import json
import os
import smtplib
import ssl
from email.message import EmailMessage

from . import netguard
from .models import sev_rank


def build_message(findings, max_items: int) -> str:
    lines = [f"SentinelGuard: {len(findings)} new finding(s)"]
    for f in findings[:max_items]:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"- [{f.severity.upper()}] {f.rule_id} {f.message[:110]} ({loc})")
    if len(findings) > max_items:
        lines.append(f"... and {len(findings) - max_items} more")
    return "\n".join(lines)


def _terminal(msg):
    print("\n" + msg)


def _webhook(cfg, sd, msg):
    w = cfg["notify"]["webhook"]
    netguard.fetch(w["url"], cfg, sd, "notification webhook", data=json.dumps({"text": msg}).encode(),
                   headers={"Content-Type": "application/json"})


def _telegram(cfg, sd, msg):
    t = cfg["notify"]["telegram"]
    token = os.environ.get(t["token_env"], "")
    if not token or not t["chat_id"]:
        raise RuntimeError("Telegram token or chat_id missing")
    netguard.fetch(f"https://api.telegram.org/bot{token}/sendMessage", cfg, sd, "notification telegram",
                   data=json.dumps({"chat_id": t["chat_id"], "text": msg}).encode(),
                   headers={"Content-Type": "application/json"})


def _email(cfg, sd, msg):
    e = cfg["notify"]["email"]
    netguard.check(e["host"], cfg, sd, "notification email")
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = "SentinelGuard alert", e["from"], ", ".join(e["to"])
    m.set_content(msg)
    with smtplib.SMTP_SSL(e["host"], e["port"], context=ssl.create_default_context(), timeout=30) as s:
        s.login(os.environ.get(e["user_env"], ""), os.environ.get(e["pass_env"], ""))
        s.send_message(m)


def dispatch(cfg, state_dir, store, terminal=True) -> int:
    """Send unnotified findings through every enabled channel. A failing channel never raises."""
    n = cfg["notify"]
    pending = store.unnotified(n["min_severity"])
    if not pending:
        return 0
    msg = build_message(pending, n["max_items"])
    delivered = False
    channels = [("terminal", terminal and n["terminal"]["enabled"], lambda: _terminal(msg)),
                ("webhook", n["webhook"]["enabled"], lambda: _webhook(cfg, state_dir, msg)),
                ("telegram", n["telegram"]["enabled"], lambda: _telegram(cfg, state_dir, msg)),
                ("email", n["email"]["enabled"], lambda: _email(cfg, state_dir, msg))]
    for name, enabled, fn in channels:
        if not enabled:
            continue
        try:
            fn()
            delivered = True
        except Exception as exc:                      # fail-open: log and continue
            print(f"[sentinel] notification channel '{name}' failed: {exc}")
    if delivered:
        store.mark_notified([f.fingerprint for f in pending])
    return len(pending)
