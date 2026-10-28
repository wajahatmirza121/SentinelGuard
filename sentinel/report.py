"""Report rendering: text, markdown, json, sarif. Secrets are already masked in findings."""
import json
import sys

from . import __version__
from .models import SEVERITIES, sev_rank
from .rules.catalog import meta

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET = "\033[0m"


def _counts(findings):
    c = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def header(result):
    if result is None:
        return ""
    return (f"SentinelGuard {__version__}: {result.scanned} files checked ({result.changed} changed) "
            f"in {result.duration:.2f}s | new: {len(result.new)} | fixed: {len(result.fixed)}")


def render_text(findings, result=None, lang="en", new_ids=frozenset()):
    color = sys.stdout.isatty()
    lines = [header(result)] if result else []
    for f in sorted(findings, key=lambda f: (-sev_rank(f.severity), f.path, f.line)):
        tag = f"[{f.severity.upper()}]"
        if color:
            tag = COLORS[f.severity] + tag + RESET
        new = " (NEW)" if f.fingerprint in new_ids else ""
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"{tag} {f.rule_id} {f.message}{new}  {loc}  id={f.fingerprint}")
        if f.snippet and f.kind != "dependency":
            lines.append(f"      code: {f.snippet}")
        lines.append(f"      fix:  {f.fix}")
        if lang == "ur" and meta(f.rule_id)["ur"]:
            lines.append(f"      اردو: {meta(f.rule_id)['ur']}")
    c = _counts(findings)
    lines.append("")
    lines.append("Open findings: " + ", ".join(f"{k}={v}" for k, v in c.items()) + f" (total {len(findings)})")
    if not findings:
        lines.append("No open findings. (This does not prove the project is secure; see docs/LIMITATIONS.)")
    return "\n".join(lines)


def render_markdown(findings, result=None, lang="en", new_ids=frozenset()):
    out = ["## SentinelGuard report", "", header(result) if result else "", ""]
    c = _counts(findings)
    out.append("| Severity | Open |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in c.items()))
    out.append("")
    for f in sorted(findings, key=lambda f: (-sev_rank(f.severity), f.path, f.line)):
        m = meta(f.rule_id)
        loc = f"`{f.path}:{f.line}`" if f.line else f"`{f.path}`"
        out.append(f"### {f.severity.upper()}: {f.message} {'**(new)**' if f.fingerprint in new_ids else ''}")
        out.append(f"- Where: {loc}  ·  Rule: `{f.rule_id}` {f.cwe}  ·  id: `{f.fingerprint}`")
        if f.snippet and f.kind != "dependency":
            out.append(f"- Code: `{f.snippet}`")
        out.append(f"- Why it matters: {m['why']}")
        out.append(f"- Fix: {f.fix}")
        if lang == "ur" and m["ur"]:
            out.append(f"- اردو: {m['ur']}")
        out.append("")
    return "\n".join(out)


def render_json(findings, result=None, **_):
    data = {"tool": "sentinelguard", "version": __version__, "findings": [f.to_dict() for f in findings]}
    if result:
        data["run"] = {"scanned": result.scanned, "changed": result.changed, "new": len(result.new),
                       "fixed": len(result.fixed), "duration": round(result.duration, 3)}
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_sarif(findings, result=None, **_):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = {f.rule_id: {"id": f.rule_id, "name": meta(f.rule_id)["title"],
                         "shortDescription": {"text": meta(f.rule_id)["title"]},
                         "help": {"text": meta(f.rule_id)["fix"]}} for f in findings}
    results = [{
        "ruleId": f.rule_id, "level": level[f.severity], "message": {"text": f.message},
        "partialFingerprints": {"sentinel/v1": f.fingerprint},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                            "region": {"startLine": max(f.line, 1)}}}]} for f in findings]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "SentinelGuard", "version": __version__,
                                                     "rules": list(rules.values())}}, "results": results}]}, indent=2)


def render(findings, fmt="text", result=None, lang="en", new_ids=frozenset()):
    fn = {"text": render_text, "markdown": render_markdown, "json": render_json, "sarif": render_sarif}[fmt]
    return fn(findings, result=result, lang=lang, new_ids=new_ids)
