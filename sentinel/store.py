"""SQLite finding store. Tracks each issue through: open -> fixed, or open -> ignored."""
import sqlite3
import time
from pathlib import Path

from .models import Finding, sev_rank

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT,
    files_scanned INTEGER DEFAULT 0, duration REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(fp TEXT PRIMARY KEY, scope TEXT, rule_id TEXT, severity TEXT, kind TEXT,
    path TEXT, line INTEGER, message TEXT, snippet TEXT, cwe TEXT, fix TEXT, status TEXT,
    first_run INTEGER, last_run INTEGER, fixed_run INTEGER, ignore_reason TEXT, notified INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, mtime_ns INTEGER, size INTEGER, sha TEXT);
CREATE INDEX IF NOT EXISTS ix_scope ON findings(scope);
"""

COLS = "fp, rule_id, severity, kind, path, line, message, snippet, cwe, fix"


def _to_finding(r) -> Finding:
    return Finding(rule_id=r[1], severity=r[2], kind=r[3], path=r[4], line=r[5], message=r[6],
                   snippet=r[7], cwe=r[8], fix=r[9], fingerprint=r[0])


class Store:
    def __init__(self, state_dir: Path, readonly: bool = False):
        self.path = Path(state_dir) / "findings.db"
        if readonly:
            self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        else:
            self.db = sqlite3.connect(self.path)
            self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    # ---- runs ----
    def begin_run(self, kind: str) -> int:
        cur = self.db.execute("INSERT INTO runs(ts, kind) VALUES(?, ?)", (time.time(), kind))
        self.db.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, files_scanned: int, duration: float):
        self.db.execute("UPDATE runs SET files_scanned=?, duration=? WHERE id=?", (files_scanned, duration, run_id))
        self.db.commit()

    def last_run(self):
        r = self.db.execute("SELECT id, ts, kind FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return r

    # ---- file hashes (incremental scanning) ----
    def get_files(self) -> dict:
        return {p: (m, s, h) for p, m, s, h in self.db.execute("SELECT path, mtime_ns, size, sha FROM files")}

    def set_file(self, path, mtime_ns, size, sha):
        self.db.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?)", (path, mtime_ns, size, sha))

    def del_file(self, path):
        self.db.execute("DELETE FROM files WHERE path=?", (path,))

    # ---- findings ----
    def sync_scope(self, scope: str, findings: list[Finding], run_id: int):
        rows = dict(self.db.execute("SELECT fp, status FROM findings WHERE scope=?", (scope,)).fetchall())
        seen = set()
        for f in findings:
            seen.add(f.fingerprint)
            st = rows.get(f.fingerprint)
            if st is None:
                self.db.execute(
                    "INSERT INTO findings(fp,scope,rule_id,severity,kind,path,line,message,snippet,cwe,fix,status,first_run,last_run) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?,?)",
                    (f.fingerprint, scope, f.rule_id, f.severity, f.kind, f.path, f.line, f.message,
                     f.snippet, f.cwe, f.fix, run_id, run_id))
            elif st == "fixed":     # it came back: treat as new again
                self.db.execute("UPDATE findings SET status='open', first_run=?, last_run=?, fixed_run=NULL, notified=0, line=? WHERE fp=?",
                                (run_id, run_id, f.line, f.fingerprint))
            else:
                self.db.execute("UPDATE findings SET last_run=?, line=?, snippet=?, severity=?, message=? WHERE fp=?",
                                (run_id, f.line, f.snippet, f.severity, f.message, f.fingerprint))
        for fp, st in rows.items():
            if fp not in seen and st in ("open", "ignored"):
                self.db.execute("UPDATE findings SET status='fixed', fixed_run=? WHERE fp=?", (run_id, fp))
        self.db.commit()

    def _query(self, where: str, params=()):
        rows = self.db.execute(f"SELECT {COLS} FROM findings WHERE {where}", params).fetchall()  # sentinel:ignore (internal constants only, values are bound parameters)
        fs = [_to_finding(r) for r in rows]
        fs.sort(key=lambda f: (-sev_rank(f.severity), f.path, f.line))
        return fs

    def open_findings(self):
        return self._query("status='open'")

    def new_in_run(self, run_id):
        return self._query("status='open' AND first_run=?", (run_id,))

    def fixed_in_run(self, run_id):
        return self._query("status='fixed' AND fixed_run=?", (run_id,))

    def unnotified(self, min_sev: str):
        return [f for f in self._query("status='open' AND notified=0") if sev_rank(f.severity) >= sev_rank(min_sev)]

    def mark_notified(self, fps):
        self.db.executemany("UPDATE findings SET notified=1 WHERE fp=?", [(fp,) for fp in fps])
        self.db.commit()

    def ignore(self, fp_prefix: str, reason: str) -> int:
        cur = self.db.execute("UPDATE findings SET status='ignored', ignore_reason=? WHERE fp LIKE ? AND status='open'",
                              (reason, fp_prefix + "%"))
        self.db.commit()
        return cur.rowcount

    def summary(self) -> dict:
        out = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for sev, n in self.db.execute("SELECT severity, COUNT(*) FROM findings WHERE status='open' GROUP BY severity"):
            out[sev] = n
        ign = self.db.execute("SELECT COUNT(*) FROM findings WHERE status='ignored'").fetchone()[0]
        fix = self.db.execute("SELECT COUNT(*) FROM findings WHERE status='fixed'").fetchone()[0]
        return {"open": out, "open_total": sum(out.values()), "ignored": ign, "fixed": fix, "last_run": self.last_run()}
