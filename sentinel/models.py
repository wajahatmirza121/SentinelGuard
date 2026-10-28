from dataclasses import dataclass, asdict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s: str) -> int:
    try:
        return SEVERITIES.index(s)
    except ValueError:
        return 0


@dataclass
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    kind: str = "code"          # code | dependency | secret | config
    snippet: str = ""
    cwe: str = ""
    fix: str = ""
    fingerprint: str = ""

    def to_dict(self):
        return asdict(self)
