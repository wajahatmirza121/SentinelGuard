# Threat model (v0.1)

Assets: the user's source code and secrets, the integrity of the project, the user's trust in findings.
Trust boundary: the scanner treats **all project files as hostile input**.

| # | Threat | Control in code | Status |
|---|---|---|---|
| T1 | Source or secrets leave the machine | Default-deny `netguard`; masked secrets in all output; notifications omit code | Implemented, tested |
| T2 | Scanner modifies project | Read-only opens; state outside tree; proof tests | Implemented, tested |
| T3 | Scanner executes project code | Parse-only design; no eval/exec/subprocess on content (only `git diff --cached --name-only` in hook) | Implemented |
| T4 | Malicious file crashes / exploits scanner | Size limit, symlinks not followed, regex-based (no native parsers), per-file failure isolated by tests; **OS sandbox recommended (see README)** | Partial |
| T5 | Catastrophic regex backtracking (ReDoS) on crafted files | Line length caps (2000), file size cap; rules reviewed for simple patterns | Partial |
| T6 | Poisoned advisory data | Advisory file names derived from ids (no zip-slip), entries schema-checked, sync is opt-in + allowlisted; **signature verification not yet implemented** | Partial |
| T7 | Compromised release of SentinelGuard | Zero dependencies, no auto-update; **signed releases / SBOM planned** | Planned |
| T8 | Over-privileged CI | Generated workflow uses `contents: read` only | Implemented |
| T9 | Hook blocks developers | Fail-open; strict mode opt-in | Implemented, tested |
| T10 | Dashboard exposure | Loopback only, GET only, read-only DB connection, CSP header | Implemented |
| T11 | Alert fatigue leads to ignoring tool | Stable fingerprints, new-only alerts, one notification per finding, ignore-with-reason | Implemented, tested |
