# Security policy

## Reporting a vulnerability
Please report privately (do not open a public issue) to the maintainers' security contact once the repository is
published. Include the version (`sentinel --version`), steps to reproduce and impact. Target response: 72 hours.

## What SentinelGuard promises (and checks itself)
| Claim | How it is enforced / verified |
|---|---|
| Never modifies your project | Files are opened with `open(path, "rb")`; scan state lives outside the project; `sentinel verify` and `tests/test_sentinel.py::TrustTests` hash the tree before and after |
| Never executes your code | The scanner only reads and pattern-matches text; no `include`, `eval`, `subprocess` on project content |
| No network by default | `netguard.py` denies every host not in `[network].allow`; every attempt is logged (`sentinel network-report`) |
| Never sends source code anywhere | Notifications carry rule, severity and `file:line` only; advisory sync downloads data, it uploads nothing |
| Fail-open | `sentinel hook` catches all errors and exits 0 unless strict mode is on |
| Config is data | TOML only, unknown keys ignored, nothing executed |
| No supply-chain surface | Python standard library only; no auto-update |
| Clean exit | `sentinel uninstall` removes only what carries the sentinel marker |

## What it cannot promise
No software can honestly promise "zero risk" or "all vulnerabilities". See `docs/LIMITATIONS.md`.
