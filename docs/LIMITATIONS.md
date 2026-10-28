# Limitations (read this before trusting a result)

1. **It does not detect all vulnerabilities.** No tool can. A clean report is "no known patterns found", not "secure".
2. **PHP analysis is token/regex based with a small taint tracker**, not a full AST/data-flow engine. It follows
   assignments, concatenation, foreach and sanitizers within one file. It does **not** follow data across functions,
   classes or files, so it will miss vulnerabilities that pass through helper functions, and may flag code that is
   protected by validation it does not recognise. Expect false negatives and some false positives.
3. **Python and JavaScript** have only a small line-pattern rule pack (hazardous calls), not taint tracking.
4. **No framework models** yet (Laravel/WordPress/Django specifics such as ORM safety, nonces, capabilities).
5. **Dependency matching depends on the advisory data you load.** Online sync (OSV ecosystem dumps) is implemented but
   could not be exercised in the build sandbox (no network); try `sentinel sync --online` after allowing the OSV host.
   Advisories for the PHP **runtime itself** are not part of standard package feeds: supply them as advisory files in
   the same OSV-style format (see `sentinel/data/demo_advisories.json`).
6. Severity for imported advisories uses the advisory's own label when present, otherwise defaults to `medium`.
7. The watcher is polling-based (default 2 s). Fine for projects up to thousands of files.
8. Not independently audited. The sandbox (container, read-only mount, no network) is documented but is your deployment
   choice; the in-process guarantees are tested but are not an OS-level barrier.
9. No runtime protection agent by design (it would run inside production and add attack surface).
