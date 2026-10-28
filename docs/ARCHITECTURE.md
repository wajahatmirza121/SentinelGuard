# Architecture

```
            +-----------+     +-----------+     +------------+
 files ---> | fingerprint| --> |  scanner  | --> |   store    | --> report / notify / dashboard
 (read-only)| + stack    |     | (rules,   |     | (SQLite,   |
            | + deps     |     |  taint)   |     |  lifecycle)|
            +-----------+     +-----+-----+     +------------+
                                    ^
              advisory (OSV, local) +        netguard: default-deny network, all attempts logged
```

* `fingerprint.py` walks the tree (no symlinks), detects the stack and parses `composer.lock`, `package-lock.json`, `requirements.txt`.
* `scanner.py` is incremental: unchanged files (mtime+size+sha256) are skipped; deleted files close their findings.
* `rules/php.py` strips comments, splits statements, tracks taint per vulnerability class, matches sinks.
* `store.py` keeps each finding as open, fixed or ignored using line-independent fingerprints.
* `notify.py` sends only new findings once; failures never raise.
* `watcher.py` (live), `hooks.py` (pre-commit, CI), `monitor` command (scheduled advisory re-check).
* State is stored in `~/.local/state/sentinel/<project-hash>/`, never in the project.
