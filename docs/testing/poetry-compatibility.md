# Poetry patches

Hosted mode rewrites `poetry.lock` to a URL source. Vendored mode writes a local wheel source. Both retain the package version, dependencies, groups, markers, extras, and the pyproject content hash. No pyproject edits are required. Repeated scans leave the lock unchanged; rollback restores the recorded originals. A forked target, an existing unrelated source, an unsupported format, or a wheel/package mismatch is refused before writing.

The committed native locks cover Poetry 0.12.17, 1.0.10, 1.1.15, 1.2.2, 1.3.2, 1.4.2, 1.5.1, 1.6.1, 1.7.1, 1.8.5, 2.0.1, 2.1.4, 2.2.1, 2.3.4, and 2.4.3. They cover legacy `metadata.hashes`, `metadata.files` in lock 1.0/1.1, and package `files` in lock 2.0/2.1.

| Poetry | Vendored | Hosted | Installer integrity |
| --- | --- | --- | --- |
| 0.12 | Supported | Refused: the installer ignores URL sources | Local wheel hashes are not checked by Poetry |
| 1.0 | Supported | Supported with a SHA-256 URL fragment | Hosted hashes are checked by pip; local wheel hashes are not checked |
| 1.1–1.3 | Supported | Supported | Hosted hashes are checked; local wheel hashes are not checked |
| 1.4–1.8 | Supported | Supported | Both modes reject mismatched lock hashes |
| 2.0–2.4 | Supported | Supported | Both modes reject mismatched lock hashes |

Poetry 1.0 requires a `source.reference` even for archive sources and appends `#egg` unconditionally. Its hosted URL fragment therefore ends with a separator to preserve the SHA-256 parameter. Poetry 1.2 drops URL hashes from `metadata.files`; lock 1.1 hosted rewrites also write `package.files`, while retaining `metadata.files` for Poetry 1.1.

The vendor warning `pypi_poetry_integrity_unverified` is emitted for lock formats readable by Poetry before 1.4. Upgrade the installer to at least 1.4 for local wheel hash enforcement. These older installers still install the patched bytes; the live backtest verifies the installed files against the patch record's SHA-256 Git blob hashes and separately records their inability to reject a changed lock hash.

Run the local Rust coverage:

```sh
cargo test -p socket-patch-core --lib vendor::pypi_poetry
cargo test -p socket-patch-core --test poetry_hosted
```

The live installer harness is `tools/pipeline/poetry-patch-backtest.py` in SocketDev/depscan. It uses public PyPI and the real patch API, bootstraps the actual Poetry versions with uv, captures both CLI modes, checks repeat scans and unchanged lockfiles, verifies installed patch bytes, and tests tampered hashes. Its additional shapes cover dev dependencies, selected and excluded optional extras, Python markers, groups, PEP 621, transitive requests dependencies, and CRLF files. The edge inputs are derived from native locks; their content hashes are computed by the matching Poetry library before running the real installer.

`poetry update` and lock regeneration can replace a patch source with an upstream source. Re-run Socket Patch after changing the dependency resolution.
