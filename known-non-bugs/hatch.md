# Hatch known non-bugs and documented limitations

One line per item. Search with `git grep`; don't read the whole file.

- Locked Hatch envs with `installer = "pip"`: Hatch's pip locker can't apply lockfiles (`LockerUnsupportedError`), so it's a Hatch limitation.
- Probing Hatch through `uv tool run` with uv 0.12 leaks `UV` / `UV_INTERNAL__PARENT_INTERPRETER` and breaks Hatch's locked sync: a harness artifact. Use installed Hatch binaries.
- Vendored PEP 735 dependency groups are refused (Hatch does not expand `{root:uri}` there): documented.
- Vendored with `installer = "uv"` / `uv-path` is refused: documented. Note that uv 0.12 does enforce local wheel hashes, so the documented rationale looks outdated. Hatch's internal uv envs (`hatch-test` etc.) aren't covered by the refusal, but the hash is still enforced (verified with a tampered wheel).
- Vendored needs `hatch` >= 1.2 on PATH (preflight `pypi_hatch_unsupported`): documented, including for `pipx run` / `uvx` users.
- Ranges, transitive-only (including workspace-member-only deps when scanned from the root), dynamic deps, sources, overrides and custom env types are refused: documented.
- Hosted project rewrites embed a direct URL in the built wheel's `Requires-Dist` (so the result can't be uploaded to PyPI): inherent to the design.
- `rollback` with nothing ever written exits 2 `Manifest not found`. `remove` after a full rollback gives `manifest_not_found`.
- Vendored scan against the mock fails `vendor_prebuilt_required` unless the grant's artifact carries `integrity.sha512` (v5): a harness requirement, not a bug.
- In mock runs every purl "has" a six patch (the batch endpoint answers six for any input). Use `scannedPackages` and the apply results, not `packages[]`, to judge discovery.
- `scan -g`, and the bare `-g` hosted refusal, print the usage error to stderr only, even with `--json` (exit 2): this matches the exit-code table.
- Hosted `rollback` only recognises wiring on `patch.socket.dev` or the `--patch-server-url` origin. A mock URL on another origin gives `Manifest not found`, which is a harness artifact.
- A "read-only" prefix the current user owns (chmod 0444 / 0555) still gets patched, because the owner can write. Only a prefix the user can't write to is a real refusal case.
- Env `overrides`, `[tool.hatch.env]` (requires / collectors), custom env `type`, and a non-table `envs` in hatch.toml are refused with nothing written: documented.
- `six==1.16` used to be refused as not exact. It's accepted since `045d7ec` (#475). `six (==1.16)`, `===1.16.0`, `+local` and `rc` pins are still refused, failing closed.
- A pyproject.toml with a UTF-8 BOM isn't loadable by Hatch (`TOMLDecodeError` at 1:1). Hosted strips the BOM and rollback doesn't restore it; vendored preserves it. Not filed, because the input is invalid for Hatch.
- vex from the project root in the sandbox can omit six as `not_applied` because of the system `/usr/lib/python3/dist-packages/six.py`: a sandbox artifact.
- Exact pins in non-canonical spellings (`===`, `(==1.16.0)`) are refused (`1.16.0.0` and `v1.16.0` are accepted since `045d7ec`) with "requires an exact ==X declaration": an over-refusal that fails closed, the same class as `six==1.16`.
- Hosted rollback rebuilds the requirement from the URL (no v5 ledger), so the original spelling isn't byte-exact (`SIX == 1.16.0` → `SIX==1.16.0`, `;` → ` ; `). It's semantically equal. Vendored rollback is exact.
- Hosted rollback removes a user-preset `allow-direct-references` (true or false, in pyproject or hatch.toml, and empties the table, which can leave a 0-byte hatch.toml) when no other direct reference remains. It can't tell ownership without a ledger, and it has no functional effect, so it's logged as low severity (`patch/redirect/upstream/pypi.rs:785`).
- Env deps whose version comes from a context field (`six=={env:SIXV:1.16.0}`, `six{env:SPEC:==1.16.0}`) are refused as not exact (hosted warns in `redirect.warnings`, vendored fails): a fail-closed over-refusal, the same class as `six==1.16`.
- `rollback` / `remove` match PURL names case-sensitively (`pkg:pypi/TOML@0.10.2` gives "No patch found"). It fails closed and isn't Hatch-specific, so it's logged, not filed.
- When hatch.toml defines `envs`, Hatch ignores pyproject's `tool.hatch.envs` entirely, and socket-patch leaves those declarations alone (they're seen as transitive). That's consistent.
- Vendored `partial_failure` for an undeclared `toml` / `six` in the sandbox comes from the system `/usr/lib/python3/dist-packages`: a sandbox artifact.
- Hosted rollback of a Hatch pylock with no sibling registry package is refused ("no sibling registry package shows the registry…"): it fails closed and is documented in CLI_CONTRACT.md.
- A vendored project's built wheel carries an absolute `file://` `Requires-Dist`, because Hatchling expands `{root:uri}` at build time. That's inherent, like the hosted direct-URL case.
- Vendored on a project with any `[tool.uv.sources]` (and no uv.lock) is refused with the uv lane's `pypi_uv_no_lockfile`: it fails closed, and the message is only confusing.
- Hosted `vex` with no Hatch environment created yet attests `not_affected`: hosted vex derives from the wired references, as for a lockfile-only checkout (2026-11-26). It refuses over a stale existing env, which is correct.
- Harness: putting a Hatch venv's whole `bin/` on PATH makes a no-env scan read Hatch's own venv as the project's (a venv `python3` on PATH counts as the project env, #2170 design). Expose only the `hatch` binary (symlink dir, like pipx) and create the env before scanning (2026-11-26).
- Harness: the mock must answer HEAD on the wheel route (uv probes with HEAD and fails on 501) and serve `/patches/blob/<sha>` for agent rollback (`missing_blob` otherwise) (2026-11-26).
- Harness: in the sandbox, a scan with no env finds six from the system `/usr/lib/python3/dist-packages`, so "first scan before any env" passing there is an artifact (2026-11-26).
- Hosted scan with `installer = "uv"` and a url / path `[tool.uv.sources]` entry for the patched package exits 0 `success` with nothing written and a warning to use agent mode: the documented #673 refusal (2026-11-26). The warning capitalises the name ("Six:"), which is cosmetic.
