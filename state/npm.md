[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-10-02 (run 9 with a ledger), main `203e092` (v5 + the #324/#326/#359/#403/#434/#454/#490/#516/#541 fixes; the binary still reports 4.0.0), latest release v4.0.0 (previous v3.3.0, both from npm `@socketsecurity/socket-patch`). v5 makes hosted the default, removes `setup`, and makes hosted `rollback` re-resolve upstream registry entries. Cells marked (v4) were last verified on `f6b7fb9`.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Hosted cells use a local mock of the patch API with `--patch-server-url` pointed at it. Agent and vendored cells use the same mock or a hand-staged `.socket/`. "Cycle" means scan → fresh `npm ci` → `vex` → `rollback` byte-exact. "Suites" means `e2e_redirect_npm_build` + `e2e_vendor_npm_build` with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`.

| OS | npm | Agent (apply / scan --mode agent) | Vendored | Hosted (v5 default) | Global `-g` (scan report / get+apply / vex / rollback) |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (v4). pass: `-g` (v4) | pass: nested v2 lock (v4). v1 lock refused loudly (documented). fail #432 (alias mirror) | pass: v1-lock cycle (npm 6 installs the patched bytes), shrinkwrap-only v1 cycle. v1 alias: not wired (#432) | pass (v4) |
| Linux | 7.0.15 / 7.24.2 | pass: scan/apply, vex, `npm ci` → vex refuses, re-apply, rollback | pass: cycle + `--omit=dev`, workspaces, vendored↔hosted takeover, revert byte-exact | pass: cycle (alias, nested, dev), workspaces, takeovers | untested |
| Linux | 8.19.4 | fail #356 (v4). #403 / #516 closed by fixes | fail #432, **#588** (same-lock unwired copy). pass: cycle + `--omit=dev`, workspaces, takeovers, rescan no-op | pass: nested v2 cycle, shrinkwrap-only, workspaces, takeovers, rescan no-op, `overrides` (flat, alias, nested). fail #432 (alias mirror, npm 6 consumer), #490 (override over a git spec; closed by #491, not re-checked), **#588** (`--no-verify`) | untested |
| Linux | 9.9.4 | pass `-g` (v4); Node 18 cycle | pass: cycle + `--omit=dev` (main), Node 18 cycle | pass: cycle (alias, nested, dev), Node 18 cycle | pass (v4) |
| Linux | 10.8.2 (Node 18) / 10.9.x | pass: Node 18 cycle. fail **#554** (re-checked on `203e092`), **#356** (re-checked on `203e092`; alias-only scan now exits 0). pass: agent vex refuses a reverted nested copy (#516 fixed), bundled copy (both copies patched + vex) | pass: CRLF / BOM / tab layout cycle (#324 fixed), `--omit=dev`, agent↔vendored takeovers, rescan after a version bump (#541 fixed). fail **#588** (same-lock unwired copy) | pass: cycles (plain, alias, nested), `npm ci --omit=dev` + vex, shrinkwrapped `file:` dep, `JSONStream`, agent↔hosted takeovers, stale tree, lockfile-only, dry-run, rescan no-op, nested project (loud), `registry=` mirror, `.npmrc` variants, `overrides` (incl. `$ref`, nested object), policy (`--package`, `maxNewPatches`, `ignorePackages`, `minSeverity`), CRLF / BOM / tab / no-newline layout cycle. fail #325 (in-run `--vex` only, reopened), **#588** (`--no-verify` only; default `vex` refuses) | pass: all four, `--global-prefix`, `SOCKET_GLOBAL`, `--mode hosted` refused. fail #464 (report-only hint has no `-g`) |
| Linux | 11.20 / 11.21 | pass (v4); linked `.store` scoped transitive (11.21, #359 fixed). fail #403 (v4) | pass (v4). #490 (11.21; closed by #491, not re-checked) | pass: scoped, duplicate nested workspace copies, dual-lock drift, `omit-lockfile-registry-resolved`, `overrides`, `install-strategy=linked/nested/shallow` | untested |
| Linux | 12.1 / 12.2.0 | fail #356, **#554** (12.2.0) | fail **#588** (12.2.0). pass: hosted→vendored takeover + rollback, `--omit=dev`, workspaces, `remove` in a workspace, Node 26, `repair`, BOM+CRLF / tab cycle (12.2.0) | fail **#588** (`--no-verify`, 12.2.0). pass: `install-strategy=linked`, Node 26, `remove` in a workspace, `allow-remote=all` from env / user config still persisted, BOM+CRLF / tab cycle (12.2.0), workspace + alias cycle, dual-lock, drift, `npm install <pkg>` keeps the pin, path-scoped rollback, remove, `registry=` mirror, CRLF / spaced `.npmrc`. fail #433 | pass: all four |
| macOS | 10.9.7 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| macOS | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| Windows | 10.9.7 | pass: linked `.store` apply/vex/rollback (main). fail #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** (default and custom prefix; `--global-prefix` works) |
| Windows | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** |
| Windows 2022 | 10.9.7 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main) | pass: cycle + `--omit=dev`, revert (main) | pass: linked cycle (probe) | **fail #434** |

## Backlog

1. **#588 follow-ups:** an unwired same-lock copy under `install-strategy=linked` and across a shrinkwrap/package-lock pair; whether `vendor --check` should flag it.
2. **Re-checks on `203e092`:** #325, #432, #490 (override over URL / `file:` transitive deps on npm 8–12).
3. **#554 follow-ups:** agent `rollback` / `vex` with path policy over nested projects.
4. **#356:** alias-only agent `scan` now exits 0 with nothing applied (since #555). Watch for a fix.
5. **Maintainer request (global `-g`), still open:** npm 6/8/11 on macOS and Windows; an unwritable prefix (root-owned / `Program Files`); nvm, volta, fnm and Homebrew prefixes on macOS; `%APPDATA%\npm` now that #434 is closed. Full checklist in the 20261001T040000Z entry.
6. Stale probe branches the proxy can't delete (`git push --delete` fails with "remote end hung up" / "Everything up-to-date"): `bughunt/npm/20260930-alias-linked`, `20260930-win-mac-e2e`, `20260930-win-old-npm`, `20261001-crlf-paths`, `20261001-optional-dep`, `20261001-v5-hosted-global`, `20261001-win-global`, `20261002-v5-agent-vendored-winmac`. A maintainer needs to delete them.

## Known non-bugs

- `patches-api.socket.dev` is unreachable from the sandbox. Use hand-staged manifests, a local mock API, or the wiremock suites.
- Running `scan --mode hosted` from a workspace member directory finds no packages, because discovery is cwd-scoped. It's loud and writes nothing.
- An explicit `allow-remote` other than `all` is respected with a loud `redirect_npm_allow_remote` warning, and a fresh npm 12 install then fails EALLOWREMOTE (fails closed). This is documented.
- `npm update` re-resolves a hosted or vendored entry back to the registry. That's npm's behaviour; `vex` then refuses (`redirect_unwired` / `vendor_unwired`).
- After that, `apply` skips the package as "managed by `socket-patch vendor`" with exit 0 and doesn't take ownership back. That's by design (`apply.rs` `VENDOR_OWNED_MARKER`), and `vex` refuses.
- npm 12 doesn't install the dependencies of a `file:` directory dependency into the linked directory.
- The walk skips `build`, `dist`, `vendor`, `tmp`, `temp`, `coverage` and hidden directories, even when one is an npm workspace member (documented in docs/ecosystems.md).
- `apply` from a workspace member directory reports `noManifest` when `.socket/` lives at the root (`--cwd` scoping).
- Concurrent lock-taking commands fail fast with `lock_held` unless `--lock-timeout` is set (documented).
- `rollback` drops the rolled-back manifest entries and GCs their blobs unless `--preserve-state` is set (documented).
- Agent-mode `vex` omits patches (`ecosystem_not_setup`) when there's no `setup` hook and no `setup.manual` (documented).
- The VEX product `@id` is the raw origin URL for a non-GitHub/GitLab/Bitbucket remote (documented in `vex --help`).
- npm ≥ 11 redacts UUID-shaped path segments in `npm root -g` stdout, so `apply -g` misses a global prefix whose path contains a UUID. That's npm's behaviour, it's loud (exit 1), and `--global-prefix` works around it. Not filed.
- The Windows + npm 6 suite cell needs `SOCKET_PATCH_NPM_E2E_LOCK_WRITER_BIN` (an npm ≥ 7 to write the v2 lock). That's a harness requirement.
- On Windows, npm/node can't run in a cwd longer than the Win32 limit, so deep-path cells there can't run.
- Hosted pins on any host other than `patch.socket.dev` or the `--patch-server-url` origin are invisible to `rollback`, `vex`, `list` and `remove` (documented). Mock runs must pass `--patch-server-url`.
- In the sandbox, hosted `rollback` can't reach registry.npmjs.org (the Rust client doesn't trust the proxy CA). Use `SOCKET_NPM_REGISTRY` pointed at a local passthrough.
- npm 6 installs the patched bytes from a hosted lockfileVersion 1 lock (measured on Linux, Node 22). npm-compatibility.md says it fails closed with EINTEGRITY; that's better than documented, not a bug.
- `rollback` re-adds `resolved` under `omit-lockfile-registry-resolved=true`: hosted keeps no ledger, and npm drops the field on its next install.
- A failed hosted lock write (an immutable lock) leaves `allow-remote=all` in `.npmrc`: exit 1, the documented mid-flush I/O residual.
- A bare hosted `scan` wires only the cwd project's lock. A nested non-workspace project warns `redirect_npm_entry_not_found`. `scan . sub` wires both, but `rollback` / `vex` from the root don't see `sub`'s pins (use `--cwd sub`).
- `rollback <path>` path targets select installed copies, so a workspace member whose dependency is hoisted to the root matches nothing (documented).
- Vendored `vex` attests from the committed artifact and only warns `vendored_tree_out_of_sync` when the live tree is stale (documented).
- `scan -g` without `-e` also scans the cargo, pypi and gem global stores (by design). `vex -g` outside a project needs `--product`.
- v5 removes `setup`, so the setup-hook cells are retired.
- Hosted `rollback` restores `resolved` to `registry.npmjs.org` (or `SOCKET_NPM_REGISTRY`) even when the project `.npmrc` uses a `registry=` mirror. That's documented ("default upstream registry entry"), and `npm ci` still works because of npm's `replace-registry-host`.
- `--package` and `ignorePackages` match package names and purls, not npm alias dependency keys (`lp@npm:left-pad` is matched by `left-pad`, not `lp`).
- npm 12 ignores `ALLOW-REMOTE=` and `allow_remote=` keys in `.npmrc`, so socket-patch appending `allow-remote=all` after them is correct.
- `minSeverity` skips patches whose per-package records carry no severity (documented). Mocks must fill `vulnerabilities` in `by-package`.
- `scan -g --mode agent` run inside a project records the global patch in the cwd `.socket/manifest.json`, and `rollback -g` drops it again. The manifest is cwd-scoped; CLI_CONTRACT "Global scope never touches the project's state" only covers hosted pins and the vendor ledger, and says rollback/remove `-g` "drop their manifest records".
- With no override, npm dedupes a root registry spec (`left-pad@1.3.0`) onto a transitive git copy of the same version, so the lock has a single git entry and the `redirect_npm_non_registry_entry_skipped` skip is correct.
- v4.0.0 agent `vex` omits patches with `ecosystem_not_setup` unless `setup.manual` lists the ecosystem (v4 behaviour). Set it when bisecting vex against v4.
- Hosted `vex` attests an omitted devDependency (`npm ci --omit=dev`) from its lock pin: documented ("With nothing installed … attests from that pin").
- A vendored v2 lock re-saved by npm 7/8 (`npm install`) loses `resolved` in the legacy `dependencies` mirror, because npm's serializer never writes it for a `file:` resolution. A cold-cache npm 6 `npm ci` then fails closed with EINTEGRITY. That's npm's behaviour; npm-compatibility.md's npm 6 + vendored v2 claim holds only until such a re-save.
- `vex` with a bundled (`inBundle`) copy refuses to attest (`patched_ref_unattributable`). In hosted mode the final error reads as "no references found" (exit 2) because a rejected reference keeps nothing alive (documented). Only the diagnostic is misleading.
- `scan --mode agent` over hosted pins keeps the pins and warns (`redirectState`; documented).
- npm vendored `scan --prune` / `vendor --revert` / `remove` keep (`keptVendoredEntries`, `vendor_artifact_kept`) an entry whose lock entry vanished after `npm uninstall` or a version bump. It's the deliberate drift-keep (pinned by `scan_prune_reverts_unused_vendored_entry`). Whether to reclaim it is an open maintainer question (#541 / PR #543 scope note). The rescan exit 1 is #541.
