[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-10-06T18Z (run 25 with a ledger), main `9c43dfc` (unchanged since 00Z), latest release v4.0.0 (previous v3.3.0, both from npm `@socketsecurity/socket-patch`). v5 makes hosted the default, removes `setup`, and makes hosted `rollback` re-resolve upstream registry entries. Cells marked (v4) were last verified on `f6b7fb9`. #432 (closed by #813) and #798 (closed by #799, re-verified 18Z: `vex` refuses the stale twin) are fixed; their old `fail` marks below are historical.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Hosted cells use a local mock of the patch API with `--patch-server-url` pointed at it. Agent and vendored cells use the same mock or a hand-staged `.socket/`. "Cycle" means scan → fresh `npm ci` → `vex` → `rollback` byte-exact. "Suites" means `e2e_redirect_npm_build` + `e2e_vendor_npm_build` with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`.

| OS | npm | Agent (apply / scan --mode agent) | Vendored | Hosted (v5 default) | Global `-g` (scan report / get+apply / vex / rollback) |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (v4), **#732** (human `scan --mode agent` re-scan after `npm ci` leaves files unpatched). pass: `-g` (v4) | pass: nested v2 lock (v4). v1 lock refused loudly (documented). fixed #432 (alias mirror; regression follow-up #879), **#659** (hosted→vendored takeover via `scan`/`get` on a v1 lock un-hosts, then refuses; `vendor` eject rolls back) | pass: v1-lock cycle (npm 6 installs the patched bytes), shrinkwrap-only v1 cycle. v1 alias: not wired (#432) | pass (v4) |
| Linux | 7.0.15 / 7.24.2 | pass: scan/apply, vex, `npm ci` → vex refuses, re-apply, rollback | pass: cycle + `--omit=dev`, workspaces, vendored↔hosted takeover, revert byte-exact | pass: cycle (alias, nested, dev), workspaces, takeovers. fail **#753** (copy nested under a `hasShrinkwrap` dep installs unpatched) | pass: all four (7.24.2, custom prefix) |
| Linux | 8.19.4 | fail #356 (v4). #403 / #516 closed by fixes | fixed #432 (see #879), **#588** (same-lock unwired copy), **#665**, **#688**. pass: alias takeover, cycle + `--omit=dev`, workspaces, takeovers, rescan no-op | pass: `peer: true` lock-entry cycle, nested v2 cycle, shrinkwrap-only, workspaces, takeovers, rescan no-op, `overrides` (flat, alias, nested). fixed #432 (alias mirror, npm 6 consumer), #490 (override over a git spec; closed by #491, not re-checked), **#588** (`--no-verify`), **#753** (`hasShrinkwrap` nested copy) | pass: all four (custom prefix) |
| Linux | 9.2.0 / 9.9.4 | pass: 9.2.0 `install-links=true` `file:` dir dep cycle; `-g` (v4); Node 18 cycle | pass: 9.2.0 `install-links` `file:` dep cycle, cycle + `--omit=dev` (main), Node 18 cycle | pass: 9.2.0 `install-links` `file:` dep cycle, cycle (alias, nested, dev), Node 18 cycle. fail **#753** | pass (v4) |
| Linux | 10.9.9 | pass: plain cycle (alias still #356) | pass: cycle, `overrides` + `file:` dependent | pass: cycle, `overrides`, shrinkwrapped `file:` tarball dep | untested |
| Linux | 10.8.2 (Node 18) / 10.9.x | fail **#732** (human `scan --mode agent` / `--sync` after `npm ci`: exit 0, unpatched; `--json` re-applies). pass: Node 18 cycle. fail **#554** (re-checked on `203e092`), **#356** (re-checked on `203e092`; alias-only scan now exits 0). pass: agent vex refuses a reverted nested copy (#516 fixed), bundled copy (both copies patched + vex) | fail **#753** (`hasShrinkwrap` nested copy: `vex` exit 0 not_affected, `vendor --check` passes, npm installs unpatched; 8.19.4 too). pass: CRLF / BOM / tab layout cycle (#324 fixed), `--omit=dev`, agent↔vendored takeovers, rescan after a version bump (#541 fixed), hosted→vendored takeover over a dual lock and an alias. fail **#588** (same-lock unwired copy), **#665** (`npm uninstall` of a vendored dep: rollback exit 1 forever), **#688** (`file:` dir named like the package: refused, and the takeover un-hosts), **#687** (a failed eject rewrites every root file), #798 fixed by #799 (stale twin: `vex` now refuses, 18Z), #725 (`vendor --check` ignores wiring). pass: `peer: true` lock entry. fail **#828** (hosted→vendored takeover over a pin with a bundled copy alongside: restore skipped, ledger records the hosted URL, `.npmrc` kept, revert lands on hosted; 8.19.4 / 12.2.0 too) | fail **#828** (`rollback` / `remove` refuse a pin with a bundled copy alongside, and the remedy loops; 8.19.4 / 12.2.0 too). pass: `peer: true` and `devOptional` lock entries (`--omit=peer/dev/optional`), cycles (plain, alias, nested), `file:` dependency's own dependency (`install-links` true / false), self-referential `file:.` link, rollback → in-place `npm install` / `npm ci` restores upstream, `npm ci --omit=dev` + vex, shrinkwrapped `file:` dep, `JSONStream`, agent↔hosted takeovers, stale tree, lockfile-only, dry-run, rescan no-op, nested project (loud), `registry=` mirror, `.npmrc` variants, `overrides` (incl. `$ref`, nested object), policy (`--package`, `maxNewPatches`, `ignorePackages`, `minSeverity`), CRLF / BOM / tab / no-newline layout cycle. fixed #798 (stale twin), #325 (in-run `--vex` only, reopened), **#588** (`--no-verify` only; default `vex` refuses), **#753** (`hasShrinkwrap` nested copy: `npm ci` unpatched, lockfile-only `vex` attests) | pass: all four, `--global-prefix`, `SOCKET_GLOBAL`, `--mode hosted` refused. fail #464 (report-only hint has no `-g`) |
| Linux | 11.20 / 11.21 / 11.6.2 | pass (v4); linked `.store` scoped transitive (11.21, #359 fixed). fail #403 (v4) | pass (v4). #490 (11.21; closed by #491, not re-checked). fail **#753** (11.6.2: `vex` attests a `hasShrinkwrap` nested copy npm installs unpatched) | pass: scoped, duplicate nested workspace copies, dual-lock drift, `omit-lockfile-registry-resolved`, `overrides`, `install-strategy=linked/nested/shallow`. fail **#753** (11.6.2) | pass: all four (11.6.2, custom prefix) |
| Linux | 12.1 / 12.2.0 | fail #356, **#554** (12.2.0), **#732** (12.2.0). `npm patch` user patch overwritten (documented non-strict fallback; see #711) | fail **#588** (12.2.0), **#665**, **#688** (12.2.0 / Node 24). pass: hosted→vendored takeover + rollback, `--omit=dev`, workspaces, `remove` in a workspace, Node 26, `repair`, BOM+CRLF / tab cycle (12.2.0), `install-strategy=linked`, `overrides`. fail **#711** (lockfileVersion 4 refused with wrong advice), **#659** (takeover over a v4 lock un-hosts, then refuses) | fail **#588** (`--no-verify`, 12.2.0). Fixed: #798 (stale package-lock twin; `vex` refuses since #799). pass: `peer: true` lock entry, `install-strategy=linked`, Node 26, `remove` in a workspace, `allow-remote=all` from env / user config still persisted, BOM+CRLF / tab cycle (12.2.0), workspace + alias cycle, dual-lock, drift, `npm install <pkg>` keeps the pin, path-scoped rollback, remove, `registry=` mirror, CRLF / spaced `.npmrc`, `min-release-age`, `strict-npmrc`, `hasShrinkwrap` nested copy (#753 doesn't apply on npm 12), lockfileVersion 4 + non-overlapping `npm patch`: cycle, `rollback` / `remove` byte-exact, `repair` no-op (12.2.0). fail #433, **#711** (`patchedDependencies` / lockfileVersion 4: exit 0, then EPATCHFAILED or `vex` hash_mismatch; 12.1.0 + 12.2.0) | pass: all four |
| macOS | 10.9.7 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| macOS | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| Windows | 10.9.7 | pass: linked `.store` apply/vex/rollback (main). fail #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** (default and custom prefix; `--global-prefix` works) |
| Windows | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** |
| Windows 2022 | 10.9.7 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main) | pass: cycle + `--omit=dev`, revert (main) | pass: linked cycle (probe) | **fail #434** |

## npm config that rewrites hosted pins (#812)

`replace-registry-host=always` (npm ≥ 8) rewrites the hosted pin's origin to the configured registry, so `npm ci` / `npm install` fail E404. The hosted scan exits 0 with no warning. **fail #812** on Linux npm 8.19.4 / 10.9.4 / 12.2.0 (project `.npmrc`, env, and user `.npmrc` via `NPM_CONFIG_USERCONFIG`). A warm npm cache masks it; test with `npm ci --cache <fresh>`. A hostname value that isn't the hosted origin passes. Vendored isn't affected; npm 6 / 7 don't have the setting.

Other 2026-10-05 passes (Linux): prerelease version (`ms@3.0.0-canary.1`) hosted / vendored / agent cycles (npm 10.9.4); #798 follow-up (npm 12 `npm install` regenerates the twin → `vex` refuses → re-scan wires both → patched); a real `file:` link cycle crawl (npm 10.9.4).

## Vendored v2 lock after `npm install` (#879, regression from #813)

npm 7–10 `npm install` on a lockfileVersion 2 lock drops `resolved` from `file:` mirror nodes. Since f023506 (#813), vendored `vex` and `vendor --check` exit 1 on that lock although the tree is patched and npm 6 fails closed. **fail #879** on Linux npm 7.24.2 / 8.19.4 / 10.9.4 (plain and alias). Hosted passes. `1714299` passes. #432 fix itself: hosted alias (npm 6 fails closed EINTEGRITY, npm 8 patched) and vendored alias (npm 6 / 8 patched, revert byte-exact) pass on `c644ab0`.

## Agent writes through links (#626)

Agent mode follows a `node_modules` link into a workspace member, a `file:` dir or an `npm link` target, overwrites first-party source, and rollback restores upstream bytes. **fail #626** on Linux npm 6 (`file:`) / 8 / 10 / 12, macOS npm 10.9.7, and Windows npm 8 / 10 / 12, also on v4.0.0. Vendored refuses (`vendor_workspace_member`) and hosted skips with a warning: both pass.

## Alias under `install-strategy=linked` (#852)

npm 9–11 store an alias as `node_modules/.store/lp@<v>-<h>/node_modules/lp`. Agent mode misses that copy. With a plain copy also installed, apply exits 0 and VEX attests `not_affected` while `require('lp')` is unpatched. **fail #852** on Linux npm 9.9.4 / 10.9.4 / 11.6.2. npm 12.2.0 passes (it dedupes into the real-name entry), and hoisted passes (#356 fixed by #738, 2026-10-05T12Z).

## Vendored artifact under `.gitignore` (#831, yarn-classic's issue)

`*.tgz`, `vendor/` and `.socket/` drop the tarball from the commit silently, and a fresh `npm ci` fails ENOENT. With `.socket/` ignored, `vendor --check` exits 0. **fail #831** on Linux npm 8.19.4 / 10.9.4 / 12.2.0 (matrix on #831; draft fix #837).

## npm 12 ignores npm-shrinkwrap.json (#899)

npm 12.0.0 / 12.1.0 / 12.2.0 don't read a root `npm-shrinkwrap.json` (npm's own docs). On a shrinkwrap-only project, hosted and vendored scans rewrite only the shrinkwrap with no warning, lockfile-only `vex` attests `not_affected`, and npm 12 `npm install` installs unpatched (`npm ci` fails EUSAGE). **fail #899** on Linux (shrinkwrap v2 from npm 8, v3 from npm 10). npm 8 / 10 consumers: pass. After the npm 12 install, `vex` refuses (the #799 twin rule): pass.

## Workspace member hosted scan (#884)

A hosted `scan` / `get <uuid>` run from an npm workspace member exits 0 with `redirected: 0` and `redirect_npm_no_lockfile`, and the root lock is untouched. **fail #884** (commented) on Linux npm 7.24.2 / 8.19.4 / 10.9.4 / 12.2.0, non-hoisted and hoisted (`get`). Vendored from the member exits 1: pass (fails closed).

## Vendored refusal diagnostics (#898, #900)

- A symlinked `package-lock.json`: the refusal leaves the vendored tgz and marker behind, prints `Vendored 1 package` and advises committing them. **fail #898** on Linux npm 8 / 10 / 12.
- `package-lock.json` + `yarn.lock` (vendored wires `yarn.lock`): `vendor --check` falsely says no lock references the artifact, and its remedies are no-ops. **fail #900** on Linux npm 10 + yarn 1.22.22.
- #879 also covers npm 12 `npm install` on an existing v2 lock (keeps v2, drops mirror `resolved`) and an npm 8 v2 shrinkwrap (commented 2026-10-06).

## Superseding patch unavailable / withdrawn (2026-10-06T18Z, main `9c43dfc`)

Mock: left-pad@1.3.0 at patch A, then the API changes. Linux npm 8.19.4 (v2) / 10.9.4 / 12.2.0 (Node 24.21).
- B free but its reference is `pending_build` / `build_failed` / `not_found`: hosted **pass** (keeps A, `redirect.skipped[]`, exit 0). Vendored **fail #954** (exit 1 `partial_failure` "Failed to vendor … 1 failed" on every re-scan, while A stays vendored, `vendor --check` passes, cold `npm ci` installs A, `vex` attests).
- B paid + `forbidden` (no paid access), A no longer offered: hosted and vendored **pass** (keep A, exit 0; `updates[]` still advertises B).
- A withdrawn (nothing offered, reference `withdrawn`): hosted / vendored **pass** (pin kept, exit 0). Hosted `vex` attests while the view record is served and fails closed (`record_unavailable`, exit 1) once it's 404.
- Agent: B offered but its view record 404s → `scan --mode agent` exits 1 "could not fetch details" every run, A stays applied. Needs an inconsistent API (offer without record); noted, not filed.

## Patch superseding (2026-10-06T12Z, main `9c43dfc`)

The same `name@version` gets a new patch UUID with different bytes. Mock: left-pad@1.3.0 A→B, cold-cache `npm ci`.
- Same-mode re-scan: hosted / vendored on npm 8.19.4 / 10.9.4 / 12.2.0 (plain + alias), agent on 10.9.4: **pass** (`updates[]`, the lock re-pinned in every node, the old artifact GC'd, `npm ci` installs B, `vex` attests B, rollback byte-exact).
- Cross-mode: hosted→vendored, vendored→hosted, agent→vendored **pass**. hosted→agent and vendored→agent keep the other mode's wiring (documented; `vex` fails closed or attests A).
- agent→hosted: **fail #933**. Manifest record A survives, so `rollback` exits 1 until a reinstall and `remove` exits 1 with pin B live (npm 8 / 10 / 12, and a v4.0.0 manifest).

## Run 23 passes (Linux, 2026-10-06T06Z, main `9c43dfc`)

- Hosted pins survive `npm dedupe`, `install --package-lock-only`, `install <new dep>` and `prune` on npm 8.19.4 / 10.9.4 / 12.2.0 (plain and scoped alias). Vendored passes on npm 10 / 12. On npm 8 (v2), everything except `dedupe` hits #879.
- Plain in-place `npm install` after a hosted / vendored scan replaces the tree with patched bytes (npm 8 / 10 / 12).
- Hosted alias `rollback` (v2 mirror `lp` node, scoped alias) is byte-exact on npm 6 / 8 / 10 / 12.
- A hosted v1 lock (npm 6) installs patched bytes under npm 8 / 10 / 12 via both `ci` and `install`.
- `bin` linking (semver@7.6.0, plain + alias), hosted and vendored, npm 8 / 10 / 12.
- Workspace member with a non-hoisted alias (`packages/a/node_modules/lp`), hosted and vendored, npm 8 / 10 / 12: cycle, `vendor --check` and `rollback` pass.
- SIGKILL-interrupted hosted / vendored scans (0.02–0.3 s) recover on re-scan, and `rollback` is byte-exact. Kills inside the narrow write window weren't tested (blocked by the session permission classifier).

## Backlog

- **New 2026-10-06T18Z:** #954 follow-ups (other vendored PMs → handover if confirmed: pnpm / yarn / bun share `ServiceFetch::settle`; `--max-new-patches` with an unavailable UPGRADE; `get <B> --mode vendored` wording). (Withdrawn / forbidden superseding: done 18Z, pass.)
- **New 2026-10-06T12Z:** #933 follow-ups (path-scoped `rollback <purl>`, agent re-scan after the takeover, other PMs → handover); Interrupted runs inside the write window.
- (Patch superseding done 2026-10-06T12Z: pass except agent→hosted, #933.)
- (Hosted alias `rollback` of the v2 mirror `lp` node: done 2026-10-06T06Z, pass.)
- **New 2026-10-06:** #899 follow-ups (dual lock without a twin, workspace shrinkwrap); #898 on other group-commit refusals (`vendor_commit_failed`, a symlinked `.npmrc`); Bun handover #2 (a `bun.lock` + stale `package-lock.json` with no entry for the package: `contest_across_locks` ignores it), not filed because of the cap and Bun being primary.
- (#879 npm 12 / shrinkwrap v2 follow-ups done 2026-10-06T00Z: both affected, commented.)

- **#879 follow-ups:** workspaces.
- (#852 and #812 re-checked on `c644ab0` 2026-10-05T18Z: both still reproduce.)

- **#852 follow-ups:** agent `rollback` over the alias store copy; a scoped alias; a transitive alias in `.store`.
- **#732 fix re-check** (human `scan --mode agent` after `npm ci`): needs a mock API, because `--offline` scan is refused. Also re-check #828 on main `4646693`.
- (#688 and #432 re-checked on `4646693`: both still reproduce, 2026-10-05T12Z.)

- **#828 follow-ups:** `get --mode vendored` takeover; the real `npm` bundle (`ansi-regex`) shape; a dual lock where only one lock carries the bundle; other `ContestedWiring` shapes (#798 stale twin) reaching the vendored takeover silently.
- **#812 variants:** global npmrc; a `registry=` mirror + `always`. macOS / Windows once probe branches are allowed again. (User `.npmrc` and hostname value done 2026-10-05T06Z.)
- (#798 re-scan follow-up done 2026-10-05T00Z: pass. Re-check when #799 lands.)
- (#753 follow-ups done 2026-10-04T12Z: npm 12 `npm install` pass, workspace member same as #753 on 10/11 and pass on 12, agent mode pass, hosted→vendored takeover on npm 12 pass.)
- (Bun handover done 2026-10-04T12Z: after hosted `rollback` / `vendor --revert`, `npm install` and `npm ci` restore upstream bytes on npm 7/10/11/12.)
- (Done 2026-10-04T18Z: npm 9.2.0 `install-links` `file:` cycle, `peer: true` / `devOptional` pins: all pass.)
- **#798 follow-ups:** a workspace member present only in the shrinkwrap; after npm 12 `npm install` regenerates the twin, does a re-scan wire both? Re-check #725 / #798 on npm when #730 lands.
- (#732 mixed run done 2026-10-04T06Z: a new patch re-applies all entries. #732 only bites when nothing is new.)
- **#711 (npm 12 native `npm patch`, lockfileVersion 4) follow-ups:** nested / workspace patched copies; agent `--strict`. `rollback` / `remove` / `repair` on v4 locks passed (2026-10-04).
0. **#659 / #688 class:** other npm per-package gates reached after the takeover restore: bundled-only, link-only and non-registry-only entries (`vendor_lock_entry_not_rewritable`) over a hosted pin; a real workspace member forked under the same name@version. Dual lock and alias passed (2026-10-03T12Z). A differing shrinkwrap/package-lock pair: #798 (2026-10-04T18Z).
1. **#687 on Windows / macOS** (a failed eject rewriting root files; on Windows a rename over a shell-held redirect target may fail with `eject_rollback_failed`). Needs a probe branch that can be deleted.
2. **#626 follow-ups** (after draft PR #634): `apply --check` / `repair` over a link; a byte-identical fork (patched silently); a nested member's `node_modules` reached through a link.
3. **#588 follow-ups** (PR #589): an unwired same-lock copy under `install-strategy=linked` and across a shrinkwrap/package-lock pair; whether `vendor --check` should flag it.
4. **Re-checks on the next main change:** #325, #433, #432, #464, #490 (override over URL / `file:` transitive deps on npm 8–12), #665 (npm matrix in the comment).
5. **#554 follow-ups:** agent `rollback` / `vex` with path policy over nested projects.
6. **#356:** alias-only agent `scan` now exits 0 with nothing applied (since #555). Watch for a fix.
7. **Maintainer request (global `-g`), still open:** Linux npm 7/8/11 passed 2026-10-04T06Z. Still to do: npm 6/8/11 on macOS and Windows; an unwritable prefix (root-owned / `Program Files`); nvm, volta, fnm and Homebrew prefixes on macOS; `%APPDATA%\npm` now that #434 is closed. Full checklist in the 20261001T040000Z entry.
8. Stale probe branches the proxy can't delete (2026-10-04T06Z: the session permission policy now refuses `git push --delete` outright, so no new probe branches are pushed until a maintainer allows it or deletes these) (`git push --delete` fails with "remote end hung up" / "Everything up-to-date"; re-checked 2026-10-03T12Z): `bughunt/npm/20260930-alias-linked`, `20260930-win-mac-e2e`, `20260930-win-old-npm`, `20261001-crlf-paths`, `20261001-optional-dep`, `20261001-v5-hosted-global`, `20261001-win-global`, `20261002-v5-agent-vendored-winmac`, `20261003-ws-link-agent`, `20261003-ws-link-mac`. A maintainer needs to delete them.

## Known non-bugs

- A withdrawn patch (nothing offered, reference `withdrawn`) keeps its hosted / vendored pin and exits 0; hosted `vex` keeps attesting while the API still serves the record. No documented contract says a withdrawal should un-pin.
- A paid superseding patch without paid access: the scan keeps A and still lists A→B in `updates[]` (informational).

- npm 6 `npm ci` that fails EINTEGRITY on a hosted alias pin (#813's fail-closed path) leaves the unpatched registry bytes extracted in `node_modules`. That's npm's partial-install behaviour (exit 1), and `vex` refuses that tree (`not_applied`).
- Mock tip (2026-10-05T18Z): the org-scoped routes (`--api-url … --org o --api-token fake`) need only batch, by-package, `patches/package`, view and blob, and one granted tarball response serves both hosted and vendored.

- Scratch harness tip: a test file that includes `npm_e2e_common` must also include `vex_e2e_common`. `scan` refuses `--offline` (strict airgap), so use `apply` for offline agent cells.

- Mocks of the public proxy need `SOCKET_PROXY_URL` (and `NO_PROXY=127.0.0.1`); `--api-url` alone still reaches `patches-api.socket.dev`.
- Project `.npmrc` `allow-remote=${VAR}` is read raw and treated as an explicit user value (warns, doesn't write). Fails safe.
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
- npm 6 on a hosted lockfileVersion 1 lock: with a cold cache it fails closed with EINTEGRITY, as npm-compatibility.md documents (re-measured 2026-10-06T12Z). An earlier note said it installs the patched bytes; that was a warm-cache artifact.
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
- Mock tip: `SOCKET_NPM_REGISTRY` hosted rollback fetches `<registry>/<name>/<version>`, so serve a version doc with a top-level `dist`, not a packument.
- (Retired 2026-10-03T12Z: npm vendored `scan --prune` / `vendor --revert` / `remove` keeping an entry whose lock entry vanished after `npm uninstall` is now tracked as a bug in #665.)
- `package-lock=false` in `.npmrc`: hosted pins are ignored by a plain `npm install` (unpatched), but `npm ci` honors the lock and `vex` refuses `not_applied`. Fails closed; the user's config choice.
- A symlinked `.npmrc` isn't written through (hosted warns that `allow-remote` must be set). A symlinked lock is refused `redirect_symlinked_file_unsupported`.
- Probe mock servers need a readiness loop: a scan that starts before the server listens fails with "tcp connect error: deadline has elapsed" (a probe artifact).
- Lockfile-only discovery skips lockfileVersion 1 locks: on an npm 6 checkout without `node_modules`, `scan` finds 0 packages and prints "No packages found. Run your package manager's install first." (exit 0). The code calls this documented (`vendor/lock_inventory/npm.rs:168`), though the user docs don't say it. It's loud, and installing first works. Not filed.
- A hosted-appended `allow-remote=all` line in a pre-existing `.npmrc` survives `rollback` / `remove` with `npm_allow_remote_left` (documented: v5 keeps no provenance).
- v5 vendoring downloads prebuilt artifacts from `POST …/patches/package`. `--vendor-source build` was removed, and `vendor --offline` over a hand-staged `.socket/` refuses `vendor_service_offline_conflict`. Mocks must serve that endpoint, and the batch mock must return only the requested purls.
- `vex --json` without `--output` exits 2 with `json_requires_output` (documented).
- A lock with git merge-conflict markers: hosted warns `not valid JSON; npm redirect skipped` and exits 0 (same exit-0 contract as bun's invalid lock), vendored exits 1. Loud; not filed.
- `scan --sync` GC deletes a recorded patch's before-blob (`.socket/blobs/<beforeHash>`). That's by design: rollback downloads the before-blob on demand.
- Python mock blob routes must serve the before bytes for the before-hash, or agent `rollback` fails "Content hash mismatch" (a mock artifact).
- npm 12 needs Node ^22.22.2 / ^24.15 / ≥26; the sandbox's Node 22.22.0 is too old. Install `node@24` from npm into a scratch prefix.
- `rollback` / `remove` delete a user-authored project `.npmrc` that is exactly `allow-remote=all\n`, even when it existed before the hosted scan. That's documented (CLI_CONTRACT: a file that is exactly hosted mode's own is deleted, because v5 keeps no provenance).
- npm 12.2.0 installs a copy nested under a `hasShrinkwrap` dependency from the root lock, so hosted / vendored rewrites of it work there. #753 covers npm 6–11 only.
- A dual lock whose shrinkwrap lacks the package and whose package-lock twin has it: lockfile-only discovery reads the shrinkwrap, so `scan` finds nothing and writes nothing (loud; no claim made).
- The sandbox sets `NPM_CONFIG_USERCONFIG=/root/.npmrc`, so a scratch `$HOME/.npmrc` is ignored unless you repoint that variable (a harness artifact).
- `vex -o` is `--org`; the output flag is `-O` / `--output`.
- `vendor --check` verifying only the artifact (not the lock wiring) for npm is tracked in #725 (generic root cause, draft fix #730). Don't re-file it per npm shape.
- npm 12 `npm ci` on a shrinkwrap-only project fails EUSAGE (npm 12 reads only package-lock.json). That's npm behaviour; the socket-patch side is #899.
- A vendored `package-lock.json` symlink refusal: re-running after replacing the link with a regular file reuses the orphan artifact and works (#898 covers the orphan itself).
