[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-10-29T01Z (run 53), main `ecd4924` (v5.0.1 `latest`). #1792 merged and closed #1791 (verified: a v5.0.1-broken bin recovers on `apply`, and `rollback` is byte-exact). Run 53 filed #1804, a regression from #1792: with `bin-links=false` or a non-registry `directories.bin`-only package, npm keeps the CRLF shebang, but main writes the LF form, so rollback isn't byte-exact. **Open npm bughunt issues: #1782 and #1804.** Every issue number marked `fail` in the matrix below other than these two is closed; those marks are historical. Probe branches remain blocked (`git push --delete` refused).
## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Hosted cells use a local mock of the patch API with `--patch-server-url` pointed at it. Agent and vendored cells use the same mock or a hand-staged `.socket/`. "Cycle" means scan → fresh `npm ci` → `vex` → `rollback` byte-exact. "Suites" means `e2e_redirect_npm_build` + `e2e_vendor_npm_build` with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`.

| OS | npm | Agent (apply / scan --mode agent) | Vendored | Hosted (v5 default) | Global `-g` (scan report / get+apply / vex / rollback) |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (v4), **#732** (human `scan --mode agent` re-scan after `npm ci` leaves files unpatched). pass: `-g` (v4) | pass: nested v2 lock (v4). v1 lock refused loudly (documented). fixed #432 (alias mirror; regression follow-up #879), **#659** (hosted→vendored takeover via `scan`/`get` on a v1 lock un-hosts, then refuses; `vendor` eject rolls back) | pass: v1-lock hosted scan on v5 main `9ab72d4` (EINTEGRITY warning, npm 6 `npm ci` fails closed, npm 10 `npm ci` patched incl. alias, `vex`, byte-exact rollback), shrinkwrap-only v1 cycle. v1 alias: not wired (#432) | pass (v4) |
| Linux | 7.0.15 / 7.24.2 | pass: scan/apply, vex, `npm ci` → vex refuses, re-apply, rollback | pass: cycle + `--omit=dev`, workspaces, vendored↔hosted takeover, revert byte-exact | pass: cycle (alias, nested, dev), workspaces, takeovers. fail **#753** (copy nested under a `hasShrinkwrap` dep installs unpatched) | pass: all four (7.24.2, custom prefix) |
| Linux | 8.19.4 | fail #356 (v4). #403 / #516 closed by fixes | fixed #432 (see #879), **#588** (same-lock unwired copy), **#665**, **#688**. pass: alias takeover, cycle + `--omit=dev`, workspaces, takeovers, rescan no-op | pass: `peer: true` lock-entry cycle, nested v2 cycle, shrinkwrap-only, workspaces, takeovers, rescan no-op, `overrides` (flat, alias, nested). fixed #432 (alias mirror, npm 6 consumer), #490 (override over a git spec; closed by #491, not re-checked), **#588** (`--no-verify`), **#753** (`hasShrinkwrap` nested copy) | pass: all four (custom prefix) |
| Linux | 9.2.0 / 9.9.4 | pass: 9.2.0 `install-links=true` `file:` dir dep cycle; `-g` (v4); Node 18 cycle | pass: 9.2.0 `install-links` `file:` dep cycle, cycle + `--omit=dev` (main), Node 18 cycle | pass: 9.2.0 `install-links` `file:` dep cycle, cycle (alias, nested, dev), Node 18 cycle. fail **#753** | pass (v4) |
| Linux | 10.9.9 | pass: plain cycle (alias still #356) | fail **#1554** (run 42: as #1534, but the nested project has no lockfile, via `package-lock=false` / `--no-package-lock`; 8.19.4 / 10.9.4 / 12.2.0). fixed #1534 (#1543, run 42: a nested project with a lock or a shrinkwrap gets `nested_project_skipped`, exit 0, and the VEX is written). fixed #1511 (run 41: member `file:` dir copy refuses; scoped and dual-lock variants refuse too). Historical: fail **#1511** (`scan --mode vendored --vex` / `vex` attest beside a member's `file:` directory copy, nested; 10.9.4 / 11.6.2 / 12.2.0). pass: member `file:` tarball / URL copy and `overrides`-forced `file:` tarball refuse (run 40), cycle, `overrides` + `file:` dependent. fail **#1155** (10.9.4 / 8.19.4 / 12.2.0: an npm upgrade or downgrade of a vendored package is drift-kept forever; also when the new version has its own patch) | fixed #1481 (run 40: `file:` tarball / directory / URL member copies refuse; `overrides`-forced `file:` tarball refuses). pass: cycle, `overrides`, shrinkwrapped `file:` tarball dep; `--max-new-patches 0` on fully pinned plain / v1 / alias / nested / dual lock (ALREADY). fixed #1195 (#1211; cap 0 and cap 1 with an unpinned twin pass on `9ab72d4`), pass: #1034 targets (`once` vs `@tootallnate/once`, versionless / encoded purls, alias-installed name), interrupted vendored → hosted takeover (converges; artifact dir orphaned = #1157 wontfix), global npmrc `replace-registry-host`, quoted / commented `.npmrc` values, **#1196** (CRLF `.npmrc` without a final newline) | pass (10.9.4, run 38): `--global-prefix` report-only scan, `scan --mode agent`, `rollback` |
| Linux | 10.8.2 (Node 18) / 10.9.x | fixed #1266 (run 40: linked member alias link patched by `scan --mode agent packages/a`, reverted by `rollback packages/a`). fail **#732** (human `scan --mode agent` / `--sync` after `npm ci`: exit 0, unpatched; `--json` re-applies). pass: Node 18 cycle. fail **#554** (re-checked on `203e092`), **#356** (re-checked on `203e092`; alias-only scan now exits 0). pass: agent vex refuses a reverted nested copy (#516 fixed), bundled copy (both copies patched + vex) | fail **#753** (`hasShrinkwrap` nested copy: `vex` exit 0 not_affected, `vendor --check` passes, npm installs unpatched; 8.19.4 too). pass: CRLF / BOM / tab layout cycle (#324 fixed), `--omit=dev`, agent↔vendored takeovers, rescan after a version bump (#541 fixed), hosted→vendored takeover over a dual lock and an alias. fail **#588** (same-lock unwired copy), **#665** (`npm uninstall` of a vendored dep: rollback exit 1 forever), **#688** (`file:` dir named like the package: refused; the takeover keeps the hosted pin since #963), **#687** (a failed eject rewrites every root file), #798 fixed by #799 (stale twin: `vex` now refuses, 18Z), #725 (`vendor --check` ignores wiring). pass: `peer: true` lock entry. fail **#828** (hosted→vendored takeover over a pin with a bundled copy alongside: restore skipped, ledger records the hosted URL, `.npmrc` kept, revert lands on hosted; 8.19.4 / 12.2.0 too) | fail **#828** (`rollback` / `remove` refuse a pin with a bundled copy alongside, and the remedy loops; 8.19.4 / 12.2.0 too). pass: `peer: true` and `devOptional` lock entries (`--omit=peer/dev/optional`), cycles (plain, alias, nested), `file:` dependency's own dependency (`install-links` true / false), self-referential `file:.` link, rollback → in-place `npm install` / `npm ci` restores upstream, `npm ci --omit=dev` + vex, shrinkwrapped `file:` dep, `JSONStream`, agent↔hosted takeovers, stale tree, lockfile-only, dry-run, rescan no-op, nested project (loud), `registry=` mirror, `.npmrc` variants, `overrides` (incl. `$ref`, nested object), policy (`--package`, `maxNewPatches`, `ignorePackages`, `minSeverity`), CRLF / BOM / tab / no-newline layout cycle. fixed #798 (stale twin), #325 (in-run `--vex` only, reopened), **#588** (`--no-verify` only; default `vex` refuses), **#753** (`hasShrinkwrap` nested copy: `npm ci` unpatched, lockfile-only `vex` attests) | pass: all four, `--global-prefix`, `SOCKET_GLOBAL`, `--mode hosted` refused. fail #464 (report-only hint has no `-g`) |
| Linux | 11.20 / 11.21 / 11.6.2 | pass (v4); linked `.store` scoped transitive (11.21, #359 fixed). fail #403 (v4) | pass (v4). #490 (11.21; closed by #491, not re-checked). fail **#753** (11.6.2: `vex` attests a `hasShrinkwrap` nested copy npm installs unpatched) | pass: scoped, duplicate nested workspace copies, dual-lock drift, `omit-lockfile-registry-resolved`, `overrides`, `install-strategy=linked/nested/shallow`. fail **#753** (11.6.2) | pass: all four (11.6.2, custom prefix) |
| Linux | 12.2.1 / Node 22.22.0 + 26.12.0 (run 45) | pass: `scan --mode agent` / versionless `get`; mode bits of a `bin` file kept | pass: hoisted / shallow / linked cycle (`npm ci` patched, `vex`), workspaces (`npm ci`, `-w a`, `-w b`), `vendor --revert` after `npm install <new dep>` keeps the new dep, plain `npm install` over a stale tree installs the patched bytes. fail **#1595** (`allowScripts` pin, hoisted + linked) | pass: the same cycles, `rollback` after `npm install <new dep>`, suites (36 + 43 tests). fail **#1595** (hoisted + linked) | pass: all four (12.2.1 / Node 24.22.0, custom prefix without a UUID segment, run 48) |
| Linux | 8.19.4 / 10.9.4 / 12.2.1, workspace member dir named `build` / `dist` / `vendor/*` (run 47) | fail **#1627** (member copy unpatched; `apply --check` in sync; `vex` not_affected). Control `packages/lib`: pass | pass (10.9.4, run 48: `packages/build` copy pinned, `npm ci` patched, `vex` and `vendor --check` pass) | pass (10.9.4, run 48: same) | n/a |
| Linux | 8.19.4 / 10.9.4 / 11.6.2 / 12.2.1, root `bundleDependencies` (run 46) | pass (patched, `vex` attests) | fail **#1618** (exit 1, 8.19.4 / 12.2.1) | fail **#1618** (skipped, unpatched; v2 lock half-wired). npm 6.14.18 v1: pass | untested |
| Linux | 12.0.0 / 12.1.0 / 12.2.0 (run 44) | n/a | fail **#1595** (`allowScripts` `pkg@ver` pin blocked after vendoring; strict → `npm ci` exit 1) | fail **#1595** (same, hosted) | untested |
| Linux | 12.1 / 12.2.0 | fail **#1576** (run 43: the v4 refusal's "remove `patchedDependencies` + `npm install`" remedy loops; npm keeps v4; 12.1.0 / 12.2.0). pass (run 43): #1541 LFS `*.tgz` repo (fresh vendor, legacy attrs upgrade, `--renormalize`). fail **#1266** (12.2.0). pass: hosted alias cycle, linked workspace vendored cycle (`a80b89e`). fail #356, **#554** (12.2.0), **#732** (12.2.0). `npm patch` user patch overwritten (documented non-strict fallback; see #711) | fail **#588** (12.2.0), **#665**, **#688** (12.2.0 / Node 24). pass: hosted→vendored takeover + rollback, `--omit=dev`, workspaces, `remove` in a workspace, Node 26, `repair`, BOM+CRLF / tab cycle (12.2.0), `install-strategy=linked`, `overrides`. fail **#711** (lockfileVersion 4 refused with wrong advice), **#659** (takeover over a v4 lock un-hosts, then refuses) | fail **#1511** (vendored `file:` directory member copy, nested, 12.2.0). Fixed #1481. fail **#588** (`--no-verify`, 12.2.0). Fixed: #798 (stale package-lock twin; `vex` refuses since #799). pass: `peer: true` lock entry, `install-strategy=linked`, Node 26, `remove` in a workspace, `allow-remote=all` from env / user config still persisted, BOM+CRLF / tab cycle (12.2.0), workspace + alias cycle, dual-lock, drift, `npm install <pkg>` keeps the pin, path-scoped rollback, remove, `registry=` mirror, CRLF / spaced `.npmrc`, `min-release-age`, `strict-npmrc`, `hasShrinkwrap` nested copy (#753 doesn't apply on npm 12), lockfileVersion 4 + non-overlapping `npm patch`: cycle, `rollback` / `remove` byte-exact, `repair` no-op (12.2.0). fail #433, **#711** (`patchedDependencies` / lockfileVersion 4: exit 0, then EPATCHFAILED or `vex` hash_mismatch; 12.1.0 + 12.2.0) | pass: all four |
| macOS | 10.9.7 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| macOS | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main, #359 fixed). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | pass: all four (custom prefix) |
| Windows | 10.9.7 | pass: linked `.store` apply/vex/rollback (main). fail #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** (default and custom prefix; `--global-prefix` works) |
| Windows | 12.1.0 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main). fail #356, #403 (v4) | pass: cycle + `--omit=dev`, revert (main) | pass: cycle, linked cycle (probe) | **fail #434** |
| Windows 2022 | 10.9.7 / 12.2.0 | pass: linked `.store` apply/vex/rollback (main) | pass: cycle + `--omit=dev`, revert (main) | pass: linked cycle (probe) | **fail #434** |
| Linux | 6.14.18 / 8.19.4 / 10.9.4 / 12.2.1, `bin` file published with a CRLF shebang (run 49; re-run 52) | fixed #1756 on `b4b6d98`, pass: fresh apply / re-apply / `vex` / `apply --check` / `repair` / byte-exact `rollback` on 6.14.18, 10.9.4, 12.2.1 linked. **fail #1791**: a tree v5.0.1 already overwrote stays at bin exit 127 after main `apply` / `repair` / `rollback` (10.9.4) | fixed #1756 (not re-run with the mock in run 52) | fixed #1756 (not re-run with the mock in run 52) | untested |
| Linux | 6.14.18 / 8.19.4 / 10.9.4 / 12.2.1, #1648 eject (plain `vendor` over hosted pins, fresh checkout) (run 49) | n/a | pass: v3 plain + nested, dual lock, alias, workspace member copy (10.9.4), v2 lock (8.19.4), plain (12.2.1); `npm ci` patched, `vex`, `vendor --check`, byte-exact `--revert`; `registry=` mirror; allowScripts warning kept. v1 lock (6.14.18): `eject_refused`, nothing changed (documented) | n/a | n/a |
| Linux | 12.2.1 `npm patch` (lockfileVersion 4) + #1646 consent (run 49) | pass (user-patched copy skipped, the other version patched) | pass (v4 lock refused, documented; the eject refuses `user_patch_conflict`) | pass (user-patched copy skipped, `rollback` keeps a working user patch, `vex` omits the double-patched copy) | untested |
| Linux | 8.19.4 / 10.9.4 / 12.2.1, #1648 eject shapes (run 50) | n/a | pass: hosted pins under `overrides` (v3 on 10.9.4, v2 on 8.19.4), `install-strategy=linked` (10.9.4), scoped + aliased `@tootallnate/once` (10.9.4), workspace with a nested member copy (12.2.1); each through `npm ci` patched, `vex`, `vendor --check`, and a byte-exact `vendor --revert`. `vendor --dry-run` writes nothing; `vendor --ecosystems pypi` leaves npm pins alone; a SIGINT / SIGKILL during the download leaves the tree clean and the re-run converges | n/a | n/a |
| Linux | 6.14.18 / 10.9.4, patch that adds a file (empty `beforeHash`), incl. a path with a space and `é` (run 50) | pass: apply, `vex`, `vex` refuses when the added file is missing, `apply` re-creates it, `rollback` removes it and its new directory | pass (`npm ci` patched, `vex`, `rollback`) | pass (10.9.4; and npm 6.14.18 v1 lock: `rollback` byte-exact) | untested |
| Linux | 10.9.4, user-patch consent with patch-package 8.0.0 (run 50) | pass: `--patch-dir fixes`, a root `patches/` with a workspace member's dep, and a member-owned `patches/` all skip `user_patch_conflict` | n/a | pass: same three shapes | n/a |
| Linux | 10.9.9 / 11.21.1 suites (run 50) | n/a | pass: `e2e_vendor_npm_build` 43/43 (both) | pass: `e2e_redirect_npm_build` 30/30 plus the 6 `#[ignore]` real-npm legs via `--ignored` (both) | n/a |
| Linux | 6.14.18 / 10.9.4 / 12.2.1, CRLF-shebang bin npm doesn't link (`--no-bin-links`; `directories.bin`-only `file:` tarball) (run 53) | **fail #1804** (main writes the LF `fixBin` form, `rollback` not byte-exact; `--no-bin-links` on all three, `directories.bin` on 10.9.4). `b4b6d98` / v5.0.1 pass | untested | untested | n/a |
| Linux | 10.9.4, v5.0.1-broken CRLF bin upgraded to main (run 53) | pass (#1791 fixed: `apply` rewrites, bin runs, `apply --check`, `vex`, `repair`, byte-exact `rollback`) | n/a | n/a | n/a |

## Run 53 (2026-10-29T01Z, main `ecd4924`)

- Re-triage: #1791 was closed by #1792. Verified on npm 10.9.4 twice: a tree v5.0.1 broke recovers on main `apply` (the bin runs), and `rollback` restores the `npm install` bytes exactly.
- Filed #1804. #1792's `is_listed_bin` writes `fixBin`'s LF form even where npm didn't link the bin and kept the CRLF shebang: `--no-bin-links` (npm 6.14.18 / 10.9.4 / 12.2.1), or a `directories.bin`-only package from a `file:` tarball (10.9.4). `apply` writes non-`afterHash` bytes, and `rollback` isn't byte-exact. First bad commit `6bdd67c`; `b4b6d98` and v5.0.1 pass.
- #1782 not re-checked: the npm eject code is unchanged and the issue is claimed.

## Run 52 (2026-10-28T19Z, main `b4b6d98`)

- Re-triage: #1756 was closed by #1757. Fresh trees pass on npm 6.14.18, 10.9.4 and 12.2.1 with `install-strategy=linked` (apply writes the LF shebang, the bin runs, `vex` attests, and `rollback` restores the bytes `npm install` wrote).
- Filed #1791. A tree that v5.0.1 patched has the raw CRLF `afterHash` bytes, and on main `apply` reports it already patched, `apply --check` reports in sync, `repair` completes, and `rollback` writes the CRLF original, all with the bin still exiting 127. Cause: `npm_bin::form_for_write` picks the form from the on-disk shebang. Reproduced 3 times on npm 10.9.4.
- #1782 not re-checked: no eject change on main since `b787454` (only the pnpm `cleanup_side_config` change in `upstream/npm.rs`), and it's claimed by a fix agent.

## Run 51 (2026-10-28T13Z, main `b787454`)

- Filed #1782. A `vendor` eject that is SIGKILLed, SIGINTed or SIGTERMed between the upstream restore (lock rewritten to the registry, `.npmrc` deleted) and the vendored commit journal leaves the project neither hosted nor vendored. A re-run then says `noManifest`, exit 0. Present in v5.0.1 and on main, npm 10.9.4 and 12.2.1. The `scan --mode vendored` takeover is crash-safe at every rename.
- pass: add-a-file patches on npm 12.2.1 with `install-strategy=linked` (transitive `ms@2.0.0` in `.store`), in agent (apply / vex / `apply --check` / rollback removes the new dir), hosted (`npm ci` installs the added file; `vex` fails safe when it's missing; byte-exact lock rollback) and vendored (`npm ci` / `vex` / `vendor --check` / byte-exact `vendor --revert`).
- pass (not filed): `vendor --revert` killed at each rename (the lock rename is first; a kill before it changes nothing, and after it the revert finishes). Hosted `rollback` killed at its lock rename has already deleted `.npmrc` with the lock still hosted. The re-run converges, but a stray `.socket-stage-package-lock.json-*` stays at the project root (cosmetic, SIGKILL only).

## Run 50 (2026-10-28T07Z, main `b787454`)

- No new issue. Commented on #1756: after `--allow-patch-conflicts` writes the CRLF shebang back, agent `rollback` restores the CRLF `beforeHash` bytes, so the bin still exits 127 (npm 10.9.4, reproduced twice). Draft PR #1757 may not cover a project already overwritten by v5.0.1.
- pass: more #1648 eject shapes, patches that add a file, patch-package consent shapes, concurrent hosted scans (the second waits, then reports "already on hosted patches"), `npm shrinkwrap` after hosted (`rollback` handles the renamed lock). Details are in the run 50 entry.

## Run 49 (2026-10-28T01Z, main `b787454`)

- Filed #1756. npm's `bin-links` `fixBin` rewrites a `#!…\r\n` shebang line to `\n` in installed `bin` files, so the installed bytes match neither patch hash.
  - Agent `apply` fails `apply_failed` on main.
  - With `--allow-patch-conflicts` (and by default on v5.0.1) it writes the CRLF shebang back and the bin exits 127.
  - Hosted `vex` omits a correct install, and vendored `vex` warns `vendored_tree_out_of_sync`.
  - Reproduced on npm 6.14.18 / 8.19.4 / 10.9.4 / 12.2.1. Handed over to pnpm and bun (both rewrite too); yarn classic keeps the CRLF.
- Closed #1072 (fixed by #1739).
- pass: the #1648 eject across v2 / v3 / dual / alias / workspace / npm 12, and #1646 consent with real `npm patch`. Details are in the run 49 entry.

## Run 48 (2026-10-18T00Z, main `7d3086f`)

- No new issue. Commented on #1581 (Bun's issue, same root cause): `repair` of an npm `<uuid>/` dir that was lost entirely restores only the `.tgz`, not `.gitignore` / `.gitattributes` / `socket-patch.vendor.json`. With a `*.tgz` ignore rule, git ignores the repaired tarball, yet `repair` and `vendor --check` both pass. A fresh clone's cold `npm ci` then exits 254 (npm 10.9.4 and 12.2.1, reproduced twice). Commented on #1618: `bundleDependencies: true` and the `bundledDependencies` spelling hit the same skip.
- pass: #1627 hosted and vendored with a `packages/build` member (lock-driven); npm 12.2.1 global `-g` (scan report, `get`, `apply --check`, `vex`, `rollback`); mixed-case `JSONStream` agent and vendored cycle; prerelease `ms@3.0.0-canary.1` in all three modes; agent over a symlinked project `node_modules`; agent keeps a 0444 file mode; vendored `repair` of a missing tarball (byte-identical); npm 12.2.1 `npm install <pkg>` with an unreachable hosted URL fails loudly and keeps the pin.
- Re-triage skipped (npm code unchanged).

## Run 47 (2026-10-17T12Z, main `657fce2`)

- Filed #1627. `npm_crawler.rs` `SKIP_DIRS` prunes `build`, `dist`, `vendor`, `tmp`, `temp` and `coverage` even when the root `workspaces` field declares them as members. A member's nested (unhoisted) copy is never crawled: `apply` reports `1 of 1 applied, 0 not found`, `apply --check` says in sync, `vex` attests not_affected, and Node resolves the unpatched copy. npm 8.19.4 / 10.9.4 / 12.2.1 (Node 24); v5.0.1 is the same. Hosted / vendored untested (lock-driven).
- Re-triage skipped (main unchanged).

## Run 46 (2026-10-17T00Z, main `657fce2`)

- Filed #1618. npm 7+ flags the root's own `bundleDependencies` (and their transitive deps) `inBundle: true`. Hosted skips them (`redirect_npm_bundled_instance_skipped`, exit 0, unpatched, `vex` omits); vendored fails them (`vendor_lock_entry_not_rewritable`, exit 1 forever). `npm ci` installs a hand-rewired entry patched (8.19.4 / 10.9.4 / 12.2.1). npm 6 v1 passes. v5.0.1 is the same.
- pass: unicode + space + `#` path three-mode cycle (12.2.1); BOM `.npmrc` `allow-remote=none` respected; scoped VEX product purl.
- Re-triage skipped (main unchanged).

## Run 45 (2026-10-16T12Z, main `657fce2`)

- New npm **12.2.1** (`next-12`, arborist 10.0.4, which changes `script-allowed.js` for linked-store targets): `e2e_redirect_npm_build` (36) and `e2e_vendor_npm_build` (43) pass with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`. Hosted and vendored cycles pass under `install-strategy=hoisted|shallow|linked`, on Node 22.22.0 and Node 26.12.0. #1595 still reproduces on 12.2.1, hoisted and linked (comment posted). Name-only `allowScripts` keys still run under linked.
- pass: workspaces (`npm ci`, `npm ci -w a|b`, `vex`); `npm ls` / `prune` / `rebuild` / `install` keep the pins; plain `npm install` over a stale, unpatched tree swaps in the patched bytes, and the hidden lockfile carries the pins; `vendor --revert` / hosted `rollback` after `npm install is-number` keep the new dep; versionless `get pkg:npm/ms` and `get ms` narrow to the installed versions in all three modes (an uninstalled 9.9.9 is skipped `package_not_installed`); agent apply keeps a `bin` file's 0755 mode.
- Not filed (see Known non-bugs): `npm dedupe` drops a pin when the patched name is duplicated; vendored `vex` over a stale tree attests with `vendored_tree_out_of_sync`; a root-level extraneous (`npm install --no-save`) copy makes vendored `scan` exit 1.

## Run 44 (2026-10-16T00Z, main `657fce2`)

- Filed #1595. npm 12's `allowScripts` matcher trusts only a registry-shaped `resolved` (`…/-/<leaf>-<ver>.tgz`), so a hosted or vendored rewrite turns a pinned approval (`esbuild@0.19.12`) into "unreviewed". The postinstall is blocked, and `strict-allow-scripts=true` fails `npm ci`. Name-only keys still match. npm 12.0.0 / 12.1.0 / 12.2.0; npm 11.21.1 / 10.9.4 / 7.24.2 run the script.
- pass: `hasInstallScript` + `os` / `cpu` / `optional` / `bin` lock fields kept by hosted and vendored (npm 7 / 10 / 11), `npm ci --os=darwin --cpu=arm64` over a Linux-vendored optional dep, a workspace member named like a patched package (all three modes refuse or skip as documented), mixed vendored + hosted (+ agent) state across `scan` / `get` / `get --save-only` / `apply` / `vex` / `vendor --check` / `rollback` (byte-exact).
- Re-triage: #1576 / #1554 unchanged (no npm code changes since run 43).

## Run 43 (2026-10-15T12Z, main `e76cb9b`)

- Filed #1576. Vendored npm's lockfileVersion 4 refusal advises removing `patchedDependencies` and re-running `npm install`, but npm 12.1.0 / 12.2.0 keep the lock at v4 (after `npm patch rm`, after `npm install`, after a clean reinstall), so vendoring stays refused. `npm install --lockfile-version 3` is the working remedy.
- pass: #1541 (LFS) on npm. Fresh vendor in a `*.tgz filter=lfs` repo, a legacy `* -text` upgrade on a no-op `vendor`, `git add --renormalize`, and a pointer checkout that fails closed (`vendor --check` / `vex` / `npm ci`).
- #1072 still reproduces at runtime; #1554 code unchanged.

## Run 42 (2026-10-15T00Z, main `e719a9b`)

- Filed #1554. A nested npm project with no lockfile (`.npmrc package-lock=false` or `--no-package-lock`) still makes a root `scan --mode vendored` fail `vendor_lock_entry_not_found` (exit 1 every run, no in-run VEX). Hosted only warns. npm 8.19.4 / 10.9.4 / 12.2.0. Cause: `nested_npm_project` requires the nested directory to have its own lock (`governing_root.rs:487`).
- Verified #1534 fixed (#1543) with real npm 10.9.4: lock and shrinkwrap-only nested projects pass. #1072 is unchanged: the remedy text at `vendor.rs:4410` is still there.

## Run 41 (2026-10-14T12Z, main `37c8918`)

- Filed #1534 (Bun handover): root `scan --mode vendored` crawls a nested independent project's `node_modules` and fails `vendor_lock_entry_not_found` on its package → `partialFailure` exit 1 on every run, in-run `--vex` omitted, `scan . tools/x` also red; hosted skips with a warning. npm 8.19.4 / 10.9.4 ×3 / 12.2.0, v5.0.1.
- Closed #1232: `vendor --check` now names the bundled copy (`copy unpatched`, fixed by #1513). Verified #1511 fixed.
- pass: #1511 siblings: scoped `file:` dir member copy (vendored + hosted refuse), dual lock (shrinkwrap + package-lock) with a member `file:` dir copy (vendored refuses both locks), agent mode with a member `file:` dir link (refuses to write into the link target, `vex` omits `not_applied`).

## Run 40 (2026-10-14T00Z, main `887a5f7`)

- Filed #1511: a vendored `scan --mode vendored --vex` and a standalone `vex` after `npm ci` attest `not_affected` while a workspace member links an unpatched `file:` directory copy of the same `name@version` (`install-strategy=nested`); `vendor --check` passes. npm 10.9.4 ×2 / 11.6.2 / 12.2.0, v5.0.1 too. Cause: `vex/discover/npm.rs` `drop_non_registry_installs` skips the versionless link entry. Tarball / URL copies refuse (pass).
- Verified fixed: #1481 (hosted tarball / dir / URL copies refuse, in-run and standalone), #1266 (linked member alias link).
- Re-triage: #1232 and #1072 still reproduce on `887a5f7`.
- pass: `overrides`-forced `file:` tarball copy (hosted + vendored); hoisted and npm 6 v1 layouts dedupe onto the `file:` link. Blocked: npm 10 `install-strategy=linked` can't install a member's relative `file:` dir (npm ENOENT).

## Run 39 (2026-10-13T12Z, main `15c2c83`)

- Filed #1481. In an npm workspace with `install-strategy=nested`, member a uses registry `left-pad@1.3.0` and member b a `file:` copy of it.
  - Tarball copy: the scan warns `redirect_npm_non_registry_entry_skipped`, but the in-run VEX still attests `not_affected`. First bad commit `f3c6313a` (#1008).
  - Directory copy: no warning, and the in-run VEX attests. Pre-existing.
  - Standalone `vex` refuses both. This is the npm counterpart of the pnpm fix in #1469.
- npm 8.19.4 can't build the shape: it dedupes onto the `file:` copy and pins nothing (pass).
- Re-triage skipped: main unchanged since run 38.

## Run 38 (2026-10-13T01Z, main `15c2c83`)

- Re-triage: #1266 and #1232 still reproduce. Verified fixed on npm: #1437 (bare `scan`/`get` → `mode_ambiguous` over plain, shrinkwrap-only, dual-lock, alias and workspace shapes; no false refusal from a nested project's own hosted pin), #1196 (npm 12.2.0), #1155, #732; #1220 cap passes under `ulimit -n 100`.
- pass (new cells): `npm shrinkwrap` after hosted, `npm dedupe` / `--package-lock-only` over hosted + vendored pins, lockfileVersion 2↔3 conversions over hosted + vendored pins, `-<digit>` names (`base-64`, `crc-32`) and a prerelease alias across hosted / vendored / agent, CACHEDIR.TAG crawl rules (8 shapes, plus apply / vex / rollback consistency), npm 10.9.4 `--global-prefix`, agent under `install-strategy=nested|shallow`.
- Nothing filed. Probe branches still blocked.

## Run 37 (2026-10-09T18Z, main `9ab72d4`)

- Re-triage: #1266 and #1232 still reproduce. #1195 verified fixed (#1211).
- pass: #1034 target grammar on npm (hosted / vendored `rollback` / `remove` / `get` with scoped, versionless, encoded, full-name-vs-last-segment, two-version names), #1277 BOM `.npmrc` (npm 12.2.0) and BOM / BOM+CRLF workspace root `package.json`, #1262 `vex -O` symlink / missing dir, killed takeover and killed dual-lock scan (`vex` refuses the half-pinned dual lock), npm 6 v1 lock on v5, global npmrc `replace-registry-host`, `.npmrc` quoting / inline comments versus `npm config get`.
- Duplicate, not filed: an orphaned vendored artifact dir after a takeover killed post-journal (#1157, wontfix).

## Run 36 (2026-10-09T12Z, main `a80b89e`)

- **fail #1266** (new): an npm `install-strategy=linked` workspace member with `"lp": "npm:left-pad@1.3.0"`. `scan --mode agent packages/a` selects only the member's plain-name links, so `lp` stays unpatched; `rollback packages/a` leaves `lp` patched. Both exit 0. npm 10.9.4 / 12.2.0 ×2. The hoisted nested-alias control passes. pnpm lead handed over.
- #809 commented: a SIGKILL after the vendored commit journal is written makes `vendor --check` fail `vendor_ledger_missing` with a VCS-restore remedy. `repair` replays and passes. `.socket-stage-*` siblings are left behind.
- pass: npm 12 linked + `allow-file=root` (warns, EALLOWFILE as warned), `allow-file=root` with an `overrides`-only vendored dep (warns), npm 12 linked workspace vendored cycle + rollback, unicode / space / `#` path vendored cycle, npm 12 hosted alias cycle, path-scoped agent scan in a hoisted workspace (#778) and `-g --global-prefix`, hosted / vendored kill-recovery, and an immutable lock rolling back `.npmrc` too.
- Re-triage: #1196 and #1233 still reproduce on `a80b89e`.

## Run 35 (2026-10-09T06Z, main `f3c6313`)

- #1008 fixes verified on Linux: #688 (namesake `file:` dir skipped, registry copy vendored), #711 (npm 12.2.0 `npm patch` → hosted skips, `npm ci` OK), #753 (`hasShrinkwrap` nested copy skipped / refused), #812 (project / env / user layers warn), #828 (bundled-copy rollback byte-exact, takeover restores), #879 (npm 8 re-saved v2 lock: `vex` + `vendor --check` pass), #899 (shrinkwrap-only warnings + `vex` omission), #969 (`allow-file=root` workspace + alias: no false warning, npm 12 installs), #554 (nested `tests/` roots skipped; shared copies patched everywhere).
- **fail #1232** (pre-existing, `16106b1` same): vendored package + bundled duplicate → `vendor --check` "wiring missing: no lockfile … references" (false); `vendor` / re-scan / `repair` no-ops. npm 8.19.4 / 10.9.4 / 12.2.0.
- **fail #1233** (#812 fix gap): `replace-registry-host=${RRH}` (project or user `.npmrc`) → no warning, `npm ci` E404 (npm 10.9.4).
- Re-triage: #1195 and #1196 still reproduce on `f3c6313`.

## Run 34 (2026-10-09T00Z, main `16106b1`)

- Re-triage: **#1094 fixed** by #1095 and closed (member stray `package-lock.json` / `npm-shrinkwrap.json` → `redirect_workspace_lockfile_elsewhere`, vendored refuses, `vex` exit 2). **#1155** still reproduces; commented with the upgraded-version-has-its-own-patch shape.
- **fail #1195** (first bad `4d06019`, #1058): a hosted pin plus an unpinned twin entry (`npm install mz@npm:ms@2.1.2` after the scan, or a dual lock where only one lock is pinned) under `--max-new-patches 0` / env / socket.yml → NEW + `rollout_deferred`, nothing rewired, `vex` remedy loops, `npm ci` unpatched copy. npm 8.19.4 / 10.9.4 / 12.2.0. `ef48495` passes.
- **fail #1196** (pre-existing, low): CRLF `.npmrc` without a final newline → `…\nallow-remote=all\r`.
- pass: CRLF-majority mixed / BOM `.npmrc` append, CR-only `.npmrc` refused loudly, BOM and CRLF locks round-trip byte-exact (npm 10.9.4).

## Run 33 (2026-10-08T18Z, main `c4235a2`)

- Bun handover: `npm install ms@2.1.3` over a vendored `ms@2.1.2` (or a downgrade): `vendor --check` sends you to `--prune`, but prune, `vendor --revert`, `remove` and `rollback` all drift-keep the entry. **fail #1155** (npm 8.19.4 / 10.9.4 ×3 / 12.2.0). The `npm uninstall` control reverts (`--json`).
- #1039: vendored → hosted takeover (pass), and its retraction when `/patch/package` answers `pending_build` / `forbidden` (dry and wet leave the tree byte-identical, exit 0): pass (npm 10.9.4).
- Re-triage: #1127 still reproduces on `c4235a2`.

## Run 32 (2026-10-08T12Z, main `e2d9633`)

- `npm uninstall` of the only patched vendored dep, then human `scan --mode vendored --prune`: "No patches available", exit 0, nothing reverted; `--json` reverts it. **fail #1127** (npm 10.9.4 ×3 incl. workspace member, 12.2.0). Control with a patched package left: pass.
- #1029 agent `apply --check`: plain, alias, linked `.store` (plain + alias), `-g` / `--global-prefix`, `tests/` / hidden / `build/` copies: pass (npm 10.9.4). Nonexistent `--global-prefix` → exit 2: pass.
- #1045: `%40`-scoped manifest key through apply / `--check` / vex / rollback by `@` purl: pass. #1029 hosted `redirect.patches[]` (`would_pin`, `pinned`, extglob member `unpinned`): pass. #1050 prune keeps live alias / nested-member entries and fails safe on a conflict-marker lock: pass.
- Re-triage: #879 and #1072 still reproduce on `e2d9633`.

## Run 31 (2026-10-08T06Z, main `ea09714`)

- Extglob `workspaces` (`packages/@(a|b)`, `+(a|c)`, `!(z)`): npm links the member, but a hosted `scan` / `get` from it exits 0 with nothing pinned. **fail #1097** (yarn classic's issue; npm matrix commented) on Linux npm 7.24.2 / 8.19.4 / 10.9.4 / 12.2.0. Brace, class, `packages/a/`, `./packages/a` and `packages/**` refuse: pass (#1071 fixed).
- A stray member `npm-shrinkwrap.json`: same as **#1094** (commented; npm 10.9.4 / 12.2.0). #1094 still reproduces on `ea09714`.
- #1035: hosted / vendored `remove` / `rollback` by uuid and purl are byte-exact, and hosted A + agent B `remove <B>` / `rollback <B>` unpin A: pass (npm 10.9.4 / 12.2.0).
- #1042: linked `.socket`: agent and hosted pass, vendored fails closed: pass (npm 10.9.4).
- #1044: shrinkwrap + package-lock dual lock (hosted + vendored), and a stray yarn / pnpm lock (hosted pins package-lock, vendored refuses): pass (npm 10.9.4).

## Workspace member with a stray own lock (#1094) (2026-10-08T00Z, main `05ecc6e`)

- A workspace member that has its own (stray) `package-lock.json`: hosted `scan` / `get <uuid>` and vendored `scan` from the member rewrite that ignored lock and exit 0 with `success`, root `npm ci` installs unpatched, and `vex` from the member attests `not_affected`. **fail #1094** on Linux npm 7.24.2 / 8.19.4 / 10.9.4 / 12.2.0 (hosted ×2 each; `get` and vendored on 10.9.4). v4.0.0 behaves the same (not a regression).
- `["!packages/b", "packages/*"]`: npm excludes `b`, and a scan from `b` pins nothing (correct): pass.

## Workspace glob refusal gap (#1071) and lost-ledger remedy loop (#1072) (2026-10-07T18Z, main `05ecc6e`)

- A hosted `scan` / `get` from an npm workspace member whose root `workspaces` uses `{a,b}` or `[a-c]`: exit 0, nothing pinned, `npm ci` unpatched. **fail #1071** on Linux npm 7.24.2 / 8.19.4 / 10.9.4 / 12.2.0. `packages/*` and `packages/a*` are refused: pass. Vendored from the member exits 1: pass.
- A lost `.socket/vendor/state.json`: `vendor --revert` advises `repair` "to re-adopt", and `repair` refuses. **fail #1072** (npm 10.9.4). Everything fails safe; `npm ci` stays patched.
- #879 re-check: still fails. Since #970, `vendor --check`'s cause line is false and its `vendor` remedy is a no-op; `scan --mode vendored` fixes it (commented).
- Pass: #852 fix (plain and scoped alias under `install-strategy=linked`, agent + vex + rollback, npm 10.9.4); #933 fix (agent → hosted → rollback byte-exact); a partial `scan --mode vendored` takeover reports what's on disk; `.npmrc` ini `[section]` handling (npm 12.2.0); a spaces / unicode path hosted + vendored cycle (npm 12.2.0).

## Takeover savepoint (#963) and eject reporting (2026-10-07T12Z, main `859a279`)

- Hosted → vendored takeover refused after the restore (`vendor_workspace_member`, #688 shape), or with a failed artifact download (HTTP 500): `scan` / `get --mode vendored` and `vendor` keep the lock and `.npmrc` byte-identical, and `npm ci` installs patched bytes. **pass** on Linux npm 10.9.4 / 12.2.0.
- Mixed takeover (one pin refused, one vendorable): `scan --mode vendored` vendors one pin, keeps the other hosted and keeps `allow-remote=all`, and `npm ci` installs both patched. **pass** (npm 10 / 12).
- A rolled-back `vendor` eject prints "Vendored 1 package" + "Commit .socket/vendor/" with no `eject_rolled_back` line, and `--json` counts the rolled-back package as `applied`. **fail #1005** (npm 8.19.4 / 10.9.4 / 12.2.0). The disk state is correct.

## Agent `--json` drops mismatch-overwrite warnings (#1004)

`scan --mode agent --json` / `get --json` overwrite a locally edited file (default policy) with no `content_mismatch_overwritten` in the JSON and nothing on stderr. Human `scan` and `apply --json` report it. **fail #1004** on Linux npm 10.9.4 / 12.2.0. v4.0.0 is the same. `--strict` → `apply_failed` in `scan --json`: pass (#955).

## npm config that rewrites hosted pins (#812)

`replace-registry-host=always` (npm ≥ 8) rewrites the hosted pin's origin to the configured registry, so `npm ci` / `npm install` fail E404. The hosted scan exits 0 with no warning. **fail #812** on Linux npm 8.19.4 / 10.9.4 / 12.2.0 (project `.npmrc`, env, and user `.npmrc` via `NPM_CONFIG_USERCONFIG`). A warm npm cache masks it; test with `npm ci --cache <fresh>`. A hostname value that isn't the hosted origin passes. Vendored isn't affected; npm 6 / 7 don't have the setting.

Other 2026-10-05 passes (Linux): prerelease version (`ms@3.0.0-canary.1`) hosted / vendored / agent cycles (npm 10.9.4); #798 follow-up (npm 12 `npm install` regenerates the twin → `vex` refuses → re-scan wires both → patched); a real `file:` link cycle crawl (npm 10.9.4).

## Vendored v2 lock after `npm install` (#879, regression from #813)

npm 7–10 `npm install` on a lockfileVersion 2 lock drops `resolved` from `file:` mirror nodes. Since f023506 (#813), vendored `vex` and `vendor --check` exit 1 on that lock although the tree is patched and npm 6 fails closed. **fail #879** on Linux npm 7.24.2 / 8.19.4 / 10.9.4 (plain and alias). Hosted passes. `1714299` passes. #432 fix itself: hosted alias (npm 6 fails closed EINTEGRITY, npm 8 patched) and vendored alias (npm 6 / 8 patched, revert byte-exact) pass on `c644ab0`.

## Agent writes through links (#626)

Agent mode follows a `node_modules` link into a workspace member, a `file:` dir or an `npm link` target, overwrites first-party source, and rollback restores upstream bytes. **fail #626** on Linux npm 6 (`file:`) / 8 / 10 / 12, macOS npm 10.9.7, and Windows npm 8 / 10 / 12, also on v4.0.0. Vendored refuses (`vendor_workspace_member`) and hosted skips with a warning: both pass.

## Alias under `install-strategy=linked` (#852)

npm 9–11 store an alias as `node_modules/.store/lp@<v>-<h>/node_modules/lp` (a scoped alias as `.store/@x/lp@<v>-<h>/node_modules/@x/lp`, also missed; 9.9.4 / 10.9.4 on `859a279`, commented 2026-10-07T12Z). npm 11.21.0 dedupes both into the real-name entry: pass. Agent mode misses that copy. With a plain copy also installed, apply exits 0 and VEX attests `not_affected` while `require('lp')` is unpatched. **fail #852** on Linux npm 9.9.4 / 10.9.4 / 11.6.2. npm 12.2.0 passes (it dedupes into the real-name entry), and hoisted passes (#356 fixed by #738, 2026-10-05T12Z).

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

## npm `allow-file` vs vendored `file:` tarballs (#969, 2026-10-07T00Z)

npm ≥ 11.14.0 has `allow-file` (`all` / `root` / `none`). Under `root` (vendored **transitive** dep) or `none`, vendored `scan` / `vendor --check` / lockfile-only `vex` succeed silently and every `npm ci` fails EALLOWFILE. **fail #969** on Linux npm 12.2.0 (project `.npmrc` x2, env var) and 11.21.0. Pass: `root` with a direct dep, default `all`. npm ≤ 11.13 has no such setting.

## Orphaned vendored entry after `npm uninstall` (Bun handover, 2026-10-07T00Z)

`scan --mode vendored --prune` reverts it (#665 fixed by #689): **pass**. `vendor --check` exits 1 with a false "fresh install gets the unpatched package" message and a no-op `socket-patch vendor` remedy: commented on **#900** (npm 8.19.4 / 10.9.4 / 12.2.0).

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

- **New 2026-10-29T01Z:** re-check #1804 when fixed (`bin-links=false` in `.npmrc`, `directories.bin` with `file:` dir / git deps, and the #1791 recovery must still pass). A bundled dep with a CRLF bin: does npm `fixBin` it, and does main agree? Hosted / vendored `vex` with a CRLF bin (mock). Re-check #1782 when its fix lands.
- **New 2026-10-28T19Z:** re-check #1791 when fixed (apply / repair / rollback over a v5.0.1-overwritten bin; also a non-bin file with a CRLF shebang must keep CRLF). Re-run the hosted / vendored `vex` halves of #1756 on `b4b6d98` with the mock (npm 8 / 12). Re-check #1782 when its fix lands (the kill-test plan below).
- **New 2026-10-28T13Z:** re-check #1782 when fixed: kill the eject at each rename (an `LD_PRELOAD` rename shim works; strace `-P` doesn't match relative paths), and with SIGINT / SIGTERM. A multi-package eject: does the window grow per package? (`vendor --revert` / hosted `rollback` kill-tested in run 51: they converge.) Re-check #1756 when #1757 lands. (Add-a-file on npm 12 / linked: done, pass.)
- **New 2026-10-28T07Z:** re-check #1756 when #1757 lands, including a bin already overwritten by v5.0.1 then rolled back with the fixed build; `vendor --check` on a shrinkwrap-only vendored lock (passes, while `vex` refuses `vex_npm_shrinkwrap_only`: parity question); an eject killed inside the write window (needs a slower hook than the download); patches that add a file on npm 12 / linked store; macOS / Windows for everything once probe branches work.
- **New 2026-10-28T01Z (done in run 50 except macOS / Windows and the root-owned prefix, which the root sandbox can't test):** #1756 on macOS / Windows once probe branches work; agent `rollback` over a consent-overwritten CRLF bin. Eject shapes: hosted pins under `overrides`, `--ecosystems pypi` beside npm pins, `vendor --dry-run`, an interrupted eject. Consent with patch-package `--patch-dir` and in a workspace member run from its cwd. npm 12 global on a root-owned prefix. The 2026-10-18 items about #1627 / #1581 / #1618 / #1595 / #1576 / #1554 / #1072 re-checks are done (all closed).
- **New 2026-10-18T00Z:** re-check #1627 when PR #1628 lands (agent `rollback` / `repair` over a `build` member too); re-check #1581 for npm once fixed (missing, not only legacy, `<uuid>/` metadata); `repair` / `vendor --check` with a gitignored artifact in other shapes (workspace, dual lock); #1618 member-level bundles; npm 12 global on a root-owned prefix.
- **New 2026-10-17T12Z:** #1627 follow-ups (hosted / vendored with a `build`-named member: lock-driven, so are the pins and `vex` right? `scan --mode agent`, `rollback` and `repair` over such a member; `install-strategy=linked` member at `packages/dist`; hand over to pnpm / yarn / bun if their workspaces hit the same `SKIP_DIRS` prune); plus the 2026-10-17T00Z items below.
- **New 2026-10-17T00Z:** #1618 siblings (`bundleDependencies: true`, `bundledDependencies` spelling, a workspace member's own bundleDependencies, takeover / rollback / remove over a root-bundled entry once fixed); do Bun / vlt / yarn locks flag root bundles too? (hand over if so); re-check #1595 / #1576 / #1554 / #1072 on the next main; `scan . tools/x` once #1591 lands.
- **New 2026-10-16T12Z:** re-check #1595 / #1576 / #1554 (PR #1591) / #1072 on the next main; a root-level extraneous copy (`npm install --no-save`) under vendored: does PR #1591 change it? (It shouldn't: the PR covers dirs strictly below the root.) npm 12.2.1's `#loadFailures` ERESOLVE relaxation with an unreachable hosted URL during `npm install <pkg>`; `allowScripts` over aliases and git deps (#1595 follow-ups, still open); `scan . tools/x` once #1591 lands.
- **New 2026-10-16T00Z:** #1595 follow-ups (git / `file:` / alias deps with `allowScripts`, `false` deny entries over a pin, `npm install` vs `ci`); re-check #1595 / #1576 / #1554 / #1072 on the next main; npm 12 `allow-git` / `allow-directory` vs takeovers; `scan . tools/x` with a lockless `tools/x`.
- **New 2026-10-15T12Z:** re-check #1576 / #1554 / #1072 on the next main; #1541 follow-ups (a `.gitattributes` inside a vendored dir payload, `.git/info/attributes`, a hosted → vendored takeover in an LFS repo); #1534 siblings (`scan . tools/x` with a lockless `tools/x`).
- **New 2026-10-15T00Z:** re-check #1554 / #1072 on the next main; #1534 siblings (a nested project inside an `ignorePaths`-excluded dir or under a workspace member, `scan . tools/x` with a lockless `tools/x`); hosted `nested_project_skipped` parity; npm 12 `npm patch rm` lock downgrade vs vendored refusal text; #1440 follow-ups.
- **New 2026-10-14T12Z:** re-check #1534 / #1072 on the next main; #1534 siblings (an `ignorePaths`-excluded nested project, a nested project with no lock, a workspace member with a stray own lock under vendored); #1440 follow-ups; npm 12 `npm patch rm` lock downgrade vs vendored refusal text.
- **New 2026-10-14T00Z:** re-check #1511 / #1232 / #1072 on the next main; #1511 siblings (a scoped `file:` dir copy, a dual lock carrying the link, agent mode with a `file:` dir copy); #1440 follow-ups (still open).
- **New 2026-10-13T12Z:** re-check #1481 / #1266 (PR #1470) on the next main; #1481 siblings (a git or URL dependency of the same `name@version` under `install-strategy=nested|linked`, an `overrides`-forced `file:` copy, `scan --mode vendored --vex` over the same shapes).
- **New 2026-10-13T01Z:** re-check #1266 / #1232 / #1072 / #1097 on the next main; #1440 follow-ups (`get --save-only` / `--mode agent` on mixed state, a mixed state left by an interrupted `--mode hosted` takeover, bare run without the `--patch-server-url` the pins were made with); CACHEDIR.TAG on a workspace member and under `install-strategy=linked`.
- **New 2026-10-09T18Z:** re-check #1266 / #1232 / #1196 / #1233 / #1155 on the next main; #1034 agent `remove <name> --preserve-state` and a scoped name that also matches a member dir; #1245 `NpmFamily` keep policy after an npm upgrade and with a shared artifact; an agent → hosted takeover killed at each rename; the npm 12 `npm patch rm` lock downgrade versus vendored refusal text; `get pkg:npm/<name>` (versionless) against the real API (the mock only answers exact purls).
- **New 2026-10-09T12Z:** #1266 follow-ups (pnpm member alias link — handed over; `apply --check packages/a` and `vex` with a member alias link; a scoped alias `@x/pad` link); an interrupted vendored → hosted takeover on npm (#1157 analogue); `vex` right after a killed hosted dual-lock scan; #1195 cap N>0 competing for a slot; re-check #1196 / #1233 / #1195 / #1155 on the next main.
- **New 2026-10-09T06Z:** #1232 siblings (a git / URL / override duplicate of a vendored name@version: same generic `vendor --check` reason?); #969 under `install-strategy=linked` and `overrides`-only declarations; #711 range / alias `patchedDependencies` selectors on a lock without a `patched` record, and a pin that predates `npm patch`; re-check #1155 / #1195 / #1196 on the next main; verify #433 (`remove --preserve-state`) on `f3c6313`.
- **New 2026-10-09T00Z:** #1195 siblings (the #828 bundled copy under a cap, the in-memory engine with partial pins, a cap N>0 competing for a slot); re-check #1155 when #1187 lands; #1031 removed flags in npm docs and remedy texts; #1027 `{code, message}` errors on npm refusal paths; re-check #325 / #433 / #490 / #828 on `16106b1`.
- **New 2026-10-08T18Z:** #1039 takeover with hosted-side refusals that aren't a service status (#828 bundled copy, linked alias, a one-sided dual lock, a mixed retract + take-over run); #1155 in a workspace member, a nested copy and an alias; re-check #325 / #433 / #490 / #828 on `c4235a2`.
- **New 2026-10-08T12Z:** #1127 on other vendored PMs (hand over if unseen); `apply --check` (#1029) on npm 6 v1 locks, `inBundle` copies, and a hosted-pinned package that still has a manifest record; re-check #325 / #433 / #490 / #828 on `e2d9633`.
- **New 2026-10-08T06Z:** re-check #1094 / #1097 when fixes land (member `package-lock.json` and `npm-shrinkwrap.json`, extglob); re-check #325 / #433 / #490 / #665 / #828 / #879 on `ea09714`; #1035 with a vendored A + hosted B mix across a dual lock.
- **New 2026-10-08T00Z:** #1094 on yarn / Bun workspaces (same `has_own_npm_family_lock` early exit; hand over if confirmed), a stray member `npm-shrinkwrap.json`, `rollback` / `remove` from the member; case-insensitive workspace globs on macOS / Windows (probe branch).
- **New 2026-10-07T18Z:** #1071 on yarn / Bun roots (shared matcher; hand over if not covered), `!` negation order and `./` patterns vs real npm; re-check #325 / #433 / #490 / #665 on `05ecc6e`. (#1005 on a `scan --mode vendored` partial takeover: done 18Z, pass.)
- **New 2026-10-07T12Z:** #1005 on `scan --mode vendored` partial takeovers (does the human summary match disk?); #1004 siblings (other nested-apply warnings dropped from `scan --json`: `package_not_installed` next to a success, sidecar advisories); re-check #325 / #433 / #490 / #665 on `859a279`. (#852 scoped alias confirmed and commented; #688 takeover half verified fixed; #828 still reproduces on `859a279`.)
- **New 2026-10-07T00Z:** #969 follow-ups (hosted→vendored takeover under `allow-file=root`; user / global `.npmrc` layers; a workspace member's vendored deps under `root`; `allow-directory` with `file:` directory deps).
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

- A registry package that declares bins only via `directories.bin`: the packument carries the expanded `bin`, so npm links it and runs `fixBin`, and main's LF form is correct (run 53). Only non-registry installs hit #1804.

- A Ctrl-C or kill during the eject's artifact *download* is safe: the download runs before the upstream restore, so the lock is still hosted (main `b787454`, 2026-10-28T13Z).
- After vendoring, `npm shrinkwrap` renames package-lock.json to npm-shrinkwrap.json. `vendor --revert` then refuses with advice that names the rename ("was the wired lockfile renamed — e.g. by `npm shrinkwrap`"), and `vex` omits the patches (`vex_npm_shrinkwrap_only`, documented). Hosted `rollback` restores the renamed lock (npm 10.9.4, 2026-10-28T07Z).
- `repair` of a deleted `<uuid>/` dir restores the tarball, `.gitignore` and `.gitattributes`, but not the `socket-patch.vendor.json` marker. The marker is documented as informational ("never a trust input"), and `repair` is documented to restore the ignore/attributes pair; `vendor --check` and a fresh clone's `npm ci` pass (npm 10.9.4 dual lock + workspace + `*.tgz` ignore, 2026-10-28T07Z).
- patch-package treats subdirectories of `patches/` as nested package paths (`patches/sub/x+1.0.0.patch` targets `node_modules/sub/x`), so the non-recursive `patches/` read in `user_patches.rs` is correct (patch-package 8.0.0, 2026-10-28T07Z).
- With a warm npm cache holding the patched tarball, npm 6.14.18 `npm ci` on a hosted v1 lock installs the patched bytes (cacache hit by integrity) rather than the EINTEGRITY the `redirect_npm_lockfile_v1` warning predicts. Harmless (2026-10-28T07Z).
- A wet `vendor` eject's `--json` lists each package as `applied` plus a `skipped` `vendor_prebuilt_downloaded` advisory event; that's the documented advisory pattern (2026-10-28T07Z).
- A workspace member's own `bundleDependencies` copy (`packages/a/node_modules/ms`, `inBundle: true` in the root lock) is neither pinned nor reported by hosted / vendored. npm itself never reinstalls such a copy from a clean tree (`npm ci` and `npm install` after `rm -rf node_modules` both leave it absent), so no unpatched copy runs (npm 10.9.4, 2026-10-28).
- After the #1648 eject, a pre-existing `.npmrc` keeps hosted mode's `allow-remote=all` line, with the documented `npm_allow_remote_left` advisory. A `.npmrc` that hosted mode created is deleted (2026-10-28).
- The #1648 eject over an npm 6 lockfileVersion 1 lock refuses `eject_refused` with nothing changed (v1 vendoring is documented as refused) (2026-10-28).
- Mock tip (2026-10-28): the org routes (`SOCKET_API_URL` + `SOCKET_API_TOKEN=fake` + `SOCKET_ORG_SLUG`) plus `SOCKET_PATCH_SERVER_URL` and `SOCKET_NPM_REGISTRY` on one mock serve hosted, vendored and the eject. `POST …/patches/package` returns `url` = `<mock>/patch/npm/<name>/<ver>/<tok>/<uuid>/<leaf>-<ver>.tgz` for both. A project `.npmrc` `registry=<mock>/` lets the mock serve hand-made packages. `vex --json` needs `--output <file>`.
- A `file:` directory dependency whose `package.json` names the patched package with no version (`{"name":"ms"}`), names nothing, or is missing isn't treated as a copy of the patched release: hosted pins, and `vex` / `vendor --check` pass. A versioned one (`ms@2.0.0`) is contested. Unlike yarn portals (#1579), npm records the directory's manifest in the lock, and a directory filled after locking (a submodule) makes `npm ci` fail EUSAGE, so the "fetch step fills it later" path fails closed (npm 10.9.4, 2026-10-18).
- npm 12.2.1 `npm install <newpkg>` while a hosted pin's URL is unreachable (cold cache) fails loudly and keeps the pin; no silent registry fallback (2026-10-18).
- Global `-g` cells need a prefix path without a UUID segment (npm >= 11 redacts it in `npm root -g`); the session scratchpad path has one (2026-10-18).
- VEX product purl for a scoped `package.json` name keeps the raw `@scope/name` (`pkg:npm/@acme/app@1.0.0`), and uppercase / `+build` versions are kept verbatim. Deliberate (`vex/product.rs:154`) (2026-10-17).
- A BOM-prefixed `.npmrc` with `allow-remote=none`: npm 12.2.1 reads `none`, and hosted respects it (warns, doesn't write) (2026-10-17).
- npm 12 `allowScripts` alias keys (`eb@npm:…`) never match in npm itself; aliased deps fall under #1595 (2026-10-17).
- `npm dedupe` re-resolves every duplicated name like `npm update <name>`. With `debug@2.6.9` (→ `ms@2.0.0`, nested) beside a root `ms@2.1.3`, a hosted or vendored `ms@2.0.0` pin goes back to the registry (npm 10.9.4 / 12.2.1). Afterwards `vex` and `vendor --check` fail closed. This is npm behaviour, the same as the `npm update` entry. With no duplicate name, dedupe keeps the pin (2026-10-16T12Z).
- Vendored `vex` run before the reinstall (stale, unpatched `node_modules`) attests with a `vendored_tree_out_of_sync` warning, while hosted refuses `not_applied`. Documented in CLI_CONTRACT.md (vendored attests the committed artifact) (2026-10-16T12Z).
- A root-level extraneous copy (`npm install --no-save left-pad`, not in the lock) makes vendored `scan` fail `vendor_lock_entry_not_found` (exit 1, no in-run VEX) on every run, while hosted warns `redirect_npm_entry_not_found` and exits 0. The remedy (`npm install`) prunes the copy and clears it, so not filed. It's a hosted/vendored parity question if a maintainer wants one (npm 10.9.4 / 12.2.1, 2026-10-16T12Z).
- Mock tip (2026-10-16T12Z): hosted `vex` / `rollback` only recognise pins on the `--patch-server-url` host, and the hosted URL must have the `/patch/npm/<name>/<ver>/<token>/<uuid>/<leaf>.tgz` shape. Vendored needs `POST …/patches/package` artifacts, since local builds are gone (`vendor_service_offline_conflict` with `--offline` and no artifact).
- Mock tip (2026-10-16): the Python mock lives in the run's scratchpad only. Compare purls URL-decoded (`%40` vs `@`), or scoped packages get no patch. The public proxy also POSTs `/patch/telemetry` (a 404 is fine).
- Vendored `scan` refuses (`vendor_workspace_member`, exit 1) a workspace member whose name@version matches a patched package, while hosted only warns (`redirect_npm_entry_not_found`, exit 0). Documented in docs/ecosystems.md (2026-10-16).
- A vendored optional platform dep (`@esbuild/linux-x64`) that `npm ci --os=darwin` skips is still listed as a not_affected subcomponent by `vex` (lock-based attestation, documented) (2026-10-16).
- npm 12 blocks dependency install scripts by default (`allowScripts`); a hosted or vendored package without an approval shows the same warning as the registry copy. Only the approval mismatch is #1595 (2026-10-16).
- Mock tip (2026-10-15): the `tests/prebuilt_common` service fixture publishes bytes per (project root, uuid) per process, so `repair` in a second clone of a vendored project gets `vendor_artifact_redownload_failed` (SHA mismatch). That's a fixture artifact, not a bug.
- A legacy `* -text` uuid `.gitattributes` in an LFS-tracking repo keeps the tarball committed as an LFS pointer until the next vendored run and a `git add --renormalize` (documented in docs/ecosystems.md, #1541) (2026-10-15).
- npm with a member `file:` directory dependency (`install-strategy=nested`, `install-links=false`) installs that directory's own devDependencies into `<dir>/node_modules`, so a root crawl sees them. That's npm's behaviour (2026-10-14).
- Agent `scan --mode agent` refuses (exit 1, `apply_failed`) to patch a `file:` directory link target outside every `node_modules`; that's the #626 fix, loud by design (2026-10-14).
- npm 10.9.4 `install-strategy=linked` fails ENOENT on a workspace member's relative `file:../../dir` dependency (it resolves the path against the wrong base). That's npm's behaviour; the shape can't be built there (2026-10-14).
- A `CACHEDIR.TAG` in a workspace member prunes that member's `node_modules` from the agent crawl. That's documented in docs/ecosystems.md, the same class as the `build/` / `dist/` member skip (2026-10-14).
- Hosted `rollback` against a registry answering 429 refuses loudly (exit 1, `git checkout` remedy, lock untouched); the upstream fetcher has no 429 / `Retry-After` retry by design (#1220 added only the concurrency cap) (2026-10-13).
- Plain `socket-patch vendor` on a project with vendored entries and hosted pins ejects the hosted pins into `.socket/vendor/` ("Ejecting 1 hosted package"): the documented eject, unlike the bare `scan`/`get` conversion fixed in #1437 (2026-10-13).
- The `mode_ambiguous` message names the project root as `.` when run from it. Cosmetic (2026-10-13).
- `npm shrinkwrap` after a hosted scan moves the pins into npm-shrinkwrap.json; `vex` then omits them with `vex_npm_shrinkwrap_only` (the documented shrinkwrap-only rule), while npm 10 `npm ci` installs the patched bytes (2026-10-13).
- Mock tip (2026-10-13): never `pkill -f mock.py` or `pgrep -f mock.py` in the same shell command; both match the calling shell. Record the mock's PID in a file at start.
- A vendored → hosted takeover SIGKILLed after its commit journal is written: the next locked command finishes the files, but the old `.socket/vendor/npm/<uuid>/` dir stays. Same as #1157 (pnpm), closed as wontfix. Reproduced on npm 10.9.4 (2026-10-09T18Z).
- npm 12.2.0 accepts range `patchedDependencies` keys (`ms@^2.1.0`). socket-patch's package.json key matcher doesn't parse ranges, but npm writes the `patched` record into the lockfileVersion 4 lock for any selector, and the hosted gate reads it. A range key without a regenerated lock fails `npm ci` anyway (2026-10-09T18Z).
- `rollback '@scope/*'` is a path glob relative to the cwd (it matches nothing loudly); use `node_modules/@scope/*` or the scoped name (2026-10-09T18Z).
- Mock tip (2026-10-09T18Z): the `SOCKET_NPM_REGISTRY` version doc's `dist.tarball` is written into the lock verbatim on hosted rollback, so serve the real `<name>/-/<leaf>-<ver>.tgz` shape for scoped names. In shells, never `pkill -f mock.py`: it matches the calling shell. Start the mock with `setsid`.
- A SIGKILL inside a hosted or vendored write window leaves a `.socket-stage-<file>-<uuid>` sibling that later runs don't remove. Every atomic-rename writer leaves that residue after a kill, and the re-run converges. Noted on #809, not filed separately (2026-10-09T12Z).
- A hosted scan with an immutable lock (chattr +i) now fails with "nothing was changed", and `.npmrc` is rolled back too. The older "mid-flush I/O residual" note below about `.npmrc` being left is outdated on `a80b89e` (2026-10-09T12Z).
- npm dedupes a root registry `ms@2.1.2` onto a git copy of the same version even when an `overrides` entry forces the git spec only under `debug`. So a registry + git duplicate of one name@version (a #1232 sibling) can't be built with npm 10 (2026-10-09T12Z).
- Mock tip (2026-10-09T12Z): the public-proxy routes need only `POST /patch/batch`, `GET /patch/by-package/<purl>`, `/patch/view/<uuid>` (with `blobContent` / `beforeBlobContent` base64 and git-sha256 `beforeHash` / `afterHash` for agent mode), `/patch/blob/<hash>`, `POST /patch/package` (`results[uuid]` with `status: granted`, `url`, `artifacts[{kind: tarball, url, integrity{sha512, sha1, md5}}]`) and the tarball URL. An `LD_PRELOAD` shim that SIGKILLs on `rename()` to a path suffix reproduces interrupted runs; `strace -e inject` counts per thread and misses.
- Shrinkwrap-only vendored project: `vex` omits (`vex_npm_shrinkwrap_only`) while `vendor --check` passes. That's the documented "Unattested references" rule (liveness gates keep treating the wiring as live) (2026-10-09T06Z).
- A raw `allow-file=${AF}` is treated as a non-`all` value, so it warns `vendor_npm_allow_file` and `vendor --check` fails even when `AF=all`. Fails safe. The silent direction for `replace-registry-host` is #1233 (2026-10-09T06Z).
- Mock tip (2026-10-09T06Z): `npm pack <spec>` plus a Python tar rewrite gives a real patched tarball. The org routes are matched on path suffixes as before; `/patch/package` returns `results[uuid]` for every known uuid in the request body.
- Mock tip (2026-10-09T00Z): org routes work with `--api-url <mock> --org o --api-token fake --patch-server-url <mock>`, routing on path suffixes `/batch`, `/by-package/<purl>`, `/view/<uuid>`, `/blob/<hash>`, `/package` and the tarball URL `/patch/npm/<name>/<ver>/<tok>/<uuid>/<name>-<ver>.tgz`. Hosted `rollback` worked without `SOCKET_NPM_REGISTRY` this run.
- A CR-only `.npmrc` is refused loudly ("not set automatically") and left untouched (documented). Only the splice that produces a bare CR is a bug (#1196).
- Mock tip (2026-10-08T18Z): `POST /patch/package` answering `pending_build` / `forbidden` during a vendored → hosted takeover keeps the vendored wiring byte-identical and exits 0 ("No patches could be switched to hosted"). That's #1039's intended retraction, not a silent no-op.
- `apply --check -g` drift text says "Run `socket-patch apply`" without `-g`; following it fails loudly (exit 1, "matched no installed package"). Noted, not filed (#464 class, low value). (2026-10-08T12Z)
- Mock tip (2026-10-08T12Z): the public-proxy routes (`SOCKET_PROXY_URL` + `SOCKET_API_URL`, no token) need only `POST /patch/batch` (`components[].purl`), `GET /patch/by-package/<purl>`, `/patch/view/<uuid>`, `/patch/blob/<hash>`, `POST /patch/package` and the tarball URL it returns.
- Mock tip (2026-10-08T06Z): when two mock origins serve patch generations A and B, `remove` / `rollback` must get the A pin's origin as `--patch-server-url`, or the pin is invisible (documented) and looks like a #1035 miss.
- A `workspaces` negation listed before the positive pattern (`["!packages/b", "packages/*"]`): npm excludes `b`, and a hosted scan from `b` pins nothing because `b` is its own project (npm 10.9.4, 2026-10-08T00Z).
- pnpm handover #1074's npm analogue (`package-lock=false`): `npm ci` still honors the lock, so a lock-only attestation matches `npm ci`, and `vex` refuses after a plain `npm install` (see the entry below; re-reviewed 2026-10-08T00Z).
- An `.npmrc` that ends inside an ini `[section]`: hosted inserts `allow-remote=all` before the first section, and an `allow-remote` that sits only inside a section is (correctly) not treated as set (npm 12.2.0, 2026-10-07T18Z).
- A lost `.socket/vendor/state.json` with the lock still wired: every command keeps the artifacts and `npm ci` stays patched (fail-safe). Only the `vendor --revert` remedy text is wrong (#1072).
- The eject `vendor --dry-run` reports `eject_planned` (exit 0) even when the wet eject will refuse a pin. CLI_CONTRACT eject step (3) says the dry run stops at the restore plan. The `scan` / `get --mode vendored --dry-run` takeover preview listing `would_vendor` is documented too ("does not model the takeover yet"). (2026-10-07T12Z)
- `content_mismatch_overwritten` (local edits overwritten under the default policy) is documented behaviour. Only its missing report in `scan` / `get --json` is a bug (#1004).

- `allow-file=root` (npm 12.2.0) admits a vendored dep that is a workspace member's direct dependency (2026-10-07T06Z).
- An alias key that shadows the patched package's name (`"left-pad": "npm:once@1.3.0"`) is correctly ignored by agent, vendored and `vex` (2026-10-07T06Z).
- An npm 10 consumer ignores a published library's vendored `npm-shrinkwrap.json` and installs registry bytes. socket-patch makes no claim about published libraries.
- `allow-file=root` admits a vendored **direct** dependency's `file:` tarball (npm 12.2.0); only transitive vendored entries are refused (#969).
- An orphaned vendored ledger entry after `npm uninstall` is cleaned up by `scan --mode vendored --prune` (since #689). Only the `vendor --check` wording is wrong (#900).
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
- npm 8 (no `install-strategy`), and npm 10 with the default hoisted layout, dedupe a registry `left-pad@1.3.0` spec onto a `file:` tarball copy of the same version. The lock then has a single `file:` entry, so the hosted scan correctly pins nothing (run 39).
