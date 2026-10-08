[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last updated: 2026-10-08 (run 33), main `a845bf9`, latest release 4.0.0, latest Bun 1.4.2 (no 1.4.3 stable yet).

Method (run 16 note: the sandbox shell exports `BUN_OPTIONS=--smol`, so unset it; run 17 note: on Bun ≥ 1.2, `bunfig [install] saveTextLockfile = false` writes a binary `bun.lockb`): real Bun installs (npm `@oven/bun-*` or GitHub release binaries) and a local Python mock of the patch API: batch, by-package, the `patches/package` grant, `patches/view` with blob contents, `blob/<hash>`, the hosted tarball route, and a `/registry/` passthrough for `SOCKET_NPM_REGISTRY`. Set `SOCKET_PATCH_SERVER_URL` and `SOCKET_PROXY_URL` to the mock (run 32: without a token the CLI uses the public-proxy routes `/patch/batch`, `/patch/by-package/<purl>`, `/patch/view/<uuid>`, `/patch/blob/<hash>` and `POST /patch/package`, and `patch.socket.dev` returns 403 through the sandbox proxy). Test repos need `node_modules/` in `.gitignore`, or the fresh-clone oracle reads committed store entries. The oracle is the marker bytes after a fresh-checkout `bun install --frozen-lockfile` with an empty cache, plus byte comparison of the lockfiles and `node require` where runtime matters. The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) already covers plain hosted and vendored shapes across Bun 0.8.1–1.4.2. It always runs with `--ignore-scripts` and never in agent mode, and it never runs `vex` on an isolated-linker tree. This ledger tracks what it doesn't.

Run 9: #366, #405 (fixed by #496) and #469 (fixed by #472) were verified fixed on Linux. Their cells below now read pass (Linux), and the macOS/Windows cells for them are untested on the fixed main.

Run 10: #599 still reproduces on `045d7ec`. New: #635 (Bun ≥ 1.3.14 `globalStore`).

Run 11 (main unchanged at `045d7ec`): #599 still reproduces. No new bugs. All the new cells pass: the run 11 section below, and the vendored row of the `globalStore` table.

Run 12 (main unchanged at `045d7ec`, so no re-triage): no new bugs. Bun 1.1.39, the oldest release in range, is now covered and passes. All the new cells pass: the run 12 section below.

Run 13 (main unchanged at `045d7ec`, so no re-triage): new #720. Lockfile-only discovery can't see hosted pins, so a hosted re-run in CI never picks up a superseding patch, and `scan --mode vendored` skips the takeover. Both report success. The other new cells pass: the run 13 section below.

Run 14 (main unchanged at `045d7ec`, so no re-triage): new #739. A `bun.lockb` holding `X@1.0.0` + `X@1.0.0-beta.1` is refused as a metadata-hash mismatch, and hosted exits 0 with nothing patched (a regression since 4.0.0). Bun cells added to #626 (agent mode overwrites first-party workspace members). The other new cells pass: the run 14 section below.

Run 15 (main unchanged at `045d7ec`, so no re-triage): new #764. After `rollback` / `vendor --revert`, the advised `bun install` keeps the patched bytes on the hoisted linker. The other new cells pass: the run 15 section below.

Run 16 (main unchanged at `045d7ec`, so no re-triage): new #784. A vendored `bun.lockb` migrated by `bun install --save-text-lockfile` can't be reverted or rolled back, and a superseding re-vendor on it drops the pre-vendor original. `remove` added to #764. The other new cells pass: the run 16 section below.

Run 17 (main unchanged at `045d7ec`, so no re-triage): new #803. A hosted or vendored **workspace** `bun.lockb` migrated to text by Bun 1.4.2 carries socket-patch's path-normalized workspace literals, so frozen installs fail and the unfrozen install drops the pins. The other new cells pass: the run 17 section below.

Run 18 (main unchanged at `045d7ec`, so no re-triage): no new bugs. #764 is confirmed on a Bun 1.2.23 hoisted workspace. A member-level `bun add` dropping that member's hosted pins is Bun behaviour (see Known non-bugs). The other new cells pass: the run 18 section below.

Run 19 (main unchanged at `045d7ec`, so no re-triage): no new issue. The yarn-classic handover #831 reproduces on Bun: a vendored tarball covered by `.gitignore` (`*.tgz`, `vendor/`, `.socket/`) exits 0, the commit drops it, and fresh frozen installs fail. That holds on text v1/v2, `bun.lockb` and an isolated workspace, and the Bun matrix is commented on #831. `bun ci` reproduces #803. The other new cells pass: the run 19 section below.

Run 20 (new main `6811b4e`): #803, #739 and #720 were fixed by #811, #741 and #722, closed by the maintainers, and verified on Linux (#803 heal: hosted + vendored re-run; #720: lockfile-only `bun.lockb` supersede + vendored takeover). #599 and #497 still reproduce, and #497 also gives a false `not_affected` from lockfile-only default `vex` (commented). New: #861. A vendored re-run after a new dependent duplicates a `bun.lockb` tarball record, and isolated frozen installs fail EEXIST intermittently on 1.3.9/1.4.2. The other new cells pass: the run 20 section below.

Run 21 (new main `9c43dfc`): #861 still reproduces. No new issue. The isolated-workspace member-run shape (hosted `scan` from a member: `success`, nothing pinned) is now tracked on #884 (commented), and is no longer a known non-bug. Three generic npm-family findings were handed to npm. The other new cells pass: the run 21 section below.

Run 22 (main unchanged at `9c43dfc`, so no re-triage): no new bugs. All the new cells pass: multi-package and large-tree (express) `bun.lockb` hosted / vendored / takeover by writers 1.1.45–1.4.2, two versions of one patched package (nested + direct, and per workspace member), and scoped `rollback` / `remove` of one of two same-name pins. See the run 22 section below.

Run 23 (main unchanged at `9c43dfc`, so no re-triage): no new issue. #861 also reproduces when `bun add` runs inside an existing member (commented). All the new cells pass: a vendored `bun.lockb` upgraded from binary format 2 to 3 by a newer Bun, `bun.lockb` takeovers by writers 1.1.39 / 1.3.4 / 1.3.10, `globalStore` + hosted workspace, and BOM / no-final-newline text locks. See the run 23 section below.

Run 24 (main unchanged at `9c43dfc`, so no re-triage): no new bugs. The Bun 1.3.10 text-lock row is now covered (agent hoisted + isolated, hosted, rollback byte-exact). A hosted 1.2.0 workspace `bun.lockb` upgraded to format 3 by 1.4.2 picks up a superseding uuid. Concurrent and SIGKILLed vendored runs, mixed-case names (`JSONStream`) and catalogs all pass. See the run 24 section below.

Run 25 (main unchanged at `9c43dfc`, so no re-triage): no new bugs. Mixed per-package modes (vendored ⇄ one package hosted, on text and `bun.lockb`, single and workspace, 1.2.23 / 1.3.9 / 1.4.2) pass, as do `globalStore` + vendored workspace lockb, `overrides`/`resolutions` and Bun lock re-serializations. #861 also reproduces under `globalStore`. `bun remove` of a vendored package leaves `vendor --check` red with a no-op remedy; it's generic, so it was handed to npm (related #900). See the run 25 section below.

Run 26 (main unchanged at `9c43dfc`, so no re-triage): no new bugs. Explicit `trustedDependencies` and `bun pm trust` on hosted / vendored packages with a postinstall keep the script running (text + `bun.lockb`, single + workspace, 1.2.23 / 1.3.9 / 1.4.2). Mixed per-package modes plus a superseding uuid, re-run in each mode, pass. `bun install --filter` frozen installs on rewired workspaces pass. Probe-branch deletion is still refused (now by the sandbox's permission classifier). See the run 26 section below.

Run 27 (main unchanged at `9c43dfc`, so no re-triage): new **#992**. Hosted `bun.lock` `rollback` / `remove` / hosted→vendored→`vendor --revert` write `""` into the registry slot, and Bun 1.1.39–1.3.6 resolve `""` against npmjs, ignoring the bunfig registry. Custom-registry projects then fail cold frozen installs (404), or silently bypass their mirror. Bun's own boundary is 1.3.7. Also passing: `preinstall` / `install` / `postinstall` on a scoped package with a `bin` and an unscoped preinstall-only package (hosted / vendored × text / `bun.lockb` × single / workspace × 1.2.23 / 1.3.9 / 1.4.2). In untrusted projects, rewiring doesn't start running scripts. `bun pm trust` and `--filter` work on 1.2.23. Plain re-installs leave a rewritten `bun.lockb` byte-identical. Bun 1.4.3-canary.1 passes hosted / vendored / agent, the takeover chain and rollback. Packages with only a sha1 `shasum` rewire fine. See the run 27 section below.

Run 28 (new main `db83f01`): #992 and #861 still reproduce (the fix is pending in draft #1009). Verified on Linux: #367 (#873, registry-keyed `bun patch` kept, text + `bun.lockb`), #884 (#901, loud member refusal), #831 (#837, Bun `*.tgz` / `.socket/` ignores) and #963 (a refused vendored takeover keeps the Bun hosted pins). New: **#1019**. On Bun 1.4, a `bun patch` made after rewiring is keyed `name@<hosted URL | vendor path>`, which the #873 guard doesn't match, so superseding re-runs, takeovers, rollback and revert silently drop it. See the run 28 section below.

Run 29 (new main `05ecc6e`): #992 still reproduces (fix pending in draft #1009). New: **#1084**. On the isolated linker, after an agent A → hosted B (superseding) migration and a `bun install`, `rollback` / `remove` exit 0 and drop record A and its blobs. #934's `rollback_record_superseded` skip ignores the orphaned `.bun/<pkg>@<ver>` store entry, which still holds A's bytes, and the advised `bun install` relinks it (first bad `04885c3`). The agent → vendored takeover leaves the same A-patched orphan behind after a revert, which was commented on #764. #934 on hoisted text locks passes. See the run 29 section below.

Run 30 (new main `fe8455d`; no Bun code changes since `05ecc6e`, so #992 / #1084 weren't re-run, and their fixes are still pending in draft #1009): new **#1101**. A hosted or vendored scan / `get` run from a Bun workspace member that holds a stray `bun.lock` / `bun.lockb` pins that lock, which Bun never reads. It exits 0, and `vex` attests `not_affected` while Bun installs unpatched (the Bun variant of #1094; PR #1095 explicitly keeps Bun's own-lock shortcut, verified on its head `cddf38d`). Bun 1.1.39–1.2.23 ignore `!` workspace patterns (1.3.0+ honour them), so #1097's negation half reproduces on old Bun (commented). #1073's brace / class / `**` / object-form member refusals pass on 1.4.2. A symlinked `bun.lock` / `bun.lockb` dry run vs wet run passes (backlog 10). See the run 30 section below.

Run 31 (new main `829d0af`: #1035 superseded-generation remove/rollback, #1044 governing-lock table, #1038, #1042, #1033): new **#1116**. Vendored `bun.lockb` workspaces write member-relative tarball mirrors (`packages/<m>/.socket/vendor/...`) with no `.gitignore` probe and no `!*` re-include, so a stock `*.tgz` rule drops them from the commit. Fresh frozen installs then fail with ENOENT (1.1.39–1.2.23) or hang (1.3.9) when the member resolves its own copy, and on 1.4.2 `vendor --check` / `vex` fail in every clone. #1101 and #1084 still reproduce. #1101 also reproduces under a root `bun.lockb` with a stray member `bun.lock` / `bun.lockb`, where lockfile-only `vex` attests (commented). #1035 on Bun passes: hosted and vendored supersede A→B then `remove B` / `rollback B`, cross-mode takeovers, the #999 shape, hosted A + agent B, and an alias of the same release (text + lockb, single + workspace, 1.2.23 / 1.3.9 / 1.4.2; the text lock is byte-exact). See the run 31 section below.

Run 32 (new main `9472be4`: #1050 one in-use verdict for the vendored prune GC, #1029 CI gates and hosted `redirect.patches[]`): new **#1132**. After `bun remove` of a vendored package in a `bun.lockb` project, `scan --prune`, `vendor --revert` and `remove` all keep the entry as "drifted" (`bun_binary.rs:526`), so `vendor --check` stays red and its `--prune` remedy loops (1.1.39–1.4.2, single + workspace). Text `bun.lock` reverts cleanly. Orphaned `.bun` store entries after an upgrade or removal make a vendored `scan` exit 1, put an `unpinned` row in hosted `redirect.patches[]`, and get patched and attested in agent mode (commented on #599). Upgrading a vendored package loops the same way on every npm-family lock (handed to npm). #1116 still reproduces. The #1050 prune GC on live vendored projects passes across 1.2.23 / 1.3.9 / 1.4.2 × text / lockb × single / workspace × hoisted / isolated. See the run 32 section below.

Run 33 (new main `a845bf9`: #1039 staged, atomic vendored → hosted takeover, #1043, #1021): no new bugs. The #1039 takeover passes on Bun: a partial takeover where hosted refuses one purl (grant `denied`, or no sha512 → `redirect_bun_missing_sha512`) keeps that purl vendored byte for byte (`redirect_takeover_kept_vendored`, artifact and member mirrors intact) and takes over the rest, the dry run predicts it exactly and writes nothing, and a later re-run completes the takeover (text + lockb, single + workspace, 1.1.39 / 1.2.23 / 1.3.9 / 1.3.10 / 1.4.2). A hosted takeover also rescues a #1116-broken clone. A SIGKILL sweep found only PRE / POST / journal-recoverable states; a kill between the commit and the deferred artifact deletions leaves inert orphan artifacts (Known non-bugs). #1132 and #1116 still reproduce. See the run 33 section below.

## Coverage matrix

| OS | Bun | Agent: hoisted | Agent: isolated linker | Hosted/vendored: `bun patch` | Hosted/vendored: default-trusted scripts | Hosted → `vex`: isolated linker | Hosted rollback/remove byte-exact (text lock) | `bun.lockb` takeover ⇄ revert |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.39 / 1.1.40 | pass (1.1.39; run 12) | n/a | untested | untested | n/a | pass (v0 hosted + vendored; lockb refuses / semantic, as documented; run 12) | pass (1.1.39 single; workspace takeover refuses, documented; run 23) |
| Linux | 1.1.45 | untested | n/a | untested | pass | n/a | pass (v0) | pass (semantic; run 10) |
| Linux | 1.2.23 | pass | pass (opt-in; run 9; peer variants run 21) | pass (#367 fixed, run 28) | pass | pass, but fail #599 after an in-place reinstall | pass (v1 single + workspace; run 21) | pass (semantic; workspace takeover refuses, documented; run 21) |
| Linux | 1.3.0–1.3.4 | pass (1.3.0, 1.3.4) | pass (1.3.0, 1.3.4; run 9) | untested | pass | pass (1.3.0, 1.3.4; run 9) | pass (single: hosted + vendored; workspace: hosted, vendored refuses as documented) | pass (1.3.4 single + isolated workspace, semantic; run 23) |
| Linux | 1.3.10 | pass (workspace; run 24) | pass (workspace; run 24) | untested | untested | untested | pass (v1 workspace hoisted + isolated; single vendored + superseding uuid + revert byte-exact; run 24) | pass (single + isolated workspace, semantic; run 23) |
| Linux | 1.3.5–1.3.9 | pass (1.3.9; run 14) | pass (1.3.9; run 14; peer variants run 21); fail #1084 (1.3.9, run 29) | fail #367 (1.3.9) | fail #371 | untested | pass (1.3.9 v1 single + workspace; run 21) | pass (1.3.9 semantic; workspace takeover refuses, documented; run 21) |
| Linux | 1.3.14 | pass | pass (run 9) | fail #367 | fail #371 | pass fresh; fail #599 in place | pass (v1, workspace, catalog) | pass (semantic; vendored lockb isolated workspace too; run 10) |
| Linux | 1.4.2 | pass; fail #635 with `globalStore`; fail #626 (first-party workspace member) | pass (run 9; peer-hash entries, symlink backend); fail #1084 (rollback after a superseded agent → hosted migration, run 29) | pass for registry keys (#367 fixed, text + lockb, run 28); fail #1019 for a `bun patch` made after rewiring | fail #371 | pass fresh (text + lockb workspace); fail #599 in place | pass (v2, alias, overrides) | pass (semantic; not byte-exact, see Known non-bugs); workspace lockb → text migration healed by a re-run (#803 fixed, run 20); vendored re-run after a new dependent: fail #861 (isolated); `bun remove` → prune/revert: fail #1132 (lockb, all versions; run 32) |
| macOS | 1.2.23 | pass | fail #366 | fail #367 | untested | fail #405 | untested | untested |
| macOS | 1.3.4 / 1.3.5 | untested | untested | untested | pass / fail #371 | untested | untested | untested |
| macOS | 1.3.14 / 1.4.2 | pass | fail #366 | fail #367 | fail #371 (1.4.2) | fail #405 | untested | untested |
| Windows | 1.2.23 | pass | fail #366 | fail #367 | untested | fail #405 | untested | untested |
| Windows | 1.3.4 / 1.3.5 | untested | untested | untested | pass / fail #371 | untested | untested | untested |
| Windows | 1.3.14 / 1.4.2 | pass | fail #366 (bunfig) | fail #367 | fail #371 (1.4.2) | fail #405 (bunfig + default workspace) | untested | untested |

### Isolated-store edge cases after #496 (run 9, Linux)

| Bun | agent: peer-hash `+<hash>` entries | agent: `--backend=symlink` | hosted `vex` fresh clone | hosted `vex` after in-place frozen reinstall (orphaned `.bun` entries) | vendored `vex` after in-place reinstall | bundled in a workspace member |
| --- | --- | --- | --- | --- | --- | --- |
| 1.4.2 | pass | pass (no write-through) | pass | fail #599 | false `vendored_tree_out_of_sync` (#599) | pass (hosted warns; vendored refuses) |
| 1.3.14 | untested | untested | pass | fail #599 | untested | untested |
| 1.2.23 | untested | untested | pass | fail #599 | untested | untested |
| macOS, Windows | untested | untested | untested | untested | untested | untested |

### Bun `globalStore` (machine-wide isolated store, Bun ≥ 1.3.14; run 10, Linux)

| Bun | config | agent: sibling project untouched by apply/rollback | agent: transitive `.bun` entries patched | hosted `vex` on stale/unpatched transitive | vendored |
| --- | --- | --- | --- | --- | --- |
| 1.4.2 | bunfig `globalStore = true` | fail #635 | fail #635 | fail #635 (verified) | pass (run 11: sibling untouched, `vex` verified, no false out-of-sync) |
| 1.4.2 | `BUN_INSTALL_GLOBAL_STORE=1` | fail #635 | fail #635 | untested | untested |
| 1.3.14 | bunfig / env | fail #635 | fail #635 | fail #635 | untested |
| 1.4.2 | bunfig `globalStore = true`, **hosted** isolated workspace | pass (run 23: sibling untouched, URL-keyed links) | n/a | pass (in-place `not_affected`; after rollback `vex` refuses) | — |
| 1.3.13 | bunfig (key ignored) | pass | pass | n/a | n/a |
| macOS, Windows | all | untested | untested | untested | untested |

### Hosted pins and registry credentials (run 10, Linux)
No `Authorization` header reaches the hosted tarball host for any of: bunfig default-registry token or basic auth, `.npmrc` host `_authToken`, global `_authToken`, `always-auth`, scoped `.npmrc`, `[install.scopes]` token, `NPM_CONFIG_TOKEN`. That holds on 1.4.2, 1.3.14, 1.2.23 and 1.1.45, cold-cache frozen installs: pass. Control: the same configs send `Bearer` to the configured registry.

### Platform-specific optional deps (run 10, Linux)
`os`/`cpu` meta (fsevents, @esbuild/darwin-arm64, @esbuild/linux-x64). The hosted rewrite keeps the meta, and Linux frozen installs fetch only linux-x64 (patched), on 1.1.45 v0 + lockb, 1.2.23, 1.3.14, 1.4.2 text + lockb: pass. Hosted rollback is byte-exact (1.4.2): pass. `minimumReleaseAge` with hosted pins (1.4.2): pass.

### Run 26 cells (Linux, main `9c43dfc`)

Fixture: a fake registry on its own origin (bunfig `[install] registry`) serving `hookpkg@1.0.0` (a `postinstall` that writes a file), `plainpkg` and `otherpkg`, plus the patch-API mock on a second origin. Oracle: fresh clone, cold `bun install --frozen-lockfile` (scripts enabled), the marker bytes, the postinstall's output file, `bun pm untrusted`, and `vex`.

| Cell | 1.2.23 | 1.3.9 | 1.4.2 |
| --- | --- | --- | --- |
| explicit `trustedDependencies: ["hookpkg"]`, hosted, text / lockb × single / workspace | pass | pass | pass |
| same, vendored | pass (text workspace refuses `vendor_bun_workspace_unsupported`, documented) | pass (same documented refusal on text workspace) | pass |
| no trust, rewire, then `bun pm trust hookpkg`, hosted + vendored × text / lockb (single) | untested | pass (script runs, `vex` attests) | pass |
| mixed modes + superseding uuid: vendored ×3 → `get plainpkg --mode hosted` → both hookpkg and plainpkg superseded → `scan --mode vendored` twice | pass (lockb single) | pass (text single); lockb isolated workspace: plainpkg stays hosted at the old uuid with `redirect_revert_failed` (documented: "workspace dependency behaviors it normalized … checkout remedy"), `vex` attests only the 2 vendored | pass (text + lockb single, text isolated workspace) |
| same, re-run `scan --mode hosted` twice | pass (lockb single; rollback refuses, documented) | pass (text single) | pass (text + lockb single, lockb isolated workspace) |
| cold frozen install with `--filter m1` / `--filter proj` / `--filter '!m1'` / `--filter './packages/*'` on hosted + vendored workspaces (text + lockb) | untested | pass | pass |

In every superseding cell the cold frozen install had the new markers, the postinstall ran, `vex` named the new uuids, `vendor --check` was clean, the stale artifacts were removed and the second re-run was a no-op. After `vendor --revert` + `rollback` the frozen install was unpatched; the lock differs from the pre-vendor one only by `""` in the registry slot of entries that went through hosted mode (the custom-registry case in Known non-bugs).

### Run 25 cells (Linux, main `9c43dfc`)

| Cell | Bun | Result |
| --- | --- | --- |
| Vendored, then `get <purl> --mode hosted` for one package: cold frozen, `vex` (vendored + redirected), `vendor --check`, `vendor --revert` keeps the hosted pin, `rollback` | 1.4.2 text v2 single + isolated workspace, 1.4.2 lockb single + isolated workspace, 1.3.9 text v1, 1.2.23 lockb | pass (text rollback byte-exact; lockb rollback refuses, documented) |
| Hosted, then `get <purl> --mode vendored` for one package: cold frozen, `vex`, `rollback` unwinds both | 1.4.2 text v2 single + isolated workspace, 1.4.2 isolated workspace lockb, 1.2.23 lockb | pass |
| `globalStore = true` + vendored isolated workspace lockb: cold frozen, `vex`, `vendor --check` | 1.4.2 | pass |
| Same + #861 trigger (new member, vendored re-run) | 1.4.2 | fail #861 (EEXIST 2/4, 1/3) |
| `overrides` / `resolutions` forcing the patched version: hosted + vendored | 1.4.2 text v2 + lockb, 1.2.23 lockb, 1.3.9 text v1 | pass |
| After hosted / vendored: `bun install --lockfile-only`, `--force`, `bun add <present>`, `bun remove <other>` | 1.4.2 text v2 + lockb | pass |
| `bun remove <vendored pkg>` → `vendor --check` | 1.4.2 text v2 + lockb (npm 10 too) | red with a no-op remedy; generic, handed to npm (related #900) |
| `get --mode agent` on a vendored package → scoped `rollback` → `bun install` | 1.4.2 lockb hoisted | patched bytes stay = #764; `vex` honest |

### Run 24 cells (Linux, main `9c43dfc`)

| Cell | Bun | Result |
| --- | --- | --- |
| Hosted workspace `bun.lockb` written by 1.2.0 (format 2), `bun add` by 1.4.2 (format 3), superseding uuid, lockfile-only hosted re-run, cold frozen install, `vex` | 1.2.0 writer; 1.4.2 reader | pass (`updates` names the new uuid, MARK2 installed, `vex` attests the new record's vuln; 1.2.0 can't read format 3, same as a socket-patch-free control) |
| Agent hoisted + isolated (text v1 workspace): apply, Bun cache stays unpatched, `rollback` | 1.3.10 | pass |
| Hosted text v1 workspace (hoisted + isolated): sha512 on every URL tuple, cold frozen install, `rollback` byte-exact | 1.3.10 | pass |
| Single text v1: hosted → vendored takeover, superseding-uuid vendored re-run, `vendor --revert` byte-exact | 1.3.10 | pass |
| 3 concurrent vendored `scan`s (text v2) | 1.4.2 | pass (one `lock_held`, the others serialize; `vendor --check` clean) |
| Vendored `bun.lockb` scan SIGKILLed at 5–60 ms: cold frozen install, re-run, `vendor --check`, `vendor --revert` (`bun pm hash-string` equals the original) | 1.4.2 | pass |
| Mixed-case legacy name `JSONStream@1.3.5`: hosted, vendored, `vex`, `vendor --revert`, agent + `rollback`, on text v2 + `bun.lockb` | 1.4.2 | pass |
| Catalogs (`catalog:` + named `catalog:old`) in an isolated v2 workspace: vendored, vendored → hosted takeover, `rollback` byte-exact | 1.4.2 | pass |
| `--dry-run` hosted / vendored on an isolated workspace `bun.lockb` (no writes); `get <purl> --mode vendored` (member copies written, only that package wired) | 1.4.2 | pass |
| Mixed per-package modes (vendored lockb, then `get <purl> --mode hosted` for one package) | 1.4.2 | blocked (the session's permission classifier refused the fixture step) |

### Run 23 cells (Linux, main `9c43dfc`)

| Cell | Bun | Result |
| --- | --- | --- |
| Vendored `bun.lockb` format 2, upgraded to format 3 by a 1.4.2 `bun add`: re-run, `vendor --revert`, scoped `rollback` / `remove`, vendored → hosted | writers 1.1.45 (single + workspace) / 1.2.0 (workspace); readers 1.4.2 / 1.3.9 / 1.2.23 | pass (revert matches the control hash) |
| `bun.lockb` hosted, hosted → vendored, vendored → hosted, `vendor` → `vendor --revert` | writers 1.1.39 / 1.3.4 / 1.3.10, single + workspace; readers writer + 1.4.2 | pass (1.1.39 workspace takeover refuses, documented) |
| `globalStore = true` + hosted isolated workspace: sibling project, in-place `vex`, `rollback` | 1.4.2 | pass |
| Text `bun.lock` with a UTF-8 BOM, or with no final newline: hosted, rollback, vendored, revert (byte-exact) | 1.4.2 | pass |
| #861 via `bun add` inside an existing member | 1.4.2 / 1.3.9 isolated lockb | fail #861 (commented) |
| Bun 1.4.3 canary | `1.4.2-canary.20261005.1` | blocked (session policy refused running an unreleased binary) |

### Run 22 cells (Linux, main `9c43dfc`)

| Cell | Bun | Result |
| --- | --- | --- |
| Multi-package `bun.lockb` (5 patches, scoped + nested `ms`): hosted, vendored, `vex`, semantic `vendor --revert` | writers 1.1.45 / 1.2.23 / 1.4.2; readers 1.1.45 / 1.2.23 / 1.4.2 | pass |
| Nested `ms@2.1.2` + direct `ms@2.1.3`, both patched: text v2 + lockb × hoisted + isolated × hosted + vendored; hosted `rollback pkg:npm/ms@2.1.2` keeps the other pin | 1.4.2 | pass |
| express tree (71 packages, 7 patches): hosted lockb, vendored lockb, hosted → vendored → `vendor --revert` | writers 1.1.45 / 1.2.23 (isolated) / 1.4.2 (isolated); readers writer + 1.4.2 | pass |
| Vendored non-workspace isolated lockb → `bun add` a new dependent → vendored re-run → 4× cold frozen | 1.4.2 | pass (no #861 duplicate outside workspaces) |
| Workspace members on different patched versions (`ms@2.0.0` / `ms@2.1.3`): hosted lockb, vendored lockb, vendored text v2, hosted text v1 | writers 1.1.45 / 1.2.23 / 1.4.2 (hoisted + isolated); readers 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 | pass |
| Scoped `remove pkg:npm/ms@2.0.0` on those vendored workspace lockbs: member copies removed, other version kept, `vendor --check` | 1.1.45 hoisted / 1.4.2 isolated | pass |
| Agent apply → `bun install --force` → `vex` refuses → `apply` re-patches | 1.4.2 hoisted + isolated | pass |

### Run 21 cells (Linux, main `9c43dfc`)

| Cell | Bun | Result |
| --- | --- | --- |
| Agent over isolated peer-variant entries (`+<hash>` ×2): apply, no cache write-through, `vex`, `rollback`; a new peer variant → `vex` refuses → `apply` patches only it | 1.4.2 / 1.3.9 / 1.2.23 | pass |
| File modes after the #858 write core: `bun.lock` / `bun.lockb` 0664 (hosted + vendored); agent bin file 0755 / 0777 through apply + rollback | 1.4.2 | pass |
| Hosted `rollback` byte-exact + frozen install, text v1 single + workspace | 1.2.23 / 1.3.9 | pass |
| `bun.lockb` hosted → vendored → revert; vendored → hosted → rollback refusal; single + workspace | 1.2.23 / 1.3.9 | pass (as documented) |
| Dual `bun.lock` + stale `bun.lockb`: hosted / vendored, `vex`, `vendor --check`, frozen | 1.4.2 | pass |
| Symlinked `bun.lockb` / `bun.lock`, vendored | 1.4.2 | pass (refused; text leaves an orphan artifact, handed to npm) |
| Hosted `scan` / `get --mode hosted` from an isolated workspace member | 1.2.23 / 1.3.9 / 1.4.2 | fail #884 (commented) |
| `bun.lock` + `package-lock.json` vendored → `vendor --check` | 1.4.2 | wrong message, no-op remedy (generic, handed to npm) |
| `bun.lock` wired + stale `package-lock.json` without the package → lockfile-only `vex` | 1.4.2 | attests (generic cross-lock rule, handed to npm) |

### Run 20 cells (Linux, main `6811b4e`)

| Cell | Bun | Result |
| --- | --- | --- |
| Vendored workspace `bun.lockb` → new member depending on the patched pkg → `bun install` → vendored re-run → fresh frozen install | 1.4.2 / 1.3.9 isolated | fail #861 (EEXIST, ~50%) |
| Same | 1.2.23 isolated, 1.4.2 hoisted, 1.4.2 text v2 isolated; hosted on 1.2.23 / 1.3.9 / 1.4.2 | pass |
| #803 heal (migrated by 1.4.2, then re-run): hosted + vendored; hosted rollback after the heal | writer 1.4.2 | pass |
| #803 heal shapes: scoped member, `packages/*/*`, dir with space/`ü`/`#`, peer workspace edge, nameless root, dir ≠ name | 1.4.2 | pass |
| `catalog:` + named `catalogs:` workspace `bun.lockb`: hosted, frozen by each reader | writers 1.4.2 / 1.3.9 / 1.2.23 | pass (takeover refuses, documented) |
| Vendored isolated catalog `bun.lockb`: frozen, `vex`, byte-exact revert; deleted member mirror → `vendor --check` / `vex` fail closed → `repair` | 1.4.2 | pass |
| #720: lockfile-only `bun.lockb` hosted supersede; lockfile-only vendored takeover | 1.4.2 | pass |
| Lockfile-only URL-only dependency (now inventoried): hosted / vendored | 1.4.2 text | pass (same as with `node_modules`) |
| #497 shape, lockfile-only default `vex` | 1.4.2 text | fail #497 (attests) |

### Run 19 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Vendored + `.gitignore` `*.tgz` / `vendor/` / `.socket/` → commit → fresh-clone frozen install | 1.4.2 text v2 + `bun.lockb`, 1.2.23 text v1, 1.1.45 `bun.lockb`, 1.4.2 v2 isolated workspace | fail #831 (scan exit 0, no warning; `vendor --check` 0 under `vendor/` / `.socket/`; `vex` fails closed) |
| `bun ci` on the #803 shape (workspace `bun.lockb` + `workspace:*`, hosted, migrated to text by 1.4.2) | 1.4.2 | fail #803 (control without socket-patch passes) |
| Superseding uuid on a hosted workspace `bun.lockb` re-serialized by a root `bun add`; fresh frozen install; `vex` | writers 1.4.2 / 1.1.45, readers writer + 1.4.2 | pass |
| Vendored clone with `core.autocrlf=true`: frozen, `vendor --check`, `vex`, `vendor --revert`, post-revert install | 1.4.2 / 1.2.23 text | pass (mixed EOL, see Known non-bugs) |
| Hosted clone with `core.autocrlf=true`: frozen, `vex`, `rollback` (CRLF kept), post-rollback install | 1.4.2 text v2 | pass |

### Run 18 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Lockfile-only hosted re-run with `--max-new-patches 1` over 2 hidden pins | 1.4.2 v2 | pass (nothing deferred or unwired; lock unchanged) |
| Workspace `bun.lockb` without inter-workspace deps → `--save-text-lockfile` by 1.4.2 → fresh frozen install | writers 1.1.45 / 1.4.2 | pass |
| Hosted `rollback` → `bun install`, workspace (hoisted default) | 1.2.23 v1 | fail #764 |
| `bun add` inside a workspace member after hosted | 1.2.23 / 1.3.14 text v1, 1.4.2 text v2 + `bun.lockb` | member pins dropped by Bun; re-run heals; no false `vex` (Known non-bugs) |
| Symlinked text `bun.lock`, hosted | 1.4.2 | pass (`redirect_symlinked_file_unsupported`, nothing written) |
| Scoped `rollback <purl>` with 2 hosted pins → frozen install; then full `rollback` byte-exact | 1.2.23 v1 / 1.4.2 v2 | pass |
| Superseding uuid on a hosted workspace `bun.lockb` re-serialized by `bun add` | 1.1.45 / 1.4.2 writers | blocked (session permission policy) |

### Run 17 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Hosted `bun.lockb` → `--save-text-lockfile` → hosted → vendored takeover → fresh frozen install → `vendor --revert` | 1.1.45 → 1.4.2 | pass (in-place reinstall afterwards = #764) |
| Hosted workspace `bun.lockb` → `--save-text-lockfile` → fresh frozen install | writers 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2, migrated by 1.4.2 | fail #803 (migrated by 1.3.14: pass) |
| Vendored workspace `bun.lockb` → `--save-text-lockfile` → fresh frozen install | writers 1.1.45 / 1.4.2, migrated by 1.4.2 | fail #803 |
| Lockfile-only `get <purl> --mode hosted` picks up a superseding uuid; frozen install; `rollback` | 1.4.2 v2 | pass |

### Run 16 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Hosted `bun.lockb` → `bun install --save-text-lockfile`: pins kept, install patched, `list`, `rollback`, fresh frozen install | writer 1.1.45, migrated by 1.4.2 | pass |
| Vendored `bun.lockb` → `--save-text-lockfile`: `vendor --revert` / `rollback` / hosted takeover | writers 1.1.45 / 1.2.23 / 1.4.2 × migrated by 1.2.23 / 1.4.2 | fail #784 |
| Same, then a superseding re-vendor → `vendor --revert` → `bun install` | 1.1.45→1.4.2, 1.2.23→1.3.14, 1.4.2→1.4.2 | fail #784 (exit 0, still vendored); controls (text from the start, unmigrated lockb) pass |
| Hosted workspace, fresh frozen `--filter <name>` / `--filter ./path` / `--production` | 1.2.23 / 1.3.14 / 1.4.2 | pass |
| `remove <purl>` → advised frozen install, hoisted, hosted + vendored | 1.4.2 | fail #764 (no warning at all) |

### Run 15 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| `bun.lockb` meta hash, numeric/alphanumeric prerelease pairs (`beta.2`/`beta.10`, `1`/`alpha`, `rc.1`/`rc.1.0`, `x.9`/`x.10`/`x.100`): hosted + frozen installs | writers 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 | pass |
| Patched package with `optionalPeers`, `optionalDependencies`, `bin`; npm aliases beside the direct copy: hosted, frozen install, `vex` | text 1.2.23 / 1.3.9 / 1.4.2; lockb 1.1.45 / 1.4.2 | pass |
| Agent ⇄ hosted takeovers, then `vex` / `apply` / `rollback` | 1.4.2 | pass |
| Hosted scan → in-place warm frozen install (hoisted); superseding uuid in place | 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2; 1.4.2 | pass |
| `rollback` / `vendor --revert` → advised in-place `bun install` restores upstream bytes, hoisted | 1.1.45 (lockb vendored) / 1.2.23 / 1.3.9 / 1.3.14 / 1.4.2 | fail #764 |
| Same, isolated linker | 1.2.23 / 1.4.2 | pass |

### Run 14 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Prerelease / build-metadata (`+`) / legacy-uppercase / scoped dotted names: hosted, vendored, agent (isolated), `vex`, rollback, `vendor --revert` | 1.4.2 text v2 | pass |
| Same five on `bun.lockb`: hosted, frozen installs by each reader, hosted → vendored → revert | writer 1.1.45; readers 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 | pass (revert semantic) |
| Agent / hosted / rollback | 1.3.9 v1, isolated | pass |
| Root `X@1.0.0-beta.1` + nested `X@1.0.0` (also under a scoped parent), text lock | 1.4.2 | pass |
| Same pair in `bun.lockb` (patch on any package) | writers 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 | fail #739 (hosted exit 0, vendored exit 1; v4.0.0 passes) |
| Agent mode with a workspace member / `link:` target matching a patched `name@version` | 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 (hoisted + isolated) | fail #626 (npm-owned; `file:` passes, hosted / vendored safe) |

### Run 13 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Lockfile-only hosted re-run picks up a superseding patch | 1.4.2 text v2, 1.3.14 v1 workspace, 1.1.45 `bun.lockb` | fail #720 (with `node_modules`: pass) |
| Lockfile-only `scan --mode vendored` over hosted pins (takeover) | 1.4.2 text v2, 1.1.45 `bun.lockb` | fail #720 (`vendor` command: pass) |
| Lockfile-only vendored re-run picks up a superseding patch | 1.4.2 text v2 | pass |
| SIGKILL during hosted → vendored takeover (52×) and vendored → hosted (30×) | 1.4.2 text v2 | pass (installable, honest `vex`, exact heal) |
| SIGKILL during agent apply on an isolated workspace (~200×) | 1.4.2 | pass (no torn files; heals with `apply` or a `--json` re-run) |
| `repair` on a vendored `bun.lockb` isolated workspace (deleted / corrupt artifact) | 1.1.45 writer, 1.4.2 reader | pass |
| `bun ci` and `--production` frozen installs with hosted pins | 1.4.2 v2, 1.3.14 v1 | pass |

### Run 12 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Text v0 + `bun.lockb`: hosted / vendored scan, frozen installs, `vex`, idempotent re-run, rollback / revert; agent scan → `vex` → rollback | 1.1.39 (oldest in range), 1.1.40 | pass |
| `bun.lockb` with `overrides` + `trustedDependencies`, hosted and vendored | writers 1.2.23 / 1.3.9; readers 1.2.23, 1.3.9, 1.3.10, 1.3.14, 1.4.2 | pass |
| v2 isolated workspace, member dirs `a b ü` and `c#d`, scoped patched dep: hosted, hosted → vendored, byte-exact `vendor --revert`, scoped `remove` | 1.4.2 (text); 1.4.2 lockb read by 1.2.23 / 1.3.14 / 1.4.2 | pass |
| `get` by CVE / GHSA / UUID / PURL / scoped name, hosted + vendored | 1.4.2 | pass |
| SIGKILL mid `scan` (hosted, vendored), mid `rollback`, mid `vendor --revert`; then re-run | 1.4.2 | pass (every intermediate lock installable and attested consistently; only a 0-byte stage temp file is left over) |
| Vendored artifact deleted or corrupted → `vex` skip → `repair` rebuilds | 1.4.2 | pass |
| `--offline` / `--prefer-offline` with hosted pins + warm registry cache | 1.4.2 | pass (`--offline` fails closed) |
| Bun auto-migration of a hosted `yarn.lock` | 1.4.2 | fail-closed until a re-run of `scan --mode hosted` heals it (same as `package-lock.json`) |
| Bun auto-migration of a hosted `pnpm-lock.yaml` | 1.3.14 / 1.4.2 | Bun fails with `IntegrityCheckFailed` (see Known non-bugs) |
| Digest-less hosted re-save after `bun add` → re-run re-pins; lockfile-only `vex` attests nothing without a pin | 1.2.23 / 1.3.9 (1.3.10 keeps the digest) | pass |
| `ignorePaths` over workspace members (hosted + agent) | 1.3.14 text v1, 1.1.45 lockb | pass |
| Multi-project policy (`includePaths`, `minSeverity` flag > file, `!/tests/`) | 1.1.45 lockb | pass |

### Run 11 cells (Linux)

| Cell | Bun | Result |
| --- | --- | --- |
| Hosted text lock, patched package with `bin` (semver): meta kept, `.bin` linked after frozen install | 1.4.2 (v2) | pass |
| Hosted `bun.lockb` (1.1.45 writer) with `bin` + scoped packages, frozen install by each reader | 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2 | pass |
| `bun update` drops hosted pins; `vex` then refuses (`manifest_not_found`), no false attestation | 1.4.2 | pass |
| v0 text lock (hosted and vendored), then a plain install migrating it to v1; pins survive; `rollback` / `vendor --revert` after the migration | 1.2.23 / 1.3.14 / 1.4.2 | pass |
| Name-colliding alias (`"left-pad": "npm:is-number@6.0.0"`), hosted + vendored | 1.4.2 | pass (agent: #356) |
| v2 isolated workspace with nested version keys: hosted → vendored takeover → `vendor --revert` (byte-exact pre-hosted lock) | 1.4.2 | pass |
| `bun.lockb` workspace with nested version keys, hosted (writers 1.1.45 and 1.4.2) | readers 1.1.45–1.4.2 | pass (1.1.45 can't read a 1.4.2 lockb, Bun limitation) |
| Concurrent hosted scans (`lock_held`); lockfile-only hosted `vex` | 1.4.2 | pass |
| Bun auto-migration of a hosted `package-lock.json` | 1.4.2 | fail-closed until a re-run of `scan --mode hosted` heals it (see Known non-bugs) |

### Global mode (`-g`, agent; run 3)

| OS | Bun | default layout: scan report / apply / vex / rollback / get | `BUN_INSTALL_BIN` set | `BUN_INSTALL_GLOBAL_DIR` set | npm-installed bun (shim only) | `-g --mode hosted` refusal |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | pass (1.4.2) | pass |
| macOS | 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | pass | pass |
| Windows | 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | fail #434 (`bun.cmd`) | pass |
| Windows | 1.1.45 / 1.2.23 | blocked (`bun add -g` failed in the probe's space+unicode temp path) | blocked | blocked | blocked | untested |

Untested: a non-writable global dir, a symlinked `BUN_INSTALL`, and Bun 1.0.x.

### Bundled dependencies (`bundled: true` lock entries; run 4)

| OS | Bun | lock | hosted scan warns/skips | vendored scan warns/skips | bundled copy patched after frozen install | vendored `vex` | hosted `vex` | hosted `vex --no-verify` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 | text v0 / lockb | fail #469 (lockb: pass after #472, run 9) | fail #469 (lockb: pass, run 9) | fail #469 | fail #469 (attests; lockb: pass, run 9) | pass (`not_applied`) | fail #469 (lockb: pass, run 9) |
| Linux | 1.2.23 / 1.3.14 | text v1 | fail #469 | fail #469 | fail #469 | fail #469 | pass | fail #469 |
| Linux | 1.4.2 | text v2 / lockb | pass (run 9, #472) | pass (run 9) | n/a (warned) | pass (run 9) | pass | pass (run 9) |
| macOS, Windows | all | all | untested | untested | untested | untested | untested | untested |

### Non-registry copies of a patched `name@version` (run 5, Linux)

| Bun | lock | URL tgz + nested registry copy: scan warns | root copy patched after frozen install | vendored `vex` | hosted `vex` | hosted `vex --no-verify` | URL-only refusal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.45 | text v0 | fail #497 | fail #497 | fail #497 (attests) | pass (`not_applied`) | fail #497 | untested |
| 1.2.23 | text v1 | fail #497 | fail #497 | fail #497 | pass | fail #497 | untested |
| 1.3.14 | text v1 | fail #497 | fail #497 | fail #497 | pass | untested | untested |
| 1.4.2 | text v2 (URL and `file:` tgz) | fail #497 | fail #497 | fail #497 | pass | fail #497 | pass |
| 1.1.45 (read by 1.1.45 / 1.2.23 / 1.4.2) | `bun.lockb` (URL tgz; run 6) | fail #497 | fail #497 | fail #497 | pass | fail #497 | untested |
| any | `github:` tuples | untested | untested | untested | untested | untested | untested |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested |

### `socket.yml` policy and staged rollout (run 6, Linux)

| Bun | lock | hosted `maxNewPatches: 1` advance | vendored `maxNewPatches: 1` advance | vendored → hosted takeover under cap | `ignorePackages` keeps pin | `enabled: false` writes nothing | hosted upgrade (new uuid) | rollback after upgrade |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.45 | lockb (workspace) | pass | untested | untested | pass | pass | pass | n/a (refuses, documented) |
| 1.3.14 | text v1 (workspace) | pass | untested | untested | untested | untested | pass | pass (byte-exact) |
| 1.4.2 | text v2 (workspace) | pass | pass | pass | pass | pass | untested | untested |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested | untested |

### `socket.yml` across several independent Bun projects in one repo (run 7, Linux)

| Bun | lock | `includePaths` (hosted, PATH glob) | shared `maxNewPatches` across dirs | `minSeverity` flag > env > file | `ignorePaths` keeps pins byte-identical | `!/tests/` re-include | `**/bun.lockb` marker | vendored PATH glob |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.4.2 | text v2 | pass | pass | pass | pass | pass | n/a | pass |
| 1.1.45 | lockb | untested | untested | untested | untested | untested | pass | n/a |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested | untested |

Agent mode applies path policy only at the scan root, so nested independent projects are always patched. That's generic, not Bun-specific: handed to npm (`entries/npm/20261002T072532Z-from-bun.md`).

### Workspace members under ignored paths, and growth after a scan (run 8, Linux)

| Bun | lock | `tests/` member: agent | `tests/` member: hosted (frozen patched) | `ignorePaths` over members keeps them (agent / hosted / vendored) | rollback / revert byte-exact | re-run rewires a newly added registry copy | dual `package-lock.json` + `bun.lock` hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.4.2 | text v2 | pass | pass | pass | pass | pass | pass (rollback byte-exact, `.npmrc` removed) |
| 1.3.14 | text v1 | untested | pass | untested | untested | untested | untested |
| 1.1.45 | lockb | untested | pass | untested | n/a (refuses, documented) | pass | untested |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested |

Between a scan and its re-run, an unwired registry copy of a patched `name@version` in the same lock is still attested by vendored `vex` and by hosted `vex --no-verify`. npm does the same, so it's handed to npm (`entries/npm/20261002T133747Z-from-bun.md`), not filed as a Bun bug.

Also passing in run 6: a dual-lock checkout (`bun.lock` + a stale `bun.lockb`, where Bun ≥ 1.2 reads `bun.lock` and hosted rewrites only it), and global mode with a symlinked `BUN_INSTALL` (1.4.2: agent scan, `vex -g`, `rollback -g`).

### Lock-shape edge cases (run 5, Linux)
- CRLF `bun.lock` + CRLF `package.json` (1.1.45 v0, 1.3.14, 1.4.2): hosted scan → frozen install → `rollback`, and vendored → `vendor --revert`. Both byte-exact: pass.
- `bun install --yarn` (sibling `yarn.lock`), on 1.1.45 lockb, 1.2.23 and 1.4.2: hosted rewires both locks; lockb `rollback` refuses and touches neither file: pass.
- `[install.scopes]` custom-registry scope (1.3.14, 1.4.2): hosted rewrite and byte-exact rollback: pass.
- 1.1.45 binary workspace lock, hosted, read by 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2. Frozen installs are patched, the takeover refuses as documented, and `vex` is correct: pass.
- `bun add` after hosted (all four versions; the pins survive) and after vendored (digest-less re-save on < 1.3.10, healed by the re-run): pass.

### Takeovers and vendored VEX (run 4, Linux)
- Hosted → vendored on a v1 workspace lock (1.3.14): pass. Refuses before any write; dry-run parity is as documented.
- Vendored + isolated linker, stale tree → `vendored_tree_out_of_sync` is missing (1.4.2): fail, under #405 (comment). Hoisted control: pass.

Other passes (Linux, 1.4.2 unless noted):
- Run 1: agent `scan --global`, and the (pre-v5) `setup` hook.
- Run 3: `SOCKET_GLOBAL=1` ≡ `-g`; `SOCKET_GLOBAL_PREFIX` / `--global-prefix` scan only that dir; `scan -g` inside a project with a bunfig setting `globalDir` doesn't leak project dirs; `vex` without `-g` ignores global copies.
- Run 2:
  - Agent scan → vex → rollback, with no cache write-through.
  - `remove`, `repair` and `list` on hosted pins.
  - Hosted `bun.lockb` idempotency, `--dry-run`, and the rollback refusal.
  - Vendored `catalog:` and `overrides`.
  - Lockfile-only vendored scan on 1.1.45 v0 with a CRLF + BOM `package.json`.
  - A corrupt served tarball rejected on 1.3.9, 1.3.10 and 1.4.2, text + lockb.

### Run 27 (Linux, main `9c43dfc`)
| Cell | Bun | Result |
| --- | --- | --- |
| Hosted/vendored rewire of a scoped package with `preinstall`/`install`/`postinstall` + `bin`, and an unscoped preinstall-only package; `trustedDependencies`; cold frozen install runs the same scripts, links `.bin`, is patched, `vex` attests | 1.2.23 / 1.3.9 / 1.4.2 × text / lockb × single / workspace (pre-v2 text workspace vendored refuses, documented) | pass |
| Same, untrusted project (no `trustedDependencies`): no scripts run before or after the rewire | 1.2.23 / 1.3.9 / 1.4.2 × text / lockb | pass |
| `bun pm trust` after rewiring; `--frozen-lockfile --filter` (`m1`, `proj`, `!m1`, `./packages/*`) | 1.2.23 | pass |
| Plain (non-frozen) `bun install` on a rewritten `bun.lockb` leaves it byte-identical (same `bun pm hash`) | 1.2.23 / 1.3.9 / 1.4.2, hosted + vendored, single + workspace | pass |
| Hosted / vendored / agent cells, the hosted→vendored→revert→hosted→rollback chain | 1.4.3-canary.1 (text v2 + lockb) | pass (lockb rollback refuses, documented) |
| sha1-only package (registry has `shasum`, no `integrity`): hosted / vendored rewire + frozen install | 1.2.23 / 1.3.9 / 1.4.2 × text / lockb | pass |
| Hosted text-lock rollback / remove / takeover-revert with a bunfig custom registry, then a cold frozen install | 1.1.45 / 1.2.23 / 1.3.6 | **fail #992** |
| Same | 1.3.7 / 1.4.2 | pass (only the `""` diff) |

### Run 28 (Linux, main `db83f01`)
| Cell | Bun | Result |
| --- | --- | --- |
| #992 re-triage: hosted rollback with bunfig registry → cold frozen install | 1.2.23 | fail #992 (still) |
| #861 re-triage: isolated `bun.lockb` workspace, vendored re-run after a new member | 1.4.2 | fail #861 (6/8 EEXIST) |
| #367: registry-keyed `bun patch` (plain + scoped) then hosted / vendored | 1.2.23 / 1.4.2 text, 1.4.2 lockb | pass (warn / refuse, user patch kept, siblings rewired) |
| `bun patch` made after a hosted or vendored rewire (key `name@<url or vendor path>`), then a superseding re-run / takeover / rollback / revert | 1.4.2 text + lockb | **fail #1019** |
| Same state | 1.2.23 / 1.3.9 | n/a (Bun's `bun patch --commit` crashes on URL-resolved packages) |
| #884: hosted `scan` from a workspace member | 1.3.9 / 1.4.2 isolated | pass (`redirect_workspace_lockfile_elsewhere`, exit 1, nothing written) |
| #831: vendored with `*.tgz` / `.socket/` in `.gitignore` | 1.4.2 text + lockb | pass (`*.tgz` kept via nested negation; `.socket/` fails closed) |
| #963: hosted text-v1 workspace → refused `scan --mode vendored` | 1.2.23 / 1.3.9 | pass (hosted pins kept, frozen install patched) |

### Run 29 (Linux, main `05ecc6e`)
| Cell | Bun | Result |
| --- | --- | --- |
| #992 re-triage: hosted rollback with bunfig registry → cold frozen install | 1.2.23 | fail #992 (still) |
| #934: agent A → hosted B (superseding) → `bun install` → rollback / remove, hoisted text lock | 1.4.2 | pass (`rollback_record_superseded`, exit 0, fresh frozen install ORIGINAL; a failed registry fetch → exit 1, and the retry heals) |
| Same, `bun.lockb` | 1.4.2 | hosted leg refuses with the documented `git checkout -- bun.lockb` remedy; record A dropped |
| Same, isolated linker | 1.4.2 / 1.3.9 | **fail #1084** (the A-patched orphan store entry is relinked; record and blobs dropped) |
| Control: agent A → hosted A → rollback, isolated | 1.4.2 | pass (orphan restored) |
| agent A → vendored A or B → rollback, isolated | 1.4.2 | fail (A-patched orphan relinked); commented on #764 |
| socket-patch 4.0.0, agent A → hosted B → rollback, isolated | 1.4.2 | exit 1, record kept (the #933 behaviour) |

### Run 30 (Linux, main `fe8455d`)
| Cell | Bun | Result |
| --- | --- | --- |
| Hosted `scan` / `get <uuid>` and vendored `scan` from a workspace member holding a stray `bun.lock` / `bun.lockb` (the root `bun.lock` governs) | 1.2.23 (hoisted, text + lockb), 1.3.9 (isolated), 1.4.2 (isolated + hoisted, text + lockb) | **fail #1101** (exit 0, the member lock is pinned or vendored, frozen installs unpatched, `vex` not_affected from a hoisted or lockfile-only member) |
| Same, PR #1095 head `cddf38d` | 1.4.2 hoisted, hosted + vendored | fail (#1095 keeps the Bun shortcut) |
| Same, release 4.0.0 | 1.4.2 hoisted | fail (not a regression) |
| #1073: hosted `scan` from a member, object-form `workspaces.packages` = `packages/{a,b}` / `packages/[a-c]` / `packages/**` / `./packages/a/` | 1.4.2 isolated | pass (`redirect_workspace_lockfile_elsewhere`) |
| `!packages/a` negation: Bun's member set | 1.1.39 / 1.2.0 / 1.2.23 include `a`; 1.3.0 / 1.3.4 / 1.3.9 / 1.4.2 exclude it | informational |
| Hosted `scan` / `get` from that negated member | 1.2.23 isolated: exit 0, `redirected: 0`, `redirect_npm_no_lockfile` (×2); 1.1.39 / 1.2.23 hoisted `get`: same | **fail**, commented on #1097 |
| Extglob `packages/@(a\|b)` | 1.2.23 / 1.4.2 | n/a (`bun install` rejects the package.json) |
| Symlinked `bun.lockb` / `bun.lock`, vendored `--dry-run` vs wet, plus hosted wet | 1.4.2 | pass (lockb dry run: `would_refuse vendor_bun_lockb_invalid`; text dry run: `vendor_would_refuse_symlinked_file`; wet runs exit 1 with the link and its target untouched; hosted `redirect_symlinked_file_unsupported`) |

### Run 31 (Linux, main `829d0af`)
| Cell | Bun | Result |
| --- | --- | --- |
| Hosted A → hosted B (superseding) → `remove B` / `rollback`, text | 1.2.23 / 1.3.9 / 1.4.2 | pass (B pinned, fresh frozen B; then registry restored, original; byte-exact) |
| Same, `bun.lockb` | 1.2.23 / 1.3.9 / 1.4.2 | supersede pass; remove → documented `hosted_revert_failed` (git checkout remedy) |
| Vendored A → vendored B → `remove B`, text + lockb | 1.2.23 / 1.3.9 / 1.4.2 | pass |
| Vendored A → hosted B and hosted A → vendored B, then `remove B` / `rollback B` | 1.4.2 text + lockb | pass (lockb hosted end: documented refusal) |
| Workspace (root + member) hosted / vendored supersede + `remove B` | 1.4.2 text v2 + lockb | pass |
| #999 shape: vendored A, `get B --mode agent`, `remove B` | 1.4.2 text + lockb | pass (vendoring reverted; `get` warns "vendored at A but the manifest now records B", `vex` attests A only) |
| Hosted A + agent B (manifest), `remove B` / `rollback B`, hoisted + isolated | 1.4.2 | pass (#1035 `hosted_pins_matching` unpins A) |
| Same release under two keys (`left-pad` + `lp: npm:left-pad@1.3.0`), hosted / vendored supersede + remove | 1.4.2 text + lockb | pass (both keys re-pinned and restored; text byte-exact) |
| `bun.lock`/`bun.lockb` + leftover `package-lock.json` (#1044 table) | 1.4.2 | pass (hosted pins both; vendored wires bun + documented `vendor_multiple_lockfiles`; `vex` refuses with `patched_ref_unattributable`) |
| #1101 re-triage, text root | 1.4.2 | fail #1101 (still) |
| #1101, root `bun.lockb` + stray member `bun.lock` / `bun.lockb` | 1.4.2 | **fail**, commented on #1101 (lock-only member `vex` attests) |
| #1084 re-triage: agent A → hosted B → rollback / remove, isolated | 1.4.2 | fail #1084 (still) |
| #635: globalStore agent cross-project patching after #1042 | 1.4.2 | fail #635 (still) |
| #831 cell: vendored lockb workspace with root `*.tgz`, member `*.tgz`, member `.socket/` | 1.1.39 / 1.1.45 / 1.2.23 / 1.3.9 / 1.4.2 | **fail #1116** (member mirrors ignored; nested shape: ENOENT / hang / `--check` red) |
| Same, root `vendor/` | 1.4.2 | pass (refused `vendor_artifact_gitignored`) |
| Text `bun.lock` workspace with `*.tgz` | 1.4.2 | pass (no mirrors written) |

### Run 32 (Linux, main `9472be4`)
| Cell | Bun | Result |
| --- | --- | --- |
| #1050 prune GC on a live vendored project, then a fresh frozen install | 1.2.23 / 1.3.9 / 1.4.2 × text / lockb × single / workspace × hoisted / isolated (1.3.9+) | pass (pre-v2 text workspace vendoring refuses, documented) |
| Same after an unrelated `bun add` | same | pass |
| `bun remove` of a vendored package → `scan --prune` | text, 1.2.23 / 1.3.9 / 1.4.2 | pass (reverted; `vendor --check` green) |
| Same | `bun.lockb` 1.1.39 / 1.2.23 / 1.3.9 / 1.4.2, single + workspace, hoisted + isolated | **fail #1132** (prune / `vendor --revert` / `remove` drift-keep; check red) |
| Upgrade of a vendored package off the patched version → `--prune` / `vendor --revert` | text + lockb 1.1.39–1.4.2; npm control | fail, generic (handed to npm) |
| Orphan `.bun/<pkg>@<old>` after `bun add <pkg>@<new>` / `bun remove`: vendored / hosted / agent `scan`, `apply --check`, `vex` | 1.3.9 / 1.4.2 × text / lockb | fail (#599, commented: vendored exit 1, hosted `unpinned` row, agent patches + attests the orphan); hoisted control passes |
| #1116 re-triage: vendored lockb workspace, `*.tgz` ignored, fresh clone `vendor --check` | 1.4.2 | fail #1116 (still) |

### Run 33 (Linux, main `a845bf9`)
| Cell | Bun | Result |
| --- | --- | --- |
| Vendored → hosted takeover, one purl's grant `denied` | 1.4.2 text | pass (denied purl stays vendored; other taken over; fresh frozen install patched) |
| Same, one grant without sha512 (`redirect_bun_missing_sha512`), dry run then wet | 1.4.2 text + lockb single | pass (`redirect_takeover_kept_vendored`; dry run matches wet, writes nothing) |
| Same, lockb workspace with member mirrors | 1.2.23 / 1.3.9 / 1.4.2 | pass (kept purl's root + member mirrors intact, taken-over purl's removed; `vendor --check` green; frozen install patched) |
| Re-run after the grant is fixed, then `rollback` | 1.4.2 text / lockb / lockb workspace | pass (takeover completes, no `.socket` residue; text rollback byte-exact to the pre-vendor lock; lockb refuses with the documented checkout remedy) |
| Full takeover, lockb workspace | 1.1.39 | pass (previously a documented refusal; now supported and installs patched) |
| Takeover after `bun add` re-saved the vendored tuples digest-less | 1.2.23 / 1.3.9 text, 1.2.23 lockb | pass (no false drift refusal) |
| Text v1 workspace (vendored refuses, documented) → hosted | 1.3.10 | pass |
| SIGKILL sweep (2–68 ms) of a lockb-workspace takeover, then re-run | 1.4.2 | pass (PRE / POST / journal states all heal); kill after commit leaves inert orphan artifacts (non-bug) |
| Hosted takeover in a #1116-broken fresh clone (member mirrors missing) | 1.4.2 | pass (takes over cleanly) |
| #1132 re-triage | 1.4.2 lockb | fail #1132 (still) |
| #1116 re-triage | 1.4.2 lockb workspace | fail #1116 (still) |

## Backlog

0. **Maintainer request (partly covered in runs 3 and 6):** global (`-g`) mode for hosted patches. Still to do: a non-writable global dir must fail loudly (needs a probe; the sandbox runs as root); Windows 1.1.45/1.2.23 with an ASCII temp path; Bun 1.0.x. #443 is still open; re-test #434 (`bun.cmd`) on Windows now that #442 has landed. Checklist: the 20261001T040000Z entry.
1. A maintainer needs to delete the probe branches `bughunt/bun/20260930-default-trust`, `bughunt/bun/20260930-isolated-bunpatch`, `bughunt/bun/20261001-vex-isolated` and `bughunt/bun/20261001-global-dirs`. Deletion is still refused from the sandbox (runs 7–26; run 26: blocked by the session permission classifier), so no new probes until then. They still existed in run 31 (run 32 made no new probes).
2. #861: macOS/Windows; re-test when fixed (the existing-member `bun add` variant reproduces, run 23). #884 and #367 verified fixed on Linux (run 28). #1019: workspace members, Bun 1.4.0-written keys, macOS/Windows; re-test when fixed. Most open issues are claimed by draft #1009: re-test all of them when it merges.
3. #831: verified on Bun 1.4.2 text + `bun.lockb` (run 28). The workspace cell is now #1116; re-test it when fixed (also on the isolated linker, and with a `.gitattributes` / LFS rule). `vendor --check` after `bun remove` (#970). #764 follow-up: macOS/Windows. Real Windows autocrlf checkouts.
4. #861, #831, #784, #764, #635, #599 and #497: re-test when fixed. #626 on Bun once PR #634 merges. Also `globalStore` + workspaces and `globalStore` on macOS/Windows. (#605/#774 store copies on Bun peer-variant entries: pass, run 21.)
5. macOS/Windows re-runs of the #366 / #405 / #469 / #803 fixes (Windows isolated uses junctions).
6. #497 `github:` tuples (needs a probe).
7. Hosted rollback on real macOS and Windows checkouts.
8. Bun 1.4.3 when stable (1.4.3-canary.1 passes, run 27). #992: re-test when fixed, including `[install.scopes]` and `NPM_CONFIG_REGISTRY` variants and the 1.1.45 `remove` / takeover cells. (Lifecycle scripts and scoped packages with scripts on `bun.lockb`: pass, run 27.) (Mixed modes, `globalStore` + vendored workspace lockb: pass, run 25. Superseding uuids in mixed modes, explicit `trustedDependencies`, `bun pm trust`, `--filter`: pass, run 26.)
9. Digest boundary with a valid substitute tarball, 1.3.9 text lock vs 1.3.10 (low priority, documented limitation).
10. #1101: re-test when fixed (and macOS/Windows); the root `bun.lockb` variant is covered (run 31). #1097 Bun < 1.3 negation: re-test when fixed. #1084: a workspace (isolated by default on Bun ≥ 1.3), macOS/Windows; re-test when fixed. The vendored dry run's symlink check doesn't list `bun.lockb` (registry row without `VENDORED`; `wiring_paths`), so check a symlinked `bun.lockb` in a vendored dry run vs a wet run.
11. #1132: re-test when fixed (still reproduces on `a845bf9`) (plus `rollback`, isolated workspace members). `apply --check` (#1029) on Bun agent trees: the #599 in-place reinstall shape, `globalStore`, lockfile-only checkouts. Hosted `redirect.patches[]` rows on `bun.lockb`, workspaces and the #1101 shape.

12. #1039 takeover follow-ups: a superseding uuid during the takeover (vendored at A, hosted offers B), takeover with `globalStore`, and the multi-lock (`bun.lock` + `package-lock.json`) hosted run that commits unjournaled.

## Known non-bugs

- A SIGKILL between the #1039 takeover's journaled commit and its deferred artifact deletions leaves `.socket/vendor/npm/<uuid>/` dirs and Bun member mirrors that nothing references. The lock and ledger are consistent, the re-run doesn't delete them, and `vendor --check` / `repair` / a later re-vendor all ignore or reuse them. Inert, crash-only and generic, so not filed (run 33).

- `get <B> --mode agent` on a package vendored at A records B in the manifest and overwrites the installed (A-patched) copy with B's full content (non-strict "did not match … applied the full verified patched content"). It warns that the vendoring is still at A, and `vex` attests A only. Documented; use `--strict` (run 31).
- Mock fixture (run 31): the grant must return `sha512-`-prefixed integrity and a tarball URL on the mock's own origin. Bare base64 lands in `bun.lock` as-is (Bun warns "malformed integrity"), and the baked `patch.socket.dev` host is unreachable. Never name a shell loop variable `M`, because it clobbers the mock URL.

- A hosted `scan` from a **hoisted** workspace member (no member `node_modules`) reports `success` with `scannedPackages: 0` and no refusal, because there are no candidates to gate. It claims nothing, and npm behaves the same; `get <uuid>` from the same member is refused. Not filed (run 30).
- A refused wet vendored run on a symlinked `bun.lock` leaves unreferenced `.socket/vendor/npm/<uuid>/` artifacts. That's documented (CLI_CONTRACT `redirect_symlinked_file_unsupported`: "the artifacts written are unreferenced orphans") (run 30).

- Mock fixture: a mode-less `scan` is hosted by default and re-pins, so don't use it as a read-only check after a rollback. Use `--dry-run` or `list`. Also, `pkill -f <pattern>` kills the calling shell when the pattern is in its own command line, so toggle the mock through an HTTP endpoint instead (run 29).
- `scan_vendor_references` reads `bun.lockb` natively only when there's no `bun.lock` beside it, which matches Bun ≥ 1.2 (it reads `bun.lock` first). Not a bug (run 29).

- Vendored `scan --dry-run` previews a `bun patch`ed package (`patchedDependencies` `name@version`) as `would_vendor`, while the wet run refuses it `vendor_lock_entry_unsupported` (exit 1). That's documented scope: `would_refuse` predicts only the Bun preflight lock codes (CLI_CONTRACT `would_refuse` row; `scan/vendor_flow.rs:80` "outside the preflights are not predicted"). Run 28.
- Bun 1.2.23 / 1.3.9 `bun patch --commit` crashes (SIGILL) on a package resolved to a URL tarball. That's a Bun bug. Bun 1.4.2 works and keys the patch by the URL (#1019).
- Mock fixture: decode by-package purls twice (`%2540` for scoped names), or scoped patches look unpatched.

- A registry document with only a sha1 `shasum` and no `integrity` makes the hosted text-lock restore refuse with `the registry records no integrity` and the checkout remedy (fail closed, generic npm-family code). npmjs has backfilled `integrity` on old versions (minimist 0.0.8, left-pad 0.0.3, qs 0.6.6, lodash 1.0.0 all checked), so it's only reachable on bare private registries. Not filed (run 27).
- Lifecycle `prepare` doesn't run for registry or tarball dependencies, on any Bun version, with or without socket-patch.

- `patches-api.socket.dev` is blocked by the sandbox proxy. Mock the API. Also, the CLI's reqwest can't reach `registry.npmjs.org` from the sandbox (curl can), so hosted rollback/remove need `SOCKET_NPM_REGISTRY` pointed at a local passthrough. Without it you get `cannot restore … error sending request`, which is a sandbox artifact.
- Agent `rollback` → `missing_blob` when the mock serves no before-blob (fixture limit).
- v5 `rollback` removes the rolled-back entries from `.socket/manifest.json`, so a later `apply` is a success no-op (CLI_CONTRACT `rollback` row).
- Hosted `bun.lockb` pins: `rollback` / `remove` refuse with the `git checkout -- bun.lockb` remedy (documented). After a hosted → vendored → `vendor --revert` round trip, `bun.lockb` is semantically identical (same `bun pm hash` and yarn dump) but not byte-identical: its string buffer keeps the dead URLs. The doc promises a byte-exact *registry record*, not the whole file.
- Bun 1.2.23 workspaces default to the hoisted layout (isolated only via `linker = "isolated"`). From Bun 1.3.x a fresh workspace lock defaults to isolated.
- `setup` was removed in v5 (#277). The run-1 `setup` pass is obsolete.
- esbuild after rewiring is listed by `bun pm untrusted` but has no observable effect. Use better-sqlite3 to observe #371.
- Documented refusals (docs/testing/bun-compatibility.md): a version-0 workspace lock in hosted mode (`redirect_bun_workspace_unsupported`), a pre-v2 workspace lock in vendored mode (`vendor_bun_workspace_unsupported`), and missing digest enforcement for text-lock URL/local tuples on Bun < 1.3.10.
- Agent-mode npm aliases under Bun are #356 (npm-owned).
- `--global-prefix` must name the `node_modules` dir itself (`~/.bun/install/global/node_modules`). Its parent scans 0 packages; the flag is documented as the packages root.
- `-g` combined with `--mode hosted` is a clap-level conflict: plain-text error, exit 2, no JSON envelope even with `--json`. Consistent with other usage errors.
- Vendored `scan --dry-run` exits 0 with `status: success` and `would_refuse` while the real run exits 1 with `partial_failure`, for the same Bun preflight refusal. Documented (CLI_CONTRACT `would_refuse`).
- Vendored `vex` attests from the committed artifact even when the installed tree is stale. By design: only a `vendored_tree_out_of_sync` warning is owed.
- Hosted default `vex` on a bundled-copy project correctly refuses (`not_applied`). #469 is about vendored mode and `--no-verify`.
- `bun pm bin -g` ignores a project-local `bunfig.toml`, so `scan -g` inside a project can't be redirected by the project.
- Vendored, then `bun add`, on Bun < 1.3.10 re-saves the local tuples without `sha512`. That's documented ("Digest-less re-saves"): the vendored re-run reports `already_vendored` and re-pins the digest.
- Bun records `""` as the registry field of a tuple even when it came from an `[install.scopes]` or custom default registry, so rollback restoring `""` is correct.
- On a `bun install --yarn` project, hosted `rollback` restores `bun.lock` byte-exact but adds a `#<sha1>` fragment to Bun's `yarn.lock` `resolved` lines. It's semantically equivalent and yarn-classic's rewriter, so it isn't filed as a Bun bug.
- Mock fixture: build the patched tarball with a fixed gzip mtime. Otherwise a mock restart changes its sha512 and later installs fail `IntegrityCheckFailed`.
- `link:` deps need `bun link` registration, and `github:` deps don't resolve in the sandbox. Both are environment limits.
- `scan <workspace-member>` (e.g. `scan packages/a`) with vendored refusing `vendor_lockfile_missing` is pinned behaviour. The hosted side (`success`, 0 redirected) is NOT a non-bug any more: since run 21 it's tracked on #884 (the isolated-workspace Bun matrix is commented there).
- Mode-less `scan -g` is report-only. Use `--mode agent` to patch global copies. `-g` agent runs record the global copies in the cwd's `.socket/manifest.json` (by design).
- A v1/v2 text `bun.lock` can't be read by Bun 1.1.45 (`lockfile had changes, but lockfile is frozen`) even without socket-patch. When `bun.lock` and `bun.lockb` are both present, Bun ≥ 1.2 reads `bun.lock`.
- Mock fixture: `SOCKET_PATCH_SERVER_URL` must name the same origin across runs. A mock on another port makes the earlier pins non-hosted.
- A hosted scan at a repo root that is itself a Bun project crawls nested independent projects' `node_modules` and warns `redirect_bun_entry_not_found` for their packages (exit 0). They have their own locks: scan them by PATH (`scan '*/*' --mode hosted`).
- Mock fixture: agent mode needs a `blob/<hash>` route. Without it the result is `partial_failure`.
- Vendored scan on a Bun 1.3.x workspace (lockfileVersion 1) refuses `vendor_bun_workspace_unsupported`. That's the documented pre-v2 workspace limitation, and the lock is untouched.
- `vex` exit 2 `product_undetected` in a fixture without a package version or git origin: pass `--product` (fixture limit).
- Bun never prunes `node_modules/.bun` entries: after a dependency is removed, its store dir (and, on 1.4.2, the member link) stays. That's Bun behaviour. It only matters to socket-patch through #599.
- Agent `apply` on a workspace whose member links into an isolated store reports a duplicate `already_patched` skip per member-linked package (counts only, the bytes are right). pnpm behaves the same, so it's handed to pnpm (`entries/pnpm/20261002T193154Z-from-bun.md`).
- `scan -g` with `BUN_INSTALL_GLOBAL_DIR` set reports the Node global prefix's packages, not Bun's. That's #443, not a new bug.
- Hosted `vex` attests darwin-only packages (fsevents, @esbuild/darwin-*) on a Linux checkout where they're not installed: the lock pins patched bytes for every platform, so that's correct.
- Mock fixture: in proxy mode set both `SOCKET_PROXY_URL` and `SOCKET_PATCH_SERVER_URL`. Without the latter, hosted pins aren't recognized and `vex` reports `manifest_not_found`.
- Bun's auto-migration of a hosted `package-lock.json` writes `bun.lock` registry 4-tuples with the hosted URL in the registry slot (`["left-pad@1.3.0", "http://…/tok/<uuid>/left-pad-1.3.0.tgz", {}, "sha512-…"]`). Bun installs the patched bytes from them. socket-patch fails closed on that shape (`vex` → `patched_ref_unattributable` / `manifest_not_found`, `list` / `rollback` → `hosted_wiring_contested`, no writes), and a re-run of `scan --mode hosted` heals it into the canonical URL tuple. No false attestation, so not filed (run 11). The `vex` detail wording ("from elsewhere (not a Socket patch)") is inaccurate for this shape.
- `bun update` re-resolves hosted pins back to the registry. That's Bun behaviour, and `vex` correctly stops attesting.
- A 1.4.2-written `bun.lockb` can't be read by Bun 1.1.45 even without socket-patch.
- Bun's auto-migration of a hosted `yarn.lock` writes the same registry-slot 4-tuples as the `package-lock.json` case, plus a `#<sha1>` fragment. socket-patch fails closed, and a re-run of `scan --mode hosted` heals it (run 12).
- Bun's auto-migration of a hosted `pnpm-lock.yaml` (1.3.14, 1.4.2) ignores `resolution.tarball`, downloads the registry tarball and fails `IntegrityCheckFailed` against the patched sha512, writing no `bun.lock`. That's a Bun migration limitation and fails closed. Remedy: migrate first, then run `scan --mode hosted`.
- `get <pkg> --mode hosted` from inside a workspace member dir is a `success` no-op with `redirect_npm_no_lockfile`, the same as `scan <member>`: tracked on #884 since run 21. Run it from the root.
- A SIGKILLed `vendor --revert` can leave a 0-byte `.socket/vendor/.socket-stage-state.json-<uuid>` temp file. It's harmless; the next run heals the state.
- Plain (human) `scan --mode agent` doesn't re-apply patches the manifest already records (`[skip] … already recorded`, "run `socket-patch apply`"), while `--json` re-applies. It's generic, not Bun-specific: handed to npm (`entries/npm/20261003T193043Z-from-bun.md`). After an interrupted agent apply, use `socket-patch apply`.
- `scan --json` `apply.patches[].action` (`added` / `skipped`) is the manifest record's state, not whether files were written.
- `repair` doesn't recreate a deleted `socket-patch.vendor.json` sidecar. It's informational only (CLI_CONTRACT). A deleted `.socket/vendor/state.json` → `repair` `vendor_ledger_missing` (documented v5: restore it from VCS).
- An interrupted vendored → hosted takeover can leave registry tuples (unpatched install) until the re-run. `vex` doesn't attest them, and the re-run heals.
- Hosted rollback on a lock whose registry slot holds a full custom-registry tarball URL (Bun writes one for a non-default `[install] registry`) restores `""`. It's pinned by the `custom-registry` shape in `backtest-bun.py`, and the restored lock frozen-installs from the configured registry (run 14). The same holds after a vendored → hosted → vendored chain: `vendor --revert` restores `""` for any entry that passed through hosted mode, and full URLs for entries that were only ever vendored (run 26). **Correction (run 27):** that's only true on Bun ≥ 1.3.7. Bun 1.1.39–1.3.6 resolve `""` against npmjs, which is #992.
- Bun resolves a dependency on `X@2.0.0+build.6` to an installed `X@2.0.0+build.5`, because semver ignores build metadata. That's Bun behaviour.
- Bun copies `file:` directory deps into `node_modules`, so agent mode patches the copy, not the source. That's safe and not part of #626.
- Mock fixture: serve the npm registry from a different origin than `SOCKET_PATCH_SERVER_URL`. Otherwise the registry URLs Bun writes into `bun.lockb` look like hosted pins, and vendored `rollback` fails `hosted_wiring_contested` (run 15; with split origins it's `success`).
- The `bun.lockb` legacy (`link://`) meta-hash dialect isn't produced by any writer in range (≥ 1.1.39); numeric prerelease ordering in the current dialect matches Bun (run 15).
- A plain `bun install` with only a `bun.lockb` keeps the binary lock on 1.2.23 / 1.3.14 / 1.4.2. Only `--save-text-lockfile` migrates it (run 16).
- Release 4.0.0 refuses `scan --mode vendored` on a `bun.lockb` (exit 1), so it isn't a baseline for vendored-lockb cells (run 16).
- A path literal (`"m1": "packages/m1"`) in a text `bun.lock` with only registry tuples frozen-installs on 1.3.14 and 1.4.2. Only together with URL/local pins does 1.4.2 re-resolve, which is #803 (run 17).
- `bun add <pkg>` run inside a workspace member re-resolves that member's dependencies and drops its hosted pins back to registry tuples, on text v1/v2 and `bun.lockb` (1.2.23 / 1.3.14 / 1.4.2). A root-level `bun add` keeps them. That's Bun behaviour, like `bun update`: a re-run of `scan --mode hosted` heals it, and `vex` doesn't attest the dropped pin (run 18).
- A lockfile-only hosted re-run can't see existing pins (#720), so `maxNewPatches` neither counts nor defers them, and nothing is unwired (run 18).
- After `vendor --revert` in a `core.autocrlf=true` clone, the restored registry line in `bun.lock` is LF inside an otherwise CRLF working copy. Git normalizes it on commit (byte-exact to the pre-vendor commit) and Bun reads it, so it's cosmetic. Hosted `rollback` keeps CRLF on every line (run 19).
- Mock fixture: `pkill -f mock.py` also matches the calling shell, whose command line contains the heredoc. Kill the mock by pidfile.
- Vendored `bun.lockb` workspaces commit an identical tarball under every member's `.socket/vendor`, even members that don't use the package. That's deliberate (Bun 0.5.9–1.3 resolves workspace local tarballs relative to the declaring member, `bun_binary.rs:142`). A missing member copy fails closed (`vendor_workspace_artifact_missing`), and `repair` restores it (run 20).
- Bun refuses a workspace member that depends on the root package via `workspace:*` (`root@workspace:* failed to resolve`), so that #803-heal shape can't occur (run 20).
- Bun 1.3.9 can't frozen-install a text `bun.lock` written by 1.4.2 (`lockfile had changes`). That's cross-version Bun behaviour.
- `get <name> --mode hosted` with several installed versions (e.g. `ms@2.0.0` nested + `ms@2.1.3` direct) acts on only one: the package-name path searches just the best fuzzy match among installed purls, by design (`get.rs:2844`), and names it on stderr. It isn't Bun-specific. Use `scan` or a purl (run 22).
- Fixture: git-ignore `node_modules` before committing, or "fresh" clones aren't empty (run 22).
- `bun install --save-text-lockfile` on 1.4.2 deletes `bun.lockb`; `bun bun.lockb` prints the ACTIVE lock (the text one when both exist). Inspect a stale binary with `strings` (run 21).
- `vex` exit 2 `manifest_not_found` ("nothing to attest") after every patch is rolled back or reverted is correct (run 25).
- `get --mode agent` on an already-vendored package doesn't take it over: the manifest and the vendored ledger coexist, and a scoped `rollback` unwinds both (run 25).
