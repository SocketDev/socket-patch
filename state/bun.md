[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last updated: 2026-10-04 (run 14), main `045d7ec`, latest release 4.0.0, latest Bun 1.4.2.

Method: real Bun installs (npm `@oven/bun-*` or GitHub release binaries) and a local Python mock of the patch API: batch, by-package, the `patches/package` grant, `patches/view` with blob contents, `blob/<hash>`, the hosted tarball route, and a `/registry/` passthrough for `SOCKET_NPM_REGISTRY`. Set `SOCKET_PATCH_SERVER_URL` to the mock. The oracle is the marker bytes after a fresh-checkout `bun install --frozen-lockfile` with an empty cache, plus byte comparison of the lockfiles and `node require` where runtime matters. The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) already covers plain hosted and vendored shapes across Bun 0.8.1–1.4.2. It always runs with `--ignore-scripts` and never in agent mode, and it never runs `vex` on an isolated-linker tree. This ledger tracks what it doesn't.

Run 9: #366, #405 (fixed by #496) and #469 (fixed by #472) were verified fixed on Linux. Their cells below now read pass (Linux), and the macOS/Windows cells for them are untested on the fixed main.

Run 10: #599 still reproduces on `045d7ec`. New: #635 (Bun ≥ 1.3.14 `globalStore`).

Run 11 (main unchanged at `045d7ec`): #599 still reproduces. No new bugs. All the new cells pass: the run 11 section below, and the vendored row of the `globalStore` table.

Run 12 (main unchanged at `045d7ec`, so no re-triage): no new bugs. Bun 1.1.39, the oldest release in range, is now covered and passes. All the new cells pass: the run 12 section below.

Run 13 (main unchanged at `045d7ec`, so no re-triage): new #720. Lockfile-only discovery can't see hosted pins, so a hosted re-run in CI never picks up a superseding patch, and `scan --mode vendored` skips the takeover. Both report success. The other new cells pass: the run 13 section below.

Run 14 (main unchanged at `045d7ec`, so no re-triage): new #739. A `bun.lockb` holding `X@1.0.0` + `X@1.0.0-beta.1` is refused as a metadata-hash mismatch, and hosted exits 0 with nothing patched (a regression since 4.0.0). Bun cells added to #626 (agent mode overwrites first-party workspace members). The other new cells pass: the run 14 section below.

## Coverage matrix

| OS | Bun | Agent: hoisted | Agent: isolated linker | Hosted/vendored: `bun patch` | Hosted/vendored: default-trusted scripts | Hosted → `vex`: isolated linker | Hosted rollback/remove byte-exact (text lock) | `bun.lockb` takeover ⇄ revert |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.39 / 1.1.40 | pass (1.1.39; run 12) | n/a | untested | untested | n/a | pass (v0 hosted + vendored; lockb refuses / semantic, as documented; run 12) | untested |
| Linux | 1.1.45 | untested | n/a | untested | pass | n/a | pass (v0) | pass (semantic; run 10) |
| Linux | 1.2.23 | pass | pass (opt-in; run 9) | fail #367 | pass | pass, but fail #599 after an in-place reinstall | untested | untested |
| Linux | 1.3.0–1.3.4 | pass (1.3.0, 1.3.4) | pass (1.3.0, 1.3.4; run 9) | untested | pass | pass (1.3.0, 1.3.4; run 9) | pass (single: hosted + vendored; workspace: hosted, vendored refuses as documented) | untested |
| Linux | 1.3.5–1.3.9 | pass (1.3.9; run 14) | pass (1.3.9; run 14) | fail #367 (1.3.9) | fail #371 | untested | untested | untested |
| Linux | 1.3.14 | pass | pass (run 9) | fail #367 | fail #371 | pass fresh; fail #599 in place | pass (v1, workspace, catalog) | pass (semantic; vendored lockb isolated workspace too; run 10) |
| Linux | 1.4.2 | pass; fail #635 with `globalStore`; fail #626 (first-party workspace member) | pass (run 9; peer-hash entries, symlink backend) | fail #367 (text + lockb) | fail #371 | pass fresh (text + lockb workspace); fail #599 in place | pass (v2, alias, overrides) | pass (semantic; not byte-exact, see Known non-bugs) |
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
| 1.3.13 | bunfig (key ignored) | pass | pass | n/a | n/a |
| macOS, Windows | all | untested | untested | untested | untested |

### Hosted pins and registry credentials (run 10, Linux)
No `Authorization` header reaches the hosted tarball host for any of: bunfig default-registry token or basic auth, `.npmrc` host `_authToken`, global `_authToken`, `always-auth`, scoped `.npmrc`, `[install.scopes]` token, `NPM_CONFIG_TOKEN`. That holds on 1.4.2, 1.3.14, 1.2.23 and 1.1.45, cold-cache frozen installs: pass. Control: the same configs send `Bearer` to the configured registry.

### Platform-specific optional deps (run 10, Linux)
`os`/`cpu` meta (fsevents, @esbuild/darwin-arm64, @esbuild/linux-x64). The hosted rewrite keeps the meta, and Linux frozen installs fetch only linux-x64 (patched), on 1.1.45 v0 + lockb, 1.2.23, 1.3.14, 1.4.2 text + lockb: pass. Hosted rollback is byte-exact (1.4.2): pass. `minimumReleaseAge` with hosted pins (1.4.2): pass.

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

## Backlog

0. **Maintainer request (partly covered in runs 3 and 6):** global (`-g`) mode for hosted patches. Still to do: a non-writable global dir must fail loudly (needs a probe; the sandbox runs as root); Windows 1.1.45/1.2.23 with an ASCII temp path; Bun 1.0.x. #443 is still open; re-test #434 (`bun.cmd`) on Windows now that #442 has landed. Checklist: the 20261001T040000Z entry.
1. A maintainer needs to delete the probe branches `bughunt/bun/20260930-default-trust`, `bughunt/bun/20260930-isolated-bunpatch`, `bughunt/bun/20261001-vex-isolated` and `bughunt/bun/20261001-global-dirs`. Deletion is still refused from the sandbox (runs 7–13), so no new probes until then.
2. #739, #720, #635 and #599: re-test when fixed. #626 on Bun once PR #634 merges (isolated member links live under `packages/<member>/node_modules`). Legacy-dialect `meta_hash` with numeric prerelease identifiers (`beta.2` vs `beta.10`). #720 follow-ups: `get --mode hosted|vendored` on a lockfile-only hosted checkout, and `maxNewPatches` counting with hosted pins it can't see. Also `globalStore` + workspaces, and `globalStore` on macOS/Windows.
3. macOS/Windows re-runs of the #366 / #405 / #469 fixes (Windows isolated uses junctions).
4. #497 `github:` tuples (needs a probe); re-test #497 when fixed.
5. Hosted rollback on real macOS and Windows checkouts.
6. Digest boundary with a valid substitute tarball, 1.3.9 text lock vs 1.3.10 (low priority, documented limitation).

## Known non-bugs

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
- `scan <workspace-member>` (e.g. `scan packages/a`): hosted reports `success` with 0 redirected and `redirect_npm_no_lockfile`; vendored refuses with `vendor_lockfile_missing`. Pinned as today's behaviour in bun-compatibility.md ("Not measured"); scan the root instead.
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
- `get <pkg> --mode hosted` from inside a workspace member dir is a `success` no-op with `redirect_npm_no_lockfile`, the same as `scan <member>`. Run it from the root.
- A SIGKILLed `vendor --revert` can leave a 0-byte `.socket/vendor/.socket-stage-state.json-<uuid>` temp file. It's harmless; the next run heals the state.
- Plain (human) `scan --mode agent` doesn't re-apply patches the manifest already records (`[skip] … already recorded`, "run `socket-patch apply`"), while `--json` re-applies. It's generic, not Bun-specific: handed to npm (`entries/npm/20261003T193043Z-from-bun.md`). After an interrupted agent apply, use `socket-patch apply`.
- `scan --json` `apply.patches[].action` (`added` / `skipped`) is the manifest record's state, not whether files were written.
- `repair` doesn't recreate a deleted `socket-patch.vendor.json` sidecar. It's informational only (CLI_CONTRACT). A deleted `.socket/vendor/state.json` → `repair` `vendor_ledger_missing` (documented v5: restore it from VCS).
- An interrupted vendored → hosted takeover can leave registry tuples (unpatched install) until the re-run. `vex` doesn't attest them, and the re-run heals.
- Hosted rollback on a lock whose registry slot holds a full custom-registry tarball URL (Bun writes one for a non-default `[install] registry`) restores `""`. It's pinned by the `custom-registry` shape in `backtest-bun.py`, and the restored lock frozen-installs from the configured registry (run 14).
- Bun resolves a dependency on `X@2.0.0+build.6` to an installed `X@2.0.0+build.5`, because semver ignores build metadata. That's Bun behaviour.
- Bun copies `file:` directory deps into `node_modules`, so agent mode patches the copy, not the source. That's safe and not part of #626.
