[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last updated: 2026-10-09 (run 35), main `03b9418`, latest release 4.0.0.

Method: real pnpm installs. Hosted, vendored and global agent mode run against a local Python mock of the patch API (batch, by-package, view with inline blobs, `patches/blob/<hash>`, package grant, hosted tarball, `/registry/<name>/<ver>` mirror; `ajv-keywords@3.5.2` serves as the peer-dependency package). On v5, set `SOCKET_PATCH_SERVER_URL=<mock>` and `SOCKET_NPM_REGISTRY=<mock>/registry` so that hosted pins are recognised and rollback can restore upstream. The oracle is a marker prepended to `index.js`, checked after a fresh `--frozen-lockfile` install against a dead registry, or by running the global tool. The repo's pinned matrix (`.github/workflows/pnpm-compatibility.yml`) already covers plain hosted and vendored installs on pnpm 1–12. This ledger tracks what it doesn't.

## Coverage matrix

Project modes (cells before run 3 were tested on main `f6b7fb9`; "v5" marks cells re-run on `2463257`):

| OS | pnpm | Agent: default `.pnpm` | Agent: global virtual store | Agent: custom virtualStoreDir | Agent: hoisted | Vendored: plain / hoisted | Vendored: workspace-file edge shapes | Hosted: plain / catalog | Hosted: trustLockfile edge shapes | Takeover vendored ⇄ hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 | untested | n/a | untested | untested | untested | n/a | pass (lock 5.4) | n/a (no trust) | untested |
| Linux | 8.15.9 | pass | n/a | pass (#365) | untested | untested | n/a | pass (lock 6.0) | n/a (no trust) | untested |
| Linux | 9.15.9 | pass | n/a | pass (#365) | untested | untested | untested | pass / pass; v5 rollback pass | untested | untested |
| Linux | 10.0.0 | untested | n/a | untested | untested | untested | pass (10.0 ignores user overrides) | untested | untested | untested |
| Linux | 10.5.2 / 10.12.1 | untested | fail #362 (10.12.1; #361 fixed) | untested | untested | untested | fail #360 | untested | untested | untested |
| Linux | 10.34.5 | pass | #361 fixed (refusal); fail #362 | pass (#365) | untested | pass | fail #360 (v5 too) | pass / pass; v5 rollback pass | fail #400 #402 | untested |
| Linux | 11.27.0 / 11.28.3 | pass | #361 fixed (refusal); fail #362 | pass (#365) | pass | pass | fail #400 #402 | pass / pass; v5 rollback pass | fail #400 #402; pass CRLF, no-EOL, comment | v5 pass (#401 closed: `pnpm_trust_lockfile_left` warning) |
| Linux | 12.8.1 | pass | #361 fixed (refusal); fail #362 | pass (#365) | untested | pass; fail #466 with `packageManager` (two-doc lock) | fail #400 #402 | pass / pass; v5 rollback pass; two-doc lock pass | fail #400 #402 | v5 pass (#401 closed); vendored→hosted on two-doc lock fail #466 |
| macOS | 10.34.5 | pass | n/a on CI (pnpm 10 disables it) | fail #362 | untested | untested | untested | untested | untested | untested |
| macOS | 11.27.0 / 12.8.1 | pass | #361 fixed (refusal); fail #362 | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 10.34.5 | pass | n/a on CI | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 11.27.0 / 12.8.1 | pass | #361 fixed (refusal); fail #362 | fail #362 | untested | untested | untested | untested | untested | untested |

Run 6 additions (main `61cfb9b`, Linux):

| pnpm | Hosted: `sharedWorkspaceLockfile: false` | Hosted: `configDependencies` (two-doc on 11+) | Vendored: `configDependencies` | Hosted: catalogs / peer-suffixed instances | Hosted: node-linker=hoisted | Agent: hard-linked CAS store |
| --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | fail #492 | untested | untested | untested | untested | untested |
| 9.15.9 | fail #492 | n/a | n/a | pass / pass | pass | pass (hardlink broken, store pristine) |
| 10.34.5 | fail #492 | pass (single doc) | pass | pass / untested | untested | untested |
| 11.28.3 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | untested | untested |
| 12.8.1 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | pass | pass |

Run 7 additions (main `61cfb9b`, Linux):

| pnpm (lock) | Agent: transitive apply / rollback | Hosted: pin → fresh frozen → rollback | Agent: peer-suffixed | Alias `npm:` agent / hosted | Hosted: injected | Rush (hosted / vex / agent transitive) |
| --- | --- | --- | --- | --- | --- | --- |
| 2.25.7 (shrinkwrap.yaml, Node 10) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 3.8.1 (5.1, Node 16) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 4.14.4 (5.1) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 5.18.10 (5.2) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 6.35.1 (5.3) | pass | pass | untested | untested | n/a | n/a |
| 7.33.7 (5.4) | untested | pass | untested | untested / pass | untested | untested |
| 8.15.9 (6.0) | untested | pass | untested | untested / pass | pass | pass / fail #518 / untested |
| 9.15.9 (9.0) | pass | pass | pass | pass / pass | blocked (upstream pnpm bug) | pass / fail #518 / fail #518 |
| 11.28.3 | untested | pass | untested | untested / pass | untested | untested |
| 12.8.1 | pass | pass | pass | pass / pass | pass | untested |

Run 8 additions (main `61cfb9b`, Linux):

| pnpm (lock) | Agent: hoisted + npm alias (two copies) | Agent: patchedDependencies instance | Hosted: patchedDependencies (other file / same file) | Hosted: scoped pkg | Agent: import-method copy / hardlink, hoisted, alias | Vendored: legacy lock | Hosted: legacy workspace (member dep) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5.18.10 (5.2) / 6.35.1 (5.3) | untested | untested | untested | untested | untested | pass (loud `vendor_lockfile_version_unsupported`) | untested |
| 7.33.7 (5.4) | untested | pass | untested | pass | pass | pass; moved checkout: documented recovery + byte-exact rollback; workspace refused as documented | pass |
| 8.15.9 (6.0) | untested | pass | pass / pass | pass | untested | pass, same as 7 | pass |
| 9.15.9 | fail #356 | pass | pass / pass (vex declines same-file) | pass | untested | n/a | n/a |
| 10.34.5 | fail #356 | pass | pass / pass | untested | pass | n/a | n/a |
| 11.28.3 | untested | n/a (package.json field ignored) | pass / pass | untested | pass | n/a | n/a |
| 12.8.1 | fail #356 | n/a (package.json field ignored) | pass / pass | pass | untested | n/a | n/a |

Run 9 additions (main `61cfb9b`, Linux):

| pnpm | Hosted: `gitBranchLockfile` (both locks / branch lock only) | Hosted: `lockfileIncludeTarballUrl` pin + fresh frozen | Rollback byte-exact with tarball URLs | Hosted: catalog + patchedDependencies + overrides | Hosted from workspace member cwd |
| --- | --- | --- | --- | --- | --- |
| 9.15.9 | n/a (no branch lock written) | pass | fail #557 | untested | untested |
| 10.34.5 | fail #556 / untested | pass | untested | untested | untested |
| 11.28.3 | fail #556 / untested | untested | untested | untested | untested |
| 12.8.1 | fail #556 / fail #556 | pass | fail #557 | pass (vex, rollback) | no-op + `redirect_npm_no_lockfile` (not filed; see #417) |

Run 10 additions (main `203e092`, Linux):

| pnpm | Agent: isolated / hoisted transitive (post-#486/#555) | Agent: GVS direct | Agent: GVS transitive | Hosted: member cwd / `lockfile-dir=..` | Vendored: member cwd | Vendored: `gitBranchLockfile` | Rush hosted / vex / agent transitive |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | pass / pass | n/a | n/a | untested | untested | n/a | untested |
| 9.15.9 | pass / pass | n/a | n/a | fail #590 / fail #590 | pass (fails closed) | n/a | pass / pass (#518 fixed) / pass |
| 10.34.5 | pass / pass | untested | untested | fail #590 / fail #590 | untested | fail #556 (frozen install breaks) | untested |
| 11.28.3 | pass / pass | untested | untested | fail #590 / n/a | untested | fail #556 | untested |
| 12.8.1 | pass / pass | pass (#361 fixed: loud refusal) | fail #362 (now exit 0 since #555) | fail #590 / fail #590 | pass (fails closed) | fail #556 | untested |

Run 11 additions (main `045d7ec`, Linux):

| pnpm (lock) | Vendored after #583: plain / transitive / user override (frozen, vex, revert) | Vendored: 2+ packages, revert / rollback byte-exact | Agent: workspace member links (event counts) | Agent: bundled copy in another store entry (isolated / hoisted) |
| --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | pass / pass / pass | fail #636 (package.json) | untested | untested |
| 8.15.9 (6.0) | pass / pass / pass | fail #636 (package.json) | untested | fail #601 / pass |
| 9.15.9 | untested | fail #636 (package.json + workspace) | fail #633 (hoisted pass) | fail #601 / pass |
| 10.34.5 | untested | fail #636 | untested (Bun saw it on 10.28.0) | fail #601 / pass |
| 11.28.3 | untested | fail #636 | untested | fail #601 / pass |
| 12.8.1 | untested | fail #636 (also 3 packages, also `rollback`) | fail #633 (hoisted pass) | fail #601 / pass |

#636 first bad commit: `09956d90` (#247). Release 4.0.0 is byte-exact.

Run 12 additions (main `045d7ec`, Linux):

| pnpm | Agent: `workspace:*` member / `link:` dir / `file:` dir named like a patched pkg (#626) | Agent: `modulesDir: deps` | Agent: `node-linker=pnp` | Agent: `virtualStoreDirMaxLength` (hashed dirs) |
| --- | --- | --- | --- | --- |
| 7.33.7 / 8.15.9 | fail #626 / fail #626 / pass | pass (store stays in `node_modules/.pnpm`) | untested | untested |
| 9.15.9 | fail #626 / fail #626 / pass (PR #634 refuses) | pass | pass | pass |
| 10.0.0 – 10.11.1 | untested | pass | untested | untested |
| 10.12.0 – 10.34.5 | fail #626 (10.28.0) | fail #661 (first bad pnpm 10.12.0) | untested | untested |
| 11.28.3 | fail #626 / fail #626 / pass | fail #661 | untested | untested |
| 12.8.1 | fail #626 / fail #626 / pass (PR #634 refuses) | fail #661 (also workspace) | pass | pass |

Run 13 additions (main `045d7ec`, Linux):

| pnpm | Hosted standalone `vex` over the upstream install: `modulesDir` | GVS transitive | `virtualStoreDir` outside project, transitive | `virtualStoreDir` in project, transitive | `pnpm patch-commit` after hosted pin, then rollback + fresh frozen |
| --- | --- | --- | --- | --- | --- |
| 9.15.9 | pass (store stays in `node_modules/.pnpm`) | n/a | untested | untested | pass |
| 10.11.1 | pass | n/a | untested | untested | untested |
| 10.12.0 / 10.34.5 | fail #696 | n/a on CI | untested | pass | pass |
| 11.28.3 | fail #696 | fail #696 (#362 root) | fail #696 | untested | pass |
| 12.8.1 | fail #696 | fail #696 (#362 root) | fail #696 | pass | pass |

#696 first bad commit: `cf8150b` (#251). Release 4.0.0 is honest with `modulesDir`.

Run 14 additions (main `045d7ec`, Linux, Rush 5.180.0):

| pnpm | Rush hosted: clean-clone `rush install` | Rush subspaces hosted (prevent off / `preventManualShrinkwrapChanges`) | Rush agent scan / vex `--product` / rollback | Hosted `remove` one of two pins / last pin | Hosted tarball-URL dep | Hosted pin survives `--no-prefer-frozen-lockfile` |
| --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | pass | untested | untested | untested | untested | untested |
| 9.15.9 | pass (run 10) | untested / fail #714 | pass (run 10) | untested | untested | pass |
| 10.34.5 | pass | pass / fail #714 | untested | untested | untested | pass |
| 11.0.0 | fail #713 (upstream installed, exit 0) | untested | untested | untested | untested | untested |
| 11.28.3 | fail #713 (`ERR_PNPM_TARBALL_URL_MISMATCH`; env trust → upstream) | untested / fail #714 | pass | untested | untested | fail (upstream pnpm, in #713) |
| 12.8.1 | fail #713 (`ERR_PNPM_TARBALL_URL_MISMATCH`; env trust → pass) | untested | untested | pass / pass (byte-exact, scaffold deleted) | pass | pass |

Run 15 additions (main `045d7ec`, Linux):

| pnpm | `pnpm add <pkg>` after hosted / vendored scaffold | Hosted `remove` 1 of 2 → last (byte-exact) | Vendored `remove` 1 of 2 → last | `repair` agent (file mode) / vendored | Hosted pin survives `pnpm add` / `dedupe` | `pnpm fetch` → `install --offline` (lock + workspace file) |
| --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | n/a (no scaffold) | pass | untested | untested | untested | untested |
| 8.15.9 (6.0) | n/a (no scaffold) | pass | untested | untested | pass / dropped (re-resolve) | untested |
| 9.0.0 / 9.7.1 | fail #734 / untested | untested | untested | untested | untested | untested |
| 9.15.9 | fail #734 / fail #734 | untested | pass | untested / pass | fail #734 / dropped | pass |
| 10.0.0 – 10.4.1 | fail #734 (vendored 10.0.0 too) | untested | untested | untested | untested | untested |
| 10.5.0 – 10.34.5 | pass | untested | untested | untested | pass / dropped | pass |
| 11.0.0 / 11.28.3 | pass (but the pin drops: upstream pnpm 11, see #713) | untested | untested | untested | dropped / dropped | pass (lock-only fetch: loud `TARBALL_URL_MISMATCH`) |
| 12.8.1 | pass | pass (two-doc lock) | pass | pass / pass | pass / dropped | pass (lock-only: same) |

#734 isn't a regression: release 4.0.0 writes the same scaffold.

Run 16 additions (main `045d7ec`, Linux):

| pnpm (lock) | Vendored: project path with ` #` / `: ` (spaces, unicode, `'`, `[]` pass) | Agent: peer-variant twin unpatched → apply / rollback report | Takeover hosted → vendored → hosted, 2 pkgs | Vendored `remove` 1 of 2 → last | Hosted: two versions of one pkg (pin, remove one, rollback) | Hosted: lock metadata (`hasBin`/`os`/`optional`/`requiresBuild`) + transitive pins | Hosted: user overrides / resolutions | Hosted: CRLF lock |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | fail #754 | untested | untested | pass | untested | untested | untested | untested |
| 8.15.9 (6.0) | fail #754 | untested | pass (#636 residue) | pass | pass | pass | pass / pass | pass |
| 9.15.9 | n/a (relative specifiers) | untested | pass (#636 residue) | pass (run 15) | pass | pass | pass / pass | pass |
| 10.34.5 | n/a | untested | pass (#636 residue) | untested | untested | pass | pass / pass / ws block+flow pass | untested |
| 11.28.3 | n/a | untested | untested | untested | untested | pass | ws block+flow pass | untested |
| 12.8.1 | n/a | fail #756 (both) | pass (#636 residue) | pass (run 15) | pass | pass | ws block+flow pass | pass |

#754 and #756 aren't regressions: release 4.0.0 behaves the same.

Run 17 additions (main `045d7ec`, Linux):

| pnpm (lock) | Agent `scan <member path>` in a workspace / `rollback <member path>` | Hosted: `file:` tarball / git dep sharing a patched name@version | Hosted: prerelease version (pin, fresh frozen) | Agent: prerelease | Hosted: peer-suffixed (pin, fresh frozen, rollback) | Hosted: block-style `resolution:` | Agent: hoisted + nested twin |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | untested | untested | pass | pass | pass | untested | untested |
| 8.15.9 (6.0) | fail #778 / selects | untested | pass | untested | pass | untested | pass |
| 9.15.9 | fail #778 / selects | untested | pass | pass | (run 6) | pass | pass |
| 10.34.5 | fail #778 / selects; hoisted n/a | untested | untested | untested | untested | untested | pass |
| 12.8.1 | fail #778 / selects (single-package project pass) | pass / pass (not pinned, not attested) | pass | pass | (run 6) | pass | pass; #756 n/a under hoisted |

#778 isn't a regression: release 4.0.0 has no `scan [PATHS]`.

Run 18 additions (main `045d7ec`, Linux):

| pnpm | Agent `scan --sync` / `--prune` with a member scope (#778 follow-up) | Hosted pin → `pnpm deploy` (deploy output patched / `vex` there) | Vendored → `pnpm deploy` | Symlinked lock / `package.json` / workspace file: hosted / vendored | Agent: `shamefullyHoist` apply / rollback | Agent `vex` after `pnpm install --force` | Hosted: `resolution-mode=time-based` | Hosted pin survives `--lockfile-only` / `--resolution-only` / `prune` / `--prod` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 9.15.9 | pass (prune skipped with a warning, manifest kept) | pass / n/a | untested | n/a / fail #627 (lock) | pass / pass | pass (declines) | pass, byte-exact rollback | pass / dropped (re-resolves) / kept / kept (each from a fresh pin; existing upstream `node_modules` keeps upstream bytes, documented) |
| 10.34.5 | untested | pass / pass (re-install in deploy dir patched) | blocked (upstream pnpm deploy fails on any `file:` override) | untested | untested | untested | pass, byte-exact rollback | pass / dropped (re-resolves) / kept / kept (each from a fresh pin; tree patched) |
| 12.8.1 | untested | pass / pass; re-install in deploy dir fails loudly (deploy drops `trustLockfile`) | pass (patched; `vex` in the deploy dir declines) | refuses / fail #627 (all three files) | pass / pass | untested | untested | pass / kept / kept / kept |
| 12.8.1 + `modulesDir` + `virtualStoreDir` | — | — | — | — | fail #661 (0 of 2 applied, `vex` honestly empty) | — | — | — |

Run 19 additions (main `045d7ec`, Linux):

| pnpm (lock) | `list` hosted (text / `--json`) | `list` vendored / agent | `list` from member cwd | `remove <uuid>` hosted / vendored | Hosted re-scan after `pnpm install` (idempotent) | Hosted transitive pin + `blockExoticSubdeps: true` | `scan --dry-run` hosted / vendored writes nothing | Takeover agent → hosted / agent → vendored | Concurrent hosted scans |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | pass | untested | untested | untested | untested | n/a | untested | untested | untested |
| 8.15.9 (6.0) | pass (also `npm:` alias) | pass / untested | untested | pass / pass | untested | n/a | pass / pass | untested | untested |
| 9.15.9 | pass | pass / pass | fail #590 | untested | pass | n/a | untested | pass / pass | untested |
| 10.34.5 | pass | untested | untested | untested | pass | pass | untested | untested | untested |
| 11.28.3 | pass (two-doc lock too) | untested | untested | untested | untested | pass | untested | untested | untested |
| 12.8.1 | pass (two-doc, alias, conflict markers, `--offline`) | pass / pass | fail #590 | pass / pass | pass | pass | pass / pass | pass / pass | pass (`lock_held`, 3/3) |

Run 21 additions (main `4646693`, Linux):

| pnpm (lock) | Hosted → vendored takeover over a vendored refusal (catalog / CRLF lock / workspace exact-pin override) | Vendored: workspace exact-pin override, bare key / versioned key | Vendored: `.gitignore` covers `*.tgz` / `vendor/` / `.socket/` (#831) | Vendored: path with `'`, `"`, ` #`, `: ` (#754 fix) |
| --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | untested | untested | untested (absolute specifier) | pass |
| 8.15.9 (6.0) | untested | untested | untested (absolute specifier) | pass (revert byte-exact) |
| 9.15.9 | fail #853 / fail #853 / fail #853 | fail #854 / untested (package.json bare key: taken over) | fail #831 (PR #837: pass) | n/a |
| 10.34.5 | untested / untested / fail #853 | fail #854 / pass | fail #831 | n/a |
| 11.28.3 | fail #853 / fail #853 / fail #853 | fail #854 / untested | fail #831 | n/a |
| 12.8.1 | fail #853 / fail #853 / fail #853 | fail #854 / pass | fail #831 (PR #837: pass) | n/a |

Fixed on main `4646693` and re-verified with real pnpm in run 21: #356 (9 / 12), #360 (10.34.5), #557 (9 / 12), #626 (12), #636 (9 / 12), #661 / #696 (10.34.5 / 12.8.1), #662 (7 / 9 / 12), #754 (7 / 8). Read the older "fail" cells for those issues as fixed. #853 and #854 aren't regressions: release 4.0.0 behaves the same.

Run 22 additions (main `9c43dfc`, Linux):

| pnpm | Hosted from a member with its own lock (`sharedWorkspaceLockfile: false`) | Vendored from the same member | Hosted from a shared-lock member (#590 refusal) | Agent: GVS direct / transitive (#362 refusal) |
| --- | --- | --- | --- | --- |
| 9.15.9 (`.npmrc` layout) | pass (nested file written, harmless) | pass | pass (`redirect_pnpm_lockfile_elsewhere`) | n/a |
| 10.34.5 (`.npmrc` layout) | pass (nested file written, harmless) | pass | untested | n/a on CI |
| 11.28.3 | fail #880 | fail #881 (frozen fails; plain install silently unpatches) | untested | pass / pass (loud refusal, exit 1) |
| 12.8.1 | fail #880 | fail #881 | untested | pass / pass |

Fixed on main `9c43dfc` and re-verified with real pnpm in run 22: #362 (11 / 12), #590 (9). #435 (12.8.1) and #734 (9.15.9) still reproduce. #880 and #881 aren't regressions: release 4.0.0 behaves the same.

Run 23 additions (main `9c43dfc`, Linux):

| pnpm (lock) | Agent: apply / rollback / store pristine | Hosted: pin → fresh frozen → vex → rollback | Hosted: hashed peer suffix (`peersSuffixMaxLength`) | Agent / hosted `node-linker=hoisted` | Hosted + unversioned `patchedDependencies` key | Rollback byte-exact with `lockfileIncludeTarballUrl` in an ignored file | BOM `pnpm-lock.yaml` (hosted) | BOM `pnpm-workspace.yaml`, edited key first (hosted / vendored) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.43.1 (shrinkwrap v3, Node 10) | pass / pass / pass | pass, byte-exact | n/a | untested | n/a | n/a | untested | n/a |
| 7.33.7 (5.4) | (run 8) | (run 7) | untested | pass / untested | n/a | untested | untested | n/a |
| 8.15.9 (6.0) | (run 6) | (run 7) | untested | pass / untested | n/a | untested | install ok; wrong (pnpm 11) advice, #903 | n/a |
| 9.15.9 | — | — | untested | (run 6) | n/a | fail #902 (workspace file) | untested | untested |
| 10.34.5 | — | — | pass | untested / pass | pass | pass (both files read) | untested | untested |
| 11.28.3 | — | — | untested | untested / pass | untested | fail #902 (`.npmrc`) | fail #903 | fail #904 / untested |
| 12.8.1 | — | — | pass (vendored refuses, documented) | (run 6) | pass | fail #902 (`.npmrc`) | fail #903 (rollback / list / remove error) | fail #904 / fail #904 |

Fixed on main `9c43dfc` and re-verified with real pnpm in run 23: #756 (12.8.1, peer variants of `ajv-keywords`) and #627 (9.15.9 / 12.8.1: a symlinked lock, `package.json` or workspace file makes vendored fail closed). #903 and #904 aren't regressions: release 4.0.0 behaves the same. #902 comes from the #557 fix (#818).

Run 24 additions (main `9c43dfc`, Linux; project on an `.npmrc` `registry=` mirror, `SOCKET_NPM_REGISTRY` at npmjs unless noted):

| pnpm | Hosted rollback, conventional mirror | Hosted rollback / remove, CDN-style mirror (`tarball:` in lock) | Hosted rollback / remove, mirror + tarball-URL setting | Control: `SOCKET_NPM_REGISTRY` = mirror | Hosted BOM `package.json` (pin, rollback) |
| --- | --- | --- | --- | --- | --- |
| 9.15.9 | untested | fail #919 / untested | fail #919 (`.npmrc`) / untested | untested | untested |
| 10.34.5 | pass, byte-exact | fail #919 / fail #919 | fail #919 (`.npmrc`) / fail #919 (workspace file) | pass | pass |
| 12.8.1 | untested | fail #919 / untested | fail #919 (workspace file) / untested | pass | pass |

#919 isn't a regression (pre-#818 the pnpm restore never wrote `tarball:`). It shares its root cause with #908 / #521, but PR #918 covers berry and vlt only.

Run 25 additions (main `9c43dfc`, Linux; yarn-classic handover lead from #921):

| pnpm (lock) | Workspace: member a → registry `left-pad@1.3.0`, member b → `file:` dir copy: hosted scan warns / lock-only `vex` / b installed / `vex` after install | Same with a `file:` tarball copy (hosted) | Same, `file:` dir copy, vendored | Vendored, BOM `pnpm-workspace.yaml` with `overrides:` first / `packages:` first |
| --- | --- | --- | --- | --- |
| 8.15.9 (6.0) | fail #935 (no warning / not_affected / unpatched / declines) | untested | untested | untested |
| 9.15.9 | fail #935 (same) | fail #935 | fail #935 (`vex` attests after install too) | fail #904 / pass |
| 10.34.5 | fail #935 | untested | untested | fail #904 / pass |
| 11.28.3 | fail #935 | untested | untested | (run 23) |
| 12.8.1 | fail #935 | fail #935 | fail #935 (`vex` attests after install too) | (run 23) |

#935 isn't a regression: release 4.0.0 has no manifest-less lockfile VEX.

Run 26 additions (main `9c43dfc`, Linux; scoped packages and `npm:` aliases):

| pnpm (lock) | Vendored: scoped `@isaacs/string-locale-compare` (scan, fresh frozen, vex) | Vendored: unscoped `left-pad` (control) | Vendored: scoped `npm:` alias | Vendored: unscoped `npm:` alias | Hosted: scoped + unscoped `npm:` alias (fresh frozen, vex) |
| --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | fail #956 (unquoted `name: @scope/pkg`, `ERR_PNPM_BROKEN_LOCKFILE`) | pass | untested | untested | untested |
| 8.15.9 (6.0) | fail #956 | pass | pass (refused: `aliased root dependency`) | pass (refused) | untested |
| 9.15.9 | pass | pass | fail #957 (success, dangling importer ref, vex attests) | pass (refused) | pass / pass |
| 10.34.5 | pass | pass | untested | untested | untested |
| 11.28.3 | pass | pass | untested | untested | untested |
| 12.8.1 | pass | pass | fail #957 | pass (refused) | pass / pass |

#956 and #957 aren't regressions: release 4.0.0 behaves the same (3.3.0 has no pnpm vendored mode).

Run 27 additions (main `9c43dfc`, Linux; aliases and scoped packages in transitive positions, `file:` tarball parents):

| pnpm (lock) | Vendored: scoped `npm:` alias in a transitive snapshot | Vendored: unscoped alias in a transitive snapshot (control) | Vendored: scoped parent → scoped transitive | Vendored: `vendor --revert` → frozen install over the patched tree | Agent: scoped `npm:` alias, direct / transitive (apply, vex, rollback) |
| --- | --- | --- | --- | --- | --- |
| 8.15.9 (6.0) | pass (refused) | untested | untested | untested | untested |
| 9.15.9 | fail #957 (snapshot path, comment) | pass (refused) | pass | pass (byte-exact, upstream relinked, `vex` declines) | pass / pass |
| 10.34.5 | untested | untested | pass | untested | untested |
| 12.8.1 | fail #957 (snapshot path, comment) | pass (refused) | pass | pass | pass / pass |

The #957 snapshot-path variant isn't a regression: release 4.0.0 behaves the same.

Run 28 additions (main `9c43dfc`, Linux; newest pnpm releases 10.34.6 / 11.28.5 / 12.10.1):

| pnpm | Hosted: 3 pkgs (scoped + unscoped) pin → fresh frozen (dead registry) → rollback byte-exact | Hosted + `trustPolicy: no-downgrade` + `minimumReleaseAge: 1440` (fresh frozen / fresh plain install) | Hosted: scoped + unscoped `npm:` alias in a transitive snapshot (fresh frozen, `vex`) | Agent `scan --mode agent` beside a `pnpm patch` edit dir (`node_modules/.pnpm_patches`) | Hosted + socket.yml `ignorePackages` over an existing pin | Hosted `--max-new-patches 1` convergence | #935 `link:` copy beside a registry copy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 9.15.9 | (run 7) | n/a | pass / pass | pass (edit dir left upstream, store copy patched) | untested | blocked (permission classifier) | blocked (permission classifier) |
| 10.34.6 | pass | pass / pass | untested | untested | untested | untested | untested |
| 11.28.5 | pass | pass / pass | untested | untested | untested | untested | untested |
| 12.10.1 | pass | pass / pass | pass / pass | pass | pass (`retained`, lock byte-identical) | blocked (permission classifier) | blocked (permission classifier) |

Run 29 additions (main `1c6c509`, Linux):

| pnpm | Standalone project nested under an unrelated `pnpm-workspace.yaml` (not in its globs): hosted / vendored | Member with its own lock (`sharedWorkspaceLockfile: false`), hosted: no root trust / root trust + fresh frozen | #853 takeover refusal keeps hosted pin (CRLF / catalog / ws override) | `link:` copy beside a registry copy (hosted, `vex`) |
| --- | --- | --- | --- | --- |
| 9.15.9 | n/a (installs the root workspace) | untested | — / pass / — | untested |
| 10.34.6 | n/a (installs the root workspace) | untested | untested | untested |
| 11.28.5 | fail #1006 / untested | pass (refuses) / pass | — / — / pass | untested |
| 12.10.1 | fail #1006 / fail #1006 | pass (refuses) / pass | pass / — / — | pass (`vex` omits, not_applied) |

#1006 is a regression: first bad commit `8e8daf0` (#888); release 4.0.0 passes. #853's `--dry-run` preview remainder still reproduces (9.15.9 / 11.28.5).

Run 30 additions (main `05ecc6e`, Linux):

| pnpm (lock) | Hosted with pnpm's lockfile disabled (`.npmrc` `lockfile=false` / workspace `lockfile: false`) | Vendored, same setting | Vendored ledger-less (#1015): `repair` / `vendor --revert` / `rollback` | Takeover vendored → hosted / hosted → vendored → rollback | Vendored transitive under a `pnpm patch`-ed parent | Vendored → `pnpm install` → re-scan → rollback | Agent `node-linker=hoisted` | BOM lock hosted / vendored (#903 fix) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | untested | untested | untested | untested | untested | untested | pass | untested |
| 8.15.9 (6.0) | untested | untested | untested | untested | untested | untested | pass | untested |
| 9.15.9 | fail #1074 (`.npmrc`) | untested | untested | pass / residue (warned, non-bug) | pass | pass | (run 6) | pass / pass |
| 10.34.6 | fail #1074 (`.npmrc`); workspace key ignored by pnpm 10 | untested | untested | pass / residue (warned, non-bug) | untested | untested | pass | untested |
| 11.28.5 | fail #1074 (workspace file) | untested | untested | untested | untested | untested | untested | BOM workspace file (#904 fix): pass / pass |
| 12.10.1 | fail #1074 (workspace file) | pass | pass / pass (keeps artifacts wired only from the workspace file) / pass (refuses) | untested | pass | pass | (run 6) | pass / pass; BOM workspace file pass / pass |

#1074 isn't a regression: release 4.0.0 behaves the same. Re-verified fixed in run 30: #935 VEX half (12.10.1; scan half still open), #956 (7.33.7 / 8.15.9), #903 / #904 (9 / 11 / 12). Vendored from a member with its own lock refuses `vendor_pnpm_settings_elsewhere` (11.28.5 / 12.10.1, pass).

Run 31 additions (main `05ecc6e`, Linux):

| pnpm | Hosted: empty / comment-only `pnpm-workspace.yaml` | Vendored: same | Hosted: `.npmrc` `lockfile=false` (#1074 variant) | Hosted: `trustLockfile: True` / `yes` / `'true'` |
| --- | --- | --- | --- | --- |
| 8.15.9 (6.0) | n/a (no trust write) | pass (workspace file untouched) | (run 30) | n/a |
| 9.15.9 | fail #1096 / fail #1096 | untested / fail #1096 | fail #1074 (run 30) | untested |
| 10.4.1 | fail #1096 / fail #1096 | fail #1096 / untested | untested | untested |
| 10.34.6 | untested / pass | untested | fail #1074 (run 30) | untested |
| 11.28.5 | untested / pass | untested | pass (pnpm 11 ignores the key) | untested |
| 12.10.1 | untested / pass | untested | pass (pnpm 12 ignores the key) | pass / pass / pass |

#1096 isn't a regression: release 4.0.0 behaves the same. pnpm 8.x, 9.x and 10.0.0–10.4.1 reject a workspace file that has keys but no `packages:`; 10.5.0+ accept it.

Run 32 additions (main `ea09714`, Linux):

| pnpm (lock) | Supersede A → B: hosted re-pin / vendored re-vendor (fresh frozen, `vex`, rollback byte-exact) | Takeover + supersede (hosted A → vendored B / vendored A → hosted B) | `--max-new-patches 1`, 3 pkgs: hosted / vendored | Agent `virtualStoreDir: ../../vs` (#1038) | Hosted + `enableGlobalVirtualStore` (pin, fresh frozen, `vex`, rollback) | Vendored + user `pnpm.overrides` in package.json | Workspace file only `---` / `%YAML` / `---`+`...` (hosted) | `--update` on a pnpm global / project install |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 (6.0) | untested / pass (absolute specifiers) | untested | untested | untested | n/a | (run 11) | n/a | untested |
| 9.15.9 | untested | untested | untested | untested | n/a | pass (rollback keeps the user override) | fail #1096 | fail #1111 / fail #1111 |
| 10.4.1 | — | — | — | — | — | — | fail #1096 | — |
| 10.34.6 | untested | untested | untested | untested | n/a on CI | pass | (10.5+ accept) | fail #1111 / fail #1111 |
| 12.10.1 | pass / pass | pass / pass | pass / pass | pass | pass | n/a (pnpm 12 ignores the field) | pass | fail #1111 / fail #1111 |

Re-triage (run 32): #1006 still reproduces on `ea09714` (12.10.1). #1111 isn't a regression: 4.0.0 gives `npm update -g` even for project installs.

Run 33 additions (main `e2d9633`, Linux; #1050 vendored-liveness GC, #1029 `apply --check` and `redirect.patches[]`):

| pnpm (lock) | `scan --mode vendored --prune`, entry in use: root / member / hoisted (no false prune) | Same, moved checkout (path with a space) / CRLF lock / BOM lock / `lockfile=false` (with and without `node_modules`) | Dependency removed + relock → `scan --prune` reverts → fresh frozen | Lock-only clone → `scan --mode vendored --prune` (detaches the entry, heals the absolute specifier) | Agent `apply --check` (#1029): direct / transitive / hoisted / member / peer-suffixed instance drift | Hosted `redirect.patches[]` rows + fresh frozen: plain / alias / two-document lock / `sharedWorkspaceLockfile: false` |
| --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | pass | untested / — / — / — | untested | pass | untested | pass |
| 8.15.9 (6.0) | pass / refuses (#830 dialect) / — | pass / — / — / — | pass | pass (moved path with a space heals) | — / pass / — / — / — | untested |
| 9.15.9 | pass / pass / — | — / pass / pass / pass | pass | pass | pass / pass / — / — / pass | — / pass / — / pass |
| 10.34.6 | — / — / pass | untested | pass | untested | — / — / pass / — / — | pass (hoisted) |
| 12.10.1 | — / pass / — | — / — / — / pass | pass (member) | pass | GVS refuses (#362, intended); member pass; peer drift pass | — / — / pass / — |

Re-triage (run 33): #466 still reproduces on `e2d9633` (12.10.1 with `packageManager`: vendor fails `vendor_lock_entry_not_found`, nothing written).

Run 34 additions (main `cf8b164`, Linux; #1039 atomic vendored → hosted takeover, #1117 BOM consolidation):

| pnpm (lock) | Takeover vendored → hosted: dry run byte-identical / wet / fresh frozen | Takeover after user drift (`pnpm add`, extra workspace key, re-quoted override key) | Takeover, 2 pkgs, one retracted (mock drops sha512): kept vendored byte-identical, fresh frozen both patched, `rollback` | Mixed vendored A + `get <uuid B>` hosted → fresh frozen → `rollback` | Shared-lock workspace takeover (member dep) | BOM `package.json` / lock / workspace file: hosted + vendored scan, fresh frozen, `rollback` | Agent `apply --check` with `modulesDir` / out-of-project `virtualStoreDir` | Hosted `redirect.patches[]` `unpinned` (stale `node_modules`, lock pins nothing) | Standalone project under a settings-only parent workspace file |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | pass (moved checkout, absolute specifier) | — | — | — | — | — | — | — | — |
| 8.15.9 (6.0) | pass (moved checkout) | — | — | pass (rollback byte-exact; a moved copy needs the documented one-time relock) | — | — | — | — | — |
| 9.15.9 | pass | — (`pnpm add` fails, #734) | pass / residue (non-bug, see below) | pass / residue (non-bug) | pass | pass ×6 (workspace file: `pnpm_trust_lockfile_left`, documented) | — / pass | pass (no lock write, `vex` refuses honestly) | — |
| 10.34.6 | — | pass (`pnpm add`) | — | — | — | — | pass / — | — | n/a (pnpm 10 installs nothing in the child) |
| 11.28.5 | — | — | — | — | — | — | — | — | fail #1006 (comment) |
| 12.10.1 | pass | pass (workspace key, re-quoted key) | pass / residue (non-bug) | pass / residue (non-bug) | pass | pass ×6 | pass / pass | pass | fail #1006 (comment) |

Interrupted takeover (debug build, `SOCKET_PATCH_FAILPOINT` = `group_commit_journal` / `group_commit_file@1` / `@2`), 9.15.9 and 12.10.1: the next locked command replays the journal, the hosted pin lands and a fresh frozen install is patched, but the vendored artifact dir is orphaned for good. Filed as #1157 (journal omits the deferred removals; vendor GC skips its orphan sweep without a ledger).

Re-triage (run 34): #466's takeover half is fixed by #1039 (fails closed with `redirect_vendored_revert_failed`, nothing touched, ledger kept); its `vendor --revert` / `rollback` halves still reproduce on 12.10.1 (commented). #734 still reproduces (9.15.9 hosted, `ERR_PNPM_ADDING_TO_ROOT`).

Run 35 additions (main `03b9418`, Linux; #1058 hosted pins through lockfile discovery, #1147 vendored revert of a removed dependency):
- Hosted, peer-suffixed `ajv-keywords@3.5.2` with two `ajv` peers (two snapshot instances): 8.15.9 (lock 6.0, two resolutions) / 9.15.9 / 12.10.1 pass. Both instances install patched on 8 and 12.
- Hosted `npm:` alias (`lp: npm:left-pad@1.3.0`): 7.33.7 / 9.15.9 / 12.10.1 pass (dead-registry frozen install patched on 7 and 12).
- Hosted catalog dependency in a pnpm 12 two-document lock (`packageManager`): pass. Supersede A → B over the two-document lock: pass (fresh install patched, `rollback` byte-exact, scaffold deleted).
- Hosted `--max-new-patches 1` with one pin already recorded, with and without `SOCKET_PATCH_SERVER_URL`: pass on 12.10.1 (`already: 1, new: 1`).
- Hosted beside a `file:` tarball copy of the same name@version: since #1058 it no longer pins the registry copy (`redirect_unattributable`, exit 0) on 9.15.9 / 12.10.1. Vendored still wires it with no warning. Commented on #935.
- node-linker=hoisted, agent / hosted / vendored: 9.15.9 (`.npmrc`) / 12.10.1 (workspace file) pass (installs patched, `vex` not_affected).
- Vendored, then `pnpm remove`: `vendor --check` flags "dependency removed", and `vendor --revert` / `scan --prune` retire the entry (9.15.9 / 12.10.1 pass). The prune still exits 1 on 9.15.9, because of #1197.
- Vendored scan after `pnpm remove` with no prior vendoring: **fail #1197** on 7.33.7 / 8.15.9 / 9.15.9 / 10.34.6 / 11.28.5 (orphaned `.pnpm` entry gives `vendor_lock_entry_not_found`, exit 1). 12.10.1 pass (pnpm drops the orphan).
- Interrupted vendored-only supersede A → B (failpoint build; `group_commit_journal`, `group_commit_file@1..3`, `vendor_group_commit`, `vendor_package_recorded`, `durability_barrier@1/2`) on 12.10.1: pass. The next locked scan finishes, the frozen install is patched, and A's dir is reclaimed by the re-scan or (for `group_commit_file@N`) by `scan --prune` (`vendorOrphanDirs: 1` in the preview).
- #1006 negated-glob variant (`!packages/excluded`): fail on 11.28.5 / 12.10.1 hosted and 12.10.1 vendored. Commented on #1006.

Run 20 additions (main `045d7ec`, Linux):

| pnpm (lock) | Vendored parent + vendored dep (`debug`→`ms`): `remove <parent>` / takeover → hosted / `rollback` | `remove <child>` (control) | Hosted parent + dep: remove parent / rollback | Mixed-case names (`Base64`, `JSONStream`): hosted / agent / vendored | User parent-selector / range-selector override (vendored) | Agent `symlink=false` / `hoist=false` | `list -g` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | fail #830 / fail #830 / fail #830 | untested | untested | pass / pass / pass (in place) | untested | untested | n/a |
| 8.15.9 (6.0) | fail #830 / fail #830 / fail #830 | untested | untested | pass / pass / pass (in place); rollback byte-exact | untested | untested | n/a |
| 9.15.9 | fail #830 / fail #830 / fail #830 (`vendor --revert` exit 0, residue) | pass | pass / pass | pass / pass / pass; rollback byte-exact | refuses (`vendor_override_conflict`) / refuses | pass / pass | n/a |
| 10.34.5 | fail #830 / fail #830 / fail #830 | untested | untested | pass / pass / pass | refuses / refuses | pass / pass | n/a |
| 11.28.3 | fail #830 / fail #830 / fail #830 | untested | untested | pass / pass / pass | untested | untested | pass |
| 12.8.1 | fail #830 / fail #830 / fail #830 (`vendor --revert` exit 0, residue) | pass | pass / pass | pass / pass / pass; rollback byte-exact | untested / refuses | pass / pass | pass |

#830 isn't a regression: release 4.0.0's `remove <parent>` leaves the same broken lock. Run 20 also: a hosted scan SIGKILLed mid-run leaves no residue (12.8.1); agent + `list` with `sharedWorkspaceLockfile: false` pass (9 / 12); global `rc` `modules-dir` reproduces #661 on 10.34.5 (PR #698's `.modules.yaml` probe covers it).

Run 19 also: hosted `pnpm deploy` on 11.28.3 pass; vendored workspace + `pnpm deploy` on 9.15.9 pass; agent `vex` on a lockfile-only checkout declines (9 / 12).

Default isolated linker + alias: pass on 7.33.7 / 9.15.9 / 10.34.5 / 11.28.3 / 12.8.1 (one shared `.pnpm` copy).

#492 also reproduces on pnpm 7.33.7 (there's no root lock at all, only `redirect_pnpm_no_lockfile`).

Hosted `--frozen-lockfile [--offline]` over an upstream `node_modules` or warm store (run 5): VEX stays honest on 9.15.9 / 10.34.5 / 11.28.3 / 12.8.1 (pass).

"Edge shapes" means a whole-document flow mapping, a `...` document end, and quoted or `key :` top-level keys.

Global mode (`-g`, v5 main `2463257`):

| OS | pnpm | `pnpm root -g` layout | scan -g report (direct) | scan -g transitive | get/apply -g direct | rollback -g | vex -g | duplicate copies across install groups | `--mode hosted` refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 / 8.15.9 / 9.15.9 / 10.34.5 | `global/5/node_modules`, `virtualStoreDir: ../.pnpm` | pass | fail #362 (fixed by PR #365) | pass | pass, byte-exact | pass | n/a (one shared `.pnpm`) | pass (9, 11) |
| Linux | 11.0.0 / 11.27.0 / 11.28.3 (default) | `global/v11/<hash>/` → global virtual store `store/v11/links` | pass | fail #362 (GVS half; also #361) | pass (writes the shared links dir) | pass | untested | pass (one shared copy) | pass |
| Linux | 11.28.3, `enableGlobalVirtualStore: false` | `global/v11/<hash>/node_modules/.pnpm` | untested | untested | pass | untested | untested | fail #435 | untested |
| Linux | 12.4.2 / 12.8.1 / 12.8.2 | `global/v11/<hash>/node_modules/.pnpm` | pass | pass | pass | pass, byte-exact | pass | fail #435 (regression since b32711f) | pass |
| Linux | any | unwritable global prefix | blocked (sandbox runs as root) | | | | | | |
| macOS / Windows | all | | untested | untested | untested | untested | untested | untested | untested |

## Backlog

00a. #1050 GC follow-ups: `scan --prune` over a peer-suffixed vendored snapshot and over Rush / subspace locks. (`sharedWorkspaceLockfile: false` member: vendored now refuses `vendor_pnpm_settings_elsewhere` on 10.34.6 too, by design. #1029 `modulesDir` / `virtualStoreDir` and `unpinned` rows: done in run 34.)
00b. #1039 follow-ups: the takeover over a `pnpm patch`-ed vendored package, and a takeover on Windows (CRLF autocrlf checkout). The interrupted takeover is #1157. (Interrupted vendored-only commit: done in run 35, pass.)
00c. #1197 follow-ups: an upgrade (`pnpm add left-pad@<newer>`) that leaves the patched version orphaned, a workspace member's orphan, agent-mode `vex` over an orphan, and re-verification on 7–11 once fixed.
00d. #1058 follow-ups: Rush / subspace locks and `sharedWorkspaceLockfile: false` through the new ProjectView discovery, a `git+` copy beside a registry copy (expect `redirect_unattributable`), and in-memory engine parity (`get <uuid> --mode hosted`).

000. #1111 follow-ups: the passive update-notifier text on a real newer release, and a pnpm global install on Windows (`%LOCALAPPDATA%\pnpm`) and macOS. Needs a probe. #1096: marker-only files are done (run 32, commented); vendored on 10.4.1 with a comment-only file is still to do.
0a. Supersede A → B on 9/10 vendored and over a `configDependencies` two-document lock (hosted over the `packageManager` two-document lock on 12: done in run 35, pass). Also `remove <B>` after an agent A + hosted B mix (blocked by the permission classifier in run 32).
00. #1074 follow-ups: the setting in the global `rc` / `config.yaml`, the pnpm 7/8 dialect, Rush, and vendored on 9/10 (12 passes). Handed an unverified npm lead (`package-lock=false`) to discussion #302.
0. **Maintainer request (global `-g` mode):** the Linux cells are done. Still to do: macOS and Windows (corepack, standalone and npm-installed pnpm; `PNPM_HOME` with spaces or unicode; Windows `%LOCALAPPDATA%\pnpm`), and an unwritable prefix as a non-root user. Full checklist in the 20261001T040000Z entry. Needs a probe branch.
1. Delete the stale probe branch `bughunt/pnpm/20260930-virtual-store`. `git push --delete` failed through the git proxy in runs 1, 3, 10 and 16, and was denied by the permission policy in runs 2, 5–9, 11–14, 16, 17, 19 and 28, so a maintainer needs to do it. macOS and Windows probes stay on hold until branch cleanup works.
2. #754 follow-ups: a Windows `C:/…/My Project #2` checkout. Needs a probe. (The Linux moved-checkout heal with a space in the path passes on 8.15.9 and 7.33.7, run 33.)
2a. #778 follow-ups: pnpm 7 workspace layout, and `-g` absolute scopes vs `rollback -g` (`--sync`/`--prune` with a scope done in run 18: fails safe).
3. #696 / #661 follow-ups (both fixed in run 21): `modulesDir` in the global `config.yaml` / `rc`, and that GVS and out-of-project `virtualStoreDir` transitive deps also stop attesting.
3a. `list` under Rush (`list -g` on 11 / 12 and `list` with `sharedWorkspaceLockfile: false` done in run 20: pass).
4. Workspace-sensitive pnpm commands under the #734 scaffold on 9.x (`pnpm link`, `publish`, `-r`).
5. #756 (fixed, run 23) variants: in global mode, and on 9.15.9 / 10.34.5 with the `ajv-keywords` peer mock.
6. #362 GVS transitive and #435 global `-g`: re-check exit codes under #555's skip semantics on 11.28.3 / 12.8.1.
7. `package-import-method=clone` on reflink (needs CI).
8. #556 follow-ups: merging branch lockfiles after a hosted pin, and agent `vex` on the branch.
8a. #830 follow-ups: a three-level vendored chain, a `scan --mode vendored` re-run over the broken `remove` state, and the pnpm 7/8 workspace dialect.
8c. #880 / #881 follow-ups: a member of a workspace whose root uses `catalogs`, and the pnpm 7/8 dialect.
8b. #853 follow-ups: the takeover over a peer-suffixed snapshot key and over a pnpm ≤6 legacy lock, and `vendor --dry-run` (manifest-driven) parity.
8d. v5 rollout and policy over pnpm locks: `--max-new-patches 1` passes on 12.10.1, hosted and vendored (run 32). Still to do: 9.15.9, a two-document lock on 12.x, and socket.yml `includePaths` in a workspace with `sharedWorkspaceLockfile: false`.
8e. #935 follow-up: `git+` / `github:` copies (`link:` copy done in run 29: pass).
8f. #1006 follow-ups (settings-only parent done in run 34; negated globs done in run 35; both commented): pnpm 10 `ignore-workspace`, and vendored from a real member on 11/12 (expect `vendor_pnpm_settings_elsewhere`).
9. Re-verify the open set when fixes land (#853 core and #880/#881 verified in run 29; #956, #903, #904 and the #935 VEX half verified in run 30): #435, #466, #492, #556, #633, #713, #714, #734, #778, #830, #831 (PR #837, pnpm gitignore matrix), #853, #854, #880, #881, #902, #903, #904 (fix PR #909), #919, #935 (vendored scan-warning half; hosted now skips loudly), #1006, #1197, #1074, #1096 and #1111.
9a. BOM follow-ups (#903 / #904): a fresh install of a hosted BOM-`package.json` pin, and Windows checkouts (needs a probe). (Vendored BOM workspace file on 9.15.9 / 10.34.5 done in run 25: #904 reproduces.)
9b. #902 follow-ups: the setting in the global `rc` / `config.yaml`. (Mirror + tarball URLs became #919 in run 24.)
9c. #919 follow-ups: scoped `@scope:registry=` mirrors, the hosted → vendored takeover + `vendor --revert` on a mirror, pnpm 7/8 lock dialects, and re-verification once PR #918 (or a successor) covers `restore_pnpm_locks`.
9d. #935 follow-ups: a `git+` / `github:` dependency sharing the patched name@version beside a registry copy, the pnpm 7 (5.4) dialect, a `link:` copy (should not contest), and `vex --product` on a member path.
9e. #956 / #957 follow-ups: scoped vendored in a pnpm 7/8 workspace layout, hosted mode over a scoped alias in a transitive snapshot, and re-verification once fixed (PR #961 covers #956; the fix for #957 must cover the snapshot path too, see the run 27 comment).
10. Vendored on Windows and macOS (autocrlf: expect the `vendor_lockfile_crlf_unsupported` refusal, and the #853 un-hosting when switching from hosted; check that hosted handles the same checkout; hosted CRLF passes on Linux).

## Known non-bugs

- `patches-api.socket.dev` and (for the Rust client) `registry.npmjs.org` are unreachable from the sandbox. Mock the API and point `SOCKET_NPM_REGISTRY` at a mirror.
- v5 recognises hosted pins only on the configured patch server. Against a mock without `SOCKET_PATCH_SERVER_URL`, `rollback` says "Manifest not found". That's a fixture artifact.
- v5 hosted rollback and takeover keep a user-edited `trustLockfile: true` and warn `pnpm_trust_lockfile_left`. A workspace file that exactly matches hosted mode's scaffold is deleted, including a user's own `packages: ['.']` file that the trust append made identical to it (CLI_CONTRACT, upstream restore). The same applies when the user's pre-existing workspace file held only other keys (for example `lockfileIncludeTarballUrl`): the hosted-added `trustLockfile: true` stays, with the warning (v5 records no provenance).
- pnpm 10 ignores `enableGlobalVirtualStore` when `CI` is set, so the global-virtual-store cells don't engage on GH runners with pnpm 10.
- pnpm 12 (and 11) ignore `.npmrc` for `virtual-store-dir` / `enable-global-virtual-store`. Put them in `pnpm-workspace.yaml`, or in the global `config.yaml`.
- pnpm 11+ `pnpm root -g` / `pnpm add -g` fail unless `$PNPM_HOME/bin` is on `PATH`. Put it there in fixtures.
- Vendored refusals that are intended, loud and fail-closed: a CRLF `pnpm-lock.yaml` or `pnpm-workspace.yaml` (`vendor_lockfile_crlf_unsupported`), a BOM package.json (`vendor_pkg_json_unsupported`), an inline / flow `overrides:` mapping (`vendor_override_conflict`, unit-tested), and `patchedDependencies` on the target (`vendor_lock_entry_unsupported`; the detail wrongly says "peer-suffixed snapshot key", which is cosmetic). On a hosted → vendored takeover these refusals fire after the hosted pin is already restored, which is #853.
- Vendored `vex` attests from the committed artifact plus lock wiring even when the tree isn't installed. That's by design (CLI_CONTRACT "Manifest-less VEX").
- `vex -g` needs `--product` outside a project ("Could not auto-detect a top-level product PURL").
- Agent-mode `get <purl>` for an uninstalled package reports `success, applied: 1` when another manifest entry applies. The nested apply fails only when nothing matches. It's not pnpm-specific (noted on #362).
- A compact single-line `package.json` comes back 2-space-indented after vendor + rollback. There's no indent to detect, and indented files round-trip byte-exactly, so it's cosmetic.
- Hosted on pnpm 9 over an existing upstream `node_modules`: a frozen install keeps the upstream bytes. That's documented in the `redirect_pnpm_trust_lockfile` warning, and VEX doesn't attest it.
- pnpm 12 warns that `package.json` `pnpm.overrides` is ignored on vendored projects. The workspace-file override is what takes effect, so this is noise only.
- A `vex --output /dev/stdout` hang when stdout is a pipe is not pnpm-specific.
- Vendored refuses pnpm catalogs (`catalogs:` entry) and peer-suffixed snapshot keys with `vendor_lock_entry_unsupported` ("this lock shape is not supported yet"). It's loud and writes nothing. Hosted handles both. (The takeover from hosted un-hosts first: #853.)
- pnpm 10's `configDependencies` copy (`node_modules/.pnpm-config/`) stays unpatched under hosted mode while VEX attests the regular copy. Config deps run only at install time, and pnpm 10 keeps their integrity in `pnpm-workspace.yaml`.
- On v5, vendoring always downloads its artifact from the patch service (`--vendor-source build` was removed), so offline vendoring with only a staged manifest fails with `vendor_service_offline_conflict`. Fixtures need the mock grant to match the manifest UUID.
- `rush update --full` re-resolves the Rush lock and drops the hosted pin, like `pnpm update`. VEX then honestly reports nothing to attest.
- pnpm 9.15.9's frozen install fails on its own unmodified lock when a workspace uses `dependenciesMeta.injected` ("importer dependencies meta (undefined) doesn't match"). That's upstream pnpm, not socket-patch.
- Old pnpm needs an old Node (≤ 6 needs Node 16, ≤ 2 needs Node 10), and pnpm 3 takes `--store` rather than `--store-dir`. Fixture notes.
- Agent apply over a pnpm `patchedDependencies` edit to the same file overwrites it with the verified patched content and warns `content_mismatch_overwritten` (documented default mismatch policy; `--strict` refuses). Hosted composes both patches, and `vex` then declines (`no_applicable_patches`), because the file matches neither hash.
- Hosted on pnpm 11/12 respects an explicit `trustLockfile: false` (any YAML spelling) and warns `redirect_pnpm_trust_lockfile` with the remedy. The following frozen install fails, which is documented.
- Vendored refuses pnpm ≤ 6 locks (5.x up to 5.3) with `vendor_lockfile_version_unsupported`, and pnpm 7/8 workspace locks with `vendor_lock_entry_unsupported`. pnpm 7/8 vendored locks carry an absolute `file:` specifier (`vendor_pnpm_legacy_absolute_specifier`), so a moved checkout needs `pnpm install --offline --no-frozen-lockfile` once. Both are documented.
- pnpm 11+ ignores `package.json` `pnpm.patchedDependencies`. Put it in `pnpm-workspace.yaml`.
- A dead-registry fresh install fails when the fixture has any unpatched dependency (it still needs the registry). Use the live registry for those fixtures, or patch every dependency. The same goes for `--offline` with an empty store (`ERR_PNPM_NO_OFFLINE_TARBALL`).
- Vendored from a workspace member cwd fails closed with `vendor_lockfile_missing` (`partial_failure`). Hosted's silent success in the same layout is #590.
- A `package.json` without a trailing newline gains one after vendor + revert. That's a fixture artifact; files that end in a newline round-trip byte-exactly.
- Bundled-copy fixtures need a registry-served host package. A `file:` tarball host (`.pnpm/bundler@file+…`) is patched correctly, so it doesn't reproduce #601.
- pnpm ≤10 `.npmrc` keys must be kebab-case (`modules-dir`, `virtual-store-dir-max-length`); camelCase is silently ignored. pnpm 7–10.11 keep the virtual store in `node_modules/.pnpm` even with `modules-dir`, so agent mode passes there.
- pnpm `file:` directory dependencies are copied into the store (`.pnpm/<name>@file+…`), so patching that copy is correct and doesn't touch the source (unlike `link:` / `workspace:`, #626).
- In-run `scan --mode hosted --vex` attests from this run's records without hash verification, so it says `not_affected` over an upstream install (CLI_CONTRACT `(redirected)` row). Use standalone `vex` after the install as the oracle.
- A `pnpm patch-commit` over a hosted pin makes `vex` decline with `hash_mismatch` (the file matches neither hash). That's honest. Rollback keeps the user's patch and restores the upstream pin.
- pnpm ≤10 `patch-commit` under `CI=true` runs a frozen install and fails with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` (fixture note: use `confirmModulesPurge=false`, not `CI`). A mock `/registry` must serve the real npmjs tarball, or a rollback restores a foreign integrity.
- Rush has no root `package.json`, so `vex` needs `--product` there (`product_undetected`), like `-g`.
- pnpm 12.0.0 doesn't run under Rush 5.180 (it rejects Rush's `--no-prefer-frozen-lockfile`). Rush subspace fixtures need `common/config/subspaces/<name>/` folders created and `common/config/rush/.pnpmfile.cjs` removed before `rush update`.
- pnpm 11.28.3 `pnpm install --no-prefer-frozen-lockfile` re-resolves hosted pins to upstream even with `trustLockfile: true` (9 / 10 / 12 keep them). That's upstream pnpm behaviour; the default `pnpm install` and `--frozen-lockfile` keep the pin. It's tracked inside #713 because Rush uses that flag by default.
- `pnpm dedupe` re-resolves and drops hosted pins on every pnpm version (like `pnpm update`). pnpm 11.0.0 / 11.28.3 `pnpm add <other>` also drops them (9 / 10 / 12 keep them). That's upstream pnpm 11 re-resolution, tracked with #713.
- `repair` in the default diff mode needs `/v0/orgs/<org>/patches/diff/<uuid>` archives. A mock without them gives `download_failed`; use `--download-mode file` with a blob route.
- pnpm 11 / 12 `pnpm fetch` with only `pnpm-lock.yaml` copied (no `pnpm-workspace.yaml`) fails loudly with `ERR_PNPM_TARBALL_URL_MISMATCH`. Commit and copy the trust config, as documented.
- Hosted standalone `vex` attests an optional dependency that isn't installed on this OS (for example `fsevents` on Linux) from its lock pin. That's the documented manifest-less attestation ("nothing installed → attests from the pin").
- pnpm 11 / 12 fail `ERR_PNPM_IGNORED_BUILDS` for `esbuild` even on the first install, unless builds are allowed. That's upstream; the patched bytes still land.
- `pnpm update <pkg>` drops the hosted pins of every package it re-resolves (pnpm 12 also re-resolves the package's dependents), like `pnpm update`.
- Agent `apply` from a pnpm workspace member cwd patches only the member's direct (linked) deps. Transitive deps in the root `.pnpm` are skipped ("No installed package matches this PURL", exit 0), and agent `vex` omits them (`package_not_found`). Agent crawls are cwd-scoped, and CLI_CONTRACT puts a member that shares the root lock in the root project, so run from the root.
- Hosted on a `pnpm-lock.yaml` with git conflict markers writes nothing and warns `redirect_pnpm_entry_not_found` for every package (exit 0). It fails safe. Resolve the conflict (`pnpm install`) first.
- Hosted leaves a `file:` tarball or git dependency that shares a patched name@version alone (`redirect_pnpm_entry_not_found`), and `vex` doesn't attest it.
- pnpm 12 `pnpm deploy` writes its own `pnpm-workspace.yaml` without the hosted `trustLockfile: true`, so a re-install inside the deploy output fails loudly (`ERR_PNPM_TARBALL_URL_MISMATCH`). That's upstream pnpm; ship the deployed `node_modules`, or add `trustLockfile: true` there. pnpm 9 / 10 deploy outputs re-install patched.
- pnpm 10 `pnpm deploy` (shared lockfile) fails with "Deployment with a shared lockfile has failed" for any `file:` tarball override, the user's own included. That's upstream, so vendored + deploy on pnpm 10 is blocked by pnpm itself.
- A deploy of a vendored project gets an absolute `file://…/.socket/vendor/…` specifier, and `vex` in the deploy dir declines (no ledger there). The bytes are patched; nothing is falsely attested.
- `pnpm install --resolution-only` on pnpm 9 / 10 re-resolves and drops hosted pins, like `pnpm update` (pnpm 12 keeps them). `prune`, `install --prod` and a plain `install` keep the pin on 9 / 10 / 12.
- Agent `scan --sync <scope>` / `--prune <scope>` where the scope matches nothing (#778) skips the prune with a warning and keeps the manifest. It fails safe.
- Hosted `vex` recognises a hosted pin only when the tarball URL is on the patch-server origin AND carries the patch uuid as a path segment. Mock fixtures need `/…/<uuid>/<file>.tgz` URLs.
- Agent → hosted takeover keeps the agent-mode manifest beside the new hosted pin (`list` shows each patch twice). The layers coexist, and `rollback` unwinds both. Agent → vendored migrates the manifest record out, as documented.
- Vendored `list` keeps listing a package after `pnpm remove <pkg>`, because pnpm keeps the override and the wiring is still live. `vex` omits it.
- Fixture note: `scan -g` also covers the npm global root, so it patches npm's own bundled deps (for example `/opt/node22/lib/node_modules/npm/node_modules/jsonparse`). That isn't pnpm-specific, but it can make a pnpm-global copy look `already_patched` in `apply -g` output.
- Vendored refuses a user parent-selector (`a>b`) or range-selector (`b@<2`) override for the target with `vendor_override_conflict` and writes nothing. The detail text is slightly off (it mentions an exact-pin takeover, or "package.json" on pnpm 12), which is cosmetic. (A bare-key exact pin in `pnpm-workspace.yaml` is NOT a genuine conflict: #854.)
- An API that answers with lowercased npm purls for a mixed-case installed name (`Base64`) isn't matched by agent apply (`package_not_installed`). There's no evidence the real API lowercases, so treat it as hypothetical (run 20).
- `scan --mode vendored --dry-run` over a hosted pin previews only `would_vendor` (no `vendor_would_revert_redirect`). It's not pnpm-specific, so it isn't filed here (run 21).
- Fixture note: global (`-g`) cells must put the pnpm under test first on `PATH`. The sandbox ships pnpm 10.28.0 in `/opt/node22/bin`, and the CLI reads the global root from whichever `pnpm` it finds (run 22).
- pnpm 9 ignores `sharedWorkspaceLockfile: false` in `pnpm-workspace.yaml` (only `.npmrc` `shared-workspace-lockfile=false` works there), so a 9.x member then has no lock of its own and the #590 refusal is correct.
- Fixture note (run 23): pnpm 1.x needs Node 10 (it crashes in graceful-fs on Node 22). Its layout is `node_modules/.registry.npmjs.org/<name>/<ver>/node_modules/<name>`, its lock is `shrinkwrap.yaml`, and it takes `--frozen-shrinkwrap` and `--store`.
- Vendored on a pnpm 1/2 `shrinkwrap.yaml` project fails closed with `vendor_lockfile_missing`, whose message lists `pnpm-lock.yaml` but not `shrinkwrap.yaml` (cosmetic; vendoring pnpm ≤ 6 is refused as documented).
- Fixture note (run 24): pnpm caches registry metadata per host in `~/.cache/pnpm/metadata/<host>+<port>`. Give each mirror cell its own `XDG_CACHE_HOME`, or a mirror that changes its `dist.tarball` style serves stale URLs. For fresh-install checks, copy the working tree; a git clone takes the committed lock.
- Fixture note (run 23): the Python mock rebuilds the patched tarball on every restart (the gzip mtime changes), so a pin's sha512 changes between mock restarts. Re-scan after restarting the mock.
- Fixture note (run 29): `vex --json` needs `--output`, and a workspace root without a `version` needs `--product`.
- Fixture note (run 27): agent `rollback --offline` needs the before blob staged in `.socket/blobs`; without it, rollback fails with `Before blob not found` (`missing_blob`). That's documented (`repair` fetches it).
- Hosted → vendored takeover of 2+ packages keeps the hosted `packages: ['.']` + `trustLockfile: true` scaffold, because the second un-host sees the first package's vendored overrides in the file. It warns `pnpm_trust_lockfile_left`, and a later `rollback` leaves the scaffold (run 30, 9.15.9 / 10.34.6). The vendored → hosted → rollback order deletes it.
- A pnpm major upgrade over hosted pins: pnpm 10/12 (and pnpm 9 over a 5.4 lock) can't read a 5.x / 6.0 lock. `--frozen-lockfile` fails loudly, and a plain install discards the lock, re-resolves and drops the pins (like `pnpm update`). Re-run the hosted scan after upgrading. pnpm 9 migrates a 6.0 lock and keeps the pins.
- Fixture note (run 30): agent `rollback` needs the mock to serve the "before" blob on `patches/blob/<hash>` (otherwise `missing_blob`).
- `vendor --revert` with a missing ledger skips with `vendor_orphan_still_wired` and says to "run `socket-patch repair` to re-adopt them", but `repair` answers `vendor_ledger_missing` ("does not rebuild the ledger from lockfiles"). The remedies contradict each other, but it's cosmetic and not pnpm-specific (run 30).
- Hosted reads only a literal `true` (optionally quoted) as `trustLockfile` already set. For `True` / `yes` it warns that the user's explicit value "was respected", but pnpm 12 treats both as trusted and installs patched. That's cosmetic (run 31).
- pnpm 11 / 12 ignore `.npmrc` `lockfile=false`, so #1074 applies there only through the `pnpm-workspace.yaml` `lockfile: false` key (run 31).
- With a stale sibling lock, vendored wires only the governing lock in the #1044 precedence table (vlt > bun > pnpm > yarn > npm) and warns `vendor_multiple_lockfiles`. That's documented. Hosted rewrites every present lock (run 32).
- `remove <uuid A>` on a release where the agent manifest holds A and a hosted pin holds a superseding B also unwinds B's pin. #1035 designed it that way: every generation of the release goes (run 32).
- `vendor --revert` (and the vendored leg of `rollback`) removes its override line from `pnpm-workspace.yaml` but leaves an empty `overrides:` header when another key follows the block, for example the user's own key or hosted mode's `trustLockfile`. pnpm 8–12 accept the null value. After a mixed vendored A + hosted B (`get <uuid B>`, or a takeover that retracts one package), `rollback` then leaves `packages: ['.']` / `overrides:` / `trustLockfile: true` in a project that had no workspace file. It warns `pnpm_trust_lockfile_left` (the same class as the run-30 hosted → vendored residue, and #401 was closed on the warning), and on 8.x–10.4 the leftover scaffold is #734. Not filed (run 34).
- Vendored from a `shared-workspace-lockfile=false` member refuses with `vendor_pnpm_settings_elsewhere` on pnpm 10 as well (run 22 passed on 10.34.5 before the #881 fix). That's correct: pnpm 10 honours the member's own `pnpm.overrides` only for an install run from the member. A root `pnpm install --frozen-lockfile` fails with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` (run 34).
- Since #1058 (run 35), hosted refuses to pin a registry copy when another lock entry installs the same name@version from a `file:` tarball (`redirect_unattributable`, nothing written, exit 0). That's deliberate: it matches the VEX contested-lock rule. The vendored scan-warning gap is still #935.
- After `pnpm remove` of a vendored package, `vendor --check` exits 1 with "dependency removed … run `scan --mode vendored --prune`" (run 35). That's correct and actionable; the prune retires the entry (its own exit 1 on 7–11 is #1197).
- An interrupted vendored-only commit at `group_commit_file@N` leaves the superseded uuid dir until `scan --prune`. It's listed as `vendorOrphanDirs` and reclaimed there, so it fails safe, unlike the takeover in #1157 (run 35).
