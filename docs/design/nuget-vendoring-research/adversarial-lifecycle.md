# Adversarial lifecycle review: NuGet vendoring v2 (unique-version fallback seed)

## Verdict

The build-time mechanism holds up: V′, the fallback folder, evaluation-time redirects and the guards. The weak part is the lifecycle, which the design does not specify well enough to implement.

The design adds generated files shared by every NuGet entry: `socket-patch.targets`, `.gitignore`, and one DBT import per directory. It then tracks them with per-entry records, inside a CLI that:
- saves the ledger and sweeps old uuid dirs *after* the backend returns;
- drops cross-uuid wiring on re-vendor;
- keeps "preserved" entries byte-identical.

Those three behaviours cause the two lifecycle blockers:
- **Patch update:** the most common lifecycle event breaks restore for every project in the repo.
- **Revert after an update, or reverting in the wrong order:** leaves an import to a deleted targets file. Restore then quietly rewrites locks to upstream.

A third blocker is the git line-ending problem: under the common `* text=auto` rule, the committed seed does not survive a clone byte-for-byte.

With the fixes below the design is still workable. §15 should grow by one structural piece: a pass that regenerates the shared NuGet outputs from the final ledger state.

## Experiments run (SDK 8.0.131)

All runs used an isolated `HOME`, `NUGET_PACKAGES`, `NUGET_HTTP_CACHE_PATH`, `TMPDIR` and `DOTNET_CLI_HOME`, under `<scratch>/adv-lifecycle/`. Env script: `adv-lifecycle/env.sh`. The fixture is a copy of design-D `e1/r` (Lib, App, Tool; 13.0.1 and 12.0.1 redirected to `.1843260417`).

| ID | Experiment | Result |
|---|---|---|
| **V1** | Cold GPF, then `dotnet restore S.sln --locked-mode` on the vendored repo | **VERIFIED.** Afterwards the GPF holds only `newtonsoft.json.bson/1.0.2`. It holds **no** `newtonsoft.json` at any version, because upstream 13.0.1 and 12.0.1 are never downloaded. `packageFolders` = [gpf, `.socket/vendor/nuget/packages`]. |
| **V2** | Add one non-existent uuid root to `RestoreAdditionalProjectFallbackFolders` | **VERIFIED.** `error NU1301: The local source '…' doesn't exist` for **every** project that imports the targets: Lib, App and Tool, including projects that do not use the patched package. |
| **V3** | Unguarded `Import` of `socket-patch.targets` with the targets file deleted | **VERIFIED.** A plain `dotnet restore` **succeeds without error**, because NuGet's restore evaluation ignores missing imports. It **rewrites `Lib/packages.lock.json` from `13.0.1.1843260417` back to upstream `13.0.1`**. Only `dotnet build` then fails with MSB4019. A later `--locked-mode` restore passes against the rewritten upstream lock. |
| **V4** | Commit the extracted seed in a repo with `.gitattributes` `* text=auto`, then `git clone` | **VERIFIED.** In the clone, `newtonsoft.json.nuspec`, `LICENSE.md` and `lib/*/Newtonsoft.Json.xml` have different sha256 (CRLF became LF). The vendoring machine's tree still reports clean. The dll and `.nupkg.metadata` are unchanged. The fix below is also VERIFIED under both `text=auto` and `core.autocrlf=true`: a nested `.socket/vendor/nuget/.gitattributes` containing `* -text -diff -merge -filter` gives byte-identical clones. |

Everything else below is **REASONED**, from the code as cited or from the verified facts above.

## Findings

### B1. Patch update to a new uuid breaks every restore, pins a dead V′, and makes revert unrecoverable (BLOCKER)

**Scenario.** Patch A (uuid `3f9a…`, 13.0.1 → V′a) is vendored. The manifest moves to patch B (new uuid) for the same purl, and the user runs `socket-patch vendor`.

**What the code does** (`vendor.rs` `record_vendor_entry` :1020, `sweep_stale_artifact` :1073):
1. The backend runs while A's entry is **still in the ledger**.
2. The CLI then replaces the entry under the same key.
3. The CLI deletes A's uuid dir.

**What goes wrong:**
- §7.1 step 5 renders the targets from "state on disk minus *this* uuid (B) plus this entry". So it renders **both** A and B:
  - A's root stays in `RestoreAdditionalProjectFallbackFolders`;
  - there are two `Update` redirects for the same declared 13.0.1, and the later one wins;
  - SOCKETPATCH001 checks A's seed.
- After `sweep_stale_artifact` deletes A's dir, every project fails with NU1301 (V2) or SOCKETPATCH001. Nothing regenerates the targets after the sweep.
- `plan_closure` and `plan_lock_edits` look for entries that resolve to **V**. After A, every lock resolves to V′a, so B finds no closure and makes no lock edits (or refuses). The targets redirect to V′b while the locks pin V′a, which gives NU1004 in locked mode.
- If B does edit V′a → V′b, it records `original` = the V′a text. `carry_forward_wiring` (`state.rs:418`) fills an original **only when `original` is None**. So B's revert would restore V′a, a version whose seed is gone (NU1301 or NU1102).
- The prelude checks `vendor_nuget_duplicate_patch` and `vendor_nuget_version_collision` against A's entry for the same purl and may refuse the update outright.

**Fix:**
- The shared-output render must exclude every entry with the same ledger key or basePurl as the entry being written.
- More robustly, regenerate `socket-patch.targets` and `.gitignore` in a CLI step that runs **after** `persist_vendor_entry`, `sweep_stale_artifact` and each revert's `save_state` (see P1).
- The closure planner and lock planner must treat any `resolved` that `parse_socket_nuget_version` decodes to (id, V) as "ours". For those entries they should record `original: None`, so that `carry_forward_wiring` fills in the true upstream original from A (the key `<lockrel>#<tfm>#<id>` is uuid-agnostic, so the match works).
- Duplicate and collision checks must ignore the entry being replaced.
- Add a docker leg: vendor A, update to B, run a locked restore, revert, then `git diff --exit-code`.

### B2. Import records are "reference-counted" per entry, but the ledger cannot hold them, leaving the repo unbuildable after revert (BLOCKER)

**Scenario 1 (patch update, then revert).** B's apply finds the imports already present. `inject_import` returns None, so nothing is recorded. `carry_forward_wiring` performs its union **only when `prev.uuid == entry.uuid`** (`state.rs:461`), so A's `nuget_msbuild_import` records are dropped. When B is reverted:
- no import record remains;
- step 2 deletes the targets because no entries are left;
- every DBT still imports a missing file.

**Scenario 2 (two ids, reverted in creation order).** Entries X and Y exist, and X created the imports. `vendor --revert` walks keys in sorted order and saves after each entry (`rollback.rs:891-902`). X is not last, so its import records vanish with X's ledger entry. Y has none, so the imports stay.

**Scenario 3 (crash).** The process is killed between the import write and the ledger save. The next run sees the imports as pre-existing and has no record to undo them.

**Outcome.** Every `dotnet build` fails with MSB4019. Worse, by V3 every plain `dotnet restore` (Dependabot, Renovate, `dotnet list package`, IDE restore) **silently rewrites the locks to upstream**. A bot PR can then commit unpatched locks.

**Fix:**
- Stop tracking imports in per-entry records.
- Make import removal deterministic and free of records: on the last `nuget-fallback` revert, discover every DBT (same discovery as apply) and excise exactly the line carrying `Label="socket-patch"`.
- Delete a DBT only if its whole text equals `created_dbt(import_rel)`.
- Optionally keep a state-level `nugetShared` object (an additive optional field on `VendorState`) with the created and edited DBT originals, for byte-exact restore.
- **Order:** remove the imports first, and delete the targets only after every import is gone. If any excision drifts, write a no-op stub `socket-patch.targets` (just `<Project/>`) rather than deleting it.

### B3. The committed seed is not byte-stable through git (BLOCKER for Windows and VS-template repos)

**Scenario.** The repo has `.gitattributes` `* text=auto` (the stock Visual Studio template), `core.autocrlf=true` on Windows, or an LFS rule such as `*.dll filter=lfs`.

**Outcome (V4).** Every fresh clone or CI checkout has different bytes for the nuspec, xml docs and LICENSE. Then:
- the seed-inventory hash in the guard fails with SOCKETPATCH002 on **every build except the vendoring machine's**;
- `fallback_in_sync` never holds, so each `socket-patch vendor` rewrites the seed, and git hides this because it normalises;
- patched text members (content files, `build/*.targets`, `.ps1`) also fail afterHash verification;
- with LFS, clones without LFS get pointer files.

The legacy layout is immune because a `.nupkg` is binary. So this is a regression specific to the new layout.

**Fix:**
- Generate `.socket/vendor/nuget/.gitattributes` with `* -text -diff -merge -filter` (V4 verified that it fixes `text=auto` and autocrlf).
- After writing, probe with `git check-attr text filter eol` on each seed file, and refuse with `vendor_artifact_git_transformed` if any file is still transformed.
- Add `.gitattributes` to the reserved names (§11.4) and the hot-path render check.

### M1. Preserved, kept or failed-save entries are re-wired by the next render (MAJOR)

**Scenario.** One of:
- `rollback --preserve-state` or `remove --preserve-state`: `VendorRevertStep::Preserved` keeps the entry byte-identical (`rollback.rs:860-864`);
- drift-keep (`Kept`);
- `LedgerWriteFailed`.

After that, any later NuGet vendor or revert, or even the hot path of a *different* entry ("targets byte-equal to a fresh render"), renders from all `nuget-fallback` entries. The supposedly reverted patch comes back into the targets.

**Outcome:**
- Locked projects: NU1004, because their locks were restored to upstream.
- Lockless projects: silently patched again.
- If the seed was deleted: NU1301 for every project (V2).

**Fix.** Render only the entries that are actually wired. Add `nuget.wired: bool`, or `unwiredAt`, to `NugetMeta`, and set it false on Preserved and Kept. Never render an entry whose seed directory is missing; emit a warning instead.

### M2. Revert step order defeats drift-keep, and deletes the targets before import removal can fail (MAJOR)

**Scenario.** §7.4 step 2 regenerates the targets **without** this uuid. Step 4 then keeps the seed only if "the live targets file still names the uuid". That can never be true at step 4, so drift-keep never fires. The seed is deleted while a drifted lock still pins V′. The result is NU1004 when locked, and a dangling V′ pin for any tool that reads the lock.

Step 2 also deletes the targets before step 3 tries to excise the imports, which is the B2 failure mode.

**Fix.** Use this order:
1. lock records;
2. compute keep = any drifted record whose live text still contains V′;
3. if keep, leave the uuid in the targets, keep the seed, and return `kept_artifact`;
4. otherwise remove imports (last entry only, per B2);
5. regenerate or delete the targets;
6. delete the seed.

### M3. On a clean machine the package never counts as installed: repair, update and migration have no pristine source (MAJOR)

**Scenario.** CI or a teammate's clone. V1 shows the GPF never holds upstream `newtonsoft.json/13.0.1` again after vendoring. With §7.5, the crawler skips the seed folders. The loop (`vendor.rs:1840-1910`) therefore sees the purl as missing, and what happens next depends on the case:
- **Same uuid:** `ledger_covers` returns true for a directory artifact with `sha256: ""` (`state.rs:293` checks existence only), so the source becomes `Deferred`. The `vend_installed!` `debug_assert!(PackageSource::Installed)` (`vendor.rs:171`) then panics in debug and test builds. In release, `installed_dir` is a hint path. This does exist for legacy with a cold GPF, but legacy's first restore repairs it; in fallback it is permanent.
- **New uuid (patch update), `repair` (service None, `repair_vendor.rs:1632`), or `--offline`:** there is no fetch rung, so `package_not_installed` and exit 1. A NuGet patch can then only be updated where the service is reachable, or after revert, restore and re-vendor.

**Fix:**
- Add a NuGet pristine-fetch rung: nuget.org flatcontainer, `<idl>/<v>/<idl>.<v>.nupkg`.
- Verify it fail-closed against the upstream `contentHash` that the ledger already holds in each `nuget_lock_entry_v2` `original`. For signed packages, compute the signed-content hash (zip without `.signature.p7s`, signing §e) instead of hashing the file.
- Treat that fragment like npm's "ledger-recovered pre-vendor registry fragment".
- Replace the `debug_assert` for nuget-fallback entries. The fallback hot path must never read `installed_dir`.

### M4. The hot path and `--check` fail on CI before restore, and the closure re-plan misreads its own output (MAJOR)

**Scenario.** §7.2 requires the recomputed closure plan to match `nuget.projects`, and §7.1 refuses `vendor_nuget_unrestored` when a project has neither a lock nor an assets file.

**Outcome:**
- On a fresh clone (no `obj/`), lockless projects have neither, so `socket-patch vendor` or `--check` refuses or reports "closure changed" on every CI run.
- Even with locks, the post-vendor lock resolves **V′**, not V. A `pin` project's entry has become `Direct`, so without V′-awareness it looks like `direct`. `auto-follow` is ambiguous in the same way. The re-plan then "re-keys" and churns the targets.

**Fix:**
- Persist the plan in state and treat it as authoritative.
- Re-plan only from csproj and CPM text plus the locks, with decoded V′ counted as V. Missing assets for a project already in the plan is not a refusal.
- Keep `vendor_nuget_unrestored` only for **new** projects that the plan has not seen.

### M5. Older binaries (v4.0.0 is released) corrupt fallback entries; the "flavor gate in the same PR" protects only v5+ (MAJOR)

**Scenario.** A teammate, or a CI action pinned to v4, runs `socket-patch vendor --revert` or `vendor` on a repo with `nuget-fallback` entries.

**v4 revert** (`nuget_feed.rs:772-873`):
- every kind is unknown, so each produces a `vendor_lock_entry_drifted` warning;
- drift-keep probes only single-segment wiring files for the literal `.socket/vendor/nuget/<uuid>`;
- `Directory.Build.targets` contains only the targets path, so the probe finds nothing;
- the seed is deleted and the call reports success;
- `revert_vendor_entry` drops the entry;
- the targets and locks still reference the uuid, so NU1301 in every project (V2), with no ledger entry left.

**v4 vendor:** `config_wired` is false (there is no `socket-patch-<uuid>` in `nuget.config`), so v4 runs a full legacy apply on top. It:
- writes a `.nupkg` into the same uuid dir;
- adds a source and catch-all to `nuget.config`;
- rewrites the root lock;
- writes a legacy entry. Because the uuid is the same, `carry_forward_wiring` merges the fallback records into it, and that entry then routes to the legacy revert.

`load_state` has no version gate (`state.rs:562-590`), so bumping `VENDOR_STATE_VERSION` does not help.

**Fix:**
- In the root DBT, emit one comment per uuid: `<!-- socket-patch: .socket/vendor/nuget/<uuid> -->`. v4's drift-keep then keeps the seed and the entry, which is fail-safe. This also fixes M6's liveness probe.
- In v5, route any entry that carries `nuget_lock_entry_v2` or `nuget_msbuild_import` records to the fallback backend, whatever its `flavor`.
- Detect and heal a legacy `socket-patch-<uuid>` source that sits beside a fallback seed.
- Document the minimum version.

### M6. VEX silently stops attesting fallback-vendored patches (MAJOR, missing from the §15 module table)

**Scenario.** `vex/discover/nuget.rs` is driven entirely by `nuget.config` (source plus mapping). The vendored liveness probe list for nuget is `CONFIG_NAMES` (`vex/discover/mod.rs:1750`). `vendored_wiring_in_files` looks for the literal `.socket/vendor/nuget/<uuid>`.

The fallback entry's recorded files are the DBT (which has only the targets path) and the locks (which have only V′). The targets file uses `$(SocketPatchNuGetDir)<uuid>`, which is not the literal string. So `vendored_wiring_live` returns false and the entry reads as dead.

**Outcome.** VEX output drops the patch without any error.

**Fix:**
- Add a fallback extractor: parse `socket-patch.targets` (uuid roots plus `Update`/`Include` V′) and every discovered lock (decode V′ to purl@V plus the uuid prefix).
- Add `.socket/vendor/nuget/socket-patch.targets` and the discovered locks to the nuget probe files.
- Spell the uuid dir literally in the targets, as a comment or in the SOCKETPATCH001 path.
- Set `artifact_rel` to the seed directory.
- Put all of this in prototype scope.

### M7. Partial-failure unwind is unsafe for shared outputs and reused seeds (MAJOR)

**Scenario:**
- §7.1 step 4 may *reuse* an existing, already committed seed, for example on a closure re-plan. The unwind for steps 5–8 then "deletes the seed".
- Step 5 overwrites the shared targets and `.gitignore`, which have no recorded original.
- A lock edit fails at project k of N, for example on an unparseable lock.

**Outcome.** A committed seed can be deleted while the targets still name it (NU1301 everywhere, V2). Alternatively, the new targets file is left behind with only some locks edited, which gives NU1004.

**Fix:**
- Snapshot the bytes of `socket-patch.targets`, `.gitignore` and `.gitattributes` before step 5, and restore them on unwind.
- Delete the seed only if this run created it.
- Stage all lock splices in memory and write them last, each by temp file and rename. Unwind must restore every written file.

### M8. Migration from the legacy layout destroys its own pristine source and leaves the repo unpatched on refusal (MAJOR)

**Scenario.** §11.1 runs the legacy revert (step 1) before the fallback apply (step 2).

**Problems:**
- The legacy revert deletes the committed patched `.nupkg`, which is the only local copy of the patched bytes.
- On a legacy machine the GPF `newtonsoft.json/13.0.1/*.nupkg` is **the patched one**, extracted from our feed. `local_rebuild` would therefore apply the patch to already-patched bytes, and the before-hash gate fails.
- Any fallback-only refusal (`exact_dependency`, `dbt_disabled`, `unrestored`, `version_literal_unknown`) that fires after step 1 leaves the repo **unpatched**.

**Fix:**
1. Run `fallback_prelude` and `plan_closure` first.
2. Materialise V′ with `reversion_nupkg(committed_legacy_nupkg)`, builder Local, and verify the afterHashes.
3. Only then revert the legacy wiring and write the fallback wiring, as one unit that can be unwound.
4. The migration must fail as a whole and leave legacy intact.

### M9. Restore does not fail closed when the targets file is missing (MAJOR; contradicts §6.4)

§6.4 says an unguarded import means "it never degrades silently to upstream". V3 shows otherwise:
- `dotnet restore` ignores the missing import and **rewrites the locks to upstream**;
- only build fails.

Restore-only pipelines therefore produce unpatched locks without any error: Dependabot/Renovate lock refresh, `dotnet restore` Docker layers without `.socket/`, and `dotnet list package --vulnerable`.

**Fix.** Update §6.4 and §9 to describe this accurately. Recommend `socket-patch vendor --check` as a required CI step, and document that lock diffs from V′ to V in bot PRs mean the patch was dropped. In Docker, the COPY step must include `.socket/vendor/nuget/` whenever it copies `Directory.Build.targets`.

### M10. Transitive pins keep themselves alive and never disengage (MAJOR)

**Scenario.** Tool pins `[12.0.1.N]` because Bson 1.0.2 pulls in 12.0.1. Later Bson is removed, or bumped to a version that needs 13.x.

**Outcome:**
- **Bson removed:** the pin's condition (the project has no PackageReference for the id) still holds. Tool keeps a direct dependency on patched 12.0.1 indefinitely, and `Publish="true"` ships the dll.
- **Bson needs ≥ 13:** NU1605 against the exact pin.
- The in-use probe ("any lock resolves V′") is satisfied by our own pin, so gc never reclaims the entry.

**Fix.** The in-use probe and `vendor --check` must ignore edges the tool created itself. A pin counts as in use only if some other package in the assets or lock `dependencies` still lists the id at a range V′ satisfies. Otherwise, report `vendor_nuget_pin_orphaned` and drop the pin on the next `vendor`.

### M11. The layout choice does not persist, so repos end up with mixed layouts (MAJOR)

**Scenario.**
- `--nuget-layout` defaults to `feed`.
- Only *existing* entries are sticky.
- The flag is threaded only into `dispatch_vendor_one` and the preflight. It is not on `scan --mode vendored`, `get --mode vendored` or `repair`.

**Outcome.** A teammate or CI adding a new NuGet patch without the flag vendors it in the legacy layout. The repo then has both a `nuget.config` catch-all and fallback targets. This is untested, and legacy GPF poisoning returns for that id.

**Fix.** Infer the layout: if any `nuget-fallback` entry exists, new entries use fallback. Or persist a `nugetLayout` optional top-level field in the state. Put the flag on `GlobalArgs`.

### Minor findings

| # | Scenario | Outcome | Fix |
|---|---|---|---|
| m1 | A user edits `socket-patch.targets`, for example to add `SocketPatchNuGetAllowUnpatched` or exclude a project | The next render overwrites the edit without warning | Store the render sha in state. If the on-disk file differs from the last render, warn `vendor_nuget_targets_edited` and refuse without `--force`. Provide a supported user hook: an optional `socket-patch.user.targets` imported last, plus per-project properties. |
| m2 | "Import into every nearest DBT" reaches git submodules, `dotnet new` template content (`PackageType=Template`), samples, or vendored third-party trees | Submodule edits cannot be committed from the superproject, so projects there resolve upstream silently. Templates ship a broken import to their consumers. | Limit to projects in the same git worktree (`git rev-parse --show-toplevel`). Skip template content. Warn `vendor_nuget_import_skipped`. |
| m3 | A new subdirectory is added later with its own DBT that does not chain to the parent | The targets are never imported, so SOCKETPATCH005 cannot fire and the project is silently unpatched. §4's claim that 005 covers new projects is only partly true. | Say so explicitly. Have `vendor --check` list uncovered projects, and make `--check` part of the recommended CI step. |
| m4 | Developers with and without service access (builder 0 vs 1), and Q4 | Different V′ for the same uuid. Lock and targets churn as soon as anyone runs `--force` or a re-plan. | Hot path accepts either builder for the same uuid. Never switch builders without an explicit `--nuget-rebuild-service`. |
| m5 | Dry run | Earlier entries in the run are not persisted, so the preview render leaves them out and understates the diff | Render from the in-memory run state. |
| m6 | Directory artifact with `sha256: ""` | `ledger_covers`, `list` and orphan labelling rely on existence only. The `path.rs` leaf parser expects a `.nupkg` leaf. | Add a `fileInventory`-based intact check for nuget-fallback artifacts, and a nested leaf parser. |
| m7 | NU1903 on V′ | VERIFIED during V1: `NU1903 … 12.0.1.1843260417 has a known high severity vulnerability`. This is the same as before the patch, but still a false positive once patched. Under `TreatWarningsAsErrors` or `NuGetAuditLevel` it fails the build. NuGetAuditSuppress is out of prototype scope. | Bring NuGetAuditSuppress into the prototype for NuGet ≥ 6.11, or document the gap. |

## P1. Can the prototype (§15) be built in the current code structure?

Only with CLI changes that §15 does not list. What is missing:

1. **No per-ecosystem finalize hook.** Shared outputs derived from the whole ledger need a `vendor::nuget_fallback::sync_shared(cwd, &VendorState)` call after every ledger mutation:
   - `run_vendor` after `persist_vendor_entry` and `sweep_stale_artifact`;
   - `run_revert`, `rollback`, `remove` (`revert_vendor_entry` after `save_state`);
   - `run_vendor_gc`, `repair`, and scan/get vendored.

   Doing this inside the backend is what causes B1 and M1.
2. **`carry_forward_wiring` contract.**
   - The backend must emit `original: None` for lock entries already at a Socket V′.
   - Import wiring must move out of per-entry records (B2).
   - A new-uuid re-vendor unions nothing.
3. **Layout plumbing is more than two call sites.**
   - `vendor::service_preflight` (`vendor/mod.rs:918`) is a public 6-argument function with no ledger access, so `layout_for(entry_flavor, …)` cannot be evaluated there without a signature change.
   - `dispatch_vendor_one` has callers at `vendor.rs:2636` and `repair_vendor.rs:1632`, and is also reached through `vendor_records` from scan and get. The flag belongs on `GlobalArgs`.
4. `vend_installed!` `debug_assert` and a NuGet fetch rung (M3).
5. VEX discovery and liveness (M6), the in-use probe with self-edge exclusion (M10), and crawler skipping all have to be in scope. Otherwise `vex`, `gc` and `list` regress as soon as the flag is used.
6. A v4 hybrid-entry router plus the DBT uuid comment (M5).

Scale: the core modules in the §15 table look sized correctly. The CLI and VEX work above probably adds another 30–40% and touches 6–8 more files. None of it conflicts with the backend and dispatch shape.

## Recommended design edits (summary)

1. Add §6.7 "Shared outputs":
   - `sync_shared` after every ledger save;
   - render only wired entries whose seed is present;
   - record-free import excision, removing imports before the targets;
   - a stub targets file on drift;
   - a generated `.gitattributes` checked with `git check-attr`.
2. Add §7.6 "Patch update":
   - V′-aware planner;
   - `original: None` carry-forward;
   - exclude the entry being replaced;
   - a docker leg for update, revert and a clean diff.
3. Reorder §7.4 revert as in M2. Reorder §11.1 migration as in M8.
4. Correct §6.4 and §9 on restore behaviour when the targets file is missing (V3), and make `vendor --check` the documented CI gate.
5. Extend §15 scope: VEX, the in-use probe, the fetch rung, the v4 hybrid router, layout inference, and the finalize hook.