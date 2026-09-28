# v5 waste review: socket-patch + depscan patch system

> Reference copy of PR #286, which was closed without merging. Each
> finding's owner (workstream, in-flight PR or owner decision) is in
> the [triage map](https://github.com/SocketDev/socket-patch/pull/286#issuecomment-5869109317).

Scope: socket-patch at `release/v5-prerelease` (8ae7dc37; in-flight branches
#279–#283 and `v5/integration` f8b8d80a where noted) and depscan `master`
(repack in `workspaces/patches/src/repack`, serving in
`workspaces/patches/src/services/patch-serving` and
`workspaces/patches-api-proxy/src/server.ts`, api-v0 endpoints). Respects the
owner decisions in [v5-plan.md](v5-plan.md): vlt stays, every PM version
stays, `setup` goes, hosted ledger goes, maven/nuget vendoring is frozen, and
WS5 (#283) keeps the local rebuild. Nothing here proposes dropping vlt or any
PM version; CI tiering only moves legs between PR, main push and nightly.

Companion: [repacking-to-depscan.md](repacking-to-depscan.md) (what each repo
builds and what moving the rest of repacking to depscan would take).

## Summary

**Method.** Both repos were inventoried: the CLI's local rebuild, the
per-ecosystem builders, hosted/napi, depscan repack, depscan's use of the
CLI, CI and test cost, and churn and bug history. Findings were swept over 9
dimensions: cross-repo duplication, intra-repo duplication, dead code, test
overlap, CI matrix, redundant network, repacking, expensive abstractions, and
high-cost/low-value features. A gap review then covered the diff channel,
the upstream fetchers vs the CLI pristine ladder, signing, fallback-rate
observability, patches-harness-contract, patch-publication, the cost of the
in-flight PRs, and the depscan bump break list. Each finding was
independently re-verified on three criteria: facts (re-measure every
claim), value (is it really waste, and does it conflict with owner
decisions?) and savings (≥150 LOC or ≥2 CI job-min/run). A finding was kept
when at least two held. Verified numbers replace the initial estimates.

**Counts.** 85 raw findings were de-duplicated to 75, and the gap round
added 31 (106 reviewed). 80 were kept and 26 dropped. Of the 80 kept, 69 are
waste (ranked below) and 11 are measurements or checks that found no waste.

**Top line (net new, after de-duplicating against v5-plan WS1–WS8 and PRs
#279–#283):**
- Actionable now: about **32.8k lines**: 9.1k code, 14.9k test, and 8.8k of
  docs and workflow YAML.
- Gated on a precondition or owner decision: a further **15.7k lines** (6.3k
  code, 9.4k test). 10.5k of that is the depscan TS rewriter twin (F01).
- CI: about **478 job-min per socket-patch `ci.yml` PR run**, or 438 on a
  main push, against a 945 job-min main-push run. Add about 95 job-min
  across the compatibility workflows per PR push that triggers them (F55 65
  pdm, F57 12 npm/pnpm, F56 ≈10 vlt, F54 8 pdm Windows; pdm-compat alone
  ≈73), and about 9.5 per depscan api-v0 CI run (roughly 130 runs a day).
- The biggest single lever is build-once fan-out for the e2e matrix (F51,
  280 job-min per run). The biggest code/test levers are the #257
  equivalence oracles (F03, 6.5k), the depscan TS rewriter twin (F01, 10.5k,
  gated) and depscan's stale refactor docs (F02, 8.2k lines).
- Precondition for reading any v5 CI: the base branch is red on one
  assertion (F77), so the e2e tier has not run on any v5 PR.

## Ranked findings

Rank is verified savings × confidence (3/3 upheld over 2/3) × low risk.
Runtime-only findings (0 LOC, 0 CI) rank by avoided work per run. `sp` means
socket-patch, `ds` means depscan. LOC is verified lines removed (src + test,
or YAML/docs where noted). CI is job-min per run of the named workflow. "⊂
Fnn" means the figure is contained in another finding and is not counted
again.

| # | id | finding | repo | category | evidence | verified LOC | CI min/run | risk | already planned? | recommendation |
|---|----|---------|------|----------|----------|-------------:|-----------:|------|------------------|----------------|
| 1 | F51 | e2e matrix recompiles the CLI and its test binary in each of 176 legs | sp | ci-matrix | .github/workflows/ci.yml:1098,1355; run 36359489402: 176 legs = 530 job-min, 2m06s compile vs 0.03s test | 0 | 280 | L | no | Per-OS `e2e-build` job (`cargo test --no-run --message-format=json`), upload the binaries, legs run the downloaded suite; pattern at vlt-compatibility.yml:143-187. Restore the CARGO_BIN_EXE path or add an override. Every leg and PM version stays. |
| 2 | F03 | ~7.5k LOC of test-only "verbatim previous implementation" oracles from #257 | sp | test-overlap | crates/socket-patch-core/src/crawlers/*/oracle.rs (2,680); crates/socket-patch-core/src/patch/redirect/pnpm_equivalence_tests.rs:1-7; xorshift constant in 23 files | 6,500 | 0.5 | L-M | no (WS3 names them as a gate) | Snapshot the generated inputs into the redirect goldens first, keep one shared test RNG, delete the crawler oracles plus their inline `mod equivalence` blocks now, and delete each rewriter oracle in its WS3 family PR. |
| 3 | F02 | depscan patches/docs/refactor: 9.4k lines; 61% of cited paths no longer exist | ds | dead-code (docs) | depscan:workspaces/patches/docs/refactor (37 files, 9,398 lines; 181/297 paths missing; README.md:3 "temporary") | 8,222 docs | 0 | none | no | Delete everything except DAG/ (1,176 lines, backfill still active); reword the dag-lift comments that cite missing files. |
| 4 | F41 | e2e-docker is a strict subset of coverage-docker | sp | test-overlap | ci.yml:1390 vs :455; 9 legs 65.1 vs 89.2 job-min; bind-mount at crates/socket-patch-cli/tests/docker_e2e_cargo.rs:34-49 | 65 YAML | 65 | L | no | Drop per-push e2e-docker, or run it nightly as the check of the full-LTO release binary (it is the only per-push run of that binary). |
| 5 | F04 | covgap_/coverage_fix_/in_process_ categories no longer mean anything; one command's tests span up to 16 binaries | sp | test-overlap | crates/socket-patch-cli/tests: covgap_* 25 files/27.6k LOC, in_process_* 38/34.3k; get_modes_e2e.rs:465 covers in_process_get_modes.rs:649 | 4,000 | ⊂ F58 | L-M | partial (WS7 deletes covgap_setup*, excluded) | When WS5/WS8 touch a command, merge its files into one suite (in-process + subprocess modules) and delete sampled duplicates. Stop adding covgap_* files. |
| 6 | F53 | Dockerfile.base release build rebuilt with no cache 27× per run; binary unused in coverage-docker | sp | ci-matrix | ci.yml:518,1421,1662; 121.5 job-min of base builds (12.9% of run) | 0 | 68 (≈35 after F41) | L | partial (setup-matrix share = WS7, excluded) | Build once, then `docker save`/load or ghcr (gha cache is unusable with `driver: docker`, ci.yml:486-494). Keep a binary for the Dockerfile.gem/deno build-time `--version` checks. |
| 7 | F55 | pdm capstone recompiles e2e_vex_build in 30 legs and repeats 7 ci.yml rows | sp | ci-matrix | pdm-compatibility.yml:151-182; run 36363939533 capstone 30 legs/91 job-min, 2m03s compile vs 9.5s tests | 0 | 65 (per pdm-compat run) | L | no | `needs: build` plus a `--no-run` test-binary artifact. Exclude the 7 cells ci.yml gates, guarded by a leg-checker like scripts/tests/test_ci_vlt_rows.py. Every PDM version stays. |
| 8 | F52 | Tier PM-version legs: boundaries on PRs, every version on main push/nightly | sp | ci-matrix | ci.yml e2e include: 176 rows, 155 version-keyed, 78 ubuntu middle rows; no `schedule` trigger (ci.yml:3-16) | 0 | ≈90 PR (≈40 after F51) | M | no | Mark middle rows `tier: full` and skip them on `pull_request`; keep them on main push, nightly and dispatch. Keep the boundary versions named in ci.yml comments on PRs. Most of the 78 middle rows are such named boundaries (bundler, pdm, hatch, vlt eras, uv 0.5.4/0.5.5, poetry lock formats, maven); about 33 carry none, so ≈90 standalone (33 × 2.75). The recorded 140 holds only if all 78 move. |
| 9 | F06 | depscan legacy/ hosts the live admin package-detail engine; it blocks the 2026-11-04 table drop | ds | dead-code | depscan:workspaces/patches/src/legacy/fetch-autopatch-package-status.ts (3,093; 68 commits); depscan:workspaces/patches/src/api/commands/review/upgrade-risk.ts:14,181-207 | 3,000 (incl. F19) | 0 | M | partial (depscan legacy/README.md:30-31) | Before 2026-11-04: make the upgrade-risk lookup one query, give detail a version-scoped path, port the admin page to the read-models, then delete the engine, poc-result.ts, queue-driven-suites.ts and their tests. |
| 10 | F01 | GitHub-app hosted PR flow keeps a ~6k-LOC TS port of the Rust rewriter; the napi engine has 0 consumers | both | cross-repo-dup | depscan:workspaces/app/src/patches/registry-rewrite (5,978 src + 5,582 test); depscan:workspaces/app/src/autopatch-pr/github-patch-pr-hosted.ts:63,308,494; depscan 9752b91237 (cargo drift) | 10,500 (gated) | 1 | M-H | partial (WS4 keeps napi; no depscan adoption plan) | After bumps past WS1 and WS4, call the Rust engine (socket-patch-node or `hosted-bundle` subprocess) and delete the TS rewriters. Freeze the TS port until then. The 141 goldens gate byte-identity. |
| 11 | F47 | cargo-vex 17-leg cross recompiles every leg; repeats e2e_safety_cargo_build | sp | ci-matrix | ci.yml:1531-1577 (18 legs/48.2 job-min); e2e safety rows 11.1 job-min; lock knob headline-only at crates/socket-patch-cli/tests/e2e_safety_cargo_build.rs:326 | 10 YAML | 30 (≈23 after F51) | L-M | no | Drop the 3 e2e_safety rows from the e2e matrix. Run a pairwise toolchain×lock subset on PRs and the full cross on main/nightly. Build once per OS. |
| 12 | F11 | depscan break list for the #279 bump: 30 loud setup e2e failures | both | cross-repo-dup | depscan:workspaces/api-v0/e2e-tests/tests/59_socket-patch-setup.js (1,344; 27 setup calls), 82_socket-patch-telemetry-coverage.js:229-262, 65_patch-telemetry.js:478-502 | 1,380 | 2 | L | partial (WS7 covers only the CLI side) | In the depscan bump past #279, delete 59_socket-patch-setup.js (the apply edge cases at :812-1114 also run `setup --yes`; move only the bun `--help` subtest at :1170 elsewhere if it is wanted) and the 82 setup case at :229-262. Retire 65's patch_setup case after an owner check. |
| 13 | F09 | Python lock family missing from WS3's PR order; 4–5 readers per format | sp | intra-dup | v5-plan.md:75-76; check_target_guards ×4 at crates/socket-patch-core/src/vendor/pypi_poetry.rs:207, pypi_uv.rs:312, pypi_pdm.rs:184, pypi_pipenv.rs:162; utils/pdm_lock.rs:129 = utils/poetry_lock.rs:105 | 1,600 | 0 | M | extends WS3 | Add a Python PR to WS3 (formats/{poetry,pdm,pipfile,pylock_uv,requirements} on utils/python_lock). One generic guard with one documented fork rule. |
| 14 | F12 | 8 npm-family vendored backends repeat one vendor/revert skeleton; pnpm vs pnpm-legacy clone survives #281 | sp | intra-dup | crates/socket-patch-core/src/vendor/{npm_lock.rs:90, pnpm_lock.rs:110, pnpm_lock_legacy.rs:287, bun_lock.rs:327} (2,076 + 1,428 LOC); 256–367 cloned lines | 1,200 | 0 | M | extends WS3/WS5 | One `NpmFlavorBackend` trait and one driver in npm_common over utils/group_commit.rs; derive Default on VendorEntry (57 literals). |
| 15 | F49 | default suite compiled twice per `test` leg (feature-set mismatch) | sp | ci-matrix | ci.yml:331-332 (`--all-features --no-run`, then default), :372-373; documented as intentional at :336-338 | 2 YAML | 18 | L | no | Use one feature set for `--no-run` and the run in test and test-release. Owner to confirm the #150 rationale. |
| 16 | F58 | 238 CLI integration-test binaries, 78 with ≤3 tests; linking dominates test/test-release | sp | test-overlap | crates/socket-patch-cli/tests (238 files; 23 with 0–1 tests); ci.yml:335-341 "~240 test binaries" | 0 | 20 (≈30 combined with F49, F04) | M | no | Consolidate into multi-module crates per command family (as tests/e2e_vex_build/), keeping `#[serial]` (565 uses in 58 files). About 21 setup binaries go with WS7 anyway. |
| 17 | F10 | CRLF/corrupt/dry-run/round-trip invariants re-tested per writer | sp | test-overlap | 79 CRLF fns in 44 files (crates/socket-patch-core/src/patch/redirect/mod.rs 11); 232 dry_run fns | 1,400 | 0.3 | M | extends WS3 | One property harness over every LockModel impl (CRLF in = out, plan+restore identity, dry run writes nothing, rerun is a no-op). Move edge cases into its fixtures. |
| 18 | F39 | 3 regenerate/reset paths; the admin routes delete Go zips before requeue and skip the gopatch refusal | ds | intra-dup | depscan:workspaces/patches/src/services/patch-package/reset-decision.ts:32-39 vs depscan:workspaces/next-app/src/pages/api/admin/patches/regenerate-range.ts:242-264 (no force guard) | 100 | 0 | L | no | Both admin routes call resetOne() in reset-ops.ts. This removes a live hazard: a range regenerate over a Go patch breaks committed go.sum pins. |
| 19 | F19 | admin package-detail "lite" engine dead since #18370 | ds | dead-code | fetch-autopatch-package-status.ts:2211-2709 and :305-352; depscan:workspaces/next-app/src/pages/api/admin/autopatch/package-detail.ts:3,27,42,47-62 | 560 (⊂ F06) | 0 | L | no | Delete now, independent of F06. |
| 20 | F24 | patches-harness-contract carries a dead autopatch-backport config module | ds | dead-code | depscan:workspaces/patches-harness-contract/src/autopatch-backport-config.ts (273) + test (143) | 425 | 0 | L | no | Delete; fix doc paths; inline the depscan:workspaces/patches/src/services/patch-publication/dependent-merges.ts:21-26 pass-through (`trx: any`). |
| 21 | F20 | purl-api-proxy keeps a full /patch/* forward that no client calls | ds | dead-code | depscan:workspaces/purl-api-proxy/routes/patch.ts (181), lib/patch-target.ts (121), lib/forward-headers.ts (57); CLI default is patches-api (crates/socket-patch-core/src/api/client.rs:1922) | 560 | 0 | L-M | no | Confirm zero traffic in gateway logs, then delete the route, guard, forward-headers, their tests and PATCHES_ORIGIN. abort-client-response and upstream-origin are shared and stay. |
| 22 | F16 | WS1 upstream/* builds a second per-format grammar outside WS3 formats/ and imports a module #281 deletes | sp | intra-dup | origin/v5/ledger-free-hosted crates/socket-patch-core/src/patch/redirect/upstream/* (8,359 @08c30b7e; 8,752 @65aa0744); formats/mod.rs:71 stub; upstream/gem.rs:61 uses removed `vendor::gemfile_lock` | 900 | 0 | M | partial (WS3 restore_upstream stub) | Rebase #280 onto integration. Split each upstream/<fmt>.rs into a pure `formats::<fmt>::restore_upstream(pins)` and one async resolver. This also fixes the compile break. |
| 23 | F07 | real-installer pdm/pipenv/poetry backtests duplicated in depscan (hatch and pip exist only in depscan), run against pinned CLI SHAs | both | cross-repo-dup | depscan:tools/pipeline/{pdm,pipenv,poetry,hatch,pip}-patch-backtest.py (3,759); depscan:.github/workflows/pdm-patch-compatibility.yaml:20 SOCKET_PATCH_REVISION; scripts/backtest-{pdm,pipenv,poetry}.py | 2,900 (gated) | 30 (ds, per pypi trigger) | M | no | socket-patch compatibility workflows publish versioned captures; depscan SBOM tests consume them via the submodule; delete depscan's pdm workflow and the pdm/pipenv/poetry scripts; delete depscan's hatch workflow and script only after socket-patch adds a hatch capture. F74 is the interim step. |
| 24 | F73 | depscan api-v0 shards rebuild the pinned CLI every run despite a 963 MB cache hit | ds | ci-matrix | depscan:workspaces/github-actions/src/jobs/test-api-v0.ts:82-91,146; depscan:.github/workflows/pull-request.yaml:2273-2277; 7 runs, mean 7.9 job-min | 0 | 7.5 (~130 runs/day) | L | no | Cache the binary keyed on `HEAD:submodules/socket-patch`, or build it once and share it; the 7.5 is this cache alone. Optional, not counted: a path-gated shard for the 23 patch e2e files (see D26; the filter must keep the lib/app/pipeline import paths). |
| 25 | F23 | deploy-patches prod/staging workflows are 500-line twins edited in lockstep | ds | intra-dup | depscan:.github/workflows/deploy-patches-{prod,staging}.yaml (500 each; 68-line diff; 62 shared commits) | 440 YAML | 0 | L | no | One `workflow_call` workflow plus two dispatch wrappers; keep environment protection bound to the right job. |
| 26 | F21 | hidden legacy scan spellings and the v3 SOCKET_PATCH_* env shim survive v5 | both | dead-code | crates/socket-patch-cli/src/commands/scan/mod.rs:291,312,322,326; crates/socket-patch-core/src/utils/env_compat.rs:20-68,108-117,165-178; depscan:workspaces/patches/src/test/integration/live/hosted-live.e2e.test.ts:569-571 | 450 | 0 | L (env, --detached) / M (flags) | partial (WS8 hid, kept) | In v5.0 drop `--detached` and SOCKET_PATCH_*. Drop or warn-and-map `--redirect/--apply/--vendor`. Update the depscan tests in the same bump. |
| 27 | F29 | `--one-off` on get/rollback exists only to error | sp | dead-code | crates/socket-patch-cli/src/commands/rollback.rs:98-115,1123-1158; crates/socket-patch-cli/src/commands/get.rs:506-521,2623-2657 | 260 | 0 | L | no (WS8 kept it) | Remove the flag, SOCKET_ONE_OFF, the tests and the CLI_CONTRACT/README rows in v5.0. |
| 28 | F30 | `.socket/packages/<uuid>.tar.gz` is never written but still probed, overlaid and swept | sp | dead-code | crates/socket-patch-core/src/api/blob_fetcher.rs:30-38; crates/socket-patch-cli/src/commands/fetch_stage.rs:212-235,339,460; apply.rs:1048-1056 | 250 | 0 | L | no | Delete resolve_from_archive, packages_path, the pkg_present arm and the sweeps (keep the archive helpers shared with diffs). gc sweeps the leftover dir for one release. Drop `appliedVia: "package"`. |
| 29 | F57 | vlt-serve-watchdog cannot alert; npm/pnpm compatibility have no path filter | sp | ci-matrix | vlt-serve-watchdog.yml:18,28; npm-compatibility.yml:9-13; pnpm-compatibility.yml:3-7 | 0 | 12 (PR pushes) | L | no | Path-filter npm/pnpm like bun-compatibility.yml. Arm the watchdog after a manual dispatch confirms depscan #26856/#26867 in prod, or run it daily until then. |
| 30 | F54 | pdm-compat Windows native legs vacuous (47/47 SKIP, green) | sp | ci-matrix | scripts/backtest-pdm.py:484-486,1320-1324,1352-1355; job 108746808097 | 0 | 8 | L | no | Treat a bootstrap failure or 100% SKIP as ERROR. Then either fix `Scripts\python.exe` (adds ~50–60 job-min) or drop the 16 Windows rows. |
| 31 | F46 | e2e_maven/e2e_nuget/e2e_composer rows spend ~2.5 min each on 0.03 s hermetic tests | sp | ci-matrix | ci.yml:686,688-693,696; crates/socket-patch-cli/tests/e2e_nuget.rs:182,250 and e2e_maven.rs:102,229 `#[ignore]` | 13 YAML | 7 (≈3 after F51) | L | extends follow-up (v5-plan.md:134-135) | Un-ignore the 4 hermetic tests so `test` runs them; delete the 3 rows. |
| 32 | F33 | npm `.berry.zip` sidecar is built, stored, served, never read | both | dead-code | crates/socket-patch-core/src/patch/redirect/mod.rs:166 (0 reads); depscan:workspaces/patches/src/services/patch-package/build.ts:475-482; serve-decision.ts:145-157 | 150 | 0 | L | no | CLI: drop `berry_zip_url` (44 lines). depscan: keep the rebuild (it is the 10c0 source) but stop storing and serving the zip after an access-log check; api-v0 package.ts:124-133 exposes it publicly. Drop the columns later. |
| 33 | F25 | parse_memo: process-global parse caches that work around per-package re-parsing | sp | expensive-abstraction | crates/socket-patch-core/src/vendor/parse_memo.rs (275; 21 statics in 16 files) | 320 | 0 | L | extends WS3/WS6 | Delete once LockModel parses once per run through ProjectContext; add no new sites. |
| 34 | F32 | Auto/Service fallback policy hand-rolled in 7 backends; the shared helper serves only frozen maven/nuget | sp | intra-dup | crates/socket-patch-core/src/vendor/service_fetch.rs:170-265 (callers maven_repo.rs:713, nuget_feed.rs:906); golang.rs:550-563,701-731 | 220 | 0 | M | extends WS5 | `acquire_service_artifact(cfg, record, verdict_fn)` → Used/FallBack/HardFail inside VendoredBackend. Ready arms stay per backend; warning codes become parameters. |
| 35 | F27 | the GitHub app mirrors the redirect-state.json schema that WS1 deletes | both | cross-repo-dup | depscan:workspaces/app/src/autopatch-pr/github-patch-pr-hosted.ts:81,235-300,534-575 | 300 | 0 | L | partial (WS1 CLI side) | In the depscan bump past #280, stop writing the ledger. The CLI keeps legacy reads (v5-plan.md:47-48), so this is a stale writer, not an attestation loss. Fixture captures are not prunable LOC. |
| 36 | F28 | vendored path POSTs /patches/package once per uuid; the endpoint takes 500 | both | redundant-network | crates/socket-patch-core/src/api/client.rs:1429-1437; crates/socket-patch-core/src/api/vendor_prefetch.rs (601 src); depscan:workspaces/api-v0/src/endpoints/orgs/patches/package.ts:287,330 | 300 | 0 | M | no | One chunked batch reference POST per vendor run; keep per-package GETs and the breaker. Also chunk hosted scan's unchunked call (client.rs:759-776), which returns 400 above 500 uuids. |
| 37 | F18 | one-off cargo index-line backfill runs inside every converter cycle | ds | high-cost-low-value | depscan:workspaces/patches/src/services/patch-package/converter.ts:341-352; queue.ts:593-686; cargo-index-backfill.test.ts (429) | 690 (gated) | 0.3 | L | no | Gate: backlog count = 0 (added 2026-09-28, not yet drained). Then a one-shot admin script, or a flag defaulting off. |
| 38 | F14 | depscan diff channel: on-demand bsdiff task, hidden route, proxy with per-request view preflight | ds | high-cost-low-value | depscan:workspaces/api-v0/src/endpoints/orgs/patches/diff.ts:93-107; generate-patch-diff-archive-task.ts:41-56,133 (throws in a task); depscan:workspaces/patches-api-proxy/src/server.ts:1263-1345 | 1,130 (gated) | 0.5 | M | no | Needs an owner decision on CLI diff mode: D19 showed default `repair` writes diff-only sources, so the channel is not dead (see F67). Meanwhile remove the task throws and the doubled preflight. If retired, a 404 is a safe interim (crates/socket-patch-core/src/api/blob_fetcher.rs:274-281). |
| 39 | F22 | 14 of 18 CLI telemetry events are never classified server-side; the endpoint sunsets 2026-12-31 | both | high-cost-low-value | crates/socket-patch-core/src/telemetry.rs:33-57,449-913; depscan:workspaces/api-v0/src/endpoints/orgs/telemetry-discriminators.ts:17-43; telemetry.ts:145 | 450 (gated) | 0 | L | no | Owner decision. Either classify the v5 events and move to `/v1/orgs/{slug}/events` (or get the sunset extended), or delete the unread track_* wrappers. |
| 40 | F56 | vlt capstones run in ci.yml (35 rows) and in vlt-compat install-proof (70 legs) | sp | ci-matrix | ci.yml:917-955 (112.5 job-min); vlt-compatibility.yml:189-270 | 0 | 60 (≈10 beyond F51) | L | no | vlt and every vlt version stay. Put the rows on F51's build-once; install-proof excludes the 35 cells ci.yml gates, enforced by test_ci_vlt_rows.py. |
| 41 | F74 | depscan pdm/hatch workflows trigger on pypi task code they never run | ds | ci-matrix | depscan:.github/workflows/pdm-patch-compatibility.yaml:8,20,39; runs 36239865114 (72.1 job-min), 36239865149 (114.9) | 0 | 15 (⊂ F07) | L | partial (F07) | Drop the `pipeline/src/task/python/pypi/**` trigger and add the fixtures/pdm path. Cache the CLI keyed on SOCKET_PATCH_REVISION. |
| 42 | F13 | shared redirect goldens cover ecosystems unevenly; each repo keeps unshared rewriter tests | both | cross-repo-dup | crates/socket-patch-core/tests/fixtures/redirect: 141 cases (vlt 68; pnpm 2; gem/golang/uv 1; poetry/pdm/pipenv 0) | 1,200 (alt. to F01) | 0 | L-M | partial (WS3 gate) | Only if F01 is not done: move byte-asserting TS and Rust cases into shared fixture dirs, starting with pnpm, package-lock, gem, golang and uv. |
| 43 | F37 | serve-route.ts re-inlines the stream/304/HEAD logic that serve-artifact.ts centralizes | ds | intra-dup | depscan:workspaces/patches/src/services/patch-serving/serve-route.ts:158-268; #26856 had to patch both | 110 | 0 | L | no | Route through `serveStoredArtifact({headFastPath: true})`; share `makeDeny`. Metadata Cache-Control is intentionally different, so it is not drift. |
| 44 | F35 | Berry 10c0 checksum implemented twice with hand-copied fixtures; vendored CLI ignores the server value | both | cross-repo-dup | crates/socket-patch-core/src/vendor/berry_zip.rs:335; depscan:workspaces/patches/src/repack/berry-cache-zip.test.ts:1-7; crates/socket-patch-core/src/api/client.rs:1278-1280 | 120 | 0 | L | no | Both implementations stay. Share the fixtures via crates/socket-patch-core/tests/fixtures/berry_zip, read by both; vendored takes the server's yarnBerry10c0 for service artifacts. repacking-to-depscan.md goes further: its verify step 6(vi) always recomputes over the verified tgz as a runtime tripwire, and step 14 puts the vectors under tests/fixtures/served/. |
| 45 | F36 | two npm-registry tarball fetchers inside depscan | ds | intra-dup | depscan:workspaces/patches/src/repack/upstream/npm.ts:56-60,89-145 vs depscan:workspaces/patches-shared/src/registry/npm-registry-source.ts; socket-patch-publishing-tool.ts:1264-1268 | 110 | 0 | L-M | no | Make npm.ts an adapter over fetchNpmTarballBytes (fetch-archive.ts is shared infra and stays); use the packument URL in the publishing tool. |
| 46 | F38 | signature handling diverges; depscan signer seam and signature columns are dead | both | dead-code | depscan:workspaces/patches/src/repack/sign.ts (defaultSign → null); repack-utils.ts:1333-1370 keeps RECORD.jws; crates/socket-patch-core/src/vendor/pypi_wheel.rs:570-585 | 110 | 0 | L | no | Strip RECORD.jws/.p7s in depscan; delete the sign seam; stop writing package_signature. Leave CLI maven alone (frozen). |
| 47 | F34 | every stored object is streamed back in full after upload | ds | expensive-abstraction | depscan:workspaces/patches/src/services/patch-package/build.ts:209,456; gcs-store.ts:108-117 (no checksum header) | 150 | 0 | L | no | Send md5/crc32c (md5 is already computed at build.ts:315,532) and read back only on a 412 collision. The berry and reset parts are in F33/F39. |
| 48 | F43 | public core fns with zero callers survive because rustc exempts pub | sp | dead-code | on integration f8b8d80a: crates/socket-patch-core/src/vendor/bun_lock.rs:89; vlt_lock.rs:1441; lock_inventory/view.rs:57,219,264 | 55 | 0 | L | no | Delete the 5 zero-caller fns and DirEntryInfo; move test-only helpers under cfg(test); add `#![warn(unreachable_pub)]`. |
| 49 | F48 | module-wide `#[allow(dead_code)]` on vlt_lock_text masks a dead method | sp | dead-code | crates/socket-patch-core/src/vendor/mod.rs:102; vlt_lock_text.rs:782 | 7 | 0 | none | no | Remove the allow; delete EdgeEntry::entry_text; use `cfg_attr` on find_node_dirs_sync. |
| 50 | F15 | setup leftovers: frozen hook wheel and Bundler plugin source, plus SetupConfig | sp | dead-code | pypi/socket-patch-hook, gem/socket-patch-bundler (1,053); crates/socket-patch-core/src/manifest/schema.rs:39-60 (43 `setup: None`) | 1,100 (70 new) | 0 | L | yes, WS7 (1,030) | Owner confirms, then delete both dirs; replace the initializers with `..Default::default()`. |
| 51 | F40 | setup-matrix (9 docker legs) is continue-on-error and tests `setup` | sp | ci-matrix | ci.yml:1634-1700; run 36359489402: 50.9 + e2e setup rows | 70 YAML | 56 | none | yes, WS7 (#279, already on integration) | Land WS7. |
| 52 | F17 | napi addon + hosted-bundle have 0 consumers; parity upkeep in 3 PRs | sp | high-cost-low-value | crates/socket-patch-cli/src/hosted_memory (4,546); crates/socket-patch-cli/src/commands/hosted_bundle.rs; ci.yml:77-105 node-addon 2m34s | 0 counted (750 claimed; parity retirement refuted, D4) | 1 | L | WS4 (owner keeps both engines) | After #280 lands and #282 is rebased onto it (F26), make no more hosted edits outside core/hosted. Run node-addon and parity only on `core/hosted/**` PRs until depscan adopts (F01). |
| 53 | F45 | publish dry run re-extracts the file map and re-unpacks upstream to disk to list names (no re-download) | ds | repacking | depscan:workspaces/patches/src/api/commands/review/validate-upstream-anchors.ts:118,178-190; publish.ts:1437-1454 | 30 | 0 | L | no | Fold into F61: convertPatchToPackage returns the entry order; drop the re-unpack. |
| 54 | F61 | one publish downloads upstream up to 3× and repacks twice | ds | repacking | validate-upstream-anchors.ts:74-86 (build discarded); depscan:workspaces/patches/src/services/patch-package/converter.ts:444-454; certify.ts:200-213,351 | 0 | 0 | L-M | no | Stage the dry-run archive by (purl, upstream digest) and let the converter adopt it after a digest re-verify, or cache verified upstream bytes by digest. |
| 55 | F59 | after WS1, vex refetches every record per run | sp | redundant-network | origin/v5/ledger-free-hosted crates/socket-patch-cli/src/commands/vex_sources.rs:888-960 (fetch_patch per uuid :930, fresh client :911) | 0 | 0 | L | partial (WS1/WS6) | Pass fetched records through WS6 ProjectContext, or add an immutable per-uuid on-disk cache (honouring `--offline`). Otherwise each vex run pays about +N views. |
| 56 | F71 | qualifier-less pypi patches: the CLI downloads the served sdist before rejecting it | both | redundant-network | crates/socket-patch-core/src/vendor/pypi.rs:1015-1041,1918-1926; crates/socket-patch-core/src/api/client.rs:1302-1308; depscan:workspaces/patches-shared/src/archive/ecosystem-archive-format.ts:146-165 | 0 | 0 | L | no | Decide from the step-1 artifact filename before the GET; server exposes artifact kind. |
| 57 | F70 | same waste seen from the vendored download path (one fix with F71) | sp | redundant-network | client.rs:1627-1631,1723 (256 MiB cap); crates/socket-patch-core/src/vendor/pypi.rs:1920,2040 | 0 | 0 | L | no | Same change as F71; add one shared sdist-served pypi golden. |
| 58 | F80 | auto mode eagerly fetches pristine upstream for uninstalled packages (only cargo defers) | sp | redundant-network | crates/socket-patch-cli/src/commands/vendor.rs:1838-1913 | −15 | 0 | L-M | no | Generalize the `cargo_via_service` deferral (PackageSource::Deferred) to every service-backed ecosystem. Superseded if repacking-to-depscan.md Phase 4 lands; the Deferred arm is deleted there (step 27). |
| 59 | F60 | hosted scan downloads each patched wheel in full to read METADATA | both | redundant-network | crates/socket-patch-cli/src/commands/scan/hosted.rs:1974-2096; crates/socket-patch-core/src/vendor/pypi.rs:89-127 | 0 | 0 | M | no | depscan persists PEP 658 metadata + hash and returns them from /patches/package; the CLI uses them and falls back to the download. |
| 60 | F66 | converter reads patched blobs one at a time | ds | other | depscan:workspaces/patches/src/repack/convert-patch.ts:140-185 | 0 | 0 | L | no | Bounded concurrency (~16), start the upstream download first; the dry-run adapter should honour abortSignal (validate-upstream-anchors.ts:323-327). |
| 61 | F69 | pypi bz2/xz sdists are selected, downloaded (≤256 MiB), then refused | ds | high-cost-low-value | depscan:workspaces/patches/src/repack/upstream/pypi.ts:152-168; repackers/pypi.ts:131-138; repack-utils.ts:771-797 | 0 | 0 | L | no | Reject non-.tar.gz/.zip sdists in the selector before downloading; add an xz arm. No CLI change. |
| 62 | F67 | disk stager treats diff-archive presence as full coverage; created files fail after default `repair` | sp | other (latent bug) | crates/socket-patch-cli/src/commands/fetch_stage.rs:212-235,316-320; crates/socket-patch-cli/src/commands/apply.rs:236,281; depscan generate-patch-diff-archive-task.ts:84-92 | 0 | 0 | L | no | Plausible, not reproduced. Make `repair` default to file mode, or require blobs for files with an empty before_hash; add a created-file test. |
| 63 | F50 | next depscan bump fails golden.test.ts on the 68 new vlt cases | both | cross-repo-dup | depscan:workspaces/app/src/patches/registry-rewrite/golden.test.ts:50-60; crates/socket-patch-core/tests/redirect_golden.rs:22-37 | 0 | 0 | L | no | Add a per-flavor TS_IMPLEMENTED allow-list mirroring RUST_IMPLEMENTED; do not port vlt to TS. |
| 64 | F77 | one red base test skips the e2e tier on all v5 PRs | sp | ci-matrix | crates/socket-patch-cli/tests/e2e_redirect_cargo_build.rs:829; ci.yml:676 `needs: test` | 0 | one-off (~3,100 spent) | L | no | Fix or quarantine case (3) and decide offline-vex-without-ledger semantics in WS1; rebase #279–#283. Do first. |
| 65 | F78 | in-flight v5 PRs: 344 runs, 34% cancelled or failed; #280 3.75 h without a CI verdict | sp | ci-matrix | ci.yml:22-24; run 36371317869 cancelled at 22 min after 303 job-min | 0 | ~200 per draft push (transient) | L | no | For drafts, run heavy CI and compatibility workflows on ready_for_review, a label or dispatch; put cheap gating jobs first. |
| 66 | F63 | five drafts cut in parallel from one base on the same hot files | sp | ci-matrix | merge-base 8ae7dc37 for all; crates/socket-patch-cli/src/commands/get.rs and tests/covgap_commands_rollback.rs touched by all 5 | 0 | ⊂ F78 | L | no | Rebase serially (WS1 → WS3 → WS4 → WS5 → WS7/8); skip compatibility workflows on drafts. |
| 67 | F26 | #282 moves the hosted ledger into core while #280 deletes it | sp | other | origin/v5/one-hosted-engine crates/socket-patch-core/src/hosted/ledger.rs (311); merge-tree: 10 conflicts | 0 terminal (311 churn) | 0 | L | partial (WS4 depends on WS1) | Land #280 first, rebase #282, drop core/hosted/ledger.rs except the migration-only reader. |
| 68 | F44 | #279 WS8 edits hosted text and tests that #280 deletes and #282 moves | sp | other | #279 469a6711/f200524f; core/hosted/guidance.rs:46-107 on #282 still says "redirect" | 0 terminal (30 churn) | 0 | L | WS8 | Apply the WS8 hosted wording after #282, in core/hosted/guidance.rs. |
| 69 | F05 | two builders per archive-shaped artifact produce different bytes; reuse.rs hides the flip | both | repacking | crates/socket-patch-core/src/vendor/npm_pack.rs:21-43 vs depscan:workspaces/patches-shared/src/archive/repack-utils.ts:597-660; crates/socket-patch-core/src/vendor/reuse.rs:1-12 | 0 counted (3,300 if rebuild dropped) | 0 | M | WS5 caveat; #283 keeps rebuild | The owner keeps the local rebuild (WS5; blockers in F72). The only actionable part is aligning the npm recipe (upstream order, mtime 0) so both builders produce the same bytes and reuse.rs shrinks; this stays useful while WS5 keeps the rebuild. See repacking-to-depscan.md for the gated deletion path (gross ~2,050 src / ~1,260 test, net ≈ −1,150 src after ~900 src / ~900 test of additions). |

## Measurements and checked-not-waste

These are kept as facts. They are not ranked and their LOC is not counted as
net-new.

| id | what it established | use |
|----|---------------------|-----|
| F08 | WS1 test surface: 80 test files and 326 refs to redirect-state; about 2.2k LOC of ledger-only tests | Within WS1: delete ledger-only corrupt/replay tests instead of porting them; keep tests for the legacy-read migration (v5-plan.md:47). |
| F31 | hosted.rs ↔ hosted_memory still share 161 verbatim lines on integration; only #282 removes them | Counted inside WS4 (#282). |
| F42 | Deprecated aliases, tool_command and the CI old-path grep are already deleted on integration | Done; list them as breaking changes in the v5 notes. |
| F62 | bun.lockb writer and vex/discover reuse the shared codecs | Not waste; WS3 `wired_refs()` absorbs the glue. |
| F64 | Per-PR deletion ledger (see Totals) | Use it for the de-duplication below. |
| F65 | #283 keeps the local rebuild and resolves repair/service | The #283 plan note is the WS5-caveat answer. |
| F68 | The diff archive and the repacked package serve different modes | Assess the diff channel against blobs, never against repacking. |
| F72 | Server fail-closed classes make the local rebuild the only vendoring path for them (pypi qualifier-less/wheel-only, locally pinned wheels and tarballs, bzip2 sdists) | Blocks F05; verification removed gem platform and go no-go.mod as blockers. |
| F75 | depscan repack tests are 0.4% of Tap Unit and 0.9% of Tap Integration time | Do not cut repack tests; patches Tap cost is orchestration and backtests. |
| F76 | Map corrections: repack 6,015 src / 4,976 test (111 `tap.test` + 22 `t.test`); berry_zip.rs 333 src; reuse.rs 382 src; purl-api-proxy path | Figures used here. |
| F79 | Bump depscan's gitlink in three steps (base tip, then integration, then past #280), pre-flighting each SHA | Sequencing for F11, F27 and F50. |

## Top-10 cuts

| # | id | cut | code | test | docs/YAML | CI job-min/run |
|---|----|-----|-----:|-----:|----------:|---------------:|
| 1 | F51 | e2e build-once fan-out | 0 | 0 | 0 | 280 (ci.yml) |
| 2 | F03 | delete #257 oracles after snapshotting inputs | 0 | 6,500 | 0 | 0.5 |
| 3 | F02 | delete depscan refactor docs except DAG/ | 0 | 0 | 8,222 | 0 |
| 4 | F41 | drop per-push e2e-docker | 0 | 0 | 65 | 65 (ci.yml) |
| 5 | F04 | one test suite per command | 0 | 4,000 | 0 | ⊂ F58 |
| 6 | F53 | build Dockerfile.base once | 0 | 0 | 0 | ≈35 after F41 (ci.yml) |
| 7 | F55 | pdm capstone build-once + dedupe | 0 | 0 | 0 | 65 (pdm-compat) |
| 8 | F52 | tier middle PM versions off PRs | 0 | 0 | 0 | ≈40 after F51 (ci.yml, PR only) |
| 9 | F06 | retire depscan legacy engine (incl. F19) | 2,750 | 250 | 0 | 0 |
| 10 | F01 | depscan calls the Rust engine; delete TS twin (gated) | 5,000 (gated) | 5,500 (gated) | 0 | 1 (depscan) |
| | | **total** | **7,750** | **16,250** | **8,287** | **≈420 ci.yml per PR run (≈380 main push) + 65 pdm-compat + 1 depscan (F01, gated)** |

32.3k lines in all, including the gated F01 (10.5k); 21.8k actionable now.

## Totals

### Net-new savings (not in v5-plan or PRs #279–#283)

| bucket | (a) code | (b) test | (c) docs/non-code | total |
|--------|---------:|---------:|------------------:|------:|
| Actionable now | 9,137 | 14,925 | 8,752 | 32,814 |
| Gated (F01 adoption, F07 capture contract, F14 diff-mode decision, F18 backlog drain, F22 telemetry decision) | 6,275 | 9,395 | 0 | 15,670 |
| **Net-new total** | **15,412** | **24,320** | **8,752** | **48,484** |

- Code (a): F06 2,750, F09 1,600, F12 1,200, F16 900, F20 360, F25 320,
  F24 280, F32 220, F21 150, F28 150, F30 150, F34 150, F27 140, F33 100,
  F39 100, F36/F37/F38 110 each, F15 (SetupConfig part) 70, F29 90, F43 55,
  F45 30, F48 7, F80 −15. Gated: F01 5,000, F14 565, F22 450, F18 260.
- Test (b): F03 6,500, F04 4,000, F10 1,400, F11 1,380, F21 300, F06 250,
  F20 200, F29 170, F27 160, F28 150, F24 145, F35 120, F30 100, F33 50.
  Gated: F01 5,500, F07 2,900 (Python harness), F18 430, F14 565.
- Docs and non-code (c): F02 8,222 (depscan refactor docs), F23 440 (depscan
  deploy YAML), F41 65, F46 13, F47 10, F49 2 (ci.yml).
- (d) CI job-min per run, de-duplicated:
  - socket-patch `ci.yml`: F51 280, F41 65, F52 ≈40 (after F51, PR only),
    F53 ≈35 (after F41), F47 ≈23 (after F51), F49+F58 ≈30 combined, F46 ≈3
    (after F51), F17 1, F03 0.5, F10 0.3. Total **≈478 per PR run, ≈438 per
    main push**, against 945 for main push 36359489402. The standalone sum
    is about 585 (F52 at ≈90); the difference is the overlaps below.
  - Compatibility workflows, per triggered PR push: F55 65, F57 12, F56 ≈10
    (install-proof dedupe beyond F51), F54 8. About **95**.
  - depscan, actionable: F73 7.5 + F11 2 ≈ **9.5 per api-v0 CI run** (~130
    runs/day). Gated: F01 1, F14 0.5, F18 0.3 (Tap unit/integration, not
    api-v0). F07 adds 30 per pdm/hatch trigger (F74's 15 is its interim
    subset).
  - Transient, during the v5 train only: F78 about 200 per draft push. F78
    uses the savings verification's ≈200 rather than the recorded 250
    (compatibility workflows are path-filtered). F63's recorded 475 is an
    upper bound on the same cancelled runs and is not counted. F77: about
    3,100 job-min already spent on runs whose result was known in advance.

### Overlaps not double counted

- F19 ⊂ F06 (same file); F74 ⊂ F07; F70 = F71 (one fix); F63 ⊂ F78;
  F45 ⊂ F61's change.
- F13 is the alternative to F01: its TS half is inside F01's 5.5k test LOC.
  It is excluded.
- F17's 750 is excluded because hosted_memory_parity retirement was refuted
  (D4); only its CI gating (1) counts. F31 is WS4.
- F56's ci.yml half (≈50 of 60) is inside F51. F52 and F46 shrink once F51
  cuts leg cost from about 3.0 to about 1.2 min.
- F47's 3 e2e_safety rows are F51 legs (11.1 job-min at full cost); after
  F51 they save ≈4, so F47 ≈23 is counted, not 30.
- F53 after F41 keeps only coverage-docker's builder stage; its setup-matrix
  share is WS7.
- F49, F58 and F04 overlap (fewer binaries and one compile), so ≈30 is
  counted, not 43.
- F11 carries the depscan setup test deletion; F40 and F73 mention the same
  59 file and are not counted again.
- F27 carries the depscan ledger change; F11(e) is the same item.
- F26 and F44 are churn avoided (0 terminal LOC).
- F05 (3,300) is excluded: the owner keeps the rebuild, and F72 lists the
  blockers.
- Residual risk of double counting: F10 vs F04 (≤0.7k of e2e/in_process
  CRLF tests); F04 vs F08 (ledger tests inside covgap files, which WS1 owns).

### Already planned (context, not counted)

Per-PR ledger (F64, verified; `git diff --shortstat 8ae7dc37`):

| branch | + / − | net | note |
|--------|-------|----:|------|
| #279 remove-setup-and-ui (WS7/WS8) | +1,599 / −31,648 | −30,049 | setup removal |
| #280 ledger-free-hosted (WS1) @08c30b7e | +21,968 / −21,268 | +700 | adds upstream/* 8.4k (see F16); at 65aa0744: +23,055 / −21,269, net +1,786; upstream/* 8,752 |
| #281 lock-models (WS3) @85421f3b | +4,495 / −3,353 | +1,142 | |
| #282 one-hosted-engine (WS4) | +5,209 / −4,634 | +575 | ports ledger into core (F26) |
| #283 vendor-backend (WS5) | +2,776 / −6,325 | −3,549 | keeps local rebuild |
| v5/integration (#279+#281+#283) | +7,974 / −40,841 | −32,867 | tests 9,256 → 8,589 |

- Setup removal is 77.5% of integration's gross deletions and about 91% of
  its net. WS1, WS3 and WS4 are net additions until F16 and F26 are folded
  in. Report v5 savings from integration totals, never per PR.
- Findings that fall inside this planned work: F08 (2.2k WS1 tests), F15
  (1,030 of 1,100, WS7), F31 (WS4), F40 (70 YAML, 56 job-min, WS7), F42
  (follow-ups, done). Also excluded: F04's covgap_setup* (2,717), F58's ~21
  setup binaries, F10's core/setup CRLF tests, and F53's setup-matrix image
  builds.
- Extends-plan items are counted as net-new because the plan does not name
  their deletions: F09, F10, F16, F25 (WS3); F12, F32 (WS3/WS5); F21, F29
  (WS8); F46 (follow-ups); F27, F59 (WS1/WS6 counterparts); F17 (WS4
  sequencing).

## Repacking summary

Full treatment: [repacking-to-depscan.md](repacking-to-depscan.md).
- depscan builds every served artifact asynchronously after publish:
  `published_patches` is the queue, patch-package-converter does the build,
  and outputs are write-once GCS objects. Only registry metadata is
  assembled per request. depscan repack is 6,015 src / 4,976 test LOC.
- The CLI's local builders are about 2.8k src (npm_pack, berry_zip,
  pypi_wheel, reuse, part of registry_fetch; F05 correction). They are the
  `auto` fallback, `build`, `--offline` and dry-run path. The 9-file map
  total of 6,515 src / 7,780 test includes golang_local.rs and prestage.rs,
  which are not the local build. Of the local build,
  repacking-to-depscan.md deletes ~2,050 src / ~1,260 test if the WS5
  caveat is reversed; pypi_wheel (the one local class), berry_zip (the
  verifier and WS1), the verifiers and maven/nuget stay.
- The two builders' bytes differ for every archive-shaped ecosystem (F05).
  #283 keeps the rebuild; F72 lists the classes only it can vendor.
- Waste on the server: F61 and F45 (publish re-downloads and repacks), F66
  (serial blob reads), F69 (bz2/xz after download), F33/F34/F38/F39
  (sidecars, read-back, sign seam, reset paths), F36 (second npm fetcher).
- Waste in the CLI: F70/F71 (discarded sdist downloads), F80 (eager
  pristine fetch), F28 (per-uuid reference POSTs).
- Shared: F35 (10c0 twins, fixtures only).
- Not waste: repack test time (F75); diff vs repack (F68).
- The service-hit vs local-fallback rate is still unmeasured. CLI telemetry
  does not record vendor-source fallback. Any decision to drop the rebuild
  needs that number first (see Caveats).

## Dropped findings (refuted; do not re-raise)

| # | finding | refuted because |
|---|---------|-----------------|
| D1 | Two lockfile patch-reference recognizers with unequal fixture corpora | Both are needed: the offline fail-closed CLI and the server SBOM resolve. Nothing is removable (0 LOC). |
| D2 | Go hosted pin implemented three times | False: the CLI has one go.sum writer; rewrite_golang calls go_sum_edit (redirect/mod.rs:7160). |
| D3 | #280 carries dead takeover.rs/replay.rs/client.rs.orig | Stale snapshot: the #280 head already deleted them (9b0f61b8). |
| D4 | hosted_memory_parity becomes a self-comparison after WS4 | False: the memory side keeps its own discovery, roots and selection front end; savings overstated ~10×. |
| D5 | vlt scenarios tested up to 4 times | Not duplicates: synthetic in-process trees vs real-installer e2e; deletion would drop unique coverage. |
| D6 | depscan api-v0 e2e retests CLI internals; vendor suites never hit the server | False: 89–94 seed real patches and download through live api-v0. |
| D7 | Test LOC concentrated in low-churn code; lock_inventory barely tested | Measurement error (test-only files counted as src); 0 savings. |
| D8 | depscan repack operator CLIs are dead | Manual operator tools, not dead code. |
| D9 | CLI fetches full patch views instead of metadata/batch records | Most call sites reuse the full view for the download; the fix adds code (a new client method and proxy route) and removes none. |
| D10 | Vendored staging downloads blobs before asking the service | False for scan/get: they seed blobs from the records download; the fix needs an endpoint the client lacks. |
| D11 | vlt preflight downloads every hosted tarball each scan | The bodies feed heal and stale detection; the fix adds code; 0 savings. |
| D12 | Telemetry builds a new HTTPS client per event | Each command sends once; negligible savings. |
| D13 | scan/vex/vendor re-crawl in separate processes | By design (VEX attests current disk bytes); `scan --vex` already reuses the crawl; 0 savings. |
| D14 | Self-evolving harness: 10.3k LOC plus 2×1 TiB Filestore | Infra is gated per env (prod disabled); the cost claim is wrong. |
| D15 | Maven/NuGet vendoring costs 13k LOC and ~87 job-min | Most of it is hosted maven/nuget (not frozen; WS1 extends it) or setup (WS7). |
| D16 | ledger_snapshots v2 schema is waste | The proposed redesign is the one reverted for data loss (5c173d6c); net savings ≈0. |
| D17 | Self-update subsystem is high-cost/low-value | Standalone install is the headline channel (Windows needs it); 0 savings proposed. |
| D18 | WS1 makes berry_zip/registry_fetch load-bearing | Already load-bearing across vendored paths; the recommendation moves code, it deletes none. |
| D19 | Default diff mode always downloads blobs; delete the bsdiff channel | The default `repair` writes diff-only sources that later apply from, so the channel does save bytes (see F14, F67). |
| D20 | Size/entry caps differ between the server and CLI fetchers | Mostly false (the CLI is more permissive on served artifacts); not waste. |
| D21 | depscan upstream fetchers have no fetch/verify tests | False: 8 live repack-checksum e2e suites (3,219 LOC); it is a coverage gap, not waste. |
| D22 | Missing-digest policy differs (composer/old npm) | Not waste; misreads when the CLI composer fetch runs. |
| D23 | Sidecar md5 computed for every artifact but served only to maven | Negligible (~15 LOC); misreads the maven freeze. |
| D24 | Service-hit vs fallback rate unobservable | Service side is observable (patchServer.downloads); the fix adds code. The data gap is kept as a caveat. |
| D25 | Build-state gauges lack an ecosystem label | Per-ecosystem failure counters already exist; the fix adds code. |
| D26 | depscan "patches - Installer E2E" path filter too broad | A safe filter must keep imported lib/app/pipeline paths; savings fall below the bar. |

## Caveats

- **History.** socket-patch history starts at 2025-11-10 (51ea2850). Churn
  and fix-commit counts cover about 10.5 months, and subject-only vs
  body-matching `--grep=fix` counts differ; the verification notes say
  which. depscan
  counts use `--follow` where files moved.
- **Moving branches.** #280 and #281 moved during the review (#280 f1cc47bb
  → 08c30b7e → dc634b31 → 65aa0744). F16, F26, F44 and F59 cite branch heads and need a
  re-check before acting.
- **Line numbers.** They are against release/v5-prerelease 8ae7dc37 unless
  marked integration (f8b8d80a) or branch. ci.yml lines differ by about 22
  between the two.
- **socket-patch CI minutes.** Job-minutes from the Actions job API: main
  push 36359489402 (246 jobs, 944.9 job-min) and PR runs 36363939533,
  36363939563, 36368399706, 36362334985. They are job-minutes, not wall-clock
  and not billed minutes (macOS bills 10×, Windows 2×). Some logs were read
  only from the 5,000-line tail, so compile shares were sampled. Numbers
  "after Fnn" are derived, not measured.
- **depscan CI minutes.** An early estimate came from
  localdev/tap/test-durations.json and was corrected by measuring 7 runs
  (F75). Deploy and pdm/hatch runs report 0 billable ms (non-billed runners),
  so their totals come from per-job durations.
- **Production data.** None of it was queried. Grafana SQL and gateway logs
  are needed for F18 (backlog count), F20 (purl-api /patch traffic), F33
  (.berry.zip fetches), F71 (bare-purl pypi share), F14 (diff-route
  telemetry), and the service-hit vs local-fallback rate that any
  local-rebuild decision needs.
- **Not measured.** The full cost of a depscan submodule bump was not run
  end to end (F11 is grep-based; its vendor suites 89–94 were not run
  against integration). F67 is plausible but not reproduced.
- **Savings.** They assume the recommended change, not deletion by default.
  Savings lens refuted but 2 of 3 upheld: F13, F17, F28, F34–F39, F43, F45,
  F48, F80 (figures are the corrected ones, or 0 where the correction says
  nothing is removable). Value lens refuted but 2 of 3 upheld: F05, F10,
  F14, F18, F23, F24, F25, F27, F63, F78. The 0-LOC ranked findings F44,
  F50, F59–F61, F66, F67, F69–F71 and F77 also had the savings lens refuted
  and count nothing. The rank column does not show votes; this list does.
