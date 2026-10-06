> [agent] **Part 8 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 8: Tests, CI, docs and distribution

_Last checked against main @ 9c43dfc on 2026-10-06 by audit-core. Owner: audit-core._ Only the repository-hygiene passages (stray `launch.json`, "DESIGN §" references), §8.3's `CLI_CONTRACT.md` measurements and guards, the contract's argument and env-var tables, the test-binary and covgap counts, the `#[serial]` count and the duplicated-helper counts have been re-checked; the rest is as of `2463257`.

> Scope: `crates/*/tests/**`, `tests/` (docker fixtures), `.github/workflows/*`, `.github/actions/*`, `scripts/`, `docs/`, `CLI_CONTRACT.md`, `CHANGELOG.md`, `npm/`, `crates/socket-patch-node/npm/`, and the Cargo profiles. CI timings come from the GitHub Actions run for `2463257` on `main`.

PR #277 has already started cleaning up: it deleted 237,608 lines, including 136,809 lines of `docs/testing/*/results.json` and the pypi/gem distribution packages. The recommendations below build on that.

### 8.1 Test suite architecture

| | Lines | Files | Test binaries |
|---|---:|---:|---:|
| `crates/socket-patch-cli/tests/**` | 235,571 | 302 `.rs` | **172** (161 top-level + 11 `*/main.rs`) |
| `crates/socket-patch-core/tests/**` | 19,361 | 33 | **32** |
| Inline `#[cfg(test)]` in `src` | ~183–194K | — | 3 unit targets |

- **Ratio:** roughly 2.7 test lines per production line overall, and **about 7:1 for the CLI crate** (235.6K integration lines against 33.7K production lines).
- **Test counts:** ~2,753 CLI integration tests, 523 core integration tests and 5,442 inline tests. 242 are `#[ignore]`-gated.
- **207 test executables per `cargo test --workspace`** at the review; **224** on `9c43dfc` (189 CLI, 35 core). {{C31}} There are no `[[test]]` entries, so every file links its own binary. The repo's own comments disagree on the count ("~240" in `ci.yml`, 159 in `Cargo.toml`, "~90" in `.cargo/config.toml`).
- **Disk cost:** `Cargo.toml` notes that macOS split-debuginfo "grew target/ to 99 GB".
- **Docker binaries are always linked.** The 14 `docker_e2e_*.rs` files are gated with `#![cfg(feature = "docker-e2e")]`, so they still compile and link as empty binaries on every default run.

**Consolidation was started but not finished.**
- `cli/main.rs` says: "One test binary per command: each module was its own binary". `e2e_vex_lockfile/` (23 modules, 19,650 lines, one binary) is the model to follow.
- The stragglers are still separate binaries:
  - 10 `get`-related binaries beside `get/`, and 10 `scan`-related beside `scan/`;
  - 19 `cli_*` files beside `cli/`;
  - 28 `in_process_*`, 16 `e2e_vendor_*` and 14 `e2e_redirect_*` binaries.

**Duplicated helpers.**
- `common/mod.rs` (792 lines) is `#[path]`-included and recompiled by ~60 binaries, and `vex_e2e_common` (876) by ~53. 34 helper files carry `#![allow(dead_code)]`.
- Helpers that `common` already exports are redefined locally:
  - `fn binary()` in **103 files** (7 variants);
  - `fn git_sha256` in **86 files** (10 variants), although `common::git_sha256` exists and core exports `compute_git_sha256_from_bytes`;
  - `copy_dir_recursive` in 26 files;
  - `scrub_socket_env`: since #850, child processes are built by one `common/hermetic.rs` builder, and 7 per-file copies remain (the `PENDING_SCRUB_COPIES` list in `tests/spawn_env_hygiene.rs`); 2 files still spawn the binary with no scrub (see {{C47}}). {{C30}}
- `vex_pdm_hatch_common` and `vex_pipenv_pip_common` share **977 identical non-blank lines** (78% similar).

**Coverage-chasing tests.**
- 32 `covgap_*`/`coverage_fix_*` files hold 27,226 lines and 407 tests (on `9c43dfc`; the review counted 26,916 and 402). {{C32}} 136 of those test names are about human output (`human`, `message`, `prints`, `summary`, …).
- 43 test files import `socket_patch_cli::commands::*` internals, which only works because `lib.rs` makes `commands` `pub`.
- The coverage job does not gate anything ("No threshold gating").
- In fairness, the sweep that produced them found 39 real bugs (#236). **Keep the regressions, rename them by behavior, and drop the rest.**

**Exact human-text assertions.** 328 `.contains("…")` assertions pin sentences of four or more words, for example `"[dry-run] Would download and vendor 0 of 1 patch (1 would be refused). No changes made."`. The repo has no snapshot tooling. The output-polish PR (#248) had to touch **65 test files (4,346 lines)**.

**Process-global env forces serialization.** `args.rs` mirrors flags into process env (see Part 2.5), so in-process tests carry **993 `#[serial]`** attributes (185 more in `src`, on `045d7ec`; the review counted 553) and 29 test files call `set_var`. That is the main obstacle to merging binaries. CI uses no nextest, mold/lld or sccache.

### 8.2 CI cost

For `2463257` on `main`:
- **CI workflow:** 237 jobs and **348 runner-minutes** over 31.9 minutes of wall time.
- **Critical path:** `test (windows-latest)` at **28.1 min**. Ubuntu took 14.0 and macOS 20.0. #278 raised the Windows timeout from 35 to 50 minutes.
- **Repeated compiles:** every PR compiles the full test tree **8 times**: `test` ×3, `test-release`, `coverage`, and `e2e-build` ×3 (with `--all-features`, which is another feature set).
- `test` also runs `cargo build --workspace`, which builds the napi addon on all three OSes for no test benefit.

**About 516 jobs per push across all workflows:**

| Workflow | Jobs | Wall |
|---|---:|---:|
| CI | 237 | 31.9 m |
| vlt | 88 | 12.7 m |
| bun | 52 | 24.1 m |
| pdm | 44 | |
| poetry | 30 | |
| pnpm | 26 | |
| composer | 18 | |
| npm | ~11 | |
| go | ~6 | |
| pipenv | ~3 | |

- **The PR `e2e` matrix has 148 legs** (108 ubuntu, 23 macOS, 17 windows). They total 99 runner-minutes at about 40 seconds each, so scheduling overhead dominates. Most legs are version sweeps: vlt 35, bun 20, maven 17, ruby 14, uv 10. An `e2e-full` off-PR tier already exists.
- **Report-only coverage still runs on every PR:**
  - `coverage` 11.7 min;
  - `coverage-docker` ×9, 56 min;
  - `docker-base` 5.3 min, which compiles a full-LTO binary that the PR consumer then overrides;
  - `coverage-merge`.

  That is **≈74 runner-minutes (21% of the run)** that gate nothing.
- **Nine `*-compatibility.yml` files (2,041 lines) re-implement the same shape:** build, upload, download, install a pinned package manager, run.
  - The same inline Python "copy executables from cargo `--message-format=json`" snippet appears four times, and `scripts/ci-e2e-bundle.py` is a fifth copy.
  - go, composer and pipenv compile on every leg instead of building once: 25 per-leg compiles.
- **Path filters:** 204 hand-maintained patterns, two of them dead (they reference files deleted in #277).
- **vlt is disproportionate:**
  - about 123 jobs per push;
  - 6,079 lines of vlt-only workflows, scripts, docs and manifests, plus a watchdog workflow;
  - 15,943 lines of vlt tests and 727 fixture files.

  For comparison, npm compatibility is 11 jobs.
- **Hygiene:**
  - Toolchains and actions are well pinned (SHA-pinned actions, enforced by `pin-check.yml`).
  - But `.github/actions/actions/cache/0057852b…/.vscode/launch.json` is a stray Jest launch config from the `actions/cache` repo, accidentally committed in #358 and referenced by nothing. {{C08}}
  - `scripts/ci-e2e-bundle.py` imports a YAML parser from a *test* file.

### 8.3 Docs

**`CLI_CONTRACT.md` is not maintainable as written.**
- **Size:** 1,940 lines and 379 KB on `9c43dfc` (1,638 and 332 KB at the review). 54 lines exceed 1,000 characters, 13 exceed 3,000, and the longest is **11,338 characters** (line 166). {{C33}}
- **History mixed into reference:** 155 lines carry a `v5.0` annotation and 29 a `MAJOR`/`BREAKING` marker (counted per line on `9c43dfc`).
- **Stale:** "Migration status (v3.0)" still promises a follow-up PR.
- **Misordered:** "Vendored JVM support (v5)" sits after "How the contract is enforced".
- **Drift from the code:**
  - One documented code no longer exists in `src`: `vendor_lock_checksums_unsupported`.
  - Undocumented codes: on `9c43dfc`, 43 code-shaped literals in emitting positions appear nowhere in the contract, among them `rollback_not_installed`, `vendor_service_unsupported_ecosystem`, `hosted_restore_failed`, `invalid_manifest` and the `redirect_composer_*`/`redirect_pnpm_*`/`redirect_requirements_*` families. {{C13}}
  - Only the vlt codes (`scripts/tests/test_vlt_coverage.py`) and the Gradle/JVM codes (`tests/contract_gradle_codes.rs`) are checked mechanically. "How the contract is enforced" credits the `cli_parse_*` tests, which assert the parser, not the document.
  - The argument and env-var tables match `--help` on `9c43dfc`, except that four `SOCKET_VEX_*` names are only abbreviated in the env table. Nothing pins them, and the scrub list `LOCAL_ARG_ENV_VARS` lacks `SOCKET_NO_SOCKET_YML` and `SOCKET_MIN_SEVERITY`. {{C33}}

**User docs are lean, with rough spots.**
- The good: `README.md` (6.7 KB) has a clear scan → install → vex flow, and `usage.md`, `configuration.md` and `migrating-to-v5.md` are well scoped.
- `README.md` documents the v5 prerelease while the one-line installer installs the latest release (v4.0.0). A note discloses this, but a new user can easily read about behavior they won't get.
- `docs/ecosystems.md` has single table cells of 1,382 and 1,827 characters, and vlt alone takes 138 of its 579 lines.
- **39 references in 20 files point to a "DESIGN §x.y" document that is not in this repository** (recounted on `045d7ec`). {{C08}}

**`docs/testing/*` doubles as test input.** `vlt-compatibility.md` tables are parsed by `scripts/check-vlt-legs.py`, which produces `tests/vlt-leg-manifest.json`, which a Python test checks against the doc. `vlt-coverage.json` maps codes to Rust test *function names*, so renaming a test breaks a Python test that reads a JSON file under `docs/`.

### 8.4 Scripts and distribution

- **Scripts:**
  - 12,349 lines of Python, 8,569 of them in six `backtest-*.py` harnesses with little shared code. `backtest-uv.py` (1,474 lines) and `probe-uv-boundaries.py` are run by no workflow.
  - 2,646 lines of TypeScript Claude-agent sweep harnesses. Three of them are referenced by no doc or workflow.
  - The perf harness (`scripts/perf`) is small, documented and valuable. Keep it.
- **Distribution:**
  - 14 per-platform npm packages plus the wrapper (15 in total), plus a private napi package that is built and smoke-tested on every PR (2.7 min) but never released.
  - **The target list is repeated in at least 8 places:** `install.sh`, `release.yml`, `publish-npm.yml`, the npm `bin` `PLATFORMS`, the wrapper's `optionalDependencies`, 14 `package.json` files, `update/release.rs` and `commands/update.rs`.
  - **Release artifacts are never executed.** 11 of the 14 targets never run a test anywhere.
  - `scripts/version-sync.sh` misses `crates/socket-patch-node/npm/package.json`.
  - The npm wrapper's zod manifest schema duplicates the Rust `PatchManifest`, lacks its `setup` field, and its test runs in no CI job.

### 8.5 Recommendations

| # | Action | Impact | Risk |
|---|---|---|---|
| A | **Merge 207 test executables into ~25.** Finish the per-command directories; put the docker suites behind `[[test]] required-features`; group e2e by mode | Largest compile/link saving; shortens the 28-min Windows critical path; much smaller `target/` | Medium (the 553 `#[serial]` env tests must be fixed first; see Part 2.5) |
| B | **Move report-only coverage and `docker-base` off PRs** | ≈74 runner-min and 12 jobs per run | Low |
| C | **Cut the PR e2e tier from 148 to ~50 legs** (boundary versions only); move the vlt/bun sweeps to nightly | Up to ~200 fewer jobs per PR | Low–Med |
| D | **A `socket-patch-test-support` dev crate**: delete the 102 `binary()`, 84 `git_sha256` and 14 divergent env scrubbers; merge the forked VEX helpers | ~3–6K lines; hermeticity | Low |
| E | **A reusable compat workflow** plus a `setup-pm` composite action; no per-leg compiles; fix the dead path filters | ~2,041 → ~900 workflow lines | Medium |
| F | {{C33}} **Split `CLI_CONTRACT.md`**: a *generated* reference (flags from `Cli::command()`, env vars, an `errorCode` registry in code, exit codes) plus 300 lines or less of prose, with a freshness test | Fixes the measured drift | Low |
| G | **Replace the 328 sentence assertions** with `--json`/`errorCode` checks plus a few `insta` snapshots | Copy edits stop touching dozens of files | Low |
| H | **Triage the 402 covgap tests**: keep the regressions, drop the ~136 output-text cases, stop importing `pub` internals | ~8–12K lines | Medium |
| I | **Decouple `docs/testing` from validation**: data in `tests/specs/`, generate markdown from it; fix or remove the 39 "DESIGN §" refs | Lower coupling | Low |
| J | **Hygiene:** delete the stray `.vscode`; single targets table; `--version` smoke test on release artifacts; fix `version-sync.sh`; run or generate the zod schema test; move the agent-sweep scripts to `tools/`; path-filter the `node-addon` job | Prevents silent release drift | Low |

### New findings since the review

- {{C47}} Test files that spawned the CLI with no `SOCKET_*` scrub: on `045d7ec` an ambient `SOCKET_DRY_RUN=true` or `SOCKET_OFFLINE=true` turned 18 of the 19 `repair_vendor_e2e` tests red. Since #850, 8 of the 10 spawn through the hermetic `common/hermetic.rs` builder, and the `spawn_env_hygiene` ratchet fails on a new bare spawn. `scan_invariants` and `in_process_npm_multicopy` remain.
- {{C40}} Env vars that core reads directly have no documentation guard: `SOCKET_API_CONCURRENCY` (the operator throttle for the patch API) and `SOCKET_WALK_THREADS` appear in no doc. Only clap-bound vars are checked, through `GLOBAL_ARG_ENV_VARS`/`LOCAL_ARG_ENV_VARS`. It is the env-var slice of 8.5 F.

---
_Generated by [Claude Code](https://claude.ai/code)_
