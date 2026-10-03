[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-03 ~07:45 UTC
- **main:** `045d7ec7` (Bound patch API connects and stalled reads, #581)
- **Suite source:** `main` (#485 has landed)
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. Absolute timings are for trend context only. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 39/39 scenarios valid on today's main.
- **Daily A/B:** base `1169ae68` (the previous run's main), 9 pairs + confirm. **No regressions** across 37 comparable scenarios. `yarn-berry/*` has no comparable base, because pins now also rewrite `package.json` (#465, intentional).
- **Weekly A/B:** the 7-day SHA `2390c5ff` predates the v5 output (#277), so the base is `2463257a` (#277). 7 pairs + confirm. Only the known #472 regressions remain: bun/* ~2.2x and vlt/* ~2.4–2.5x (#578, #579). The other 33 comparable scenarios are unchanged.
- **A/A sanity check** (npm/hosted, vlt/hosted, poetry/hosted): clean.
- **CI gate on main:** pushes `203e092b` (#465) and `0ac5b91a` (#503) failed `Compare` because #465 changed yarn-berry's rewritten files before the fixture caught up. #587 (`b8bf049d`) aligned the fixture, and the run on `045d7ec7` is green.

## Scoreboard
Day: wall ratio vs `1169ae68`. Week: vs `2463257a` (#277). ms/pkg median across `*/hosted` is 0.1275.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 204.0 | 0.0680 | 1.020 | 1.053 | OK |
| `npm/rescan` | 189.7 | 0.0632 | 0.997 | 1.024 | OK |
| `pnpm/hosted` | 180.5 | 0.0602 | 1.071 | 1.025 | OK |
| `pnpm/rescan` | 147.9 | 0.0493 | 1.036 | 1.014 | OK |
| `yarn-classic/hosted` | 195.4 | 0.0651 | 1.062 | 1.010 | OK |
| `yarn-classic/rescan` | 172.3 | 0.0574 | 1.029 | 1.027 | OK |
| `yarn-berry/hosted` | 228.8 | 0.0763 | — | — | OK |
| `yarn-berry/rescan` | 190.6 | 0.0635 | — | — | OK |
| `bun/hosted` | 303.6 | 0.1012 | 0.993 | 2.166 | **regressed** (#578) |
| `bun/rescan` | 305.5 | 0.1018 | 1.017 | 2.247 | **regressed** (#578) |
| `vlt/hosted` | 894.2 | 0.5962 | 1.021 | 2.386 | **regressed** (#579), slow |
| `vlt/rescan` | 908.4 | 0.6056 | 1.009 | 2.534 | **regressed** (#579), slow |
| `pip/hosted` | 97.0 | 0.0970 | 1.022 | 1.017 | OK |
| `pip/rescan` | 90.6 | 0.0906 | 1.041 | 1.071 | OK |
| `uv/hosted` | 143.9 | 0.3598 | 1.011 | 0.993 | slow |
| `uv/rescan` | 145.4 | 0.3636 | 0.955 | 0.952 | slow |
| `pylock/hosted` | 142.1 | 0.3552 | 0.987 | 1.044 | slow |
| `pylock/rescan` | 104.5 | 0.2613 | 0.988 | 1.082 | slow |
| `poetry/hosted` | 221.4 | 0.5535 | 1.000 | 0.964 | slow |
| `poetry/rescan` | 224.4 | 0.5609 | 1.007 | 1.024 | slow |
| `pipenv/hosted` | 96.5 | 0.2413 | 0.988 | 1.016 | OK |
| `pipenv/rescan` | 94.3 | 0.2358 | 0.986 | 1.007 | OK |
| `pdm/hosted` | 180.5 | 0.4513 | 0.976 | 0.999 | slow |
| `pdm/rescan` | 164.8 | 0.4119 | 1.045 | 0.977 | slow |
| `bundler/hosted` | 180.4 | 0.2256 | 1.063 | 0.988 | OK |
| `bundler/rescan` | 154.3 | 0.1928 | 0.983 | 1.024 | OK |
| `composer/hosted` | 123.0 | 0.1537 | 0.967 | 1.011 | OK |
| `composer/rescan` | 111.6 | 0.1395 | 0.994 | 0.967 | OK |
| `cargo/hosted` | 262.5 | 0.4375 | 0.981 | 0.994 | slow |
| `cargo/rescan` | 251.4 | 0.4190 | 0.998 | 1.057 | slow |
| `golang/hosted` | 71.4 | 0.0595 | 1.089 | 1.026 | OK |
| `golang/rescan` | 73.4 | 0.0611 | 1.049 | 0.956 | OK |
| `nuget/hosted` | 90.1 | 0.1001 | 0.999 | 1.000 | OK |
| `nuget/rescan` | 76.6 | 0.0851 | 1.024 | 1.014 | OK |
| `maven/hosted` | 81.6 | 0.0816 | 1.005 | 1.025 | OK |
| `maven/rescan` | 69.6 | 0.0696 | 1.026 | 0.996 | OK |
| `npm/dry-run` | 207.3 | 0.0691 | 0.954 | 1.049 | OK |
| `npm/public-proxy` | 218.5 | 0.0728 | 0.993 | 0.983 | OK |
| `npm/latency` | 653.0 | 0.2177 | 1.008 | 1.016 | OK |
| `bun-isolated/hosted` (in #667) | 321.9 | 0.1073 | — | — | new |
| `bun-isolated/rescan` (in #667) | 332.6 | 0.1109 | — | — | new |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only.

| pm | 2026-10-02 | 2026-10-03 |
|---|---:|---:|
| npm | 198.6 | 204.0 |
| pnpm | 153.6 | 180.5 |
| yarn-classic | 179.9 | 195.4 |
| yarn-berry | 219.5 | 228.8 |
| bun | 289.7 | 303.6 |
| vlt | 843.8 | 894.2 |
| pip | 102.2 | 97.0 |
| uv | 136.0 | 143.9 |
| pylock | 113.6 | 142.1 |
| poetry | 187.6 | 221.4 |
| pipenv | 106.2 | 96.5 |
| pdm | 180.4 | 180.5 |
| bundler | 136.0 | 180.4 |
| composer | 122.2 | 123.0 |
| cargo | 228.4 | 262.5 |
| golang | 68.5 | 71.4 |
| nuget | 90.9 | 90.1 |
| maven | 79.3 | 81.6 |

## Open issues and PR
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still regressed (weekly +117% / +125%). Hot spot: `rewrite_bun_lock` calls `bun_lock_text::is_bundled_entry`, which JSON-parses each entry once per patch.
- #579: Perf regression: vlt/hosted wall +127% (1169ae68, #472). Still regressed (weekly +139% / +153%). Hot spot: the `vlt_bundled::store_bundled_copies` walk (async canonicalize/read_dir per node), which runs twice per scan.
- #667 (`bench/refresh`): Bench: cover Bun isolated .bun store layout (adds `bun-isolated/{hosted,rescan}`).

## Standing slow-systems list
A package manager is slow when its ms/pkg is more than 2x the median across `*/hosted` (0.1275), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs.

| pm | ms/pkg today (x median) | consecutive runs | hot spot (callgrind, 2026-10-02) |
|---|---|---:|---|
| vlt | 0.596 (4.7x) | 2 of 3 | #472 bundled-copy walk (#579), plus DepId re-splitting in `redirect::vlt::every_instance_pinned` / `partition_instances` / `vlt_preflight::preflight_scope` (~35%) |
| poetry | 0.553 (4.3x) | 2 of 3 | `utils::poetry_lock::rewrite_poetry_lock_in`, 77% of instructions |
| pdm | 0.451 (3.5x) | 2 of 3 | `utils::pdm_lock::rewrite_pdm_lock_in`, 77% |
| cargo | 0.438 (3.4x) | 2 of 3 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (per-patch re-parse of Cargo.lock) |
| uv | 0.360 (2.8x) | 2 of 3 | `utils::python_lock::PythonLockSession::rewrite`, 39%; vex `pypi_locks::extract`, 23% |
| pylock | 0.355 (2.8x) | 2 of 3 | not profiled yet (same Python lock session as uv) |

Dropped off today: pipenv (0.241, 1.9x; borderline, it was 2.1x on run 1). No scenario's peak RSS is above 2x the median (34.0 MiB).

## Coverage-gap backlog
- ~~**Bun isolated `.bun` store** (#496)~~: covered by `bun-isolated/*` in #667.
- **Yarn 4 pnpm linker** (`nodeLinker: pnpm`, `node_modules/.store`, #496): yarn-berry is covered only with the node-modules linker.
- **Yarn berry re-pin of old `npm:…::__archiveUrl` pins** (#465): a rescan over pre-#465 lockfiles rewrites them to the new tarball-URL form. Uncovered.
- **bun.lockb (binary lockfile):** only text `bun.lock` is covered. The `bun_binary` rewriter and codec (#472) are unbenchmarked.
- **Bundled copies:** no fixture has a Bun `{"bundled": true}` entry or a vlt bundled store copy, so the `redirect_*_bundled_instance_skipped` paths (#472) are never hit.
- **hatch:** `hatch.toml` is a HOSTED|PROBE pypi input in `formats/registry.rs`, but there is no `pm:hatch` scenario.
- **gradle:** Maven hosted with Gradle build scripts is uncovered (`pm:gradle`).
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venv locations (#540), `.egg-info` installs (#452), Poetry `envs.toml` (#527) and lock-only `requirements.txt` (#530) are uncovered.
- **pnpm-workspace.yaml append** (#414): only the fresh-file case is covered.
- **Gemfile multi-layer `.bundle/config`** (#532) and Gemfile declaration dedupe (#552): only one layer is covered.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None yet. 14+ days of history are needed before merging any hosted/rescan pairs. Candidate: `bun/rescan` now overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
