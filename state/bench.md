[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-05 ~07:00 UTC
- **main:** `045d7ec7` (Bound patch API connects and stalled reads, #581). Unchanged since 2026-10-02.
- **Suite source:** `main` plus #667 (`bench/refresh`: `bun-isolated/*` and the rescan-restore harness fix). The CLI is identical to main.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. This runner is about 1.4x slower than on earlier runs across *every* scenario, while the weekly A/B stayed flat, so the jump in absolute medians is the machine. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 41/41 scenarios valid on today's main.
- **Daily A/B:** skipped, because main didn't move (LAST_SHA == HEAD == `045d7ec7`).
- **Weekly A/B:** the 7-day SHA `1a8608b3` predates the v5 output (#277), so the base is `2463257a` (#277). 7 pairs + 10 confirm. Still confirmed: bun/hosted +107.3%, bun/rescan +92.2% (#578, open) and vlt/hosted +123.3% (#579, **accepted**). vlt/rescan wasn't completed today: the compare was interrupted by a session timeout during its confirm round, and its cost is already accepted. The other 33 comparable scenarios are unchanged. `yarn-berry/*` and `bun-isolated/*` have no comparable base.
- **A/A sanity check** (npm/hosted, uv/hosted, poetry/hosted, 7 pairs): clean (+1.6%, +0.8%, +0.2%).

## Scoreboard
Day: no daily base today. Week: wall ratio vs `2463257a` (#277). ms/pkg median across `*/hosted` is 0.1481 (on today's slower runner).

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 296.1 | 0.0987 | — | 1.025 | OK |
| `npm/rescan` | 250.6 | 0.0835 | — | 1.035 | OK |
| `pnpm/hosted` | 234.8 | 0.0783 | — | 1.029 | OK |
| `pnpm/rescan` | 175.7 | 0.0586 | — | 1.037 | OK |
| `yarn-classic/hosted` | 227.5 | 0.0758 | — | 0.975 | OK |
| `yarn-classic/rescan` | 211.1 | 0.0704 | — | 1.008 | OK |
| `yarn-berry/hosted` | 293.5 | 0.0978 | — | — | OK |
| `yarn-berry/rescan` | 260.7 | 0.0869 | — | — | OK |
| `bun/hosted` | 394.6 | 0.1315 | — | 2.073 | **regressed** (#578) |
| `bun/rescan` | 360.0 | 0.1200 | — | 1.922 | **regressed** (#578) |
| `bun-isolated/hosted` (in #667) | 392.4 | 0.1308 | — | — | OK |
| `bun-isolated/rescan` (in #667) | 396.0 | 0.1320 | — | — | OK |
| `vlt/hosted` | 1109.7 | 0.7398 | — | 2.233 | slow; #472 cost accepted (#579 closed) |
| `vlt/rescan` | 1120.9 | 0.7473 | — | n/a (not rerun) | slow; #472 cost accepted (#579 closed) |
| `pip/hosted` | 125.8 | 0.1258 | — | 1.068 | OK |
| `pip/rescan` | 122.0 | 0.1220 | — | 1.058 | OK |
| `uv/hosted` | 244.0 | 0.6099 | — | 0.995 | slow (#836) |
| `uv/rescan` | 186.1 | 0.4653 | — | 0.914 | slow (#836) |
| `pylock/hosted` | 179.8 | 0.4494 | — | 1.038 | slow (#836) |
| `pylock/rescan` | 160.3 | 0.4006 | — | 1.081 | slow (#836) |
| `poetry/hosted` | 342.9 | 0.8572 | — | 0.964 | slow (#760) |
| `poetry/rescan` | 280.4 | 0.7010 | — | 1.040 | slow (#760) |
| `pipenv/hosted` | 143.9 | 0.3597 | — | 1.021 | slow (run 1, borderline) |
| `pipenv/rescan` | 113.9 | 0.2848 | — | 1.015 | slow (run 1, borderline) |
| `pdm/hosted` | 260.3 | 0.6508 | — | 1.068 | slow (#762) |
| `pdm/rescan` | 233.6 | 0.5841 | — | 1.011 | slow (#762) |
| `bundler/hosted` | 205.9 | 0.2574 | — | 1.005 | OK |
| `bundler/rescan` | 203.6 | 0.2544 | — | 1.089 | OK |
| `composer/hosted` | 180.8 | 0.2260 | — | 1.004 | OK |
| `composer/rescan` | 171.4 | 0.2142 | — | 0.973 | OK |
| `cargo/hosted` | 364.1 | 0.6069 | — | 0.985 | slow (#761) |
| `cargo/rescan` | 319.6 | 0.5327 | — | 1.025 | slow (#761) |
| `golang/hosted` | 110.3 | 0.0919 | — | 1.041 | OK |
| `golang/rescan` | 96.1 | 0.0801 | — | 1.033 | OK |
| `nuget/hosted` | 133.3 | 0.1481 | — | 1.010 | OK |
| `nuget/rescan` | 103.7 | 0.1152 | — | 1.011 | OK |
| `maven/hosted` | 87.4 | 0.0874 | — | 1.010 | OK |
| `maven/rescan` | 103.3 | 0.1033 | — | 1.006 | OK |
| `npm/dry-run` | 251.3 | 0.0838 | — | 1.053 | OK |
| `npm/public-proxy` | 272.5 | 0.0908 | — | 1.065 | OK |
| `npm/latency` | 708.2 | 0.2361 | — | 1.015 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs (10-05 was about 1.4x slower everywhere), so read these as trends only.

| pm | 2026-10-02 | 2026-10-03 | 2026-10-04 | 2026-10-05 |
|---|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 |
| bun-isolated | — | — | 336.6 | 392.4 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 |

## Open issues and PR
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still regressed (weekly +107% / +92%). Hot spot: `rewrite_bun_lock` calls `bun_lock_text::is_bundled_entry`, which JSON-parses each entry once per patch. Accepting it the way #579 was accepted is a human call.
- #579 (closed 2026-10-03 by a maintainer): the vlt/* #472 cost is accepted. Tracked as slow only.
- #760: Slow scan: poetry (per-patch poetry.lock re-parse).
- #761: Slow scan: cargo (per-patch Cargo.lock re-parse).
- #762: Slow scan: pdm (per-patch pdm.lock re-parse).
- #836: Slow scan: uv/pylock hosted 4.1x/3.0x median ms/pkg (per-patch lock re-serialize). **New today** (deferred from 10-04 by the issue cap).
- #667 (`bench/refresh`): Bench: cover Bun isolated .bun store; fix rescan restore. Ready for review, CI green. No changes today.

## Standing slow-systems list
A package manager is slow when its ms/pkg is more than 2x the median across `*/hosted` (0.1481 today), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run.

| pm | ms/pkg today (x median) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| poetry | 0.857 (5.8x) | 4 | #760 | `utils::poetry_lock::rewrite_poetry_lock_in`, 77% (`toml_edit` parse 45.5%, re-serialize 18%; whole lock re-parsed per patch). Callgrind 10-04 |
| vlt | 0.740 (5.0x) | 4 | none (#579 accepted) | #472 bundled-copy walk, plus DepId re-splitting in `redirect::vlt` (callgrind 10-02) |
| pdm | 0.651 (4.4x) | 4 | #762 | `utils::pdm_lock::rewrite_pdm_lock_in`, 77% (same per-patch re-parse as Poetry). Callgrind 10-04 |
| uv | 0.610 (4.1x) | 4 | #836 | `PythonLockSession::rewrite` 39%, mostly `DocumentMut` Display (whole lock re-serialized per patched dep, `redirect/mod.rs` ~L4675); vex `pypi_locks::extract` re-parse 23%. Callgrind 10-05 |
| cargo | 0.607 (4.1x) | 4 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (several full parses per patched crate). Callgrind 10-04 |
| pylock | 0.449 (3.0x) | 4 | #836 | Same as uv: `PythonLockSession::rewrite` 38% (Display 35%); vex `pypi_locks::extract` 31%. Callgrind 10-05 |
| pipenv | 0.360 (2.4x) | 1 | none | Borderline and noisy: the run's 3-sample median was 143.9 ms, while the compare head median was 115.7 ms (≈2.0x). Was 1.9x on 10-03 and 10-04. Not profiled |

No scenario's peak RSS is above 2x the median (34.8 MiB). Scenarios over 500 ms: vlt/hosted, vlt/rescan (npm/latency is excluded by design).

## Coverage-gap backlog
No new scan commits on main since 2026-10-02, so no new gaps. Carried over:
- **Yarn 4 pnpm linker** (`nodeLinker: pnpm`, `node_modules/.store`, #496): yarn-berry is covered only with the node-modules linker.
- **Yarn berry re-pin of old `npm:…::__archiveUrl` pins** (#465): a rescan over pre-#465 lockfiles is uncovered.
- **bun.lockb (binary lockfile):** the `bun_binary` rewriter and codec (#472) are unbenchmarked.
- **Bundled copies:** no fixture hits the `redirect_*_bundled_instance_skipped` paths (#472).
- **hatch:** `hatch.toml` is a HOSTED|PROBE pypi input, but there is no `pm:hatch` scenario. Open PRs #700/#743/#680 are reworking Hatch, so add coverage after they land.
- **gradle:** Maven hosted with Gradle build scripts is uncovered (`pm:gradle`). #646 (open) adds full Gradle support.
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venv locations (#540), `.egg-info` (#452), Poetry `envs.toml` (#527) and lock-only `requirements.txt` (#530) are uncovered.
- **pnpm-workspace.yaml append** (#414): only the fresh-file case is covered.
- **Gemfile multi-layer `.bundle/config`** (#532) and Gemfile declaration dedupe (#552): only one layer is covered.
- ~~Bun isolated `.bun` store (#496)~~: covered by `bun-isolated/*` in #667.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None yet. 14+ days of history are needed before merging any hosted/rescan pairs (4 days so far). Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
