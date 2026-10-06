[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-06 ~07:00 UTC
- **main:** `9c43dfc9` (Cache the macOS vexctl build in the test job, #874). That is 74 commits after the last measured SHA, `045d7ec7`, and 66 of them touch `core`/`cli` src.
- **Suite source:** `main` (#667 merged), plus `gradle/*` from #925, measured with the #925 bench binary on the same main CLI.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 41/41 main scenarios are valid on today's main, plus 2/2 new `gradle/*`.
- **Daily A/B** (`045d7ec7` → `9c43dfc9`): **no regressions**. `nuget/hosted` got **26% faster** (`0.739` [0.686, 0.901]), most likely from #597 (unified hosted NuGet routing). Request counts are unchanged in every scenario.
- **Weekly A/B:** the 7-day SHA `f6b7fb9e` predates the v5 output (#277), and every scenario was invalid on it, so the base is again `2463257a` (#277). Only the known #472 regressions remain: bun/hosted +111.6%, bun/rescan +122.5% (#578, data commented), vlt/hosted +104.5% and vlt/rescan +133.2% (accepted, #579). nuget/hosted is 22% faster. Everything else is within noise; npm/hosted is +10.0% with a CI of [-0.3, +15.9], so not flagged. `yarn-berry/*` and `bun-isolated/*` have no comparable base.
- **A/A sanity check:** clean. npm/hosted +2.0%, uv/hosted -0.1%, poetry/hosted -2.8%; for #925, gradle/hosted -1.1% and gradle/rescan +4.5%.

## Scoreboard
Day: wall ratio vs `045d7ec7`. Week: wall ratio vs `2463257a` (#277). The median ms/pkg across `*/hosted` is 0.1361; gradle is excluded until it lands.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 233.5 | 0.0778 | 1.027 | 1.100 | OK |
| `npm/rescan` | 202.4 | 0.0675 | 1.012 | 1.059 | OK |
| `pnpm/hosted` | 197.4 | 0.0658 | 1.044 | 0.998 | OK |
| `pnpm/rescan` | 156.7 | 0.0522 | 1.015 | 1.012 | OK |
| `yarn-classic/hosted` | 181.9 | 0.0606 | 1.033 | 1.065 | OK |
| `yarn-classic/rescan` | 157.6 | 0.0525 | 1.009 | 1.064 | OK |
| `yarn-berry/hosted` | 242.0 | 0.0807 | 1.045 | — | OK |
| `yarn-berry/rescan` | 194.7 | 0.0649 | 1.089 | — | OK |
| `bun/hosted` | 297.0 | 0.0990 | 1.008 | 2.116 | **regressed** (#578) |
| `bun/rescan` | 327.9 | 0.1093 | 1.054 | 2.225 | **regressed** (#578) |
| `bun-isolated/hosted` | 342.4 | 0.1141 | 1.059 | — | OK |
| `bun-isolated/rescan` | 338.3 | 0.1128 | 1.005 | — | OK |
| `vlt/hosted` | 840.0 | 0.5600 | 1.038 | 2.045 | slow; #472 cost accepted (#579) |
| `vlt/rescan` | 838.2 | 0.5588 | 1.027 | 2.332 | slow; #472 cost accepted (#579) |
| `pip/hosted` | 136.1 | 0.1361 | 1.038 | 1.049 | OK |
| `pip/rescan` | 90.2 | 0.0902 | 0.933 | 1.053 | OK |
| `uv/hosted` | 156.6 | 0.3914 | 1.002 | 0.988 | slow (#836) |
| `uv/rescan` | 127.2 | 0.3179 | 1.054 | 0.997 | slow (#836) |
| `pylock/hosted` | 122.1 | 0.3052 | 1.034 | 0.961 | slow (#836) |
| `pylock/rescan` | 110.8 | 0.2770 | 0.987 | 0.926 | slow (#836) |
| `poetry/hosted` | 261.7 | 0.6542 | 1.058 | 1.024 | slow (#760) |
| `poetry/rescan` | 207.7 | 0.5192 | 1.005 | 1.043 | slow (#760) |
| `pipenv/hosted` | 100.2 | 0.2504 | 1.023 | 1.032 | OK |
| `pipenv/rescan` | 86.3 | 0.2159 | 0.988 | 1.048 | OK |
| `pdm/hosted` | 193.6 | 0.4841 | 1.084 | 0.968 | slow (#762) |
| `pdm/rescan` | 172.8 | 0.4320 | 1.067 | 1.051 | slow (#762) |
| `bundler/hosted` | 165.6 | 0.2069 | 1.036 | 1.041 | OK |
| `bundler/rescan` | 159.5 | 0.1993 | 0.930 | 1.044 | OK |
| `composer/hosted` | 122.9 | 0.1536 | 1.035 | 0.974 | OK |
| `composer/rescan` | 112.0 | 0.1400 | 1.022 | 1.003 | OK |
| `cargo/hosted` | 255.1 | 0.4251 | 0.993 | 0.961 | slow (#761) |
| `cargo/rescan` | 275.1 | 0.4585 | 0.995 | 0.999 | slow (#761) |
| `golang/hosted` | 80.5 | 0.0671 | 1.053 | 1.044 | OK |
| `golang/rescan` | 71.7 | 0.0598 | 1.065 | 1.000 | OK |
| `nuget/hosted` | 91.3 | 0.1015 | 0.739 | 0.776 | OK (faster: day 0.739, week 0.776) |
| `nuget/rescan` | 63.8 | 0.0708 | 0.919 | 0.988 | OK |
| `maven/hosted` | 73.5 | 0.0735 | 0.970 | 0.928 | OK |
| `maven/rescan` | 66.8 | 0.0668 | 1.072 | 1.062 | OK |
| `npm/dry-run` | 187.7 | 0.0626 | 1.038 | 1.094 | OK |
| `npm/public-proxy` | 234.0 | 0.0780 | 1.004 | 1.083 | OK |
| `npm/latency` | 686.0 | 0.2287 | 1.002 | 1.034 | OK |
| `gradle/hosted` (new, in #925) | 170.5 | 0.1705 | — | — | OK |
| `gradle/rescan` (new, in #925) | 259.2 | 0.2592 | — | — | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs (10-05 was about 1.4x slower everywhere), so read these as trends only.

| pm | 2026-10-02 | 2026-10-03 | 2026-10-04 | 2026-10-05 | 2026-10-06 |
|---|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 |
| gradle | — | — | — | — | 170.5 |

## Open issues and PR
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still regressed (weekly +112% / +123%); today's data is commented. Hot spot: `rewrite_bun_lock` → `bun_lock_text::is_bundled_entry` JSON-parses each entry once per patch. Accepting it the way #579 was accepted is a human call.
- #579 (closed 2026-10-03 by a maintainer): the vlt/* #472 cost is accepted. Tracked as slow only.
- #760: Slow scan: poetry. Draft fix in #877.
- #761: Slow scan: cargo.
- #762: Slow scan: pdm. Draft fix in #877.
- #836: Slow scan: uv/pylock (per-patch lock re-serialize).
- **#925 (`bench/refresh`): Bench: cover Gradle hosted mode (gradle/hosted, gradle/rescan).** New today, `state: ready`.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted` (0.1361 today), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run.

| pm | ms/pkg today (x median) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| poetry | 0.654 (4.8x) | 5 | #760 (fix draft #877) | `utils::poetry_lock::rewrite_poetry_lock_in`, 77% (whole lock re-parsed per patch). Callgrind 10-04 |
| vlt | 0.560 (4.1x) | 5 | none (#579 accepted) | #472 bundled-copy walk, plus DepId re-splitting in `redirect::vlt` (callgrind 10-02) |
| pdm | 0.484 (3.6x) | 5 | #762 (fix draft #877) | `utils::pdm_lock::rewrite_pdm_lock_in`, 77% (same per-patch re-parse as Poetry). Callgrind 10-04 |
| cargo | 0.425 (3.1x) | 5 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79%. Callgrind 10-04 |
| uv | 0.391 (2.9x) | 5 | #836 | `PythonLockSession::rewrite` 39%, mostly `DocumentMut` Display (whole lock re-serialized per patched dep). Callgrind 10-05 |
| pylock | 0.305 (2.2x) | 5 | #836 | Same as uv: `PythonLockSession::rewrite` 38%; vex `pypi_locks::extract` 31%. Callgrind 10-05 |
| ~~pipenv~~ | 0.250 (1.8x) | 0 | none | Back under 2x. 10-05's 2.4x was noise |

No scenario's peak RSS is above 2x the median (35.3 MiB). Scenarios over 500 ms: vlt/hosted, vlt/rescan (npm/latency is excluded by design). The new gradle/hosted runs at 0.171 ms/pkg (1.25x), so it is not slow. gradle/rescan (259 ms) is about 1.5x slower than gradle/hosted; it is a candidate to profile once #925 lands.

## Coverage-gap backlog
New since 10-05: 74 commits on main. Gradle (#646) and Hatch (#743, #680) landed.
- ~~**gradle**~~ (#646): covered by `gradle/*` in #925.
- **hatch:** #743/#680/#617 have landed, and `hatch.toml` is a HOSTED pypi input. There is still no `pm:hatch` scenario. **Next to add.**
- **Gradle variants:** Kotlin DSL, multi-project builds, version catalogs, `gradle/verification-metadata.xml` rewrite and `mavenLocal()` m2 gating are all uncovered (#646).
- **Yarn 4 pnpm linker** (`nodeLinker: pnpm`, #496): uncovered.
- **Yarn berry re-pin of old `npm:…::__archiveUrl` pins** (#465): uncovered.
- **bun.lockb (binary lockfile):** the `bun_binary` rewriter and codec (#472) are unbenchmarked.
- **Bundled copies:** no fixture hits the `redirect_*_bundled_instance_skipped` paths (#472, #669).
- **pnpm global store / modulesDir store** (#829, #698): uncovered.
- **vlt 1.3 brotli lock nodes** (#820): uncovered.
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venv locations (#540), `.egg-info` (#452), Poetry `envs.toml` (#527) and lock-only `requirements.txt` (#530) are uncovered.
- **pnpm-workspace.yaml append** (#414): only the fresh-file case is covered.
- **Gemfile multi-layer `.bundle/config`** (#532, #577), `gems.locked` (#750) and Bundler 4 standalone (#797): uncovered.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None yet. Merging hosted/rescan pairs needs 14+ days of history; there are 5 days so far. Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
