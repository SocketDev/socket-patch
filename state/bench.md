[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-08 ~07:00–08:00 UTC
- **main:** `ea097142` (Decide which lockfile governs installs in one table, #1044). That is 73 commits since `9c43dfc9`, including #877 (Poetry/PDM per-patch lock re-parse fix) and #925 (gradle/hatch scenarios).
- **Suite source:** `main`. #925 has merged, so all 45 scenarios now come from main.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 45/45 scenarios are valid on today's main. Request counts match 10-07 in every scenario.
- **Daily A/B** (`9c43dfc9` → `ea097142`):
  - **Improvements from #877:** poetry/hosted -45.7%, poetry/rescan -49.4%, pdm/hosted -43.6%, pdm/rescan -45.6%.
  - `yarn-berry/rescan` was flagged at +14.3%, but the confirmation round (30+ pairs) gave +2.6% [-7.7, +9.5], so it is not confirmed. Nothing else moved.
- **Weekly A/B** (`2463257a` #277 → `ea097142`). The base can't run `yarn-berry/*`, `bun-isolated/*` or `gradle/*` (it fails validation there, as expected), so those have no weekly ratio.
  - Known #472 regressions: bun/hosted +102.1%, bun/rescan +125.5% (#578, data commented; fix in #1009). vlt/hosted +111.7%, vlt/rescan +134.4% (accepted, #579).
  - **#993 npm drift has shrunk.** npm/hosted is +4.5% (≈). npm/rescan was +6.8% and then +8.9% in round 2 (≈, CPU +8.8%). npm/dry-run is still confirmed at +14.7% → +10.0%. Data is commented on #993; fix in #1008.
  - **New, confirmed, below the issue gate:** yarn-classic/rescan wall +14.5% → +13.3% [+7.4, +15.5] (~15–25 ms; daily +5.4% unconfirmed; candidates #1083, #917, #1044; under 15%, so not bisected). hatch/rescan CPU +12.6%, wall +9.6% (~5 ms). pdm/hosted peak RSS +16.1% → +17.6% from #877's batched rewrite, while its wall time is -41%.
  - `pip/rescan` was flagged again (+14.5%) and again not confirmed (+9.9% [+5.0, +11.8]). That's the second run in a row just under the gate. Watch it.
  - nuget/hosted is 27.6% faster (#597).
- **A/A sanity check:** clean. npm/hosted +0.6%, yarn-berry/rescan -1.5%, golang/hosted -4.6%.
- **Full `compare` wall time:** 15.8 min on this runner for 45 scenarios, over the ~12-minute budget. See the backlog below.

## Scoreboard
Day: wall ratio vs `9c43dfc9`. Week: wall ratio vs `2463257a` (#277). The median ms/pkg across `*/hosted` is 0.1197 today.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 222.4 | 0.0741 | 0.968 | 1.045 | OK, drift below gate (#993) |
| `npm/rescan` | 211.0 | 0.0703 | 1.014 | 1.068 | watch, week +8.9% (#993) |
| `pnpm/hosted` | 188.2 | 0.0627 | 0.999 | 1.043 | OK |
| `pnpm/rescan` | 156.5 | 0.0522 | 1.070 | 1.061 | OK |
| `yarn-classic/hosted` | 199.8 | 0.0666 | 1.062 | 1.082 | OK |
| `yarn-classic/rescan` | 170.4 | 0.0568 | 1.054 | 1.145 | regressed, week +13.3% (ledger only) |
| `yarn-berry/hosted` | 231.0 | 0.0770 | 1.063 | — | OK |
| `yarn-berry/rescan` | 242.0 | 0.0807 | 1.143 | — | OK |
| `bun/hosted` | 350.7 | 0.1169 | 0.972 | 2.021 | regressed (#578) |
| `bun/rescan` | 377.2 | 0.1257 | 1.019 | 2.255 | regressed (#578) |
| `bun-isolated/hosted` | 359.2 | 0.1197 | 0.995 | — | OK |
| `bun-isolated/rescan` | 333.6 | 0.1112 | 0.978 | — | OK |
| `vlt/hosted` | 840.7 | 0.5605 | 0.990 | 2.117 | slow; #472 cost accepted (#579) |
| `vlt/rescan` | 778.5 | 0.5190 | 1.029 | 2.344 | slow; #472 cost accepted (#579) |
| `pip/hosted` | 104.5 | 0.1045 | 0.983 | 1.067 | OK |
| `pip/rescan` | 84.7 | 0.0847 | 1.027 | 1.145 | watch, week +9.9% |
| `uv/hosted` | 165.0 | 0.4126 | 1.024 | 1.072 | slow (#836) |
| `uv/rescan` | 139.3 | 0.3483 | 1.020 | 1.062 | slow (#836) |
| `pylock/hosted` | 127.8 | 0.3195 | 1.006 | 1.028 | slow (#836) |
| `pylock/rescan` | 131.3 | 0.3283 | 1.005 | 1.012 | slow (#836) |
| `poetry/hosted` | 111.3 | 0.2783 | 0.543 | 0.520 | slow (2.3x; 45% faster after #877) |
| `poetry/rescan` | 100.5 | 0.2512 | 0.506 | 0.505 | OK (49% faster after #877) |
| `pipenv/hosted` | 105.3 | 0.2633 | 0.968 | 0.985 | slow (none, 2 runs) |
| `pipenv/rescan` | 94.5 | 0.2364 | 1.018 | 1.068 | OK |
| `pdm/hosted` | 133.2 | 0.3329 | 0.564 | 0.588 | slow (2.8x; 41% faster after #877, RSS +17.6%) |
| `pdm/rescan` | 116.1 | 0.2903 | 0.544 | 0.599 | OK (40% faster after #877) |
| `hatch/hosted` | 78.0 | 0.0780 | 1.091 | 1.054 | OK |
| `hatch/rescan` | 70.6 | 0.0706 | 0.990 | 1.082 | regressed, week CPU +12.6% (ledger only) |
| `bundler/hosted` | 149.9 | 0.1874 | 0.970 | 1.063 | OK |
| `bundler/rescan` | 165.7 | 0.2072 | 1.053 | 1.121 | OK |
| `composer/hosted` | 136.0 | 0.1700 | 1.060 | 1.072 | OK |
| `composer/rescan` | 154.8 | 0.1934 | 1.005 | 1.056 | OK |
| `cargo/hosted` | 254.0 | 0.4234 | 0.958 | 0.989 | slow (#761) |
| `cargo/rescan` | 295.2 | 0.4919 | 0.969 | 1.059 | slow (#761) |
| `golang/hosted` | 104.8 | 0.0873 | 1.141 | 0.917 | OK |
| `golang/rescan` | 77.1 | 0.0643 | 1.051 | 1.021 | OK |
| `nuget/hosted` | 73.4 | 0.0815 | 1.021 | 0.724 | OK (faster, week) |
| `nuget/rescan` | 84.4 | 0.0938 | 1.010 | 0.959 | OK |
| `maven/hosted` | 67.8 | 0.0678 | 1.037 | 1.077 | OK |
| `maven/rescan` | 67.3 | 0.0673 | 1.045 | 1.047 | OK |
| `gradle/hosted` | 197.6 | 0.1976 | 1.067 | — | OK |
| `gradle/rescan` | 239.0 | 0.2390 | 1.017 | — | OK |
| `npm/dry-run` | 205.9 | 0.0686 | 1.026 | 1.147 | regressed, week +10.0% (#993) |
| `npm/public-proxy` | 220.0 | 0.0733 | 1.005 | 1.044 | OK |
| `npm/latency` | 656.8 | 0.2189 | 1.011 | 1.023 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs (10-05 and 10-07 were about 1.3–1.4x slower everywhere), so read these as trends only. The poetry and pdm drop on 10-08 is #877.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 |
|---|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 |
| gradle | — | — | — | — | 170.5 | — | 197.6 |
| hatch | — | — | — | — | — | 86.1 | 78.0 |

## Open issues and PR
- #993: Perf regression: npm/hosted wall +15% (2463257a..9c43dfc9). Today only npm/dry-run still confirms (+10.0%), and npm/hosted is +4.5%. Fix PR #1008 is open.
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still +102% / +125%. Fix PR #1009 is open.
- #579 (closed): the vlt #472 cost is accepted.
- #761: Slow scan: cargo.
- #836: Slow scan: uv/pylock.
- #760 and #762 (poetry/pdm slow) were closed when #877 merged. Measured today: -46% / -44% wall.
- #580: Benchmark tracking.
- No open `bench/refresh` PR (#925 merged 10-07). No suite changes today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted` (0.1197 today), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run.

| pm | ms/pkg today (x median) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| vlt | 0.561 (4.7x) | 7 | none (#579 accepted) | #472 bundled-copy walk, plus DepId re-splitting in `redirect::vlt` (callgrind 10-02) |
| cargo | 0.423 (3.5x) | 7 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| uv | 0.413 (3.4x) | 7 | #836 | `PythonLockSession::rewrite` 39%: whole lock re-serialized per patched dep (callgrind 10-05) |
| pdm | 0.333 (2.8x) | 1 since #877 | none (#762 closed) | After #877: `lock_fragments::rewrite_batch` 45% inclusive, vex `pypi_locks::extract` 26%, `inventory_pypi_locks_raw_in` 10% (callgrind 10-08). Its ms/pkg went from 0.77 to 0.33 |
| pylock | 0.320 (2.7x) | 7 | #836 | Same as uv: `PythonLockSession::rewrite` 38%; vex `pypi_locks::extract` 31% (callgrind 10-05) |
| poetry | 0.278 (2.3x) | 1 since #877 | none (#760 closed) | Its ms/pkg went from 0.92 to 0.28 after #877. Likely the same batched-rewrite and VEX lock-extract split as pdm (not profiled today) |
| pipenv | 0.263 (2.2x) | 2 | none | `patch::redirect::pipenv::entries` 69% inclusive: Pipfile.lock re-tokenized per patch (callgrind 10-07) |

The poetry and pdm counters restart at #877, because the 7-run streak was the per-patch re-parse that #877 fixed, so no new issue opens for them. If pipenv is still over 2x tomorrow, that's its 3rd consecutive run and it gets an issue. No scenario's peak RSS is above 2x the median (35.0 MiB). Scenarios over 500 ms: vlt/hosted, vlt/rescan.

## Coverage-gap backlog
New since 10-07 (from `9c43dfc9..ea097142`):
- **Yarn classic offline mirror** (#1083, `redirect::yarnrc`): a `.yarnrc` `yarn-offline-mirror` project gets a new hosted rewrite path. Uncovered.
- **Multi-lockfile projects** (#1044 governing-lock table): a project with both `package-lock.json` and `yarn.lock` (or `bun.lock`) picks one governing lock. Every fixture has exactly one lock, so this is uncovered.
- **Patch-generation re-pin** (#1035, `redirect::generation`): re-pinning over an older generation's wiring. The rescan scenarios only cover the same generation.

Carried over:
- **Hatch variants:** `[tool.hatch.envs]` in pyproject only, hatch + `requirements.txt`, uv-installer refusal.
- **Gradle variants:** Kotlin DSL, multi-project builds, version catalogs, `verification-metadata.xml`, `mavenLocal()` (#646).
- **Yarn 4 pnpm linker** (#496); **yarn berry re-pin of `__archiveUrl` pins** (#465).
- **bun.lockb** binary lockfile (#472); **bundled copies** (`redirect_*_bundled_instance_skipped`, #472/#669).
- **pnpm global store / modulesDir store** (#829, #698); **vlt 1.3 brotli lock nodes** (#820).
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venvs (#540), `.egg-info` (#452), Poetry `envs.toml` (#527), lock-only `requirements.txt` (#530).
- **pnpm-workspace.yaml append** (#414): non-fresh-file case.
- **Gemfile multi-layer `.bundle/config`** (#532, #577), `gems.locked` (#750), Bundler 4 standalone (#797).
- **Suite runtime:** a full `compare` took 15.8 min on a 4 vCPU sandbox (45 scenarios). Before more scenarios land, shrink something, e.g. drop `--runs` for the `*/rescan` twins of the npm family, or merge `bun/rescan` into `bun-isolated/rescan`.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None removed. Merging hosted/rescan pairs needs 14+ days of history; there are 7 days so far. Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
