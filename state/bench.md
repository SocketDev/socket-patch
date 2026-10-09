[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-09, about 06:35–09:05 UTC
- **main:** `f3c6313a` (Fix open npm issues, #1008). That is 37 first-parent commits since `ea097142`, including #1051 (bun lock re-parse fix), #1008 (npm/bun/vlt lock rework), #1183 (NuGet restore-scoped crawl), #1205 (Cargo.lock-scoped crawl), #1058 (hosted pins decided through lockfile discovery) and #1031 (removes `scan --apply/--vendor`; the suite never used them).
- **Suite source:** `main`, 45 scenarios. #1250 updates the nuget fixture; it was measured separately and is not in today's numbers.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. Verdicts come only from same-machine interleaved `compare`. The 3a `run` was noisy today (pnpm/hosted ranged 224–396 ms; npm/hosted's 515 ms median is about 330 ms in every `compare`), so treat today's absolute medians loosely.
- **Validation:** 45/45 scenarios are valid on today's main. Request counts are unchanged in every scenario.
- **Daily A/B** (`ea097142` → `f3c6313a`):
  - **Big wins:** bun/hosted -53.3%, bun/rescan -61.7%, bun-isolated -52% / -56% (#1051). vlt/hosted -51.2%, vlt/rescan -52.3%. npm/rescan -25.5%, yarn-classic/rescan -22.8%, gradle/rescan -31.1%, composer/rescan -18.9%, pdm/rescan -17.1%, nuget/rescan -12.9%, and pnpm, yarn-berry, uv and pylock rescans 10–14% faster.
  - **Peak RSS +15–17% on npm-family hosted scans** (confirmed): npm/hosted +16.6% (44.0 → 50.6 MiB), yarn-classic/hosted +16.5%, npm/public-proxy +15.2% and npm/latency +15.6%. npm/dry-run +13.4% and yarn-berry/hosted +11.1% are under the 15% gate. Wall time is flat. Bisected with 3 builds: #1008 is cleared (identical RSS before and after). About half the growth is in `ea097142..ef48495c` (13 commits; #1051, #1027 and #1147 are candidates) and half is #1058 (`4d06019b`). This is under the 30% RSS issue gate, so it's ledger only.
- **Weekly A/B** (`61cfb9b2`, which predates #472, → `f3c6313a`). The base fails validation on yarn-berry, bun-isolated and gradle (it predates those fixtures), so those have no weekly ratio.
  - **bun is back to its pre-#472 baseline:** bun/hosted -8.1% (≈), bun/rescan -26.3%. That's run 1 of 2 for closing #578 (evidence commented).
  - **vlt:** +13.9% and +17.3% vs pre-#472 (it was about +110% yesterday). This is the accepted #472 residual (#579).
  - **Confirmed, below the issue gate:** hatch/hosted wall +11.1% → **+19.3%** [+12.1, +25.0] in round 2 (~19 ms, just under the 20% gate). maven/hosted +10.2% → +14.7% [+7.4, +18.3] (~17 ms). Neither is bisected (the build budget went to RSS). npm-family RSS is +22–25%.
  - **Not confirmed:** bundler/rescan +10.6% → +8.3%, golang/hosted +14.0% → +6.6%, and npm/dry-run wall +10.0% → +1.0%.
  - Faster: poetry -44% / -52%, pdm -40% / -51% (#877), nuget/hosted -21.2%, npm/rescan -20.1%, yarn-classic/rescan -19.2%.
- **A/A sanity check:** clean. npm/hosted +2.4%, hatch/hosted +1.9% and maven/hosted -1.0%, all ≈.
- **Full `compare` wall time:** 21.7 min for the daily run (45 scenarios plus 4 confirmation rounds) on this runner. That is still over the ~12-minute budget.

## Scoreboard
Day: wall ratio vs `ea097142`. Week: wall ratio vs `61cfb9b2`. The median ms/pkg across `*/hosted` is 0.1716 today (from the noisy 3a run).

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 514.9 | 0.1716 | 1.004 | 0.999 | OK; RSS +16.6% day (ledger) |
| `npm/rescan` | 253.6 | 0.0845 | 0.745 | 0.799 | OK |
| `pnpm/hosted` | 313.0 | 0.1043 | 0.892 | 1.031 | OK |
| `pnpm/rescan` | 202.1 | 0.0674 | 0.862 | 0.902 | OK |
| `yarn-classic/hosted` | 332.8 | 0.1109 | 0.936 | 1.009 | OK; RSS +16.5% day (ledger) |
| `yarn-classic/rescan` | 221.2 | 0.0737 | 0.772 | 0.808 | OK |
| `yarn-berry/hosted` | 312.1 | 0.1040 | 0.908 | — | OK |
| `yarn-berry/rescan` | 269.5 | 0.0898 | 0.866 | — | OK |
| `bun/hosted` | 234.0 | 0.0780 | 0.467 | 0.919 | recovered (#578, run 1/2) |
| `bun/rescan` | 187.8 | 0.0626 | 0.383 | 0.737 | recovered (#578, run 1/2) |
| `bun-isolated/hosted` | 218.9 | 0.0730 | 0.482 | — | OK (faster, #1051) |
| `bun-isolated/rescan` | 223.1 | 0.0744 | 0.440 | — | OK (faster, #1051) |
| `vlt/hosted` | 635.9 | 0.4239 | 0.488 | 1.139 | slow; -51% day, week +13.9% (accepted #472 residual) |
| `vlt/rescan` | 598.9 | 0.3993 | 0.477 | 1.173 | slow; -52% day, week +17.3% (accepted #472 residual) |
| `pip/hosted` | 138.4 | 0.1384 | 1.072 | 1.069 | OK |
| `pip/rescan` | 122.6 | 0.1226 | 1.005 | 0.985 | OK |
| `uv/hosted` | 339.3 | 0.8482 | 1.010 | 1.036 | slow (#836) |
| `uv/rescan` | 210.8 | 0.5271 | 0.865 | 0.901 | slow (#836) |
| `pylock/hosted` | 213.2 | 0.5331 | 1.044 | 1.032 | slow (#836) |
| `pylock/rescan` | 202.6 | 0.5064 | 0.877 | 0.881 | slow (#836) |
| `poetry/hosted` | 197.3 | 0.4932 | 0.978 | 0.557 | slow (2.9x, 2 runs since #877) |
| `poetry/rescan` | 138.5 | 0.3463 | 0.945 | 0.482 | OK |
| `pipenv/hosted` | 181.4 | 0.4535 | 0.971 | 1.069 | slow (#1246) |
| `pipenv/rescan` | 139.4 | 0.3485 | 0.981 | 0.986 | OK |
| `pdm/hosted` | 170.1 | 0.4254 | 1.001 | 0.600 | slow (2.5x, 2 runs since #877) |
| `pdm/rescan` | 139.1 | 0.3478 | 0.829 | 0.489 | OK |
| `hatch/hosted` | 96.3 | 0.0963 | 1.020 | 1.111 | regressed, week +19.3% confirmed (ledger) |
| `hatch/rescan` | 94.9 | 0.0949 | 0.969 | 1.014 | OK |
| `bundler/hosted` | 246.2 | 0.3078 | 1.033 | 1.092 | OK |
| `bundler/rescan` | 220.0 | 0.2751 | 0.938 | 1.106 | OK |
| `composer/hosted` | 218.7 | 0.2733 | 1.047 | 1.099 | OK |
| `composer/rescan` | 180.7 | 0.2259 | 0.811 | 0.864 | OK |
| `cargo/hosted` | 340.5 | 0.5675 | 1.057 | 1.038 | slow (#761) |
| `cargo/rescan` | 325.5 | 0.5425 | 1.000 | 0.976 | slow (#761) |
| `golang/hosted` | 141.2 | 0.1176 | 1.088 | 1.140 | OK |
| `golang/rescan` | 101.3 | 0.0844 | 0.916 | 0.997 | OK |
| `nuget/hosted` | 106.6 | 0.1184 | 1.056 | 0.788 | OK (fixture updated in #1250) |
| `nuget/rescan` | 116.1 | 0.1290 | 0.871 | 0.886 | OK (faster, #1183; fixture updated in #1250) |
| `maven/hosted` | 124.7 | 0.1247 | 1.093 | 1.102 | regressed, week +14.7% confirmed (ledger) |
| `maven/rescan` | 87.9 | 0.0879 | 1.017 | 0.977 | OK |
| `gradle/hosted` | 215.0 | 0.2150 | 0.954 | — | OK |
| `gradle/rescan` | 219.7 | 0.2197 | 0.689 | — | OK |
| `npm/dry-run` | 282.3 | 0.0941 | 0.966 | 1.100 | OK; RSS +13.4% day |
| `npm/public-proxy` | 391.1 | 0.1304 | 1.036 | 1.060 | OK; RSS +15.2% day (ledger) |
| `npm/latency` | 786.4 | 0.2621 | 1.002 | 1.015 | OK; RSS +15.6% day (ledger) |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs (10-05, 10-07 and 10-09 ran on slower or noisier sandboxes), so read these as trends only. The poetry and pdm drop on 10-08 is #877. The bun drop on 10-09 is #1051. The 10-09 npm value is a noisy outlier.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 |

## Open issues and PR
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Recovered today: -53% day, ≈ vs pre-#472. It closes after a 2nd run within 5%. #1009 (bun fixes) is still open.
- #1246 (**new**): Slow scan: pipenv. Flagged in 3 consecutive runs. Hot spot: `redirect::pipenv::entries`, 61%.
- #761: Slow scan: cargo.
- #836: Slow scan: uv/pylock.
- #993: closed (npm drift; #1008 merged). Today npm/hosted is ≈ day and week, and npm/dry-run's wall did not confirm.
- #579 (closed): the vlt #472 cost is accepted. Most of it is gone today.
- #580: Benchmark tracking.
- **PR #1250** (`bench/refresh`): the nuget fixture gets `obj/project.assets.json`, so the suite times #1183's restore-scoped crawl.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run. Today's 3a run was noisy, so the same ranking was cross-checked against the daily `compare` head samples (median 0.143 ms/pkg). Both put the same 7 package managers over 2x.

| pm | x median today (3a / compare) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| uv | 4.9x / 3.9x | 8 | #836 | `PythonLockSession::rewrite` 39%: the whole lock is re-serialized per patched dep (callgrind 10-05) |
| cargo | 3.3x / 4.9x | 8 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04). #1205 scoped the crawl but not the rewrite |
| pylock | 3.1x / 3.7x | 8 | #836 | Same as uv (callgrind 10-05) |
| poetry | 2.9x / 3.3x | 2 since #877 | none | Likely the batched-rewrite and VEX lock-extract split, as for pdm (not profiled) |
| pipenv | 2.6x / 2.8x | 3 | **#1246** | `patch::redirect::pipenv::entries` 61% inclusive (`properties` 40%): `plan()` re-tokenizes Pipfile.lock once per patch (callgrind 10-09) |
| pdm | 2.5x / 2.9x | 2 since #877 | none | `lock_fragments::rewrite_batch` 45%, vex `pypi_locks::extract` 26% (callgrind 10-08) |
| vlt | 2.5x / 2.9x | 8 | none (#579 accepted) | Halved today. Its two scenarios are still over 500 ms (636 / 599 ms) |

If poetry and pdm are still over 2x tomorrow, that's their 3rd run since #877 and each gets an issue. No scenario's peak RSS is above 2x the median (34.2 MiB). Scenarios over 500 ms: vlt/hosted and vlt/rescan (npm/hosted's 515 ms in the 3a run is noise; it was about 330 ms in every `compare`).

## Coverage-gap backlog
New since 10-08 (from `ea097142..f3c6313a`):
- **Covered by #1250:** NuGet restore-scoped crawl (#1183).
- **Cargo.lock-scoped crawl** (#1205): already exercised. The fixture has a `Cargo.lock` and no `vendor/`, so it takes the new lookup. Uncovered: extra crates in `~/.cargo/registry` that the lock doesn't name (the scope's whole point), which would need a fixture change that the base can't validate.
- **Non-UTF-8 requirements files** (#1152): Latin-1 with a PEP 263 coding line, or UTF-16 with a BOM. Uncovered.
- **Gem lock re-sort on re-scan** (#1190): a superseding patch or rotated grant moves a GEM section. The rescan only covers the same grant. Uncovered.

Carried over:
- **Yarn classic offline mirror** (#1083), **multi-lockfile governance** (#1044) and **patch-generation re-pin** (#1035).
- **Hatch variants:** `[tool.hatch.envs]` in pyproject only, hatch + `requirements.txt`, uv-installer refusal.
- **Gradle variants:** Kotlin DSL, multi-project builds, version catalogs, `verification-metadata.xml`, `mavenLocal()` (#646).
- **Yarn 4 pnpm linker** (#496); **yarn berry re-pin of `__archiveUrl` pins** (#465).
- **bun.lockb** binary lockfile (#472); **bundled copies** (`redirect_*_bundled_instance_skipped`, #472/#669).
- **pnpm global store / modulesDir store** (#829, #698); **vlt 1.3 brotli lock nodes** (#820).
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venvs (#540), `.egg-info` (#452), Poetry `envs.toml` (#527), lock-only `requirements.txt` (#530).
- **pnpm-workspace.yaml append** (#414): the non-fresh-file case.
- **Gemfile multi-layer `.bundle/config`** (#532, #577), `gems.locked` (#750), Bundler 4 standalone (#797).
- **Suite runtime:** a full `compare` takes 16–22 min on a 4 vCPU sandbox. Before more scenarios land, shrink something, e.g. fewer `--runs` for the npm family's `*/rescan` twins, or merge `bun/rescan` into `bun-isolated/rescan`.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None removed. #1031 removed `scan --apply/--vendor`, and no scenario used them. Merging hosted/rescan pairs needs 14+ days of history; there are 8 days so far. Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path. Both moved together today (-62% / -56%).

---
_Generated by [Claude Code](https://claude.ai/code)_
