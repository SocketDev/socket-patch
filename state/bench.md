[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-07 ~08:30 UTC
- **main:** `9c43dfc9` (Cache the macOS vexctl build in the test job, #874). Unchanged since the 10-06 run, so there was no daily A/B.
- **Suite source:** `main`, plus `hatch/*` from #925, measured with the #925 bench binary on the same main CLI. `gradle/*` (also in #925) was not re-measured today.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. It ran about 1.3x slower than 10-06's runner on absolute medians. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 41/41 main scenarios are valid on today's main, plus 2/2 new `hatch/*`. Request counts match 10-06 in every scenario.
- **Daily A/B:** skipped (LAST_SHA == HEAD).
- **Weekly A/B** (`2463257a` #277 → `9c43dfc9`; the 7-day SHA `f6b7fb9e` predates the v5 output):
  - **New and confirmed: npm drift** of +15.0% to +19.6% on `npm/hosted` and +12.6% to +15.8% on `npm/rescan`, over two rounds. Filed as **#993**. `npm/dry-run` (+15.1%) and `npm/public-proxy` (+10.1%) move the same way. There is no single culprit: about half lands before `045d7ec7` and half after, and neither half is significant alone. Callgrind shows +9.4% instructions, from new npm lock passes in VEX discovery (#345, #491, #799) and the shared lock cache (#646).
  - Known #472 regressions: bun/hosted +99.2%, bun/rescan +98.7% (#578, data commented); vlt/hosted +127.6%, vlt/rescan +142.8% (accepted, #579).
  - `pip/rescan` was flagged at +12.7%, but the confirmation round gave +8.9% [+2.3, +15.8], under the gate, so it is not confirmed. Watch it.
  - nuget/hosted is still 19.5% faster (#597).
- **A/A sanity check:** clean. npm/hosted -2.3%, uv/hosted +2.2%, poetry/hosted +2.8%, pip/rescan +3.5%; hatch/hosted -2.1%, hatch/rescan +2.5%.

## Scoreboard
Day: no daily A/B today (main unchanged). Week: wall ratio vs `2463257a` (#277). The median ms/pkg across `*/hosted` is 0.1553; hatch is excluded until it lands. `npm/hosted`'s 439.7 ms median comes from a noisy 3-sample run (min 331.6 ms). The compare medians of 317–322 ms are the better figure.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 439.7 | 0.1466 | — | 1.150 | regressed (#993) |
| `npm/rescan` | 258.5 | 0.0862 | — | 1.158 | regressed (#993) |
| `pnpm/hosted` | 216.5 | 0.0722 | — | 1.042 | OK |
| `pnpm/rescan` | 213.6 | 0.0712 | — | 0.998 | OK |
| `yarn-classic/hosted` | 303.1 | 0.1010 | — | 1.058 | OK |
| `yarn-classic/rescan` | 246.4 | 0.0821 | — | 1.055 | OK |
| `yarn-berry/hosted` | 412.8 | 0.1376 | — | — | OK |
| `yarn-berry/rescan` | 283.7 | 0.0946 | — | — | OK |
| `bun/hosted` | 396.5 | 0.1322 | — | 1.992 | regressed (#578) |
| `bun/rescan` | 367.7 | 0.1226 | — | 1.987 | regressed (#578) |
| `bun-isolated/hosted` | 465.8 | 0.1553 | — | — | OK |
| `bun-isolated/rescan` | 467.1 | 0.1557 | — | — | OK |
| `vlt/hosted` | 1246.6 | 0.8311 | — | 2.276 | slow; #472 cost accepted (#579) |
| `vlt/rescan` | 1301.7 | 0.8678 | — | 2.428 | slow; #472 cost accepted (#579) |
| `pip/hosted` | 126.3 | 0.1263 | — | 1.060 | OK |
| `pip/rescan` | 126.3 | 0.1263 | — | 1.127 | OK |
| `uv/hosted` | 220.3 | 0.5507 | — | 1.033 | slow (#836) |
| `uv/rescan` | 213.1 | 0.5327 | — | 0.956 | slow (#836) |
| `pylock/hosted` | 194.8 | 0.4869 | — | 1.027 | slow (#836) |
| `pylock/rescan` | 183.0 | 0.4575 | — | 1.041 | slow (#836) |
| `poetry/hosted` | 369.5 | 0.9237 | — | 0.988 | slow (#760) |
| `poetry/rescan` | 294.2 | 0.7354 | — | 1.048 | slow (#760) |
| `pipenv/hosted` | 133.8 | 0.3345 | — | 1.021 | slow (none) |
| `pipenv/rescan` | 151.8 | 0.3795 | — | 0.981 | slow (none) |
| `pdm/hosted` | 309.5 | 0.7738 | — | 1.052 | slow (#762) |
| `pdm/rescan` | 277.0 | 0.6924 | — | 1.032 | slow (#762) |
| `bundler/hosted` | 204.7 | 0.2559 | — | 1.078 | OK |
| `bundler/rescan` | 265.4 | 0.3317 | — | 1.099 | OK |
| `composer/hosted` | 175.7 | 0.2197 | — | 1.026 | OK |
| `composer/rescan` | 217.3 | 0.2717 | — | 1.111 | OK |
| `cargo/hosted` | 332.4 | 0.5540 | — | 1.011 | slow (#761) |
| `cargo/rescan` | 331.9 | 0.5532 | — | 1.010 | slow (#761) |
| `golang/hosted` | 95.1 | 0.0792 | — | 1.052 | OK |
| `golang/rescan` | 100.6 | 0.0838 | — | 1.082 | OK |
| `nuget/hosted` | 98.5 | 0.1095 | — | 0.805 | OK (faster, week 0.805) |
| `nuget/rescan` | 90.4 | 0.1004 | — | 1.042 | OK |
| `maven/hosted` | 98.8 | 0.0988 | — | 1.016 | OK |
| `maven/rescan` | 103.5 | 0.1035 | — | 1.079 | OK |
| `npm/dry-run` | 387.9 | 0.1293 | — | 1.151 | regressed, week (#993) |
| `npm/public-proxy` | 398.4 | 0.1328 | — | 1.101 | regressed, week (#993) |
| `npm/latency` | 756.4 | 0.2521 | — | 1.038 | OK |
| `hatch/hosted` (new, in #925) | 86.1 | 0.0861 | — | — | OK |
| `hatch/rescan` (new, in #925) | 77.0 | 0.0770 | — | — | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs (10-05 and 10-07 were about 1.3-1.4x slower everywhere), so read these as trends only.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 |
|---|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 |
| gradle | — | — | — | — | 170.5 | — |
| hatch | — | — | — | — | — | 86.1 |

## Open issues and PR
- **#993 (new): Perf regression: npm/hosted wall +15% (2463257a..9c43dfc9).** Weekly drift with no single culprit. Candidates: #799, #646, #345, #491.
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still regressed (weekly +99%); today's data is commented. Accepting it the way #579 was accepted is a human call.
- #579 (closed 2026-10-03 by a maintainer): the vlt/* #472 cost is accepted. Tracked as slow only.
- #760: Slow scan: poetry. Draft fix in #877.
- #761: Slow scan: cargo.
- #762: Slow scan: pdm. Draft fix in #877.
- #836: Slow scan: uv/pylock (per-patch lock re-serialize).
- **#925 (`bench/refresh`): Bench: cover Gradle and Hatch hosted modes.** Today it gained `hatch/hosted` and `hatch/rescan` (`5b9ae8ea`). `state: ready`, with a fresh CI run on the new head.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted` (0.1553 today), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run.

| pm | ms/pkg today (x median) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| poetry | 0.924 (5.9x) | 6 | #760 (fix draft #877) | `utils::poetry_lock::rewrite_poetry_lock_in`, 77% (whole lock re-parsed per patch). Callgrind 10-04 |
| vlt | 0.831 (5.4x) | 6 | none (#579 accepted) | #472 bundled-copy walk, plus DepId re-splitting in `redirect::vlt` (callgrind 10-02) |
| pdm | 0.774 (5.0x) | 6 | #762 (fix draft #877) | `utils::pdm_lock::rewrite_pdm_lock_in`, 77% (same per-patch re-parse as Poetry). Callgrind 10-04 |
| cargo | 0.554 (3.6x) | 6 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79%. Callgrind 10-04 |
| uv | 0.551 (3.5x) | 6 | #836 | `PythonLockSession::rewrite` 39%, mostly `DocumentMut` Display (whole lock re-serialized per patched dep). Callgrind 10-05 |
| pylock | 0.487 (3.1x) | 6 | #836 | Same as uv: `PythonLockSession::rewrite` 38%; vex `pypi_locks::extract` 31%. Callgrind 10-05 |
| pipenv | 0.335 (2.15x) | 1 | none | `patch::redirect::pipenv::entries` 69% inclusive (`pipenv::properties` 45%): Pipfile.lock re-tokenized per patch. Callgrind 10-07. It flips around 2x (10-05 2.4x, 10-06 1.8x) |

No scenario's peak RSS is above 2x the median (34.2 MiB). Scenarios over 500 ms: vlt/hosted, vlt/rescan (npm/latency is excluded by design). The new hatch/hosted runs at 0.086 ms/pkg (0.55x), so it is not slow.

## Coverage-gap backlog
main hasn't changed since 10-06.
- ~~**gradle**~~ (#646): covered by `gradle/*` in #925.
- ~~**hatch**~~ (#743/#680): covered by `hatch/*` in #925 (lockless `hatch.toml` env pins).
- **Hatch variants:** `[tool.hatch.envs]` in pyproject only (no hatch.toml), a hatch project with a `requirements.txt` (confirmation via requirements), and the uv-installer refusal path.
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
None yet. Merging hosted/rescan pairs needs 14+ days of history; there are 6 days so far. Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
