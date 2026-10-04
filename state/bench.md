[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-04 ~07:20 UTC
- **main:** `045d7ec7` (Bound patch API connects and stalled reads, #581). Unchanged since the 2026-10-03 run.
- **Suite source:** `main` plus #667 (`bench/refresh`: `bun-isolated/*` and today's harness fix). The CLI is identical to main.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox. Absolute timings are for trend context only. Verdicts come only from same-machine interleaved `compare`.
- **Validation:** 41/41 scenarios valid on today's main.
- **Daily A/B:** skipped, because main didn't move (LAST_SHA == HEAD == `045d7ec7`).
- **Weekly A/B:** the 7-day SHA `3efdc31d` predates the v5 output (#277), so the base is `2463257a` (#277). 7 pairs + 10 confirm. Still confirmed: bun/* +117% / +127% (#578, open) and vlt/* +112% / +116% (#579, which a maintainer **closed as an accepted cost** of scanning previously skipped copies). The other 33 comparable scenarios are unchanged. `yarn-berry/*` and `bun-isolated/*` have no comparable base.
- **A/A sanity check** (npm/hosted, vlt/hosted, poetry/hosted, 9 pairs): clean.
- **Harness bug found and fixed** (#667, `93b1c929`): a rescan whose preparatory scan failed validation skipped the tree restore. In `compare`, the other binary was then falsely reported INVALID: the weekly head was flagged on `bun-isolated/rescan`.

## Scoreboard
Day: no daily base today. Week: wall ratio vs `2463257a` (#277). ms/pkg median across `*/hosted` is 0.1122.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 198.3 | 0.0661 | — | 1.022 | OK |
| `npm/rescan` | 176.7 | 0.0589 | — | 1.055 | OK |
| `pnpm/hosted` | 162.1 | 0.0540 | — | 0.953 | OK |
| `pnpm/rescan` | 138.4 | 0.0461 | — | 1.031 | OK |
| `yarn-classic/hosted` | 166.9 | 0.0556 | — | 0.997 | OK |
| `yarn-classic/rescan` | 157.0 | 0.0523 | — | 1.006 | OK |
| `yarn-berry/hosted` | 208.6 | 0.0695 | — | — | OK |
| `yarn-berry/rescan` | 172.3 | 0.0574 | — | — | OK |
| `bun/hosted` | 321.5 | 0.1072 | — | 2.167 | **regressed** (#578) |
| `bun/rescan` | 287.9 | 0.0960 | — | 2.267 | **regressed** (#578) |
| `bun-isolated/hosted` (in #667) | 336.6 | 0.1122 | — | — | OK |
| `bun-isolated/rescan` (in #667) | 301.5 | 0.1005 | — | — | OK |
| `vlt/hosted` | 764.0 | 0.5093 | — | 2.116 | slow; #472 cost accepted (#579 closed) |
| `vlt/rescan` | 698.5 | 0.4656 | — | 2.156 | slow; #472 cost accepted (#579 closed) |
| `pip/hosted` | 81.8 | 0.0818 | — | 1.067 | OK |
| `pip/rescan` | 75.2 | 0.0752 | — | 1.004 | OK |
| `uv/hosted` | 127.1 | 0.3177 | — | 1.023 | slow |
| `uv/rescan` | 111.0 | 0.2776 | — | 1.158 | slow |
| `pylock/hosted` | 126.2 | 0.3156 | — | 0.992 | slow |
| `pylock/rescan` | 102.2 | 0.2554 | — | 1.016 | slow |
| `poetry/hosted` | 201.6 | 0.5040 | — | 0.980 | slow (#760) |
| `poetry/rescan` | 175.1 | 0.4377 | — | 0.971 | slow (#760) |
| `pipenv/hosted` | 86.5 | 0.2162 | — | 1.006 | OK |
| `pipenv/rescan` | 79.8 | 0.1995 | — | 1.032 | OK |
| `pdm/hosted` | 162.4 | 0.4061 | — | 0.962 | slow (#762) |
| `pdm/rescan` | 159.9 | 0.3997 | — | 1.046 | slow (#762) |
| `bundler/hosted` | 141.5 | 0.1769 | — | 1.036 | OK |
| `bundler/rescan` | 124.6 | 0.1558 | — | 1.042 | OK |
| `composer/hosted` | 115.4 | 0.1443 | — | 1.057 | OK |
| `composer/rescan` | 103.3 | 0.1291 | — | 1.043 | OK |
| `cargo/hosted` | 258.5 | 0.4309 | — | 1.033 | slow (#761) |
| `cargo/rescan` | 213.9 | 0.3566 | — | 0.993 | slow (#761) |
| `golang/hosted` | 64.3 | 0.0536 | — | 1.057 | OK |
| `golang/rescan` | 77.7 | 0.0648 | — | 1.054 | OK |
| `nuget/hosted` | 87.2 | 0.0969 | — | 1.045 | OK |
| `nuget/rescan` | 73.2 | 0.0814 | — | 0.989 | OK |
| `maven/hosted` | 62.0 | 0.0620 | — | 0.986 | OK |
| `maven/rescan` | 56.6 | 0.0566 | — | 0.960 | OK |
| `npm/dry-run` | 200.4 | 0.0668 | — | 1.068 | OK |
| `npm/public-proxy` | 201.2 | 0.0671 | — | 1.044 | OK |
| `npm/latency` | 647.8 | 0.2159 | — | 1.028 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only.

| pm | 2026-10-02 | 2026-10-03 | 2026-10-04 |
|---|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 |
| pnpm | 153.6 | 180.5 | 162.1 |
| yarn-classic | 179.9 | 195.4 | 166.9 |
| yarn-berry | 219.5 | 228.8 | 208.6 |
| bun | 289.7 | 303.6 | 321.5 |
| bun-isolated | — | — | 336.6 |
| vlt | 843.8 | 894.2 | 764.0 |
| pip | 102.2 | 97.0 | 81.8 |
| uv | 136.0 | 143.9 | 127.1 |
| pylock | 113.6 | 142.1 | 126.2 |
| poetry | 187.6 | 221.4 | 201.6 |
| pipenv | 106.2 | 96.5 | 86.5 |
| pdm | 180.4 | 180.5 | 162.4 |
| bundler | 136.0 | 180.4 | 141.5 |
| composer | 122.2 | 123.0 | 115.4 |
| cargo | 228.4 | 262.5 | 258.5 |
| golang | 68.5 | 71.4 | 64.3 |
| nuget | 90.9 | 90.1 | 87.2 |
| maven | 79.3 | 81.6 | 62.0 |

## Open issues and PR
- #578: Perf regression: bun/hosted wall +110% (1169ae68, #472). Still regressed (weekly +117% / +127%). Hot spot: `rewrite_bun_lock` calls `bun_lock_text::is_bundled_entry`, which JSON-parses each entry once per patch. Today's comment points to the #579 precedent; closing it is a human call.
- #579 (closed 2026-10-03 by a maintainer): the vlt/* #472 cost is accepted ("correctly scanning code that it was skipping"). Tracked as slow only.
- #760: Slow scan: poetry hosted 4.5x median ms/pkg (per-patch poetry.lock re-parse). **New today.**
- #761: Slow scan: cargo hosted 3.8x median ms/pkg (per-patch Cargo.lock re-parse). **New today.**
- #762: Slow scan: pdm hosted 3.6x median ms/pkg (per-patch pdm.lock re-parse). **New today.**
- #667 (`bench/refresh`): Bench: cover Bun isolated .bun store; fix rescan restore. Today it added the harness fix `93b1c929`.

## Standing slow-systems list
A package manager is slow when its ms/pkg is more than 2x the median across `*/hosted` (0.1122), or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). An issue opens after 3 consecutive runs, capped at 3 new issues per run.

| pm | ms/pkg today (x median) | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| vlt | 0.509 (4.5x) | 3 | none (#579 accepted) | #472 bundled-copy walk, plus DepId re-splitting in `redirect::vlt` (callgrind 10-02) |
| poetry | 0.504 (4.5x) | 3 | #760 | `utils::poetry_lock::rewrite_poetry_lock_in`, 77% (`toml_edit` parse 45.5%, re-serialize 18%; whole lock re-parsed per patch). Callgrind 10-04 |
| cargo | 0.431 (3.8x) | 3 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (several full parses per patched crate). Callgrind 10-04 |
| pdm | 0.406 (3.6x) | 3 | #762 | `utils::pdm_lock::rewrite_pdm_lock_in`, 77% (same per-patch re-parse as Poetry). Callgrind 10-04 |
| uv | 0.318 (2.8x) | 3 | overflow (cap of 3); file next run | `utils::python_lock::PythonLockSession::rewrite` 39%; vex `pypi_locks::extract` 23% (10-02) |
| pylock | 0.316 (2.8x) | 3 | overflow (cap of 3); file next run | not profiled yet (same Python lock session as uv) |

Borderline: pipenv 0.216 (1.9x). No scenario's peak RSS is above 2x the median (34.0 MiB). Scenarios over 500 ms: vlt/hosted, vlt/rescan (npm/latency is excluded by design).

## Coverage-gap backlog
No new scan commits on main since 2026-10-03, so no new gaps. Carried over:
- ~~**Bun isolated `.bun` store** (#496)~~: covered by `bun-isolated/*` in #667.
- **Yarn 4 pnpm linker** (`nodeLinker: pnpm`, `node_modules/.store`, #496): yarn-berry is covered only with the node-modules linker.
- **Yarn berry re-pin of old `npm:…::__archiveUrl` pins** (#465): a rescan over pre-#465 lockfiles is uncovered.
- **bun.lockb (binary lockfile):** the `bun_binary` rewriter and codec (#472) are unbenchmarked.
- **Bundled copies:** no fixture hits the `redirect_*_bundled_instance_skipped` paths (#472).
- **hatch:** `hatch.toml` is a HOSTED|PROBE pypi input, but there is no `pm:hatch` scenario. Open PRs #700/#743/#680 are reworking Hatch, so add coverage after they land.
- **gradle:** Maven hosted with Gradle build scripts is uncovered (`pm:gradle`). #646 (open) adds full Gradle support.
- **Python env discovery:** `UV_PROJECT_ENVIRONMENT` / PDM venv locations (#540), `.egg-info` (#452), Poetry `envs.toml` (#527) and lock-only `requirements.txt` (#530) are uncovered.
- **pnpm-workspace.yaml append** (#414): only the fresh-file case is covered.
- **Gemfile multi-layer `.bundle/config`** (#532) and Gemfile declaration dedupe (#552): only one layer is covered.
- deno: no hosted rewrite, so no scenario is needed.

## Stale / redundant scenarios
None yet. 14+ days of history are needed before merging any hosted/rescan pairs. Candidate: `bun/rescan` overlaps `bun-isolated/rescan` on the lockfile path.

---
_Generated by [Claude Code](https://claude.ai/code)_
