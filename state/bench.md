[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-12, about 06:50–08:10 UTC. No runs on 10-10 or 10-11.
- **main:** `17793173`, 161 commits since `f3c6313a`. They include the v5.0 JSON envelope (#1369), #1328 (yarn classic sha1 pins from served tarballs), #1403 (Go replace for unselected versions), #1340/#1341/#1344 (NuGet locks, sources and stale-cache warning), #1361 (Maven project-mode crawl) and #1049 (`--download-mode` removed; the suite never used it).
- **Suite source:** `main` plus **#1422**. Without #1422, 4 scenarios are INVALID on `main`: yarn-classic (60 unexpected served-tarball GETs from #1328) and nuget (the new `redirect_nuget_stale_global_package` warning from #1344). Both are legitimate behavior changes, and the fixtures are updated in #1422.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox.
- **Validation:** 45/45 scenarios valid with #1422 (41/45 on plain `main`). The only request-count change is yarn-classic/hosted, 127 → 187.
- **A/A:** clean (npm/hosted -3.6%, pip/rescan +0.4%, golang/rescan +2.6%, all ≈). A second A/A on the #1422 scenarios was also all ≈.
- **Daily A/B** (`f3c6313a` → `17793173`), each regression confirmed in a second round with 20+10 pairs:
  - **yarn-classic/hosted +164.8%** [+149, +178] and **yarn-classic/rescan +152.7%**, from #1328 (`5096c41a`). Filed as **#1423**.
  - **golang/rescan +34.3%** and **golang/hosted +23.4%**, from #1403 (`1d523d30`). Filed as **#1424**.
  - **nuget/rescan +30.7%** and **nuget/hosted +28.2%**. Candidates are #1340 and #1341; not bisected. Filed as **#1425**.
  - Below the gate (ledger only): yarn-berry/rescan +13.6%, bun-isolated/rescan +14.0%, and maven/rescan CPU +22.1% (its wall is -8.8%).
  - Did not confirm: pip/rescan, +17.0% → +7.4%.
- **Weekly A/B** (`045d7ec7` → `17793173`, 8 pairs plus an 8-pair confirmation round). The base predates gradle support, so gradle has no weekly ratio.
  - Faster: bun -59% / -64%, bun-isolated -49% / -57%, vlt -50% / -51%, poetry -44% / -54%, pdm -38% / -44%, npm/rescan -24%.
  - Slower: yarn-classic (+155% / +116%) and golang (+25% / +20%), the same regressions as the daily A/B. hatch/hosted +11.2% and hatch/rescan +12.3%. maven/hosted CPU +30.8% (its wall is -1.3%).
  - **npm-family hosted peak RSS is +19% to +27%:** npm/hosted +24.8%, yarn-classic/hosted +27.4%, yarn-berry/hosted +20.5%, pnpm/hosted +19.2%, npm/latency +25.4%. This is still below the 30% issue gate and keeps creeping up. Watch it.
- **Pre-#472 check** (`61cfb9b2` → head): bun/hosted -10.8%, bun/rescan -16.1%, npm/hosted -1.4%, npm/dry-run -1.5%. That's the 2nd consecutive run within 5%, so **#578 and #993 are closed** with evidence.
- **Issue cap:** 3 new issues this run. hatch/hosted (≥10% in 2 consecutive runs) and maven CPU are the overflow. File them next run if they persist.

## Scoreboard
Day: wall ratio vs `f3c6313a`. Week: wall ratio vs `045d7ec7`. From today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is 0.1622, which is yarn-classic/hosted's regressed value. Without that regression the median would be about 0.13.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 230.6 | 0.0769 | 1.063 | 1.045 | OK |
| `npm/rescan` | 188.5 | 0.0628 | 0.968 | 0.765 | OK |
| `pnpm/hosted` | 158.2 | 0.0527 | 1.075 | 0.962 | OK |
| `pnpm/rescan` | 147.8 | 0.0493 | 1.083 | 0.854 | OK |
| `yarn-classic/hosted` | 486.6 | 0.1622 | 2.592 | 2.545 | regressed (#1423), +60 requests |
| `yarn-classic/rescan` | 325.2 | 0.1084 | 2.537 | 2.159 | regressed (#1423) |
| `yarn-berry/hosted` | 215.5 | 0.0718 | 1.101 | 0.992 | OK |
| `yarn-berry/rescan` | 200.4 | 0.0668 | 1.154 | 0.957 | regressed day +13.6% (ledger) |
| `bun/hosted` | 143.8 | 0.0479 | 1.010 | 0.409 | OK |
| `bun/rescan` | 112.9 | 0.0376 | 1.140 | 0.358 | OK |
| `bun-isolated/hosted` | 168.1 | 0.0560 | 1.089 | 0.515 | OK |
| `bun-isolated/rescan` | 152.9 | 0.0510 | 1.150 | 0.432 | regressed day +14.0% (ledger) |
| `vlt/hosted` | 477.4 | 0.3183 | 1.004 | 0.500 | OK |
| `vlt/rescan` | 414.6 | 0.2764 | 1.038 | 0.488 | OK |
| `pip/hosted` | 93.3 | 0.0933 | 0.973 | 1.026 | OK |
| `pip/rescan` | 89.5 | 0.0895 | 1.170 | 0.992 | OK |
| `uv/hosted` | 169.8 | 0.4246 | 0.985 | 1.002 | slow (#836) |
| `uv/rescan` | 134.2 | 0.3356 | 1.016 | 0.956 | slow (#836) |
| `pylock/hosted` | 145.0 | 0.3625 | 1.070 | 1.168 | slow (#836) |
| `pylock/rescan` | 134.4 | 0.3360 | 1.057 | 0.878 | slow (#836) |
| `poetry/hosted` | 129.9 | 0.3247 | 0.966 | 0.556 | slow (#760) |
| `poetry/rescan` | 93.7 | 0.2342 | 0.956 | 0.459 | OK |
| `pipenv/hosted` | 105.9 | 0.2646 | 0.998 | 1.213 | OK |
| `pipenv/rescan` | 119.6 | 0.2991 | 0.983 | 1.011 | OK |
| `pdm/hosted` | 115.8 | 0.2896 | 1.030 | 0.621 | OK |
| `pdm/rescan` | 90.0 | 0.2250 | 1.117 | 0.558 | OK |
| `hatch/hosted` | 72.8 | 0.0728 | 1.116 | 1.112 | week +11.2% (ledger; 2nd run >=10%) |
| `hatch/rescan` | 63.0 | 0.0630 | 0.977 | 1.123 | week +12.3% (ledger) |
| `bundler/hosted` | 172.4 | 0.2155 | 1.061 | 1.068 | OK |
| `bundler/rescan` | 159.9 | 0.1999 | 1.051 | 1.066 | OK |
| `composer/hosted` | 169.0 | 0.2113 | 1.027 | 1.087 | OK |
| `composer/rescan` | 103.8 | 0.1297 | 1.064 | 0.869 | OK |
| `cargo/hosted` | 287.9 | 0.4799 | 0.995 | 1.052 | slow (#761) |
| `cargo/rescan` | 227.1 | 0.3785 | 0.986 | 1.042 | slow (#761) |
| `golang/hosted` | 106.9 | 0.0891 | 1.273 | 1.250 | regressed (#1424) |
| `golang/rescan` | 91.5 | 0.0762 | 1.455 | 1.204 | regressed (#1424) |
| `nuget/hosted` | 117.8 | 0.1309 | 1.284 | 0.983 | regressed (#1425) |
| `nuget/rescan` | 79.3 | 0.0881 | 1.345 | 1.039 | regressed (#1425) |
| `maven/hosted` | 88.0 | 0.0880 | 0.880 | 0.987 | CPU +31% week, wall flat (ledger) |
| `maven/rescan` | 74.5 | 0.0745 | 0.862 | 0.923 | CPU +22% day, wall -9% (ledger) |
| `gradle/hosted` | 187.0 | 0.1870 | 1.123 | — | OK |
| `gradle/rescan` | 170.4 | 0.1704 | 1.013 | — | OK |
| `npm/dry-run` | 227.0 | 0.0757 | 1.086 | 0.959 | OK |
| `npm/public-proxy` | 229.8 | 0.0766 | 0.985 | 1.050 | OK |
| `npm/latency` | 674.3 | 0.2248 | 1.014 | 0.980 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only. The 10-12 yarn-classic jump is #1423.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 |

## Open issues and PR
- **#1423** (new): Perf regression: yarn-classic/hosted wall +165% (`5096c41a`, #1328). Hot spot: `hosted::engine::classic_locks_registry_copy`, which runs `scan_blocks` per dep (61% Ir).
- **#1424** (new): Perf regression: golang/rescan wall +34% (`1d523d30`, #1403). Hot spot: `GoSumEditor::zip_versions` per dep (30% Ir).
- **#1425** (new): Perf regression: nuget/rescan wall +31% (#1340/#1341 candidates). Hot spot: `presence::groups_present` in `engine::confirm` (35% Ir), and `project.assets.json` parsed 4 times.
- #1246: Slow scan: pipenv. #836: Slow scan: uv/pylock. #761: Slow scan: cargo. #760: Slow scan: poetry. #762: Slow scan: pdm.
- #578 (bun) and #993 (npm drift): **closed today**, recovered 2 runs in a row.
- #580: Benchmark tracking.
- **PR #1422** (`bench/refresh`): serve real npm tarballs for yarn classic; allow the NuGet stale-cache warning.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). The median is inflated today by the yarn-classic regression, so the borderline package managers are noted below.

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| cargo | 2.96x | 9 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| uv | 2.62x | 9 | #836 | `PythonLockSession::rewrite` 39%: the lock is re-serialized per patched dep (callgrind 10-05) |
| pylock | 2.23x | 9 | #836 | Same as uv |
| poetry | 2.00x | 3 since #877 | #760 | Not re-profiled. Likely the batched-rewrite and VEX lock-extract split, as for pdm |
| vlt | 1.96x (under) | was 8 | none (#579 accepted) | Just under 2x today. vlt/hosted is 477 ms, under 500 ms |
| pdm | 1.79x (under) | was 3 | #762 | `lock_fragments::rewrite_batch` 45% (callgrind 10-08) |
| pipenv | 1.63x (under) | was 4 | #1246 | `redirect::pipenv::entries` 61% (callgrind 10-09) |

No scenario's peak RSS is above 2x the median (37.5 MiB). No scenario is over 500 ms other than npm/latency.

## Coverage-gap backlog
New since 10-09 (from `f3c6313a..17793173`):
- **Covered by #1422:** yarn classic served-tarball manifest check (#1328, #558/#591), and the NuGet stale global-packages warning (#1344).
- **Maven reactor / multi-module hosted** (#1349, #261): the maven fixture is single-module.
- **NuGet member and named locks** (#1340) and **inherited nuget.config sources** (#1341): the fixture has one project and one config.
- **Go workspaces:** `go.work` replaces (#1393) and pre-1.17 graphs that select unselected versions (#1403, #509). The golang fixture is a single go ≥ 1.17 module.
- **uv workspace member dir** scans (#1335), and **Pipenv/uv vendored pylock co-wiring** (#1399, #1390).
- **Yarn berry pin beside a later registry entry** (#1397).
- **OS trust store / SSL_CERT_FILE** (#1326): the mock is plain HTTP, so TLS setup isn't timed.

Carried over: non-UTF-8 requirements (#1152); gem section re-sort on re-scan (#1190); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Hatch and Gradle variants; Yarn 4 pnpm linker (#496); bun.lockb (#472); pnpm global store (#829, #698); vlt brotli lock nodes (#820); Python env discovery variants (#540, #452, #527, #530); Gemfile multi-layer `.bundle/config` (#532, #577). deno has no hosted rewrite, so it needs no scenario.

**Suite runtime:** the full daily `compare` took 16.5 min (15 pairs, 45 scenarios, 9 confirmation rounds), still over the ~12-minute budget. Before adding scenarios, shrink something, e.g. fewer `--runs` for the npm family's `*/rescan` twins.

## Stale / redundant scenarios
None removed. No scenario uses `--download-mode` (#1049 removed it). Merging the hosted/rescan pairs needs 14+ days of history; there are 9 runs so far. Candidate: `bun/rescan` and `bun-isolated/rescan` moved together again today (+14.0% vs +15.0% day; only bun-isolated crossed the gate).

---
_Generated by [Claude Code](https://claude.ai/code)_
