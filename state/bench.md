[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-16, about 06:50–09:10 UTC.
- **main:** `657fce2b`, 14 commits since `e76cb9b3`. 9 of them touch scan code, all edge-case fixes: yarn portal copies read as no package (#1586), yarn berry missing `portal:`/`link:` copies (#1571), pnpm 11 env booleans (#1575), uv project shadowing parent uv settings (#1566), vlt 1.4 `pnpm-workspace.yaml` members (#1574), PyPI direct refs contesting wiring (#1562), VEX gemspec / pyproject (#1582, #1577) and a CLI test cleanup (#1565).
- **Suite source:** `main`.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. Absolute times are about 1.2x yesterday's, so this runner is slower.
- **Validation:** **45/45 scenarios valid** on plain `main`.
- **A/A:** clean. npm/hosted -3.9%, pip/hosted -3.1%, cargo/hosted +5.1%, all ≈.
- **Daily A/B** (`e76cb9b3` → `657fce2b`, 15 pairs): **no regressions**. Every scenario is ≈ and request counts are unchanged.
- **Weekly A/B** (`cc938aa6` → `657fce2b`, 15 pairs; new flags re-run with 25+15 pairs). The week base moved past last week's large bun/vlt speedup, which uncovered drift it had been hiding:
  - **New, confirmed: yarn-berry/rescan +21.4%** [+13.8, +25.1] (+53 ms) → **#1607**, and **bun-isolated/rescan +21.3%** [+12.7, +32.7] (+40 ms) → **#1606**. bun-isolated/hosted +15.6% and bun/hosted +12.9% are confirmed too, but under the 20% gate, so they're tracked on #1606. All four were first seen in the 10-12 daily run at about +15%.
  - **Bisect** (3 builds over `cc938aa6..17793173`): both regressions are split. bun-isolated/rescan gets about half in `1438b1a7..a43cf327` (`dcdc1043`, #1279, is the candidate). yarn-berry/rescan gets about half in `a43cf327..eca5d247` (#1321/#1323 are the candidates). For both, the rest lands in `eca5d247..17793173` (#1397 is the berry candidate).
  - Known and confirmed: golang/hosted +25.8% and golang/rescan +25.3% (#1424); nuget/hosted +21.9% and nuget/rescan +29.9% (#1425); maven CPU +17.7% and +32.4%, with wall -10% and -5% (#1472); yarn-classic +60 requests, the intended tarball reads from #1328/#1463.
  - Not confirmed: npm/rescan (+12.2% → +9.9%), pnpm/rescan (+14.6% → +12.1%, CI crosses 0), pipenv/hosted (+13.9% → +9.0%).

## Scoreboard
Day: wall ratio vs `e76cb9b3`. Week: wall ratio vs `cc938aa6`. Both are paired A/B medians. Median wall comes from today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is **0.1612**.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 331.1 | 0.1104 | 1.002 | 1.065 | OK |
| `npm/rescan` | 254.2 | 0.0847 | 0.954 | 1.122 | OK |
| `pnpm/hosted` | 294.7 | 0.0982 | 1.010 | 1.114 | OK |
| `pnpm/rescan` | 247.8 | 0.0826 | 1.010 | 1.146 | OK |
| `yarn-classic/hosted` | 339.1 | 0.1130 | 1.004 | 1.169 | week +16.9% / +60 req (#1328, intended) |
| `yarn-classic/rescan` | 258.4 | 0.0861 | 1.026 | 1.290 | week +29.0% / +60 req (#1328/#1463, intended) |
| `yarn-berry/hosted` | 350.4 | 0.1168 | 1.047 | 1.068 | OK |
| `yarn-berry/rescan` | 307.0 | 0.1023 | 1.048 | 1.185 | regressed (#1607, week) |
| `bun/hosted` | 200.9 | 0.0670 | 1.057 | 1.125 | week +12.9% (#1606, below gate) |
| `bun/rescan` | 164.6 | 0.0549 | 1.006 | 1.070 | OK |
| `bun-isolated/hosted` | 249.3 | 0.0831 | 0.975 | 1.169 | week +15.6% (#1606, below gate) |
| `bun-isolated/rescan` | 234.5 | 0.0782 | 1.037 | 1.229 | regressed (#1606, week) |
| `vlt/hosted` | 647.1 | 0.4314 | 1.012 | 1.087 | slow (2.68x, 647 ms; #1570) |
| `vlt/rescan` | 651.2 | 0.4342 | 0.978 | 1.059 | slow (651 ms; #1570) |
| `pip/hosted` | 150.2 | 0.1502 | 1.058 | 1.043 | OK |
| `pip/rescan` | 161.6 | 0.1616 | 0.953 | 1.096 | OK |
| `uv/hosted` | 272.1 | 0.6802 | 0.988 | 1.057 | slow (4.22x; #836) |
| `uv/rescan` | 200.4 | 0.5011 | 1.019 | 0.971 | OK |
| `pylock/hosted` | 233.8 | 0.5846 | 1.016 | 1.011 | slow (3.63x; #836) |
| `pylock/rescan` | 182.9 | 0.4571 | 1.060 | 0.975 | OK |
| `poetry/hosted` | 171.8 | 0.4296 | 1.024 | 0.917 | slow (2.67x; #1473) |
| `poetry/rescan` | 140.5 | 0.3512 | 0.945 | 1.010 | OK |
| `pipenv/hosted` | 160.4 | 0.4011 | 1.016 | 1.139 | slow (2.49x; #1246) |
| `pipenv/rescan` | 145.6 | 0.3640 | 0.987 | 1.047 | OK |
| `pdm/hosted` | 150.8 | 0.3769 | 0.949 | 0.970 | slow (2.34x) |
| `pdm/rescan` | 130.6 | 0.3265 | 0.982 | 0.982 | OK |
| `hatch/hosted` | 88.2 | 0.0882 | 0.947 | 0.976 | OK |
| `hatch/rescan` | 87.9 | 0.0879 | 1.046 | 0.911 | OK |
| `bundler/hosted` | 251.0 | 0.3137 | 1.057 | 1.127 | OK |
| `bundler/rescan` | 254.3 | 0.3179 | 1.059 | 1.089 | OK |
| `composer/hosted` | 187.9 | 0.2349 | 0.954 | 1.083 | OK |
| `composer/rescan` | 154.7 | 0.1934 | 0.996 | 1.023 | OK |
| `cargo/hosted` | 362.8 | 0.6047 | 1.031 | 1.000 | slow (3.75x; #761) |
| `cargo/rescan` | 362.4 | 0.6040 | 0.974 | 1.001 | slow (#761) |
| `golang/hosted` | 145.0 | 0.1208 | 1.044 | 1.258 | regressed (#1424, week) |
| `golang/rescan` | 131.6 | 0.1097 | 1.052 | 1.253 | regressed (#1424, week) |
| `nuget/hosted` | 145.1 | 0.1612 | 0.988 | 1.219 | regressed (#1425, week) |
| `nuget/rescan` | 120.0 | 0.1334 | 1.014 | 1.299 | regressed (#1425, week) |
| `maven/hosted` | 115.2 | 0.1152 | 0.967 | 0.900 | CPU regressed (#1472) |
| `maven/rescan` | 97.5 | 0.0975 | 1.057 | 0.952 | CPU regressed (#1472) |
| `gradle/hosted` | 274.4 | 0.2744 | 1.022 | 0.905 | OK |
| `gradle/rescan` | 236.2 | 0.2362 | 0.968 | 0.981 | OK |
| `npm/dry-run` | 299.4 | 0.0998 | 1.011 | 1.082 | OK |
| `npm/public-proxy` | 396.9 | 0.1323 | 1.004 | 1.023 | OK |
| `npm/latency` | 809.0 | 0.2697 | 1.011 | 1.009 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 | 10-13 | 10-14 | 10-15 | 10-16 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 | 217.5 | 345.9 | 284.9 | 331.1 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 | 164.1 | 233.6 | 185.4 | 294.7 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 | 197.6 | 335.9 | 251.3 | 339.1 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 | 223.6 | 344.9 | 287.5 | 350.4 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 | 176.0 | 197.3 | 196.4 | 200.9 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 | 167.0 | 243.5 | 192.3 | 249.3 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 | 437.8 | 743.2 | 514.9 | 647.1 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 | 107.0 | 247.1 | 134.1 | 150.2 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 | 162.0 | 226.9 | 166.1 | 272.1 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 | 149.1 | 227.4 | 176.0 | 233.8 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 | 112.6 | 152.0 | 127.2 | 171.8 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 | 101.6 | 137.0 | 122.1 | 160.4 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 | 113.1 | 153.8 | 108.5 | 150.8 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 | 64.4 | 88.7 | 72.3 | 88.2 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 | 178.7 | 278.2 | 211.9 | 251.0 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 | 126.3 | 196.3 | 186.2 | 187.9 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 | 266.5 | 350.9 | 328.8 | 362.8 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 | 86.4 | 142.4 | 114.8 | 145.0 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 | 88.9 | 120.5 | 92.4 | 145.1 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 | 83.2 | 140.4 | 107.4 | 115.2 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 | 151.2 | 254.3 | 186.1 | 274.4 |

## Open issues and PR
- **#1606 (new)** Perf regression: bun-isolated/rescan wall +21% (`cc938aa6..17793173`; #1279 candidate).
- **#1607 (new)** Perf regression: yarn-berry/rescan wall +21% (`a43cf327..17793173`; #1321/#1323/#1397 candidates).
- #1424: Perf regression: golang (#1403). Still +26% week. No fix PR.
- #1425: Perf regression: nuget (#1340/#1341). Still +22–30% week. No fix PR.
- #1472: Perf regression: maven CPU. +18–32% CPU week, wall flat or down.
- #1570: Slow scan: vlt. #1473: Slow scan: poetry. #1246: Slow scan: pipenv. #836: Slow scan: uv/pylock. #761: Slow scan: cargo.
- #580: Benchmark tracking.
- No open `bench/refresh` PR. The suite needed no change today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded).

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| uv | 4.22x | 13 | #836 | `PythonLockSession::rewrite`: the lock is re-serialized per patched dep (callgrind 10-05) |
| cargo | 3.75x | 13 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| pylock | 3.63x | 13 | #836 | Same as uv |
| vlt | 2.68x; vlt/hosted 647 ms, vlt/rescan 651 ms (>500) | 4 | #1570 | `vlt::every_instance_pinned`/`partition_instances` → `split_dep_id`, 35% Ir; `vlt_preflight::preflight_scope` 32% (callgrind 10-15) |
| poetry | 2.67x | 2 | #1473 | `lock_fragments::rewrite_batch` + VEX lock re-parse (#1473) |
| pipenv | 2.49x | 2 | #1246 | per-patch Pipfile.lock re-tokenize (#1246) |
| pdm | 2.34x | 2 | none | not profiled. A 3rd consecutive run tomorrow would qualify for an issue |

No scenario's peak RSS is above 2x the median (37.8 MiB).

## Coverage-gap backlog
New since 10-15 (`e76cb9b3..657fce2b`): none needs a scenario. The scan commits are edge-case fixes for layouts the fixtures don't model: yarn `portal:`/`link:` copies (#1579, #1561), pnpm 11 non-boolean env values (#1557), a uv project under a parent with uv settings (#1545), vlt 1.4 `pnpm-workspace.yaml` members (#1564), and PyPI direct refs (#1549).

Carried over: Git LFS vendored tarballs (#1541); vlt extglob workspace globs (#1542); berry absolute `portal:`/`link:` (#1540); gem source blocks (#1531, #1509); pnpm `trustLockfile` env (#1514); untagged Bun 1.3.0/1.3.1 lock (#1521); renamed yarn copies (#1489, #1517); Bun 1.3+ `bun.lockb` tag (#1496); npm alias links from a workspace member (#1500); hosted pnpm pin beside a `file:` copy (#1469); workspace member globs (#1480, #1493); uv script no-sources (#1504); Poetry source pin over a pre-2.1 lock (#1506); gem lockfile DSL calls (#1479, #1478); Cargo source replacement (#1420); `--system-site-packages` venvs (#1419); `.yarnrc.yml` `${VAR}` (#1433); uv `no-sources` (#1434); pnpm ignored lock (#1431); Composer global home (#1421); moved `BUNDLE_GEMFILE` (#1430); Poetry `source = "pypi"` (#1413); hosted cargo `registry = "crates-io"` (#1412); Maven reactor / multi-module (#1349, #261); NuGet member and named locks (#1340) and inherited sources (#1341); Go workspaces (#1393) and pre-1.17 graphs (#1403); uv workspace member dirs (#1335); Pipenv/uv vendored pylock co-wiring (#1399, #1390); OS trust store (#1326); non-UTF-8 requirements (#1152); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Yarn 4 pnpm linker (#496); pnpm global store (#829, #698); vlt brotli lock nodes (#820). Every `pm:*` label has a scenario except deno, which has no hosted rewrite.

**Suite runtime:** the full daily `compare` (15 pairs, 45 scenarios) took **20.4 min** today, on a slower runner (10-15: 14.6 min; 10-14: 21.2 min). That's still over the ~12-minute budget. Shrink something before adding scenarios.

## Stale / redundant scenarios
None removed. Merging needs 14+ days of history; there are 13 runs so far. The 10-15 candidate, `bun/rescan` vs `bun-isolated/rescan`, now diverges: bun-isolated/rescan is +21% week and bun/rescan is +7% ≈. That's distinct signal, so keep both.

---
_Generated by [Claude Code](https://claude.ai/code)_
