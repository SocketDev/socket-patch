[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-15, about 06:50–08:10 UTC.
- **main:** `e76cb9b3`, 26 commits since `313d5324`. 12 of them touch scan code, all edge-case fixes: Git LFS vendored npm tarballs (#1559), vlt extglob workspace members (#1555), yarn berry absolute `portal:`/`link:` copies (#1551), yarn classic VEX for unlocked ranges (#1548), nested vendored npm projects (#1543), gem source blocks (#1537, #1520), pnpm `trustLockfile` env (#1533), pyproject product detection (#1529), vendored PyPI revert (#1526), old-uv bare manifest overrides (#1525), and the untagged Bun 1.3.0/1.3.1 lock dialect (#1523).
- **Suite source:** `main`.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. Absolute times are about 0.8x yesterday's, so this runner is faster.
- **Validation:** **45/45 scenarios valid** on plain `main`.
- **A/A:** clean. npm/hosted -1.4%, pip/hosted +1.5%, cargo/hosted +5.1%, all ≈.
- **Daily A/B** (`313d5324` → `e76cb9b3`, 15 pairs): **no regressions**. Every scenario is ≈ and request counts are unchanged. nuget/hosted is the largest at +8.3% [+0.4, +14.8], under the gate.
- **Weekly A/B** (`6fcc51b4` → `e76cb9b3`, 15 pairs; flagged scenarios re-run with 25+15 pairs):
  - Known and confirmed: **golang/hosted +32.0%** (#1424), **nuget/hosted +20.2%** and nuget/rescan +11.0% (#1425), and **maven/hosted CPU +17.2%** with wall -5.9% (#1472). No fixes have merged.
  - yarn-classic/hosted +14.3% wall with +60 requests. This is the intended served-tarball read from #1328 (#1423 is closed), now inside the week window. It's under the 20% gate.
  - npm-family **peak RSS +15–23%**, still under the 30% gate.
  - Not confirmed: **pip/hosted** +11.4% in round 1 and +8.9% [+7.0, +13.9] in round 2, so it's under the 10% gate. That breaks the "two consecutive runs ≥10%" streak from 10-14. pipenv/hosted was +14.1% in round 1 and +3.7% in round 2.
  - Faster: bun -55% / -64%, bun-isolated -48% / -55%, vlt -50% / -53%, gradle/rescan -31%, npm/rescan -21%, maven/rescan -20%, pylock/rescan -14%, composer/rescan -11%.

## Scoreboard
Day: wall ratio vs `313d5324`. Week: wall ratio vs `6fcc51b4`. Both are paired A/B medians. Median wall comes from today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is **0.134**. It fell from 0.245 because pip, which is the median, ran 0.54x on this runner, so more package managers clear 2x than yesterday.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 284.9 | 0.0950 | 1.046 | 1.035 | OK |
| `npm/rescan` | 232.9 | 0.0776 | 1.005 | 0.789 | OK |
| `pnpm/hosted` | 185.4 | 0.0618 | 1.021 | 1.025 | OK |
| `pnpm/rescan` | 180.1 | 0.0600 | 0.934 | 0.939 | OK |
| `yarn-classic/hosted` | 251.3 | 0.0838 | 0.987 | 1.108 | week +14.3% / +60 req (#1328, intended) |
| `yarn-classic/rescan` | 185.6 | 0.0619 | 1.028 | 0.909 | requests 127->187 (#1463, intended) |
| `yarn-berry/hosted` | 287.5 | 0.0958 | 1.048 | 1.061 | OK |
| `yarn-berry/rescan` | 208.6 | 0.0695 | 1.025 | 0.972 | OK |
| `bun/hosted` | 196.4 | 0.0655 | 1.004 | 0.448 | OK |
| `bun/rescan` | 133.9 | 0.0446 | 1.017 | 0.365 | OK |
| `bun-isolated/hosted` | 192.3 | 0.0641 | 1.013 | 0.525 | OK |
| `bun-isolated/rescan` | 165.9 | 0.0553 | 0.965 | 0.449 | OK |
| `vlt/hosted` | 514.9 | 0.3433 | 0.956 | 0.496 | slow (2.56x, 515 ms; #1570) |
| `vlt/rescan` | 550.7 | 0.3671 | 1.005 | 0.470 | slow (551 ms; #1570) |
| `pip/hosted` | 134.1 | 0.1341 | 1.015 | 1.114 | OK |
| `pip/rescan` | 105.2 | 0.1052 | 1.036 | 0.991 | OK |
| `uv/hosted` | 166.1 | 0.4152 | 1.025 | 0.979 | slow (#836) |
| `uv/rescan` | 144.0 | 0.3601 | 1.002 | 0.942 | OK |
| `pylock/hosted` | 176.0 | 0.4400 | 0.984 | 0.995 | slow (#836) |
| `pylock/rescan` | 121.3 | 0.3031 | 1.011 | 0.859 | OK |
| `poetry/hosted` | 127.2 | 0.3180 | 1.071 | 0.949 | slow (2.37x; #1473) |
| `poetry/rescan` | 100.8 | 0.2519 | 1.022 | 0.907 | OK |
| `pipenv/hosted` | 122.1 | 0.3052 | 0.958 | 1.141 | slow (2.28x; #1246) |
| `pipenv/rescan` | 99.4 | 0.2485 | 0.957 | 1.002 | OK |
| `pdm/hosted` | 108.5 | 0.2713 | 1.020 | 0.961 | slow (2.02x) |
| `pdm/rescan` | 94.2 | 0.2354 | 0.950 | 0.906 | OK |
| `hatch/hosted` | 72.3 | 0.0723 | 1.042 | 0.948 | OK |
| `hatch/rescan` | 65.2 | 0.0652 | 0.989 | 0.931 | OK |
| `bundler/hosted` | 211.9 | 0.2649 | 0.965 | 1.097 | OK |
| `bundler/rescan` | 200.8 | 0.2510 | 0.981 | 1.020 | OK |
| `composer/hosted` | 186.2 | 0.2328 | 0.982 | 1.045 | OK |
| `composer/rescan` | 128.1 | 0.1601 | 1.012 | 0.890 | OK |
| `cargo/hosted` | 328.8 | 0.5480 | 0.997 | 1.072 | slow (#761) |
| `cargo/rescan` | 380.7 | 0.6344 | 0.992 | 1.051 | slow (#761) |
| `golang/hosted` | 114.8 | 0.0957 | 1.049 | 1.352 | regressed (#1424, week) |
| `golang/rescan` | 111.7 | 0.0931 | 1.026 | 1.222 | regressed (#1424, week) |
| `nuget/hosted` | 92.4 | 0.1027 | 1.083 | 1.360 | regressed (#1425, week) |
| `nuget/rescan` | 98.0 | 0.1089 | 0.947 | 1.100 | regressed (#1425, week) |
| `maven/hosted` | 107.4 | 0.1074 | 1.042 | 0.976 | CPU regressed (#1472) |
| `maven/rescan` | 95.3 | 0.0953 | 0.984 | 0.798 | OK |
| `gradle/hosted` | 186.1 | 0.1861 | 1.032 | 0.903 | OK |
| `gradle/rescan` | 181.0 | 0.1810 | 1.005 | 0.693 | OK |
| `npm/dry-run` | 247.7 | 0.0826 | 0.987 | 1.038 | OK |
| `npm/public-proxy` | 247.7 | 0.0826 | 1.000 | 1.037 | OK |
| `npm/latency` | 683.9 | 0.2280 | 1.017 | 1.019 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 | 10-13 | 10-14 | 10-15 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 | 217.5 | 345.9 | 284.9 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 | 164.1 | 233.6 | 185.4 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 | 197.6 | 335.9 | 251.3 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 | 223.6 | 344.9 | 287.5 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 | 176.0 | 197.3 | 196.4 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 | 167.0 | 243.5 | 192.3 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 | 437.8 | 743.2 | 514.9 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 | 107.0 | 247.1 | 134.1 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 | 162.0 | 226.9 | 166.1 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 | 149.1 | 227.4 | 176.0 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 | 112.6 | 152.0 | 127.2 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 | 101.6 | 137.0 | 122.1 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 | 113.1 | 153.8 | 108.5 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 | 64.4 | 88.7 | 72.3 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 | 178.7 | 278.2 | 211.9 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 | 126.3 | 196.3 | 186.2 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 | 266.5 | 350.9 | 328.8 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 | 86.4 | 142.4 | 114.8 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 | 88.9 | 120.5 | 92.4 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 | 83.2 | 140.4 | 107.4 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 | 151.2 | 254.3 | 186.1 |

## Open issues and PR
- **#1570 (new)** Slow scan: vlt. It's the 3rd consecutive slow run. Hot spot: `vlt::every_instance_pinned` → `partition_instances` → `vlt_lock_text::split_dep_id`, about 35% of instructions.
- #1472: Perf regression: maven CPU. Still +17% CPU week, wall flat.
- #1424: Perf regression: golang (#1403). Still +32% week. No fix PR.
- #1425: Perf regression: nuget (#1340/#1341). Still +20% week. No fix PR.
- #1473: Slow scan: poetry (2.37x today against a lower median). #1246: Slow scan: pipenv (2.28x). #836: Slow scan: uv/pylock. #761: Slow scan: cargo.
- #580: Benchmark tracking.
- No open `bench/refresh` PR. The suite needed no change today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded).

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| cargo | 4.09x | 12 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| pylock | 3.28x | 12 | #836 | `PythonLockSession::rewrite`: the lock is re-serialized per patched dep (callgrind 10-05) |
| uv | 3.10x | 12 | #836 | Same as pylock |
| vlt | 2.56x; vlt/hosted 515 ms, vlt/rescan 551 ms (>500) | 3 | **#1570** | `vlt::every_instance_pinned`/`partition_instances` → `split_dep_id` (`registry_identity`, `is_npm_semver`), 35% Ir; `vlt_preflight::preflight_scope` 32% (callgrind 10-15) |
| poetry | 2.37x | 1 | #1473 | see #1473 |
| pipenv | 2.28x | 1 | #1246 | per-patch Pipfile.lock re-tokenize (#1246) |
| pdm | 2.02x | 1 | none | not profiled; borderline |

poetry, pipenv and pdm came back because the median dropped (pip ran 0.54x on this runner), not because they slowed down: day A/B is ≈ for all three. No scenario's peak RSS is above 2x the median (37.4 MiB).

## Coverage-gap backlog
New since 10-14 (`313d5324..e76cb9b3`): none that needs a scenario. The 12 scan commits are edge-case fixes for layouts the fixtures don't model: Git LFS-captured vendored tarballs (#1541), vlt extglob workspace globs (#1542), berry absolute `portal:`/`link:` (#1540), gem `;`/multi-line source blocks (#1531, #1509), pnpm `trustLockfile` env (#1514), and the untagged Bun 1.3.0/1.3.1 lock (#1521).

Carried over: renamed yarn copies (#1489, #1517); Bun 1.3+ `bun.lockb` tag (#1496); npm alias links from a workspace member (#1500); hosted pnpm pin beside a `file:` copy (#1469); workspace member globs (#1480, #1493); uv script no-sources (#1504); Poetry source pin over a pre-2.1 lock (#1506); gem lockfile DSL calls (#1479, #1478); Cargo source replacement (#1420); `--system-site-packages` venvs (#1419); `.yarnrc.yml` `${VAR}` (#1433); uv `no-sources` (#1434); pnpm ignored lock (#1431); Composer global home (#1421); moved `BUNDLE_GEMFILE` (#1430); Poetry `source = "pypi"` (#1413); hosted cargo `registry = "crates-io"` (#1412); Maven reactor / multi-module (#1349, #261); NuGet member and named locks (#1340) and inherited sources (#1341); Go workspaces (#1393) and pre-1.17 graphs (#1403); uv workspace member dirs (#1335); Pipenv/uv vendored pylock co-wiring (#1399, #1390); OS trust store (#1326); non-UTF-8 requirements (#1152); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Yarn 4 pnpm linker (#496); pnpm global store (#829, #698); vlt brotli lock nodes (#820). Every `pm:*` label has a scenario except deno, which has no hosted rewrite.

**Suite runtime:** the full daily `compare` (15 pairs, 45 scenarios) took **14.6 min** today (10-14: 21.2 min on a slower runner; 10-13: 13.5 min). That's still over the ~12-minute budget. Shrink something before adding scenarios.

## Stale / redundant scenarios
None removed. Merging needs 14+ days of history; there are 12 runs so far. Candidate: `bun/rescan` and `bun-isolated/rescan` moved together again (day +1.7% / -3.5%; week -64% / -55%).

---
_Generated by [Claude Code](https://claude.ai/code)_
