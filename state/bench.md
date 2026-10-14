[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-14, about 06:50–08:15 UTC.
- **main:** `313d5324`, 46 commits since `15c2c839`. They include #1474 (the quadratic hosted Hatch rewrite, fixing #1471), #1475 and #1486 (the Poetry/PDM batched lock rewrite and copy-free VEX lock reads, for #1473), #1463 (yarn classic rescan of v4 pins), #1489 and #1517 (renamed yarn copies), #1496 (Bun 1.3 `bun.lockb`) and #1449 (release `codegen-units = 1`; the perf profile keeps 16, so A/B stays comparable).
- **Suite source:** `main`.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.80GHz, cloud sandbox. Absolute times are about 1.6x yesterday's runner, so read the Trends column for today with that in mind.
- **Validation:** **45/45 scenarios valid** on plain `main`.
- **A/A:** clean. npm/hosted -2.2%, yarn-classic/rescan -2.6%, pip/rescan -4.3%, all ≈.
- **Daily A/B** (`15c2c839` → `313d5324`, 15 pairs): no time regressions. **yarn-classic/rescan requests 127 → 187** (+60 artifact GETs). This is intended: #1463 (`4c4cb67b`) makes the rescan read the served tarball of every pinned artifact so a stale v4 pin gets a warning (#1462). Wall +7.0% [-0.9, +18.4] is not significant. Faster: **poetry/hosted -18.6%** (#1475/#1486) and gradle/hosted -9.8%.
- **Weekly A/B** (`9c43dfc9` → `313d5324`, 8 pairs, pip confirmed with 20):
  - **pip/hosted +14.2%** [+5.8, +19.7] (+14.5 ms) and pip/rescan +9.4% [+5.1, +12.3]. **New**, confirmed, below the 20% issue gate. Day is flat, so this is drift inside `9c43dfc9..15c2c839`. Candidates: #1381, #1333, #1419. Not bisected.
  - golang/hosted +33.9% (#1424), nuget/hosted +19.4% (#1425) and maven CPU +27–29% with wall flat (#1472). All are unfixed.
  - npm-family **peak RSS +17–22%** (npm/hosted +20.0%, yarn-classic/hosted +22.4%, npm/public-proxy +20.2%), still under the 30% gate.
  - Recovered: **hatch** +4.6% / -2.5% (≈), so #1471 is fixed by #1474 (closed).
  - Faster: poetry -57% / -59%, pdm -45% / -52%, bun -52% / -62%, bun-isolated -47% / -53%, vlt -48% / -54%, npm/rescan -29%, gradle/rescan -26%.

## Scoreboard
Day: wall ratio vs `15c2c839`. Week: wall ratio vs `9c43dfc9`. From today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is **0.245** on today's slower runner (10-13: 0.107).

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 345.9 | 0.1153 | 1.019 | 1.010 | OK |
| `npm/rescan` | 249.0 | 0.0830 | 0.962 | 0.711 | OK |
| `pnpm/hosted` | 233.6 | 0.0779 | 1.009 | 0.962 | OK |
| `pnpm/rescan` | 182.0 | 0.0607 | 1.004 | 0.854 | OK |
| `yarn-classic/hosted` | 335.9 | 0.1120 | 0.940 | 1.204 | OK |
| `yarn-classic/rescan` | 242.7 | 0.0809 | 1.070 | 0.972 | requests 127->187 (#1463, intended) |
| `yarn-berry/hosted` | 344.9 | 0.1150 | 0.972 | 1.025 | OK |
| `yarn-berry/rescan` | 277.9 | 0.0926 | 1.070 | 0.930 | OK |
| `bun/hosted` | 197.3 | 0.0658 | 0.992 | 0.481 | OK |
| `bun/rescan` | 154.5 | 0.0515 | 1.032 | 0.380 | OK |
| `bun-isolated/hosted` | 243.5 | 0.0812 | 1.065 | 0.529 | OK |
| `bun-isolated/rescan` | 209.8 | 0.0699 | 0.991 | 0.471 | OK |
| `vlt/hosted` | 743.2 | 0.4954 | 1.072 | 0.520 | slow (2.02x, 743 ms; streak 2) |
| `vlt/rescan` | 587.3 | 0.3916 | 1.044 | 0.458 | slow (587 ms) |
| `pip/hosted` | 247.1 | 0.2471 | 1.028 | 1.177 | regressed (week +14.2%, ledger) |
| `pip/rescan` | 159.4 | 0.1594 | 1.006 | 1.098 | regressed (week +9.4%, ledger) |
| `uv/hosted` | 226.9 | 0.5673 | 0.981 | 1.040 | slow (#836) |
| `uv/rescan` | 193.2 | 0.4831 | 0.878 | 0.974 | OK |
| `pylock/hosted` | 227.4 | 0.5684 | 0.985 | 0.978 | slow (#836) |
| `pylock/rescan` | 171.3 | 0.4283 | 0.943 | 0.909 | OK |
| `poetry/hosted` | 152.0 | 0.3799 | 0.814 | 0.433 | OK |
| `poetry/rescan` | 138.0 | 0.3449 | 0.983 | 0.412 | OK |
| `pipenv/hosted` | 137.0 | 0.3424 | 0.983 | 1.051 | OK |
| `pipenv/rescan` | 137.4 | 0.3435 | 1.060 | 1.008 | OK |
| `pdm/hosted` | 153.8 | 0.3845 | 0.952 | 0.549 | OK |
| `pdm/rescan` | 138.8 | 0.3470 | 0.906 | 0.485 | OK |
| `hatch/hosted` | 88.7 | 0.0887 | 0.907 | 1.046 | OK |
| `hatch/rescan` | 79.3 | 0.0793 | 0.874 | 0.975 | OK |
| `bundler/hosted` | 278.2 | 0.3478 | 0.995 | 1.014 | OK |
| `bundler/rescan` | 231.2 | 0.2890 | 0.973 | 1.039 | OK |
| `composer/hosted` | 196.3 | 0.2453 | 1.017 | 1.075 | OK |
| `composer/rescan` | 150.3 | 0.1879 | 0.927 | 0.914 | OK |
| `cargo/hosted` | 350.9 | 0.5848 | 0.934 | 1.082 | slow (#761) |
| `cargo/rescan` | 334.2 | 0.5570 | 1.076 | 1.087 | slow (#761) |
| `golang/hosted` | 142.4 | 0.1186 | 1.029 | 1.339 | regressed (#1424, week) |
| `golang/rescan` | 144.3 | 0.1203 | 1.048 | 1.218 | regressed (#1424, week) |
| `nuget/hosted` | 120.5 | 0.1339 | 1.021 | 1.194 | regressed (#1425, week) |
| `nuget/rescan` | 115.6 | 0.1285 | 1.059 | 1.091 | regressed (#1425) |
| `maven/hosted` | 140.4 | 0.1404 | 0.983 | 0.972 | CPU regressed (#1472) |
| `maven/rescan` | 108.0 | 0.1080 | 1.058 | 0.960 | CPU regressed (#1472) |
| `gradle/hosted` | 254.3 | 0.2543 | 0.902 | 0.906 | OK |
| `gradle/rescan` | 254.1 | 0.2541 | 0.978 | 0.738 | OK |
| `npm/dry-run` | 286.3 | 0.0954 | 1.001 | 0.995 | OK |
| `npm/public-proxy` | 416.9 | 0.1390 | 0.979 | 0.975 | OK |
| `npm/latency` | 764.0 | 0.2547 | 1.014 | 1.012 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only. Today's runner is uniformly about 1.6x slower; poetry, pdm and hatch still dropped against that.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 | 10-13 | 10-14 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 | 217.5 | 345.9 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 | 164.1 | 233.6 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 | 197.6 | 335.9 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 | 223.6 | 344.9 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 | 176.0 | 197.3 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 | 167.0 | 243.5 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 | 437.8 | 743.2 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 | 107.0 | 247.1 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 | 162.0 | 226.9 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 | 149.1 | 227.4 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 | 112.6 | 152.0 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 | 101.6 | 137.0 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 | 113.1 | 153.8 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 | 64.4 | 88.7 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 | 178.7 | 278.2 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 | 126.3 | 196.3 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 | 266.5 | 350.9 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 | 86.4 | 142.4 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 | 88.9 | 120.5 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 | 83.2 | 140.4 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 | 151.2 | 254.3 |

## Open issues and PR
- **#1473** Slow scan: poetry. The fixes landed (#1475, #1486). Poetry is 1.55x the median today, no longer flagged. Data was added to the issue; it's left open for a human.
- #1472: Perf regression: maven CPU. Still +27% week.
- #1424: Perf regression: golang (#1403). Still +34% week. No fix PR.
- #1425: Perf regression: nuget (#1340/#1341). Still +19% week. No fix PR.
- #1246: Slow scan: pipenv (1.40x today, not flagged). #836: Slow scan: uv/pylock. #761: Slow scan: cargo.
- #1471 (hatch) **closed** by #1474. Week A/B is back to ≈.
- #580: Benchmark tracking.
- No open `bench/refresh` PR. The suite needed no change today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded).

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| cargo | 2.38x | 11 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| pylock | 2.32x | 11 | #836 | `PythonLockSession::rewrite`: the lock is re-serialized per patched dep (callgrind 10-05) |
| uv | 2.31x | 11 | #836 | Same as pylock |
| vlt | 2.02x; vlt/hosted 743 ms, vlt/rescan 587 ms (>500) | 2 | none (#579 accepted) | Not re-profiled today. An issue is due if it's flagged in the next run too |

Dropped off today: poetry (1.55x, after #1475/#1486), pdm (1.57x), bundler (1.42x), pipenv (1.40x). No scenario's peak RSS is above 2x the median (37.6 MiB).

## Coverage-gap backlog
New since 10-13 (from `15c2c839..313d5324`):
- **Renamed yarn copies** (#1489, #1517): `lp2@file:./x.tgz`, url tarballs and berry `portal:`/`link:` aliases, now read through one identity helper. No yarn fixture has a renamed copy.
- **Bun 1.3+ `bun.lockb` config-version tag** (#1496), **npm alias links from a workspace member** (#1500), **hosted pnpm pin beside a `file:` copy** (#1469), and **yarn 1 / npm workspace member globs** (#1480) and berry glob regex groups (#1493).
- **uv script no-sources in a parent config** (#1504), **Poetry source pin over a pre-2.1 lock** (#1506), and **gem lockfile DSL calls** (#1479, #1478).

Carried over: Cargo source replacement (#1420); `--system-site-packages` venvs (#1419); `.yarnrc.yml` `${VAR}` expansion (#1433); uv `no-sources` (#1434); pnpm ignored lock (#1431); Composer global home (#1421); moved `BUNDLE_GEMFILE` (#1430); Poetry `source = "pypi"` (#1413); hosted cargo `registry = "crates-io"` (#1412); Maven reactor / multi-module hosted (#1349, #261); NuGet member and named locks (#1340) and inherited sources (#1341); Go workspaces (#1393) and pre-1.17 graphs (#1403); uv workspace member dirs (#1335); Pipenv/uv vendored pylock co-wiring (#1399, #1390); OS trust store (#1326); non-UTF-8 requirements (#1152); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Yarn 4 pnpm linker (#496); pnpm global store (#829, #698); vlt brotli lock nodes (#820). deno has no hosted rewrite, so it needs no scenario.

**Suite runtime:** the full daily `compare` (15 pairs, 45 scenarios) took **21.2 min** on today's slower runner (07:14 → 07:35); it took 13.5 min on 10-13. That's over the ~12-minute budget either way. Shrink something (e.g. fold `bun/rescan` into `bun-isolated/rescan`, or shrink the npm family to 2000 packages) before adding scenarios.

## Stale / redundant scenarios
None removed. Merging hosted/rescan pairs needs 14+ days of history; there are 11 runs so far. Candidate: `bun/rescan` and `bun-isolated/rescan` moved together again (day +3.2% / -0.9%; week -62% / -53%).

---
_Generated by [Claude Code](https://claude.ai/code)_
