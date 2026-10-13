[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-13, about 06:50–08:15 UTC.
- **main:** `15c2c839`, 31 commits since `17793173`. They include #1426 (the yarn classic lock-rescan fix for #1423), #1420 (Cargo source replacement), #1419 (`--system-site-packages` venvs), #1433 (YAML `.yarnrc.yml` reads), #1434 (uv `no-sources`), #1431 (pnpm ignored lock), #1440 (bare scan mode on vendored + hosted projects) and #1442 (bun.lockb workspace mirrors).
- **Suite source:** `main`. #1422 merged as `cc841a18`.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox.
- **Validation:** **45/45 scenarios valid** on plain `main`. Request counts are unchanged since 10-12.
- **A/A:** clean. npm/hosted +0.0%, pip/rescan +9.3% [-6.7, +13.2], golang/rescan +4.4%, all ≈.
- **Daily A/B** (`17793173` → `15c2c839`, 15 pairs): **no regressions**. yarn-classic/hosted is **-55.1%** and yarn-classic/rescan is **-56.9%** (#1426), back to the pre-#1328 level. Everything else is ≈.
- **Weekly A/B** (`9c43dfc9` → `15c2c839`, 8+8 pairs), with hatch and maven confirmed in a second round of 20+10 pairs:
  - **hatch/hosted +21.2%** [+14.2, +26.0] (+11.5 ms) and hatch/rescan +12.6%. That's the 3rd consecutive run at 10% or more. Filed as **#1471**.
  - **maven/hosted CPU +22.7%** (+17.8 ms) and maven/rescan CPU +20.6%, with wall -2% / -10%. That's the 2nd consecutive run. Filed as **#1472**.
  - golang/hosted +36.1% and golang/rescan +17.9% (#1424); nuget/hosted +23.9% (#1425). Both are unfixed. Data was added to both issues.
  - npm-family hosted **peak RSS +14–23%** (npm/hosted +19.9%, yarn-classic/hosted +22.7%, npm/latency +20.0%). This is still under the 30% gate.
  - Faster: bun -54% / -66%, bun-isolated -49% / -57%, vlt -54% / -49%, poetry -44% / -53%, pdm -42% / -44%, gradle/rescan -24%, npm/rescan -23%.
- **Bisect:** one extra build at `f3c6313a` splits both hatch and maven roughly in half: hatch +11.0% and maven CPU +11.5% by `f3c6313a`. This is drift; no single commit was named.

## Scoreboard
Day: wall ratio vs `17793173`. Week: wall ratio vs `9c43dfc9`. From today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is **0.107** (10-12: 0.162, inflated by #1423).

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 217.5 | 0.0725 | 1.032 | 0.969 | OK |
| `npm/rescan` | 172.2 | 0.0574 | 0.967 | 0.769 | OK |
| `pnpm/hosted` | 164.1 | 0.0547 | 1.042 | 1.002 | OK |
| `pnpm/rescan` | 128.3 | 0.0428 | 0.973 | 0.872 | OK |
| `yarn-classic/hosted` | 197.6 | 0.0659 | 0.449 | 1.109 | OK (recovered, #1426) |
| `yarn-classic/rescan` | 165.3 | 0.0551 | 0.431 | 0.797 | OK (recovered, #1426) |
| `yarn-berry/hosted` | 223.6 | 0.0745 | 1.015 | 0.958 | OK |
| `yarn-berry/rescan` | 200.7 | 0.0669 | 0.952 | 0.931 | OK |
| `bun/hosted` | 176.0 | 0.0587 | 1.003 | 0.458 | OK |
| `bun/rescan` | 106.6 | 0.0355 | 1.029 | 0.336 | OK |
| `bun-isolated/hosted` | 167.0 | 0.0557 | 1.001 | 0.511 | OK |
| `bun-isolated/rescan` | 139.5 | 0.0465 | 0.993 | 0.427 | OK |
| `vlt/hosted` | 437.8 | 0.2918 | 0.970 | 0.463 | slow (streak 1, #579 accepted) |
| `vlt/rescan` | 388.2 | 0.2588 | 1.034 | 0.508 | OK |
| `pip/hosted` | 107.0 | 0.1070 | 1.021 | 1.064 | OK |
| `pip/rescan` | 87.2 | 0.0872 | 1.005 | 0.982 | OK |
| `uv/hosted` | 162.0 | 0.4050 | 0.918 | 1.077 | slow (#836) |
| `uv/rescan` | 112.2 | 0.2806 | 1.056 | 0.949 | OK |
| `pylock/hosted` | 149.1 | 0.3728 | 1.041 | 1.094 | slow (#836) |
| `pylock/rescan` | 100.3 | 0.2507 | 0.924 | 0.927 | OK |
| `poetry/hosted` | 112.6 | 0.2815 | 1.085 | 0.564 | slow (#1473) |
| `poetry/rescan` | 87.2 | 0.2181 | 1.030 | 0.468 | OK |
| `pipenv/hosted` | 101.6 | 0.2539 | 1.053 | 1.040 | slow (#1246, streak 1) |
| `pipenv/rescan` | 94.0 | 0.2350 | 0.968 | 1.012 | OK |
| `pdm/hosted` | 113.1 | 0.2828 | 0.988 | 0.581 | slow (streak 1) |
| `pdm/rescan` | 94.0 | 0.2351 | 1.011 | 0.559 | OK |
| `hatch/hosted` | 64.4 | 0.0644 | 1.047 | 1.139 | regressed (#1471) |
| `hatch/rescan` | 59.9 | 0.0599 | 0.949 | 1.186 | regressed (#1471) |
| `bundler/hosted` | 178.7 | 0.2234 | 1.005 | 1.020 | slow (2.09x, streak 1) |
| `bundler/rescan` | 137.4 | 0.1718 | 1.021 | 1.041 | OK |
| `composer/hosted` | 126.3 | 0.1579 | 0.981 | 1.056 | OK |
| `composer/rescan` | 81.0 | 0.1012 | 0.960 | 0.947 | OK |
| `cargo/hosted` | 266.5 | 0.4442 | 0.992 | 1.031 | slow (#761) |
| `cargo/rescan` | 248.6 | 0.4143 | 1.079 | 1.027 | OK |
| `golang/hosted` | 86.4 | 0.0720 | 0.987 | 1.361 | regressed (#1424, week) |
| `golang/rescan` | 109.1 | 0.0909 | 0.921 | 1.179 | regressed (#1424, week) |
| `nuget/hosted` | 88.9 | 0.0988 | 1.015 | 1.239 | regressed (#1425, week) |
| `nuget/rescan` | 78.0 | 0.0867 | 1.014 | 1.127 | regressed (#1425) |
| `maven/hosted` | 83.2 | 0.0832 | 0.997 | 0.962 | CPU regressed (#1472), wall flat |
| `maven/rescan` | 74.9 | 0.0749 | 0.951 | 0.907 | CPU regressed (#1472), wall faster |
| `gradle/hosted` | 151.2 | 0.1512 | 0.985 | 0.873 | OK |
| `gradle/rescan` | 136.9 | 0.1369 | 1.068 | 0.756 | OK |
| `npm/dry-run` | 174.9 | 0.0583 | 1.053 | 0.972 | OK |
| `npm/public-proxy` | 198.9 | 0.0663 | 1.021 | 0.936 | OK |
| `npm/latency` | 698.3 | 0.2328 | 0.999 | 0.978 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only. The yarn-classic spike on 10-12 was #1423, fixed by #1426.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 | 10-13 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 | 217.5 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 | 164.1 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 | 197.6 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 | 223.6 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 | 176.0 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 | 167.0 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 | 437.8 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 | 107.0 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 | 162.0 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 | 149.1 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 | 112.6 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 | 101.6 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 | 113.1 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 | 64.4 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 | 178.7 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 | 126.3 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 | 266.5 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 | 86.4 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 | 88.9 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 | 83.2 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 | 151.2 |

## Open issues and PR
- **#1471** (new): Perf regression: hatch/hosted wall +21%. Hot spot: `utils::hatch::plan` (40% Ir) and `PurlKey::new` canonicalization (13%).
- **#1472** (new): Perf regression: maven/hosted CPU +23%. Hot spot: `crawlers::maven_scope::project_scope` (36% Ir), which re-parses the pom model through `maven_reactor` per crawled artifact.
- **#1473** (new): Slow scan: poetry. Hot spot: `lock_fragments::rewrite_batch` (41%) plus the VEX `pypi_locks::extract` re-parse (29%).
- #1424: Perf regression: golang (#1403). Open, no fix PR.
- #1425: Perf regression: nuget (#1340/#1341). Open, no fix PR.
- #1246: Slow scan: pipenv. #836: Slow scan: uv/pylock. #761: Slow scan: cargo.
- #1423 (yarn-classic): **closed** by #1426. Today's day A/B confirms the -55% recovery.
- #580: Benchmark tracking.
- No open `bench/refresh` PR. #1422 merged, and the suite needed no change today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded). Today's median (0.107) is lower than 10-12's (0.162, inflated by #1423), so more borderline package managers cross 2x.

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| cargo | 4.15x | 10 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| uv | 3.79x | 10 | #836 | `PythonLockSession::rewrite` 39%: the lock is re-serialized per patched dep (callgrind 10-05) |
| pylock | 3.48x | 10 | #836 | Same as uv |
| vlt | 2.73x | 1 | none (#579 accepted) | vlt/hosted 438 ms, under 500 |
| pdm | 2.64x | 1 | none (#762 closed) | `lock_fragments::rewrite_batch` 45% (callgrind 10-08) |
| poetry | 2.63x | 4 since #877 | **#1473** | `rewrite_batch` 41% + VEX `pypi_locks::extract` 29% (callgrind 10-13) |
| pipenv | 2.37x | 1 | #1246 | `redirect::pipenv::entries` 61% (callgrind 10-09) |
| bundler | 2.09x | 1 | none | New today, borderline. Not profiled |

No scenario's peak RSS is above 2x the median (37.9 MiB). No scenario is over 500 ms other than npm/latency.

## Coverage-gap backlog
New since 10-12 (from `17793173..15c2c839`):
- **Cargo source replacement and custom vendor dirs** (#1420): the cargo fixture has no `[source]` replacement.
- **`--system-site-packages` venvs** (#1419): the Python fixtures set `include-system-site-packages = false`. Covering it hermetically needs a fake base interpreter tree under the fixture.
- **`.yarnrc.yml` `${VAR}` expansion** (#1433): the yarn-berry fixture's `.yarnrc.yml` now goes through the YAML reader, but uses no variables.
- **uv `no-sources = true`** (#1434), **pnpm ignored lock** (#1431), **Composer global home** (#1421), **moved `BUNDLE_GEMFILE`** (#1430), **Poetry `source = "pypi"`** (#1413), and **hosted cargo `registry = "crates-io"`** (#1412).

Carried over: Maven reactor / multi-module hosted (#1349, #261); NuGet member and named locks (#1340) and inherited sources (#1341); Go workspaces (#1393) and pre-1.17 graphs (#1403); uv workspace member dirs (#1335); Pipenv/uv vendored pylock co-wiring (#1399, #1390); Yarn berry pin beside a later registry entry (#1397); OS trust store (#1326); non-UTF-8 requirements (#1152); gem section re-sort (#1190); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Yarn 4 pnpm linker (#496); bun.lockb (#472, #1442); pnpm global store (#829, #698); vlt brotli lock nodes (#820); Python env discovery variants; Gemfile multi-layer `.bundle/config`. deno has no hosted rewrite, so it needs no scenario.

**Suite runtime:** the full daily `compare` (15 pairs, 45 scenarios) took **13.5 min** today (07:12 → 07:25), with no confirmation rounds needed. That's still just over the ~12-minute budget. Shrink something before adding scenarios.

## Stale / redundant scenarios
None removed. Merging hosted/rescan pairs needs 14+ days of history; there are 10 runs so far. Candidate: `bun/rescan` and `bun-isolated/rescan` moved together again (day +2.9% / -0.7%; week -66% / -57%).

---
_Generated by [Claude Code](https://claude.ai/code)_
