[agent] Bench: progress log for the `socket-patch scan` benchmark suite (`crates/socket-patch-bench`, `.github/workflows/bench.yml`). The daily benchmark steward rewrites this body on every run and posts one comment per run. Machine-readable history is in `history.json` on the [`bench/ledger`](https://github.com/SocketDev/socket-patch/tree/bench/ledger) branch. The first run (2026-10-02) was logged in #580 and backfilled there.

## Last run
- **When:** 2026-10-17, about 06:45–07:30 UTC.
- **main:** `657fce2b`, unchanged since the 10-16 run (no commits to main since 2026-10-15 19:48 UTC).
- **Suite source:** `main`.
- **Runner:** 4 vCPU, Intel(R) Xeon(R) Processor @ 2.10GHz, cloud sandbox. Absolute times are about 0.7x yesterday's, so this runner is faster.
- **Validation:** **45/45 scenarios valid** on plain `main`.
- **A/A:** clean. npm/hosted -2.8%, pip/hosted -2.6%, golang/hosted +4.9%, all ≈.
- **Daily A/B:** skipped, because LAST_SHA equals today's main.
- **Weekly A/B** (`ade046a1` → `657fce2b`, 15 pairs + 10 confirmation pairs per flagged scenario):
  - **No new regressions.**
  - Known and confirmed: golang/hosted +24.5% [+16.5, +32.6] and golang/rescan +27.8% (#1424); nuget/hosted +18.1% and nuget/rescan +20.9% (#1425); maven/rescan CPU +15.2% with wall -13.5% (#1472); yarn-classic/rescan +60 requests, the intended tarball reads from #1463.
  - Not confirmed: yarn-berry/rescan flagged in round 1, ended +7.5% [+3.2, +13.1] after confirmation. The new week base `ade046a1` sits past part of the #1607 window, as it does for #1606 (bun-isolated/rescan now +0.3% ≈). Neither is a recovery; both issues stay open.
  - Faster vs week base: yarn-classic/hosted -56.8% (#1426), poetry/hosted -14.1%, hatch/hosted -12.8%, maven wall -13–15%.

## Scoreboard
Day: not run (main unchanged). Week: wall ratio vs `ade046a1`, paired A/B median. Median wall comes from today's 3a run (3 runs per scenario). The median ms/pkg across `*/hosted` is **0.1060**.

| scenario | median wall (ms) | ms/pkg | day | week | status |
|---|---:|---:|---:|---:|---|
| `npm/hosted` | 221.2 | 0.0737 | — | 1.061 | OK |
| `npm/rescan` | 188.0 | 0.0627 | — | 1.024 | OK |
| `pnpm/hosted` | 186.1 | 0.0620 | — | 1.128 | OK |
| `pnpm/rescan` | 152.4 | 0.0508 | — | 1.094 | OK |
| `yarn-classic/hosted` | 198.0 | 0.0660 | — | 0.432 | OK |
| `yarn-classic/rescan` | 155.5 | 0.0518 | — | 0.511 | +60 req vs week base (#1463, intended); wall -48.9% |
| `yarn-berry/hosted` | 223.1 | 0.0744 | — | 1.075 | OK |
| `yarn-berry/rescan` | 196.6 | 0.0655 | — | 1.075 | OK |
| `bun/hosted` | 132.2 | 0.0441 | — | 1.070 | OK |
| `bun/rescan` | 121.1 | 0.0404 | — | 1.022 | OK |
| `bun-isolated/hosted` | 163.4 | 0.0545 | — | 1.126 | OK |
| `bun-isolated/rescan` | 163.5 | 0.0545 | — | 1.003 | OK |
| `vlt/hosted` | 454.1 | 0.3027 | — | 1.013 | slow (2.86x; #1570) |
| `vlt/rescan` | 424.6 | 0.2831 | — | 0.986 | slow (#1570) |
| `pip/hosted` | 97.6 | 0.0976 | — | 1.068 | OK |
| `pip/rescan` | 82.4 | 0.0824 | — | 1.040 | OK |
| `uv/hosted` | 138.7 | 0.3467 | — | 0.988 | slow (3.27x; #836) |
| `uv/rescan` | 130.3 | 0.3258 | — | 0.985 | OK |
| `pylock/hosted` | 122.4 | 0.3061 | — | 0.965 | slow (2.89x; #836) |
| `pylock/rescan` | 105.9 | 0.2647 | — | 1.020 | OK |
| `poetry/hosted` | 106.5 | 0.2663 | — | 0.859 | slow (2.51x; #1473) |
| `poetry/rescan` | 87.1 | 0.2178 | — | 0.990 | OK |
| `pipenv/hosted` | 111.4 | 0.2784 | — | 0.980 | slow (2.63x; #1246) |
| `pipenv/rescan` | 115.0 | 0.2874 | — | 1.022 | OK |
| `pdm/hosted` | 115.0 | 0.2875 | — | 1.039 | slow (2.71x; #1624) |
| `pdm/rescan` | 104.0 | 0.2599 | — | 1.006 | OK |
| `hatch/hosted` | 66.2 | 0.0662 | — | 0.872 | OK |
| `hatch/rescan` | 58.0 | 0.0580 | — | 0.916 | OK |
| `bundler/hosted` | 182.9 | 0.2286 | — | 1.007 | slow (2.16x; 1st run) |
| `bundler/rescan` | 150.1 | 0.1876 | — | 0.975 | OK |
| `composer/hosted` | 120.2 | 0.1503 | — | 1.006 | OK |
| `composer/rescan` | 121.8 | 0.1522 | — | 1.029 | OK |
| `cargo/hosted` | 248.2 | 0.4137 | — | 0.993 | slow (3.90x; #761) |
| `cargo/rescan` | 218.9 | 0.3648 | — | 0.980 | slow (#761) |
| `golang/hosted` | 97.3 | 0.0811 | — | 1.245 | regressed (#1424, week) |
| `golang/rescan` | 87.5 | 0.0729 | — | 1.278 | regressed (#1424, week) |
| `nuget/hosted` | 95.4 | 0.1060 | — | 1.181 | regressed (#1425, week) |
| `nuget/rescan` | 93.6 | 0.1039 | — | 1.209 | regressed (#1425, week) |
| `maven/hosted` | 99.1 | 0.0991 | — | 0.850 | OK |
| `maven/rescan` | 73.1 | 0.0731 | — | 0.865 | CPU regressed (#1472, week CPU +15.2%, wall -13.5%) |
| `gradle/hosted` | 160.4 | 0.1604 | — | 0.993 | OK |
| `gradle/rescan` | 152.8 | 0.1528 | — | 0.959 | OK |
| `npm/dry-run` | 181.3 | 0.0604 | — | 1.011 | OK |
| `npm/public-proxy` | 250.7 | 0.0836 | — | 1.043 | OK |
| `npm/latency` | 692.6 | 0.2309 | — | 0.992 | OK |

## Trends
Median `<pm>/hosted` wall time per run, oldest → newest (ms). Runners differ between runs, so read these as trends only.

| pm | 10-02 | 10-03 | 10-04 | 10-05 | 10-06 | 10-07 | 10-08 | 10-09 | 10-12 | 10-13 | 10-14 | 10-15 | 10-16 | 10-17 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npm | 198.6 | 204.0 | 198.3 | 296.1 | 233.5 | 439.7 | 222.4 | 514.9 | 230.6 | 217.5 | 345.9 | 284.9 | 331.1 | 221.2 |
| pnpm | 153.6 | 180.5 | 162.1 | 234.8 | 197.4 | 216.5 | 188.2 | 313.0 | 158.2 | 164.1 | 233.6 | 185.4 | 294.7 | 186.1 |
| yarn-classic | 179.9 | 195.4 | 166.9 | 227.5 | 181.9 | 303.1 | 199.8 | 332.8 | 486.6 | 197.6 | 335.9 | 251.3 | 339.1 | 198.0 |
| yarn-berry | 219.5 | 228.8 | 208.6 | 293.5 | 242.0 | 412.8 | 231.0 | 312.1 | 215.5 | 223.6 | 344.9 | 287.5 | 350.4 | 223.1 |
| bun | 289.7 | 303.6 | 321.5 | 394.6 | 297.0 | 396.5 | 350.7 | 234.0 | 143.8 | 176.0 | 197.3 | 196.4 | 200.9 | 132.2 |
| bun-isolated | — | — | 336.6 | 392.4 | 342.4 | 465.8 | 359.2 | 218.9 | 168.1 | 167.0 | 243.5 | 192.3 | 249.3 | 163.4 |
| vlt | 843.8 | 894.2 | 764.0 | 1109.7 | 840.0 | 1246.6 | 840.7 | 635.9 | 477.4 | 437.8 | 743.2 | 514.9 | 647.1 | 454.1 |
| pip | 102.2 | 97.0 | 81.8 | 125.8 | 136.1 | 126.3 | 104.5 | 138.4 | 93.3 | 107.0 | 247.1 | 134.1 | 150.2 | 97.6 |
| uv | 136.0 | 143.9 | 127.1 | 244.0 | 156.6 | 220.3 | 165.0 | 339.3 | 169.8 | 162.0 | 226.9 | 166.1 | 272.1 | 138.7 |
| pylock | 113.6 | 142.1 | 126.2 | 179.8 | 122.1 | 194.8 | 127.8 | 213.2 | 145.0 | 149.1 | 227.4 | 176.0 | 233.8 | 122.4 |
| poetry | 187.6 | 221.4 | 201.6 | 342.9 | 261.7 | 369.5 | 111.3 | 197.3 | 129.9 | 112.6 | 152.0 | 127.2 | 171.8 | 106.5 |
| pipenv | 106.2 | 96.5 | 86.5 | 143.9 | 100.2 | 133.8 | 105.3 | 181.4 | 105.9 | 101.6 | 137.0 | 122.1 | 160.4 | 111.4 |
| pdm | 180.4 | 180.5 | 162.4 | 260.3 | 193.6 | 309.5 | 133.2 | 170.1 | 115.8 | 113.1 | 153.8 | 108.5 | 150.8 | 115.0 |
| hatch | — | — | — | — | — | 86.1 | 78.0 | 96.3 | 72.8 | 64.4 | 88.7 | 72.3 | 88.2 | 66.2 |
| bundler | 136.0 | 180.4 | 141.5 | 205.9 | 165.6 | 204.7 | 149.9 | 246.2 | 172.4 | 178.7 | 278.2 | 211.9 | 251.0 | 182.9 |
| composer | 122.2 | 123.0 | 115.4 | 180.8 | 122.9 | 175.7 | 136.0 | 218.7 | 169.0 | 126.3 | 196.3 | 186.2 | 187.9 | 120.2 |
| cargo | 228.4 | 262.5 | 258.5 | 364.1 | 255.1 | 332.4 | 254.0 | 340.5 | 287.9 | 266.5 | 350.9 | 328.8 | 362.8 | 248.2 |
| golang | 68.5 | 71.4 | 64.3 | 110.3 | 80.5 | 95.1 | 104.8 | 141.2 | 106.9 | 86.4 | 142.4 | 114.8 | 145.0 | 97.3 |
| nuget | 90.9 | 90.1 | 87.2 | 133.3 | 91.3 | 98.5 | 73.4 | 106.6 | 117.8 | 88.9 | 120.5 | 92.4 | 145.1 | 95.4 |
| maven | 79.3 | 81.6 | 62.0 | 87.4 | 73.5 | 98.8 | 67.8 | 124.7 | 88.0 | 83.2 | 140.4 | 107.4 | 115.2 | 99.1 |
| gradle | — | — | — | — | 170.5 | — | 197.6 | 215.0 | 187.0 | 151.2 | 254.3 | 186.1 | 274.4 | 160.4 |

## Open issues and PR
- **#1624 (new)** Slow scan: pdm hosted 2.7x median ms/pkg (3rd consecutive run). Hot spot: `toml_edit` parses `pdm.lock` 14x per scan, in `lock_fragments::rewrite_batch` (39% Ir) and VEX `pypi_locks::extract` (28%).
- #1606: Perf regression: bun-isolated/rescan wall +21%. #1607: Perf regression: yarn-berry/rescan wall +21%. No fix PRs.
- #1424: Perf regression: golang (#1403). Still +25–28% week. No fix PR.
- #1425: Perf regression: nuget (#1340/#1341). Still +18–21% week. No fix PR.
- #1472: Perf regression: maven CPU. maven/rescan CPU +15% week, wall down.
- #1570: Slow scan: vlt. #1473: Slow scan: poetry. #1246: Slow scan: pipenv. #836: Slow scan: uv/pylock. #761: Slow scan: cargo.
- #580: Benchmark tracking.
- No open `bench/refresh` PR. The suite needed no change today.

## Standing slow-systems list
A package manager is slow when its hosted ms/pkg is more than 2x the median across `*/hosted`, or when any of its scenarios takes over 500 ms (`npm/latency` is excluded).

| pm | x median today | consecutive runs | issue | hot spot |
|---|---|---:|---|---|
| cargo | 3.90x | 14 | #761 | `formats::cargo::CargoLock::parse` inside `rewrite_cargo`, 79% (callgrind 10-04) |
| uv | 3.27x | 14 | #836 | `PythonLockSession::rewrite`: the lock is re-serialized per patched dep (callgrind 10-05) |
| pylock | 2.89x | 14 | #836 | Same as uv |
| vlt | 2.86x (vlt/hosted 454 ms, under 500 today) | 5 | #1570 | `vlt::every_instance_pinned`/`partition_instances` → `split_dep_id`, 35% Ir; `vlt_preflight::preflight_scope` 32% (callgrind 10-15) |
| pdm | 2.71x | 3 | **#1624 (new)** | `toml_edit::Document::parse` 14x per scan, 44% Ir: `lock_fragments::rewrite_batch` 39%, VEX `pypi_locks::extract` 28% (callgrind 10-17) |
| pipenv | 2.63x | 3 | #1246 | per-patch Pipfile.lock re-tokenize (#1246) |
| poetry | 2.51x | 3 | #1473 | `lock_fragments::rewrite_batch` + VEX lock re-parse (#1473) |
| bundler | 2.16x | 1 | none | `patch::redirect::rewrite_gem` 61% Ir, of which `formats::gem::hosted::converge_gem_lock_source` 28% and `formats::gem::parse` 17% (callgrind 10-17). Was 1.95x on 10-16 |

No scenario's peak RSS is above 2x the median (37.5 MiB).

## Coverage-gap backlog
No new scan commits since 10-16 (main is still `657fce2b`). From 10-16 (`e76cb9b3..657fce2b`), none needs a scenario. Its scan commits are edge-case fixes for layouts the fixtures don't model: yarn `portal:`/`link:` copies (#1579, #1561), pnpm 11 non-boolean env values (#1557), a uv project under a parent with uv settings (#1545), vlt 1.4 `pnpm-workspace.yaml` members (#1564), and PyPI direct refs (#1549).

Carried over: Git LFS vendored tarballs (#1541); vlt extglob workspace globs (#1542); berry absolute `portal:`/`link:` (#1540); gem source blocks (#1531, #1509); pnpm `trustLockfile` env (#1514); untagged Bun 1.3.0/1.3.1 lock (#1521); renamed yarn copies (#1489, #1517); Bun 1.3+ `bun.lockb` tag (#1496); npm alias links from a workspace member (#1500); hosted pnpm pin beside a `file:` copy (#1469); workspace member globs (#1480, #1493); uv script no-sources (#1504); Poetry source pin over a pre-2.1 lock (#1506); gem lockfile DSL calls (#1479, #1478); Cargo source replacement (#1420); `--system-site-packages` venvs (#1419); `.yarnrc.yml` `${VAR}` (#1433); uv `no-sources` (#1434); pnpm ignored lock (#1431); Composer global home (#1421); moved `BUNDLE_GEMFILE` (#1430); Poetry `source = "pypi"` (#1413); hosted cargo `registry = "crates-io"` (#1412); Maven reactor / multi-module (#1349, #261); NuGet member and named locks (#1340) and inherited sources (#1341); Go workspaces (#1393) and pre-1.17 graphs (#1403); uv workspace member dirs (#1335); Pipenv/uv vendored pylock co-wiring (#1399, #1390); OS trust store (#1326); non-UTF-8 requirements (#1152); yarn classic offline mirror (#1083); multi-lockfile governance (#1044); Yarn 4 pnpm linker (#496); pnpm global store (#829, #698); vlt brotli lock nodes (#820). Every `pm:*` label has a scenario except deno, which has no hosted rewrite.

**Suite runtime:** the weekly `compare` (15 pairs, 45 scenarios, 6 confirmation rounds) took **14.7 min** today on a faster runner (10-16: 20.4 min). Still over the ~12-minute budget. Shrink something before adding scenarios.

## Stale / redundant scenarios
None removed. History now spans 14 runs over 15 days. No pair is a merge candidate: `bun/rescan` vs `bun-isolated/rescan` diverged on 10-16 (#1606), and the `*/hosted` vs `*/rescan` pairs carry distinct regressions (golang, nuget, maven, yarn-classic).

---
_Generated by [Claude Code](https://claude.ai/code)_
