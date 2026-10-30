### Refactor routine
_Last updated 2026-10-30T09:35Z · main @ 5ca5623_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| [#1842](https://github.com/SocketDev/socket-patch/pull/1842) | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready |
| [#1855](https://github.com/SocketDev/socket-patch/pull/1855) | sweep | `cli/src/commands/{bun_preflight,composer_hints,context,fetch_stage}.rs` | ready; Bugbot clean; CI lost Depot runners twice (0 steps), needs a fresh run |
| [#1849](https://github.com/SocketDev/socket-patch/pull/1849) | structural | A01 [#1832](https://github.com/SocketDev/socket-patch/issues/1832): `utils/cargo_build_cache.rs` | ready; CI and Bugbot green |
| [#1864](https://github.com/SocketDev/socket-patch/pull/1864) | sweep | `cli/src/commands/{hosted_bundle,hosted_unwind,list,lock_cli,mod,pypi_reinstall}.rs` (+ dead branch in `rollback.rs`) | ready; CI (82 checks) and Bugbot green |
| [#1870](https://github.com/SocketDev/socket-patch/pull/1870) | structural | A27 [#1869](https://github.com/SocketDev/socket-patch/issues/1869): `api/client.rs`, one serve GET and one vendor retry loop | ready; CI (82 checks) and Bugbot green |
| [#1875](https://github.com/SocketDev/socket-patch/pull/1875) | sweep | `cli/src/commands/{remove,repair}.rs` | ready; CI (82 checks) and Bugbot green |
| [#1884](https://github.com/SocketDev/socket-patch/pull/1884) | sweep | `cli/src/commands/scan/discovery.rs` (+ T18 [#1859](https://github.com/SocketDev/socket-patch/issues/1859); tests moved to core `ranking.rs`, `lock_inventory/tests.rs`, `ui/text.rs`) | ready; CI (82 checks) and Bugbot green |
| [#1892](https://github.com/SocketDev/socket-patch/pull/1892) | sweep | `cli/src/commands/scan/gc.rs` | ready; CI (82 checks) and Bugbot green |
| [#1897](https://github.com/SocketDev/socket-patch/pull/1897) | sweep | `cli/src/commands/scan/hosted.rs` (all but `run_redirect_selected_untracked`, T24; 13 guidance tests moved to core `hosted/guidance.rs`, 2 to `formats/pnpm/mod.rs`) | ready; CI (82 checks) and Bugbot green |

#### Merged
_None._

#### Queue
Structural candidates, scored `3·B + 2·U + 2·D + 2·C − risk`:
1. T09 [#1858](https://github.com/SocketDev/socket-patch/issues/1858), lock acquire open-coded 9×: D2.6 C2, risk M. **~7** (blocked while #1864 touches `lock_cli.rs` and #1698 touches `vendor.rs` / `get.rs` / `agent_download.rs`)
2. T01 [#1835](https://github.com/SocketDev/socket-patch/issues/1835), `get <uuid>` re-implements `download_and_apply_patches_into`: D2.2 C2, risk M. **~6.4** (blocked by #1698)
3. T25 [#1877](https://github.com/SocketDev/socket-patch/issues/1877), `--vex` embed hand-written ~8×: D2 C2, risk M. **~6** (blocked by #1698: `apply.rs`, `vendor.rs`)
4. T16 [#1861](https://github.com/SocketDev/socket-patch/issues/1861), remove/rollback `VendorRevertStep` loops: D1.75 C2, risk M. **~5.5** (blocked by #1864, #1875, #1698)
5. A30 [#1887](https://github.com/SocketDev/socket-patch/issues/1887), Maven `${…}` interpolation ×5: D3.35 C2, risk M. **~8.7** (blocked by #1886: `maven_scope.rs`, `maven_reactor.rs`). A05 [#1844](https://github.com/SocketDev/socket-patch/issues/1844) (~8, blocked by #1865: `poetry_lock.rs`) and A32 [#1888](https://github.com/SocketDev/socket-patch/issues/1888) (~6, blocked by #1882: all three crawlers) also wait. A20 [#1848](https://github.com/SocketDev/socket-patch/issues/1848) and A26 [#1867](https://github.com/SocketDev/socket-patch/issues/1867) score 4 (files free).

A03 [#1834](https://github.com/SocketDev/socket-patch/issues/1834) is the fixer's #1876. T28 [#1880](https://github.com/SocketDev/socket-patch/issues/1880) and T23 [#1860](https://github.com/SocketDev/socket-patch/issues/1860) wait on #1864 (`list.rs`) and #1698 (`get.rs`).

The next run is structural if a candidate scores 6 or more and its files are free, else a sweep. Next sweep files, in order: `scan/hosted/{nuget,takeover}.rs` (`python.rs` is in #1883), then `scan/policy.rs` and `scan/render.rs` once #1856/#1884 merge (policy's getters and `admit_crawled` are called from `scan/mod.rs`), then `core/constants.rs`, `core/utils/cargo_home.rs`. `core/lib.rs` is in #1891 and `core/utils/cargo_workspace.rs` in #1866. Skip `agent_download.rs`, `apply.rs`, `get.rs`, `vendor.rs` while #1698 is open, `rollback.rs` while #1864 is open, `cargo_build_cache.rs` (#1849) and `api/client.rs` (#1870).

#### Notes
- The PRs of the first thread (`arch-refactor/<issue>-*`) are listed in `review/2026-10-v1/register/90-refactor.md`.
- The `args.rs` note "drop api_client_overrides empty filter" was wrong: core `build_proxy_fallback_client` uses `overrides.proxy_url` unfiltered, so the CLI filter is load-bearing. Check every "redundant filter" note against all consumers of the value.
- Field doc comments on clap structs are `--help` output. Trimming them changes output bytes, so sweeps leave them alone.
- `--cwd` defaults to `.`, and `Path::new(".").ancestors()` stops at `.`. Any core walk up from the cwd must absolutize it first (`cargo_crawler::resolve_for` and `nuget_config` do; `cargo_build_cache` didn't until #1849). A test that spells the cwd as a relative path *with* components can't catch this: chdir under `#[serial]` and pass `"."`.
- `vendor/cargo_config.rs` (~L165-L190) keeps a third, async copy of the `.cargo/config` pick, with canonical dedup. It agrees on precedence; fold it into `config_layer_paths` when that file is swept.
- #1698 also touches `vendor.rs`, so the three `bun_vendor_preflight*` entry points (callers in `get.rs`, `agent_download.rs`, `vendor.rs`) and `StageOutcome::Unavailable`'s payload (caller `apply.rs`) wait until it merges. Check every caller file against open PRs, not only the swept file.
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`: a default debug build of the CLI tests exhausts the session disk allowance. CI's clippy is `--workspace --all-features` without `--tests`; the integration tests carry pre-existing lints.
- `ApiClient::with_vendor_retry` is the policy builder; a new private helper with that name collides (E0592). Grep a name before you introduce it.
- `tests/repair` has 2 chmod-based tests that fail under the root sandbox (`repair_cleanup_failure_is_reported_in_json_and_silent_modes`, `repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`); they pass in CI.
- remove's ~900-line `run` split (audit note) is too big for a sweep; it wants an issue alongside T16/T17/T20.
- A shared GET must keep every caller's bounds: folding an uncapped `resp.text()` error read into the capped `PatchApi` path is what /code-review caught on #1870.
- `ui::shell_word` has no escaping for an embedded `"` on Windows, and cmd still expands `%VAR%` inside its double quotes. Every pasteable command shares it, so fix it there (issue-worthy), not per caller.
- A test of a re-export or forwarding wrapper belongs beside the real function: move it to the defining crate and rebuild it on that module's helpers, instead of deleting coverage the target lacks (`ui::shell_word` had no test).
- `scan/gc.rs`'s pre-lock ledger gate (`has_ledger`) probes `--cwd`, while `run_vendor_gc` reads `project_root()` (C43): a foreign `--manifest-path` skips a due vendor-only revert. Pre-existing; it wants an issue. The preview path also drops `cargo_cache_patch_kept` warnings.
- Pushing a branch deletion (`git push origin :branch`) is refused by the sandbox proxy. Name the branch right the first time: `arch-refactor/sweep-scan-gc-policy` is left stale.
- `scan::hosted::run_redirect` runs only under `--json` (scan/mod.rs calls it inside `if args.common.json`); the human arm goes through `boxed_run_redirect_selected`. `run_redirect_selected` still takes `Option<Envelope>` keyed on `common.json`; making it a value touches `get.rs` (#1698) and the T24 body.
- The gem stale probe (`scan/hosted.rs` pass 3) has two pre-existing gaps /code-review found on #1897: it dedups vendor/cache warnings by purl string (two spellings of one installed dir can warn twice), and it names the standalone archive `{name}-{version}.gem`, missing a platform gem's suffix. Both change output, so they want an issue.
