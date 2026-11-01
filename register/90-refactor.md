### Refactor routine
_Last updated 2026-11-01T05:25Z · main @ cbbbdb9_

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
| [#1897](https://github.com/SocketDev/socket-patch/pull/1897) | sweep | `cli/src/commands/scan/hosted.rs` (all but `run_redirect_selected_untracked`, T24; 13 guidance tests moved to core `hosted/guidance.rs`, 2 to `formats/pnpm/mod.rs`) | ready; CI and Bugbot green; burn-down final review done |
| [#1903](https://github.com/SocketDev/socket-patch/pull/1903) | sweep | `cli/src/commands/scan/hosted/{nuget,takeover}.rs` | ready; CI (82 checks) and Bugbot green |
| [#1907](https://github.com/SocketDev/socket-patch/pull/1907) | sweep | core `constants.rs`, `utils/{cargo_home,composer_version,concurrent,containment,digest,durability,env_compat,failpoint}.rs` (+ `socket_dir.rs`, `purl_key.rs` tests) | ready; CI (82 checks) and Bugbot green |
| [#1914](https://github.com/SocketDev/socket-patch/pull/1914) | sweep | core `utils/{http,mod,hatch_workspace,hatch}.rs` (`line_endings.rs` clean) | ready; CI and Bugbot pending |

#### Merged
_None._

#### Queue
Structural candidates, scored `3·B + 2·U + 2·D + 2·C − risk`. Every one scoring 6 or more is blocked by an open PR as of 2026-11-01T05Z (nothing merged since 2026-10-29):
1. A30 [#1887](https://github.com/SocketDev/socket-patch/issues/1887), Maven `${…}` interpolation ×5: **~8.7** (blocked by #1886: `maven_scope.rs`, `maven_reactor.rs`).
2. T09 [#1858](https://github.com/SocketDev/socket-patch/issues/1858), lock acquire open-coded 9×: **~7** (blocked by #1864 `lock_cli.rs`, #1698 `vendor.rs`/`get.rs`/`agent_download.rs`).
3. A41 [#1899](https://github.com/SocketDev/socket-patch/issues/1899), npm store-child classification ×3: D2 C2, risk M, **~6** (blocked by #1891, #1829 and #1906: `npm_crawler.rs`).
4. A43 [#1900](https://github.com/SocketDev/socket-patch/issues/1900), package.json `workspaces` read 5×: **~6** (blocked by #1863 `governing_root.rs`, #1698 `vendor/mod.rs`).
5. T01 [#1835](https://github.com/SocketDev/socket-patch/issues/1835) (~6.4) and T25 [#1877](https://github.com/SocketDev/socket-patch/issues/1877) (~6): blocked by #1698.

A05 is the fixer's #1898, A32 its #1895. A42 [#1901](https://github.com/SocketDev/socket-patch/issues/1901) (~4) waits on `npm_crawler.rs`; A45 [#1902](https://github.com/SocketDev/socket-patch/issues/1902) is a P1 bug (~5) for the fixer. A20 [#1848](https://github.com/SocketDev/socket-patch/issues/1848) and A26 [#1867](https://github.com/SocketDev/socket-patch/issues/1867) score 4 (files free).

The next run is structural if a candidate scoring 6 or more has free files, else a sweep. Next sweep files, in order: `scan/policy.rs` and `scan/render.rs` once #1856/#1884 merge; core `utils/lock_fragments.rs` (wait on #1898), then `utils/notice.rs`, `npm_range.rs`, `package_manager.rs` onward if audited. Waiting on PRs: `utils/fs.rs` and core `lib.rs` (#1891), `go_env.rs`/`go_installed_tools.rs` (#1876), `cargo_workspace.rs` (#1866), `cargo_build_cache.rs` (#1849), `group_commit.rs` is free but 2,163 lines (sweep a region). `scan/hosted/python.rs` is in #1883. Skip `agent_download.rs`, `apply.rs`, `get.rs`, `vendor.rs` while #1698 is open, `rollback.rs` while #1864 is open. Left from #1914: delete the String `read_capped` wrapper (callers in `maven_repo.rs`, held by #1886/#1891; or rename `read_capped_typed`, touching `api/client.rs`, held by #1870/#1891); `lock_fragments`/`pdm_lock` `pub mod` → `pub(crate)` waits on #1898. Left from #1907: `CargoCrawler::cargo_home` forwarder (#1882), digest's `vendor/jvm` copies (#1886), async `fs::is_symlink` (#1891).

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
- `run_redirect_selected` still takes `Option<Envelope>` keyed on `common.json`; making it a value touches `get.rs` (#1698) and T24.
- The gem stale probe (`scan/hosted.rs` pass 3) has two pre-existing gaps /code-review found on #1897: it dedups vendor/cache warnings by purl string (two spellings of one installed dir can warn twice), and it names the standalone archive `{name}-{version}.gem`, missing a platform gem's suffix. Both change output, so they want an issue.
- A dead-branch proof needs the earlier branch's exact condition: in takeover's `stage`, the residual-reference conjunct of the keep-wiring branch was dead only because `residual_only_keep` returns `Some` whenever nothing drifted. Core's `kept_for_residual_reference` also requires `kept_artifact`, which a dry-run pypi revert doesn't set, so swapping it in would not have been behavior-neutral.
- Never restore a file with `git checkout <file>` after a mutation test while the sweep is uncommitted: it reverts the whole file to HEAD. Commit first, then mutate and `git checkout HEAD -- <file>`.
- Making a `pub` core item private can leave public docs linking it (`rustdoc::private_intra_doc_links`); CI doesn't run rustdoc, but /code-review checks. Unlink in the same commit.
- Folding an "is anything pending?" check ahead of a take splits one atomic step into two: keep take-then-act (durability `barrier`).
- `hatch::require_pip_installer_documents` ignores the hatch.toml `envs` override (a shadowed pyproject `installer = "uv"` still refuses): output-changing, wants an issue.
