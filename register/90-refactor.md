### Refactor routine
_Last updated 2026-11-02T09:20Z · main @ cbbbdb9_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| #1842 | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready |
| #1855 | sweep | `commands/{bun_preflight,composer_hints,context,fetch_stage}.rs` | ready; CI needs a re-run (Depot) |
| #1849 | structural | A01 #1832: `utils/cargo_build_cache.rs` | ready; green |
| #1864 | sweep | `commands/{hosted_bundle,hosted_unwind,list,lock_cli,mod,pypi_reinstall}.rs` (+ `rollback.rs` dead branch) | ready; green |
| #1870 | structural | A27 #1869: `api/client.rs`, one serve GET and one vendor retry loop | ready; green |
| #1875 | sweep | `commands/{remove,repair}.rs` | ready; green |
| #1884 | sweep | `scan/discovery.rs` (+ T18 #1859; tests to core `ranking.rs`, `lock_inventory/tests.rs`, `ui/text.rs`) | ready; green |
| #1892 | sweep | `scan/gc.rs` | ready; green |
| #1897 | sweep | `scan/hosted.rs` (all but `run_redirect_selected_untracked`, T24; tests to core `hosted/guidance.rs`, `formats/pnpm/mod.rs`) | ready; green |
| #1903 | sweep | `scan/hosted/{nuget,takeover}.rs` | ready; green |
| #1907 | sweep | core `constants.rs`, `utils/{cargo_home,composer_version,concurrent,containment,digest,durability,env_compat,failpoint}.rs` (+ `socket_dir.rs`, `purl_key.rs` tests) | ready; green |
| #1914 | sweep | core `utils/{http,mod,hatch_workspace,hatch}.rs` (`line_endings.rs` clean) | ready; green |
| #1920 | sweep | core `utils/{notice,npm_range,package_manager,pep440,pipenv,purl}.rs` (+ `target.rs` callers) | ready; green |
| #1923 | sweep + A20 #1848 | core `utils/{redact,repo_root,serde,toml_edit_ext,uri,uv_workspace}.rs` (+ `vex/product.rs`, `redirect/upstream/npm.rs`, advisory lint moved to `vendor/service_fetch.rs`) | ready; green |
| #1929 | sweep | `commands/{update,user_patches,vendor_orphans,vlt_heal}.rs` (+ `InstallChannel::id` in core `update/channel.rs`) | ready; green |
| #1936 | structural | A54 #1932: `formats/gem/{gemspec,manifest}.rs`, `vex/product.rs` (`for_each_code_line` → `code_lines`) | ready; green |
| #1939 | sweep | `commands/vendored_backend/{mod,repair}.rs` | ready; green |
| #1944 | structural | T51 #1941: 11 `tests/apply` suites + `common/envelope.rs` onto `apply_fixture` (test-only, −635 net) | ready; `hosted-e2e` red on a live 403, not this diff |
| #1955 | structural | T52 #1942: 7 PTY runners → `common/pty_io::{run,run_command}` (test-only, +172/−567) | ready; green |
| #1948 | sweep | `commands/{vex_consumed,vex_sources}.rs` (+ 2 tests moved to `ecosystem_dispatch.rs`) | ready; green |
| #1961 | sweep | `cli/src/ui/{mod,prompt,status}.rs` (`test_support.rs` clean) | ready; green |
| #1964 | structural | T59 #1958: `tests/common/hermetic.rs` color scrub; seeds → parent-env canary (test-only, +69/−82) | ready; green |
| #1967 | sweep | `cli/src/{json_envelope,update_notifier,main,interrupt,path_scope}.rs` (path_scope tests only, #1864) | ready; green |
| #1972 | structural | T60 #1968 slice 1: `tests/docker_common` + 15 `docker_e2e_*` suites (test-only, +260/−1,113) | ready; green |
| #1975 | sweep | core `api/{blob_fetcher,date,retry,types}.rs` | ready; green |
| #1978 | structural | T56 #1956: 9 `cli_parse_*`/`cli_global_args` suites onto `hermetic::try_parse` + new `common/clap_parse.rs` (test-only, +418/−1,471) | ready; green |

#### Merged
_None._

#### Queue
Structural, scored `3·B + 2·U + 2·D + 2·C − risk`. Nothing merged since 2026-10-29, so most candidates ≥6 stay blocked: A30 #1887 (~8.7, #1886), T09 #1858 (~7, #1864/#1698), A41 #1899 (~6, #1891/#1829/#1906), A43 #1900 (~6, #1863/#1698), T01 #1835 / T25 #1877 (#1698), A53 #1931 / A57 #1935 (`ruby_crawler.rs`, #1882/#1895/#1943), A55 #1933 (`redirect/mod.rs`). Free test-only: T60 #1968 rest (~7, after #1972: CI REQUIRED export, `assert_api_exercised`, `GIT_SHA256_FN` ×3, bash summary greps), T61 #1969 (~6; `e2e_bun_lockb.rs` held by #1905), T50 #1940 (~7; land the suites not held by #1698/#1843/#1893/#1894), T55 #1959 (~7, ~35 files; `tests/apply` is #1944), T58 #1957 (~6).
A26 #1867, A46 #1917, A44 #1918 score ~4.

Next sweep files, in order: `scan/{rollout,rollout_args,socket_yml_args,withdrawn}.rs` (free); `scan/policy.rs`, `scan/render.rs` after #1856/#1884; `python_lock.rs` (2,283), `python_script.rs` (1,768), `api/vendor_prefetch.rs`, crawler rows; `group_commit.rs` (2,163, region); `tests/apply/*` rows not covered by #1944 (their notes list fake tests). Held: `vlt_preflight.rs`, `agent_download.rs`, `apply.rs`, `get.rs`, `vendor.rs` (#1698); `rollback.rs` (#1864); `utils/fs.rs`, core `lib.rs` (#1891); `lock_fragments.rs`/`pdm_lock.rs` (#1898); `poetry_lock.rs` (#1865/#1898); `pnpm_workspace.rs` (#1863); `process.rs` (#1895); `go_env.rs` (#1876); `cargo_workspace.rs` (#1866). Leftovers from merged-pending sweeps: `ui/text.rs` sweep and the text-shaping move out of `ui/mod.rs` (#1884), `StatusLine::stderr(json, silent)` → one `report` bool (scan/mod.rs, lock_cli.rs) (#1961); `toml_edit_ext` deletion and `uv_workspace` fold (#1923); 7 `build_*_purl` wrappers + `parse_jsr_purl`, purl's PurlKey asserts → `purl_key.rs`, pipenv `installed_major`'s `_root` (#1920); String `read_capped` wrapper, `lock_fragments`/`pdm_lock` `pub mod` → `pub(crate)` (#1914); `CargoCrawler::cargo_home`, `vendor/jvm` digest copies, async `fs::is_symlink` (#1907); `api_auth_fallback_warning` → `json_envelope` and `PlanNote` → `RunWarning` (callers in `vendor.rs`/`apply.rs`/`vex.rs`, #1698), `store_variants` test → core `npm_crawler.rs` (#1829/#1891/#1906/#1915) (#1948); `PathScope::matches` (1 caller, rollback L1814, in a loop) → `bind` once, plus `BoundScope::matching_pattern_indices` for rollback's `raw()` re-parse with `expect` (#1864); `AppliedVia` one-variant mirror + `from_core` (apply.rs, #1698) (#1967).

#### Notes
- Want issues (output-changing, found in sweeps): `ui::shell_word` misses `"`/`%VAR%` on cmd; `scan/gc.rs` `has_ledger` probes `--cwd` but `run_vendor_gc` reads `project_root()` (C43); gem stale probe dedups by purl and drops the platform suffix; `hatch::require_pip_installer_documents` ignores the `envs` override; `npm_range_admits(">=", v)` admits all; npm `upstream_registry_fallback` leaks `?token=` (use `redact_urls_in`); `vlt_heal` swallows `load_state`/lock read errors; `strip_url_userinfo`'s scp branch keeps `u:p@`.
- Check every "redundant filter" note against all consumers and derived `GlobalArgs` (the `args.rs` proxy filter, `select_one`'s `quiet()`).
- Clap field doc comments are `--help` output: leave them.
- `--cwd` defaults to `.`: absolutize before walking `ancestors()`; test via chdir under `#[serial]`.
- `vendor/cargo_config.rs` (~L165-L190) has a third `.cargo/config` pick: fold into `config_layer_paths` when swept.
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` (disk). CI's clippy has no `--tests`.
- Root-sandbox failures that pass in CI: 2 chmod tests in `tests/repair`, and core `copy_tree` symlinked-root, `vlt_heal` unremovable-lock, `pypi_poetry`/`pypi_requirements` wire-failure tests.; `in_process_redirect`'s 3 chmod tests
- The proxy refuses branch deletions: name branches right first time (`sweep-scan-gc-policy` is stale).
- `run_redirect_selected` still takes `Option<Envelope>` keyed on `common.json`; making it a value touches `get.rs` (#1698) and T24.
- Making a `pub` core item private can leave rustdoc links to it; unlink in the same commit.
- Test runners that pin `--cwd` must not also set the child's cwd to the project, or a crawler reading the process cwd passes (found by /code-review on #1944).
- Left from #1929: `UpdateArgs.pin_version` as `semver::Version` waits on `lib.rs` (#1842); `sweep_orphan_vendor_dirs` forwarder on `vendor.rs` (#1698).
- Left from #1936: `vendor/gem.rs` `plan_gemfile_edit`, `vex/discover/gem.rs` (~L252) and `redirect/upstream/gem.rs` (~L661) still hand-scan `=begin`; route them through `manifest::code_lines` (the pin writer refuses a Gemfile whose duplicate `gem` line sits in `=begin`). `code_lines`'s heredoc heuristic reads `x <<FLAG` (a shift) as a heredoc and closes a plain `<<ID` at an indented terminator.
- Left from #1939: `remove.rs` L1327 doc still names the deleted `revert_vendor_entry` (#1875); `commands/repair.rs` ~L429 copies the build-once client (use `vendored_backend::repair::ensure_client`, #1875); `ApplyRequest.manifest` → `&HashMap` (drop `records_manifest`) and `stop_on_failure` wait on #1698/#1864/#1875; split `repair()`'s phases.
- Keep a single-caller fn that is a constant's only test seam or names a phase of a long fn (`fetch_concurrency`, `build_candidates`).
- Left from #1955: PTY watchdog SIGHUPs; fixed 10 s prompt waits.
- Left from #1967: core `UpdateTimeouts::from_env` and the notifier both parse `SOCKET_UPDATE_TIMEOUT_MS`; core caps `connect` at 10 s, the notifier doesn't (A09/C19).
- Left from #1964: `CI`/`GITHUB_ACTIONS` still reach test children; a HOME pin in `hermetic::command` hits ~150 suites. Test a scrub with a parent-env canary.
- Left from #1975: `blob_fetcher` `on_progress`/`OnProgress` (callers in `fetch_stage.rs` #1855, `repair.rs` #1875, `rollback.rs` #1864) and `BlobFetchResult.success` (literals in #1855's tests); `concise_fetch_error` re-parses the client's text; `store_verified_blob` vs `stream_cache_entry_atomic` drift. `scan --json` serializes `BatchPackagePatches`: keep a serialize test.
- Left from #1978: T57 can use `clap_parse::global_defaults()`; `derive(PartialEq)` on `GlobalArgs` (after #1842) retires `Globals`. The scrub is `Once`: set vars via `try_parse_with_env`; binaries calling `run()` in-process keep `FORCED_OPT_OUTS`.
- Left from #1972: `run_container` takes no extra args (sbt `run_cell`, `docker_vendor_common::docker_command`, npm vlt smoke still build `docker run`); `host.docker.internal` URL ×15. Docker can't run here: build the 15 binaries with `--features docker-e2e`, run host-side tests.
