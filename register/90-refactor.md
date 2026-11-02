### Refactor routine
_Last updated 2026-11-02T01:20Z · main @ cbbbdb9_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| #1842 | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready |
| #1855 | sweep | `cli/src/commands/{bun_preflight,composer_hints,context,fetch_stage}.rs` | ready; Bugbot clean; CI lost Depot runners twice (0 steps), needs a fresh run |
| #1849 | structural | A01 #1832: `utils/cargo_build_cache.rs` | ready; CI and Bugbot green |
| #1864 | sweep | `cli/src/commands/{hosted_bundle,hosted_unwind,list,lock_cli,mod,pypi_reinstall}.rs` (+ dead branch in `rollback.rs`) | ready; CI and Bugbot green |
| #1870 | structural | A27 #1869: `api/client.rs`, one serve GET and one vendor retry loop | ready; CI and Bugbot green |
| #1875 | sweep | `cli/src/commands/{remove,repair}.rs` | ready; CI and Bugbot green |
| #1884 | sweep | `cli/src/commands/scan/discovery.rs` (+ T18 #1859; tests moved to core `ranking.rs`, `lock_inventory/tests.rs`, `ui/text.rs`) | ready; CI and Bugbot green |
| #1892 | sweep | `cli/src/commands/scan/gc.rs` | ready; CI and Bugbot green |
| #1897 | sweep | `cli/src/commands/scan/hosted.rs` (all but `run_redirect_selected_untracked`, T24; 13 guidance tests moved to core `hosted/guidance.rs`, 2 to `formats/pnpm/mod.rs`) | ready; CI and Bugbot green |
| #1903 | sweep | `cli/src/commands/scan/hosted/{nuget,takeover}.rs` | ready; CI and Bugbot green |
| #1907 | sweep | core `constants.rs`, `utils/{cargo_home,composer_version,concurrent,containment,digest,durability,env_compat,failpoint}.rs` (+ `socket_dir.rs`, `purl_key.rs` tests) | ready; CI and Bugbot green |
| #1914 | sweep | core `utils/{http,mod,hatch_workspace,hatch}.rs` (`line_endings.rs` clean) | ready; CI and Bugbot green |
| #1920 | sweep | core `utils/{notice,npm_range,package_manager,pep440,pipenv,purl}.rs` (+ `target.rs` callers) | ready; CI and Bugbot green |
| #1923 | sweep + A20 #1848 | core `utils/{redact,repo_root,serde,toml_edit_ext,uri,uv_workspace}.rs` (+ `vex/product.rs`, `redirect/upstream/npm.rs`, advisory lint moved to `vendor/service_fetch.rs`) | ready; CI and Bugbot green |
| #1929 | sweep | `cli/src/commands/{update,user_patches,vendor_orphans,vlt_heal}.rs` (+ `InstallChannel::id` in core `update/channel.rs`) | ready; CI and Bugbot green |
| #1936 | structural | A54 #1932: `formats/gem/{gemspec,manifest}.rs`, `vex/product.rs` (`for_each_code_line` → `code_lines`) | ready; CI and Bugbot green |
| #1939 | sweep | `cli/src/commands/vendored_backend/{mod,repair}.rs` | ready; CI and Bugbot green |
| #1944 | structural | T51 #1941: 11 `tests/apply` suites + `common/envelope.rs` onto `apply_fixture` (test-only, −635 net) | ready; Bugbot clean, 80/82 green; `hosted-e2e` red on a live patch.socket.dev 403 (minimist tgz), not this diff; re-run once |
| #1955 | structural | T52 #1942: 7 PTY runners → `common/pty_io::{run,run_command}` (test-only, +172/−567) | ready; CI and Bugbot green |
| #1948 | sweep | `cli/src/commands/{vex_consumed,vex_sources}.rs` (+ 2 tests moved to `ecosystem_dispatch.rs`) | ready; CI (ci-ok) and Bugbot green |
| #1961 | sweep | `cli/src/ui/{mod,prompt,status}.rs` (`test_support.rs` clean) | ready; CI and Bugbot green |
| #1964 | structural | T59 #1958: `tests/common/hermetic.rs` color scrub; seeds → parent-env canary (test-only, +69/−82) | ready; CI and Bugbot green |

#### Merged
_None._

#### Queue
Structural, scored `3·B + 2·U + 2·D + 2·C − risk`. Nothing merged since 2026-10-29, so most candidates ≥6 stay blocked: A30 #1887 (~8.7, #1886), T09 #1858 (~7, #1864/#1698), A41 #1899 (~6, #1891/#1829/#1906), A43 #1900 (~6, #1863/#1698), T01 #1835 / T25 #1877 (#1698), A53 #1931 / A57 #1935 (`ruby_crawler.rs`, #1882/#1895/#1943), A55 #1933 (`redirect/mod.rs`). Free test-only: T50 #1940 (~7; land the suites not held by #1698/#1843/#1893/#1894), T55 #1959 (~7, ~35 files; `tests/apply` is #1944), T56 #1956 (~7), T58 #1957 (~6).
A26 #1867, A46 #1917, A44 #1918 score ~4.

Next sweep files, in order: `update_notifier.rs`, `path_scope.rs`, `main.rs`+`interrupt.rs`, `json_envelope.rs`; `scan/policy.rs`, `scan/render.rs` after #1856/#1884; `python_lock.rs` (2,283), `python_script.rs` (1,768), `api/{blob_fetcher,date,retry,types}.rs`, crawler rows; `group_commit.rs` (2,163, region); `tests/apply/*` rows not covered by #1944 (their notes list fake tests). Held: `vlt_preflight.rs`, `agent_download.rs`, `apply.rs`, `get.rs`, `vendor.rs` (#1698); `rollback.rs` (#1864); `utils/fs.rs`, core `lib.rs` (#1891); `lock_fragments.rs`/`pdm_lock.rs` (#1898); `poetry_lock.rs` (#1865/#1898); `pnpm_workspace.rs` (#1863); `process.rs` (#1895); `go_env.rs` (#1876); `cargo_workspace.rs` (#1866). Leftovers from merged-pending sweeps: `ui/text.rs` sweep and the text-shaping move out of `ui/mod.rs` (#1884), `StatusLine::stderr(json, silent)` → one `report` bool (scan/mod.rs, lock_cli.rs) (#1961); `toml_edit_ext` deletion and `uv_workspace` fold (#1923); 7 `build_*_purl` wrappers + `parse_jsr_purl`, purl's PurlKey asserts → `purl_key.rs`, pipenv `installed_major`'s `_root` (#1920); String `read_capped` wrapper, `lock_fragments`/`pdm_lock` `pub mod` → `pub(crate)` (#1914); `CargoCrawler::cargo_home`, `vendor/jvm` digest copies, async `fs::is_symlink` (#1907); `api_auth_fallback_warning` → `json_envelope` and `PlanNote` → `RunWarning` (callers in `vendor.rs`/`apply.rs`/`vex.rs`, #1698), `store_variants` test → core `npm_crawler.rs` (#1829/#1891/#1906/#1915) (#1948).

#### Notes
- Check every "redundant filter" note against all consumers and derived `GlobalArgs` (the `args.rs` proxy filter, `select_one`'s `quiet()`).
- Clap field doc comments are `--help` output: sweeps leave them alone.
- `--cwd` defaults to `.`: absolutize before walking `ancestors()`; test via chdir under `#[serial]`.
- `vendor/cargo_config.rs` (~L165-L190) has a third `.cargo/config` pick: fold into `config_layer_paths` when swept.
- Check every caller file against open PRs, not only the swept file.
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` (disk). CI's clippy has no `--tests`.
- Grep a name before introducing it (E0592).
- Root-sandbox failures that pass in CI: 2 chmod tests in `tests/repair`, and core `copy_tree` symlinked-root, `vlt_heal` unremovable-lock, `pypi_poetry`/`pypi_requirements` wire-failure tests.; `in_process_redirect`'s 3 chmod tests
- Wants an issue: `ui::shell_word` does not escape `"` or `%VAR%` for Windows cmd; fix it there, not per caller.
- `scan/gc.rs`'s `has_ledger` gate probes `--cwd` but `run_vendor_gc` reads `project_root()` (C43): a foreign `--manifest-path` skips a due vendor-only revert. Wants an issue.
- The sandbox proxy refuses branch deletions: name branches right the first time (`arch-refactor/sweep-scan-gc-policy` is stale).
- `run_redirect_selected` still takes `Option<Envelope>` keyed on `common.json`; making it a value touches `get.rs` (#1698) and T24.
- Wants an issue: gem stale probe (`scan/hosted.rs` pass 3) dedups warnings by purl string and drops a platform gem's suffix (output-changing).
- Making a `pub` core item private can leave rustdoc links to it; unlink in the same commit.
- `hatch::require_pip_installer_documents` ignores the hatch.toml `envs` override (a shadowed pyproject `installer = "uv"` still refuses): output-changing, wants an issue.
- `npm_range_admits(">=", v)` (an operator with no version) reads as `*` and admits everything, where npm admits nothing: output-changing, wants an issue (found by /code-review on #1920).
- Commit *every* edit before a mutation test.
- Test runners that pin `--cwd` must not also set the child's cwd to the project, or a crawler reading the process cwd passes (found by /code-review on #1944).
- Wants an issue: npm `upstream_registry_fallback` (`redirect/upstream/npm.rs` ~L158) strips only userinfo, so a registry `?token=` reaches output and `--json` (fix: `redact_urls_in`, output-changing).
- Wants an issue: `vlt_heal::artifact_preflight` swallows a `load_state` error and `rollback_heal` drops a lock read error with `.ok()` (output-changing).
- Left from #1929: `UpdateArgs.pin_version` as `semver::Version` waits on `lib.rs` (#1842); `sweep_orphan_vendor_dirs` forwarder on `vendor.rs` (#1698).
- Wants an issue: `strip_url_userinfo`'s scp branch keeps credentials in `u:p@host:team@2024/r.git` (changes VEX `@id` bytes).
- Left from #1936: `vendor/gem.rs` `plan_gemfile_edit`, `vex/discover/gem.rs` (~L252) and `redirect/upstream/gem.rs` (~L661) still hand-scan `=begin`; route them through `manifest::code_lines` (the pin writer refuses a Gemfile whose duplicate `gem` line sits in `=begin`). `code_lines`'s heredoc heuristic reads `x <<FLAG` (a shift) as a heredoc and closes a plain `<<ID` at an indented terminator.
- Left from #1939: `remove.rs` L1327 doc still names the deleted `revert_vendor_entry` (#1875); `commands/repair.rs` ~L429 copies the build-once client (use `vendored_backend::repair::ensure_client`, #1875); `ApplyRequest.manifest` → `&HashMap` (drop `records_manifest`) and `stop_on_failure` wait on #1698/#1864/#1875; split `repair()`'s phases.
- /code-review pushes back on inlining a single-caller fn that is the only unit-test seam for a constant (`fetch_concurrency`'s ceiling) or that names a phase of a 350-line fn (`build_candidates`): keep those.
- Left from #1955 (pre-existing in every old PTY copy): the watchdog kills with SIGHUP (`ChildKiller::kill`), not SIGKILL; prompt waits are a fixed 10 s regardless of the run's timeout; dropping the writer sends `\n`+EOF, so an empty-input run still presses Enter.
- Left from #1964: `CI`/`GITHUB_ACTIONS` still reach test children (PM grandchildren may need them); a HOME pin in `hermetic::command` hits ~150 suites. Only a parent-env canary tests a scrub.
