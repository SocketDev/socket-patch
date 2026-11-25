### Refactor routine
_Last updated 2026-11-25T15:40Z · main @ e685fb1_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| #2241 | structural | T55 #1959 slice 1: `tests/` copies of `has_command` ×6, `git_sha256_file` ×4, `sha256_hex` ×9, `stderr_chatter` ×4, dead `common` helpers (test-only) | ready; CI running |

#### Merged
All 29 PRs merged on 2026-11-02. Net lines (`src/` incl. inline tests / `tests/`):
#1842 −326 · #1855 −113 · #1849 +62 · #1864 −140 · #1870 −21 · #1875 −218 · #1884 −156 · #1892 −269 · #1897 −151 · #1903 −29 · #1907 −128 · #1914 +26 · #1920 −297 · #1923 −105 · #1929 −36 · #1936 +24 · #1939 −54 · #1948 −38 · #1961 −155 · #1967 −250 · #1975 −494 · #1985 +3 · #1990 −305 (src −3,170); test-only #1944 −635 · #1955 −395 · #1964 −13 · #1972 −853 · #1978 −1,053 · #1988 −371 (tests −3,320).

#### Queue
Structural, scored `3·B + 2·U + 2·D + 2·C − risk`, re-checked 2026-11-25 @ e685fb1:
- A30 #1887: mostly done on `main` (`formats/maven/properties.rs` `interpolate_strict` serves scope, selection and reactor); left: `maven_crawler::{interpolate, interpolate_defined}` (one-level, Maven settings/`maven.config` semantics, not a dup) and the model-field lookup closure copied in `maven_scope`/`maven_selection` (~4).
- T09 #1858 (~7): held by #2237 (`apply.rs`, `rollback.rs`, `agent_download.rs`).
- T55 #1959 rest (~6): shared-module `sha256_hex` copies (`vex_pypi_real_common`, `vex_pipenv_pip_real`, `hosted_maven_common`, `jvm_fixture_repo`, `e2e_artifactory_mirror`) via `common/oracle.rs`; `rollback_json` → `envelope`; local `assert_run_ok`/`npm_run` (bound to each file's own `run`, and `common::run_toolchain` doesn't scrub `SOCKET_*`); held: `e2e_bazel_build/*`, `e2e_redirect_gem_build.rs`, `maven_build_common`, `rollback/cli_rollback_silent.rs`.
- A74 #1974 (p1, ~5, risk M): `governing_root` membership model → `formats/npm_workspace.rs`; #1928/#1971 have merged.
- A57 #1935 (p1): #1931 merged; check `ruby_crawler.rs` against open gem fix PRs.
- T60 #1968 rest, T64 #1979 rest, T50 #1940, T58 #1957: re-check against `main`.

Next sweep files: re-derive from `coverage/files.tsv` against `main` (3 weeks of drift since 2026-11-02); `scan/policy.rs`, `scan/render.rs`, `api/vendor_prefetch.rs`, the free crawler rows, `group_commit.rs` (region).
Leftovers from merged sweeps (all still to do): `socket_yml_args.rs` `min_severity` → `Option<u8>` + injected env (held by #1978/#1864), `cli_parse_scan` env subset test + `"1.5"` reject row (#1978), rollout `offer`/`manifest` fixtures in CLI+core → `test-fixtures` (#1985); `ui/text.rs` sweep and the text-shaping move out of `ui/mod.rs` (#1884), `StatusLine::stderr(json, silent)` → one `report` bool (scan/mod.rs, lock_cli.rs) (#1961); `toml_edit_ext` deletion and `uv_workspace` fold (#1923); 7 `build_*_purl` wrappers + `parse_jsr_purl`, purl's PurlKey asserts → `purl_key.rs`, pipenv `installed_major`'s `_root` (#1920); String `read_capped` wrapper, `lock_fragments`/`pdm_lock` `pub mod` → `pub(crate)` (#1914); `CargoCrawler::cargo_home`, `vendor/jvm` digest copies, async `fs::is_symlink` (#1907); `api_auth_fallback_warning` → `json_envelope` and `PlanNote` → `RunWarning` (#1698), `store_variants` test → core `npm_crawler.rs` (#1829/#1891/#1906/#1915) (#1948); `PathScope::matches` (rollback L1814 loop) → `bind` once, plus `BoundScope::matching_pattern_indices` for rollback's `raw()` re-parse with `expect` (#1864); `AppliedVia` one-variant mirror + `from_core` (apply.rs, #1698) (#1967); `check_python_lock_source_scope` is test-only (its caller in `redirect/mod.rs`, held by 7 PRs), `artifact_filename` ×4 (`pypi_locks::basename` also splits `\\`), `ancestor_uv_config_files` → `relpath` (A19), `PythonLockSession::plan`'s `text` arg → keep the rendering in the session (#1990).

#### Notes
- Want issues (output-changing, found in sweeps): `ui::shell_word` misses `"`/`%VAR%` on cmd; `scan/gc.rs` `has_ledger` probes `--cwd` but `run_vendor_gc` reads `project_root()` (C43); gem stale probe dedups by purl and drops the platform suffix; `hatch::require_pip_installer_documents` ignores the `envs` override; `npm_range_admits(">=", v)` admits all; npm `upstream_registry_fallback` leaks `?token=` (use `redact_urls_in`); `vlt_heal` swallows `load_state`/lock read errors; `strip_url_userinfo`'s scp branch keeps `u:p@`.
- Check "redundant filter" notes against all consumers and derived `GlobalArgs`.
- Clap field doc comments are `--help` output: leave them.
- `--cwd` defaults to `.`: absolutize before walking `ancestors()`; test via chdir under `#[serial]`.
- `vendor/cargo_config.rs` (~L165-L190) has a third `.cargo/config` pick: fold into `config_layer_paths` when swept.
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` (disk). CI's clippy has no `--tests`.
- A shallow clone hides merges: deepen (`git fetch --shallow-since=<date> origin main`) before grepping `main` for `(#N)`.
- Root-sandbox failures that pass in CI: 2 chmod tests in `tests/repair`, and core `copy_tree` symlinked-root, `vlt_heal` unremovable-lock, `pypi_poetry`/`pypi_requirements` wire-failure tests.; `in_process_redirect`'s 3 chmod tests
- The proxy refuses branch deletions: name branches right first time.
- `run_redirect_selected` still takes `Option<Envelope>` keyed on `common.json`; making it a value touches `get.rs` (#1698) and T24.
- Making a `pub` core item private can leave rustdoc links to it; unlink in the same commit.
- Test runners that pin `--cwd` must not also set the child's cwd to the project, or a crawler reading the process cwd passes (found by /code-review on #1944).
- Left from #1929: `UpdateArgs.pin_version` as `semver::Version` waits on `lib.rs` (#1842); `sweep_orphan_vendor_dirs` forwarder on `vendor.rs` (#1698).
- Left from #1936: `vendor/gem.rs` `plan_gemfile_edit`, `vex/discover/gem.rs` (~L252), `redirect/upstream/gem.rs` (~L661) hand-scan `=begin`: use `manifest::code_lines`. Its heredoc heuristic misreads `x <<FLAG` and indented `<<ID` terminators.
- Left from #1939: `remove.rs` L1327 doc still names the deleted `revert_vendor_entry` (#1875); `commands/repair.rs` ~L429 copies `ensure_client` (#1875); `ApplyRequest.manifest` → `&HashMap` (drop `records_manifest`) and `stop_on_failure` wait on #1698/#1864/#1875; split `repair()`'s phases.
- Keep a single-caller fn that is a constant's only test seam or names a phase of a long fn (`fetch_concurrency`, `build_candidates`).
- Left from #1955: PTY watchdog SIGHUPs, 10 s prompt waits.
- Left from #1967: core `UpdateTimeouts::from_env` and the notifier both parse `SOCKET_UPDATE_TIMEOUT_MS`; core caps `connect` at 10 s, the notifier doesn't (A09/C19).
- Left from #1964: `CI`/`GITHUB_ACTIONS` still reach test children; test a scrub with a parent-env canary.
- Left from #1975: `blob_fetcher` `on_progress` (#1855/#1875/#1864) and `BlobFetchResult.success` (#1855); `concise_fetch_error` re-parses the client's text; `store_verified_blob` vs `stream_cache_entry_atomic` drift. `scan --json` serializes `BatchPackagePatches`: keep a serialize test.
- Left from #1978: T57 can use `clap_parse::global_defaults()`; `derive(PartialEq)` on `GlobalArgs` (after #1842) retires `Globals`. Set vars via `try_parse_with_env` (the scrub is `Once`).
- Left from #1988: `assert_proxy_served_scans` counts 404s too (a wrong mount path stays green). A `#[path]` in a non-`mod.rs` file resolves under its stem dir: declare in `main.rs`.
- Left from #1972: `run_container` takes no extra args (3 callers still build `docker run`); `host.docker.internal` ×15. No Docker here: build with `--features docker-e2e`.
