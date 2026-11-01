### Refactor routine
_Last updated 2026-11-01T15:15Z · main @ cbbbdb9_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| #1842 | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready |
| #1855 | sweep | `cli/src/commands/{bun_preflight,composer_hints,context,fetch_stage}.rs` | ready; Bugbot clean; CI lost Depot runners twice (0 steps), needs a fresh run |
| #1849 | structural | A01 #1832: `utils/cargo_build_cache.rs` | ready; CI and Bugbot green |
| #1864 | sweep | `cli/src/commands/{hosted_bundle,hosted_unwind,list,lock_cli,mod,pypi_reinstall}.rs` (+ dead branch in `rollback.rs`) | ready; CI (82 checks) and Bugbot green |
| #1870 | structural | A27 #1869: `api/client.rs`, one serve GET and one vendor retry loop | ready; CI (82 checks) and Bugbot green |
| #1875 | sweep | `cli/src/commands/{remove,repair}.rs` | ready; CI (82 checks) and Bugbot green |
| #1884 | sweep | `cli/src/commands/scan/discovery.rs` (+ T18 #1859; tests moved to core `ranking.rs`, `lock_inventory/tests.rs`, `ui/text.rs`) | ready; CI (82 checks) and Bugbot green |
| #1892 | sweep | `cli/src/commands/scan/gc.rs` | ready; CI (82 checks) and Bugbot green |
| #1897 | sweep | `cli/src/commands/scan/hosted.rs` (all but `run_redirect_selected_untracked`, T24; 13 guidance tests moved to core `hosted/guidance.rs`, 2 to `formats/pnpm/mod.rs`) | ready; CI and Bugbot green; burn-down final review done |
| #1903 | sweep | `cli/src/commands/scan/hosted/{nuget,takeover}.rs` | ready; CI (82 checks) and Bugbot green |
| #1907 | sweep | core `constants.rs`, `utils/{cargo_home,composer_version,concurrent,containment,digest,durability,env_compat,failpoint}.rs` (+ `socket_dir.rs`, `purl_key.rs` tests) | ready; CI (82 checks) and Bugbot green |
| #1914 | sweep | core `utils/{http,mod,hatch_workspace,hatch}.rs` (`line_endings.rs` clean) | ready; CI (82 checks) and Bugbot green |
| #1920 | sweep | core `utils/{notice,npm_range,package_manager,pep440,pipenv,purl}.rs` (+ `target.rs` callers) | ready; CI (82 checks) and Bugbot green |
| #1923 | sweep + A20 #1848 | core `utils/{redact,repo_root,serde,toml_edit_ext,uri,uv_workspace}.rs` (+ `vex/product.rs`, `redirect/upstream/npm.rs`, advisory lint moved to `vendor/service_fetch.rs`) | ready; CI (82 checks) and Bugbot green |
| #1929 | sweep | `cli/src/commands/{update,user_patches,vendor_orphans,vlt_heal}.rs` (+ `InstallChannel::id` in core `update/channel.rs`) | ready; CI (82 checks) and Bugbot green |
| #1936 | structural | A54 #1932: `formats/gem/{gemspec,manifest}.rs`, `vex/product.rs` (`for_each_code_line` → `code_lines`) | ready; CI (82 checks) and Bugbot green |
| #1939 | sweep | `cli/src/commands/vendored_backend/{mod,repair}.rs` | ready; CI and Bugbot pending |

#### Merged
_None._

#### Queue
Structural candidates, scored `3·B + 2·U + 2·D + 2·C − risk`. As of 2026-11-01T13Z, the audit's A53-A57 (#1931-#1935) are new: A54 is in #1936; A53 #1931 (~9) and A57 #1935 wait on `ruby_crawler.rs` (#1882, #1895); A55 #1933 (~11, risk M) waits on `redirect/mod.rs` (#1841, #1843, #1866, #1885, #1886, #1893); A56 #1934 is a fixer bug (free, ~5). Every older one scoring 6 or more is blocked by an open PR (nothing merged since 2026-10-29); T38-T45 (#1908-#1912, #1924-#1927) touch `scan/mod.rs`, `vendor.rs`, `rollback.rs` or `remove.rs`, all held. A46 #1917, A44 #1918 score ~4:
1. A30 [#1887](https://github.com/SocketDev/socket-patch/issues/1887), Maven `${…}` interpolation ×5: **~8.7** (blocked by #1886: `maven_scope.rs`, `maven_reactor.rs`).
2. T09 [#1858](https://github.com/SocketDev/socket-patch/issues/1858), lock acquire open-coded 9×: **~7** (blocked by #1864 `lock_cli.rs`, #1698 `vendor.rs`/`get.rs`/`agent_download.rs`).
3. A41 [#1899](https://github.com/SocketDev/socket-patch/issues/1899), npm store-child classification ×3: D2 C2, risk M, **~6** (blocked by #1891, #1829 and #1906: `npm_crawler.rs`).
4. A43 [#1900](https://github.com/SocketDev/socket-patch/issues/1900), package.json `workspaces` read 5×: **~6** (blocked by #1863 `governing_root.rs`, #1698 `vendor/mod.rs`).
5. T01 [#1835](https://github.com/SocketDev/socket-patch/issues/1835) (~6.4) and T25 [#1877](https://github.com/SocketDev/socket-patch/issues/1877) (~6): blocked by #1698.

A05/A32 are the fixer's (#1898/#1895); A42 #1901 and A45 #1902 likewise. A26 [#1867](https://github.com/SocketDev/socket-patch/issues/1867) scores 4 (files free).

The next run is structural if a candidate scoring 6 or more has free files, else a sweep. Next sweep files, in order: `vlt_preflight.rs` (callers in `vendor.rs`, #1698), `vex_consumed.rs`, `vex_sources.rs` (free; check callers), `scan/policy.rs` and `scan/render.rs` once #1856/#1884 merge; core `utils/lock_fragments.rs` (wait on #1898); next free: `python_lock.rs` (2,283), `python_script.rs` (1,768), then `api/{blob_fetcher,date,retry,types}.rs` and the crawler rows. `purl_key_nuget_vendor_tests.rs` waits on #1907 (`purl_key.rs` mounts it); scan `policy`/`rollout`/`rollout_args`/`socket_yml_args`/`withdrawn` have free files but their callers sit in `scan/mod.rs` (#1856, #1884, #1897). Left from #1923: delete `toml_edit_ext` (move `ensure_table`/`has_table` beside their one caller each; `utils/mod.rs` held by #1914, `vendor/pypi.rs` by the pypi PRs) and fold `uv_workspace`'s two-call pattern (`governing_root.rs` #1863, `vendor/pypi.rs`). `process.rs` waits on #1895, `pdm_lock.rs` on #1898, `poetry_lock.rs` on #1865/#1898, `pnpm_workspace.rs` on #1863. Left from #1920: inline the 7 `build_*_purl` wrappers and `parse_jsr_purl` (callers held by #1882/#1886/#1891/#1698), move purl's PurlKey asserts to `purl_key.rs` (#1907), drop pipenv `installed_major`'s `_root` (callers in #1897 and the `vendor/pypi.rs` PRs). Waiting on PRs: `utils/fs.rs` and core `lib.rs` (#1891), `go_env.rs`/`go_installed_tools.rs` (#1876), `cargo_workspace.rs` (#1866), `cargo_build_cache.rs` (#1849), `group_commit.rs` is free but 2,163 lines (sweep a region). Skip `agent_download.rs`, `apply.rs`, `get.rs`, `vendor.rs` while #1698 is open, `rollback.rs` while #1864 is open. Left from #1914: delete the String `read_capped` wrapper (callers in `maven_repo.rs`, held by #1886/#1891; or rename `read_capped_typed`, touching `api/client.rs`, held by #1870/#1891); `lock_fragments`/`pdm_lock` `pub mod` → `pub(crate)` waits on #1898. Left from #1907: `CargoCrawler::cargo_home` forwarder (#1882), digest's `vendor/jvm` copies (#1886), async `fs::is_symlink` (#1891).

#### Notes
- First-thread PRs: `review/2026-10-v1/register/90-refactor.md`.
- Check every "redundant filter" note against all consumers (the `args.rs` proxy filter is load-bearing).
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
- Wants an issue: npm `upstream_registry_fallback` (`redirect/upstream/npm.rs` ~L158) strips only userinfo, so a registry `?token=` reaches output and `--json` (fix: `redact_urls_in`, output-changing).
- Wants an issue: `vlt_heal::artifact_preflight` swallows a `load_state` error and `rollback_heal` drops a lock read error with `.ok()` (output-changing).
- Left from #1929: `UpdateArgs.pin_version` as `semver::Version` waits on `lib.rs` (#1842); `sweep_orphan_vendor_dirs` forwarder on `vendor.rs` (#1698).
- Wants an issue: `strip_url_userinfo`'s scp branch keeps credentials in `u:p@host:team@2024/r.git` (changes VEX `@id` bytes).
- Left from #1936: `vendor/gem.rs` `plan_gemfile_edit`, `vex/discover/gem.rs` (~L252) and `redirect/upstream/gem.rs` (~L661) still hand-scan `=begin`; route them through `manifest::code_lines` (the pin writer refuses a Gemfile whose duplicate `gem` line sits in `=begin`). `code_lines`'s heredoc heuristic reads `x <<FLAG` (a shift) as a heredoc and closes a plain `<<ID` at an indented terminator.
- Left from #1939: `remove.rs` L1327 doc still names the deleted `revert_vendor_entry` (#1875); `commands/repair.rs` ~L429 copies the build-once client (use `vendored_backend::repair::ensure_client`, #1875); `ApplyRequest.manifest` → `&HashMap` (drop `records_manifest`) and `stop_on_failure` wait on #1698/#1864/#1875; split `repair()`'s phases.
