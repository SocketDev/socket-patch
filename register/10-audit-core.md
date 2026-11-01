### Core audit (A rows)
_Last updated 2026-11-01T19:20Z · main @ cbbbdb9 · owner: audit-core_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| A01 | 1 | Cargo config chain walked 3× (`source_replacement::config_layer_paths`, `cargo_build_cache` prefers `config.toml`: wrong target dir, executed; `vendor/cargo_config` L160-200 drifts on symlinks and a `config` dir) plus 4 legacy-file picks. | #1832 | in PR #1849 |
| A02 | 1 | `cargo_workspace::wildcard_match` has no `[...]` classes (executed); one of three segment glob matchers. | #1833 | in PR #1866 |
| A03 | 2 | GOMODCACHE/GOPATH default ×2 (`go_crawler`, `go_installed_tools`), drifted on empty GOPATH and home fallback. | #1834 | in PR #1876 |
| A04 | 2 | Callers re-derive `utils::line_endings` (vendor/common, python_lock, lock_fragments) plus 3 `eol_eq` copies. | #814, #815 | filed #814; new sites added to the tracker's scope |
| A05 | 2 | `lock_fragments` pairs fragments in three drifted loops; pdm/poetry each repeat the rewrite triad. | #1844 | in PR #1898 |
| A06 | 2 | Lowercase-hex/sha256 validators re-written ~10×; `vendor/jvm` `sha1_hex`/`sha256_hex` are computations under validator names; poetry/pdm twin hex+wheel validators. |  | to verify |
| A07 | 2 | `GroupCommit::commit_unjournaled` never drains the `after_commit` queues `commit_changes` drains. Reachability unproven. |  | to verify |
| A08 | 2 | Ecosystem code in `utils/` (hatch*, pdm/poetry locks, lock_fragments, go_*, cargo_*, pnpm_workspace) and `utils`→`vendor`/`crawlers` imports; `formats`→`vendor` imports too (nuget lock, pipenv, yarn copy). Overlaps #833. | #833 | to verify |
| A09 | 3 | Env parsing has 3 vocabularies (`env_compat` exact `1`/`true`, `socket_cli_config::env_truthy` yes/on/y/t, `concurrent` trim+log); python_crawler has 7 more truthy parsers; `PYENV_ROOT=` counts as set (executed); `walk_pool` drops a bad `SOCKET_WALK_THREADS`. Related #793. |  | to verify |
| A10 | 2 | Home resolved by many rules (`fs::home_dir`, hatch_env L491, `repo_root::home`, `neutral_probe_dir_with`, `socket_cli_config`, python ×2, NuGet ×2); `fs.rs` is a grab-bag. |  | to verify |
| A11 | 3 | The tool `--version` probe is written twice: `utils/pipenv.rs` runs it in `temp_dir` with `PIPENV_DONT_LOAD_ENV`, while `vendor/pypi_hatch.rs:202` runs it in the project root. Suspected hardening drift. |  | to verify |
| A12 | 3 | Prune-empty-dirs ×3 (inclusive/exclusive/sync), "remove, NotFound ok, sync parent" ×3, `group_commit::sync_dir` duplicates `fs.rs`. |  | to verify |
| A13 | 3 | The yarn major is parsed from `packageManager` twice: `update/channel.rs:361` (no trim) and `vendor/mod.rs:274` (after `package_manager::pinned_version`). |  | to verify |
| A14 | 2 | `pkg:` purls split by hand ~12×; `purl.rs` has 3 splitters that disagree on empty parts; composer purl ×4. Parsing half of #748. | #748 | filed #748; copies listed in a comment |
| A15 | 3 | Uuid shape is checked 4 ways (`target::is_uuid_shaped`, `redact`'s private twin, `path_safety::is_canonical_uuid`, `Uuid::parse_str` in `python_script` L99, which also accepts braced/urn/simple forms). | #705, #1845 | filed #705; #1845 closed as its duplicate |
| A16 | 3 | Committed JSON ledgers written 3 ways (`socket_dir::write_json_ledger`, `write_manifest` no newline, two state markers). Changes manifest bytes. |  | to verify |
| A17 | 3 | pnpm `packages:` membership refuses `{}[]` globs the shared matcher reads; hosted keeps a second reader. | #1846 | in PR #1863 |
| A18 | 3 | "poetry.lock written before 1.4" ×2 while `poetry_lock::lock_writer_version` is dead. | #1847 | in PR #1865 |
| A19 | 3 | Lexical `..` folding ×5 beside `utils::relpath` (maven_scope, cargo_crawler, hatch_env, python_script, `formats::nuget::lock::resolve_relative`, drifted on `C:x` and `x/..`). Unexecuted. |  | to verify |
| A20 | 3 | URL credential stripping ×2: `redact::strip_url_credentials` is dead while VEX `@id` and upstream npm use `vex::product::strip_url_userinfo`; the copies differ on query and authority end. | #1848 | in PR #1923 |
| A21 | 3 | The walk to the enclosing `.git` is hand-written outside `repo_root` (core `patch/user_patches.rs` L49/L65, `governing_root.rs` L528, `hatch_workspace.rs` L101): no `GIT_CEILING_DIRECTORIES`, any `.git` file type. Unexecuted. |  | to verify |
| A22 | 3 | uv settings-file choice and `no-binary` precedence ×2 (`python_script`, `redirect/upstream/uv.rs`); drifted on refusal labels. |  | to verify |
| A23 | 3 | Hosted `redirect/requirements.rs` keeps its own logical-line lexer beside `utils::requirements`. |  | to verify |
| A24 | 3 | "Is this our earlier hosted pin" ×2 (`python_lock::is_prior_hosted_url`, `python_script::same_hosted_artifact`). |  | to verify |
| A25 | 3 | PEP 508 leading-name scanner ×3 (`vendor/common.rs` L602, `requirements.rs` L438, inline `python_lock.rs` L665, which skips `trim_start`); `canonicalize_pypi_name` still in `crawlers::python_crawler` (#883 closed). |  | to verify |
| A26 | 3 | Civil-date math lives in three modules: `days_from_civil` twice (`api/date.rs` L48, `formats/cargo/floor.rs` L26) and its inverse in `vex/time.rs`, whose doc claims to be the only copy. Target: one `utils::time`. | #1867 | filed #1867 |
| A27 | 2 | `api/client.rs`: two near-copy serve GETs, 4 hand retry loops, two retry policies that disagree (executed). | #1869 | in PR #1870 |
| A28 | 3 | `api/` is not a leaf: `vendor_prefetch` belongs in `vendor/`; `client.rs` carries the pypi wheel gate; `api::types` imports `patch::redirect`. Overlaps #833. | #833 | to verify |
| A29 | 3 | Four xorshift64* test RNGs; eight `crawlers/**/oracle.rs` (2,978 lines) keep pre-migration crawlers as oracles. | #1868 | in PR #1882; oracle deletion still to decide (npm oracle: retire, 2026-11-01 entry) |
| A30 | 2 | Maven `${…}` interpolation ×5 (`maven_crawler`, `formats::maven`, `maven_scope`, `maven_reactor` ×2); drifted on recursion, undefined names, and only `formats::maven` caps output length. | #1887 | filed #1887 |
| A31 | 2 | A POM's own coordinates read 3 ways (`maven_crawler` line scanner, `formats::maven::model_refs`, `maven_reactor::pom_model`), drifted. | #715 | filed #715 |
| A32 | 3 | Env-keyed subprocess memo ×3 (composer `EnvKeyedMemo`, python `KeyedMemo`, ruby `GemEnvMemo`) with byte-identical keys; python caches answers computed under a changed env. | #1888 | in PR #1895 |
| A33 | 3 | "Is this a Coursier root" ×2 (`maven_crawler::coursier_spelled` vs `JvmCacheLayout::classify`). Unexecuted. |  | to verify |
| A34 | 3 | Go coordinate gate ×4 (`go_crawler`, `golang_local`, `purl::golang_purl`, `vendor/path.rs`; identical today) and Go module-cache layout (`encode_module_path`, `cache/download` paths, `get_gomodcache`) in the crawler but used by vendor and redirect. Extends E37, A03. | #748 | to verify |
| A35 | 3 | JVM cache plumbing split: `JvmEnv`/`M2Gate` in `maven_crawler`; gradle roots ×2, hash-dir listing ×3, wrapper init.d ×2, `-D` parsing ×2, Maven2 root climb ×2; `formats::sbt::{Ga,JvmResolution,gate}` serve scala-cli too (target `formats::jvm`). |  | to verify |
| A36 | 3 | platformdirs-style user cache/data/config dirs ×8 (coursier, deno, poetry cache; hatch, pdm/poetry data/config; uv, pipx, pipenv WORKON_HOME), absolute-XDG filter ×6; drifted on Windows fallback and macOS `XDG_*`. Extends A10. |  | to verify |
| A37 | 3 | `EnvGuard` test helper ×11 plus `with_env`/`with_home_env`. | #1889 | in PR #1891 |
| A38 | 3 | All 8 crawlers are stateless unit structs with `new()` + `Default`; free functions would do. |  | to verify |
| A39 | 3 | Hatch legacy `<name>-<id>` env layout is checked only for the first project id, and macOS lists the casefolded id first, so Hatch 1.0–1.2 envs under raw ids are missed ([hatch_env.rs L128-L178](https://github.com/SocketDev/socket-patch/blob/5ca5623863eee274851df4a941a86ba36f284dc3/crates/socket-patch-core/src/crawlers/hatch_env.rs#L128-L178)). Unexecuted. |  | to verify |
| A40 | 3 | The effective-POM walk ×2 (`maven_scope::Walk`, `maven_reactor`); drifted: scope matches a local parent on artifactId only and has no BOM-import seen-set. `maven_scope` imports `vendor::jvm`. Extends E83, A30. |  | to verify |
| A41 | 2 | `npm_crawler` classifies `node_modules` store children 3× (resolver, scan, peer finder), drifted on nested stores. | #1899 | filed #1899 |
| A42 | 3 | Yarn-classic `.yarnrc` tokenized ×2 (npm_crawler, redirect/yarnrc), drifted on quotes. | #1901 | in PR #1915 |
| A43 | 3 | package.json `workspaces` is read 5× (`governing_root::workspace_patterns`, `npm_crawler` Bun walk, `update::channel`, `vendor/mod.rs`, `user_patches`); they disagree on non-string items, `null` and `!` patterns. | #1900 | filed #1900 |
| A44 | 3 | `.modules.yaml` parsed 3× (npm_crawler, `formats/pnpm/version.rs`, upstream npm; first vs last key, executed) + YAML scalar unquote ×4. | #1918 | filed #1918 |
| A45 | 1 | Default `--cwd .` hides a parent `.yarnrc`/yarn store from the npm crawler (executed): `crawler_options()` never absolutizes `cwd`. | #1902 | in PR #1906 |
| A46 | 3 | NuGet project-tree walk ×2 (`nuget_crawler::restore_walk`, `vendor::nuget_config::project_files`/`governed_locks_in`) and project-file test ×2 (case-sensitive crawler copy vs `formats::nuget::lock::is_project_file`); drifted on case and non-UTF-8 names. | #1917 | filed #1917 |
| A47 | 2 | "Declares `[tool.poetry]`" ×3 (`declares_tool_poetry` TOML parse, `claimed_by_non_uv_manager` substring, `toml_edit_ext::has_table`). Executed: a lockless uv project with `[tool.poetry-dynamic-versioning]` loses its `UV_PROJECT_ENVIRONMENT` site-packages. | #1916 | filed #1916 |
| A48 | 2 | Crawler unit tests read the real env: 12 `pkg_managers`/`pnpm_layout` PnP tests fail under `YARN_NODE_LINKER` or a `~/.yarnrc.yml` linker (executed); 5 python `crawl_all` tests read `VIRTUAL_ENV` (unexecuted). | #1919 | filed #1919 |
| A49 | 3 | Python env-dir naming ×3 (Poetry, Pipenv, Hatch `path_id`), not drifted. Windows verbatim-prefix strip ×6, drifted: `npmrc::strip_verbatim` has no UNC case, `pnpm_workspace::without_verbatim_prefix` strips only before a drive letter (others: python_crawler, hatch_env, sbt_evidence, `pnpm_lock_legacy`). |  | to verify |
| A50 | 3 | Python site rules drifted inside `python_crawler`: user site ×2 (`base_site_dirs` honours `PYTHONUSERBASE`/`PYTHONNOUSERSITE`; the global scan hardcodes `~/.local`); site-packages-under-prefix ×3 (lib only vs lib+lib64); PDM config/`.pdm-python` read twice (project `take(1)` vs global all layers, relative path, `~`). |  | to verify |
| A51 | 3 | FIFO test scaffolding ~25 `mkfifo` copies (nuget/cargo `make_fifo`+`within_deadline` byte-identical) beside `oracle_support::fifo`; reader-release helper ×3. Target: one test-support module with A37's guard and `test_rng`. |  | to verify |
| A52 | 3 | `crawlers/pkg_managers` crawls nothing: `YarnEnv`/rc resolution and `yarn_pnpm_store_folder_in` belong in `formats::yarn`, `YarnPnpLoader` (CLI vex only) in `vex`; the root-linker read is copied in `lock_inventory/view.rs` L858. npm-family ownership order ×3 extends E75. Extends A08. |  | to verify |
| A53 | 2 | Bundler path tier rule ×2 in `ruby_crawler` (`bundler_sets_explicit_path` vs `bundler_path_tier`/`config_path_tier`) + 3 partial copies; discovery ignores a falsy `disable_shared_gems` (executed). | #1931 | in PR #1943 |
| A54 | 2 | `gemspec_directives`/`dev_dependency_requirements` bypass `manifest::for_each_code_line`, so `=begin` blocks and heredocs are read as code (executed on copies). | #1932 | in PR #1936 |
| A55 | 2 | "Is crates.io" ×4 (substring, exact, normalized, `[patch]` key); `CargoLock::entries` accepts `index.crates.io.evil.example` (executed). | #1933 | filed #1933 |
| A56 | 2 | Hosted composer splices server url/sha1 via expanding `Regex::replace`, unvalidated and unescaped: lock stops parsing (executed). Extends A06. | #1934 | filed #1934 |
| A57 | 3 | ~1.26K lines of Bundler settings in `ruby_crawler`, imported by `formats/gem`; `.bundle/config` key reader ×2 drifted; manifest-name list ×2. Extends E20. | #1935 | filed #1935 |
| A58 | 3 | Gemfile.lock read beside its model: `BUNDLED WITH` ×2 (`gemspec` L64, `hosted` L389; exact header), CHECKSUMS ×5 (upstream accepts any `sha256=`), upstream gem section model takes the FIRST DEPENDENCIES, the model the LAST. Extends E19. |  | to verify |
| A59 | 3 | Ruby string literal ×4 (`gemspec::literal`, `manifest::plain_literal`, `vex/product`, `vendor/gem`) + 6 quote loops, drifted on `%q`, escapes, `#{`. Target `formats/gem/ruby.rs`. |  | to verify |
| A60 | 3 | sbt evidence path table ×2 (`sbt_evidence` PATTERNS, `formats::sbt::evidence::classify_path`); vex `evidence_blocker` re-implements `sbt::gate::check_new` and loses `read_error`; scala_evidence drops its reason too. |  | to verify |
| A61 | 3 | Streaming file sha256 ×2 (`sbt_evidence` refuses symlinks, 256 MiB; `vendor/verify::file_sha256_hex` follows, 512 MiB). Target `utils::digest`. |  | to verify |
| A62 | 3 | JSON text scanners ×5 (composer hosted/source, vlt, bun, `formats::pipenv`; drifted on escapes/removal); BOM-tolerant JSON parse ×8; bun.lock line split ×3. Target `formats/json.rs`. |  | to verify |
| A63 | 3 | `gem env` probe runs in the project cwd under `--global` (npm/composer use `GlobalProbeRunner`) and bypasses `CommandRunner`. Unexecuted. |  | to verify |
| A64 | 2 | `PnpmLock::parse` inventories a pnpm 11 env-lockfile document; `InstalledPackages` and upstream evidence drop it (executed). | #1949 | filed #1949 |
| A65 | 2 | `xml::attr` matches inside quoted values, never decodes entities (executed); NuGet keeps a quote-aware twin, `decode_entities` and an encoder ×2. Extends E10. | #1950 | filed #1950 |
| A66 | 3 | Yarn classic `file:`/url copy identity ×2 (`source.rs` hosted, `copy.rs` vendored), drifted on `file:../x` (executed). | #1951 | filed #1951 |
| A67 | 3 | pnpm "importers list a member" ×2 (`formats::pnpm::workspace`, `utils::pnpm_workspace`), drifted on comment keys (executed). | #1952 | filed #1952 |
| A68 | 3 | Berry `dependencies:` line and `patch:` inner parsed ×2 (`berry_entry`/`berry_prune` vs `blocks`/`patterns::patch_layers`), drifted on tabs and nested patches. Unexecuted. |  | to verify |
| A69 | 3 | Yarn lock grammar decided on head-only (4 KiB: `update/channel`, `governing_root`) or substring reads (`vendor/mod.rs` L198/L231) beside `formats::yarn::grammar`. Unexecuted. |  | to verify |
| A70 | 3 | sbt preflight `DepLiteral::declares` (exact `%` name) vs generated Scala `@ID@Verify` (`startsWith(name+"_")`) disagree. Unexecuted. |  | to verify |
| A71 | 3 | pnpm `lockfileVersion` head sniff ×5 (two scan windows, three trims) and remedy ladder ×2 in `formats/pnpm`; lock filename consts repeated (`PACKAGES_LOCK` ×3, `YARN_LOCK` ×4, pnpm names ×4). |  | to verify |

#### Handed off
_None._

#### Rejected
_None._
