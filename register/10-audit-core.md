### Core audit (A rows)
_Last updated 2026-10-29T15:14Z · main @ b291caa · owner: audit-core_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| A01 | 1 | Cargo config chain is read twice. `cargo_build_cache::ConfigDirs::read` prefers `config.toml`, while `source_replacement::config_layer_paths` and cargo prefer `config`, so the build-cache cleaner invalidates the wrong target dir (executed). | #1832 | filed #1832 |
| A02 | 1 | `cargo_workspace::wildcard_match` has no `[...]` classes, so `members = ["crates/[ab]*"]` expands to nothing (executed). It is one of three segment glob matchers, with `workspace_globs::segment_glob_matches` and `hatch_workspace::fnmatch`. | #1833 | filed #1833 |
| A03 | 2 | GOMODCACHE/GOPATH default is written twice (`go_crawler::get_gomodcache`, `go_installed_tools` L176-186), and the copies drifted on empty GOPATH entries and the home fallback. | #1834 | filed #1834 |
| A04 | 2 | Callers re-derive `utils::line_endings`: `vendor/common.rs:198` copies `terminator`, and `python_lock::preserve_line_endings` and `lock_fragments` L434 hand-roll CRLF detection that ignores bare `\r`. There are three more `eol_eq` copies (`hosted/engine.rs:2900`, `vendor/jvm/scala_cli.rs:76`, `vendor/nuget_feed.rs:1004`). | #814, #815 | filed #814; new sites added to the tracker's scope |
| A05 | 2 | `lock_fragments` pairs fragments in three loops that drifted on which text they check for uniqueness. pdm and poetry each repeat the rewrite/`_with_edits`/`_in`/steps/batch triad. To confirm once `poetry_lock.rs` has been audited. |  | to verify |
| A06 | 2 | The lowercase-hex/sha256 validators are re-written at ~10 sites (`cargo_build_cache` ×2, `pdm_lock` ×2, `vendor/pypi*.rs`, `patch/apply.rs`, `redirect/*`). `vendor/jvm/mod.rs:621` defines `sha1_hex`/`sha256_hex` as *computations* under `digest`'s validator names. |  | to verify |
| A07 | 2 | `GroupCommit::commit_unjournaled` never drains the `after_commit`/`dirs_after_commit` queues that `commit_changes` drains ([L659-L695](https://github.com/SocketDev/socket-patch/blob/b291caa39b08eb28d9ef578cb556449380b7fdff/crates/socket-patch-core/src/utils/group_commit.rs#L659-L695)). The code is confirmed; whether a hosted-only run queues anything (staged.rs:79 `remove_dir_after_commit`) is unproven. |  | to verify |
| A08 | 2 | Ecosystem code sits in `utils/`: hatch, hatch_workspace, pdm_lock, poetry_lock, lock_fragments, go_env, go_installed_tools, cargo_*. `utils::hatch` imports `vendor::*`, and `group_commit::is_captured` imports `vendor::jvm`. Overlaps #833. | #833 | to verify |
| A09 | 3 | Env parsing has three vocabularies: `env_compat` (exact `1`/`true`), `socket_cli_config::env_truthy` (yes/on/y/t, case-insensitive) and `concurrent` (trim plus debug log). Related to #793. |  | to verify |
| A10 | 2 | The user's home is resolved by three rules: `fs::home_dir` (usable/absolute), `crawlers/hatch_env.rs:491` (HOME, else USERPROFILE, no checks) and `repo_root::home`. `fs.rs` is also a four-concern grab-bag. |  | to verify |
| A11 | 3 | The tool `--version` probe is written twice: `utils/pipenv.rs` runs it in `temp_dir` with `PIPENV_DONT_LOAD_ENV`, while `vendor/pypi_hatch.rs:202` runs it in the project root. Suspected hardening drift. |  | to verify |
| A12 | 3 | Three prune-empty-dirs loops (`group_commit::remove_tree_pruned` inclusive, `socket_dir::prune_empty_dirs` exclusive, the sync `prune_created`), three "remove, NotFound ok, sync parent" copies, and `group_commit::sync_dir` duplicating `fs.rs`. |  | to verify |
| A13 | 3 | The yarn major is parsed from `packageManager` twice: `update/channel.rs:361` (no trim) and `vendor/mod.rs:274` (after `package_manager::pinned_version`). |  | to verify |

#### Handed off
_None._

#### Rejected
_None._
