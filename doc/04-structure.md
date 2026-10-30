## Part 4

_Last checked against main @ 5ca5623 on 2026-10-30 by audit-cli-tests._

 Structure, abstraction and placement:Needless layers (one-impl traits, forwarding modules, invariant-free newtypes), tiny-function clusters, unclear control flow (mode flags, giant functions, accumulate-then-decide), and misplaced code (with its destination). Per-directory tallies of single-caller functions, wrappers and deletable comment lines go here as the audit covers each directory.

### Findings
- **`utils/` holds ecosystem code**, and some of it imports `vendor::*`: hatch ×2, pdm/poetry/lock_fragments, go ×2, cargo ×3, `pnpm_workspace` (imports `patch::redirect`), `purl_key` (imports `crawlers`/`vendor`) and `python_lock`. {{A08}}
- **`utils/fs.rs` is a grab-bag** of four concerns: dir helpers, FIFO-safe readers, home resolution and the atomic writer. {{A10}}
- **`GroupCommit::commit_unjournaled` skips the post-commit removal queues** that `commit_changes` drains. {{A07}}
- **Tally for `utils/` (first 28 files, 14.5K lines):**
  - about 75 single-caller functions;
  - about 30 trivial wrappers;
  - 0 one-implementation traits;
  - about 30 `pub` items with no caller outside their file (mostly in `go_installed_tools`, `cargo_build_cache` and `concurrent`), plus one dead function (`pdm_lock::wheel_matches`);
  - about 280 deletable comment lines.
- **`DownloadParams` re-copies `GlobalArgs`** field by field, and the nested apply rebuilds a `GlobalArgs` from it. {{T11}}
- **composer.lock parsing lives in the CLI** (`composer_hints`), beside a prefix re-parse of vendored paths. {{T12}}
- **Tally for `crates/socket-patch-cli/src` (first 8 files, 15.9K lines: `args.rs`, `commands/agent_download.rs` → `commands/get.rs`):**
  - about 74 single-caller functions (≈25 worth inlining; the rest are long or tested);
  - about 21 trivial wrappers or forwarders;
  - dead code: `--vendor-source` plumbing (one-variant `VendorSource`, C23), `FetchBatch.already_recorded`, `apply`'s `args.check` branch and two unreachable variant arms;
  - about 760 deletable comment lines (`apply.rs` alone: 909 of 3,542 production lines are comments, 32 bare `#NNN` refs).
- **Giant functions:** `get::run` (~760 lines), `apply::apply_patches_inner` (~700), `apply::run_locked` (~510, folds the same results three times), `agent_download::fetch_selected_patches` (~280, branches on the store in 5 places).
- **Tally for the rest of `utils/` (20 files, 16.4K lines, `pnpm_workspace.rs` → `workspace_globs.rs`):**
  - about 28 single-caller functions worth inlining;
  - about 36 trivial wrappers (7 bare `build_*_purl` `format!`s, 4 `refuse_uv_*` forwarders);
  - dead `pub` code: `poetry_lock::lock_writer_version`, `python_lock::complete_python_lock_metadata(+_in)`, `redact::strip_url_credentials`/`url_userinfo`, `target::Target::ambiguity`, `pnpm_workspace::shared_lockfile_disabled`/`git_branch_lockfile_setting`;
  - `toml_edit_ext.rs` is a two-function module whose functions each have one caller elsewhere;
  - about 210 deletable comment lines.
- **Module docs that claim a monopoly they don't have:** `relpath` ("every normalizer") {{A19}}, `repo_root` ("the one walk") {{A21}}, `redact` (VEX `@id`) {{A20}}.
- **Tally for `crates/socket-patch-cli/src/commands` (next 10 files, 15.5K lines: `hosted_bundle.rs` → `scan/discovery.rs`):**
  - about 57 single-caller functions (≈20 worth inlining; the rest are tested formatters);
  - about 12 trivial wrappers or shims (`patch_server_origins`, `HostedUnwindError`, 2 `pub use` re-exports in discovery);
  - dead code: `HostedLegOutcome::unsupported` (never written; rollback still branches on it), `InnerSelection::Identifier(None)` (test-only), repair's `ArtifactNoun` parameter (always `BLOB`);
  - about 380 deletable comment lines.
- **Giant functions (cont.):** `rollback::run` (~1,210 lines), `rollback::rollback_patches_inner` (~830), `remove::run` (~920). C11/#843 covers `run_scan` only.
- **`rollback.rs` is `remove`'s helper library:** remove imports 12 items from it (text helpers such as `join_clauses`/`as_question` belong in `ui`; hosted ones such as `retire_legacy_redirect_ledger` in `hosted_unwind`). Local notes.
- **`scan/discovery.rs` is a grab-bag:** discovery, update detection, severity helpers and hosted/vendored nested-project policy (`nested_project_skips`, which belongs in `scan/hosted.rs`). Local note; C11.
- **`api/` is not a leaf layer:** `vendor_prefetch` belongs in `vendor/`, the pypi wheel gate sits in `client.rs`, and `api::types` imports `patch::redirect`. {{A28}}
- **Tally for `api/` (8 files, 12.0K lines) and `crawlers/cargo_crawler*` (1.7K):**
  - about 20 single-caller functions worth inlining (`fetch_binary`/`binary_url`, `format_fetch_result_for`, the `download_vendor_archive*` chain, `verify_crate_at_path`);
  - about 12 trivial wrappers (identity `ranking::merged_coverage`, `org_slug`/`uses_public_proxy` over `route()`, `CargoCrawler::cargo_home`);
  - dead code: `get_api_client_from_env` (no caller), `blob_fetcher`'s `on_progress` parameter (every caller passes `None`), `CargoCrawler`'s `Default`;
  - about 140 deletable comment lines (mostly `vendor_prefetch`'s 110-line module doc and `client.rs` history notes).
- **Tally for `crates/socket-patch-cli/src/commands/scan/` (8 files, 15.5K lines: `gc.rs`, `hosted.rs`, `hosted/{nuget,python,takeover}.rs`, `mod.rs`, `policy.rs`, `render.rs`):**
  - about 90 single-caller functions (≈25 worth inlining; render's byte-tested builders stay);
  - about 26 trivial wrappers or shims (`count`, `run_warning_of`, `emit_json_error`, 4 re-export shims in `mod.rs`, 3 policy getters over a `pub` field);
  - dead code: `selection_args` (its only caller always takes the branch that ignores it), `run_redirect`'s non-JSON arm and `Option<Envelope>` (called only from the JSON arm);
  - about 335 deletable comment lines.
- **Giant functions (cont.):** `run_scan` is now 1,864 lines (C11/#843; it calls `discover_selected` twice in a row in its JSON arm), `run_redirect_selected_untracked` 1,233 {{T24}}.
- **Engine code in `scan/`:** `hosted/takeover.rs` (a 425-line plan/stage/retract/finish engine over `GroupCommit`) and `hosted/nuget.rs` belong in core; scan imports `commands::vendor::{dispatch_revert_one, run_vendor_gc, unused_vendored_manifest_keys}`. C12. `takeover.rs` also parses core warning prose (`residual_only_keep`), and `npm_allow_remote_one_line` matches `guidance` sentences.
- **Misplaced in `scan/mod.rs`:** the takeover section (L926-L1123, used only by `hosted.rs`) and `gradle_scan` (L1194-L1387, Maven-specific). `policy_bypass_warnings` is get-only policy evaluation that belongs in core `policy`.
