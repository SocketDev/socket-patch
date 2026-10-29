## Part 4

_Last checked against main @ c07af61 on 2026-10-29 by audit-cli-tests._

 Structure, abstraction and placement:Needless layers (one-impl traits, forwarding modules, invariant-free newtypes), tiny-function clusters, unclear control flow (mode flags, giant functions, accumulate-then-decide), and misplaced code (with its destination). Per-directory tallies of single-caller functions, wrappers and deletable comment lines go here as the audit covers each directory.

### Findings
- **`utils/` holds ecosystem code**, and some of it imports `vendor::*`: hatch ×2, pdm/poetry/lock_fragments, go ×2 and cargo ×3. {{A08}}
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
