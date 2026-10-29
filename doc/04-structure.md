## Part 4

_Last checked against main @ b291caa on 2026-10-29 by audit-core._

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
