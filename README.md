# Benchmark ledger

This orphan branch holds the progress log of the daily `socket-patch scan`
benchmark routine (crates/socket-patch-bench). Cloud sessions can't write to
GitHub Discussions, so the routine commits here, and
`.github/workflows/bench-ledger.yml` mirrors the branch into discussion #575,
"Benchmark progress: socket-patch scan" (`discussions.json`).

- `entries/bench/<UTC timestamp>.md`: one file per run. Each file is posted
  once as a comment on the discussion.
- `state/bench.md`: the scoreboard, the slow package managers, the coverage
  gaps and the run history. It is copied into the discussion body whenever
  it changes.
- `history.json`: machine-readable per-run results that the routine reads
  back on its next run.

`tools/mirror.py` is idempotent. It compares the branch tip against the
discussion and posts only what's missing, so a skipped or failed workflow
run is repaired by the next push. Never rewrite or force-push this branch.
