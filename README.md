# Bug-hunt ledger

This orphan branch holds the progress ledgers of the scheduled socket-patch
bug-hunt routines, one per package manager. Cloud sessions can't write to
GitHub Discussions, so the routines commit here and
`.github/workflows/bughunt-ledger.yml` mirrors each change into that package
manager's "Bug hunt ledger: …" discussion (numbers in `discussions.json`).

- `entries/<pm>/<UTC timestamp>.md`: one file per run. Every file added here
  is posted as a comment on the discussion.
- `state/<pm>.md`: the current coverage matrix, backlog and known non-bugs.
  Every change is copied into the discussion body.

`INSTRUCTIONS.md` is the shared procedure that every routine reads at the
start of each run. Edit it to retune all the routines at once.

Only add files under your own `<pm>`. Never rewrite or force-push this branch.
