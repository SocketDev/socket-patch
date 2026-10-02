# Janitor ledger

The Discussions bridge for the hourly issue & discussion janitor routine.
Cloud sessions can't use GitHub GraphQL, which is the only Discussions API,
so `.github/workflows/janitor-ledger.yml` does that work on every push here:

- **Read:** `snapshot/discussions.json` holds every discussion, its body and
  all of its comments, as of `snapshot/meta.json` → `generated_at`. The
  workflow commits it back to this branch, so `git fetch` always has the
  last snapshot.
- **Write:** push `ops/<UTC ts>-<slug>.json`, a JSON array of operations
  (`comment`, `close`, `update_body` (only for discussions listed in
  `owned.json`), `mark_answer`). The format is documented in
  `tools/janitor_sync.py`. `applied.json` records which op files are done or
  failed.
- **Fresh snapshot:** push any commit, even `git commit --allow-empty`,
  then wait for `meta.json` to show a `trigger_sha` equal to your commit.

Never rewrite or force-push this branch. Never edit `applied.json` or
`snapshot/` by hand: the workflow owns them.
