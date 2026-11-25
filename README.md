# Architecture refactor ledger

This orphan branch holds the working state of the scheduled socket-patch architecture refactor routine. Cloud sessions can't write to GitHub Discussions, so the routine commits here, and `.github/workflows/arch-audit-ledger.yml` runs `tools/mirror.py` on every push to mirror the branch into the discussion named in `ledger.json`.

| Path | What it is | Mirrored to |
|---|---|---|
| `REFACTOR.md` | The procedure the routine reads at the start of every run | — |
| `doc/01-summary.md` | The charter | The discussion body |
| `register/10-refactor.md` | PRs in flight and merged, leads, areas examined, notes | The register comment (the first comment) |
| `entries/refactor/<UTC timestamp>.md` | One file per routine run: the log | A new discussion comment for each file added |
| `review/2026-10/` | The original October review snapshot (read-only) | — |
| `review/2026-10-v1/` | The first thread (#560), archived 2026-10-29 (read-only) | — |
| `review/2026-11-v2/` | The second thread (#1830): file-by-file sweeps, its audit and refactor procedures, register, coverage manifest, living document and entries, archived 2026-11-25 (read-only) | — |
| `tools/mirror.py` | The renderer and mirror, which the workflow runs | — |

The `refactor` routine runs on a schedule. Each run fixes at most one real problem: a defect shown on `main` by a failing test, then fixed. Edit `REFACTOR.md` to retune it. The two audit routines from the second thread are off, and their procedure (`review/2026-11-v2/AUDIT.md`) is history.

Never rewrite or force-push this branch. To preview the rendering locally, run `python3 tools/mirror.py --worktree --dry-run --out /tmp/render` from the branch root.
