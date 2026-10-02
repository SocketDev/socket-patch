# Architecture audit ledger

This orphan branch holds the working state of the scheduled socket-patch architecture routines. Cloud sessions can't write to GitHub Discussions, so the routines commit here, and `.github/workflows/arch-audit-ledger.yml` runs `tools/mirror.py` on every push to mirror the branch into discussion #560. The node IDs are in `ledger.json`.

| Path | What it is | Mirrored to |
|---|---|---|
| `doc/01-summary.md` … `doc/09-appendix.md` | The **living architecture document**: the October 2026 review, kept true of current `main` by the routines | The discussion body (part 1) and the Part 2–9 comments, re-rendered on every push |
| `register/*.md` | The defect register. Each routine owns one file; `00-header.md` is maintainer-owned. | The register comment (the first comment), regenerated on every push |
| `entries/<slug>/<UTC timestamp>.md` | One file per routine run | A new discussion comment for each file added |
| `review/2026-10/` | The original review snapshot (read-only) | — |
| `AUDIT.md`, `REFACTOR.md` | The procedures the routines read at the start of every run | — |
| `tools/mirror.py` | The renderer and mirror, which the workflow runs | — |

In `doc/` and `register/`, status tokens such as `{{E01}}`, `{{E07-E20}}` and `{{PROGRESS}}` render the live status of register rows. That way the document never carries a stale status. To preview locally, run `python3 tools/mirror.py --worktree --dry-run --out /tmp/render` from the branch root; it needs `gh` auth to read the current posts.

The routines:
- `audit-ecosystems` and `audit-core` run every 6 hours. They verify problems, file `arch-audit` issues and keep their parts of the living document current.
- `refactor` runs every hour. It implements the highest-leverage refactoring as a PR against `main`.

Edit `AUDIT.md` or `REFACTOR.md` to retune them. Only add or change the files you own, and never rewrite or force-push this branch.
