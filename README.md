# Architecture audit ledger

This orphan branch holds the working state of the scheduled socket-patch architecture routines. Cloud sessions can't write to GitHub Discussions, so the routines commit here, and `.github/workflows/arch-audit-ledger.yml` runs `tools/mirror.py` on every push to mirror the branch into the discussion named in `ledger.json`.

| Path | What it is | Mirrored to |
|---|---|---|
| `doc/01-summary.md` … `doc/06-history.md` | The living document, organized by concern: mechanisms, duplication, structure, tests, history | The discussion body and its Part 2–6 comments, re-rendered on every push |
| `register/*.md` | The defect register. `00-header.md` is maintainer-owned; each routine owns one file; `50-`/`60-carried-*` hold the open items carried over from #560 | The register comment (the first comment) |
| `coverage/files.tsv` | The file-by-file manifest: every `.rs` file, who audits it, when it was audited and swept, and its local cleanup notes | The `{{COVERAGE}}` line |
| `entries/<slug>/<UTC timestamp>.md` | One file per routine run: the log | A new discussion comment for each file added |
| `AUDIT.md`, `REFACTOR.md` | The procedures the routines read at the start of every run | — |
| `review/2026-10/` | The original October review snapshot (read-only) | — |
| `review/2026-10-v1/` | The first thread (#560): living document, register, procedures and entries, archived 2026-10-29 (read-only) | — |
| `tools/mirror.py` | The renderer and mirror, which the workflow runs | — |

The routines:
- `audit-core` (core crate sources) and `audit-cli-tests` (the CLI crate and all tests) run every 6 hours, staggered. They read the code file by file, never change it, and file `arch-audit` issues.
- `refactor` runs every 2 hours. It alternates between sweep PRs (applying the auditors' per-file cleanups) and structural PRs (the highest-leverage register item).

Edit `AUDIT.md` or `REFACTOR.md` to retune them. Only add or change the files you own, and never rewrite or force-push this branch. To preview the rendering locally, run `python3 tools/mirror.py --worktree --dry-run --out /tmp/render` from the branch root.
