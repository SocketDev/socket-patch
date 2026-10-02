# Architecture audit ledger

This orphan branch holds the working state of the scheduled socket-patch architecture routines. Cloud sessions can't write to GitHub Discussions, so the routines commit here, and `.github/workflows/arch-audit-ledger.yml` mirrors each push into the architecture review discussion. Its number and node IDs are in `ledger.json`.

| Path | What it is | Mirrored to |
|---|---|---|
| `review/2026-10/` | The October 2026 architecture review (read-only) | The discussion body (part 1) and its first comments (parts 2–9) |
| `register/*.md` | The living defect register. Each routine owns one file; `00-header.md` is maintainer-owned. | The register comment, regenerated on every push from all the files joined in name order |
| `entries/<slug>/<UTC timestamp>.md` | One file per routine run | A new discussion comment for each file added |
| `AUDIT.md` | The procedure for the `audit-ecosystems` and `audit-core` routines | — |
| `REFACTOR.md` | The procedure for the `refactor` routine | — |

The routines are `audit-ecosystems` (formats, hosted, vendored, discovery, VEX), `audit-core` (CLI layer, core infrastructure, agent mode, tests, docs) and `refactor` (implements `refactor` issues, one small PR at a time). Edit `AUDIT.md` or `REFACTOR.md` to retune them; each routine reads its procedure at the start of every run.

Only add or change the files you own. Never rewrite or force-push this branch.
