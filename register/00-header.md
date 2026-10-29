<!-- arch-audit-register -->
## Defect register

[agent] This comment is the living register for this thread. It is regenerated from the `register/` files on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch on every push, so any edit made directly to it is overwritten. Its Status column drives every status shown in the Parts.

{{PROGRESS}}

{{COVERAGE}}

- **Status:**
  - The normal path is `to verify` → `filed #n` → `in PR #n` → `fixed (#n)`.
  - Rows carried over from #560 start as `carried` while one of their issues is still open.
  - Other statuses: `partly fixed (#n)`, `already fixed (#n)`, `decision #n`, `handed off` and `rejected`.
- **P:** 1 = fix now; 2 = high-leverage simplification; 3 = later.
- **IDs:** `A` = core audit, `T` = CLI and tests audit, `R` = found by the refactor routine, `E`/`C` = carried over from #560.
- **Routines:**
  - `audit-core` and `audit-cli-tests` read the code file by file, every 6 hours, staggered.
  - `refactor` runs every 2 hours and opens sweep or structural PRs.

  Their procedures are `AUDIT.md` and `REFACTOR.md` on the ledger branch.
