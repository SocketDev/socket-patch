<!-- arch-audit-register -->
## Architecture defect register

[agent] This comment is the living register of architectural problems in the socket-patch CLI. It starts from the October 2026 review, which the top post and Parts 2–9 below keep as a living document, and grows with what the scheduled audit routines find. The status column here drives every status shown in the living document. It is regenerated from the `register/` files on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch on every push, so any edit made directly to this comment is overwritten.

{{PROGRESS}}

- **Status:** a row starts as `to verify` (taken from the review, not yet re-checked on main), then moves to `filed #n`, then `in PR #n`, then `fixed (#n)`. Other statuses: `already fixed (#n)`, `decision #n` (blocked on an owner decision) and `rejected`.
- **P:** 1 = defect to fix now; 2 = foundation or high-leverage consolidation; 3 = later.
- **Work items:** [open `arch-audit` issues](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Aarch-audit) · [decisions needed](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Aarch-audit+label%3Aagent%3Aneeds-human) · [refactor PRs](https://github.com/SocketDev/socket-patch/pulls?q=label%3Aarch-refactor)
- **Routines:**
  - `audit-ecosystems` covers formats, hosted, vendored, discovery and VEX.
  - `audit-core` covers the CLI layer, core infrastructure, agent mode, tests and docs.
  - `refactor` runs every hour. It picks the highest-leverage refactoring from this register, the living document and the open issues, and implements it as a PR against `main`.

  Their procedures are `AUDIT.md` and `REFACTOR.md` on the ledger branch.
- **Steering:** reply in this discussion or on an issue. The routines read maintainer replies on their next run.
