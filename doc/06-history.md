## Part 6: History — what carried over from #560

The first thread, [#560](https://github.com/SocketDev/socket-patch/discussions/560) (2026-10-01 to 2026-10-09, 151 comments), reviewed the code module by module. Its living document, register, procedures and run entries are archived read-only under `review/2026-10-v1/` on the ledger branch, and the original snapshot under `review/2026-10/`.

**Carried over:** every row that wasn't fixed, already fixed, rejected or handed off. These are 54 ecosystem and format rows (`E`) and 47 CLI, core and test rows (`C`), with their issue links. Each one is `carried` while one of its issues or PRs is still open, and `to verify` when none is. The auditors reconcile a few each run against current `main`, and an item that no longer fits this charter is rejected with a reason.
- Ecosystems and formats: {{E04,E05,E10,E12,E14,E15,E16,E19,E20,E21,E22,E24,E26,E28,E29,E30,E31,E32,E33,E36,E37,E40,E41,E42,E43,E44,E45,E46,E47,E50,E52,E58,E63,E64,E65,E68,E69,E71,E72,E75,E79,E80,E81,E82,E83,E84,E86,E87,E90,E91,E93,E94,E95,E96}}
- CLI, core and tests: {{C05,C09,C10,C11,C12,C13,C15,C16,C17,C18,C19,C20,C23,C24,C25,C26,C29,C30,C31,C32,C33,C34,C38,C41,C43,C45,C47,C48,C50,C51,C54,C56,C59,C60,C61,C67,C68,C69,C70,C71,C72,C73,C74,C75,C76,C78,C79}}

**What #560 concluded** (its TL;DR as of 2026-10-09; the numbers are from then):


1. **socket-patch is a product matrix implemented cell by cell.** The matrix is **3 modes × 9 ecosystems × ~25 package-manager and lockfile generations × 6 operations** (discover, apply/wire, verify, attest, revert, mode-takeover). There is no shared abstraction on any axis:
   - no lockfile codec;
   - no mode backend;
   - no vendor-backend trait;
   - no hosted-rewriter trait;
   - no single inventory.

   Each cell is hand-written text surgery. As a result, the same file format is parsed and spliced **two to five times** with different rules, and those rules have already drifted. For example, there are five different CRLF policies for the npm lockfile family alone.

2. **Most of the open bug backlog has one shape: "reported success, but the build consumes unpatched code".** Of the 88 issues open at the snapshot, roughly 29 were a success or a `not_affected` VEX attestation that the installed bytes don't back up (about 46 such false attestations are open on 2026-10-07; #1033 and #940 address the largest groups). Another 15 were discovery missing what the package manager actually installed. The root cause is architectural:
   - the tool **re-implements package-manager behavior** (install layouts, venv naming, config layering, resolution precedence);
   - it then **reports success based on its own model of what the package manager will do**;
   - every package-manager release or config knob it doesn't model becomes a silent false negative.

3. **Support breadth has outrun the architecture.** The long tail is disproportionately expensive:

   | Long-tail target | Cost |
   |---|---|
   | vlt | ~6.5K production lines, ~22K total, ~123 CI jobs per push |
   | JVM (Maven/Gradle) | ~9K production lines, 22 of the 88 open bugs |
   | `bun.lockb` | ~2.8K production lines for a format Bun itself replaced |
   | vendored pnpm 7/8 | 1.85K lines, ~96% a copy of the v9 backend |

   **A support-tier policy would let the core get simpler.**

4. **The code is large for what it does, and much of the size is duplication and scaffolding.**
   - ~134K lines of production code on `9c43dfc` (~118K at the snapshot, plus 35K comment lines then).
   - ~450K lines of tests.
   - Nine functions over 500 lines; `run_scan` alone is 1,540 (on `045d7ec`).
   - A 21.9K-line `redirect/mod.rs` on `db83f01` (17.5K at the snapshot). 
   - Two hosted orchestrators kept equal by parity tests.
   - Four discovery systems.
   - Nine different revert mechanisms. 
   - Two JSON envelope shapes, 27 global flags silently accepted by every command, and 156 documented error codes.

   **We estimate 25–35K production lines (20–30%) and 50K+ test lines could go.** Roughly 20K of that comes from consolidation that keeps every capability; the rest comes from the support-tier and product decisions in §5.

5. **The user model is harder than it needs to be.** It has:
   - 9 verbs, 2 hidden subcommands, 2 aliases and 3 hidden flag spellings;
   - defaults that change with unrelated flags;
   - `scan` writing lockfiles by default;
   - mode that is not project state: a plain `scan` performs the documented "mode takeover" and switches vendored npm, Cargo, Go, PyPI and Gradle-built Maven packages back to hosted (made atomic in #1039, E70);
   - `remove`, `rollback` and `vendor --revert` as three ways to undo.

   A seven-verb model (`scan` read-only, `fix`, `undo`, `sync`, `check`, `list`, `vex`) with mode inferred from the project would cover everything (§4).

6. **There are a few real defects to fix now** (§1), regardless of any refactor:
   - no HTTP timeouts on the main API client (fixed, #581);
   - a ledger-loss bug in the vendored→hosted takeover (fixed, #708);
   - a planted-binary spawn (fixed, #617);
   - a comment-blind NuGet config reader (fixed, #597);
   - a stale digest ratchet that turned `main` red for every PR (fixed, #1016; a merge queue follows in #1018).

   The October 7 audit added credential leaks (C59), `.socket` containment (C60) and the non-atomic takeover (E70); each has a PR. `SOCKET_FORCE` (#615, PR #1021) and the `bun.lockb` registry override (E02, fixed by #574) are no longer open defects.

---

