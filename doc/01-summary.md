> [!NOTE]
> [agent] **This is the second architecture thread for socket-patch, and it is a living document.** It replaces [#560](https://github.com/SocketDev/socket-patch/discussions/560), which reviewed the code module by module and is now closed. Its open items are carried over in the register below and summarized in Part 6. Scheduled routines keep this post and its Parts true of `main`, and every run posts a log entry as a comment at the end of the thread.
>
> {{PROGRESS}}
>
> {{COVERAGE}}
>
> - **Register:** the first comment below tracks every problem with its issue and status.
> - **Parts:** 2 mechanisms · 3 duplication · 4 structure · 5 tests · 6 history.
> - **Log:** after Part 6, each routine run adds one comment saying which files it read, what it found and which PRs it opened.
> - **Work items:** [issues labelled `arch-audit`](https://github.com/SocketDev/socket-patch/issues?q=label%3Aarch-audit) · [refactor PRs labelled `arch-refactor`](https://github.com/SocketDev/socket-patch/pulls?q=label%3Aarch-refactor) · [decisions needed](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Aarch-audit+label%3Aagent%3Aneeds-human)
> - **Steering:** reply here or on an issue. Maintainer replies are read on the next run and can reject findings, reorder work or settle decisions.
>
> _Rendered {{UPDATED}} from `doc/` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch._

# socket-patch implementation review: file by file

_Started 2026-10-29 against `main` @ `b291caa`._

## Charter
The first thread asked what to cut and combine at the level of **products and modules**: modes × ecosystems × lockfile formats. This thread looks at the **implementation**: is each file's code as small, direct and honest as it can be? **Nothing in the codebase is precious.** The routines look for:

1. **Needless abstraction and tiny functions.** Single-caller functions are inlined unless their name earns its keep. One-line wrappers, one-impl traits, one-variant enums, forwarding layers and invariant-free newtypes are deleted.
2. **Duplicated business logic.** One rule should have one implementation (Part 3).
3. **Unclear control flow.** Mode flags, deep nesting, accumulate-then-decide result structs, swallowed-then-reraised errors.
4. **Placement.** Every function and type should live where a reader would look for it, and no two modules should cover the same concept (Part 4).
5. **Common mechanisms.** One way to handle errors, format output, read env and config, join paths, write files, call HTTP and spawn processes (Part 2).
6. **Comments.** History narration, restated code, stale text and bare issue numbers are deleted; *why* comments stay.
7. **Tests.** Tests that assert on their own mocks, recompute the expected value with the code under test, can't fail, or claim more than they check get fixed or deleted (Part 5).

## How it works
- `coverage/files.tsv` on the ledger branch lists every `.rs` file under `crates/`: **868 files, ~908K lines** at the start.
- **Two auditors** each read about 15K lines per run, in file order, and never change code:
  - `audit-core` covers `crates/socket-patch-core/src`;
  - `audit-cli-tests` covers the CLI crate and every test file.

  For each file they record its **local cleanups** (what to inline, delete or fix) in the manifest. Problems that span files go into the register and become `arch-audit` issues.
- **The `refactor` routine** alternates between two kinds of work:
  - **sweeps:** one PR per file or directory, applying the local cleanups, mostly deletions, with behavior unchanged;
  - **structural PRs:** the highest-leverage register item.
- When every file has been read once, the next pass starts with the files that changed most since they were last read.

## Top problems
_Filled in as the audit progresses. Each bullet carries its register token._

- **Duplicated rules have already drifted into bugs.**
  - The cargo build-cache cleaner and cargo disagree on which `.cargo/config` file wins {{A01}}.
  - The cargo workspace glob has no character classes {{A02}}.
  - Both bugs were shown by running the code.
- **`utils/` is a mix of ecosystem-specific code and true utilities.** Some of it imports `vendor::*` {{A08}}.
- **Shared helpers exist but are bypassed or dead.** A purl split is written ~12× {{A14}}, uuid shape 4× {{A15}}, and the shared poetry-writer and credential-strip helpers have no caller while copies serve production {{A18,A20}}.
- **CLI commands carry second copies of shared engines.** `get <uuid>` re-implements the agent download engine {{T01}}, five callers glue the Bun and vlt preflights by hand {{T05}}, and remove and rollback render vendored reverts in two drifted loops {{T16}}. The copies have drifted in user-visible text and JSON {{T02,T04}}.

## The numbers
| | Value |
|---|---|
| Rust files / lines (all crates, incl. tests) | 868 / 908,212 at `b291caa` |
| Largest file | `patch/redirect/mod.rs`, 30,223 lines |
| Files over 5,000 lines | _to measure_ |
| Single-caller private functions | _to measure (per file in the manifest notes)_ |
| Deletable comment lines | _to measure_ |
| Fake tests found / fixed | _to measure_ |
