> [!NOTE]
> [agent] **This is the third architecture thread for socket-patch.** It replaces [#1830](https://github.com/SocketDev/socket-patch/discussions/1830) (file-by-file sweeps, now closed), which replaced [#560](https://github.com/SocketDev/socket-patch/discussions/560) (module-level review). Both are archived on the ledger branch under `review/`.
>
> {{PROGRESS}}
>
> - **Register:** the first comment below lists the PRs in flight and merged, the leads being verified, and the areas examined.
> - **Log:** each routine run adds one comment: what it chose and why, the evidence, and the PR.
> - **Work items:** [refactor PRs labelled `arch-refactor`](https://github.com/SocketDev/socket-patch/pulls?q=label%3Aarch-refactor) · [issues labelled `arch-audit`](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Aarch-audit) · [decisions needed](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Aarch-audit+label%3Aagent%3Aneeds-human)
> - **Steering:** reply here. The routine reads maintainers' replies at the start of each run.
>
> _Rendered {{UPDATED}} from `doc/` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch._

# socket-patch architecture refactor: real problems only

_Started 2026-11-25._

## Charter
A scheduled routine improves socket-patch's structure, **one real problem per PR**. Each PR shows the problem on `main` with a failing test or a command's output, and shows it gone after the fix. A problem counts when it is one of these:

1. **Drifted duplicates:** copies of one rule that already give different answers for inputs real projects produce.
2. **Errors that lie:** a dropped or downgraded error that leads to a false success, a false VEX statement, a half-written file, or wrong advice to the user.
3. **Mechanism bugs users can see:** `--json`/`--silent` handled two ways, leaked credentials, wrong exit codes, `--cwd` ignored.
4. **Tests that can't catch what they claim:** shown by breaking the behavior and watching the test still pass.
5. **Structure that keeps causing bugs:** the same class of bug already fixed in one copy and still live in another.

These aren't enough on their own: inlining, wrappers, comments, naming, moving code, helper copies that still agree, and line counts. They are welcome only inside code a real fix already touches.

A run that finds nothing worth fixing records what it examined and opens no PR. At most 3 of the routine's PRs are open at a time, because a person reviews every one.

The full procedure is [`REFACTOR.md`](https://github.com/SocketDev/socket-patch/blob/arch-audit/ledger/REFACTOR.md) on the ledger branch.
