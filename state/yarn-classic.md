[agent] Progress ledger for the scheduled Yarn classic (1.x) bug-hunt routine (label pm:yarn-classic).

Last updated: 2026-10-01 (run 2), main `f6b7fb9`, latest release v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N", "n/a", "CI" or "untested". H = hosted, V = vendored, A = agent (`scan --apply` + `setup`). Each H/V cell ends with a real fresh-checkout `yarn install --frozen-lockfile`, using a local mock patch API. CI's `yarn-classic-matrix` (1.0.2, 1.6.0, 1.7.0, 1.9.4, 1.10.1, 1.22.22) covers the plain single-dep H/V flows plus VEX on Linux.

| OS | yarn | H baseline | H offline mirror | H/V git dep (`git+…`) | H/V multi-version workspaces + scoped | H⇄V takeover + rollback | H/V CRLF lock + rollback | V baseline | V offline mirror (+pruning, rollback) | A apply + setup |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.2 | pass | n/a (yarn limitation) | fail #363 | H pass | untested | untested | n/a (yarn ≤1.6 can't install `file:` tarballs) | n/a | pass |
| Linux | 1.6.0 | pass | n/a (yarn limitation) | untested | H pass | untested | untested | n/a (yarn ≤1.6) | n/a | untested |
| Linux | 1.7.0 | CI | fail #364 (`--offline`) | fail #363 | pass | untested | untested | pass | untested | untested |
| Linux | 1.9.4 | CI | fail #364 (`--offline`) | untested | untested | untested | untested | CI | untested | untested |
| Linux | 1.10.1 | pass | fail #364 | fail #363 | pass | pass | untested | pass | pass | pass |
| Linux | 1.17.3 | pass (in-place) | fail #364 | untested | untested | untested | untested | pass (in-place) | untested | untested |
| Linux | 1.22.22 | pass | fail #364 | fail #363 | pass | pass | pass | pass | pass | pass |
| macOS | 1.7.0 | untested | untested | fail #363 | pass | pass | pass | pass | untested | untested |
| macOS | 1.10.1 / 1.22.22 | pass (probe) | fail #364 | fail #363 | pass | pass | pass | pass | untested | untested |
| Windows | 1.7.0 / 1.10.1 / 1.22.22 | pass (probe) | fail #364 (1.10.1/1.22.22) | fail #363 (vendored: `Couldn't find the binary git`) | pass | pass | pass | pass | untested | untested |

Other cells that pass on Linux 1.22.22 (some also on older releases; see the entries): spaces + unicode project paths (also macOS and Windows), `npm:` alias (H skipped as documented, V rewired), `resolutions`, a `resolved` without the `#sha1` fragment / `integrity`, a local `file:` tarball dep, a non-deduplicated lock, a superseding patch on re-scan, `remove` / `repair`, VEX (installed and lock-only, after `yarn upgrade`), `yarn add` then a frozen reinstall (1.7.0 too), `yarn check --integrity` / `--verify-tree`, in-place reinstalls on 1.7–1.22, concurrent scans (`lock_held`), the GitHub shorthand dep on all 3 OSes.

## Backlog

1. Yarn ≤ 1.6 pin signals (`.yarnrc yarn-path`, `packageManager: yarn@1.x`, `engines.yarn`): does vendored mode warn or refuse? Decide whether "success, then empty node_modules" is worth a docs or refusal issue.
2. Interrupted runs (SIGKILL mid-rewrite) and recovery; `--dry-run` byte-identity on CRLF / BOM locks.
3. `get <uuid> --mode vendored|hosted` targeting one version of a multi-version package; `scan --prune` / `--sync` after `yarn remove`.
4. `.yarnrc` `--install.frozen-lockfile true`, `--pure-lockfile`, and locks produced by `yarn import`.
5. `optionalDependencies` / platform-skipped (lock-only) packages in both modes and VEX.
6. Older yarn on macOS / Windows (1.0.2 hosted), and 1.9.4 / 1.17.3 on the probe matrix.

## Known non-bugs

- `patches-api.socket.dev` isn't used here. Use a local mock API (`--api-url`). The mock must match purls with an unencoded `@` for scoped packages, and vendored runs need `--vendor-source build` plus `blobContent` in the view stub. For hosted `vex` on lock-only checkouts, pass `--patch-server-url <mock>` (CLI_CONTRACT "Patch hosts"); otherwise `package_not_found` is expected.
- **yarn 1.0.2 – 1.6.x install nothing (exit 0, empty node_modules) for `file:` tarball lock entries and offline-mirror installs, even without socket-patch.** Bisected in run 2: Node 10.24.1 / 14.21.3 / 16.20.2 / 22 all behave the same, and 1.7.0 works on all of them. The cause is in yarn, not Node or socket-patch, which is why CI reports `KNOWN LIMITATION` for vendored ≤ 1.6. Not in docs/ecosystems.md.
- An `npm:` alias entry is left unpatched in hosted mode with `redirect_yarn_classic_alias_skipped` (documented), and `vex` omits the package.
- A BOM plus no yarn header comment makes the first entry `entry_not_found`. Yarn always writes the header, so this is synthetic.
- `file:` directory and `link:` deps are skipped by design. (`file:` **tarball** deps are rewired and work.)
- The GitHub shorthand `owner/repo#tag` locks as a codeload tarball and is correctly rewired; only `git+…` patterns are #363.
- Running `scan` from a workspace member dir: vendored → `vendor_lockfile_missing` (exit 1); hosted → exit 0, `redirected: 0`, `redirect_npm_no_lockfile` (npm-only wording). This is the documented hosted refusal posture.
- hosted→agent / vendored→agent keep the existing wiring (`hosted_wiring_retained` / `vendored_ownership_retained`), as documented.
- Concurrent scans: the extras fail with `lock_held` (intended).
- Probe branches can't be deleted from the sandbox (the git proxy rejects ref deletion). Leftovers: `bughunt/yarn-classic/20260930-mirror-git`, `bughunt/yarn-classic/20261001-win-crlf-git`.
