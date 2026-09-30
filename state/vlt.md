[agent] Progress ledger for the scheduled vlt bug-hunt routine (label pm:vlt).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0 (which has no vlt hosted/vendored support; previous 3.3.0).

Method: real vlt installs (`scripts/install-vlt.sh`) against a local Node mock of the npm registry plus the patch API (`mock.mjs` in the run-1 entry), plus the repo's real-vlt capstones (`--include-ignored vlt_pinned_matrix` + `scripts/check-vlt-legs.py`). The oracle is `require('left-pad')` printing `patched` / `pristine`. CI already runs the capstones on 57 releases × 3 OS (vlt-compatibility.yml, ci.yml). This ledger tracks what CI doesn't: new releases, registry features, odd project shapes.

## Coverage matrix

| OS | vlt | Hosted | Vendored | Agent | Capstones (5 suites) | Brotli `tar.br` registry |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.0-rc.14 / 1.0.10 | untested (CI) | untested (CI) | untested (CI) | CI | n/a |
| Linux | 1.2.0 | untested (CI) | untested (CI) | untested (CI) | CI | pass (flag stays 0) |
| Linux | 1.3.0 | untested | untested | untested | untested | vlt itself fails install |
| Linux | 1.3.1 | untested | untested | untested | pass (nightly canary) | fail #372 |
| Linux | 1.3.2 | pass (direct, direct+transitive) | pass (root, workspaces incl. space/unicode dirs, revert byte-exact; transitive refused as designed) | pass | pass (run 1) | fail #372 (hosted, vendored); agent pass |
| macOS | 1.3.x | untested | untested | untested | untested (canary only for latest) | untested |
| Windows | 1.3.x | untested | untested | untested | untested (canary only for latest) | untested |

## Backlog

1. #372 follow-ups: a mixed brotli / non-brotli lock (per-dep refusal wording); a brotli dev node (flag 6) heal (`reinstalls_after_removal`); VEX discovery on brotli nodes.
2. Probe branch: vlt 1.3.2 capstones on macOS and Windows, plus `store-linker` hardlink/copy/unpack on 1.3.2.
3. Workspaces nested ≥ 3 deep; member → member → target chains (member-transitive refusal).
4. `vlt install --lockfile-only` checkouts through hosted/vendored → `vlt ci`.
5. vlt 0.0.0-x / rc era locks with odd package names (uppercase, `_`, `~`, scoped with `+`) through the hosted slot rewrite.

## Known non-bugs

- The nightly canary failure "vlt 1.3.x is published but neither supported nor excluded" is the docs Releases table lagging new vlt releases. It's not a code bug (capstones pass on 1.3.1/1.3.2).
- `vendor_vlt_transitive_unsupported` for a target that is also a transitive dep is documented and fail-closed (lock untouched).
- vlt 1.3.0 fails `vlt install` with "Integrity check failure" against registries advertising `tar.br` alternates. That's vlt's bug, fixed in 1.3.1.
- Sandbox: the Rust capstone harness can't fetch npmjs through the TLS proxy. Prefill `/tmp/socket-patch-test-caches/vlt-e2e-registry/v1/`. The patch API mock needs `blobContent` in views and `/patches/blob/<hash>` for vendored mode.
- Release 4.0.0 reports `redirect_npm_no_lockfile` on vlt projects: it predates vlt support.
