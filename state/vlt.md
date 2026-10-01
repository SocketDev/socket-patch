[agent] Progress ledger for the scheduled vlt bug-hunt routine (label pm:vlt).

Last updated: 2026-10-01 (run 2), main `2463257` (v5 consolidation, #277), latest release 4.0.0 (no vlt support; previous 3.3.0).

Method: real vlt installs (`scripts/install-vlt.sh`) against a local Node mock of the npm registry plus the patch API. It's a pure-JS tar writer, so it runs on every OS. The registry is on :18555 and the patch server on :18556 via `SOCKET_PATCH_SERVER_URL`; set `SOCKET_NPM_REGISTRY` to the registry for v5 rollback. The oracle is `require('left-pad')` printing `patched` / `pristine`. The 3-OS probe script is in the run-2 workflow (run 36803186961). CI already runs the capstones and the native backtest on 57 releases × 3 OS.

## Coverage matrix

| OS | vlt | Hosted (scan / rollback / remove) | Vendored (+ takeover, rollback) | Agent | Notes |
| --- | --- | --- | --- | --- | --- |
| Linux | 1.0.0-rc.14 | pass (rollback byte-exact, era B 3-tuple) | untested (CI) | untested (CI) | CI native leg flaked once (`warmOrdinary`, PR #277 run), root cause blocked |
| Linux | 1.0.0-rc.32 | untested (resolves from npmjs; mock can't serve it) | untested (CI) | untested (CI) | |
| Linux | 1.0.10 | pass (incl. `config.registry` 3-tuple) | untested (CI) | untested (CI) | |
| Linux | 1.2.0 | pass | pass | pass | brotli: flag stays 0 |
| Linux | 1.3.0 | untested | untested | untested | vlt itself fails install against `tar.br` registries |
| Linux | 1.3.1 | fail #372 (brotli registries) | fail #372 | untested | |
| Linux | 1.3.2 | pass on npm-style registries; fail #372 with `tar.br` alternates | pass (workspaces incl. 4-deep, space/unicode dirs; takeover; repair; re-run idempotent); fail #372 with `tar.br` | pass (hardlinked store is copy-on-write) | |
| macOS | 1.2.0 / 1.3.2 | pass (probe run 2) | pass (probe run 2) | pass (probe run 2) | brotli untested |
| Windows | 1.2.0 / 1.3.2 | pass (probe run 2) | pass (probe run 2) | pass (probe run 2) | brotli untested |

## Backlog

1. **Maintainer request:** test global (`-g`) mode for hosted patches on Linux, macOS and Windows across every major vlt version. `scan -g` must report exactly the global installs that have hosted patches; `-g --mode hosted` must refuse loudly; `-g` apply, rollback and vex must hit the real global copy. Full checklist in the 20261001T040000Z entry on this discussion.
2. v5 upstream restore against a registry with non-conventional `dist.tarball` (Artifactory scoped `/-/@scope/name-ver.tgz`). The restore rebuilds slot [3] conventionally and takes integrity from `SOCKET_NPM_REGISTRY`, not the project registry.
3. #372 follow-ups once fixed: a mixed brotli / non-brotli lock, a brotli dev node (flag 6) heal, the restore putting bit 4 back, and VEX on brotli nodes.
4. Peer-extras DepIDs (two instances of one name@version) through hosted scan → `remove`.
5. Concurrent or interrupted `scan` / `rollback` on vlt projects.
6. Root-cause the intermittent CI `native (ubuntu, rc.14) hosted-direct warmOrdinary` failure if it recurs (needs the result artifact, which the sandbox can't download).
7. Once vlt 1.3.x lands in CI's matrix, drop it from the probe.

## Known non-bugs

- Hosted pins are recognized only on `patch.socket.dev` or `SOCKET_PATCH_SERVER_URL`. Against a mock without it, `rollback` says "Manifest not found" (documented).
- If the patch server shares the project registry's `config.registry` origin, vlt omits slot [3] on re-save and the pin becomes invisible. That's a mock artifact only.
- vlt re-saves CRLF locks as LF on any install (documented). socket-patch itself keeps `\r` through scan and rollback.
- `scan <member-dir>` in hosted mode scans the member as its own project (contract: "as if it were `--cwd`"), so a workspace member with no lock redirects nothing (`redirect_npm_no_lockfile`, rc 0; the human output says "Switched 0").
- Vendored refuses a package entirely when any instance is on a named non-default registry (`vendor_lock_entry_unsupported`). That's loud and fail-closed.
- vlt 1.0.0-rc.14 / rc.32 resolve from public npmjs despite `registries.npm`.
- The nightly canary failure "vlt 1.3.x is published but neither supported nor excluded" is the docs Releases table lagging new vlt releases.
- `vendor_vlt_transitive_unsupported` for a target that is also a transitive dep is documented and fail-closed.
- vlt 1.3.0 fails `vlt install` with "Integrity check failure" against registries advertising `tar.br` alternates (a vlt bug, fixed in 1.3.1).
- Sandbox: the Rust binaries can't reach npmjs through the TLS proxy (serve version docs locally), vlt's cold-cache "security data" fetch fails, vlt's machine cache must be isolated per mock change (XDG/HOME), the Actions artifact/log blob host is blocked, and the git proxy drops branch deletions.
- Release 4.0.0 reports `redirect_npm_no_lockfile` on vlt projects: it predates vlt support.
