[agent] Progress ledger for the scheduled vlt bug-hunt routine (label pm:vlt).

Last updated: 2026-10-03 (run 10), main `045d7ec`, latest release 4.0.0 (no vlt support; previous 3.3.0). Newest vlt: 1.3.6 (2026-10-03; manifest-picking change only, no lock-format change). Locally, run `vlt ci --allow-scripts :scripts` (otherwise vlt POSTs to api.socket.dev and the sandbox's 403 fails `ci` on 1.0.10 / 1.2.0; see #448). Run 9 mock adds `left-pad@1.2.0` (`'old'`) for bump tests.

Method: real vlt installs (`scripts/install-vlt.sh`) against a local Node mock of the npm registry plus the patch API. It's a pure-JS tar writer, so it runs on every OS. The registry is on :18555 and the patch server on :18556 via `SOCKET_PATCH_SERVER_URL`; set `SOCKET_NPM_REGISTRY` to the registry for v5 rollback. The oracle is `require('left-pad')` printing `patched` / `pristine`. The 3-OS probe scripts are in the run-2 workflow (run 36803186961), the run-3 global-mode workflow (run 36834317384) and the run-4 bundled-copy workflow (run 36871535059, whose mock adds a `bundler@1.0.0` that bundles left-pad). Run 6 mock adds `PKG=` (scoped names) and `CDN=1` (non-conventional `dist.tarball`); the patch artifact leaf must be the unscoped basename. The mock's `/patches/batch` must answer only for purls in the request body, or `scan -g` shows false hits. CI already runs the capstones and the native backtest on 57 releases × 3 OS.

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
| Linux / macOS / Windows | 1.3.3 | scan → `vlt ci` patched (probe run 3); peer-extra DepID across workspaces, alias / remote / file mix: pass (Linux, run 5); fail #372 with `tar.br` (Linux) | scan → `vlt ci` patched (probe run 3); frozen / vex / workspaces untested | pass (Linux, run 5: peer-extra store, workspaces, rollback, re-run) | new release, 2026-10-01 |
| Linux | 1.3.4 / 1.3.5 | pass (run-2 matrix; dev / optional flags; multi-instance `~peer.<hex>` ×2; lock mutation between scan and rollback); fail #372 with `tar.br` | pass (run-2 matrix, frozen, vex, dev / optional); bump / uninstall after scan: pass on main `b1f9818` (#541 fixed by #543, verified 1.2.0 / 1.3.5) | pass (incl. multi-instance peer store) | new releases |
| Linux | 1.0.10 / 1.2.0 / 1.3.3 | non-conventional `dist.tarball` rollback / remove: **fail #521** (run 6); scoped target scan / vex: pass (1.3.3) | scoped target: pass (1.3.3) | scoped target via store symlink: pass (1.3.3) | concurrent scans / SIGKILL mid-run: pass (1.3.3) |
| Linux | 1.0.0-rc.34 / 1.0.5 / 1.1.1 / 1.3.0 | pass (run-8 probe matrix; 1.3.0 without `tar.br`) | pass (run-8 probe matrix) | pass (run-8) | first local runs of these versions |
| Linux | 1.3.6 | run-2 matrix: pass (run 10); graph-modifier DepIDs (incl. `:semver()` / `:v()` selectors, plus a direct copy): pass; root peer+dev and peer-only: pass; #372 still fails with `tar.br` | run-2 matrix: pass; modifier variant and peer-only root: refused `vendor_lock_entry_unsupported` (documented); peer+dev root: pass | run-2 matrix, modifier variant (+ direct copy), peer-only root: pass | new release |
| Linux | 1.3.5 | prerelease target, object-form workspace groups, `catalog:` specs, peer-shape `list` / `remove`: pass (run 8) | prerelease, object workspaces, `catalog:`, peer-shape takeover refusal: pass; named catalogs `catalog:<name>` in workspaces: pass (run 9, also 1.2.0) | prerelease, object workspaces, `catalog:`: pass | |

### Bundled copies (a package bundling the patched name@version; vlt-lock.json never records the bundled copy)

| OS | vlt 1.0.10 | vlt 1.2.0 | vlt 1.3.3 |
| --- | --- | --- | --- |
| Linux / macOS / Windows | hosted + vendored: **fail #471** before #472. Linux on main `b1f9818`: pass (skip warning, vex refuses) | same as 1.0.10 | same as 1.0.10 (1.3.5 also passes on Linux) |
| Linux (agent: bundled copy plus a normal install of the same name@version) | **fail #601** | **fail #601** | **fail #601** (1.3.5 too; pnpm 10.28 too). Bundled-only: pass |

### Global mode (`-g`; vlt has no global install, so this is an npm global prefix with a vlt project in the cwd)

| OS | vlt | `scan -g` report | `-g` / `SOCKET_GLOBAL` / `--global-prefix` × `--mode hosted` refusal | agent apply / vex / rollback (`-g`, `get -g`, env) | `--global-prefix` with space + unicode | unwritable prefix | `rollback -g` / `remove -g` leave the project alone | `vendor -g` / `vendor --revert -g` leave the project alone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.10 / 1.2.0 / 1.3.3 | pass | pass | pass | pass | pass (scan); `get` re-run → npm handover | pass (#446; with a hosted project too, run 5) | pass after #499 (1.2.0 / 1.3.6, flags and env: exit 2 `global_scope_unsupported`, project kept; run 10) |
| macOS | 1.0.10 / 1.2.0 / 1.3.3 | pass | pass | pass | pass | pass (scan) | untested since #446 | untested |
| Windows | 1.0.10 / 1.2.0 / 1.3.3 | fail #434 (default prefix) | pass | fail #434 (default prefix) | pass | untested | untested since #446 | untested |

## Backlog

1. vlt 1.3.6 on macOS / Windows, plus 1.3.5 frozen / workspaces / catalog cells there (probe branches are blocked).
2. #601 on macOS / Windows, with a bundled copy at a different version and a nested bundle; re-test once #605 merges.
3. #521 follow-ups: re-test once fixed, macOS / Windows, the 3-tuple (`config.registry`) project, and the hosted→vendored takeover with a non-conventional tarball.
4. #434 (closed by #442): Windows with the default prefix. The rest of the **maintainer `-g` request** (20261001T040000Z): the Windows unwritable prefix, and the macOS / Windows re-check of `rollback -g` after #446 and of `vendor -g` after #499.
5. #372 follow-ups once fixed: a mixed brotli / non-brotli lock, a brotli dev node (flag 6) heal, the restore putting bit 4 back, and VEX on brotli nodes.
6. A version-changing graph modifier (hosted / agent), which needs a second left-pad version in the mock.
7. Vendored + `vlt update` after a catalog bump.
8. The vlt 1.3.4 tarball-cache integrity changes: a warm cache with pristine bytes at a reused patch URL.
9. Perf: #579 (vlt/hosted wall +127% after #472) isn't a bughunt issue; just watch it.
10. Probe branches are blocked: branch deletion is denied, and 3 old `bughunt/vlt/*` branches still need a maintainer to delete them.

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
- vlt has no global install surface (no `vlt install -g`, as of 1.0.10 … 1.3.3). `-g` only covers npm/pnpm/yarn/bun globals.
- `vex -g` in a hosted or vendored project attests the cwd project's patches (the project is the VEX product). That's deliberate per `commands/vex.rs:1013` (cwd ledgers gate discovery under `--global`).
- A `-g` "unwritable prefix" test needs files the user doesn't own: socket-patch may chmod files it owns.
- vlt-lock.json has no node for a bundled copy (1.0.10 … 1.3.3). That's vlt's format, not a socket-patch parse bug. The bug is #471 (not detecting it).
- vlt 1.0.10 `vlt ci` fails EINTEGRITY on a `remote~` (tarball URL) dependency whenever vlt's machine cache is warm, with or without socket-patch. It's a vlt bug that's gone by 1.2.0.
- vlt dedupes a peer-dependent package to one `~peer.<hex>` instance across workspaces when the peer range is `*`, even with different peer versions installed.
- A mock patch artifact whose leaf keeps the scope (`@sc/name-ver.tgz`) is refused as `patched_ref_invalid`. The real service uses the unscoped leaf, so that's a mock artifact.
- Concurrent socket-patch runs in one directory: the losers fail with "Another socket-patch process is operating in this directory" (`.socket/apply.lock`, `--lock-timeout`). That's by design.
- Vendored refuses a target with several `~peer.<hex>` instances (`vendor_lock_entry_unsupported`, "peer/modifier variants; use --mode hosted"). That's loud and fail-closed. Hosted and agent handle the shape.
- `vex` exits 1 after the vendored target was bumped away: nothing patched is installed, so that's correct.
- A hosted scan deletes the stale installed store copies, including every `~peer.<hex>` instance, so `require` fails until `vlt install` / `vlt ci`. That's documented, and the scan prints a warning.
- vlt 1.0.0-rc.14 full-probe rollback mismatches against the mock because rc.14 resolves left-pad from public npmjs. That's a mock artifact.
- vlt `ci` / `install` with a cold machine cache fails "Failed to fetch security data" (403 `host_not_allowed` to api.socket.dev) in the sandbox. That's a sandbox artifact; use `--allow-scripts :scripts`.
- Agent-mode patches disappear after `rm -rf node_modules && vlt ci`. That's expected: a reinstall replaces agent edits.
- Vendored refuses graph-modifier variants (`~<selector>` DepID suffix) and root peer-only edges with `vendor_lock_entry_unsupported` ("use --mode hosted"). That's loud and fail-closed; hosted and agent handle both.
- Vendored `rollback` after a refused vendored scan returns "Manifest not found": nothing was written.
