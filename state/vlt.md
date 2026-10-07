[agent] Progress ledger for the scheduled vlt bug-hunt routine (label pm:vlt).

Last updated: 2026-10-07 (run 14), main `db83f01`, latest release 4.0.0 (no vlt support; previous 3.3.0). Newest vlt: 1.3.7 (2026-10-06; adds `vlt outdated` and a hidden-lock rule that reuses a reference node's `resolved` only when its tarball format matches the brotli flag; no lock-format change). Locally, run `vlt ci --allow-scripts :scripts` (otherwise vlt POSTs to api.socket.dev and the sandbox's 403 fails `ci` on 1.0.10 / 1.2.0; see #448). Run 9 mock adds `left-pad@1.2.0` (`'old'`) for bump tests. The run-11 mock adds a `time` map and `WDEP=` (wrapper's left-pad spec) for version-changing modifiers. The run-12 mock (rebuilt from the run-2 mock) adds `ADD=1` (the patch adds `lib/extra/deep/new.js`) and `EMPTYDIR=1` (the tarball ships empty dir entries), plus `CDN=1` and `bundler`. Run 14 mock (the run-2 mock from branch `bughunt/vlt/20261001-v5-rollback-3os`) adds `CDN=1` and `PKG=`. The sandbox has no `ss`, so poll ports with `/dev/tcp`. Wait for ports 18555/18556 to free up before restarting the mock: a stale mock silently serves the previous mode. Kill mocks with `pkill -f '^node .*mock[.]mjs'`: a bare path pattern also kills the calling shell.

Method: real vlt installs (`scripts/install-vlt.sh`) against a local Node mock of the npm registry plus the patch API. It's a pure-JS tar writer, so it runs on every OS. The registry is on :18555 and the patch server on :18556 via `SOCKET_PATCH_SERVER_URL`; set `SOCKET_NPM_REGISTRY` to the registry for v5 rollback. The oracle is `require('left-pad')` printing `patched` / `pristine`. The 3-OS probe scripts are in the run-2 workflow (run 36803186961), the run-3 global-mode workflow (run 36834317384) and the run-4 bundled-copy workflow (run 36871535059, whose mock adds a `bundler@1.0.0` that bundles left-pad). Run 6 mock adds `PKG=` (scoped names) and `CDN=1` (non-conventional `dist.tarball`); the patch artifact leaf must be the unscoped basename. The mock's `/patches/batch` must answer only for purls in the request body, or `scan -g` shows false hits. CI already runs the capstones and the native backtest on 57 releases × 3 OS.

## Coverage matrix

| OS | vlt | Hosted (scan / rollback / remove) | Vendored (+ takeover, rollback) | Agent | Notes |
| --- | --- | --- | --- | --- | --- |
| Linux | 1.0.0-rc.14 | pass (rollback byte-exact, era B 3-tuple) | untested (CI) | untested (CI) | CI native leg flaked once (`warmOrdinary`, PR #277 run), root cause blocked |
| Linux | 1.0.0-rc.32 | untested (resolves from npmjs; mock can't serve it) | untested (CI) | untested (CI) | |
| Linux | 1.0.10 | pass (incl. `config.registry` 3-tuple) | untested (CI) | untested (CI) | |
| Linux | 1.2.0 | pass | pass | pass | brotli: flag stays 0 |
| Linux | 1.3.0 | untested | untested | untested | vlt itself fails install against `tar.br` registries |
| Linux | 1.3.1 | fail #372 (brotli registries) before #820 | fail #372 before #820 | untested | |
| Linux | 1.3.2 | pass on npm-style registries; fail #372 with `tar.br` alternates | pass (workspaces incl. 4-deep, space/unicode dirs; takeover; repair; re-run idempotent); fail #372 with `tar.br` | pass (hardlinked store is copy-on-write) | |
| macOS | 1.2.0 / 1.3.2 | pass (probe run 2) | pass (probe run 2) | pass (probe run 2) | brotli untested |
| Windows | 1.2.0 / 1.3.2 | pass (probe run 2) | pass (probe run 2) | pass (probe run 2) | brotli untested |
| Linux / macOS / Windows | 1.3.3 | scan → `vlt ci` patched (probe run 3); peer-extra DepID across workspaces, alias / remote / file mix: pass (Linux, run 5); fail #372 with `tar.br` (Linux) | scan → `vlt ci` patched (probe run 3); frozen / vex / workspaces untested | pass (Linux, run 5: peer-extra store, workspaces, rollback, re-run) | new release, 2026-10-01 |
| Linux | 1.3.4 / 1.3.5 | pass (run-2 matrix; dev / optional flags; multi-instance `~peer.<hex>` ×2; lock mutation between scan and rollback); fail #372 with `tar.br` | pass (run-2 matrix, frozen, vex, dev / optional); bump / uninstall after scan: pass on main `b1f9818` (#541 fixed by #543, verified 1.2.0 / 1.3.5) | pass (incl. multi-instance peer store) | new releases |
| Linux | 1.0.10 / 1.2.0 / 1.3.3 | non-conventional `dist.tarball` rollback / remove: **fail #521** (run 6); scoped target scan / vex: pass (1.3.3) | scoped target: pass (1.3.3) | scoped target via store symlink: pass (1.3.3) | concurrent scans / SIGKILL mid-run: pass (1.3.3) |
| Linux | 1.0.0-rc.34 / 1.0.5 / 1.1.1 / 1.3.0 | pass (run-8 probe matrix; 1.3.0 without `tar.br`) | pass (run-8 probe matrix) | pass (run-8) | first local runs of these versions |
| Linux | 1.3.6 | run-2 matrix: pass (run 10); graph-modifier DepIDs (incl. `:semver()` / `:v()` selectors, plus a direct copy): pass; root peer+dev and peer-only: pass; #372 fixed by #820 (run 13); brotli rollback fails #941 | run-2 matrix: pass; modifier variant and peer-only root: refused `vendor_lock_entry_unsupported` (documented); peer+dev root: pass | run-2 matrix, modifier variant (+ direct copy), peer-only root: pass | new release |
| Linux | 1.2.0 / 1.3.6 | version-changing modifier (1.2.0→1.3.0 via `:root > #wrapper > #left-pad`): scan / ci / vex / rollback, plus `get` / `repair` / `remove` (1.3.6): pass (run 11); modifier down to 1.2.0 + direct 1.3.0: pass | modifier-up refused (documented); modifier-down + direct, workspace chain (b → a@workspace:* → target), catalog bump after vendoring: pass (1.3.6) | modifier up / down, re-run: pass | run 11 |
| Linux | 1.2.0 / 1.3.6 | run 12 (main `6811b4e`): #601 fixed; #521 still fails (cold `ci` 404); npm alias `lp`→left-pad: pass; pin survives `vlt install <other>` / `vlt uninstall <direct>`, rollback = fresh lock: pass; patch adds a file in a new dir: pass | alias, added-file: pass | added file in a new dir, rollback / remove prune exactly: pass; **added file under a shipped empty dir: fail #862** (rollback deletes the shipped dirs); linked workspace member of the same name@version refused (#634): pass, JSON gap is #424 | run 12 |
| Linux | 1.0.10 / 1.2.0 / 1.3.7 | run 14 (main `db83f01`): non-conventional `dist.tarball` rollback / remove (also scoped): pass when the vlt registry differs from `SOCKET_NPM_REGISTRY`, **fail #521 residual** when they're the same; scalar `config.registry` 3-tuple rollback: pass (1.0.10 / 1.3.7); #941 / #942 still fail | hosted pin kept when a vendored takeover is refused (transitive target, modifier variant): pass (#963, 1.3.7) | untested | run 14 |
| Linux | 1.3.7 | run-2 matrix: pass (run 13); brotli (`tar.br`) scan / warm + cold install / frozen / vex / mixed lock / dev node: pass (#372 fixed); brotli rollback / remove / takeover: **fail #941**; scan / `get` from a `vlt.json` workspace member: **fail #942** (also 1.2.0) | run-2 matrix, brotli: pass; rollback byte-exact | brotli lock: pass | new release |
| Linux | 1.3.5 | prerelease target, object-form workspace groups, `catalog:` specs, peer-shape `list` / `remove`: pass (run 8) | prerelease, object workspaces, `catalog:`, peer-shape takeover refusal: pass; named catalogs `catalog:<name>` in workspaces: pass (run 9, also 1.2.0) | prerelease, object workspaces, `catalog:`: pass | |

### Bundled copies (a package bundling the patched name@version; vlt-lock.json never records the bundled copy)

| OS | vlt 1.0.10 | vlt 1.2.0 | vlt 1.3.3 |
| --- | --- | --- | --- |
| Linux / macOS / Windows | hosted + vendored: **fail #471** before #472. Linux on main `b1f9818`: pass (skip warning, vex refuses) | same as 1.0.10 | same as 1.0.10 (1.3.5 also passes on Linux) |
| Linux (agent: bundled copy plus a normal install of the same name@version) | fail #601 before #605 | pass on main `6811b4e` (run 12) | fail #601 before #605 (1.3.6 passes on `6811b4e`) |

### Global mode (`-g`; vlt has no global install, so this is an npm global prefix with a vlt project in the cwd)

| OS | vlt | `scan -g` report | `-g` / `SOCKET_GLOBAL` / `--global-prefix` × `--mode hosted` refusal | agent apply / vex / rollback (`-g`, `get -g`, env) | `--global-prefix` with space + unicode | unwritable prefix | `rollback -g` / `remove -g` leave the project alone | `vendor -g` / `vendor --revert -g` leave the project alone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.10 / 1.2.0 / 1.3.3 | pass | pass | pass | pass | pass (scan); `get` re-run → npm handover | pass (#446; with a hosted project too, run 5) | pass after #499 (1.2.0 / 1.3.6, flags and env: exit 2 `global_scope_unsupported`, project kept; run 10) |
| macOS | 1.0.10 / 1.2.0 / 1.3.3 | pass | pass | pass | pass | pass (scan) | untested since #446 | untested |
| Windows | 1.0.10 / 1.2.0 / 1.3.3 | fail #434 (default prefix) | pass | fail #434 (default prefix) | pass | untested | untested since #446 | untested |

## Backlog

1. The #521 residual (same-mirror `SOCKET_NPM_REGISTRY`, [comment](https://github.com/SocketDev/socket-patch/issues/521#issuecomment-6039419242)) once it's fixed, then #941 (same restorer).
2. #941 / #942 once they're fixed (#942: object-form workspace groups, a nested `vlt.json`, a member with its own lock, `get` / `rollback` from a member).
3. #862 once it's fixed: shipped empty dirs, nested new dirs under a shipped dir, `remove`, macOS / Windows.
4. vlt 1.3.7 on the remaining cells: `~peer.<hex>` ×2 vex after #774, graph modifiers, catalogs, bundled copies.
5. vlt 1.3.6 / 1.3.7 on macOS / Windows (probe branches are blocked).
6. #434 (closed by #442): Windows with the default prefix. The rest of the **maintainer `-g` request** (20261001T040000Z): the Windows unwritable prefix, and the macOS / Windows re-check of `rollback -g` after #446 and of `vendor -g` after #499.
7. vlt 1.3.6+ `pickManifest` `time`-map skip: a packument with missing `time` entries against hosted pins and vendored specs.
8. Probe branches are blocked: branch deletion is denied, and 3 old `bughunt/vlt/*` branches still need a maintainer to delete them.

## Known non-bugs

- Hosted pins are recognized only on `patch.socket.dev` or `SOCKET_PATCH_SERVER_URL`. Against a mock without it, `rollback` says "Manifest not found" (documented).
- If the patch server shares the project registry's `config.registry` origin, vlt omits slot [3] on re-save and the pin becomes invisible. That's a mock artifact only.
- vlt re-saves CRLF locks as LF on any install (documented). socket-patch itself keeps `\r` through scan and rollback.
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
- Vendoring a `catalog:` member rewrites its spec to `file:`, so a later catalog bump doesn't move it until rollback restores `catalog:` (consistent with vendored owning the spec).
- Agent mode refuses a `node_modules` link to a first-party workspace member / `file:` dir that shares the patched name@version (#634, #626). That's intended. The missing failure count in `scan --json` is #424 (generic, not vlt).
- A rerun that "passes" right after switching mock modes can be a stale mock still bound to the port. That's a harness artifact.
- With a scalar `config.registry` (3-tuple lock) and a registry whose `dist.tarball` isn't conventional, vlt drops the URL and a cold `vlt ci` 404s even without socket-patch (vlt 1.0.10 … 1.3.7). That's vlt behavior.
- vlt 1.0.10 … 1.3.7 refuse to install with only a scalar `config.registry` ("Missing npm registry configuration"). Set `registries.npm` too.
