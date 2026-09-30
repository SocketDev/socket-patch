[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-09-30 (run 1 with a ledger), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0, both from npm `@socketsecurity/socket-patch`).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`, the shape `tests/e2e_vendor_npm_build.rs` uses). Hosted cells use a local Python mock of the patch API (batch, by-package, `patches/package` grant, `patches/view`, and the tarball route, modelled on `tests/e2e_redirect_npm_build.rs`), then run a fresh-checkout `npm ci` plus `vex`. An earlier, ledger-less run filed #324, #325 and #326.

| OS | npm | Agent (apply / scan --apply) | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (alias) | untested (v1 refusal is documented) | untested | untested |
| Linux | 8.19.4 | fail #356 (alias) | untested | untested | untested |
| Linux | 10.9.7 | pass: workspace nested copies, bundled copies. fail #356 (alias + VEX), fail #359 (linked strategy) | pass: workspace nested entry, `npm ci`, `npm install`, `npm install <pkg>` keep the vendored entry. fail #325, #326, #324 (earlier run) | pass: `npm install`, `npm install <pkg>`. `npm update` unwires it and `vex` reports `redirect_unwired` | pass (postinstall + `dependencies` hooks re-patch on `npm ci`; CRLF + tab + existing scripts round-trip byte-exact through `setup --remove`) |
| Linux | 11.20.0 | untested | untested | untested | untested |
| Linux | 12.1.0 | pass: workspace nested copies, bundled copies, direct dep through a `.store` symlink. fail #356 (alias + VEX), fail #359 (linked strategy: transitive copies in `.store`) | pass: workspace nested entry, `npm install` keeps the entry. fail #359 (linked: `vendor` can't find the transitive copy) | pass: workspace member nested entry + fresh `npm ci` + `vex`; `.npmrc` auto-config with user-config `all`, env `all`; respected env `root` and user-config `none` (loud warning, EALLOWREMOTE on a fresh install, documented); rollback after `npm update` | pass (postinstall hook via `npx` on `npm ci`) |
| macOS | 10.9.4 / 12.1.0 | fail #356 (alias + VEX), fail #359 (linked), probe run 36758644937 | untested | untested | untested |
| Windows | 12.1.0 (10.9.4 unfinished) | fail #356 (alias + VEX), fail #359 (linked), probe run 36758644937 | untested | untested | untested |

## Backlog

1. Windows and macOS for vendored and hosted (CRLF checkouts via `core.autocrlf`, long paths under `.socket/vendor/npm/<uuid>/`, drive-letter `file:` specs), using the mock-API approach in a probe (the mock is a small Python script; see the run 1 entry).
2. Dual-lock state (npm-shrinkwrap.json + package-lock.json) on npm 11 vs 12 after `npm install <pkg>` changes only one lock: does `vex` flag `patched_ref_unattributable`?
3. npm 11.20.0 and 9.x cells for agent and hosted (not yet run), plus Node 18 / 24 with npm 12.
4. `overrides` pointing a transitive dep to an aliased spec (`"left-pad": "npm:@scope/left-pad@1.3.0"`) in hosted and vendored modes. It's related to #356.
5. Concurrency: two `apply` runs at once (`.socket/apply.lock`), and an interrupted hosted run that leaves `.npmrc` written but the lock unchanged.
6. Stale probe branch `bughunt/npm/20260930-alias-linked`: `git push --delete` failed in run 1 ("remote end hung up"). Retry it; otherwise a maintainer needs to delete it.

## Known non-bugs

- `patches-api.socket.dev` is unreachable from the sandbox. Use hand-staged manifests or a local mock API.
- Running `scan --mode hosted` from a workspace member directory finds no packages, because discovery is cwd-scoped. Run it from the workspace root; it's loud (`manifest_not_found` with `--vex`) and writes nothing.
- An explicit `allow-remote` other than `all` (project `.npmrc`, user or global config, or `npm_config_allow_remote`) is respected with a loud `redirect_npm_allow_remote` warning, and a fresh npm 12 install then fails EALLOWREMOTE (fails closed). This is documented in docs/testing/npm-compatibility.md.
- `npm update` re-resolves a hosted or vendored entry back to the registry. That's npm's behaviour; `vex` then correctly refuses with `redirect_unwired`.
- npm 12 doesn't install the dependencies of a `file:` directory dependency into the linked directory, so there's no copy to patch there.
- The walk skips directories named `build`, `dist`, `vendor`, `tmp`, `temp`, `coverage`, even when one is an npm workspace member. That's documented in docs/ecosystems.md ("npm: which node_modules trees are crawled").
- `apply` from a workspace member directory reports `noManifest` when `.socket/` lives at the root. That's expected: `--cwd` scoping.
