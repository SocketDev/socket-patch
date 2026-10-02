[agent] Progress ledger for the scheduled Yarn classic (1.x) bug-hunt routine (label pm:yarn-classic).

Last updated: 2026-10-02 (run 7), main `61cfb9b`, latest release v4.0.0. Runs 5–7 added the cells in "Run 5 cells", "Run 6 cells" and "Run 7 cells" below. The project-mode matrix below was measured on `f6b7fb9` (v4); cells marked "(v5)", the global matrix and the "v5 project-mode cells" list were re-run on v5.

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
| Linux | 1.22.22 | pass (v5, + hosted rollback pass) | fail #364 (v5) | fail #363 (v5; rollback also wrong) | pass | pass | pass | pass | pass | pass |
| macOS | 1.7.0 | untested | untested | fail #363 | pass | pass | pass | pass | untested | untested |
| macOS | 1.10.1 / 1.22.22 | pass (probe) | fail #364 | fail #363 | pass | pass | pass | pass | untested | untested |
| Windows | 1.7.0 / 1.10.1 / 1.22.22 | pass (probe) | fail #364 (1.10.1/1.22.22) | fail #363 (vendored: `Couldn't find the binary git`) | pass | pass | pass | pass | untested | untested |

### Global mode (`-g`) on v5 `2463257`
Report = `scan -g` report-only + no leakage; refusal = `scan -g/--global-prefix/SOCKET_GLOBAL --mode hosted` exits 2; A = agent apply + import + `vex -g` + `rollback -g` byte-exact; get-mode = `get -g --mode hosted|vendored` / `scan -g --mode vendored`; RO = read-only global folder fails loudly.

| OS | yarn | report | refusal | A apply/vex/rollback | get-mode | RO | custom global-folder (space+unicode) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.2 | fail #437 | pass | fail #437 | fixed (#436 closed by #446; not re-run) | n/a (nothing found) | untested |
| Linux | 1.10.1 / 1.22.22 | pass | pass | pass | fixed (#436 closed by #446; not re-run) | pass (CI runner) | pass (1.22.22) |
| macOS | 1.0.2 | fail #437 | pass | fail #437 | fail #436 | n/a | untested |
| macOS | 1.10.1 / 1.22.22 | pass | pass | pass | fail #436 | pass | untested |
| Windows | 1.0.2 | fail #437 / #434 | pass | fail #434 | fail #436 | untested | untested |
| Windows | 1.10.1 / 1.22.22 | fail #434 | pass | fail #434 | fail #436 | untested | untested |

Other cells that pass on Linux 1.22.22 (some also on older releases; see the entries): spaces + unicode project paths (also macOS and Windows), `npm:` alias (H skipped as documented, V rewired), `resolutions`, a `resolved` without the `#sha1` fragment / `integrity`, a local `file:` tarball dep, a non-deduplicated lock, a superseding patch on re-scan, `remove` / `repair`, VEX (installed and lock-only, after `yarn upgrade`), `yarn add` then a frozen reinstall (1.7.0 too), `yarn check --integrity` / `--verify-tree`, in-place reinstalls on 1.7–1.22, concurrent scans (`lock_held`), the GitHub shorthand dep on all 3 OSes.

### v5 project-mode cells (Linux, run 4)
- Mixed CRLF+LF lock, H and V: **fail #467** (line endings converted; rollback not byte-exact).
- Uniform CRLF / BOM+CRLF: H⇄V takeovers + rollback, pass. `--dry-run` byte-identity (H / V / A / rollback) on CRLF / BOM / mixed, pass.
- V service artifacts: workspaces + multi-version + merged key + `npm:` alias, vex / `vendor --check` / `repair` / frozen offline / rollback, pass (1.22.22).
- V + offline mirror + pruning: pass (1.7.0 / 1.10.1 / 1.22.22).
- No-`integrity` (1.7-style) locks, H and V: pass (1.7.0 / 1.22.22). Tarball-URL dep, H and V: pass. `file:` dir dep, H: pass.
- SIGKILL-interrupted scans, H and V: pass (recoverable by `repair` / re-scan).

### Run 5 cells (Linux, `61cfb9b`)
- `.yarnrc --modules-folder`, agent mode: **fail #493** (1.7.0 / 1.10.1 / 1.22.22).
- Workspaces with `nohoist`, A/H/V + frozen install + vex: pass (1.22.22).
- `--max-new-patches` on a workspace, A/H/V + re-run + frozen install: pass (1.22.22).
- Custom `.yarnrc registry`, hosted rewire + rollback: pass (rollback uses `SOCKET_NPM_REGISTRY`, as documented).
- Hosted over an installed tree, then an in-place frozen reinstall: pass.
- #363 re-checked: still fails (1.22.22).

### Run 6 cells (Linux, `61cfb9b`)
- PnP (`installConfig.pnp`) with a stale `.pnp.js` + hosted pin → `vex`: **fail #519** (1.12.3 / 1.17.3 / 1.22.22). PnP `scan` refusal in all modes: pass. PnP lock-only hosted + frozen install: patched.
- `--modules-folder` + stale `deps/` + hosted pin → `vex`: **fail #493** (commented; 1.10.1 / 1.22.22). `--modules-folder` hosted / vendored + frozen install: pass.
- `optionalDependencies` incl. platform-skipped `fsevents`, H/V + frozen install + vex: pass (1.22.22).
- Uppercase names (`JSONStream`), A/H/V + frozen + vex + rollback: pass. `yarn import` locks, H/V: pass.
- Hosted pin `Authorization` leakage (6 `.npmrc` auth configs): none on 1.0.2 / 1.6.0 / 1.9.4 / 1.12.3 / 1.17.3 / 1.22.22: pass.

### Run 7 cells (`61cfb9b`)
- Dev flow after scan (`yarn add`, then a frozen fresh install, `vex`, `vendor --check`, `--pure-lockfile` reinstall), H and V: pass on Linux 1.0.2 / 1.6.0 (H) and 1.7.0 / 1.10.1 / 1.22.22, Windows 1.7.0 / 1.10.1 / 1.22.22, macOS 1.7.0 / 1.22.22 (probe).
- `--production` install, hosted + vex: pass (1.22.22). `integrity sha1-` locks, H / V + rollback: pass (1.10.1 / 1.22.22).
- Odd range keys (`">= a < b"`, `||`, `x`, hyphen, `latest`, `v`-prefix), H: pass. Workspace member under `tests/` + `socket.yml` policies (A/H): pass.
- `yarn set version classic` layout (`.yarnrc.yml` yarnPath + `packageManager`), A/H/V: pass. `vendor --revert` on LF / CRLF / BOM+CRLF (1.7.0 / 1.22.22): byte-exact.

## Backlog

1. **Maintainer request (global mode), still open:** Windows once #442 merges (#434 / #437, and the Berry handover lead about the `.cmd` shim); yarn via corepack and the Windows MSI; 1.6.0 / 1.9.4 on the probe; a read-only prefix on Windows (Program Files). Re-run get-mode cells after #446.
2. Re-check #493 after #520 merges: workspace-level and `--install.modules-folder` forms.
3. Hosted rollback on `integrity sha1-` locks (what integrity the restored entry gets).
4. `.yarnclean` / `yarn autoclean` vs agent / hosted patched files and VEX hash verification.
5. Re-run the v4-only project matrix columns (git dep #363, offline mirror H #364) on macOS/Windows once fixes land.

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
- **v5 hosted `rollback` / `remove` need the npm registry.** In the sandbox the CLI's rustls client rejects the TLS-intercepting proxy CA (`error sending request for url (https://registry.npmjs.org/…)`). That's a sandbox artifact. Use a local plain-HTTP registry passthrough with `env -u HTTPS_PROXY -u https_proxy SOCKET_NPM_REGISTRY=http://127.0.0.1:<port>`. With `SOCKET_NPM_REGISTRY` set, the restored `resolved` uses `dist.tarball` verbatim (registry.npmjs.org), not registry.yarnpkg.com. That's by design (`npm.rs` `yarn_classic_tarball`).
- v5 vendored mode has no local build (`--vendor-source build` is rejected). The mock must serve a `tarball` artifact from `POST …/patches/package`.
- `scan -g` also reports npm's own bundled deps (npm global root), e.g. `@isaacs/string-locale-compare`. That's correct global discovery.
- Probe branch `bughunt/yarn-classic/20261001-global-mode` is also left on the remote (the proxy blocks deletion).

- Hosted pins are recognized only on `patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. With a mock at another origin and no such setting, `rollback` says `Manifest not found` (truly-empty project). Set `SOCKET_PATCH_SERVER_URL=<mock>`.
- Hosted rollback of a lock without `integrity` lines (yarn < 1.10) adds `integrity` lines. That's the "default upstream entry", and yarn 1.7 still installs it frozen.
- Vendored mode on yarn ≤ 1.6 installs nothing. The harness asserts this as a KNOWN LIMITATION (`tests/common/yarn_classic_vex.rs:89`); it's not in the user docs.
- A tarball-URL dependency of the patched name@version is rewired in both modes (it installs patched). Whether a URL "fork" should be refused, as vlt does, is a design question.
- A SIGKILL can leave the lock wired with no `vendor/state.json`. `rollback` then refuses with a remedy, and `repair` / a re-scan rebuild the ledger. That's intended crash handling.
- Hosted rollback ignores the `.yarnrc` `registry` and queries `SOCKET_NPM_REGISTRY` (default registry.npmjs.org). That's documented (CLI_CONTRACT Hosted unwind / env table). Set `SOCKET_NPM_REGISTRY` behind a private registry.
- A nested non-workspace project (its own `yarn.lock` under the root) in hosted mode from the root: `redirect_yarn_classic_entry_not_found`, because hosted reads only the root lock. That's the documented one-project model (run with `--cwd` per project).
- A stale `node_modules` left beside an active `--modules-folder`: Node loads `node_modules` first, so agent patching it is correct.
- Yarn classic never sends `.npmrc` registry auth (host token, bare `_authToken`, `always-auth`, scoped registry, `_auth`) to the hosted patch host, on any release from 1.0.2 to 1.22.22. The berry #404 leak doesn't apply to classic.
- Vendored `vex` attests from the committed artifact even when the installed tree is unpatched (by design, with a `vendored_tree_out_of_sync` warning).
- `scan --vex` in a PnP project exits 1 `manifest_not_found` only because there is nothing to attest. Plain `scan` exits 0 with `yarn_pnp_unsupported`, as pinned by `e2e_safety_yarn_pnp.rs`.
- A platform-skipped optional dep (`fsevents` on Linux) is rewired and attested from the lock pin in hosted mode: the documented lock-only basis, and it installs patched on macOS.
- The mock harness must exclude `node_modules` relative to the package dir, or it serves empty tarballs (a harness bug, not socket-patch).
- yarn classic ignores `YARN_MODULES_FOLDER` / `npm_config_modules_folder` (installs into `node_modules`), so the crawler needn't read them. A `~/.yarnrc` `--modules-folder` resolves relative to `$HOME`, not the project.
- v5 has no `setup` subcommand. Agent cells use `apply`.
- Probe branch `bughunt/yarn-classic/20261002-dev-flow` is also left on the remote (the proxy blocks deletion).
