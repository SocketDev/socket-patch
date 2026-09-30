[agent] Progress ledger for the scheduled Yarn classic (1.x) bug-hunt routine (label pm:yarn-classic).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N", "blocked" or "untested". H = hosted, V = vendored, A = agent (`scan --apply` + `setup`). Each hosted and vendored cell ends with a real fresh-checkout `yarn install --frozen-lockfile`, using a local mock patch API. CI's `yarn-classic-matrix` (1.0.2, 1.6.0, 1.7.0, 1.9.4, 1.10.1, 1.22.22) already covers the plain single-dep hosted and vendored flows plus VEX on Linux.

| OS | yarn | H baseline | H offline mirror | H/V git-sourced dep | H workspaces / alias / resolutions / scoped | H CRLF·BOM + rollback | V baseline | V offline mirror | V CRLF·BOM + revert | A apply + setup hook |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.2 | pass | n/a (yarn limitation) | fail #363 | untested | untested | CI (known limitation) | untested | untested | pass |
| Linux | 1.6.0 | pass | n/a (yarn limitation) | untested | untested | untested | CI (known limitation) | untested | untested | untested |
| Linux | 1.7.0 | CI | fail #364 (`--offline`) | fail #363 | untested | untested | CI | untested | untested | untested |
| Linux | 1.9.4 | CI | fail #364 (`--offline`) | untested | untested | untested | CI | untested | untested | untested |
| Linux | 1.10.1 | pass | fail #364 | fail #363 | untested | untested | CI | pass | untested | pass |
| Linux | 1.17.3 | untested | fail #364 | untested | untested | untested | untested | untested | untested | untested |
| Linux | 1.22.22 | pass | fail #364 | fail #363 | pass | pass | pass | pass | pass | pass |
| macOS | 1.10.1 / 1.22.22 | untested | fail #364 | fail #363 | untested | untested | untested | untested | untested | untested |
| Windows | 1.10.1 / 1.22.22 | untested | fail #364 | blocked (probe had no git for yarn) | untested | untested | untested | untested | untested | untested |

## Backlog

1. Why yarn ≤ 1.6 installs nothing from local tarballs or offline mirrors on modern Node (CI `KNOWN LIMITATION`): bisect by Node version, and decide whether vendored mode should refuse on those releases instead of reporting success.
2. Windows probe: git-sourced dep (put git on yarn's PATH), a yarn-written CRLF lock, spaces / unicode / drive-letter project paths for vendored `file:./.socket/…`.
3. Takeovers (hosted ⇄ vendored) and `rollback` with an offline mirror; `yarn-offline-mirror-pruning`.
4. Frozen installs after `yarn add` / `yarn upgrade` on 1.0–1.9 locks; multiple patched versions of one package; `get <uuid> --mode hosted`, `remove`, `repair`.
5. VEX on lockfile-only checkouts with aliases and resolutions.

## Known non-bugs

- `patches-api.socket.dev` isn't used here. Use a local mock API (`--api-url`). The mock must match purls with an unencoded `@` for scoped packages, and vendored runs need `--vendor-source build` plus `blobContent` in the view stub.
- yarn 1.0.2 and 1.6.0 exit 0 with an empty `node_modules` for `file:` tarballs and offline-mirror installs even without socket-patch (yarn on Node 22). CI reports this as `KNOWN LIMITATION`.
- An `npm:` alias entry (`lp@npm:left-pad@1.3.0`) is left unpatched in hosted mode with `redirect_yarn_classic_alias_skipped`. This is documented, and `vex` omits the package.
- A BOM plus no yarn header comment makes the first entry `entry_not_found`. Yarn always writes the header, so this is synthetic.
- `file:` directory and `link:` deps are skipped by design.
- GitHub git specs can't be fetched through the sandbox proxy. Use a local `git+file://` repo.
- Probe branches can't be deleted from the sandbox (the git proxy rejects ref deletion).
