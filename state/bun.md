[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last run: 2026-11-28 (run 51), main `cfc870f`, latest release v5.1.0, newest Bun 1.4.5 (canary 1.4.5-canary.20261127.1).

The per-run narrative (runs 1–48) and the old per-version matrices are in the branch history (`git log -p -- state/bun.md`) and in `entries/bun/`.

## Method (Linux sandbox)

- `unset BUN_OPTIONS` (the sandbox exports `--smol`). Bun binaries: `npm i --no-save --ignore-scripts @oven/bun-linux-x64@<v>` in a scratch dir. On Bun ≥ 1.2, `bunfig [install] saveTextLockfile = false` writes `bun.lockb`; Bun 1.1.x writes `bun.lockb` only.
- The patch API is mocked locally (patch.socket.dev and patches-api are blocked). Use the authenticated routes: `--api-url http://127.0.0.1:A --org o --api-token fake`, serving `POST /v0/orgs/o/patches/batch` (answer only for the requested purls), `GET …/by-package/<purl>`, `POST …/package` (grants: `{"results":{uuid:{"status":"granted","url","purl","artifacts":[{"kind":"tarball","url","integrity":{"sha512":"sha512-…"}}]}}}`), `GET …/view/<uuid>` (with `files` before/after git-sha256 + blob contents) and the tarball at `/patch/npm/<name>/<ver>/<tok>/<uuid>/<name>-<ver>.tgz`. Set `SOCKET_PATCH_SERVER_URL`, `SOCKET_PROXY_URL` and `SOCKET_VENDOR_URL` to the mock's origin. Hosted rollback needs `SOCKET_NPM_REGISTRY` if the CLI can't reach npmjs. A ~100-line Python `http.server` mock that builds each patched tarball from the registry tarball (marker prepended to `index.js`) covers all three modes; agent mode needs `blobContent` (base64) in `view`. Also serve the public routes: `GET /patch/view/<uuid>` (hosted-only `vex` without `--api-url` reads it) and `GET /patch/blob/<git-sha256>` or `/v0/orgs/o/patches/blob/<hash>` (agent `rollback` downloads before-blobs).
- The repo's real-Bun e2e suites run with `PATH=<bun dir>:$PATH SOCKET_PATCH_BUN_E2E_REQUIRED=1 SOCKET_PATCH_BUN_E2E_VERSION=<v> SOCKET_PATCH_BUN_LOCKB_REQUIRED=1 cargo test --release -p socket-patch-cli --test …`.
- Patch mirror: a second port serving the same tarball paths under `/artifactory/socket-patch` (HEAD and GET). Pass `--patch-mirror-url http://127.0.0.1:B/artifactory/socket-patch`, or set `SOCKET_PATCH_MIRROR_URL` for later commands.
- Oracle: a fresh-checkout `bun install --frozen-lockfile` with an empty `BUN_INSTALL_CACHE_DIR`, then the marker bytes in `node_modules`, the mock's request log (which host served the tarball), byte compares of the lock, and `vex -O`. Test repos need `node_modules/` in `.gitignore`.
- The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) covers plain hosted / vendored across Bun 0.8.1–1.4.2 with `--ignore-scripts`, without agent mode and without `vex` on isolated trees. The patch-mirror live test covers only a fresh single-project `bun.lock`.

## Coverage matrix

Release focus: a cell last passed before 2026-11-11 counts as untested until it's re-run on main. "pre-5.1" marks those cells.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Repo real-Bun e2e suites (redirect, vendor, lockb, mode migration, takeover, eject: 101 tests) | pass 1.1.39 / 1.2.23 / 1.3.9 / 1.3.10 / 1.4.5 (2026-11-27) | | |
| Common path, single project, `bun.lock` v0/v1/v2 (scan → frozen fresh install → `vex` → rollback → install) | pass 1.1.39 v0 / 1.2.23 v1 / 1.3.10 v1 / 1.4.5 v2 (2026-11-27) | pass same (2026-11-27) | pass same, rollback byte-exact (2026-11-27) |
| Common path, single project, `bun.lockb` (1.1.39 → 1.4.5) | pass 1.1.39 / 1.2.23 / 1.3.10 / 1.4.5 (2026-11-27) | pass same, revert byte-exact (2026-11-27) | pass same; rollback refuses (documented) (2026-11-27) |
| Workspaces (text v0/v1/v2 + lockb, hoisted + isolated) | pass 1.1.39 / 1.2.23 / 1.3.10 / 1.4.5 (2026-11-27) | pass lockb all four + text v2 1.4.5; text v0/v1 refused `vendor_bun_workspace_unsupported` (documented); lockb on 1.2.23/1.3.10 survives unfrozen install + member `bun add` (2026-11-27) | pass v1/v2 + lockb; v0 refused `redirect_bun_workspace_unsupported` (documented) (2026-11-27). Catalogs (`catalog:` / named), `!` negation, dot-dir members: pass all three modes, text + lockb 1.4.5 (2026-11-28) |
| Takeovers (agent → hosted, hosted ⇄ vendored, partial #1039, superseding uuid) | agent → hosted pass text + lockb 1.4.5, lockb 1.2.23 (2026-11-28) | hosted → vendored full + partial pass text + lockb 1.4.5 (2026-11-27); superseding uuid pass text + lockb 1.4.5, live-tree `bun install` picks it up (2026-11-28) | vendored → hosted with mirror pass (2026-11-27); superseding uuid pass text + lockb 1.4.5 (2026-11-28) |
| Unwinds (rollback / remove / `vendor --revert` / `scan --prune` / `repair`) | rollback + `remove <purl>` pass 1.4.5 text + lockb ws (2026-11-27) | `vendor --revert` byte-exact, `repair` re-downloads a deleted tarball, `vendor --check` pass 1.4.5 text + lockb ws (2026-11-27) | rollback pass text (all versions); `scan --prune` n/a (`redirect_prune_ignored`). Vendored `--prune` after `bun remove` pass text + lockb; agent `--sync` prunes (1.4.5, 2026-11-28) |
| `vex` (isolated linker, lockfile-only, workspaces) | pass all common-path cells (2026-11-27) | pass all common-path cells (2026-11-27) | pass all common-path cells + mirror ws (2026-11-27); refuses on an unreinstalled live tree with a clear message |
| sha512 boundary (1.3.9 digest-less 2-tuple heal vs 1.3.10) | n/a | pass 1.3.9 `bun add` drop → re-run re-pins on disk (2026-11-27) | pass 1.3.9 heal on a mirror URL, install from mirror (2026-11-27) |
| `--frozen-lockfile` / `bun ci` / `--filter` after rewiring | n/a | pre-5.1 | pass 1.4.4 single + mirror (2026-11-26) |
| Patch mirror (experimental, #2180): fresh pin | n/a | n/a | pass 1.4.5 text v2 + lockb, single + ws hoisted/isolated, 1.3.10 text v1 ws; trailing-slash base; 404 mirror → `redirect_mirror_unavailable`, nothing written (2026-11-27) |
| Patch mirror: project already pinned on the patch server | n/a | n/a | fail #2279 (lockb: no `redirect_mirror_pin_not_moved`; false `redirect_bun_non_registry_entry_skipped`). Reverse case (mirror pin, run without the setting): text gives `redirect_pin_on_unconfigured_host`; lockb gives the false warning instead, added to #2279 (2026-11-27) |
| npm-style `bin` CRLF shebang rewrite (#1756, Bun does it too) | pass hoisted + isolated: apply, bin runs, `vex`, rollback keeps LF (1.4.4, 2026-11-26) | untested | untested |
| `globalStore` (Bun ≥ 1.3.14) | refuses with a working remedy (1.4.5, 2026-11-28) | pass, private cache link (1.4.5, 2026-11-28) | pass, shared registry entry untouched (1.4.5, 2026-11-28) |
| Global `-g` | pre-5.1 (run 3) | n/a | pre-5.1 |
| `bun patch` interplay (#367 / #1019) | n/a | URL-keyed user patch skipped on takeover, rollback warns dropped (1.4.5, 2026-11-28) | URL-keyed survives superseding; registry-keyed lockb skipped (1.4.5, 2026-11-28) |
| Lifecycle scripts / `trustedDependencies` / default trust | n/a | default-trust refusal incl. alias pass; explicit trust by real name on an npm alias: fail #2335 (1.4.0+ lockb, 1.4.4+ text) (2026-11-28) | same: skip pass, alias trust fail #2335 (2026-11-28) |
| `.gitignore` / LFS on vendored artifacts | n/a | `*.tgz` rule: still committed; `.socket/` / `vendor/` rules: clear refusal, nothing written (1.4.5, 2026-11-28). LFS pre-5.1 | n/a |
| Self-update of a Bun-installed CLI (#1621) | pre-5.1 | — | — |
| Canary lock bytes vs stable | 1.4.5 = 1.4.4 for text + lockb (2026-11-26) | | |
| macOS / Windows | untested on main: probe workflows are off, Linux only | | |

## Backlog

1. #2335: re-test when fixed (alias trusted by real name, hosted + vendored, text 1.4.4+ / lockb 1.4.0+; also the reverse, trusted by alias name only, where a rewire newly runs the scripts; and the default-trust skip remedy for an alias).
2. #2279: re-test when fixed (text + lockb, both directions; remedy text on lockb; `vex` count).
3. Remaining pre-5.1 rows: global `-g`, self-update (#1621), `.gitignore` + LFS `repair` (#1581), `--frozen-lockfile` / `bun ci` / `--filter` in vendored mode. Re-run on main.
4. Other alias shapes on Bun 1.4: an aliased package hosted / vendored in workspaces, aliased `bun patch` keys, `vex` / rollback on an alias pin.
5. Patch mirror: HEAD answering 401 / 403 (`redirect_mirror_unverified`) and a timeout; a superseding uuid on a pin already on the mirror.
6. Spot-check the closed Bun issues on main: #1631 (dot-dir workspaces, partly re-covered 2026-11-28), #1600 (`vendor --check` reason for git / `file:` copies), #1084 (isolated orphan).
7. `bin` CRLF shebang (#1756) in vendored and hosted modes on Bun.
8. Each new Bun release or canary: compare its text and lockb bytes with the latest stable.
9. macOS / Windows (path quoting, junctions, `bun.cmd`): can't be probed now. Note likely platform differences in issues.

## Known non-bugs

Full list: `known-non-bugs/bun.md`. Search it with `git grep -n <term> origin/bughunt/ledger -- known-non-bugs/bun.md`. The ones most likely to be re-filed:

- Hosted `bun.lockb` pins: `rollback` / `remove` refuse with the `git checkout -- bun.lockb` remedy (documented). `bun.lockb` takeovers are semantically identical, not byte-exact.
- Documented refusals (docs/testing/bun-compatibility.md): a version-0 workspace lock in hosted mode (`redirect_bun_workspace_unsupported`), a pre-v2 workspace lock in vendored mode (`vendor_bun_workspace_unsupported`).
- A hosted run on a user `file:` / URL tarball of the patched `name@version` warns `redirect_bun_non_registry_entry_skipped` and doesn't attest it (#497 design). Only the patch-server-pin case under a mirror is a bug (#2279).
- With pins on the mirror, `vex` / `rollback` run without `SOCKET_PATCH_MIRROR_URL` see no hosted pins (documented).
- `vex --json` with no `--output` is the `json_requires_output` usage error (exit 2).
- A mode-less `scan` is hosted by default on a Bun project and re-pins, so use `--mode agent` for agent cells and `--dry-run` / `list` as read-only checks.
- A patch that edits `package.json` (new dependency or `bin`) installs patched bytes, but Bun's frozen install uses the lock's metadata.
- Bun ignores `NPM_CONFIG_USERCONFIG`. `bun update -g` doesn't upgrade an exact-pinned global install (Bun behaviour).
- A hosted rollback without the original `BUN_CONFIG_REGISTRY` restores `""` in the registry slot, which is what Bun itself writes.
- Lifecycle `prepare` doesn't run for registry or tarball dependencies on any Bun version.
