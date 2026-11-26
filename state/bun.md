[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last run: 2026-11-26 (run 49), main `cfc870f`, latest release v5.1.0, newest Bun 1.4.5 (canary 1.4.5-canary.20261125.1).

Run 49 compacted this file from 111 KB. The per-run narrative (runs 1–48) and the old per-version matrices are in the branch history (`git log -p -- state/bun.md`) and in `entries/bun/`. The known non-bugs moved to `known-non-bugs/bun.md`.

## Method (Linux sandbox)

- `unset BUN_OPTIONS` (the sandbox exports `--smol`). Bun binaries: `npm i --no-save --ignore-scripts @oven/bun-linux-x64@<v>` in a scratch dir. On Bun ≥ 1.2, `bunfig [install] saveTextLockfile = false` writes `bun.lockb`; Bun 1.1.x writes `bun.lockb` only.
- The patch API is mocked locally (patch.socket.dev and patches-api are blocked). Use the authenticated routes: `--api-url http://127.0.0.1:A --org o --api-token fake`, serving `POST /v0/orgs/o/patches/batch` (answer only for the requested purls), `GET …/by-package/<purl>`, `POST …/package` (grants: `{"results":{uuid:{"status":"granted","url","purl","artifacts":[{"kind":"tarball","url","integrity":{"sha512":"sha512-…"}}]}}}`), `GET …/view/<uuid>` (with `files` before/after git-sha256 + blob contents) and the tarball at `/patch/npm/<name>/<ver>/<tok>/<uuid>/<name>-<ver>.tgz`. Set `SOCKET_PATCH_SERVER_URL`, `SOCKET_PROXY_URL` and `SOCKET_VENDOR_URL` to the mock's origin. Hosted rollback needs `SOCKET_NPM_REGISTRY` if the CLI can't reach npmjs.
- Patch mirror: a second port serving the same tarball paths under `/artifactory/socket-patch` (HEAD and GET). Pass `--patch-mirror-url http://127.0.0.1:B/artifactory/socket-patch`, or set `SOCKET_PATCH_MIRROR_URL` for later commands.
- Oracle: a fresh-checkout `bun install --frozen-lockfile` with an empty `BUN_INSTALL_CACHE_DIR`, then the marker bytes in `node_modules`, the mock's request log (which host served the tarball), byte compares of the lock, and `vex -O`. Test repos need `node_modules/` in `.gitignore`.
- The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) covers plain hosted / vendored across Bun 0.8.1–1.4.2 with `--ignore-scripts`, without agent mode and without `vex` on isolated trees. The patch-mirror live test covers only a fresh single-project `bun.lock`.

## Coverage matrix

Release focus: a cell last passed before 2026-11-11 counts as untested until it's re-run on main. "pre-5.1" marks those cells.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path, single project, `bun.lock` v0/v1/v2 (scan → install → `vex` → rollback → install) | pre-5.1 (1.1.39–1.4.3, run 48) | pre-5.1 (1.1.39–1.4.3) | pass 1.4.4 v2 + mirror, rollback byte-exact (2026-11-26); otherwise pre-5.1 |
| Common path, single project, `bun.lockb` (1.1.39 v2 → 1.4.x v3) | pre-5.1 | pre-5.1 | pass 1.4.4 + mirror, frozen install from the mirror (2026-11-26); rollback refuses (documented) |
| Workspaces (text v1/v2 + lockb, hoisted + isolated, catalogs, `!` / dot-dir patterns) | pre-5.1 | pre-5.1 | pre-5.1 |
| Takeovers (agent → hosted, hosted ⇄ vendored, partial #1039, superseding uuid) | pre-5.1 | pre-5.1 | pre-5.1 |
| Unwinds (rollback / remove / `vendor --revert` / `scan --prune` / `repair`) | pre-5.1 | pre-5.1 | pre-5.1 |
| `vex` (isolated linker, lockfile-only, workspaces) | pass `bin` CRLF shebang, hoisted + isolated 1.4.4 (2026-11-26) | pre-5.1 | pass 1.4.4 + mirror (2026-11-26) |
| sha512 boundary (1.3.9 digest-less 2-tuple heal vs 1.3.10) | n/a | pre-5.1 | pre-5.1 |
| `--frozen-lockfile` / `bun ci` / `--filter` after rewiring | n/a | pre-5.1 | pass 1.4.4 single + mirror (2026-11-26) |
| Patch mirror (experimental, #2180): fresh pin | n/a | n/a | pass 1.4.4 text v2 + lockb (2026-11-26) |
| Patch mirror: project already pinned on the patch server | n/a | n/a | fail #2279 (lockb: no `redirect_mirror_pin_not_moved`; text + lockb: false `redirect_bun_non_registry_entry_skipped`; 1.1.39 / 1.2.23 / 1.4.4 / 1.4.5). Text remedy (`rollback <purl>`, re-run) works |
| npm-style `bin` CRLF shebang rewrite (#1756, Bun does it too) | pass hoisted + isolated: apply, bin runs, `vex`, rollback keeps LF (1.4.4, 2026-11-26) | untested | untested |
| `globalStore` (Bun ≥ 1.3.14) | refuses (#635 fixed), pre-5.1 | pre-5.1 | pre-5.1 |
| Global `-g` | pre-5.1 (run 3) | n/a | pre-5.1 |
| `bun patch` interplay (#367 / #1019) | n/a | pre-5.1 | pre-5.1 |
| Lifecycle scripts / `trustedDependencies` / default trust | n/a | pre-5.1 | pre-5.1 |
| `.gitignore` / LFS on vendored artifacts | n/a | pre-5.1 | n/a |
| Self-update of a Bun-installed CLI (#1621) | pre-5.1 | — | — |
| Canary lock bytes vs stable | 1.4.5 = 1.4.4 for text + lockb (2026-11-26) | | |
| macOS / Windows | untested on main: probe workflows are off, Linux only | | |

## Backlog

1. Release focus: re-run the pre-5.1 common-path cells on main. Agent / vendored / hosted × text v0 / v1 / v2 × `bun.lockb`, on Bun 1.1.39 / 1.2.23 / 1.3.10 / 1.4.5, single project + workspace (hoisted and isolated), with a fresh frozen install, `vex` and rollback. If something fails, compare against v5.1.0.
2. Patch mirror follow-ups (experimental, new since v5.1.0): workspaces (text v1 / v2, lockb member layouts); a superseding uuid on a pin that's already on the mirror (same-origin takeover); mirror HEAD answers 401 / 404 / timeout with Bun; a vendored → hosted takeover with the mirror set; `redirect_pin_on_unconfigured_host` (a pin on the mirror re-run without the setting); mirror base with a trailing slash or port; the 1.3.9 digest-less 2-tuple heal on a mirror URL.
3. #2279: re-test when fixed (text + lockb, the lockb remedy text, `vex` count).
4. Friction: `rollback` without the mirror setting on a mirror-pinned project says only `manifest_not_found` / "Manifest not found", and `vex` says "No patches in this project". Both are documented, but check whether either names the mirror setting as a hint before deciding on a UX issue.
5. Spot-check that the closed Bun issues still hold on main: #1631 (dot-dir workspaces), #1621 (self-update), #1600 (`vendor --check` reason for git / `file:` copies), #1581 (LFS `repair`), #1084 (isolated orphan).
6. `bin` CRLF shebang (#1756) in vendored and hosted modes (`vendor --check`, hosted `vex`) on Bun.
7. Partial-takeover remedy text on a shared `bun.lockb`: `redirect_revert_failed` advises `git checkout -- bun.lockb`, which would also discard the purls vendored in the same run (a re-run is the working remedy). Compare with the text lock and npm before filing.
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
