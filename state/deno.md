[agent] Progress ledger for the scheduled Deno bug-hunt routine (label pm:deno).

Last updated: 2026-10-01 (run 5), main `61cfb9b`, latest release 4.0.0 (previous 3.3.0). Newest Deno is 2.9.7.

Method: real Deno binaries (GitHub release zips; `denoland/setup-deno` in probes), a per-project `DENO_DIR`, and a local manifest plus blobs driven by `apply --offline`. The patched bytes record themselves in `globalThis.__SP`, so `deno run` shows which patched modules actually loaded. For scan / get / hosted / vendored there's a local stub of the public proxy (`SOCKET_PROXY_URL` + `SOCKET_PATCH_SERVER_URL`) serving batch, by-package, view (real blobs), package grants and a patched tarball at `/patch/npm/<uuid>/<name>-<ver>.tgz`. Deno's npm packages are `pkg:npm` (npm crawler), and the Deno ecosystem proper is JSR (`pkg:jsr`).

## Coverage matrix

| OS | Deno | Agent: direct npm dep (incl. scoped, alias, workspace member) | Agent: transitive npm dep (`node_modules/.deno`) | Agent: `nodeModulesDir` none | Agent: JSR (`vendor: true`) | JSR via `--global-prefix vendor/jsr.io` | vendored refusal | hosted / vendored (npm deps via package-lock.json) | VEX |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.46.3 | pass | fail #373 | known limitation | fail #374 | pass | untested | hosted fail #406 | pass (agent), fail #406 (hosted) |
| Linux | 2.0.6 | pass (run 1) | fail #373 | known limitation | fail #374 | untested | untested | untested | untested |
| Linux | 2.2.15 | pass | fail #373 | known limitation | fail #374 | pass | untested | hosted + vendored fail #406 (package-lock + deno.lock) | fail #406 |
| Linux | 2.9.6 | pass | fail #373 (also `--prune` drops records) | known limitation | fail #374 | pass (scan + apply; unsafe with npm deps, see #374) | pass for `pkg:jsr` (`vendor_unsupported_ecosystem`) | hosted + vendored fail #406 | pass (agent), fail #406 (hosted) |
| macOS | 1.46.3 / 2.2.15 / 2.9.6 | pass (scoped; apply / vex / rollback) | fail #373 | untested | fail #374 | pass | untested | untested | pass (agent) |
| Windows | 1.46.3 / 2.2.15 / 2.9.6 | pass (scoped via junctions; apply / vex / rollback) | fail #373 | untested | fail #374 | pass | untested | untested | pass (agent) |
| Linux | 2.9.7 | pass (also `links`) | fail #373 (re-checked on `61cfb9b`) | untested | untested | untested | pass for `pkg:npm` in a deno.lock-only project (`vendor_lockfile_missing`, exit 1, files untouched) | fail #406 (lockfile-only vex) | pass (agent) |

### `nodeModulesLinker: "hoisted"` (Deno ≥ 2.8, needs `nodeModulesDir: manual`), agent mode

| OS | Deno | direct | nested transitive | `DENO_DIR` cache untouched | re-apply | vex | rollback | scan discovery |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux / macOS / Windows | 2.8.3, 2.9.7 | pass | pass | pass | pass | pass | pass | pass (Linux 2.9.7) |
| Linux | 2.9.7, `workspace` members | pass (doubly nested too) | pass | — | — | pass | pass | — |
| Linux | 2.9.7, duplicate copies of one `name@version` | pass (both patched) | — | — | — | fail (only the first copy is hashed; handed over to npm) | — | — |

### Global mode (`-g` / `--global-prefix` / `SOCKET_GLOBAL`), `deno install -g` of a tool with an `npm:` dep

| OS | Deno | `scan -g` report | `apply -g` | `--global-prefix` on `$DENO_DIR` layouts | 2.9 per-tool `bin/.<tool>/node_modules` | rollback -g | vex -g | hosted refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.46.3 / 2.2.15 | fail #444 | fail #444 | fail #444 | n/a | untested (blocked by #444) | fail #444 (`no_applicable_patches`) | pass (2.9.6) |
| Linux | 2.9.6 | fail #444 | fail #444 | fail #444 | fail #444 (false `applied` + VEX for local/JSR tools; pass for `npm:` tools) | untested | fail #444 | pass |
| Linux | 2.7.0 → 2.9.7 (layout only) | — | — | — | per-tool dir from 2.7.0; decoy `node_modules` for local tools by 2.7.14 (#444 comment) | — | — | — |
| Linux / macOS / Windows | 1.46.3, 2.0.6, 2.2.15, 2.4.5, 2.9.6 (probe) | Windows also #434 | fail #444 | fail #444 | 2.9.6 only: fail #444 | untested | 2.9.6 decoy: false `not_affected` | untested |

Other passes (Linux): an immutable (`chattr +i`) target fails loudly (`apply_failed`, exit 1), `list --json`, re-apply idempotency, rollback, `remove`, breaking cache hardlinks, end-to-end `scan --mode agent` via the stub, unicode / space paths, and deno.lock v3 / v5 never edited (`--frozen` still OK).

## Backlog

0. **Maintainer request (global mode), partly covered.** Filed #444 (still open on `61cfb9b`, no fix PR). Still to do: an unwritable global prefix (read-only `DENO_INSTALL_ROOT` / `DENO_DIR`) on macOS / Windows (the Linux sandbox runs as root; `chattr +i` passes for project installs), `rollback -g` after #444 is fixed, and `DENO_DIR` with spaces or unicode.
1. A maintainer needs to delete the stale probe branches `bughunt/deno/20260930-deno-store`, `bughunt/deno/20261001-scoped-jsr`, `bughunt/deno/20261001-global` and `bughunt/deno/20261001-hoisted`. The git proxy refuses `push --delete`.
2. Re-test #373 once draft PR #496 lands, then cover isolated `.deno` peer-variant and scoped transitive entries (use hoisted as the control).
3. Hoisted + `vendor: true` JSR.
4. #406 follow-ups: pnpm-lock / yarn.lock / bun.lock beside deno.lock. Done: Deno 1.46.3 (affected) and vendored (affected, and VEX survives the install).
5. Hosted `get` / `scan` for `pkg:jsr` against the real proxy (the stub can't decide the real grant status).
6. CRLF / BOM `deno.jsonc` / `deno.lock`, and `DENO_DIR` with spaces, on Windows.
7. Follow the npm handover (agent vex hashes only the first copy, `commands/vex.rs:556`) and re-check the Deno hoisted duplicate-copy cell once it's filed or fixed.

## Known non-bugs

- `patches-api.socket.dev` and `dl.deno.land` / `deno.land` are proxy-denied in the sandbox. Use GitHub release zips and a local stub.
- `nodeModulesDir: "none"` (the Deno 2 default without package.json) keeps npm packages only in the shared `DENO_DIR/npm/registry.npmjs.org/<name>/<ver>`. Agent apply fails loudly (`package_not_installed`, `partialFailure`). `scan` says "No packages found" because deno.lock isn't a documented lockfile-supplement source.
- `setup` was removed in v5 (#277). The earlier "package.json postinstall hook Deno never runs" GAP and the `setup.manual` VEX gating no longer apply; v5 VEX attests agent patches from the installed bytes without any setup.
- `vex --no-verify` trusts agent records without hashing, by documented design.
- Hosted `scan` in a deno.json-only project warns `redirect_npm_no_lockfile` and exits 0 / success. Hosted refusals don't change exit status (CLI_CONTRACT).
- Hosted `get pkg:jsr/...` gives `redirected: 0` with only a human "no lockfile entry" line (no JSON code). Unverified against the real proxy; revisit (backlog 3).
- `nodeModulesDir: "auto"` / `"manual"` are Deno 2 values; on 1.x, use `true`.
- `setup.manual: ["deno"]` (legacy) covered only `pkg:jsr`; `npm:` deps are the npm ecosystem.
- `get -g --mode hosted|vendored` not refusing was #436 (generic), fixed by #446. It now refuses on `61cfb9b`.
- `scan -g --mode hosted` / `--global-prefix --mode hosted` exit 2 with the documented refusal. That's correct.
- A Deno 2.9 `npm:`-entrypoint global tool gets `"nodeModulesDir": "manual"` and really loads `bin/.<tool>/node_modules`. Only local/JSR-entrypoint tools load the `DENO_DIR` copy (#444).
- `nodeModulesLinker: "hoisted"`: every `deno install` (including `--frozen`) re-links from `DENO_DIR` and drops agent patches. Agent mode needs `apply` after each install (documented), and vex then says `not_applied`.
- `repair --offline` GCs before-blobs, so a later `rollback --offline` fails with `missing_blob` and a repair remedy. Offline design, not Deno-specific.
- `list --json` `files[].verified` is always `false` (hardcoded). Generic, cosmetic.
- `vex` without `--product` in a deno.json-only project fails with "Could not auto-detect a top-level product PURL". deno.json isn't in the documented auto-detect list.
- Deno `"links"` copies the linked package into `node_modules/.deno/<name>@<ver>`. An agent patch only touches that copy, never the linked source.
- Agent-mode VEX checking only the first of several copies of a `name@version` is a generic npm-family defect (`commands/vex.rs:556`), handed over to npm. Don't re-file it from Deno; comment on the npm issue instead.
