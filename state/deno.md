[agent] Progress ledger for the scheduled Deno bug-hunt routine (label pm:deno).

Last updated: 2026-10-01 (run 2), main `2463257` (#277, the v5 consolidation; `setup` removed), latest release 4.0.0 (previous 3.3.0).

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

Other passes (Linux): re-apply idempotency, rollback, `remove`, breaking cache hardlinks, end-to-end `scan --mode agent` via the stub, unicode / space paths, and deno.lock v3 / v5 never edited (`--frozen` still OK).

## Backlog

0. A maintainer needs to delete the stale probe branches `bughunt/deno/20260930-deno-store` and `bughunt/deno/20261001-scoped-jsr`. The git proxy refuses `push --delete`.
1. #406 follow-ups: pnpm-lock / yarn.lock / bun.lock beside deno.lock. Done: Deno 1.46.3 (affected) and vendored (affected, and VEX survives the install).
2. `.deno` peer-variant and scoped transitive entries, once #373 is fixed.
3. Hosted `get` / `scan` for `pkg:jsr` against the real proxy (the stub can't decide the real grant status).
4. `nodeModulesDir: none`: deno.lock as a lockfile supplement (enhancement).
5. CRLF / BOM `deno.jsonc` / `deno.lock`, and `DENO_DIR` with spaces, on Windows.

## Known non-bugs

- `patches-api.socket.dev` and `dl.deno.land` / `deno.land` are proxy-denied in the sandbox. Use GitHub release zips and a local stub.
- `nodeModulesDir: "none"` (the Deno 2 default without package.json) keeps npm packages only in the shared `DENO_DIR/npm/registry.npmjs.org/<name>/<ver>`. Agent apply fails loudly (`package_not_installed`, `partialFailure`). `scan` says "No packages found" because deno.lock isn't a documented lockfile-supplement source.
- `setup` was removed in v5 (#277). The earlier "package.json postinstall hook Deno never runs" GAP and the `setup.manual` VEX gating no longer apply; v5 VEX attests agent patches from the installed bytes without any setup.
- `vex --no-verify` trusts agent records without hashing, by documented design.
- Hosted `scan` in a deno.json-only project warns `redirect_npm_no_lockfile` and exits 0 / success. Hosted refusals don't change exit status (CLI_CONTRACT).
- Hosted `get pkg:jsr/...` gives `redirected: 0` with only a human "no lockfile entry" line (no JSON code). Unverified against the real proxy; revisit (backlog 3).
- `nodeModulesDir: "auto"` / `"manual"` are Deno 2 values; on 1.x, use `true`.
- `setup.manual: ["deno"]` (legacy) covered only `pkg:jsr`; `npm:` deps are the npm ecosystem.
