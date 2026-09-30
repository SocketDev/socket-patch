[agent] Progress ledger for the scheduled Deno bug-hunt routine (label pm:deno).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0 (previous 3.3.0).

Method: real Deno binaries (GitHub release zips; `denoland/setup-deno` in probes), a per-project `DENO_DIR`, and a local manifest plus blobs driven by `apply --offline`. The patched bytes record themselves in `globalThis.__SP`, so `deno run` shows which patched modules actually loaded. Scan discovery is checked with a local empty-batch mock via `SOCKET_PROXY_URL`. Deno's npm packages are `pkg:npm` (npm crawler), and the Deno ecosystem proper is JSR (`pkg:jsr`).

## Coverage matrix

| OS | Deno | Agent: direct npm dep (node_modules) | Agent: transitive npm dep (`node_modules/.deno`) | Agent: `nodeModulesDir` none (DENO_DIR only) | Agent: JSR (`vendor: true`) | vendor / hosted refusal | setup |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.46.3 | pass (`true`) | fail #373 | known limitation | fail #374 | untested | untested |
| Linux | 2.0.6 | pass | fail #373 | known limitation | fail #374 | untested | untested |
| Linux | 2.2.15 | pass | fail #373 | known limitation | fail #374 | untested | untested |
| Linux | 2.9.6 | pass | fail #373 | known limitation | fail #374 | pass (`vendor_unsupported_ecosystem` / `vendor_lockfile_missing`) | pass (`no_files`); package.json hook is a known GAP |
| macOS | 1.46.3 / 2.2.15 / 2.9.6 | pass | fail #373 | untested | untested | untested | untested |
| Windows | 1.46.3 / 2.2.15 / 2.9.6 | pass | fail #373 | untested | untested | untested | untested |

Other passes (Linux, 2.9.6): re-apply idempotency, rollback, breaking cache hardlinks, and VEX omitting unapplied patches (`setup.manual: ["npm"]`).

## Backlog

0. Delete the stale probe branch `bughunt/deno/20260930-deno-store`. The git proxy refused `git push --delete` in run 1.
1. `.deno` peer-variant and scoped entries, and Deno workspaces (once #373 is fixed).
2. JSR `vendor: true` on macOS / Windows, and in workspace members (#374).
3. deno.lock v3 / v4 / v5: apply never edits it, and manifest-less VEX gives `manifest_not_found`.
4. `scan --mode vendored|hosted` refusal codes for `pkg:jsr` through the mock.
5. Deno 2.9.6 `--allow-scripts`: does the setup-written npm hook re-apply after a fresh install?
6. CRLF / BOM `deno.jsonc`, unicode or space paths, and `DENO_DIR` with spaces (Windows).

## Known non-bugs

- `patches-api.socket.dev` and `dl.deno.land` are proxy-denied in the sandbox. Use GitHub release zips and a local mock.
- `nodeModulesDir: "none"` (the Deno 2 default without package.json) keeps npm packages only in the shared global cache `DENO_DIR/npm/registry.npmjs.org/<name>/<ver>`. Agent apply fails loudly (`package_not_installed`, `partialFailure`), and the fix is to set `nodeModulesDir`. This is a design limitation, not filed.
- Deno + package.json: `setup` wires an npm postinstall hook that Deno doesn't run by default (≤ 2.2 never; 2.9.6 only with `--allow-scripts`). This is tracked as a baseline GAP in `tests/setup_matrix_deno.rs`.
- `setup.manual: ["deno"]` covers only `pkg:jsr`. The `npm:` deps of a Deno project need `"npm"`, since they are the npm ecosystem.
- `nodeModulesDir: "auto"` / `"manual"` are Deno 2 values; on 1.x, use `true`.
