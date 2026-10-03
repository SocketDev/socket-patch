[agent] Progress ledger for the scheduled Deno bug-hunt routine (label pm:deno).

Last updated: 2026-10-03 (run 11), main `045d7ec`, latest release 4.0.0 (previous 3.3.0). Newest Deno is 2.9.7. #373 is fixed on main (#496) and verified on Linux, macOS and Windows. #603 (`_1` VEX) still reproduces on main. Its unmerged fix PR #605 (`b92456b`) fixes the vex verdict in both directions on Linux 2.9.7 / 2.2.15, but not the rollback under-count.

Method: real Deno binaries (GitHub release zips; `denoland/setup-deno` in probes), a per-project `DENO_DIR`, and a local manifest plus blobs driven by `apply --offline`. The patched bytes record themselves in `globalThis.__SP`, so `deno run` shows which patched modules actually loaded. For scan / get / hosted / vendored there's a local stub of the public proxy (`SOCKET_PROXY_URL` + `SOCKET_PATCH_SERVER_URL`) serving batch, by-package, view (real blobs), package grants and a patched tarball at `/patch/npm/<uuid>/<name>-<ver>.tgz`. Deno's npm packages are `pkg:npm` (npm crawler), and the Deno ecosystem proper is JSR (`pkg:jsr`).

## Coverage matrix

| OS | Deno | Agent: direct npm dep (incl. scoped, alias, workspace member) | Agent: transitive npm dep (`node_modules/.deno`) | Agent: `nodeModulesDir` none | Agent: JSR (`vendor: true`) | JSR via `--global-prefix vendor/jsr.io` | vendored refusal | hosted / vendored (npm deps via package-lock.json) | VEX |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.46.3 | pass | pass on `045d7ec` | known limitation | fail #374 | pass | pass for `pkg:npm` (deno.lock v3 only: `vendor_lockfile_missing`, rc 1) | hosted fail #406 | pass (agent), fail #406 (hosted) |
| Linux | 2.0.6 | pass (run 1) | pass on `045d7ec` | known limitation | fail #374 | untested | pass for `pkg:npm` (deno.lock v4: `vendor_lockfile_missing`, rc 1) | untested | pass (agent) |
| Linux | 2.2.15 | pass | fail #373 on `61cfb9b` (fixed on main) | known limitation | fail #374 | pass | pass for `pkg:npm` (deno.lock v4: `vendor_lockfile_missing`, rc 1) | hosted + vendored fail #406 (package-lock + deno.lock) | fail #406 |
| Linux | 2.9.6 | pass | fail #373 on `61cfb9b` (also `--prune` drops records); fixed on main | known limitation | fail #374 | pass (scan + apply; unsafe with npm deps, see #374) | pass for `pkg:jsr` (`vendor_unsupported_ecosystem`) | hosted + vendored fail #406 | pass (agent), fail #406 (hosted) |
| macOS | 1.46.3 / 2.2.15 / 2.9.6 | pass (scoped; apply / vex / rollback) | pass on `045d7ec` (2.2.15, 2.9.7 probe) | untested | fail #374 | pass | untested | untested | pass (agent) |
| Windows | 1.46.3 / 2.2.15 / 2.9.6 | pass (scoped via junctions; apply / vex / rollback) | pass on `045d7ec` (2.2.15, 2.9.7 probe) | untested | fail #374 | pass | untested | untested | pass (agent) |
| Linux | 2.9.7 | pass (also `links`) | pass on `b1f9818` (#373 fixed) | untested | untested | untested | pass for `pkg:npm` in a deno.lock-only project (`vendor_lockfile_missing`, exit 1, files untouched) | fail #406 (lockfile-only vex) | pass (agent) |

### Isolated `.deno` store edge cases (agent mode, Linux)

| Deno | copy-index peer variant `<name>@<ver>_1` of a direct dep | hashed mixed-case name `_<base32>@<ver>` | scoped transitive `@scope+name@ver` | isolated workspace (deno.json + package.json members) |
| --- | --- | --- | --- | --- |
| 1.46.3 | n/a (single copy) | pass on `045d7ec` | pass on `045d7ec` | pass on `045d7ec` (run 11) |
| 2.0.6 / 2.2.15 | apply: fail #373 on `61cfb9b`, fixed on main; VEX partial revert of `_1`: fail #603 (2.2.15), fixed by #605 head `b92456b` | untested | fail #373 on `61cfb9b` | 2.2.15: pass on `045d7ec` (run 11) |
| 2.9.7 | apply / runtime / rollback / remove / `get --mode agent` / `scan --mode agent` / `scan --sync`: pass on `045d7ec`; VEX partial revert of either copy: fail #603 on main, pass on #605 head `b92456b`; rollback count with a mixed state under-reports (#603 comments, still there on #605) | pass on `045d7ec` | pass on `045d7ec` | pass (also wipe + reinstall vex, incremental `deno add`) |
| macOS / Windows 2.2.15, 2.9.7 (probe) | apply / runtime / vex / rollback / frozen reinstall: pass on `045d7ec` | pass (case-insensitive FS) | — | untested |

### `nodeModulesLinker: "hoisted"` (Deno ≥ 2.8, needs `nodeModulesDir: manual`), agent mode

| OS | Deno | direct | nested transitive | `DENO_DIR` cache untouched | re-apply | vex | rollback | scan discovery |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux / macOS / Windows | 2.8.3, 2.9.7 | pass | pass | pass | pass | pass | pass | pass (Linux 2.9.7) |
| Linux | 2.9.7, `workspace` members | pass (doubly nested too) | pass | — | — | pass | pass | — |
| Linux | 2.9.7, duplicate copies of one `name@version` | pass (both patched) | — | — | — | fail (only the first copy is hashed; handed over to npm) | — | — |
| Linux | 2.9.7, `deno install` after apply, then rollback | — | — | — | — | — | pass (`alreadyOriginal`, rc 0, manifest emptied) | — |

### Global mode (`-g` / `--global-prefix` / `SOCKET_GLOBAL`), `deno install -g` of a tool with an `npm:` dep

| OS | Deno | `scan -g` report | `apply -g` | `--global-prefix` on `$DENO_DIR` layouts | 2.9 per-tool `bin/.<tool>/node_modules` | rollback -g | vex -g | hosted refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.46.3 / 2.2.15 | fail #444 | fail #444 | fail #444 | n/a | untested (blocked by #444) | fail #444 (`no_applicable_patches`) | pass (2.9.6) |
| Linux | 2.9.6 | fail #444 | fail #444 | fail #444 | fail #444 (false `applied` + VEX for local/JSR tools; pass for `npm:` tools) | untested | fail #444 | pass |
| Linux | 2.7.0 → 2.9.7 (layout only) | — | — | — | per-tool dir from 2.7.0; decoy `node_modules` for local tools by 2.7.14 (#444 comment) | — | — | — |
| Linux / macOS / Windows | 1.46.3, 2.0.6, 2.2.15, 2.4.5, 2.9.6 (probe) | Windows also #434 | fail #444 | fail #444 | 2.9.6 only: fail #444 | untested | 2.9.6 decoy: false `not_affected` | untested |

Other passes (Linux): `DENO_DIR` inside the project (`./.deno_cache`; never patched, `none` gives the documented `package_not_installed`), interrupted `apply` (SIGKILL mid-run; the hardlinked `DENO_DIR` cache stays pristine and a re-run completes), concurrent `apply` / `rollback` (`lock_held`), an immutable (`chattr +i`) target fails loudly (`apply_failed`, exit 1), `list --json`, re-apply idempotency, rollback, `remove`, breaking cache hardlinks, end-to-end `scan --mode agent` via the stub, unicode / space paths, and deno.lock v3 / v4 (2.2.15) / v5 never edited (`--frozen` still OK, patched copy loads).

## Backlog

0. **Maintainer request (global mode), partly covered.** Filed #444 (still open on `045d7ec`, no fix PR). Still to do: an unwritable global prefix (read-only `DENO_INSTALL_ROOT` / `DENO_DIR`) on macOS / Windows, `rollback -g` after #444 is fixed, and `DENO_DIR` with spaces or unicode.
1. A maintainer needs to delete the probe branches `bughunt/deno/20260930-deno-store`, `bughunt/deno/20261001-scoped-jsr`, `bughunt/deno/20261001-global`, `bughunt/deno/20261001-hoisted` and `bughunt/deno/20261003-store-xos`. The git proxy refuses `push --delete` (the remote hangs up).
2. #603 once #605 lands: re-run the two-direction revert on main and close #603. Raise the rollback under-count (pristine root + patched `_1` reports `rolledBack: 0`) separately if it's still there (check npm/pnpm for a duplicate first).
3. #406 follow-ups: pnpm-lock / yarn.lock / bun.lock beside deno.lock (check for duplicates of #406 first).
4. Isolated workspace on macOS / Windows (probe), and the hashed mixed-case name on Linux 2.2.15.
5. JSR: `get` by GHSA / CVE through the stub (needs a search route), and hosted `get pkg:jsr/...` against the real proxy shape. `nodeModulesDir: none` on macOS / Windows (low value).

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
- Deno names a second peer resolution `.deno/<name>@<ver>_N` (copy index) and a mixed-case package `.deno/_<base32 hash>@<ver>` (in `$DENO_DIR` too). Those are real installs, not junk; #496 (on main) decodes both.
- `rollback` removes the manifest entries it restores (`manifest.removedEntries`), so a later `apply` is a no-op. That's by design.
- Offline VEX fixtures: give each patch its own GHSA. A shared vulnerability ID lets one verified PURL keep the statement alive and hides per-PURL failures.
- The duplicate `applied` + `already_patched` events for one PURL in an isolated Deno workspace come from the member `node_modules/<dep>` symlink reaching the same file. Cosmetic.
- SIGKILL / SIGTERM during `apply` leaves one `.socket-stage-*` file in the package dir that later runs never remove. This is generic to the atomic writer, harmless (never loaded), and SIGINT exits cleanly.
- When a probe snapshots `node_modules/.deno` with `cp -R`, macOS reports "Directory loop detected" and Windows git-bash can't recreate junctions ("Only in …"). Those are probe artifacts. Judge rollback by its JSON and the runtime markers.
- Deno 2.2.15 (not 2.9.7) leaves stale `.deno/<name>@<old>` dirs after a version change. A patched orphan copy keeps `vex` attesting `not_affected` for a version the product no longer loads. That's harmless, because the vulnerable component isn't present either.
- `apply -e deno` in a project with only `npm:` deps is a clean no-op: those deps are the npm ecosystem, and `-e npm` patches them.
