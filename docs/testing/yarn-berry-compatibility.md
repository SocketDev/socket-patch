# yarn berry compatibility

socket-patch supports yarn berry at cacheKey `10c0` — yarn 4 with the default
`compressionLevel: 0`, the one cache-zip checksum recipe it can reproduce
offline — in both modes: hosted (`scan --mode hosted` routes the locked
descriptors to the hosted tarball through root `package.json` `resolutions` and
re-keys the lock entry `<name>@https://…/<name>-<v>.tgz`, see below) and
vendored (`vendor` wires the root
`package.json` `resolutions` plus the lock's `file:` entry). yarn 2 and 3
(cacheKeys `7` / `8`) are refused by both modes. The node-modules and pnpm
linkers are covered end to end; Plug'n'Play keeps packages inside
`.yarn/cache` zips, so `vendor` refuses it (`vendor_yarn_berry_unsupported`)
and so does `apply` (`yarn_pnp_unsupported`), while standalone `vex` still
attests a hosted lock's `checksum:` pin. Plug'n'Play is decided by the
configured linker (`YARN_NODE_LINKER`, else the nearest rc file at or above
the project that sets `nodeLinker`, else the home folder's rc file; the rc
file is `.yarnrc.yml` unless `YARN_RC_FILENAME` renames it; unset means
berry's default, `pnp`), not by whether a `.pnp.*` loader happens to exist:
`vendor` refuses a lock-only PnP checkout up front, and a stale `.pnp.js` left
by a Yarn 2 migration to `node-modules` or `pnpm` is ignored. Yarn 1 PnP
(`installConfig.pnp`, a classic `yarn.lock`) has no `nodeLinker`, so its
loader is always refused, whatever a berry setting says.

## Hosted pin shape and registry credentials

The hosted pin is what yarn itself writes for a root `resolutions` entry:

- `package.json` gains one descriptor-specific selector per range the lock
  entry carries, routed to the hosted tarball:
  `"resolutions": {"left-pad@npm:^1.3.0": "https://patch.socket.dev/…/left-pad-1.3.0.tgz"}`;
- `yarn.lock` re-keys only that entry, `"left-pad@https://…/left-pad-1.3.0.tgz":`,
  with the same URL as its `resolution:` and the patched `10c0` checksum. Its
  `version:`, `dependencies:` and every dependent's descriptors stay
  byte-identical, and the entry moves to where yarn sorts it.

Why this shape (#404):

- An `npm:` locator — including the `npm:<v>::__archiveUrl=<url>` pin releases
  up to 5.0 wrote — is fetched with yarn's npm fetcher, which attaches the
  configured registry auth (`npmAuthToken`, `YARN_NPM_AUTH_TOKEN`,
  `npmScopes.<scope>.npmAuthToken`) to every scoped package's request, and to
  every request under `npmAlwaysAuth: true`, whatever host the URL names. The
  tarball fetcher sends none.
- A tarball locator under the untouched `npm:` key is rejected by yarn's
  hardened mode (`YN0078: Invalid resolution`), which yarn turns on by itself
  for CI runs on public pull requests and `enableHardenedMode: true` turns on
  anywhere. The `resolutions` pin passes it, so hosted mode assumes every
  berry project may run hardened.

Measured on yarn 4.12.0 (fresh checkout, cold cache, `YARN_NPM_AUTH_TOKEN` +
`npmAlwaysAuth`, hardened mode): `yarn install --immutable --check-cache`
passes for direct and transitive packages, leaves the lock untouched, and the
patch host receives no `Authorization` header; another locked version of the
same package keeps its registry entry. The real-yarn capstone
(`e2e_redirect_yarn_berry_build`) runs that fresh install in hardened mode with
a registry token configured and asserts the patch host received none.

Only yarn berry projects are touched this way: `package.json` is read beside a
berry `yarn.lock` only, and yarn classic, npm, pnpm, bun and vlt pins are
unchanged. `rollback` / `remove` rebuild the original lock key from the
selectors and drop them (an emptied `resolutions` table is removed); a lock
pinned by an older release (`::__archiveUrl=`) is still recognized by `vex`,
rollback and the mode takeovers, and the next hosted `scan` re-pins it.

Refusals (nothing written, the warning names the cause):

- `redirect_yarn_berry_resolutions_conflict` — `package.json` already has a
  user-authored `resolutions` entry for the package (bare, ranged or nested);
  hosted mode never overwrites it.
- `redirect_yarn_berry_manifest_missing` — no root `package.json` object.
- `redirect_yarn_berry_shared_descriptor` — the package is also locked through
  a non-npm entry (yarn's builtin `patch:` compatibility entries for
  `resolve`, `typescript`, `fsevents`), which wraps the same descriptor a pin
  would move.
- `redirect_yarn_berry_artifact_url_unsupported` — an artifact URL yarn could
  not fetch as a tarball (not `http(s)`, not ending in `.tgz`/`.tar.gz`, or
  carrying a query or fragment).

## Test matrix

The `yarn-berry-e2e` job in `.github/workflows/ci.yml` runs
`scripts/yarn-berry-vex-matrix.sh` with `SOCKET_PATCH_YARN_E2E_REQUIRED=1`
(a toolchain or registry problem fails instead of skipping):

| OS | yarn |
| --- | --- |
| ubuntu-latest | 4.0.2 (bare-hex checksums), 4.1.0 (first `10c0/` spelling), 4.6.0, 4.12.0, 4.18.0 |
| macos-latest | 4.12.0 |
| windows-latest | 4.12.0 |

Pull requests skip ubuntu 4.6.0 and 4.12.0 (the `yarn-berry-full` job, which
runs on main pushes, nightly and dispatch).

Each release drives four real-yarn suites — `e2e_redirect_yarn_berry_build`,
`e2e_vendor_yarn_berry_build`, `e2e_yarn4_pnpm_linker_build` and
`e2e_yarn4_workspaces_build` — each ending in the manifest-less VEX matrix of
`tests/yarn_berry_common`, plus `e2e_yarn_legacy_cachekey_refusal_build`
against yarn 2.4.3 and 3.8.7. `mode_migration_npm` covers both mode
takeovers against yarn 4.12.0. Hermetic twins of every shape (no toolchain)
live in `in_process_redirect`, `in_process_vendor`, `e2e_vex_lockfile` and the
core unit tests.

## Line endings

Yarn Berry preserves a file's majority line ending and uses the platform's
ending for a new file. Uniform LF and CRLF files are supported. Mixed line
endings can fail Yarn's immutable-install check; Socket Patch refuses mixed
lockfiles before rewriting them. The suites below cover native and forced CRLF
checkouts.

What socket-patch does with those files:

| | hosted (`yarn.lock`) | vendored (`yarn.lock` + root `package.json`) |
| --- | --- | --- |
| uniformly LF or CRLF | rewritten in the file's own ending; no hosted ledger | lock entry spliced in the file's ending; `package.json` re-serialized in its own layout (BOM, indent, ending, trailing newline) |
| leading BOM | kept | kept, both files |
| mixed CRLF / LF, or a bare CR | refused untouched: `redirect_yarn_berry_mixed_line_endings` | refused before any write: `vendor_yarn_berry_mixed_line_endings` |
| revert (`rollback`, `remove`, takeovers) | upstream entries reconstructed from registry metadata; mixed endings refuse as drift | byte-exact; a lock mixed after vendoring gets the restored entry in the terminator of the entry it replaces |
| mode takeover into this mode | the berry gates (line endings, `cacheKey`, `compressionLevel`) run BEFORE the vendored wiring is reverted; a refused purl stays vendored, byte-identical | the backend's project gates (both files' line endings, `cacheKey`, `compressionLevel`) run BEFORE the hosted redirect is reverted; a refused purl stays hosted, byte-identical |

Every reader — manifest-less `vex`, the lockfile inventory, the npm flavor
sniff, `repair` — splits CRLF lines like LF ones and skips a leading BOM.
The shared hosted golden fixtures stay LF: their TypeScript twin in the
depscan backend has no CRLF path yet.

## Running the suites locally

```bash
SOCKET_PATCH_YARN_E2E_REQUIRED=1 SOCKET_PATCH_YARN_BERRY_VERSION=4.12.0 \
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
cargo test -p socket-patch-cli \
  --test e2e_redirect_yarn_berry_build --test e2e_vendor_yarn_berry_build \
  --test e2e_yarn4_pnpm_linker_build --test e2e_yarn4_workspaces_build \
  --test e2e_yarn_legacy_cachekey_refusal_build -- --nocapture
```

`SOCKET_PATCH_YARN_BERRY_EOL=crlf` runs the same flows on CRLF files on macOS
or Linux: right after each fixture's first `yarn install`, the files yarn
wrote are respelled CRLF — what yarn itself writes on Windows — and yarn keeps
them CRLF on every later write. Each fixture file prints one
`BERRY-EOL|<yarn>|<flow>|<file>|yarn=<ending>|flow=<ending>` line: the ending
yarn wrote (`lf` on macOS and Linux, `crlf` on Windows) and the one the flow
ran on. The `mode_migration_npm` berry legs honor the variable too (run them
with `CI` unset: they do not pin yarn's CI defaults).
