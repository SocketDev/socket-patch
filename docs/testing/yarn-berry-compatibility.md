# yarn berry compatibility

socket-patch supports yarn berry at cacheKey `10c0` — yarn 4 with the default
`compressionLevel: 0`, the one cache-zip checksum recipe it can reproduce
offline — in both modes: hosted (`scan --mode hosted` rewrites the lock entry's
`resolution:` to the hosted tarball-URL locator `<name>@https://…/<name>-<v>.tgz`)
and vendored (`vendor` wires the root
`package.json` `resolutions` plus the lock's `file:` entry). yarn 2 and 3
(cacheKeys `7` / `8`) are refused by both modes. The node-modules and pnpm
linkers are covered end to end; Plug'n'Play keeps packages inside
`.yarn/cache` zips, so `vendor` refuses it (`vendor_yarn_berry_unsupported`)
and so does `apply` (`yarn_pnp_unsupported`), while standalone `vex` still
attests a hosted lock's `checksum:` pin.

## Registry credentials

The hosted pin is a plain tarball-URL locator, never an `npm:` one. Yarn
fetches an `npm:` locator — including the `npm:<v>::__archiveUrl=<url>` form
releases up to 5.0 wrote — with its npm fetcher, which attaches the configured
registry auth (`npmAuthToken`, `YARN_NPM_AUTH_TOKEN`, `npmScopes.<scope>.npmAuthToken`)
to every scoped package's request, and to every request under
`npmAlwaysAuth: true`, whatever host the URL names (#404). The tarball fetcher
sends no registry auth and builds the identical cache zip, so the `10c0`
checksum is unchanged. Measured on yarn 4.12.0 with a fresh checkout and a cold
cache: the old form sent `Authorization: Bearer <token>` to the patch host in all
three configurations, the tarball locator sent none, and `yarn install
--immutable` left the lock untouched. A lock carrying the old form keeps being
recognized by `vex`, rollback and the mode takeovers, and the next hosted `scan`
re-pins it. An artifact URL yarn could not fetch as a tarball (not `http(s)`, not
ending in `.tgz`/`.tar.gz`, or carrying a query or fragment) is refused with
`redirect_yarn_berry_artifact_url_unsupported`, leaving the entry untouched.

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
