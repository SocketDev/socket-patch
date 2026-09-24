# yarn berry compatibility

socket-patch supports yarn berry at cacheKey `10c0` — yarn 4 with the default
`compressionLevel: 0`, the one cache-zip checksum recipe it can reproduce
offline — in both modes: hosted (`scan --mode hosted` rewrites the lock entry
to the hosted `::__archiveUrl=`) and vendored (`vendor` wires the root
`package.json` `resolutions` plus the lock's `file:` entry). yarn 2 and 3
(cacheKeys `7` / `8`) are refused by both modes. The node-modules and pnpm
linkers are covered end to end; Plug'n'Play keeps packages inside
`.yarn/cache` zips, so `vendor` refuses it (`vendor_yarn_berry_unsupported`)
and so does `apply` (`yarn_pnp_unsupported`), while standalone `vex` still
attests a hosted lock's `checksum:` pin.

## Test matrix

The `yarn-berry-e2e` job in `.github/workflows/ci.yml` runs
`scripts/yarn-berry-vex-matrix.sh` with `SOCKET_PATCH_YARN_E2E_REQUIRED=1`
(a toolchain or registry problem fails instead of skipping):

| OS | yarn |
| --- | --- |
| ubuntu-latest | 4.0.2 (bare-hex checksums), 4.1.0 (first `10c0/` spelling), 4.6.0, 4.12.0, 4.18.0 |
| macos-latest | 4.12.0 |
| windows-latest | 4.12.0 |

Each release drives four real-yarn suites — `e2e_redirect_yarn_berry_build`,
`e2e_vendor_yarn_berry_build`, `e2e_yarn4_pnpm_linker_build` and
`e2e_yarn4_workspaces_build` — each ending in the manifest-less VEX matrix of
`tests/yarn_berry_common`, plus `e2e_yarn_legacy_cachekey_refusal_build`
against yarn 2.4.3 and 3.8.7. `mode_migration_npm` covers both mode
takeovers against yarn 4.12.0. Hermetic twins of every shape (no toolchain)
live in `in_process_redirect`, `in_process_vendor`, `e2e_vex_lockfile` and the
core unit tests.

## Line endings

yarn berry keeps one line ending per file, chosen by the same function for
the lockfile and every manifest. At tag `@yarnpkg/cli/4.12.0` (the same code
ships at 4.0.0 and 4.18.0; the published 3.8.7, 4.0.2, 4.6.0, 4.9.2 and
4.18.0 bundles carry it verbatim, and 2.4.3 applies the same rule through
`changeFilePromise`):

- `packages/yarnpkg-fslib/sources/FakeFS.ts` (lines 799–812):
  `getEndOfLine(content)` returns `os.EOL` when `content` has no line break —
  the file is new — and otherwise `\r\n` only when CRLF breaks strictly
  outnumber LF ones (a tie is LF); `normalizeLineEndings(original, next)`
  respells every break of `next` that way.
- `packages/yarnpkg-core/sources/Project.ts`: `persistLockfile` (lines
  2014–2033) writes the generated lock through `normalizeLineEndings` against
  the current file; the `--immutable` check (lines 1789–1858) fails with
  YN0028 whenever `normalizeLineEndings(initialLockfile, generateLockfile())`
  differs from the file — so a uniformly CRLF lock passes, while a lock with
  mixed endings (or a BOM, which the re-render never writes) always fails.
- `packages/yarnpkg-core/sources/Workspace.ts` (lines 217–229):
  `persistManifest` writes `JSON.stringify(data, null, indent) + "\n"` through
  `changeFilePromise(…, {automaticNewlines: true})`, the same rule, after every
  install (`Project.ts` line 1881, `--immutable` included).
  `Manifest.loadFromText` strips a BOM when reading (`Manifest.ts` lines
  135–146 and 984–990); the rewrite never writes one back.
- `packages/yarnpkg-parsers/sources/syml.ts`: `parseSyml` reads the lock with
  js-yaml, which accepts CRLF.

So on Windows every yarn berry project starts CRLF: the first `yarn install`
writes a CRLF `yarn.lock`, and a `package.json` yarn pretty-prints for the
first time (any compact one) comes back CRLF. On macOS and Linux both are LF.
An existing file keeps its majority ending on every OS. Git adds its own
path to CRLF: `core.autocrlf=true` (the Git for Windows installer's default)
checks LF-committed text out as CRLF, and so does `core.autocrlf=true` or a
`text eol=crlf` attribute on macOS and Linux; a lock committed with CRLF stays
CRLF in every checkout.

What socket-patch does with those files:

| | hosted (`yarn.lock`) | vendored (`yarn.lock` + root `package.json`) |
| --- | --- | --- |
| uniformly LF or CRLF | rewritten in the file's own ending; ledger fragments recorded as on disk | lock entry spliced in the file's ending; `package.json` re-serialized in its own layout (BOM, indent, ending, trailing newline) |
| leading BOM | kept | kept, both files |
| mixed CRLF / LF, or a bare CR | refused untouched: `redirect_yarn_berry_mixed_line_endings` | refused before any write: `vendor_yarn_berry_mixed_line_endings` |
| revert (`rollback`, `remove`, takeovers) | byte-exact; a ledger recorded before a uniform LF ↔ CRLF checkout flip is replayed respelled; a mixed lock refuses as drift | byte-exact; a lock mixed after vendoring gets the restored entry in the terminator of the entry it replaces |

`setup` / `setup --remove` write `package.json` in the same layout-keeping
way (BOM, indent, ending, trailing newline), so the pair round-trips
byte-exactly on a CRLF manifest too.

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
