# npm hosted / vendored compatibility

Hosted mode (`scan --mode hosted`, `get --mode hosted`) repoints a
package-lock.json / npm-shrinkwrap.json entry's `resolved` + `integrity` at the
patched tarball on the Socket patch server; vendored mode (`vendor`,
`scan --mode vendored`) repoints it at a committed
`.socket/vendor/npm/<uuid>/<name>-<version>.tgz`. Both leave NO
`.socket/manifest.json` requirement behind: `socket-patch vex` attests them
from the lockfile wiring alone (plus the ledgers, or the patch API).

## What each npm major writes and installs

Measured against the real releases (Node 24.21 on macOS, 2026-09-22):

| npm | `npm install` writes | `npm shrinkwrap` | Hosted install of a redirected lock | Vendored install |
| --- | --- | --- | --- | --- |
| 6.14.18 | lockfileVersion 1 | renames the lock | **fails closed**: EINTEGRITY — npm 6 fetches registry dependencies from the configured registry and ignores `resolved`, so the patched sha512 pin rejects the registry bytes (`redirect_npm_legacy_client` warns) | a v1 lock is refused (`vendor_lockfile_version_unsupported`); npm 6 DOES install a vendored **v2** lock (written by npm 7+) from its legacy `dependencies` mirror |
| 7.0.0, 7.24.2, 8.19.4 | lockfileVersion 2 (+ v1 mirror) | renames the lock | patched | patched |
| 9.0.0, 9.9.4, 10.9.9, 11.20.0 | lockfileVersion 3 | renames the lock | patched | patched |
| 12.0.0, 12.1.0 | lockfileVersion 3 | **removed** — a committed shrinkwrap gets a package-lock.json twin on first install, and installs read the twin | patched with a plain `npm ci` — the hosted run writes `allow-remote=all` to the project `.npmrc` (`redirect_npm_allow_remote` warns on every npm hosted run); the same checkout WITHOUT that `.npmrc` is refused EALLOWREMOTE | patched (both locks are rewired in the dual-lock state) |

npm 12 notes:

- `allow-remote` defaults to `none`: any tarball whose `resolved` origin is not
  the configured registry is refused. `allow-remote=root` admits only direct
  dependencies. `allow-remote=all` is the setting a hosted redirect needs; it
  also admits any other url-resolved dependency (the per-entry sha512 pins
  stay enforced). The hosted run writes it to the project `.npmrc` (created,
  or one appended line; ledger kind `redirect_npmrc_allow_remote`, removed by
  `rollback` / `remove` / the vendored takeover once no package-lock entry
  needs it), respects an explicit other value — in the project `.npmrc`, the
  user / global / builtin npm config, or an `npm_config_allow_remote`
  environment variable (which beats every `.npmrc`) — and is disabled by
  `--no-npm-allow-remote-config`.
- `.npmrc` grammar, measured on 12.1.0 with a real EALLOWREMOTE/ENOTFOUND
  install probe: only the exact key `allow-remote` is honored (`allow_remote`
  and `ALLOW-REMOTE` are ignored — npm normalizes `npm_config_*` environment
  variables, not `.npmrc` keys); a BOM, CRLF, surrounding whitespace, quotes
  and inline `;` comments are tolerated; keys under an ini `[section]` are not
  top-level config; the last top-level assignment wins. The sniff follows
  npm's bundled `ini` parser exactly (cross-checked differentially in the
  `npmrc` unit tests): a bare `\r` ends a line like `\n`, and a section
  header only counts when the UNTRIMMED line matches `^\[...\]\s*$` — an
  indented or BOM-prefixed `[sec]` is a plain top-level key. The gate compares the
  value case-sensitively (`all` admits everything, `none` nothing, anything
  else — `root`, `All`, a typo — only direct dependencies).
- `npm ci` refuses a project whose only lock is npm-shrinkwrap.json; `npm
  install` copies it to package-lock.json and installs from the copy. With
  both present, npm 12 installs from package-lock.json while npm <= 11 installs
  from the shrinkwrap — so hosted and vendored rewrites wire BOTH, and
  manifest-less VEX refuses to attest a package one lock wires while the other
  still resolves it from the registry (`patched_ref_unattributable`).
- `allow-file` defaults to `all`: vendored `file:` tarballs install unchanged.

## Suites

| Suite | npm | What it proves |
| --- | --- | --- |
| `e2e_redirect_npm_build` (`#[ignore]`) | real | scan / get-uuid / get-ghsa hosted redirects, shrinkwrap flavor, tampered-tarball rejection, fresh-checkout `npm ci`, manifest-less VEX tail |
| `e2e_vendor_npm_build` | real | vendor / get-vendored, shrinkwrap flavor, npm 6 × v2 lock, idempotency, byte-exact revert, manifest-less VEX tail |
| `e2e_vex_lockfile::npm` | none | tamper / spoof / mismatch / pin cells over lockfileVersion 1, 2, 3, shrinkwrap and dual-lock shapes |
| `redirect_npm_allow_remote` | none | the npm 12 `allow-remote` auto-config: `.npmrc` create / append (BOM, CRLF), explicit values respected (project file, user / global config, env var), unhonored spellings, bare-CR and indented-section files, section-scoped copies, opt-out flag + env, dry run, symlinked `.npmrc`, `--silent`, rollback removing exactly what was added, `remove` surfacing `redirect_npmrc_allow_remote_modified` |
| `e2e_hosted_production` / `e2e_vendored_production` (`#[ignore]`) | real (ambient) | the same flows against production, ending in the manifest-less VEX tail |

The manifest-less VEX tail (`tests/npm_e2e_common/manifestless.rs`) runs four
cells over the committed + freshly installed checkout: manifest deleted
(attested with the `(redirected)` / `(vendored)` marker and the record's vuln
ids), ledgers deleted too (attested from lockfile discovery + the patch API),
`--offline` without ledgers (`record_unavailable`, zero API requests), and the
lock reverted to its registry bytes with ledgers and artifacts kept (not
attested — `redirect_unwired` / `vendor_unwired` — with and without
`--no-verify`), plus the embedded `apply --vex` / `vendor --vex` twins.

## Running one npm release locally

```sh
npm install --prefix /tmp/npm-12 --no-audit --no-fund npm@12.1.0
export SOCKET_PATCH_NPM_E2E_BIN=/tmp/npm-12/node_modules/.bin/npm
export SOCKET_PATCH_NPM_E2E_VERSION=12.1.0
export SOCKET_PATCH_NPM_E2E_REQUIRED=1
cargo test -p socket-patch-cli --test e2e_redirect_npm_build -- --include-ignored
cargo test -p socket-patch-cli --test e2e_vendor_npm_build -- --include-ignored
```

`SOCKET_PATCH_NPM_E2E_REQUIRED` turns a missing npm, a version mismatch or an
unreachable registry into a failure instead of a skip.
`SOCKET_PATCH_NPM_E2E_RESULTS=<file>` appends one results row per flow. The npm
6 cross-version cell needs an npm >= 7 to write its v2 lock: `npm` on `PATH`,
or `SOCKET_PATCH_NPM_E2E_LOCK_WRITER_BIN`.

## Local results (2026-09-22)

Every row below ran both real-npm suites with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`
on Node 24.21 (macOS): all 20 legs green, 77 manifest-less VEX matrices, each
with all four cells (manifest deleted, ledgers deleted, `--offline`, lock
reverted) passing. Re-run 2026-09-23 after the `.npmrc` auto-config landed:
`e2e_redirect_npm_build` on 10.9.9, 11.20.0 and 12.1.0 (every hosted flow
installs from the committed, auto-configured `.npmrc` with a plain `npm ci`;
the main capstone's `rollback` removes it) and `e2e_vendor_npm_build` on
12.1.0 (no `.npmrc`), all green with every manifest-less VEX cell passing.

| npm | hosted flows (scan, get uuid, get GHSA, shrinkwrap) | hosted fresh install | vendored flows | vendored fresh install |
| --- | --- | --- | --- | --- |
| 6.14.18 | 4 | refused EINTEGRITY (fail closed); VEX cells on the lockfile basis | v1 lock refused; npm 6 × v2-lock cell | patched (from the v2 legacy mirror) |
| 7.0.0 | 4 | patched | vendor, get vendored, in-place VEX, shrinkwrap | patched |
| 7.24.2 | 4 | patched | 4 | patched |
| 8.19.4 | 4 | patched | 4 | patched |
| 9.0.0 | 4 | patched | 4 | patched |
| 9.9.4 | 4 | patched | 4 | patched |
| 10.9.9 | 4 | patched | 4 | patched |
| 11.20.0 | 4 | patched | 4 | patched |
| 12.0.0 | 4 | EALLOWREMOTE, then patched with `allow-remote=all` (measured before the auto-config) | 4 (shrinkwrap: both locks wired) | patched |
| 12.1.0 | 4 | patched with a plain `npm ci` from the auto-configured `.npmrc` (EALLOWREMOTE without it); `rollback` removes the `.npmrc` | 4 (shrinkwrap: both locks wired) | patched |
