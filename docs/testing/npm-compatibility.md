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
| 6.14.18 | lockfileVersion 1 | renames the lock | **fails closed**: EINTEGRITY — npm 6 fetches registry dependencies from the configured registry and ignores `resolved`, so the patched sha512 pin rejects the registry bytes (`redirect_npm_legacy_client` warns) | a v1 lock is refused (`vendor_lockfile_version_unsupported`), and a hosted → vendored takeover refuses it before restoring the hosted pin, so the package stays hosted; npm 6 DOES install a vendored **v2** lock (written by npm 7+) from its legacy `dependencies` mirror |
| 7.0.0, 7.24.2, 8.19.4 | lockfileVersion 2 (+ v1 mirror) | renames the lock | patched (npm 6 installing this v2 lock: patched, except an npm alias, which npm 6 fetches from the registry, so it **fails closed** with EINTEGRITY and `redirect_npm_legacy_alias_client` warns) | patched (npm 6 installing this v2 lock: patched, alias nodes included) |
| 9.0.0, 9.9.4, 10.9.9, 11.20.0 | lockfileVersion 3 | renames the lock | patched | patched |
| 12.0.0, 12.1.0 | lockfileVersion 3 | **removed** — npm 12 never reads npm-shrinkwrap.json: a shrinkwrap-only checkout is resolved from the registry into a fresh package-lock.json (so its patches stay unpatched under npm 12, see below), and installs read package-lock.json | patched with a plain `npm ci` — the hosted run writes `allow-remote=all` to the project `.npmrc` (`redirect_npm_allow_remote` warns on every npm hosted run); the same checkout WITHOUT that `.npmrc` is refused EALLOWREMOTE | patched (both locks are rewired in the dual-lock state) |

npm 12 notes:

- `npm patch add` / `npm patch commit` (npm >= 12.1) record the project's own
  diff in the root `package.json` `patchedDependencies`, store it under
  `patches/`, add a `patched: {integrity, path}` record to the lock entry and
  write lockfileVersion 4. Every install extracts the locked tarball and then
  applies that diff, failing `EPATCHFAILED` when it no longer applies. Hosted
  mode therefore leaves such a package on its registry entry, in every npm
  lock, and warns `redirect_npm_patched_dependency_skipped`; other packages in
  the lock are still pinned. Vendored mode refuses the v4 lock
  (`vendor_lockfile_version_unsupported`, naming `npm patch`) (#711).
- `allow-remote` defaults to `none`: any tarball whose `resolved` origin is not
  the configured registry is refused. `allow-remote=root` admits only direct
  dependencies. `allow-remote=all` is the setting a hosted redirect needs; it
  also admits any other url-resolved dependency (the per-entry sha512 pins
  stay enforced). The hosted run writes it to the project `.npmrc` (created,
  or one appended line). Hosted mode keeps no ledger. Once rollback, removal,
  or vendored takeover removes the last hosted npm pin, an `.npmrc` containing
  only that setting is deleted; a file with other settings is retained with
  `npm_allow_remote_left`. The writer respects an explicit other value — in the
  project `.npmrc`, the
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
  install` ignores it, resolves the tree from the registry and writes a fresh
  package-lock.json (npm 12.0.0 – 12.2.0, #899), so a shrinkwrap-only
  rewrite reaches npm <= 11 only: hosted and vendored runs warn
  `redirect_npm_shrinkwrap_only` / `vendor_npm_shrinkwrap_only` and `vex`
  omits the patch (`vex_npm_shrinkwrap_only`). With
  both present, npm 12 installs from package-lock.json while npm <= 11 installs
  from the shrinkwrap — so hosted and vendored rewrites wire BOTH, and
  manifest-less VEX refuses to attest a package one lock wires while the other
  still resolves it from the registry or has no entry for that `name@version`
  (missing, or only another version that may no longer satisfy
  `package.json`), which npm can re-resolve from the registry
  (`patched_ref_unattributable`).
- `allow-file` defaults to `all`: vendored `file:` tarballs install unchanged.

Dependencies that ship their own `npm-shrinkwrap.json` (#753): the lock marks
such a package `"hasShrinkwrap": true` (`firebase-tools`, `netlify-cli`), and
npm 7–11 install everything beneath it from that package's own shrinkwrap,
ignoring the root lock's entries (npm 12.2.0 honors the root lock). A copy of
the patched `name@version` there is never rewired: hosted and vendored scans
skip it with `redirect_npm_shrinkwrapped_instance_skipped` /
`vendor_shrinkwrapped_instance_skipped` (vendoring refuses with
`vendor_lock_entry_not_rewritable` when it is the only copy), and VEX does not
attest the package while that unpatched copy installs
(`patched_ref_unattributable`); `vendor --check` fails naming that copy.

## Suites

| Suite | npm | What it proves |
| --- | --- | --- |
| `e2e_redirect_npm_build` (`#[ignore]`) | real | scan / get-uuid / get-ghsa hosted redirects, shrinkwrap flavor, tampered-tarball rejection, fresh-checkout `npm ci`, manifest-less VEX tail |
| `e2e_vendor_npm_build` | real | vendor / get-vendored, shrinkwrap flavor, npm 6 × v2 lock, idempotency, byte-exact revert, manifest-less VEX tail |
| `e2e_vex_lockfile::npm` | none | tamper / spoof / mismatch / pin cells over lockfileVersion 1, 2, 3, shrinkwrap and dual-lock shapes |
| `redirect_npm_allow_remote` | none | the npm 12 `allow-remote` auto-config: `.npmrc` create / append (BOM, CRLF), explicit values respected (project file, user / global config, env var), unhonored spellings, bare-CR and indented-section files, section-scoped copies, opt-out flag + env, dry run, symlinked `.npmrc`, `--silent`, rollback/removal deleting a standalone setting or warning `npm_allow_remote_left` when other settings remain; `replace-registry-host` rewriting the hosted pin (project file, user config, env var) warned `redirect_npm_replace_registry_host` |
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

Full run results belong with the source revision and toolchain versions in CI
artifacts or a local output directory. See the [testing guide](README.md#ci-and-results).
