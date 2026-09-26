# Composer compatibility

`socket-patch` supports hosted and vendored Composer patches on every Composer
release from 1.10 through 2.10. Both modes edit `composer.lock` only:
`composer.json` and the lock's `content-hash` (which covers `composer.json`
alone) are never touched, so the edit raises no "lock file is not up to date"
warning. The real-Composer capstones install from the rewritten lock and
compare the installed bytes with the patch; rewriting alone is not an
installation result.

See the [ecosystem matrix](../ecosystems.md#mode--ecosystem-matrix) for other
package managers and `crates/socket-patch-cli/CLI_CONTRACT.md` for the wiring
contract.

## What each mode writes

| Mode | Lock entry after the rewrite |
| --- | --- |
| Vendored (`vendor`, `scan`/`get --mode vendored`) | `dist` → `{"type": "path", "url": ".socket/vendor/composer/<uuid>/<vendor>/<name>@<version>", "reference": "<patch-uuid>"}` in the original slot, `"transport-options": {"symlink": false}` after it, `source` removed. The patched copy is committed under `.socket/vendor/composer/`. |
| Hosted (`scan --mode hosted`) | `dist.type` → `zip`, `dist.url` → the hosted archive, `dist.shasum` → its sha1 (inserted when the lock had none). The entry's top-level `source` is removed wherever it sits in the entry, and `dist.mirrors` is removed (`redirect_composer_dist_mirrors_removed`). A `source` that is not an object is left and warned about (`redirect_composer_source_kept`). |

The lock's `version` spelling is never rewritten (`v6.4.1` stays `v6.4.1`).
Patch coordinates are matched by Composer release identity, so a lock
`3.0.2`, `v3.0.2` and a patch purl `3.0.2.0` name the same release.

Both modes are idempotent: a re-run over a rewritten lock records no edit.
A hosted re-run over a lock rewritten by an older CLI or by the GitHub app
(redirected `dist` with `source` or `mirrors` still present) heals it with one
edit. `vendor --revert` and the hosted revert restore the recorded fragments
byte for byte.

## Test matrix

`.github/workflows/composer-compatibility.yml` runs, for each cell, the
vendored (`e2e_vendor_composer_build`) and hosted
(`e2e_redirect_composer_build`) real-Composer capstones plus the hermetic
`composer::` VEX cells, against a checksum-pinned `composer.phar`:

| OS | Composer (PHP) |
| --- | --- |
| Ubuntu | 1.10.28 (8.1), 2.0.14 (8.0), 2.1.14 (8.1), 2.2.30 (8.1, 8.3), 2.5.8 (8.2), 2.8.12 (8.4), 2.9.8 (8.4), 2.10.3 (8.5) |
| Windows | 1.10.28 (8.1), 2.2.30 (8.3), 2.9.8 (8.4), 2.10.3 (8.5) |
| macOS | 1.10.28 (8.1), 2.2.30 (8.3), 2.10.3 (8.5) |
| Docker (Debian 12, PHP 8.2) | 2.2.30, 2.10.3 (`docker_e2e_vendor_composer`) |

The capstones pin psr/log 3.0.2 (PHP ≥ 8.0) and, for the `v`-tagged cells,
symfony/deprecation-contracts `v3.5.1` (`v2.5.4` below PHP 8.1). Run one cell
locally with:

```text
SOCKET_PATCH_PHP_BIN=<php> SOCKET_PATCH_COMPOSER_PHAR=<composer.phar> \
SOCKET_PATCH_COMPOSER_E2E_REQUIRED=1 SOCKET_PATCH_COMPOSER_E2E_VERSION=<version> \
  cargo test -p socket-patch-cli --test e2e_vendor_composer_build \
    --test e2e_redirect_composer_build -- --ignored --nocapture
```

Composer 1.10.28 cannot download on PHP 8.5 (`stream_context_create()` fatal);
pair it with PHP 8.4 or older. The official `composer:1` Docker images ship PHP
8.5 and are unusable for that reason.

## Why `source` is removed: the source fallback

When a dist download fails (a checksum mismatch, an expired grant token, an
outage) Composer may install the package from its `source` instead — the
pristine upstream git commit.

| Composer | Failed dist download with `source` present |
| --- | --- |
| 1.x, 2.0 – 2.9 | "Now trying to download from source": exit 0, **pristine** code installed |
| 2.10+ | "Source fallback is disabled": exit 1, nothing installed (`source-fallback` defaults to false) |

With `source` removed the dist is the only way to install the package, so a
failed fetch fails the install on every version. The
`composer_hosted_keep_source_control_documents_fallback` capstone pins this
table.

`--prefer-source`, `config.preferred-install: "source"` (or a pattern that
resolves to `source` for the package), and, on Composer 1, a `dev-*` version
with no preference, install from `source` even when the dist is fine. A lock
entry that still carries `source` in those setups installs the pristine code
deterministically, which is why the rewriters remove it (only a non-object
`source` is left in place, with a warning).

`dist.mirrors` (written for repositories that advertise dist mirrors, such as
Private Packagist) is tried before `dist.url` when `preferred`; every mirror
serves the unpatched archive, so the hosted rewrite removes it.

## Reinstalling over an existing `vendor/`

| Composer | `composer install` after the lock was rewritten |
| --- | --- |
| 2.x | Reinstalls the package (its dist or source reference changed): patched |
| 1.x | Leaves an installed stable package as it is: **pristine**. Remove `vendor/<vendor>/<name>` first, then run `composer install` |

A fresh checkout installs the patched bytes on every version. `vendor`,
`scan --mode vendored` and `get --mode vendored` print both instructions after
a run that leaves composer packages vendored; `scan --mode hosted` names them in
its next steps. Nothing else prints a Composer reinstall hint.

## Vendored copies and Composer's mirror filters

`transport-options.symlink: false` makes Composer MIRROR the vendored copy into
`vendor/` through the finder `composer archive` uses. That finder skips files
matched by the copy's:

| Filter file | Composer versions that apply it |
| --- | --- |
| `.gitignore` | 1.x – 2.1.x |
| `.gitattributes` `export-ignore` / `-export-ignore` | all |
| `.hgignore` | 1.x |

A package shipping one of them would install with files missing, a patched
file included. The vendored copy's `.gitignore` and `.hgignore` are therefore
truncated to empty and its `.gitattributes` `export-ignore` lines dropped
(`vendor_composer_mirror_filters_neutralized`). Only these three files in the
copy change; the installed `vendor/` tree and the patched files are never
touched. A patch that itself rewrites a filter file needing a change is
refused (`vendor_composer_mirror_filter_conflict`), because neutralizing it
would break the patched file's hash. A re-run over a copy vendored by an older
CLI heals it (commit the change).

## Security blocking in 2.9 and 2.10

Composer 2.9 blocks `update`/`require` of versions with security advisories by
default (`audit.block-insecure`); 2.10 adds the `policy` configuration and
blocks known malware at install time. A lock that pins a vulnerable version
installs, but re-resolving it (for example to reproduce a patched fixture) needs
`config.audit.block-insecure: false` (2.9), `config.policy.advisories.block:
false` (2.10) or `--no-security-blocking`.

## What undoes the wiring

`composer update <pkg>`, `composer update --lock` and a full `composer update`
re-resolve the entry from the repositories on every tested version: the lock
goes back to the registry dist (and `source`), so the patch is silently
dropped. Re-run `socket-patch scan` afterwards.

## Not covered

- `vendor/composer/installed.json` and `COMPOSER=<other>.json` renamed locks
  are not read by `vex`; only the root `composer.lock` is.
- Nested Composer projects are not discovered (discovery is cwd-only).
