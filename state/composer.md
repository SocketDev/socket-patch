[agent] Progress ledger for the scheduled Composer bug-hunt routine (label pm:composer).

Last updated: 2026-10-01 (run 5), main `61cfb9b` (after #358 Composer rewriter + hosted-by-default scan/get, #446 `-g` scoping), latest release v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Upstream `composer-compatibility.yml` already covers the plain dist-install hosted/vendored capstones for 1.10 → 2.10 on Ubuntu/Windows/macOS. This ledger tracks the edges it doesn't.

| OS | Composer (PHP) | Agent: `setup` (LF) | Agent: `setup` CRLF / escapes | Agent: apply (path repo / installed.json) | Scan: custom vendor-dir | Hosted: repo capstones | Hosted: repo `options` → transport-options | Hosted: warm cache | Vendored: dist / path-copy install + revert | Vendored: source install → git clone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 (8.1/8.3) | untested | untested (OS/version-independent) | pass | untested | CI | fail #399 | pass | pass | untested on v5 (#355 closed) |
| Linux | 2.2.30 (8.3) | untested | untested | pass | untested | CI | fail #399 | pass | pass | untested on v5 (#355 closed) |
| Linux | 2.8.12 (8.3/8.4) | removed in v5 | removed in v5 (#351 closed) | pass | pass | pass (5/5) | fail #399 | pass | pass | pass ×2 (v5; #355 closed) |
| Linux | 2.10.3 (8.3/8.5) | untested | untested | pass | untested | pass (run 5) | untested (expected #399) | untested | pass | untested on v5 (#355 closed) |
| macOS | 1.10 / 2.2 / 2.10 | untested | untested | pass | untested | CI | untested | untested | pass | untested on v5 (#355 closed) |
| Windows | 1.10 / 2.2 / 2.10 | untested | untested | pass (junction) | untested | CI | untested | untested | pass | untested on v5 (#355 closed) |

"Vendored: source install" covers both `--prefer-source` and source-only VCS lock entries (no dist). "Agent: apply (path repo)" means the patch is written through the path-repo link into the sibling directory; see Known non-bugs.

### Hosted v5 defaults (run 5, main `61cfb9b`, Linux PHP 8.3 unless noted)

| Composer | bare `scan` → reinstall → vex (idempotent re-run) | `--package` / `scan apps/*` / `get <uuid>` | patch upgrade A→B (`updates[]`, `--max-new-patches 0`) | lockfile-only / `packages-dev` / CRLF lock | hosted path-repo entry → install |
| --- | --- | --- | --- | --- | --- |
| 1.10.28 | pass | untested | pass | untested | **fail #399** (PHP 7.2–8.4, Linux/macOS/Windows) |
| 2.2.30 | pass | untested | pass | untested | pass (PHP 7.2 / 8.3) |
| 2.8.12 | pass | pass | pass | pass | pass |
| 2.10.3 | pass | untested | untested | untested | pass |

### Global (`-g`) mode — run 3, main `2463257`

| OS | Composer | `scan -g` report (default home) | hosted `-g` refusal | `-g` apply / vex / rollback | custom global vendor-dir | composer not on PATH |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 / 2.2.30 / 2.8.12 / 2.10.3 | pass | pass | pass | fail #439 | pass (`~/.config`), fail #438 with `XDG_CONFIG_HOME` |
| macOS | 1.10.28 / 2.2.30 / 2.10.3 | pass | pass | pass | fail #439 | untested |
| Windows | 1.10.28 / 2.2.30 / 2.10.3 | fail #438 | pass | fail #438 (pass with explicit `COMPOSER_HOME`) | fail #439 | fail #438 |

Local agent scan with a user-level `$COMPOSER_HOME/config.json` vendor-dir: fail #439 (Linux 2.8.12). Hosted on v5: #399 still reproduces.

### composer/installers `installer-paths` (run 4, main `2463257`, Linux, installers 1.12.0 / 2.3.0)

| Composer | `install-path` recorded | Agent scan / apply / vex / rollback | Hosted rewrite → fresh install → vex | Hosted vex with pristine live bytes | Vendored → install → vex → rollback |
| --- | --- | --- | --- | --- | --- |
| 1.10.28 | no | fail #463 (skipped "not installed", exit 0) | pass (install) | fail #463 (false `not_affected`) | pass (hint names the wrong dir, cosmetic) |
| 2.2.30 | yes | pass | untested | untested | untested |
| 2.8.12 | yes | pass | pass | pass (omits `not_applied`) | pass |
| 2.10.3 | yes (expected) | untested | untested | untested | untested |

OS-independent (pure path logic). macOS/Windows: untested.

## Backlog

1. **Maintainer request (in progress):** global `-g` mode. Remaining: a non-writable global dir must fail loudly (non-root probe), `SOCKET_GLOBAL=1` and space/unicode `--global-prefix` cells, and a re-run after #438/#439 are fixed (PR #442 targets #438), including #446's `-g` scoping inside a hosted Composer project.
2. Hosted rollback on a packagist-origin entry with a non-default `notification-url` / `ssl` transport option (#399 family). Packagist metadata is reachable from the sandbox; zipballs are not.
3. Re-run the Composer 1 installers cells when a fix for #463 lands, and add 2.10.3 installers cells. Re-run the path-repo hosted cell when #399 is fixed.
4. Concurrent `vendor` + `composer install`; an interrupted vendor followed by `repair`.
5. `COMPOSER=<other>.json`: the crawler and hosted mode ignore it (scan finds 0 packages). Only the vex gap is documented. Ask maintainers whether to document it or file it.
6. Delete the leftover probe branches `bughunt/composer/20260930-srconly-probe`, `bughunt/composer/20261001-global-probe` and `bughunt/composer/20261001-c1-topts` (the sandbox git proxy refuses deletes, re-tried in run 5). Needs a maintainer.

## Known non-bugs

- A BOM composer.json: Composer itself rejects it, so a socket-patch refusal is correct.
- Composer 1.10 can't download on PHP 8.5 (documented). Pair it with PHP ≤ 8.4.
- `composer update <pkg>` drops the wiring (documented). Re-run `scan`.
- Composer 1.x keeps an already-installed package on `composer install` after rewiring (documented). Remove `vendor/<v>/<n>` first.
- A `"packages-dev": null` lock: Composer 2.8 itself can't install from it.
- Agent apply follows a path repository's symlink/junction and patches the sibling source. This matches the npm `npm link` / `file:` posture, and Composer created the link from the user's own composer.json.
- Vendored refuses a `/` in a dev branch version (`dev-feature/foo`) with `unsafe_coordinates`: an explicit fail-closed refusal on a shape Socket patches don't target.
- `setup` (and its `--check` / CRLF issues) is gone in v5 (#277/#279). Don't file `setup` bugs against main.
- Sandbox: GitHub zipball downloads and getcomposer.org fail. Composer installs from source, and the phars come from GitHub releases. Prefer local path/VCS/composer-repo fixtures and a mock patch API.
- Repro hygiene: a `vendor/` `.gitignore` pattern also ignores `.socket/vendor/`. Use `/vendor/`.
- Agent mode under `-g` keeps `.socket/manifest.json` in the cwd, so run `rollback -g` from the same directory. This is per-cwd manifest design.
- Mock hygiene: a rollback mock needs `beforeBlobContent` or a `/patches/blob/<hash>` route, or rollback fails with "Before blob could not be downloaded".
- Windows probe hygiene: `composer global config <key> '<json>'` through `composer.bat` mangles the quotes. Write `$COMPOSER_HOME/composer.json` directly.
- A `COMPOSER=<other>.json` renamed manifest/lock isn't read (docs/testing/composer-compatibility.md "Not covered", stated for vex). Scan then reports 0 packages.
- Vendored `vex` still attests when the live installed tree is pristine, with the `vendored_tree_out_of_sync` warning: the committed `.socket/vendor` artifact that the lock consumes is the evidence (docs/usage.md VEX table).
- Hosted → vendored takeover refuses an entry from an inline `package`/custom repository ("does not record packagist as its origin"; restore with `git checkout -- composer.lock`). That's documented fail-closed behaviour, so use a packagist-origin fixture to test takeovers.
- Mock hygiene: manifestless hosted vex only recognizes archive URLs in the canonical `/patch/composer/<name>/<ver>/<token>/<uuid>/<leaf>.zip` shape. Vendored mode needs a `/patch/package` route serving a single-top-dir dist zip.
- `scan --package tool` matching `acme/tool` is documented (last-segment, case-insensitive matching). Prefer purls.
- Hosted `vex` attests an uninstalled entry (`--no-dev`, lockfile-only) from the lock's pinned shasum (CLI_CONTRACT "Hosted … With nothing installed … attests from that pin").
- A hosted pin on a loopback mock origin counts as NEW (not UPGRADE/ALREADY) unless `--patch-server-url` names it. Pass `--patch-server-url` in mock repros of upgrades, `rollback` and `vex`.
- Probe hygiene: `shell: bash` on Actions runs `bash -e`. Put `set +e` in probes that record failing exit codes.
