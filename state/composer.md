[agent] Progress ledger for the scheduled Composer bug-hunt routine (label pm:composer).

Last updated: 2026-10-02 (run 9), main `203e092` (after #442 global-probe / Composer home fix for #438, #555), latest release v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Upstream `composer-compatibility.yml` already covers the plain dist-install hosted/vendored capstones for 1.10 → 2.10 on Ubuntu/Windows/macOS. This ledger tracks the edges it doesn't.

| OS | Composer (PHP) | Agent: `setup` (LF) | Agent: `setup` CRLF / escapes | Agent: apply (path repo / installed.json) | Scan: custom vendor-dir | Hosted: repo capstones | Hosted: repo `options` → transport-options | Hosted: warm cache | Vendored: dist / path-copy install + revert | Vendored: source install → git clone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 (8.1/8.3) | untested | untested (OS/version-independent) | pass | untested | CI | fail #399 | pass | pass | pass (v5, run 6) |
| Linux | 2.2.30 (8.3) | untested | untested | pass | untested | CI | fail #399 | pass | pass | pass (v5, run 6) |
| Linux | 2.8.12 (8.3/8.4) | removed in v5 | removed in v5 (#351 closed) | pass | pass | pass (5/5) | fail #399 | pass | pass | pass ×2 (v5; #355 closed) |
| Linux | 2.10.3 (8.3/8.5) | untested | untested | pass | untested | pass (run 5) | untested (expected #399) | untested | pass | pass (v5, run 6) |
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

### Vendored v5 edges (run 6, main `61cfb9b`, Linux PHP 8.3)

| Composer | path-repo entry with existing `transport-options` → install → revert | `require-dev` + space/unicode project path → install / `--no-dev` / vex | deleted uuid dir → `repair` / re-vendor | concurrent `vendor` ×4 | SIGKILL mid-download → re-run |
| --- | --- | --- | --- | --- | --- |
| 1.10.28 | pass | pass | fail #515 | untested | untested |
| 2.2.30 | untested | pass | untested (expected #515) | untested | untested |
| 2.10.3 | pass | pass | fail #515 | pass | pass |

Hosted packagist-origin psr/log (lockfile-only, 2.10.3): scan → rollback byte-identical: pass. Hand-added `transport-options` kept: #399.

### Mode takeovers (run 7, main `61cfb9b`, Linux PHP 8.3, packagist-origin psr/log 3.0.2)

| Composer | hosted → vendored → install → vex | vendored → hosted → install | vendored → hosted → `rollback` | `vendor --revert` → hosted (control) |
| --- | --- | --- | --- | --- |
| 1.10.28 | pass | **fail #536** (ValueError) | **fail #536** (refused) | pass |
| 2.2.30 | pass | pass | **fail #536** | untested |
| 2.8.12 | untested | pass | **fail #536** | untested |
| 2.10.3 | pass | pass | **fail #536** | untested |

macOS/Windows: untested (pure lock logic; Composer 1's `transport-options` crash is cross-OS per #399's probe).

### Global (`-g`) mode — run 3, main `2463257`

| OS | Composer | `scan -g` report (default home) | hosted `-g` refusal | `-g` apply / vex / rollback | custom global vendor-dir | composer not on PATH |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 / 2.2.30 / 2.8.12 / 2.10.3 | pass | pass | pass | fail #439 | pass (`~/.config`; `XDG_CONFIG_HOME` pass on `203e092`); **fail #586** on 2.x when a stale `~/.composer` also exists |
| macOS | 1.10.28 / 2.2.30 / 2.10.3 | pass | pass | pass | fail #439 | untested |
| Windows | 1.10.28 / 2.2.30 / 2.10.3 | fail #438 (closed by #442; re-probe pending) | pass | fail #438 (pass with explicit `COMPOSER_HOME`) | fail #439 | fail #438 |

Local agent scan with a user-level `$COMPOSER_HOME/config.json` vendor-dir: fail #439 (Linux 2.8.12). Hosted on v5: #399 still reproduces.

### composer/installers `installer-paths` (run 4, main `2463257`, Linux, installers 1.12.0 / 2.3.0)

| Composer | `install-path` recorded | Agent scan / apply / vex / rollback | Hosted rewrite → fresh install → vex | Hosted vex with pristine live bytes | Vendored → install → vex → rollback |
| --- | --- | --- | --- | --- | --- |
| 1.10.28 | no | fail #463 (skipped "not installed", exit 0) | pass (install) | fail #463 (false `not_affected`) | pass (hint names the wrong dir, cosmetic) |
| 2.2.30 | yes | pass | untested | untested | untested |
| 2.8.12 | yes | pass | pass | pass (omits `not_applied`) | pass |
| 2.10.3 | yes (expected) | untested | untested | untested | untested |

OS-independent (pure path logic). macOS/Windows: untested.

### Re-resolution, install flags, exec bits and plugins (run 8, main `61cfb9b`, Linux PHP 8.3)

| Composer | hosted → `require <other>` keeps rewrite | hosted → `--prefer-source` / `reinstall` / `preferred-install: source` | exec bits (bin + non-bin) hosted / vendored | `composer-plugin` activates patched (hosted / vendored) | `get <uuid> --mode hosted` over vendored |
| --- | --- | --- | --- | --- | --- |
| 1.10.28 | no (inline repo; Composer 1 behaviour, docs gap) | untested | pass / pass | pass / pass | untested (expected #536) |
| 2.2.30 | pass (packagist + inline) | pass | pass / pass | pass / pass | untested (expected #536) |
| 2.10.3 | pass (packagist + inline) | pass | pass / pass | pass / pass | **fail #536** |

## Backlog

1. #555 composer cell: agent `apply` with a manifest entry for a lock-only (not installed) package, including a `v`-prefixed lock version. Expected: skip with exit 0.
2. Re-run #536 once Composer joins the vendored → hosted `takeover_capable` set (PR #503 adds only pypi). Cover both `scan` and `get <uuid> --mode hosted`.
3. Windows probe: re-verify #438 on `203e092` (`composer.bat` probe and the `%APPDATA%\Composer` fallback), plus the macOS-with-`XDG_*`-var variant of #586. Re-run #586 once fixed.
4. Global `-g` leftovers: a non-writable global dir must fail loudly (non-root probe), `SOCKET_GLOBAL=1`, a space/unicode `--global-prefix`, and #446's `-g` scoping inside a hosted Composer project.
5. macOS/Windows probe of vendored path-repo + source-install revert (a Windows junction path repo with existing `transport-options`), plus the Windows long-path depth of `.socket/vendor/composer/<uuid>/<v>/<n>@<ver>`.
6. Re-run the Composer 1 installers cells when #463 is fixed, and add 2.10.3 installers cells. Re-run #399 and #515 when they're fixed.
7. Ask maintainers whether to document `COMPOSER=<other>.json` and Composer 1's `composer require <other>` re-resolving custom-repo entries.
8. PHP 7.2 / 7.4 cells for Composer 2.2 LTS (probe with setup-php).
9. Delete the leftover probe branches `bughunt/composer/20260930-srconly-probe`, `bughunt/composer/20261001-global-probe` and `bughunt/composer/20261001-c1-topts` (the sandbox git proxy refuses deletes). Needs a maintainer.

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
- Vendored mode is service-only in v5: `vendor --offline` without a committed artifact is `vendor_service_offline_conflict`. Mock `POST …/patches/package` (granted, sha512 SRI) plus a single-top-dir zip.
- Hosted rollback restores `dist`/`source` from packagist metadata (`SOCKET_PACKAGIST_URL`), not from the pre-rewrite lock, so hand-added fields such as `dist.mirrors` on a packagist-origin entry aren't restored. Documented. Packagist.org entries carry no mirrors.
- Mock hygiene: agent-mode `repair` fetches `/patches/diff/<uuid>`. Without that route it reports `download_failed`.
- A hosted rewrite of a dist-only entry (no `source`) doesn't reinstall over an existing `vendor/` on Composer 2 (Composer compares only version and dist/source references). The CLI's next steps say to remove `vendor/<v>/<n>` first, and `vex` omits it as `not_applied`.
- Mock hygiene: on Composer 2, a loopback `http://` mock needs `secure-http: false`. Put it in `$COMPOSER_HOME/config.json`, not composer.json.
- Composer 1 `composer require <other>` re-resolves unchanged custom-repo (inline `package`) entries from composer.json and drops a hosted rewrite. That's Composer 1 behaviour; Composer 2 keeps it. Re-run `scan`. (Not yet in the docs; see Backlog 5.)
- Composer 2.10 disables plugins for root in non-interactive sessions. Set `COMPOSER_ALLOW_SUPERUSER=1` in plugin repros.
- Hosted `rollback` of an inline/custom-repo entry is refused ("restore it from version control"): documented fail-closed behaviour.
- Packagist's Composer 1 metadata is frozen: Composer 1.10 can't resolve new packagist packages (`require` reports "Did you mean…"). Use inline/local repos for Composer 1 update cells.
- Composer 1.x prefers `~/.composer` over the XDG home even when both exist (`global config home` on 1.10.28). socket-patch's `~/.composer`-first fallback is correct for Composer 1. #586 is about Composer 2 only.
