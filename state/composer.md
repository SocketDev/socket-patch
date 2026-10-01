[agent] Progress ledger for the scheduled Composer bug-hunt routine (label pm:composer).

Last updated: 2026-10-01 (run 3), main `2463257` (v5 consolidation), latest release v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Upstream `composer-compatibility.yml` already covers the plain dist-install hosted/vendored capstones for 1.10 → 2.10 on Ubuntu/Windows/macOS. This ledger tracks the edges it doesn't.

| OS | Composer (PHP) | Agent: `setup` (LF) | Agent: `setup` CRLF / escapes | Agent: apply (path repo / installed.json) | Scan: custom vendor-dir | Hosted: repo capstones | Hosted: repo `options` → transport-options | Hosted: warm cache | Vendored: dist / path-copy install + revert | Vendored: source install → git clone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 (8.1/8.3) | untested | untested (OS/version-independent) | pass | untested | CI | fail #399 | pass | pass | fail #355 |
| Linux | 2.2.30 (8.3) | untested | untested | pass | untested | CI | fail #399 | pass | pass | fail #355 |
| Linux | 2.8.12 (8.3/8.4) | removed in v5 | removed in v5 (#351 closed) | pass | pass | pass (5/5) | fail #399 | pass | pass | fail #355 |
| Linux | 2.10.3 (8.5) | untested | untested | pass | untested | CI | untested (expected #399) | untested | pass | fail #355 |
| macOS | 1.10 / 2.2 / 2.10 | untested | untested | pass | untested | CI | untested | untested | pass | fail #355 |
| Windows | 1.10 / 2.2 / 2.10 | untested | untested | pass (junction) | untested | CI | untested | untested | pass | fail #355 |

"Vendored: source install" covers both `--prefer-source` and source-only VCS lock entries (no dist). "Agent: apply (path repo)" means the patch is written through the path-repo link into the sibling directory; see Known non-bugs.

### Global (`-g`) mode — run 3, main `2463257`

| OS | Composer | `scan -g` report (default home) | hosted `-g` refusal | `-g` apply / vex / rollback | custom global vendor-dir | composer not on PATH |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 / 2.2.30 / 2.8.12 / 2.10.3 | pass | pass | pass | fail #439 | pass (`~/.config`), fail #438 with `XDG_CONFIG_HOME` |
| macOS | 1.10.28 / 2.2.30 / 2.10.3 | pass | pass | pass | fail #439 | untested |
| Windows | 1.10.28 / 2.2.30 / 2.10.3 | fail #438 | pass | fail #438 (pass with explicit `COMPOSER_HOME`) | fail #439 | fail #438 |

Local agent scan with a user-level `$COMPOSER_HOME/config.json` vendor-dir: fail #439 (Linux 2.8.12). Hosted on v5: #399 still reproduces.

## Backlog

1. **Maintainer request (in progress):** global `-g` mode. Remaining: a non-writable global dir must fail loudly (non-root probe), `SOCKET_GLOBAL=1` and space/unicode `--global-prefix` cells, and a re-run after #438/#439 are fixed.
2. Hosted on v5: other repo-scoped lock fields (`notification-url`, `ssl` transport options). Re-check #355 on v5 vendored.
3. composer/installers custom `install-path` (a WordPress plugin) for agent apply and vendored discovery, Composer 2 vs 1.
4. `COMPOSER=<other>.json` projects (crawler vendor-dir resolution).
5. Concurrent `vendor` + `composer install`; an interrupted vendor followed by `repair`.
6. Delete the leftover probe branches `bughunt/composer/20260930-srconly-probe` and `bughunt/composer/20261001-global-probe` (the sandbox git proxy refuses deletes). Needs a maintainer.

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
