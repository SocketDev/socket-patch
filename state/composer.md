[agent] Progress ledger for the scheduled Composer bug-hunt routine (label pm:composer).

Last updated: 2026-10-01 (run 2), main `f6b7fb9`, latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Upstream `composer-compatibility.yml` already covers the plain dist-install hosted/vendored capstones for 1.10 → 2.10 on Ubuntu/Windows/macOS. This ledger tracks the edges it doesn't.

| OS | Composer (PHP) | Agent: `setup` (LF) | Agent: `setup` CRLF / escapes | Agent: apply (path repo / installed.json) | Scan: custom vendor-dir | Hosted: repo capstones | Hosted: repo `options` → transport-options | Hosted: warm cache | Vendored: dist / path-copy install + revert | Vendored: source install → git clone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 (8.1/8.3) | untested | untested (OS/version-independent) | pass | untested | CI | fail #399 | pass | pass | fail #355 |
| Linux | 2.2.30 (8.3) | untested | untested | pass | untested | CI | fail #399 | pass | pass | fail #355 |
| Linux | 2.8.12 (8.3/8.4) | pass (one-event hook: check/setup disagree, not filed) | fail #351 | pass | pass | pass (5/5) | fail #399 | pass | pass | fail #355 |
| Linux | 2.10.3 (8.5) | untested | untested | pass | untested | CI | untested (expected #399) | untested | pass | fail #355 |
| macOS | 1.10 / 2.2 / 2.10 | untested | untested | pass | untested | CI | untested | untested | pass | fail #355 |
| Windows | 1.10 / 2.2 / 2.10 | untested | untested | pass (junction) | untested | CI | untested | untested | pass | fail #355 |

"Vendored: source install" covers both `--prefer-source` and source-only VCS lock entries (no dist). "Agent: apply (path repo)" means the patch is written through the path-repo link into the sibling directory; see Known non-bugs.

## Backlog

1. Hosted: other repo-scoped lock fields that follow the package to the hosted origin (`notification-url`, `ssl` transport options, `http.proxy`). Check that `rollback` / the vendored takeover restore `transport-options`.
2. Re-check #399 / #355 on `release/v5-prerelease` (#277), where the hosted ledger is gone.
3. composer/installers custom `install-path` (a WordPress plugin) for agent apply and vendored discovery, Composer 2 vs 1.
4. `COMPOSER=<other>.json` projects (crawler vendor-dir resolution).
5. Concurrent `vendor` + `composer install`; an interrupted vendor followed by `repair`.
6. Delete the leftover probe branch `bughunt/composer/20260930-srconly-probe` (the sandbox git proxy refuses branch deletes). Needs a maintainer.

## Known non-bugs

- A BOM composer.json: Composer itself rejects it, so a socket-patch refusal is correct.
- Composer 1.10 can't download on PHP 8.5 (documented). Pair it with PHP ≤ 8.4.
- `composer update <pkg>` drops the wiring (documented). Re-run `scan`.
- Composer 1.x keeps an already-installed package on `composer install` after rewiring (documented). Remove `vendor/<v>/<n>` first.
- A `"packages-dev": null` lock: Composer 2.8 itself can't install from it.
- Agent apply follows a path repository's symlink/junction and patches the sibling source. This matches the npm `npm link` / `file:` posture, and Composer created the link from the user's own composer.json.
- Vendored refuses a `/` in a dev branch version (`dev-feature/foo`) with `unsafe_coordinates`: an explicit fail-closed refusal on a shape Socket patches don't target.
- `setup --check` treats a hook in either event as configured, while `setup` wants both. This is confirmed on 4.x but wasn't filed, because `setup` is removed in v5 (#279). Don't re-file unless v5 keeps `setup`.
- Sandbox: GitHub zipball downloads and getcomposer.org fail. Composer installs from source, and the phars come from GitHub releases. Prefer local path/VCS/composer-repo fixtures and a mock patch API.
- Repro hygiene: a `vendor/` `.gitignore` pattern also ignores `.socket/vendor/`. Use `/vendor/`.
