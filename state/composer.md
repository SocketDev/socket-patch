[agent] Progress ledger for the scheduled Composer bug-hunt routine (label pm:composer).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Upstream `composer-compatibility.yml` already covers the plain dist-install hosted/vendored capstones for 1.10 → 2.10 on Ubuntu/Windows/macOS. This ledger tracks the edges it doesn't.

| OS | Composer (PHP) | Agent: `setup` (LF) | Agent: `setup` CRLF / escapes | Agent: hook on real install | Scan: custom vendor-dir | Hosted: repo capstones | Vendored: dist install | Vendored: source install → git clone |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.10.28 (8.1) | untested | untested (OS/version-independent) | untested | untested | untested | CI pass | untested |
| Linux | 2.2.30 (8.3) | untested | untested | untested | untested | untested | CI pass | untested |
| Linux | 2.8.12 (8.4) | pass | fail #351 | pass | pass | pass (5/5) | CI pass | fail #355 |
| Linux | 2.10.x (8.5) | untested | untested | untested | untested | untested | CI pass | untested |
| macOS | any | untested | untested | untested | untested | CI | CI | untested |
| Windows | any | untested | untested | untested | untested | CI | CI | untested |

## Backlog

1. Probe branch: #355 on Composer 1.10 / 2.2 / 2.10 across ubuntu/macos/windows, plus a `--prefer-source` hosted cell.
2. `setup` edge JSON: floats/exponents, duplicate keys, `@php` / `@putenv` scripts, a hook present in only one event, `setup --check` parity.
3. Hosted/vendored: path-repository siblings (`dist.type: path`), `dev-*` versions, `packages-dev`-only targets, `"packages-dev": null` locks.
4. composer/installers custom `install-path` for agent apply and vendored discovery.
5. Composer 1.x reinstall hint and `--no-scripts` (hook skipped) coverage; concurrent `vendor` + `composer install`.

## Known non-bugs

- A BOM composer.json: Composer itself rejects it, so a socket-patch refusal is correct.
- Composer 1.10 can't download on PHP 8.5 (documented). Pair it with PHP ≤ 8.4.
- `composer update <pkg>` drops the wiring (documented). Re-run `scan`.
- Composer 1.x keeps an already-installed package on `composer install` after rewiring (documented). Remove `vendor/<v>/<n>` first.
- Sandbox: GitHub zipball downloads fail, so Composer installs everything from source. Local dist controls aren't possible; rely on upstream CI. The two vendored capstones that fail locally are #355, not a sandbox flake.
- Repro hygiene: a `vendor/` `.gitignore` pattern also ignores `.socket/vendor/`. Use `/vendor/`.
