[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't.

| OS | Ruby | Bundler | Agent / `setup` plugin | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: stale-install guard (local / env / global `BUNDLE_PATH`) | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `gems.rb` only |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 1.17.x | untested (must refuse) | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.4.22 | untested | pass | fail #340 | untested | untested | untested | fail #341 | untested |
| Linux | 3.3.6 | 2.6.9 | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 4.0.9 | untested | pass (CHECKSUMS + none) | fail #340 | pass | pass | pass (control via twin run) | fail #341 | refused (odd reason, backlog 2) |
| macOS | any | any | untested | untested | untested (OS-independent) | untested | untested | untested | untested (OS-independent) | untested |
| Windows | any | any | untested | untested | untested (OS-independent) | untested | untested | untested | untested (OS-independent) | untested |

## Backlog

1. Native/platform gems on a CHECKSUMS-less lock (Bundler 2.2–2.5): the `redirect_gem_platform_unsupported` guard only reads CHECKSUMS lines, so a `name (ver-x86_64-linux)` spec may be redirected to the ruby-platform gem. Needs platform `.gem` fixtures.
2. Vendored on a `gems.rb`-only project reports `package_not_installed` / `vendor_fetch_unverifiable` although the gem is installed (the same install is found when a `Gemfile` twin exists). Check the crawler / lock-inventory spelling handling.
3. `setup` (bundler plugin): Bundler 2.2 / 2.3 / 4.x, the 1.x refusal + `setup --check`, `gems.rb`, git/path sources, `setup --remove`, re-run idempotency.
4. macOS/Windows probe branch: hosted CRLF Gemfile/lock, a Windows `BUNDLE_PATH` with a drive letter or spaces, and `vendor/bundle` deployment mode.
5. Hosted with git/path-sourced siblings, `BUNDLE_GEMFILE=Gemfile.next` dual-boot, and `scan` from a subdirectory of a bundler project; Ruby 2.7 / 3.4 runtimes.

## Known non-bugs

- `patches-api.socket.dev` / `api.socket.dev` are blocked from the sandbox. Use a local mock API (`--api-url`); a hold-open copy of `e2e_redirect_gem_build.rs` works well.
- Vendored runs against that mock fail with `no_local_source` unless you pass `--vendor-source build` and the `patches/view` stub includes `blobContent`. That's a mock artifact.
- A `gems.rb`-only project can't vendor: documented in docs/ecosystems.md (the refusal *reason* is still on the backlog).
- A CHECKSUMS-less lock gets `redirect_gem_no_checksums_section` + `redirect_gem_frozen_install` and needs one unfrozen `bundle install`. Documented.
- `bundle install --deployment` exits 15 on Bundler 4 (the flag was removed). Use `BUNDLE_DEPLOYMENT=true` / `--frozen`.
- Moving a gem into a hosted `source` block inside a `group … do` block dedents it. Cosmetic; bundler installs the patched gem.
