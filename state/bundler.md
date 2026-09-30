[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-09-30 (run 2), main `f6b7fb9`, latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't.

| OS | Ruby | Bundler | Agent / `setup` plugin (install, fresh clone) | Agent: `bundle pristine` healed | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: platform gem, no CHECKSUMS | Hosted: stale-install guard | Hosted / setup: `BUNDLE_GEMFILE` in `.bundle/config` | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `gems.rb` only |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 1.17.x | refused (pass, via `BUNDLED WITH`) | n/a | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.2.33 | pass | fail #389 | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.3.27 | pass | fail #389 | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.4.22 | pass | fail #389 | untested | fail #340 | untested | untested | untested | untested | untested | fail #341 | untested |
| Linux | 3.3.6 | 2.5.22 | pass | pass | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.6.9 | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 4.0.x | pass (`Gemfile` + `gems.rb`) | pass | pass | fail #340 | pass | pass (switches to patched ruby gem) | pass | fail #390 | pass | fail #341 | refused (documented) |
| macOS | any | any | untested | untested (Bundler-side, expect same) | untested | untested (OS-independent) | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested |
| Windows | any | any | untested | untested (Bundler-side, expect same) | untested | untested (OS-independent) | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested |

## Backlog

1. Vendored mode with `BUNDLE_GEMFILE` in `.bundle/config`: confirm it shares the #390 gap, and comment on #390.
2. #390 on Bundler 2.2–2.6, and the `BUNDLE_GEMFILE` env-only form with `setup`.
3. Git- and path-sourced gems (`bundler/gems/<name>-<sha>`): hosted redirect and agent patch targets, and the plugin's `patch_target_files`.
4. A macOS/Windows probe branch: hosted CRLF Gemfile/lock, a Windows `BUNDLE_PATH` with a drive letter or spaces, `vendor/bundle` deployment mode, and plugin `Dir.glob` on `x64-mingw-ucrt` platform gems.
5. Ruby 2.7 / 3.4 runtimes, and `scan` from a subdirectory of a bundler project.

## Known non-bugs

- `patches-api.socket.dev` / `api.socket.dev` are blocked from the sandbox. Use a local mock API (`--api-url`); a hold-open copy of `e2e_redirect_gem_build.rs` works well.
- Vendored runs against that mock fail with `no_local_source` unless you pass `--vendor-source build` and the `patches/view` stub includes `blobContent`. That's a mock artifact.
- A `gems.rb`-only project can't vendor. It's documented, and the refusal is `no Gemfile at …/Gemfile` (run 1's `package_not_installed` came from the platform/mock setup).
- A CHECKSUMS-less lock gets `redirect_gem_no_checksums_section` + `redirect_gem_frozen_install` and needs one unfrozen `bundle install`. Documented.
- A platform-resolved gem (`-x86_64-linux`) on a CHECKSUMS-less lock is redirected, and the next install switches to the patched ruby-platform gem. It's intended, and patched bytes load. With CHECKSUMS it fails closed (`redirect_gem_platform_unsupported`).
- `bundle install --deployment` exits 15 on Bundler 4 (the flag was removed). Use `BUNDLE_DEPLOYMENT=true` / `--frozen`.
- Moving a gem into a hosted `source` block inside a `group … do` block dedents it. Cosmetic; bundler installs the patched gem.
- `setup --json` reports `"packageManager": "npm"` on a Bundler-only project. Documented in CLI_CONTRACT.
- With no lock, `setup` probes the machine bundler, so the 1.x refusal needs a `BUNDLED WITH 1.x` lock. Intended.
- Bundler 1.17 on Ruby 3.3 can't resolve against the mock compact index (a harness limit). Test the 1.x refusal through `BUNDLED WITH`.
