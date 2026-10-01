[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-10-01 (run 3), main `2463257` (v5 consolidation, #277), latest release tag v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't. `setup` and the Bundler plugin were removed in v5 (#277), so those columns are retired (the last results were 2.2–2.4 fail #389 → closed, and 2.5 / 4.x pass).

### Project modes

| OS | Ruby | Bundler | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: platform gem, no CHECKSUMS | Hosted: CHECKSUMS lock | Hosted: stale-install guard | Hosted: `BUNDLE_GEMFILE` in `.bundle/config` | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `BUNDLE_GEMFILE` | Vendored: `gems.rb` only | Agent: multi-home `vex` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 1.17.x | untested | untested | untested | untested | n/a | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.2–2.4 | untested | fail #340 (2.4) | untested | untested | n/a | untested | untested | untested | fail #341 (2.4) | untested | untested | untested |
| Linux | 3.3.6 | 2.6.9 | pass | untested | untested | untested | pass | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 4.0.17 | pass | fail #340 | pass | pass (switches to patched ruby gem) | pass | pass | fail #390 | pass | fail #341 | fail #390 | refused (documented) | fail #420 |
| Linux (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fail #420 |
| macOS (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fail #420 |
| Windows (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 4.0 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | blocked by #421 |

### Global mode (`-g`)

| OS | Ruby / Bundler | `scan -g` report | `-g` vs project scoping | `scan -g --mode hosted` refused | `get -g` / `apply -g` | `rollback -g` byte-exact | `vex -g` | `--global-prefix <gems dir>` / `SOCKET_GLOBAL=1` | Non-writable gem dir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux (sandbox, rbenv) | 3.3.6 / 4.0.17 | pass | pass | pass | pass (both homes) | pass | fail #420 (multi-home); pass (single home) | pass | pass (loud `Permission denied`) |
| ubuntu-latest | 2.7 / 3.3 / 3.4 | pass | untested | pass | pass | pass | fail #420 | pass | untested |
| macos-latest (setup-ruby) | 2.7 / 3.3 / 3.4 | pass | untested | pass | pass | pass | fail #420 | pass | untested |
| windows-latest (RubyInstaller) | 3.3 / 3.4 | fail #421 (finds nothing) | untested | pass | fail #421 | n/a | fail #421 | `--global-prefix` pass; `SOCKET_GLOBAL=1` fail #421 | untested |
| windows-latest (RubyInstaller) | 2.7 | fail #421 (user dir only) | untested | pass | fail #421 (system copy missed) | pass | fail #421 | `--global-prefix` pass | untested |
| macOS system / Homebrew Ruby, rvm, chruby, asdf | any | untested | untested | untested | untested | untested | untested | untested | untested |

## Backlog

1. **Maintainer request (still open):** global (`-g`) mode on every major version and OS. Remaining: macOS system Ruby and Homebrew Ruby; rbenv / rvm / chruby / asdf layouts; unicode or space-containing `--global-prefix`; a non-writable dir on macOS and Windows (Program Files); `-g` from inside a project on macOS and Windows.
2. Windows local mode for a Bundler project on system gems (no `BUNDLE_PATH`): does #421's `gem env` failure hide the project's gems too? Comment on #421.
3. #340 / #341 / #390 on Bundler 2.2–2.5 (Linux).
4. Windows hosted cells: CRLF Gemfile / lock, a `BUNDLE_PATH` with a drive letter or spaces, `x64-mingw-ucrt` platform gems, and `vendor/bundle` deployment mode.
5. Git- and path-sourced gems (`bundler/gems/<name>-<sha>`) in hosted and vendored modes: GIT / PATH sections in the redirect, the stale-install guard and vex. The agent crawl skipping them looked intended.
6. Ruby 3.4 + Bundler 2.2 can't boot. Check the floor messaging, and run `scan` from a subdirectory of a Bundler project.

## Known non-bugs

- `patches-api.socket.dev` / `api.socket.dev` are blocked from the sandbox. Use a local mock API (`--api-url`, `--api-token fake --org org`). A ~60-line Python mock serving `/v0/orgs/org/patches/{batch,view/<uuid>,by-package/…}` with `blobContent` is enough for agent and `-g` flows; for hosted, use a hold-open copy of `e2e_redirect_gem_build.rs`.
- v5 vendoring downloads service artifacts only (`--vendor-source build` is gone). To drive vendored cells, copy `e2e_vendor_gem_build.rs` (its `prebuilt_common` fixture serves the artifact) rather than calling the CLI by hand: `vendor --offline` without a prestaged artifact fails with `vendor_service_offline_conflict`, which is expected.
- `--global-prefix` takes the package-leaf dir (`<gem home>/gems`), like `node_modules` / `site-packages` for the other ecosystems. Pointing it at the gem home itself scans 0 packages; that's the convention, not a bug.
- `-g` agent runs keep their manifest at `<cwd>/.socket/manifest.json`, and `rollback -g` removes the entry. `vex -g` then needs a fresh `get -g` plus `--product` (no project to auto-detect from).
- A git-sourced gem (`bundler/gems/<name>-<sha>`) isn't crawled in agent mode. Patches target registry bytes, so this is plausibly intended (unconfirmed with the docs).
- A `gems.rb`-only project can't vendor. It's documented, and the refusal is `no Gemfile at …/Gemfile`.
- A CHECKSUMS-less lock gets `redirect_gem_no_checksums_section` + `redirect_gem_frozen_install` and needs one unfrozen `bundle install`. Documented.
- A platform-resolved gem (`-x86_64-linux`) on a CHECKSUMS-less lock is redirected, and the next install switches to the patched ruby-platform gem. It's intended. With CHECKSUMS it fails closed (`redirect_gem_platform_unsupported`).
- `bundle install --deployment` exits 15 on Bundler 4 (the flag was removed). Use `BUNDLE_DEPLOYMENT=true` / `--frozen`.
- Moving a gem into a hosted `source` block inside a `group … do` block dedents it. Cosmetic.
- Bundler 1.17 on Ruby 3.3 can't resolve against the mock compact index (a harness limit).
- Probe branches can't be deleted from the cloud sandbox (`git push --delete` gets 403 from the git proxy). `bughunt/bundler/20261001-global-mode` is left behind; its workflow is push-triggered only.
