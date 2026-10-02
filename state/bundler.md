[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-10-02 (run 8), main `61cfb9b`, latest release tag v4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't. `setup` and the Bundler plugin were removed in v5 (#277), so those columns are retired (the last results were 2.2–2.4 fail #389 → closed, and 2.5 / 4.x pass).

### Project modes

| OS | Ruby | Bundler | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: platform gem, no CHECKSUMS | Hosted: CHECKSUMS lock | Hosted: stale-install guard | Hosted: `BUNDLE_GEMFILE` in `.bundle/config` | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `BUNDLE_GEMFILE` | Vendored: `gems.rb` only | Agent: multi-home `vex` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 1.17.x | untested | untested | untested | untested | n/a | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.2–2.4 | untested | fail #340 (2.4) | untested | untested | n/a | untested | fixed #390 (#431) | untested | fixed #341 (#431) | untested | untested | untested |
| Linux | 3.3.6 | 2.6.9 | pass | untested | untested | untested | pass | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 4.0.17 | pass | fail #340 | pass | pass (switches to patched ruby gem) | pass | pass | fixed #390 (#431) | pass | fixed #341 (#431) | fixed #390 (#431) | refused (documented) | fail #420 |
| Linux (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fail #420 |
| macOS (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fail #420 |
| Windows (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 4.0 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | blocked by #421 |

### Hosted unwind (`rollback` / `remove`, v5 upstream restore; real rubygems.org upstream)

| OS | Ruby | Bundler | Direct dep (`~>`) | Transitive dep | Transitive, Gemfile ends in a blank line | `group` block + options | CRLF Gemfile | Non-rubygems.org upstream refused | Mixed (no-CHECKSUMS) lock |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 4.0.17 | pass (exact pin, documented) | fixed #457 (#460) | pass | pass | pass | pass | n/a |
| Linux | 3.3.6 | 2.6.9 | untested | fixed #457 (#460) | untested | untested | untested | untested | documented (Gemfile-only pin is out of reach) |
| macOS / Windows | any | any | untested | untested (OS-independent) | untested | untested | untested | untested | untested |

### Other hosted shapes (run 4)

| OS | Ruby / Bundler | Multi-platform lock + CHECKSUMS | Multi-platform lock, no CHECKSUMS | `gemspec` project (PATH) | GIT + PATH sections |
| --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 / 4.0.17 | pass (refused, documented) | pass (documented caveat) | pass | pass |

### Declaration and cache shapes (run 5, hosted, Linux, Ruby 3.3.6)

| Bundler | `eval_gemfile` declaration | loop-generated `gem g` | Transitive, no trailing newline | Transitive, CRLF | Committed `vendor/cache` guard | Committed cache at configured `cache_path` | Vendored `eval_gemfile` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fail #482 | fail #482 | pass | pass | pass | fail #483 | fail #482 |
| 2.6.9 | fail #482 | untested | untested | untested | pass | fail #483 | fail #482 |
| 2.4.22 | fail #482 | untested | untested | untested | pass (warns; install stays unpatched per the remedy) | fail #483 (silent unpatched install) | fail #482 |

### `BUNDLE_GEMFILE` env vs `.bundle/config` (run 6, Linux, Ruby 3.3.6)

| Bundler | Hosted: config `Gemfile.next` + env `Gemfile` | Vendored: same | Env only `Gemfile.next` | Config only `Gemfile.next` |
| --- | --- | --- | --- | --- |
| 4.0.17 | fail #507 | fail #507 | vendored pass (refused) | pass (e2e suite) |
| 2.6.9 | fail #507 | fail #507 | untested | untested |
| 2.4.22 | fail #507 | fail #507 | untested | untested |

### Vendored declaration shapes and lifecycle (run 7, Linux, Ruby 3.3.6)

| Bundler | Multi-line decl | `if` modifier | `group` + `platforms:` | CRLF + `gem(...)` | Re-run idempotent | Double `--revert` byte-exact |
| --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | pass (refused) | pass (refused) | pass (refused) | pass (refused) | pass | pass |
| 2.4.22 | untested | untested | untested | untested | pass | pass |

### Run 8 (Linux, Ruby 3.3.6)

| Bundler | Hosted: gem in two `group` blocks | Hosted: top-level + `group` dup | Vendored: dup decl | Vendored: CHECKSUMS lock (direct / transitive) | Vendored: `gemspec` transitive | Vendored: multi-platform lock | Vendored: native platform gem | Hosted: env `BUNDLE_CACHE_PATH` | Hosted: `BUNDLE_APP_CONFIG` + `Gemfile.next` | Hosted: `source … do` / `platforms:` / `install_if` / `group:` / quotes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fail #548 | fail #548 | pass (refused) | pass | pass | pass | refused (documented) | fail #483 (fixed in PR #532) | pass (refused) | pass |
| 2.6.9 | fail #548 | untested | untested | pass | pass | untested | untested | untested | untested | untested |
| 2.4.22 | fail #548 | untested | untested | n/a | pass | untested | untested | fail #483 (silent unpatched) | untested | untested |

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

1. **Maintainer request (still open):** global (`-g`) mode on every major version and OS. Remaining: macOS system Ruby and Homebrew Ruby; rbenv / rvm / chruby / asdf layouts; unicode or space-containing `--global-prefix`; a non-writable dir on macOS and Windows (Program Files); `-g` from inside a project on macOS and Windows. Re-check #421 once #442 merges.
2. Re-verify #483 / #507 when PR #532 merges; re-run #548 / #340 / #482 when the hosted Gemfile rewriter changes (including `rollback` on a doubly-declared gem).
3. #340 on Bundler 2.2–2.5 (Linux).
4. Windows hosted and vendored cells: CRLF Gemfile / lock, a `BUNDLE_PATH` with a drive letter or spaces, `x64-mingw-ucrt` platform gems, and `vendor/bundle` deployment mode.
5. Windows local mode for a Bundler project on system gems (no `BUNDLE_PATH`): does #421 hide the project's gems too?
6. Ruby 3.4 + Bundler 2.2 can't boot. Check the floor messaging.

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
- Hosted `rollback` / `remove` refuse a gem whose upstream `GEM` remote isn't rubygems.org (its CHECKSUMS can't be re-derived). To test the restore, use a real rubygems.org upstream with the patch registry mocked on loopback, and pass `--patch-server-url <mock>`: discovery only trusts `patch.socket.dev` or that origin.
- After `rollback`, a direct dep's original constraint (`~> 1.1`) comes back as the exact pin `"1.1.0"`. That's documented in "Hosted unwind coverage".
- On a mixed-state (no-CHECKSUMS) lock, `rollback` reports `Manifest not found`. The pin is Gemfile-only, which is documented as out of the restore's reach.
- Bundler 2.6 writes no CHECKSUMS by default. Run `bundle lock --add-checksums` to get the converged shape.
- An in-place hosted rewrite swallows the blank lines before the declaration (the `^\s*gem` match). That's cosmetic, and `rollback` re-derives the layout.
- Probe branches can't be deleted from the cloud sandbox (`git push --delete` gets 403 from the git proxy). `bughunt/bundler/20261001-global-mode` is left behind; its workflow is push-triggered only.
- `scan --vex` takes `--vex-product`, not `--product` (that's `vex`'s flag). Without either, a gem project fails with `product_undetected`.
- A committed `vendor/cache` with a stale archive still installs unpatched on Bundler 2.4 after the hosted scan. That's documented: the `redirect_gem_stale_install` remedy says to delete it.
- Bundler's runtime `require "bundler/setup"` (without `bundle exec`) reads only the `BUNDLE_GEMFILE` env var, not `.bundle/config`; the CLI commands (`install`, `lock`, `exec`) let `.bundle/config` win. #507 is about the CLI order, which decides what gets installed.
- Vendored mode refuses multi-line, conditional (`if`/`unless`), indented (`group`) and parenthesized `gem(...)` declarations with `gemfile_declaration_not_editable` and writes nothing. That's fail-closed by design, unlike the hosted rewriter (#340).
- The vendor probes need `BUNDLER_VERSION=<v>` alongside `SOCKET_PATCH_BUNDLER_E2E_VERSION=<v>` to pick a Bundler older than the Ruby default (2.5.22 on 3.3.6).
- `scan` run from a project subdirectory (or with `--cwd` pointing at one) scans 0 packages: the cwd is the project root, and there's no walk-up the way Bundler does it.
- Vendoring a native platform gem (`ffi-…-x86_64-linux-gnu`) is refused with `platform_gem_unsupported`. Documented.
- Hosted refuses a declaration with an inline `source:` option (`redirect_gem_source_option`). With `--vex` the scan exits 1 and writes no VEX. That's fail-closed by design.
