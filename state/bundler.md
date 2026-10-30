[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-10-30 (run 59), main `5ca5623` (unchanged since run 58; no gem code changes since `b291caa`), latest release v5.0.1 (npm; no git tags). Newest Bundler: 4.0.23 stable, 4.1.0.beta3. Run 59 closed backlog item 4 (Bundler 4.0.23 phantom platform lock entry: re-scan, remedy, re-converge, `vex`, `rollback` / `remove`) and the 2.6.9 hosted-unwind direct-dep and `group` cells. Run 59 used a standalone harness instead of a scratch Rust test: a Python mock (upstream compact index with ruby + `x86_64-linux` variants, patch registry, patches API) plus real `gem build` fixtures. Pass `--patch-server-url <mock>` to `rollback` / `remove` / `vex`, or a 127.0.0.1 pin isn't treated as hosted and the commands report `manifest_not_found`. Ruby 3.1.6 is in the sandbox (`/opt/rbenv/versions/3.1.6/bin`); `gem install bundler -v 1.17.3` / `2.1.4` there and export `BUNDLER_VERSION` + `SOCKET_PATCH_BUNDLER_E2E_VERSION`. A fresh container's Ruby 3.3.6 only has 2.5.22 / 4.0.18, so `gem install bundler -v 2.6.9` / `4.0.23` / `4.1.0.beta3` first and export `BUNDLER_VERSION`. Bundler 2.6 has no `install -q` (use `--quiet`).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't. `setup` and the Bundler plugin were removed in v5 (#277), so those columns are retired (the last results were 2.2–2.4 fail #389 → closed, and 2.5 / 4.x pass).

### Project modes

| OS | Ruby | Bundler | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: platform gem, no CHECKSUMS | Hosted: CHECKSUMS lock | Hosted: stale-install guard | Hosted: `BUNDLE_GEMFILE` in `.bundle/config` | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `BUNDLE_GEMFILE` | Vendored: `gems.rb` only | Agent: multi-home `vex` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.1.6 | 1.17.3 | pass (suites, run 51) | untested | untested | untested | n/a | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 2.2–2.4 | untested | fixed #340 (#637) | untested | untested | n/a | untested | fixed #390 (#431) | untested | fixed #341 (#431) | untested | untested | untested |
| Linux | 3.3.6 | 2.6.9 | pass | untested | untested | untested | pass | untested | untested | untested | untested | untested | untested | untested |
| Linux | 3.3.6 | 4.0.17 | pass | fixed #340 (#637) | pass | pass (switches to patched ruby gem) | pass | pass | fixed #390 (#431) | pass | fixed #341 (#431) | fixed #390 (#431) | refused (documented) | fixed #420 (#517) |
| Linux (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fixed #420 (#517) |
| macOS (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 2.5 / 2.6 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fixed #420 (#517, probe pass) |
| Windows (CI) | 2.7 / 3.3 / 3.4 | 2.4 / 4.0 | untested | untested (OS-independent) | untested | untested | untested | untested | untested (OS-independent) | untested | untested (OS-independent) | untested | untested | fixed #420 (#517, probe pass) |

### Hosted unwind (`rollback` / `remove`, v5 upstream restore; real rubygems.org upstream)

| OS | Ruby | Bundler | Direct dep (`~>`) | Transitive dep | Transitive, Gemfile ends in a blank line | `group` block + options | CRLF Gemfile | Non-rubygems.org upstream refused | Mixed (no-CHECKSUMS) lock |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 4.0.17 | pass (exact pin, documented) | fixed #457 (#460) | pass | pass | pass | pass | n/a |
| Linux | 3.3.6 | 2.6.9 | pass (exact pin, documented; mock upstream, no CHECKSUMS; run 59) | fixed #457 (#460) | untested | pass (`group :development, :test` + `require: false # keep`; run 59) | untested | n/a (no CHECKSUMS, so no sha to re-derive) | documented (Gemfile-only pin is out of reach) |
| Linux | 3.3.6 | 4.0.23 | refused, documented (mock upstream on 127.0.0.1 with CHECKSUMS; run 59) | untested | untested | refused, documented (same) | untested | pass (`hosted_restore_refused` / `hosted_revert_failed`, nothing written; run 59) | n/a |
| macOS / Windows | any | any | untested | untested (OS-independent) | untested | untested | untested | untested | untested |

### Platform gem, converged before the stale-guard remedy (Bundler 4.0.23, Ruby 3.3.6, CHECKSUMS-less lock, run 59)

| Step | Result |
| --- | --- |
| Hosted scan over a platform lock with CHECKSUMS | refused `redirect_gem_platform_unsupported` (documented) |
| Hosted scan, CHECKSUMS stripped | redirect + `redirect_gem_stale_install` naming the `-x86_64-linux` gems/cache/spec paths: pass |
| `bundle install` before the remedy | phantom `vuln-gem (1.0.0-x86_64-linux)` under the patch-registry remote; `bundle exec` loads VULNERABLE; fresh frozen install exits 16 (Bundler) |
| Re-scan `--vex` / standalone `vex` over the phantom lock + stale install | stale warning again, exit 1 `no_applicable_patches`, no attestation: pass |
| Remedy (delete the 3 listed paths) + `bundle install` | phantom entry dropped, lock converges to ruby `vuln-gem (1.0.0)`, PATCHED, fresh frozen install passes, `vex` attests: pass |
| Non-frozen fresh install from the phantom lock (no stale install) | Bundler drops the phantom and installs the patched ruby gem: pass |
| `rollback` / `remove` from the phantom lock | refused (`hosted_restore_refused` / `hosted_revert_failed`: "Socket GEM section does not lock exactly vuln-gem (1.0.0)"), nothing written, remedy names `git checkout`: pass (fail-closed) |
| `rollback` / `remove` from the re-converged lock | restore + `reinstall_required`, fresh frozen install passes (VULNERABLE, as expected): pass |

### Other hosted shapes (run 4)

| OS | Ruby / Bundler | Multi-platform lock + CHECKSUMS | Multi-platform lock, no CHECKSUMS | `gemspec` project (PATH) | GIT + PATH sections |
| --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 / 4.0.17 | pass (refused, documented) | pass (documented caveat) | pass | pass |

### Declaration and cache shapes (run 5, hosted, Linux, Ruby 3.3.6)

| Bundler | `eval_gemfile` declaration | loop-generated `gem g` | Transitive, no trailing newline | Transitive, CRLF | Committed `vendor/cache` guard | Committed cache at configured `cache_path` | Vendored `eval_gemfile` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fixed #482 (#552) | fixed #482 (#552) | pass | pass | pass | fixed #483 (#532) | fixed #482 (#552) |
| 2.6.9 | fixed #482 (#552) | untested | untested | untested | pass | fixed #483 (#532) | fixed #482 (#552) |
| 2.4.22 | fixed #482 (#552) | untested | untested | untested | pass (warns; install stays unpatched per the remedy) | fixed #483 (#532) | fixed #482 (#552) |

### `BUNDLE_GEMFILE` env vs `.bundle/config` (run 6, Linux, Ruby 3.3.6)

| Bundler | Hosted: config `Gemfile.next` + env `Gemfile` | Vendored: same | Env only `Gemfile.next` | Config only `Gemfile.next` |
| --- | --- | --- | --- | --- |
| 4.0.17 | fixed #507 (#532) | fixed #507 (#532) | vendored pass (refused) | pass (e2e suite) |
| 2.6.9 | fixed #507 (#532, OS/version-independent) | fixed #507 (#532) | untested | untested |
| 2.4.22 | fixed #507 (#532) | fixed #507 (#532) | untested | untested |

### Vendored declaration shapes and lifecycle (run 7, Linux, Ruby 3.3.6)

| Bundler | Multi-line decl | `if` modifier | `group` + `platforms:` | CRLF + `gem(...)` | Re-run idempotent | Double `--revert` byte-exact |
| --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | pass (refused) | pass (refused) | pass (refused) | pass (refused) | pass | pass |
| 2.4.22 | untested | untested | untested | untested | pass | pass |

### Run 8 (Linux, Ruby 3.3.6)

| Bundler | Hosted: gem in two `group` blocks | Hosted: top-level + `group` dup | Vendored: dup decl | Vendored: CHECKSUMS lock (direct / transitive) | Vendored: `gemspec` transitive | Vendored: multi-platform lock | Vendored: native platform gem | Hosted: env `BUNDLE_CACHE_PATH` | Hosted: `BUNDLE_APP_CONFIG` + `Gemfile.next` | Hosted: `source … do` / `platforms:` / `install_if` / `group:` / quotes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fixed #548 (#552) | fixed #548 (#552) | pass (refused) | pass | pass | pass | refused (documented) | fixed #483 (#532) | pass (refused) | pass |
| 2.6.9 | fixed #548 (#552) | untested | untested | pass | pass | untested | untested | untested | untested | untested |
| 2.4.22 | fixed #548 (#552) | untested | untested | n/a | pass | untested | untested | fixed #483 (#532) | untested | untested |

### Bundler global config tier (run 9, Linux, Ruby 3.3.6)

| Bundler | Hosted: global `cache_path` (`~/.bundle/config`) | Hosted: global `cache_path` (`BUNDLE_USER_CONFIG`) | Hosted: global `gemfile Gemfile.next` | Agent: global `path` |
| --- | --- | --- | --- | --- |
| 4.0.17 | fixed #577 (#621) | fixed #577 (#621) | fixed #577 (#621) | fixed #577 (#621) |
| 2.4.22 | fixed #577 (#621) | fixed #577 (#621) | fixed #577 (#621) | fixed #577 (#621) |

### Run 10 (agent mode, Bundler project on system gems, `colorize@0.8.1` mock patch)

| OS | Ruby / Bundler | Agent `scan` / `get` / `vex` / `rollback`, path with a space | Env `BUNDLE_PATH` + local config `path` |
| --- | --- | --- | --- |
| Linux | 3.3.6 / 4.0.17 | pass | pass (fans out to every store) |
| windows-latest | 2.7 / 3.3 / 3.4 (Bundler 4.0.x) | pass | untested |
| macos-latest | 2.7 / 3.3 / 3.4 (Bundler 4.0.x) | pass | untested |

### Run 11 (hosted, git-sourced declarations, Linux, Ruby 3.3.6)

| Bundler | Custom `git_source` key | Built-in `gitlab:` | String-keyed `"git" =>` | `"github" =>` |
| --- | --- | --- | --- | --- |
| 4.0.17 | fixed #652 (#731) | fixed #652 (#731) | fixed #652 (#731) | untested (needs network) |
| 2.5.22 | fixed #652 (#731) | untested | untested | untested |

### Run 12 (Linux, Ruby 3.3.6)

| Bundler | Repo gem e2e suites | Vendored: custom `git_source` gem | Hosted: `mirror.all` in `.bundle/config`, no CHECKSUMS | Hosted: `mirror.all`, CHECKSUMS lock |
| --- | --- | --- | --- | --- |
| 4.0.17 | pass | pass (fails closed) | fail #681 | fail #681 (exit 37) |
| 2.7.2 | pass (11 + 6 + 25) | untested | untested | untested |
| 2.6.9 | untested | untested | untested | fail #681 (exit 37) |
| 2.5.22 | untested | untested | fail #681 | n/a |
| 2.4.22 | untested | untested | fail #681 | n/a |

### Run 13: hosted lifecycle on more shapes (mock patch API + registry, **real rubygems.org upstream**)

| OS | Ruby | Bundler | `gems.rb` redirect → install → `rollback` → frozen install | `Gemfile` + `gems.rb` twin unwind | CRLF manifest + CRLF lock cycle | `remove` purl / uuid (CRLF `gems.rb`) | Unwind: direct `~>` / `group` + opts | Uppercase name (`ZenTest`), 2-constraint decl | Config `path` outside the project (stale guard + VEX) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 4.0.17 | pass | pass | pass | pass | pass | pass | fixed #709 (#712) |
| Linux | 3.3.6 | 2.6.9 | pass | untested | pass | untested | pass | pass | fixed #709 (#712) |
| Linux | 3.3.6 | 2.4.22 | converged-lock unwind pass | untested | untested | untested | untested | untested | fixed #709 (#712) |
| windows-latest | 3.3 / 3.4 | 2.6.9 / 4.0.17 | pass (`Gemfile` too) | untested | pass | untested | untested | untested | fixed #709 (#712; was 4.0.17, `D:/…`) |
| macos-latest | 3.3 / 3.4 | 2.6.9 / 4.0.17 | pass (`Gemfile` too) | untested | pass | untested | untested | untested | fixed #709 (#712) |

Controls for #709 (Linux, 4.0.17): config `path` relative, config `path` absolute inside the project, env `BUNDLE_PATH` absolute outside the project, and `path.system: true` all pass (stale warning; `vex` refuses `not_applied`).

### Run 14: stale-install warning flavor and `BUNDLE_IGNORE_CONFIG` (Linux, Ruby 3.3.6)

| Bundler | Hosted stale warning, `--cwd` omitted / `.` | Hosted stale warning, absolute or `../proj` `--cwd` | Hosted `BUNDLE_IGNORE_CONFIG` + config `path vendor/bundle` | Agent + `vex`, same shape |
| --- | --- | --- | --- | --- |
| 4.0.17 | fail #729 (also on the v4.0.0 release) | pass | documented heuristic (warns about the wrong copy) | documented heuristic (false VEX; see Known non-bugs) |
| 2.6.9 | fail #729 | pass | untested | untested |
| 2.4.22 | fail #729 | pass | untested | untested |

### Run 15: Bundler 1.17 / 2.2 / 2.3 hosted, custom lockfiles, odd files

| OS | Ruby | Bundler | Hosted `Gemfile` only | Hosted `gems.rb` only | Hosted `Gemfile` + `gems.rb` twin | Hosted cycle incl. rollback (Linux) | Custom lock: config `lockfile` / env `BUNDLE_LOCKFILE` | Stale twin `Gemfile.lock` → pre-install `vex` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ubuntu-latest | 2.7 / 3.1 | 1.17.3 | pass | pass | fail #751 | untested | n/a | untested |
| windows-latest | 2.7 | 1.17.3 | pass | pass | fail #751 | untested | n/a | untested |
| ubuntu-latest / windows-latest | 2.7 / 3.1 | 2.2.33 | pass | pass | pass | untested | n/a | untested |
| Linux | 3.3.6 | 2.2.33 / 2.3.27 | pass | pass | untested | pass | n/a | untested |
| Linux | 3.3.6 | 2.6.9 | — | — | — | — | n/a | fixed #736 (#750) |
| Linux | 3.3.6 | 4.0.17 | — | — | — | — | fail #749 | fixed #736 (#750) |

Also on 4.0.17: BOM `Gemfile` passes; symlinked `Gemfile` / lock is refused (pass); `--dry-run` writes nothing (pass).

### Run 16: mode takeovers (Linux, Ruby 3.3.6; OS-independent logic)

| Bundler | H→V `scan --mode vendored`, `group` decl | H→V `get --mode vendored`, `group` decl | H→V `vendor` eject, `group` decl | H→V top-level decl | V→H `scan --mode hosted` | V→H remedy (`remove` → hosted) |
| --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fail #775 | fail #775 | pass (rolled back) | blocked (mock grant conflict) | refused (fail-safe, see Known non-bugs) | pass |
| 2.6.9 | fail #775 | untested | untested | untested | untested | untested |
| 2.4.22 | fail #775 | untested | untested | untested | untested | untested |

### Run 17: vendored `repair`, custom lock, standalone installs (Linux, Ruby 3.3.6)

| Bundler | Vendored `repair` (corrupt / missing file / missing dir / extra file) | Vendored `lockfile custom.lock` | Agent `apply` + `vex` on `bundle install --standalone` |
| --- | --- | --- | --- |
| 4.0.17 | pass | pass (fails closed) | fixed #796 (#797) |
| 2.7.2 / 2.6.9 / 2.5.22 / 2.4.22 | untested | n/a | pass |

### Run 18: multi-gem hosted lifecycle and takeover (Linux, Ruby 3.3.6, real rubygems.org upstream)

| Bundler | Hosted: 3 gems one scan (frozen fresh install) | Hosted: incremental + byte-identical re-run | Hosted: `rollback` 1 of 3, then all | H→V takeover, 1 gem | H→V takeover, 3 gems | H→V takeover, mixed no-CHECKSUMS pair |
| --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | pass | pass | pass | pass | fixed #779 (#805) | n/a |
| 2.6.9 | pass | untested | pass | untested | untested | untested |
| 2.4.22 | pass (after the documented unfrozen install) | untested | untested | untested | fixed #779 (#805) | fails closed (documented mixed state) |

### Run 19: single-line declaration shapes, deployment config, 2.6.9 suites (Linux, Ruby 3.3.6, real rubygems.org upstream)

| Bundler | Repo gem e2e suites | Hosted: trailing `# comment` | Hosted: `gem(...)` | Hosted: `y; gem "x"` (patched 2nd) | Hosted: `gem "x"; gem "y"` (patched 1st) | Hosted: `gem "x", opt; gem "y"` | Vendored: `gem "x"; gem "y"` | Agent: `BUNDLE_DEPLOYMENT` config | Agent `vex`: stale `ruby/<old ABI>` scope |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | pass | pass (comment dropped) | pass | pass (refused) | fail #826 (also `gems.rb`, and PR #637) | fail #826 | fail #826 | pass | pass (refuses) |
| 2.6.9 | pass (21 + 16 + 25) | untested | untested | untested | fail #826 | untested | untested | untested | untested |
| 2.4.22 | untested | untested | untested | untested | fail #826 | untested | fail #826 | untested | untested |

### Run 20 (Linux, Ruby 3.3.6, real rubygems.org upstream; plus a macOS/Windows global-mode probe)

| Bundler | Hosted: `gem "x", "1"; # c` / `# …; gem "y"` in a comment | Hosted: one-line `group … do gem … end` / `gem %q(x)` | Hosted: `*V` / `ENV.fetch(…)` / tab / `:require =>` / `platforms: [...]` / `group: [...]` / `"x" ,` | Hosted `rollback` of those shapes | Hosted: decl duplicated in `=begin`/heredoc/`__END__` | Hosted: `gem "x-y", path:` next to the patched `gem "x"` | Hosted: 3 concurrent scans | Hosted: env `BUNDLE_GEMFILE` (6 spellings) | Vendored: `*V` / `ENV.fetch(…)` / `CONST, require: false` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0.17 | fail #826 (`;` now refused since #637, comment) | pass (refused: `redirect_gem_declaration_not_visible`) | pass | pass (exact pin + kept args, documented) | pass (refused: `declared_more_than_once`) | pass | pass (apply.lock) | pass | fixed #847 (#849) |
| 2.6.9 | fail #826 (`;` refused) | untested | pass | untested | untested | untested | untested | untested | untested |
| 2.4.22 | fail #826 (`;` refused) | untested | pass (after the documented unfrozen install) | untested | untested | untested | untested | untested | fixed #847 (#849) |

### Run 21 (main `0d302dc`; Linux Ruby 3.3.6 unless noted; real rubygems.org upstream)

| Cell | 4.0.22 | 4.0.17 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- | --- |
| Repo gem e2e suites (redirect 25 / vendor 18 / stale 29) | pass | — | — | — |
| Hosted single-line CHECKSUMS cycle, `Gemfile` and `gems.rb` | pass | pass | — | — |
| Hosted transitive (via `path:` gem) / `group` block / CRLF `Gemfile`, then `rollback` → frozen install | pass (lock byte-restored) | — | — | — |
| Hosted, lock `PLATFORMS` = `x86_64-linux` only | pass | — | — | — |
| Hosted, 9 one-line shapes after #637 (`gem(...)`, trailing `# … if …`, 2 constraints, `%i[]`, `"#{…}"`, `!=`, `!true`, `group:` + `require:`) | — | pass | — | — |
| Hosted `gem "x", "1";` / `gem "x", "1"; # c` | — | fail #826 (refused since #637) | fail #826 | fail #826 |
| Hosted `rollback` after a user `bundle update` of another gem | — | pass (the other gem's update kept) | — | — |
| Hosted stale guard, `--standalone` install (`./bundle`) | — | pass (warns, VEX withheld; remedy wording, see Known non-bugs) | — | — |
| Hosted stale guard, system-gems install (no `path`) | — | pass | — | — |
| Vendored `CONST` / `*%w[]` / `*EXTRA` / `**OPTS` / two constants (after #849) | — | pass | — | — |
| Vendored transitive gem from the lock's 2nd GEM section (after #805) | — | pass | — | — |
| Agent: locked default gem (`uri 0.13.1`), system gems | — | pass (Bundler installs a regular copy, which is patched) | — | — |
| Windows (RubyInstaller 3.4.9) Bundler 4.0.22 agent cycle, path with a space | pass | — | — | — |

### Run 22 (main `9c43dfc`; Linux Ruby 3.3.6 unless noted; real rubygems.org upstream)

| Cell | 4.0.22 | 2.7.2 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- | --- |
| Hosted CHECKSUMS cycle + `rollback` → frozen install | pass | pass | pass | documented (no CHECKSUMS) |
| Hosted 4-platform lock + CHECKSUMS (pure-ruby gem) + rollback | pass | — | — | — |
| Hosted `gems.rb` + stale `Gemfile.lock` twin (#736 fix) + rollback | pass | — | — | — |
| Hosted gem in `git … do` / `path … do` / `git:` (#652 fix) | pass (refused via lock section) | — | — | — |
| Hosted `BUNDLE_GEMFILE` = project Gemfile via symlinked dir (env / `--cwd` / config); `vex` / `rollback` | fail #896 (also macos-latest `/tmp`, ubuntu-latest) | — | — | — |
| Hosted `gem "x", "1"; gem "y"` (bare 2nd gem) | fail #826 (new shape; PR #875 passes) | — | — | — |

### Run 23 (main `9c43dfc`; Linux Ruby 3.3.6; agent mode, hand-written manifest + `apply --offline`)

| Cell | 4.0.22 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- |
| Local `path.system: true` + leftover `vendor/bundle`: `apply` / `vex` | fail #915 | fail #915 | fail #915 |
| Env `BUNDLE_PATH__SYSTEM=true` + leftover `vendor/bundle` | fail #915 | fail #915 | fail #915 |
| Local `path.system: true`, no leftover (control) | pass | pass | untested |

### Run 24 (main `9c43dfc`; Linux Ruby 3.3.6; Bundler 4.1.0.beta1)

| Cell | 4.1.0.beta1 |
| --- | --- |
| Repo gem e2e suites (redirect 26 / vendor 22 / stale 32) | pass |
| Agent `apply --offline` + `vex`, unquoted `BUNDLE_PATH: vendor/my bundle` (4.1 config spelling) | pass |
| Config readers on main vs 4.1 `.bundle/config` (`BUNDLE_PATH` / `GEMFILE` / `CACHE_PATH` / `PATH__SYSTEM`) | pass |
| URL-scoped `mirror.<patch source>` quoted key vs PR #684 | gap in the PR (comment on #681) |

### Run 25 (main `9c43dfc`; Linux Ruby 3.3.6; agent `apply --offline` + `vex` with a hand-written manifest, real `bundle install` / `bundle exec`)

| Cell | 4.1.0.beta1 | 4.0.22 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- | --- |
| Agent: `.bundle/config` `BUNDLE_PATH: .gems # comment` (system copy also present) | fail #951 | fail #951 (×2) | fail #951 | fail #951 |
| Agent: `BUNDLE_PATH: .gems` control | — | pass | pass | pass |
| Hosted stale guard: `BUNDLE_CACHE_PATH: vendor/gems # comment` + stale archive (e2e harness case) | — | fail #951 (2/2, OS/version-independent) | — | — |
| Agent: env `BUNDLE_GEMFILE=gemfiles/alt.gemfile`, `path vendor/bundle` in `gemfiles/.bundle/config` | — | fail #952 (×2) | fail #952 | — |
| Agent: env `BUNDLE_GEMFILE=gemfiles/alt.gemfile` + env `BUNDLE_PATH=vendor/bundle` (relative) | — | fail #952 | fail #952 | — |

### Run 26 (main `9c43dfc`; Linux Ruby 3.3.6; agent `apply --offline` + `vex`, real `bundle install` / `bundle exec`)

| Cell | 4.0.22 | 2.6.9 | 2.5.22 |
| --- | --- | --- | --- |
| Agent: Bundler's `.bundle` default path (local `simulate_version 5` on 4.x / `default_install_uses_path true` on 2.x) | fail #967 (×2) | fail #967 (×2) | fail #967 |
| Same, env spelling (`BUNDLE_SIMULATE_VERSION=5` / `BUNDLE_DEFAULT_INSTALL_USES_PATH=true`) | fail #967 | fail #967 | — |
| Control: no setting (system install) | pass | — | — |
| PR #953 head `52542db` on the #951 agent shape | pass (fixes #951) | — | — |

### Run 27 (main `9c43dfc`; Linux Ruby 3.3.6; `gemspec` library projects)

| Cell | 4.0.22 | 4.0.0 / 4.0.10 / 4.0.17 | 2.7.2 | 2.6.9 |
| --- | --- | --- | --- | --- |
| Hosted: gemspec dev dep only (no Gemfile line) | pass (refused: `redirect_gem_declaration_not_visible`) | — | — | — |
| Hosted, CHECKSUMS lock: gemspec dev dep + Gemfile `gem` line → fresh frozen install | fail #985 (×3) | fail #985 | fail #985 | pass |
| Hosted: gemspec runtime dep + Gemfile `gem` line → fresh frozen install | pass | — | — | — |
| Vendored: gemspec dev dep + Gemfile `gem` line → fresh frozen install | fail #985 (×2) | — | fail #985 | pass |

### Run 28 (main `9c43dfc`; Linux Ruby 3.3.6; hosted mock + real rubygems.org upstream)

| Cell | 4.0.22 | 2.6.9 |
| --- | --- | --- |
| Hosted stale guard: config/env `path vendor/bundle` not installed + unused system copy | fail #1001 (×3; also v4.0.0, PR #968) | fail #1001 |
| Hosted stale guard: `simulate_version 5`, unpatched `.bundle` install | fail #967 (false VEX; PR #968 pass) | — |
| Agent #967 shapes on PR #968 `25e3ca6` | pass | pass |
| Hosted gemspec dev-dep: converge → `rollback` → frozen install | pass | — |
| Hosted transitive via `git:` gem: cycle + `rollback` | pass (lock byte-identical) | — |
| Agent env `BUNDLE_PATH='~/x'` | pass | — |

### Run 29 (main `d47eab3`; Linux Ruby 3.3.6; hosted mock + real rubygems.org upstream, agent hand-written manifest)

| Cell | 4.0.22 | 2.6.9 |
| --- | --- | --- |
| Re-triage #951 agent shape (`BUNDLE_PATH: .gems # comment`) | still fails #951 | — |
| Re-triage #952 agent shape (`BUNDLE_GEMFILE=gemfiles/alt.gemfile`) | still fails #952 | — |
| Hosted: `~> 1.0` locked at 1.1.0, 0.8.1 only in the shared system gem home | **fail #1055** (×2; also v4.0.0) | **fail #1055** |
| Hosted: same, transitive via a path gem (`~> 1.0`) | **fail #1055** (unresolvable) | — |
| Hosted unwind: gem inside `source "https://rubygems.org" do` (4 shapes), `rollback` and `remove` | **fail #1056** (×2) | **fail #1056** |
| Hosted cycle + rollback: prerelease `1.0.0.pre.1` | pass | — |
| Hosted cycle + rollback: `ruby "3.3.6"` / `ruby file:` / `# frozen_string_literal` / trailing `;` / `; # c` (#875) | pass | — |
| Hosted cycle + rollback: `install_if` / `platforms` / `group :a, :b` / `env` blocks | pass (lock byte-restored) | — |
| Hosted: `source: "https://rubygems.org"` option | pass (refused, documented) | — |
| Repo gem e2e suites | pass (redirect 32 / vendor 22 / stale 33) | — |

### Run 30 (main `05ecc6e`; Linux; agent hand-written manifest + `apply --offline`; real `bundle install` / `bundle exec`)

| Cell | Ruby 3.3.6 / Bundler 4.0.18 | Ruby 3.1.6 / Bundler 2.6.9 |
| --- | --- | --- |
| Agent: `ffi-1.17.2/` + `ffi-1.17.2-x86_64-linux-gnu/` in `vendor/bundle` (`force_ruby_platform` toggled), unqualified and `?platform=x86_64-linux-gnu` keys | **fail #1092** (×2) | — |
| Agent: same pair in a shared `GEM_HOME` (`gem install --platform ruby` + default) | **fail #1092** | **fail #1092** |
| Global `apply -g` on the same pair | **fail #1092** (comment) | — |
| Re-triage #952 (`BUNDLE_GEMFILE=gemfiles/alt.gemfile`, root Gemfile present) | still fails #952 | — |
| #952 variant without a root `Gemfile` | pass (nothing applied, `vex` writes nothing) | — |
| Bisect #1092 on v4.0.0 | also patches only the ruby dir (pre-v5) | — |

### Run 31 (main `05fd82b`; Linux Ruby 3.3.6; hosted stale guard via the `e2e_redirect_gem_stale_install.rs` harness, ×2 incl. real `gem env`; real `bundle install` for Bundler's own behaviour)

| Cell | 4.0.18 | 2.5.22 |
| --- | --- | --- |
| Hosted stale guard, explicit `path` not installed + unused system copy (#1001 fix) | pass | — |
| Same, local `deployment true` (no `path`) | **fail #1109** (real Bundler installs into `vendor/bundle`) | — |
| Same, env `BUNDLE_DEPLOYMENT=true` | **fail #1109** | real Bundler installs into `vendor/bundle` |
| Same, `simulate_version 5` / `default_install_uses_path true` | **fail #1109** (real Bundler installs into `.bundle`) | — |
| Control: no setting (system gems) | pass (warns) | — |

### Run 32 (main `b96a785`; Linux Ruby 3.3.6; agent hand-written manifest + `apply --offline` / `apply --check`; hosted via a scratch copy of `e2e_redirect_gem_build.rs` with real `bundle install`)

| Cell | 4.0.18 | 2.5.22 |
| --- | --- | --- |
| Repo gem e2e suites (redirect 32 / stale 37 / vendor 22 / multi-platform 7) | pass | — |
| Agent `apply --check`: system install / #915 / #967 / #951 / out-of-tree config + env path shapes | pass | — |
| Agent `apply --check`: #952 shape | fail #952 | — |
| Agent `apply --check`: #1092 dual-platform pair (both key spellings); `rollback` | fail #1092; rollback pass | — |
| Hosted, lockless Gemfile `~> 2.0`, older version only in the shared home | **fail #1125** | **fail #1125** |
| Hosted, lockless Gemfile not declaring the shared-home gem | **fail #1125** | **fail #1125** |

### Run 33 (main `823810a`; Linux Ruby 3.3.6; scratch copy of `e2e_redirect_gem_build.rs`, real `bundle install`)

| Cell | 4.0.18 |
| --- | --- |
| Hosted `lockfile custom.lock` via `.bundle/config` + leftover `Gemfile.lock` (#749 fixture) | pass (refused) |
| Hosted `Gemfile` + `gems.rb` twin (#751 fixture) | pass (refused) |
| Hosted Gemfile DSL `lockfile "custom.lock"` + leftover `Gemfile.lock` | **fail, #749 gap** (commented; ×2) |

### Run 34 (main `cb16bdd`; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_build.rs`, real `bundle install`, CHECKSUMS lock)

| Cell | 4.0.22 | 4.0.18 |
| --- | --- | --- |
| Hosted 1-gem superseding patch (new uuid, same version): re-scan, stale warning, cold frozen install of gen B, `vex` | — | pass |
| Hosted 2-gem re-scan, sorted section insert | pass | pass |
| Hosted 2-gem re-scan superseding one gem to a later-sorting uuid | fixed #1186 (#1190) | lock re-sorted by Bundler (warning only) |

### Run 35 (main `f3c6313`; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_build.rs`; rollout cap)

| Cell | 4.1.0.beta2 | 4.0.22 | 2.5.22 |
| --- | --- | --- | --- |
| Repo gem e2e suites (redirect 35 / stale 37 / vendor 41 / multi-platform 7) | pass | — | — |
| Hosted, no-CHECKSUMS lock, re-scan `--max-new-patches 0` | — | **fail #1224** | **fail #1224** |
| Hosted, 2 gems, no-CHECKSUMS lock, `--max-new-patches 1` ×4 | — | **fail #1224** (starves) | **fail #1224** (first bad `4d06019`) |
| Same, CHECKSUMS lock | — | pass | n/a |
| Hosted superseding patch under `--max-new-patches 0`, no-CHECKSUMS | — | — | fail (#1224 comment; predates #1058) |
| Same, CHECKSUMS lock | — | pass (`upgrade: 1`) | — |

### Run 36 (main `a80b89e`; Linux Ruby 3.3.6; 3–4 gem hosted mock + real rubygems.org upstream)

| Cell | 4.1.0.beta2 | 4.0.22 | 2.6.9 | 2.5.22 |
| --- | --- | --- | --- | --- |
| Hosted 3 gems CHECKSUMS: `rollback` first / middle / last / all, `remove` middle → frozen install | pass (middle) | pass | pass (middle) | — |
| Unfrozen install between scan and `rollback` | pass | — | pass | — |
| Patched gem with deps (`rack-test` → `rack`) cycle + `rollback` | — | pass | — | — |
| In-run `--vex` with 1 of 3 refused | — | pass | — | — |
| #1224 fix, capped re-scan `Gemfile` / `gems.rb` / lockless | — | — | — | pass |
| `bundle cache` after scan → `rollback` / `remove` | fixed #1260 (#1263) | fixed #1260 (#1263, run 37) | fixed #1260 (#1263) | fixed #1260 (#1263) |

### Run 37 (main `a8e9397`, v5.0.0; Linux Ruby 3.3.6)

| Cell | 4.0.18 | 2.6.9 | 2.5.22 | 2.4.22 | 2.3.27 |
| --- | --- | --- | --- | --- | --- |
| #1260 fix: hosted `bundle cache` → `rollback <bare name>` / `remove <versionless purl>` / `rollback VULN-GEM` / bare `rollback` (#1034 target grammar) | pass (`upstream_gem_stale_cache` names the archive) | — | — | — | — |
| #1260 fix with config `cache_path vendor/gems` | pass | — | — | — | — |
| v4 `setup` plugin registered, then the v5 cleanup commit lands (block + `.socket/bundler-plugin/` removed) | warning on every install (#1295) | warning on every install (#1295) | **fail #1295** (`LoadError`) | **fail #1295** | **fail #1295** |
| Migrator's own checkout following migrating-to-v5.md (incl. `bundle plugin uninstall`) | pass | — | — | — | — |
| v4.0.0 hosted scan → v5 re-scan (lock byte-identical) → v5 `rollback` | — | — | pass (documented exact pin) | — | — |

### Run 38 (main `6ad6add`, v5.0.0; Linux Ruby 3.3.6; agent hand-written manifest + `apply --offline` / `vex` / `rollback`, real `bundle install` / `bundle exec`; hosted via a scratch copy of `e2e_redirect_gem_build.rs`)

| Cell | 4.0.22 | 4.0.18 | 2.6.9 | 2.5.22 | 2.3.27 |
| --- | --- | --- | --- | --- | --- |
| #952 fix: env `BUNDLE_GEMFILE=gemfiles/alt.gemfile` + `gemfiles/.bundle/config` path | — | pass | — | pass | — |
| #952 neighbours: root-config `gemfile` (+ gemfiles path / + root-only path), env `BUNDLE_PATH` relative, `gemfiles` deployment, absolute env gemfile | — | pass | — | — | — |
| #952 neighbours: `gemfiles/gems.rb`, leftover unpatched root `vendor/bundle` (left untouched) | pass | — | — | — | — |
| #1092 fix: `ffi-1.17.2/` + `ffi-1.17.2-x86_64-linux-gnu/` in one home: apply both / runtime / `vex` / `rollback` both | pass | — | — | — | — |
| #1295 fix: real Bundler-written stale `plugin/index` → `apply` `gem_bundler_plugin_stale` | — | pass | — | pass | pass |
| #1056 fix: source-block unwind (plain / CRLF) | pass | pass | pass | — | — |
| #1056 gap: `v = if … end` / `v = case … end` inside the user's `source … do` block → unwind drops `!` | fail (#1056 comment; exit 16 with CHECKSUMS) | fail (×2) | fail | — | — |
| macOS / Windows probe (#952 backslash spelling, #1092 ucrt pair, #1295) | blocked: probe branch pushed, no Actions run triggered | | | | |

### Run 39 (main `15c2c83`, v5.0.0; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_build.rs`, real `bundle install`)

| Cell | 4.0.22 | 4.0.18 |
| --- | --- | --- |
| `v = if … end` in the user's `source … do` block → `rollback` keeps the `!` | **fail #1476** | **fail #1476** |
| Same → frozen install of the restored pair | **fail #1476** (exit 16) | pass (warning only) |
| Gemfile `lockfile "custom.lock"` DSL → hosted scan refused | **fail #1477** | **fail #1477** |

### Run 40 (main `aa85c6c`, v5.0.1; Linux Ruby 3.3.6; scratch copy of `gem_hosted_unwind_keeps_a_source_block_bang`, real `bundle install`)

| Cell | 4.0.22 | 2.6.9 |
| --- | --- | --- |
| #1476 fix: `x = while/until/unless … end`, endless def, one-line `x = if … then … end` in a source block (unit probe) | pass | — |
| Paren multi-line `source(\n "…"\n) do` → `rollback` / `remove` keeps the `!` | **fail #1509** (exit 16) | **fail #1509** (warning) |
| Brace `source("…") { … }` → `rollback` / `remove` | **fail #1509** (exit 16, Gemfile not byte-restored) | **fail #1509** |

### Run 41 (main `a8da202`, v5.0.1; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_build.rs` / `e2e_vendor_gem_build.rs`, real `bundle install`)

| Cell | 4.0.23 |
| --- | --- |
| Repo gem e2e suites (redirect 51 / stale 42 / vendor 43 / multi-platform 27) | pass |
| #1509 fix: multi-line `source(` opener / brace block → `rollback` / `remove` → frozen install | pass |
| `zz = 1; source "…" do` → `rollback` / `remove` | **fail #1531** (frozen exit 16) |
| `in_source_block` unit probe, 52 other shapes | pass |
| Vendored + Gemfile `lockfile "custom.lock"` / `lockfile false` | pass (refused `gemfile_not_loaded`) |
| Vendored + `lockfile "Gemfile.lock"` | pass |

### Run 42 (main `015e871`, v5.0.1; Linux Ruby 3.3.6; scratch copies of `gem_hosted_unwind_keeps_a_source_block_bang`, real `bundle install`)

| Cell | 4.1.0.beta2 | 4.0.23 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- | --- |
| Repo gem e2e suites (redirect 51 / stale 42 / vendor 43) | — | pass | — | — |
| #1531 fix + all 10 source-block unwind shapes → frozen install | pass | pass | pass | pass |
| #1531 neighbours: `;`-opener inside `group … do`, `source … do end; source … do`, `if true; source … do` | — | pass | — | — |
| `in_source_block` unit probe, 64 shapes | 63 pass (`self.source` miss, see Known non-bugs) | | | |

### Run 43 (main `e76cb9b`, v5.0.1; Linux Ruby 3.3.6, Bundler 2.5.22; agent hand-written manifest + `apply --offline` / `vex`, real `bundle install`)

| Cell | Result |
| --- | --- |
| Docker-style `GEM_HOME` = `BUNDLE_APP_CONFIG` = one dir, committed project `.bundle/config` `BUNDLE_PATH: vendor/bundle` (ignored by Bundler) → agent `apply` patches the `GEM_HOME` copy, `vex` attests | pass |
| Same, `$BUNDLE_APP_CONFIG/config` sets a `BUNDLE_PATH` with no install → `vex` refuses | pass |
| Gemspec product: commented `# spec.version = "…"` above `spec.version = Acme::VERSION` | **fail #1573** (`pkg:gem/acme@0.0.1`) |
| Gemspec product: commented `# spec.name = "…"` above the real one | **fail #1573** |

### Run 44 (main `657fce2`, v5.0.1; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_stale_install.rs` / `e2e_redirect_gem_build.rs`, real `bundle install` / `bundle cache`)

| Cell | 4.0.18 | 2.5.22 |
| --- | --- | --- |
| #1573 fix (#1582): commented / `=begin` / heredoc `spec.name` / `spec.version`, last assignment wins | pass (closed) | — |
| Docker layout hosted stale guard (`GEM_HOME` = `BUNDLE_APP_CONFIG`): project `.bundle/config` `BUNDLE_PATH` / `BUNDLE_DEPLOYMENT` ignored → shared-home warning + not attested; same keys in `$BUNDLE_APP_CONFIG/config` → quiet + attested (6 variants) | pass | — |
| H→V takeover over a patched `vendor/cache` archive → takeover advisory `upstream_gem_stale_cache` | pass | pass |
| Same → `vendor --revert` / `remove` / `rollback` of the vendored gem → no warning, fresh frozen install keeps patched bytes | **fail #1594** | **fail #1594** |
| H→V takeover on a CHECKSUMS lock with a non-rubygems.org upstream | pass (refused `redirect_revert_failed`, documented) | — |

### Run 45 (main `657fce2`, v5.0.1; Linux Ruby 3.3.6; the repo's real-Bundler suites with `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1`)

| Suite | 4.0.23 | 2.7.2 |
| --- | --- | --- |
| `e2e_redirect_gem_build` (hosted, 51 tests) | pass | pass |
| `e2e_redirect_gem_stale_install` (42 tests) | pass | pass |
| `e2e_vendor_gem_build` (vendored, 43 tests) | pass | pass |

### Run 46 (main `657fce2`, v5.0.1; Linux Ruby 3.3.6; scratch copy of the superseding-patch test with a committed `vendor/cache`, real `bundle install` / `bundle cache`)

| Cell | 4.0.18 | 2.4.22 |
| --- | --- | --- |
| Superseding hosted rescan with the gen-2 patched archive committed in `vendor/cache` (no CHECKSUMS) → `redirect_gem_stale_install` names the archive | pass | pass |
| Same, CHECKSUMS lock | pass (fresh install fails closed, exit 37) | n/a |
| Same, cache-only checkout (no `vendor/bundle`) | pass | pass |

### Run 47 (main `657fce2`, v5.0.1; Linux Ruby 3.3.6; scratch copy of the superseding-patch test, then `rollback` / `remove`, real `bundle install` / `bundle cache`)

| Cell | 4.0.18 | 2.6.9 | 2.4.22 |
| --- | --- | --- | --- |
| Unwind after a superseding rescan with the gen-2 archive in `vendor/cache` → `upstream_gem_stale_cache` | pass | pass | pass |
| Unwind in the unconverged (no-CHECKSUMS) supersede window → consistent pair | **fail #1626** | **fail #1626** | **fail #1626** |

### Run 58 (main `5ca5623`, v5.0.1; Linux; scratch platform-gem variant of `e2e_redirect_gem_build.rs` (mock upstream serving `vuln-gem-1.0.0.gem` + `vuln-gem-1.0.0-x86_64-linux.gem`), real `bundle install` / `bundle exec`)

| Cell | 2.2.33 (Ruby 3.1.6) | 2.3.27 (Ruby 3.1.6) | 2.4.22 (Ruby 3.1.6) | 2.5.22 (Ruby 3.3.6) | 2.6.9 (Ruby 3.1.6) | 4.0.23 (Ruby 3.3.6) |
| --- | --- | --- | --- | --- | --- | --- |
| Fixture lock shape | `x86_64-linux` variant only, `PLATFORMS x86_64-linux` | same | same | both variants, `PLATFORMS ruby` + `x86_64-linux` | both | both |
| Hosted platform-gem redirect (no CHECKSUMS) → converge → `bundle exec` loads the patched ruby gem | pass | pass | pass | pass | pass | pass (run 57) |
| `vendor` eject dry (`eject_planned`) / wet (PATH wiring) → frozen fresh install → `bundle exec` loads the patched copy | pass | pass | pass | pass | pass | pass (run 57) |
| Re-run `vendor` after the eject | pass (`noManifest`, exit 0; documented) | pass | pass | pass | pass | — |
| Ejected → `vendor --revert` / `rollback` / `remove` → frozen fresh install | pass (all three) | pass | pass | pass | pass | pass (run 57) |
| Stale-install guard with the pristine `vuln-gem-1.0.0-x86_64-linux` dir left installed | warns + same-run VEX exit 1; Bundler actually fetches the patched ruby gem (over-warning, conservative) | — | same as 2.2 | same as 2.2 | warns; Bundler **reuses** the stale platform copy (`VULNERABLE` loads): true positive | warns; Bundler reuses the stale copy and locks a phantom `vuln-gem (1.0.0-x86_64-linux)` under the patch registry: true positive |

### Run 57 (main `c8e26f6`, v5.0.1; Linux; scratch platform-gem variant of `e2e_redirect_gem_build.rs` (mock upstream serving `vuln-gem-1.0.0.gem` + `vuln-gem-1.0.0-x86_64-linux.gem`), real `bundle install` / `bundle exec`)

| Cell | 4.0.23 | 2.6.9 | 1.17.3 (Ruby 3.1.6) |
| --- | --- | --- | --- |
| Hosted redirect of a platform-resolved gem, no CHECKSUMS → converging install → `vendor` eject (dry: `eject_planned`; wet: PATH wiring, no platform sibling left) → frozen fresh install / `bundle exec` loads the patched copy | pass | pass | pass (1.17 locks only the ruby variant) |
| Same, eject in the unconverged window (lock still holds `vuln-gem (1.0.0)` + `(1.0.0-x86_64-linux)` upstream) | pass (`noManifest`, exit 0, nothing written; documented mixed state) | — | — |
| Ejected platform project → `vendor --revert` / `remove <purl>` / `rollback` → frozen fresh install | pass (all three) | — | — |
| Platform gem + CHECKSUMS lock: hosted scan | pass (`redirect_gem_platform_unsupported`, nothing written) | — | — |
| Repo gem suites (redirect 58 / vendor 46 / stale 42 / in-process apply 22 / multi-platform 27), `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1` | — | — | pass (redirect / vendor / stale) |
| Same suites on 4.1.0.beta3 / Ruby 3.3.6 | pass (all five) | | |

### Run 56 (main `b291caa`, v5.0.1; Linux Ruby 3.3.6; scratch tests in `e2e_vendor_gem_build.rs` / `e2e_redirect_gem_build.rs`, real `bundle install`)

| Cell | 2.6.9 | 4.0.23 |
| --- | --- | --- |
| Re-check #1808 (CRLF lock vendor / revert, repo test `gem_vendor_crlf_lock_fresh_checkout_and_revert`) | pass | pass (fixed, #1811) |
| Re-check #1821 (CRLF Gemfile vendor keeps CRLF, `gem_vendor_keeps_a_crlf_gemfile_crlf`) | pass | pass (fixed, #1822) |
| H→V eject on a CRLF Gemfile / lock (`gem_hosted_pin_with_a_crlf_lock_ejects_cleanly`) | — | pass |
| Vendored `Append` arm (transitive rack via rack-test), CRLF Gemfile ± CRLF lock: no mixed endings, re-run `already`, revert byte-exact | — | pass |
| Vendored `Append` arm, LF pair re-checked-out CRLF → `vendor --revert` / `rollback` / `remove` (CRLF kept, no mixed) / re-run no-op | — | pass |
| Hosted redirect, CRLF Gemfile (single-line decl, user `source` block; LF or CRLF lock): Gemfile endings | **fail #1831** | **fail #1831** |
| … lock endings, converging install, re-scan no-op, `rollback` / `remove` restore CRLF | pass | pass |

### Run 55 (main `ecd4924`, v5.0.1 + #1811 head; Linux Ruby 3.3.6; vendored CRLF Gemfile / autocrlf re-checkout, scratch probes in `e2e_vendor_gem_build.rs`)

| Cell | 2.6.9 | 4.0.23 | #1811 head (4.0.23) |
| --- | --- | --- | --- |
| `vendor` on CRLF `Gemfile` + LF lock: rewired line keeps CRLF | **fail #1821** | **fail #1821** | — |
| … then revert / rollback / remove byte-exact | pass | pass | — |
| Vendored LF pair re-checked-out CRLF → `vendor` re-run / `rollback` / `remove` | — | fail #1808 | pass |
| … → `vendor --revert` | — | drift-kept exit 0 (documented; root cause #1808) | pass (Gemfile line restored LF, #1821 note) |

### Run 54 (main `ecd4924`, v5.0.1; Linux Ruby 3.3.6; scratch tests in `e2e_redirect_gem_build.rs` / `e2e_vendor_gem_build.rs`, real `bundle install` / `bundle exec`)

| Cell | 2.6.9 | 4.0.23 | 4.1.0.beta3 |
| --- | --- | --- | --- |
| #1786 clean eject (LF pair): `vendor --dry-run` → `vendor` → fresh frozen install → `bundle exec` loads patched | pass | pass | pass |
| H→V `scan --mode vendored` takeover (LF pair): dry → wet → frozen install | pass | pass | pass |
| Eject, CRLF `Gemfile` + CRLF lock (`vendor` and `scan --mode vendored`) | **fail #1808** (dry 0 → wet 1) | **fail #1808** | **fail #1808** |
| Eject, CRLF lock only | — | **fail #1808** | — |
| Eject, CRLF `Gemfile` only | — | pass | — |
| Eject, BOM `Gemfile` | pass | pass | pass |
| Plain vendored, CRLF lock (dry and wet) | **fail #1808** (exit 1 both) | **fail #1808** | — |

### Run 53 (main `3a5f0d5`, v5.0.1; Linux Ruby 3.3.6; scratch tests in `e2e_redirect_gem_build.rs`, upstream spelled `https://rubygems.org` and served via `SOCKET_RUBYGEMS_URL` + `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/`)

| Cell | 4.0.18 | 4.0.23 | 4.1.0.beta3 | 2.6.9 |
| --- | --- | --- | --- | --- |
| Eject on a CHECKSUMS lock: dry run → wet run → fresh frozen install → `bundle exec` loads patched | pass | pass | pass | pass |
| Then `vendor --revert` (upstream sha re-derived) → fresh frozen install | pass | pass | pass | pass |
| Eject with a `path:` sibling, CHECKSUMS → frozen install → `rollback <purl>` → frozen install | — | pass | pass | pass |

### Run 52 (main `a8a10dc`, v5.0.1; Linux; scratch tests in `e2e_redirect_gem_build.rs`, real `bundle install` / `bundle exec`)

| Cell | 1.17.3 (Ruby 3.1.6) | 2.1.4 (Ruby 3.1.6) | 4.0.18 (Ruby 3.3.6) | 4.1.0.beta3 (Ruby 3.3.6) |
| --- | --- | --- | --- | --- |
| #1749 two hosted gems, merged lock: re-scan / supersede / `vex` / two-gem eject (`gem_hosted_two_gems_rescan_supersede_and_attest`) | pass (fixed by #1750) | pass (fixed by #1750) | — | pass (suite) |
| #1761 group-block eject dry run vs wet run | pass (fixed by #1762) | pass (fixed by #1762) | — | pass (suite) |
| Two hosted gems, supersede one, no converge → fresh frozen install | pass (lock remote moves) | pass | fails (the documented #1626 window) | — |
| Then `rollback` / `remove` of ONE gem → fresh frozen install, other gem still patched → unwind the second | pass | pass | pass | — |
| Eject with `git:` + `path:` sibling gems (no CHECKSUMS) → fresh frozen install / `bundle exec` | — | — | pass (GIT/PATH sections kept) | — |
| Eject with `git:` + `path:` siblings, CHECKSUMS lock, mock upstream | — | — | dry run and wet run both refuse `redirect_revert_failed` (non-rubygems upstream, documented; parity holds) | — |
| Eject, `gems.rb`-only project | — | — | refused `gemfile_not_loaded` (documented) | — |
| Eject → `vendor` re-run (idempotent, byte-identical) → `vendor --dry-run` → `scan --mode hosted` | — | — | pass; the V→H scan skips with `redirect_gem_source_option` (known) | — |
| `BUNDLE_DEPLOYMENT=true` install of the ejected pair | — | — | pass | — |
| Full redirect (56) + vendor (44) + stale-install (42) suites | — | pass (`two_gems` / `group_block` only) | — | pass |
| macOS probe of the gem suites (1.17.3 → 4.1.0.beta3) | blocked: pushed `bughunt/bundler/20261028-macos-gem-suites`, no Actions run triggered, and the branch can't be deleted from the sandbox (remote hangs up) | | | |

### Run 51 (main `b787454`, v5.0.1; Linux; #1648 plain `vendor` eject, scratch tests in `e2e_redirect_gem_build.rs`, real `bundle install` / `bundle exec`)

| Cell | 1.17.3 (Ruby 3.1.6) | 2.1.4 (Ruby 3.1.6) | 4.0.18 (Ruby 3.3.6) |
| --- | --- | --- | --- |
| Eject, one hosted gem (merged lock on ≤ 2.1) → frozen install | pass | pass | pass (run 50) |
| Eject → `vendor --revert` ×2 → frozen install | pass (back to upstream, documented) | pass (back to upstream, documented) | pass (run 50) |
| Eject, two hosted gems: dry run / wet run | refused `hosted_wiring_contested` (#1749, commented) | refused `hosted_wiring_contested` (#1749, commented) | pass (both ejected, frozen install, `bundle exec` loads both patched, `vex` `not_affected`) |
| Two-gem merged 2.1.4 lock → unfrozen `bundle install` on 2.6.9 | — | lock splits into one section per remote; eject then plans (exit 0) | — |
| Eject after a dual boot is added (`BUNDLE_GEMFILE: Gemfile.next` in `.bundle/config`, or the env var; `Gemfile.next` evals `Gemfile`) | pass (both refuse `hosted_wiring_contested`, nothing written) | — | pass (same) |
| Redirect (54) + vendor (44) + stale-install (42) suites | pass | — | — |

### Run 50 (main `b787454`, v5.0.1; Linux Ruby 3.3.6; #1648 plain `vendor` eject, scratch tests in `e2e_redirect_gem_build.rs`, real `bundle install`)

| Cell | 4.0.18 | 2.5.22 |
| --- | --- | --- |
| Eject, top-level decl, fresh checkout → frozen install → `vendor --revert` → frozen install | pass | — |
| Eject with a stale `.socket/manifest.json` (other uuid + manifest-only gem) | pass (manifest ignored, byte-identical) | — |
| Eject, `gems.rb` twin, dry run and wet run | pass (both `gemfile_not_loaded`) | — |
| Eject, `group`-block decl: dry run vs wet run parity | **fail #1761** | **fail #1761** |
| Eject on an unconverged Gemfile-only pin | no-op `noManifest` (documented) | — |

### Run 49 (main `4654b7c`, v5.0.1; Linux; scratch tests in `e2e_redirect_gem_build.rs`, real `bundle install` / `bundle exec`)

| Cell | 1.17.3 (Ruby 3.1.6) | 2.1.4 | 2.5.22 | 4.0.18 | 4.0.23 |
| --- | --- | --- | --- | --- | --- |
| Hosted: 2 gems redirected (merged section, 2 Socket remotes): in-sync re-scan / supersede / `vex` | **fail #1749** | **fail #1749** | pass | — | pass |
| Hosted: one gem, supersede (#1688 fix) | — | pass | — | — | — |
| Hosted #985: gemspec dev dep with multi requirement (`">= 0.5", "< 2"`), CHECKSUMS → frozen install | — | — | — | pass (`(>= 0.5, = 1.0.0, < 2)!`) | — |
| Hosted #985: merged pin → `rollback` / `remove` → frozen install | — | — | — | pass | — |
| Hosted: gem only a gemspec dev dep (no `gem` line) | — | — | — | refused `redirect_gem_declaration_not_visible` (documented) | — |
| Full redirect + vendor gem suites | — | — | — | — | pass (33 + 9) |

### Run 48 (main `7d3086f`, v5.0.1; Linux Ruby 3.3.6; scratch copies of `e2e_redirect_gem_build.rs` with sha512 + `gem-stub-gemspec` grants, real `bundle install` / `bundle exec`)

| Cell | 4.0.18 | 2.5.22 |
| --- | --- | --- |
| Hosted rotated grant (same uuid) → `rollback` / `remove` in the unconverged window | pass | — |
| H→V takeover in the #1626 unconverged-supersede window | pass (fails closed) | — |
| Vendored gen-1 → superseding gen-3 re-vendor → frozen install / `vex` (± CHECKSUMS) | pass | pass |
| Then `rollback` / `remove` / `vendor --revert` → byte-pristine | pass | pass |
| Vendored supersede with options + comment / CRLF Gemfile | pass | — |
| Vendored superseding patch `pending_build` / `build_failed` | fail #1235 (exit 1, gen-1 kept) | — |

### Global mode (`-g`)

| OS | Ruby / Bundler | `scan -g` report | `-g` vs project scoping | `scan -g --mode hosted` refused | `get -g` / `apply -g` | `rollback -g` byte-exact | `vex -g` | `--global-prefix <gems dir>` / `SOCKET_GLOBAL=1` | Non-writable gem dir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux (sandbox, rbenv) | 3.3.6 / 4.0.17 | pass | pass | pass | pass (both homes) | pass | fixed #420 (#517); pass (single home) | pass | pass (loud `Permission denied`) |
| ubuntu-latest | 2.7 / 3.3 / 3.4 | pass | untested | pass | pass | pass | fixed #420 (#517) | pass | untested |
| macos-latest (setup-ruby) | 2.7 / 3.3 / 3.4 | pass | untested | pass | pass | pass | fixed #420 (#517) | pass | untested |
| windows-latest (RubyInstaller) | 3.3 / 3.4 | fixed #421 (#442, run 10 probe) | untested | pass | pass (both homes) | pass | pass (refuses after a user reinstall) | pass | untested |
| windows-latest (RubyInstaller) | 2.7 | fixed #421 (#442, run 10 probe) | untested | pass | pass (both homes) | pass | pass | pass | untested |
| macos-14 / macos-15 system Ruby 2.6 (`--user-install`) | 2.6 / bundled | pass | untested | untested | pass | pass | pass | n/a | n/a |
| macos-14 / macos-15 system Ruby 2.6, root-owned `/Library/Ruby/Gems` | 2.6 | pass | n/a | untested | pass (exit 1 `partial_failure`, nothing written) | n/a | pass (refuses) | pass | pass (`partial_failure`, exit 1) |
| macos-14 / macos-15 Homebrew Ruby 4.0.6 | 4.0.6 / bundled | pass | pass (`-g` inside a project leaves `vendor/bundle` alone) | untested | pass | pass | pass | pass | untested |
| macOS / Windows / Linux unicode + space `--global-prefix` | 3.3 | pass | n/a | n/a | pass | pass | pass | pass | n/a |
| windows-latest `-g` inside a Bundler project | 3.3.12 | pass | pass | untested | pass | pass | untested | untested | untested |
| Linux, chruby layout (`GEM_HOME=~/.gem/ruby/<v>`) | 3.3.6 | pass | n/a | untested | pass | pass | pass | untested | n/a |
| Linux, rvm layout (`@app` + `@global` gemsets, incl. a shadowing gemset copy) | 3.3.6 | pass | n/a | untested | pass (patches both) | pass (both) | pass (refuses while the shadowing copy is unpatched) | untested | n/a |
| asdf | any | untested (same layout as the rbenv rows) | untested | untested | untested | untested | untested | untested | untested |
| windows-latest, deny-write ACE on the gem dir | 3.4.9 | pass | n/a | n/a | pass (exit 1 `partial_failure`, nothing written) | n/a | pass (refuses) | n/a | pass (fails closed; the ACE also blocks Ruby's own load) |
| macos-14 system Ruby 2.6 / Bundler 1.17, `-g` inside a project | 2.6 | pass | pass (project `vendor/bundle` untouched) | untested | pass | pass | pass | n/a | n/a |

## Backlog

1. Re-check #1831 once fixed (PR #1841, ready for review, not merged): hosted redirect on a CRLF Gemfile keeps CRLF in the in-place and the append (transitive) arms; `rollback` / `remove` still byte-exact; an autocrlf re-checkout of a redirected LF Gemfile re-scans as a no-op.
2. Re-run #1109 (`agent:needs-human`) when it's fixed.
3. The gem suites on 4.1.0 final when it ships; a 2.2 / 2.4 leg (Ruby 3.1.6) on the next main that touches gem code.
4. 2.6.9 hosted-unwind cells still untested: transitive with a trailing blank line, CRLF Gemfile (after #1841 lands). Also the 4.0.23 direct / `group` unwind with the upstream spelled `https://rubygems.org` + `SOCKET_RUBYGEMS_URL` (the e2e suites' trick).
5. Vendored stub-vs-lock runtime-dependency drift, only if the service `gem-stub-gemspec` can declare other deps than the lifted GEM spec block (a file patch can't).
6. macOS / Windows probes stay blocked until a maintainer deletes the leftover `bughunt/bundler/*` branches and push-triggered runs work again (none has triggered since 2026-10-05).

## Known non-bugs

- `rollback` / `remove` refuse to restore a gem whose upstream GEM remote isn't literally rubygems.org when the lock has CHECKSUMS, even with `SOCKET_RUBYGEMS_URL` pointing at that remote. `SOCKET_RUBYGEMS_URL` only sets where rubygems.org's sha is fetched from (the e2e suites spell the upstream as `https://rubygems.org` and serve it from the mock). `rubygems_locked` (`upstream/gem.rs:1480`) does accept the stand-in, but it only gates the stale-cache warning. Not filed (run 59).
- A Bundler 4.x platform project that runs `bundle install` before applying the stale-install remedy locks a phantom `x (V-x86_64-linux)` under the patch-registry remote (a fresh frozen install exits 16). socket-patch keeps warning, never attests, and the remedy plus `bundle install` re-converges. `rollback` / `remove` refuse that lock fail-closed with a `git checkout` remedy. That's the documented behaviour (run 59).
- The gem stale-install guard flags a pristine platform-suffixed install dir (`x-V-x86_64-linux`) after a hosted redirect to the ruby-platform patched gem, and the same-run `--vex` then exits 1 (`no_applicable_patches`). On Bundler 2.6.9 and 4.0.23 that's a true positive: `bundle install` keeps the installed platform copy and `bundle exec` loads the unpatched code. On 2.2–2.5 Bundler fetches the patched ruby gem instead, so the warning is conservative there; the guard can't know which Bundler will run, so this isn't filed (run 58).
- After a hosted redirect of a platform-resolved gem converges, the lock holds only the ruby-platform patched gem, so a later eject or unwind (`vendor --revert` / `remove` / `rollback`) restores the plain `x (V)` upstream entry, not the original `x (V-x86_64-linux)` sibling, and the next install uses the ruby build. That follows from the documented hosted platform behaviour; frozen installs pass (run 57).
- The `redirect_scanned_project` fixture deletes `vendor/` after its install (lock-only checkout), so a re-scan inside it reports `notInstalled: true` / `package_not_installed`. That's the fixture, not a crawler miss (run 57 near-miss).
- Hosted redirect and `rollback` swallow the blank line before a rewritten single-line declaration, and `rollback` restores a direct dep as an exact pin (`gem "x", "1.0.0"`). That's the same on LF and CRLF, and it's documented (#457, "Hosted unwind coverage") (run 56).
- Mixed line endings in a rewritten Gemfile are no longer "cosmetic": the vendored case was filed and fixed (#1821 / #1822), and the hosted case is #1831 (run 56).

- `vendor --revert` exits 0 (`status: success`) when every vendored entry is drift-kept (`vendor_lock_entry_drifted` + `vendor_artifact_kept` + `vendor_revert_kept`). That's documented in CLI_CONTRACT.md; `remove` / `rollback` exit 1 on the same state (run 55).

- Bundler keeps a CRLF `Gemfile.lock` CRLF on purpose (`definition.rb:428`, autocrlf), so a CRLF lock is a supported shape. A frozen fresh install of any CRLF lock exits 16 on Bundler 4.0.23 / 4.1.0.beta3 ("Your lockfile needs to be updated"), pristine or patched, and passes on 2.6.9. That's Bundler's own behaviour, not socket-patch (run 54).

- To drive a successful gem H→V takeover from `e2e_redirect_gem_build.rs`, mount a priority-1 `/patches/package` answer with a `sha512` tarball artifact and a `gem-stub-gemspec` artifact (`gem spec <archive> --ruby`); without them vendored mode fails `vendor_prebuilt_required` (run 44).
- In the Docker layout, the stale-install remedy's `bundle config set --local path vendor/bundle` writes to `$BUNDLE_APP_CONFIG/config` (Bundler's own behaviour); it still takes effect (run 44).
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
- Bundler 1.17 doesn't run on Ruby ≥ 3.2 (`String#untaint` was removed). Use Ruby 2.7 / 3.1 (setup-ruby probe) for 1.x cells.
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
- `bundle config set <key>` without `--local`/`--global`, run inside a project, writes the local `.bundle/config` on Bundler 2.4 / 2.6 / 4.0 (verified in run 9). Only an explicit `--global` reaches the global tier (#577).
- Probe workflows must wait for the mock API to listen before the first call. The run-10 Windows `scan -g` "0 found" was a "connection refused" race, not a crawler miss.
- `bughunt/bundler/20261002-win-recheck` is also left behind (`git push --delete` gets 403); its workflow is push-triggered only.
- `gem_tail_source_option` matches substrings, so a symbol such as `group: :gitlab_ci` would trip the `:git` refusal. It's fail-closed and contrived, so it's not filed.
- Vendoring a git-sourced gem (`git:`, `gitlab:`, custom `git_source`) fails closed with `apply_failed` ("GEM specs has no entry"), because the lock check fires before the Gemfile token list matters. It writes nothing, so it's not a #652 twin.
- On a CHECKSUMS lock whose install failed (nothing installed), the post-install `vex` still attests the redirected gem. That's consistent with the "missing files never prove staleness" rule in CLI_CONTRACT.md.
- `get <uuid> --mode hosted` for a version the lock doesn't hold pins (and downgrades to) the patched version, adds a second CHECKSUMS entry, and leaves a mixed pair that `rollback` / `remove` can't see (`Manifest not found`) until the prescribed unfrozen `bundle install` converges it (after that, rollback works). The uuid path is documented as exempt from installed narrowing (run 13).
- Bundler 4 prints "Cannot write a changed lockfile while frozen." (exit 0) for any CRLF lock under `BUNDLE_FROZEN`, including the pristine lock. It's Bundler's own behaviour.
- Hosted `rollback` / `remove` can be exercised by hand with no Rust harness: a Python mock of the patch API + the patch-registry compact index (rebuild the real `.gem` with `gem unpack` / `gem spec --ruby` / `gem build`), with rubygems.org as the real upstream. The run-13 entry describes it; the mock must ignore nothing the CLI checks (`registryOverride.identifiers.gemChecksumSha256` = the sha256 of the served `.gem`).
- `bughunt/bundler/20261003-hosted-xos` is also left behind (`git push --delete` hangs up / 403); its workflow is push-triggered only.
- `BUNDLE_IGNORE_CONFIG` is not honored when the crawler reads `.bundle/config` `path` (it is for `cache_path`/`gemfile`). It's harmless on its own: a non-default config path still gets the `gem env` homes appended. The only harmful shape is a populated `vendor/bundle` that bundler doesn't use (agent patches it, `vex` attests while the system copy loads), and that's the documented "`vendor/bundle` holds stores, so no `gem env` homes" rule; a leftover `vendor/bundle` with no config does the same (run 14).
- To bisect, the published binary is at `npm pack @socketsecurity/socket-patch-linux-x64-gnu@<ver>` (`package/socket-patch`). v4 needs `--mode hosted` explicitly.
- `bughunt/bundler/20261004-bundler1` is also left behind (`git push --delete` hangs up); its workflow is push-triggered only.
- With a Gemfile `lockfile "x.lock"` DSL, Bundler 4.0.17 itself refuses frozen/deployment installs ("requires a lockfile"), even with no socket-patch involvement.
- Lexical `starts_with(cwd)` sweep (run 15): the only gem-path hits are `scan/hosted.rs:218` / `:423` (#729). `resolve_config_bundle_path` absolutizes before comparing.
- Vendored → hosted takeover for a gem is refused with `redirect_gem_source_option` ("carries `path:` pointing into .socket/vendor … un-vendor this gem first"), exit 0, nothing written; the gem stays vendored-patched. The remedy (`remove <purl>`, then `scan --mode hosted`) works (run 16). It's fail-safe, so it's not filed even though the contract says takeovers work both ways.
- Vendored artifacts by hand (run 16): build a scratch test binary in `crates/socket-patch-cli/tests/` that starts `prebuilt_common::Server::project_with_env(<root>)`, writes its URI, and blocks; export `SOCKET_VENDOR_URL`. The root needs `.socket/manifest.json` + blobs + an unpatched install. Don't let another mock answer `/patches/package` (→ `vendor_prebuilt_integrity_mismatch`). Delete the scratch file afterwards.
- When copying a project to a "fresh checkout" via git, gitignore `vendor/bundle/` first, or the patched install travels along (run 16 false alarm).
- Vendored `repair` doesn't restore Gemfile / lock wiring the user reverted. It reports success with no events, matching the docs ("preserves project wiring"); `vex` reports `vendor_unwired` (run 17).
- Multi-source locks (a private `source … do` writes its own `GEM` section): vendored is tracked by #779 / #780 (arch audit). Hosted redirects a gem from any `GEM` remote; mirrors are legitimate, so that's policy, not a bug.
- In helper scripts, never `pkill -f` / `pgrep -f` a name that also appears in the same shell command; it kills the agent's own shell (exit 144).
- Hosted → vendored takeover by hand (run 18): `--patch-server-url <api mock>` is needed so vendored mode recognizes the loopback patch-registry wiring, but it also rewrites artifact download hosts. Have the API mock proxy `/artifacts/*` (every non-`/v0`, non-`/patch-registry` GET) to the prebuilt server, and export `SOCKET_VENDOR_URL=<prebuilt uri>` as well.
- Hosted → vendored takeover on a mixed (no-CHECKSUMS, not yet re-installed) pair fails closed with `gemfile_declaration_not_editable` and writes nothing. The takeover can't see the unconverged hosted wiring, consistent with the documented mixed-state limits (run 18).
- When verifying several fix PRs, build each into its own `CARGO_TARGET_DIR`; reusing one silently tests the wrong head (run 18 near-miss).
- `scan` defaults to hosted mode in v5. An agent probe must pass `--mode agent`, or it fails with "Failed to resolve patch references" against a mock with no `/patches/package` (run 19).
- `cargo test --test <t> -- --ignored --include-ignored` prints no results (conflicting flags). Use `--include-ignored` alone (run 19).
- A hosted rewrite drops a trailing `# comment` on the patched gem's line. That's cosmetic; vendored does the same and keeps the original in its ledger.
- Agent `vex` refuses `not_applied` when any crawled copy (e.g. a leftover `vendor/bundle/ruby/<old ABI>` scope) is unpatched, even if the live scope is patched. It's fail-safe, so it's not filed (run 19).
- Run-19 mocks (`mock.py` agent, `mock2.py` hosted grant + patch-registry compact index, with ETags) are described in the run-19 entry. Each is about 50 lines, and a rebuilt marker gem (`gem unpack` → append → `gem spec --ruby` → `gem build`) is enough for full hosted cycles against real rubygems.org.
- `get --json` on an apply that fails (e.g. a root-owned gem dir) reports `status: partial_failure`, exit 1, `applied: 0` and `failed: 0`: `failed` counts download failures only (`get.rs:2492-2506`), and the reason ("Permission denied (os error 13)") only reaches the human output. That's by design and not specific to gems, so it's not filed (run 20).
- A hosted declaration whose name is also mentioned inside `=begin`/`=end`, a heredoc or after `__END__` is refused with `redirect_gem_declared_more_than_once` (nothing written). It's fail-closed, so it's not filed (run 20).
- Hosted `rollback` of `gem "x", *V` / `gem "x", ENV.fetch(…)` leaves `gem "x", "<ver>", *V`: the documented exact-pin restore plus the kept argument. The lock is byte-restored and frozen installs pass (run 20).
- `bughunt/bundler/20261005-global-macos` is left behind if `git push --delete` fails; its workflow is push-triggered only.
- Bundler 4.0.19+ fails a frozen install with exit 16 ("Your lockfile needs to be updated, but it can't be because frozen mode is set") for any CRLF lock, including a pristine one with no socket-patch involvement (4.0.17 only printed "Cannot write a changed lockfile while frozen." and exited 0). It's Bundler's own change (rubygems #9750), so CRLF-lock cells on 4.0.19+ can't use frozen installs.
- Bundler 4.0.18+ `cooldown` ignores versions with no `created_at` and never retracts a locked version, so it doesn't affect a hosted exact pin (checked in the 4.0.22 source, run 21).
- The hosted stale-install remedy for a Bundler 4 `--standalone` project says "run `bundle install`". Plain `bundle install` then installs into system gems, and the standalone app fails loudly (`LoadError`) until `bundle install --standalone` is re-run, which yields the patched copy. That's a remedy wording nit with no silent unpatching, so it's not filed (run 21).
- Hosted `rollback` can leave one extra blank line after the `source` line in the Gemfile. That's cosmetic; the lock is byte-restored (run 21).
- A Bundler project that locks a Ruby default gem (e.g. `uri 0.13.1` on Ruby 3.3.6) gets a regular installed copy from Bundler 4, so the crawler sees and patches it. Default gems only exist as stdlib files (`gems/<name>-<ver>/` empty) outside Bundler (run 21). Clean up after agent tests on system gems: they patch the real system copy.
- In the Windows probe's MSYS bash, `icacls` needs `MSYS2_ARG_CONV_EXCL="*"`, or `/deny` is converted into a path. A deny-write ACE `(OI)(CI)(W,D,DC)` on the gem dir also makes Ruby's `require` fail, so it only tests fail-closed behavior. Don't check writability by appending to the gem file (`echo >>`): it changes the hash and breaks the cell (run 21).
- `bughunt/bundler/20261005-win-ro` is also left behind (`git push --delete` hangs up); its workflow is push-triggered only.
- Hand-rolled hosted harness: commit the project *after* the scan and before cloning the "fresh checkout"; committing before it clones the pristine Gemfile and fakes an "UNPATCHED" result (run 22 near-miss). A manifest-less `vex` needs `--patch-server-url <mock>` too, or it finds no hosted references.
- A Gemfile reverted by hand while the lock still carries the hosted wiring: `vex` attests as long as the installed bytes are patched (verified on disk), and refuses once `bundle install` re-resolves the lock to upstream (Bundler keeps the patched installed copy, but the reference is gone). That's fail-safe, so it's not filed (run 22).
- `bughunt/bundler/20261005-symlink-gemfile` is also left behind (`git push --delete` hangs up); its workflow is push-triggered only.
- Agent cells need no mock API: write `.socket/manifest.json` (`files` keys `package/<rel>`, git-sha256 `beforeHash`/`afterHash`) plus `.socket/blobs/<afterHash>` by hand and run `apply --offline` (run 23). Restore a patched system gem with `gem pristine <gem> -v <ver>`.
- A leftover populated `vendor/bundle` with **no** config while Bundler uses system gems makes agent `apply` patch the unused copy and `vex` attest. That matches the documented "`vendor/bundle` holds stores, so no `gem env` homes" heuristic and isn't filed; #915 covers only the explicit `path.system` signal (run 23).
- Bundler refuses `path` together with `path.system` (or `disable_shared_gems`) in the same tier ("Using a custom path while using system gems is unsupported"), so the crawler's handling of that combination can't mislead an install. Only the #915 shape (no `path`, leftover `vendor/bundle`) matters (run 24).
- `parse_dir_name_version` misparses gem names that contain `-<digits>.<…>` (32 of 197k rubygems.org names, all obscure, e.g. `citus-rails-4.2`). Not filed (run 24).
- Bundler 4.1 writes `.bundle/config` with unquoted values and double-quotes any key containing `:` (URL-scoped `mirror.` / credential keys). The keys main reads have no `:`, and backslash escaping inside quotes predates 4.1 (4.0's `inspect` did it too) (run 24).
- Bundler 4.1's Gemfile `override` DSL can't silently unpatch a hosted pin (the pinned source only serves the patched version), and it isn't counted as a `gem` declaration (run 24).
- Bundler's config loader keeps the double quotes when a quoted value is followed by a comment (`BUNDLE_PATH: ".gems" # c` → `"\".gems\""`) or by trailing spaces. Bundler itself breaks there, so only the unquoted `value # comment` shape (#951) is a socket-patch bug (run 25).
- Bundler's config loader doesn't unescape `inspect`-written values (`"D:\\a\\proj"`, `"\u00FC"`), and neither does socket-patch, so they agree (run 25).
- Under `BUNDLE_GEMFILE=gemfiles/x.gemfile`, Bundler reads `gemfiles/.bundle/config` and ignores the root `.bundle/config` (verified with 4.0.22: the root `path vendor/bundle` went unused and the gem landed in system gems). setup-ruby's `bundler-cache` writes an absolute `$PWD/vendor/bundle`, so the crawler's default `vendor/bundle` probe happens to find it; only relative paths hit #952 (run 25).
- Gemspec-library cells (run 27): the hosted/vendored harness copies must also copy `mylib.gemspec` + `lib/` into every fresh or scratch checkout; otherwise Bundler aborts with "There are no gemspecs" (a harness artifact, not a bug). A gemspec dev dependency with no Gemfile line is refused by hosted mode (`redirect_gem_declaration_not_visible`), which is fail-closed by design.
- Agent `.bundle/config` `path "~/x"` (tilde, so out of tree) is skipped as a write root with `gem_bundle_config_path_ignored`, and `vex` refuses `not_applied`. Documented (#709 contract); env `BUNDLE_PATH='~/x'` is expanded and works (run 28).
- In mock dirs, never run `gem install <gem>` from a cwd that holds a rebuilt `*.gem` of the same name and version: RubyGems installs the local file first, which silently patches the system copy and fakes "pass" results. Reinstall from an empty dir, and check the system cache `.gem` sha (run 28 near-miss).
- Bundler with an explicit `path` doesn't reuse a non-default gem from the system home (verified with `rexml 3.3.9`: it fetches into `vendor/bundle`). Default gems can still come from the system homes (run 28).
- A global (`~/.bundle/config`) `mirror.all` isn't inspected by the #681 mirror guard. That's documented in the docs/ecosystems.md RubyGems row ("user-global config … not inspected"), so it's not filed (run 29).
- Bundler 4.0.22 `Settings#path` applies `deployment` → `vendor/bundle` only when no tier sets `path` / `path.system` / `disable_shared_gems`, so a global `path.system true` plus a local `deployment true` really does use system gems; the crawler agrees (run 29). `disable_shared_gems: false` means system gems in Bundler, and the crawler ignores it, but Bundler never writes `false` itself (1.x writes `true` or removes the key), so it's contrived and not filed.
- An unconstrained `gem "x"` whose lock resolves a newer version than the shared-home copy hits #1055, not a separate bug (run 29).
- The #951 fix (#953) models Bundler's `strip_comment` exactly as Bundler 2.5.22 / 2.6.9 / 4.0.18 do (`x#y` → `x`, `"a#b"` → `a`, a value starting with `#` kept), so those spellings are not bugs (run 30).
- The sandbox's rbenv also has Ruby 3.1.6 (Bundler 2.6.9 installable) and 3.2.6, plus Bundler 4.0.18 on 3.3.6. Use an isolated `GEM_HOME` per cell so the system gems stay clean (run 30).
- To get both builds of a native gem into one gem home: `gem install <x> -v V --platform ruby` then `gem install <x> -v V` (needs gcc + libffi-dev for `ffi`, both present). Bundler 2.6+ locks list every platform variant by default (run 30).
- Bundler's `deployment true` (local or env) and `simulate_version 5` never reuse a system gem-home copy: they fetch into `vendor/bundle` / `.bundle` (verified with real installs, run 31). The hosted stale guard's false warning there is #1109.
- The worktree is a fresh container each run: there's no rbenv now, only `/usr/local/bin/ruby` 3.3.6 with Bundler 2.5.22 (default) + 4.0.18. Install other Bundlers into an isolated `GEM_HOME` (run 31).
- Hand-written agent manifests need BOTH blobs (`beforeHash` and `afterHash`) in `.socket/blobs`, or `rollback --offline` fails with "Before blob not found" (run 32 near-miss). Never derive a fixture from an already-patched file.
- A scratch hosted test in `e2e_redirect_gem_build.rs` needs `GEM_PATH=<shared home>:<system gem dir>` to pick a non-default Bundler via `BUNDLER_VERSION`; otherwise it silently falls back to the default 2.5.22 (run 32).
- Bundler 4.0.18 refuses every frozen install of a project whose Gemfile uses the `lockfile "x.lock"` DSL when no `Gemfile.lock` exists ("The frozen setting requires a lockfile"). With a leftover `Gemfile.lock` it passes that check and reads the DSL lock. That's Bundler's own behaviour (run 33).
- `#749` / `#751` are fixed for the config / env / global spellings and the twin (#768). The DSL spelling is tracked as a comment on #749.
- #1039 made the V→H takeover atomic, but gem is not in `hosted::takeover::takeover_ecosystem` (cargo / npm / golang / pypi / maven), so the run-16 gem V→H refusal is unchanged (run 34).
- A hosted single-gem superseding patch (same version, new uuid) works: the re-scan rewrites the block, lock remote and CHECKSUMS, and the stale guard flags the gen-A install (its wording says "UNPATCHED" for older-patch bytes; fail-safe, not filed) (run 34).
- Layer extra patch generations over the e2e fixture's mocks with wiremock `Mock::with_priority(1|2)` (default priority is 5); `cargo test` on a cold target takes >10 min, so run it with a long background timeout (run 34).
- A capped hosted re-scan never un-wires a deferred gem: the Gemfile `source` block stays, so #1224 is a stuck rollout, not silent unpatching (run 35).
- Bundler 4.1.0.beta2 lock / DSL changes (`OPTIONS` regex allows `_` for `sparse_checkout:`, the `override from:/to:` DSL, empty-CHECKSUMS re-resolve only when fetching remotely) don't touch the shapes socket-patch writes; the gem suites pass (run 35).
- Bisect without rebuilding tests: temporarily make `binary()` in the e2e file honour a `ZZ_BIN` env override, and build the old commit's release binary into its own `CARGO_TARGET_DIR` (about 6 min) (run 35). `std::env::var("X").is_ok()` is true for `X=""`, so leave scratch toggles unset rather than empty.
- A 3–4 gem hosted mock (run 36) is in the run-36 entry's description: one uuid per gem, so the patch-registry `GEM` sections sort in a known order, and the compact-index `info` carries `deps` (`rack-test` → `rack:>= 1.3`). Its `/patches/batch` offers every gem whatever the query, so a lockless or shared-home scan "finds" gems the project never declared (a mock artifact, not #1125).
- A partial hosted `rollback` leaves a VEX statement whose subcomponents list only the still-patched gems, even when they share one advisory with the rolled-back gem (correct OpenVEX scoping, run 36).
- A hosted unwind against the e2e harness's mock upstream on a CHECKSUMS lock is refused ("upstream GEM remote … is not rubygems.org"), so the #1260 CHECKSUMS branch can only be driven with a real rubygems.org upstream (run-36 harness); the e2e capstone covers the no-CHECKSUMS branch (run 37).
- Bundler's `Source::Path#cache` never copies a path gem that lives inside the project root, so `bundle cache --all` leaves vendored `.socket/vendor/...` gems alone and `vendor/cache/<name>/` can't shadow them (checked in the 4.0.18 source, run 37).
- The v4.0.0 binary still runs `setup` for migration tests (`npm pack @socketsecurity/socket-patch-linux-x64-gnu@4.0.0`); `bundle plugin uninstall` exists on Bundler 2.3+ and clears `.bundle/plugin/index` even after the plugin dir is gone (run 37).
- v5 `list` on a hosted gem project with a loopback patch registry shows 0 results unless `--patch-server-url <mock>` is passed (discovery trust rule, same as `vex`).
- `gem_bundler_plugin_stale` reads only `<root>/.bundle/plugin/index` (or `BUNDLE_APP_CONFIG`), not the moved `gemfiles/.bundle` under a `BUNDLE_GEMFILE` Appraisal layout. It's warning-only, so a miss there isn't filed (run 38).
- `scan --mode agent` with an unreachable API returns `status: error` with no warnings, so the #1295 warning isn't shown on that path. That's expected; `apply --offline` shows it (run 38).
- `bughunt/bundler/20261012-win-mac-recheck` is also left behind (`git push --delete` hangs up), and no run ever triggered on it; its workflow is push-triggered only.
- Bundler 4.0.18 only warns ("Cannot write a changed lockfile while frozen.", exit 0) when a source-block gem's DEPENDENCIES `!` is missing. 4.0.19+ fails with exit 16. Use 4.0.22 to show the frozen-install impact of `!` bugs (run 39).
- The `bundle` / `bundle_env` helpers in `e2e_redirect_gem_build.rs` strip `GEM_*`, so a Bundler installed into a scratch `GEM_HOME` is silently not used. `gem install bundler -v <v>` into the system gems, then set `BUNDLER_VERSION` + `SOCKET_PATCH_BUNDLER_E2E_VERSION` (run 39).
- `source "…", type: "rubygems" do` isn't a valid Bundler source (`type:` selects a plugin source; Bundler fails with "Could not find gem 'bundler-source-rubygems'"). Use a paren multi-line opener to test multi-line `source` shapes (run 40).
- The #1478 source-block scanner misses a regex after a predicate method with no parentheses (`x.match? /end/`) and a `%w[end]` argument with no parentheses. Both are contrived, so they're not filed (run 40).
- gemfile(5) lists `BUNDLE_LOCKFILE` env above the Gemfile `lockfile` DSL, but `Dsl#to_definition` lets the DSL win for `install` (4.0.23 changes only `bundle lock`, #9661). socket-patch follows the install order and refuses any DSL lock other than the default one, so the mismatch can't mislead an install (run 41).
- The vendored `gemfile_not_loaded` message for `lockfile false` reads "bundler reads the lockfile `lockfile false`". That's cosmetic (run 41).
- Wait loops like `while pgrep -f "cargo test …"` match their own shell and never exit. Wait on an output file instead (run 41 near-miss).
- `zz = 1; self.source "…" do` isn't seen as a source block by the #1531 fix, which deliberately excludes receiver calls (`x.source`). An explicit `self.` on a Gemfile DSL call is contrived, so it's not filed (run 42).
- `vex --json` needs `--output` (`json_requires_output`); grep the human output instead in probes (run 43).
- `e2e_gem.rs` needs the real public patch API (`patches-api.socket.dev`), which the sandbox blocks, so its 3 lifecycle tests fail with "tunnel error". That's a sandbox artifact. Run the Bundler suites with `cargo test --no-fail-fast`, or cargo stops at that first failing binary (run 45).
- Gemspec product: `Gem::Specification.new "name", "1.0" do |s|` constructor arguments aren't read, so the purl falls back to the file stem with no version. That's rare and only touches the VEX product id, so it's not filed (run 45, read-only).
- When the stale cached archive is a superseded hosted patch (not upstream), the `redirect_gem_stale_install` detail still calls it "UNPATCHED" / "vulnerable upstream bytes". It's cosmetic: the warning fires and the remedy is right (run 46).
- A superseded (gen-2) patched archive in `vendor/cache` after a superseding rescan is flagged by `upstream_gem_stale_cache` on unwind (it compares against upstream). Its scan-side wording ("UNPATCHED") is cosmetic (runs 46–47).
- A hosted grant rotation (new token, same uuid) in the no-CHECKSUMS window unwinds cleanly: `find_block` matches on the uuid, so only a uuid change hits #1626 (run 48).
- A hosted→vendored takeover in the #1626 unconverged-supersede window fails closed with `gemfile_declaration_not_editable` and writes nothing (run 48).
- Successful vendored gem fixtures in `e2e_redirect_gem_build.rs`: the `.gem` lives at `<stage>/<uuid>/<name>-src/<name>-<v>.gem` (not `<stage>/<uuid>/`), the stub is `gem spec <that .gem> --ruby`, and the grant needs a `tarball` with `sha512` SRI plus a `gem-stub-gemspec` artifact. Reset the fixture to `pristine_gemfile` / `pristine_lock` and delete `.socket` to start from an unpatched project (run 48).
- A Gemfile that gets the vulnerable gem only through a `gemspec` development dependency (no `gem` line) is refused with `redirect_gem_declaration_not_visible`, which names the gemspec case. That's a documented refusal (run 49).
- The #1646 user-patch consent gate has no gem evidence (CLI_CONTRACT.md's detection table lists no Bundler mechanism). That's documented scope (run 49).
- Bundler 2.5 / 2.6 never merge a gemspec dev dep into a later Gemfile `gem` line (they only merge dev + dev). 2.7 is the right boundary for `bundler_merges_dev_dependencies` (checked in the 2.5.23 / 2.6.9 / 2.7.0 `dsl.rb`, run 49).
- Manifestless `vex` in the redirect harness needs `--api-url`, `--org`, `--api-token` and `--patch-server-url <mock>`, or every Bundler version reads `manifest_not_found` (run 49).
- Plain `vendor` on a hosted gem whose lock isn't converged yet (Gemfile-only wiring, before the first unfrozen `bundle install`) finds no hosted pins and exits 0 with `noManifest`. That's documented: Gemfile-only pins aren't references (CLI_CONTRACT "Lockless pins") (run 50).
- After an eject (#1648), a later plain `vendor` with a `.socket/manifest.json` present falls back to manifest-driven vendoring, because no hosted pins are left. That's the documented legacy fallback (run 50).
- An eject's later `vendor --revert` returns the project to the upstream (unpatched) gem, not to hosted. That's documented in CLI_CONTRACT "Eject a hosted project (v5.0)" (run 51).
- Adding a `BUNDLE_GEMFILE` dual boot to a hosted project makes `vendor` (dry and wet) refuse `hosted_wiring_contested`, even when `Gemfile.next` evals `Gemfile`. It fails closed and matches the documented #390 dual-boot refusal (run 51).
- `vendor` eject on a `gems.rb`-only project (no `Gemfile`) is refused `gemfile_not_loaded`, as documented ("Gemfile spelling only"). The message still says "a gems.rb sits beside the Gemfile" when there's no Gemfile. That's a wording nit only (run 52).
- Pushed `bughunt/bundler/*` probe branches haven't triggered an Actions run since 2026-10-05, and `git push --delete` from the sandbox hangs up. Nine leftover branches up to `20261028-macos-gem-suites` need a maintainer to delete them.
- An eject on a CHECKSUMS lock can be driven with the mock upstream by spelling it `https://rubygems.org` in the pair, exporting `SOCKET_RUBYGEMS_URL=<mock>/upstream` for socket-patch and `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/=<mock>/upstream/` for Bundler. `mount_vendored_grant` supplies the vendored artifacts (run 53).
- A Bundler 2.1.4 merged multi-remote lock under a newer Bundler is Bundler's own upgrade behaviour (it splits sections on an unfrozen install), not socket-patch output, so it's not a cell (run 53).
