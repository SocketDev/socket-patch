[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last updated: 2026-10-09 (run 36), main `a80b89e`, latest release v4.0.0 (npm; no git tags). Newest Bundler tested: 4.1.0.beta2; newest stable 4.0.22.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (the sandbox blocks the real one) around real `gem build` fixtures, followed by a real `bundle install` on a fresh checkout. The repo's own e2e suites (`e2e_redirect_gem_build.rs`, `e2e_vendor_gem_build.rs`, `e2e_redirect_gem_stale_install.rs`) already cover the plain single-line Gemfile cells across 1.17 → 4.x. This ledger tracks what they don't. `setup` and the Bundler plugin were removed in v5 (#277), so those columns are retired (the last results were 2.2–2.4 fail #389 → closed, and 2.5 / 4.x pass).

### Project modes

| OS | Ruby | Bundler | Hosted: single-line decl | Hosted: multi-line decl / `if` modifier | Hosted: decl in `group` block | Hosted: platform gem, no CHECKSUMS | Hosted: CHECKSUMS lock | Hosted: stale-install guard | Hosted: `BUNDLE_GEMFILE` in `.bundle/config` | Vendored: `Gemfile` only | Vendored: `gems.rb` + `Gemfile` twin | Vendored: `BUNDLE_GEMFILE` | Vendored: `gems.rb` only | Agent: multi-home `vex` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.3.6 | 1.17.x | blocked (1.17 needs Ruby ≤ 3.1) | untested | untested | untested | n/a | untested | untested | untested | untested | untested | untested | untested |
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
| Linux | 3.3.6 | 2.6.9 | untested | fixed #457 (#460) | untested | untested | untested | untested | documented (Gemfile-only pin is out of reach) |
| macOS / Windows | any | any | untested | untested (OS-independent) | untested | untested | untested | untested | untested |

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
| `bundle cache` after scan → `rollback` / `remove` | fail #1260 | fail #1260 | fail #1260 | fail #1260 |

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

1. Vendored with a committed `vendor/cache` (`bundle cache --all` and the `.socket/vendor` path gem; `vendor --revert` with a stale cache).
2. H→V takeover with the hosted patched archive in `vendor/cache` (#1260 neighbour).
3. #749 DSL gap: vendored DSL `lockfile`, and `lockfile false`.
4. #1092 neighbours: Windows `x64-mingw-ucrt` + `x64-mingw32` pairs (probe branch). #1056 neighbours: CRLF Gemfile and `gems.rb`.
5. Re-run #896 / #952 / #985 / #1056 / #1092 / #1109 / #1125 / #1260 when fixes merge.

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
- The in-place hosted rewrite of a CRLF manifest writes the `source … do` block with LF endings (mixed endings). Bundler, frozen installs and `rollback` accept it, so it's cosmetic.
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
