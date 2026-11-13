[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last run: none since the reset below.

**Reset on 2026-11-13 by the maintainer.** Runs 1 to 66 (2026-09-30 to 2026-11-02) tested main up to `cbbbdb9` (v5.0.1). Main has since gained v5.1.0 and about 135 commits, including native-extension rebuilds for gems (#1998, #2048), the Bundler hosted-mode fixes from the 5.1.0 review (#2052), nested `source` block attribution (#1999), the Bundler 4.1 override restore (#1991) and CRLF Gemfile handling (#1841). Treat every cell as untested on the current main. The old 97 KB ledger is in this branch's history (`git show ec2d4516f:state/bundler.md`); search it with `git grep` when you want to know whether a shape was covered before, and don't copy it back here.

## Coverage matrix

Linux only. One row per workflow, one column per mode. A cell is `pass` with the Bundler versions and the date, `fail #N`, `n/a`, or `untested`.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan, patch, fresh `bundle install`, app loads patched code, `vex`, rollback, `bundle install` again | untested | untested | untested |
| System or user gem home (no `BUNDLE_PATH`) | untested | untested | untested |
| `bundle config set path vendor/bundle` | untested | untested | untested |
| Deployment and frozen installs (`BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, `.bundle/config`) | untested | untested | untested |
| Multi-platform lock, platform gem (`-x86_64-linux`) | untested | untested | untested |
| Gem with a native extension (rebuild after patching, rollback restores the build) | untested | untested | untested |
| Patched gem that is only a transitive dependency | untested | untested | untested |
| Git and path sources next to a patched gem | untested | untested | untested |
| `bundle update` / `bundle add` / `bundle remove` / `bundle outdated` after patching | untested | untested | untested |
| Rollback and remove restore `Gemfile` and `Gemfile.lock` byte for byte | untested | untested | untested |
| `vex` reports only what is really applied | untested | untested | untested |
| `gems.rb` / `gems.locked` spelling | untested | untested | untested |
| Lock with a CHECKSUMS section (Bundler 2.6+) | untested | untested | untested |
| Monorepo: several Gemfiles, nested projects, scan from the repo root | untested | untested | untested |
| `setup` and the Bundler plugin it installs | untested | untested | untested |
| Re-runs (idempotency) and `--json` output | untested | untested | untested |
| Bundler 4.1 prerelease (`OVERRIDES`, `CONTENT ADDRESSES` lock sections) | untested | untested | untested |
| Bundler 1.x refused where the docs say so | untested | untested | untested |

## Backlog

1. The common path in all three modes on Bundler 2.5, 2.6 and 4.0 (the first matrix row), on a project that looks like a real Rails app rather than a one-gem fixture. Use a real patched gem from the public catalog if the sandbox can reach the API (`activestorage` 6.0.3 has a free patch); otherwise use the repo's fixtures and mock registry (`e2e_redirect_gem_build`, `e2e_vendor_gem_build`).
2. Native extensions in agent mode (#1998, #2048). Read "Ruby gems: native extensions" in `docs/ecosystems.md` and test what it promises: the rebuild uses the Ruby that owns the gem home, `--no-gem-native-rebuild` opts out, `vex` and `apply --check` report `native_extension_not_rebuilt` until the rebuild is recorded, rollback restores the original build, and a relative crawl root works.
3. Hosted mode after #2052. Read "Ruby gems: hosted mode" and "Ruby gems: gems already installed" and test what they promise: frozen installs on Bundler older than 2.6, how the `Gemfile` is edited and restored, and which installed gems are refreshed (`--gem-refresh-shared`).
4. Keeping up to date after a hosted patch: do `bundle outdated` and `bundle update <gem>` still show and reach newer upstream versions of a hosted-patched gem? Search the issues first; file it if it reproduces and nothing covers it.
5. Vendored mode: does `vex` warn on a correctly vendored project? Does `vendor --revert` give back the original pair?
6. Deployment mode and `.bundle/config` shapes around the stale-install guard. #1109 is open and waiting on a maintainer decision; don't re-file it, and note anything new on it.
7. Bundler 4.1 prerelease: more `OVERRIDES` shapes (`version:`, `:ignore_upper`, `with: nil`) and the `CONTENT ADDRESSES` section, in hosted and vendored mode.
8. Monorepos and nested Gemfiles, scanning from the repository root and from a subdirectory (#2025 limits reads and writes to the git root).
9. Friction pass: run the common path as a first-time user would, following only the CLI's own messages and `docs/usage.md`. File misleading messages and remedies that don't work, with the `ux` label added.

## Known non-bugs

Documented limitations and verified false positives from runs 1 to 66 (about 150 entries) are in `known-non-bugs/bundler.md` on this branch. Search it with `git grep` before filing, and append one line when you rule something out. Don't read it whole.
