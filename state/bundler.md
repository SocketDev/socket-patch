[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last run: 2026-11-15, main `63f791d`, release 5.1.0, newest Bundler 4.0.24 stable and 4.1.0.beta3 prerelease (tested so far: 2.3.27, 2.4.19, 2.5.22/23, 2.6.9, 4.0.18, 4.0.24, 4.1.0.beta3). Ruby 3.1.6, 3.2.6 and 3.3.6.

The ledger was reset on 2026-11-13. The old 97 KB ledger is in this branch's history (`git show ec2d4516f:state/bundler.md`); search it with `git grep`, don't copy it back.

Harness notes: the sandbox reaches rubygems.org but not the Socket patch API. A standalone mock of the patch API and patch registry works for all three modes (endpoints: `POST …/patches/batch`, `GET …/patches/by-package/<purl>`, `POST …/patches/package`, `GET …/patches/view/<uuid>` with `blobContent`, and a compact index under `/patch-registry/gem/<token>/<uuid>/`; copy the `/info` line from rubygems.org and swap the checksum). Build the patched gem by repacking the upstream `.gem` with its `metadata.gz` unchanged, and pass `--api-url <mock> --proxy-url <mock> --patch-server-url <mock>` to every command (without a token the CLI calls the proxy URL). For vendored mode the grant's `tarball` artifact needs `integrity.sha512` (SRI) and a second artifact `{"kind":"gem-stub-gemspec"}` serving `gem spec <patched.gem> --ruby`. Give test repos a `**/vendor/bundle/` ignore line. `--api-token fake --org test` works in place of the proxy route. For a gem with precompiled builds, `nokogiri 1.16.0` compiles from source in under a minute here. rbenv Rubies are in `/opt/ruby-3.1.6` (Bundler 2.3.27, 2.6.9), `/opt/ruby-3.2.6` (2.4.19, 4.0.18), `/opt/ruby-3.3.6` (2.5.22, 4.0.18); `gem install bundler -v 4.0.24` / `4.1.0.beta3` works there.

## Coverage matrix

Linux only. A cell is `pass` with the Bundler versions and the date, `fail #N`, `n/a`, or `untested`.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan, patch, fresh `bundle install`, app loads patched code, `vex`, rollback, `bundle install` again | pass 2.5.22, 2.6.9, 4.0.18 (11-15) | pass 2.5.22, 2.6.9, 4.0.18, 4.1.0.beta3, CRLF pair too (11-15); `vex` warning fail #2076 | pass 2.3.27 to 4.0.24, 4.1.0.beta3 (11-14) |
| System or user gem home (no `BUNDLE_PATH`) | pass 4.0.18, 2.5.22 with `GEM_HOME` (11-15) | fail #2075 (2.6.9, 4.0.18) | pass 4.0.18: warning, `scan` and `rollback` with `--gem-refresh-shared` (11-15); the remedy after a plain rollback / remove fail #2086 |
| `bundle config set path vendor/bundle` | pass 2.6.9 (11-13) | pass 4.0.18 (11-14) | pass 2.3.27 to 4.0.18 (11-14) |
| Deployment and frozen installs (`BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, `.bundle/config`) | pass frozen 2.6.9, 4.0.18 (11-13) | pass frozen and deployment clone, with `BUNDLE_WITHOUT` too, 4.0.18 (11-14) | pass frozen on all, deployment clone 2.5.22, 2.6.9, 4.0.18 (11-14) |
| Multi-platform lock, platform gem (`-x86_64-linux`) | pass 4.0.18: Ruby-file patch applied, C patch refused as documented (11-15) | pass 4.0.18: 7-platform lock, precompiled gem beside vendored ones (11-15) | pass 4.0.18: nokogiri refused, rest installs (11-14); moved to the `ruby` platform it installs patched, standalone `vex` fail #2087 |
| Gem with a native extension (rebuild after patching, rollback restores the build) | pass 2.5.22, 2.6.9, 4.0.18, build failure restored too (11-15); `scan --no-gem-native-rebuild` fail #2069 | refused as documented, exit 1, other gems vendored, 4.0.24 (11-14) | pass 4.0.18, 4.0.24 (11-14) |
| Patched gem that is only a transitive dependency | pass 2.6.9, 4.0.18 (11-14) | installs and reverts 4.0.18; `Bundler.require` loads it fail #2084 | pass 2.5.23 to 4.0.24 (11-14) |
| Git and path sources next to a patched gem | pass 4.0.18 (11-14) | pass 4.0.24, 4.1.0.beta3 (11-14) | pass 4.0.18, 4.0.24, incl. a gem transitive through a path gem (11-14) |
| `bundle update` / `bundle add` / `bundle remove` / `bundle outdated` after patching | pass 4.0.18: add, remove, clean, outdated, `--redownload` then `apply` (11-14) | pass 4.0.18: add, remove, update, outdated, `lock --add-platform`, `cache` (11-14) | add / remove pass 2.6.9 (11-13); `lock --add-platform`, `update <other gem>`, `clean`, `doctor`, `binstubs` pass 4.0.18 (11-14); outdated / update fail #2070 |
| Rollback and remove restore `Gemfile` and `Gemfile.lock` byte for byte | pass (pair never touched) (11-14) | rollback, `remove`, `vendor --revert` pass 4.0.18 (11-14) | rollback and `remove` pass on all, CRLF and `vendor/cache` archives too (11-14) |
| `vex` reports only what is really applied | pass 2.6.9, 4.0.18, after `bundle pristine` too (11-13) | attests correctly 4.0.18; false `vendored_tree_out_of_sync` fail #2076 | pass 2.6.9, 4.0.18, stale shared-home copy omitted (11-15); orphan platform dir fail #2087 |
| `gems.rb` / `gems.locked` spelling | pass 2.5.22 (11-15) | refused as documented (`gemfile_not_loaded`), not re-run | pass 4.0.18 (11-14) |
| Lock with a CHECKSUMS section (Bundler 2.6+) | n/a | pass 4.0.18; without the section 2.5.22, 2.6.9 (11-15) | pass 4.0.18 (11-13) |
| Monorepo: several Gemfiles, nested projects, scan from the repo root | untested (agent scans one project by design) | untested | pass 4.0.18: scan, `list`, rollback from the root (11-14) |
| `setup` and the Bundler plugin it installs | n/a: `setup` and the plugin were removed in v5 (CLI_CONTRACT "…no longer published"); only `gem_bundler_plugin_stale` detection is left, untested | n/a | n/a |
| Re-runs (idempotency) and `--json` output | pass 4.0.18 (11-14) | re-scan pass 2.6.9, 4.0.18 (apart from #2075) | pass 4.0.18 (11-14) |
| Switching modes on one project | untested | hosted to vendored: pair and mixed state pass 4.0.24; rollback afterwards leaves patched installs, fail #2083 | vendored to hosted refused by design (not re-run) |
| Bundler 4.1 prerelease | untested | pass 4.1.0.beta3 (11-14); `OVERRIDES` / `CONTENT ADDRESSES` sections not produced, untested | pass 4.1.0.beta3 (11-14); same sections untested |
| Bundler 1.x refused where the docs say so | untested | untested | untested |

## Backlog

1. Friction pass as a first-time user following only the CLI's messages and `docs/usage.md`. Known candidates: `redirect_gem_no_checksums_section` says "bundler < 2.6 does not write one" on a 2.6.9 lock (its remedy works); vendored mode refuses every gem inside a `group do` block, which is most Rails Gemfiles (by design, #340: is the message's remedy clear?); `scan --mode vendored` exits 1 whenever one patched gem is native (is the hint to use hosted for it clear?); `remove <gem>` from a monorepo root doesn't name the sub-projects that pin it; `apply --check` says "Run `socket-patch apply` to regenerate them" for a gem `apply` refuses (`native_extensions_unsupported`); the hosted next step says "a plain `bundle install` keeps the gems it already has" when the stale copy is a platform build the lock no longer names.
2. A realistic Rails-sized project (a Rails 7 or 8 Gemfile with groups, bootsnap, a `Bundler.require` boot) through hosted mode end to end, on Bundler 2.5, 2.6 and 4.0.
3. Vendored mode, the rest: `remove` / `vendor --revert` after a hosted to vendored takeover (#2083 covers `rollback` only), `scan --prune`.
4. Agent mode, the rest: Bundler 2.4, the system gem home under `/opt/ruby-*` itself, switching agent to hosted and back, `apply --dry-run` starts no Ruby, a relative crawl root (#2048), an interrupted rebuild, a monorepo.
5. Other flags the nested apply of `scan --mode agent` may drop (same cause as #2069: `nested_apply_args_from_params` fills `GlobalArgs` from defaults).
6. Hosted shared gem home, the rest: `--gem-refresh-shared` with two projects pinning the same gem version (the documented cost), `remove` of one gem out of several, `SOCKET_GEM_REFRESH_SHARED=1`.
7. Bundler 4.1 lock sections `OVERRIDES` and `CONTENT ADDRESSES`: find which Gemfile or setting makes 4.1.0.beta3 write them, then hosted and vendored. Ruby 3.4 is not in the sandbox.
8. Deployment mode and `.bundle/config` shapes around the stale-install guard. #1109 is open and waiting on a maintainer decision; don't re-file it.
9. Bundler 1.x refused where the docs say so (needs a Ruby that still runs Bundler 1.17; none in the sandbox).
10. Re-check #2069, #2070, #2075, #2076, #2083, #2084, #2086 and #2087 once fixed.

## Known non-bugs

The full list is in `known-non-bugs/bundler.md` on this branch. Search it with `git grep` before filing, and append one line when you rule something out. Don't read it whole. Most likely to be re-filed:

- "the patched gem's gemspec differs from the installed one" after a hosted scan: a mock gem rebuilt with `gem build` has a different gemspec. Repack with the original `metadata.gz`.
- `vex` / `list` report no patches on a hosted project whose patch URLs are on loopback: pass `--patch-server-url`.
- `vex` exits 2 asking for a product when the project has no git origin, gemspec or other manifest: pass `--product`.
- Hosted scan leaves gems in a shared gem home unpatched and warns: documented ("Ruby gems: gems already installed").
