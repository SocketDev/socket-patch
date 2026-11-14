[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last run: 2026-11-14, main `7c5240e`, release 5.1.0, newest Bundler 4.0.24 stable and 4.1.0.beta3 prerelease (tested so far: 2.3.27, 2.4.19, 2.5.22/23, 2.6.9, 4.0.18; 4.0.24 not yet). Ruby 3.1.6, 3.2.6 and 3.3.6.

The ledger was reset on 2026-11-13. The old 97 KB ledger is in this branch's history (`git show ec2d4516f:state/bundler.md`); search it with `git grep`, don't copy it back.

Harness notes: the sandbox reaches rubygems.org but not the Socket patch API. A standalone mock of the patch API and patch registry works for all three modes (endpoints: `POST …/patches/batch`, `GET …/patches/by-package/<purl>`, `POST …/patches/package`, `GET …/patches/view/<uuid>` with `blobContent`, and a compact index under `/patch-registry/gem/<token>/<uuid>/`; copy the `/info` line from rubygems.org and swap the checksum). Build the patched gem by repacking the upstream `.gem` with its `metadata.gz` unchanged, and pass `--api-url <mock> --patch-server-url <mock>` to every command. For vendored mode the grant's `tarball` artifact needs `integrity.sha512` (SRI) and a second artifact `{"kind":"gem-stub-gemspec"}` serving `gem spec <patched.gem> --ruby`. Give test repos a `**/vendor/bundle/` ignore line. rbenv Rubies are in `/opt/ruby-3.1.6` (Bundler 2.3.27, 2.6.9), `/opt/ruby-3.2.6` (2.4.19, 4.0.18), `/opt/ruby-3.3.6` (2.5.22, 4.0.18).

## Coverage matrix

Linux only. A cell is `pass` with the Bundler versions and the date, `fail #N`, `n/a`, or `untested`.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan, patch, fresh `bundle install`, app loads patched code, `vex`, rollback, `bundle install` again | pass 2.6.9, 4.0.18 (11-13) | pass 4.0.18 (11-14); `vex` warning fail #2076 | pass 2.3.27, 2.4.19, 2.5.23, 2.6.9, 4.0.18 (11-14) |
| System or user gem home (no `BUNDLE_PATH`) | pass 4.0.18 (11-13) | fail #2075 (2.6.9, 4.0.18) | pass 4.0.18, warning and its remedy (11-13); `--gem-refresh-shared` untested |
| `bundle config set path vendor/bundle` | pass 2.6.9 (11-13) | pass 4.0.18 (11-14) | pass 2.3.27 to 4.0.18 (11-14) |
| Deployment and frozen installs (`BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, `.bundle/config`) | pass frozen 2.6.9, 4.0.18 (11-13) | pass frozen and deployment clone, with `BUNDLE_WITHOUT` too, 4.0.18 (11-14) | pass frozen on all, deployment clone 2.5.22, 2.6.9, 4.0.18 (11-14) |
| Multi-platform lock, platform gem (`-x86_64-linux`) | untested | untested | pass 4.0.18: nokogiri refused, rest installs (11-14) |
| Gem with a native extension (rebuild after patching, rollback restores the build) | pass 2.6.9 (11-13); `scan --no-gem-native-rebuild` fail #2069 | untested | pass 4.0.18 (11-13) |
| Patched gem that is only a transitive dependency | pass 2.6.9, 4.0.18 (11-13) | untested | pass 2.5.23, 2.6.9, 4.0.18 (11-13) |
| Git and path sources next to a patched gem | untested | untested | pass 4.0.18, incl. a gem transitive through a path gem (11-14) |
| `bundle update` / `bundle add` / `bundle remove` / `bundle outdated` after patching | untested | `outdated` pass 4.0.18 (11-14); rest untested | add / remove pass 2.6.9 (11-13); `lock --add-platform`, `update <other gem>`, `clean`, `doctor`, `binstubs` pass 4.0.18 (11-14); outdated / update fail #2070 |
| Rollback and remove restore `Gemfile` and `Gemfile.lock` byte for byte | pass (pair never touched) (11-13) | rollback pass 4.0.18 (11-14); `vendor --revert`, `remove` untested | rollback and `remove` pass on all, CRLF and `vendor/cache` archives too (11-14) |
| `vex` reports only what is really applied | pass 2.6.9, 4.0.18, after `bundle pristine` too (11-13) | attests correctly 4.0.18; false `vendored_tree_out_of_sync` fail #2076 | pass 2.6.9, 4.0.18 (11-14); stale shared-home copy untested |
| `gems.rb` / `gems.locked` spelling | untested | refused as documented (`gemfile_not_loaded`), not re-run | pass 4.0.18 (11-14) |
| Lock with a CHECKSUMS section (Bundler 2.6+) | n/a | untested | pass 4.0.18 (11-13) |
| Monorepo: several Gemfiles, nested projects, scan from the repo root | untested (agent scans one project by design) | untested | pass 4.0.18: scan, `list`, rollback from the root (11-14) |
| `setup` and the Bundler plugin it installs | n/a: `setup` and the plugin were removed in v5 (CLI_CONTRACT "…no longer published"); only `gem_bundler_plugin_stale` detection is left, untested | n/a | n/a |
| Re-runs (idempotency) and `--json` output | untested | re-scan pass 2.6.9 (apart from #2075) | pass 4.0.18 (11-14) |
| Bundler 4.1 prerelease (`OVERRIDES`, `CONTENT ADDRESSES` lock sections) | untested | untested | untested |
| Bundler 1.x refused where the docs say so | untested | untested | untested |

## Backlog

1. Agent mode beyond the common path: next to git and path sources, `bundle update` / `add` / `remove` / `clean` after `apply`, a multi-platform lock with a precompiled gem (refused?), `gems.rb`, re-runs and `--json`, Bundler 2.4 and 2.5.
2. Vendored mode, the rest: `vendor --revert` and `remove` byte-exact, `bundle update` / `add` after vendoring, native gems refused with `native_extensions_unsupported`, hosted to vendored takeover and back, a transitive-only gem (managed block), CRLF, Bundler 2.5 and 2.6 locks without CHECKSUMS, git and path sources beside it.
3. Hosted `--gem-refresh-shared`, and `vex` with a stale copy in a shared gem home.
4. Agent native extensions, the rest of what the docs promise: build failure puts sources and build back (`native_extension_build_failed`), `apply --dry-run` starts no Ruby, a relative crawl root (#2048), an interrupted rebuild, a precompiled platform gem refused.
5. Other flags the nested apply of `scan --mode agent` may drop (same cause as #2069: `nested_apply_args_from_params` fills `GlobalArgs` from defaults).
6. Bundler 4.0.24 and the 4.1 prerelease (`OVERRIDES`, `CONTENT ADDRESSES`), hosted and vendored. Ruby 3.4 is not in the sandbox.
7. Friction pass as a first-time user following only the CLI's messages and `docs/usage.md`. Known candidates: `redirect_gem_no_checksums_section` says "bundler < 2.6 does not write one" on a 2.6.9 lock (its remedy works); vendored mode refuses every gem inside a `group do` block, which is most Rails Gemfiles (by design, #340: is the message's remedy clear?); `remove <gem>` from a monorepo root doesn't name the sub-projects that pin it.
8. Deployment mode and `.bundle/config` shapes around the stale-install guard. #1109 is open and waiting on a maintainer decision; don't re-file it.
9. Re-check #2069, #2070, #2075 and #2076 once fixed.

## Known non-bugs

The full list is in `known-non-bugs/bundler.md` on this branch. Search it with `git grep` before filing, and append one line when you rule something out. Don't read it whole. Most likely to be re-filed:

- "the patched gem's gemspec differs from the installed one" after a hosted scan: a mock gem rebuilt with `gem build` has a different gemspec. Repack with the original `metadata.gz`.
- `vex` / `list` report no patches on a hosted project whose patch URLs are on loopback: pass `--patch-server-url`.
- `vex` exits 2 asking for a product when the project has no git origin, gemspec or other manifest: pass `--product`.
- Hosted scan leaves gems in a shared gem home unpatched and warns: documented ("Ruby gems: gems already installed").
