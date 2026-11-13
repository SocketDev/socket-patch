[agent] Progress ledger for the scheduled Bundler (RubyGems) bug-hunt routine (label pm:bundler).

Last run: 2026-11-13, main `7c5240e`, release 5.1.0, newest Bundler 4.0.24 stable and 4.1.0.beta3 prerelease (tested: 2.5.23, 2.6.9, 4.0.18; 4.0.24 not yet). Ruby 3.3.6 only so far.

The ledger was reset on 2026-11-13. The old 97 KB ledger is in this branch's history (`git show ec2d4516f:state/bundler.md`); search it with `git grep`, don't copy it back.

Harness notes: the sandbox reaches rubygems.org but not the Socket patch API. A standalone mock of the patch API and patch registry works (endpoints: `POST …/patches/batch`, `GET …/patches/by-package/<purl>`, `POST …/patches/package`, `GET …/patches/view/<uuid>`, and a compact index under `/patch-registry/gem/<token>/<uuid>/`). Build the patched gem by repacking the upstream `.gem` with its `metadata.gz` unchanged, and pass `--patch-server-url <mock>` to every command. Vendored mode needs the service archive format, which only the Rust harness builds (`e2e_vendor_gem_build`, `prebuilt_common::mount_view_from_source`).

## Coverage matrix

Linux only. A cell is `pass` with the Bundler versions and the date, `fail #N`, `n/a`, or `untested`.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan, patch, fresh `bundle install`, app loads patched code, `vex`, rollback, `bundle install` again | pass 2.6.9, 4.0.18 (11-13) | untested | pass 2.5.23, 2.6.9, 4.0.18 (11-13) |
| System or user gem home (no `BUNDLE_PATH`) | pass 4.0.18 (11-13) | untested | pass 4.0.18, warning and its remedy (11-13); `--gem-refresh-shared` untested |
| `bundle config set path vendor/bundle` | pass 2.6.9 (11-13) | untested | pass 2.5.23, 2.6.9, 4.0.18 (11-13) |
| Deployment and frozen installs (`BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, `.bundle/config`) | pass frozen 2.6.9, 4.0.18 (11-13) | untested | pass frozen on all three, deployment clone 2.6.9 (11-13) |
| Multi-platform lock, platform gem (`-x86_64-linux`) | untested | untested | untested |
| Gem with a native extension (rebuild after patching, rollback restores the build) | pass 2.6.9 (11-13); `scan --no-gem-native-rebuild` fail #2069 | untested | pass 4.0.18 (11-13) |
| Patched gem that is only a transitive dependency | pass 2.6.9, 4.0.18 (11-13) | untested | pass 2.5.23, 2.6.9, 4.0.18 (11-13) |
| Git and path sources next to a patched gem | untested | untested | untested |
| `bundle update` / `bundle add` / `bundle remove` / `bundle outdated` after patching | untested | untested | add / remove pass 2.6.9 (11-13); outdated / update fail #2070 |
| Rollback and remove restore `Gemfile` and `Gemfile.lock` byte for byte | pass (pair never touched) (11-13) | untested | rollback pass on all three (11-13); `remove` untested |
| `vex` reports only what is really applied | pass 2.6.9, 4.0.18, after `bundle pristine` too (11-13) | untested | pass 2.6.9, 4.0.18 (11-13); stale shared-home copy untested |
| `gems.rb` / `gems.locked` spelling | untested | untested | untested |
| Lock with a CHECKSUMS section (Bundler 2.6+) | n/a | untested | pass 4.0.18 (11-13) |
| Monorepo: several Gemfiles, nested projects, scan from the repo root | untested | untested | untested |
| `setup` and the Bundler plugin it installs | untested (the 5.1.0 CLI lists no `setup` command; check the docs) | untested | untested |
| Re-runs (idempotency) and `--json` output | untested | untested | untested |
| Bundler 4.1 prerelease (`OVERRIDES`, `CONTENT ADDRESSES` lock sections) | untested | untested | untested |
| Bundler 1.x refused where the docs say so | untested | untested | untested |

## Backlog

1. Vendored mode common path on 2.5, 2.6 and 4.0 through the Rust harness (`cargo test -p socket-patch-cli --test e2e_vendor_gem_build -- --ignored`, plus scratch tests): `vex` on a correctly vendored project, `vendor --revert` gives back the original pair, native gems refused with `native_extensions_unsupported`.
2. Hosted: platform gems and multi-platform locks (nokogiri with `x86_64-linux`: `redirect_gem_platform_unsupported`, and does the rest of the project still install), `--gem-refresh-shared`, `vendor/cache` from `bundle cache`, `remove` byte-exact, re-scan idempotency and `--json`.
3. Hosted and agent next to git and path sources, `gems.rb`, and a monorepo with several Gemfiles scanned from the root and from a subdirectory (#2025).
4. Agent native extensions, the rest of what the docs promise: build failure puts sources and build back (`native_extension_build_failed`), `apply --dry-run` starts no Ruby, a relative crawl root (#2048), an interrupted rebuild, a precompiled platform gem refused.
5. Other flags the nested apply of `scan --mode agent` may drop (same cause as #2069: `nested_apply_args_from_params` fills `GlobalArgs` from defaults). Compare `scan --mode agent` with `apply` for each `GlobalArgs` flag that apply reads.
6. Deployment mode and `.bundle/config` shapes around the stale-install guard. #1109 is open and waiting on a maintainer decision; don't re-file it, note anything new on it.
7. Bundler 4.1 prerelease: `OVERRIDES` shapes and `CONTENT ADDRESSES`, hosted and vendored. Ruby 3.2 and 3.4 legs (rbenv has 3.1.6, 3.2.6, 3.3.6 in `/opt`).
8. Friction pass as a first-time user following only the CLI's messages and `docs/usage.md`. Known candidate: `redirect_gem_no_checksums_section` says "bundler < 2.6 does not write one" on a 2.6.9 lock; check whether its remedy (`bundle lock --add-checksums`, re-scan) works when followed.
9. Re-check #2069 and #2070 once fixed.

## Known non-bugs

The full list is in `known-non-bugs/bundler.md` on this branch. Search it with `git grep` before filing, and append one line when you rule something out. Don't read it whole. Most likely to be re-filed:

- "the patched gem's gemspec differs from the installed one" after a hosted scan: a mock gem rebuilt with `gem build` has a different gemspec. Repack with the original `metadata.gz`.
- `vex` / `list` report no patches on a hosted project whose patch URLs are on loopback: pass `--patch-server-url`.
- `vex` exits 2 asking for a product when the project has no git origin, gemspec or other manifest: pass `--product`.
- Hosted scan leaves gems in a shared gem home unpatched and warns: documented ("Ruby gems: gems already installed").
