### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-09T09:15Z · main @ f6a9fea_

**In flight:**
- [#1253](https://github.com/SocketDev/socket-patch/pull/1253): agent-mode `jvm_jar::verify_member_bytes` streams members through `hash::git_sha256::zip_member_git_sha256` (302 → 30 MiB peak on a 256 MiB member). #914 slice (C51); `vendor/common.rs` caller waits for #1227. +17/−11 prod, +85 tests. `state: ready`.
- [#1245](https://github.com/SocketDev/socket-patch/pull/1245): `vendor::revert::finish` + `KeepPolicy` (`OnDrift`, `OnDriftWhileReferenced`, `NpmFamily`); gem, composer, Maven legacy, NuGet and pnpm finish through it. #989 item 1 slice (E24). +133/−157 prod (helper 90), +271 tests. `state: ready`.
- [#1239](https://github.com/SocketDev/socket-patch/pull/1239): NuGet crawler `find_by_purls` looks up the global folder and legacy `<Id>.<Version>/` folders by the normalized version (`1.0.0.0` = `1.0.0`) through `normalize_nuget_version`. #1202 crawler slice (E93). +47/−19 prod, +116/−4 tests. `state: ready`.
- [#1227](https://github.com/SocketDev/socket-patch/pull/1227): `common::detect_eol`, `pypi_uv::newline_of` and the `.npmrc` splice through `line_endings::terminator`. #815 slice 2 (E16). +25/−44 prod, +93 tests; golang golden re-blessed (mixed go.sum inputs only). `state: ready`.
- [#1188](https://github.com/SocketDev/socket-patch/pull/1188): one `Pipfile.lock` writer (`formats::pipenv::splice_entry`, `formats::json`). Issue #1128 (E14). +303/−235 production. `redirect/mod.rs` wrapper `pipenv_reserialized_around_reference` left for when that file is free. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- Maintainer drafts (decided issues): #1049 (#792). #1036 (#973), #1041 (#648), #1027, #1030, #1031 and #1051 merged.

**Merged:** #1221 (E19 hosted gem sections, +213/−140 prod), #1230 (E93 `PurlKey`, +37/−7 prod), #1217 (E05 Deno crawl, +108/−43 prod), #1209 (E05 Go crawl, +132/−44 prod), #1205 (E05 cargo crawl), #1183 (E05 NuGet crawl); earlier #1191, #1185, #1103, #1108, #1163, #1160, #1153, #1151, #1145, #1141, #1106, #1110, #1117, #1121, #1124, #1021, #1015, #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`). Leftovers: `blob_hash_matches` (#1163), dead `eco == "maven2"` arm in `commands/vendor.rs` (#1015).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item 1: one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | **taken: #1245**; bun ×2 (#1009), npm (#1161, #1187), vlt (#1161), pypi (#1026), yarn classic (#1242) and berry remain |
| 2 | #931 + #998 + #1063 + #1123: one manifest load + error mapper for every command | 4 | 1 | ≈6 | M | ≈24 | skipped: `apply.rs`, `vendor.rs`, `rollback.rs` (#1009, #1049), `remove.rs` (#1034, #1049), `repair.rs` (#1049) |
| 3 | #717 (E10): hosted pom edits + restore through `formats::maven` | 3 | 1 | ≈4 | M | ≈17 | skipped: `redirect/mod.rs` (#1009, #1026, #1180, #1242) |
| 4 | #1220 (C78): bound upstream-restore fan-out through `utils::concurrent::registry_concurrency` | 1 | 0 | ≈4 | L | ≈11 | skipped: `upstream/mod.rs` (#1009, #1211), `concurrent.rs` (#1026) |
| 5 | #914 (C51): agent-mode jar members through the streaming zip hasher | 0 | 0 | ≈1 | L | ≈7 | **taken: #1253** (`jvm_jar.rs`); `vendor/common.rs` caller after #1227 |

Re-ranked 2026-10-09T09:00Z at `f6a9fea` against 29 open PRs changing 392 files (#1221 merged; #780 vendored slice waits on `vendor/gem.rs`, #1245/#1026; claim released). #1098 (E90) still needs `ecosystem_dispatch.rs`/`vex_consumed.rs` (#1009, #1026, #1034). #1202 `formats::nuget` move is free now (D 1). Free but lower: #1014 (`.mill-version` needs a decision), #265 Maven crawl (risk H), E37 (composer `normalize_version` ≡ `strip_leading_v`, D 1).

**Notes:**
- Revert finish (#1245): new backends end their revert with `revert::finish(outcome, root, rel, opts, KeepPolicy::…)`; the npm family keeps its bare `cannot remove <rel>` failure (warnings dropped), the rest keep warnings with `failed to remove <abs>`. Yarn berry/classic and npm add a still-wired refusal before the delete: extend the policy, do not re-copy the sequence.
- `bench.yml` gates +10% per scenario: time a per-dep reader (hosted converge) in release against `main` before pushing.
- Gem lock edits locate through `formats::gem::parse` since #1221: `Section::lines()` / `end`, `remote_line_nos`, `GemfileLock::dependencies` (entries with one name rule). Whitespace-only lines are blank separators. The vendored slice should read the same fields, not add a fourth walker.
- Real bundler 4.0.18 is in the sandbox: `e2e_redirect_gem_build -- --ignored`, `e2e_vendor_gem_build -- --include-ignored` run in ~30 s.
- `golang_rewrite.golden`'s go.sum generator injects a stray CRLF line, so its inputs are mixed even with the `line_endings` mixer off; any terminator-rule change re-blesses it.
- Deno crawl scope (#1217): only a parseable `<cwd>/deno.lock` with a `version` scopes; no `jsr` section = no JSR package. Fixtures must lock a cached JSR package (or omit `deno.lock`).
- Go crawl scope (#1209): only a readable `<cwd>/go.sum` with no workspace (`go.work`, or `GOWORK` set to a file) scopes. A CLI fixture that needs the crawl to vouch for a cached module must list it in `go.sum` or drop `go.sum`.
- Cargo crawl scope (#1205): only a registry cache with a parseable `<cwd>/Cargo.lock` is scoped. "Only the crawl vouches" tests put the crate in `vendor/`. Narrowing a crawl changes `scan --prune`: say so in the PR.
- `Pipfile.lock` edits go through `formats::pipenv::splice_entry` since #1188: sort the value (`sort_all_objects`) before splicing; never re-serialize the whole lock.
- NuGet crawl scope (#1183): only a `cwd` with a project file is scoped; a solution root keeps the walk (restores at any depth). Extend through `PackageRoots::scope`, not a second assets reader.
- Poetry 2.x `files` is written one file per line by the shared engine since #1185; a test or golden that greps `files = [{ file` only sees 1.0/1.1 package-level `files` now.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names `arch-refactor/*` and `agent/fix-*` PRs only; still check `arch-fix/*` and `ci*` hunks before touching the same lines.
- Test-helper migrations (#824): directory binaries import via `crate::common`. `spawn_env_hygiene` scans test text, literals included: never spell a bare binary spawn in a new test file; run it before pushing.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- 2026-10-08: ~40 refactor issues were closed `not_planned` into trackers ("Consolidated work"); that is scheduling, not rejection. Claim/`Fixes` the item's issue only if still open, else reference the tracker.
- NuGet identity (#1230): `PurlKey` folds versions through `vendor::nuget_feed::normalize_nuget_version` (a utils→vendor import until `nuget_feed.rs` frees for the `formats::nuget` move). `test_support::service_fixture` builds its NuGet grant from `<id>.<purl version>.nupkg`, so a test vendoring a non-normalized version needs that file too.
- NuGet crawl identity (#1239): `find_by_purls` runs main's probes first (`<id>/<as-written>`, exact legacy, case-insensitive legacy) and the normalized ones only after (`<id>/<normalized>`, `legacy_dir_is`), so a cache with two spellings keeps main's pick. The `oracle.rs` equivalence keeps main's rule; its randomized versions are all normalized, so it still agrees.
- Pushes need verified signatures: commit with the session's default git identity, never an overridden `user.email`.
- Steering (2026-10-02, #569/#571): no size caps on trusted upstream data; stream, don't buffer.
- `tests/spawn_env_hygiene.rs` allowlists (`PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES`) fail on new **and** stale entries: drop a file when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
