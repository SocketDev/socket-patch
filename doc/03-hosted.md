> [agent] **Part 3 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 3: Hosted mode (redirect, hosted engine, upstream restore, Node addon)

_Last checked against main @ 03b9418 on 2026-10-09 by audit-ecosystems (3.6 in-memory engine sizes and gaps re-measured for decision #1200; the pinned-check bullet rewritten for #1058). Earlier: `cf8b164` on 2026-10-08 by audit-ecosystems; older checks are in the run entries. Owner: audit-ecosystems._

> Scope: `patch/redirect/**`, `hosted/**`, `crates/socket-patch-node/**`, CLI `scan/hosted.rs`, `scan/hosted/*`, `hosted_bundle.rs`.

### 3.1 Size

| Area | Prod (code-only) | Inline tests |
|---|---:|---:|
| `patch/redirect/` (excl. `upstream/`) | 10,517 (8,117) | 18,806 — 11,365 of it in `mod.rs` |
| `patch/redirect/upstream/` | 7,446 (6,323) | 1,605 |
| `hosted/` (engine 1,448; memory/* 3,466) | 5,601 (4,426) | 1,013 |
| `socket-patch-node` | 651 Rust + 517 JS/TS | 479 |
| CLI hosted (`scan/hosted.rs` 2,267, `hosted/*` 601, `hosted_bundle.rs` 184) | 3,052 | 2,166 |

The table predates Gradle (#646), sbt (#690) and `hosted/governing_root.rs`; at `1c6c509` `redirect/mod.rs` alone is 21.9K lines (7.6K production) and upstream restore is ~8.8K production lines. {{E30}}

That is **about 27K production lines** for hosted mode at the snapshot (more now), plus about 23.6K lines of inline tests and about 42K lines of hosted integration tests (`e2e_redirect_*`, `in_process_redirect*`, `hosted_memory_*`, rollback-hosted, core goldens).

### 3.2 How the redirect logic is organized

**There is no trait.** Each rewriter is a free function with the signature `fn(&BTreeMap<String,String>, &[DepOverride], &mut RewriteResult)`, wired up by hand:

- `rewriter_groups` builds a `Vec<Box<dyn Fn>>` (`redirect/mod.rs:426-457`).
- A serial "withholding prefix" runs first: pdm, then pipenv, then `withhold` (`:379-412`).
- Each rewriter filters its own dependencies with `o.ecosystem == "npm"`-style string compares: 12 in `mod.rs`, 7 in `engine.rs`.

**`RewriteResult` is a cross-ecosystem grab bag** (`mod.rs:220-370` at `05ecc6e`). It holds 27 per-ecosystem uuid sets (20 at the review; sbt and Gradle added the rest), such as `confirmed_cargo_uuids`, `refused_pdm_uuids` and `vlt_foreign_uuids`. The CLI (`scan/hosted.rs`) and `vex/discover/gradle.rs` read some of them directly. Two places consume them all: {{E31}}
- `merge_group_delta`, which destructures every field (`:753-831`);
- `engine::confirm`, a 225-line ordered chain of 25 `ProbeStep` outcomes keyed on purl prefixes, driver predicates and those sets (`hosted/engine.rs:1652-1876`).

**Adding an ecosystem to hosted mode means editing at least eight parallel tables:**
- `formats::registry::REGISTRY`;
- `upstream::format_of` and the `restore_pass` match;
- `engine::file_ecosystem`;
- `memory::select::classify`;
- `roots::UNSUPPORTED_MARKERS`;
- `rewriter_groups`;
- the `RewriteResult` fields;
- `confirm()`.

**Long functions.**

| Lines | Function |
|---:|---|
| 836 | `run_redirect_selected` (CLI `scan/hosted.rs:639`) |
| 604 | `engine` (`hosted/memory/mod.rs:430`) |
| 455 | `rewrite_gem` (`mod.rs:4750`) |
| 439 | `plan_cargo_toml` (`mod.rs:2516`) {{E15}} |
| 394 | `rewrite_cargo` (`mod.rs:1062`) |
| 361 | `vendored_takeover` (`scan/hosted.rs:1497`) |
| 357 | `rewrite_maven_pom` (`mod.rs:5341`) |
| 283 | `rewrite_golang` |
| 272 | `rewrite_yarn_berry` |
| 196 | `pnpm_trust` (`engine.rs:897`) |

In total there are 647 functions, 44 of them over 100 lines.

Other symptoms:
- Four telescoping public entry points each add one parameter: `rewrite_registry_redirect` → `_with_python_metadata` → `_with_pipenv_version` → `_withholding_vlt` (`mod.rs:292-412`).
- `boxed_run_redirect_selected` exists only because the async future is too large for the 1 MiB Windows main-thread stack (`scan/hosted.rs:2213`). That is a direct symptom of the 836-line function.

**`redirect/mod.rs` is a 21.9K-line god module** (21,936 lines at `db83f01`; 17.5K at the snapshot). Its 7.6K production lines (L1–L7622) mix six concerns: {{E30}}
1. wire types (`Integrity`, `DepOverride`, `FileEdit`, `RewriteWarning`, `RewriteResult`);
2. orchestration: entry points, withholding, and a parallel-groups engine that runs each group on a `prefix.clone()` in a scoped thread, merges the deltas, and falls back to serial;
3. **eleven ecosystem rewriters**, where cargo alone takes lines 1050–2952 (1,903 lines);
4. hosted-URL ownership and grant-token redaction, separate from the 47-line `hosted_url.rs` beside it;
5. a utility library for *other modes*: `cargo_socket_registry_pin`, `TRUSTED_CHECKSUMS_ON`, `local_repo_artifact_path` and `gem_line_trailing_options` are imported by `vendor/cargo.rs`, `vendor/gem.rs`, `vendor/nuget_feed.rs` and `vex/discover/maven.rs`; since #690, `formats/sbt/owned_file.rs` also imports `bare_sha256_hex` from it (a new `formats → redirect` edge);
6. 14.3K lines of inline tests at `db83f01` (L7623–L21936; 322 tests in six modules). Moving them to sibling files is #1011, the first step of the split (#1010).

**Misplaced and dead code.**
- `redirect/golang_local.rs` (690 prod / 1,733 test) documents itself as the "Project-local Go replace-redirect engine (local mode only)". It is called from `apply.rs`, `vendor/golang.rs`, `rollback.rs` and `vex.rs`; it is not hosted code.
- `vlt_heal::ledger_targets` (~58 lines) and `vlt::edit_dep_id`, `lock_node_ids` and `carried_pin_original` are `pub` but are called only from their own tests. They read the retired pre-v5 `RedirectState` ledger, which `state.rs:1-8` says is "never" written.

### 3.3 Two orchestrators: disk and in-memory

The shared stages are good: `build_candidates`, `read_candidate_files`, `rewrite`, `confirm` and `guard` live in `hosted/engine.rs` and run over `ProjectView::{Disk, Memory, Snapshot}`. **The orchestration around them is written twice**: once in the CLI's `run_redirect_selected` (836 lines), and again in the memory engine's `engine` (604), `stages.rs` (319) and `discover.rs` (366).

| Step | Disk (CLI) | Memory |
|---|---|---|
| Reference fetch, lenient for capped all-NEW runs | `hosted.rs:665-713` | `memory/mod.rs:754-788` |
| vlt preflight → `withhold_everywhere` | `hosted.rs:742-754` (online) | `stages.rs:180-193` (offline, so vlt is **always** withheld) |
| Wheel-metadata fetch | `hosted.rs:818-903`, bespoke retry window | `discover.rs:320` + `stages.rs:256-281` |
| Rollout second-pass rewrite | `hosted.rs:950-1011` | `memory/mod.rs:839-930` |
| Selection policy | `ScanPolicy::select` (recorded-aware) | `select_with_policy` ("without a recorded view") |
| Bounded concurrency | `utils/concurrent.rs::ordered_concurrent` | `discover.rs::join_bounded`, a hand-rolled ~45-line `poll_fn` |
| Warning merge order | rewrite, **vlt preflight**, record, rush, pnpm, npm | rewrite, record, rush, pnpm, npm, **vlt preflight** |

**The warning-order row is a real divergence,** and nothing catches it: `hosted_memory_parity.rs` has no vlt cases.

**`ProjectView` leaks.**
- `engine.rs` has seven `match view { Disk | Snapshot => …, Memory => … }` branches.
- `memory/select.rs::classify` must mirror `read_candidate_files` by hand: python scripts, Cargo members, Rush subspaces and `EXTRA_TEXT_FILES`. Any new disk read that is not mirrored there turns into a `candidate_file_unreadable` refusal in memory.

**The parity suites exist only because there are two orchestrators:** `hosted_memory_parity.rs` (1,113 lines, 31 tests), `hosted_memory_common` (473) and `hosted_memory_rollout.rs` (639). Some outputs even need normalizing before they compare equal (`without_pipenv_advice`).

**The memory engine also cannot reach several rewriters:** vlt is always offline-withheld, maven and nuget raise `ecosystem_unsupported_in_memory`, and only npm, cargo and golang takeovers are refused (`refuse_takeovers`, `memory/stages.rs`): a vendored PyPI or Gradle-built Maven entry, which the disk flow takes over, is not on the memory list (B15; PR #1039 shares one predicate). {{E70}} So about 1,060 lines of maven/nuget rewriter plus the vlt rewriter are disk-only.

**Recommendation.** Both paths converge on `selected: &[(purl, uuid)]`. Build the disk path as `DiskSnapshot` → `MemoryProject`, then run a single `redirect_root(view, selected, api, hooks)`. Host-only effects become hooks: the apply lock, performing versus refusing a takeover, online versus offline vlt preflight, the pipenv probe, write-back, the stale-install probe, vlt heal and VEX. That saves roughly 700–900 production lines, and the parity suite becomes ordinary tests.

### 3.4 Duplication with vendored, VEX and formats

A "one model per format" layer (`formats/`) has been started, and **hosted mode is the main holdout.** Several module docs say so explicitly.

- **package-lock.json: four walks and two serializers.** Hosted `serialize_json` (`mod.rs:273`) always writes 2-space JSON. Vendor's serializer preserves the file's indent. Upstream restore uses the hosted one, so hosted rewrites *and rollback* reformat a 4-space or tab-indented lock in full (open issue #324).
- **yarn.lock: one grammar module.** Hosted classic rewrite and restore splice blocks through `formats::yarn::blocks` (`scan_blocks`, `repin_classic_block`), the reader vendor, inventory and VEX use; hosted berry rewrite and restore re-key entries through `formats::yarn::stanzas`, and the grammar is decided once (`formats::yarn::grammar`). The five `split("\n\n")` + regex copies were deleted (#1057). {{E08}}
- **NuGet.config: two readers.** Hosted routing and splice anchors now go through `formats::nuget::parse_config`, the bounded tokenizer that upstream restore and VEX use; the hosted regex reader `nuget_package_source_keys` and the regex anchors were deleted (#597). Vendored `nuget_feed.rs` still keeps its own comment-blanking reader ([`parse_config_source_keys`](https://github.com/SocketDev/socket-patch/blob/4646693150cf5efca6222b87092e1620e58566f8/crates/socket-patch-core/src/vendor/nuget_feed.rs#L1053-L1112)) and `find`-based anchors. {{E10}}
  - A commented-out `<add key="…">` no longer suppresses the nuget.org seed, because hosted reads through the shared reader (#597). {{E01}}
- **requirements.txt:** `utils/requirements.rs:1-9` says vendor, inventory and VEX share `logical_lines`, but "the hosted requirements rewriter … keeps its own line splitter" (`redirect/requirements.rs:17`). Upstream has a fourth reader.
- **Cargo.toml: two grammars inside one rewriter.** There are six `LazyLock` regexes plus `classify_cargo_section`, alongside four `toml_edit` parses of the same file. The dependency tables are walked five times across hosted, `utils/cargo_workspace` and VEX.
- **Gemfile / Gemfile.lock:** `formats/gem` claims to be "the ONE read model", yet `rewrite_gem` still regex-scans CHECKSUMS and the Ruby source, compiling a `Regex::new` **per dependency inside the loop** (`mod.rs:4866-4945`). Open issue #340, which breaks multi-line `gem` declarations, lives here.

**What already works, and is the template to copy:** `formats::bun::BunTextLock`, `formats::cargo::CargoLock`, `vendor::go_mod_edit`/`go_sum_edit` and `formats::pnpm` are each one model shared by hosted, inventory, VEX and upstream.

**Module cycles** (production `crate::X::` references):

| From → To | Refs | Reverse | Refs |
|---|---:|---|---:|
| redirect → vendor | 49 | vendor → redirect | 10 |
| vex → redirect | 16 | redirect → vex | 5 |
| redirect → formats | 19 | formats → redirect | 5 |

`formats/pnpm/hosted.rs:11` imports `RewriteResult` and `FileEdit`, so the "pure" format models depend on the hosted engine's result type. In practice `vendor/` has become the codec library.

### 3.5 Upstream restore: rebuilding what was thrown away

**Cost.** 8,769 production lines at `e2d9633` (7,446 at the snapshot: Python 2,474 (`uv` 1,152), infrastructure 1,395, gem 743, npm 754, maven 400, composer 373, cargo 361, nuget 350, vlt 329, bun.lockb 153, golang 114). PR #918 has since taken over part of this section's npm restore; #919 and #992 remain open. Tests add 1,605 inline lines, 1,913 lines of golden tests and about 1.9K lines of `in_process_rollback_hosted`.

**Why it exists.** v5 dropped the redirect ledger. Yet every rewriter still computes `FileEdit { original, new }`, with 36 `FileEdit {` literals in `mod.rs` at `e2d9633`. In production, `original` is read only by the Composer reinstall hint (`cli composer_hints.rs:69-99`). **So the original bytes are computed, discarded, and later re-derived from the network.**

**Network dependencies:** the npm registry, the crates.io sparse index, the Go proxy and `sum.golang.org`, the PyPI JSON API, RubyGems, Packagist, NuGet `registration5-gz`, and a Socket `/upstream/npm/<uuid>.json` endpoint for berry checksums. That last one may download the whole upstream tarball to verify it.

**Failure modes:**
- refused when offline;
- registry fetches never send credentials, so a private registry that needs auth is unreachable;
- **private registries and mirrors are ignored.** npm restore always uses `SOCKET_NPM_REGISTRY` or the public registry, so an Artifactory project comes back with public URLs;
- heuristic re-derivation of package-manager output (uv re-derives specifiers "in uv's spelling" and the sdist/wheel shape from sibling entries);
- `bun.lockb` is always refused;
- partial writes;
- a pass-until-stable loop (`upstream/mod.rs:564-610`).

The open backlog shows the cost:
- #411: uv rollback deletes a user's own `override-dependencies` pin;
- #410: requirements.txt with only hosted pins can be patched but never unpatched;
- #408: uv `upload-time` gains milliseconds;
- #407: `uv pip compile` pylock always refused;
- #385: Hatch refuses after a version bump;
- #382 and #331: PDM rollback fails permanently or leaves the pin;
- #271: Maven hosted redirects cannot be reverted at all.

**Assessment.** Upstream restore is justified only where the original entry is a *pure function of registry data*: npm/pnpm/bun-text `resolved` + `integrity`, cargo `cksum`, go.sum, the gem checksum, the composer dist and the nuget hash. That is about 2.2K lines.

For uv, pylock, poetry, pdm, hatch, vlt, maven and bun.lockb, the module's own fallback (`checkout_remedy`: "`git checkout -- <lockfile>`") or a package-manager relock is cheaper and more correct:
- `uv lock --upgrade-package X`
- `poetry lock --no-update`
- `bundle lock --update X`

**There are two cheaper alternatives** (owner decision: {{E45}}):
- **(a) Narrow restore** to the pure-function formats and refuse the rest with a precise remedy: about −3.3K production and −2K test lines.
- **(b) Keep the originals the rewriters already compute** in a tiny content-addressed sidecar, for example `.socket/hosted-originals/<sha>.json`, ignorable and git-committable. Byte-exact rollback then needs no network at all. This is the same "record original → splice back" approach vendored mode uses.

### 3.6 Per-package-manager features with poor complexity-to-value

| Feature | Prod LOC (approx.) | Notes |
|---|---:|---|
| vlt hosted | 2,454 + 1,707 tests | The warm-tree heal deletes `node_modules/.vlt` store entries: installed-tree surgery in a lockfile-only mode. vlt never redirects in memory. Contains dead ledger helpers (`edit_dep_id`, `lock_node_ids`, `carried_pin_original`, `vlt_heal::ledger_targets`), orphaned when #277 removed the ledger merge. {{E58}} |
| npm `allow-remote` auto-config | ~900 + 514 tests | `npmrc.rs` re-implements npm's `ini` tokenizer and its user/global/builtin/env config layering, all to decide whether to append one line to `.npmrc`. |
| pnpm `trustLockfile` auto-config | ~450 | Heal-on-rerun, takeover previews, legacy and Rush special cases. Open issues #400, #401, #402 (quoted keys, flow style, duplicate keys) are all here. |
| Parallel rewriter groups | ~260 + 451 equivalence tests | Parallelizes CPU work over a handful of texts that is already single-pass. Benchmark it, or delete it. |
| In-memory engine + napi addon + `hosted-bundle` | ~4.5K (memory 3,660, addon 649, `hosted-bundle` 183, plus 75 `ProjectView::Memory` arms elsewhere) + ~4.7K tests | `npm/package.json` is `"private": true`; CI only builds and smoke-tests it. The contract now says it "remain[s] supported for callers such as the future GitHub App" (#1029). Maven, NuGet and sbt never pin in memory, vlt is preflighted offline, and takeovers are refused. Whether it is a supported product is decision #1200. {{E44}} |
| bun.lockb hosted | ~260 on top of the 2.25K shared codec | Legacy format. |
| Equivalence-test scaffolding | 2,592 lines + 252 KB goldens | Refactor oracles ("blessed while the previous rewriter still ran beside it"), now frozen as snapshots. |
| Warning vocabulary | ~130 distinct codes in this slice; 89 `RewriteWarning {` literals in `mod.rs`; no enum | Families repeat per ecosystem: missing-integrity ×15, entry/package-not-found ×13, no-lockfile/manifest ×7. |

### 3.7 Recommendations

1. **Split `redirect/mod.rs` mechanically** (net ~0 lines, low risk): {{E30}}
   - `model.rs` for the DTOs;
   - `driver.rs` for orchestration;
   - one file per ecosystem, with `cargo/` split into `{manifest, config, lock, pins}`;
   - merge the hosted-URL and token helpers into `hosted_url.rs`;
   - move `golang_local.rs` to agent mode;
   - move the 11.4K test lines into sibling `tests.rs` files.
2. **Introduce `trait HostedRewriter { ecosystem(); drives(&FileSet) -> bool; rewrite(&FileSet, &[&DepOverride]) -> Outcome }`**, with `Outcome { files, edits, warnings, per_dep: BTreeMap<Uuid, DepStatus> }` where `DepStatus` is Confirmed, Refused, Foreign or Unclaimed. It replaces the 27 `RewriteResult` sets, `merge_group_delta` and most of `confirm()`. The "driver" rules for pdm/vlt/uv/sbt become `drives()`. {{E31}}: tracking #1075, step 1 (one report map, mechanical) is #1076.
3. **Finish one codec per format** in `formats/`, in this order:
   - package-lock (4 walks → 1, indent-preserving);
   - yarn (done: #1057 moved every yarn.lock grammar into `formats/yarn`);
   - NuGet config (3 readers → 1, which fixes the comment bug);
   - requirements;
   - Cargo.toml (regex scanner → `toml_edit`).

   Move the neutral types (`Edit`, `Warning`, `LockfileEntry`) into `formats` to break the cycles.
4. **One hosted pipeline for disk and memory** (about −800 lines; the parity suites become ordinary tests) Blocked on decision #1200. {{E32}}
5. **Narrow upstream restore, or replace it with an originals sidecar** (about −3.3K production lines). This also fixes a whole family of open rollback bugs.
6. **Decide the addon's fate** (decision #1200). If it is a supported engine, make it the one hosted pipeline (recommendation 4) and close or tier its coverage gaps. If not, delete the addon, `hosted-bundle` and the memory-only branches (about −4.5K production, −4.7K test). {{E44}}
7. **Simplify the npm `allow-remote` handling** to project-file-only planning plus a warning (about −700). Drop the parallel groups unless benchmarks justify them, and delete the dead vlt ledger helpers.
8. **Make warning codes typed:** `enum Reason { MissingIntegrity, EntryNotFound, NoLockfile, … } × Ecosystem`, serializing to today's strings.
9. **Retire the refactor-oracle equivalence suites** (2.6K lines + 252 KB goldens) and the telescoping entry points; use one `RewriteOptions` struct instead.

### New findings since the review

- {{E50}}: hosted `rewrite_nuget` and upstream restore rewrite every `packages.lock.json` entry of the patched id, in every target framework, whatever its `resolved` version; vendored `locked_at` only touches entries at the patched version. `packages.lock.json` has four walkers (hosted, restore, vendored, VEX).
- {{E52}}: every go.sum edit goes through the `GoSumEditor` the hosted Go rewriter uses; the free oracle-only copies were deleted (#1103). The pure hosted codec still lives in `vendor/go_sum_edit.rs`, not `formats/`.
- {{E15}}: the hosted cargo planner `plan_cargo_toml` is a line scanner, gated by a second `toml_edit` classifier of the same declarations. It refuses `serde = { version = "1", features = [⏎ "derive",⏎] }` as "inline table does not close on its line", although cargo and `toml_edit` accept it, so hosted skips a crate that vendored mode handles. Upstream restore unpins with a third, line-level grammar.
- {{E58}}: the hosted-vlt ledger helpers left without a caller by #277 were deleted (#1141); `UpstreamClient::seed_rubygems_sha256` is still a test helper compiled into production.
- {{E73}} "Is this hosted patch pinned" is now decided by lockfile discovery alone, in one gate shared by the disk and memory engines (#1058). `confirm()`'s needles only pre-check that a write landed. A lockless NuGet/Cargo pin is still written, now with a `redirect_pin_lockless` warning and a refusal remedy that names the lockfile to create.
- {{E85}} The NuGet lock writer and its restore drop CRLF and BOM (`serialize_json`), unlike every other hosted JSON writer. A maintainer closed #1068 as cosmetic on 2026-10-08; the reader's BOM refusal stays open as #623.
- {{E63}}: hosted Maven splices the API's `maven_suffixed_version` into every matching `pom.xml` `<version>` without checking it (proven with `-socket.DEADBEEF`, `-patched` and markup), while the hosted Gradle planner (#646) refuses the same grant unless it is `<base>-socket.<uuid[..8]>`. The suffix grammar has four builders (vendored `jvm::Coords`, hosted Gradle, the CLI `vex_consumed` copy and the server) and no shared validator.

---
_Generated by [Claude Code](https://claude.ai/code)_
