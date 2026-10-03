> [agent] **Part 3 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 3: Hosted mode (redirect, hosted engine, upstream restore, Node addon)

_Last checked against main @ 203e092 on 2026-10-02 by audit-ecosystems. Owner: `audit-ecosystems`._

> Scope: `patch/redirect/**`, `hosted/**`, `crates/socket-patch-node/**`, CLI `scan/hosted.rs`, `scan/hosted/*`, `hosted_bundle.rs`.

### 3.1 Size

| Area | Prod (code-only) | Inline tests |
|---|---:|---:|
| `patch/redirect/` (excl. `upstream/`) | 10,517 (8,117) | 18,806 — 11,365 of it in `mod.rs` |
| `patch/redirect/upstream/` | 7,446 (6,323) | 1,605 |
| `hosted/` (engine 1,448; memory/* 3,466) | 5,601 (4,426) | 1,013 |
| `socket-patch-node` | 651 Rust + 517 JS/TS | 479 |
| CLI hosted (`scan/hosted.rs` 2,267, `hosted/*` 601, `hosted_bundle.rs` 184) | 3,052 | 2,166 |

That is **about 27K production lines** for hosted mode, plus about 23.6K lines of inline tests and about 42K lines of hosted integration tests (`e2e_redirect_*`, `in_process_redirect*`, `hosted_memory_*`, rollback-hosted, core goldens).

### 3.2 How the redirect logic is organized

**There is no trait.** Each rewriter is a free function with the signature `fn(&BTreeMap<String,String>, &[DepOverride], &mut RewriteResult)`, wired up by hand:

- `rewriter_groups` builds a `Vec<Box<dyn Fn>>` (`redirect/mod.rs:426-457`).
- A serial "withholding prefix" runs first: pdm, then pipenv, then `withhold` (`:379-412`).
- Each rewriter filters its own dependencies with `o.ecosystem == "npm"`-style string compares: 12 in `mod.rs`, 7 in `engine.rs`.

**`RewriteResult` is a cross-ecosystem grab bag** (`mod.rs:200-260`). It holds 20 per-ecosystem uuid sets, such as `confirmed_cargo_uuids`, `refused_pdm_uuids` and `vlt_foreign_uuids`. Two places consume them:
- `merge_group_delta`, which destructures every field (`:503-557`);
- `engine::confirm`, an ordered if-chain of about 16 per-ecosystem rules keyed on purl prefixes and those sets (`hosted/engine.rs:1239-1315`).

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
| 440 | `plan_cargo_toml` (`mod.rs:2409`) |
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

**`redirect/mod.rs` is a 17.5K-line god module.** Its 6.2K production lines mix six concerns:
1. wire types (`Integrity`, `DepOverride`, `FileEdit`, `RewriteWarning`, `RewriteResult`);
2. orchestration: entry points, withholding, and a parallel-groups engine that runs each group on a `prefix.clone()` in a scoped thread, merges the deltas, and falls back to serial;
3. **eleven ecosystem rewriters**, where cargo alone takes lines 1050–2952 (1,903 lines);
4. hosted-URL ownership and grant-token redaction, separate from the 47-line `hosted_url.rs` beside it;
5. a utility library for *other modes*: `cargo_socket_registry_pin`, `TRUSTED_CHECKSUMS_ON`, `local_repo_artifact_path` and `gem_line_trailing_options` are imported by `vendor/cargo.rs`, `vendor/gem.rs`, `vendor/nuget_feed.rs` and `vex/discover/maven.rs`;
6. 11.4K lines of tests (262 tests, 80 of them for cargo).

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

**The memory engine also cannot reach several rewriters:** vlt is always offline-withheld, maven and nuget raise `ecosystem_unsupported_in_memory`, and takeovers are refused. So about 1,060 lines of maven/nuget rewriter plus the vlt rewriter are disk-only.

**Recommendation.** Both paths converge on `selected: &[(purl, uuid)]`. Build the disk path as `DiskSnapshot` → `MemoryProject`, then run a single `redirect_root(view, selected, api, hooks)`. Host-only effects become hooks: the apply lock, performing versus refusing a takeover, online versus offline vlt preflight, the pipenv probe, write-back, the stale-install probe, vlt heal and VEX. That saves roughly 700–900 production lines, and the parity suite becomes ordinary tests.

### 3.4 Duplication with vendored, VEX and formats

A "one model per format" layer (`formats/`) has been started, and **hosted mode is the main holdout.** Several module docs say so explicitly.

- **package-lock.json: four walks and two serializers.** Hosted `serialize_json` (`mod.rs:273`) always writes 2-space JSON. Vendor's serializer preserves the file's indent. Upstream restore uses the hosted one, so hosted rewrites *and rollback* reformat a 4-space or tab-indented lock in full (open issue #324).
- **yarn.lock: five copies of a `split("\n\n")` + regex grammar** (`mod.rs:2992`, `:3159`, `:3278`, `upstream/npm.rs:289`, `:390`), alongside the shared `scan_blocks` used by vendor, inventory and VEX.
- **NuGet.config: three readers.** Hosted uses regexes (`mod.rs:4942-4975`), and its splice anchors (`insert_nuget_source`, `nuget_mapping_open_end`) are comment-blind regexes too (#585); vendor's `nuget_feed.rs` blanks comments and then scans; `formats::nuget::parse_config` is a bounded tokenizer used by upstream and VEX. Hosted restore's `remove_source` adds a fourth regex reader. {{E11}}
  - **Likely bug (verified by reading the code):** hosted `nuget_package_source_keys` (`mod.rs:4956`) runs its regex over raw text without masking `<!-- -->`. A commented-out `<add key="…">` therefore suppresses the nuget.org seed. {{E01}}
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

**Cost.** 7,446 production lines: Python 2,474 (`uv` 1,152), infrastructure 1,395, gem 743, npm 754, maven 400, composer 373, cargo 361, nuget 350, vlt 329, bun.lockb 153, golang 114. Tests add 1,605 inline lines, 1,913 lines of golden tests and about 1.9K lines of `in_process_rollback_hosted`.

**Why it exists.** v5 dropped the redirect ledger. Yet every rewriter still computes `FileEdit { original, new }`, with 30 `FileEdit {` literals in `mod.rs`. In production, `original` is read only by the Composer reinstall hint (`cli composer_hints.rs:69-99`). **So the original bytes are computed, discarded, and later re-derived from the network.**

**Network dependencies:** the npm registry, the crates.io sparse index, the Go proxy and `sum.golang.org`, the PyPI JSON API, RubyGems, Packagist, NuGet `registration5-gz`, and a Socket `/upstream/npm/<uuid>.json` endpoint for berry checksums. That last one may download the whole upstream tarball to verify it.

**Failure modes:**
- refused when offline;
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

**There are two cheaper alternatives:**
- **(a) Narrow restore** to the pure-function formats and refuse the rest with a precise remedy: about −3.3K production and −2K test lines.
- **(b) Keep the originals the rewriters already compute** in a tiny content-addressed sidecar, for example `.socket/hosted-originals/<sha>.json`, ignorable and git-committable. Byte-exact rollback then needs no network at all. This is the same "record original → splice back" approach vendored mode uses.

### 3.6 Per-package-manager features with poor complexity-to-value

| Feature | Prod LOC (approx.) | Notes |
|---|---:|---|
| vlt hosted | 2,454 + 1,707 tests | The warm-tree heal deletes `node_modules/.vlt` store entries: installed-tree surgery in a lockfile-only mode. vlt never redirects in memory. Contains dead ledger helpers. |
| npm `allow-remote` auto-config | ~900 + 514 tests | `npmrc.rs` re-implements npm's `ini` tokenizer and its user/global/builtin/env config layering, all to decide whether to append one line to `.npmrc`. |
| pnpm `trustLockfile` auto-config | ~450 | Heal-on-rerun, takeover previews, legacy and Rush special cases. Open issues #400, #401, #402 (quoted keys, flow style, duplicate keys) are all here. |
| Parallel rewriter groups | ~260 + 451 equivalence tests | Parallelizes CPU work over a handful of texts that is already single-pass. Benchmark it, or delete it. |
| In-memory engine + napi addon + `hosted-bundle` | ~4.8K + ~4.6K tests | `npm/package.json` is `"private": true`; CI only builds and smoke-tests it. **Worth it only if the depscan backend actually replaces its TypeScript rewriters with it.** Otherwise there are three implementations: TS, disk and memory. |
| bun.lockb hosted | ~260 on top of the 2.25K shared codec | Legacy format. |
| Equivalence-test scaffolding | 2,592 lines + 252 KB goldens | Refactor oracles ("blessed while the previous rewriter still ran beside it"), now frozen as snapshots. |
| Warning vocabulary | ~130 distinct codes in this slice; 89 `RewriteWarning {` literals in `mod.rs`; no enum | Families repeat per ecosystem: missing-integrity ×15, entry/package-not-found ×13, no-lockfile/manifest ×7. |

### 3.7 Recommendations

1. **Split `redirect/mod.rs` mechanically** (net ~0 lines, low risk):
   - `model.rs` for the DTOs;
   - `driver.rs` for orchestration;
   - one file per ecosystem, with `cargo/` split into `{manifest, config, lock, pins}`;
   - merge the hosted-URL and token helpers into `hosted_url.rs`;
   - move `golang_local.rs` to agent mode;
   - move the 11.4K test lines into sibling `tests.rs` files.
2. **Introduce `trait HostedRewriter { ecosystem(); drives(&FileSet) -> bool; rewrite(&FileSet, &[&DepOverride]) -> Outcome }`**, with `Outcome { files, edits, warnings, per_dep: BTreeMap<Uuid, DepStatus> }` where `DepStatus` is Confirmed, Refused, Foreign or Unclaimed. It replaces the 20 `RewriteResult` sets, `merge_group_delta` and most of `confirm()`. The "driver" rules for pdm/vlt/uv become `drives()`.
3. **Finish one codec per format** in `formats/`, in this order:
   - package-lock (4 walks → 1, indent-preserving);
   - yarn (five `split("\n\n")` sites → `scan_blocks`);
   - NuGet config (3 readers → 1, which fixes the comment bug);
   - requirements;
   - Cargo.toml (regex scanner → `toml_edit`).

   Move the neutral types (`Edit`, `Warning`, `LockfileEntry`) into `formats` to break the cycles.
4. **One hosted pipeline for disk and memory** (about −800 lines; the parity suites become ordinary tests).
5. **Narrow upstream restore, or replace it with an originals sidecar** (about −3.3K production lines). This also fixes a whole family of open rollback bugs.
6. **Decide the addon's fate.** If depscan adopts it, delete the TS rewriters and relax the `JSON.stringify(…, 2)` golden contract, which unblocks indent preservation. If not, delete the addon, `hosted-bundle` and the memory-only branches (about −4.8K production, −4.6K test).
7. **Simplify the npm `allow-remote` handling** to project-file-only planning plus a warning (about −700). Drop the parallel groups unless benchmarks justify them, and delete the dead vlt ledger helpers.
8. **Make warning codes typed:** `enum Reason { MissingIntegrity, EntryNotFound, NoLockfile, … } × Ecosystem`, serializing to today's strings.
9. **Retire the refactor-oracle equivalence suites** (2.6K lines + 252 KB goldens) and the telescoping entry points; use one `RewriteOptions` struct instead.

### New findings since the review

- {{E50}}: hosted `rewrite_nuget` and upstream restore rewrite every `packages.lock.json` entry of the patched id, in every target framework, whatever its `resolved` version; vendored `locked_at` only touches entries at the patched version. `packages.lock.json` has four walkers (hosted, restore, vendored, VEX).
- {{E52}}: `vendor/go_sum_edit.rs` keeps free `upsert_module_lines` / `has_module_version` / `remove_exact_module_version_lines` with no production caller, re-implemented by the `GoSumEditor` the hosted Go rewriter uses; the free copies survive only as a test oracle, and the pure hosted codec lives in `vendor/`.

---
_Generated by [Claude Code](https://claude.ai/code)_
