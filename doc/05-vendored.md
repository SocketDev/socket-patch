> [agent] **Part 5 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 5: Vendored mode and the non-JS backends

_Last checked against main @ 045d7ec on 2026-10-04 by audit-ecosystems (5.4 Python, Cargo, Maven XML, Gem and Go). Owner: audit-ecosystems._

> Scope: `vendor/` framework (`mod`, `common`, `state`, `verify`, `registry_fetch`, `service_fetch`, `prestage`, `reuse`, `redownload`, `ledger_snapshots`, `parse_memo`, `path`, `source`, `toml_surgery`, `lock_inventory`); backends for cargo, gem, pypi (×10 files), golang, composer, nuget, maven and `jvm/`; related `utils/` parsers; and the CLI `vendor.rs` + `vendored_backend/`.

### 5.1 Size

| Area | Prod | Inline tests |
|---|---:|---:|
| `vendor/` excluding the npm family (framework + 7 backends + lock_inventory) | 37,603 | 58,095 |
| Related utils (python_lock, poetry_lock, pdm_lock, hatch, requirements, pipenv, cargo_workspace, group_commit, durability, fs, line_endings, …) | 6,972 | 5,735 |
| CLI `commands/vendor.rs` + `vendored_backend/*` | ~4,500 | 2,607 |

Production lines per backend:

| Backend | Prod |
|---|---:|
| JVM (`maven_repo` 1,845 + `jvm/*` 5,540 + a 66-line `.gradle` script) | 7,451 |
| PyPI (10 files; plus `lock_inventory/pypi` 663 and ~3,390 shared utils) | 7,270 |
| Cargo | 4,351 |
| Gem | 2,389 |
| Go | 2,072 |
| NuGet | 1,406 |
| Composer | 1,393 |

Framework files: `registry_fetch` 1,535, `mod` 838, `common` 831, `state` 824, `verify` 823, `redownload` 462, `prestage` 425, `path` 421, `service_fetch` 386, `ledger_snapshots` 352, `reuse` 349, `toml_surgery` 292, `parse_memo` 147.

### 5.2 No backend trait

The only traits under `vendor/` are a private `EditLines` and a test-helper trait; backends are uniform by naming convention only. Each non-npm backend defines:
- `struct <Eco>Prelude` + `async fn <eco>_prelude` (`cargo.rs:425/439`, `gem.rs:121/139`, `golang.rs:53/66`, `composer_lock.rs:99/121`, `nuget_feed.rs:158/178`, `maven_repo.rs:91/114`, `pypi.rs:674/690`);
- `service_preflight`, `vendor_*`, `revert_*` and `revert_*_opts`.

The signatures are close but not identical:
- nuget and maven take `&Path` where the others take `impl Into<PackageSource>`;
- pypi takes two extra cache arguments;
- cargo, golang and composer ignore three of their parameters (`_sources`, `_force`, `let _pristine_src = …into()` at `cargo.rs:768-779`).

The CLI papers over the differences with two macros, `vend!` and `vend_installed!` (`cli/commands/vendor.rs:153-192`).

**16 production sites enumerate the ecosystems**, and each is a place a new ecosystem must be added:
1. `vendor/path.rs:43` `ECOSYSTEM_DIRS`
2. `vendor/path.rs:233-320` `leaf_to_purl` (8 arms)
3. `vendor/mod.rs:754-772` `service_preflight` (7 arms)
4. `vendor/mod.rs` `lock_text_refusals`
5. `vendor/mod.rs:~395-410` harvest suffix branches
6. `verify.rs:526` `artifact_is_file_shaped`
7. `redownload.rs:166-302`
8. `prestage.rs:350` `PRESTAGED_ECOSYSTEMS`
9. `lock_inventory/mod.rs:250`
10. `lock_inventory/recover.rs:42-144`
11. `ledger_snapshots.rs:55` `WHOLE_FILE_KINDS`
12. `state.rs:439+` `carry_forward_wiring`
13. CLI `vendor.rs:137` `SERVICE_ECOSYSTEMS`
14. CLI `vendor.rs:194` vendor dispatch
15. CLI `vendor.rs:241` revert dispatch
16. CLI `vendor.rs:261` in-use dispatch

Inside backends there is a second dispatch layer: `PypiFlavor` has 7 variants, matched at `pypi.rs:727, 744, 1123` and again as strings at `:1545`; `NpmLockFlavor` does the same for npm.

**Ecosystem identity is inconsistent.** The legacy single-POM Maven entry is `"maven"`, but the reactor/Gradle backend rewrites it to `"jvm"` (`maven_repo.rs:1089`). That forces `"maven" | "jvm"` aliases at CLI `vendor.rs:249` and four times in `redownload.rs`.

**The CLI reaches into backend internals:** 54 distinct `vendor::<mod>::<item>` paths are used from 25 CLI files. Examples:
- `vendor.rs` calls `jvm::apply::{is_jvm_entry, check_entry, upstream_unverified, sweep_replaced_tree}`;
- `repair.rs` calls `cargo::migrate_legacy_wiring` and bun binary helpers.

These are hooks a trait should expose.

**The orchestrator** `vendor_records_reusing` (CLI `vendor.rs:1971`) is **about 970 lines**. It mixes:
- the vendor loop;
- hosted→vendored takeover;
- berry and vlt special cases;
- prefetch and prestage;
- group commit;
- a composer special case.

### 5.3 The ledger, and nine ways to undo a change

Each `VendorEntry` (`state.rs:215-282`) stores:
- `artifact {path, sha256, size, platform_locked, file_inventory}`;
- `wiring: Vec<WiringRecord {file, kind, action, key, original: Value, new: Value}>`;
- per-flavor typed fields (`lock: CargoLockOriginal`, `uv`, `pnpm`, `poetry`, `pdm`, `pipenv`, `took_over_go_patches`, `flavor`);
- `detached`, plus an embedded patch `record`.

`original`/`new` are untyped JSON whose shape depends on `kind`, and there are **more than 45 distinct kind strings**.

"Record the original and restore it" is the right idea, but it is **implemented about nine different ways**:

| Mechanism | Used by |
|---|---|
| Regenerated by ownership rule; recorded `original` ignored | cargo `Cargo.toml`, go `drop_replace_entry` |
| Typed side field | Cargo.lock from `entry.lock`. The same data is also written as a `cargo_lock_entry` record that nothing reads. |
| Text-fragment splice with drift detection (`common.rs:693-810`, the only shared helper) | poetry, pdm |
| JSON value replace + reserialize | composer; pipenv (canonical rewrite of the whole lock) |
| Line arrays | gem; requirements, which has its *own* drift codes, `vendor_revert_line_drifted`, instead of the `vendor_lock_entry_drifted` contract |
| Whole-file snapshot, restored if live == new | maven legacy pom, nuget config, pylock / PEP 723 / hatch |
| Three-way structural TOML merge | `pypi_lock.rs:414-569` |
| Pure plan/unplan with shared-fragment refcounting | JVM (`jvm/mod.rs`, `jvm/apply.rs`), the best design in the slice |

Revert/restore/unwind code in the non-npm backends totals **about 3,540 lines**: gem 422, nuget 305, pypi 291, pypi_lock 254, uv 231, cargo 220, composer 205, and more.

**Back-compat costs:**
- Whole-file snapshots made ledgers grow by tens of MB, so schema v2 was added to compensate: `ledger_snapshots.rs`, 352 lines of ops-delta encoding. It is a workaround for the snapshot design.
- The cargo pre-v5 `.cargo/config` migration and its legacy code paths: 29 "legacy" mentions in `cargo.rs`.
- Committed ledgers in users' repositories make every `kind` string a permanent API. The legacy-ledger fixtures (`tests/fixtures/legacy-ledgers/<9 ecosystems>`) are the right guardrail.

### 5.4 Duplication

**Format parsers live in three homes** (`formats/`, `utils/`, `vendor/`), and `formats/` has no pypi, golang or package-lock model. 50 non-vendor files import `crate::vendor::*`: 48 references to `vendor::lock_inventory`, 15 to `registry_fetch` and 9 to `go_mod_edit`. `vendor/pypi.rs:87-230` holds hosted-mode wheel-metadata code that is used by `hosted/memory/discover.rs` and CLI `scan/hosted.rs`.

**XML: eight hand-rolled scanners and no XML crate.**
- `<!--` handling is implemented independently in 8 files, including two strippers inside `maven_repo.rs`.
- There are four attribute extractors with three different tokenization rules:
  - `nuget_feed.rs:1094 attr_value` matches any substring, with no word boundary;
  - `redirect/upstream/nuget.rs:39` uses a regex;
  - `jvm/gradle.rs:1538` checks for preceding whitespace;
  - `formats/nuget/mod.rs:41` does a real tag parse.
- The NuGet writers (`nuget_feed.rs`, the hosted splicer) never use the shared reader `formats::nuget::parse_config` that VEX uses, **so reader and writer can disagree about what a file contains**. {{E11}}
- `pom.xml` alone has seven scanners (checked on `045d7ec`): `formats::maven::parse_pom` (VEX, restore gate); the hosted rewriter's raw regex (`MAVEN_DEPENDENCY_BLOCK_RE`, `insert_maven_*`), which upstream restore reuses and which masks nothing; vendored `maven_repo.rs` (`comment_spans`/`profiles_spans`, plus a second `declares_modules`); the reactor's `mask` + `Doc` tree and, in the same file, `scan_pom_project` (a depscan port); and the crawler's and `vex/product.rs`'s own readers. None of the three writers (hosted, restore, vendored single-pom) locates elements through a reader. Target: one masked element tree in `formats::maven` that readers and splicing writers both query. {{E10}}
- The Maven share of the open backlog is mostly this: #259 "edits commented-out, plugin and profile markup", #342 "adds a second section when the existing one is self-closed or has a comment", #683 (`<exclusions>` first) and {{E55}}.

**Python:**
- `utils/poetry_lock.rs` and `utils/pdm_lock.rs` are near-twins with mirrored function sets (`rewrite_*_lock`, `*_with_edits`, `plan_*_rewrite`, `*_lock_edits`, `*_lock_fragments`, `extend_span`, `pair_*`).
  - After renaming, `poetry_lock_edits` and `pdm_lock_edits` are **identical**.
  - `pair_*` differs by three lines: pdm has a shape check that poetry lacks. For Poetry this is unreachable, because a rewrite pairs fragments of one document before and after its own edit, so the fragment count cannot change.
  - `next_header_end`, the rewrite struct with `edits()`, the parse holder and the finish step (render → reparse → pair → splice) are also copied. The finish steps differ only in their line-ending rule, which is a real drift: on a mixed-line-ending lock, Poetry turns the edited unit CRLF and PDM turns it LF ([`poetry_lock.rs#L366-L369`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/utils/poetry_lock.rs#L366-L369), [`pdm_lock.rs#L268`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/utils/pdm_lock.rs#L268)). {{E13}} {{E54}}
- `vendor/pypi_{poetry,pdm,pipenv}.rs` repeat one skeleton:
  - `load_*_project`
  - `classify_dependency`
  - `check_target_guards` (missing / forked / ours-in-sync / ours-stale / user-authored)
  - `wire_*`
  - `revert_*`
- Pipfile.lock is read through one shared parser but **written two ways**: vendored reserializes canonically, hosted splices spans.
- Hosted-URL recognition for Pipenv is shared: hosted `owned_url` and the vendored Pipenv guard both ask `lock_inventory::pypi::hosted_pypi_reference`, which applies `hosted_patch_uuid`'s origin allowlist to `hosted_artifact_url`'s tail grammar; the vendored guard gets the run's `--patch-server-url` origin (#572). {{E04}}

**Cargo:**
- `Cargo.toml` `[package]` is read in five places. Two are line scanners: [`crawlers/cargo_crawler.rs#L12-L113`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/crawlers/cargo_crawler.rs#L12-L113) ("no TOML crate dependency") and `vex/product.rs` `scan_toml_section`. Three are ad hoc `toml_edit` lookups: `cargo_tag::version_literal` (`[package]` or legacy `[project]`; it now finds the literal's span through `toml_edit` and splices only those bytes), `cargo.rs` `path_crate_version` (`[package]` only) and `declared_cargo_minor` (#651).
  - They have drifted, proven by execution: a BOM manifest is invisible to the crawler but read by VEX and `cargo_tag`; `[project]` and dotted keys are read only by `cargo_tag`; `[package] junk` (invalid TOML) is accepted only by the crawler. {{E15}}
  - Hosted mode plans the dependency pin itself with a line scanner (`plan_cargo_toml`, six regexes), then re-checks it with a second, `toml_edit` classifier (`validate_cargo_toml_pins`). `CargoRegistryPins`, a `#[cfg(test)]` oracle and upstream restore's `unpin_line` are three more line-level readers of the same declarations. Vendored edits only through `toml_edit`. The scanner refuses an inline table whose `features` array spans lines, which is valid TOML and accepted by cargo, so hosted skips a crate that vendors fine. {{E57}}

**Gem:** `vendor/gem.rs` imports three token helpers from `formats::gem` and keeps its own section model (`section_span` / `section_end`, which take the *first* line equal to a header). With `formats::gem::parse` and hosted's `GemLockSection` that makes three section models and three DEPENDENCIES-name parsers; the name rules agree on Bundler-written entries. {{E19}}
  - The section models have drifted, proven by execution: Bundler 2 writes one `GEM` section per source, and vendored `edit_lock` looks only in the first, so a gem from any later source (rubygems.org, when a private source sorts first) is refused with "GEM specs has no entry", while hosted and the shared parser handle it. {{E59}}

**Go:** `go_mod_edit.rs` is properly shared (9 users) but lives under `vendor/`. `crawlers/go_crawler.rs:63` still has its own `parse_go_mod_module`, which has no production caller; the live `module` reader is `vex/product.rs`'s own, and both misread Go's block form `module ( … )` as the module `(`. {{E19}}

**Small helpers:**
- **CRLF:** four policies for the same "`toml_edit` emits LF" problem:
  - `line_endings` refuses mixed files;
  - `python_lock` converts CRLF-only files and leaves mixed files as LF;
  - `poetry_lock` has its own inline rule: any CRLF turns the whole rendering CRLF, which disagrees with `python_lock` on mixed files {{E54}};
  - `cargo_manifest` aligns lines with an LCS diff.

  There are also ad-hoc helpers in four more files.
- **Per-backend copies:**
  - `cleanup_failed_stage` is byte-identical in cargo and gem, and one line different in composer.
  - `<eco>_service_copy` (fetch → settle → claim_prestaged-or-extract → afterHash check → swap) is repeated for cargo, composer, gem and golang.
- **Process-global memo caches:** 22 `static …: ParseMemo` across 16 files. They exist because backends are called once per package and would otherwise re-parse the same lock each time.
- **Atomic writes:** centralized in `utils/fs.rs`, but in seven variants.

### 5.5 Security: unbounded zip inflate (verified)

`vendor/common.rs:305-330 zip_bytes_match_after_hashes` decompresses archive members with **no size cap**. It also pre-allocates `Vec::with_capacity(entry.size() as usize)` from the archive's *own declared* size.

It runs on:
- committed, tamperable artifacts (the NuGet hot path, `nuget_feed.rs:266`; the committed Maven jar, `maven_repo.rs:736` and `:1464`);
- service archives (`service_fetch.rs:312`).

Its twin `vendor/mod.rs:526 capped()` explicitly guards against zip bombs with a 64 MiB cap. The codebase also has three different archive size caps: 512 MiB (`common.rs:278`), 256 MiB (`mod.rs:342`) and 128 MiB (`registry_fetch.rs:22`).

A malicious PR that commits a crafted `.nupkg` can make CI's `vendor --check` / `vex` allocate without bound. **Fix:** route every zip read through one capped reader with one cap constant.

### 5.6 Scaffolding left over from the removed local-build path

v5 removed local artifact building, but the scaffolding remains:
- `VendorSource` has one variant, and `may_use_service()`/`requires_service()` always return `true` (`mod.rs:212-237`).
- `PackageSource` has one variant.
- `SERVICE_ECOSYSTEMS` lists every ecosystem, so its refusal can never fire.
- `ServicePolicy::new(_cfg)` ignores its config, and `miss()` does `let _ = (warnings, code)`.
- `vend_installed!` exists for a "registry-fetch rung" whose function no longer exists.
- `PatchSources::mem_blobs` (`patch/apply.rs:96`) is `None` at every production construction site.
- Stale docs:
  - `args.rs:59` still lists `build` as valid;
  - `lock_inventory/mod.rs:9-12` says vendor fetches from the registry;
  - `gem.rs` refers to a `FallBack` variant that does not exist.
- `registry_fetch.rs` (1,535 lines) is now really archive extraction plus integrity checks plus the hosted-restore HTTP client. It is misnamed and misplaced.
- **`--vendor-source` accepts only `service` or its alias `auto`.** It is a user-facing flag with exactly one behavior.

**Value: negative. Delete it** (about 250 lines, near-zero risk).

### 5.7 Complexity vs value

- **JVM (7,451 production lines; ~6,300 inline tests; ~1.7K CLI e2e): two backends for one ecosystem.**
  - The legacy single-POM backend (`maven_repo.rs`) uses whole-file pom snapshots.
  - The v5 `jvm/*` handles reactor and Gradle builds and is the best-designed code in vendored mode: pure planners over a `ReadFn` that return file writes plus fragment records, with an order-independent unplan.
  - It uses three artifact roots (`.socket/vendor/maven/<uuid>`, `.socket/vendor/maven2`, `.socket/vendor/gradle`) plus `.socket/gradle/` and `gradle-index.tsv`. None of them follows the `<eco>/<uuid>` convention that `path.rs` and the orphan sweep rely on.
  - `--maven-config auto|none` is a *global* CLI flag consumed by one function.
  - **Merge the two backends** into one planner with a `Shape::Single` variant, drop the `"jvm"` alias, and make `--maven-config` a `vendor`/`scan --mode vendored` flag.
- **PyPI's seven flavors** (uv 1,775; requirements 830; pylock 678; pipenv 657; pdm 496; poetry 477; hatch 303; router 1,928 production lines).
  - Each flavor is needed for correctness, but they share no trait.
  - Poetry, pdm and pipenv together are ~1,600 production lines in vendor plus ~1,150 in utils, for what is one pattern: a lock-only per-package splice with guards.
- **Performance and durability machinery (~3K production lines):**
  - `group_commit.rs` (1,059) intercepts the `utils::fs` writers globally per root, renders values lazily via `Any`, and does three-way hand-edit reconciliation in `recover`;
  - `durability.rs` (315);
  - `prestage.rs` (425);
  - `api/vendor_prefetch.rs` (694);
  - `parse_memo` (147) plus its 22 statics;
  - `ledger_snapshots` (352).

  Almost all of it compensates for the **per-package call model**: each call re-reads, re-parses and durably re-writes the same lockfile and ledger. A batched planner API (the JVM pattern) removes the root cause.

  Writes that bypass `utils::fs` (for example `blob_fetcher.rs:471`) are silently not captured by group commit. Group commit still journals `redirect-state.json`, which has no production writer.
- **Cargo tags** (`cargo_tag.rs`, 259 lines): small and justified, because they make Cargo.lock self-describing. Keep them.
- **Cargo legacy `.cargo/config` migration** (~200 lines in `cargo.rs` plus part of `cargo_config.rs`): sunset it after a deprecation window.

### 5.8 Target design

```rust
trait VendorBackend {                       // one impl per ecosystem, listed in a static REGISTRY
    const ECO: &str;
    fn artifact_shape(&self) -> Shape;
    fn leaf_to_purl(..);
    fn wiring_files(&self, v: &ProjectView) -> Vec<String>;
    fn preflight(&self, v, pkg) -> Result<Option<PlannedDownload>, Refusal>; // = lock_text_refusal + service_preflight
    fn plan(&self, v: &ProjectView, pkgs: &[Pkg]) -> Result<Plan, Refusal>;  // pure, BATCHED
    fn materialize(&self, archive, stage) -> Result<(), String>;             // extract / tag / afterHash check
    fn in_use(&self, v, e) -> Option<bool>;
    fn recover(&self, e) -> Option<LockfileEntry>;
}
struct Plan { writes: Vec<FileWrite>, records: Vec<SpliceRecord { file, anchor, original: String, new: String }> }
```

**The engine owns:**
- reading and the `ProjectView`;
- one atomic multi-file commit;
- the ledger;
- stage/swap/cleanup;
- **one generic revert**: the existing `common.rs:722` splice algorithm, generalized. It splices `new` back to `original`, converges silently when `original` is already present, and warns on drift.

Old `kind`s are translated into `SpliceRecord`s when the ledger loads, so legacy ledgers keep reverting byte for byte. The JVM `JvmPlan`/`JvmUnplan` design is the in-repo precedent.

**Estimated saving:** about 6–8K production lines of the ~44K in this slice (15–18%), and more in tests. Per-backend conformance tests collapse into one suite; for example, `service_preflight_names_exactly_the_*_that_ask_for_a_grant` is copied into seven files.

**Risks:**
- committed ledgers are a permanent API, so the legacy-kind adapters must stay;
- byte-exact lock output per package manager must not change. The `legacy-ledgers` fixtures and the `e2e_vendor_*_build` suites are the guardrail;
- batching changes the time-of-check/time-of-use posture that `parse_memo` deliberately preserves.

### New findings since the review

- {{E59}}: vendored gem `edit_lock` searches only the first `GEM` section of `Gemfile.lock`. Bundler 2 writes one per source, so in a project with a private source that sorts first, every rubygems.org gem is refused with "GEM specs has no entry"; see 5.4.
- {{E58}}: production `pub fn`s with no production caller, orphaned by #277: `VendorEntry::committed_artifact_intact` and `go_sum_edit::remove_lines` (no reference at all), plus test-only helpers compiled into production (`cargo_tag::copy_manifest_tag`, `jvm::apply::read_project_file`). The hosted-vlt half is in Part 3.
- {{E55}}: vendored Maven decides "is this a reactor?" twice. `jvm::detect` uses the reactor's `Doc`-based `declares_modules`, which ignores plugin `<configuration><modules>`, then the legacy single-pom path re-checks with its own comment-stripping `declares_modules` and refuses `vendor_maven_multimodule_unsupported`. That refusal fires only on the disagreement, so every `maven-ear-plugin` project is refused; see 5.4.
- {{E54}}: the Poetry and PDM lock rewriters restore line endings with different rules, so a mixed-line-ending lock's edited unit becomes CRLF under Poetry and LF under PDM; see 5.4.
- {{E49}}: hosted Pipenv used to reject its own pins on path-prefixed `--patch-server-url` origins and sdists. Both private grammars (`owned_url`'s segment count, `is_socket_hosted_reference`) are deleted; Pipenv now uses `hosted_pypi_reference` (#572); see 5.4.

---
_Generated by [Claude Code](https://claude.ai/code)_
