> [agent] **Part 5 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 5: Vendored mode and the non-JS backends

_Last checked against main @ 9c43dfc on 2026-10-06 by audit-ecosystems (5.2 dead `force`/`sources` parameters re-checked at `9c43dfc`; per-backend service-copy and cleanup copies re-checked at `9c43dfc`; 5.4 NuGet, Poetry/PDM and Gem re-checked at `4646693`; as of `045d7ec`: 5.4 Python, Cargo, Maven XML, Gem, Go and CRLF helpers; 5.6 scaffolding; the vendored-reference scan behind repair and the orphan sweeps). Owner: audit-ecosystems._

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
- every backend now discards `sources` and `force` at its acquisition sink (10 `_sources`/`_force` parameters, since acquisition went service-only), so `vendor --force` only bypasses the CLI variant probe, although its help and `CLI_CONTRACT.md` still promise missing-file tolerance. {{E65}}

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
- The vendored NuGet writer (`nuget_feed.rs`) never uses the shared reader `formats::nuget::parse_config`, **so its reader and writer can disagree about what a file contains**. The hosted splicer now uses it (#597). {{E11}}
- `pom.xml` alone has seven scanners (checked on `045d7ec`): `formats::maven::parse_pom` (VEX, restore gate); the hosted rewriter's raw regex (`MAVEN_DEPENDENCY_BLOCK_RE`, `insert_maven_*`), which upstream restore reuses and which masks nothing; vendored `maven_repo.rs` (`comment_spans`/`profiles_spans`, plus a second `declares_modules`); the reactor's `mask` + `Doc` tree and, in the same file, `scan_pom_project` (a depscan port); and the crawler's and `vex/product.rs`'s own readers. None of the three writers (hosted, restore, vendored single-pom) locates elements through a reader. Target: one masked element tree in `formats::maven` that readers and splicing writers both query. {{E10}}
- The Maven share of the open backlog is mostly this: #259 "edits commented-out, plugin and profile markup", #342 "adds a second section when the existing one is self-closed or has a comment", #683 (`<exclusions>` first) and {{E55}}.

**Python:**
- `utils/poetry_lock.rs` and `utils/pdm_lock.rs` now share one fragment-splice engine, [`utils/lock_fragments.rs`](https://github.com/SocketDev/socket-patch/blob/4646693150cf5efca6222b87092e1620e58566f8/crates/socket-patch-core/src/utils/lock_fragments.rs) (344 lines: the parse holder, pairing, splicing and one `majority_terminator` line-ending rule). Only the per-format fragment ownership and refusals stay in each file (#703). {{E13}} {{E54}}
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

**Gem:** `vendor/gem.rs` imports three token helpers from `formats::gem` and keeps its own section model: `section_span` / `section_end` for DEPENDENCIES and CHECKSUMS, plus [`gem_section_spans` / `record_gem_section`](https://github.com/SocketDev/socket-patch/blob/4646693150cf5efca6222b87092e1620e58566f8/crates/socket-patch-core/src/vendor/gem.rs#L1947-L1975), added by #805. With `formats::gem::parse` and hosted's `GemLockSection`, that makes three section models and three DEPENDENCIES-name parsers; the name rules agree on Bundler-written entries. {{E19}}
  - The models had drifted: vendored `edit_lock` looked only in the first `GEM` section, so a gem from a later source was refused. It now searches every GEM section, and refuses a spec listed in two (#805). {{E59}}

**Go:** `go_mod_edit.rs` is properly shared (VEX `--product` now included) but lives under `vendor/`. Since #870 the go.mod `module` directive has one reader, `go_mod_edit::module_path`, built on the same directive walker as `require` and `replace` (block form included); the crawler's dead `parse_go_mod_module` is gone. {{E19}}

**Small helpers:**
- **CRLF:** four policies for the same "`toml_edit` emits LF" problem:
  - `line_endings` refuses mixed files;
  - `python_lock` converts CRLF-only files and leaves mixed files as LF;
  - `utils/lock_fragments` (Poetry and PDM) re-terminates spliced lines with `majority_terminator` (#703) {{E54}};
  - `cargo_manifest` aligns lines with an LCS diff.

  There are also ad-hoc helpers in four more files: on main, `common::detect_eol`, `pypi_uv::newline_of` and `gradle::newline_of` (a different, first-line rule under the same name), plus inline any-CRLF copies in `maven_reactor.rs` (×2) and `pypi_pipenv.rs`. One classifier is the target. {{E16}}
- **Per-backend copies:**
  - `cleanup_failed_stage` is byte-identical in cargo and gem, and one line different in composer; golang has its own `cleanup_failed_service_stage`.
  - `<eco>_service_copy` (fetch → settle → claim_prestaged-or-extract → afterHash check → swap) is repeated for cargo, composer, gem and golang (`go_service_redirect`): about 500 lines, with the layout-mismatch message spelled four times. No drift proven yet. {{E25}}
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
- `VendorSource` has one variant, and `may_use_service()`/`requires_service()` always return `true` (`mod.rs:212-237`). Deleting the predicates is #746 (audit-core C23).
- `PackageSource` has one variant, but 53 production references across 19 files take `impl Into<PackageSource>` only to call `.path()`. One of them is `redirect/golang_local.rs`, which adds a `redirect` → `vendor` import. {{E28}}
- `SERVICE_ECOSYSTEMS` lists every name `ecosystem_dir_for_purl` can return, so its `vendor_service_unsupported_ecosystem` refusal can never fire. The code's only test asserts its absence. {{E28}}
- `ServicePolicy::new(_cfg)` ignores its config, and `miss()` does `let _ = (warnings, code)`.
- `vend_installed!` exists for a "registry-fetch rung" whose function no longer exists. Its `debug_assert!` matches the only `PackageSource` variant, so it always holds. {{E28}}
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

**Estimated saving:** about 6–8K production lines of the ~44K in this slice (15–18%), and more in tests. Per-backend conformance tests collapse into one suite; for example, `service_preflight_names_exactly_the_*_that_ask_for_a_grant` is copied into seven files, though its body now shares `test_support::plan_matches_grants`, so only the fixture remains per backend.

**Risks:**
- committed ledgers are a permanent API, so the legacy-kind adapters must stay;
- byte-exact lock output per package manager must not change. The `legacy-ledgers` fixtures and the `e2e_vendor_*_build` suites are the guardrail;
- batching changes the time-of-check/time-of-use posture that `parse_memo` deliberately preserves.

### New findings since the review

- {{E65}}: `vendor --force` documents a missing-file tolerance and a `vendor_content_mismatch_overwritten` warning that no backend implements; every acquisition sink takes `_force`/`_sources`, and `vendor` with and without `--force` behave the same (executed twice). Bears on #615; see 5.2.
- {{E61}}: the vendored-reference scan behind `repair`, the `vendor` stranded-reference gate and the orphan sweeps never sees NuGet or Maven wiring. `nuget.config` and `pom.xml` lack the `VENDORED` registry role, and both backends reference the bare uuid directory, which `parse_vendor_path` rejects (it needs a leaf). So with a missing ledger entry, `vendor --revert` and the vendored gc delete a feed or repository that `nuget.config` / `pom.xml` still name (proven by execution). The `eco == "maven2"` arm of the stranded-reference gate is dead.
- {{E59}}: vendored gem `edit_lock` searched only the first `GEM` section of `Gemfile.lock`, so a gem from a later source was refused; fixed by #805; see 5.4.
- {{E58}}: production `pub fn`s with no production caller, orphaned by #277: `VendorEntry::committed_artifact_intact` and `go_sum_edit::remove_lines` (no reference at all), plus test-only helpers compiled into production (`cargo_tag::copy_manifest_tag`, `jvm::apply::read_project_file`). The hosted-vlt half is in Part 3.
- {{E55}}: vendored Maven decides "is this a reactor?" twice. `jvm::detect` uses the reactor's `Doc`-based `declares_modules`, which ignores plugin `<configuration><modules>`, then the legacy single-pom path re-checks with its own comment-stripping `declares_modules` and refuses `vendor_maven_multimodule_unsupported`. That refusal fires only on the disagreement, so every `maven-ear-plugin` project is refused; see 5.4.
- {{E54}}: the Poetry and PDM lock rewriters restored line endings with different rules; they now share `lock_fragments` and its majority rule (#703); see 5.4.
- {{E49}}: hosted Pipenv used to reject its own pins on path-prefixed `--patch-server-url` origins and sdists. Both private grammars (`owned_url`'s segment count, `is_socket_hosted_reference`) are deleted; Pipenv now uses `hosted_pypi_reference` (#572); see 5.4.

---
_Generated by [Claude Code](https://claude.ai/code)_
