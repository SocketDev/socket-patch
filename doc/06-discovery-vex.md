> [agent] **Part 6 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 6: Discovery, inventory and VEX

_Last checked against main @ 045d7ec on 2026-10-04 by audit-ecosystems (gem lock selection and the go.mod row re-checked). Owner: `audit-ecosystems`._

> Scope: `vex/**` (incl. `vex/discover/*`), `crawlers/**`, `formats/**`, `vendor/lock_inventory/*`, and the CLI consumers `vex.rs`, `vex_sources.rs`, `vex_consumed.rs`, `scan/discovery.rs`, `context.rs`, `list.rs`, `ecosystem_dispatch.rs`.

### 6.1 Size

| Area | Total | Production | Notes |
|---|---:|---:|---|
| `vex/` | 28,788 | ~10,040 | `discover/` alone is 8,499 production lines, 27% of them comments |
| `crawlers/` | 23,739 | 8,930 | 3,007 test-only oracle/equivalence lines; 32% of production lines are comments |
| `formats/` | 5,131 | 4,650 | |
| `vendor/lock_inventory/` | 7,605 | 3,659 | |
| CLI consumers | — | 4,798 | `vex.rs` 1,334, `vex_sources.rs` 976, `vex_consumed.rs` 596, `ecosystem_dispatch.rs` 816 |

The VEX stack is about **13K production lines tested by about 59K test lines**: ~11K of core crawler tests and ~40K of CLI `*vex*` end-to-end tests.

### 6.2 Four discovery systems

| System | Entry point | Reads | Returns |
|---|---|---|---|
| **A. Crawlers** | `crawl_every_ecosystem` (`ecosystem_dispatch.rs:719-815`); nine crawlers in a `tokio::join!` | installed trees (`node_modules`, `site-packages`, `vendor/composer/installed.json`) **and whole machine caches**: `$CARGO_HOME/registry/src`, `GOMODCACHE`, `~/.m2`, `~/.nuget/packages`, `DENO_DIR` | `CrawledPackage {name, version, namespace, purl, path}` |
| **B. Lock inventory** | `inventory_project_diagnosed_in` / `union_views_in` (`lock_inventory/mod.rs:320-370`) | one lockfile per ecosystem, chosen by precedence (shrinkwrap wins; uv is exclusive; poetry → pdm → Pipfile). **No Maven, NuGet or Deno.** | `LockfileEntry {ecosystem: &'static str, name, version, purl, resolved, integrity, source_kind}` |
| **C. Wiring discovery** | `discover_with_ctx` (`vex/discover/mod.rs:725-745`); 13 extractors in fixed order, then `contest_across_locks` | **every** lock/config present ("rule 1: never apply precedence"), each swept for Socket identities | `Discovery {refs: Vec<PatchedRef>, diagnostics, recognized, unlocked_pins, elsewhere}` |
| **D. Vendor-ledger supplement** | `vendored_ledger_supplement` (`scan/discovery.rs:141`) | `.socket/vendor/state.json` + artifacts | fabricated `CrawledPackage`s |

How `scan` combines them (`scan/mod.rs:1589-1660`):
1. **Crawl first, in every mode.**
2. Append lockfile-only entries as fabricated `CrawledPackage`s. `crawled_from_purl` (`discovery.rs:113-133`) sets `path: cwd.join("node_modules").join(name_part)` **for every ecosystem**, including cargo and pypi.
3. Append ledger-only entries.
4. Fold hosted pins from C into update detection.

**Overlaps:**
- B and C walk the same per-format entries. B keeps registry entries; C classifies the Socket-owned ones *and* emits `ResolvedElsewhere`, which is a second registry view.
- Liveness then calls B a **third** time, straight from disk (`inventory_project_every_lock(root)`, `mod.rs:1602`), bypassing the shared `DiskSnapshot`.
- B has two parallel modes, `Instances::Every` and `Instances::Collapsed`, with an if/else for every format.
- A is unrelated to B and C.

**This could be one pass**, because the per-format parsers are already mostly shared. What is duplicated is the *classification and selection layer*. One model would replace all of them:

```rust
struct Instance {
    purl: CanonicalPurl,
    declared_in: Option<Rel>,
    resolution: Registry { url, integrity, source_kind }
              | Hosted { uuid, url, integrity, required }
              | Vendored { uuid, artifact_rel, integrity }
              | Other,
    installed_at: Vec<PathBuf>,   // filled in by locators (ex-crawlers)
}
```

From that model:
- `LockfileEntry` is the Registry instances, filtered by precedence and deduplicated;
- `PatchedRef` and `HostedPin` are the Hosted and Vendored instances;
- `ResolvedElsewhere` is the Registry and Other instances;
- the scan supplement is instances with an empty `installed_at`, which removes the fake `node_modules` path.

`formats/mod.rs:1-25` already documents this target (`entries()`, `wired_refs()`, `plan_hosted()`), but `entries()` exists only for composer, pnpm, gem and cargo, and `wired_refs()` only for pnpm.

### 6.3 Format × subsystem matrix (abridged)

| Format | Shared read model | Writers with their own walk |
|---|---|---|
| package-lock | `lock_inventory::npm_lock_nodes` | vendored `scan_lock_matches`, hosted `mod.rs:837`, upstream `npm_lock_hits` |
| Pipfile.lock | `lock_inventory::pypi::pipfile_lock_entries` | vendored `pypi_pipenv.rs` (×3), hosted `redirect/pipenv.rs:98`; the crawler re-implements Pipenv venv hashing |
| Cargo.toml | — | hand-rolled **twice** (`cargo_crawler.rs:21`, `vex/product.rs:167/380`) despite `toml_edit` |
| go.mod | `go_mod_edit` | `module` directive parsed again at `product.rs:175` and in `go_crawler.rs:63` (no production caller); both misread the block form `module ( … )` {{E19}} |
| NuGet | `formats::nuget::parse_open_tag` | vendored has its own XML scanner. The crawler reads `obj/project.assets.json` **only for `packageFolders`**, never `libraries`/`targets`, then enumerates the global `~/.nuget/packages` |
| Maven | `formats::maven::parse_pom` | vendored `jvm/maven_reactor.rs` `Doc::parse` and `gradle.rs`; hosted's own tag scanner; the crawler's own XML parser; `product.rs` again |

Across the repo that is **eight hand-rolled XML scanners**, 4–5 independent walks of package-lock `packages`, and 3 of Pipfile.lock categories.

### 6.4 Recurring helpers (confirmed)

- **`utils/purl.rs` contains two purl-builder families.**
  - The unchecked `build_{gem,maven,golang,composer,jsr,nuget,cargo}_purl`, used by crawlers and `vendor/*`.
  - The validating `npm_purl`, `pypi_purl`, `simple_purl`, `golang_purl`, `composer_purl` and `maven_purl`, used by inventory and VEX.
  - On top of those: `build_npm_purl` in `npm_crawler.rs`, 13 inline `format!("pkg:…")` in `product.rs`, and **78 hand-built purl strings outside `purl.rs`** in total.
- **The crawlers re-implement the validators.** `is_safe_cargo_coordinate`, `is_safe_gem_coordinate` and `is_safe_nuget_coordinate` have byte-identical bodies and equal `simple_purl`'s check; `utils::purl::maven_purl` and `vendor/maven_repo.rs` import `crawlers::maven_crawler::is_safe_maven_coordinate`. {{E37}}
- **`composer_crawler::normalize_version`** behaves exactly like `utils/composer_version::strip_leading_v`, and `formats::composer` and `upstream::composer` import the crawler copy (a `formats` → `crawlers` edge). {{E37}}
- **Layering inversion.** `canonicalize_pypi_name` lives in `crawlers/python_crawler.rs` and is imported by **29 files**, including `lock_inventory`, `vex::discover`, `utils::purl` and `patch::redirect`. `Ecosystem` itself lives in `crawlers/types.rs`, while `LockfileEntry.ecosystem` is a string tag beside it.
- **The product-manifest probe table is copied three times, and has drifted.** `vex.rs:1118 PRODUCT_MANIFESTS` copies `product.rs:80-87` but lacks the csproj and gemspec probes. The `--product` help text is a third copy.
- **Test RNG.** xorshift is implemented four times.

**Dead code:**
- `lock_inventory/wired.rs` (`wired_vendor_integrity`, 221 production lines) has **no production caller** (verified); only tests use it. That matches the v5 migration note "`repair` no longer reconstructs a missing ledger from lockfiles". The module docs at `lock_inventory/mod.rs:13-15` are stale.
- `vex/discover/deno.rs` is an empty extractor.

### 6.5 VEX design

- **`verify.rs` is small** (346 production lines): a hash check per record, the vendored artifact basis, and `HostedCopies`. The complexity lives elsewhere:
  - **`vex_sources.rs`** (976) merges five sources: manifest, vendor ledger, *legacy* redirect ledger, discovery refs and API-fetched records. It has 5 omission gates, 7 note codes and 3 `Basis` kinds.
  - **`vex_consumed.rs`** (596) decides "which installed copy the hosted build consumes". That covers cargo registry host-hash matching, Maven `-socket.<hex8>` dirs, the Go replacement module, and npm alias and store variants. **This is a third copy of package-manager layout knowledge** (after the crawlers and `vendor/*`), and it lives in the CLI.
  - **Discovery liveness** (`discover/mod.rs:1490-1990`, ~500 lines), including the raw-text fallbacks `vendored_wiring_in_files` and `hosted_wiring_in_files`.
- **`product.rs`** (659 production lines) only auto-detects the top-level product purl:
  - ~200 lines parse the git `origin` remote;
  - 8 manifest probes each have their own parser, and none reuses `formats::maven`, `toml_edit` or `go_mod_edit`;
  - `--product` overrides the result anyway.
- **"Wired" vs "consumed" evidence.**
  - *Wired* means a lockfile pin on an allowlisted host plus an integrity pin. `lockfile_basis_ok` lets an attestation stand with no installed bytes.
  - *Consumed* means hashing the installed copy that the wiring routes to.
  - **This is where the 16 open "VEX attests not_affected while unpatched" bugs come from.** The wired basis assumes the package manager honors the pin. Every package-manager quirk that breaks that assumption becomes a false attestation:
    - warm caches (#352);
    - a `go.work` override (#393);
    - Bun's isolated linker (#405);
    - `deno.lock` (#406);
    - `--system-site-packages` (#409);
    - Gradle locking (#396);
    - Maven mirrors (#263).
  - See the appendix for the architectural fix.
- **Standalone vs embedded `--vex`.** Generation is shared: apply, vendor and scan call the same `generate_vex_*` functions. Two problems remain:
  - Embedded runs inject bypass sets (`assume_applied`, `known_stale`, `hosted_records`, `npm_prior`), which couples VEX correctness to each caller.
  - The rendering glue is duplicated per command: dry-run skip, JSON folding, "nothing to attest", exit codes. It appears in `scan/mod.rs:360-470` and `apply.rs:790-860`, and in three variants inside `vendor.rs`.
- **Low-value paths:**
  - The pre-v5 redirect-ledger path. No command writes it (`state.rs:148`: "socket-patch v5 never writes this file"), yet it still drives `redirect_record_live`/`LedgerLiveness`, `hosted_wiring_in_files` and `HostedFileRole` (~430 lines), plus the CLI-side handling.
  - **Naming:** `vex::discover` is really the v5 *hosted-state store*. Scan, get, apply, vendor, rollback, list and core hosted rollback all use it. It is not VEX-specific.

### 6.6 Crawlers

- **Oracles.** The npm "oracle" is the pre-parallel crawler, "kept verbatim as the equivalence oracle" (1,846 lines, test-only). Six more oracles plus `oracle_support.rs` and `maven_pom_equivalence_tests.rs` bring this to 3,007 lines. The parallel walk has shipped, so retire them.
- **`walk_pool.rs`** (338 production lines) adds a rayon pool with an fd budget, an 8 MiB stack, a 16-thread ceiling and a performance-core probe. It is justified by its benchmark table, but sized for npm only.
- **Global mode** (`--global`/`--global-prefix`) adds a branch to every crawler. The npm/yarn/pnpm/bun global-prefix probes alone are ~240 lines of subprocess spawning.
- **Python environment discovery** is ~1,060 of `python_crawler.rs`'s 1,616 production lines:
  - `VIRTUAL_ENV`, `.venv`, `venv` and nested venvs;
  - pyenv, conda, Homebrew and uv tools;
  - re-implementations of **Poetry's and Pipenv's venv-name hashing**;
  - a **fallback to global site-packages** when no venv exists.

  The open issues #327, #329, #334 and #384 are all this re-implementation diverging from the real tools. Asking the tool instead (`poetry env info -p`, `pipenv --venv`, `uv python find`) is cheaper and correct by construction.
- **Cache crawls are not project-scoped.** In local mode, cargo, go, maven, nuget and deno enumerate the **entire machine cache** as soon as a marker file exists (`cargo_crawler.rs:144-183`, `go_crawler.rs:133-158`, `maven_crawler.rs:565-607`, `nuget_crawler.rs:37-90`, `deno_crawler.rs:65-81`). Scan then sends all of it to the API. {{E05}}
  - Hosted mode can only act on lock entries, so the rest becomes "unconfirmed" noise.
  - For Maven and NuGet this crawl is the *only* discovery. Issue #265 ("Maven hosted scan pins, and VEX attests, artifacts the project doesn't depend on, because the crawler lists all of `~/.m2`") is this bug.
- **FIFO safety.** Three project-tree reads predate the FIFO-safe read discipline and hang on a planted FIFO (verified by execution): `nuget_crawler.rs:506` (`obj/project.assets.json`) and the cargo `vendor/<crate>/Cargo.toml` reads at `cargo_crawler.rs:289` and `:401`. The Python `.venv` read is guarded by `is_file()`. {{E06}}

**Are crawlers needed in hosted and vendored modes? Only as *locators*, not enumerators.**
- **Vendored:** artifacts come from the service ("backends never construct an archive locally"); the installed tree is an "optional installed location used for identity and release-variant probes".
- **Hosted:** it needs `get_site_packages_paths` / `get_gem_paths` for stale-install probes and copy lookups for VEX. Candidate discovery should be inventory-driven.
- **Enumeration (`crawl_all`)** is genuinely needed only for agent mode, `--global`, `get <name>`, and projects with no lockfile.

### 6.7 Target layout

```
core/src/ecosystem.rs       Ecosystem + tag/cli/purl-type maps (from crawlers/types.rs, vendor/path.rs)
core/src/purl/              ONE validating builder set; pep503 name; composer identity; go case-encoding
core/src/formats/<fmt>/     pure model per lock/manifest: parse → entries() (with key/pointer + resolution) → plan_hosted / plan_vendored / restore
core/src/inventory/         Inventory { instances, diagnostics, recognized, unlocked_pins }
    read.rs                 file selection over ProjectView + guarded reads + identity sweep
    classify.rs             Registry | Hosted | Vendored | Other
    views.rs                registry_view (= LockfileEntry), wiring_view (= PatchedRef/HostedPin), contest, liveness
core/src/locate/            ex-crawlers: per-ecosystem find(purl) incl. "consumed copy" rules (from vex_consumed.rs);
                            enumerate() only for project trees / --global; env/ (python, ruby, npm-global)
core/src/vex/               schema, build, time, verify, product (reusing formats)
cli: ProjectContext owns ONE Inventory; one EmbeddedVex helper
```

**Risks.** Discovery is fail-closed, security-sensitive code. The golden snapshots and the ~40K lines of end-to-end tests are the safety net, so migrate one format at a time behind them. The `CLI_CONTRACT` warning codes must not change. Scoping the cache crawls changes output for lockless cargo, Gradle and NuGet projects, so keep a fallback flag for those.

### New findings since the review

- Three rules pick the live Bundler lock: hosted, vendored and the crawler use `LoadedManifest::pair` (`gems.rb` → `gems.locked`); lock inventory reads only `Gemfile.lock`; VEX discovery reads both. A `gems.rb` project is invisible to the inventory (scan supplement, in-memory hosted engine, VEX liveness), and a stale `Gemfile.lock` twin is read instead. {{E56}}

---
_Generated by [Claude Code](https://claude.ai/code)_
