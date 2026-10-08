> [agent] **Part 4 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 4: JavaScript lockfiles (npm, pnpm, yarn, bun, vlt)

_Last checked against main @ e2d9633 on 2026-10-08 by audit-ecosystems (4.1 `formats/yarn` contents and the 4.3 yarn rows after #1057). Earlier: `ea09714` on 2026-10-08 by audit-ecosystems (the governing-lock passage after #1044 only). Earlier: `431b818` on 2026-10-07 by the October 7 reconciliation (`formats/yarn` contents, the governing-lock count, the pnpm-legacy row and the yarn grammar copies re-checked; sizes and line references in 4.1–4.4 are still from the snapshot and drift by 200–1,000 lines). Earlier: `9c43dfc` by audit-ecosystems (vendor driver skeleton re-checked at `9c43dfc`; pnpm BOM handling in `formats::pnpm` re-checked at `9c43dfc`; §4.4 vendored pnpm `package.json` writer re-checked at `4646693`; as of `045d7ec`: pnpm, berry gates, package-lock walks, JSON writers, bun-lock presence, CRLF policies, wiring-kind and lines↔JSON helpers and the 4.5 #2 layering re-checked; the rest is as of `2463257`). Owner: `audit-ecosystems`._

> Scope: `vendor/{npm_*,pnpm_*,yarn_*,bun_*,vlt_*,berry_zip}.rs`, `formats/{pnpm,yarn,bun,registry}`, `crawlers/npm_crawler*`, `vendor/lock_inventory/*`, `vex/discover/{npm,yarn,bun,vlt}.rs`, and the JS parts of `patch/redirect/` and `hosted/vlt.rs`. Line counts are production / inline-test, split at the first top-level `#[cfg(test)] mod`.

### 4.1 Summary

- **The read side is mostly consolidated; the write side is not.** VEX discovery and lock inventory already share one entry walk per format: `npm_lock_nodes`, `formats::pnpm::pnpm_packages`, `classic_entries`/`berry_entries`, `BunTextLock`, `BunLockb::parse_packages` and `vlt_lock_model`. The writers are separate: the hosted rewriter, the hosted upstream restore and the vendored backend each still have their own splicer for package-lock, pnpm and yarn.
- **There is no lockfile abstraction.** The only lockfile trait in this area is a private `EditLines` (`vendor/pnpm_lock.rs:2295`). Each mode dispatches its own way:
  - Vendored mode switches on a 7-variant `NpmLockFlavor` enum in six separate `match` blocks (`npm_flavor.rs:59, :75, :383, :485, :591, :691`). On top of that sits a `vend!` macro (`:367-382`), which exists because nine-argument functions have no trait to attach to.
  - Hosted mode runs every rewriter in a fixed chain (`patch/redirect/mod.rs:435-439`).
  - VEX calls every extractor in turn (`vex/discover/mod.rs:727-730`).
- **`formats/` is a half-finished migration.** Its module doc promises each format owns "the entry grammar, the key rules, the version sniff and the planners" (`formats/mod.rs:1-24`). Reality:
  - pnpm partly conforms.
  - `formats/yarn` now holds every yarn.lock grammar (~1.8K lines at `e2d9633`): the version sniff and the one grammar decision (`grammar`), the classic/berry block walk (`blocks.rs`), key and descriptor patterns, the copy-source classifier (`source.rs`), the berry stanza view the hosted re-keying writers use (`stanzas.rs`), the berry entry reader and the berry gates (#657). The seven `split("\n\n")` writer grammars were deleted (#1057). {{E08}}
  - `formats/bun` is a 49-line wrapper around `vendor::bun_lock_text`.
  - package-lock and vlt have no `formats` module at all.
- **Legacy and rare formats are the cost centers.** Vendored pnpm-legacy, `bun.lockb` and vlt together are about 11.2K production lines and more than 15K inline-test lines, with roughly 10K more lines of CLI integration tests.

### 4.2 Code per format

| Format | Main files (prod/test) | Prod | Inline tests | CLI test files |
|---|---|---:|---:|---:|
| package-lock | `npm_lock.rs` 1291/3230; redirect §745-1049 (305); `upstream/npm.rs` 21-240 (~220); `lock_inventory/npm.rs` 155; `vex/discover/npm.rs` 57-301 (~245) | ~2.2K | 3.2K+ | — |
| pnpm v9 + hosted (all generations) | `pnpm_lock.rs` 3174/5341; `formats/pnpm` 1431/85; `lock_inventory/pnpm.rs` 151; upstream 478-583; vex 302-491 | ~5.0K | 5.4K + 544 equivalence | 6.1K (all pnpm) |
| **pnpm legacy (5.4/6.0, vendored)** | `pnpm_lock_legacy.rs` (thin dialect wrappers over `pnpm_lock.rs` since #583; 4,918 lines with tests at `431b818`) | **1,853** at the snapshot | **3,217** | (in 6.1K) |
| yarn classic | `yarn_classic_lock.rs` 1099/1916; redirect §2952-3140 (189); upstream 241-364 | ~1.8K | 1.9K+ | 7.3K (yarn total) |
| yarn berry | `yarn_berry_lock.rs` 1417/2723; redirect §3141-3510 (370); upstream 365-477 | ~2.3K | 2.7K + 1,061 layering | (in 7.3K) |
| bun.lock (text) | `bun_lock.rs` 1033/2838; `bun_lock_text.rs` 275/245; redirect §3511-3768 (258); upstream 584-686 | ~1.7K | 3.1K | 6.6K |
| **bun.lockb (binary)** | `bun_lockb.rs` 1663/591; `bun_binary.rs` 664/351; `bun_workspace.rs` 184/199; `redirect/bun_binary.rs` 108/61; `upstream/bun_lockb.rs` 152/229 | **2,771** | **1,431** | 1,574 |
| **vlt** | `vlt_lock.rs` 2080/2032; `vlt_lock_text.rs` 1008/1540; `npm_dir.rs` 910/319; `redirect/vlt.rs` 676/313; `vlt_heal.rs` 542/573; `vlt_preflight.rs` 233/302; `hosted/vlt.rs` 217; `upstream/vlt.rs` 328/268; inventory 165; vex 392/794 | **6,551** | **6,141** | ~9.3K (10 files + 3 shared dirs) |

Shared npm-family infrastructure adds `npm_common.rs` 613/832, `npm_flavor.rs` 707/1338 and about 1.8K lines in `lock_inventory/{mod,view,wired,recover,npm_family}`.

`crawlers/npm_crawler/oracle.rs` (1,846 lines) is **entirely test code**: a verbatim copy of the old crawler, kept as an equivalence oracle (`oracle.rs:1-5`). It has done its job and can be retired.

### 4.3 Parser and splicer matrix

| Format | Vendored writer | Hosted writer | Hosted restore | Inventory + VEX | `recover.rs` | Independent parsers |
|---|---|---|---|---|---|---|
| package-lock | `scan_lock_matches` :854, `rewrite_legacy_tree` :978 (serde `Value`, rendered with `JsonLayout` since #357) | `rewrite_one_npm_lock` :881, `rewrite_npm_v2_deps` :1095 (`serialize_json_like` → `JsonLayout`, #357) | `npm_lock_hits` :62, `v2_hits` :98 | `npm_lock_nodes` | full-object original :307 | **4 entry walks** {{E07}} |
| pnpm | `formats/pnpm/lines.rs` (`Vec<String>`, **refuses CRLF**) + own `LockIndex`/memo (446 lines) | `formats/pnpm/hosted.rs::plan_hosted` over `grammar.rs` (byte offsets, CRLF-aware) | `grammar.rs` | `grammar.rs` | shared | **2 grammars; 3 `resolution:` emitters** (`grammar.rs:164`, `pnpm_lock.rs:1992`, `pnpm_lock_legacy.rs:1137`) |
| yarn classic | `formats::yarn::blocks` (`scan_blocks`, `repin_classic_block`) | same, spliced per block (#1057) | same | `scan_blocks` | ad-hoc `strip_prefix("integrity ")` | **1 block parser + 1 ad-hoc** |
| yarn berry | `scan_blocks` + `berry_field` | `formats::yarn::stanzas` (re-keys and re-sorts entries) | `stanzas` | `berry_entries` | `inline_yaml_field` | **2 views of one grammar module + 1 ad-hoc; gates shared (#657)** |
| bun.lock | `bun_lock_text` | same | same | same | `split('"')` | 1 codec (good) + 1 ad-hoc |
| bun.lockb | `bun_lockb.rs` | same | same | same | snapshot JSON | 1 codec (good) |
| vlt-lock.json | `vlt_lock_text` | same | same | same | `parse_node_entry_text` | 1 codec (good) |

The question "which lockfile drives installs?" was answered in **at least eight places** with different rules (the five below, plus `vlt_drives` with `SIBLING_LOCKS`, the bun presence probes and the PyPI precedence). Since #1044, the npm-family precedence and the PyPI tool-lock order come from one `formats::governing_locks` table, and the in-memory router copy (item 2) is deleted. Outside the table remain: agent-mode `pkg_managers` (item 5, which answers "who installed `node_modules`"), the bun presence probes ({{E17}}), the lock inventory's own PyPI order ({{E91}}), and hosted `pdm_drives` ignoring standalone pylock. #612 is now a warning; the takeover restore scope is still open. {{E75}}
1. `vendor/npm_flavor.rs:151-300`.
2. A hand-written copy for in-memory projects, `detect_npm_lock_flavor_in` (`lock_inventory/view.rs:360-447`). It re-spells the refusal strings, never emits `vendor_multiple_lockfiles`, and lacks the pnpm-PnP carve-out.
3. `LOCKFILE_FAMILIES` (`npm_flavor.rs:98`).
4. A hard-coded sibling-lock list in `redirect/mod.rs:776-787` that bypasses `formats::registry`.
5. Layout-based detection in `crawlers/pkg_managers.rs:96`, with a different precedence.

**The modes disagree on policy.** Vendored mode picks one flavor and warns about the rest. Hosted mode runs all five npm-family rewriters over every lock present. A repo with both `yarn.lock` and `package-lock.json` therefore gets both rewritten in hosted mode but only `yarn.lock` in vendored mode.

### 4.4 Verified duplication

**pnpm v9 vs pnpm legacy.** The drivers are now shared (#583): `vendor_pnpm_legacy` and `revert_pnpm_legacy_opts` are thin wrappers over `pnpm_lock::vendor_pnpm_dialect` / `revert_pnpm_dialect` with `PnpmDialect::Legacy` ([`pnpm_lock_legacy.rs#L200-L223`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/vendor/pnpm_lock_legacy.rs#L200-L223), [`#L894-L900`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/vendor/pnpm_lock_legacy.rs#L894-L900)), and `KIND_LOCK_PACKAGE` is imported, not redefined. What stays per dialect is the legacy line grammar: `read_lock`, `preflight_package(s)`, `lock_has_target_package`, `edit_*_v54/v60`, `revert_lock_record` and the `Ctx` methods. {{E12}}

**The vendor driver skeleton is copied seven times.** npm_lock, pnpm (both dialects since #583), yarn-berry, yarn-classic, bun_lock, bun_binary and vlt (about 1,940 lines) all repeat the same sequence:
`guard_coordinates` → read the lock → preflight → `stage_patch_pack` (`stage_patch_dir` for vlt) → `already_patched_result` → `write_marker_or_warn` → a literal 20-field `VendorEntry { … pdm: None, pipenv: None, poetry: None, uv: None, … }`.
The copies have drifted: the "patch rewrites `package.json`" warning has two codes (`vendor_dep_manifest_rewritten` vs `_stale`) and fires on in-sync re-runs for pnpm and bun only, and `bun_binary` computes its own `uuid_dir_preexisted`. `read_project`, `preflight_package(s)` and `revert_*_opts` exist in 7-9 files each. {{E22}}

**Yarn berry project gates are written twice.** {{E09}}
- cacheKey `10c0` appears as `SUPPORTED_CACHE_KEY` ([`yarn_berry_lock.rs#L89`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/vendor/yarn_berry_lock.rs#L89)) and as `YARN_BERRY_SUPPORTED_CACHE_KEY` ([`redirect/mod.rs#L3289`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/patch/redirect/mod.rs#L3287-L3289)).
- cacheKey extraction exists as `berry_metadata` + `berry_field` and as `berry_cache_key` (split-based, [`#L3291-L3306`](https://github.com/SocketDev/socket-patch/blob/045d7ec783d788bf3c5a1310724b51e09fb6505d/crates/socket-patch-core/src/patch/redirect/mod.rs#L3291-L3306)). The latter's own comment says it is "mirroring the vendored backend's `berry_field`".
- The gate drivers are implemented twice (`yarn_berry_lock.rs:1001-1103` vs `preflight_yarn_berry_hosted`, `redirect/mod.rs:3355-3398`), with per-mode codes and differently worded details. Only the `.yarnrc.yml` reader `yarnrc_compression_level` is shared, so #370 was fixed once (#508); hosted imports it from `vendor/`.
- The copies have drifted: vendored refuses a mixed-EOL root `package.json` and an unreadable `.yarnrc.yml`, while hosted checks only `yarn.lock` and treats an unreadable `.yarnrc.yml` as absent. {{E09}}

**Small helpers that have already drifted apart:**
- **JSON-pointer escape:** byte-identical `escape_json_pointer_token` (`npm_lock.rs:1022`) and `json_pointer_escape` (`upstream/npm.rs:136`).
- **JSON re-serialization, three strategies:**
  - `common::JsonLayout`: keeps BOM, indent, EOL and trailer. Every package-lock writer (vendored, hosted, restore) and the npm and berry `package.json` writers use it since #357.
  - `common::serialize_json(indent)`: detected indent, always LF, no BOM. Vendored pnpm's root `package.json` no longer uses it: it is written through `JsonLayout`, so CRLF and BOM survive vendor and revert (#810). {{E53}}
  - `redirect::serialize_json`: fixed 2-space, LF; now used only for NuGet `packages.lock.json` (hosted and restore).
- **Wiring lines ↔ JSON:** two identical encoders (`yarn_classic_lock::lines_to_json`, `pnpm_lock::lines_value`) and three decoders that have drifted: yarn's `json_to_lines` refuses a non-string element, while `pnpm_lock::value_lines` and `recover::lines_of` silently drop it. {{E18}}
- **sha512 SRI formatting** is inlined at `npm_pack.rs:27`, `bun_lock.rs:388` and `vlt_preflight.rs:70`. `utils/digest.rs` has no SRI helper.
- **npm tarball URLs:** the canonical `registry_fetch::npm_tarball_url` is re-implemented only at `bun_lockb.rs:235`, which writes format-1 lock semantics, not a fetch URL. vlt inventory uses the canonical helper, and the second `NPM_REGISTRY` constant is gone (#574). {{E02}}
- **vlt `registry_base`:** one shared `vlt_lock_text::registry_base` serves lock inventory and hosted restore. It follows vlt 1.3.5 DepID hydration (scoped registries; `~~` as the `npm` alias); the two private copies were deleted (#574). {{E03}}
- **"Is a bun lock present":** seven sites with three semantics. lstat (`lock_inventory/bun.rs::bun_text_lock_present`, which also feeds the GC in-use probe, and VEX `DiscoverCtx::exists`) treats a dangling `bun.lock` symlink as present; `Path::exists` (`hosted/engine.rs::bun_lock_present`, `bun_lock.rs::binary_lock_drives`, `bun_workspace.rs`, CLI `repair.rs`) and `is_file` (`pkg_managers.rs`) treat it as absent, like Bun itself. Proved on `045d7ec`: with a dangling `bun.lock` beside a `bun.lockb` that Bun installs from, the inventory returns nothing while vendored and hosted write `bun.lockb`. {{E17}}
- **`name@spec` splitting** is written twice (`yarn_classic_lock::split_pattern`, `bun_lock_text::split_name_spec`). npm purl → (name, version) is parsed three more times outside `utils/purl.rs`.
- **Wiring `KIND_*` constants** are private to each backend but re-spelled as string literals in `recover.rs` (7 production sites); the `state.rs` copy is test-only. {{E18}}
- **Recursion depth:** the legacy npm `dependencies` recursion is bounded at 64 in two places and unbounded in two others.
- **Regex compilation inside per-dependency loops** (`redirect:3013`, `:3305`).

**CRLF policy is inconsistent for the same file family:**
- vendored pnpm refuses CRLF, while hosted pnpm handles it;
- vendored yarn classic keeps CRLF, while hosted classic normalizes it by hand;
- berry uses `utils::line_endings::LineEndings`;
- npm_lock keeps the file's layout through `JsonLayout` (#357), and so does vendored pnpm's `package.json` writer (#810, {{E53}});
- vlt has its own `strip_cr`.

Five different answers to one question, and every one of them is a bug class (see the open-issue appendix). Across the whole crate there are five terminator rules (any-CRLF, first line, majority, CRLF-only re-expansion, refuse); on main the any-CRLF rule alone is written 14 times, in `common::detect_eol`, a byte-identical `pypi_uv::newline_of` and 12 inline copies, and `gradle::newline_of` uses the first-line rule under the same name. A probe on `045d7ec` gives three answers for one mixed input. {{E16}}

### 4.5 Architecture defects

1. **Silos with no trait** (see 4.1).
2. **Layering is inverted and cyclic.**
   - 33 non-test files in `patch/`, `vex/`, `formats/`, `hosted/` and `crawlers/` import grammar from `vendor::*` backends.
   - On `045d7ec`, `formats/{cargo,composer,gem,pnpm}/mod.rs` import the entry types from `vendor::lock_inventory`, `formats/bun/mod.rs:11` imports `vendor::bun_lock_text`, all four `formats/*/hosted.rs` import `patch::redirect`, and `formats/composer` and `formats/gem` import `crawlers`. {{E20}}
   - `vendor` imports `patch::redirect` in about 12 places.
   - Several codecs are already pure and are simply in the wrong place. `bun_lockb.rs`, `bun_lock_text.rs` and `vlt_lock_text.rs` do no I/O and would pass the `formats` purity guard (`formats/mod.rs:43-91`) unchanged. {{E20}}
3. **God files and long functions.**
   - `pnpm_lock.rs` is 8,515 lines.
   - Longest drivers: `vendor_yarn_berry` 402 lines, `vendor_bun` 332, `vendor_npm` 325, `vendor_pnpm_dialect` 259 (both dialects; as of `9c43dfc`), `revert_pnpm_opts` 234, `rewrite_yarn_berry` 272, `plan_hosted` 236, `recover_lock_entry` 221, `bun_lockb::meta_hash` 187.
4. **Two lookup paths in pnpm v9.** A linear scan and a memoized index (`LockLines`/`LockIndex`, `INDEX_AFTER_PROBES = 2`) coexist. That doubles the functions: `lock_has_target_package` vs `…_in`, `check_rewritable_refs` vs `…_with`.
5. **Stale docs.** `berry_zip` compiles only under `cfg(any(test, feature = "test-fixtures"))` (`vendor/mod.rs:51`), so cache-zip surgery does not ship; production gets the checksum from the patch service. Yet `yarn_berry_lock.rs:15` and `npm_flavor.rs:323-325` still say berry's checksum is "rebuilt by berry_zip".

### 4.6 Complexity vs value

- **`bun.lockb` (binary).**
  - The repo itself labels it "(binary, legacy)" (`pkg_managers.rs:139-140`); Bun ≥ 1.2 writes text `bun.lock` by default.
  - The codec supports binary format 1 ("before 0.1.7", 2022-era Bun) with promotion and demotion.
  - It recomputes Bun's 187-line meta hash.
  - It writes a private `sktpnrm` marker into an unused union slot of the user's lockfile (`bun_lockb.rs:22-29`).
  - About 5.8K lines including tests.
  - **Recommend:** refuse, with the remedy `bun install --save-text-lockfile --frozen-lockfile --lockfile-only` followed by deleting `bun.lockb`. If inventory/VEX must still read old repos, keep a read-only parser of about 300 lines.
- **Vendored pnpm legacy (lockfile 5.4 = pnpm 7, 6.0 = pnpm 8).**
  - Both pnpm majors are out of maintenance.
  - The legacy specifier is absolute, so `--frozen-lockfile` passes only at the original checkout path, which the module documents itself (`pnpm_lock_legacy.rs:22-31`). That undercuts the main point of vendoring.
  - About 5.1K lines including tests.
  - **Recommend:** refuse with "re-lock with pnpm ≥ 9", or at minimum fold it into the v9 backend as a `PnpmDialect`.
- **Hosted pnpm ≤ 6** (`shrinkwrap.yaml`, lockfile 5.0-5.3, `may_need_store_flag`, `unsupported_early_shrinkwrap`). This covers 2017-2021 releases; refusing it saves a modest amount.
- **vlt.**
  - The most expensive format: 6.5K production + 6.1K inline-test + about 9.3K CLI test lines.
  - It supports pre-1.0 RC DepID encodings ("vlt ≤ 1.0.0-rc.14").
  - On top of that it has a directory-artifact backend (`npm_dir.rs`), a warm-store heal (`vlt_heal.rs`) and an artifact preflight.
  - Architecturally it is the best of the JS formats (one codec). The concern is size against a very small user base.
  - **Recommend:** drop the pre-1.0 RC encodings now. Gate further vlt investment on telemetry, and consider making vendored vlt refuse-only (about 3K production lines) while keeping hosted.
- **Yarn PnP** is already refused, and `nodeLinker: pnpm` costs nothing in production. No cuts are needed beyond fixing the stale berry_zip docs.

### 4.7 Target structure

```
formats/npm_lock/  { model (NpmLockDoc: nodes() with JSON pointers + JsonLayout), splice }
formats/pnpm/      { grammar (sole, CRLF-aware, byte ranges), keys, dialect {V54,V60,V9}, plan_hosted, plan_vendored }
formats/yarn/      { blocks (scan_blocks/LockBlock/replace_block), classic, berry (fields, locator, gates) }
formats/bun/       { text, binary (read-only stub or removed) }
formats/vlt/       { text, registry (one registry_base) }
formats/js_common  { name@spec split, SRI, tarball_url, LineEndings, wiring KINDS }
```

Each format exposes `parse(&[u8]) -> Model`, `entries()`, `wired_refs()`, `plan_hosted(deps)`, `plan_vendored(ctx)` and `restore(record)`. Behind them sits one `trait NpmLockBackend { read_project, preflight, plan, revert_record }` with one generic vendor/revert driver. One flavor decision table, written over `ProjectView`, would be used by vendored mode, hosted mode and the in-memory engine.

| # | Change | Prod LOC saved | Test LOC | Risk |
|---|---|---:|---:|---|
| A | `bun.lockb` → refuse (keep a ~300-line read-only parser) | ~2.4K | ~3K | Med (unmigrated Bun repos) |
| B | Drop vendored pnpm-legacy (or merge it as a dialect) | 1.85K (merge: ~0.8K) | 3.2K (~1K) | Low-Med |
| C | Generic vendor driver + `NpmLockBackend` trait | 0.8-1.0K | — | Med |
| D | Hosted yarn writers/restorers on `LockBlock`; one berry gate set | 0.3-0.4K | some | Low-Med |
| E | One package-lock walk (`JsonLayout` half done by #357) {{E07}} | ~0.3K | — | Low |
| F | One flavor decision table | ~0.15K | — | Low |
| G | pnpm: retire `lines.rs` + the CRLF refusal, one `resolution:` emitter, one index path | 0.3-0.5K | — | Med |
| H | vlt: drop pre-1.0 encodings, unify `registry_base`, decide the vendored-dir backend on data | 0.2-3K | up to ~6K | Low → High |
| I | Helper dedup (SRI, pointer escape, tarball URL, KINDS, lines↔JSON, bun presence, purl) | ~0.15K | — | Low; fixes real divergences |
| J | Move pure codecs into `formats/` (removes the `vendor`↔`redirect`/`vex` cycles) | ~0 | — | Low |

**Combined (A, B-drop, C-G, I): about 6-7K production lines and 8-10K test lines**, before any vlt decision.

### New findings since the review

- Hosted yarn berry rewrites (majority-normalizes) a mixed-line-ending root `package.json` that vendored mode refuses with `vendor_yarn_berry_mixed_line_endings`; the gates live once per mode. {{E09}}
- Vendored pnpm wrote the root `package.json` with `serialize_json` instead of `JsonLayout`, losing CRLF and refusing a BOM; it now uses `JsonLayout` like npm and berry (#810). {{E53}}
- {{E16}}: the "any `\r\n` → CRLF" terminator rule is written 14 times, mostly outside the npm family (gem, Maven, composer and Cargo restore, Pipenv, `.npmrc`, uv, PEP 723 scripts), and hosted Cargo refuses a mixed `Cargo.lock` that upstream restore re-expands wholesale to CRLF; folded into the line-ending tracking issue.
- {{E76}} October 7: hosted yarn classic replaced `file:`, URL and codeload copies with the Socket artifact; one copy-source classifier (`formats::yarn::source`) now leaves them unpinned (#1057).
- {{E78}} October 7: pnpm readers and writers ignore `---`, so a two-document pnpm lock gets the wrong document edited (#466, pnpm workstream).
- {{E64}}: BOM handling has one helper, `formats::text` (`split_bom`, `strip_bom`, `strip_bom_bytes`); the named `strip_bom` copies are gone and `formats::pnpm`'s `lockfileVersion` readers skip a BOM (#909). #1117 moved 8 inline strips (yarn blocks/stanzas, Gradle DSL, npm manifest, requirements, `socket.yml`, manifest operations) onto it, and a one-sided guard in `formats::text` rejects new inline strips. Inline `\u{feff}` handling still sits in 26 files on the guard's pending list (#905).

---
_Generated by [Claude Code](https://claude.ai/code)_
