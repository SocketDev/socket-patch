# One lock model for every reader

Status: in progress (stacked PRs `lock-model/*`). Owner decisions are dated
2026-11-04.

Paths below are relative to `crates/socket-patch-core/src/`.

## Problem

Three groups of code read the same project files, and each reads them its own
way:

* **Lockfile discovery** (`vex/discover/`) finds Socket wiring: the hosted
  pins and vendored paths in lockfiles and package-manager configs. It is not
  only for `vex`. `scan`, `vendor`, the hosted engine, the hosted unwind,
  rollout and ledger liveness all call it.
* **The lock inventory** (`vendor/lock_inventory/`) lists every package a
  lockfile resolves. `scan` and `get` use it to supplement the installed-tree
  crawl, `vendor` uses it to fetch pristine artifacts, `repair` uses it to
  recover ledger entries, and ledger liveness uses its every-lock view.
* **The writers** (`patch/redirect/`, `hosted/`, `vendor/`) parse the same
  files again to plan their edits.

`formats/` was started as the shared home ("one model per lockfile format"),
but only pnpm has both an entry view and a wiring view there. A survey of
every format on 2026-11-04 found the duplicated work below. What discovery
adds on top of a walk (the contests between locks, ledger claims and
attestation rules) is real policy and stays.

| Duplicated work | Where |
|---|---|
| Two Socket-origin classifiers | discovery's `DiscoverCtx::locate` / `hosted_uuid` checks a Socket host allowlist. The inventory's `parse_vendor_path` / hosted-URL-leaf matching accepts any host. `utils/poetry_lock::lock_wiring` uses a third, looser substring test. |
| Three Python precedence rules | the inventory's chain (uv by parse success, then poetry or pdm if they have entries, then Pipfile.lock plus requirements), `formats/governing_locks.rs` (uv, poetry, pdm, Pipfile.lock by presence) and discovery (every lock, plus the cross-lock contest). They disagree on four common layouts. |
| Second walks of one file | `vendor/npm_origin.rs` walks package-lock `packages` again. Yarn writers call `scan_blocks` directly, and the Berry rewriter uses a third model (`formats/yarn/stanzas.rs`). The vlt writers use a separate line grammar. pnpm's `InstalledPackages` and `vendored_npm_uuids`, and the hosted planner's whole-text `grammar::entries`, skip the env-document filter. |
| Second parses of one file | `vex/discover/pypi_locks.rs` parses uv, pylock and script locks itself. The inventory parses them again. `deno.lock` is parsed by `crawlers/deno_crawler.rs` for discovery, the hosted engine and the npm flavor probe. |
| Repeated helper parsers | two Python lock listers, two `-r` include walkers, two PEP 508 direct-reference parsers, five walks of `Cargo.toml` dependency tables, two Rush lock listings, three readers of Maven's `checksums.sha256`, two Gradle Socket-index parsers, two routes to sbt resolution evidence |
| Two file-selection layers | the npm flavor router (`lock_inventory/npm_family.rs`) picks one family and one lock. Discovery reads every lock and sweeps the ignored ones with `recognize_ignored`. |

The inventory also has gaps. It has no models for NuGet, Maven, Gradle, sbt,
Hatch or Deno, and it reads no `composer.lock` that starts with a BOM, which
discovery reads.

## Goal

One per-project lock model. Every consumer reads it, and the end state has
fewer implementation lines than today. `scripts/loc-budget.py` tracks the
lines (see [Size budget](#size-budget)).

Non-goals: changing what any mode writes, or adding new hosted or vendored
backends.

## The model

### Layers

1. **`formats/`: pure models.** Text in, records out. Each record carries
   the raw location strings the lock spells (resolved URL, tarball, path,
   source). The existing architecture test keeps these models free of I/O
   and of the host policy, and that rule stays.
2. **`origin`: the one classifier.** A top-level module, not part of
   `formats/`, because it applies the host policy. See [Origin](#origin).
3. **The project layer.** Reads files through `ProjectView`, picks install
   trees, joins files where a format needs it, and turns each record's raw
   location into an `Origin`. Discovery, the inventory and the writers all
   consume it.

### Entries

Every reader yields `LockEntry` records. Each record holds the package
coordinates as the lock spells them, the integrity the lock records, the
resolved location, a source span for writers that splice the file, and an
`Origin`:

```rust
pub enum Origin {
    /// Resolves from a registry the package manager would use anyway.
    Registry { resolved: Option<String> },
    /// Routes to a Socket-hosted artifact.
    Hosted { uuid: String, url: String },
    /// Routes to a committed `.socket/vendor/<eco>/<uuid>/<leaf>` artifact.
    Vendored { uuid: String, artifact_rel: String },
    /// git, path, link, workspace, or a URL on another host.
    Other(OtherSource),
    /// Looks like Socket wiring but fails validation. Keeps the identity
    /// the entry would have had, so contests and recognition still see it.
    Rejected { would_be: Option<Wired>, diag: Diag },
}
```

Formats with install semantics that discovery's contests need also carry
flags: bundled, link, the v2 mirror, a `hasShrinkwrap` ancestor, Yarn's
`live`, Berry's checksum cache key, and so on. These are fields of the format's
record, not new side channels.

### Origin

One classifier, the `origin` module, decides `Origin`. It is moved, not
rewritten, from two places:

* from `patch::redirect`: `hosted_patch_uuid` (Socket's patch server or a
  configured origin, the last canonical-uuid path segment) and
  `SOCKET_PATCH_SERVER_HOST`. The hosted unwind already calls these
  directly;
* from discovery: `OriginPolicy::hosted_uuid` (the same rule with a memoized
  fast path for plain registry URLs), `vendor_ref`, `vendor_ref_decorated`
  and `vendor_uuid_dir`, `locate`, `Wired`, and the `socket-patch-<uuid>`
  name grammar.

The validating purl builders already live in `utils::purl`.

The inventory's any-host matching goes away. That is a behavior change only
where a non-allowlisted host serves a URL that looks like Socket's, and it
lands in the install-tree PR with a golden review.

### Joins

For JVM and NuGet, origin is not a property of one entry:

* **Maven:** a pom dependency's `-socket.<hex8>` version joins one
  `<repository>`.
* **Gradle:** a lockfile entry joins a row of `.socket/gradle/hosted-index.tsv`
  or `.socket/vendor/gradle-index.tsv`.
* **sbt:** pins live in owned files and are confirmed by resolution evidence.
* **NuGet:** `packages.lock.json` entries join `nuget.config`'s
  `<packageSourceMapping>`.

So a reader works on a project view, not on a single text. A reader may read
several files and still yield one list of records. The same applies to Cargo,
where `Cargo.toml` `registry =` pins join `.cargo/config.toml` registries,
and to Go, where `go.mod` `replace` directives join `go.sum` lines.

### Install trees

File selection is one function over `formats::registry()`:

```rust
pub struct InstallTree {
    /// The files the package manager reads for this tree, governing first.
    pub files: Vec<String>,
    /// Present files the package manager ignores in favor of `files`.
    /// They are swept for Socket identities (discovery rule 11) and never
    /// read as wiring.
    pub shadowed: Vec<String>,
}
```

Rule: **precedence within a tree, union across trees.**

* npm: `npm-shrinkwrap.json` governs and `package-lock.json` is shadowed.
  pnpm: `pnpm-lock.yaml` governs `shrinkwrap.yaml`. Bun: `bun.lock` governs
  `bun.lockb`, which `bun_text_lock_drives` already decides.
* **Python (owner decision):** each tool's lock is its own tree, because
  which lock is installed depends on which tool runs. uv.lock, poetry.lock,
  pdm.lock, Pipfile.lock, each pylock, each PEP 723 script lock, and
  `requirements.txt` with its `-r` includes are separate trees.
  Discovery's cross-lock contest stays. It is the safety check that withholds
  a uv ref when poetry.lock pins the same release unpatched. The inventory
  unions the trees, so `scan` sees a patch wired into an exported
  `requirements.txt` beside `poetry.lock`. The inventory's precedence chain
  and `governing_locks`' presence rule are deleted. The vendor router's
  question ("which lock do I write?") becomes a query over the trees.
* **Deno (owner decision: deprecated but supported):** `deno install` reads
  `deno.lock` for a `package.json` project's npm dependencies and never reads
  the npm-family locks. `deno.lock` and the npm-family lock are one tree with
  undecided governance: the files don't say which tool fills
  `node_modules`. Today's outcome is kept: a ref in the npm-family lock stays
  a ref but is marked unattested. It is now expressed as a tree property,
  not the `UnwiredCopy` side channel.
* Rush subspace locks, workspace-member locks and Go workspace members are
  trees of their own, as discovery already treats them.

### Consumers

* **Inventory**: every entry of every tree, read by the package it resolves.
  Socket entries are listed as the package they replace, as today, so a
  rescan of a wired checkout still lists it. Then path-safety guards and
  `dedup_prefer_integrity`. `inventory_project_every_lock` becomes the
  same list without the dedup.
* **Discovery**: the `Hosted`, `Vendored` and `Rejected` entries of each tree
  become refs and diagnostics, the shadowed files are swept, and the contests
  and ledger claims run as today. The `Registry` and `Other` entries of
  other trees replace the `resolved_elsewhere` collection that each extractor
  feeds by hand today.
* **Ledger liveness** reads `Origin` directly instead of looking for a uuid
  inside the inventory's `resolved` URL.
* **Writers** plan over the same records, using the source spans.

## JVM and NuGet support (owner decision: in scope)

What committed files can give the inventory:

| Ecosystem | Coordinates | Integrity |
|---|---|---|
| NuGet | every `(id, resolved)` per target framework in `packages.lock.json` | `contentHash`, which needs a new `LockIntegrity::NugetContentHash`. For signed packages, and nuget.org signs all of them, it hashes the archive with the signature stripped (`formats/nuget/package.rs::package_content_hash`), not the raw `.nupkg` bytes. |
| Gradle | the resolved GAVs per configuration in `gradle.lockfile` (settings and buildscript locks tagged as build logic) | `verification-metadata.xml`, which has editors but no reader today. `sha256` and `sha1` map to existing variants. `sha512` needs `Sha512Hex`. |
| Maven | the root pom's direct and managed GAVs only. Maven has no lockfile, so transitive dependencies are not in committed files. | `.mvn/checksums/checksums.sha256` lines, normally only for Socket pins |
| sbt | Socket pins only (owned files). No committed file resolves registry entries. | the jar sha256 in the owned file |

Vendor fetch refuses entries without a verifier, and JVM and NuGet vendoring
take their bytes from caches, registry sidecars or the installed directory
anyway. So the new entries first serve `scan`/`get`, discovery and ledger
liveness. Ledger liveness also needs a `SourceKind` for "mapped to a
non-Socket NuGet source" and the Gradle equivalent, since these entries carry
no URL.

## Deno

Deno stays supported while deprecated. It is ported like any other format, so
deprecating it later means deleting one reader and one tree rule. The
`deno.lock` reader moves from `crawlers/deno_crawler.rs` into `formats/` and
serves the crawler, discovery, the hosted engine and the npm flavor probe.
Deprecation messaging is separate from this work.

## Size budget

`scripts/loc-budget.py` counts implementation lines: code outside comments,
outside `#[cfg(test)]` items and outside test-only modules. It compares the
groups in `scripts/loc-budget.json` with their maxima. CI's
`lint-ecosystems` job runs it with `--warn`, which annotates a group over
budget but never fails, so another PR's bug fix in one of these files never
fails on it. There are two groups:
`lock-readers` (`formats/`, `vex/discover/`, `vendor/lock_inventory/`,
`gradle/`, the Python lock helpers in `utils/`, `vendor/npm_origin.rs` and
`crawlers/deno_crawler.rs`) and `lock-writers` (`patch/redirect/`, `hosted/`
and the rest of `vendor/`). At 7bde3ba55 they hold 30,898 and 88,363 lines.
Each PR in this stack
lowers the maxima with `--lower` in the same commit. The NuGet and JVM PRs
add code and raise the readers' maximum by hand, saying why.

## Stack

Each PR is based on the one before. PRs 1 to 11 must leave
`tests/fixtures/vex-discover-golden/` and the redirect goldens byte for byte
unchanged. Only PR 12 may change them, and its golden diff is reviewed line
by line.

| PR | Branch | Change |
|---|---|---|
| 0 | `lock-model/0-design` | This document and the size budget |
| 1 | `lock-model/1-origin` | The `origin` module: discovery's classifier and the redirect's hosted-URL rule, moved verbatim. Discovery and the redirect re-export it. |
| 2 | `lock-model/2-pnpm` | Pilot. One pnpm reader feeds the inventory, discovery and the hosted planner. Removes `InstalledPackages`, `vendored_npm_uuids`, the whole-text planner walk and the second Rush listing. |
| 3 | `lock-model/3-npm` | package-lock and shrinkwrap. Folds `vendor/npm_origin.rs`'s second walk into the records. |
| 4 | `lock-model/4-yarn` | Classic and Berry. One block model for every reader and writer, `BerryStanzas` included. |
| 5 | `lock-model/5-bun-vlt` | `bun.lock`, `bun.lockb` and vlt. The vlt writers move off their line grammar. |
| 6 | `lock-model/6-deno` | The `deno.lock` reader in `formats/`, for all four of its callers |
| 7 | `lock-model/7-python` | One lister, one parse per lock, one include walker and one PEP 508 parser. `pypi_locks.rs` stops parsing TOML itself. Poetry wiring uses `origin`. Hatch gets inventory entries. |
| 8 | `lock-model/8-cargo-go` | One `Cargo.toml` dependency-table walk. Go `replace` and `go.sum` records. |
| 9 | `lock-model/9-gem-composer` | Gemfile.lock and composer.lock records. The inventory stops dropping BOM-prefixed `composer.lock` files. |
| 10 | `lock-model/10-nuget` | NuGet records with the config join, `NugetContentHash`, and inventory entries |
| 11 | `lock-model/11-jvm` | One `checksums.sha256` reader, one Gradle index parser, a `verification-metadata.xml` reader, then Gradle-lock and root-pom inventory entries and sbt's owned-file entries |
| 12 | `lock-model/12-install-trees` | Install-tree selection, Python trees, Deno governance, the single classifier for the inventory, liveness on `Origin`. Deletes the npm flavor router's lock choice, the Python precedence rules, `resolved_elsewhere` and the `UnwiredCopy` plumbing. |
| 13 | `lock-model/13-cleanup` | Removes the raw-text liveness fallbacks if the model makes them redundant, plus whatever is left of `vendor/lock_inventory/`. Final budget. |

## Open questions

* Whether discovery's hosted NuGet refs, which set `Sri("sha512-" +
  contentHash)`, are verified anywhere against raw bytes. Socket-served
  packages may be unsigned, in which case the two hashes agree. PR 10 checks
  this before it adds `NugetContentHash`.
* Whether the raw-text fallbacks (`hosted_wiring_in_files`,
  `vendored_wiring_live`) can go entirely. They exist for formats that no
  reader reads and for patch servers outside the allowlist. PR 13 decides
  from what is left by then.
