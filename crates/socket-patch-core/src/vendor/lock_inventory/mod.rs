//! Read-only lockfile inventories: the dependency set a project's lockfile
//! resolves, independent of what is installed on disk.
//!
//! Consumers:
//!
//! * `scan` / `get` supplement their installed-tree crawl with lockfile-only
//!   entries (discovery on fresh clones and partial installs), warning that
//!   those packages are not yet installed;
//! * `vendor` fetches the pristine artifact for a lockfile-resolved package
//!   with no installed copy ([`super::registry_fetch`]), verifying the bytes
//!   against the integrity the lock records — FAIL-CLOSED: an entry whose
//!   lock carries no content verifier is never fetched;
//! * `repair` recovers ledger entries ([`recover_lock_entry`]) and the pin a
//!   rewired lock records for a vendored artifact
//!   ([`wired_vendor_integrity`]);
//! * ledger liveness (`vex::discover`) reads EVERY lock's instance
//!   ([`inventory_project_every_lock`]) as evidence that a package resolves
//!   from somewhere other than its patch.
//!
//! # Layout
//!
//! One submodule per lock format, laid out in up to three sections (an
//! architecture test below enforces the order and the purity):
//!
//! 1. the ENTRY MODEL: a pure reader (text or a parsed document in) that
//!    yields every entry the package manager installs from — Socket-hosted
//!    and vendored ones included — with the raw location and pin strings.
//!    Lockfile discovery (`vex::discover`) iterates the same models, so the
//!    two see one entry walk per format;
//! 2. `// ── file selection ──`: stat / list helpers discovery shares (never
//!    a content read, so discovery's recognizing reads stay its only ones);
//! 3. `// ── registry view ──`: the `inventory_*` function — this module's
//!    I/O and precedence chain (shrinkwrap wins; uv exclusive; poetry → pdm
//!    → Pipfile + requirements), Socket-owned entries dropped, and
//!    `dedup_prefer_integrity` over its `*_raw` body (every instance, which
//!    [`inventory_project_every_lock`] unions for ledger liveness).
//!
//! Formats whose reader a writer already owns keep the model there
//! (`cargo_lock::locked_packages`, `gemfile_lock`, `utils::python_lock` /
//! `poetry_lock`, `utils::requirements`), and only the registry view lives
//! here. [`LockfileEntry::source_kind`] carries provenance a view knows
//! positively (crates.io), which ledger liveness reads instead of inferring
//! it from the verifier.
//!
//! Parsing is fail-soft per entry (a malformed entry is skipped, never an
//! error; a malformed text file yields `None`, while a malformed binary Bun
//! lock emits `bun_lockb_invalid`) and fail-closed per value:
//! names/versions are path-safety-guarded before an entry is emitted — the
//! lockfile is committed, tamperable input that later feeds filesystem paths
//! and download URLs.

use std::collections::HashMap;
use std::path::Path;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::purl::strip_purl_qualifiers;

pub(crate) mod bun;
pub(crate) mod cargo;
pub(crate) mod composer;
pub(crate) mod gem;
pub(crate) mod golang;
pub(crate) mod npm;
pub(crate) mod npm_family;
pub(crate) mod pnpm;
pub(crate) mod pypi;
pub(crate) mod recover;
pub(crate) mod wired;
pub(crate) mod yarn;

pub(crate) use self::composer::{composer_lock_packages, ComposerLockPackage};
pub(crate) use self::npm::{npm_lock_nodes, NpmLockNode};
pub(crate) use self::npm_family::inventory_npm_lock;
pub(crate) use self::pnpm::pnpm_registry_key;
pub(crate) use self::pypi::pipfile_lock_entries;
pub use self::recover::recover_lock_entry;
pub use self::wired::wired_vendor_integrity;

// The per-format views `inventory_project_diagnosed` unions (and the test
// modules reach through `super::*`).
use self::cargo::inventory_cargo_lock;
use self::composer::inventory_composer_lock;
use self::gem::inventory_gemfile_lock;
use self::golang::inventory_go_sum;
use self::pypi::inventory_pypi_locks;
#[cfg(test)]
use self::{
    bun::inventory_bun,
    gem::gem_remotes,
    npm::inventory_package_lock,
    npm_family::finalize_npm,
    pnpm::{inventory_pnpm_lock, inventory_pnpm_lock_at},
    pypi::{is_public_pypi_url, python_lock_inventory, socket_reference_coords},
    recover::pure_wheel_from_uv_unit,
    yarn::{inventory_yarn_berry, inventory_yarn_classic},
};
#[cfg(test)]
use crate::vendor::npm_flavor::NpmLockFlavor;

/// The content verifier a lockfile records for an entry. The fetch layer
/// refuses entries whose verifier is [`LockIntegrity::None`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockIntegrity {
    /// SRI string (`sha512-<b64>`, possibly multi-hash space-separated) —
    /// npm family; verified against the raw tarball bytes.
    Sri(String),
    /// yarn classic `resolved "...#<sha1>"` fragment (40-hex) — verified
    /// against the raw tarball bytes.
    Sha1Hex(String),
    /// yarn berry cache-zip checksum (`<cacheKey>/<b64>`, e.g. `10c0/…`) —
    /// verified by rebuilding the deterministic cache zip from the fetched
    /// tarball and comparing (the lock never hashes the tarball itself).
    BerryChecksum(String),
    /// Hex sha256 of the artifact (Cargo.lock `checksum`, pypi file hashes,
    /// Gemfile.lock `CHECKSUMS`).
    Sha256Hex(String),
    /// One of several hex sha256 digests: the lock records every release
    /// file's digest without saying which file is which (Pipfile.lock
    /// `hashes`), so the fetcher picks the pure-Python wheel whose PyPI
    /// digest is in the set and verifies the download against that digest.
    Sha256AnyOf(Vec<String>),
    /// go.sum module-zip dirhash (`h1:<b64>`).
    GoH1(String),
    /// The lock records no content verifier.
    None,
}

/// Where a lock entry resolves from, when the registry view knows it
/// POSITIVELY — the provenance ledger liveness reads
/// (`vex::discover::resolves_elsewhere`) instead of inferring it from which
/// verifier the entry happens to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceKind {
    /// Nothing is claimed (every format but cargo; a cargo entry from a git,
    /// path or custom-registry source).
    #[default]
    Unspecified,
    /// A crates.io-sourced `Cargo.lock` entry: its `checksum` is the sha256
    /// of the `.crate` crates.io serves.
    CratesIo,
}

/// One lockfile-resolved package.
#[derive(Debug, Clone)]
pub struct LockfileEntry {
    /// Vendor-ecosystem tag (`npm`, `cargo`, `golang`, `pypi`, `gem`,
    /// `composer`) — matches `VendorEntry::ecosystem`.
    pub ecosystem: &'static str,
    /// Literal (percent-decoded) package name, e.g. `@scope/name`.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Canonical literal purl (`pkg:npm/@scope/name@1.0.0`) — the same form
    /// the crawlers emit.
    pub purl: String,
    /// Artifact URL when the lock records one (package-lock `resolved`,
    /// yarn `resolved` minus its `#sha1` fragment, pnpm `tarball:`); `None`
    /// means the fetcher constructs the conventional registry URL.
    pub resolved: Option<String>,
    pub integrity: LockIntegrity,
    /// See [`SourceKind`].
    pub source_kind: SourceKind,
}

impl LockfileEntry {
    fn npm(
        name: impl Into<String>,
        version: impl Into<String>,
        resolved: Option<String>,
        integrity: LockIntegrity,
    ) -> Self {
        let (name, version) = (name.into(), version.into());
        let purl = format!("pkg:npm/{name}@{version}");
        LockfileEntry {
            ecosystem: "npm",
            source_kind: SourceKind::Unspecified,
            name,
            version,
            purl,
            resolved,
            integrity,
        }
    }
}

/// A project layout or lockfile that cannot be inventoried safely.
/// Consumers surface these diagnoses instead of treating an unreadable
/// dependency graph as an empty project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedNpmLayout {
    /// Stable diagnosis code, including `bun_lockb_invalid` for malformed
    /// binary Bun locks and the flavor probe's Plug'n'Play refusal codes.
    pub code: &'static str,
    /// Human-readable diagnosis with format or filesystem error details.
    pub detail: String,
}

/// Match a manifest/API purl (possibly percent-encoded, possibly carrying
/// qualifiers) against the inventory: components decode via
/// [`crate::utils::purl::normalize_purl`], so `pkg:npm/%40scope/x@1`
/// matches the literal entry.
pub fn lookup<'a>(entries: &'a [LockfileEntry], purl: &str) -> Option<&'a LockfileEntry> {
    let decoded = crate::utils::purl::normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (purl_type, rest) = rest.split_once('/')?;
    // purl types double as the vendor-ecosystem tags (same set the
    // dispatcher recognizes).
    let eco = match purl_type {
        "npm" | "cargo" | "golang" | "pypi" | "gem" | "composer" => purl_type,
        _ => return None,
    };
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&rest[..at], &rest[at + 1..]);
    // pypi names compare in PEP 503 normalized form.
    let name = if eco == "pypi" {
        canonicalize_pypi_name(name)
    } else {
        name.to_string()
    };
    entries
        .iter()
        .find(|e| e.ecosystem == eco && e.name == name && e.version == version)
}

/// Everything every recognized lockfile in the project resolves — the
/// union the scan supplement and the vendor auto-fetch consume. Drops the
/// npm-layout diagnosis; callers that must surface refusals (scan) use
/// [`inventory_project_diagnosed`].
pub async fn inventory_project(project_root: &Path) -> Vec<LockfileEntry> {
    inventory_project_diagnosed(project_root).await.0
}

/// [`inventory_project`] plus the npm-family layout refusals it hit: a
/// Plug'n'Play project yields no npm entries AND a diagnosis, so consumers
/// can tell "nothing to inventory" from "packages structurally unreachable"
/// and refuse explicitly instead of silently reporting an empty project.
pub async fn inventory_project_diagnosed(
    project_root: &Path,
) -> (Vec<LockfileEntry>, Vec<UnsupportedNpmLayout>) {
    union_views(project_root, Instances::Collapsed).await
}

/// EVERY instance every recognized lockfile resolves: the same views,
/// precedence and guards as [`inventory_project`], without collapsing
/// duplicate (name, version) instances ([`dedup_prefer_integrity`] keeps one
/// per package — across a PEP 723 script lock and `uv.lock`, or Rush's
/// common and subspace locks, too). The view for evidence about ONE lock's
/// entry — ledger liveness (`vex::discover`), where the instance a collapse
/// dropped may be exactly the one that routes the package to its patch.
pub async fn inventory_project_every_lock(project_root: &Path) -> Vec<LockfileEntry> {
    union_views(project_root, Instances::Every).await.0
}

/// Which instances a view returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Instances {
    /// One per (name, version) — [`dedup_prefer_integrity`].
    Collapsed,
    /// Every lock's every entry.
    Every,
}

/// The union of the per-format views, in the one precedence order.
async fn union_views(
    project_root: &Path,
    instances: Instances,
) -> (Vec<LockfileEntry>, Vec<UnsupportedNpmLayout>) {
    let every = instances == Instances::Every;
    let mut out: Vec<LockfileEntry> = Vec::new();
    let mut unsupported: Vec<UnsupportedNpmLayout> = Vec::new();
    let npm = if every {
        npm_family::inventory_npm_lock_raw(project_root).await
    } else {
        inventory_npm_lock(project_root).await
    };
    match npm {
        Ok(Some((_, entries))) => out.extend(entries),
        Ok(None) => {}
        Err(diag) => unsupported.push(diag),
    }
    let views = [
        if every {
            cargo::inventory_cargo_lock_raw(project_root).await
        } else {
            inventory_cargo_lock(project_root).await
        },
        if every {
            golang::inventory_go_sum_raw(project_root).await
        } else {
            inventory_go_sum(project_root).await
        },
        if every {
            composer::inventory_composer_lock_raw(project_root).await
        } else {
            inventory_composer_lock(project_root).await
        },
        if every {
            gem::inventory_gemfile_lock_raw(project_root).await
        } else {
            inventory_gemfile_lock(project_root).await
        },
        if every {
            pypi::inventory_pypi_locks_raw(project_root).await
        } else {
            inventory_pypi_locks(project_root).await
        },
    ];
    out.extend(views.into_iter().flatten().flatten());
    (out, unsupported)
}

/// Collapse duplicate (name, version) instances, preferring one that
/// carries a verifier. Each view applies it ONCE, at its public boundary,
/// over its `*_raw` body (collapsing is associative over concatenation —
/// the first verifier-bearing instance wins, else the first — so a union of
/// raw sub-views collapses to what collapsing each sub-view first would).
fn dedup_prefer_integrity(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<LockfileEntry> = Vec::new();
    for entry in raw {
        let key = (entry.name.clone(), entry.version.clone());
        match seen.get(&key) {
            Some(&i) => {
                if out[i].integrity == LockIntegrity::None && entry.integrity != LockIntegrity::None
                {
                    out[i] = entry;
                }
            }
            None => {
                seen.insert(key, out.len());
                out.push(entry);
            }
        }
    }
    out
}

/// Keep a lock-recorded URL only when it is a plain http(s) artifact URL
/// (drops `git+…`, `file:…`, `link:…` — content the registry conventions
/// cannot reproduce; such entries stay listed for discovery but the fetch
/// layer's integrity rule decides fetchability).
fn http_url(raw: &str) -> Option<String> {
    (raw.starts_with("https://") || raw.starts_with("http://")).then(|| raw.to_string())
}

/// ARCHITECTURE GUARD (module docs): each per-format file is laid out as
/// up to three sections, in order — the pure entry model (text or a parsed
/// document in, entries out: no filesystem and no host policy),
/// `// ── file selection ──` (stat / list only, never a content read), and
/// `// ── registry view ──` (unrestricted) — so lockfile discovery can
/// import the models without bypassing its recognizing ctx reads. The same
/// rule covers the other readers discovery imports: `vendor::maven_pom`,
/// `vendor::nuget_config`'s reader half, and the `// ── pure reader ──`
/// regions of the writer-owned `go_mod_edit`, `go_sum_edit`,
/// `cargo_config` and `cargo_manifest`.
#[cfg(test)]
mod architecture_tests {
    use std::path::Path;

    const FILE_SELECTION: &str = "// ── file selection ──";
    const REGISTRY_VIEW: &str = "// ── registry view ──";
    const PURE_READER: &str = "// ── pure reader ──";
    /// Anything that reads content, does I/O, or applies the hosted-origin
    /// policy.
    const IMPURE: [&str; 9] = [
        "tokio::fs",
        "std::fs",
        "read_regular_",
        "File::open",
        "OpenOptions",
        "hosted_patch_uuid",
        "hosted_patch_url_uuids",
        "async fn",
        ".await",
    ];
    /// Content reads (a file-selection helper may stat and list).
    const CONTENT_READS: [&str; 6] = [
        "fs::read(",
        "read_to_string",
        "read_regular_",
        "File::open",
        "OpenOptions",
        "hosted_patch_uuid",
    ];

    fn check(name: &str, src: &str) {
        let prod = src.split("#[cfg(test)]").next().unwrap_or_default();
        let fs_at = prod.find(FILE_SELECTION);
        let view_at = prod.find(REGISTRY_VIEW);
        if let (Some(f), Some(v)) = (fs_at, view_at) {
            assert!(
                f < v,
                "{name}: file selection must precede the registry view"
            );
        }
        let model_end = fs_at.or(view_at).unwrap_or(prod.len());
        // Skip the module docs and imports: the model starts after them.
        let model = &prod[..model_end];
        let model_code: String = model
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.starts_with("use "))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in IMPURE {
            assert!(
                !model_code.contains(needle),
                "{name}: the entry-model section uses `{needle}` — entry models are pure \
                 (module docs)"
            );
        }
        if let Some(f) = fs_at {
            let selection = &prod[f..view_at.unwrap_or(prod.len())];
            for needle in CONTENT_READS {
                assert!(
                    !selection.contains(needle),
                    "{name}: the file-selection section uses `{needle}` — it may only stat \
                     and list (module docs)"
                );
            }
        }
    }

    #[test]
    fn format_files_keep_model_file_selection_and_view_sections() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let dir = src.join("vendor/lock_inventory");
        let formats = [
            "npm.rs",
            "npm_family.rs",
            "pnpm.rs",
            "yarn.rs",
            "bun.rs",
            "cargo.rs",
            "golang.rs",
            "composer.rs",
            "gem.rs",
            "pypi.rs",
        ];
        for name in formats {
            let text = std::fs::read_to_string(dir.join(name)).expect("read format file");
            assert!(
                text.contains(REGISTRY_VIEW),
                "{name}: no `{REGISTRY_VIEW}` marker"
            );
            check(name, &text);
        }
        // Vendor-side readers lockfile discovery imports.
        for rel in ["vendor/nuget_config.rs", "vendor/maven_pom.rs"] {
            let text = std::fs::read_to_string(src.join(rel)).expect("read reader module");
            check(rel, &text);
        }
        // Read-only entry points of writer-owned modules sit in a
        // `// ── pure reader ──` region (to the next `// ──` marker), held to
        // the model rule while the rest of the module keeps its I/O.
        for rel in [
            "vendor/go_mod_edit.rs",
            "vendor/go_sum_edit.rs",
            "vendor/cargo_config.rs",
            "vendor/cargo_manifest.rs",
            "vendor/nuget_config.rs",
            "vendor/maven_pom.rs",
        ] {
            let text = std::fs::read_to_string(src.join(rel)).expect("read reader module");
            assert!(
                text.contains(PURE_READER),
                "{rel}: no `{PURE_READER}` marker"
            );
            let found = pure_reader_violations(&text);
            assert!(
                found.is_empty(),
                "{rel}: a `{PURE_READER}` region uses {found:?} (module docs)"
            );
        }
    }

    /// The impure needles used inside `// ── pure reader ──` regions of
    /// `text`'s production part.
    fn pure_reader_violations(text: &str) -> Vec<&'static str> {
        let prod = text.split("#[cfg(test)]").next().unwrap_or_default();
        let mut found = Vec::new();
        let mut rest = prod;
        while let Some(at) = rest.find(PURE_READER) {
            let region = &rest[at + PURE_READER.len()..];
            let end = region.find("\n// ──").unwrap_or(region.len());
            let code: String = region[..end]
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            found.extend(IMPURE.iter().copied().filter(|n| code.contains(n)));
            rest = &region[end..];
        }
        found
    }

    #[test]
    fn pure_reader_regions_reject_io_up_to_the_next_marker() {
        let ok = "// ── pure reader ──\nfn f(s: &str) -> bool { s.is_empty() }\n\
                  // ── writer ──\nasync fn g() { tokio::fs::read(\"x\").await; }\n";
        assert!(pure_reader_violations(ok).is_empty());
        let bad = "// ── pure reader ──\nasync fn f() { std::fs::read(\"x\"); }\n";
        assert_eq!(pure_reader_violations(bad), vec!["std::fs", "async fn"]);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recover_tests;

#[cfg(test)]
mod python_lock_union_tests;
