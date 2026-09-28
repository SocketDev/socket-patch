//! `Cargo.lock` (formats v1–v4) and its hosted splices: the ONE model of
//! the format.
//!
//! [`CargoLock`] parses a lock once (`toml_edit`) and answers what the modes
//! ask of it:
//!
//! * [`CargoLock::entries`] — the registry inventory (`scan` / `get`
//!   lockfile supplements, `vendor`'s pristine fetch);
//! * [`CargoLock::packages`] — every `[[package]]` as cargo resolves it
//!   ([`LockedPackage`], a v1 lock's `[metadata]` checksums included), the
//!   raw material lockfile discovery (`vex::discover::cargo`) classifies as
//!   hosted / vendored refs and the vendor probes rank;
//! * [`CargoLock::dependents`] — the packages whose `dependencies` name a
//!   crate (the hosted planner's unpinnable-dependents refusal);
//! * [`CargoLock::vendored_in_use`] — whether the lock builds a vendored
//!   `[patch]` copy ([`CopyClaim`]);
//! * [`hosted::plan_cargo_lock`] — the hosted planner's lock splice, and the
//!   line-grammar probes the hosted rewriter reads with;
//! * the vendored planner (`vendor::cargo_lock`) edits the same document
//!   with `toml_edit`;
//!
//! Everything here is pure; the callers own the reads.

pub(crate) mod hosted;

use toml_edit::{DocumentMut, Item};

use crate::utils::digest::is_hex;
use crate::utils::purl::simple_purl;
use crate::vendor::cargo_tag;
use crate::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};


// ── entry model ──

/// The `[metadata]` key a v1 lock files `name`+`version`'s checksum under.
pub(crate) fn metadata_checksum_key(name: &str, version: &str, source: &str) -> String {
    format!("checksum {name} {version} ({source})")
}

/// One `[[package]]` of a parsed `Cargo.lock`, as cargo resolves it — the
/// read model every Cargo.lock reader shares (the lock inventory, the vendor
/// probes, lockfile discovery, the hosted planner's dependents check), so a v1 lock's `[metadata]` checksums
/// and a missing `source` read the same everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockedPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    /// `None` for a workspace member, a path dependency, or a `[patch]` path
    /// copy (the vendored "detached" shape).
    pub(crate) source: Option<String>,
    /// The inline `checksum` (v2+), else a v1 lock's `[metadata]`
    /// `"checksum <name> <version> (<source>)"` entry — the same pin.
    pub(crate) checksum: Option<String>,
    /// The `dependencies` references as spelled (`"name"`, `"name
    /// version"`, `"name version (source)"`; see [`parse_ref`]).
    pub(crate) dependencies: Vec<String>,
}

/// Every `[[package]]` of `doc` (lock formats v1–v4), in lock order; an
/// entry without a string `name` and `version` is skipped. A lock with no
/// packages has no `package` key and yields nothing.
pub(crate) fn locked_packages(doc: &DocumentMut) -> Vec<LockedPackage> {
    let metadata = doc.get("metadata").and_then(Item::as_table_like);
    let metadata_checksum = |name: &str, version: &str, source: Option<&str>| {
        let key = metadata_checksum_key(name, version, source?);
        metadata?.get(&key)?.as_str().map(str::to_string)
    };
    doc.get("package")
        .and_then(Item::as_array_of_tables)
        .map(|pkgs| {
            pkgs.iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_string();
                    let version = t.get("version")?.as_str()?.to_string();
                    let source = t.get("source").and_then(Item::as_str).map(str::to_string);
                    let checksum = t
                        .get("checksum")
                        .and_then(Item::as_str)
                        .map(str::to_string)
                        .or_else(|| metadata_checksum(&name, &version, source.as_deref()));
                    let dependencies = t
                        .get("dependencies")
                        .and_then(Item::as_array)
                        .map(|deps| {
                            deps.iter()
                                .filter_map(|d| d.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(LockedPackage {
                        name,
                        version,
                        source,
                        checksum,
                        dependencies,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `(name, version)` of every `[[patch.unused]]` entry: a `[patch]` cargo
/// resolved and then did NOT use in the crate graph — the lock's own record
/// that a patch (e.g. a vendored copy) is not what builds.
pub(crate) fn unused_patches(doc: &DocumentMut) -> Vec<(String, String)> {
    doc.get("patch")
        .and_then(|patch| patch.get("unused"))
        .and_then(Item::as_array_of_tables)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|t| {
                    Some((
                        t.get("name")?.as_str()?.to_string(),
                        t.get("version")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// How `Cargo.lock` relates to the `[patch]` path copy of `name`@`version`
/// vendored for patch `uuid` ([`vendored_copy_claim`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyClaim<'a> {
    /// The lock builds this copy.
    Consumed,
    /// The lock builds the copy tagged for ANOTHER patch uuid (and none
    /// tagged for this one): a stale lock, or a `[patch]` override
    /// elsewhere.
    OtherTag(&'a str),
    /// The copy is tagged, but the lock holds only UNTAGGED sourceless
    /// entries: cargo built some other untagged crate (a config-level
    /// override, a user path dependency), never this copy.
    UntaggedOverride,
    /// No sourceless entry for it, or cargo recorded the patch as
    /// `[[patch.unused]]`.
    NotConsumed,
}

/// Whether the lock BUILDS the `[patch]` path copy of `name`@`version`
/// vendored for patch `uuid`. `copy_tagged`: the copy's own `Cargo.toml`
/// carries a Socket version tag (every copy vendored since tagged
/// versions; `false` for a copy vendored before them, or none on disk).
///
/// * a SOURCELESS entry at the tagged version `<version>+socket.<uuid>`
///   (and no `[[patch.unused]]` for it) is this copy — whatever untagged
///   sourceless siblings exist (real cargo 1.97 locks a member's own path
///   dependency on a same-version fork beside the tagged copy);
/// * otherwise a sourceless entry tagged for ANOTHER uuid is another
///   copy's resolution → [`CopyClaim::OtherTag`], even beside an untagged
///   sibling;
/// * an UNTAGGED sourceless entry is the pre-tag legacy shape only while
///   the copy is untagged too: cargo locks a tagged copy at its tagged
///   version, so for a tagged copy the untagged entry is something else
///   cargo built → [`CopyClaim::UntaggedOverride`].
///
/// A sourceless entry alone does not prove the copy builds — a path
/// dependency on the user's own checkout of the crate is sourceless too,
/// and cargo records the `[patch]` it resolved but left out of the graph as
/// `[[patch.unused]]` (real cargo 1.97: `serde = { path = "my-serde" }`
/// beside a stale `[patch]` locks a sourceless serde AND
/// `[[patch.unused]] serde`).
pub(crate) fn vendored_copy_claim<'a>(
    pkgs: &'a [LockedPackage],
    unused: &[(String, String)],
    name: &str,
    version: &str,
    uuid: &str,
    copy_tagged: bool,
) -> CopyClaim<'a> {
    let mut own = false;
    let mut other: Option<&'a str> = None;
    let mut untagged = false;
    for p in pkgs
        .iter()
        .filter(|p| p.name == name && p.source.is_none() && cargo_tag::denotes(&p.version, version))
    {
        match cargo_tag::tag_uuid(&p.version) {
            Some(tag) if tag == uuid => own = true,
            Some(tag) => {
                other.get_or_insert(tag);
            }
            None => untagged = true,
        }
    }
    let unused_hit = unused
        .iter()
        .any(|(n, v)| n == name && cargo_tag::denotes(v, version));
    if own {
        return if unused_hit {
            CopyClaim::NotConsumed
        } else {
            CopyClaim::Consumed
        };
    }
    if let Some(tag) = other {
        return CopyClaim::OtherTag(tag);
    }
    if !untagged || unused_hit {
        return CopyClaim::NotConsumed;
    }
    if copy_tagged {
        CopyClaim::UntaggedOverride
    } else {
        CopyClaim::Consumed
    }
}

/// `(name, version, source)` of a dependency reference string
/// (`"name"`, `"name version"`, `"name version (source)"`).
pub(crate) fn parse_ref(spelled: &str) -> (&str, Option<&str>, Option<&str>) {
    let mut parts = spelled.splitn(3, ' ');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();
    let source = parts
        .next()
        .and_then(|s| s.strip_prefix('('))
        .and_then(|s| s.strip_suffix(')'));
    (name, version, source)
}


// ── the model ──

/// One `Cargo.lock`, parsed once (see the module docs).
#[derive(Debug)]
pub struct CargoLock {
    packages: Vec<LockedPackage>,
    unused: Vec<(String, String)>,
}

impl CargoLock {
    /// The model of an already-parsed lock document.
    pub fn from_doc(doc: &DocumentMut) -> Self {
        CargoLock {
            packages: locked_packages(doc),
            unused: unused_patches(doc),
        }
    }

    /// Parse a lock text; `Err` when it is not TOML (cargo itself refuses
    /// to build from it).
    pub fn parse(text: &str) -> Result<Self, toml_edit::TomlError> {
        Ok(Self::from_doc(&text.parse::<DocumentMut>()?))
    }

    /// Every `[[package]]`, in lock order.
    pub(crate) fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }

    /// The registry inventory: one entry per SOURCED `[[package]]`
    /// (workspace members and vendored copies have none), under its purl
    /// identity (a Socket tag stripped). Only a crates.io entry whose
    /// checksum is a 64-hex `.crate` sha256 — and whose version is not
    /// tagged — carries a verifier; git / custom-registry sources stay
    /// listed for discovery without one.
    pub fn entries(&self) -> Vec<LockfileEntry> {
        let mut out = Vec::new();
        for pkg in &self.packages {
            let Some(source) = &pkg.source else {
                continue; // workspace member
            };
            let version = cargo_tag::strip_tag(&pkg.version).to_string();
            let tagged = version != pkg.version;
            let Some(purl) = simple_purl("cargo", &pkg.name, &version) else {
                continue;
            };
            let crates_io = source.contains("github.com/rust-lang/crates.io-index")
                || source.contains("index.crates.io");
            // The crates.io provenance is recorded exactly where the checksum
            // is kept as the `.crate`'s sha256.
            let (integrity, source_kind) = match &pkg.checksum {
                Some(c) if crates_io && !tagged && is_hex(c, 64) => {
                    (LockIntegrity::Sha256Hex(c.clone()), SourceKind::CratesIo)
                }
                _ => (LockIntegrity::None, SourceKind::Unspecified),
            };
            out.push(LockfileEntry {
                ecosystem: "cargo",
                source_kind,
                purl,
                name: pkg.name.clone(),
                version,
                resolved: None,
                integrity,
            });
        }
        out
    }

    /// Every package whose `dependencies` reference `name` at `version` (or
    /// by plain name, which cargo writes while the name is unambiguous), in
    /// lock order.
    pub(crate) fn dependents<'a>(
        &'a self,
        name: &'a str,
        version: &'a str,
    ) -> impl Iterator<Item = &'a LockedPackage> + 'a {
        self.packages.iter().filter(move |p| {
            p.dependencies.iter().any(|d| {
                let (n, v, _) = parse_ref(d);
                n == name && v.is_none_or(|v| v == version)
            })
        })
    }

    /// How the lock relates to the vendored `[patch]` copy of
    /// `name`@`version` for patch `uuid` ([`vendored_copy_claim`]).
    pub(crate) fn vendored_in_use(
        &self,
        name: &str,
        version: &str,
        uuid: &str,
        copy_tagged: bool,
    ) -> CopyClaim<'_> {
        vendored_copy_claim(&self.packages, &self.unused, name, version, uuid, copy_tagged)
    }
}

