//! Surgical `Cargo.lock` edits for the cargo vendor backend.
//!
//! A `[patch.crates-io]` path entry alone does NOT survive `cargo build
//! --locked`: the lock still records the crate's registry `source` +
//! `checksum`, so cargo wants to re-lock and `--locked` fails closed with a
//! generic error (spike-verified — `spikes/PHASE0-FINDINGS.txt` cargo claim
//! 1). Deleting exactly the `source` and `checksum` keys from the crate's
//! `[[package]]` entry makes cargo accept the path patch as the lock's sole
//! provider; the edited lock is **byte-stable across builds** (locked and
//! unlocked, claims 2/4) and the `dependencies` arrays reference the crate by
//! plain name, so nothing else needs rewriting (claim 8).
//!
//! Claim 8 holds only while `name`+`version` is unique in the lock. When the
//! same name+version resolves from MULTIPLE sources (a registry entry plus a
//! same-version git fork — a legal, cargo-generated shape), consumers'
//! `dependencies` arrays disambiguate with FULL package-id strings
//! (`"cfg-if 1.0.0 (registry+…)"`); detaching `source`/`checksum` from one
//! entry dangles those references and breaks `--locked` builds. Vendor
//! refuses that shape upstream via [`count_lock_entries`].
//!
//! The lock is generated-but-committed, so edits are text-preserving
//! (`toml_edit`): untouched entries, the `@generated` header comment, and the
//! `version = 4` line keep their exact bytes — zero formatting churn in the
//! committed diff.
//!
//! Lock format v1 (cargo < 1.41, still read by every cargo and never
//! rewritten under `--locked`) spells the pair differently: the entry holds
//! only `source`, the checksum sits in the trailing `[metadata]` table as
//! `"checksum <name> <version> (<source>)"`, and dependents reference the
//! crate by that full `"<name> <version> (<source>)"` id. Detaching there
//! also drops the `[metadata]` key and rewrites the references to the
//! sourceless `"<name> <version>"` form cargo v1 uses for path packages —
//! otherwise they name a package the lock no longer has and cargo refuses
//! the lock under `--locked` (real cargo 1.93: "cannot update the lock
//! file … because --locked was passed"). Restore reverses all three.
//!
//! Tagged versions (v5): the detached entry's `version` becomes the copy's
//! TAGGED version `<version>+socket.<uuid>` ([`super::cargo_tag`]) — exactly
//! what cargo itself locks when it resolves the `[patch]` against the
//! tagged copy — and every dependency reference that spells the version
//! (`"<name> <version>"`, v1's `"<name> <version> (<source>)"`) is rewritten
//! to `"<name> <tagged>"`; plain-name references need nothing. A reference
//! the rewrite cannot account for (a leftover spelling, a v1 `replace`, an
//! existing entry at the tagged version) refuses the edit
//! ([`LockEditError::Inconsistent`]) instead of writing a lock cargo would
//! reject. [`retag_lock_entry`] moves an already-detached entry to a new
//! tag (a uuid bump, or an untagged pre-tag vendor), and
//! [`restore_lock_entry`] drops the tag with the rest of the detach.
//!
//! The removed `source`/`checksum` pair is not recoverable offline (the
//! checksum is the sha256 of the registry `.crate` tarball, not of the
//! extracted tree), so [`detach_lock_entry`] returns it as the vendor ledger's
//! [`CargoLockOriginal`] and [`restore_lock_entry`] writes it back on revert.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use toml_edit::{DocumentMut, Item, Table};

use super::cargo_tag;
use super::state::CargoLockOriginal;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};

/// Why a lock edit could not be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockEditError {
    /// `Cargo.lock` does not exist (callers proceed with a warning — the
    /// first build generates a path-form lock).
    NoLockfile,
    /// No `[[package]]` entry matches the name+version.
    EntryMissing,
    /// The entry has no `source` (a workspace/path/git dependency) — there is
    /// nothing registry-shaped to detach; callers refuse upstream.
    NotRegistry,
    /// The version cannot be (re)tagged consistently: a dependency
    /// reference or entry the rewrite cannot keep in step with it.
    Inconsistent(String),
    Io(String),
    Parse(String),
}

impl std::fmt::Display for LockEditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLockfile => write!(f, "Cargo.lock not found"),
            Self::EntryMissing => write!(f, "no matching [[package]] entry in Cargo.lock"),
            Self::NotRegistry => write!(
                f,
                "the Cargo.lock entry is not a registry dependency (no `source`)"
            ),
            Self::Inconsistent(e) => write!(f, "Cargo.lock cannot be retagged consistently: {e}"),
            Self::Io(e) => write!(f, "Cargo.lock I/O error: {e}"),
            Self::Parse(e) => write!(f, "Cargo.lock parse error: {e}"),
        }
    }
}

/// Read + parse `<root>/Cargo.lock`, mapping errors to [`LockEditError`]
/// (the lock inventory reads the lock through it too).
pub(crate) async fn read_lock(
    project_root: &Path,
) -> Result<(std::path::PathBuf, DocumentMut), LockEditError> {
    let path = project_root.join("Cargo.lock");
    let content = match read_regular_to_string(&path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LockEditError::NoLockfile)
        }
        Err(e) => return Err(LockEditError::Io(e.to_string())),
    };
    let doc = content
        .parse::<DocumentMut>()
        .map_err(|e| LockEditError::Parse(e.to_string()))?;
    Ok((path, doc))
}

/// The `[[package]]` table for `name` whose version DENOTES `version` —
/// the version itself or a Socket-tagged spelling of it (multi-entry
/// name+version shapes are refused upstream by [`count_lock_entries`]).
fn find_denoting_mut<'a>(
    doc: &'a mut DocumentMut,
    name: &str,
    version: &str,
) -> Option<&'a mut Table> {
    doc.get_mut("package")?
        .as_array_of_tables_mut()?
        .iter_mut()
        .find(|t| {
            t.get("name").and_then(Item::as_str) == Some(name)
                && t.get("version")
                    .and_then(Item::as_str)
                    .is_some_and(|v| cargo_tag::denotes(v, version))
        })
}

/// Replace the entry's `version` value, keeping its formatting.
fn set_version(table: &mut Table, version: &str) {
    if let Some(value) = table.get_mut("version").and_then(Item::as_value_mut) {
        let decor = value.decor().clone();
        *value = toml_edit::Value::from(version);
        *value.decor_mut() = decor;
    }
}

/// The `[metadata]` key a v1 lock files `name`+`version`'s checksum under.
fn metadata_checksum_key(name: &str, version: &str, source: &str) -> String {
    format!("checksum {name} {version} ({source})")
}

/// One `[[package]]` of a parsed `Cargo.lock`, as cargo resolves it — the
/// read model every Cargo.lock reader shares (the lock inventory, the vendor
/// probes below, lockfile discovery), so a v1 lock's `[metadata]` checksums
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
                    Some(LockedPackage {
                        name,
                        version,
                        source,
                        checksum,
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

/// Whether the lock BUILDS the `[patch]` path copy of `name`@`version`
/// vendored for patch `uuid`: it holds a SOURCELESS `[[package]]` for that
/// name at the copy's tagged version `<version>+socket.<uuid>` — or, for a
/// copy vendored before tagged versions, at the untagged version — and no
/// `[[patch.unused]]` entry for it. A sourceless entry tagged for ANOTHER
/// uuid is another copy's resolution: not this one. A sourceless entry alone
/// does not prove the copy builds — a path dependency on the user's own
/// checkout of the crate is sourceless too, and cargo records the `[patch]`
/// it resolved but left out of the graph as `[[patch.unused]]` (real cargo
/// 1.97: `serde = { path = "my-serde" }` beside a stale `[patch]` locks a
/// sourceless serde AND `[[patch.unused]] serde`).
pub(crate) fn vendored_copy_consumed(
    pkgs: &[LockedPackage],
    unused: &[(String, String)],
    name: &str,
    version: &str,
    uuid: &str,
) -> bool {
    pkgs.iter().any(|p| {
        p.name == name
            && p.source.is_none()
            && (p.version == version || cargo_tag::split_tag(&p.version) == Some((version, uuid)))
    }) && !unused
        .iter()
        .any(|(n, v)| n == name && cargo_tag::denotes(v, version))
}

/// The uuid of the Socket tag on the SOURCELESS `[[package]]` for `name`
/// that denotes `version`: `Some(None)` for an untagged sourceless entry,
/// `None` when there is no sourceless entry for it.
pub(crate) fn detached_tag<'a>(
    pkgs: &'a [LockedPackage],
    name: &str,
    version: &str,
) -> Option<Option<&'a str>> {
    pkgs.iter()
        .find(|p| p.name == name && p.source.is_none() && cargo_tag::denotes(&p.version, version))
        .map(|p| cargo_tag::tag_uuid(&p.version))
}

/// A v1 lock: no top-level `version` key and a `[metadata]` table (kept,
/// even emptied, by [`detach_lock_entry`] — so a detached v1 lock still
/// reads as v1 on restore).
fn is_v1_lock(doc: &DocumentMut) -> bool {
    doc.get("version").is_none() && doc.get("metadata").is_some_and(Item::is_table_like)
}

/// Every table that carries a `dependencies` array: each `[[package]]`,
/// plus the `[root]` table of the oldest v1 locks.
fn dependency_tables_mut(doc: &mut DocumentMut) -> Vec<&mut Table> {
    let mut out: Vec<&mut Table> = Vec::new();
    let (root, pkgs) = {
        let table = doc.as_table_mut();
        let mut root = None;
        let mut pkgs = None;
        for (key, item) in table.iter_mut() {
            match key.get() {
                "root" => root = item.as_table_mut(),
                "package" => pkgs = item.as_array_of_tables_mut(),
                _ => {}
            }
        }
        (root, pkgs)
    };
    out.extend(root);
    if let Some(pkgs) = pkgs {
        out.extend(pkgs.iter_mut());
    }
    out
}

/// `(name, version, source)` of a dependency reference string
/// (`"name"`, `"name version"`, `"name version (source)"`).
fn parse_ref(spelled: &str) -> (&str, Option<&str>, Option<&str>) {
    let mut parts = spelled.splitn(3, ' ');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();
    let source = parts
        .next()
        .and_then(|s| s.strip_prefix('('))
        .and_then(|s| s.strip_suffix(')'));
    (name, version, source)
}

/// Rewrite every dependency reference to `name` at exactly `version` —
/// `"name version"`, or `"name version (source)"` when `source` is given —
/// to `to`, keeping each entry's formatting.
fn rewrite_version_refs(
    doc: &mut DocumentMut,
    name: &str,
    version: &str,
    source: Option<&str>,
    to: &str,
) {
    for table in dependency_tables_mut(doc) {
        let Some(deps) = table.get_mut("dependencies").and_then(Item::as_array_mut) else {
            continue;
        };
        for i in 0..deps.len() {
            let hit = deps
                .get(i)
                .and_then(toml_edit::Value::as_str)
                .is_some_and(|spelled| {
                    let (n, v, s) = parse_ref(spelled);
                    n == name && v == Some(version) && (s.is_none() || s == source)
                });
            if hit {
                deps.replace(i, to);
            }
        }
    }
}

/// Fail when anything in the lock still names `name` at exactly
/// `version` after the rewrite — a reference in a spelling the rewrite
/// does not own (another source), or a v1 `replace` — or when another
/// entry already sits at the new version `to`: cargo would reject the
/// edited lock under `--locked`.
fn ensure_consistent(
    doc: &DocumentMut,
    name: &str,
    version: &str,
    to: &str,
) -> Result<(), LockEditError> {
    let names = |spelled: &str| {
        let (n, v, _) = parse_ref(spelled);
        n == name && v == Some(version)
    };
    let tables = doc.get("root").and_then(Item::as_table).into_iter().chain(
        doc.get("package")
            .and_then(Item::as_array_of_tables)
            .into_iter()
            .flat_map(|pkgs| pkgs.iter()),
    );
    let mut at_target = 0;
    for table in tables {
        let deps = table
            .get("dependencies")
            .and_then(Item::as_array)
            .into_iter()
            .flat_map(|a| a.iter())
            .filter_map(toml_edit::Value::as_str);
        let replace = table.get("replace").and_then(Item::as_str);
        if let Some(bad) = deps.chain(replace).find(|s| names(s)) {
            return Err(LockEditError::Inconsistent(format!(
                "a reference `{bad}` would be left naming the old version"
            )));
        }
        if table.get("name").and_then(Item::as_str) == Some(name)
            && table.get("version").and_then(Item::as_str) == Some(to)
        {
            at_target += 1;
        }
    }
    if at_target > 1 {
        return Err(LockEditError::Inconsistent(format!(
            "another `{name} {to}` entry is already locked"
        )));
    }
    Ok(())
}

/// Commit the edited lock atomically (stage + fsync + rename). The lock is a
/// committed file shared with cargo itself; a torn write would corrupt the
/// whole project's resolution, so never truncate-in-place. Mode-preserving:
/// the lock is a user-owned file we merely edit, so the swapped-in inode must
/// keep its permission bits rather than reset them to umask defaults.
async fn write_lock(path: &Path, doc: &DocumentMut) -> Result<(), LockEditError> {
    atomic_write_bytes_preserving_mode(path, doc.to_string().as_bytes())
        .await
        .map_err(|e| LockEditError::Io(e.to_string()))
}

/// Detach the `[[package]]` entry for `name`+`version` from the registry
/// and tag it for patch `uuid`: remove its `source` and `checksum` keys,
/// set its `version` to `<version>+socket.<uuid>` and point every
/// version-spelled dependency reference at the tagged version, returning
/// the verbatim originals for the vendor ledger. Everything else in the
/// lock — including the entry's own `name`/`dependencies` — keeps its exact
/// bytes.
///
/// `dry_run` performs the full lookup and edit (so refusals are accurate)
/// but writes nothing.
pub async fn detach_lock_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    dry_run: bool,
) -> Result<CargoLockOriginal, LockEditError> {
    let (path, mut doc) = read_lock(project_root).await?;
    let table = find_denoting_mut(&mut doc, name, version).ok_or(LockEditError::EntryMissing)?;

    // A workspace/path/git dependency has no `source` — vendoring it would be
    // wrong (the user already controls those bytes); refuse.
    let source = match table.get("source").and_then(Item::as_str) {
        Some(s) => s.to_string(),
        None => return Err(LockEditError::NotRegistry),
    };
    if table.get("version").and_then(Item::as_str) != Some(version) {
        return Err(LockEditError::Inconsistent(format!(
            "the registry entry for {name} {version} already carries a Socket tag"
        )));
    }
    let mut checksum = table
        .get("checksum")
        .and_then(Item::as_str)
        .map(str::to_string);
    let tagged = cargo_tag::tag_version(version, uuid);

    table.remove("source");
    table.remove("checksum");
    set_version(table, &tagged);

    // v1: the checksum lives in `[metadata]`, and dependents name the crate
    // by its full id (any format may spell an ambiguous ref that way).
    let key = metadata_checksum_key(name, version, &source);
    if let Some(meta) = doc.get_mut("metadata").and_then(Item::as_table_like_mut) {
        if let Some(sum) = meta.remove(&key) {
            checksum = checksum.or_else(|| sum.as_str().map(str::to_string));
        }
    }
    let to = format!("{name} {tagged}");
    rewrite_version_refs(&mut doc, name, version, Some(&source), &to);
    ensure_consistent(&doc, name, version, &tagged)?;

    if !dry_run {
        write_lock(&path, &doc).await?;
    }
    Ok(CargoLockOriginal { source, checksum })
}

/// Move the already-detached (sourceless) entry for `name`+`version` to the
/// tag of patch `uuid` — a uuid bump, or an entry an earlier release
/// detached without a tag — with its version-spelled references.
/// `Ok(Some(previous version))` when it changed, `Ok(None)` when it
/// already carries this tag; [`retag_lock_entry_to`] with the returned
/// version undoes it.
pub async fn retag_lock_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    dry_run: bool,
) -> Result<Option<String>, LockEditError> {
    let tagged = cargo_tag::tag_version(version, uuid);
    retag_lock_entry_to(project_root, name, version, &tagged, dry_run).await
}

/// [`retag_lock_entry`] to an explicit `target` spelling of `version`
/// (tagged or not).
pub async fn retag_lock_entry_to(
    project_root: &Path,
    name: &str,
    version: &str,
    target: &str,
    dry_run: bool,
) -> Result<Option<String>, LockEditError> {
    let (path, mut doc) = read_lock(project_root).await?;
    let table = find_denoting_mut(&mut doc, name, version).ok_or(LockEditError::EntryMissing)?;
    if table.get("source").is_some() {
        return Err(LockEditError::Inconsistent(format!(
            "the entry for {name} {version} still carries a registry source"
        )));
    }
    let current = table
        .get("version")
        .and_then(Item::as_str)
        .unwrap_or_default()
        .to_string();
    if current == target {
        return Ok(None);
    }
    set_version(table, target);
    rewrite_version_refs(&mut doc, name, &current, None, &format!("{name} {target}"));
    ensure_consistent(&doc, name, &current, target)?;
    if !dry_run {
        write_lock(&path, &doc).await?;
    }
    Ok(Some(current))
}

/// Re-attach the original `source`/`checksum` to the `name`+`version` entry on
/// revert and drop its Socket tag (with the references
/// [`detach_lock_entry`] retargeted). Returns `Ok(false)` when the entry is no
/// longer in patch `uuid`'s detached form — it is absent (the dependency was
/// dropped), already carries a `source` (cargo/the user re-resolved it), or
/// is tagged for ANOTHER patch — in which case the lock is left alone and
/// the caller warns instead of clobbering a newer resolution. An untagged
/// sourceless entry (vendored before tagged versions) is restored.
pub async fn restore_lock_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    original: &CargoLockOriginal,
    dry_run: bool,
) -> Result<bool, LockEditError> {
    let (path, mut doc) = read_lock(project_root).await?;
    let v1 = is_v1_lock(&doc);
    let Some(table) = find_denoting_mut(&mut doc, name, version) else {
        return Ok(false);
    };
    if table.get("source").is_some() {
        return Ok(false);
    }
    let current = table
        .get("version")
        .and_then(Item::as_str)
        .unwrap_or_default()
        .to_string();
    if current != version && cargo_tag::tag_uuid(&current) != Some(uuid) {
        return Ok(false);
    }
    set_version(table, version);

    table.insert("source", toml_edit::value(original.source.as_str()));
    if let (Some(checksum), false) = (&original.checksum, v1) {
        table.insert("checksum", toml_edit::value(checksum.as_str()));
    }
    // `insert` appends, but cargo's canonical key order is
    // name/version/source/checksum/dependencies — restore it so the reverted
    // lock is byte-identical to what cargo originally generated (no diff
    // churn, and the round-trip is verifiable in tests).
    let rank = |k: &str| match k {
        "name" => 0,
        "version" => 1,
        "source" => 2,
        "checksum" => 3,
        _ => 4, // dependencies / replace / anything else stays after
    };
    table.sort_values_by(|k1, _, k2, _| rank(k1.get()).cmp(&rank(k2.get())));

    if v1 {
        // Back into `[metadata]` (cargo writes its keys sorted).
        if let (Some(checksum), Some(meta)) = (
            &original.checksum,
            doc.get_mut("metadata").and_then(Item::as_table_mut),
        ) {
            meta.insert(
                &metadata_checksum_key(name, version, &original.source),
                toml_edit::value(checksum.as_str()),
            );
            meta.sort_values();
        }
    }
    // Dependents named the detached entry `"<name> <tagged>"`: back to the
    // original spelling (v1's full id, v2+'s `"<name> <version>"`).
    let back = if v1 {
        format!("{name} {version} ({})", original.source)
    } else {
        format!("{name} {version}")
    };
    if v1 || current != version {
        rewrite_version_refs(&mut doc, name, &current, None, &back);
    }

    if !dry_run {
        write_lock(&path, &doc).await?;
    }
    Ok(true)
}

/// Parse `<root>/Cargo.lock` into `name -> {resolved versions}`. Returns
/// `None` when the lockfile is absent, unreadable, unparseable, or missing the
/// `[[package]]` array — in every such case the caller's version cross-check
/// is skipped (a malformed lock would itself break a real `cargo build`).
/// Multi-version aware: a v4 lock may resolve the same name at several
/// versions. A Socket-tagged vendored entry counts as its untagged version.
/// Reads only the project lockfile: no registry, no network.
pub async fn read_locked_versions(project_root: &Path) -> Option<HashMap<String, HashSet<String>>> {
    let (_path, doc) = read_lock(project_root).await.ok()?;
    doc.get("package")?.as_array_of_tables()?;
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for pkg in locked_packages(&doc) {
        let version = cargo_tag::strip_tag(&pkg.version).to_string();
        map.entry(pkg.name).or_default().insert(version);
    }
    Some(map)
}

/// Read-only shape of the `[[package]]` entry for `name`+`version` — the
/// lock-level truth source cross-mode takeover logic keys off (which mode a
/// crate's resolution actually points at right now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockEntryProbe {
    /// No `Cargo.lock`.
    NoLockfile,
    /// A `Cargo.lock` that cannot be read or parsed.
    Unreadable,
    /// The lock parses but has no entry at this name+version.
    EntryMissing,
    /// Entry present with no `source` — the vendored detached shape (the
    /// `[patch.crates-io]` path copy is the lock's sole provider) — with the
    /// uuid of its Socket tag (`None`: untagged, vendored before tagged
    /// versions).
    Detached(Option<String>),
    /// Entry present with this registry `source` (crates.io, a hosted
    /// socket-patch sparse index, or any other registry).
    Source(String),
}

/// Probe the `[[package]]` entry for `name`+`version` (or a Socket-tagged
/// spelling of it) without editing anything. Unreadable/unparseable locks
/// read as [`LockEntryProbe::Unreadable`] so callers stay fail-safe (cannot
/// determine ⇒ keep / stay silent).
pub async fn probe_lock_entry(project_root: &Path, name: &str, version: &str) -> LockEntryProbe {
    let doc = match read_lock(project_root).await {
        Ok((_path, doc)) => doc,
        Err(LockEditError::NoLockfile) => return LockEntryProbe::NoLockfile,
        Err(_) => return LockEntryProbe::Unreadable,
    };
    match locked_packages(&doc)
        .into_iter()
        .find(|p| p.name == name && cargo_tag::denotes(&p.version, version))
    {
        None => LockEntryProbe::EntryMissing,
        Some(LockedPackage {
            source: Some(source),
            ..
        }) => LockEntryProbe::Source(source),
        Some(p) => LockEntryProbe::Detached(cargo_tag::tag_uuid(&p.version).map(str::to_string)),
    }
}

/// Number of `[[package]]` entries matching `name`+`version`. More than one
/// means the lock resolves the same name+version from multiple sources (e.g.
/// registry + git fork), the shape whose `dependencies` arrays use full
/// package-id strings that [`detach_lock_entry`]'s surgery would dangle —
/// callers refuse to vendor it. A missing/unparseable lock (or one without a
/// `[[package]]` array) counts zero: the same "no usable lock" treatment as
/// [`read_locked_versions`].
pub async fn count_lock_entries(project_root: &Path, name: &str, version: &str) -> usize {
    let Ok((_path, doc)) = read_lock(project_root).await else {
        return 0;
    };
    locked_packages(&doc)
        .iter()
        .filter(|p| p.name == name && cargo_tag::denotes(&p.version, version))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const CHECKSUM: &str = "9d8f4e3bd2c8f1f5d1a3f5e7c9b1d3f5e7a9b1c3d5f7e9a1b3c5d7e9f1a3b5c7";
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID2: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

    /// A realistic cargo-1.93-shaped v4 lock (header comment, version line,
    /// plain-name dependencies array — spike claim 8).
    fn lock_body() -> String {
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\
             \n\
             [[package]]\n\
             name = \"app\"\n\
             version = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\
             \n\
             [[package]]\n\
             name = \"cfg-if\"\n\
             version = \"1.0.4\"\n\
             source = \"{SOURCE}\"\n\
             checksum = \"{CHECKSUM}\"\n"
        )
    }

    async fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Cargo.lock"), lock_body())
            .await
            .unwrap();
        dir
    }

    /// Cargo.lock v1: checksum in `[metadata]`, dependents referencing the
    /// crate by full id. REGRESSION: detach removed only the entry's
    /// `source`, leaving `"cfg-if 1.0.4 (registry+…)"` references (and the
    /// `[metadata]` checksum) naming a package the lock no longer has —
    /// real cargo then refuses the vendored lock under `--locked`.
    #[tokio::test]
    async fn detach_and_restore_a_v1_lock_follow_metadata_and_full_id_refs() {
        let other = "a".repeat(64);
        let v1 = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({SOURCE})\",\n \"log 0.4.20 ({SOURCE})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
             [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{SOURCE}\"\n\
             dependencies = [\n \"cfg-if 1.0.4 ({SOURCE})\",\n]\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n\
             \"checksum log 0.4.20 ({SOURCE})\" = \"{other}\"\n"
        );
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("Cargo.lock");
        tokio::fs::write(&lock, &v1).await.unwrap();

        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        assert_eq!(orig.source, SOURCE);
        assert_eq!(
            orig.checksum.as_deref(),
            Some(CHECKSUM),
            "read from [metadata]"
        );
        let detached = tokio::fs::read_to_string(&lock).await.unwrap();
        assert_eq!(
            detached,
            format!(
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
                 \"cfg-if 1.0.4+socket.{UUID}\",\n \"log 0.4.20 ({SOURCE})\",\n]\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4+socket.{UUID}\"\n\n\
                 [[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"{SOURCE}\"\n\
                 dependencies = [\n \"cfg-if 1.0.4+socket.{UUID}\",\n]\n\n\
                 [metadata]\n\"checksum log 0.4.20 ({SOURCE})\" = \"{other}\"\n"
            )
        );
        assert_eq!(
            probe_lock_entry(dir.path(), "cfg-if", "1.0.4").await,
            LockEntryProbe::Detached(Some(UUID.to_string()))
        );

        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        assert_eq!(tokio::fs::read_to_string(&lock).await.unwrap(), v1);
    }

    #[tokio::test]
    async fn detach_removes_only_source_and_checksum() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        assert_eq!(orig.source, SOURCE);
        assert_eq!(orig.checksum.as_deref(), Some(CHECKSUM));

        let body = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert!(!body.contains("source ="), "source line gone");
        assert!(!body.contains("checksum ="), "checksum line gone");
        // Everything else is byte-preserved: header, version line, the app
        // entry with its plain-name dependencies array, and cfg-if's name;
        // its version carries the patch uuid tag.
        assert!(body.starts_with("# This file is automatically @generated by Cargo.\n"));
        assert!(body.contains("version = 4\n"));
        assert!(body
            .contains("name = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if\",\n]\n"));
        assert!(body.contains(&format!(
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4+socket.{UUID}\"\n"
        )));
    }

    #[tokio::test]
    async fn detach_restore_round_trip_is_byte_identical() {
        let dir = fixture().await;
        let before = tokio::fs::read(dir.path().join("Cargo.lock"))
            .await
            .unwrap();

        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );

        let after = tokio::fs::read(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&before),
            String::from_utf8_lossy(&after),
            "restored lock must be byte-identical to the pristine fixture"
        );
    }

    #[tokio::test]
    async fn detach_missing_lock_is_no_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let err = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::NoLockfile);
    }

    #[tokio::test]
    async fn detach_missing_entry_and_wrong_version() {
        let dir = fixture().await;
        let err = detach_lock_entry(dir.path(), "nope", "1.0.4", UUID, false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::EntryMissing);
        // Version is part of the key — a different version must not match.
        let err = detach_lock_entry(dir.path(), "cfg-if", "9.9.9", UUID, false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::EntryMissing);
        // The refusals wrote nothing.
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn detach_path_dep_is_not_registry() {
        let dir = fixture().await;
        // `app` is the workspace member: no `source` key.
        let err = detach_lock_entry(dir.path(), "app", "0.1.0", UUID, false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::NotRegistry);
    }

    #[tokio::test]
    async fn detach_dry_run_reports_but_does_not_write() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, true)
            .await
            .unwrap();
        assert_eq!(orig.source, SOURCE);
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "dry-run must not write"
        );
    }

    #[tokio::test]
    async fn detach_unparseable_lock_is_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Cargo.lock"), "not = = toml [[[")
            .await
            .unwrap();
        let err = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap_err();
        assert!(matches!(err, LockEditError::Parse(_)));
    }

    /// Drift pin: a lock that GAINED a `[[patch.unused]]` table after vendor
    /// (a user added a dep whose resolution left an unused patch entry, or
    /// hand-edits) must still restore the detached entry cleanly — the extra
    /// table is untouched and the round trip stays byte-faithful for the
    /// edited entry.
    #[tokio::test]
    async fn restore_tolerates_patch_unused_table_gained_post_vendor() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();

        // Post-vendor drift: cargo appended a [[patch.unused]] section.
        let mut body = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        body.push_str("\n[[patch.unused]]\nname = \"other\"\nversion = \"2.0.0\"\n");
        tokio::fs::write(dir.path().join("Cargo.lock"), &body)
            .await
            .unwrap();

        let restored = restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
            .await
            .unwrap();
        assert!(
            restored,
            "detached entry must restore despite the extra table"
        );

        let after = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert!(after.contains(&format!("source = \"{SOURCE}\"")));
        assert!(after.contains(&format!("checksum = \"{CHECKSUM}\"")));
        assert!(
            after.contains("[[patch.unused]]") && after.contains("name = \"other\""),
            "the drift table must be left untouched: {after}"
        );
    }

    #[tokio::test]
    async fn restore_skips_re_resolved_and_absent_entries() {
        let dir = fixture().await;
        let orig = CargoLockOriginal {
            source: SOURCE.to_string(),
            checksum: Some(CHECKSUM.to_string()),
        };
        // The entry still has its registry source (the user/cargo re-resolved
        // it after a hand-revert) — restoring would clobber it: Ok(false).
        assert!(
            !restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        // The entry is gone entirely (the dependency was dropped): Ok(false).
        assert!(
            !restore_lock_entry(dir.path(), "gone", "1.0.0", UUID, &orig, false)
                .await
                .unwrap()
        );
        // Neither skip touched the file.
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn restore_dry_run_does_not_write() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        let detached = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, true)
                .await
                .unwrap()
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
                .await
                .unwrap(),
            detached,
            "dry-run restore must not write"
        );
    }

    #[tokio::test]
    async fn restore_entry_without_checksum() {
        // Some sources (git pins) have no checksum; restore must not invent one.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/x#abc\"\n",
        )
        .await
        .unwrap();
        let orig = detach_lock_entry(dir.path(), "x", "1.0.0", UUID, false)
            .await
            .unwrap();
        assert_eq!(orig.checksum, None);
        assert!(
            restore_lock_entry(dir.path(), "x", "1.0.0", UUID, &orig, false)
                .await
                .unwrap()
        );
        let body = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert!(body.contains("source = \"git+https://example.com/x#abc\""));
        assert!(!body.contains("checksum"));
    }

    #[tokio::test]
    async fn locked_versions_is_multi_version_aware() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n",
        )
        .await
        .unwrap();
        let map = read_locked_versions(dir.path()).await.unwrap();
        let versions = &map["cfg-if"];
        assert!(versions.contains("1.0.4") && versions.contains("0.1.10"));

        // Absent / unparseable lock → None (cross-check skipped).
        let empty = tempfile::tempdir().unwrap();
        assert!(read_locked_versions(empty.path()).await.is_none());
        tokio::fs::write(empty.path().join("Cargo.lock"), "[[[ nope")
            .await
            .unwrap();
        assert!(read_locked_versions(empty.path()).await.is_none());
    }

    /// The lock is a user-owned committed file we merely edit: the atomic
    /// rename must not reset its permission bits to umask defaults (a 0600
    /// private lock silently becoming 0644, a 0664 group-writable one locking
    /// the group out).
    #[cfg(unix)]
    #[tokio::test]
    async fn lock_edits_preserve_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture().await;
        let path = dir.path().join("Cargo.lock");
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();

        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600, "detach must not reset the lock's mode");

        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600, "restore must not reset the lock's mode");
    }

    /// Round trip for a realistic entry: mid-file (another `[[package]]`
    /// follows) and carrying a `dependencies` array, so restore's key re-sort
    /// must slot source/checksum between `version` and `dependencies`.
    #[tokio::test]
    async fn round_trip_mid_file_entry_with_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\
             \n\
             [[package]]\n\
             name = \"app\"\n\
             version = \"0.1.0\"\n\
             dependencies = [\n \"serde\",\n]\n\
             \n\
             [[package]]\n\
             name = \"serde\"\n\
             version = \"1.0.219\"\n\
             source = \"{SOURCE}\"\n\
             checksum = \"{CHECKSUM}\"\n\
             dependencies = [\n \"serde_derive\",\n]\n\
             \n\
             [[package]]\n\
             name = \"serde_derive\"\n\
             version = \"1.0.219\"\n\
             source = \"{SOURCE}\"\n\
             checksum = \"{CHECKSUM}\"\n"
        );
        tokio::fs::write(dir.path().join("Cargo.lock"), &body)
            .await
            .unwrap();

        let orig = detach_lock_entry(dir.path(), "serde", "1.0.219", UUID, false)
            .await
            .unwrap();
        assert!(
            restore_lock_entry(dir.path(), "serde", "1.0.219", UUID, &orig, false)
                .await
                .unwrap()
        );
        let after = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert_eq!(
            after, body,
            "mid-file entry with dependencies must round-trip byte-identically"
        );
    }

    /// AUDIT B2 helper: the same name+version under multiple sources must be
    /// counted, so vendor can refuse the lock shape whose `dependencies`
    /// arrays reference entries by full package-id string.
    #[tokio::test]
    async fn count_lock_entries_sees_multi_source_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.lock"),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"git+https://example.com/fork/cfg-if#abcdef\"\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\nsource = \"{SOURCE}\"\n"
            ),
        )
        .await
        .unwrap();
        assert_eq!(count_lock_entries(dir.path(), "cfg-if", "1.0.4").await, 2);
        assert_eq!(count_lock_entries(dir.path(), "cfg-if", "0.1.10").await, 1);
        assert_eq!(count_lock_entries(dir.path(), "cfg-if", "9.9.9").await, 0);

        // Missing / unparseable locks count zero (the caller's cross-check is
        // skipped, matching read_locked_versions).
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(count_lock_entries(empty.path(), "cfg-if", "1.0.4").await, 0);
        tokio::fs::write(empty.path().join("Cargo.lock"), "[[[ nope")
            .await
            .unwrap();
        assert_eq!(count_lock_entries(empty.path(), "cfg-if", "1.0.4").await, 0);

        // A lock that parses but has no [[package]] array counts zero too
        // (the documented "no usable lock" contract, matching
        // read_locked_versions).
        let bare = tempfile::tempdir().unwrap();
        tokio::fs::write(bare.path().join("Cargo.lock"), "version = 4\n")
            .await
            .unwrap();
        assert_eq!(count_lock_entries(bare.path(), "cfg-if", "1.0.4").await, 0);
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as `Cargo.lock` must fail fast instead of wedging every
    /// caller — scan's `probe_lock_entry`, vendor mode detection, the version
    /// cross-check, and wet detach/restore all read the lock — forever in an
    /// `open(2)` that waits for a writer that never comes. Same
    /// `open_regular_file` guard class as the Cargo.toml and
    /// .cargo/config.toml twins in this module's siblings. Probes stay
    /// fail-safe (`Unreadable` / `None` / zero); edits refuse loudly with
    /// `Io`.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_instead_of_wedging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        mkfifo(&path);

        let orig = CargoLockOriginal {
            source: SOURCE.to_string(),
            checksum: Some(CHECKSUM.to_string()),
        };
        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                probe_lock_entry(dir.path(), "cfg-if", "1.0.4").await,
                read_locked_versions(dir.path()).await,
                count_lock_entries(dir.path(), "cfg-if", "1.0.4").await,
                detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false).await,
                restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false).await,
            )
        };
        let Ok((probe, versions, count, detach, restore)) =
            tokio::time::timeout(deadline, all).await
        else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path);
            panic!("lock reads must fail fast on a FIFO Cargo.lock");
        };
        assert_eq!(probe, LockEntryProbe::Unreadable);
        assert!(versions.is_none());
        assert_eq!(count, 0);
        assert!(matches!(detach, Err(LockEditError::Io(_))), "{detach:?}");
        assert!(matches!(restore, Err(LockEditError::Io(_))), "{restore:?}");
    }

    #[tokio::test]
    async fn edits_leave_no_stage_litter() {
        let dir = fixture().await;
        detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        for e in std::fs::read_dir(dir.path()).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.contains("socket-stage"), "stage litter: {name}");
        }
    }

    // ── tagged versions ──────────────────────────────────────────────────

    async fn lock_dir(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Cargo.lock"), body)
            .await
            .unwrap();
        dir
    }

    async fn read(dir: &tempfile::TempDir) -> String {
        tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap()
    }

    /// Two locked versions of one crate: v2+ dependents spell the version
    /// (`"cfg-if 1.0.4"`), which the detach must retarget at the tagged
    /// version and the restore must put back — the other version's
    /// references stay untouched.
    #[tokio::test]
    async fn detach_retargets_version_spelled_refs_and_restore_reverses() {
        let body = format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 3\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if 0.1.10\",\n \"cfg-if 1.0.4\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\nsource = \"{SOURCE}\"\nchecksum = \"{}\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n",
            "e".repeat(64)
        );
        let dir = lock_dir(&body).await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        let tagged = format!("1.0.4+socket.{UUID}");
        assert_eq!(
            read(&dir).await,
            body.replace(" \"cfg-if 1.0.4\",", &format!(" \"cfg-if {tagged}\","))
                .replace(
                    &format!(
                        "version = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n"
                    ),
                    &format!("version = \"{tagged}\"\n"),
                )
        );
        assert_eq!(
            probe_lock_entry(dir.path(), "cfg-if", "1.0.4").await,
            LockEntryProbe::Detached(Some(UUID.to_string()))
        );
        assert_eq!(count_lock_entries(dir.path(), "cfg-if", "1.0.4").await, 1);
        let versions = read_locked_versions(dir.path()).await.unwrap();
        assert!(
            versions["cfg-if"].contains("1.0.4"),
            "tag stripped: {versions:?}"
        );
        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        assert_eq!(read(&dir).await, body, "restore is byte-identical");
    }

    /// A version with its own build metadata (`zstd-sys 2.0.1+zstd.1.5.2`
    /// style) keeps it and appends the tag.
    #[tokio::test]
    async fn detach_tags_a_version_that_already_has_build_metadata() {
        let body = format!(
            "version = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"zstd-sys\",\n]\n\n\
             [[package]]\nname = \"zstd-sys\"\nversion = \"2.0.1+zstd.1.5.2\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n"
        );
        let dir = lock_dir(&body).await;
        let orig = detach_lock_entry(dir.path(), "zstd-sys", "2.0.1+zstd.1.5.2", UUID, false)
            .await
            .unwrap();
        assert!(read(&dir)
            .await
            .contains(&format!("version = \"2.0.1+zstd.1.5.2.socket.{UUID}\"\n")));
        assert!(restore_lock_entry(
            dir.path(),
            "zstd-sys",
            "2.0.1+zstd.1.5.2",
            UUID,
            &orig,
            false
        )
        .await
        .unwrap());
        assert_eq!(read(&dir).await, body);
    }

    /// A uuid bump (or an untagged pre-tag vendor) moves the detached entry
    /// and its version-spelled references to the new tag; the returned
    /// previous version undoes it, and a re-run is a no-op.
    #[tokio::test]
    async fn retag_moves_a_detached_entry_and_undoes() {
        let untagged = "version = 3\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if 0.1.10\",\n \"cfg-if 1.0.4\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n";
        let dir = lock_dir(untagged).await;
        assert_eq!(
            probe_lock_entry(dir.path(), "cfg-if", "1.0.4").await,
            LockEntryProbe::Detached(None)
        );
        let prev = retag_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        assert_eq!(prev.as_deref(), Some("1.0.4"));
        let t1 = format!("1.0.4+socket.{UUID}");
        assert_eq!(read(&dir).await, untagged.replace("1.0.4", &t1));
        assert_eq!(
            retag_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
                .await
                .unwrap(),
            None,
            "already tagged"
        );
        let prev = retag_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID2, false)
            .await
            .unwrap();
        assert_eq!(prev.as_deref(), Some(t1.as_str()));
        assert_eq!(
            read(&dir).await,
            untagged.replace("1.0.4", &format!("1.0.4+socket.{UUID2}"))
        );
        retag_lock_entry_to(dir.path(), "cfg-if", "1.0.4", "1.0.4", false)
            .await
            .unwrap();
        assert_eq!(read(&dir).await, untagged, "undo restores the bytes");
        // A registry entry is not retaggable (it needs the detach).
        let reg = fixture().await;
        assert!(matches!(
            retag_lock_entry(reg.path(), "cfg-if", "1.0.4", UUID, true).await,
            Err(LockEditError::Inconsistent(_))
        ));
        assert_eq!(
            retag_lock_entry(reg.path(), "nope", "1.0.4", UUID, true).await,
            Err(LockEditError::EntryMissing)
        );
    }

    /// Restore owns only its own generation: an untagged detached entry
    /// (vendored before tagged versions) restores, an entry tagged for
    /// another uuid is left alone.
    #[tokio::test]
    async fn restore_takes_untagged_and_refuses_another_uuids_tag() {
        let orig = CargoLockOriginal {
            source: SOURCE.to_string(),
            checksum: Some(CHECKSUM.to_string()),
        };
        let detached_untagged = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n";
        let dir = lock_dir(detached_untagged).await;
        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        assert_eq!(read(&dir).await, lock_body().replace("# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\n", ""));

        let other = detached_untagged.replace(
            "version = \"1.0.4\"",
            &format!("version = \"1.0.4+socket.{UUID2}\""),
        );
        let dir = lock_dir(&other).await;
        assert!(
            !restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap(),
            "another generation's tag is not ours to restore"
        );
        assert_eq!(read(&dir).await, other);
    }

    /// Shapes the retargeting cannot keep consistent refuse without
    /// writing: a reference to the version in a spelling the edit does not
    /// own (another source), a v1 `replace` naming it, and an entry already
    /// at the tagged version.
    #[tokio::test]
    async fn inconsistent_lock_shapes_refuse_the_detach() {
        let git = "git+https://example.com/fork/cfg-if#abc";
        let cases = [
            format!(
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
                 \"cfg-if 1.0.4 ({git})\",\n]\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
                 [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n"
            ),
            format!(
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nreplace = \"cfg-if 1.0.4 ({SOURCE})\"\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
                 [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n"
            ),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4+socket.{UUID}\"\n"
            ),
        ];
        for body in cases {
            let dir = lock_dir(&body).await;
            let err = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
                .await
                .unwrap_err();
            assert!(
                matches!(err, LockEditError::Inconsistent(_)),
                "{err:?}\n{body}"
            );
            assert_eq!(read(&dir).await, body, "a refused edit writes nothing");
        }
    }

    /// The oldest v1 locks list the root package in a `[root]` table whose
    /// `dependencies` reference the crate by full id too.
    #[tokio::test]
    async fn detach_and_restore_follow_a_v1_root_table() {
        let body = format!(
            "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({SOURCE})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n"
        );
        let dir = lock_dir(&body).await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, false)
            .await
            .unwrap();
        let detached = read(&dir).await;
        assert!(
            detached.contains(&format!(" \"cfg-if 1.0.4+socket.{UUID}\",\n")),
            "{detached}"
        );
        assert!(
            restore_lock_entry(dir.path(), "cfg-if", "1.0.4", UUID, &orig, false)
                .await
                .unwrap()
        );
        assert_eq!(read(&dir).await, body);
    }

    #[test]
    fn copy_consumption_is_tag_aware() {
        let pkg = |version: &str, source: Option<&str>| LockedPackage {
            name: "cfg-if".into(),
            version: version.into(),
            source: source.map(str::to_string),
            checksum: None,
        };
        let tagged = format!("1.0.4+socket.{UUID}");
        let other = format!("1.0.4+socket.{UUID2}");
        let none: Vec<(String, String)> = Vec::new();
        assert!(vendored_copy_consumed(
            &[pkg(&tagged, None)],
            &none,
            "cfg-if",
            "1.0.4",
            UUID
        ));
        assert!(!vendored_copy_consumed(
            &[pkg(&other, None)],
            &none,
            "cfg-if",
            "1.0.4",
            UUID
        ));
        assert!(
            vendored_copy_consumed(&[pkg("1.0.4", None)], &none, "cfg-if", "1.0.4", UUID),
            "an untagged pre-tag vendor still counts"
        );
        assert!(!vendored_copy_consumed(
            &[pkg("1.0.4", Some(SOURCE))],
            &none,
            "cfg-if",
            "1.0.4",
            UUID
        ));
        let unused = vec![("cfg-if".to_string(), tagged.clone())];
        assert!(!vendored_copy_consumed(
            &[pkg(&tagged, None)],
            &unused,
            "cfg-if",
            "1.0.4",
            UUID
        ));
        assert_eq!(
            detached_tag(&[pkg(&other, None)], "cfg-if", "1.0.4"),
            Some(Some(UUID2))
        );
        assert_eq!(
            detached_tag(&[pkg("1.0.4", None)], "cfg-if", "1.0.4"),
            Some(None)
        );
        assert_eq!(
            detached_tag(&[pkg("1.0.4", Some(SOURCE))], "cfg-if", "1.0.4"),
            None
        );
    }
}
