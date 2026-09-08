//! The committed vendor ledger: `.socket/vendor/state.json`.
//!
//! `vendor --revert` must restore the EXACT pre-vendor lockfile fragments —
//! registry `resolved` URLs (which may point at a private mirror), the
//! sha512/sha256 integrity strings of registry artifacts, verbatim
//! requirement lines, Cargo.lock `source`/`checksum` pairs. None of those are
//! recoverable offline from the vendored tree, so every wiring edit records
//! the verbatim original (and the new fragment we wrote, so revert can detect
//! third-party drift) here. The file is committed alongside `.socket/vendor/`
//! so any checkout can revert.
//!
//! Trust model: state.json is tamper-able like the manifest. Nothing here is
//! trusted to *name paths for deletion or hashing* without re-validating
//! through `path_safety` / `vendor::path` first; the artifact contents are
//! always re-verified against the manifest's afterHashes, never against this
//! file alone.
//!
//! Forward compatibility: the schema evolves by ADDING optional fields and
//! new [`WiringRecord::kind`] STRINGS — never new [`WiringAction`] variants
//! (an older binary must still deserialize a newer ledger). A revert routine
//! that meets an unknown `kind` degrades to a `vendor_lock_entry_drifted`
//! warning and leaves the fragment alone; flavor routers fail closed on
//! flavor strings they have no backend for. Both keep an old binary safe
//! against a newer project checkout.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::manifest::schema::PatchRecord;
use crate::utils::fs::atomic_write_bytes;
use crate::utils::serde::serialize_sorted;

use super::path::VENDOR_DIR;

/// Project-relative path of the ledger.
pub const VENDOR_STATE_REL: &str = ".socket/vendor/state.json";

/// Current schema version.
const VENDOR_STATE_VERSION: u32 = 1;

/// The vendored artifact (a tarball/wheel file, or the copy directory for the
/// dir-shaped ecosystems).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VendorArtifact {
    /// Project-relative, forward-slashed path of the artifact
    /// (`.socket/vendor/<eco>/<uuid>/<leaf>`).
    pub path: String,
    /// Plain sha256 hex of the artifact file (tarball/wheel); empty for
    /// dir-shaped ecosystems (their integrity is per-file afterHashes).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    /// Artifact byte size (recorded where the lock format wants it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// True when the artifact is platform-locked (a compiled-extension wheel
    /// replacing multi-platform registry wheels).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_locked: Option<bool>,
    /// Full-file inventory of a DIR-shaped artifact: relative forward-slashed
    /// path inside the artifact dir → plain sha256 hex, sorted (the dir
    /// counterpart of `sha256` — no lockfile integrity covers a path-source
    /// dir's bytes, so without this only the patched members are verifiable
    /// and drifted/tampered UNPATCHED files pass every audit). Recorded at
    /// vendor time; verification compares the whole tree against it
    /// (missing, extra and modified files all fail). Absent on file-shaped
    /// artifacts and on pre-inventory ledger entries — those keep member-only
    /// verification, and `repair` warns about the gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_inventory: Option<BTreeMap<String, String>>,
}

/// How a wiring edit changed a file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WiringAction {
    /// An existing fragment was replaced (`original` holds the verbatim old
    /// value to restore).
    Rewritten,
    /// A new fragment was added (revert deletes it; `original` is absent).
    Added,
}

/// One recorded lockfile/manifest edit. `original`/`new` are verbatim
/// fragments whose shape is per-`kind`: JSON objects for package-lock
/// entries, strings for TOML/go.mod/requirement fragments, arrays of strings
/// for multi-line blocks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WiringRecord {
    /// Project-relative file that was edited (`package-lock.json`, `go.mod`,
    /// `pyproject.toml`, …).
    pub file: String,
    /// Discriminator for the fragment shape and the revert routine, e.g.
    /// `npm_lock_entry`, `go_replace`, `cargo_patch_entry`, `cargo_lock_entry`,
    /// `composer_lock_package`, `uv_sources_entry`, `uv_override`,
    /// `uv_lock_package`, `uv_lock_requires_dist`, `requirements_line`,
    /// `gemfile_line`, `gemfile_lock_spec`.
    pub kind: String,
    pub action: WiringAction,
    /// A kind-specific key locating the fragment (the lock path
    /// `node_modules/lodash`, the package/module name, a line anchor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Verbatim original fragment ([`WiringAction::Rewritten`] only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<serde_json::Value>,
    /// The fragment vendor wrote (lets revert detect third-party drift: if
    /// the live fragment is neither `new` nor pointing into `.socket/vendor/`,
    /// it is left alone with a warning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<serde_json::Value>,
}

/// Original Cargo.lock fields removed by the path-dep surgery; not
/// recomputable offline (the checksum is the sha256 of the registry `.crate`
/// tarball, not of the extracted tree).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CargoLockOriginal {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

/// pypi/uv bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UvMeta {
    /// `direct` (declared in project.dependencies → tool.uv.sources entry) or
    /// `override` (transitive → tool.uv override-dependencies + sources).
    pub dep_class: String,
    /// The `==X.Y.Z` specifier the lock's requires-dist/overrides carried
    /// before the path source replaced it (uv DROPS the specifier for path
    /// sources; revert restores it from here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_specifier: Option<String>,
    /// Whether vendor created the `[tool.uv.sources]` table itself (revert
    /// then removes the empty table too).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_sources_table: bool,
    /// uv.lock `revision` observed at vendor time (diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_revision: Option<u64>,
}

/// npm/pnpm bookkeeping: which `pnpm-workspace.yaml`/`package.json` tables
/// the wiring had to create (revert then removes the emptied tables too).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PnpmMeta {
    /// Vendor created the package.json `pnpm.overrides` table itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_overrides_table: bool,
    /// Vendor created the enclosing package.json `pnpm` table itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_pnpm_table: bool,
    /// Vendor created the `pnpm-workspace.yaml` file itself (pnpm >= 11 reads
    /// `overrides` only from there); revert deletes it when it still holds
    /// only the vendoring scaffold.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_workspace_file: bool,
    /// Vendor created the `overrides:` section in a pre-existing
    /// `pnpm-workspace.yaml`; revert removes just that section once emptied.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_workspace_overrides: bool,
}

/// pypi/poetry bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoetryMeta {
    /// How the target is declared (`direct` | `transitive`).
    pub dep_class: String,
    /// poetry.lock `lock-version` observed at vendor time.
    pub lock_version: String,
}

/// pypi/pdm bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PdmMeta {
    /// How the target is declared (`direct` | `transitive`).
    pub dep_class: String,
    /// pdm.lock `lock_version` observed at vendor time.
    pub lock_version: String,
    /// pdm.lock `strategy` list observed at vendor time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strategy: Vec<String>,
}

/// pypi/pipenv bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PipenvMeta {
    /// The Pipfile/Pipfile.lock sections the wiring touched (`default`,
    /// `develop`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<String>,
}

/// One vendored package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VendorEntry {
    /// Vendor ecosystem dir name (`npm`, `cargo`, `golang`, `composer`,
    /// `gem`, `pypi`).
    pub ecosystem: String,
    /// Qualifier-free base PURL (`pkg:npm/lodash@4.17.21`). The map key is
    /// the manifest PURL (possibly qualified); this is the resolved base.
    pub base_purl: String,
    /// The patch UUID — redundant with the artifact path's uuid level, kept
    /// as a cross-check.
    pub uuid: String,
    pub artifact: VendorArtifact,
    /// Every lockfile/manifest edit, in application order (revert runs them
    /// in reverse).
    pub wiring: Vec<WiringRecord>,
    /// cargo: the lock fields the surgery removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<CargoLockOriginal>,
    /// golang: vendor took over an existing `.socket/go-patches/` redirect.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub took_over_go_patches: bool,
    /// Which wiring flavor was used, for the multi-flavor ecosystems —
    /// npm: `package-lock` | `yarn-classic` | `yarn-berry` | `pnpm` | `bun`
    /// (absent on pre-flavor entries ⇒ `package-lock`); pypi: `uv` | `requirements` |
    /// `poetry` | `pdm` | `pipenv`. Reverts route on this and fail closed
    /// on flavors this build has no backend for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
    /// pypi/uv extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv: Option<UvMeta>,
    /// npm/pnpm extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pnpm: Option<PnpmMeta>,
    /// pypi/poetry extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poetry: Option<PoetryMeta>,
    /// pypi/pdm extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdm: Option<PdmMeta>,
    /// pypi/pipenv extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipenv: Option<PipenvMeta>,
    /// True when vendored without a manifest record (`scan --vendor
    /// --detached`). The manifest reconcile must not revert such an entry —
    /// it is never "dropped from the manifest" because it was never in it;
    /// [`VendorEntry::record`] is the verification source instead.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detached: bool,
    /// The embedded patch record for detached entries (afterHashes,
    /// vulnerabilities, description, tier) — present iff `detached`. Trust
    /// class: the same committed-file trust as `.socket/manifest.json`; the
    /// artifact is still re-verified against these afterHashes and
    /// `checked_artifact_path`'s uuid cross-checks before any disk access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::manifest::schema::PatchRecord>,
}

/// The ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorState {
    pub version: u32,
    #[serde(serialize_with = "serialize_sorted")]
    pub entries: HashMap<String, VendorEntry>,
}

impl VendorState {
    pub fn new() -> Self {
        Self {
            version: VENDOR_STATE_VERSION,
            entries: HashMap::new(),
        }
    }
}

impl Default for VendorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Carry a re-vendor's ledger entry forward from the one it replaces so a
/// later `--revert` can still undo every surface an *earlier* vendoring of
/// the same package touched.
///
/// A backend rebuilds `entry.wiring` from only the surfaces it changed THIS
/// run. When a re-vendor adds a NEW surface while the others are already in
/// sync — e.g. a project vendored before pnpm >= 11 support, whose
/// `package.json` + `pnpm-lock.yaml` already carry the override, gaining the
/// `pnpm-workspace.yaml` mirror on re-vendor — the fresh entry names ONLY the
/// new surface. Replacing the prior ledger entry wholesale would then drop
/// the pre-vendor originals the FIRST vendoring recorded for the untouched
/// surfaces, and revert could no longer restore them (it would undo only the
/// newly added surface). This reconciles the two:
///
///   * fills a `Rewritten` record's missing `original` from the prior entry —
///     a re-vendor rewrites its OWN stale `.socket/vendor/` pointer and so
///     records `original: None` (it must never record a vendored pointer as
///     the pre-vendor fragment); the true original lives in the entry being
///     replaced (matched by file+kind+key, with the key compared
///     uuid-agnostically via [`super::path::wiring_key_matches`] — berry's
///     lock key embeds the vendored path, so the uuid change that CAUSED the
///     re-vendor changes the key too);
///   * carries forward any prior wiring record for a surface THIS run did not
///     re-touch (union by file+kind+key), so revert still restores it;
///   * OR-merges the pnpm "created this table/file/section" bookkeeping so a
///     create recorded by the first vendoring is not lost when a re-vendor
///     finds the surface already present (revert byte-restores an emptied
///     table/file only when it knows vendor created it);
///   * carries forward the cargo lock originals — the removed
///     `source`/`checksum` pair is NOT recoverable offline, so the ledger
///     entry is its only home. A re-vendor over already-detached wiring
///     records `lock: None` (there was nothing left to detach), and taking
///     the fresh entry verbatim would destroy the first run's originals;
///   * preserves the go-patch-takeover flag.
///
/// The wiring UNION is scoped to a re-vendor of the SAME patch generation
/// (`prev.uuid == entry.uuid`): a new-uuid re-vendor rewires every surface
/// fresh under the new uuid, so the prior uuid's records name nothing the
/// new entry left behind and carrying them forward would only dangle.
/// Everything else — the original-fill, lock originals, takeover flag, and
/// the pnpm "created this table/file/section" facts (which describe who
/// created a surface, not which generation wired it) — is generation-
/// independent and runs unconditionally: a NEW-uuid re-vendor finds every
/// surface already present and records all-false creation flags, and
/// dropping the prior entry's flags would make `--revert` leave the
/// vendor-created pnpm-workspace.yaml and emptied package.json tables
/// behind.
pub fn carry_forward_wiring(prev: &VendorEntry, entry: &mut VendorEntry) {
    entry.took_over_go_patches = entry.took_over_go_patches || prev.took_over_go_patches;
    if entry.lock.is_none() {
        entry.lock = prev.lock.clone();
    }

    for rec in &mut entry.wiring {
        if rec.action == WiringAction::Rewritten && rec.original.is_none() {
            if let Some(prev_rec) = prev.wiring.iter().find(|p| {
                p.file == rec.file
                    && p.kind == rec.kind
                    && match (p.key.as_deref(), rec.key.as_deref()) {
                        (Some(a), Some(b)) => super::path::wiring_key_matches(a, b),
                        (a, b) => a == b,
                    }
            }) {
                rec.original = prev_rec.original.clone();
            }
        }
    }

    if let Some(prev_meta) = prev.pnpm.as_ref() {
        match entry.pnpm.as_mut() {
            Some(meta) => {
                meta.created_overrides_table |= prev_meta.created_overrides_table;
                meta.created_pnpm_table |= prev_meta.created_pnpm_table;
                meta.created_workspace_file |= prev_meta.created_workspace_file;
                meta.created_workspace_overrides |= prev_meta.created_workspace_overrides;
            }
            None => entry.pnpm = Some(prev_meta.clone()),
        }
    }

    if prev.uuid != entry.uuid {
        return;
    }

    for prev_rec in &prev.wiring {
        let present = entry
            .wiring
            .iter()
            .any(|r| r.file == prev_rec.file && r.kind == prev_rec.kind && r.key == prev_rec.key);
        if !present {
            entry.wiring.push(prev_rec.clone());
        }
    }
}

/// The ledger entry addressable as `purl`: the exact map key first, then
/// any entry whose resolved `base_purl` equals it (a qualified manifest
/// key resolves to the entry recorded under the base PURL).
pub fn lookup_entry<'a>(
    entries: &'a HashMap<String, VendorEntry>,
    purl: &str,
) -> Option<&'a VendorEntry> {
    entries
        .get(purl)
        .or_else(|| entries.values().find(|e| e.base_purl == purl))
}

fn state_path(project_root: &Path) -> PathBuf {
    project_root.join(VENDOR_STATE_REL)
}

/// Load the ledger. A missing file is an empty ledger; an unreadable or
/// unparseable file is an error (fail-closed — revert must not guess).
///
/// One deliberate exception to fail-closed: a parseable JSON object that is
/// clearly a DIFFERENT Socket ledger (it carries a `mode` tag and no
/// `entries` — e.g. an early registry-redirect ledger committed to this path
/// by the depscan GitHub-app flow) is treated as an empty vendor ledger
/// instead of bricking every vendor-adjacent command (`remove`, `vendor`,
/// `repair`) with `vendor_state_unreadable`. Such a file carries no vendor
/// data by construction, so nothing is guessed.
pub async fn load_state(project_root: &Path) -> std::io::Result<VendorState> {
    let path = state_path(project_root);
    match read_state_bytes(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).or_else(|e| {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if value.get("mode").is_some() && value.get("entries").is_none() {
                    return Ok(VendorState::new());
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt {}: {e}", path.display()),
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VendorState::new()),
        Err(e) => Err(e),
    }
}

/// Read the ledger bytes from the (untrusted) project tree. Opens via
/// [`open_regular_file`](crate::utils::fs::open_regular_file) — non-blocking
/// on Unix, rejecting FIFOs/devices/directories — so a planted special file
/// fails loudly instead of wedging every vendor-adjacent command (`vendor`,
/// `remove`, `repair`) on a FIFO `open(2)` that waits forever for a writer;
/// same guard as the sibling redirect ledger.
async fn read_state_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// Persist the ledger atomically with sorted keys + 2-space indent + trailing
/// newline (deterministic bytes — the file is committed). An EMPTY ledger
/// deletes `state.json` and prunes `.socket/vendor/` when that leaves it
/// empty, so a fully-reverted project carries no vendor residue.
pub async fn save_state(project_root: &Path, state: &VendorState) -> std::io::Result<()> {
    let path = state_path(project_root);
    if state.entries.is_empty() {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Prune now-empty ecosystem levels, then .socket/vendor itself.
        // `remove_dir` is non-recursive: a dir still holding artifacts (or
        // anything we don't own) fails harmlessly and is kept.
        let vendor_root = project_root.join(VENDOR_DIR);
        for eco in super::path::ECOSYSTEM_DIRS {
            let _ = tokio::fs::remove_dir(vendor_root.join(eco)).await;
        }
        let _ = tokio::fs::remove_dir(&vendor_root).await;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    atomic_write_bytes(&path, &bytes).await
}

/// The informational marker written inside each vendored unit
/// (`socket-patch.vendor.json`, a sibling of the artifact in the uuid dir).
/// Belt-and-braces for tools that have the tree but not the lockfile; never
/// a trust input — sweep/verify key off state.json + the path uuid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VendorMarker {
    pub schema_version: u32,
    pub purl: String,
    pub patch_uuid: String,
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<String>,
    /// RFC3339 timestamp supplied by the caller (the CLI formats it).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendored_at: String,
}

impl VendorMarker {
    /// The schema-v1 marker every backend writes: `record`'s uuid plus its
    /// vulnerability ids, sorted.
    pub(crate) fn new(
        ecosystem: &str,
        purl: &str,
        record: &PatchRecord,
        vendored_at: &str,
    ) -> Self {
        let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
        vulnerabilities.sort();
        VendorMarker {
            schema_version: 1,
            purl: purl.to_string(),
            patch_uuid: record.uuid.clone(),
            ecosystem: ecosystem.to_string(),
            vulnerabilities,
            vendored_at: vendored_at.to_string(),
        }
    }
}

/// File name of the marker inside the uuid dir.
pub(crate) const VENDOR_MARKER_FILE: &str = "socket-patch.vendor.json";

/// Write the marker atomically into `uuid_dir`.
pub(crate) async fn write_marker(uuid_dir: &Path, marker: &VendorMarker) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    atomic_write_bytes(&uuid_dir.join(VENDOR_MARKER_FILE), &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn sample_entry() -> VendorEntry {
        VendorEntry {
            ecosystem: "npm".into(),
            base_purl: "pkg:npm/lodash@4.17.21".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{UUID}/lodash-4.17.21.tgz"),
                sha256: "ab".repeat(32),
                size: Some(3668),
                platform_locked: None,
                file_inventory: None,
            },
            wiring: vec![WiringRecord {
                file: "package-lock.json".into(),
                kind: "npm_lock_entry".into(),
                action: WiringAction::Rewritten,
                key: Some("node_modules/lodash".into()),
                original: Some(serde_json::json!({
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-orig"
                })),
                new: Some(serde_json::json!({
                    "version": "4.17.21",
                    "resolved": format!("file:.socket/vendor/npm/{UUID}/lodash-4.17.21.tgz"),
                    "integrity": "sha512-ours"
                })),
            }],
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    #[tokio::test]
    async fn round_trip_and_determinism() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());

        save_state(root, &state).await.unwrap();
        let loaded = load_state(root).await.unwrap();
        assert_eq!(loaded, state);

        // Byte-deterministic across re-saves (committed file).
        let bytes1 = tokio::fs::read(root.join(VENDOR_STATE_REL)).await.unwrap();
        save_state(root, &loaded).await.unwrap();
        let bytes2 = tokio::fs::read(root.join(VENDOR_STATE_REL)).await.unwrap();
        assert_eq!(bytes1, bytes2);
        assert!(bytes1.ends_with(b"\n"));
        // Empty optional fields are omitted from the wire form.
        let text = String::from_utf8(bytes1).unwrap();
        assert!(!text.contains("tookOverGoPatches"));
        assert!(!text.contains("\"flavor\""));
        for absent in [
            "\"uv\"",
            "\"pnpm\"",
            "\"poetry\"",
            "\"pdm\"",
            "\"pipenv\"",
            "\"detached\"",
            "\"record\"",
            "\"fileInventory\"",
        ] {
            assert!(
                !text.contains(absent),
                "{absent} must not serialize when None"
            );
        }
        assert!(text.contains("\"basePurl\""), "camelCase keys: {text}");
    }

    /// The dir-shaped full-file inventory: camelCase wire key, sorted map
    /// order on the wire, lossless round trip, and absent-key tolerance
    /// (a pre-inventory ledger deserializes to `None` — the additive-fields
    /// forward-compat contract).
    #[tokio::test]
    async fn file_inventory_round_trips_sorted_camel_case() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut entry = sample_entry();
        entry.ecosystem = "gem".into();
        entry.artifact.path = format!(".socket/vendor/gem/{UUID}/rack-3.2.6");
        entry.artifact.sha256 = String::new();
        entry.artifact.size = None;
        entry.artifact.file_inventory = Some(BTreeMap::from([
            ("rack.gemspec".to_string(), "cd".repeat(32)),
            ("lib/rack.rb".to_string(), "ab".repeat(32)),
        ]));
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:gem/rack@3.2.6".into(), entry.clone());

        save_state(root, &state).await.unwrap();
        let loaded = load_state(root).await.unwrap();
        assert_eq!(loaded, state, "inventory survives the round trip");

        let text = tokio::fs::read_to_string(root.join(VENDOR_STATE_REL))
            .await
            .unwrap();
        assert!(text.contains("\"fileInventory\""), "camelCase key: {text}");
        let lib_at = text.find("lib/rack.rb").unwrap();
        let spec_at = text.find("rack.gemspec").unwrap();
        assert!(
            lib_at < spec_at,
            "inventory keys serialize sorted (BTreeMap): {text}"
        );

        // A pre-inventory ledger (no `fileInventory` key) deserializes to
        // `None`, keeping member-only verification.
        let mut legacy = serde_json::to_value(&state).unwrap();
        legacy["entries"]["pkg:gem/rack@3.2.6"]["artifact"]
            .as_object_mut()
            .unwrap()
            .remove("fileInventory");
        let back: VendorState = serde_json::from_value(legacy).unwrap();
        assert!(back.entries["pkg:gem/rack@3.2.6"]
            .artifact
            .file_inventory
            .is_none());
    }

    #[tokio::test]
    async fn detached_entry_round_trips_with_embedded_record() {
        use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut entry = sample_entry();
        entry.detached = true;
        entry.record = Some(PatchRecord {
            uuid: UUID.into(),
            exported_at: "2026-06-10T00:00:00Z".into(),
            files: HashMap::from([(
                "lodash.js".to_string(),
                PatchFileInfo {
                    before_hash: "aa".repeat(32),
                    after_hash: "bb".repeat(32),
                },
            )]),
            vulnerabilities: HashMap::from([(
                "GHSA-xxxx-yyyy-zzzz".to_string(),
                VulnerabilityInfo {
                    cves: vec!["CVE-2026-0001".into()],
                    summary: "prototype pollution".into(),
                    severity: "high".into(),
                    description: "details".into(),
                },
            )]),
            description: "fixes prototype pollution".into(),
            license: "MIT".into(),
            tier: "free".into(),
        });
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), entry.clone());

        save_state(root, &state).await.unwrap();
        let loaded = load_state(root).await.unwrap();
        assert_eq!(loaded, state, "detached entry + record survive round trip");

        let text = tokio::fs::read_to_string(root.join(VENDOR_STATE_REL))
            .await
            .unwrap();
        assert!(text.contains("\"detached\": true"), "wire form: {text}");
        // The embedded record keeps the manifest's camelCase wire shape.
        for key in [
            "\"record\"",
            "\"beforeHash\"",
            "\"afterHash\"",
            "\"exportedAt\"",
        ] {
            assert!(text.contains(key), "{key} missing from wire form: {text}");
        }

        // A pre-detached ledger (no `detached`/`record` keys) deserializes to
        // the defaults — the additive-fields forward-compat contract.
        let mut legacy = serde_json::to_value(&state).unwrap();
        let legacy_entry = legacy["entries"]["pkg:npm/lodash@4.17.21"]
            .as_object_mut()
            .unwrap();
        legacy_entry.remove("detached");
        legacy_entry.remove("record");
        let back: VendorState = serde_json::from_value(legacy).unwrap();
        let back_entry = &back.entries["pkg:npm/lodash@4.17.21"];
        assert!(!back_entry.detached);
        assert!(back_entry.record.is_none());
    }

    #[tokio::test]
    async fn v2_meta_structs_round_trip_with_camel_case() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut entry = sample_entry();
        entry.flavor = Some("pnpm".into());
        entry.pnpm = Some(PnpmMeta {
            created_overrides_table: true,
            created_workspace_file: true,
            ..Default::default()
        });
        entry.poetry = Some(PoetryMeta {
            dep_class: "direct".into(),
            lock_version: "2.1".into(),
        });
        entry.pdm = Some(PdmMeta {
            dep_class: "transitive".into(),
            lock_version: "4.5.0".into(),
            strategy: vec!["inherit_metadata".into(), "static_urls".into()],
        });
        entry.pipenv = Some(PipenvMeta {
            sections: vec!["default".into(), "develop".into()],
        });
        let mut state = VendorState::new();
        state.entries.insert("pkg:npm/lodash@4.17.21".into(), entry);

        save_state(root, &state).await.unwrap();
        let loaded = load_state(root).await.unwrap();
        assert_eq!(loaded, state, "every meta survives the round trip");

        let text = tokio::fs::read_to_string(root.join(VENDOR_STATE_REL))
            .await
            .unwrap();
        // camelCase keys on the wire.
        for key in [
            "\"createdOverridesTable\"",
            "\"createdWorkspaceFile\"",
            "\"depClass\"",
            "\"lockVersion\"",
            "\"strategy\"",
            "\"sections\"",
        ] {
            assert!(text.contains(key), "{key} missing: {text}");
        }
        // Skip-empty inner fields: the false bools and any empty vec vanish.
        assert!(
            !text.contains("createdPnpmTable"),
            "false bool omitted: {text}"
        );
        assert!(
            !text.contains("createdWorkspaceOverrides"),
            "false bool omitted: {text}"
        );
    }

    #[test]
    fn v2_meta_empty_inner_fields_do_not_serialize() {
        let pnpm = serde_json::to_string(&PnpmMeta::default()).unwrap();
        assert_eq!(pnpm, "{}", "all-default PnpmMeta serializes empty");

        let pipenv = serde_json::to_string(&PipenvMeta {
            sections: Vec::new(),
        })
        .unwrap();
        assert_eq!(pipenv, "{}", "empty sections omitted");

        let pdm = serde_json::to_string(&PdmMeta {
            dep_class: "direct".into(),
            lock_version: "4.5.0".into(),
            strategy: Vec::new(),
        })
        .unwrap();
        assert!(!pdm.contains("strategy"), "empty strategy omitted: {pdm}");

        // And the omitted spellings deserialize back to the defaults.
        let back: PnpmMeta = serde_json::from_str("{}").unwrap();
        assert_eq!(back, PnpmMeta::default());
        let back: PipenvMeta = serde_json::from_str("{}").unwrap();
        assert!(back.sections.is_empty());
    }

    /// mkfifo(2) directly — `mkfifo` the binary may be absent, and the
    /// syscall needs no process at all.
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

    /// A FIFO planted at the ledger path must not wedge the loader: a plain
    /// `tokio::fs::read` open(2)s the FIFO with `O_RDONLY` and waits for a
    /// writer that never comes, hanging every vendor-adjacent command
    /// (`vendor`, `remove`, `repair`) with no error and no timeout. Same
    /// class as the `open_regular_file` guard on the sibling redirect
    /// ledger. The non-regular file is a loud fail-closed error, never an
    /// empty ledger.
    #[cfg(unix)]
    #[tokio::test]
    async fn load_fifo_state_fails_fast_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let fifo = dir.join("state.json");
        mkfifo(&fifo);

        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(result) = tokio::time::timeout(deadline, load_state(tmp.path())).await else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("load_state must complete promptly with a FIFO ledger");
        };
        result.unwrap_err();
        // The pure load never mutates the project — the FIFO stays put.
        assert!(fifo.exists());
    }

    /// "Vendor created this table/file/section" is a historical fact
    /// independent of the patch generation: a NEW-uuid re-vendor finds every
    /// surface already present (created by the FIRST vendoring) and records
    /// all-false creation flags, so dropping the prior entry's flags would
    /// make `--revert` leave the vendor-created pnpm-workspace.yaml and the
    /// emptied package.json `pnpm`/`overrides` tables behind. The OR-merge
    /// must survive the uuid change (unlike the wiring union, nothing here
    /// can dangle).
    #[test]
    fn carry_forward_merges_pnpm_created_flags_across_uuid_generations() {
        let mut prev = sample_entry();
        prev.pnpm = Some(PnpmMeta {
            created_overrides_table: true,
            created_pnpm_table: true,
            created_workspace_file: true,
            created_workspace_overrides: false,
        });

        // The re-vendor under a NEW uuid probes the surfaces as pre-existing.
        let mut entry = sample_entry();
        entry.uuid = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d".into();
        entry.pnpm = Some(PnpmMeta::default());

        carry_forward_wiring(&prev, &mut entry);
        let meta = entry.pnpm.as_ref().unwrap();
        assert!(
            meta.created_overrides_table && meta.created_pnpm_table && meta.created_workspace_file,
            "creation facts must survive a new-uuid re-vendor: {meta:?}"
        );

        // And a fresh entry with NO meta inherits the prior one wholesale.
        let mut entry = sample_entry();
        entry.uuid = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d".into();
        carry_forward_wiring(&prev, &mut entry);
        assert_eq!(entry.pnpm, prev.pnpm, "absent meta inherits the prior");
    }

    /// The original-fill matcher's non-(Some,Some) key arm (`(a, b) => a == b`):
    /// line-anchored kinds like `requirements_line`/`gemfile_line` record
    /// `key: None`, so (None, None) must MATCH — the re-vendor's missing
    /// pre-vendor original is filled from the prior generation — while a
    /// one-sided key, (Some, None) or (None, Some), must NOT (a keyed record
    /// and an unkeyed one name different fragments; filling across them would
    /// restore the wrong original on `--revert`).
    #[test]
    fn carry_forward_fills_original_across_none_keys() {
        let requirements_rec =
            |key: Option<&str>, original: Option<serde_json::Value>| WiringRecord {
                file: "requirements.txt".into(),
                kind: "requirements_line".into(),
                action: WiringAction::Rewritten,
                key: key.map(str::to_string),
                original,
                new: Some(serde_json::json!(format!(
                    "left-pad @ file:.socket/vendor/pypi/{UUID}/left_pad-1.3.0.whl"
                ))),
            };

        // (None, None): the prior entry's original fills the re-vendor's gap.
        let mut prev = sample_entry();
        prev.wiring = vec![requirements_rec(
            None,
            Some(serde_json::json!("left-pad==1.3.0")),
        )];
        let mut entry = sample_entry();
        entry.wiring = vec![requirements_rec(None, None)];
        carry_forward_wiring(&prev, &mut entry);
        assert_eq!(
            entry.wiring[0].original,
            Some(serde_json::json!("left-pad==1.3.0")),
            "(None, None) keys must match and fill the original"
        );

        // (Some, None): a keyed prior record must NOT fill an unkeyed one.
        let mut prev = sample_entry();
        prev.wiring = vec![requirements_rec(
            Some("left-pad"),
            Some(serde_json::json!("left-pad==1.3.0")),
        )];
        let mut entry = sample_entry();
        entry.wiring = vec![requirements_rec(None, None)];
        carry_forward_wiring(&prev, &mut entry);
        assert_eq!(
            entry.wiring[0].original, None,
            "(Some, None) keys must not match"
        );

        // (None, Some): the symmetric refusal.
        let mut prev = sample_entry();
        prev.wiring = vec![requirements_rec(
            None,
            Some(serde_json::json!("left-pad==1.3.0")),
        )];
        let mut entry = sample_entry();
        entry.wiring = vec![requirements_rec(Some("left-pad"), None)];
        carry_forward_wiring(&prev, &mut entry);
        assert_eq!(
            entry.wiring[0].original, None,
            "(None, Some) keys must not match"
        );
    }

    #[tokio::test]
    async fn missing_file_is_empty_corrupt_file_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(load_state(root).await.unwrap().entries.is_empty());

        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        tokio::fs::write(root.join(VENDOR_STATE_REL), b"{not json")
            .await
            .unwrap();
        let err = load_state(root).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A mode-tagged NON-vendor ledger squatting on this path (an early
    /// registry-redirect ledger committed by the depscan GitHub-app flow)
    /// must read as an EMPTY vendor ledger, not brick `remove`/`vendor`/
    /// `repair` with vendor_state_unreadable. A vendor-shaped file that is
    /// genuinely corrupt stays fail-closed.
    #[tokio::test]
    async fn foreign_mode_ledger_reads_as_empty_vendor_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(VENDOR_STATE_REL),
            br#"{ "version": 1, "mode": "registry", "edits": [] }"#,
        )
        .await
        .unwrap();
        assert!(
            load_state(root).await.unwrap().entries.is_empty(),
            "a foreign mode-tagged ledger is not vendor data"
        );

        // Fail-closed control: valid JSON that is neither a vendor ledger
        // nor mode-tagged still errors.
        tokio::fs::write(root.join(VENDOR_STATE_REL), br#"{ "version": 1 }"#)
            .await
            .unwrap();
        let err = load_state(root).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn empty_state_removes_file_and_prunes_empty_vendor_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(root, &state).await.unwrap();
        assert!(root.join(VENDOR_STATE_REL).exists());

        state.entries.clear();
        save_state(root, &state).await.unwrap();
        assert!(!root.join(VENDOR_STATE_REL).exists());
        assert!(
            !root.join(VENDOR_DIR).exists(),
            ".socket/vendor pruned when empty"
        );

        // But a vendor dir that still holds artifacts is NOT pruned.
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(root, &state).await.unwrap();
        tokio::fs::create_dir_all(root.join(".socket/vendor/npm"))
            .await
            .unwrap();
        tokio::fs::write(root.join(".socket/vendor/npm/stray.tgz"), b"x")
            .await
            .unwrap();
        state.entries.clear();
        save_state(root, &state).await.unwrap();
        assert!(
            root.join(".socket/vendor/npm").exists(),
            "non-empty dir kept"
        );
    }

    #[tokio::test]
    async fn marker_writes_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let marker = VendorMarker {
            schema_version: 1,
            purl: "pkg:npm/lodash@4.17.21".into(),
            patch_uuid: UUID.into(),
            ecosystem: "npm".into(),
            vulnerabilities: vec!["GHSA-xxxx-yyyy-zzzz".into()],
            vendored_at: "2026-06-09T00:00:00Z".into(),
        };
        write_marker(dir, &marker).await.unwrap();
        let text = tokio::fs::read_to_string(dir.join(VENDOR_MARKER_FILE))
            .await
            .unwrap();
        assert!(text.contains("\"patchUuid\""));
        assert!(text.contains(UUID));
        // No stage litter.
        for e in std::fs::read_dir(dir).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.starts_with(".socket-stage-"), "litter: {name}");
        }
    }
}
