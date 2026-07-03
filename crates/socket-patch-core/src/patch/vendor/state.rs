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

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::utils::fs::atomic_write_bytes;
use crate::utils::serde::serialize_sorted;

use super::path::VENDOR_DIR;

/// Project-relative path of the ledger.
pub const VENDOR_STATE_REL: &str = ".socket/vendor/state.json";

/// Current schema version.
pub const VENDOR_STATE_VERSION: u32 = 1;

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PnpmMeta {
    /// Vendor created the `overrides` table itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_overrides_table: bool,
    /// Vendor created the enclosing `pnpm` table itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_pnpm_table: bool,
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
    /// npm: `package-lock` | `yarn-classic` | `pnpm` | `bun` (absent on
    /// pre-flavor entries ⇒ `package-lock`); pypi: `uv` | `requirements` |
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

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for VendorState {
    fn default() -> Self {
        Self::new()
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
    match tokio::fs::read(&path).await {
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

/// Persist the ledger atomically with sorted keys + 2-space indent + trailing
/// newline (deterministic bytes — the file is committed). An EMPTY ledger
/// deletes `state.json` and prunes `.socket/vendor/` when that leaves it
/// empty, so a fully-reverted project carries no vendor residue.
pub async fn save_state(project_root: &Path, state: &VendorState) -> std::io::Result<()> {
    let path = state_path(project_root);
    if state.is_empty() {
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
pub struct VendorMarker {
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

/// File name of the marker inside the uuid dir.
pub const VENDOR_MARKER_FILE: &str = "socket-patch.vendor.json";

/// Write the marker atomically into `uuid_dir`.
pub async fn write_marker(uuid_dir: &Path, marker: &VendorMarker) -> std::io::Result<()> {
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
        ] {
            assert!(
                !text.contains(absent),
                "{absent} must not serialize when None"
            );
        }
        assert!(text.contains("\"basePurl\""), "camelCase keys: {text}");
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
            created_pnpm_table: false,
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
            "\"depClass\"",
            "\"lockVersion\"",
            "\"strategy\"",
            "\"sections\"",
        ] {
            assert!(text.contains(key), "{key} missing: {text}");
        }
        // Skip-empty inner fields: the false bool and any empty vec vanish.
        assert!(
            !text.contains("createdPnpmTable"),
            "false bool omitted: {text}"
        );
    }

    #[test]
    fn v2_meta_empty_inner_fields_do_not_serialize() {
        let pnpm = serde_json::to_string(&PnpmMeta {
            created_overrides_table: false,
            created_pnpm_table: false,
        })
        .unwrap();
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
        assert_eq!(
            back,
            PnpmMeta {
                created_overrides_table: false,
                created_pnpm_table: false
            }
        );
        let back: PipenvMeta = serde_json::from_str("{}").unwrap();
        assert!(back.sections.is_empty());
    }

    #[tokio::test]
    async fn missing_file_is_empty_corrupt_file_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(load_state(root).await.unwrap().is_empty());

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
            load_state(root).await.unwrap().is_empty(),
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
