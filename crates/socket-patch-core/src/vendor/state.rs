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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::constants::SOCKET_DIR;
use crate::manifest::schema::PatchRecord;
use crate::utils::fs::{atomic_write_artifact, read_regular_to_bytes};
use crate::utils::purl_key::PurlKey;
use crate::utils::serde::serialize_sorted;
use crate::utils::socket_dir::{prune_empty_dirs, remove_file_and_prune, write_json_ledger};
use crate::utils::target::Target;

use super::parse_memo::ParseMemo;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yarn_berry10c0: Option<String>,
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

impl VendorArtifact {
    /// The packed npm tarball at `rel_tgz`, pinned by its sha256 and size.
    /// `yarn_berry10c0` stays `None`: only the yarn-berry flavor records
    /// the checksum, and only when it is the service's own.
    pub(crate) fn tarball(rel_tgz: String, packed: &super::npm_pack::PackedTarball) -> Self {
        Self {
            yarn_berry10c0: None,
            path: rel_tgz,
            sha256: packed.sha256_hex.clone(),
            size: Some(packed.size),
            platform_locked: None,
            file_inventory: None,
        }
    }

    /// A vendored package DIRECTORY at `rel_dir` (vlt): no file hash or
    /// size, its whole-tree `inventory` instead.
    pub(crate) fn dir(rel_dir: String, inventory: BTreeMap<String, String>) -> Self {
        Self {
            yarn_berry10c0: None,
            path: rel_dir,
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: Some(inventory),
        }
    }
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
    /// Vendor added the root-only `packages:` scaffold to a pre-existing
    /// `pnpm-workspace.yaml` that had no keys (#1096); revert removes it
    /// with the emptied `overrides:` section.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created_workspace_packages: bool,
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
    /// `gem`, `pypi`, `nuget`, `maven`).
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
    /// npm: `package-lock` | `yarn-classic` | `yarn-berry` | `pnpm` |
    /// `pnpm-legacy` | `bun` | `vlt` (absent on pre-flavor entries ⇒
    /// `package-lock`; a `vlt` artifact is a package directory, whose
    /// `fileInventory` excludes its `node_modules/`); pypi: `uv` |
    /// `python-lock` | `requirements` | `hatch` | `poetry` | `pdm` |
    /// `pipenv`. Reverts route on this and fail closed on flavors this build
    /// has no backend for.
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
    /// True when vendored WITHOUT a manifest record — the posture of every
    /// `scan` / `get --mode vendored` entry (vendored mode writes no
    /// `.socket/manifest.json`); only the manifest-driven standalone
    /// `vendor` command records `false`. The manifest reconcile must not
    /// revert a detached entry — it is never "dropped from the manifest"
    /// because it was never in it; [`VendorEntry::record`] is the
    /// verification source instead. Always serialized when true so older
    /// readers keep the same exemption.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detached: bool,
    /// The embedded patch record (afterHashes, vulnerabilities, description,
    /// tier). Current writers embed it in EVERY entry: it is the ONLY
    /// verification source for a `detached` entry, and for a non-detached
    /// one (the manifest-driven standalone `vendor`) a fallback copy — the
    /// manifest record stays authoritative wherever both exist — so a
    /// checkout whose manifest is gone can still verify and attest offline.
    /// `record.is_some()` therefore does NOT imply `detached`; entries the
    /// standalone `vendor` wrote before 5.0 carry none. Trust class: the same
    /// committed-file trust as `.socket/manifest.json`; the artifact is still
    /// re-verified against these afterHashes and `checked_artifact_path`'s
    /// uuid cross-checks before any disk access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<PatchRecord>,
}

impl VendorEntry {
    /// Create an entry with no ecosystem-specific metadata or embedded record.
    pub fn new(
        ecosystem: String,
        base_purl: String,
        uuid: String,
        artifact: VendorArtifact,
        wiring: Vec<WiringRecord>,
    ) -> Self {
        Self {
            ecosystem,
            base_purl,
            uuid,
            artifact,
            wiring,
            lock: None,
            took_over_go_patches: false,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
            detached: false,
            record: None,
        }
    }

    /// The ledger entry every npm-family vendor backend records: ecosystem
    /// `npm`, the wiring flavor (`None` is package-lock's pre-flavor
    /// spelling) and no other ecosystem's extras. A flavor sets its one
    /// meta field afterwards (`pnpm`, `artifact.yarn_berry10c0`).
    pub(crate) fn npm(
        base_purl: String,
        uuid: String,
        artifact: VendorArtifact,
        wiring: Vec<WiringRecord>,
        flavor: Option<&str>,
    ) -> Self {
        Self {
            flavor: flavor.map(str::to_string),
            ..Self::new("npm".to_string(), base_purl, uuid, artifact, wiring)
        }
    }

    /// Whether this entry's committed artifact is on disk under
    /// `project_root` — for a FILE artifact (wheel, tarball: a recorded
    /// `sha256`), only when its bytes still hash to that pin; a copy dir
    /// (no `sha256`) is only stat-ed. Read-only, no network.
    pub async fn committed_artifact_intact(&self, project_root: &Path) -> bool {
        if self.artifact.path.is_empty() {
            return false;
        }
        let path = project_root.join(&self.artifact.path);
        if self.artifact.sha256.is_empty() {
            return tokio::fs::metadata(&path).await.is_ok();
        }
        match read_regular_to_bytes(&path).await {
            Ok(bytes) => crate::utils::digest::sha256_hex_of(&bytes)
                .eq_ignore_ascii_case(&self.artifact.sha256),
            Err(_) => false,
        }
    }

    /// Does this entry, stored under ledger `key`, match a remove/rollback
    /// target? By its ledger key or by its base purl (the manifest rule,
    /// [`Target::matches_patch`]; a golang key is case-encoded while
    /// `base_purl` holds the decoded spelling users type), or by uuid.
    pub fn matches_target(&self, key: &str, target: &Target) -> bool {
        target.matches_patch(key, &self.uuid) || target.matches_patch(&self.base_purl, &self.uuid)
    }

    /// The purl that names this entry's package for
    /// [`Target::ambiguity`]: the decoded `base_purl` when `target`
    /// reaches the entry through it, otherwise the ledger `key`. A golang
    /// key is case-encoded (`!core`) and so can miss a last-segment name
    /// that its `base_purl` (`Core`) matches; feeding the key alone would
    /// skip the refusal while [`Self::matches_target`] still selects the
    /// entry. One purl per entry, so an encoded key and its decoded base
    /// never count as two packages.
    pub fn ambiguity_purl<'a>(&'a self, key: &'a str, target: &Target) -> &'a str {
        if target.matches_patch(&self.base_purl, &self.uuid) {
            &self.base_purl
        } else {
            key
        }
    }

    /// Does this entry, stored under ledger `key`, own the manifest purl
    /// `purl`? By [`PurlKey`] of its ledger key or its base purl (any
    /// qualifier variant, encoding, PyPI/NuGet name spelling or composer
    /// release spelling) — the per-entry form of the set
    /// [`VendorState::purl_keys`] flattens.
    pub fn covers_purl(&self, key: &str, purl: &str) -> bool {
        let purl = PurlKey::new(purl);
        PurlKey::new(key) == purl || PurlKey::new(&self.base_purl) == purl
    }
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

    /// The [`PurlKey`]s under which this ledger's entries are addressable:
    /// each entry's map key (the manifest purl, possibly qualified) and its
    /// resolved base purl. The one derivation behind every whole-set
    /// vendor-ownership match (apply / rollback / remove / scan prune);
    /// match against it with [`purl_keys_cover`].
    /// [`super::vendored_purl_keys`] is its load-then-derive convenience.
    pub fn purl_keys(&self) -> HashSet<PurlKey> {
        self.entries
            .iter()
            .flat_map(|(key, entry)| [PurlKey::new(key), PurlKey::new(&entry.base_purl)])
            .collect()
    }

    /// The created-scaffold flags every entry should carry: the union
    /// over the entries that wire the same project-root files (every uv
    /// entry shares `pyproject.toml`'s `[tool.uv.sources]`; every pnpm
    /// entry shares `package.json` and `pnpm-workspace.yaml`).
    fn shared_scaffold_flags(&self) -> (bool, PnpmMeta) {
        let mut uv = false;
        let mut pnpm = PnpmMeta::default();
        for entry in self.entries.values() {
            if let Some(m) = &entry.uv {
                uv |= m.created_sources_table;
            }
            if let Some(m) = &entry.pnpm {
                pnpm.created_overrides_table |= m.created_overrides_table;
                pnpm.created_pnpm_table |= m.created_pnpm_table;
                pnpm.created_workspace_file |= m.created_workspace_file;
                pnpm.created_workspace_overrides |= m.created_workspace_overrides;
                pnpm.created_workspace_packages |= m.created_workspace_packages;
            }
        }
        (uv, pnpm)
    }

    /// Whether every entry already carries [`Self::shared_scaffold_flags`].
    fn scaffold_flags_shared(&self) -> bool {
        let (uv, pnpm) = self.shared_scaffold_flags();
        self.entries.values().all(|entry| {
            entry
                .uv
                .as_ref()
                .is_none_or(|m| m.created_sources_table == uv)
                && entry.pnpm.as_ref().is_none_or(|m| *m == pnpm)
        })
    }

    /// Make "vendor created this table/file" a property of the shared
    /// scaffold rather than of the one entry that happened to be wired
    /// first (#636, #670). Each later package finds the scaffold already
    /// there and records `false`, and revert removes an emptied scaffold
    /// only when the entry it reverts carries the flag, so a residue was
    /// left unless the creator was reverted last. With the flags shared,
    /// whichever entry empties the scaffold removes it, in any order;
    /// revert still keeps a scaffold that holds anything else.
    pub fn share_scaffold_flags(&mut self) {
        let (uv, pnpm) = self.shared_scaffold_flags();
        for entry in self.entries.values_mut() {
            if let Some(m) = entry.uv.as_mut() {
                m.created_sources_table = uv;
            }
            if let Some(m) = entry.pnpm.as_mut() {
                *m = pnpm.clone();
            }
        }
    }

    /// `self` with [`Self::share_scaffold_flags`] applied, copied only
    /// when that changes something.
    fn with_shared_scaffold_flags(state: Arc<Self>) -> Arc<Self> {
        if state.scaffold_flags_shared() {
            return state;
        }
        let mut owned = (*state).clone();
        owned.share_scaffold_flags();
        Arc::new(owned)
    }
}

/// Whether `purl` is vendor-owned according to `keys`, a
/// [`VendorState::purl_keys`] set: by its [`PurlKey`], so a scan that sees
/// composer `@3.0.2` still finds the entry vendored as `@3.0.2.0`, and a
/// lowercase NuGet crawl the entry the API spelled `Newtonsoft.Json`.
pub fn purl_keys_cover(keys: &HashSet<PurlKey>, purl: &str) -> bool {
    keys.contains(&PurlKey::new(purl))
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
///   * carries forward a cargo copy's whole-tree file inventory when the
///     fresh entry names the SAME copy (same uuid + artifact path) and
///     records none — the cargo backend never inventories, and a re-run
///     that only (re)tags or migrates the wiring of that copy must not
///     silently downgrade whole-tree verification to the patched members
///     (the inventory check compares the copy's `Cargo.toml` with this
///     uuid's tag dropped, so the tag itself still verifies);
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
    if entry.ecosystem == "cargo"
        && prev.ecosystem == "cargo"
        && entry.artifact.file_inventory.is_none()
        && prev.uuid == entry.uuid
        && prev.artifact.path == entry.artifact.path
    {
        entry.artifact.file_inventory = prev.artifact.file_inventory.clone();
    }

    for rec in &mut entry.wiring {
        if rec.action == WiringAction::Rewritten && rec.original.is_none() {
            let mut candidates = prev
                .wiring
                .iter()
                .filter(|p| wiring_surface_matches(p, rec));
            if rec.kind == "bun_lock_package" && !prev.wiring.iter().any(|p| p.kind == rec.kind) {
                rec.original = migrated_bun_original(prev, rec);
            } else if let Some(prev_rec) = candidates.next() {
                // Multiple equal binary resolutions can have different
                // registry originals. Renumbered IDs cannot disambiguate
                // them, so do not attach a guessed restore payload.
                if rec.kind == "bun_lockb_package"
                    && candidates.any(|p| match (&p.original, &prev_rec.original) {
                        (Some(a), Some(b)) => !binary_snapshot_identity_matches(a, b),
                        (a, b) => a != b,
                    })
                {
                    continue;
                }
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
                meta.created_workspace_packages |= prev_meta.created_workspace_packages;
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
            .any(|r| wiring_surface_matches(prev_rec, r));
        if !present {
            entry.wiring.push(prev_rec.clone());
        }
    }
}

/// The pre-vendor original of a `bun.lock` record that re-pinned a tuple
/// Bun migrated from the binary lock (#784): the previous entry recorded it
/// as a `bun.lockb` package snapshot, rebuilt here as the registry tuple Bun
/// writes for it. `None` when the binary records disagree on it.
fn migrated_bun_original(prev: &VendorEntry, current: &WiringRecord) -> Option<serde_json::Value> {
    let line = current.new.as_ref()?.as_str()?;
    let mut lines = prev
        .wiring
        .iter()
        .filter(|p| p.kind == "bun_lockb_package")
        .filter_map(|p| super::bun_binary::migrated_registry_line(line, p.original.as_ref()?));
    let first = lines.next()?;
    lines
        .all(|other| other == first)
        .then_some(serde_json::Value::String(first))
}

/// Binary IDs are offsets into Bun's package array and may change after an
/// installer re-save. Match the predecessor's semantic resolution instead.
fn wiring_surface_matches(previous: &WiringRecord, current: &WiringRecord) -> bool {
    // A cargo entry has ONE `[patch.crates-io]` surface wherever it lives:
    // the pre-v5 `.cargo/config*` record and the v5 `Cargo.toml` record (or
    // a manifest record under another key) are the same wiring, so a
    // migrated entry never carries the retired config record forward.
    if previous.kind == "cargo_patch_entry" && current.kind == "cargo_patch_entry" {
        return true;
    }
    if previous.file != current.file || previous.kind != current.kind {
        return false;
    }
    if current.kind == "bun_lockb_package" {
        return match (&previous.new, &current.new) {
            (Some(previous), Some(current)) => binary_snapshot_identity_matches(
                previous,
                current.get("previous").unwrap_or(current),
            ),
            _ => false,
        };
    }
    match (previous.key.as_deref(), current.key.as_deref()) {
        (Some(a), Some(b)) => super::path::wiring_key_matches(a, b),
        (a, b) => a == b,
    }
}

fn binary_snapshot_identity_matches(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    // Require the mandatory identity fields; a corrupt snapshot with missing
    // fields must not accidentally compare equal to another corrupt record.
    a.get("name").and_then(serde_json::Value::as_str).is_some()
        && a.get("resolution")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && ["name", "version", "resolution", "integrity"]
            .iter()
            .all(|key| a.get(key) == b.get(key))
}

/// The ledger entry addressable as `purl`: the exact map key first, then
/// the entry (the smallest such key, so the pick is deterministic) whose
/// key is `purl` in another spelling ([`PurlKey::qualified`]: encoding,
/// PyPI/NuGet name spelling, composer release spelling — a qualified purl
/// still names only its own variant), or whose resolved `base_purl` is the
/// unqualified `purl` (a qualified manifest key resolves to the entry
/// recorded under the base PURL).
pub fn lookup_entry<'a>(
    entries: &'a HashMap<String, VendorEntry>,
    purl: &str,
) -> Option<&'a VendorEntry> {
    lookup_entry_kv(entries, purl).map(|(_, entry)| entry)
}

/// [`lookup_entry`], keeping the ledger key the entry is filed under.
pub fn lookup_entry_kv<'a>(
    entries: &'a HashMap<String, VendorEntry>,
    purl: &str,
) -> Option<(&'a String, &'a VendorEntry)> {
    entries.get_key_value(purl).or_else(|| {
        let want = PurlKey::qualified(purl);
        entries
            .iter()
            .filter(|(key, e)| {
                PurlKey::qualified(key) == want || PurlKey::qualified(&e.base_purl) == want
            })
            .min_by(|(a, _), (b, _)| a.cmp(b))
    })
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
///
/// The bytes come from the (untrusted) project tree through the FIFO-safe
/// [`read_regular_to_bytes`] — non-blocking on Unix, rejecting FIFOs /
/// devices / directories — so a planted special file fails loudly instead of
/// wedging every vendor-adjacent command on an `open(2)` that waits forever
/// for a writer; same guard as the sibling redirect ledger.
pub async fn load_state(project_root: &Path) -> std::io::Result<VendorState> {
    let path = state_path(project_root);
    if let Some(state) = crate::utils::group_commit::read_value::<VendorState>(&path) {
        let mut state = (*state).clone();
        state.share_scaffold_flags();
        return Ok(state);
    }
    match read_regular_to_bytes(&path).await {
        Ok(bytes) => parse_state(&bytes, &path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VendorState::new()),
        Err(e) => Err(e),
    }
}

/// The ledger bytes as a [`VendorState`], created-scaffold flags shared
/// across entries ([`VendorState::share_scaffold_flags`], which also
/// repairs a ledger written before they were); see [`load_state`] for the
/// `mode`-tagged exception.
fn parse_state(bytes: &[u8], path: &Path) -> std::io::Result<VendorState> {
    let mut state = parse_state_raw(bytes, path)?;
    state.share_scaffold_flags();
    Ok(state)
}

fn parse_state_raw(bytes: &[u8], path: &Path) -> std::io::Result<VendorState> {
    if super::ledger_snapshots::may_have_snapshots(bytes) {
        return parse_snapshot_state(bytes, path);
    }
    serde_json::from_slice(bytes).or_else(|e| {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if value.get("mode").is_some() && value.get("entries").is_none() {
                return Ok(VendorState::new());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupt {}: {e}", path.display()),
        ))
    })
}

/// A ledger that may carry version-2 snapshot edits (see
/// [`super::ledger_snapshots`]): resolved back to full strings, every one
/// checked against its hash, before the typed parse.
fn parse_snapshot_state(bytes: &[u8], path: &Path) -> std::io::Result<VendorState> {
    let corrupt = |detail: String| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupt {}: {detail}", path.display()),
        )
    };
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| corrupt(e.to_string()))?;
    if value.get("mode").is_some() && value.get("entries").is_none() {
        return Ok(VendorState::new());
    }
    super::ledger_snapshots::decode(&mut value).map_err(corrupt)?;
    serde_json::from_value(value).map_err(|e| corrupt(e.to_string()))
}

/// The run's ledger parse. The hatch backend asks the ledger the same two
/// questions for every patched package — which entry carries this uuid, and
/// which wiring record already allows direct references — and a ledger
/// holding a whole-file snapshot per wired file runs to megabytes, so an
/// idempotent re-run (which writes no ledger at all) would otherwise parse
/// the same bytes once per package. See [`ParseMemo`]: the read still happens every time,
/// and a ledger something else rewrote between two packages differs in its
/// bytes and is re-parsed.
static STATE_MEMO: ParseMemo<VendorState> = ParseMemo::new();

/// [`load_state`], reusing the run's parse while the ledger's bytes are the
/// ones that produced it — for the read-only callers that ask the same
/// ledger about every patched package. The state comes back shared: nobody
/// on this path mutates it (the writers go through [`save_state`], which
/// drops the slot).
pub(crate) async fn load_state_shared(project_root: &Path) -> std::io::Result<Arc<VendorState>> {
    let path = state_path(project_root);
    if let Some(state) = crate::utils::group_commit::read_value::<VendorState>(&path) {
        return Ok(VendorState::with_shared_scaffold_flags(state));
    }
    match read_regular_to_bytes(&path).await {
        Ok(bytes) => STATE_MEMO.parse(&bytes, || parse_state(&bytes, &path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Arc::new(VendorState::new())),
        Err(e) => Err(e),
    }
}

/// Persist the ledger atomically with sorted keys + 2-space indent + trailing
/// newline (deterministic bytes — the file is committed; a byte-identical
/// ledger is not rewritten). An EMPTY ledger deletes `state.json` and prunes
/// `.socket/vendor/` when that leaves it empty, so a fully-reverted project
/// carries no vendor residue below `.socket/` itself (the lock guard's
/// level). A failed unlink propagates before any prune.
pub async fn save_state(project_root: &Path, state: &VendorState) -> std::io::Result<()> {
    let path = state_path(project_root);
    // Dropped before the write, so a torn one leaves nothing behind either.
    // Never needed for correctness — [`load_state_shared`] keys on the bytes
    // it just read — this is how the run stops holding a ledger nothing will
    // hit again.
    STATE_MEMO.invalidate();
    if !state.entries.is_empty() {
        // Inside a group-committed run the ledger is held as a value and
        // rendered once, at the commit (or when something reads its bytes).
        if crate::utils::group_commit::capture_value(&path, Arc::new(state.clone()), render_state) {
            return Ok(());
        }
        return write_json_ledger(&path, &ledger_value(state)?).await;
    }
    let socket_dir = project_root.join(SOCKET_DIR);
    // Delete the ledger; a read-only parent surfaces here, before anything
    // is pruned.
    remove_file_and_prune(&path, &socket_dir).await?;
    // Backstop for ecosystem-level husks left by per-unit reverts that did
    // not prune their own parents. `remove_dir` is non-recursive: a dir
    // still holding artifacts (or anything we don't own) is kept, and then
    // so is `.socket/vendor/`.
    let vendor_root = project_root.join(VENDOR_DIR);
    for eco in super::path::ECOSYSTEM_DIRS {
        prune_empty_dirs(&vendor_root.join(eco), &socket_dir).await;
    }
    Ok(())
}

/// [`save_state`] for a caller that holds the ledger as an `Arc` and
/// changes it once per save (the vendor loop, one entry per package):
/// `edit` is applied to `state` and the result persisted exactly as
/// [`save_state`] would persist it. Inside a group commit the ledger the
/// group holds IS `state` — the edit happens in place and nothing is
/// copied — where [`save_state`] captured a deep copy of the whole ledger
/// per package, O(P²) over a run. The bytes the commit renders are the
/// same, since the captured value is the same ledger.
///
/// `edit` always runs, before any write is attempted, so a failed save
/// leaves `state` edited exactly as the caller's own edit-then-save did.
pub async fn save_state_shared(
    project_root: &Path,
    state: &mut Arc<VendorState>,
    edit: impl FnOnce(&mut VendorState),
) -> std::io::Result<()> {
    let path = state_path(project_root);
    STATE_MEMO.invalidate();
    match crate::utils::group_commit::edit_value(&path, state, edit, render_state) {
        Ok(()) if !state.entries.is_empty() => return Ok(()),
        // Captured but emptied: `save_state` turns it into the removal.
        Ok(()) => {}
        Err(edit) => edit(Arc::make_mut(state)),
    }
    save_state(project_root, state).await
}

/// The ledger's on-disk JSON: a whole-file wiring record's `new` is
/// stored as a version-2 edit of its `original` (see
/// `super::ledger_snapshots`); a ledger without one keeps its version-1
/// form.
fn ledger_value(state: &VendorState) -> std::io::Result<serde_json::Value> {
    // A package wired this run beside one that created a shared scaffold
    // records `false`; persist the shared flags so a later run's revert
    // order cannot matter.
    let mut ledger = if state.scaffold_flags_shared() {
        serde_json::to_value(state)
    } else {
        let mut shared = state.clone();
        shared.share_scaffold_flags();
        serde_json::to_value(&shared)
    }
    .map_err(std::io::Error::other)?;
    super::ledger_snapshots::encode(&mut ledger);
    Ok(ledger)
}

/// The bytes [`write_json_ledger`] writes for a captured ledger.
fn render_state(value: &(dyn std::any::Any + Send + Sync)) -> std::io::Result<Vec<u8>> {
    let state = value
        .downcast_ref::<VendorState>()
        .ok_or_else(|| std::io::Error::other("captured ledger is not a VendorState"))?;
    let mut bytes =
        serde_json::to_vec_pretty(&ledger_value(state)?).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
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
    // Never a trust input, so an artifact write (no fsync of its own).
    atomic_write_artifact(&uuid_dir.join(VENDOR_MARKER_FILE), &bytes).await
}

/// [`write_marker`], downgrading a failure to ONE `vendor_marker_write_failed`
/// warning on `warnings`. The marker is belt-and-braces metadata — never a
/// trust input (sweep/verify key off state.json + the path uuid) — so its
/// failure must not undo an otherwise fully-wired vendor. Every backend's
/// fresh and rebuild paths report it through here so the code and wording
/// cannot drift.
pub(crate) async fn write_marker_or_warn(
    uuid_dir: &Path,
    marker: &VendorMarker,
    warnings: &mut Vec<super::VendorWarning>,
) {
    if let Err(e) = write_marker(uuid_dir, marker).await {
        warnings.push(super::VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write the informational vendor marker {VENDOR_MARKER_FILE}: {e}"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn sample_entry() -> VendorEntry {
        VendorEntry::new(
            "npm".into(),
            "pkg:npm/lodash@4.17.21".into(),
            UUID.into(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: format!(".socket/vendor/npm/{UUID}/lodash-4.17.21.tgz"),
                sha256: "ab".repeat(32),
                size: Some(3668),
                platform_locked: None,
                file_inventory: None,
            },
            vec![WiringRecord {
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
        )
    }

    /// A cargo entry migrated from the pre-v5 `.cargo/config.toml` wiring to
    /// `Cargo.toml` must not carry the retired config record forward (one
    /// `[patch]` surface per entry), while the lock record and originals
    /// still carry over.
    #[test]
    fn carry_forward_drops_the_legacy_cargo_config_record() {
        let rec = |file: &str, kind: &str, key: &str| WiringRecord {
            file: file.into(),
            kind: kind.into(),
            action: WiringAction::Added,
            key: Some(key.into()),
            original: None,
            new: None,
        };
        let uuid = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        let base = |wiring: Vec<WiringRecord>, lock: Option<CargoLockOriginal>| VendorEntry {
            lock,
            ..VendorEntry::new(
                "cargo".into(),
                "pkg:cargo/cfg-if@1.0.4".into(),
                uuid.into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: format!(".socket/vendor/cargo/{uuid}/cfg-if-1.0.4"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring,
            )
        };
        let orig = CargoLockOriginal {
            source: "registry+https://github.com/rust-lang/crates.io-index".into(),
            checksum: Some("a".repeat(64)),
        };
        let prev = base(
            vec![
                rec(".cargo/config.toml", "cargo_patch_entry", "cfg-if"),
                rec("Cargo.lock", "cargo_lock_entry", "cfg-if@1.0.4"),
            ],
            Some(orig.clone()),
        );
        let mut fresh = base(vec![rec("Cargo.toml", "cargo_patch_entry", "cfg-if")], None);
        carry_forward_wiring(&prev, &mut fresh);
        let files: Vec<&str> = fresh.wiring.iter().map(|w| w.file.as_str()).collect();
        assert_eq!(files, vec!["Cargo.toml", "Cargo.lock"]);
        assert_eq!(fresh.lock, Some(orig));
    }

    /// A cargo re-run that only (re)tags or migrates the SAME copy records
    /// no inventory (the cargo backend never takes one): the previous
    /// entry's whole-tree inventory carries forward, so verification is not
    /// silently downgraded to the patched members. A new uuid or copy path
    /// is a new tree: nothing carries.
    #[test]
    fn carry_forward_keeps_a_cargo_inventory_for_the_same_copy() {
        let uuid2 = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
        let cargo = |uuid: &str, inventory: Option<BTreeMap<String, String>>| {
            let mut e = sample_entry();
            e.ecosystem = "cargo".into();
            e.base_purl = "pkg:cargo/cfg-if@1.0.4".into();
            e.uuid = uuid.into();
            e.wiring.clear();
            e.artifact.path = format!(".socket/vendor/cargo/{uuid}/cfg-if-1.0.4");
            e.artifact.file_inventory = inventory;
            e
        };
        let inventory: BTreeMap<String, String> = [("Cargo.toml".to_string(), "ab".repeat(32))]
            .into_iter()
            .collect();
        let prev = cargo(UUID, Some(inventory.clone()));

        let mut same = cargo(UUID, None);
        carry_forward_wiring(&prev, &mut same);
        assert_eq!(same.artifact.file_inventory, Some(inventory.clone()));

        let mut fresh_inventory: BTreeMap<String, String> = BTreeMap::new();
        fresh_inventory.insert("src/lib.rs".into(), "cd".repeat(32));
        let mut own = cargo(UUID, Some(fresh_inventory.clone()));
        carry_forward_wiring(&prev, &mut own);
        assert_eq!(
            own.artifact.file_inventory,
            Some(fresh_inventory),
            "never overwritten"
        );

        let mut bumped = cargo(uuid2, None);
        carry_forward_wiring(&prev, &mut bumped);
        assert_eq!(
            bumped.artifact.file_inventory, None,
            "another uuid: another tree"
        );

        let mut moved = cargo(UUID, None);
        moved.artifact.path = format!(".socket/vendor/cargo/{UUID}/cfg-if-1.0.5");
        carry_forward_wiring(&prev, &mut moved);
        assert_eq!(moved.artifact.file_inventory, None, "another copy path");

        let mut npm_prev = sample_entry();
        npm_prev.artifact.file_inventory = Some(inventory);
        let mut npm = sample_entry();
        carry_forward_wiring(&npm_prev, &mut npm);
        assert_eq!(npm.artifact.file_inventory, None, "cargo only");
    }

    /// Every spelling `purl_keys` covers: the (possibly qualified,
    /// percent-encoded) map key, the entry's base purl and the
    /// qualifier-stripped key all share one `PurlKey`; an empty ledger
    /// yields the empty set.
    #[test]
    fn purl_keys_carry_every_spelling() {
        let mut state = VendorState::new();
        let mut entry = sample_entry();
        entry.base_purl = "pkg:npm/@scope/pkg@1.0.0".into();
        state
            .entries
            .insert("pkg:npm/%40scope/pkg@1.0.0?artifact_id=x".into(), entry);
        let keys = state.purl_keys();
        for spelling in [
            "pkg:npm/%40scope/pkg@1.0.0?artifact_id=x",
            "pkg:npm/%40scope/pkg@1.0.0",
            "pkg:npm/@scope/pkg@1.0.0",
        ] {
            assert!(
                purl_keys_cover(&keys, spelling),
                "missing {spelling}: {keys:?}"
            );
        }
        assert_eq!(keys.len(), 1);
        assert!(VendorState::new().purl_keys().is_empty());
    }

    /// `matches_identifier`: ledger key, base purl (the decoded spelling a
    /// golang user types) and uuid all address the entry; a foreign purl or
    /// uuid does not.
    #[test]
    fn entry_matches_identifier_by_key_base_purl_or_uuid() {
        let mut entry = sample_entry();
        entry.ecosystem = "golang".into();
        entry.base_purl = "pkg:golang/github.com/BurntSushi/toml@1.0.0".into();
        let key = "pkg:golang/github.com/!burnt!sushi/toml@1.0.0";
        assert!(entry.matches_target(key, &Target::parse(key)));
        assert!(entry.matches_target(
            key,
            &Target::parse("pkg:golang/github.com/BurntSushi/toml@1.0.0")
        ));
        assert!(entry.matches_target(key, &Target::parse(UUID)));
        assert!(!entry.matches_target(
            key,
            &Target::parse("pkg:golang/github.com/BurntSushi/toml@2.0.0")
        ));
        assert!(!entry.matches_target(key, &Target::parse("00000000-0000-4000-8000-000000000000")));

        // A last-segment name reaching the entry only through its decoded
        // base purl is counted under that purl, never under the encoded key.
        let name = Target::parse("Toml");
        assert_eq!(entry.ambiguity_purl(key, &name), entry.base_purl);
        let mut core = sample_entry();
        core.ecosystem = "golang".into();
        core.base_purl = "pkg:golang/github.com/x/Core@1.0.0".into();
        let core_key = "pkg:golang/github.com/x/!core@1.0.0";
        // Another last-segment-only match: a full-name match such as
        // `pkg:npm/core` would settle the name on its own.
        let other = "pkg:npm/@x/core@1.0.0";
        let core_name = Target::parse("core");
        assert!(core.matches_target(core_key, &core_name));
        assert!(core_name
            .ambiguity([core.ambiguity_purl(core_key, &core_name), other])
            .is_some());
        // One entry, encoded key plus decoded base: one package.
        let sushi = Target::parse("toml");
        assert_eq!(sushi.ambiguity([entry.ambiguity_purl(key, &sushi)]), None);

        // A qualified pypi key: the base identifier covers it, another
        // variant's qualifier does not.
        let mut entry = sample_entry();
        entry.base_purl = "pkg:pypi/requests@2.28.0".into();
        let key = "pkg:pypi/requests@2.28.0?artifact_id=abc";
        assert!(entry.matches_target(key, &Target::parse("pkg:pypi/requests@2.28.0")));
        assert!(entry.matches_target(key, &Target::parse(key)));
        assert!(!entry.matches_target(
            key,
            &Target::parse("pkg:pypi/requests@2.28.0?artifact_id=zzz")
        ));
    }

    /// `covers_purl`: the exact key, a qualifier-stripped twin of the key
    /// and the base purl all belong to the entry; a different package does
    /// not, and the match is by spelling (no percent-decoding — the set
    /// form `purl_keys` carries the same three spellings).
    #[test]
    fn entry_covers_purl_by_key_stripped_key_or_base_purl() {
        let mut entry = sample_entry();
        entry.base_purl = "pkg:npm/@scope/pkg@1.0.0".into();
        let key = "pkg:npm/%40scope/pkg@1.0.0?artifact_id=x";
        assert!(entry.covers_purl(key, key));
        assert!(entry.covers_purl(key, "pkg:npm/%40scope/pkg@1.0.0"));
        assert!(entry.covers_purl(key, "pkg:npm/%40scope/pkg@1.0.0?artifact_id=other"));
        assert!(entry.covers_purl(key, "pkg:npm/@scope/pkg@1.0.0"));
        assert!(entry.covers_purl(key, "pkg:npm/@scope/pkg@1.0.0?artifact_id=y"));
        assert!(!entry.covers_purl(key, "pkg:npm/@scope/pkg@1.0.1"));
        assert!(!entry.covers_purl(key, "pkg:npm/other@1.0.0"));
    }

    /// #553 / B20: a NuGet ledger entry recorded under the lockfile's
    /// lowercase purl is the same package as the API's mixed-case purl, for
    /// every ownership check (per-entry, whole-set, lookup).
    #[test]
    fn nuget_case_spellings_are_one_vendored_package() {
        let mut entry = sample_entry();
        entry.base_purl = "pkg:nuget/newtonsoft.json@13.0.3".into();
        let key = "pkg:nuget/newtonsoft.json@13.0.3";
        let api = "pkg:nuget/Newtonsoft.Json@13.0.3";
        assert!(entry.covers_purl(key, api));
        let mut state = VendorState::new();
        state.entries.insert(key.to_string(), entry);
        assert!(purl_keys_cover(&state.purl_keys(), api));
        assert!(!purl_keys_cover(
            &state.purl_keys(),
            "pkg:nuget/Newtonsoft.Json@13.0.4"
        ));
        let (found, _) = lookup_entry_kv(&state.entries, api).expect("case variant found");
        assert_eq!(found, key);
    }

    /// A maven-shaped entry: the wiring record holds the whole pom before
    /// and after the vendored `<repository>` was added.
    fn whole_file_entry(purl: &str, uuid: &str, before: &str, after: &str) -> VendorEntry {
        let mut entry = sample_entry();
        entry.ecosystem = "maven".into();
        entry.base_purl = purl.into();
        entry.uuid = uuid.into();
        entry.wiring = vec![WiringRecord {
            file: "pom.xml".into(),
            kind: "maven_pom_repository".into(),
            action: WiringAction::Added,
            key: Some(format!("socket-patch-vendor-{uuid}")),
            original: Some(serde_json::Value::String(before.into())),
            new: Some(serde_json::Value::String(after.into())),
        }];
        entry
    }

    /// A whole-file record's `new` is stored as a small edit of its own
    /// `original` (version 2) and loads back to exactly the in-memory
    /// state, `version` included.
    #[tokio::test]
    async fn whole_file_snapshots_are_stored_as_edits_and_load_back_exactly() {
        let tmp = tempfile::tempdir().unwrap();
        let pom0 = format!(
            "<project>\n{}</project>\n",
            "  <dependency><artifactId>filler</artifactId></dependency>\n".repeat(400)
        );
        let pom1 = pom0.replace(
            "</project>",
            "  <repositories>one</repositories>\n</project>",
        );
        let pom2 = pom1.replace("</repositories>", "two</repositories>");
        let mut state = VendorState::new();
        state.entries.insert(
            "pkg:maven/g/a@1".into(),
            whole_file_entry("pkg:maven/g/a@1", UUID, &pom0, &pom1),
        );
        state.entries.insert(
            "pkg:maven/g/b@1".into(),
            whole_file_entry(
                "pkg:maven/g/b@1",
                "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d",
                &pom1,
                &pom2,
            ),
        );
        save_state(tmp.path(), &state).await.unwrap();
        let bytes = std::fs::read(tmp.path().join(VENDOR_STATE_REL)).unwrap();
        let on_disk: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(on_disk["version"], 2);
        assert!(
            bytes.len() < 2 * pom0.len() + 4096,
            "two full poms plus two edits, not four poms: {} bytes",
            bytes.len()
        );
        assert_eq!(load_state(tmp.path()).await.unwrap(), state);

        // Losing the last whole-file record (a revert of that package)
        // re-saves the plain version-1 bytes.
        let mut back = load_state(tmp.path()).await.unwrap();
        back.entries.clear();
        back.entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(tmp.path(), &back).await.unwrap();
        let mut expected = serde_json::to_vec_pretty(&back).unwrap();
        expected.push(b'\n');
        assert_eq!(
            std::fs::read(tmp.path().join(VENDOR_STATE_REL)).unwrap(),
            expected
        );
    }

    /// A ledger with no snapshot-sized string keeps its version-1 bytes,
    /// exactly what the plain serializer writes; a version-1 ledger with
    /// inline whole-file snapshots (every ledger before version 2) loads
    /// as it always did.
    #[tokio::test]
    async fn version_one_ledgers_keep_their_bytes_and_still_load() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(tmp.path(), &state).await.unwrap();
        let mut expected = serde_json::to_vec_pretty(&state).unwrap();
        expected.push(b'\n');
        assert_eq!(
            std::fs::read(tmp.path().join(VENDOR_STATE_REL)).unwrap(),
            expected
        );

        let pom0 = "x".repeat(5000);
        let pom1 = format!("{pom0}<repo/>");
        let mut legacy = VendorState::new();
        legacy.entries.insert(
            "pkg:maven/g/a@1".into(),
            whole_file_entry("pkg:maven/g/a@1", UUID, &pom0, &pom1),
        );
        let mut bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        bytes.push(b'\n');
        std::fs::write(tmp.path().join(VENDOR_STATE_REL), &bytes).unwrap();
        assert_eq!(load_state(tmp.path()).await.unwrap(), legacy);
    }

    fn composer_entry(base_purl: &str) -> VendorEntry {
        let mut entry = sample_entry();
        entry.ecosystem = "composer".into();
        entry.base_purl = base_purl.into();
        entry
    }

    /// Composer ownership is by release identity: an entry vendored as
    /// `@3.0.2.0` owns the `@3.0.2` / `@v3.0.2` a later scan sees, and the
    /// reverse; another release or another ecosystem's spelling games do not.
    #[test]
    fn composer_ownership_matches_every_version_spelling() {
        let padded = "pkg:composer/psr/log@3.0.2.0";
        let entry = composer_entry(padded);
        for purl in [
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/Psr/Log@v3.0.2",
            padded,
        ] {
            assert!(entry.covers_purl(padded, purl), "{purl}");
        }
        assert!(!entry.covers_purl(padded, "pkg:composer/psr/log@3.0.3"));
        let bare = composer_entry("pkg:composer/psr/log@3.0.2");
        assert!(bare.covers_purl("pkg:composer/psr/log@3.0.2", padded));

        let mut state = VendorState::new();
        state.entries.insert(padded.into(), entry);
        let keys = state.purl_keys();
        assert!(purl_keys_cover(&keys, "pkg:composer/psr/log@3.0.2"));
        assert!(purl_keys_cover(&keys, "pkg:composer/psr/log@v3.0.2"));
        assert!(purl_keys_cover(&keys, padded));
        assert!(!purl_keys_cover(&keys, "pkg:composer/psr/log@3.0.3"));
        assert!(!purl_keys_cover(&keys, "pkg:npm/psr/log@3.0.2"));

        // Non-composer ownership keeps exact spelling semantics.
        let mut npm = VendorState::new();
        npm.entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        let npm_keys = npm.purl_keys();
        assert!(purl_keys_cover(&npm_keys, "pkg:npm/lodash@4.17.21?x=y"));
        assert!(!purl_keys_cover(&npm_keys, "pkg:npm/lodash@4.17.21.0"));
    }

    /// `lookup_entry_kv` finds a composer entry filed under another spelling
    /// of the same release, preferring an exact key and picking the smallest
    /// equivalent key when several exist.
    #[test]
    fn lookup_finds_a_composer_entry_by_release_identity() {
        let mut entries = HashMap::new();
        entries.insert(
            "pkg:composer/psr/log@3.0.2.0".to_string(),
            composer_entry("pkg:composer/psr/log@3.0.2.0"),
        );
        let (key, _) = lookup_entry_kv(&entries, "pkg:composer/psr/log@3.0.2").unwrap();
        assert_eq!(key, "pkg:composer/psr/log@3.0.2.0");
        assert!(lookup_entry(&entries, "pkg:composer/psr/log@3.0.3").is_none());

        entries.insert(
            "pkg:composer/psr/log@v3.0.2".to_string(),
            composer_entry("pkg:composer/psr/log@v3.0.2"),
        );
        let (key, _) = lookup_entry_kv(&entries, "pkg:composer/psr/log@v3.0.2").unwrap();
        assert_eq!(key, "pkg:composer/psr/log@v3.0.2", "an exact key wins");
        let (key, _) = lookup_entry_kv(&entries, "pkg:composer/psr/log@3.0.2").unwrap();
        assert_eq!(
            key, "pkg:composer/psr/log@3.0.2.0",
            "smallest equivalent key"
        );
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

    /// #636 / #670: the created-scaffold flags the first package recorded
    /// are shared with every entry wiring the same files — on load (which
    /// repairs a ledger written before) and on save — so revert order no
    /// longer decides whether the emptied scaffold is removed.
    #[tokio::test]
    async fn created_scaffold_flags_are_shared_across_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let with = |flavor: &str, uv: Option<UvMeta>, pnpm: Option<PnpmMeta>| {
            let mut e = sample_entry();
            e.flavor = Some(flavor.into());
            e.uv = uv;
            e.pnpm = pnpm;
            e
        };
        let uv_meta = |created| UvMeta {
            dep_class: "direct".into(),
            original_specifier: None,
            created_sources_table: created,
            lock_revision: None,
        };
        let creator = PnpmMeta {
            created_overrides_table: true,
            created_pnpm_table: true,
            created_workspace_file: true,
            created_workspace_overrides: false,
            created_workspace_packages: false,
        };
        let mut state = VendorState::new();
        for (key, entry) in [
            ("pkg:npm/a@1.0.0", with("pnpm", None, Some(creator.clone()))),
            (
                "pkg:npm/b@1.0.0",
                with("pnpm", None, Some(PnpmMeta::default())),
            ),
            ("pkg:pypi/c@1.0.0", with("uv", Some(uv_meta(true)), None)),
            ("pkg:pypi/d@1.0.0", with("uv", Some(uv_meta(false)), None)),
            ("pkg:cargo/e@1.0.0", sample_entry()),
        ] {
            state.entries.insert(key.into(), entry);
        }

        save_state(root, &state).await.unwrap();
        let text = tokio::fs::read_to_string(root.join(VENDOR_STATE_REL))
            .await
            .unwrap();
        assert_eq!(text.matches("\"createdSourcesTable\": true").count(), 2);
        assert_eq!(text.matches("\"createdOverridesTable\": true").count(), 2);

        // A ledger with only the creator flagged (as older releases wrote
        // it) loads with the flags shared.
        let mut legacy: serde_json::Value = serde_json::from_str(&text).unwrap();
        legacy["entries"]["pkg:npm/b@1.0.0"]["pnpm"] = serde_json::json!({});
        legacy["entries"]["pkg:pypi/d@1.0.0"]["uv"]
            .as_object_mut()
            .unwrap()
            .remove("createdSourcesTable");
        tokio::fs::write(
            root.join(VENDOR_STATE_REL),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .await
        .unwrap();
        let loaded = load_state(root).await.unwrap();
        assert_eq!(loaded.entries["pkg:npm/b@1.0.0"].pnpm, Some(creator));
        assert!(
            loaded.entries["pkg:pypi/d@1.0.0"]
                .uv
                .as_ref()
                .unwrap()
                .created_sources_table
        );
        assert!(loaded.entries["pkg:cargo/e@1.0.0"].pnpm.is_none());
        assert!(loaded.entries["pkg:cargo/e@1.0.0"].uv.is_none());

        // Nothing flagged stays unflagged.
        let mut plain = VendorState::new();
        plain.entries.insert(
            "pkg:npm/a@1.0.0".into(),
            with("pnpm", None, Some(PnpmMeta::default())),
        );
        plain.share_scaffold_flags();
        assert_eq!(
            plain.entries["pkg:npm/a@1.0.0"].pnpm,
            Some(PnpmMeta::default())
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
            created_workspace_packages: false,
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

    #[test]
    fn binary_carry_forward_preserves_original_after_id_reordering_and_supersede() {
        let snapshot = |name: &str, resolution: &str| {
            serde_json::json!({
                "name": name, "version": null, "resolution": resolution, "integrity": "sha512-ours",
            })
        };
        let old = snapshot("minimist", "./.socket/vendor/npm/old/minimist-1.2.2.tgz");
        let original = serde_json::json!({"name":"minimist", "version":"1.2.2", "resolution":"https://registry/minimist-1.2.2.tgz", "integrity":"sha512-original"});
        let record = |key: &str, original, new| WiringRecord {
            file: "bun.lockb".into(),
            kind: "bun_lockb_package".into(),
            key: Some(key.into()),
            action: WiringAction::Rewritten,
            original,
            new: Some(new),
        };
        for supersede in [false, true] {
            let mut previous = sample_entry();
            previous.wiring = vec![record("2", Some(original.clone()), old.clone())];
            let mut current = sample_entry();
            if supersede {
                current.uuid = "22222222-2222-4222-8222-222222222222".into();
            }
            let mut next = snapshot("minimist", "./.socket/vendor/npm/new/minimist-1.2.2.tgz");
            next["previous"] = old.clone();
            current.wiring = vec![record("7", None, next)];
            carry_forward_wiring(&previous, &mut current);
            assert_eq!(
                current.wiring.len(),
                1,
                "moved IDs must not retain stale duplicate wiring"
            );
            assert_eq!(current.wiring[0].original, Some(original.clone()));
            assert_eq!(current.wiring[0].key.as_deref(), Some("7"));
        }

        // Reusing the same numeric ID for another package must never copy
        // that package's registry snapshot into the current record.
        let mut previous = sample_entry();
        previous.wiring = vec![record("2", Some(original), old)];
        let mut current = sample_entry();
        current.uuid = "22222222-2222-4222-8222-222222222222".into();
        current.wiring = vec![record("2", None, snapshot("other", "file:other"))];
        carry_forward_wiring(&previous, &mut current);
        assert!(current.wiring[0].original.is_none());
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

    /// The shared ledger read answers exactly what [`load_state`] answers,
    /// for every shape the loader distinguishes — a present ledger, a
    /// missing one, the foreign mode-tagged file, and a corrupt one (whose
    /// failure is never cached, so the next read reports it again).
    #[tokio::test]
    async fn the_shared_ledger_read_matches_the_unshared_one() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(
            *load_state_shared(root).await.unwrap(),
            load_state(root).await.unwrap(),
            "a missing ledger"
        );

        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(root, &state).await.unwrap();
        assert_eq!(
            *load_state_shared(root).await.unwrap(),
            load_state(root).await.unwrap(),
            "a wired ledger"
        );
        // Twice, so the second read is the one the memo answers.
        assert_eq!(
            *load_state_shared(root).await.unwrap(),
            load_state(root).await.unwrap(),
            "the memoized read of a wired ledger"
        );

        tokio::fs::write(
            root.join(VENDOR_STATE_REL),
            br#"{ "version": 1, "mode": "registry", "edits": [] }"#,
        )
        .await
        .unwrap();
        assert_eq!(
            *load_state_shared(root).await.unwrap(),
            load_state(root).await.unwrap(),
            "a foreign mode-tagged ledger"
        );

        tokio::fs::write(root.join(VENDOR_STATE_REL), b"{not json")
            .await
            .unwrap();
        for attempt in 0..2 {
            assert_eq!(
                load_state_shared(root).await.unwrap_err().kind(),
                std::io::ErrorKind::InvalidData,
                "a corrupt ledger must fail closed on attempt {attempt}"
            );
        }
    }

    /// The ledger memo skips the parse, never the read: a ledger something
    /// else rewrote between two packages of a run — a concurrent
    /// `socket-patch` on the same project, a hand edit — must be seen by the
    /// second, without anyone invalidating anything.
    #[tokio::test]
    async fn an_external_ledger_edit_between_reads_is_not_memoized() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        let mut state = VendorState::new();
        state
            .entries
            .insert("pkg:npm/lodash@4.17.21".into(), sample_entry());
        save_state(root, &state).await.unwrap();
        assert_eq!(load_state_shared(root).await.unwrap().entries.len(), 1);

        // Written behind the loader's back: no save_state, no invalidate.
        let mut other = VendorState::new();
        other
            .entries
            .insert("pkg:npm/left-pad@1.3.0".into(), sample_entry());
        tokio::fs::write(
            root.join(VENDOR_STATE_REL),
            serde_json::to_vec(&other).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            load_state_shared(root)
                .await
                .unwrap()
                .entries
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["pkg:npm/left-pad@1.3.0".to_string()],
            "the second read must build on the bytes on disk"
        );
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

        // An empty ecosystem husk left by a per-unit revert goes too.
        tokio::fs::create_dir_all(root.join(".socket/vendor/npm"))
            .await
            .unwrap();
        // `.socket/` holds something else (the lock, a manifest…).
        tokio::fs::write(root.join(".socket/apply.lock"), b"")
            .await
            .unwrap();
        state.entries.clear();
        save_state(root, &state).await.unwrap();
        assert!(!root.join(VENDOR_STATE_REL).exists());
        assert!(
            !root.join(VENDOR_DIR).exists(),
            ".socket/vendor (and its empty eco husks) pruned when empty"
        );
        assert!(
            root.join(SOCKET_DIR).exists(),
            ".socket/ itself is never pruned here"
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

    /// The ledger path is spelled as a literal (a `const` cannot be built
    /// from another with `concat!`); pin it to the directory constant it
    /// re-spells so the two can never drift apart.
    #[test]
    fn vendor_state_rel_lives_directly_under_vendor_dir() {
        assert_eq!(VENDOR_STATE_REL, format!("{VENDOR_DIR}/state.json"));
        assert!(VENDOR_DIR.starts_with(&format!("{SOCKET_DIR}/")));
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

    /// SC5: [`save_state_shared`] persists exactly what the edit-then-
    /// [`save_state`] it replaces persists — the same ledger seen by every
    /// read, the same committed bytes, the same removal once emptied —
    /// with and without a group commit; inside one, the edit is made on
    /// the ledger the group holds instead of a per-save copy.
    #[tokio::test]
    async fn shared_save_matches_edit_then_save_state() {
        use crate::utils::group_commit::GroupCommit;
        for grouped in [false, true] {
            let (shared_dir, owned_dir) =
                (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let (a, b) = (shared_dir.path(), owned_dir.path());
            let mut seed = VendorState::new();
            seed.entries
                .insert("pkg:npm/seed@1.0.0".into(), sample_entry());
            save_state(a, &seed).await.unwrap();
            save_state(b, &seed).await.unwrap();

            let groups = grouped.then(|| (GroupCommit::begin(a), GroupCommit::begin(b)));
            let mut shared = Arc::new(load_state(a).await.unwrap());
            let mut owned = load_state(b).await.unwrap();
            for i in 0..6 {
                let key = format!("pkg:npm/p{i}@1.0.0");
                let mut entry = sample_entry();
                entry.uuid = format!("{i:08}-0000-4000-8000-000000000000");
                owned.entries.insert(key.clone(), entry.clone());
                save_state(b, &owned).await.unwrap();
                let before = Arc::as_ptr(&shared);
                save_state_shared(a, &mut shared, |s| {
                    s.entries.insert(key, entry);
                })
                .await
                .unwrap();
                if grouped && i > 0 {
                    assert_eq!(Arc::as_ptr(&shared), before, "edited in place, not copied");
                }
                assert_eq!(*shared, owned);
                assert_eq!(load_state(a).await.unwrap(), load_state(b).await.unwrap());
                assert_eq!(*load_state_shared(a).await.unwrap(), owned);
            }
            if let Some((ga, gb)) = groups {
                ga.commit().await.unwrap();
                gb.commit().await.unwrap();
            }
            assert_eq!(
                std::fs::read(a.join(VENDOR_STATE_REL)).unwrap(),
                std::fs::read(b.join(VENDOR_STATE_REL)).unwrap(),
                "grouped {grouped}: committed ledger bytes"
            );

            // Emptied: both remove the ledger.
            let groups = grouped.then(|| (GroupCommit::begin(a), GroupCommit::begin(b)));
            owned.entries.clear();
            save_state(b, &owned).await.unwrap();
            save_state_shared(a, &mut shared, |s| s.entries.clear())
                .await
                .unwrap();
            if let Some((ga, gb)) = groups {
                ga.commit().await.unwrap();
                gb.commit().await.unwrap();
            }
            assert!(!a.join(VENDOR_STATE_REL).exists(), "grouped {grouped}");
            assert!(!b.join(VENDOR_STATE_REL).exists(), "grouped {grouped}");
        }
    }

    /// #922: the npm-family constructor serializes to exactly the ledger
    /// JSON the yarn-classic backend's literal entry did.
    #[test]
    fn npm_constructor_matches_the_yarn_classic_literal() {
        let packed = super::super::npm_pack::PackedTarball::from_bytes(b"tarball bytes");
        let rel = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
        let wiring = vec![WiringRecord {
            file: "yarn.lock".to_string(),
            kind: "yarn_lock_block".to_string(),
            action: WiringAction::Rewritten,
            key: Some("left-pad@^1.3.0".to_string()),
            original: Some(serde_json::json!(["left-pad@^1.3.0:"])),
            new: Some(serde_json::json!([
                "left-pad@^1.3.0:",
                "  version \"1.3.0\""
            ])),
        }];
        let literal = VendorEntry {
            ecosystem: "npm".to_string(),
            base_purl: "pkg:npm/left-pad@1.3.0".to_string(),
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            artifact: VendorArtifact {
                yarn_berry10c0: None,
                path: rel.to_string(),
                sha256: packed.sha256_hex.clone(),
                size: Some(packed.size),
                platform_locked: None,
                file_inventory: None,
            },
            wiring: wiring.clone(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("yarn-classic".to_string()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        };
        let built = VendorEntry::npm(
            "pkg:npm/left-pad@1.3.0".to_string(),
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            VendorArtifact::tarball(rel.to_string(), &packed),
            wiring,
            Some("yarn-classic"),
        );
        assert_eq!(built, literal);
        assert_eq!(
            serde_json::to_string_pretty(&built).unwrap(),
            serde_json::to_string_pretty(&literal).unwrap()
        );
        // The pinned JSON: no other ecosystem's extras, no
        // `yarnBerry10c0`, no `fileInventory`.
        assert_eq!(
            serde_json::to_value(&built).unwrap(),
            serde_json::json!({
                "ecosystem": "npm",
                "basePurl": "pkg:npm/left-pad@1.3.0",
                "uuid": "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
                "artifact": {"path": rel, "sha256": packed.sha256_hex, "size": packed.size},
                "wiring": [{
                    "file": "yarn.lock",
                    "kind": "yarn_lock_block",
                    "action": "rewritten",
                    "key": "left-pad@^1.3.0",
                    "original": ["left-pad@^1.3.0:"],
                    "new": ["left-pad@^1.3.0:", "  version \"1.3.0\""],
                }],
                "flavor": "yarn-classic",
            })
        );

        // package-lock keeps the pre-flavor spelling; vlt's dir artifact
        // carries its inventory and no file hash.
        assert_eq!(
            VendorEntry::npm(
                String::new(),
                String::new(),
                built.artifact.clone(),
                vec![],
                None
            )
            .flavor,
            None
        );
        let inventory = BTreeMap::from([("index.js".to_string(), "ab".repeat(32))]);
        let dir = VendorArtifact::dir("dir".to_string(), inventory.clone());
        assert_eq!(
            serde_json::to_value(&dir).unwrap(),
            serde_json::json!({"path": "dir", "fileInventory": inventory})
        );
    }
}
