//! The hosted-mode ledger (`.socket/vendor/redirect-state.json`), written by
//! `scan --mode hosted` (a.k.a. `scan --redirect`).
//!
//! Mirrors the vendor `state.json` shape but records a REMOTE per-dependency
//! redirect (no local artifact bytes). It carries the recorded [`FileEdit`]s
//! (for a future `--revert`) plus, per redirected PURL, the manifest
//! [`PatchRecord`] (file hashes + vulnerability metadata) so a post-install
//! `socket-patch vex` can attest the redirected patches against the installed
//! tree exactly as it does for `apply` / `vendor`. `augment_with_redirect`
//! folds `records` straight into a `PatchManifest` (keyed by PURL, the same
//! key the manifest and VEX use).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::FileEdit;
use crate::manifest::schema::PatchRecord;
use crate::utils::fs::atomic_write_bytes;

/// Repo-relative path of the redirect ledger.
pub const REDIRECT_STATE_REL: &str = ".socket/vendor/redirect-state.json";

/// On-disk schema for the redirect ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectState {
    pub version: u32,
    /// The mode that produced this ledger. Current writers emit `"hosted"`
    /// (the final mode name); the loader is tolerant of any string, so
    /// ledgers written before the rename (`"redirect"`) still load.
    pub mode: String,
    /// Recorded [`FileEdit`]s, appended in write order (a revert walks them
    /// in reverse). `kind` is an open vocabulary — additive kinds (e.g. the
    /// hosted pnpm flow's `redirect_pnpm_workspace_trust`, recording the
    /// auto-configured pnpm-workspace.yaml `trustLockfile: true` with
    /// `action` `"created"` for a new file or `"added"` for a spliced-in
    /// line) must round-trip through ledgers written before they existed,
    /// so no field here may ever tighten into an enum.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edits: Vec<FileEdit>,
    /// PURL -> manifest patch record. Present so VEX can attest redirected
    /// patches after install (file hashes) and reference the vulnerabilities
    /// they fix.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub records: BTreeMap<String, PatchRecord>,
}

impl RedirectState {
    pub fn new() -> Self {
        Self {
            version: 1,
            mode: "hosted".to_string(),
            edits: Vec::new(),
            records: BTreeMap::new(),
        }
    }
}

impl Default for RedirectState {
    fn default() -> Self {
        Self::new()
    }
}

/// A redirect ledger that exists on disk but cannot be loaded (torn write,
/// truncation, hand-editing gone wrong, or an unreadable file). The ledger is
/// the ONLY store of the pre-redirect lockfile originals a future revert
/// needs, so a loader that shrugged this off as "no ledger" would let the
/// next hosted run start fresh and silently overwrite that revert data.
/// Instead every load distinguishes absent (fine, fresh start) from malformed
/// (this error), and the hosted writer refuses to proceed.
#[derive(Debug)]
pub struct CorruptRedirectState {
    /// Absolute path of the malformed ledger.
    pub path: PathBuf,
    /// What went wrong reading/parsing it.
    pub detail: String,
    /// Where [`CorruptRedirectState::quarantine`] moved the file, when it did.
    pub quarantined_to: Option<PathBuf>,
}

impl CorruptRedirectState {
    /// Move the malformed ledger aside to `redirect-state.json.corrupt` so no
    /// later run can overwrite the revert data it may still hold. Never
    /// clobbers an existing `.corrupt` file (an earlier quarantine may hold
    /// older revert data); on any failure the original file simply stays put
    /// — the caller's hard error already prevents overwriting it.
    pub async fn quarantine(&mut self) {
        let target = match self.path.parent() {
            Some(parent) => parent.join("redirect-state.json.corrupt"),
            None => return,
        };
        if !matches!(tokio::fs::try_exists(&target).await, Ok(false)) {
            return;
        }
        if tokio::fs::rename(&self.path, &target).await.is_ok() {
            self.quarantined_to = Some(target);
        }
    }
}

impl std::fmt::Display for CorruptRedirectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the redirect ledger {} is malformed ({}); it records the \
             pre-redirect lockfile values a future revert needs, so it will \
             not be overwritten. ",
            self.path.display(),
            self.detail
        )?;
        match &self.quarantined_to {
            Some(target) => write!(
                f,
                "The unreadable file was moved aside to {}; to recover, repair \
                 its JSON and rename it back to redirect-state.json, or restore \
                 the ledger and the rewritten files from version control. If \
                 the revert data is expendable, delete the moved-aside file and \
                 re-run.",
                target.display()
            ),
            None => write!(
                f,
                "To recover, repair its JSON, restore it from version control, \
                 or move it aside if the revert data is expendable, then re-run."
            ),
        }
    }
}

impl std::error::Error for CorruptRedirectState {}

/// Load the redirect ledger. Missing → `Ok(None)` (a fresh start is fine).
/// Present but unreadable/malformed → [`CorruptRedirectState`], so no caller
/// can mistake a torn ledger for "no ledger" and overwrite the revert data it
/// still holds (see the type's docs). Read-only consumers may degrade a
/// malformed ledger to "nothing to consult", but must surface it; the hosted
/// writer must abort.
pub async fn load_redirect_state(
    project_root: &Path,
) -> Result<Option<RedirectState>, CorruptRedirectState> {
    let path = project_root.join(REDIRECT_STATE_REL);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CorruptRedirectState {
                path,
                detail: format!("unreadable: {e}"),
                quarantined_to: None,
            });
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(state) => Ok(Some(state)),
        Err(e) => Err(CorruptRedirectState {
            path,
            detail: format!("invalid JSON: {e}"),
            quarantined_to: None,
        }),
    }
}

/// Persist the redirect ledger atomically (stage + fsync + rename, the same
/// hardened writer the sibling vendor ledger uses). A bare `fs::write`
/// truncates the target first, so a crash or `ENOSPC` mid-write would tear
/// the only store of the pre-redirect originals a future revert needs.
pub async fn save_redirect_state(
    project_root: &Path,
    state: &RedirectState,
) -> std::io::Result<()> {
    let path = project_root.join(REDIRECT_STATE_REL);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let json = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    atomic_write_bytes(&path, format!("{json}\n").as_bytes()).await
}

/// `pkg:<type>/<name>@<version>` → `(<name>, <version>)`; the name keeps any
/// namespace slashes (`@scope/pkg`). `None` when either part is missing.
/// Input must already be canonicalized (qualifiers stripped, percent-decoded).
fn purl_name_version(purl: &str) -> Option<(&str, &str)> {
    let rest = purl.strip_prefix("pkg:")?;
    let (_, coord) = rest.split_once('/')?;
    let at = coord.rfind('@').filter(|&i| i > 0)?;
    Some((&coord[..at], &coord[at + 1..]))
}

/// Drop one PURL's superseded takeover leftovers from the ledger: its
/// `records` entry (canonical-purl match, qualifiers stripped and
/// percent-decoded) and every recorded edit keyed to that package. This is
/// the npm-family half of the hosted→vendored takeover reconciliation: the
/// vendored flows call it ONLY after the LIVE lockfile provably wires the
/// package to the committed `.socket/vendor/` artifact and no longer
/// resolves the hosted URL — at that point the vendor ledger's wiring
/// `original` embeds the hosted-spliced lock fragment, so `vendor --revert`
/// stays lossless without these ledger edits, and keeping them would feed
/// VEX/updates stale records and re-fire the takeover warning on every
/// later run. CARGO purls are refused (returns `false`, drops nothing): a
/// cargo takeover must revert the hosted edits ON DISK first — that path is
/// [`revert_cargo_redirect_purl`](super::revert_cargo_redirect_purl), which
/// does its own ledger drop.
///
/// The edit matcher is ARTIFACT-ANCHORED, never name-anchored. An edit is
/// claimed when either:
///
/// * its `new` content references THIS purl's hosted artifact — every hosted
///   artifact URL embeds the patch uuid (on ANY patch-server host; the same
///   invariant the takeover classifier's `hosted_wiring_live` proof rests
///   on), and a uuid is hex-and-dashes so it spells identically raw,
///   `\/`-escaped (old composer) and percent-encoded (yarn-berry
///   `::__archiveUrl=`). The uuid(s) come from this purl's own `records`
///   entry, captured before it is removed. This is what claims the
///   version-blind key shapes: npm `node_modules/…` path keys, legacy
///   `dependencies` bare-name keys, bun `<prefix>/<name>` keys.
/// * (secondary guard, for when the record — and with it the artifact URL —
///   is unavailable) its key is a VERSION-EXACT instance key:
///   `"name@version"`, pnpm v6 peer-suffixed `"name@version(peer…)"`, or the
///   pnpm-v5 respelling `"name@version_peer…"`.
///
/// The old matcher claimed by NAME alone (`key == name`, key ends with
/// `"/name"`): with two versions of one package hosted, vendoring one
/// deleted BOTH versions' path-keyed edits, destroying the other version's
/// revert originals. Name-only matching is gone; version-blind keys with no
/// artifact anchor are KEPT (fail-closed — they may be the other version's
/// only revert data). Consequence for the CLI's takeover-overlap fallback
/// matcher (which still matches edit keys by bare name, but ONLY when
/// `records` is empty — the degraded record-fetch-failed ledger): a normal
/// record-carrying ledger reconciles fully here (the record removal alone
/// ends the overlap), while a degraded ledger's unattributable path-keyed
/// edits stay and its takeover warning keeps advising the manual per-package
/// cleanup — the correct outcome when the ledger lacks the records needed to
/// attribute edits to a version safely.
///
/// Edits that are not package-keyed (e.g. the pnpm workspace-trust edit,
/// keyed `"trustLockfile"`) stay: they belong to the hosted flow's own
/// config surface and other still-redirected package(s) may ride on them.
///
/// Returns whether anything was removed. The caller persists the mutated
/// ledger via [`persist_redirect_state`] (atomic; an emptied ledger is
/// deleted).
pub fn drop_superseded_purl(state: &mut RedirectState, purl: &str) -> bool {
    use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let target = canon(purl);
    if target.starts_with("pkg:cargo/") {
        return false;
    }
    let Some((name, version)) = purl_name_version(&target) else {
        return false;
    };
    let (name, version) = (name.to_string(), version.to_string());

    let record_keys: Vec<String> = state
        .records
        .keys()
        .filter(|k| canon(k) == target)
        .cloned()
        .collect();
    // THIS purl's patch uuid(s), captured before the records are removed —
    // the artifact anchor (see the doc comment). Distinct purls (including
    // two versions of one package) carry distinct patch uuids, so a uuid
    // match is version-exact by construction.
    let uuids: Vec<String> = record_keys
        .iter()
        .filter_map(|k| state.records.get(k))
        .map(|r| r.uuid.clone())
        .collect();
    for key in &record_keys {
        state.records.remove(key);
    }

    let name_at_version = format!("{name}@{version}");
    let edits_before = state.edits.len();
    state.edits.retain(|e| {
        let Some(key) = e.key.as_deref() else {
            // No key ⇒ not attributable to any package; keep.
            return true;
        };
        // Version-exact instance keys: `name@version`, pnpm v6 peer-suffixed
        // `name@version(peer…)`, pnpm v5 respelled `name@version_peer…`.
        let version_exact = key == name_at_version
            || key
                .strip_prefix(name_at_version.as_str())
                .is_some_and(|rest| rest.starts_with('(') || rest.starts_with('_'));
        // Artifact anchor: the edit's rewritten (`new`) content references
        // this purl's hosted artifact (its patch uuid — spelling-invariant
        // across raw / `\/`-escaped / percent-encoded URL forms).
        let anchored = !uuids.is_empty()
            && e.new.as_ref().is_some_and(|new| {
                let text = new.to_string();
                uuids.iter().any(|uuid| text.contains(uuid.as_str()))
            });
        !(version_exact || anchored)
    });

    !record_keys.is_empty() || state.edits.len() != edits_before
}

/// Persist the redirect ledger via [`save_redirect_state`]'s atomic writer.
/// An EMPTY ledger (no edits, no records) is DELETED instead: a residual
/// empty file would keep takeover-overlap detection and VEX reading a ledger
/// that asserts nothing.
pub async fn persist_redirect_state(
    project_root: &Path,
    state: &RedirectState,
) -> std::io::Result<()> {
    if state.edits.is_empty() && state.records.is_empty() {
        let path = project_root.join(REDIRECT_STATE_REL);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        return Ok(());
    }
    save_redirect_state(project_root, state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

    /// The sample record's patch uuid — hosted artifact URLs embed it (the
    /// artifact anchor `drop_superseded_purl` claims edits by).
    const SAMPLE_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn sample_record() -> PatchRecord {
        record_with_uuid(SAMPLE_UUID)
    }

    fn record_with_uuid(uuid: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2024-1".to_string()],
                summary: "s".to_string(),
                severity: "high".to_string(),
                description: "d".to_string(),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: vulns,
            description: "x".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    /// The hosted artifact URL shape the patch server serves: the patch uuid
    /// is a path segment, exactly the anchor `drop_superseded_purl` matches.
    fn hosted_url(name: &str, version: &str, uuid: &str) -> String {
        format!("https://patch.test/patch/npm/{name}/{version}/{uuid}/{name}-{version}.tgz")
    }

    #[test]
    fn round_trips_records_through_json() {
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        let json = serde_json::to_string_pretty(&state).unwrap();
        let back: RedirectState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.mode, "hosted");
        let rec = back.records.get("pkg:npm/left-pad@1.3.0").unwrap();
        assert_eq!(rec.files["package/index.js"].after_hash, "b".repeat(64));
        assert!(rec.vulnerabilities.contains_key("GHSA-xxxx-yyyy-zzzz"));
    }

    /// The hosted pnpm flow's `redirect_pnpm_workspace_trust` edit (the
    /// auto-configured pnpm-workspace.yaml `trustLockfile: true`) is plain
    /// `FileEdit` vocabulary: it must round-trip byte-losslessly (camelCase
    /// contract keys, revert-relevant fields intact) alongside the classic
    /// lock edits — and, being additive, its ABSENCE must change nothing
    /// (the legacy-ledger tests below stay green without it).
    #[test]
    fn workspace_trust_edit_round_trips_as_plain_file_edit_vocabulary() {
        let mut state = RedirectState::new();
        state.edits.push(FileEdit {
            path: "pnpm-lock.yaml".to_string(),
            kind: "redirect_pnpm_resolution".to_string(),
            action: "rewritten".to_string(),
            key: Some("left-pad@1.3.0".to_string()),
            original: Some(serde_json::json!("{integrity: sha512-UPSTREAM==}")),
            new: Some(serde_json::json!(
                "{integrity: sha512-PATCHED==, tarball: http://patch.test/x.tgz}"
            )),
        });
        state.edits.push(FileEdit {
            path: "pnpm-workspace.yaml".to_string(),
            kind: "redirect_pnpm_workspace_trust".to_string(),
            action: "created".to_string(),
            key: Some("trustLockfile".to_string()),
            original: None,
            new: Some(serde_json::json!("true")),
        });
        let json = serde_json::to_string_pretty(&state).unwrap();
        let back: RedirectState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.edits, state.edits, "edits must round-trip losslessly");
        // Edit order is the revert contract (walked in reverse): the trust
        // edit stays AFTER the lock edit it accompanies.
        assert_eq!(back.edits[1].kind, "redirect_pnpm_workspace_trust");
        assert_eq!(back.edits[1].action, "created");
        assert_eq!(back.edits[1].key.as_deref(), Some("trustLockfile"));
        assert!(
            back.edits[1].original.is_none(),
            "a created file records no original"
        );
    }

    /// A ledger written by a FUTURE (or concurrent) writer carrying an edit
    /// kind/action this build has never heard of must still load — kind and
    /// action are opaque strings, exactly like `mode`. Guards against
    /// tightening the edit vocabulary into an enum, which would brick every
    /// existing ledger the moment a new kind ships.
    #[tokio::test]
    async fn load_tolerates_unknown_edit_kinds_and_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            br#"{
  "version": 1,
  "mode": "hosted",
  "edits": [
    {
      "path": "pnpm-workspace.yaml",
      "kind": "redirect_pnpm_workspace_trust",
      "action": "added",
      "key": "trustLockfile",
      "new": "true"
    },
    {
      "path": "some-future-file",
      "kind": "redirect_kind_from_the_future",
      "action": "transmogrified"
    }
  ]
}"#,
        )
        .await
        .unwrap();
        let loaded = load_redirect_state(tmp.path()).await.unwrap().unwrap();
        assert_eq!(loaded.edits.len(), 2);
        assert_eq!(loaded.edits[0].kind, "redirect_pnpm_workspace_trust");
        assert_eq!(loaded.edits[0].action, "added");
        assert_eq!(loaded.edits[0].original, None);
        assert_eq!(loaded.edits[1].kind, "redirect_kind_from_the_future");
    }

    fn edit(path: &str, kind: &str, key: Option<&str>) -> FileEdit {
        FileEdit {
            path: path.to_string(),
            kind: kind.to_string(),
            action: "rewritten".to_string(),
            key: key.map(str::to_string),
            original: Some(serde_json::json!("orig")),
            new: Some(serde_json::json!("new")),
        }
    }

    /// An edit whose rewritten content points at a hosted artifact URL — the
    /// shape the npm rewriter records (`new` = the spliced resolved/integrity
    /// pair), carrying the artifact anchor.
    fn edit_resolved(path: &str, kind: &str, key: &str, url: &str) -> FileEdit {
        FileEdit {
            path: path.to_string(),
            kind: kind.to_string(),
            action: "rewritten".to_string(),
            key: Some(key.to_string()),
            original: Some(serde_json::json!({
                "resolved": "https://registry.npmjs.org/upstream.tgz",
                "integrity": "sha512-UPSTREAM=="
            })),
            new: Some(serde_json::json!({ "resolved": url, "integrity": "sha512-P==" })),
        }
    }

    /// The takeover reconciliation drops exactly the superseded package's
    /// halves — its `records` entry and every edit keyed to it (pnpm
    /// `name@version`, pnpm v6 peer-suffixed and v5 `_`-suffixed instances,
    /// npm `node_modules/…` paths whose rewritten content carries this purl's
    /// hosted artifact) — while other packages' data and non-package-keyed
    /// edits (the pnpm workspace-trust edit) survive verbatim.
    #[test]
    fn drop_superseded_purl_removes_both_halves_and_only_them() {
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        state
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), sample_record());
        state.edits = vec![
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0"),
            ),
            // pnpm v6 peer-suffixed instance key for the SAME package.
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0(react@18.2.0)"),
            ),
            // pnpm v5 `_`-suffixed instance key (the rewriter's own respelled
            // `/left-pad/1.3.0_react@18.2.0` key) for the same package.
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0_react@18.2.0"),
            ),
            // npm nested node_modules path for the same package: the key is
            // version-blind, so the claim rides the artifact anchor in `new`.
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_entry",
                "node_modules/a/node_modules/left-pad",
                &hosted_url("left-pad", "1.3.0", SAMPLE_UUID),
            ),
            // Another package's edit — must survive.
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("minimist@1.2.2"),
            ),
            // Non-package-keyed workspace-trust edit — must survive.
            edit(
                "pnpm-workspace.yaml",
                "redirect_pnpm_workspace_trust",
                Some("trustLockfile"),
            ),
        ];

        assert!(drop_superseded_purl(&mut state, "pkg:npm/left-pad@1.3.0"));

        assert!(
            !state.records.contains_key("pkg:npm/left-pad@1.3.0"),
            "the superseded record must be dropped"
        );
        assert!(
            state.records.contains_key("pkg:npm/minimist@1.2.2"),
            "other packages' records must survive"
        );
        let keys: Vec<&str> = state
            .edits
            .iter()
            .filter_map(|e| e.key.as_deref())
            .collect();
        assert_eq!(
            keys,
            vec!["minimist@1.2.2", "trustLockfile"],
            "only the superseded package's edits may be dropped: {keys:?}"
        );

        // Idempotent: a second drop finds nothing and reports it.
        assert!(!drop_superseded_purl(&mut state, "pkg:npm/left-pad@1.3.0"));
    }

    /// TWO versions of one package hosted at once: dropping the vendored one
    /// must not touch the other version's halves. The npm path keys
    /// (`node_modules/…/left-pad`) and legacy `dependencies` bare-name keys
    /// carry NO version, so the old name-anchored matcher claimed BOTH
    /// versions' edits here — destroying left-pad@2.0.0's pre-redirect
    /// originals (its only revert data) when left-pad@1.3.0 was vendored.
    /// The matcher is artifact-anchored now: only edits whose rewritten
    /// content references the dropped purl's own hosted artifact go.
    #[test]
    fn drop_superseded_purl_never_claims_the_other_hosted_versions_edits() {
        const UUID_V2: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0f9e8d7c6b5a";
        let url_v1 = hosted_url("left-pad", "1.3.0", SAMPLE_UUID);
        let url_v2 = hosted_url("left-pad", "2.0.0", UUID_V2);
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        state.records.insert(
            "pkg:npm/left-pad@2.0.0".to_string(),
            record_with_uuid(UUID_V2),
        );
        state.edits = vec![
            // v1's edits: a version-blind path key (anchored via `new`) and
            // a version-exact pnpm key.
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_entry",
                "node_modules/left-pad",
                &url_v1,
            ),
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0"),
            ),
            // v2's edits: a nested path key, a legacy bare-name key, and a
            // version-exact pnpm key — ALL must survive dropping v1.
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_entry",
                "node_modules/a/node_modules/left-pad",
                &url_v2,
            ),
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_dep",
                "left-pad",
                &url_v2,
            ),
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@2.0.0"),
            ),
        ];

        assert!(drop_superseded_purl(&mut state, "pkg:npm/left-pad@1.3.0"));

        assert!(
            !state.records.contains_key("pkg:npm/left-pad@1.3.0"),
            "the vendored version's record must be dropped"
        );
        assert!(
            state.records.contains_key("pkg:npm/left-pad@2.0.0"),
            "the still-hosted version's record must survive"
        );
        let keys: Vec<&str> = state
            .edits
            .iter()
            .filter_map(|e| e.key.as_deref())
            .collect();
        assert_eq!(
            keys,
            vec![
                "node_modules/a/node_modules/left-pad",
                "left-pad",
                "left-pad@2.0.0"
            ],
            "the other hosted version's edits are its only revert data and \
             must survive verbatim: {keys:?}"
        );
    }

    /// A DEGRADED ledger (record fetch failed: `records` empty, edits only)
    /// offers no artifact anchor. The secondary guard must stay version-exact
    /// — `name@version` plus the `(`/`_` instance suffixes — and version-blind
    /// path/bare-name keys must be KEPT (they cannot be attributed to a
    /// version, and dropping them could destroy another version's revert
    /// originals). Fail closed: leftover keys mean the takeover warning's
    /// manual advisory keeps firing, which is the correct degraded outcome.
    #[test]
    fn drop_superseded_purl_without_a_record_claims_only_version_exact_keys() {
        let mut state = RedirectState::new();
        state.edits = vec![
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0"),
            ),
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0_react@18.2.0"),
            ),
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.0(react@18.2.0)"),
            ),
            // A LONGER version sharing the prefix: `1.3.0` must not claim
            // `1.3.01`'s instances (the `_`/`(` boundary is load-bearing).
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.01_react@18.2.0"),
            ),
            // Version-blind keys: unattributable without the anchor — keep.
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_entry",
                "node_modules/left-pad",
                "https://patch.test/no-uuid-here/left-pad-1.3.0.tgz",
            ),
            edit_resolved(
                "package-lock.json",
                "redirect_npm_lock_dep",
                "left-pad",
                "https://patch.test/no-uuid-here/left-pad-1.3.0.tgz",
            ),
        ];

        assert!(drop_superseded_purl(&mut state, "pkg:npm/left-pad@1.3.0"));

        let keys: Vec<&str> = state
            .edits
            .iter()
            .filter_map(|e| e.key.as_deref())
            .collect();
        assert_eq!(
            keys,
            vec![
                "left-pad@1.3.01_react@18.2.0",
                "node_modules/left-pad",
                "left-pad"
            ],
            "without an artifact anchor only version-exact instance keys may \
             be claimed: {keys:?}"
        );
    }

    /// A version-boundary key (`left-pad@1.3.10`) and a different package
    /// whose name merely ends with the target's (`not-left-pad`) must never
    /// be claimed — the `/`-boundary and `(`-boundary checks are load-bearing.
    #[test]
    fn drop_superseded_purl_respects_name_and_version_boundaries() {
        let mut state = RedirectState::new();
        state.edits = vec![
            edit(
                "pnpm-lock.yaml",
                "redirect_pnpm_resolution",
                Some("left-pad@1.3.10"),
            ),
            edit(
                "package-lock.json",
                "redirect_npm_lock_entry",
                Some("node_modules/not-left-pad"),
            ),
        ];
        assert!(!drop_superseded_purl(&mut state, "pkg:npm/left-pad@1.3.1"));
        assert_eq!(state.edits.len(), 2, "no foreign edit may be claimed");
    }

    /// Scoped names: the record key may carry the percent-encoded API form
    /// while the caller passes the canonical decoded purl; both halves must
    /// still be claimed (the path-keyed edit via the artifact anchor its
    /// rewritten content carries).
    #[test]
    fn drop_superseded_purl_matches_percent_encoded_scoped_records() {
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/%40scope%2Fpkg@1.0.0".to_string(), sample_record());
        state.edits = vec![edit_resolved(
            "package-lock.json",
            "redirect_npm_lock_entry",
            "node_modules/@scope/pkg",
            &hosted_url("%40scope%2Fpkg", "1.0.0", SAMPLE_UUID),
        )];
        assert!(drop_superseded_purl(&mut state, "pkg:npm/@scope/pkg@1.0.0"));
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// Cargo purls are refused: their takeover must revert the hosted edits
    /// ON DISK first (`revert_cargo_redirect_purl`), so a bare ledger drop
    /// would destroy the only revert data. Fail closed by dropping nothing.
    #[test]
    fn drop_superseded_purl_refuses_cargo() {
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:cargo/cfg-if@1.0.4".to_string(), sample_record());
        state.edits = vec![edit(
            "Cargo.lock",
            "redirect_cargo_lock_entry",
            Some("cfg-if@1.0.4"),
        )];
        assert!(!drop_superseded_purl(&mut state, "pkg:cargo/cfg-if@1.0.4"));
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.edits.len(), 1);
    }

    #[tokio::test]
    async fn load_missing_ledger_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_redirect_state(tmp.path()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn load_reads_written_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();

        let loaded = load_redirect_state(tmp.path()).await.unwrap().unwrap();
        assert!(loaded.records.contains_key("pkg:npm/left-pad@1.3.0"));
    }

    #[tokio::test]
    async fn load_legacy_redirect_mode_string_still_loads() {
        // Ledgers written before the mode-string rename carry
        // `"mode": "redirect"`. `mode` is an opaque string to the loader, so
        // these must still deserialize (a hosted re-run normalizes them to
        // "hosted"). Regression guard against tightening `mode` into an enum.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            br#"{ "version": 1, "mode": "redirect" }"#,
        )
        .await
        .unwrap();
        let loaded = load_redirect_state(tmp.path()).await.unwrap().unwrap();
        assert_eq!(loaded.mode, "redirect");
    }

    #[tokio::test]
    async fn load_malformed_ledger_is_a_hard_error_naming_the_file() {
        // A torn/hand-mangled ledger must NOT load as "no ledger": the old
        // tolerant `None` let the next hosted run start a fresh ledger and
        // silently overwrite the only copy of the pre-redirect revert data.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("redirect-state.json"), b"{ not json")
            .await
            .unwrap();
        let err = load_redirect_state(tmp.path()).await.unwrap_err();
        assert_eq!(err.path, dir.join("redirect-state.json"));
        let message = err.to_string();
        assert!(
            message.contains("redirect-state.json"),
            "error must name the file: {message}"
        );
        assert!(
            message.contains("revert"),
            "error must explain what is at stake: {message}"
        );
        // The pure load never mutates the project.
        assert!(dir.join("redirect-state.json").exists());
        assert!(!dir.join("redirect-state.json.corrupt").exists());
    }

    #[tokio::test]
    async fn quarantine_moves_the_malformed_ledger_aside_preserving_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("redirect-state.json"), b"{ torn ledger")
            .await
            .unwrap();
        let mut err = load_redirect_state(tmp.path()).await.unwrap_err();
        err.quarantine().await;
        assert_eq!(
            err.quarantined_to.as_deref(),
            Some(dir.join("redirect-state.json.corrupt").as_path())
        );
        assert!(
            err.to_string().contains("redirect-state.json.corrupt"),
            "error must point at the moved-aside file: {err}"
        );
        assert!(!dir.join("redirect-state.json").exists());
        assert_eq!(
            tokio::fs::read(dir.join("redirect-state.json.corrupt"))
                .await
                .unwrap(),
            b"{ torn ledger",
            "quarantine must preserve the corrupt bytes verbatim"
        );
    }

    #[tokio::test]
    async fn quarantine_never_clobbers_an_earlier_corrupt_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json.corrupt"),
            b"older revert data",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.join("redirect-state.json"), b"{ newer torn")
            .await
            .unwrap();
        let mut err = load_redirect_state(tmp.path()).await.unwrap_err();
        err.quarantine().await;
        assert!(err.quarantined_to.is_none());
        assert_eq!(
            tokio::fs::read(dir.join("redirect-state.json.corrupt"))
                .await
                .unwrap(),
            b"older revert data",
            "an earlier quarantine snapshot must never be overwritten"
        );
        assert!(
            dir.join("redirect-state.json").exists(),
            "with the quarantine slot taken the malformed file stays put"
        );
    }

    #[tokio::test]
    async fn save_writes_atomically_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        // Creates `.socket/vendor` itself.
        save_redirect_state(tmp.path(), &state).await.unwrap();

        let loaded = load_redirect_state(tmp.path()).await.unwrap().unwrap();
        assert!(loaded.records.contains_key("pkg:npm/left-pad@1.3.0"));
        let text = tokio::fs::read_to_string(tmp.path().join(REDIRECT_STATE_REL))
            .await
            .unwrap();
        assert!(text.ends_with('\n'), "ledger keeps its trailing newline");
        // The atomic writer must not leave its stage file behind.
        let mut entries = tokio::fs::read_dir(tmp.path().join(".socket/vendor"))
            .await
            .unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".socket-stage-"),
                "stage litter left behind: {name}"
            );
        }
    }
}
