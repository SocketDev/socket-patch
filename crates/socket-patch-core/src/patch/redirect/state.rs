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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

    fn sample_record() -> PatchRecord {
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
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: vulns,
            description: "x".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
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
