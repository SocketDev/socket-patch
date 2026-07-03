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
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::FileEdit;
use crate::manifest::schema::PatchRecord;

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

/// Load the redirect ledger. Missing OR malformed → `None` (VEX then simply
/// has nothing extra to attest, and per-entry verification still fails closed
/// downstream) rather than aborting the command.
pub async fn load_redirect_state(project_root: &Path) -> Option<RedirectState> {
    let path = project_root.join(REDIRECT_STATE_REL);
    let bytes = tokio::fs::read(&path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
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
        assert!(load_redirect_state(tmp.path()).await.is_none());
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

        let loaded = load_redirect_state(tmp.path()).await.unwrap();
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
        let loaded = load_redirect_state(tmp.path()).await.unwrap();
        assert_eq!(loaded.mode, "redirect");
    }

    #[tokio::test]
    async fn load_malformed_ledger_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("redirect-state.json"), b"{ not json")
            .await
            .unwrap();
        assert!(load_redirect_state(tmp.path()).await.is_none());
    }
}
