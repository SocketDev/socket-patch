//! The retired pre-v5 hosted-mode ledger (`.socket/vendor/redirect-state.json`).
//!
//! socket-patch v5 derives hosted state from the lockfiles (see
//! `upstream::HostedPin` / `vex::discover`) and never writes this file. It
//! is read only for migration: `list` and `vex` may borrow a record's patch
//! details (vulnerabilities, file hashes) for a pin that is still wired in a
//! lockfile, and `rollback` / `remove` delete it once no hosted pin remains.
//! Its recorded edits are never replayed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::FileEdit;
use crate::manifest::schema::PatchRecord;
use crate::utils::fs::read_regular_to_bytes;

use crate::utils::socket_dir::write_json_ledger;

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
    /// line; likewise the hosted npm flow's `redirect_npmrc_allow_remote`
    /// for the project `.npmrc` `allow-remote=all`) must round-trip through
    /// ledgers written before they existed, so no field here may ever
    /// tighten into an enum.
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

/// A pre-v5 redirect ledger that exists on disk but cannot be loaded (torn
/// write, truncation, hand-editing gone wrong, or an unreadable file). Every
/// load distinguishes absent from malformed so read-only consumers can
/// surface it (as the `redirect_ledger_corrupt` warning) instead of silently
/// treating it as "no ledger".
#[derive(Debug)]
pub struct CorruptRedirectState {
    /// Absolute path of the malformed ledger.
    pub path: PathBuf,
    /// What went wrong reading/parsing it.
    pub detail: String,
    /// True when the ledger could not be READ (an I/O error, or a directory /
    /// FIFO squatting the path) rather than parsed. The bytes on disk may be
    /// perfectly valid pre-v5 data — or not a file at all — so the message
    /// asks for the I/O problem to be fixed, not for JSON repair.
    pub unreadable: bool,
}

impl std::fmt::Display for CorruptRedirectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.unreadable {
            return write!(
                f,
                "the pre-v5 redirect ledger {} cannot be read ({}); it was left \
                 in place. Fix the file's \
                 permissions (or move a stray directory or special file at that \
                 path aside), then re-run.",
                self.path.display(),
                self.detail
            );
        }
        write!(
            f,
            "the pre-v5 redirect ledger {} is malformed ({}); socket-patch v5 \
             only reads it for migration and never overwrites it. Repair its \
             JSON or restore it from version control, or delete it if you no \
             longer need its patch details.",
            self.path.display(),
            self.detail
        )
    }
}

impl std::error::Error for CorruptRedirectState {}

/// Load the redirect ledger. Missing → `Ok(None)` (a fresh start is fine).
/// Present but unreadable/malformed → [`CorruptRedirectState`]. Consumers
/// degrade a malformed ledger to "nothing to consult", but must surface it.
///
/// The bytes come from the (untrusted) project tree through the FIFO-safe
/// [`read_regular_to_bytes`] — non-blocking on Unix, rejecting FIFOs /
/// devices / directories — so a planted special file fails loudly instead of
/// wedging every flow that consults the ledger (scan, vex, list, vendor) on
/// an `open(2)` that waits forever for a writer.
pub async fn load_redirect_state(
    project_root: &Path,
) -> Result<Option<RedirectState>, CorruptRedirectState> {
    let path = project_root.join(REDIRECT_STATE_REL);
    let bytes = match read_regular_to_bytes(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CorruptRedirectState {
                path,
                detail: e.to_string(),
                unreadable: true,
            });
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(state) => Ok(Some(state)),
        Err(e) => Err(CorruptRedirectState {
            path,
            detail: format!("invalid JSON: {e}"),
            unreadable: false,
        }),
    }
}

/// Write a redirect ledger atomically. socket-patch v5 never writes this
/// file: this exists only so tests (and migration tooling) can lay down a
/// pre-v5 ledger fixture in the exact on-disk shape older releases wrote.
#[doc(hidden)]
pub async fn save_redirect_state(
    project_root: &Path,
    state: &RedirectState,
) -> std::io::Result<()> {
    write_json_ledger(&project_root.join(REDIRECT_STATE_REL), state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

    /// The sample record's patch uuid.
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
        // A torn/hand-mangled ledger must NOT load as "no ledger": callers
        // surface it rather than silently ignoring it.
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
            message.contains("pre-v5") && message.contains("never overwrites"),
            "error must say the file is a read-only pre-v5 leftover: {message}"
        );
        // The pure load never mutates the project.
        assert!(dir.join("redirect-state.json").exists());
        assert!(!dir.join("redirect-state.json.corrupt").exists());
    }

    /// mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    /// flakes under heavy parallel load (fork/exec starvation) and the
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
    /// writer that never comes, hanging every flow that consults the ledger
    /// (scan, vex, list, vendor) with no error and no timeout. Same class as
    /// the `open_regular_file` guards in the npm/composer/python/ruby
    /// crawlers and package_json discovery. The non-regular file is a loud
    /// fail-closed [`CorruptRedirectState`], never `Ok(None)`.
    #[cfg(unix)]
    #[tokio::test]
    async fn load_fifo_ledger_fails_fast_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let fifo = dir.join("redirect-state.json");
        mkfifo(&fifo);

        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(result) = tokio::time::timeout(deadline, load_redirect_state(tmp.path())).await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("load_redirect_state must complete promptly with a FIFO ledger");
        };
        let err = result.unwrap_err();
        assert_eq!(err.path, fifo, "the error must name the planted path");
        assert!(err.unreadable, "a non-regular file is an I/O problem");
        // The pure load never mutates the project — the FIFO stays put.
        assert!(fifo.exists());
    }

    /// An I/O failure (here: a directory squatting the ledger path) is
    /// classified as UNREADABLE, not malformed: the message names the I/O
    /// problem and does not tell the user to "repair its JSON".
    #[tokio::test]
    async fn load_unreadable_ledger_is_not_called_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let squatter = tmp.path().join(REDIRECT_STATE_REL);
        tokio::fs::create_dir_all(&squatter).await.unwrap();

        let err = load_redirect_state(tmp.path()).await.unwrap_err();
        assert!(err.unreadable);
        let message = err.to_string();
        assert!(
            message.contains("cannot be read") && message.contains("redirect-state.json"),
            "unreadable wording names the file and the I/O class: {message}"
        );
        assert!(
            !message.contains("malformed") && !message.contains("repair its JSON"),
            "an unreadable ledger must not be described as malformed: {message}"
        );
        assert!(squatter.is_dir(), "the squatting path is left in place");

        // Parse failures are classified as malformed.
        tokio::fs::remove_dir(&squatter).await.unwrap();
        tokio::fs::write(&squatter, b"{ torn").await.unwrap();
        let err = load_redirect_state(tmp.path()).await.unwrap_err();
        assert!(!err.unreadable);
        assert!(err.to_string().contains("malformed"));
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
        assert_eq!(
            text,
            format!("{}\n", serde_json::to_string_pretty(&state).unwrap()),
            "wire bytes: pretty JSON plus one trailing newline"
        );
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

    /// An idempotent hosted re-run re-saves the ledger it just loaded. A
    /// byte-identical ledger must not be re-staged and renamed over (mtime
    /// churn on a committed file, a needless fsync): with the parent made
    /// read-only the identical save still succeeds — nothing is written —
    /// while a changed ledger still has to write, and fails.
    #[cfg(unix)]
    #[tokio::test]
    async fn save_skips_a_byte_identical_ledger() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".to_string(), sample_record());
        save_redirect_state(tmp.path(), &state).await.unwrap();

        let dir = tmp.path().join(".socket/vendor");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::File::create(dir.join("probe")).is_ok() {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::remove_file(dir.join("probe"));
            eprintln!("skipping: running as root, 0555 does not block writes");
            return;
        }

        let identical = save_redirect_state(tmp.path(), &state).await;
        state
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), sample_record());
        let changed = save_redirect_state(tmp.path(), &state).await;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(identical.is_ok(), "identical bytes: no write attempted");
        assert_eq!(
            changed.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "changed bytes still go through the (here refused) atomic write"
        );
    }

}
