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
//! The lock is generated-but-committed, so edits are text-preserving
//! (`toml_edit`): untouched entries, the `@generated` header comment, and the
//! `version = 4` line keep their exact bytes — zero formatting churn in the
//! committed diff.
//!
//! The removed `source`/`checksum` pair is not recoverable offline (the
//! checksum is the sha256 of the registry `.crate` tarball, not of the
//! extracted tree), so [`detach_lock_entry`] returns it for the vendor ledger
//! ([`super::state::CargoLockOriginal`]) and [`restore_lock_entry`] writes it
//! back on revert.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use toml_edit::{DocumentMut, Item, Table};

use crate::utils::fs::atomic_write_bytes;

/// The original lock fields removed by [`detach_lock_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntryOriginal {
    pub source: String,
    pub checksum: Option<String>,
}

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
            Self::Io(e) => write!(f, "Cargo.lock I/O error: {e}"),
            Self::Parse(e) => write!(f, "Cargo.lock parse error: {e}"),
        }
    }
}

/// Read + parse `<root>/Cargo.lock`, mapping errors to [`LockEditError`].
async fn read_lock(project_root: &Path) -> Result<(std::path::PathBuf, DocumentMut), LockEditError> {
    let path = project_root.join("Cargo.lock");
    let content = match tokio::fs::read_to_string(&path).await {
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

/// Find the index of the `[[package]]` table matching `name`+`version`.
fn find_package_index(doc: &DocumentMut, name: &str, version: &str) -> Option<usize> {
    let pkgs = doc.get("package")?.as_array_of_tables()?;
    pkgs.iter().position(|t| {
        t.get("name").and_then(Item::as_str) == Some(name)
            && t.get("version").and_then(Item::as_str) == Some(version)
    })
}

fn package_table_mut(doc: &mut DocumentMut, idx: usize) -> Result<&mut Table, LockEditError> {
    doc.get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|a| a.get_mut(idx))
        .ok_or(LockEditError::EntryMissing)
}

/// Commit the edited lock atomically (stage + fsync + rename). The lock is a
/// committed file shared with cargo itself; a torn write would corrupt the
/// whole project's resolution, so never truncate-in-place.
async fn write_lock(path: &Path, doc: &DocumentMut) -> Result<(), LockEditError> {
    atomic_write_bytes(path, doc.to_string().as_bytes())
        .await
        .map_err(|e| LockEditError::Io(e.to_string()))
}

/// Detach the `[[package]]` entry for `name`+`version` from the registry:
/// remove ONLY its `source` and `checksum` keys, returning the verbatim
/// originals for the vendor ledger. Everything else in the lock — including
/// the entry's own `name`/`version`/`dependencies` — keeps its exact bytes.
///
/// `dry_run` performs the full lookup (so refusals are accurate) but writes
/// nothing.
pub async fn detach_lock_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    dry_run: bool,
) -> Result<LockEntryOriginal, LockEditError> {
    let (path, mut doc) = read_lock(project_root).await?;
    let idx = find_package_index(&doc, name, version).ok_or(LockEditError::EntryMissing)?;
    let table = package_table_mut(&mut doc, idx)?;

    // A workspace/path/git dependency has no `source` — vendoring it would be
    // wrong (the user already controls those bytes); refuse.
    let source = match table.get("source").and_then(Item::as_str) {
        Some(s) => s.to_string(),
        None => return Err(LockEditError::NotRegistry),
    };
    let checksum = table
        .get("checksum")
        .and_then(Item::as_str)
        .map(str::to_string);

    table.remove("source");
    table.remove("checksum");

    if !dry_run {
        write_lock(&path, &doc).await?;
    }
    Ok(LockEntryOriginal { source, checksum })
}

/// Re-attach the original `source`/`checksum` to the `name`+`version` entry on
/// revert. Returns `Ok(false)` when the entry is no longer in the detached
/// form — it is absent (the dependency was dropped) or already carries a
/// `source` (cargo/the user re-resolved it) — in which case the lock is left
/// alone and the caller warns instead of clobbering a newer resolution.
pub async fn restore_lock_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    original: &LockEntryOriginal,
    dry_run: bool,
) -> Result<bool, LockEditError> {
    let (path, mut doc) = read_lock(project_root).await?;
    let Some(idx) = find_package_index(&doc, name, version) else {
        return Ok(false);
    };
    let table = package_table_mut(&mut doc, idx)?;
    if table.get("source").is_some() {
        return Ok(false);
    }

    table.insert("source", toml_edit::value(original.source.as_str()));
    if let Some(checksum) = &original.checksum {
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
/// versions. Reads only the project lockfile: no registry, no network.
pub async fn read_locked_versions(
    project_root: &Path,
) -> Option<HashMap<String, HashSet<String>>> {
    let content = tokio::fs::read_to_string(project_root.join("Cargo.lock"))
        .await
        .ok()?;
    let doc = content.parse::<DocumentMut>().ok()?;
    let pkgs = doc.get("package")?.as_array_of_tables()?;
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for t in pkgs.iter() {
        let name = t.get("name").and_then(Item::as_str);
        let ver = t.get("version").and_then(Item::as_str);
        if let (Some(n), Some(v)) = (name, ver) {
            map.entry(n.to_string()).or_default().insert(v.to_string());
        }
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const CHECKSUM: &str = "9d8f4e3bd2c8f1f5d1a3f5e7c9b1d3f5e7a9b1c3d5f7e9a1b3c5d7e9f1a3b5c7";

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

    #[tokio::test]
    async fn detach_removes_only_source_and_checksum() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
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
        // entry with its dependencies array, and cfg-if's name/version pair.
        assert!(body.starts_with("# This file is automatically @generated by Cargo.\n"));
        assert!(body.contains("version = 4\n"));
        assert!(body.contains("name = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if\",\n]\n"));
        assert!(body.contains("[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n"));
    }

    #[tokio::test]
    async fn detach_restore_round_trip_is_byte_identical() {
        let dir = fixture().await;
        let before = tokio::fs::read(dir.path().join("Cargo.lock")).await.unwrap();

        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        assert!(restore_lock_entry(dir.path(), "cfg-if", "1.0.4", &orig, false)
            .await
            .unwrap());

        let after = tokio::fs::read(dir.path().join("Cargo.lock")).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&before),
            String::from_utf8_lossy(&after),
            "restored lock must be byte-identical to the pristine fixture"
        );
    }

    #[tokio::test]
    async fn detach_missing_lock_is_no_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let err = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::NoLockfile);
    }

    #[tokio::test]
    async fn detach_missing_entry_and_wrong_version() {
        let dir = fixture().await;
        let err = detach_lock_entry(dir.path(), "nope", "1.0.4", false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::EntryMissing);
        // Version is part of the key — a different version must not match.
        let err = detach_lock_entry(dir.path(), "cfg-if", "9.9.9", false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::EntryMissing);
        // The refusals wrote nothing.
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock")).await.unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn detach_path_dep_is_not_registry() {
        let dir = fixture().await;
        // `app` is the workspace member: no `source` key.
        let err = detach_lock_entry(dir.path(), "app", "0.1.0", false)
            .await
            .unwrap_err();
        assert_eq!(err, LockEditError::NotRegistry);
    }

    #[tokio::test]
    async fn detach_dry_run_reports_but_does_not_write() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", true)
            .await
            .unwrap();
        assert_eq!(orig.source, SOURCE);
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock")).await.unwrap(),
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
        let err = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
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
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
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

        let restored = restore_lock_entry(dir.path(), "cfg-if", "1.0.4", &orig, false)
            .await
            .unwrap();
        assert!(restored, "detached entry must restore despite the extra table");

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
        let orig = LockEntryOriginal {
            source: SOURCE.to_string(),
            checksum: Some(CHECKSUM.to_string()),
        };
        // The entry still has its registry source (the user/cargo re-resolved
        // it after a hand-revert) — restoring would clobber it: Ok(false).
        assert!(!restore_lock_entry(dir.path(), "cfg-if", "1.0.4", &orig, false)
            .await
            .unwrap());
        // The entry is gone entirely (the dependency was dropped): Ok(false).
        assert!(!restore_lock_entry(dir.path(), "gone", "1.0.0", &orig, false)
            .await
            .unwrap());
        // Neither skip touched the file.
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock")).await.unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn restore_dry_run_does_not_write() {
        let dir = fixture().await;
        let orig = detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        let detached = tokio::fs::read_to_string(dir.path().join("Cargo.lock"))
            .await
            .unwrap();
        assert!(restore_lock_entry(dir.path(), "cfg-if", "1.0.4", &orig, true)
            .await
            .unwrap());
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("Cargo.lock")).await.unwrap(),
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
        let orig = detach_lock_entry(dir.path(), "x", "1.0.0", false).await.unwrap();
        assert_eq!(orig.checksum, None);
        assert!(restore_lock_entry(dir.path(), "x", "1.0.0", &orig, false)
            .await
            .unwrap());
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

    #[tokio::test]
    async fn edits_leave_no_stage_litter() {
        let dir = fixture().await;
        detach_lock_entry(dir.path(), "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        for e in std::fs::read_dir(dir.path()).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.contains("socket-stage"), "stage litter: {name}");
        }
    }
}
