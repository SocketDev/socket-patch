use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::utils::env_compat::is_debug_enabled;

use super::state::{load_state_shared, VendorEntry};
use super::verify::{
    checked_artifact_path, read_zip_bytes_to_map_strict, verify_member_map, MAX_HEALTH_HASH_BYTES,
};

/// A committed artifact that passed every reuse check.
#[derive(Debug)]
pub(crate) struct CommittedArtifact {
    /// Normalized (forward-slashed) ledger `artifact.path`.
    pub rel_path: String,
    /// The EXACT bytes that were hashed and verified (read once).
    pub bytes: Vec<u8>,
    /// Members decoded from `bytes` (tarball keys `package/`-stripped, the
    /// `normalize_file_path` key space; wheel keys as stored).
    pub members: HashMap<String, Vec<u8>>,
    /// The anchoring ledger entry.
    pub entry: VendorEntry,
}

/// Why the committed artifact was not reused. Never surfaced to users (a
/// miss simply means "acquire as usual"); debug-logged only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReuseMiss {
    NoFiles,
    NoLedger,
    NoEntry,
    Ambiguous,
    PathUnsafe,
    UuidMismatch,
    Missing,
    NotRegular,
    TooLarge,
    Sha256Mismatch,
    SizeMismatch,
    Unreadable,
    NonCanonical,
    MemberMismatch(String),
    PlatformLocked,
}

/// Debug-log a reuse miss (`SOCKET_DEBUG`); the caller then acquires.
pub(crate) fn log_miss(purl: &str, miss: &ReuseMiss) {
    if is_debug_enabled() {
        eprintln!("[socket-patch debug] vendor reuse skipped for {purl}: {miss:?}");
    }
}

fn norm(path: &str) -> String {
    path.replace('\\', "/")
}

/// The ledger entry anchoring `record.uuid` for `ecosystem`: same ecosystem
/// and uuid, a non-empty artifact sha256, and (when given) a normalized
/// artifact path equal to `expected_rel`. Qualified-purl twins may each
/// carry an entry for the same uuid; they must all agree on (path, sha256)
/// or the answer is [`ReuseMiss::Ambiguous`]. An unreadable ledger is
/// [`ReuseMiss::NoLedger`] (reuse is skipped; acquisition runs as before).
///
/// The ledger comes from [`load_state_shared`]: the run asks it once per
/// npm/pypi package, and on a big monorepo the ledger runs to megabytes,
/// so re-parsing (or, inside a group commit, deep-cloning) it per package
/// would dominate the vendored re-run. The shared read still reads
/// the bytes every time and re-parses whenever they changed, answers from
/// the group commit's captured ledger when there is one, and fails exactly
/// where [`super::state::load_state`] fails. Only the one matching entry is
/// cloned.
pub(crate) async fn prior_entry(
    project_root: &Path,
    ecosystem: &str,
    record: &PatchRecord,
    expected_rel: Option<&str>,
) -> Result<VendorEntry, ReuseMiss> {
    let state = load_state_shared(project_root)
        .await
        .map_err(|_| ReuseMiss::NoLedger)?;
    select_prior_entry(state.entries.values(), ecosystem, record, expected_rel).cloned()
}

/// [`prior_entry`]'s choice over the ledger's entries, in the ledger map's
/// iteration order: the LAST match is the answer, the rest must agree with
/// it on (path, sha256).
fn select_prior_entry<'a>(
    entries: impl Iterator<Item = &'a VendorEntry>,
    ecosystem: &str,
    record: &PatchRecord,
    expected_rel: Option<&str>,
) -> Result<&'a VendorEntry, ReuseMiss> {
    let expected = expected_rel.map(norm);
    let mut hits: Vec<&VendorEntry> = entries
        .filter(|e| {
            e.ecosystem == ecosystem
                && e.uuid == record.uuid
                && !e.artifact.sha256.is_empty()
                && expected
                    .as_deref()
                    .is_none_or(|want| norm(&e.artifact.path) == want)
        })
        .collect();
    let Some(first) = hits.pop() else {
        return Err(ReuseMiss::NoEntry);
    };
    let agree = hits.iter().all(|e| {
        norm(&e.artifact.path) == norm(&first.artifact.path)
            && e.artifact
                .sha256
                .eq_ignore_ascii_case(&first.artifact.sha256)
    });
    if !agree {
        return Err(ReuseMiss::Ambiguous);
    }
    Ok(first)
}

/// The reloading form of [`prior_entry`], kept as the equivalence oracle: a full
/// [`super::state::load_state`] per call, entries taken by value.
#[cfg(test)]
pub(crate) async fn prior_entry_reloading(
    project_root: &Path,
    ecosystem: &str,
    record: &PatchRecord,
    expected_rel: Option<&str>,
) -> Result<VendorEntry, ReuseMiss> {
    let state = super::state::load_state(project_root)
        .await
        .map_err(|_| ReuseMiss::NoLedger)?;
    let expected = expected_rel.map(norm);
    let mut hits: Vec<VendorEntry> = state
        .entries
        .into_values()
        .filter(|e| {
            e.ecosystem == ecosystem
                && e.uuid == record.uuid
                && !e.artifact.sha256.is_empty()
                && expected
                    .as_deref()
                    .is_none_or(|want| norm(&e.artifact.path) == want)
        })
        .collect();
    let Some(first) = hits.pop() else {
        return Err(ReuseMiss::NoEntry);
    };
    let agree = hits.iter().all(|e| {
        norm(&e.artifact.path) == norm(&first.artifact.path)
            && e.artifact
                .sha256
                .eq_ignore_ascii_case(&first.artifact.sha256)
    });
    if !agree {
        return Err(ReuseMiss::Ambiguous);
    }
    Ok(first)
}

/// Verify the committed artifact `entry` names against the ledger anchor and
/// `record`'s afterHashes (see the module docs for the ordered checks).
/// Read-only; never touches the network.
pub(crate) async fn verify_committed_artifact(
    project_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> Result<CommittedArtifact, ReuseMiss> {
    use tokio::io::AsyncReadExt as _;

    if record.files.is_empty() {
        return Err(ReuseMiss::NoFiles);
    }
    let abs = checked_artifact_path(project_root, entry, record).map_err(|tag| {
        if tag == "vendor_uuid_mismatch" {
            ReuseMiss::UuidMismatch
        } else {
            ReuseMiss::PathUnsafe
        }
    })?;
    let rel_path = norm(&entry.artifact.path);

    // No link anywhere below the project root: a symlinked uuid dir (or
    // artifact) would let bytes from outside the vendored tree be "reused"
    // and then pinned into the lock. `checked_artifact_path` already
    // rejected `..`/empty segments, so each prefix is a real path level.
    let mut prefix = project_root.to_path_buf();
    for seg in rel_path.split('/') {
        prefix.push(seg);
        match tokio::fs::symlink_metadata(&prefix).await {
            Ok(meta) if meta.file_type().is_symlink() => return Err(ReuseMiss::NotRegular),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReuseMiss::Missing),
            Err(_) => return Err(ReuseMiss::Unreadable),
        }
    }

    // One FIFO-safe open (O_NONBLOCK + fstat on the handle): the size gate
    // and every byte below come from the same inode.
    let (file, meta) = match crate::utils::fs::open_regular_file(&abs).await {
        Ok(pair) => pair,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReuseMiss::Missing),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(ReuseMiss::NotRegular)
        }
        Err(_) => return Err(ReuseMiss::Unreadable),
    };
    if meta.len() > MAX_HEALTH_HASH_BYTES {
        return Err(ReuseMiss::TooLarge);
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    // +1: a file that grew past the cap after the fstat reads one byte over
    // and is rejected rather than truncated.
    file.take(MAX_HEALTH_HASH_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ReuseMiss::Unreadable)?;
    if bytes.len() as u64 > MAX_HEALTH_HASH_BYTES {
        return Err(ReuseMiss::TooLarge);
    }

    // The ledger anchor.
    let sha = crate::utils::digest::sha256_hex_of(&bytes);
    if !sha.eq_ignore_ascii_case(&entry.artifact.sha256) {
        return Err(ReuseMiss::Sha256Mismatch);
    }
    if entry
        .artifact
        .size
        .is_some_and(|size| size != bytes.len() as u64)
    {
        return Err(ReuseMiss::SizeMismatch);
    }

    // Members from the SAME buffer.
    let is_tarball = rel_path.ends_with(".tgz") || rel_path.ends_with(".tar.gz");
    let is_wheel = rel_path.ends_with(".whl") || rel_path.ends_with(".zip");
    if !is_tarball && !is_wheel {
        return Err(ReuseMiss::Unreadable);
    }
    let python_name = (entry.ecosystem == "pypi").then(|| rel_path.clone());
    let (bytes, members) = tokio::task::spawn_blocking(move || {
        let members = if let Some(name) = &python_name {
            super::pypi_distribution::read_members(&bytes, name).map_err(|error| {
                if error == "vendor_artifact_non_canonical" {
                    ReuseMiss::NonCanonical
                } else {
                    ReuseMiss::Unreadable
                }
            })
        } else if is_tarball {
            crate::patch::package::read_archive_bytes_to_map_strict(&bytes).map_err(|e| match e {
                crate::patch::package::ArchiveError::NonCanonical(_) => ReuseMiss::NonCanonical,
                _ => ReuseMiss::Unreadable,
            })
        } else {
            read_zip_bytes_to_map_strict(&bytes).map_err(|e| {
                if e == "vendor_artifact_non_canonical" {
                    ReuseMiss::NonCanonical
                } else {
                    ReuseMiss::Unreadable
                }
            })
        };
        (bytes, members)
    })
    .await
    .map_err(|_| ReuseMiss::Unreadable)?;
    let members = members?;
    if entry.ecosystem == "pypi" {
        super::pypi_distribution::verify_members(&members, &rel_path, record)
    } else {
        verify_member_map(&members, record)
    }
    .map_err(ReuseMiss::MemberMismatch)?;

    Ok(CommittedArtifact {
        rel_path,
        bytes,
        members,
        entry: entry.clone(),
    })
}

/// [`prior_entry`] followed by [`verify_committed_artifact`].
pub(crate) async fn reusable_committed_artifact(
    project_root: &Path,
    ecosystem: &str,
    record: &PatchRecord,
    expected_rel: Option<&str>,
) -> Result<CommittedArtifact, ReuseMiss> {
    let entry = prior_entry(project_root, ecosystem, record, expected_rel).await?;
    verify_committed_artifact(project_root, &entry, record).await
}

/// The committed vlt package dir at `rel_dir`, when
/// the ledger records it for `record.uuid` with an inventory and the tree
/// still verifies (no link on the path, the structure rule, only links and
/// `.bin/` scripts under its `node_modules/`, every member and the whole
/// inventory). Returns the recorded inventory. Read-only.
pub(crate) async fn reusable_committed_dir(
    project_root: &Path,
    record: &PatchRecord,
    rel_dir: &str,
) -> Result<std::collections::BTreeMap<String, String>, ReuseMiss> {
    if record.files.is_empty() {
        return Err(ReuseMiss::NoFiles);
    }
    let state = load_state_shared(project_root)
        .await
        .map_err(|_| ReuseMiss::NoLedger)?;
    let mut hits: Vec<VendorEntry> = state
        .entries
        .values()
        .filter(|e| {
            e.ecosystem == "npm"
                && e.uuid == record.uuid
                && e.flavor.as_deref() == Some(super::vlt_lock::FLAVOR)
                && norm(&e.artifact.path) == rel_dir
                && e.artifact.file_inventory.is_some()
        })
        .cloned()
        .collect();
    let Some(entry) = hits.pop() else {
        return Err(ReuseMiss::NoEntry);
    };
    if hits
        .iter()
        .any(|e| e.artifact.file_inventory != entry.artifact.file_inventory)
    {
        return Err(ReuseMiss::Ambiguous);
    }
    let mut prefix = project_root.to_path_buf();
    for seg in rel_dir.split('/') {
        prefix.push(seg);
        match tokio::fs::symlink_metadata(&prefix).await {
            Ok(meta) if meta.file_type().is_symlink() => return Err(ReuseMiss::NotRegular),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReuseMiss::Missing),
            Err(_) => return Err(ReuseMiss::Unreadable),
        }
    }
    super::verify::verify_vendored_patch_record(project_root, &entry, record)
        .await
        .map_err(ReuseMiss::MemberMismatch)?;
    Ok(entry.artifact.file_inventory.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::vendor::state::{save_state, VendorArtifact, VendorState};
    use sha2::{Digest, Sha256};
    use std::io::Write as _;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const OTHER_UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
    const PATCHED: &[u8] = b"module.exports = 'patched';\n";

    fn record(uuid: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: compute_git_sha256_from_bytes(PATCHED),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn good_tgz() -> Vec<u8> {
        tgz(&[
            ("package/index.js", PATCHED),
            ("package/package.json", b"{\"name\":\"left-pad\"}"),
        ])
    }

    fn rel_for(uuid: &str) -> String {
        format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz")
    }

    fn entry_for(uuid: &str, rel: &str, bytes: &[u8]) -> VendorEntry {
        VendorEntry {
            ecosystem: "npm".into(),
            base_purl: "pkg:npm/left-pad@1.3.0".into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                yarn_berry10c0: None,
                path: rel.into(),
                sha256: hex::encode(Sha256::digest(bytes)),
                size: Some(bytes.len() as u64),
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            flavor: Some("package-lock".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
            detached: false,
            record: None,
        }
    }

    /// A project with `bytes` committed at the UUID's tarball path and a
    /// ledger entry anchoring them.
    async fn project(bytes: &[u8]) -> (tempfile::TempDir, VendorEntry) {
        let tmp = tempfile::tempdir().unwrap();
        let rel = rel_for(UUID);
        let abs = tmp.path().join(&rel);
        tokio::fs::create_dir_all(abs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&abs, bytes).await.unwrap();
        let entry = entry_for(UUID, &rel, bytes);
        write_ledger(tmp.path(), &[("pkg:npm/left-pad@1.3.0", entry.clone())]).await;
        (tmp, entry)
    }

    async fn write_ledger(root: &Path, entries: &[(&str, VendorEntry)]) {
        let mut state = VendorState::new();
        for (k, e) in entries {
            state.entries.insert(k.to_string(), e.clone());
        }
        save_state(root, &state).await.unwrap();
    }

    async fn reuse(root: &Path, rec: &PatchRecord) -> Result<CommittedArtifact, ReuseMiss> {
        reusable_committed_artifact(root, "npm", rec, Some(&rel_for(&rec.uuid))).await
    }

    #[tokio::test]
    async fn verified_artifact_is_reused_with_its_exact_bytes() {
        let bytes = good_tgz();
        let (tmp, entry) = project(&bytes).await;
        let art = reuse(tmp.path(), &record(UUID)).await.unwrap();
        assert_eq!(art.bytes, bytes);
        assert_eq!(art.rel_path, rel_for(UUID));
        assert_eq!(art.entry, entry);
        assert_eq!(
            art.members.get("index.js").map(Vec::as_slice),
            Some(PATCHED)
        );
        assert!(art.members.contains_key("package.json"));
    }

    #[tokio::test]
    async fn empty_record_is_never_reused() {
        let (tmp, _) = project(&good_tgz()).await;
        let mut rec = record(UUID);
        rec.files.clear();
        assert_eq!(
            reuse(tmp.path(), &rec).await.unwrap_err(),
            ReuseMiss::NoFiles
        );
    }

    #[tokio::test]
    async fn unreadable_or_missing_ledger_misses() {
        let (tmp, _) = project(&good_tgz()).await;
        tokio::fs::write(tmp.path().join(".socket/vendor/state.json"), b"{not json")
            .await
            .unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::NoLedger
        );
        tokio::fs::remove_file(tmp.path().join(".socket/vendor/state.json"))
            .await
            .unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::NoEntry
        );
    }

    #[tokio::test]
    async fn entry_must_match_ecosystem_uuid_path_and_carry_a_sha() {
        let bytes = good_tgz();
        let (tmp, entry) = project(&bytes).await;
        // Wrong ecosystem.
        assert_eq!(
            reusable_committed_artifact(tmp.path(), "pypi", &record(UUID), None)
                .await
                .unwrap_err(),
            ReuseMiss::NoEntry
        );
        // Different expected path.
        assert_eq!(
            reusable_committed_artifact(
                tmp.path(),
                "npm",
                &record(UUID),
                Some(".socket/vendor/npm/x/other.tgz")
            )
            .await
            .unwrap_err(),
            ReuseMiss::NoEntry
        );
        // A new record uuid finds no entry (acquisition runs; the old dir is
        // never read).
        assert_eq!(
            reuse(tmp.path(), &record(OTHER_UUID)).await.unwrap_err(),
            ReuseMiss::NoEntry
        );
        // An entry without a sha anchors nothing.
        let mut no_sha = entry.clone();
        no_sha.artifact.sha256.clear();
        write_ledger(tmp.path(), &[("pkg:npm/left-pad@1.3.0", no_sha)]).await;
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::NoEntry
        );
    }

    #[tokio::test]
    async fn qualified_twins_must_agree() {
        let bytes = good_tgz();
        let (tmp, entry) = project(&bytes).await;
        // Agreeing twins (same path, sha in a different case): reused.
        let mut twin = entry.clone();
        twin.artifact.sha256 = twin.artifact.sha256.to_ascii_uppercase();
        write_ledger(
            tmp.path(),
            &[
                ("pkg:npm/left-pad@1.3.0", entry.clone()),
                ("pkg:npm/left-pad@1.3.0?artifact_id=x", twin),
            ],
        )
        .await;
        assert!(reuse(tmp.path(), &record(UUID)).await.is_ok());
        // Disagreeing twins: ambiguous.
        let mut twin = entry.clone();
        twin.artifact.sha256 = "0".repeat(64);
        write_ledger(
            tmp.path(),
            &[
                ("pkg:npm/left-pad@1.3.0", entry),
                ("pkg:npm/left-pad@1.3.0?artifact_id=x", twin),
            ],
        )
        .await;
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::Ambiguous
        );
    }

    #[tokio::test]
    async fn unsafe_and_uuid_mismatched_paths_miss() {
        let bytes = good_tgz();
        let (tmp, entry) = project(&bytes).await;
        let mut escaping = entry.clone();
        escaping.artifact.path = format!(".socket/vendor/npm/{UUID}/../../../../etc/x.tgz");
        assert_eq!(
            verify_committed_artifact(tmp.path(), &escaping, &record(UUID))
                .await
                .unwrap_err(),
            ReuseMiss::PathUnsafe
        );
        // The same verified bytes committed under ANOTHER uuid's directory
        // are never reused for this record.
        let other_rel = rel_for(OTHER_UUID);
        let abs = tmp.path().join(&other_rel);
        tokio::fs::create_dir_all(abs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&abs, &bytes).await.unwrap();
        let wrong_dir = entry_for(UUID, &other_rel, &bytes);
        assert_eq!(
            verify_committed_artifact(tmp.path(), &wrong_dir, &record(UUID))
                .await
                .unwrap_err(),
            ReuseMiss::UuidMismatch
        );
    }

    #[tokio::test]
    async fn missing_artifact_misses() {
        let (tmp, _) = project(&good_tgz()).await;
        tokio::fs::remove_file(tmp.path().join(rel_for(UUID)))
            .await
            .unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::Missing
        );
    }

    #[tokio::test]
    async fn regzipped_artifact_fails_the_ledger_anchor() {
        let bytes = good_tgz();
        let (tmp, _) = project(&bytes).await;
        let alt = super::super::test_support::regzip(&bytes);
        tokio::fs::write(tmp.path().join(rel_for(UUID)), &alt)
            .await
            .unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::Sha256Mismatch
        );
    }

    /// An UNPATCHED member edited and re-gzipped, with the ledger still
    /// recording the original sha: the anchor rejects it (the rebuild then
    /// heals it).
    #[tokio::test]
    async fn edited_unpatched_member_with_stale_ledger_sha_misses() {
        let (tmp, _) = project(&good_tgz()).await;
        let tampered = tgz(&[
            ("package/index.js", PATCHED),
            (
                "package/package.json",
                b"{\"name\":\"left-pad\",\"evil\":1}",
            ),
        ]);
        tokio::fs::write(tmp.path().join(rel_for(UUID)), &tampered)
            .await
            .unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::Sha256Mismatch
        );
    }

    #[tokio::test]
    async fn size_mismatch_misses() {
        let bytes = good_tgz();
        let (tmp, mut entry) = project(&bytes).await;
        entry.artifact.size = Some(bytes.len() as u64 + 1);
        assert_eq!(
            verify_committed_artifact(tmp.path(), &entry, &record(UUID))
                .await
                .unwrap_err(),
            ReuseMiss::SizeMismatch
        );
        // An absent size is not checked.
        entry.artifact.size = None;
        assert!(verify_committed_artifact(tmp.path(), &entry, &record(UUID))
            .await
            .is_ok());
    }

    /// A patched member edited AND the ledger sha forged to match: the
    /// afterHash check still rejects it.
    #[tokio::test]
    async fn forged_ledger_over_edited_patched_member_misses() {
        let forged = tgz(&[("package/index.js", b"module.exports = 'evil';\n")]);
        let (tmp, _) = project(&forged).await;
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::MemberMismatch("vendor_hash_mismatch".into())
        );
        let no_member = tgz(&[("package/other.js", PATCHED)]);
        let (tmp, _) = project(&no_member).await;
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::MemberMismatch("file_not_found".into())
        );
    }

    #[tokio::test]
    async fn undecodable_or_unknown_shape_misses() {
        let (tmp, _) = project(b"not a tarball").await;
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::Unreadable
        );
        // A dir-shaped / unknown extension is not this helper's business.
        let tmp = tempfile::tempdir().unwrap();
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.zip");
        let abs = tmp.path().join(&rel);
        tokio::fs::create_dir_all(abs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&abs, good_tgz()).await.unwrap();
        let entry = entry_for(UUID, &rel, &good_tgz());
        assert_eq!(
            verify_committed_artifact(tmp.path(), &entry, &record(UUID))
                .await
                .unwrap_err(),
            ReuseMiss::Unreadable
        );
    }

    #[tokio::test]
    async fn wheel_members_verify_from_the_same_buffer() {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file::<_, ()>("index.js", Default::default())
            .unwrap();
        zip.write_all(PATCHED).unwrap();
        let whl = zip.finish().unwrap().into_inner();
        let tmp = tempfile::tempdir().unwrap();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.0-py3-none-any.whl");
        let abs = tmp.path().join(&rel);
        tokio::fs::create_dir_all(abs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&abs, &whl).await.unwrap();
        let mut entry = entry_for(UUID, &rel, &whl);
        entry.ecosystem = "pypi".into();
        let art = verify_committed_artifact(tmp.path(), &entry, &record(UUID))
            .await
            .unwrap();
        assert_eq!(art.bytes, whl);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_artifact_or_uuid_dir_misses() {
        let bytes = good_tgz();
        // Symlinked artifact file.
        let (tmp, _) = project(&bytes).await;
        let abs = tmp.path().join(rel_for(UUID));
        let outside = tmp.path().join("outside.tgz");
        tokio::fs::write(&outside, &bytes).await.unwrap();
        tokio::fs::remove_file(&abs).await.unwrap();
        std::os::unix::fs::symlink(&outside, &abs).unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::NotRegular
        );

        // Symlinked uuid directory.
        let (tmp, _) = project(&bytes).await;
        let uuid_dir = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        let real = tmp.path().join("real-dir");
        tokio::fs::rename(&uuid_dir, &real).await.unwrap();
        std::os::unix::fs::symlink(&real, &uuid_dir).unwrap();
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::NotRegular
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_artifact_misses_promptly() {
        let (tmp, _) = project(&good_tgz()).await;
        let abs = tmp.path().join(rel_for(UUID));
        tokio::fs::remove_file(&abs).await.unwrap();
        let c = std::ffi::CString::new(abs.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reuse(tmp.path(), &record(UUID)),
        )
        .await
        .expect("a FIFO must never wedge the reuse probe");
        assert_eq!(res.unwrap_err(), ReuseMiss::NotRegular);
    }

    #[tokio::test]
    async fn oversized_artifact_misses_before_reading() {
        let (tmp, _) = project(&good_tgz()).await;
        let abs = tmp.path().join(rel_for(UUID));
        let f = std::fs::OpenOptions::new().write(true).open(&abs).unwrap();
        // Sparse: no real disk use.
        f.set_len(MAX_HEALTH_HASH_BYTES + 1).unwrap();
        drop(f);
        assert_eq!(
            reuse(tmp.path(), &record(UUID)).await.unwrap_err(),
            ReuseMiss::TooLarge
        );
    }

    // ── Canonical-archive gate: an archive whose decoded members differ
    //    from what an installer extracts is never reused, even with the
    //    ledger sha recomputed (a plain sha256 anyone committing
    //    state.json can forge).

    const EVIL: &[u8] = b"module.exports = 'UNPATCHED';\n";
    const PKG_JSON: &[u8] = b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}";

    fn tgz_typed(members: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, data, ty) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(*ty);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    async fn forged_reuse(bytes: &[u8]) -> Result<CommittedArtifact, ReuseMiss> {
        let (tmp, _) = project(bytes).await;
        reuse(tmp.path(), &record(UUID)).await
    }

    /// npm/pnpm/yarn/bun strip the FIRST segment whatever it is: a second
    /// top-level dir shadows the verified `package/index.js` at install.
    #[tokio::test]
    async fn second_top_level_dir_is_not_canonical() {
        use tar::EntryType::Regular;
        let bytes = tgz_typed(&[
            ("package/index.js", PATCHED, Regular),
            ("package/package.json", PKG_JSON, Regular),
            ("zzz/index.js", EVIL, Regular),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
    }

    /// node-tar extracts a type-'7' (contiguous) entry as a file; the
    /// lenient decoder skips it.
    #[tokio::test]
    async fn contiguous_twin_entry_is_not_canonical() {
        use tar::EntryType::{Continuous, Regular};
        let bytes = tgz_typed(&[
            ("package/index.js", PATCHED, Regular),
            ("package/package.json", PKG_JSON, Regular),
            ("package/index.js", EVIL, Continuous),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
        // A symlink / hardlink entry is refused the same way.
        let bytes = tgz_typed(&[
            ("package/index.js", PATCHED, Regular),
            ("package/evil.js", b"", tar::EntryType::Symlink),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
    }

    /// A case-insensitive filesystem keeps one of `index.js` / `INDEX.js`
    /// (the later write) — and an exact duplicate lets the LAST one win in
    /// both the decoder and the installer, but whichever wins is not ours
    /// to guess.
    #[tokio::test]
    async fn case_folded_or_exact_duplicate_is_not_canonical() {
        use tar::EntryType::Regular;
        let bytes = tgz_typed(&[
            ("package/index.js", PATCHED, Regular),
            ("package/INDEX.js", EVIL, Regular),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
        let bytes = tgz_typed(&[
            ("package/index.js", EVIL, Regular),
            ("package/index.js", PATCHED, Regular),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
        // `./` aliases collapse onto the same key.
        let bytes = tgz_typed(&[
            ("package/index.js", PATCHED, Regular),
            ("package/./Index.js", EVIL, Regular),
        ]);
        assert_eq!(
            forged_reuse(&bytes).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );
    }

    /// Honest shapes stay reusable: directory entries, a `package/` root
    /// dir entry, and a pax/GNU long-name member.
    #[tokio::test]
    async fn canonical_archive_with_dirs_and_long_names_is_reused() {
        let long = format!("package/{}/deep.js", "d".repeat(120));
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for dir in ["package/", "package/lib/"] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_size(0);
            h.set_mode(0o755);
            h.set_cksum();
            builder.append_data(&mut h, dir, std::io::empty()).unwrap();
        }
        for (name, data) in [
            ("package/index.js", PATCHED),
            ("package/lib/a.js", b"a" as &[u8]),
            (long.as_str(), b"deep"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append_data(&mut h, name, data).unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let art = forged_reuse(&bytes).await.unwrap();
        assert!(art.members.contains_key("lib/a.js"));
        assert!(art.members.keys().any(|k| k.ends_with("/deep.js")));
    }

    async fn wheel_reuse(whl: &[u8]) -> Result<CommittedArtifact, ReuseMiss> {
        let tmp = tempfile::tempdir().unwrap();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.0-py3-none-any.whl");
        let abs = tmp.path().join(&rel);
        tokio::fs::create_dir_all(abs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&abs, whl).await.unwrap();
        let mut entry = entry_for(UUID, &rel, whl);
        entry.ecosystem = "pypi".into();
        verify_committed_artifact(tmp.path(), &entry, &record(UUID)).await
    }

    fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in members {
            zip.start_file::<_, ()>(*name, Default::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    /// Wheel twin of the case-fold shape, plus an exact duplicate name
    /// (made by renaming a same-length sibling in place: the name is not
    /// covered by the CRC).
    #[tokio::test]
    async fn case_folded_or_exact_duplicate_wheel_member_is_not_reused() {
        let whl = zip_of(&[("index.js", PATCHED), ("INDEX.js", EVIL)]);
        assert_eq!(
            wheel_reuse(&whl).await.unwrap_err(),
            ReuseMiss::NonCanonical
        );

        let whl = zip_of(&[("index.js", PATCHED), ("indeX.js", EVIL)]);
        let mut dup = whl.clone();
        let (from, to) = (b"indeX.js", b"index.js");
        let mut i = 0;
        while i + from.len() <= dup.len() {
            if &dup[i..i + from.len()] == from {
                dup[i..i + from.len()].copy_from_slice(to);
            }
            i += 1;
        }
        assert!(
            wheel_reuse(&dup).await.is_err(),
            "an exact duplicate must never be reused"
        );
        // The canonical wheel is still reused.
        assert!(wheel_reuse(&zip_of(&[("index.js", PATCHED)])).await.is_ok());
    }

    /// The shared-ledger [`prior_entry`] answers exactly what the
    /// reloading oracle answers — hits, path filters, twins that agree or
    /// disagree, a missing or corrupt ledger — including after the ledger
    /// changes between two calls (the memo must miss) and inside a group
    /// commit that captured a newer ledger.
    #[tokio::test]
    async fn shared_prior_entry_matches_the_reloading_oracle() {
        use crate::utils::group_commit::GroupCommit;
        async fn both(root: &Path, rec: &PatchRecord, rel: Option<&str>) {
            for eco in ["npm", "pypi"] {
                assert_eq!(
                    prior_entry(root, eco, rec, rel).await,
                    prior_entry_reloading(root, eco, rec, rel).await,
                    "eco {eco}, rel {rel:?}"
                );
            }
        }
        let bytes = good_tgz();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = rel_for(UUID);
        let other_rel = rel_for(OTHER_UUID);
        let rec = record(UUID);
        let rels = [None, Some(rel.as_str()), Some(other_rel.as_str())];

        // Missing ledger.
        for r in rels {
            both(root, &rec, r).await;
        }
        // One entry.
        let entry = entry_for(UUID, &rel, &bytes);
        write_ledger(root, &[("pkg:npm/left-pad@1.3.0", entry.clone())]).await;
        for r in rels {
            both(root, &rec, r).await;
        }
        // Agreeing twins (a qualified twin, backslash-spelled path, upper
        // hex) — the answer is one of identical-anchor entries.
        let mut twin = entry.clone();
        twin.artifact.path = rel.replace('/', "\\");
        twin.artifact.sha256 = twin.artifact.sha256.to_ascii_uppercase();
        write_ledger(
            root,
            &[
                ("pkg:npm/left-pad@1.3.0", entry.clone()),
                ("pkg:npm/left-pad@1.3.0?x=1", twin),
            ],
        )
        .await;
        for r in rels {
            let (a, b) = (
                prior_entry(root, "npm", &rec, r).await,
                prior_entry_reloading(root, "npm", &rec, r).await,
            );
            assert_eq!(a.is_ok(), b.is_ok());
            match (a, b) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(norm(&a.artifact.path), norm(&b.artifact.path));
                    assert!(a.artifact.sha256.eq_ignore_ascii_case(&b.artifact.sha256));
                }
                (a, b) => assert_eq!(a.unwrap_err(), b.unwrap_err()),
            }
        }
        // Disagreeing twins, an empty-sha entry, another ecosystem.
        let mut bad = entry.clone();
        bad.artifact.sha256 = "0".repeat(64);
        let mut empty = entry.clone();
        empty.artifact.sha256.clear();
        let mut pypi = entry.clone();
        pypi.ecosystem = "pypi".into();
        write_ledger(
            root,
            &[
                ("pkg:npm/left-pad@1.3.0", entry.clone()),
                ("pkg:npm/left-pad@1.3.0?x=1", bad),
                ("pkg:npm/left-pad@1.3.0?x=2", empty),
                ("pkg:pypi/left-pad@1.3.0", pypi),
            ],
        )
        .await;
        for r in rels {
            both(root, &rec, r).await;
        }
        // Rewritten between two calls: the memo holds the old parse and
        // must not answer from it.
        write_ledger(root, &[("pkg:npm/left-pad@1.3.0", entry.clone())]).await;
        for r in rels {
            both(root, &rec, r).await;
        }
        // Inside a group commit, after a captured save of a different
        // ledger: both answer from the captured value.
        let group = GroupCommit::begin(root);
        let moved = entry_for(UUID, &other_rel, &bytes);
        write_ledger(root, &[("pkg:npm/left-pad@1.3.0", moved)]).await;
        for r in rels {
            both(root, &rec, r).await;
        }
        drop(group);
        // Corrupt ledger.
        tokio::fs::write(root.join(".socket/vendor/state.json"), b"{not json")
            .await
            .unwrap();
        for r in rels {
            both(root, &rec, r).await;
        }
    }
}
