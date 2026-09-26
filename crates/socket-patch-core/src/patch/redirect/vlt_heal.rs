//! Warm-tree heal for hosted vlt redirects (DESIGN D7).
//!
//! vlt never refreshes a store entry it already holds: after the lock is
//! repointed, `vlt install` keeps `node_modules/.vlt/<DepID>` and the
//! hidden lock as they are. A store entry whose bytes are not the ones the
//! lock now pins is invalidated (the entry plus `node_modules/.vlt-lock.json`)
//! so the next install extracts the pinned artifact. An entry whose state
//! cannot be determined is never removed, and nothing outside the project
//! root is ever touched.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{hosted_patch_uuid, vlt, RedirectState};
use crate::constants::npm_family::{VLT_HIDDEN_LOCK_REL, VLT_STORE_DIR};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{is_safe_relative_subpath, normalize_file_path};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::patch::package::read_archive_bytes_to_map_strict;
use crate::utils::purl::{canonical_purl, purl_parts};
use crate::vendor::vlt_lock_text::{
    is_default_registry, is_registry_package_name, parse_node_entry_text, sniff_lock, split_dep_id,
    DepIdKind, LockSniff,
};

/// The installed state a target should be in: patched after a redirect,
/// pristine after a rollback or remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    Patched,
    Pristine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Healthy,
    Stale,
    Undeterminable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteCheck {
    Match,
    Mismatch,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoreState {
    /// No `node_modules` or no `node_modules/.vlt`: nothing is installed.
    Absent,
    /// Both are real directories inside the canonical project root.
    Real,
    /// A link, a non-directory, or a store outside the root.
    Unsafe,
}

#[derive(Debug, Clone)]
enum HiddenLock {
    Absent,
    Unreadable,
    Parsed(Map<String, Value>),
}

/// The project's vlt install state, read once per heal.
#[derive(Debug, Clone)]
pub struct InstallState {
    store: StoreState,
    hidden: HiddenLock,
    hidden_present: bool,
}

/// One default-registry node of the lock that Socket hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedInstance {
    pub dep_id: String,
    pub name: String,
    pub version: String,
    pub patch_uuid: String,
    pub url: String,
    pub sha512: Option<String>,
}

/// A store entry to classify.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub dep_id: &'a str,
    pub name: &'a str,
    /// Slot [2] of the node in the final `vlt-lock.json` (`None` when the
    /// node is gone or the slot is null).
    pub lock_sha512: Option<&'a str>,
    pub record: Option<&'a PatchRecord>,
    /// The artifact bytes the preflight downloaded.
    pub artifact: Option<&'a [u8]>,
}

/// A ledger vlt node of one purl, for the rollback heal.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerTarget {
    pub purl: String,
    pub dep_id: String,
    pub name: String,
    pub record: Option<PatchRecord>,
}

/// What invalidation removed and what it could not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invalidation {
    pub removed: Vec<String>,
    pub failed: Vec<(String, String)>,
}

fn url_leaf(url: &str) -> &str {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/').next().unwrap_or(path)
}

/// Every default-registry node whose slot [3] is a Socket-hosted URL (on
/// patch.socket.dev or one of `origins`) whose leaf `<bare>-<version>.tgz`
/// agrees with the DepID. An unreadable lock has none.
pub fn socket_owned_instances(lock_text: &str, origins: &[String]) -> Vec<OwnedInstance> {
    let LockSniff::Readable(lock) = sniff_lock(lock_text) else {
        return Vec::new();
    };
    let options = lock.options();
    let Some(nodes) = lock.nodes() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, tuple) in nodes {
        let Some(dep_id) = split_dep_id(id) else {
            continue;
        };
        if dep_id.kind != DepIdKind::Registry || !is_default_registry(&dep_id.first, options) {
            continue;
        }
        let Some((name, version)) = dep_id.registry_identity() else {
            continue;
        };
        let Some(url) = tuple.get(3).and_then(Value::as_str) else {
            continue;
        };
        let Some(patch_uuid) = hosted_patch_uuid(url, origins) else {
            continue;
        };
        let bare = name.rsplit('/').next().unwrap_or(name);
        if url_leaf(url) != format!("{bare}-{version}.tgz") {
            continue;
        }
        out.push(OwnedInstance {
            dep_id: id.clone(),
            name: name.to_string(),
            version: version.to_string(),
            patch_uuid,
            url: url.to_string(),
            sha512: tuple.get(2).and_then(Value::as_str).map(str::to_string),
        });
    }
    out
}

/// Slot [2] of `dep_id`'s node in `lock_text`.
pub fn lock_sha512(lock_text: &str, dep_id: &str) -> Option<String> {
    let LockSniff::Readable(lock) = sniff_lock(lock_text) else {
        return None;
    };
    lock.nodes()?
        .get(dep_id)?
        .get(2)?
        .as_str()
        .map(str::to_string)
}

/// vlt's `isDepID` path-safety rule: the id is used as one path segment.
pub fn is_safe_dep_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !id.is_empty()
        && !drive
        && !id.contains(['/', '\\'])
        && !id.chars().any(char::is_control)
        && id
            .split(['~', '·'])
            .all(|field| field != "." && field != "..")
}

async fn store_state(root: &Path) -> StoreState {
    let node_modules = root.join("node_modules");
    let store = root.join(VLT_STORE_DIR);
    for dir in [&node_modules, &store] {
        match tokio::fs::symlink_metadata(dir).await {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return StoreState::Unsafe,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoreState::Absent,
            Err(_) => return StoreState::Unsafe,
        }
    }
    match (
        tokio::fs::canonicalize(root).await,
        tokio::fs::canonicalize(&store).await,
    ) {
        (Ok(root), Ok(store)) if store.starts_with(&root) => StoreState::Real,
        _ => StoreState::Unsafe,
    }
}

async fn hidden_lock(root: &Path) -> (HiddenLock, bool) {
    let path = root.join(VLT_HIDDEN_LOCK_REL);
    let meta = match tokio::fs::symlink_metadata(&path).await {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (HiddenLock::Absent, false),
        Err(_) => return (HiddenLock::Unreadable, true),
    };
    if !meta.file_type().is_file() {
        return (HiddenLock::Unreadable, true);
    }
    let parsed = crate::utils::fs::read_regular_to_string(&path)
        .await
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|json| json.get("nodes").and_then(Value::as_object).cloned());
    match parsed {
        Some(nodes) => (HiddenLock::Parsed(nodes), true),
        None => (HiddenLock::Unreadable, true),
    }
}

/// Read the store precondition and the hidden lock.
pub async fn read_install_state(root: &Path) -> InstallState {
    let store = store_state(root).await;
    let (hidden, hidden_present) = hidden_lock(root).await;
    InstallState {
        store,
        hidden,
        hidden_present,
    }
}

fn package_dir(root: &Path, dep_id: &str, name: &str) -> PathBuf {
    let mut dir = root.join(VLT_STORE_DIR).join(dep_id).join("node_modules");
    for part in name.split('/') {
        dir.push(part);
    }
    dir
}

async fn file_hash(path: &Path) -> Result<Option<String>, ()> {
    match compute_file_git_sha256(path).await {
        Ok(hash) => Ok(Some(hash)),
        Err(e) if crate::patch::apply::is_missing_path(&e) => Ok(None),
        Err(_) => Err(()),
    }
}

async fn record_check(dir: &Path, record: &PatchRecord, expected: Expected) -> ByteCheck {
    let mut unknown = false;
    for (file, info) in &record.files {
        let rel = normalize_file_path(file);
        if !is_safe_relative_subpath(rel) {
            return ByteCheck::Unknown;
        }
        let Ok(current) = file_hash(&dir.join(rel)).await else {
            unknown = true;
            continue;
        };
        let want = match expected {
            Expected::Patched => &info.after_hash,
            Expected::Pristine => &info.before_hash,
        };
        let matches = match current.as_deref() {
            None => want.is_empty(),
            Some(hash) => hash == want.as_str(),
        };
        if !matches {
            return ByteCheck::Mismatch;
        }
    }
    if unknown {
        ByteCheck::Unknown
    } else {
        ByteCheck::Match
    }
}

/// The regular files under `dir` (its own `node_modules/` excluded) by
/// `/`-joined relative path; `Err(true)` when a link or special file is
/// present (never an extracted artifact), `Err(false)` when unreadable.
fn installed_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, bool> {
    let mut out = BTreeMap::new();
    let walk = walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !(e.depth() == 1 && e.file_name() == "node_modules"));
    for entry in walk {
        let entry = entry.map_err(|_| false)?;
        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(true);
        }
        let rel = entry.path().strip_prefix(dir).map_err(|_| false)?;
        let key = rel
            .components()
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or(false)?
            .join("/");
        out.insert(key, std::fs::read(entry.path()).map_err(|_| false)?);
    }
    Ok(out)
}

fn artifact_check(dir: &Path, artifact: &[u8]) -> ByteCheck {
    let Ok(expected) = read_archive_bytes_to_map_strict(artifact) else {
        return ByteCheck::Unknown;
    };
    let installed = match installed_files(dir) {
        Ok(files) => files,
        Err(true) => return ByteCheck::Mismatch,
        Err(false) => return ByteCheck::Unknown,
    };
    let expected: BTreeMap<String, Vec<u8>> = expected
        .into_iter()
        .filter(|(path, _)| path != "node_modules" && !path.starts_with("node_modules/"))
        .collect();
    if expected == installed {
        ByteCheck::Match
    } else {
        ByteCheck::Mismatch
    }
}

async fn bytes_check(dir: &Path, target: &Target<'_>, expected: Expected) -> ByteCheck {
    if let Some(record) = target.record.filter(|r| !r.files.is_empty()) {
        return record_check(dir, record, expected).await;
    }
    match (expected, target.artifact) {
        (Expected::Patched, Some(artifact)) => artifact_check(dir, artifact),
        _ => ByteCheck::Unknown,
    }
}

/// Is `target`'s store entry stale against `expected`, healthy, or
/// impossible to judge? See DESIGN §3.9 "Heal" for the rules.
pub async fn classify_target(
    state: &InstallState,
    root: &Path,
    target: &Target<'_>,
    expected: Expected,
) -> TargetState {
    match state.store {
        StoreState::Absent => return TargetState::Healthy,
        StoreState::Unsafe => return TargetState::Undeterminable,
        StoreState::Real => {}
    }
    if !is_safe_dep_id(target.dep_id) || !is_registry_package_name(target.name) {
        return TargetState::Undeterminable;
    }
    let dir = package_dir(root, target.dep_id, target.name);
    if !tokio::fs::metadata(&dir).await.is_ok_and(|m| m.is_dir()) {
        return TargetState::Healthy;
    }
    let bytes = bytes_check(&dir, target, expected).await;
    if let HiddenLock::Parsed(nodes) = &state.hidden {
        match nodes.get(target.dep_id) {
            None => return TargetState::Stale,
            Some(node) => {
                if node.get(2).and_then(Value::as_str) != target.lock_sha512 {
                    return TargetState::Stale;
                }
            }
        }
    }
    if bytes == ByteCheck::Mismatch {
        return TargetState::Stale;
    }
    if !matches!(state.hidden, HiddenLock::Parsed(_)) && bytes == ByteCheck::Unknown {
        return TargetState::Undeterminable;
    }
    TargetState::Healthy
}

async fn remove_entry(path: &Path) -> std::io::Result<()> {
    let meta = tokio::fs::symlink_metadata(path).await?;
    if meta.file_type().is_symlink() {
        crate::utils::fs::remove_link(path).await
    } else if meta.file_type().is_dir() {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_file(path).await
    }
}

/// Remove the hidden lock and each stale store entry. Callers pass only
/// ids [`classify_target`] judged stale, which requires a real store dir.
/// A hidden lock that cannot be removed keeps every store entry: vlt would
/// trust it and leave the importer links dangling.
pub async fn invalidate(root: &Path, state: &InstallState, stale: &[String]) -> Invalidation {
    let mut out = Invalidation::default();
    if stale.is_empty() || state.store != StoreState::Real {
        return out;
    }
    let unique: BTreeSet<&String> = stale.iter().collect();
    if state.hidden_present {
        if let Err(e) = remove_entry(&root.join(VLT_HIDDEN_LOCK_REL)).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                let why = e.to_string();
                out.failed
                    .push((VLT_HIDDEN_LOCK_REL.to_string(), why.clone()));
                out.failed.extend(
                    unique
                        .into_iter()
                        .map(|id| (id.clone(), format!("kept: {VLT_HIDDEN_LOCK_REL}: {why}"))),
                );
                return out;
            }
        }
    }
    for id in unique {
        if !is_safe_dep_id(id) {
            continue;
        }
        match remove_entry(&root.join(VLT_STORE_DIR).join(id)).await {
            Ok(()) => out.removed.push(id.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => out.removed.push(id.clone()),
            Err(e) => out.failed.push((id.clone(), e.to_string())),
        }
    }
    out
}

/// The vlt nodes the ledger's `redirect_vlt_lock_node` edits name for each
/// of `purls`, with the purl's patch record.
pub fn ledger_targets(state: &RedirectState, purls: &[String]) -> Vec<LedgerTarget> {
    let mut out: Vec<LedgerTarget> = Vec::new();
    for purl in purls {
        let Some((ecosystem, name, version)) = purl_parts(purl) else {
            continue;
        };
        if ecosystem != "npm" {
            continue;
        }
        let canon = canonical_purl(purl);
        let record = state
            .records
            .iter()
            .find(|(key, _)| canonical_purl(key) == canon)
            .map(|(_, record)| record.clone());
        for edit in &state.edits {
            if edit.kind != vlt::KIND
                || !edit
                    .key
                    .as_deref()
                    .is_some_and(|key| vlt::claims_key(key, &name, &version))
            {
                continue;
            }
            let Some(entry) = edit
                .original
                .as_ref()
                .and_then(Value::as_str)
                .and_then(parse_node_entry_text)
            else {
                continue;
            };
            if out.iter().any(|t| t.dep_id == entry.key && t.purl == *purl) {
                continue;
            }
            out.push(LedgerTarget {
                purl: purl.clone(),
                dep_id: entry.key.to_string(),
                name: name.clone(),
                record: record.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::redirect::FileEdit;
    use std::collections::HashMap;

    const ID: &str = "~npm~left-pad@1.3.0";
    const PRISTINE: &[u8] = b"module.exports = 'pristine'\n";
    const PATCHED: &[u8] = b"module.exports = 'patched'\n";
    const LOCK_SHA: &str = "sha512-PATCHED";

    fn record() -> PatchRecord {
        PatchRecord {
            uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            exported_at: String::new(),
            files: HashMap::from([(
                "package/index.js".to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(PRISTINE),
                    after_hash: compute_git_sha256_from_bytes(PATCHED),
                },
            )]),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn store(root: &Path, id: &str, index: &[u8]) -> PathBuf {
        let dir = package_dir(root, id, "left-pad");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), index).unwrap();
        std::fs::write(dir.join("package.json"), b"{\"name\":\"left-pad\"}").unwrap();
        dir
    }

    fn hidden(root: &Path, slot2: Option<&str>) {
        let nodes = match slot2 {
            Some(sha) => serde_json::json!({ ID: [0, "left-pad", sha, null] }),
            None => serde_json::json!({}),
        };
        std::fs::write(
            root.join(VLT_HIDDEN_LOCK_REL),
            serde_json::to_vec(&serde_json::json!({ "nodes": nodes })).unwrap(),
        )
        .unwrap();
    }

    fn target<'a>(record: Option<&'a PatchRecord>, artifact: Option<&'a [u8]>) -> Target<'a> {
        Target {
            dep_id: ID,
            name: "left-pad",
            lock_sha512: Some(LOCK_SHA),
            record,
            artifact,
        }
    }

    async fn classify(root: &Path, target: &Target<'_>, expected: Expected) -> TargetState {
        let state = read_install_state(root).await;
        classify_target(&state, root, target, expected).await
    }

    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[tokio::test]
    async fn rule_a_hidden_lock_integrity_differs() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        hidden(tmp.path(), Some("sha512-UPSTREAM"));
        let rec = record();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Stale
        );
    }

    #[tokio::test]
    async fn rule_b_hidden_lock_without_the_node() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        hidden(tmp.path(), None);
        let rec = record();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Stale
        );
    }

    #[tokio::test]
    async fn rule_c_bytes_mismatch_whatever_the_hidden_lock_says() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PRISTINE);
        hidden(tmp.path(), Some(LOCK_SHA));
        let rec = record();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Stale
        );
        std::fs::remove_file(tmp.path().join(VLT_HIDDEN_LOCK_REL)).unwrap();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Stale
        );
    }

    #[tokio::test]
    async fn healthy_patched_and_pristine_trees() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        hidden(tmp.path(), Some(LOCK_SHA));
        let rec = record();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Healthy
        );
        std::fs::remove_file(tmp.path().join(VLT_HIDDEN_LOCK_REL)).unwrap();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Healthy,
            "a tree without a hidden lock is judged by its bytes"
        );
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Pristine).await,
            TargetState::Stale,
            "patched bytes are stale once the pin is restored"
        );
        store(tmp.path(), ID, PRISTINE);
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Pristine).await,
            TargetState::Healthy
        );
    }

    #[tokio::test]
    async fn undeterminable_without_hidden_lock_record_or_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        assert_eq!(
            classify(tmp.path(), &target(None, None), Expected::Patched).await,
            TargetState::Undeterminable
        );
        hidden(tmp.path(), Some(LOCK_SHA));
        assert_eq!(
            classify(tmp.path(), &target(None, None), Expected::Patched).await,
            TargetState::Healthy,
            "a parsed hidden lock that agrees decides alone"
        );
        std::fs::write(tmp.path().join(VLT_HIDDEN_LOCK_REL), b"{not json").unwrap();
        assert_eq!(
            classify(tmp.path(), &target(None, None), Expected::Pristine).await,
            TargetState::Undeterminable
        );
    }

    #[tokio::test]
    async fn no_record_compares_against_the_artifact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        let dir = package_dir(tmp.path(), ID, "left-pad");
        std::fs::create_dir_all(dir.join("node_modules/dep")).unwrap();
        std::fs::write(dir.join("node_modules/dep/x.js"), b"ignored").unwrap();
        let good = tarball(&[
            ("package/index.js", PATCHED),
            ("package/package.json", b"{\"name\":\"left-pad\"}"),
        ]);
        let bad = tarball(&[
            ("package/index.js", PRISTINE),
            ("package/package.json", b"{\"name\":\"left-pad\"}"),
        ]);
        assert_eq!(
            classify(tmp.path(), &target(None, Some(&good)), Expected::Patched).await,
            TargetState::Healthy
        );
        assert_eq!(
            classify(tmp.path(), &target(None, Some(&bad)), Expected::Patched).await,
            TargetState::Stale
        );
        std::fs::write(dir.join("extra.js"), b"x").unwrap();
        assert_eq!(
            classify(tmp.path(), &target(None, Some(&good)), Expected::Patched).await,
            TargetState::Stale,
            "an extra installed file is not the artifact"
        );
        assert_eq!(
            classify(
                tmp.path(),
                &target(None, Some(b"not a tarball")),
                Expected::Patched
            )
            .await,
            TargetState::Undeterminable
        );
    }

    #[tokio::test]
    async fn bundled_node_modules_in_the_artifact_are_not_compared() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        let dir = package_dir(tmp.path(), ID, "left-pad");
        std::fs::create_dir_all(dir.join("node_modules/x")).unwrap();
        std::fs::write(dir.join("node_modules/x/index.js"), b"bundled").unwrap();
        let bundling = tarball(&[
            ("package/index.js", PATCHED),
            ("package/package.json", b"{\"name\":\"left-pad\"}"),
            ("package/node_modules/x/index.js", b"bundled"),
        ]);
        assert_eq!(
            classify(
                tmp.path(),
                &target(None, Some(&bundling)),
                Expected::Patched
            )
            .await,
            TargetState::Healthy
        );
    }

    #[tokio::test]
    async fn an_uninstalled_target_is_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let rec = record();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Healthy
        );
        std::fs::create_dir_all(tmp.path().join(VLT_STORE_DIR)).unwrap();
        assert_eq!(
            classify(tmp.path(), &target(Some(&rec), None), Expected::Patched).await,
            TargetState::Healthy
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_node_modules_or_store_outside_the_root_is_undeterminable_and_kept() {
        for linked in ["node_modules", VLT_STORE_DIR] {
            let tmp = tempfile::tempdir().unwrap();
            let project = tmp.path().join("project");
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&project).unwrap();
            let real_root = outside.join("root");
            store(&real_root, ID, PRISTINE);
            if linked == "node_modules" {
                std::os::unix::fs::symlink(real_root.join("node_modules"), project.join(linked))
                    .unwrap();
            } else {
                std::fs::create_dir_all(project.join("node_modules")).unwrap();
                std::os::unix::fs::symlink(real_root.join(VLT_STORE_DIR), project.join(linked))
                    .unwrap();
            }
            hidden(&real_root, Some("sha512-UPSTREAM"));
            let rec = record();
            let state = read_install_state(&project).await;
            assert_eq!(
                classify_target(
                    &state,
                    &project,
                    &target(Some(&rec), None),
                    Expected::Patched
                )
                .await,
                TargetState::Undeterminable,
                "{linked}"
            );
            let out = invalidate(&project, &state, &[ID.to_string()]).await;
            assert!(out.removed.is_empty() && out.failed.is_empty(), "{out:?}");
            assert!(package_dir(&real_root, ID, "left-pad")
                .join("index.js")
                .exists());
        }
    }

    #[test]
    fn dep_ids_are_single_safe_segments() {
        for ok in [
            ID,
            "··left-pad@1.3.0",
            "~npm~@a+b@1.0.0~peer.2",
            "·npm·x@1.0.0",
        ] {
            assert!(is_safe_dep_id(ok), "{ok}");
        }
        for bad in [
            "",
            "..",
            ".",
            "~npm~../x@1",
            "~..~x@1.0.0",
            "a/b",
            "a\\b",
            "C:x",
            "~npm~x@1.0.0\n",
        ] {
            assert!(!is_safe_dep_id(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn invalidation_removes_the_hidden_lock_and_stale_entries_only() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PRISTINE);
        let other = "~npm~ms@2.1.3";
        let other_dir = package_dir(tmp.path(), other, "left-pad");
        std::fs::create_dir_all(&other_dir).unwrap();
        hidden(tmp.path(), Some("sha512-UPSTREAM"));
        let state = read_install_state(tmp.path()).await;
        let out = invalidate(tmp.path(), &state, &[ID.to_string(), "../escape".into()]).await;
        assert_eq!(out.removed, [ID.to_string()]);
        assert!(out.failed.is_empty());
        assert!(!tmp.path().join(VLT_HIDDEN_LOCK_REL).exists());
        assert!(!tmp.path().join(VLT_STORE_DIR).join(ID).exists());
        assert!(other_dir.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unremovable_hidden_lock_keeps_every_store_entry() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PRISTINE);
        hidden(tmp.path(), Some("sha512-UPSTREAM"));
        let state = read_install_state(tmp.path()).await;
        let node_modules = tmp.path().join("node_modules");
        std::fs::set_permissions(&node_modules, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = invalidate(tmp.path(), &state, &[ID.to_string()]).await;
        std::fs::set_permissions(&node_modules, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(out.removed.is_empty(), "{out:?}");
        let failed: Vec<&str> = out.failed.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(failed, [VLT_HIDDEN_LOCK_REL, ID]);
        assert!(tmp.path().join(VLT_HIDDEN_LOCK_REL).exists());
        assert!(package_dir(tmp.path(), ID, "left-pad")
            .join("index.js")
            .exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_store_entry_is_unlinked_not_traversed() {
        let tmp = tempfile::tempdir().unwrap();
        let target_root = tmp.path().join("elsewhere");
        store(&target_root, ID, PRISTINE);
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join(VLT_STORE_DIR)).unwrap();
        std::os::unix::fs::symlink(
            target_root.join(VLT_STORE_DIR).join(ID),
            root.join(VLT_STORE_DIR).join(ID),
        )
        .unwrap();
        let dep_link = root.join(VLT_STORE_DIR).join("~npm~ms@2.1.3");
        std::fs::create_dir_all(dep_link.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            target_root.join(VLT_STORE_DIR),
            dep_link.join("node_modules/linked"),
        )
        .unwrap();
        let state = read_install_state(&root).await;
        let out = invalidate(&root, &state, &[ID.to_string(), "~npm~ms@2.1.3".into()]).await;
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(!root.join(VLT_STORE_DIR).join(ID).exists());
        assert!(
            package_dir(&target_root, ID, "left-pad")
                .join("index.js")
                .exists(),
            "the link target survives"
        );
        assert!(!dep_link.exists());
        assert!(target_root.join(VLT_STORE_DIR).exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn store_entries_with_junction_and_dir_symlink_children_are_removed_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let sibling = "~npm~ms@2.1.3";
        let sibling_dir = package_dir(root, sibling, "ms");
        std::fs::create_dir_all(&sibling_dir).unwrap();
        std::fs::write(sibling_dir.join("index.js"), b"ms").unwrap();
        let entry = root.join(VLT_STORE_DIR).join(ID).join("node_modules");
        std::fs::create_dir_all(entry.join("left-pad")).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(entry.join("ms"))
            .arg(
                root.join(VLT_STORE_DIR)
                    .join(sibling)
                    .join("node_modules/ms"),
            )
            .status()
            .unwrap();
        assert!(status.success());
        if std::os::windows::fs::symlink_dir(
            root.join(VLT_STORE_DIR).join(sibling),
            entry.join("dir-link"),
        )
        .is_err()
        {
            eprintln!("dir symlinks need Developer Mode; junction leg only");
        }
        let state = read_install_state(root).await;
        let out = invalidate(root, &state, &[ID.to_string()]).await;
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(!root.join(VLT_STORE_DIR).join(ID).exists());
        assert!(sibling_dir.join("index.js").exists());
    }

    #[test]
    fn owned_instances_need_a_socket_url_whose_leaf_matches_the_dep_id() {
        let lock = r#"{
  "lockfileVersion": 1,
  "options": {},
  "nodes": {
    "~npm~left-pad@1.3.0": [0,"left-pad","sha512-P","https://patch.socket.dev/patch/npm/t/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz"],
    "~npm~ms@2.1.3": [0,"ms","sha512-M","https://patch.socket.dev/patch/npm/t/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/left-pad-1.3.0.tgz"],
    "~npm~@a+b@1.0.0": [0,"@a/b","sha512-S","http://localhost:4026/patch/npm/t/cccccccc-cccc-4ccc-8ccc-cccccccccccc/b-1.0.0.tgz"],
    "~custom~c@1.0.0": [0,"c","sha512-C","https://patch.socket.dev/patch/npm/t/dddddddd-dddd-4ddd-8ddd-dddddddddddd/c-1.0.0.tgz"],
    "~npm~d@1.0.0": [0,"d","sha512-D","https://registry.npmjs.org/d/-/d-1.0.0.tgz"]
  },
  "edges": {}
}
"#;
        let ids: Vec<String> = socket_owned_instances(lock, &[])
            .into_iter()
            .map(|i| i.dep_id)
            .collect();
        assert_eq!(ids, ["~npm~left-pad@1.3.0"]);
        let with_origin = socket_owned_instances(lock, &["http://localhost:4026".into()]);
        let scoped = with_origin.iter().find(|i| i.name == "@a/b").unwrap();
        assert_eq!(scoped.patch_uuid, "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        assert_eq!(scoped.sha512.as_deref(), Some("sha512-S"));
        assert_eq!(
            lock_sha512(lock, "~npm~d@1.0.0").as_deref(),
            Some("sha512-D")
        );
        assert!(socket_owned_instances("\u{feff}{}", &[]).is_empty());
    }

    #[test]
    fn ledger_targets_follow_the_claimed_edits() {
        let mut state = RedirectState::new();
        let edit = |key: &str, id: &str| FileEdit {
            path: "vlt-lock.json".into(),
            kind: vlt::KIND.into(),
            action: "rewritten".into(),
            key: Some(key.into()),
            original: Some(Value::String(format!("\"{id}\": [0,\"x\"]"))),
            new: Some(Value::String(format!("\"{id}\": [0,\"x\",\"s\",\"u\"]"))),
        };
        state.edits = vec![
            edit("left-pad@1.3.0", "~npm~left-pad@1.3.0"),
            edit("left-pad@1.3.0~peer.2", "~npm~left-pad@1.3.0~peer.2"),
            edit("left-pad@1.3.1", "~npm~left-pad@1.3.1"),
        ];
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0".into(), record());
        let targets = ledger_targets(&state, &["pkg:npm/left-pad@1.3.0".into()]);
        let ids: Vec<&str> = targets.iter().map(|t| t.dep_id.as_str()).collect();
        assert_eq!(ids, ["~npm~left-pad@1.3.0", "~npm~left-pad@1.3.0~peer.2"]);
        assert!(targets.iter().all(|t| t.record.is_some()));
    }
}
