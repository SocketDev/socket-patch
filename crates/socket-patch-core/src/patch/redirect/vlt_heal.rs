//! Warm-tree heal for hosted vlt redirects.
//!
//! vlt never refreshes a store entry it already holds: after the lock is
//! repointed, `vlt install` keeps `node_modules/.vlt/<DepID>` and the
//! hidden lock as they are. A store entry the hidden lock does not record
//! at the integrity the lock now pins is invalidated (the entry plus
//! `node_modules/.vlt-lock.json`) so the next install extracts the pinned
//! artifact. An entry whose state cannot be determined is never removed,
//! nor is one vlt would not reinstall (an optional node), and nothing
//! outside the project root is ever touched.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::constants::npm_family::{VLT_HIDDEN_LOCK_REL, VLT_STORE_DIR};
use crate::origin::hosted_patch_uuid;
use crate::utils::purl_key::PurlKey;
use crate::vendor::vlt_lock_text::{
    is_default_registry, is_registry_package_name, sniff_lock, split_dep_id, DepIdKind, LockSniff,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Healthy,
    Stale,
    Undeterminable,
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
    /// Slot [0]: 0 prod, 1 optional, 2 dev, 3 dev+optional.
    pub flags: Option<u64>,
}

/// A store entry to classify.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub dep_id: &'a str,
    pub name: &'a str,
    /// Slot [2] of the node in the final `vlt-lock.json` (`None` when the
    /// node is gone or the slot is null).
    pub lock_sha512: Option<&'a str>,
    /// Slot [0] of the node, see [`reinstalls_after_removal`].
    pub flags: Option<u64>,
}

/// A Socket-hosted vlt node of one purl, for the rollback heal
/// ([`lock_targets`]).
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerTarget {
    pub purl: String,
    pub dep_id: String,
    pub name: String,
    /// Slot [0] of the node in the pre-restore lock.
    pub flags: Option<u64>,
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
            flags: tuple.get(0).and_then(Value::as_u64),
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

/// Slot [0] of `dep_id`'s node in `lock_text`.
pub fn lock_flags(lock_text: &str, dep_id: &str) -> Option<u64> {
    let LockSniff::Readable(lock) = sniff_lock(lock_text) else {
        return None;
    };
    lock.nodes()?.get(dep_id)?.get(0)?.as_u64()
}

/// Whether `vlt install` puts a node's store entry back once the heal has
/// removed it. Only prod and dev nodes: vlt treats a missing optional node
/// (flags 1 or 3) as a skipped optional dependency, so every release from
/// 0.0.0-32 to 1.2.0 leaves it missing (its importer link dangling) unless
/// the same install also reinstalls a non-optional node; `vlt ci` restores
/// it. Unknown flags are not guaranteed either. vlt 1.3's brotli bit (4)
/// only says which artifact the node fetches, so a brotli prod or dev node
/// (4 or 6) is reinstalled like any other (#372).
pub fn reinstalls_after_removal(flags: Option<u64>) -> bool {
    flags.is_some_and(|flags| flags <= 7 && flags & 1 == 0)
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

/// Is `target`'s store entry stale against the pin `target` names (the
/// lock's slot [2]), healthy, or impossible to judge? The hidden lock
/// records the integrity of what vlt installed for each DepID, so it
/// decides: a missing node or another integrity is stale, the pinned one
/// healthy. Without a readable hidden lock nothing proves which bytes the
/// entry holds.
pub async fn classify_target(
    state: &InstallState,
    root: &Path,
    target: &Target<'_>,
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
    let HiddenLock::Parsed(nodes) = &state.hidden else {
        return TargetState::Undeterminable;
    };
    match nodes.get(target.dep_id) {
        Some(node) if node.get(2).and_then(Value::as_str) == target.lock_sha512 => {
            TargetState::Healthy
        }
        _ => TargetState::Stale,
    }
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

/// The Socket-hosted vlt nodes of `lock` (read BEFORE a restore rewrites
/// it) that stand for one of `purls` — the ledger-free rollback heal's
/// targets, each judged against the lock's own pins.
pub fn lock_targets(lock: &str, origins: &[String], purls: &[String]) -> Vec<LedgerTarget> {
    let wanted: Vec<PurlKey> = purls.iter().map(|p| PurlKey::new(p)).collect();
    socket_owned_instances(lock, origins)
        .into_iter()
        .filter_map(|instance| {
            let purl = crate::utils::purl::npm_purl(&instance.name, &instance.version)?;
            let key = PurlKey::new(&purl);
            let at = wanted.iter().position(|w| *w == key)?;
            Some(LedgerTarget {
                purl: purls[at].clone(),
                dep_id: instance.dep_id,
                name: instance.name,
                flags: instance.flags,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "~npm~left-pad@1.3.0";
    const PRISTINE: &[u8] = b"module.exports = 'pristine'\n";
    const PATCHED: &[u8] = b"module.exports = 'patched'\n";
    const LOCK_SHA: &str = "sha512-PATCHED";

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

    fn target() -> Target<'static> {
        Target {
            dep_id: ID,
            name: "left-pad",
            lock_sha512: Some(LOCK_SHA),
            flags: Some(0),
        }
    }

    async fn classify(root: &Path, target: &Target<'_>) -> TargetState {
        let state = read_install_state(root).await;
        classify_target(&state, root, target).await
    }

    #[tokio::test]
    async fn rule_a_hidden_lock_integrity_differs() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        hidden(tmp.path(), Some("sha512-UPSTREAM"));
        assert_eq!(classify(tmp.path(), &target()).await, TargetState::Stale);
    }

    #[tokio::test]
    async fn rule_b_hidden_lock_without_the_node() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        hidden(tmp.path(), None);
        assert_eq!(classify(tmp.path(), &target()).await, TargetState::Stale);
    }

    #[tokio::test]
    async fn a_hidden_lock_at_the_pin_is_healthy_and_none_is_undeterminable() {
        let tmp = tempfile::tempdir().unwrap();
        store(tmp.path(), ID, PATCHED);
        assert_eq!(
            classify(tmp.path(), &target()).await,
            TargetState::Undeterminable
        );
        hidden(tmp.path(), Some(LOCK_SHA));
        assert_eq!(classify(tmp.path(), &target()).await, TargetState::Healthy);
        let pristine = Target {
            lock_sha512: Some("sha512-UPSTREAM"),
            ..target()
        };
        assert_eq!(
            classify(tmp.path(), &pristine).await,
            TargetState::Stale,
            "the patched entry is stale once the pin is restored"
        );
        std::fs::write(tmp.path().join(VLT_HIDDEN_LOCK_REL), b"{not json").unwrap();
        assert_eq!(
            classify(tmp.path(), &target()).await,
            TargetState::Undeterminable
        );
    }

    #[tokio::test]
    async fn an_uninstalled_target_is_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(classify(tmp.path(), &target()).await, TargetState::Healthy);
        std::fs::create_dir_all(tmp.path().join(VLT_STORE_DIR)).unwrap();
        assert_eq!(classify(tmp.path(), &target()).await, TargetState::Healthy);
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
            let state = read_install_state(&project).await;
            assert_eq!(
                classify_target(&state, &project, &target()).await,
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
        if unsafe { libc::geteuid() } == 0 {
            return; // root bypasses permission bits; nothing to test
        }
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
        // `mklink` reads a `/` as a switch: build both paths from components.
        let vlt_dir = root.join("node_modules").join(".vlt");
        let entry = vlt_dir.join(ID).join("node_modules");
        std::fs::create_dir_all(entry.join("left-pad")).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(entry.join("ms"))
            .arg(vlt_dir.join(sibling).join("node_modules").join("ms"))
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
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

    /// The rollback heal's only target source (the ledger-driven
    /// `ledger_targets` is gone): every Socket-owned instance of a wanted
    /// purl, peer contexts included, with its slot [0] flags.
    #[test]
    fn lock_targets_name_every_owned_instance_of_the_purls() {
        let lock = r#"{
  "lockfileVersion": 1,
  "options": {},
  "nodes": {
    "~npm~left-pad@1.3.0": [0,"left-pad","sha512-P","https://patch.socket.dev/patch/npm/t/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz"],
    "~npm~left-pad@1.3.0~peer.1": [3,"left-pad","sha512-P","https://patch.socket.dev/patch/npm/t/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz"],
    "~npm~left-pad@1.3.1": [0,"left-pad","sha512-Q","https://patch.socket.dev/patch/npm/t/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/left-pad-1.3.1.tgz"],
    "~npm~ms@2.1.3": [2,"ms","sha512-R","https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"]
  },
  "edges": {}
}
"#;
        let purls = [
            "pkg:npm/left-pad@1.3.0".to_string(),
            "pkg:npm/ms@2.1.3".to_string(),
        ];
        let targets = lock_targets(lock, &[], &purls);
        let got: Vec<(&str, &str, Option<u64>)> = targets
            .iter()
            .map(|t| (t.purl.as_str(), t.dep_id.as_str(), t.flags))
            .collect();
        assert_eq!(
            got,
            [
                ("pkg:npm/left-pad@1.3.0", "~npm~left-pad@1.3.0", Some(0)),
                (
                    "pkg:npm/left-pad@1.3.0",
                    "~npm~left-pad@1.3.0~peer.1",
                    Some(3)
                ),
            ]
        );
        assert!(targets.iter().all(|t| t.name == "left-pad"));
        assert!(lock_targets("\u{feff}{}", &[], &purls).is_empty());
    }

    #[test]
    fn only_prod_and_dev_nodes_are_reinstalled_after_removal() {
        assert!(reinstalls_after_removal(Some(0)));
        assert!(reinstalls_after_removal(Some(2)));
        // #372: vlt 1.3's brotli bit leaves a prod or dev node reinstalled.
        assert!(reinstalls_after_removal(Some(4)));
        assert!(reinstalls_after_removal(Some(6)));
        for flags in [Some(1), Some(3), Some(5), Some(7), Some(8), None] {
            assert!(!reinstalls_after_removal(flags), "{flags:?}");
        }
    }

    #[test]
    fn owned_instances_and_lock_flags_read_slot_zero() {
        let lock = r#"{
  "lockfileVersion": 1,
  "options": {},
  "nodes": {
    "~npm~fsevents@2.3.3": [1,"fsevents","sha512-F","https://patch.socket.dev/patch/npm/t/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/fsevents-2.3.3.tgz",null,null,null,{"os":["darwin"]}],
    "~npm~ms@2.1.2": [3,"ms","sha512-M","https://patch.socket.dev/patch/npm/t/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/ms-2.1.2.tgz"],
    "~npm~semver@7.6.0": [2,"semver"]
  },
  "edges": {}
}
"#;
        let flags: Vec<(String, Option<u64>)> = socket_owned_instances(lock, &[])
            .into_iter()
            .map(|i| (i.dep_id, i.flags))
            .collect();
        assert_eq!(
            flags,
            [
                ("~npm~fsevents@2.3.3".to_string(), Some(1)),
                ("~npm~ms@2.1.2".to_string(), Some(3)),
            ]
        );
        assert_eq!(lock_flags(lock, "~npm~semver@7.6.0"), Some(2));
        assert_eq!(lock_flags(lock, "~npm~absent@1.0.0"), None);
    }
}
