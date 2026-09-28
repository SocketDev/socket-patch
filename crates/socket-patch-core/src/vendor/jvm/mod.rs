//! Prototype of the v5 vendored JVM backend (`docs/design/maven-vendoring.md`).
//!
//! Handles only the shapes the legacy `maven_repo` backend refuses — a
//! multi-module Maven reactor and a Gradle build — and only when
//! [`EXPERIMENTAL_ENV`] is set (or the ledger already holds an entry this
//! backend wrote), so every shape vendored today keeps its current behavior.
//!
//! The planners are pure: they read project files through a [`ReadFn`] and
//! return the full post-vendor bytes of every file they touch plus one
//! fragment record per edit (§7.1: never a whole file). Revert is planned the
//! same way ([`maven_reactor::unplan`], [`gradle::unplan`]): per-patch
//! fragments are cut by their exact text or their `socket-patch` tag, and a
//! shared fragment (repository block, `maven.config` lines, apply lines,
//! owned files) goes only once no other patch's reference is left in the
//! project, so the result does not depend on revert order (§7.3). [`apply`]
//! does the disk side.

pub mod apply;
pub mod gradle;
pub mod maven_reactor;

use serde_json::{json, Value};

use super::state::{WiringAction, WiringRecord};

/// Fragment of a reactor pom: `pin`, `version:…` (per patch),
/// `pin_section`, `repository` (shared).
pub const POM_FRAGMENT_KIND: &str = "maven_pom_fragment";
/// The shared `.mvn/maven.config` lines.
pub const CONFIG_LINE_KIND: &str = "maven_config_line";
/// Fragment of a settings file: `apply`, `in_block_section` (shared),
/// `in_block:<gav>` (per patch).
pub const SETTINGS_FRAGMENT_KIND: &str = "gradle_settings_fragment";
/// The patched hash in an existing `gradle/verification-metadata.xml`.
pub const VERIFICATION_FRAGMENT_KIND: &str = "gradle_verification_fragment";
/// A file the backend owns outright (script, index, tree `.gitattributes`).
pub const OWNED_FILE_KIND: &str = "jvm_owned_file";
/// One vendored artifact file; `new` = its sha256.
pub const TREE_KIND: &str = "jvm_vendor_tree";
/// A directory vendor created; removed on revert once empty.
pub const CREATED_DIR_KIND: &str = "jvm_created_dir";
/// Every kind this backend records.
pub const KINDS: &[&str] = &[
    POM_FRAGMENT_KIND,
    CONFIG_LINE_KIND,
    SETTINGS_FRAGMENT_KIND,
    VERIFICATION_FRAGMENT_KIND,
    OWNED_FILE_KIND,
    TREE_KIND,
    CREATED_DIR_KIND,
];

/// Opt-in switch for the prototype backend.
pub const EXPERIMENTAL_ENV: &str = "SOCKET_PATCH_EXPERIMENTAL_JVM_VENDOR";

/// Whether [`EXPERIMENTAL_ENV`] is set to a non-empty value other than `0`.
pub fn experimental_enabled() -> bool {
    std::env::var(EXPERIMENTAL_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Reads a project-relative, forward-slash path. `None` = missing or
/// unreadable.
pub type ReadFn<'a> = &'a dyn Fn(&str) -> Option<Vec<u8>>;

/// The identity of one patch: enough to find (and revert) its wiring.
#[derive(Debug, Clone, Copy)]
pub struct Coords<'a> {
    pub group_id: &'a str,
    pub artifact_id: &'a str,
    /// The upstream (base) version.
    pub version: &'a str,
    pub uuid: &'a str,
}

impl Coords<'_> {
    /// `org.apache.commons` → `org/apache/commons`.
    pub fn group_path(&self) -> String {
        self.group_id.replace('.', "/")
    }

    /// First 8 lowercase hex of the uuid.
    pub fn hex8(&self) -> String {
        self.uuid
            .chars()
            .filter(|c| *c != '-')
            .take(8)
            .collect::<String>()
            .to_ascii_lowercase()
    }

    /// The Maven suffixed version: `<base>-socket.<first 8 hex of the uuid>`,
    /// the same rule as the patch server's `mavenSuffixedVersion`.
    pub fn suffixed_version(&self) -> String {
        format!("{}-socket.{}", self.version, self.hex8())
    }
}

/// One patched artifact, fully materialised.
#[derive(Debug, Clone)]
pub struct JvmPatch<'a> {
    pub group_id: &'a str,
    pub artifact_id: &'a str,
    /// The upstream (base) version.
    pub version: &'a str,
    pub uuid: &'a str,
    /// The patched jar bytes.
    pub jar: &'a [u8],
    /// The upstream pom, verbatim.
    pub upstream_pom: &'a [u8],
    /// The upstream Gradle module metadata, verbatim, when published.
    pub upstream_module: Option<&'a [u8]>,
}

impl<'a> JvmPatch<'a> {
    pub fn coords(&self) -> Coords<'a> {
        Coords {
            group_id: self.group_id,
            artifact_id: self.artifact_id,
            version: self.version,
            uuid: self.uuid,
        }
    }

    pub fn group_path(&self) -> String {
        self.coords().group_path()
    }

    pub fn suffixed_version(&self) -> String {
        self.coords().suffixed_version()
    }
}

/// Which JVM build the project root holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A root `pom.xml` that declares `<modules>`.
    MavenReactor,
    /// No root `pom.xml`, and a Gradle settings or build script.
    Gradle,
    /// Anything else (including a single-module pom, which stays legacy).
    Other,
}

/// A planned file: project-relative forward-slash path and its full new
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWrite {
    pub rel: String,
    pub bytes: Vec<u8>,
    /// Vendored artifact tree file (jar, pom, sidecar, marker): recorded by
    /// hash and deleted on revert; every other write is described by the
    /// plan's fragment records.
    pub tree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmWarning {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmRefusal {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct JvmPlan {
    /// Sorted by `rel`, no duplicates. Files whose new bytes equal their
    /// current bytes are omitted.
    pub writes: Vec<FileWrite>,
    /// One record per text fragment the patch relies on, including shared
    /// fragments another patch already wrote (`op: adopt`, which the caller
    /// replaces with that patch's creation record, §7.3).
    pub records: Vec<WiringRecord>,
    /// Every file of the patch's tree with its sha256, whether this plan
    /// writes it or it is already in place (a patch update recording only
    /// what changed would let the stale sweep delete the rest).
    pub tree_files: Vec<(String, String)>,
    pub warnings: Vec<JvmWarning>,
    /// The tree directory holding the vendored artifact (project-relative).
    pub tree_dir: String,
    /// The vendored jar (project-relative).
    pub jar_rel: String,
}

/// A committed tree as planner input: `(jar, upstream pom, module)`.
pub type CommittedTree = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// A planned revert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JvmUnplan {
    /// Sorted by path: the new bytes, or `None` to delete the file.
    pub changes: Vec<(String, Option<Vec<u8>>)>,
    /// `vendor_lock_entry_drifted` details: a fragment that is still there
    /// but no longer has the shape vendor wrote.
    pub drifted: Vec<String>,
    /// The project still references this patch's tree (a drifted fragment),
    /// so the tree must stay.
    pub still_wired: bool,
}

/// Classify the project root.
pub fn detect(read: ReadFn<'_>) -> Shape {
    if let Some(pom) = read("pom.xml") {
        let text = String::from_utf8_lossy(&pom);
        // Single-pom projects stay on the legacy path until Phase 4 (§7.6).
        return if maven_reactor::declares_modules(&text) {
            Shape::MavenReactor
        } else {
            Shape::Other
        };
    }
    const GRADLE_FILES: &[&str] = &[
        "settings.gradle",
        "settings.gradle.kts",
        "build.gradle",
        "build.gradle.kts",
    ];
    if GRADLE_FILES.iter().any(|f| read(f).is_some()) {
        Shape::Gradle
    } else {
        Shape::Other
    }
}

/// Plan the vendoring of `patch` for a project of `shape`.
pub fn plan(shape: Shape, read: ReadFn<'_>, patch: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
    match shape {
        Shape::MavenReactor => maven_reactor::plan(read, patch),
        Shape::Gradle => gradle::plan(read, patch),
        Shape::Other => Err(JvmRefusal {
            code: "vendor_jvm_shape_unsupported",
            detail: "reason: no_build_file: not a multi-module Maven reactor or a Gradle build"
                .to_string(),
        }),
    }
}

/// D15 narrowed to what every written file accepts unescaped: g is
/// dot-separated `[A-Za-z0-9_-]` segments, a is `[A-Za-z0-9_.-]`, v is
/// `[A-Za-z0-9_.+-]` not ending in `+` nor starting with `latest.`; neither a
/// nor v is all dots, and none holds `--` (it ends an XML comment).
pub fn safe_coordinates(g: &str, a: &str, v: &str) -> bool {
    let seg = |s: &str, extra: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c) || extra.contains(c))
    };
    g.split('.').all(|s| seg(s, ""))
        && seg(a, ".")
        && seg(v, ".+")
        && !a.chars().all(|c| c == '.')
        && !v.chars().all(|c| c == '.')
        && !v.ends_with('+')
        && !v.starts_with("latest.")
        && ![g, a, v].iter().any(|s| s.contains("--"))
}

/// A fragment record. `op` (a JSON object with an `"op"` field) goes in
/// `new`; `original` is the text a rewrite replaced, when known.
pub(crate) fn fragment(
    file: &str,
    kind: &str,
    key: &str,
    action: WiringAction,
    original: Option<String>,
    op: Value,
) -> WiringRecord {
    WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action,
        key: Some(key.to_string()),
        original: original.map(Value::String),
        new: Some(op),
    }
}

/// A tree root's owned `.gitattributes` (D14): created when absent,
/// adopted (never overwritten) when present.
pub(crate) fn owned_file(read: ReadFn<'_>, rel: &str, writes: &mut Vec<FileWrite>) -> WiringRecord {
    if read(rel).is_some() {
        return adopt(rel, OWNED_FILE_KIND, "owned");
    }
    writes.push(FileWrite {
        rel: rel.to_string(),
        bytes: TREE_GITATTRIBUTES.as_bytes().to_vec(),
        tree: false,
    });
    fragment(
        rel,
        OWNED_FILE_KIND,
        "owned",
        WiringAction::Added,
        None,
        json!({ "op": "create" }),
    )
}

/// A shared fragment another patch (or the user) already put in place.
pub(crate) fn adopt(file: &str, kind: &str, key: &str) -> WiringRecord {
    fragment(
        file,
        kind,
        key,
        WiringAction::Added,
        None,
        json!({ "op": "adopt" }),
    )
}

/// A `replace` op: revert swaps `to` back to `from` where `to` occurs once.
pub(crate) fn replace_op(from: &str, to: &str) -> Value {
    json!({ "op": "replace", "from": from, "to": to })
}

/// The `op` of a record, `""` when malformed.
pub(crate) fn op_of(w: &WiringRecord) -> &str {
    w.new
        .as_ref()
        .and_then(|n| n.get("op"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// String field `name` of a record's op.
pub(crate) fn op_str<'w>(w: &'w WiringRecord, name: &str) -> Option<&'w str> {
    w.new.as_ref()?.get(name)?.as_str()
}

/// `text` with the only occurrence of `to` replaced by `from`; `None` when
/// `to` is empty, absent or ambiguous.
pub(crate) fn undo_replace(text: &str, from: &str, to: &str) -> Option<String> {
    if to.is_empty() {
        return None;
    }
    let mut hits = text.match_indices(to);
    let (at, _) = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(format!("{}{from}{}", &text[..at], &text[at + to.len()..]))
}

/// The changed files between `before` and `after` (both path → text, `None`
/// = absent), in [`JvmUnplan::changes`] form.
pub(crate) fn changes_between(
    before: &std::collections::BTreeMap<String, Option<String>>,
    after: &std::collections::BTreeMap<String, Option<String>>,
) -> Vec<(String, Option<Vec<u8>>)> {
    after
        .iter()
        .filter(|(rel, text)| before.get(*rel) != Some(*text))
        .map(|(rel, text)| (rel.clone(), text.clone().map(String::into_bytes)))
        .collect()
}

/// `(rel, sha256)` of every tree write in `writes`.
pub(crate) fn tree_files(writes: &[FileWrite]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = writes
        .iter()
        .filter(|w| w.tree)
        .map(|w| (w.rel.clone(), sha256_hex(&w.bytes)))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Keep only writes that change a file, sorted and de-duplicated by path
/// (the last write for a path wins).
pub(crate) fn finish_writes(read: ReadFn<'_>, writes: Vec<FileWrite>) -> Vec<FileWrite> {
    let mut by_rel = std::collections::BTreeMap::new();
    for w in writes {
        by_rel.insert(w.rel.clone(), w);
    }
    by_rel
        .into_values()
        .filter(|w| read(&w.rel).as_deref() != Some(w.bytes.as_slice()))
        .collect()
}

/// `sha1` hex of `bytes`, the bare-40-hex sidecar body Maven reads.
pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest as _, Sha1};
    hex::encode(Sha1::digest(bytes))
}

/// `sha256` hex of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// `.gitattributes` for an owned tree root: keeps git from rewriting line
/// endings in vendored poms and module files (layer-1 hashes are exact).
pub(crate) const TREE_GITATTRIBUTES: &str = "* -text\n";

/// A disk round-trip harness for the planners' tests: vendor and revert
/// the way the CLI does (ledger peers, carry-forward, stale sweep).
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::super::state::{carry_forward_wiring, VendorEntry};
    use super::super::{RevertOpts, RevertOutcome};
    use super::{apply, JvmPatch, JvmPlan, JvmRefusal, Shape};

    /// A ledger entry for `patch` holding `wiring`.
    pub fn entry(patch: &JvmPatch<'_>, wiring: Vec<super::WiringRecord>) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "maven",
            "basePurl": format!("pkg:maven/{}/{}@{}", patch.group_id, patch.artifact_id, patch.version),
            "uuid": patch.uuid,
            "artifact": { "path": "", "sha256": "" },
            "wiring": serde_json::to_value(wiring).unwrap(),
        }))
        .unwrap()
    }

    /// Vendor `patch` under `root` and record it in `ledger` (keyed by purl).
    pub async fn vendor(
        root: &Path,
        shape: Shape,
        patch: &JvmPatch<'_>,
        ledger: &mut BTreeMap<String, VendorEntry>,
    ) -> Result<JvmPlan, JvmRefusal> {
        let reader = apply::ProjectReader::new(root);
        let plan = super::plan(shape, &|rel: &str| reader.read(rel), patch)?;
        assert_eq!(reader.escaped(), None);
        if plan.writes.is_empty() {
            return Ok(plan);
        }
        let mut wiring = apply::write_plan(root, &plan).await.expect("write plan");
        apply::inherit_peer_records(&mut wiring, ledger.values());
        let mut fresh = entry(patch, wiring);
        let key = fresh.base_purl.clone();
        let prev = ledger.get(&key).cloned();
        if let Some(prev) = &prev {
            carry_forward_wiring(prev, &mut fresh);
        }
        ledger.insert(key, fresh);
        if let Some(prev) = prev.filter(|p| p.uuid != patch.uuid) {
            apply::sweep_replaced_tree(root, &prev, ledger.values())
                .await
                .expect("sweep");
        }
        Ok(plan)
    }

    /// Revert `patch`'s ledger entry, dropping it unless kept.
    pub async fn revert(
        root: &Path,
        patch: &JvmPatch<'_>,
        ledger: &mut BTreeMap<String, VendorEntry>,
    ) -> RevertOutcome {
        let key = format!(
            "pkg:maven/{}/{}@{}",
            patch.group_id, patch.artifact_id, patch.version
        );
        let e = ledger.get(&key).expect("ledger entry").clone();
        let out = apply::revert(root, &e, RevertOpts::new(false)).await;
        if out.success && !out.kept_artifact {
            ledger.remove(&key);
        }
        out
    }

    /// Every file under `root` (relative path → bytes).
    pub fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let meta = std::fs::symlink_metadata(&p).unwrap();
                if meta.is_dir() {
                    walk(root, &p, out);
                } else {
                    let rel = p
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, std::fs::read(&p).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    /// Every directory under `root`, relative.
    pub fn dirs(root: &Path) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if std::fs::symlink_metadata(&p).unwrap().is_dir() {
                    out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
                    walk(root, &p, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }

    /// Write `files` under `root`.
    pub fn populate(root: &Path, files: &[(&str, &str)]) {
        for (rel, body) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid: "5E6F7081-92a3-4b4c-8d5e-6f708192a3b4",
            jar: b"jar",
            upstream_pom: b"pom",
            upstream_module: None,
        }
    }

    #[test]
    fn suffixed_version_uses_first_eight_lowercase_hex() {
        assert_eq!(patch().suffixed_version(), "1.10.0-socket.5e6f7081");
        assert_eq!(patch().coords().hex8(), "5e6f7081");
    }

    #[test]
    fn safe_coordinates_follow_d15_and_forbid_comment_dashes() {
        assert!(safe_coordinates(
            "org.apache.commons",
            "commons-text",
            "1.10.0"
        ));
        assert!(safe_coordinates("g", "a.b_c", "1.0+build.2-rc_1"));
        for (g, a, v) in [
            ("com.ex&ample", "a", "1"),
            ("g", "a<b", "1"),
            ("g", "a", "1.0--x"),
            ("g--h", "a", "1"),
            ("g", "a--b", "1"),
            ("g", "a", "1 0"),
            ("g", "a", "1+"),
            ("g", "a", "latest.release"),
            ("g", "a", "[1,2)"),
            ("g..h", "a", "1"),
            ("g", "..", "1"),
            ("g", "a", "..."),
            ("", "a", "1"),
            ("g", "a", "1'"),
            ("g", "a", "1\\"),
        ] {
            assert!(!safe_coordinates(g, a, v), "{g}:{a}:{v}");
        }
    }

    #[test]
    fn undo_replace_needs_one_occurrence() {
        assert_eq!(undo_replace("a[x]b", "", "[x]").as_deref(), Some("ab"));
        assert_eq!(undo_replace("[x][x]", "", "[x]"), None);
        assert_eq!(undo_replace("ab", "", "[x]"), None);
        assert_eq!(undo_replace("ab", "q", ""), None);
    }

    #[test]
    fn detect_classifies_roots() {
        let reactor = |p: &str| {
            (p == "pom.xml")
                .then(|| b"<project><modules><module>a</module></modules></project>".to_vec())
        };
        assert_eq!(detect(&reactor), Shape::MavenReactor);
        let single = |p: &str| (p == "pom.xml").then(|| b"<project></project>".to_vec());
        assert_eq!(detect(&single), Shape::Other);
        let gradle = |p: &str| (p == "settings.gradle.kts").then(Vec::new);
        assert_eq!(detect(&gradle), Shape::Gradle);
        let empty = |_: &str| None;
        assert_eq!(detect(&empty), Shape::Other);
    }
}
