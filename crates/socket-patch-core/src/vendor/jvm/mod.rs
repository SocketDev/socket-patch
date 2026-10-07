//! The v5 vendored JVM backend (`docs/design/maven-vendoring.md`).
//!
//! Handles every Maven root (a single-module pom is planned as a reactor
//! of one), Gradle builds, mixed Maven + Gradle roots, sbt builds and
//! scala-cli directory builds.
//!
//! The planners are pure: they read project files through a [`ReadFn`] and
//! return the full post-vendor bytes of every file they touch plus one
//! fragment record per edit (never a whole file). Revert is planned the
//! same way ([`maven_reactor::unplan`], [`gradle::unplan`]): per-patch
//! fragments are cut by their exact text or their `socket-patch` tag, and a
//! shared fragment (repository block, `maven.config` lines, apply lines,
//! owned files) goes only once no other patch's reference is left in the
//! project, so the result does not depend on revert order. [`apply`]
//! does the disk side.

pub mod apply;
pub mod coursier_gate;
pub mod coursier_tree;
pub mod gradle;
pub mod maven_reactor;
pub mod sbt;
pub mod sbt_gate;
pub mod scala_cli;

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
/// The Gradle tree's artifact-level `maven-metadata.xml`, derived from the
/// index rows of the GA (shared by every vendored version of it).
pub const DERIVED_METADATA_KIND: &str = "gradle_derived_metadata";
/// One vendored artifact file; `new` = its sha256.
pub const TREE_KIND: &str = "jvm_vendor_tree";
/// A directory vendor created; removed on revert once empty.
pub const CREATED_DIR_KIND: &str = "jvm_created_dir";
/// Whether upstream metadata was verified against registry checksums.
pub const UPSTREAM_KIND: &str = "jvm_upstream_status";
/// Fragment of the generated `socket-patch-vendor.sbt`: `file` (shared),
/// `pin:<uuid>` (per patch).
pub const SBT_FRAGMENT_KIND: &str = "sbt_build_fragment";
/// Rows of `.socket/vendor/coursier-index.tsv` (scala-cli).
pub const COURSIER_INDEX_KIND: &str = "coursier_index_fragment";
/// Every kind this backend records.
pub const KINDS: &[&str] = &[
    POM_FRAGMENT_KIND,
    CONFIG_LINE_KIND,
    SETTINGS_FRAGMENT_KIND,
    VERIFICATION_FRAGMENT_KIND,
    OWNED_FILE_KIND,
    DERIVED_METADATA_KIND,
    TREE_KIND,
    CREATED_DIR_KIND,
    UPSTREAM_KIND,
    SBT_FRAGMENT_KIND,
    COURSIER_INDEX_KIND,
];

/// Parse the distribution version from a checked-in wrapper only; never runs the build tool.
pub fn wrapper_version(read: ReadFn<'_>, tool: &str) -> Option<(u32, u32, u32)> {
    let path = match tool {
        "maven" => ".mvn/wrapper/maven-wrapper.properties",
        "gradle" => "gradle/wrapper/gradle-wrapper.properties",
        _ => return None,
    };
    let bytes = read(path)?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let url = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("distributionUrl="))?;
    let re = regex::Regex::new(&format!(r"{tool}-(\d+)\.(\d+)(?:\.(\d+))?")).ok()?;
    let caps = re.captures(url)?;
    Some((
        caps[1].parse().ok()?,
        caps[2].parse().ok()?,
        caps.get(3).map_or(Some(0), |m| m.as_str().parse().ok())?,
    ))
}

/// Reads a project-relative, forward-slash path. `None` = missing or
/// unreadable.
pub type ReadFn<'a> = &'a dyn Fn(&str) -> Option<Vec<u8>>;

/// Lists a project-relative directory (`""` = the root) the way
/// [`crate::gradle::ListFn`] does: bare names, directories ending in `/`.
pub type ListFn<'a> = crate::gradle::ListFn<'a>;

/// A directory listing that knows nothing (for callers with no tree).
pub fn no_list(_: &str) -> Vec<String> {
    Vec::new()
}

/// Project text for the script graph: a BOM is dropped and bytes that are
/// not UTF-8 read as missing (unparseable), never decoded lossily.
pub(crate) fn text_reader<'a>(read: ReadFn<'a>) -> impl Fn(&str) -> Option<String> + 'a {
    move |rel: &str| crate::gradle::dsl::decode(&read(rel)?)
}

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

/// An extra artifact of the patched GAV the Gradle tree also serves
/// unchanged (`<a>-<v>-<classifier>.<extension>`): a classifier variant a
/// build script declares, or the `sources` jar IDEs ask for. Gradle's
/// `exclusiveContent` claims every file of the GAV, so one the tree lacks
/// stops resolving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraArtifact {
    pub classifier: String,
    pub extension: String,
    /// The upstream bytes, verbatim.
    pub bytes: Vec<u8>,
}

impl ExtraArtifact {
    /// `<a>-<v>-<classifier>.<extension>`.
    pub fn file_name(&self, artifact_id: &str, version: &str) -> String {
        format!(
            "{artifact_id}-{version}-{}.{}",
            self.classifier, self.extension
        )
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
    /// Classifier artifacts served beside the jar (Gradle only).
    pub extra_artifacts: &'a [ExtraArtifact],
    /// The jar members the patch rewrote (the record's files): a classifier
    /// artifact holding one with other bytes than the patched jar's is an
    /// unpatched copy (#533).
    pub patched_members: &'a [String],
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
    /// A root `pom.xml`, whether it declares `<modules>` or is a single
    /// module (a reactor of one).
    MavenReactor,
    /// No root `pom.xml`, and a Gradle settings or build script.
    Gradle,
    /// A root `pom.xml` (a reactor or a single module) next to a Gradle
    /// build: both are planned (see [`Detected`]).
    Mixed,
    /// An sbt build root ([`sbt::detect`]).
    Sbt,
    /// A scala-cli directory build ([`scala_cli::detect`]).
    ScalaCli,
    /// No root `pom.xml` and no Gradle, sbt or scala-cli build.
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
    /// replaces with that patch's creation record).
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

/// The Maven half of a project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MavenShape {
    /// A root `pom.xml` that declares `<modules>`.
    Reactor,
    /// A root `pom.xml` without `<modules>`.
    Single,
}

/// Every JVM build the project root holds. A root can hold both a
/// `pom.xml` and a Gradle build (a migration, or a repository publishing
/// with both): each build resolves on its own, so both are vendored, in
/// one transaction (#395).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detected {
    pub maven: Option<MavenShape>,
    /// A Gradle settings or build script.
    pub gradle: bool,
    /// An sbt build root ([`sbt::detect`], [`Shape::Sbt`]) or a scala-cli
    /// directory build ([`scala_cli::detect`], [`Shape::ScalaCli`]). It
    /// takes the root: a pom or Gradle build beside it is not planned
    /// (unless that backend already wired the root, which `sbt::detect`
    /// leaves on it).
    pub scala: Option<Shape>,
}

impl Detected {
    /// The backend's planner shape. Any root pom, single-module or not, is
    /// planned as a reactor; next to a Gradle build both halves are planned
    /// together, so they share one ledger entry.
    pub fn shape(&self) -> Shape {
        if let Some(scala) = self.scala {
            return scala;
        }
        match (self.maven, self.gradle) {
            (Some(_), true) => Shape::Mixed,
            (Some(_), false) => Shape::MavenReactor,
            (None, true) => Shape::Gradle,
            (None, false) => Shape::Other,
        }
    }
}

const GRADLE_FILES: &[&str] = &[
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
];

/// Every build the project root holds.
pub fn detect_builds(read: ReadFn<'_>) -> Detected {
    let maven = read("pom.xml").map(|pom| {
        if maven_reactor::declares_modules(&String::from_utf8_lossy(&pom)) {
            MavenShape::Reactor
        } else {
            MavenShape::Single
        }
    });
    Detected {
        maven,
        gradle: GRADLE_FILES.iter().any(|f| read(f).is_some()),
        scala: sbt::detect(read).or_else(|| scala_cli::detect(read)),
    }
}

/// Classify the project root (see [`Detected::shape`]).
pub fn detect(read: ReadFn<'_>) -> Shape {
    detect_builds(read).shape()
}

/// Plan the vendoring of `patch` for a project of `shape`.
pub fn plan(
    shape: Shape,
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
) -> Result<JvmPlan, JvmRefusal> {
    plan_with_config(shape, read, list, patch, true)
}

/// [`plan`] with an explicit Maven config policy (reactor and mixed roots).
pub fn plan_with_config(
    shape: Shape,
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
    config_enabled: bool,
) -> Result<JvmPlan, JvmRefusal> {
    match shape {
        Shape::MavenReactor => maven_reactor::plan_with_config(read, patch, config_enabled),
        Shape::Gradle => gradle::plan(read, list, patch),
        Shape::Mixed => {
            // Both halves or neither: a refusal of either writes nothing.
            let maven = maven_reactor::plan_with_config(read, patch, config_enabled)?;
            let gradle = gradle::plan(read, list, patch)?;
            Ok(compose(maven, gradle))
        }
        Shape::Sbt => sbt::plan(read, patch),
        Shape::ScalaCli => scala_cli::plan(read, patch),
        Shape::Other => Err(no_build_file_refusal()),
    }
}

/// The refusal of a [`Shape::Other`] root.
pub fn no_build_file_refusal() -> JvmRefusal {
    JvmRefusal {
        code: "vendor_jvm_shape_unsupported",
        detail: "reason: no_build_file: no pom.xml, Gradle, sbt or scala-cli build at the \
                 project root"
            .to_string(),
    }
}

/// One plan for a mixed root: the Maven tree's jar is the entry's artifact
/// (the Gradle tree holds the same bytes under the base version).
fn compose(maven: JvmPlan, gradle: JvmPlan) -> JvmPlan {
    let mut writes = maven.writes;
    writes.extend(gradle.writes);
    writes.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut records = maven.records;
    records.extend(gradle.records);
    let mut tree_files = maven.tree_files;
    tree_files.extend(gradle.tree_files);
    tree_files.sort();
    tree_files.dedup();
    let mut warnings = maven.warnings;
    warnings.extend(gradle.warnings);
    JvmPlan {
        writes,
        records,
        tree_files,
        warnings,
        tree_dir: maven.tree_dir,
        jar_rel: maven.jar_rel,
    }
}

/// Safe coordinates that every written file accepts unescaped: g is
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

/// A tree root's owned `.gitattributes`: created when absent,
/// adopted (never overwritten) when present.
pub(crate) fn owned_file(read: ReadFn<'_>, rel: &str, writes: &mut Vec<FileWrite>) -> WiringRecord {
    owned_file_with(read, rel, TREE_GITATTRIBUTES.as_bytes(), writes)
}

/// An owned file with the given bytes: created when absent, adopted (never
/// overwritten) when present.
pub(crate) fn owned_file_with(
    read: ReadFn<'_>,
    rel: &str,
    bytes: &[u8],
    writes: &mut Vec<FileWrite>,
) -> WiringRecord {
    if read(rel).is_some() {
        return adopt(rel, OWNED_FILE_KIND, "owned");
    }
    writes.push(FileWrite {
        rel: rel.to_string(),
        bytes: bytes.to_vec(),
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
/// (the last write for a path wins). An owned text file ([`eol_blind`])
/// that differs only in line endings is unchanged: a `core.autocrlf`
/// checkout holds it with CRLF (#429).
pub(crate) fn finish_writes(read: ReadFn<'_>, writes: Vec<FileWrite>) -> Vec<FileWrite> {
    let mut by_rel = std::collections::BTreeMap::new();
    for w in writes {
        by_rel.insert(w.rel.clone(), w);
    }
    by_rel
        .into_values()
        .filter(|w| match read(&w.rel) {
            None => true,
            Some(cur) if !w.tree && eol_blind(&w.rel) => {
                !crate::gradle::eol::eol_eq(&cur, &w.bytes)
            }
            Some(cur) => cur != w.bytes,
        })
        .collect()
}

/// The text files the backend owns or derives whole (script, index,
/// `.gitattributes`, `.gitignore`, derived `maven-metadata.xml`,
/// `.mvn/maven.config`, the generated sbt / scala-cli build files):
/// compared line-ending-blind. Tree files stay byte-exact.
pub(crate) fn eol_blind(rel: &str) -> bool {
    [
        gradle::SCRIPT_REL,
        gradle::INDEX_REL,
        gradle::GITATTRIBUTES_REL,
        gradle::SCRIPT_GITATTRIBUTES_REL,
        gradle::VENDOR_GITATTRIBUTES_REL,
        maven_reactor::GITATTRIBUTES_REL,
        maven_reactor::MAVEN_CONFIG,
        sbt::BUILD_FILE,
        sbt::TREE_GITIGNORE_REL,
        scala_cli::ROOT_FILE,
        scala_cli::GUARD_REL,
        coursier_tree::INDEX_REL,
        coursier_tree::GITIGNORE_REL,
        coursier_tree::GITATTRIBUTES_REL,
    ]
    .contains(&rel)
        || gradle::is_derived_metadata_path(rel)
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

/// Whether `current` is still the owned text `ours` (line endings aside).
pub(crate) fn is_ours(current: Option<&[u8]>, ours: &str) -> bool {
    current.is_some_and(|c| crate::gradle::eol::eol_eq(c, ours.as_bytes()))
}

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
        let plan = super::plan(
            shape,
            &|rel: &str| reader.read(rel),
            &|dir: &str| reader.list(dir),
            patch,
        )?;
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

    #[test]
    fn sbt_and_scala_cli_owned_files_are_unchanged_by_a_crlf_checkout() {
        for rel in [
            sbt::BUILD_FILE,
            scala_cli::ROOT_FILE,
            coursier_tree::INDEX_REL,
        ] {
            let lf = b"line one\nline two\n".to_vec();
            let crlf = b"line one\r\nline two\r\n".to_vec();
            let read = |r: &str| (r == rel).then(|| crlf.clone());
            let writes = vec![FileWrite {
                rel: rel.to_string(),
                bytes: lf,
                tree: false,
            }];
            assert!(finish_writes(&read, writes).is_empty(), "{rel}");
        }
    }

    fn patch() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid: "5E6F7081-92a3-4b4c-8d5e-6f708192a3b4",
            jar: b"jar",
            upstream_pom: b"pom",
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
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
        assert_eq!(detect(&single), Shape::MavenReactor);
        let gradle = |p: &str| (p == "settings.gradle.kts").then(Vec::new);
        assert_eq!(detect(&gradle), Shape::Gradle);
        let empty = |_: &str| None;
        assert_eq!(detect(&empty), Shape::Other);
    }

    /// #395: a `pom.xml` next to a Gradle build is both, whichever kind of
    /// pom it is; a single pom alone is a reactor of one (#973).
    #[test]
    fn detect_reports_both_builds_of_a_mixed_root() {
        let files = |pom: &'static [u8], gradle: Option<&'static str>| {
            move |p: &str| {
                if p == "pom.xml" {
                    Some(pom.to_vec())
                } else {
                    (Some(p) == gradle).then(Vec::new)
                }
            }
        };
        let reactor = b"<project><modules><module>a</module></modules></project>";
        let single = b"<project></project>";
        for (pom, gradle, maven, shape) in [
            (
                &single[..],
                Some("build.gradle"),
                MavenShape::Single,
                Shape::Mixed,
            ),
            (
                &single[..],
                Some("settings.gradle.kts"),
                MavenShape::Single,
                Shape::Mixed,
            ),
            (
                &reactor[..],
                Some("build.gradle.kts"),
                MavenShape::Reactor,
                Shape::Mixed,
            ),
            (&reactor[..], None, MavenShape::Reactor, Shape::MavenReactor),
            (&single[..], None, MavenShape::Single, Shape::MavenReactor),
        ] {
            let read = files(pom, gradle);
            let d = detect_builds(&read);
            assert_eq!(d.maven, Some(maven), "{gradle:?}");
            assert_eq!(d.gradle, gradle.is_some(), "{gradle:?}");
            assert_eq!(d.shape(), shape, "{gradle:?}");
        }
    }

    const MIXED_UUID: &str = "1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

    fn mixed_patch() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid: MIXED_UUID,
            jar: b"PATCHED-JAR",
            upstream_pom: b"<project><modelVersion>4.0.0</modelVersion><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.10.0</version></project>\n",
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    const MIXED_POM: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.x</groupId>\n  <artifactId>app</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.commons</groupId>\n      <artifactId>commons-text</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";

    /// #395: a single pom next to a Gradle build vendors both in one
    /// transaction (the suffixed Maven tree and pin, the Gradle tree and
    /// apply line), re-plans to nothing, and reverts every byte.
    #[tokio::test]
    async fn mixed_root_vendors_both_builds_and_reverts_byte_exact() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        testing::populate(
            root,
            &[
                ("pom.xml", MIXED_POM),
                ("settings.gradle", "rootProject.name = 'app'\r\n"),
                (
                    "build.gradle",
                    "plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.apache.commons:commons-text:1.10.0' }\n",
                ),
            ],
        );
        let (pristine, pristine_dirs) = (testing::snapshot(root), testing::dirs(root));
        let read = |rel: &str| apply::read_project_file(root, rel);
        assert_eq!(detect(&read), Shape::Mixed);
        let mut ledger = std::collections::BTreeMap::new();
        let p = mixed_patch();
        let plan = testing::vendor(root, Shape::Mixed, &p, &mut ledger)
            .await
            .unwrap();
        let sv = p.suffixed_version();
        assert_eq!(
            plan.jar_rel,
            format!(
                ".socket/vendor/maven2/org/apache/commons/commons-text/{sv}/commons-text-{sv}.jar"
            )
        );
        let on_disk = testing::snapshot(root);
        assert_eq!(
            on_disk[".socket/vendor/gradle/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"],
            b"PATCHED-JAR"
        );
        assert_eq!(on_disk[&plan.jar_rel], b"PATCHED-JAR");
        assert!(String::from_utf8_lossy(&on_disk["pom.xml"]).contains(&sv));
        assert!(
            String::from_utf8_lossy(&on_disk["settings.gradle"]).ends_with(
                "apply from: '.socket/gradle/socket-patch.settings.gradle' // socket-patch\r\n"
            )
        );
        let entry = ledger.values().next().unwrap().clone();
        assert!(apply::entry_wired_checked(root, &entry).unwrap());
        apply::check_entry(root, &entry, None).unwrap();
        let again = plan_with_config(
            Shape::Mixed,
            &read,
            &|d: &str| apply::ProjectReader::new(root).list(d),
            &p,
            true,
        )
        .unwrap();
        assert!(again.writes.is_empty(), "{:?}", again.writes);
        let out = testing::revert(root, &p, &mut ledger).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(testing::snapshot(root), pristine);
        assert_eq!(testing::dirs(root), pristine_dirs);
    }

    /// #395: a refusal by either half writes nothing for the other.
    #[tokio::test]
    async fn mixed_root_refusal_on_either_side_writes_nothing() {
        for (rel, body, pom) in [
            (
                "build.gradle",
                "plugins { id 'com.android.application' }\n",
                MIXED_POM,
            ),
            (
                "build.gradle",
                "plugins { id 'java' }\n",
                "<project><modules></project>",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            testing::populate(
                root,
                &[("pom.xml", pom), ("settings.gradle", ""), (rel, body)],
            );
            let pristine = testing::snapshot(root);
            let mut ledger = std::collections::BTreeMap::new();
            assert!(
                testing::vendor(root, Shape::Mixed, &mixed_patch(), &mut ledger)
                    .await
                    .is_err()
            );
            assert_eq!(testing::snapshot(root), pristine, "{rel}: {pom}");
            assert!(ledger.is_empty());
        }
    }

    #[test]
    fn owned_text_compares_ignore_only_line_endings() {
        let read = |rel: &str| match rel {
            ".socket/vendor/gradle-index.tsv" => Some(b"#h\r\nrow\r\n".to_vec()),
            ".socket/vendor/gradle/g/a/1/a-1.pom" => Some(b"<p>\r\n".to_vec()),
            _ => None,
        };
        let writes = vec![
            FileWrite {
                rel: ".socket/vendor/gradle-index.tsv".into(),
                bytes: b"#h\nrow\n".to_vec(),
                tree: false,
            },
            FileWrite {
                rel: ".socket/vendor/gradle/g/a/1/a-1.pom".into(),
                bytes: b"<p>\n".to_vec(),
                tree: true,
            },
        ];
        let kept: Vec<String> = finish_writes(&read, writes)
            .into_iter()
            .map(|w| w.rel)
            .collect();
        assert_eq!(kept, [".socket/vendor/gradle/g/a/1/a-1.pom"]);
        assert!(is_ours(Some(b"* -text\r\n"), TREE_GITATTRIBUTES));
        assert!(!is_ours(Some(b"* -text \n"), TREE_GITATTRIBUTES));
        assert!(!is_ours(None, TREE_GITATTRIBUTES));
    }
}

pub(crate) fn is_signature(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == ".SIGNATURE.P7S"
        || upper.strip_prefix("META-INF/").is_some_and(|n| {
            !n.contains('/')
                && [".SF", ".RSA", ".DSA", ".EC"]
                    .iter()
                    .any(|ext| n.ends_with(ext))
        })
}
