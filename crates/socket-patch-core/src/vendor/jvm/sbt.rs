//! Vendored sbt: one generated root file, [`BUILD_FILE`]
//! (`socket-patch-vendor.sbt`, `formats::sbt::owned_file`), over the
//! reactor-style suffixed tree `.socket/vendor/maven2/<g>/<a>/<v>-socket.<hex8>/`
//! (with the same version, sbt's resolvers would serve Central's copy
//! first). The file pins each tree file's sha256, resolves from the tree
//! and forces the suffixed version with `dependencyOverrides`; no user file
//! is edited.
//!
//! Records: [`super::SBT_FRAGMENT_KIND`] for the generated file (`file`:
//! `create`, or `adopt` when another patch already owns it), `pin:<uuid>`
//! for the patch's rows, the tree root's owned `.gitattributes` and
//! `.gitignore` ([`TREE_GITIGNORE_REL`], `!*`), plus the tree records.
//! Revert drops the patch's rows and deletes the file once none remain and
//! the strict parse proved it ours; the tree root's owned files go with it.
//! [`super::sbt_gate`] gates a pin on the build's resolution evidence
//! before planning (`vendor/maven_repo.rs`), so the planner stays pure and
//! `vendor --check` / `repair` re-plan without evidence.
//!
//! The build sources the planner reads (for the version, the build edits
//! that defeat a pin and the dependency digest) are a fixed set reachable
//! through a [`ReadFn`] ([`build_sources`]); a build edit outside it is
//! still caught at load by the generated file's verifier.

use std::collections::BTreeMap;

use serde_json::json;

use super::layout::{self, safe_coordinates};
use super::{
    adopt, coursier_tree, finish_writes, fragment, maven_reactor, owned_file, CommittedTree,
    Coords, FileWrite, JvmPatch, JvmPlan, JvmRefusal, JvmUnplan, JvmWarning, ReadFn, Shape,
    WiringAction, WiringRecord, OWNED_FILE_KIND, SBT_FRAGMENT_KIND, TREE_GITATTRIBUTES,
};
use crate::formats::sbt::build::{
    declared_projects, deps_digest, is_sbt_build, is_sbt_build_root, sbt_support, sbt_version,
    scan_build_sources, SbtSupport, BUILD_PROPERTIES, BUILD_SBT, DEPENDENCY_LOCK, OPTS_FILES,
};
use crate::formats::sbt::owned_file::{
    parse, render, OwnedFileError, SbtFileMode, SbtOwnedFile, SbtPin, HOSTED_FILE, VENDORED_FILE,
};
// Beside an sbt build, which of these builds a developer runs is unknowable.
use super::layout::{GRADLE_ROOT_FILES as GRADLE_FILES, MILL_MARKERS};

/// The generated root file.
pub const BUILD_FILE: &str = VENDORED_FILE;
/// The tree's owned `.gitignore` (`!*`, so a user's `*.jar` rule cannot
/// drop vendored jars from a fresh clone).
pub const TREE_GITIGNORE_REL: &str = ".socket/vendor/maven2/.gitignore";

/// Conventional `project/` definition sources read beside the root ones.
const PROJECT_SOURCES: &[&str] = &[
    "project/plugins.sbt",
    "project/Dependencies.scala",
    "project/Build.scala",
];

/// Text-to-bytes adapter for the `formats::sbt::build` predicates.
fn text<'a>(read: ReadFn<'a>) -> impl Fn(&str) -> Option<String> + 'a {
    move |rel| read(rel).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// [`Shape::Sbt`] for a directory holding an sbt marker, unless the
/// project is already vendored through the Maven reactor, the pre-v5
/// single-pom path, the Gradle backend or the scala-cli backend (its wiring
/// stays on that backend; a new pin there then plans as before).
pub fn detect(read: ReadFn<'_>) -> Option<Shape> {
    let read_text = text(read);
    if !is_sbt_build(&read_text) {
        return None;
    }
    // Beside a Maven or Gradle build, a stray `project/build.properties`
    // naming no `sbt.version` is not an sbt marker.
    let other_build =
        read(layout::POM_FILE).is_some() || GRADLE_FILES.iter().any(|f| read(f).is_some());
    if other_build && read(BUILD_SBT).is_none() && !is_sbt_build_root(&read_text) {
        return None;
    }
    (!reactor_wired(read)
        && !legacy_pom_wired(read)
        && !gradle_wired(read)
        && !scala_cli_wired(read))
    .then_some(Shape::Sbt)
}

/// The scala-cli backend already wired this root (its `socket-patch.scala`
/// or the Coursier tree's index): re-planning it as sbt would replace its
/// ledger entry and orphan that wiring, which `--revert` then never removes.
fn scala_cli_wired(read: ReadFn<'_>) -> bool {
    read(super::scala_cli::ROOT_FILE).is_some() || read(super::coursier_tree::INDEX_REL).is_some()
}

/// The pre-v5 single-pom backend already wired the root pom: its
/// `<repository>` id. The root stays off sbt so that `vendor --revert` can
/// unwind it first (vendoring it is refused as `legacy_maven_root`).
fn legacy_pom_wired(read: ReadFn<'_>) -> bool {
    read("pom.xml").is_some_and(|b| {
        let pom = String::from_utf8_lossy(&b);
        !maven_reactor::declares_modules(&pom)
            && pom.contains(&format!(
                "<id>{}",
                crate::vendor::maven_repo::VENDOR_REPO_ID_PREFIX
            ))
    })
}

/// The Maven reactor backend already wired this root (a multi-module
/// reactor or a single pom): its tagged block or pin in the root pom, or
/// its repository tail in `.mvn/maven.config`.
fn reactor_wired(read: ReadFn<'_>) -> bool {
    let Some(pom) = read(layout::POM_FILE).map(|b| String::from_utf8_lossy(&b).into_owned()) else {
        return false;
    };
    pom.contains(maven_reactor::BEGIN_MARKER)
        || pom.contains(maven_reactor::PIN_TAG)
        || read(maven_reactor::MAVEN_CONFIG)
            .is_some_and(|c| String::from_utf8_lossy(&c).contains(layout::MAVEN2_TREE))
}

/// The Gradle backend already wired this root (its settings apply line).
fn gradle_wired(read: ReadFn<'_>) -> bool {
    layout::GRADLE_SETTINGS_FILES.iter().any(|f| {
        read(f).is_some_and(|b| String::from_utf8_lossy(&b).contains(super::gradle::SCRIPT_REL))
    })
}

/// Whether a project at `project` (an sbt directory that is not a build
/// root) sits inside the sbt build rooted at `ancestor`: vendoring must
/// run from the root (`vendor_jvm_shape_unsupported`, `not_build_root`).
pub fn nested_in_build(project: ReadFn<'_>, ancestor: ReadFn<'_>) -> bool {
    is_sbt_build(&text(project))
        && !is_sbt_build_root(&text(project))
        && is_sbt_build_root(&text(ancestor))
}

/// The patch's tree directory: the reactor's suffixed layout.
pub fn tree_dir(c: &Coords<'_>) -> String {
    maven_reactor::tree_dir(c)
}

/// Whether `rel` is a file this planner edits or owns.
pub fn is_wiring_file(rel: &str) -> bool {
    rel == BUILD_FILE
}

/// Whether `rel` is a file this planner owns outright.
pub fn is_owned_file(rel: &str) -> bool {
    rel == TREE_GITIGNORE_REL
}

/// Whether `wiring` belongs to this planner.
pub fn owns(wiring: &[WiringRecord]) -> bool {
    wiring
        .iter()
        .any(|w| w.kind == SBT_FRAGMENT_KIND || w.file == BUILD_FILE)
}

/// The build sources the planner reads: the root build files, the
/// conventional `project/` sources, and each declared subproject's
/// `build.sbt` / `build.sbt.lock` (generated files excluded).
pub fn build_sources(read: ReadFn<'_>) -> Vec<(String, String)> {
    let read_text = text(read);
    let mut out: Vec<(String, String)> = Vec::new();
    let push = |rel: &str, out: &mut Vec<(String, String)>| {
        if let Some(t) = read_text(rel) {
            out.push((rel.to_string(), t));
        }
    };
    for rel in [BUILD_SBT, BUILD_PROPERTIES, DEPENDENCY_LOCK]
        .iter()
        .chain(OPTS_FILES)
        .chain(PROJECT_SOURCES)
    {
        push(rel, &mut out);
    }
    let dirs: Vec<String> = declared_projects(&out)
        .into_iter()
        .flat_map(BTreeMap::into_values)
        .filter(|d| d != ".")
        .collect();
    for dir in dirs {
        for leaf in [BUILD_SBT, DEPENDENCY_LOCK] {
            push(&format!("{dir}/{leaf}"), &mut out);
        }
    }
    out
}

fn refusal(code: &'static str, detail: impl Into<String>) -> JvmRefusal {
    JvmRefusal {
        code,
        detail: detail.into(),
    }
}

fn warning(code: &'static str, detail: impl Into<String>) -> JvmWarning {
    JvmWarning {
        code,
        detail: detail.into(),
    }
}

/// The parsed generated file of `mode` at its root path; `Ok(None)` when
/// absent.
fn read_owned(read: ReadFn<'_>, mode: SbtFileMode) -> Result<Option<SbtOwnedFile>, OwnedFileError> {
    let Some(bytes) = read(mode.file()) else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| OwnedFileError::Modified("the file is not UTF-8".to_string()))?;
    parse(mode, &text).map(Some)
}

/// The refusal for an unusable generated file.
fn owned_file_refusal(e: OwnedFileError) -> JvmRefusal {
    match e {
        OwnedFileError::Modified(reason) => refusal(
            "vendor_sbt_owned_file_modified",
            format!(
                "{BUILD_FILE} is socket-patch's but was edited ({reason}); restore it (git \
                 checkout {BUILD_FILE}) or delete it and its .socket/vendor/maven2 tree, then \
                 re-run socket-patch vendor"
            ),
        ),
        OwnedFileError::Foreign => refusal(
            "vendor_sbt_owned_file_foreign",
            format!(
                "{BUILD_FILE} exists but was not generated by socket-patch; rename your file so \
                 socket-patch can write its own"
            ),
        ),
    }
}

/// Plan vendoring `patch` into the sbt build `read` serves (`docs/design/
/// sbt-support.md` §5.1). Refusals come before any write is planned.
pub fn plan(read: ReadFn<'_>, patch: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
    plan_with_digest(read, patch, None)
}

/// [`plan`], the pin recording `deps` as its dependency digest: the
/// vendored gate's (`sbt_gate::GatePass::deps_digest`, over every build
/// source, the hosted rewriter's definition), which also decides when an
/// existing pin's digest is refreshed. `None` (no gate ran): the digest of
/// the conventional sources [`build_sources`] reads, an existing pin's kept.
pub fn plan_with_digest(
    read: ReadFn<'_>,
    patch: &JvmPatch<'_>,
    deps: Option<&str>,
) -> Result<JvmPlan, JvmRefusal> {
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    if !safe_coordinates(g, a, v) {
        return Err(refusal(
            "unsafe_coordinates",
            format!("unsafe maven coordinates `{g}:{a}:{v}`"),
        ));
    }
    let read_text = text(read);
    let mut warnings = Vec::new();

    if let Some(pom) = read_text("pom.xml") {
        if maven_reactor::declares_modules(&pom) {
            return Err(refusal(
                "vendor_jvm_build_ambiguous",
                "a root pom.xml declaring <modules> sits beside the sbt build, so which build \
                 runs is unknowable; vendor from a checkout holding only one of them",
            ));
        }
        warnings.push(warning(
            "vendor_sbt_pom_ignored",
            "the root pom.xml is not wired (sbt never reads it); vendoring wires the sbt build",
        ));
    }
    if let Some(other) = GRADLE_FILES
        .iter()
        .chain(MILL_MARKERS)
        .find(|f| read(f).is_some())
    {
        return Err(refusal(
            "vendor_jvm_build_ambiguous",
            format!(
                "{other} sits beside the sbt build, so which build runs is unknowable; vendor \
                 from a checkout holding only one of them"
            ),
        ));
    }

    let Some(version) = read_text(BUILD_PROPERTIES).and_then(|t| sbt_version(&t)) else {
        return Err(refusal(
            "vendor_sbt_build_root_unknown",
            format!(
                "{BUILD_PROPERTIES} does not name an sbt.version, so this is not an sbt build \
                 root; run vendor from the build root (pin the version with `sbt.version=` there)"
            ),
        ));
    };
    let line = match sbt_support(&version) {
        SbtSupport::Unsupported => {
            return Err(refusal(
                "vendor_sbt_unsupported_version",
                format!(
                    "sbt {version} is not supported (0.13.18 and later); upgrade sbt in \
                     {BUILD_PROPERTIES}"
                ),
            ))
        }
        SbtSupport::Supported(line) => line,
        SbtSupport::Untested(line) => {
            warnings.push(warning(
                "vendor_sbt_version_untested",
                format!("sbt {version} is newer than the releases socket-patch was tested on"),
            ));
            line
        }
    };

    let mut file = read_owned(read, SbtFileMode::Vendored)
        .map_err(owned_file_refusal)?
        .unwrap_or(SbtOwnedFile {
            mode: SbtFileMode::Vendored,
            line,
            crlf: false,
            pins: BTreeMap::new(),
        });
    let sv = patch.suffixed_version();
    let existing = file
        .pins
        .get(patch.uuid)
        .filter(|p| p.group == g && p.artifact == a && p.base == v && p.sv == sv)
        .cloned();

    let sources = build_sources(read);
    let findings = scan_build_sources(&sources);
    if existing.is_none() {
        let refuse = |code, what: &str, at: &[String], remedy: &str| {
            refusal(
                code,
                format!(
                    "{what} at {} would replace socket-patch's pin; {remedy}",
                    at.join(", ")
                ),
            )
        };
        if !findings.overrides_assignment.is_empty() {
            return Err(refuse(
                "vendor_sbt_overrides_assignment",
                "a `dependencyOverrides :=` assignment",
                &findings.overrides_assignment,
                "use `dependencyOverrides +=` instead",
            ));
        }
        if !findings.resolvers_assignment.is_empty() {
            return Err(refuse(
                "vendor_sbt_resolvers_assignment",
                "a `resolvers :=` assignment",
                &findings.resolvers_assignment,
                "use `resolvers +=` instead",
            ));
        }
        if !findings.dependency_lock.is_empty() {
            return Err(refuse(
                "vendor_sbt_dependency_lock_present",
                "an sbt-dependency-lock lock file",
                &findings.dependency_lock,
                "remove the lock, vendor, then re-lock with `sbt dependencyLockWrite`",
            ));
        }
    }
    if !findings.override_build_repos.is_empty() {
        warnings.push(warning(
            "vendor_sbt_override_build_repos",
            format!(
                "sbt.override.build.repos=true ({}) replaces the build's resolvers, so the \
                 vendored resolver is dropped and the build fails closed at load",
                findings.override_build_repos.join(", ")
            ),
        ));
    }

    let hosted = read_owned(read, SbtFileMode::Hosted).map_err(|_| {
        refusal(
            "vendor_sbt_hosted_conflict",
            format!(
                "{HOSTED_FILE} cannot be read as socket-patch's hosted file, so its pins cannot \
                 be checked against this one; restore or remove it"
            ),
        )
    })?;
    if hosted
        .iter()
        .flat_map(|h| h.pins.values())
        .any(|p| p.group == g && p.artifact == a)
    {
        return Err(refusal(
            "vendor_sbt_hosted_conflict",
            format!(
                "{g}:{a} is pinned by the hosted {HOSTED_FILE}; roll the hosted patch back first"
            ),
        ));
    }

    let (tree_dir, jar_rel, tree) = maven_reactor::suffixed_tree(patch)?;
    let tree_hash = |ext: &str| {
        let rel = format!("{tree_dir}/{a}-{sv}.{ext}");
        tree.iter()
            .find(|w| w.rel == rel)
            .map(|w| super::sha256_hex(&w.bytes))
            .expect("the suffixed tree holds the pom and the jar")
    };
    let digest = deps_digest(&sources);
    let deps = match (&existing, deps) {
        (_, Some(gated)) => gated.to_string(),
        (Some(p), None) if p.deps_digest != digest => {
            warnings.push(warning(
                "vendor_sbt_pin_unverifiable",
                format!(
                    "the build's dependencies changed since {g}:{a} was pinned; run `sbt \
                     update` and re-check that it still resolves {sv}"
                ),
            ));
            p.deps_digest.clone()
        }
        (Some(p), None) => p.deps_digest.clone(),
        (None, None) => digest,
    };
    for other in file.pins.values() {
        if other.uuid != patch.uuid && other.group == g && other.artifact == a && other.base != v {
            return Err(refusal(
                "vendor_sbt_override_conflict",
                format!(
                    "{BUILD_FILE} already pins {g}:{a} at {} (patch {}); one build forces one \
                     version, so revert that patch first",
                    other.sv, other.uuid
                ),
            ));
        }
    }
    // A patch update (same GA and base, a new uuid) replaces the old pin.
    file.pins
        .retain(|uuid, p| uuid == patch.uuid || p.group != g || p.artifact != a);
    let pin = SbtPin {
        uuid: patch.uuid.to_string(),
        group: g.to_string(),
        artifact: a.to_string(),
        base: v.to_string(),
        sv: sv.clone(),
        pom_sha256: tree_hash("pom"),
        jar_sha256: tree_hash("jar"),
        deps_digest: deps,
        index_url: None,
    };
    crate::formats::sbt::owned_file::validate_values(&pin)
        .map_err(|reason| refusal("vendor_sbt_unsafe_value", format!("{g}:{a}: {reason}")))?;
    file.pins.insert(pin.uuid.clone(), pin);
    file.line = line;
    let rendered = render(&file).map_err(|e| {
        refusal(
            "vendor_sbt_unsafe_value",
            format!("{g}:{a}: cannot render {BUILD_FILE}: {e:?}"),
        )
    })?;

    let mut writes = Vec::new();
    let mut records = vec![
        owned_file(read, maven_reactor::GITATTRIBUTES_REL, &mut writes),
        super::owned_file_with(
            read,
            TREE_GITIGNORE_REL,
            coursier_tree::GITIGNORE.as_bytes(),
            &mut writes,
        ),
    ];
    records.push(if read(BUILD_FILE).is_some() {
        adopt(BUILD_FILE, SBT_FRAGMENT_KIND, "file")
    } else {
        fragment(
            BUILD_FILE,
            SBT_FRAGMENT_KIND,
            "file",
            WiringAction::Added,
            None,
            json!({ "op": "create" }),
        )
    });
    records.push(fragment(
        BUILD_FILE,
        SBT_FRAGMENT_KIND,
        &format!("pin:{}", patch.uuid),
        WiringAction::Added,
        None,
        json!({ "op": "pin", "ga": format!("{g}:{a}"), "sv": sv }),
    ));
    writes.push(FileWrite {
        rel: BUILD_FILE.to_string(),
        bytes: rendered.into_bytes(),
        tree: false,
    });
    writes.extend(tree);
    Ok(JvmPlan {
        tree_files: super::tree_files(&writes),
        writes: finish_writes(read, writes),
        records,
        warnings,
        tree_dir,
        jar_rel,
    })
}

/// Plan the revert of the patch at `c` from its `records`: its rows go;
/// the file is re-rendered while other pins remain and deleted once none
/// do (the strict parse proves it ours), together with the tree root's
/// owned files this backend created. An unparsable file is drift: left
/// alone, and the tree kept while it still names the patch.
pub fn unplan(read: ReadFn<'_>, c: &Coords<'_>, records: &[WiringRecord]) -> JvmUnplan {
    let mut out = JvmUnplan::default();
    let sv = c.suffixed_version();
    let last_out = match read(BUILD_FILE) {
        None => true,
        Some(bytes) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            match read_owned(read, SbtFileMode::Vendored) {
                Ok(Some(mut file)) => {
                    let before = file.pins.len();
                    file.pins.retain(|uuid, _| uuid != c.uuid);
                    if file.pins.is_empty() {
                        out.changes.push((BUILD_FILE.to_string(), None));
                        true
                    } else {
                        if file.pins.len() != before {
                            match render(&file) {
                                Ok(t) => out
                                    .changes
                                    .push((BUILD_FILE.to_string(), Some(t.into_bytes()))),
                                Err(e) => {
                                    out.drifted
                                        .push(format!("{BUILD_FILE} cannot be re-rendered: {e:?}"));
                                    out.still_wired = true;
                                }
                            }
                        }
                        false
                    }
                }
                Ok(None) => true,
                Err(e) => {
                    let reason = match e {
                        OwnedFileError::Modified(r) => r,
                        OwnedFileError::Foreign => "it is no longer socket-patch's".to_string(),
                    };
                    out.drifted
                        .push(format!("{BUILD_FILE} was modified ({reason})"));
                    out.still_wired = text.contains(c.uuid) || text.contains(&sv);
                    false
                }
            }
        }
    };
    if last_out {
        for (rel, body) in [
            (maven_reactor::GITATTRIBUTES_REL, TREE_GITATTRIBUTES),
            (TREE_GITIGNORE_REL, coursier_tree::GITIGNORE),
        ] {
            let created = records
                .iter()
                .any(|w| w.kind == OWNED_FILE_KIND && w.file == rel && super::op_of(w) == "create");
            if created && read(rel).as_deref() == Some(body.as_bytes()) {
                out.changes.push((rel.to_string(), None));
            }
        }
    }
    out.changes.sort();
    out
}

/// Whether the build still pins the patch at `c` (its rows present and the
/// file parsing strictly). An unparsable file cannot tell.
pub fn wired_checked(read: ReadFn<'_>, c: &Coords<'_>) -> Result<bool, JvmRefusal> {
    let file = read_owned(read, SbtFileMode::Vendored).map_err(owned_file_refusal)?;
    let sv = c.suffixed_version();
    Ok(file.is_some_and(|f| {
        f.pins.get(c.uuid).is_some_and(|p| {
            p.group == c.group_id
                && p.artifact == c.artifact_id
                && p.base == c.version
                && p.sv == sv
        })
    }))
}

/// The committed tree bytes of the patch at `c` (the reactor's tree).
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<CommittedTree> {
    maven_reactor::committed(read, c).map(|(jar, pom)| (jar, pom, None))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::super::testing::{dirs, populate, revert, snapshot, vendor};
    use super::super::{apply, sha256_hex, TREE_KIND};
    use super::*;
    use crate::vendor::state::VendorEntry;

    const UUID_A: &str = "1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const UUID_B: &str = "9a8b7c6d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const UUID_A2: &str = "2e4d6f80-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const POM_TEXT: &str = "<project>\n  <groupId>org.apache.commons</groupId>\n  \
        <artifactId>commons-text</artifactId>\n  <version>1.10.0</version>\n</project>\n";
    const POM_GSON: &str = "<project>\n  <groupId>com.google.code.gson</groupId>\n  \
        <artifactId>gson</artifactId>\n  <version>2.8.9</version>\n</project>\n";
    const BUILD: &str =
        "libraryDependencies += \"org.apache.commons\" % \"commons-text\" % \"1.10.0\"\n";

    fn text_patch(uuid: &'static str) -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid,
            jar: b"PK-text",
            upstream_pom: POM_TEXT.as_bytes(),
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn gson_patch() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "com.google.code.gson",
            artifact_id: "gson",
            version: "2.8.9",
            uuid: UUID_B,
            jar: b"PK-gson",
            upstream_pom: POM_GSON.as_bytes(),
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn build(version: &str, extra: &[(&'static str, &'static str)]) -> BTreeMap<String, Vec<u8>> {
        let mut m: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        m.insert(
            BUILD_PROPERTIES.into(),
            format!("sbt.version={version}\n").into_bytes(),
        );
        m.insert(BUILD_SBT.into(), BUILD.as_bytes().to_vec());
        for (k, v) in extra {
            m.insert(k.to_string(), v.as_bytes().to_vec());
        }
        m
    }

    fn plan_over(
        files: &BTreeMap<String, Vec<u8>>,
        p: &JvmPatch<'_>,
    ) -> Result<JvmPlan, JvmRefusal> {
        plan(&|rel: &str| files.get(rel).cloned(), p)
    }

    fn code(r: Result<JvmPlan, JvmRefusal>) -> &'static str {
        r.expect_err("refused").code
    }

    fn write(root: &Path, version: &str, extra: &[(&str, &str)]) {
        let props = format!("sbt.version={version}\n");
        let mut files = vec![(BUILD_PROPERTIES, props.as_str()), (BUILD_SBT, BUILD)];
        files.extend_from_slice(extra);
        populate(root, &files);
    }

    #[test]
    fn detect_routes_sbt_and_keeps_existing_backends() {
        let files = build("1.9.9", &[]);
        assert_eq!(detect(&|p: &str| files.get(p).cloned()), Some(Shape::Sbt));
        assert_eq!(
            super::super::detect(&|p: &str| files.get(p).cloned()),
            Shape::Sbt
        );
        // A subproject directory (no project/) is still sbt-shaped.
        let sub = |p: &str| (p == BUILD_SBT).then(Vec::new);
        assert_eq!(detect(&sub), Some(Shape::Sbt));
        // A reactor already wired by the Maven backend stays a reactor.
        let reactor = build(
            "1.9.9",
            &[(
                "pom.xml",
                "<project><modules><module>a</module></modules>\
                 <!-- socket-patch:begin --></project>",
            )],
        );
        let read = |p: &str| reactor.get(p).cloned();
        assert_eq!(detect(&read), None);
        assert_eq!(super::super::detect(&read), Shape::MavenReactor);
        // An unwired reactor beside sbt routes to sbt, which refuses it.
        let ambiguous = build(
            "1.9.9",
            &[(
                "pom.xml",
                "<project><modules><module>a</module></modules></project>",
            )],
        );
        assert_eq!(
            detect(&|p: &str| ambiguous.get(p).cloned()),
            Some(Shape::Sbt)
        );
        assert_eq!(
            code(plan_over(&ambiguous, &text_patch(UUID_A))),
            "vendor_jvm_build_ambiguous"
        );
        // A Gradle build already wired keeps Gradle.
        let gradle = build(
            "1.9.9",
            &[(
                "settings.gradle",
                "apply from: '.socket/gradle/socket-patch.settings.gradle'\n",
            )],
        );
        let read = |p: &str| gradle.get(p).cloned();
        assert_eq!(detect(&read), None);
        assert_eq!(super::super::detect(&read), Shape::Gradle);
        // A scala-cli build already wired keeps scala-cli when it gains
        // sbt files.
        let scala = build(
            "1.9.9",
            &[
                ("project.scala", "//> using scala 3.3.1\n"),
                (
                    super::super::scala_cli::ROOT_FILE,
                    super::super::scala_cli::ROOT_BYTES,
                ),
            ],
        );
        let read = |p: &str| scala.get(p).cloned();
        assert_eq!(detect(&read), None);
        assert_eq!(super::super::detect(&read), Shape::ScalaCli);
        // A single-module pom the pre-v5 path already wired stays off sbt
        // (a Maven root, refused until reverted); an unwired one beside
        // sbt routes to sbt.
        let legacy = build(
            "1.9.9",
            &[(
                "pom.xml",
                "<project><repositories><repository>\
                 <id>socket-patch-vendor-1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d</id>\
                 </repository></repositories></project>",
            )],
        );
        let read = |p: &str| legacy.get(p).cloned();
        assert_eq!(detect(&read), None);
        assert_eq!(super::super::detect(&read), Shape::MavenReactor);
        // A Gradle build with an unrelated `project/build.properties` is
        // not sbt-shaped.
        let stray: BTreeMap<String, Vec<u8>> = [
            (BUILD_PROPERTIES.to_string(), b"version=1\n".to_vec()),
            ("settings.gradle".to_string(), Vec::new()),
        ]
        .into();
        let read = |p: &str| stray.get(p).cloned();
        assert_eq!(detect(&read), None);
        assert_eq!(super::super::detect(&read), Shape::Gradle);
        let plain = build("1.9.9", &[("pom.xml", "<project></project>")]);
        assert_eq!(
            super::super::detect(&|p: &str| plain.get(p).cloned()),
            Shape::Sbt
        );
    }

    #[test]
    fn nested_subproject_is_guarded() {
        let root = build("1.9.9", &[]);
        let sub = |p: &str| (p == BUILD_SBT).then(Vec::new);
        assert!(nested_in_build(&sub, &|p: &str| root.get(p).cloned()));
        assert!(!nested_in_build(
            &|p: &str| root.get(p).cloned(),
            &|p: &str| root.get(p).cloned()
        ));
    }

    #[test]
    fn suffixed_tree_is_the_reactors_tree() {
        let p = text_patch(UUID_A);
        let (dir, jar, writes) = maven_reactor::suffixed_tree(&p).unwrap();
        assert_eq!(dir, maven_reactor::tree_dir(&p.coords()));
        let reactor = |rel: &str| match rel {
            "pom.xml" => Some(
                b"<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId>\
                  <artifactId>agg</artifactId><version>1</version><modules><module>a</module>\
                  </modules></project>\n"
                    .to_vec(),
            ),
            "a/pom.xml" => Some(
                b"<project><modelVersion>4.0.0</modelVersion><parent><groupId>x</groupId>\
                  <artifactId>agg</artifactId><version>1</version></parent><artifactId>a\
                  </artifactId></project>\n"
                    .to_vec(),
            ),
            _ => None,
        };
        let planned = maven_reactor::plan(&reactor, &p).unwrap();
        let tree: Vec<_> = planned.writes.into_iter().filter(|w| w.tree).collect();
        assert_eq!(tree, writes);
        assert_eq!(planned.jar_rel, jar);
        let sbt = plan_over(&build("1.9.9", &[]), &p).unwrap();
        let sbt_tree: Vec<_> = sbt.writes.into_iter().filter(|w| w.tree).collect();
        assert_eq!(sbt_tree, tree);
    }

    #[test]
    fn plan_writes_the_owned_file_tree_and_records() {
        let files = build("1.9.9", &[]);
        let p = text_patch(UUID_A);
        let plan = plan_over(&files, &p).unwrap();
        let rels: Vec<&str> = plan.writes.iter().map(|w| w.rel.as_str()).collect();
        let tree = ".socket/vendor/maven2/org/apache/commons/commons-text/1.10.0-socket.1d3c1fd2";
        assert_eq!(
            rels,
            [
                ".socket/vendor/maven2/.gitattributes".to_string(),
                ".socket/vendor/maven2/.gitignore".to_string(),
                format!("{tree}/commons-text-1.10.0-socket.1d3c1fd2.jar"),
                format!("{tree}/commons-text-1.10.0-socket.1d3c1fd2.jar.sha1"),
                format!("{tree}/commons-text-1.10.0-socket.1d3c1fd2.pom"),
                format!("{tree}/commons-text-1.10.0-socket.1d3c1fd2.pom.sha1"),
                format!("{tree}/socket-patch.vendor.json"),
                BUILD_FILE.to_string(),
            ]
        );
        let gitignore = &plan.writes[1];
        assert_eq!(gitignore.bytes, b"!*\n");
        assert_eq!(plan.tree_dir, tree);
        assert_eq!(
            plan.jar_rel,
            format!("{tree}/commons-text-1.10.0-socket.1d3c1fd2.jar")
        );
        let keys: Vec<(&str, &str, &str)> = plan
            .records
            .iter()
            .map(|r| {
                (
                    r.file.as_str(),
                    r.key.as_deref().unwrap_or_default(),
                    super::super::op_of(r),
                )
            })
            .collect();
        assert_eq!(
            keys,
            [
                (".socket/vendor/maven2/.gitattributes", "owned", "create"),
                (".socket/vendor/maven2/.gitignore", "owned", "create"),
                (BUILD_FILE, "file", "create"),
                (BUILD_FILE, &format!("pin:{UUID_A}") as &str, "pin"),
            ]
        );
        let text = String::from_utf8(plan.writes.last().unwrap().bytes.clone()).unwrap();
        let parsed = parse(SbtFileMode::Vendored, &text).unwrap();
        let pin = &parsed.pins[UUID_A];
        assert_eq!(pin.sv, "1.10.0-socket.1d3c1fd2");
        assert_eq!(pin.jar_sha256, sha256_hex(b"PK-text"));
        assert_eq!(
            pin.deps_digest,
            deps_digest(&build_sources(&|p: &str| files.get(p).cloned()))
        );
        assert!(text.contains("Global / onLoad"), "{text}");
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
    }

    #[test]
    fn syntax_line_follows_the_sbt_version() {
        for (version, needle) in [
            ("0.13.18", "onLoad in Global"),
            ("1.2.8", "Global / onLoad"),
            ("2.0.9", "Def.uncached"),
        ] {
            let plan = plan_over(&build(version, &[]), &text_patch(UUID_A)).unwrap();
            let text = String::from_utf8(plan.writes.last().unwrap().bytes.clone()).unwrap();
            assert!(text.contains(needle), "{version}");
        }
        let plan = plan_over(&build("2.1.0", &[]), &text_patch(UUID_A)).unwrap();
        assert_eq!(plan.warnings[0].code, "vendor_sbt_version_untested");
    }

    #[test]
    fn refusals_come_before_any_write() {
        let p = text_patch(UUID_A);
        for (files, expected) in [
            (build("0.13.17", &[]), "vendor_sbt_unsupported_version"),
            (
                build("1.0", &[])
                    .into_iter()
                    .filter(|(k, _)| k != BUILD_PROPERTIES)
                    .collect(),
                "vendor_sbt_build_root_unknown",
            ),
            (
                build("1.9.9", &[("build.gradle", "")]),
                "vendor_jvm_build_ambiguous",
            ),
            (
                build("1.9.9", &[("build.mill", "")]),
                "vendor_jvm_build_ambiguous",
            ),
            (
                build("1.9.9", &[(BUILD_FILE, "// mine\n")]),
                "vendor_sbt_owned_file_foreign",
            ),
            (
                build(
                    "1.9.9",
                    &[(BUILD_FILE, "// Generated by socket-patch. edited\n")],
                ),
                "vendor_sbt_owned_file_modified",
            ),
            (
                build(
                    "1.9.9",
                    &[(HOSTED_FILE, "// Generated by socket-patch. edited\n")],
                ),
                "vendor_sbt_hosted_conflict",
            ),
            (
                build("1.9.9", &[("zz.sbt", ""), (DEPENDENCY_LOCK, "{}")]),
                "vendor_sbt_dependency_lock_present",
            ),
            (
                build(
                    "1.9.9",
                    &[(
                        "project/Dependencies.scala",
                        "object D { dependencyOverrides := Nil }",
                    )],
                ),
                "vendor_sbt_overrides_assignment",
            ),
            (
                build(
                    "1.9.9",
                    &[
                        ("project/plugins.sbt", ""),
                        ("project/Build.scala", "object B { resolvers := Nil }"),
                    ],
                ),
                "vendor_sbt_resolvers_assignment",
            ),
        ] {
            assert_eq!(code(plan_over(&files, &p)), expected);
        }
        let mut unsafe_patch = text_patch(UUID_A);
        unsafe_patch.version = "1.0--x";
        assert_eq!(
            code(plan_over(&build("1.9.9", &[]), &unsafe_patch)),
            "unsafe_coordinates"
        );
        let mut computed = text_patch(UUID_A);
        computed.upstream_pom = b"<project><version>${revision}</version></project>";
        assert_eq!(
            code(plan_over(&build("1.9.9", &[]), &computed)),
            "vendor_jvm_upstream_unavailable"
        );
    }

    #[test]
    fn subproject_sources_are_scanned_and_warnings_carried() {
        let files = build(
            "1.9.9",
            &[
                (
                    BUILD_SBT,
                    "lazy val a = project\nlazy val b = (project in file(\"mods/b\"))\n",
                ),
                ("mods/b/build.sbt", "dependencyOverrides := Seq.empty\n"),
            ],
        );
        assert_eq!(
            code(plan_over(&files, &text_patch(UUID_A))),
            "vendor_sbt_overrides_assignment"
        );
        let files = build(
            "1.9.9",
            &[
                (".sbtopts", "-Dsbt.override.build.repos=true\n"),
                ("pom.xml", "<project></project>"),
            ],
        );
        let plan = plan_over(&files, &text_patch(UUID_A)).unwrap();
        let codes: Vec<_> = plan.warnings.iter().map(|w| w.code).collect();
        assert_eq!(
            codes,
            ["vendor_sbt_pom_ignored", "vendor_sbt_override_build_repos"]
        );
    }

    #[test]
    fn hosted_pin_of_the_same_ga_conflicts_and_other_gas_coexist() {
        let hosted = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sbt/owned_file/hosted-1-1pin.sbt"),
        )
        .unwrap();
        let hosted: &'static str = Box::leak(hosted.into_boxed_str());
        let files = build("1.9.9", &[(HOSTED_FILE, hosted)]);
        let pinned = parse(SbtFileMode::Hosted, hosted).unwrap();
        let p = pinned.pins.values().next().unwrap();
        let conflicting = JvmPatch {
            group_id: Box::leak(p.group.clone().into_boxed_str()),
            artifact_id: Box::leak(p.artifact.clone().into_boxed_str()),
            version: Box::leak(p.base.clone().into_boxed_str()),
            uuid: UUID_A,
            jar: b"x",
            upstream_pom: Box::leak(
                format!(
                    "<project><groupId>{}</groupId><artifactId>{}</artifactId><version>{}\
                     </version></project>",
                    p.group, p.artifact, p.base
                )
                .into_boxed_str(),
            )
            .as_bytes(),
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        };
        assert_eq!(
            code(plan_over(&files, &conflicting)),
            "vendor_sbt_hosted_conflict"
        );
        assert!(plan_over(&files, &gson_patch()).is_ok());
    }

    #[test]
    fn existing_pin_is_kept_and_a_dependency_edit_only_warns() {
        let mut files = build("1.9.9", &[]);
        let p = text_patch(UUID_A);
        let first = plan_over(&files, &p).unwrap();
        for w in &first.writes {
            files.insert(w.rel.clone(), w.bytes.clone());
        }
        let again = plan_over(&files, &p).unwrap();
        assert!(again.writes.is_empty(), "{:?}", again.writes);
        assert_eq!(again.tree_files, first.tree_files);
        assert_eq!(super::super::op_of(&again.records[2]), "adopt");
        // A dependency edit after wiring: the row keeps its digest and the
        // re-plan warns, writing nothing.
        files.insert(
            BUILD_SBT.into(),
            format!("{BUILD}libraryDependencies += \"a\" % \"b\" % \"1\"\n").into_bytes(),
        );
        let bumped = plan_over(&files, &p).unwrap();
        assert!(bumped.writes.is_empty());
        assert_eq!(bumped.warnings[0].code, "vendor_sbt_pin_unverifiable");
        // Build edits that block a NEW pin do not refuse the existing one.
        files.insert(
            "project/Build.scala".into(),
            b"object B { resolvers := Nil }".to_vec(),
        );
        assert!(plan_over(&files, &p).is_ok());
        assert_eq!(
            code(plan_over(&files, &gson_patch())),
            "vendor_sbt_resolvers_assignment"
        );
    }

    /// The pin records the gate's digest (every build source, the hosted
    /// definition), so a `project/Deps.scala` literal the conventional
    /// sources miss neither warns forever nor hides a bump; the gate's
    /// digest also refreshes an existing pin.
    #[test]
    fn the_gate_digest_is_the_one_recorded() {
        let mut files = build("1.9.9", &[]);
        let p = text_patch(UUID_A);
        let read = |files: &BTreeMap<String, Vec<u8>>| {
            let files = files.clone();
            move |rel: &str| files.get(rel).cloned()
        };
        let first = plan_with_digest(&read(&files), &p, Some("feedf00d")).unwrap();
        for w in &first.writes {
            files.insert(w.rel.clone(), w.bytes.clone());
        }
        let pin = |files: &BTreeMap<String, Vec<u8>>| {
            parse(
                SbtFileMode::Vendored,
                std::str::from_utf8(&files[BUILD_FILE]).unwrap(),
            )
            .unwrap()
            .pins[UUID_A]
                .clone()
        };
        assert_eq!(pin(&files).deps_digest, "feedf00d");
        let same = plan_with_digest(&read(&files), &p, Some("feedf00d")).unwrap();
        assert!(same.writes.is_empty() && same.warnings.is_empty());
        let refreshed = plan_with_digest(&read(&files), &p, Some("0badcafe")).unwrap();
        assert!(refreshed.warnings.is_empty(), "{:?}", refreshed.warnings);
        for w in &refreshed.writes {
            files.insert(w.rel.clone(), w.bytes.clone());
        }
        assert_eq!(pin(&files).deps_digest, "0badcafe");
    }

    #[test]
    fn same_ga_other_base_conflicts() {
        let mut files = build("1.9.9", &[]);
        for w in plan_over(&files, &text_patch(UUID_A)).unwrap().writes {
            files.insert(w.rel, w.bytes);
        }
        let mut other = text_patch(UUID_B);
        other.version = "1.9";
        other.upstream_pom = b"<project><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></project>";
        assert_eq!(
            code(plan_over(&files, &other)),
            "vendor_sbt_override_conflict"
        );
    }

    #[test]
    fn crlf_file_is_kept_crlf() {
        let mut files = build("1.9.9", &[]);
        for w in plan_over(&files, &text_patch(UUID_A)).unwrap().writes {
            files.insert(w.rel, w.bytes);
        }
        let lf = String::from_utf8(files[BUILD_FILE].clone()).unwrap();
        files.insert(BUILD_FILE.into(), lf.replace('\n', "\r\n").into_bytes());
        let plan = plan_over(&files, &gson_patch()).unwrap();
        let out = plan.writes.iter().find(|w| w.rel == BUILD_FILE).unwrap();
        let text = String::from_utf8(out.bytes.clone()).unwrap();
        assert_eq!(text.matches('\n').count(), text.matches("\r\n").count());
        assert_eq!(parse(SbtFileMode::Vendored, &text).unwrap().pins.len(), 2);
    }

    #[test]
    fn unplan_without_file_and_with_drift() {
        let c = text_patch(UUID_A).coords();
        let none = |_: &str| None;
        assert_eq!(unplan(&none, &c, &[]), JvmUnplan::default());
        let mut files = build("1.9.9", &[]);
        for w in plan_over(&files, &text_patch(UUID_A)).unwrap().writes {
            files.insert(w.rel, w.bytes);
        }
        let mut text = String::from_utf8(files[BUILD_FILE].clone()).unwrap();
        text.push_str("// mine\n");
        files.insert(BUILD_FILE.into(), text.into_bytes());
        let read = |p: &str| files.get(p).cloned();
        let out = unplan(&read, &c, &[]);
        assert!(out.changes.is_empty());
        assert!(out.still_wired);
        assert!(out.drifted[0].contains("was modified"), "{:?}", out.drifted);
        assert!(wired_checked(&read, &c).is_err());
        // Drift that no longer names the patch frees its tree.
        let other = text_patch(UUID_B).coords();
        assert!(!unplan(&read, &other, &[]).still_wired);
    }

    #[tokio::test]
    async fn idempotent_replan_then_two_patches_revert_in_either_order_byte_exact() {
        for first_out in [0usize, 1] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            write(root, "1.9.9", &[]);
            let pristine = snapshot(root);
            let pristine_dirs = dirs(root);
            let patches = [text_patch(UUID_A), gson_patch()];
            let mut ledger = BTreeMap::new();
            vendor(root, Shape::Sbt, &patches[0], &mut ledger)
                .await
                .unwrap();
            let one = snapshot(root);
            let again = vendor(root, Shape::Sbt, &patches[0], &mut ledger)
                .await
                .unwrap();
            assert!(again.writes.is_empty(), "{:?}", again.writes);
            vendor(root, Shape::Sbt, &patches[1], &mut ledger)
                .await
                .unwrap();
            let both = snapshot(root);
            assert_eq!(
                parse(
                    SbtFileMode::Vendored,
                    std::str::from_utf8(&both[BUILD_FILE]).unwrap()
                )
                .unwrap()
                .pins
                .len(),
                2
            );
            for e in ledger.values() {
                assert!(apply::entry_wired_checked(root, e).unwrap());
                apply::check_entry(root, e, None).unwrap();
                // The second patch adopted, then inherited, the creation records.
                let file = e
                    .wiring
                    .iter()
                    .find(|w| w.key.as_deref() == Some("file"))
                    .unwrap();
                assert_eq!(super::super::op_of(file), "create");
            }
            let out = revert(root, &patches[first_out], &mut ledger).await;
            assert!(out.success && !out.kept_artifact, "{out:?}");
            assert!(out.warnings.is_empty(), "{:?}", out.warnings);
            let remaining = &patches[1 - first_out];
            if first_out == 1 {
                assert_eq!(snapshot(root), one, "reverting gson leaves exactly text");
            }
            let e = ledger.values().next().unwrap();
            assert!(apply::entry_wired_checked(root, e).unwrap());
            apply::check_entry(root, e, None).unwrap();
            let out = revert(root, remaining, &mut ledger).await;
            assert!(out.success && !out.kept_artifact, "{out:?}");
            assert_eq!(snapshot(root), pristine, "first_out={first_out}");
            assert_eq!(dirs(root), pristine_dirs, "first_out={first_out}");
        }
    }

    #[tokio::test]
    async fn patch_update_replaces_the_pin_and_sweeps_the_old_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "1.13.0", &[]);
        let pristine = snapshot(root);
        let mut ledger = BTreeMap::new();
        vendor(root, Shape::Sbt, &text_patch(UUID_A), &mut ledger)
            .await
            .unwrap();
        let old_tree = root.join(tree_dir(&text_patch(UUID_A).coords()));
        assert!(old_tree.is_dir());
        vendor(root, Shape::Sbt, &text_patch(UUID_A2), &mut ledger)
            .await
            .unwrap();
        assert!(!old_tree.exists(), "the stale sweep removes the old tree");
        let text = std::fs::read_to_string(root.join(BUILD_FILE)).unwrap();
        assert!(!text.contains(UUID_A) && text.contains(UUID_A2), "{text}");
        assert!(text.contains("1.10.0-socket.2e4d6f80"));
        let e = ledger.values().next().unwrap();
        apply::check_entry(root, e, None).unwrap();
        revert(root, &text_patch(UUID_A2), &mut ledger).await;
        assert_eq!(snapshot(root), pristine);
    }

    #[tokio::test]
    async fn drifted_file_keeps_the_tree_and_check_reports_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "1.9.9", &[]);
        let mut ledger = BTreeMap::new();
        vendor(root, Shape::Sbt, &text_patch(UUID_A), &mut ledger)
            .await
            .unwrap();
        let e: VendorEntry = ledger.values().next().unwrap().clone();
        let path = root.join(BUILD_FILE);
        let good = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            good.replace("dependencyOverrides +=", "dependencyOverrides  +="),
        )
        .unwrap();
        assert!(apply::check_entry(root, &e, None).is_err());
        let out = apply::revert(root, &e, crate::vendor::RevertOpts::new(false)).await;
        assert!(out.success && out.kept_artifact, "{out:?}");
        assert_eq!(out.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(root
            .join(&e.wiring.iter().find(|w| w.kind == TREE_KIND).unwrap().file)
            .is_file());
        // A tree file edit is drift for --check too.
        std::fs::write(&path, &good).unwrap();
        apply::check_entry(root, &e, None).unwrap();
        let jar = root.join(&e.artifact.path);
        let jar = if e.artifact.path.is_empty() {
            root.join(format!(
                "{}/commons-text-1.10.0-socket.1d3c1fd2.jar",
                tree_dir(&text_patch(UUID_A).coords())
            ))
        } else {
            jar
        };
        std::fs::write(&jar, b"tampered").unwrap();
        assert!(apply::check_entry(root, &e, None).is_err());
    }

    #[tokio::test]
    async fn last_out_delete_spares_user_owned_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // The user already had a tree .gitattributes: adopted, never deleted.
        write(
            root,
            "1.9.9",
            &[(".socket/vendor/maven2/.gitattributes", "* -text\n")],
        );
        let pristine = snapshot(root);
        let mut ledger = BTreeMap::new();
        vendor(root, Shape::Sbt, &text_patch(UUID_A), &mut ledger)
            .await
            .unwrap();
        let out = revert(root, &text_patch(UUID_A), &mut ledger).await;
        assert!(out.success, "{out:?}");
        assert_eq!(snapshot(root), pristine);
        // Reverting one of two pins re-renders the file, never deletes it.
        let mut ledger = BTreeMap::new();
        vendor(root, Shape::Sbt, &text_patch(UUID_A), &mut ledger)
            .await
            .unwrap();
        vendor(root, Shape::Sbt, &gson_patch(), &mut ledger)
            .await
            .unwrap();
        let only_gson = {
            let files = snapshot(root);
            let read = |p: &str| files.get(p).cloned();
            unplan(&read, &text_patch(UUID_A).coords(), &[])
        };
        assert_eq!(only_gson.changes.len(), 1);
        assert!(only_gson.changes[0].1.is_some());
    }

    #[tokio::test]
    async fn forged_ledger_records_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "1.9.9", &[]);
        let mut ledger = BTreeMap::new();
        vendor(root, Shape::Sbt, &text_patch(UUID_A), &mut ledger)
            .await
            .unwrap();
        let before = snapshot(root);
        for (file, kind) in [
            ("build.sbt", SBT_FRAGMENT_KIND),
            ("../escape.sbt", SBT_FRAGMENT_KIND),
            ("project/plugins.sbt", OWNED_FILE_KIND),
            (".socket/vendor/maven2/other/x.jar", TREE_KIND),
        ] {
            let mut e = ledger.values().next().unwrap().clone();
            e.wiring.push(WiringRecord {
                file: file.into(),
                kind: kind.into(),
                action: WiringAction::Added,
                key: Some("file".into()),
                original: None,
                new: Some(json!({ "op": "create" })),
            });
            let out = apply::revert(root, &e, crate::vendor::RevertOpts::new(false)).await;
            assert!(!out.success, "{file}: {out:?}");
            assert!(apply::check_entry(root, &e, None).is_err(), "{file}");
            assert_eq!(snapshot(root), before, "{file}");
        }
    }

    #[tokio::test]
    async fn reactor_vendored_before_sbt_files_appear_stays_a_reactor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        populate(
            root,
            &[
                (
                    "pom.xml",
                    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  \
                     <artifactId>agg</artifactId>\n  <version>1</version>\n  \
                     <packaging>pom</packaging>\n  <modules>\n    <module>a</module>\n  \
                     </modules>\n</project>\n",
                ),
                (
                    "a/pom.xml",
                    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
                     <groupId>x</groupId>\n    <artifactId>agg</artifactId>\n    \
                     <version>1</version>\n  </parent>\n  <artifactId>a</artifactId>\n  \
                     <dependencies>\n    <dependency>\n      \
                     <groupId>org.apache.commons</groupId>\n      \
                     <artifactId>commons-text</artifactId>\n      \
                     <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n\
                     </project>\n",
                ),
            ],
        );
        let reader = |root: &Path| {
            let r = apply::ProjectReader::new(root);
            super::super::detect(&|rel: &str| r.read(rel))
        };
        assert_eq!(reader(root), Shape::MavenReactor);
        let mut ledger = BTreeMap::new();
        let p = text_patch(UUID_A);
        vendor(root, Shape::MavenReactor, &p, &mut ledger)
            .await
            .unwrap();
        write(root, "1.9.9", &[]);
        assert_eq!(reader(root), Shape::MavenReactor);
        let again = vendor(root, reader(root), &p, &mut ledger).await.unwrap();
        assert!(again.writes.is_empty(), "{:?}", again.writes);
        assert!(!root.join(BUILD_FILE).exists());
        // A second patch on the same checkout also stays on the reactor.
        let mut fresh = ledger.clone();
        let mut gson = gson_patch();
        gson.uuid = UUID_A2;
        vendor(root, reader(root), &gson, &mut fresh).await.unwrap();
        assert!(!root.join(BUILD_FILE).exists());
    }

    #[tokio::test]
    async fn redownload_view_reproduces_the_tree() {
        // `repair` re-plans with `.socket/vendor/` hidden: the tree writes
        // must match the recorded tree exactly.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "1.9.9", &[]);
        let mut ledger = BTreeMap::new();
        let p = text_patch(UUID_A);
        vendor(root, Shape::Sbt, &p, &mut ledger).await.unwrap();
        let e = ledger.values().next().unwrap();
        let reader = apply::ProjectReader::new(root);
        let read = |rel: &str| {
            if rel.starts_with(".socket/vendor/") {
                None
            } else {
                reader.read(rel)
            }
        };
        assert_eq!(super::super::detect(&read), Shape::Sbt);
        let replanned = super::super::plan(Shape::Sbt, &read, &super::super::no_list, &p).unwrap();
        let tree: Vec<_> = replanned.writes.iter().filter(|w| w.tree).collect();
        let recorded: Vec<_> = e.wiring.iter().filter(|w| w.kind == TREE_KIND).collect();
        assert_eq!(tree.len(), recorded.len());
        for w in tree {
            let rec = recorded.iter().find(|r| r.file == w.rel).expect("recorded");
            assert_eq!(
                rec.new.as_ref().and_then(|v| v.as_str()),
                Some(sha256_hex(&w.bytes).as_str())
            );
        }
        // The generated file is untouched by that re-plan.
        assert!(!replanned.writes.iter().any(|w| w.rel == BUILD_FILE));
        // And the committed tree re-plans with no writes at all.
        let read = |rel: &str| reader.read(rel);
        let (jar, pom, module) = committed(&read, &p.coords()).unwrap();
        let again = JvmPatch {
            jar: &jar,
            upstream_pom: &pom,
            upstream_module: module.as_deref(),
            ..p
        };
        assert!(plan(&read, &again).unwrap().writes.is_empty());
    }
}
