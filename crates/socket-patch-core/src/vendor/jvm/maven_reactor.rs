//! Multi-module Maven reactor planner. See the module doc of
//! [`super`] and `docs/design/maven-vendoring.md` (the v5 behavior: 2-line `maven.config`, a fallback repository and a pin per local
//! root, declaration rewrites; no build-time checksum pins).
//!
//! Every pom is edited by splicing at byte offsets found on a masked copy
//! (comments, CDATA and processing instructions blanked), so line endings,
//! tabs, comments and unrelated content survive untouched.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde_json::{json, Value};

use crate::formats::maven::{
    classpath_copy, interpolate_keeping, interpolate_strict, is_executable_classifier,
    lookup_property, maven_config_properties as cli_properties, profile_combinations, Definitions,
    Interpolate, PomLayer, MAX_COMBINED_PROFILES, MAX_INTERPOLATION_DEPTH,
};

use super::super::state::{WiringAction, WiringRecord};
use super::layout::{self, safe_coordinates};
use super::{
    adopt, changes_between, finish_writes, fragment, op_of, op_str, owned_file, replace_op,
    sha1_hex, sha256_hex, undo_replace, Coords, FileWrite, JvmPatch, JvmPlan, JvmRefusal,
    JvmUnplan, JvmWarning, ListFn, ReadFn, CONFIG_LINE_KIND, OWNED_FILE_KIND, POM_FRAGMENT_KIND,
    TREE_GITATTRIBUTES,
};

/// The committed maven2 tree.
use super::layout::MAVEN2_TREE as TREE_ROOT;
pub const MAVEN_CONFIG: &str = ".mvn/maven.config";
/// The tree root's `.gitattributes`, shared by every Maven patch.
pub const GITATTRIBUTES_REL: &str = ".socket/vendor/maven2/.gitattributes";
/// The tree root's `.gitignore` (`!*`), shared with sbt: re-includes the
/// vendored jars against a user's `*.jar` rule (Java.gitignore), #1061.
pub use super::sbt::TREE_GITIGNORE_REL as GITIGNORE_REL;
const OFFLINE_LINE: &str = "-Daether.offline.protocols=file";
const OFFLINE_KEY: &str = "-Daether.offline.protocols=";
const TAIL_KEY: &str = "-Dmaven.repo.local.tail=";
pub(crate) const TAIL_DIR: &str = "${session.rootDirectory}/.socket/vendor/maven2";
pub const REPO_ID: &str = "socket-patch-vendor";
pub const REPO_URL: &str = "file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2";
pub(crate) const BEGIN_MARKER: &str = "<!-- socket-patch:begin -->";
const END_MARKER: &str = "<!-- socket-patch:end -->";
/// Prefix of the comment tagging a pin: `<!-- socket-patch <uuid>: g:a:v -->`.
pub(crate) const PIN_TAG: &str = "<!-- socket-patch ";
/// Files whose presence makes a module directory a Maven root of its own,
/// which would move `${maven.multiModuleProjectDirectory}` under `cd module`.
const NESTED_MVN_FILES: &[&str] = &[
    "maven.config",
    "extensions.xml",
    "jvm.config",
    "wrapper/maven-wrapper.properties",
];
const SHAPE_UNSUPPORTED: &str = "vendor_jvm_shape_unsupported";
const UPSTREAM_UNAVAILABLE: &str = "vendor_jvm_upstream_unavailable";
const DEGRADED: &str = "vendor_jvm_degraded";

/// Whether the pom declares a `<modules>` or `<subprojects>` of the project
/// or of a profile (plugin configuration, comments and CDATA do not count).
pub fn declares_modules(pom: &str) -> bool {
    match Doc::parse(pom.to_string()) {
        Ok(doc) => doc.nodes.iter().any(|n| {
            matches!(n.name.as_str(), "modules" | "subprojects")
                && n.parent.is_some_and(|p| doc.is_model_root(p))
        }),
        // An unparseable pom: the masked scan decides, and the reactor
        // planner then refuses it as unreadable.
        Err(_) => {
            let (masked, _) = mask(pom);
            has_open_tag(&masked, "modules") || has_open_tag(&masked, "subprojects")
        }
    }
}

/// Whether the project's root pom heads a multi-module reactor: it
/// declares `<modules>`/`<subprojects>` ([`declares_modules`]), or Maven 4
/// discovers a subproject under it ([`may_discover_subprojects`] and a
/// direct subdirectory holding a `pom.xml`). The rule the reactor planner
/// builds by, for every caller that only asks "reactor or single pom?".
pub fn is_reactor_root(read: ReadFn<'_>, list: ListFn<'_>) -> bool {
    let Some(pom) = read(layout::POM_FILE) else {
        return false;
    };
    let pom = String::from_utf8_lossy(&pom);
    if declares_modules(&pom) {
        return true;
    }
    let config = read(MAVEN_CONFIG).map(|b| String::from_utf8_lossy(&b).into_owned());
    may_discover_subprojects(&pom, config.as_deref()) && !implicit_subprojects(list, "").is_empty()
}

/// Whether Maven 4 discovers the subprojects of the root `pom` on its own
/// ([`discovers_subprojects`]) under the root's `.mvn/maven.config`
/// (`maven_config`), which may turn discovery off. The subprojects are
/// then the direct subdirectories holding a `pom.xml`
/// ([`implicit_subprojects`]).
pub fn may_discover_subprojects(pom: &str, maven_config: Option<&str>) -> bool {
    discovery_on(&maven_config.map(cli_properties).unwrap_or_default())
        && Doc::parse(pom.to_string()).is_ok_and(|doc| discovers_subprojects(&doc))
}

/// [`implicit_subprojects`] of the root over a [`ProjectView`]: the direct
/// subdirectories (a link to one included) holding a regular `pom.xml`,
/// `.git` never, for the hosted engine and VEX discovery.
pub async fn implicit_subprojects_in(
    view: &crate::vendor::lock_inventory::ProjectView<'_>,
) -> Vec<String> {
    let mut out = Vec::new();
    for entry in view.list_dir("").await.unwrap_or_default() {
        if entry.name == GIT_DIR || !(entry.is_dir || view.is_symlink(&entry.name)) {
            continue;
        }
        if view.is_file(&format!("{}/{}", entry.name, layout::POM_FILE)) {
            out.push(entry.name);
        }
    }
    out
}

/// A checkout's git directory: never a subproject, whatever it holds (the
/// planner's reader refuses every path through it).
const GIT_DIR: &str = ".git";

/// Maven 4's opt-out among the `.mvn/maven.config` user properties, read
/// with Java's `Boolean.parseBoolean`: once set, anything but `true` turns
/// discovery off.
fn discovery_on(cli_props: &BTreeMap<String, String>) -> bool {
    cli_props
        .get(DISCOVER_SUBPROJECTS)
        .is_none_or(|v| v.eq_ignore_ascii_case("true"))
}

/// The tree directory of `c`'s suffixed version.
pub fn tree_dir(c: &Coords<'_>) -> String {
    c.tree_dir(TREE_ROOT, &c.suffixed_version())
}

/// The committed tree of `c`, as the [`JvmPatch`] bytes that re-plan it
/// unchanged: `(jar, upstream pom)`, the pom un-suffixed (what
/// [`suffixed_pom`] added for inherited versions stays, so the re-plan
/// needs no parent). `None` when a file is missing or the pom does not
/// carry the suffixed version.
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<(Vec<u8>, Vec<u8>)> {
    let sv = c.suffixed_version();
    let dir = tree_dir(c);
    let a = c.artifact_id;
    let jar = read(&format!("{dir}/{a}-{sv}.jar"))?;
    let pom = committed_pom(read, c)?;
    Some((jar, unsuffixed(&pom, c.version, &sv)?.into_bytes()))
}

/// The suffixed pom the tree of `c` serves, when it is UTF-8.
fn committed_pom(read: ReadFn<'_>, c: &Coords<'_>) -> Option<String> {
    let sv = c.suffixed_version();
    let path = format!("{}/{}-{sv}.pom", tree_dir(c), c.artifact_id);
    String::from_utf8(read(&path)?).ok()
}

/// A suffixed pom with `base` back in its `<version>`: the inverse of
/// [`suffix_maven_pom`] up to the references that one made literal. `None`
/// when the pom does not carry `suffixed`.
fn unsuffixed(pom: &str, base: &str, suffixed: &str) -> Option<String> {
    let children = scan_pom_project(pom)?;
    let version = scan_find(&children, "version")?;
    if pom[version.inner_start..version.inner_end].trim() != suffixed {
        return None;
    }
    Some(format!(
        "{}{base}{}",
        &pom[..version.inner_start],
        &pom[version.inner_end..]
    ))
}

/// Plan vendoring `patch` into the reactor rooted at `pom.xml`.
pub fn plan(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
) -> Result<JvmPlan, JvmRefusal> {
    plan_with_config(read, list, patch, true)
}

/// Plan with an explicit Maven config policy. A disabled policy is recorded for re-runs.
pub fn plan_with_config(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
    config_enabled: bool,
) -> Result<JvmPlan, JvmRefusal> {
    plan_with_external(read, list, patch, config_enabled, None)
}

/// [`plan_with_config`] that also weighs the management a local root's pin
/// would override from outside the checkout: imported BOMs and parents
/// resolved from a repository (#488). `external` holds those poms as the
/// caller could fetch them ([`external_poms_needed`] says which); `None`
/// skips the check (callers that plan only to probe a shape).
pub fn plan_with_external(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
    config_enabled: bool,
    external: Option<&ExternalPoms>,
) -> Result<JvmPlan, JvmRefusal> {
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    if !safe_coordinates(g, a, v) {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("unsafe maven coordinates `{g}:{a}:{v}`"),
        });
    }
    let sv = patch.suffixed_version();
    let suffixed_pom = suffixed_pom(patch)?;

    let reactor = Reactor::discover(read, list)?;
    let mut warnings = Vec::new();
    let wrapper = super::wrapper_version(read, "maven");
    if config_enabled && wrapper.is_none_or(|v| ((3, 9, 2)..(3, 9, 9)).contains(&v)) {
        warnings.push(degraded("maven_f_outside_root", "Maven 3.9.2–3.9.8 cannot interpolate the repository tail with -f from outside the project; run Maven from this root or vendor with --maven-config=none"));
    }
    if !config_enabled || wrapper.is_none_or(|v| v < (3, 9, 2)) {
        warnings.push(degraded("maven_mirror_of_all", "Maven before 3.9.2, or --maven-config=none, relies on the file repository; exclude socket-patch-vendor from mirrorOf=* in your Maven settings"));
    }

    let mut edits: BTreeMap<String, Vec<Edit>> = BTreeMap::new();
    let mut unpinned: BTreeSet<String> = BTreeSet::new();
    let mut managed_roots: BTreeSet<String> = BTreeSet::new();
    for rel in &reactor.scope {
        reactor.rewrite_declarations(
            rel,
            patch,
            &sv,
            &mut edits,
            &mut warnings,
            &mut unpinned,
            &mut managed_roots,
            &mut BTreeSet::new(),
        );
    }

    if let Some(external) = external {
        let lookup = |gav: &Gav| match external.get(gav) {
            Some(Some(bytes)) => Lookup::Found(bytes.as_slice()),
            _ => Lookup::Unavailable,
        };
        for root in reactor.wired_roots() {
            if unpinned.contains(&root) || managed_roots.contains(&root) {
                continue;
            }
            match reactor.external_management(&root, patch, &lookup) {
                Ok(None) => {}
                Ok(Some(conflict)) => {
                    warnings.push(degraded(
                        "conflicting_managed_version",
                        format!(
                            "{}: {}:{} is {} at {}, not {}; {root} is not pinned, so the build \
                             keeps resolving {}",
                            conflict.at,
                            patch.group_id,
                            patch.artifact_id,
                            conflict.how,
                            conflict.version,
                            patch.version,
                            conflict.version
                        ),
                    ));
                    unpinned.insert(root);
                }
                Err(Missing::Unresolved(why) | Missing::Need(_, why)) => {
                    warnings.push(degraded(
                        "management_unresolved",
                        format!(
                            "{why}, so whether a pin of {}:{}:{} in {root} would override a \
                             different managed version cannot be told; {root} is not pinned \
                             (resolve the project once, e.g. `mvn -q dependency:resolve`, \
                             and vendor again)",
                            patch.group_id, patch.artifact_id, patch.version
                        ),
                    ));
                    unpinned.insert(root);
                }
            }
        }
    }

    let banning = reactor
        .scope
        .iter()
        .find(|rel| bans_repositories(&reactor.poms[*rel].doc.masked));
    if let Some(rel) = banning {
        warnings.push(degraded(
            "maven_fallback_omitted",
            format!(
                "{rel} configures a maven-enforcer repository ban; no fallback repository is \
                 written, so the build needs Maven 3.9.2+ (maven.repo.local.tail)"
            ),
        ));
    }
    let mut records: Vec<WiringRecord> = Vec::new();
    for root in reactor.wired_roots() {
        let doc = &reactor.poms[&root].doc;
        let file_edits = edits.entry(root.clone()).or_default();
        let pinned = !unpinned.contains(&root) && !managed_roots.contains(&root);
        match pin_of(doc, patch) {
            Some(pin) if !pinned => file_edits.push(Edit::plain(pin.start, pin.end, "")),
            Some(pin) if pin.uuid == patch.uuid => {}
            Some(pin) => {
                records.push(adopt(&root, POM_FRAGMENT_KIND, "pin_section"));
                file_edits.push(pin_update(doc, &pin, patch));
            }
            None if pinned => {
                let (edit, section) = pin_edit(doc, patch, &sv);
                if !section {
                    records.push(adopt(&root, POM_FRAGMENT_KIND, "pin_section"));
                }
                file_edits.push(edit);
            }
            None => {}
        }
        if banning.is_none() {
            if has_fallback_repository(doc) {
                records.push(adopt(&root, POM_FRAGMENT_KIND, "repository"));
            } else {
                file_edits.push(repository_edit(doc));
            }
        }
    }
    if let Some(rel) = edits
        .iter()
        .filter(|(_, e)| !e.is_empty())
        .map(|(rel, _)| rel)
        .find(|rel| reactor.chain(rel).any(|p| reactor.poms[p].deploys()))
    {
        warnings.push(degraded(
            "publishes_suffixed_poms",
            format!("{rel} is deployed (<distributionManagement>) and will publish {sv}"),
        ));
    }

    let mut writes = Vec::new();
    for (rel, file_edits) in edits {
        if file_edits.is_empty() {
            continue;
        }
        let text = &reactor.poms[&rel].doc.text;
        records.extend(
            file_edits
                .iter()
                .filter_map(|e| e.record(&rel, text))
                .flatten(),
        );
        writes.push(FileWrite {
            rel,
            bytes: apply_edits(text, file_edits).into_bytes(),
            tree: false,
        });
    }
    if config_enabled {
        let (config, config_op) = merge_maven_config(read(MAVEN_CONFIG).as_deref());
        let action = match op_of_value(&config_op) {
            "config" if read(MAVEN_CONFIG).is_some() => WiringAction::Rewritten,
            _ => WiringAction::Added,
        };
        records.push(fragment(
            MAVEN_CONFIG,
            CONFIG_LINE_KIND,
            "config",
            action,
            None,
            config_op,
        ));
        writes.push(FileWrite {
            rel: MAVEN_CONFIG.to_string(),
            bytes: config,
            tree: false,
        });
    } else {
        if banning.is_some() {
            return Err(JvmRefusal { code: SHAPE_UNSUPPORTED, detail: "reason: maven_repository_banned: --maven-config=none requires the fallback file repository".into() });
        }
        records.push(fragment(
            MAVEN_CONFIG,
            CONFIG_LINE_KIND,
            "disabled",
            WiringAction::Added,
            None,
            json!({"op": "config_none"}),
        ));
    }
    records.push(owned_file(read, GITATTRIBUTES_REL, &mut writes));
    records.push(super::owned_file_with(
        read,
        GITIGNORE_REL,
        super::coursier_tree::GITIGNORE.as_bytes(),
        &mut writes,
    ));
    let (tree_dir, jar_rel, tree) = tree_writes(patch, &sv, suffixed_pom);
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

fn op_of_value(op: &Value) -> &str {
    op.get("op").and_then(Value::as_str).unwrap_or_default()
}

/// Plan the revert of `c`'s wiring. The pin and the rewritten
/// versions go now; `pin_section` shells once empty; the repository block,
/// the `maven.config` lines and the tree `.gitattributes` only once no pom
/// references another patch.
pub fn unplan(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
    records: &[WiringRecord],
) -> JvmUnplan {
    let sv = c.suffixed_version();
    let mut files: BTreeSet<String> = records
        .iter()
        .filter(|w| w.kind == POM_FRAGMENT_KIND)
        .map(|w| w.file.clone())
        .collect();
    let reactor = Reactor::discover(read, list).ok();
    if let Some(reactor) = &reactor {
        files.extend(reactor.scope.iter().cloned());
    }
    let mut before: BTreeMap<String, Option<String>> = files
        .into_iter()
        .filter_map(|rel| {
            let text = String::from_utf8(read(&rel)?).ok()?;
            Some((rel, Some(text)))
        })
        .collect();
    let mut after = before.clone();
    let mut drifted = Vec::new();
    for (rel, text) in after.iter_mut() {
        let Some(t) = text.as_mut() else { continue };
        let recs: Vec<&WiringRecord> = records
            .iter()
            .filter(|w| w.kind == POM_FRAGMENT_KIND && w.file == *rel)
            .collect();
        *t = cut_pin(rel, t, c, &recs, &mut drifted);
        *t = restore_versions(rel, t, c, &sv, &recs, reactor.as_ref(), &mut drifted);
        for w in recs
            .iter()
            .filter(|w| w.key.as_deref() == Some("pin_section"))
        {
            if let (Some(from), Some(to)) = (op_str(w, "from"), op_str(w, "to")) {
                if let Some(undone) = undo_replace(t, from, to) {
                    *t = undone;
                }
            }
        }
    }
    let mut still_wired = false;
    let mut live = false;
    for (rel, text) in &after {
        let Some(t) = text else { continue };
        let (masked, _) = mask(t);
        if t.contains(&pin_tag(c)) || masked.contains(&sv) {
            still_wired = true;
            if !drifted.iter().any(|d| d.starts_with(rel.as_str())) {
                drifted.push(format!("{rel} still references {sv}"));
            }
        }
        live |= references_other_patch(t, &masked, c);
    }
    live |= still_wired;
    if !live {
        for (rel, text) in after.iter_mut() {
            let Some(t) = text.as_mut() else { continue };
            let repo = records.iter().find(|w| {
                w.kind == POM_FRAGMENT_KIND
                    && w.file == *rel
                    && w.key.as_deref() == Some("repository")
                    && op_of(w) == "replace"
            });
            if let Some(w) = repo {
                let undone = match (op_str(w, "from"), op_str(w, "to")) {
                    (Some(from), Some(to)) => undo_replace(t, from, to),
                    _ => None,
                };
                if let Some(undone) = undone.or_else(|| cut_marked_block(t)) {
                    *t = undone;
                }
            }
        }
        if let Some(w) = records
            .iter()
            .find(|w| w.kind == CONFIG_LINE_KIND && w.file == MAVEN_CONFIG && op_of(w) == "config")
        {
            if let Some(text) = read(MAVEN_CONFIG).and_then(|b| String::from_utf8(b).ok()) {
                after.insert(MAVEN_CONFIG.to_string(), undo_config(&text, w));
                before.insert(MAVEN_CONFIG.to_string(), Some(text));
            }
        }
        for (rel, body) in [
            (GITATTRIBUTES_REL, TREE_GITATTRIBUTES),
            (GITIGNORE_REL, super::coursier_tree::GITIGNORE),
        ] {
            let created = records
                .iter()
                .any(|w| w.kind == OWNED_FILE_KIND && w.file == rel && op_of(w) == "create");
            if created && read(rel).as_deref() == Some(body.as_bytes()) {
                before.insert(rel.to_string(), Some(body.to_string()));
                after.insert(rel.to_string(), None);
            }
        }
    }
    JvmUnplan {
        changes: changes_between(&before, &after),
        drifted,
        still_wired,
    }
}

/// Whether a declaration Maven always reads wires `c`: a `<dependencies>`
/// or `<dependencyManagement>` entry of a reactor pom (outside
/// `<profiles>`, `<build>` and `<reporting>`) naming `c`'s main jar at its
/// suffixed version — literally or through a property the checkout defines
/// for the pom that declares it or one that inherits it, as Maven
/// interpolates after inheritance — or the root's pin. The liveness proof
/// `vex` needs for this layout: the suffixed version left only in a build
/// plugin's dependencies, a profile, an unused property, a comment or a
/// classifier copy does not put the patched jar on the project's
/// classpath.
pub fn wired_checked(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
) -> Result<bool, JvmRefusal> {
    Reactor::discover(read, list).map(|reactor| reactor.wires(c))
}

/// Whether a pom of the reactor still names `c`'s suffixed version
/// anywhere outside comments — a declaration, a build plugin's dependency,
/// a profile or a property: anything that may still resolve from the tree
/// (the maven.config tail serves plugin resolution too), so what the
/// `scan --prune` GC must not revert from under the build. Broader than
/// [`wired_checked`], which is what attests.
pub fn references_checked(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
) -> Result<bool, JvmRefusal> {
    let sv = c.suffixed_version();
    Reactor::discover(read, list).map(|reactor| {
        reactor
            .scope
            .iter()
            .any(|rel| reactor.poms[rel].doc.masked.contains(&sv))
    })
}

/// Refuse `plan` when, written over `read`, no pom of the reactor would
/// name `c`'s suffixed version: every declaration was left as is and no
/// root pinned (#513). Vendoring it would count the patch as applied while
/// the build keeps resolving the base; the refusal carries the degraded
/// reasons that left it unwired.
pub fn refuse_unwired(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
    plan: &JvmPlan,
) -> Result<(), JvmRefusal> {
    let planned = |rel: &str| match plan.writes.iter().find(|w| w.rel == rel) {
        Some(w) => Some(w.bytes.clone()),
        None => read(rel),
    };
    if wired_checked(&planned, list, c)? {
        return Ok(());
    }
    // Only the reasons that leave a declaration or a root alone; the
    // repository and config notes (and a mixed root's Gradle warnings)
    // say nothing about why the reactor is unwired.
    const UNWIRING: [&str; 7] = [
        "property_unresolved",
        "conflicting_literal_version",
        "conflicting_managed_version",
        "management_unresolved",
        "range",
        "coordinates_overridden",
        "classifier_declared",
    ];
    let why: Vec<&str> = plan
        .warnings
        .iter()
        .filter(|w| w.code == DEGRADED)
        .map(|w| w.detail.as_str())
        .filter(|d| {
            UNWIRING
                .iter()
                .any(|r| d.starts_with(&format!("reason: {r}: ")))
        })
        .collect();
    let why = if why.is_empty() {
        "no declaration or pin of the reactor can take it".to_string()
    } else {
        why.join("; ")
    };
    Err(JvmRefusal {
        code: SHAPE_UNSUPPORTED,
        detail: format!(
            "reason: nothing_wired: no pom of the reactor would build {}:{}:{}, so Maven \
             keeps resolving {} ({why})",
            c.group_id,
            c.artifact_id,
            c.suffixed_version(),
            c.version
        ),
    })
}

/// [`wired_checked`], and no declaration of `c`'s g:a is left at a version
/// that may still read the base: the base itself, as a module or
/// dependency added since vendoring declares it (#584), or a `${...}` the
/// checkout does not define or that an inheriting pom or a profile moves
/// (#513, #459), a version-less one whose local root is left unpinned, or
/// an executable classifier or type copy of the GA (`tests`, `test-jar`, a
/// native build) the pin does not retarget. Such a module builds the
/// unpatched jar, so `vex` must not attest.
pub fn attestable_checked(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
) -> Result<bool, JvmRefusal> {
    Ok(unattestable_checked(read, list, c)?.is_none())
}

/// Why [`attestable_checked`] fails for `c`, `None` when it passes.
pub fn unattestable_checked(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
) -> Result<Option<String>, JvmRefusal> {
    let sv = c.suffixed_version();
    let ga = format!("{}:{}", c.group_id, c.artifact_id);
    let reactor = Reactor::discover(read, list)?;
    if !reactor.wires(c) {
        return Ok(Some(format!(
            "no dependency or dependencyManagement declaration Maven always reads names \
             {ga}:{sv}"
        )));
    }
    let patch = JvmPatch {
        group_id: c.group_id,
        artifact_id: c.artifact_id,
        version: c.version,
        uuid: c.uuid,
        jar: &[],
        upstream_pom: &[],
        upstream_parents: None,
        upstream_module: None,
        extra_artifacts: &[],
        patched_members: &[],
    };
    let mut edits = BTreeMap::new();
    let mut uncertain = BTreeSet::new();
    for rel in &reactor.scope {
        reactor.rewrite_declarations(
            rel,
            &patch,
            &sv,
            &mut edits,
            &mut Vec::new(),
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            &mut uncertain,
        );
    }
    let mut at: Vec<String> = edits.into_keys().collect();
    at.extend(uncertain);
    Ok((!at.is_empty()).then(|| {
        format!(
            "{} may still build {ga}:{} rather than {sv}: a base version declared since \
             vendoring, a version a property, profile or unpinned root may move, or an \
             executable classifier or type copy the pin does not retarget",
            at.join(", "),
            c.version
        )
    }))
}

/// `<!-- socket-patch <uuid>:` — the start of `c`'s pin comment.
fn pin_tag(c: &Coords<'_>) -> String {
    format!("{PIN_TAG}{}:", c.uuid)
}

/// Whether `text` (masked: `masked`) holds another patch's pin comment or,
/// outside comments, its suffixed version.
fn references_other_patch(text: &str, masked: &str, c: &Coords<'_>) -> bool {
    let tags = text.match_indices(PIN_TAG).any(|(at, _)| {
        let rest = &text[at + PIN_TAG.len()..];
        rest.get(..36).is_some_and(|uuid| uuid != c.uuid) && rest.get(36..37) == Some(":")
    });
    let hex8 = c.hex8();
    tags || masked.match_indices("-socket.").any(|(at, _)| {
        masked.get(at + 8..at + 16).is_some_and(|h| {
            h != hex8
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

/// `text` with `c`'s pin cut: the recorded text when it is there once, else
/// the tagged `<dependency>` by its lines.
fn cut_pin(
    rel: &str,
    text: &str,
    c: &Coords<'_>,
    recs: &[&WiringRecord],
    drifted: &mut Vec<String>,
) -> String {
    if !text.contains(&pin_tag(c)) {
        return text.to_string();
    }
    let key = format!("pin:{}:{}", c.group_id, c.artifact_id);
    if let Some(p) = recs
        .iter()
        .find(|w| w.key.as_deref() == Some(key.as_str()))
        .and_then(|w| op_str(w, "text"))
    {
        if let Some(cut) = undo_replace(text, "", p) {
            return cut;
        }
    }
    let Ok(doc) = Doc::parse(text.to_string()) else {
        drifted.push(format!(
            "{rel} is not parseable; its socket-patch pin was left alone"
        ));
        return text.to_string();
    };
    let mut pins: Vec<Pin> = doc
        .declarations()
        .into_iter()
        .filter_map(|dep| doc.pin_at(dep))
        .filter(|p| p.uuid == c.uuid)
        .collect();
    match pins.pop() {
        Some(pin) if pins.is_empty() => {
            format!("{}{}", &text[..pin.start], &text[pin.end..])
        }
        _ => {
            drifted.push(format!(
                "{rel}: the socket-patch pin comment for {} no longer tags one <dependency>",
                c.uuid
            ));
            text.to_string()
        }
    }
}

/// `text` with every g:a declaration at `sv` back at its recorded original
/// (else the base version). `reactor` interpolates `${...}` coordinates in
/// `rel`'s context, as the plan matched them.
fn restore_versions(
    rel: &str,
    text: &str,
    c: &Coords<'_>,
    sv: &str,
    recs: &[&WiringRecord],
    reactor: Option<&Reactor>,
    drifted: &mut Vec<String>,
) -> String {
    if !text.contains(sv) {
        return text.to_string();
    }
    let Ok(doc) = Doc::parse(text.to_string()) else {
        drifted.push(format!(
            "{rel} is not parseable; its {sv} versions were left alone"
        ));
        return text.to_string();
    };
    let resolve = |v: &str| {
        reactor
            .filter(|r| r.poms.contains_key(rel))
            .and_then(|r| r.interpolate(rel, v))
    };
    let mut edits = Vec::new();
    for (dep, key) in doc.keyed_declarations(c.group_id, c.artifact_id, &resolve) {
        let Some(version) = doc.child(dep, "version") else {
            continue;
        };
        if doc.text_of(version) != sv {
            continue;
        }
        let original = recs
            .iter()
            .find(|w| w.key.as_deref() == Some(key.as_str()))
            .and_then(|w| w.original.as_ref())
            .and_then(Value::as_str)
            .unwrap_or(c.version);
        let span = doc.value_span(version);
        edits.push(Edit::plain(span.start, span.end, original));
    }
    apply_edits(text, edits)
}

/// `text` with the marked fallback repository cut by its lines.
fn cut_marked_block(text: &str) -> Option<String> {
    let begin = text.find(BEGIN_MARKER)?;
    let end = begin + text[begin..].find(END_MARKER)? + END_MARKER.len();
    if !text[begin..end].contains(&format!("<id>{REPO_ID}</id>")) {
        return None;
    }
    let (start, end) = line_span(text, begin, end);
    Some(format!("{}{}", &text[..start], &text[end..]))
}

/// `[start, end)` widened to whole lines when only blanks surround it there.
fn line_span(text: &str, start: usize, end: usize) -> (usize, usize) {
    let ls = text[..start].rfind('\n').map_or(0, |n| n + 1);
    let lead_blank = text[ls..start].bytes().all(|b| b == b' ' || b == b'\t');
    let rest = &text[end..];
    let trail = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let nl = match &rest.as_bytes()[trail..] {
        [b'\r', b'\n', ..] => Some(2),
        [b'\n', ..] => Some(1),
        _ => None,
    };
    match (lead_blank, nl) {
        (true, Some(n)) => (ls, end + trail + n),
        _ => (start, end),
    }
}

/// Undo a `config` op: rewritten lines back, appended text cut, a file
/// vendor created and left empty deleted (`None`).
fn undo_config(text: &str, w: &WiringRecord) -> Option<String> {
    let op = w.new.as_ref();
    let mut out = text.to_string();
    for pair in op
        .and_then(|o| o.get("rewritten"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(from), Some(to)) = (
            pair.get("from").and_then(Value::as_str),
            pair.get("to").and_then(Value::as_str),
        ) else {
            continue;
        };
        out = rewrite_line(&out, to, from);
    }
    if let Some(appended) = op_str(w, "appended").filter(|a| !a.is_empty()) {
        match out.strip_suffix(appended) {
            Some(cut) => out = cut.to_string(),
            None => {
                for line in appended.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    out = remove_last_line(&out, line);
                }
            }
        }
    }
    let created = op
        .and_then(|o| o.get("created"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (!(created && out.trim().is_empty())).then_some(out)
}

/// `text` with the last line whose body is `from` rewritten to `to`.
fn rewrite_line(text: &str, from: &str, to: &str) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let Some(i) = lines
        .iter()
        .rposition(|l| l.trim_end_matches(['\r', '\n']) == from)
    else {
        return text.to_string();
    };
    let ending = &lines[i][from.len()..];
    let mut out: String = lines[..i].concat();
    out.push_str(to);
    out.push_str(ending);
    out.push_str(&lines[i + 1..].concat());
    out
}

/// `text` without the last whole line whose trimmed body is `line`.
pub(crate) fn remove_last_line(text: &str, line: &str) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    match lines.iter().rposition(|l| l.trim() == line) {
        Some(i) => format!("{}{}", lines[..i].concat(), lines[i + 1..].concat()),
        None => text.to_string(),
    }
}

fn shape_refusal(reason: &str, detail: impl std::fmt::Display) -> JvmRefusal {
    JvmRefusal {
        code: SHAPE_UNSUPPORTED,
        detail: format!("reason: {reason}: {detail}"),
    }
}

fn degraded(reason: &str, detail: impl std::fmt::Display) -> JvmWarning {
    JvmWarning {
        code: DEGRADED,
        detail: format!("reason: {reason}: {detail}"),
    }
}

/// Whether an ancestor reactor owns the requested pom. Used to reject partial vendoring.
pub fn contains_module(read: ReadFn<'_>, list: ListFn<'_>, rel: &str) -> bool {
    Reactor::discover(read, list).is_ok_and(|r| r.reactor.iter().any(|p| p == rel))
}

pub(crate) type Gav = (String, String, String);

/// `(groupId, artifactId, version, relativePath)` of a pom's `<parent>`.
pub(crate) type PomParent = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// One `<dependency>` of a [`PomModel`], as written (no interpolation).
#[derive(Debug, Clone)]
pub(crate) struct PomDecl {
    pub group: String,
    pub artifact: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    pub optional: bool,
    pub kind: Option<String>,
}

/// The parts of a pom a dependency-graph walk reads: coordinates, parent,
/// `<properties>`, `<dependencies>`, `<dependencyManagement>` and modules
/// of the project (and of its profiles when asked). Plugin dependencies and
/// exclusions are never declarations.
#[derive(Debug, Clone)]
pub(crate) struct PomModel {
    pub group: Option<String>,
    pub artifact: Option<String>,
    pub version: Option<String>,
    /// `(groupId, artifactId, version, relativePath)` of `<parent>`.
    pub parent: Option<PomParent>,
    pub props: BTreeMap<String, String>,
    pub deps: Vec<PomDecl>,
    pub managed: Vec<PomDecl>,
    pub modules: Vec<String>,
    /// `(groupId, artifactId, version)` of
    /// `<distributionManagement><relocation>`: a missing part keeps the
    /// pom's own.
    pub relocation: Option<(Option<String>, Option<String>, Option<String>)>,
}

/// [`PomModel`] of `text`; `include_profiles` adds every profile's
/// dependencies, management and modules (an over-approximation of the
/// active ones).
pub(crate) fn pom_model(text: &str, include_profiles: bool) -> Result<PomModel, String> {
    let doc = Doc::parse(text.to_string())?;
    let project = doc.project;
    let mut roots = vec![project];
    if include_profiles {
        if let Some(profiles) = doc.child(project, "profiles") {
            roots.extend(doc.children(profiles, "profile"));
        }
    }
    let decl = |dep: usize| -> Option<PomDecl> {
        Some(PomDecl {
            group: doc.child_text(dep, "groupId")?,
            artifact: doc.child_text(dep, "artifactId")?,
            version: doc.child_text(dep, "version").filter(|v| !v.is_empty()),
            scope: doc.child_text(dep, "scope").filter(|v| !v.is_empty()),
            optional: doc.child_text(dep, "optional").as_deref() == Some("true"),
            kind: doc.child_text(dep, "type").filter(|v| !v.is_empty()),
        })
    };
    let (mut deps, mut managed, mut modules) = (Vec::new(), Vec::new(), Vec::new());
    for &root in &roots {
        if let Some(list) = doc.child(root, "dependencies") {
            deps.extend(doc.children(list, "dependency").filter_map(decl));
        }
        if let Some(list) = doc
            .child(root, "dependencyManagement")
            .and_then(|dm| doc.child(dm, "dependencies"))
        {
            managed.extend(doc.children(list, "dependency").filter_map(decl));
        }
        for (list, item) in [("modules", "module"), ("subprojects", "subproject")] {
            if let Some(list) = doc.child(root, list) {
                modules.extend(doc.children(list, item).map(|m| doc.text_of(m)));
            }
        }
    }
    let mut props = BTreeMap::new();
    if let Some(p) = doc.child(project, "properties") {
        for &c in &doc.nodes[p].children {
            props.insert(doc.nodes[c].name.clone(), doc.text_of(c));
        }
    }
    Ok(PomModel {
        group: doc.child_text(project, "groupId"),
        artifact: doc.child_text(project, "artifactId"),
        version: doc.child_text(project, "version"),
        parent: doc.child(project, "parent").map(|p| {
            (
                doc.child_text(p, "groupId"),
                doc.child_text(p, "artifactId"),
                doc.child_text(p, "version"),
                doc.child(p, "relativePath").map(|r| doc.text_of(r)),
            )
        }),
        props,
        deps,
        managed,
        modules,
        relocation: doc
            .child(project, "distributionManagement")
            .and_then(|dm| doc.child(dm, "relocation"))
            .map(|r| {
                let part = |name| doc.child_text(r, name).filter(|v| !v.is_empty());
                (part("groupId"), part("artifactId"), part("version"))
            }),
    })
}

/// Poms from outside the checkout (parents, imported BOMs) by GAV, as a
/// caller fetched them: `None` when looked up and unavailable.
pub type ExternalPoms = BTreeMap<(String, String, String), Option<Vec<u8>>>;

/// Most external poms one plan reads (a BOM graph is shallow; Spring Boot's
/// imports a few dozen).
const MAX_EXTERNAL_POMS: usize = 256;
/// Deepest parent chain / import nesting followed outside the checkout.
const MAX_EXTERNAL_DEPTH: usize = 16;

/// An external pom as a lookup sees it.
enum Lookup<'b> {
    Found(&'b [u8]),
    /// Looked up and unavailable (in no local cache, not fetchable).
    Unavailable,
    /// Not looked up yet: [`external_poms_needed`] collects these.
    Unknown,
}

/// Why external management could not be decided: an unresolvable value,
/// or a pom (with what it was needed for) that is unavailable or not yet
/// looked up.
enum Missing {
    Unresolved(String),
    Need(Gav, String),
}

/// Management from outside the checkout that disagrees with the patch.
struct ManagedConflict {
    /// The reactor pom whose effective model it is.
    at: String,
    /// How it is managed (`managed by the imported BOM g:a:v`, …).
    how: String,
    version: String,
}

/// The external poms [`plan_with_external`] still needs for `patch`, given
/// `known` (fetched or found unavailable): call until it returns nothing,
/// fetching each, then plan. Empty when the reactor cannot be read (the
/// plan refuses it on its own).
pub fn external_poms_needed(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    patch: &JvmPatch<'_>,
    known: &ExternalPoms,
) -> Vec<Gav> {
    let Ok(reactor) = Reactor::discover(read, list) else {
        return Vec::new();
    };
    if known.len() >= MAX_EXTERNAL_POMS {
        return Vec::new();
    }
    let lookup = |gav: &Gav| match known.get(gav) {
        Some(Some(bytes)) => Lookup::Found(bytes.as_slice()),
        Some(None) => Lookup::Unavailable,
        None => Lookup::Unknown,
    };
    let mut need = Vec::new();
    for root in reactor.wired_roots() {
        if let Err(Missing::Need(gav, _)) = reactor.external_management(&root, patch, &lookup) {
            if !known.contains_key(&gav) && !need.contains(&gav) {
                need.push(gav);
            }
        }
    }
    need
}

/// One pom outside the checkout, parsed.
struct ExternalPom {
    gav: Gav,
    pom: Pom,
}

impl Reactor {
    /// Management of `patch`'s g:a that a pin in local root `root` would
    /// override and that does not manage it at the patch's base version:
    /// for each pom resolving through `root` whose own chain declares no
    /// version for g:a in the checkout, the version an external parent
    /// chain declares or manages, else the first imported BOM (the
    /// project's own imports, then the external parents') that manages it.
    /// `Ok(None)` when nothing outside the checkout manages g:a, or only at
    /// the base version.
    fn external_management<'b>(
        &self,
        root: &str,
        patch: &JvmPatch<'_>,
        lookup: &dyn Fn(&Gav) -> Lookup<'b>,
    ) -> Result<Option<ManagedConflict>, Missing> {
        let (g, a) = (patch.group_id, patch.artifact_id);
        let ext_chain = self.external_chain(root, lookup)?;
        // Every module under this root must agree: one module whose
        // management already resolves the base version says nothing about
        // the next, which may interpolate a different one the root pin would
        // override.
        'modules: for rel in self.scope.iter().filter(|rel| self.local_root(rel) == root) {
            let locally_versioned = self.chain(rel).any(|p| {
                let doc = &self.poms[p].doc;
                self.keyed_declarations(p, g, a)
                    .iter()
                    .any(|(dep, _)| doc.child(*dep, "version").is_some())
            });
            if locally_versioned {
                continue;
            }
            // Maven interpolates after inheritance: the reactor pom's own
            // chain overrides an external parent's properties.
            let props = |name: &str| -> Option<String> {
                self.lookup(rel, name).or_else(|| {
                    ext_chain
                        .iter()
                        .find_map(|e| e.pom.props.get(name).cloned())
                })
            };
            let resolve = |value: &str, what: &str| -> Result<String, Missing> {
                interpolate_strict(value, &props).ok_or_else(|| {
                    Missing::Unresolved(format!("{rel}: {what} {value} is not defined"))
                })
            };
            // An external parent's own declaration or management of g:a.
            for ext in &ext_chain {
                let doc = &ext.pom.doc;
                let (eg, ea, ev) = &ext.gav;
                if let Some((dep, managed)) = jar_declaration(doc, g, a) {
                    let Some(version) = doc.child_text(dep, "version") else {
                        continue;
                    };
                    let v = resolve(
                        &version,
                        &format!("{g}:{a} version in parent {eg}:{ea}:{ev}"),
                    )?;
                    // An inherited `<dependencies>` literal is never
                    // overridden by management, so a pin cannot reach it
                    // even at the base version.
                    if managed && is_base_like(&v, patch.version) {
                        continue 'modules;
                    }
                    let how = if managed {
                        "managed by"
                    } else {
                        "declared (a literal no pin overrides) by"
                    };
                    return Ok(Some(ManagedConflict {
                        at: rel.clone(),
                        how: format!("{how} the parent {eg}:{ea}:{ev}"),
                        version: v,
                    }));
                }
            }
            // Imported BOMs: the reactor chain's own (nearest first), then
            // the external parents'.
            let mut imports: Vec<(Gav, String)> = Vec::new();
            for p in self.chain(rel) {
                for (ig, ia, iv) in imports_of(&self.poms[p].doc) {
                    let what = format!("the BOM import {ig}:{ia} in {p}");
                    let gav = (
                        resolve(&ig, &what)?,
                        resolve(&ia, &what)?,
                        resolve(&iv, &what)?,
                    );
                    imports.push((gav, p.to_string()));
                }
            }
            for ext in &ext_chain {
                for (ig, ia, iv) in imports_of(&ext.pom.doc) {
                    let (eg, ea, ev) = &ext.gav;
                    let what = format!("the BOM import {ig}:{ia} in parent {eg}:{ea}:{ev}");
                    let gav = (
                        resolve(&ig, &what)?,
                        resolve(&ia, &what)?,
                        resolve(&iv, &what)?,
                    );
                    imports.push((gav, format!("{eg}:{ea}:{ev}")));
                }
            }
            for (bom, _) in &imports {
                let mut seen = BTreeSet::new();
                if let Some(v) = bom_manages(bom, g, a, lookup, &mut seen, 0)? {
                    if is_base_like(&v, patch.version) {
                        continue 'modules;
                    }
                    let (bg, ba, bv) = bom;
                    return Ok(Some(ManagedConflict {
                        at: rel.clone(),
                        how: format!("managed by the imported BOM {bg}:{ba}:{bv}"),
                        version: v,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// The parents of local root `root` outside the checkout, nearest
    /// first.
    fn external_chain<'b>(
        &self,
        root: &str,
        lookup: &dyn Fn(&Gav) -> Lookup<'b>,
    ) -> Result<Vec<ExternalPom>, Missing> {
        let mut chain: Vec<ExternalPom> = Vec::new();
        let mut parent = self.poms[root].parent.as_ref().map(|p| {
            let local = |v: &Option<String>| v.as_deref().and_then(|v| self.interpolate(root, v));
            (local(&p.group), local(&p.artifact), local(&p.version))
        });
        while let Some((pg, pa, pv)) = parent {
            let (Some(pg), Some(pa), Some(pv)) = (pg, pa, pv) else {
                return Err(Missing::Unresolved(format!(
                    "a parent of {root} has no literal groupId/artifactId/version"
                )));
            };
            if chain.len() >= MAX_EXTERNAL_DEPTH {
                return Err(Missing::Unresolved(format!(
                    "the parents of {root} nest too deep"
                )));
            }
            let gav = (pg, pa, pv);
            let pom = fetch_external(&gav, lookup, &format!("the parent of {root}"))?;
            parent = pom
                .parent
                .as_ref()
                .map(|p| (p.group.clone(), p.artifact.clone(), p.version.clone()));
            chain.push(ExternalPom { gav, pom });
        }
        Ok(chain)
    }
}

/// `gav` parsed, or why not.
fn fetch_external<'b>(
    gav: &Gav,
    lookup: &dyn Fn(&Gav) -> Lookup<'b>,
    role: &str,
) -> Result<Pom, Missing> {
    let (g, a, v) = gav;
    let named = format!("{role} {g}:{a}:{v}");
    if !safe_coordinates(g, a, v) {
        return Err(Missing::Unresolved(format!(
            "{named} has unsafe coordinates"
        )));
    }
    match lookup(gav) {
        Lookup::Found(bytes) => Pom::parse(&format!("{g}:{a}:{v}"), bytes.to_vec())
            .map_err(|e| Missing::Unresolved(format!("{named} is unreadable ({})", e.detail))),
        // A copy in a local cache is used whatever a registry says of it,
        // so this is a pom neither holds.
        Lookup::Unavailable => Err(Missing::Need(
            gav.clone(),
            format!(
                "{named} is in no local Maven repository (nor, vendoring online, on the registry)"
            ),
        )),
        Lookup::Unknown => Err(Missing::Need(
            gav.clone(),
            format!("{named} is not read yet"),
        )),
    }
}

/// The top-level declaration of g:a's main jar in `doc`: its
/// `<dependencyManagement>` entry (`true`) before a `<dependencies>` one.
fn jar_declaration(doc: &Doc, g: &str, a: &str) -> Option<(usize, bool)> {
    let is_jar = |dep: usize| {
        doc.child_text(dep, "groupId").as_deref() == Some(g)
            && doc.child_text(dep, "artifactId").as_deref() == Some(a)
            && doc.is_main_jar(dep)
    };
    let managed = doc
        .child(doc.project, "dependencyManagement")
        .and_then(|dm| doc.child(dm, "dependencies"))
        .and_then(|deps| doc.children(deps, "dependency").find(|d| is_jar(*d)));
    if let Some(dep) = managed {
        return Some((dep, true));
    }
    doc.child(doc.project, "dependencies")
        .and_then(|deps| doc.children(deps, "dependency").find(|d| is_jar(*d)))
        .map(|dep| (dep, false))
}

/// The raw `(groupId, artifactId, version)` of each
/// `<scope>import</scope>` BOM in `doc`, in order: the project's own, then
/// each profile's (Maven appends an active profile's management after the
/// project's). Profile activation is not evaluated, so every profile counts:
/// a BOM that might apply is weighed rather than letting a root pin override
/// it.
fn imports_of(doc: &Doc) -> Vec<(String, String, String)> {
    let profiles = doc
        .child(doc.project, "profiles")
        .into_iter()
        .flat_map(|ps| doc.children(ps, "profile"));
    std::iter::once(doc.project)
        .chain(profiles)
        .filter_map(|model| {
            doc.child(model, "dependencyManagement")
                .and_then(|dm| doc.child(dm, "dependencies"))
        })
        .flat_map(|deps| doc.children(deps, "dependency"))
        .filter(|d| {
            doc.child_text(*d, "scope").as_deref() == Some("import")
                && doc.child_text(*d, "type").as_deref() == Some("pom")
        })
        .map(|d| {
            (
                doc.child_text(d, "groupId").unwrap_or_default(),
                doc.child_text(d, "artifactId").unwrap_or_default(),
                doc.child_text(d, "version").unwrap_or_default(),
            )
        })
        .collect()
}

/// The version BOM `bom` manages g:a at, in the BOM's own effective model
/// (its parents' management and properties, then its own imports); `None`
/// when it does not manage g:a.
fn bom_manages<'b>(
    bom: &Gav,
    g: &str,
    a: &str,
    lookup: &dyn Fn(&Gav) -> Lookup<'b>,
    seen: &mut BTreeSet<Gav>,
    depth: usize,
) -> Result<Option<String>, Missing> {
    if !seen.insert(bom.clone()) {
        return Ok(None);
    }
    if depth > MAX_EXTERNAL_DEPTH || seen.len() > MAX_EXTERNAL_POMS {
        return Err(Missing::Unresolved(format!(
            "the BOM imports under {}:{}:{} nest too deep",
            bom.0, bom.1, bom.2
        )));
    }
    // The BOM and its parents, nearest first.
    let mut chain: Vec<ExternalPom> = Vec::new();
    let mut next = Some(bom.clone());
    while let Some(gav) = next {
        if chain.len() >= MAX_EXTERNAL_DEPTH {
            return Err(Missing::Unresolved(format!(
                "the parents of the BOM {}:{}:{} nest too deep",
                bom.0, bom.1, bom.2
            )));
        }
        let role = if chain.is_empty() {
            "the imported BOM".to_string()
        } else {
            format!("a parent of the imported BOM {}:{}:{}", bom.0, bom.1, bom.2)
        };
        let pom = fetch_external(&gav, lookup, &role)?;
        next = pom
            .parent
            .as_ref()
            .map(|p| (p.group.clone(), p.artifact.clone(), p.version.clone()))
            .and_then(|(pg, pa, pv)| Some((pg?, pa?, pv?)));
        chain.push(ExternalPom { gav, pom });
    }
    let props = |name: &str| -> Option<String> {
        let own = &chain[0].pom;
        match name {
            "project.version" | "pom.version" | "version" => {
                return own.effective_version().map(str::to_string)
            }
            "project.groupId" => return own.effective_group().map(str::to_string),
            "project.parent.version" => return own.parent.as_ref()?.version.clone(),
            _ => {}
        }
        chain.iter().find_map(|e| e.pom.props.get(name).cloned())
    };
    let resolve = |value: &str| -> Result<String, Missing> {
        interpolate_strict(value, &props).ok_or_else(|| {
            Missing::Unresolved(format!(
                "the BOM {}:{}:{} manages {g}:{a} at {value}, which it does not define",
                bom.0, bom.1, bom.2
            ))
        })
    };
    for ext in &chain {
        if let Some((dep, true)) = jar_declaration(&ext.pom.doc, g, a) {
            if let Some(version) = ext.pom.doc.child_text(dep, "version") {
                return resolve(&version).map(Some);
            }
        }
    }
    for ext in &chain {
        for (ig, ia, iv) in imports_of(&ext.pom.doc) {
            let gav = (resolve(&ig)?, resolve(&ia)?, resolve(&iv)?);
            if let Some(v) = bom_manages(&gav, g, a, lookup, seen, depth + 1)? {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

/// Metadata needed to verify upstream parents and imported BOMs in Gradle.
pub(crate) struct MetadataModel {
    pub parent: Option<Gav>,
    pub imports: Vec<Gav>,
    pub properties: BTreeMap<String, String>,
}

pub(crate) fn metadata_model(
    bytes: &[u8],
    inherited: &BTreeMap<String, String>,
    descendant: &BTreeMap<String, String>,
    include_imports: bool,
) -> Result<MetadataModel, String> {
    let pom = Pom::parse("upstream.pom", bytes.to_vec()).map_err(|e| e.detail)?;
    let mut properties = inherited.clone();
    properties.extend(pom.props.clone());
    properties.extend(descendant.clone());
    for (key, value) in [
        ("project.version", pom.effective_version()),
        ("project.groupId", pom.effective_group()),
        ("project.artifactId", pom.artifact.as_deref()),
    ] {
        if let Some(v) = value {
            properties.insert(key.into(), v.into());
        }
    }
    let resolve = |value: &str| -> Result<String, String> {
        let mut value = value.to_string();
        for _ in 0..MAX_INTERPOLATION_DEPTH {
            let Some(start) = value.find("${") else {
                return Ok(value);
            };
            let end = value[start..]
                .find('}')
                .map(|n| start + n)
                .ok_or("invalid metadata property")?;
            let key = &value[start + 2..end];
            let replacement = properties
                .get(key)
                .ok_or_else(|| format!("unresolved metadata property {key}"))?;
            value.replace_range(start..=end, replacement);
        }
        Err("cyclic metadata property".into())
    };
    let gav = |g: Option<String>, a: Option<String>, v: Option<String>| -> Result<Gav, String> {
        let (g, a, v) = (
            resolve(&g.ok_or("missing groupId")?)?,
            resolve(&a.ok_or("missing artifactId")?)?,
            resolve(&v.ok_or("missing version")?)?,
        );
        if !safe_coordinates(&g, &a, &v) {
            return Err("unsafe metadata coordinates".into());
        }
        Ok((g, a, v))
    };
    let parent = pom
        .parent
        .as_ref()
        .map(|p| gav(p.group.clone(), p.artifact.clone(), p.version.clone()))
        .transpose()?;
    let mut imports = Vec::new();
    if include_imports {
        for dep in pom.doc.declarations() {
            if pom.doc.is_top_level_managed(dep)
                && pom.doc.child_text(dep, "scope").as_deref() == Some("import")
                && pom.doc.child_text(dep, "type").as_deref() == Some("pom")
            {
                imports.push(gav(
                    pom.doc.child_text(dep, "groupId"),
                    pom.doc.child_text(dep, "artifactId"),
                    pom.doc.child_text(dep, "version"),
                )?);
            }
        }
    }
    Ok(MetadataModel {
        parent,
        imports,
        properties,
    })
}

// ── reactor discovery ─────────────────────────────────────────────

/// One loaded pom.
struct Pom {
    doc: Doc,
    /// Directory of the pom (`""` for the project root).
    dir: String,
    group: Option<String>,
    artifact: Option<String>,
    version: Option<String>,
    packaging: String,
    parent: Option<ParentRef>,
    /// Top-level `<properties>` (profiles excluded).
    props: BTreeMap<String, String>,
    /// Each profile's id and `<properties>`, in document order.
    profile_props: Vec<(String, BTreeMap<String, String>)>,
    /// Model 4.1.0 (Maven 4): omitted parent coordinates are inferred
    /// from the pom at the relative path.
    infers_parent: bool,
    /// Maven 4 discovers this pom's subprojects itself: see
    /// [`discovers_subprojects`].
    discovers_subprojects: bool,
}

/// A pom and one of its profiles' `<properties>`.
type Overlay<'a> = (&'a str, &'a BTreeMap<String, String>);

struct ParentRef {
    group: Option<String>,
    artifact: Option<String>,
    version: Option<String>,
    /// `None` = the default `../pom.xml`; `Some("")` = `<relativePath/>`
    /// (the parent is remote).
    relative_path: Option<String>,
}

impl Pom {
    fn parse(rel: &str, bytes: Vec<u8>) -> Result<Pom, JvmRefusal> {
        let text = String::from_utf8(bytes)
            .map_err(|_| shape_refusal("build_file_unreadable", format!("{rel} is not UTF-8")))?;
        let doc = Doc::parse(text)
            .map_err(|e| shape_refusal("build_file_unreadable", format!("{rel}: {e}")))?;
        let project = doc.project;
        let parent = doc.child(project, "parent").map(|p| ParentRef {
            group: doc.child_text(p, "groupId"),
            artifact: doc.child_text(p, "artifactId"),
            version: doc.child_text(p, "version"),
            relative_path: doc.child(p, "relativePath").map(|r| doc.text_of(r)),
        });
        let properties_of = |model: usize| {
            let mut props = BTreeMap::new();
            if let Some(p) = doc.child(model, "properties") {
                for &c in &doc.nodes[p].children {
                    props.insert(doc.nodes[c].name.clone(), doc.text_of(c));
                }
            }
            props
        };
        let props = properties_of(project);
        let profile_props = doc
            .child(project, "profiles")
            .into_iter()
            .flat_map(|ps| doc.children(ps, "profile"))
            .map(|p| {
                let id = doc.child_text(p, "id").unwrap_or_else(|| "default".into());
                (id, properties_of(p))
            })
            .filter(|(_, props)| !props.is_empty())
            .collect();
        let infers_parent = doc.child_text(project, "modelVersion").as_deref() == Some("4.1.0")
            || doc.masked.contains("maven.apache.org/POM/4.1.0");
        Ok(Pom {
            infers_parent,
            discovers_subprojects: discovers_subprojects(&doc),
            dir: rel.rsplit_once('/').map_or("", |(d, _)| d).to_string(),
            group: doc.child_text(project, "groupId"),
            artifact: doc.child_text(project, "artifactId"),
            version: doc.child_text(project, "version"),
            packaging: doc
                .child_text(project, "packaging")
                .unwrap_or_else(|| "jar".to_string()),
            parent,
            props,
            profile_props,
            doc,
        })
    }

    fn effective_group(&self) -> Option<&str> {
        self.group
            .as_deref()
            .or_else(|| self.parent.as_ref()?.group.as_deref())
    }

    fn effective_version(&self) -> Option<&str> {
        self.version
            .as_deref()
            .or_else(|| self.parent.as_ref()?.version.as_deref())
    }

    /// Whether the pom declares any dependency or dependency management
    /// (top-level or in a profile).
    fn declares_dependencies(&self) -> bool {
        let doc = &self.doc;
        doc.nodes.iter().enumerate().any(|(i, n)| {
            n.name == "dependencies"
                && n.parent.is_some_and(|p| {
                    doc.is_model_root(p) || {
                        doc.nodes[p].name == "dependencyManagement"
                            && doc.nodes[p].parent.is_some_and(|gp| doc.is_model_root(gp))
                    }
                })
                && !doc.nodes[i].children.is_empty()
        })
    }

    /// A top-level `<distributionManagement>`: the reactor is deployed.
    fn deploys(&self) -> bool {
        self.doc
            .child(self.doc.project, "distributionManagement")
            .is_some()
    }
}

struct Reactor {
    poms: BTreeMap<String, Pom>,
    /// Reactor poms in discovery order.
    reactor: Vec<String>,
    /// Reactor poms plus every in-checkout pom on a reactor parent chain.
    scope: Vec<String>,
    /// pom → its local parent pom.
    local_parent: BTreeMap<String, String>,
    /// User properties from `.mvn/maven.config` ([`cli_properties`]).
    cli_props: BTreeMap<String, String>,
}

impl Reactor {
    fn discover(read: ReadFn<'_>, list: ListFn<'_>) -> Result<Reactor, JvmRefusal> {
        let root = read("pom.xml")
            .ok_or_else(|| shape_refusal("no_build_file", "no pom.xml at the project root"))?;
        let cli_props = read(MAVEN_CONFIG)
            .map(|bytes| cli_properties(&String::from_utf8_lossy(&bytes)))
            .unwrap_or_default();
        let discovery = discovery_on(&cli_props);
        let mut poms = BTreeMap::new();
        poms.insert("pom.xml".to_string(), Pom::parse("pom.xml", root)?);
        let mut reactor = vec!["pom.xml".to_string()];
        let mut next = 0;
        while next < reactor.len() {
            let rel = reactor[next].clone();
            next += 1;
            let mut modules = module_refs(&poms[&rel].doc);
            if discovery && poms[&rel].discovers_subprojects {
                modules.extend(implicit_subprojects(list, &poms[&rel].dir));
            }
            for module in modules {
                let (module_rel, bytes) = resolve_module(read, &poms[&rel].dir, &rel, &module)?;
                if poms.contains_key(&module_rel) {
                    if !reactor.contains(&module_rel) {
                        reactor.push(module_rel);
                    }
                    continue;
                }
                let pom = Pom::parse(&module_rel, bytes)?;
                let nested = NESTED_MVN_FILES.iter().find(|f| {
                    !pom.dir.is_empty() && read(&format!("{}/.mvn/{f}", pom.dir)).is_some()
                });
                if let Some(f) = nested {
                    return Err(shape_refusal(
                        "nested_mvn_dir",
                        format!(
                            "module {} has its own .mvn/{f}; remove or merge {}/.mvn",
                            pom.dir, pom.dir
                        ),
                    ));
                }
                poms.insert(module_rel.clone(), pom);
                reactor.push(module_rel);
            }
        }

        let mut scope = reactor.clone();
        let mut local_parent = BTreeMap::new();
        for rel in &reactor {
            let mut cur = rel.clone();
            while !local_parent.contains_key(&cur) {
                let Some(parent_rel) = local_parent_of(read, &mut poms, &cur)? else {
                    break;
                };
                local_parent.insert(cur.clone(), parent_rel.clone());
                if !scope.contains(&parent_rel) {
                    scope.push(parent_rel.clone());
                }
                cur = parent_rel;
            }
        }

        Ok(Reactor {
            poms,
            reactor,
            scope,
            local_parent,
            cli_props,
        })
    }

    /// `rel`, then each local ancestor, nearest first.
    fn chain<'s>(&'s self, rel: &'s str) -> impl Iterator<Item = &'s str> + 's {
        let mut seen = BTreeSet::new();
        std::iter::successors(Some(rel), move |cur| {
            let next = self.local_parent.get(*cur).map(String::as_str)?;
            seen.insert(*cur).then_some(next)
        })
    }

    /// The topmost local ancestor of `rel`.
    fn local_root(&self, rel: &str) -> String {
        self.chain(rel).last().unwrap_or(rel).to_string()
    }

    /// Local roots that get a pin and the fallback repository. A root that
    /// no other pom inherits from, packaged `pom` and declaring no
    /// dependencies, is a pure aggregator: nothing resolves through it, so
    /// it stays untouched.
    fn wired_roots(&self) -> Vec<String> {
        let mut roots: Vec<String> = Vec::new();
        for rel in &self.reactor {
            let root = self.local_root(rel);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        roots.retain(|root| {
            let pom = &self.poms[root];
            let inherited = self
                .scope
                .iter()
                .any(|rel| rel != root && self.local_root(rel) == *root);
            inherited || pom.packaging != "pom" || pom.declares_dependencies()
        });
        roots
    }

    /// Whether a pom of the scope declares `c`'s main jar at its suffixed
    /// version where Maven always reads it (see [`wired_checked`]).
    fn wires(&self, c: &Coords<'_>) -> bool {
        let sv = c.suffixed_version();
        self.scope.iter().any(|rel| {
            let doc = &self.poms[rel].doc;
            doc.declarations()
                .into_iter()
                .filter(|&dep| !doc.section_of(dep).starts_with("profile:") && doc.is_main_jar(dep))
                .any(|dep| {
                    // Maven interpolates after inheritance: the declaring
                    // pom or any pom inheriting it may define the property.
                    std::iter::once(rel.as_str())
                        .chain(self.inheritors(rel))
                        .any(|reader| {
                            let resolve = |v: &str| self.interpolate(reader, v);
                            let value = |name: &str| doc.coordinate(dep, name, &resolve);
                            value("groupId").as_deref() == Some(c.group_id)
                                && value("artifactId").as_deref() == Some(c.artifact_id)
                                && value("version").as_deref() == Some(sv.as_str())
                        })
                })
        })
    }

    /// The version `rel` reads for `g:a`'s main jar from
    /// `<dependencyManagement>`: the nearest local pom on its chain that
    /// manages it (Maven merges management child over parent; the local
    /// root's pin is such an entry), interpolated as `rel` reads it.
    /// `None` when no local pom manages it — the version then comes from
    /// outside the checkout (an external parent or BOM) or a transitive
    /// path — or when it cannot be interpolated.
    fn managed_version(&self, rel: &str, g: &str, a: &str) -> Option<String> {
        let resolve = |v: &str| self.interpolate(rel, v);
        self.chain(rel)
            .find_map(|p| {
                let doc = &self.poms[p].doc;
                doc.declarations()
                    .into_iter()
                    .find(|&dep| {
                        doc.is_top_level_managed(dep)
                            && doc.is_main_jar(dep)
                            && doc.coordinate(dep, "groupId", &resolve).as_deref() == Some(g)
                            && doc.coordinate(dep, "artifactId", &resolve).as_deref() == Some(a)
                    })
                    .map(|dep| doc.coordinate(dep, "version", &resolve))
            })
            .flatten()
    }

    /// Whether a version-less `g:a` declaration of `rel` always reads `sv`
    /// from management: the nearest local management resolves to `sv`
    /// ([`Self::managed_version`]), no inheritor or active profile moves
    /// the property it names ([`Self::version_moved`]), and no profile on
    /// the chain of `rel` or an inheritor manages `g:a`'s main jar at
    /// another version (a profile's management overrides the base's).
    fn always_managed_at(&self, rel: &str, g: &str, a: &str, sv: &str) -> bool {
        if self.managed_version(rel, g, a).as_deref() != Some(sv) {
            return false;
        }
        let resolve = |v: &str| self.interpolate(rel, v);
        let is_ga = |doc: &Doc, dep: usize| {
            doc.is_main_jar(dep)
                && doc.coordinate(dep, "groupId", &resolve).as_deref() == Some(g)
                && doc.coordinate(dep, "artifactId", &resolve).as_deref() == Some(a)
        };
        let declared = self.chain(rel).find_map(|p| {
            let doc = &self.poms[p].doc;
            doc.declarations()
                .into_iter()
                .find(|&dep| doc.is_top_level_managed(dep) && is_ga(doc, dep))
                .and_then(|dep| doc.child_text(dep, "version"))
        });
        if declared.as_deref().is_some_and(|d| {
            d.contains("${") && self.version_moved(rel, d, &|v: &str| v != sv).is_some()
        }) {
            return false;
        }
        let up = |doc: &Doc, n: usize| doc.nodes[n].parent;
        let readers: Vec<&str> = std::iter::once(rel).chain(self.inheritors(rel)).collect();
        !readers.iter().flat_map(|r| self.chain(r)).any(|p| {
            let doc = &self.poms[p].doc;
            doc.declarations().into_iter().any(|dep| {
                let profile_managed = up(doc, dep).and_then(|d| up(doc, d)).is_some_and(|dm| {
                    doc.nodes[dm].name == "dependencyManagement"
                        && up(doc, dm).is_some_and(|m| doc.is_profile(m))
                });
                profile_managed
                    && is_ga(doc, dep)
                    && doc.coordinate(dep, "version", &resolve).as_deref() != Some(sv)
            })
        })
    }

    /// Whether every pom that reads `dep` of `rel` resolves its version
    /// to `sv`: `rel` and each pom inheriting it, with or without a
    /// profile on its chain active (see [`Self::version_moved`]).
    fn always_reads(&self, rel: &str, dep: usize, sv: &str) -> bool {
        let doc = &self.poms[rel].doc;
        let Some(declared) = doc.child_text(dep, "version") else {
            return false;
        };
        let resolve = |v: &str| self.interpolate(rel, v);
        doc.coordinate(dep, "version", &resolve).as_deref() == Some(sv)
            && (!declared.contains("${")
                || self
                    .version_moved(rel, &declared, &|v: &str| v != sv)
                    .is_none())
    }

    /// The g:a declarations of `rel`, with `${...}` coordinates
    /// interpolated in its context.
    fn keyed_declarations(&self, rel: &str, g: &str, a: &str) -> Vec<(usize, String)> {
        self.poms[rel]
            .doc
            .keyed_declarations(g, a, &|v| self.interpolate(rel, v))
    }

    /// Interpolate every `${name}` in `value` in the context of `rel`;
    /// `None` when any name is undefined in the checkout.
    fn interpolate(&self, rel: &str, value: &str) -> Option<String> {
        self.interpolate_with(rel, value, &[], interpolate_strict)
    }

    /// [`Self::interpolate`] with the `active` profiles' properties layered
    /// over their poms' own, as when those profiles are active, through
    /// `interpolate` ([`interpolate_strict`] for a version,
    /// [`interpolate_keeping`] for coordinates).
    fn interpolate_with(
        &self,
        rel: &str,
        value: &str,
        active: &[Overlay<'_>],
        interpolate: Interpolate,
    ) -> Option<String> {
        interpolate(value, &|name| self.lookup_with(rel, name, active))
    }

    /// Maven's lookup order ([`lookup_property`], shared with VEX
    /// discovery): the model's own coordinates, user properties, then
    /// `<properties>` up the local chain with the `active` profiles merged
    /// over their poms', then the deprecated bare `${version}`.
    fn lookup(&self, rel: &str, name: &str) -> Option<String> {
        self.lookup_with(rel, name, &[])
    }

    fn lookup_with(&self, rel: &str, name: &str, active: &[Overlay<'_>]) -> Option<String> {
        let layers = self.chain(rel).map(|p| PomLayer {
            own: &self.poms[p].props,
            profiles: active
                .iter()
                .filter(|(at, _)| *at == p)
                .map(|(_, props)| *props)
                .collect(),
        });
        lookup_property(name, &|n| self.model_ref(rel, n), &self.cli_props, layers)
    }

    /// The project model reference `name` of `rel` (`project.version`,
    /// `project.groupId`, ...; the deprecated bare `version`), raw.
    fn model_ref(&self, rel: &str, name: &str) -> Option<String> {
        let pom = &self.poms[rel];
        // A Maven 4 child may omit its parent's coordinates too: they come
        // from the inferred local parent.
        match name {
            "project.version" | "pom.version" | "version" => self
                .chain(rel)
                .find_map(|p| self.poms[p].effective_version())
                .map(str::to_string),
            "project.groupId" | "pom.groupId" => self
                .chain(rel)
                .find_map(|p| self.poms[p].effective_group())
                .map(str::to_string),
            "project.artifactId" | "pom.artifactId" => pom.artifact.clone(),
            "project.parent.version" => pom.parent.as_ref()?.version.clone(),
            "project.parent.groupId" => pom.parent.as_ref()?.group.clone(),
            _ => None,
        }
    }

    /// A version `declared` (with `${...}`) reaches in a pom that reads
    /// it, an inheritor of `rel` or `rel` itself with some combination of
    /// the profiles on its chain active, that is neither the base nor `sv`:
    /// the version and where. Profile activation is not evaluated, so every
    /// combination of profiles that may change it counts
    /// ([`profile_combinations`], shared with VEX discovery); more of them
    /// than are combined fails closed.
    fn version_override(
        &self,
        rel: &str,
        declared: &str,
        base: &str,
        sv: &str,
    ) -> Option<(String, String)> {
        self.version_moved(rel, declared, &|v: &str| !is_base_like(v, base) && v != sv)
    }

    /// The first version `declared` reaches in a pom that reads it (an
    /// inheritor of `rel`, or `rel` or an inheritor with a profile on its
    /// chain active) for which `moved` holds, and where; an undefined
    /// value is passed as `an undefined value` ([`Self::read_elsewhere`]).
    fn version_moved(
        &self,
        rel: &str,
        declared: &str,
        moved: &dyn Fn(&str) -> bool,
    ) -> Option<(String, String)> {
        self.read_elsewhere(rel, &[(declared, interpolate_strict)], &|v| moved(&v[0]))
            .map(|(mut v, at)| (v.remove(0), at))
    }

    /// Where `texts` (one declaration's, each read through its own
    /// interpolation) read values `hit` accepts, other than in `rel` with
    /// no profile active: in an inheritor of `rel` (Maven interpolates
    /// after inheritance), or in `rel` or an inheritor with some combination
    /// of the profiles on its chain active ([`Self::profile_override`]);
    /// with those values (an undefined one reads "an undefined value") and
    /// where.
    fn read_elsewhere(
        &self,
        rel: &str,
        texts: &[(&str, Interpolate)],
        hit: &dyn Fn(&[String]) -> bool,
    ) -> Option<(Vec<String>, String)> {
        std::iter::once(rel)
            .chain(self.inheritors(rel))
            .find_map(|reader| {
                // `rel` resolves it, so a reader or profile that does not
                // has redefined something it names: that moves it too.
                let plain = (reader != rel)
                    .then(|| self.read_under(reader, texts, &[]))
                    .filter(|v| hit(v))
                    .map(|v| (v, reader.to_string()));
                plain.or_else(|| self.profile_override(reader, texts, hit))
            })
    }

    /// What each of `texts` reads in `reader` with the `active` profiles
    /// active, through its own interpolation and work budget ("an
    /// undefined value" when that fails).
    fn read_under(
        &self,
        reader: &str,
        texts: &[(&str, Interpolate)],
        active: &[Overlay<'_>],
    ) -> Vec<String> {
        texts
            .iter()
            .map(|(text, interpolate)| {
                self.interpolate_with(reader, text, active, *interpolate)
                    .unwrap_or_else(|| "an undefined value".to_string())
            })
            .collect()
    }

    /// The first combination of the profiles on `reader`'s chain under
    /// which `texts` (all read under the same combination,
    /// [`Self::read_under`]) read values `moved` accepts, with the values
    /// and where; fails closed (undetermined values, whatever `moved` says)
    /// when more profiles may change them than are combined, so a caller
    /// that weighs only some declarations filters them first.
    fn profile_override(
        &self,
        reader: &str,
        texts: &[(&str, Interpolate)],
        moved: &dyn Fn(&[String]) -> bool,
    ) -> Option<(Vec<String>, String)> {
        let profiles: Vec<(&str, &str, &BTreeMap<String, String>)> = self
            .chain(reader)
            .flat_map(|at| {
                self.poms[at]
                    .profile_props
                    .iter()
                    .map(move |(id, props)| (at, id.as_str(), props))
            })
            .collect();
        let definitions = |name: &str| {
            if let Some(fixed) =
                Definitions::fixed(name, &|n| self.model_ref(reader, n), &self.cli_props)
            {
                return fixed;
            }
            let mut d = Definitions::default();
            d.texts.extend(
                self.chain(reader)
                    .filter_map(|p| self.poms[p].props.get(name).cloned()),
            );
            d.texts.extend(self.model_ref(reader, name));
            for (i, (_, _, props)) in profiles.iter().enumerate() {
                if let Some(v) = props.get(name) {
                    d.texts.push(v.clone());
                    d.profiles.push(i);
                }
            }
            d
        };
        let values: Vec<&str> = texts.iter().map(|(text, _)| *text).collect();
        let Some(combinations) = profile_combinations(&values, &definitions) else {
            return Some((
                vec!["an undetermined value".to_string(); texts.len()],
                format!(
                    "{reader} under some combination of the more than {MAX_COMBINED_PROFILES} \
                     profiles on its chain that redefine what it names"
                ),
            ));
        };
        combinations.into_iter().find_map(|combination| {
            let active: Vec<Overlay<'_>> = combination
                .iter()
                .map(|&i| (profiles[i].0, profiles[i].2))
                .collect();
            let v = self.read_under(reader, texts, &active);
            moved(&v).then(|| {
                let under = combination
                    .iter()
                    .map(|&i| format!("profile {} of {}", profiles[i].1, profiles[i].0))
                    .collect::<Vec<_>>()
                    .join(" + ");
                (v, format!("{reader} under {under}"))
            })
        })
    }

    /// Where `dep` of `rel`, a declaration named through `${...}`
    /// coordinates, reads a groupId and artifactId that `hit` accepts,
    /// other than `rel` with no profile active ([`Self::read_elsewhere`],
    /// which covers the profile holding `dep`): each read under the same
    /// profiles but on its own, an unresolved reference kept as written
    /// ([`interpolate_keeping`]). Maven interpolates after inheritance and
    /// with the active profiles' `<properties>` merged in, then matches
    /// management and pins. More profiles than are combined fail closed
    /// (accepted whatever `hit` says).
    fn coordinates_elsewhere(
        &self,
        rel: &str,
        dep: usize,
        hit: &dyn Fn(&str, &str) -> bool,
    ) -> Option<String> {
        let doc = &self.poms[rel].doc;
        let group = doc.child_text(dep, "groupId")?;
        let artifact = doc.child_text(dep, "artifactId")?;
        let texts: [(&str, Interpolate); 2] = [
            (&group, interpolate_keeping),
            (&artifact, interpolate_keeping),
        ];
        self.read_elsewhere(rel, &texts, &|v| hit(&v[0], &v[1]))
            .map(|(_, at)| at)
    }

    /// Every pom in scope that inherits from `rel` (has it on its chain).
    fn inheritors<'s>(&'s self, rel: &'s str) -> impl Iterator<Item = &'s str> + 's {
        self.scope
            .iter()
            .map(String::as_str)
            .filter(move |p| *p != rel && self.chain(p).any(|a| a == rel))
    }

    /// Rewrite the base declarations of `rel` and record the
    /// warnings, the local roots not to pin, the local roots whose own
    /// top-level management already covers g:a, and the declarations left
    /// at a version that may still read the base (`uncertain`).
    #[allow(clippy::too_many_arguments)]
    fn rewrite_declarations(
        &self,
        rel: &str,
        patch: &JvmPatch<'_>,
        sv: &str,
        edits: &mut BTreeMap<String, Vec<Edit>>,
        warnings: &mut Vec<JvmWarning>,
        unpinned: &mut BTreeSet<String>,
        managed_roots: &mut BTreeSet<String>,
        uncertain: &mut BTreeSet<String>,
    ) {
        let doc = &self.poms[rel].doc;
        let ga = format!("{}:{}", patch.group_id, patch.artifact_id);
        self.warn_property_coordinates(rel, patch, warnings, unpinned, uncertain);
        for (dep, key) in self.keyed_declarations(rel, patch.group_id, patch.artifact_id) {
            let at = format!("{rel}:{}", doc.line_of(doc.nodes[dep].start));
            let managed_section = doc.section_of(dep).ends_with("dependencyManagement");
            if !doc.is_main_jar(dep) {
                let type_text = doc.child_text(dep, "type").filter(|t| !t.is_empty());
                let classifier = doc.child_text(dep, "classifier").filter(|c| !c.is_empty());
                let executable = crate::formats::maven::is_executable_variant(
                    type_text.as_deref(),
                    classifier.as_deref(),
                );
                if classifier.is_some() || executable {
                    let what = match (&classifier, &type_text) {
                        (Some(c), _) => format!("classifier {c}"),
                        (None, Some(t)) => format!("<type>{t}</type>"),
                        (None, None) => "classifier".to_string(),
                    };
                    warnings.push(degraded(
                        "classifier_declared",
                        format!("{at}: the {what} variant of {ga} bypasses the pin"),
                    ));
                }
                // The classifier-less pin does not retarget the copy and the
                // tree serves only the main jar, so Maven fetches the public
                // release: an executable copy (tests, a `test-jar`, a native
                // build) keeps the unpatched code on the classpath, which
                // hosted mode and VEX discovery refuse to attest too. Only a
                // used copy counts; a managed entry alone puts nothing on a
                // classpath.
                if executable && !managed_section && !self.always_reads(rel, dep, sv) {
                    uncertain.insert(at);
                }
                continue;
            }
            let root = self.local_root(rel);
            // Maven interpolates after inheritance and with the active
            // profiles: a pom that inherits this declaration, or a profile
            // redefining a property it names, may make it another artifact,
            // which the literal SV must not reach.
            if doc.has_property_coordinate(dep) {
                let other = self.coordinates_elsewhere(rel, dep, &|g, a| {
                    g != patch.group_id || a != patch.artifact_id
                });
                if let Some(p) = other {
                    warnings.push(degraded(
                        "coordinates_overridden",
                        format!(
                            "{at}: {ga} is named through properties that {p} resolves \
                             differently; left as is and {root} is not pinned"
                        ),
                    ));
                    unpinned.insert(root);
                    uncertain.insert(at);
                    continue;
                }
            }
            let top_managed = doc.is_top_level_managed(dep);
            if top_managed && root == rel {
                managed_roots.insert(root.clone());
            }
            let Some(version) = doc.child(dep, "version") else {
                // A version-less declaration reads its management: under a
                // local root left unpinned (management conflicting or
                // unresolved outside the checkout) that may be the base.
                if !managed_section
                    && !self.always_managed_at(rel, patch.group_id, patch.artifact_id, sv)
                {
                    uncertain.insert(at);
                }
                continue;
            };
            let declared = doc.text_of(version);
            let resolved = if declared.contains("${") {
                match self.interpolate(rel, &declared) {
                    Some(v) => v,
                    None => {
                        warnings.push(degraded(
                            "property_unresolved",
                            format!(
                                "{at}: {ga} version {declared} is not defined in the checkout; \
                                 left as is, probably unpatched, and {root} is not pinned"
                            ),
                        ));
                        // The explicit version beats any pin of the root.
                        unpinned.insert(root);
                        uncertain.insert(at);
                        continue;
                    }
                }
            } else {
                declared.clone()
            };
            if resolved == sv {
                continue;
            }
            if is_base_like(&resolved, patch.version) {
                // Maven interpolates after inheritance and with the active
                // profiles: a pom that inherits this declaration and
                // overrides the property, or a profile that does, must keep
                // its own version, so the literal SV cannot go here.
                let overridden = declared
                    .contains("${")
                    .then(|| self.version_override(rel, &declared, patch.version, sv))
                    .flatten();
                if let Some((v, p)) = overridden {
                    warnings.push(degraded(
                        "conflicting_literal_version",
                        format!(
                            "{at}: {ga} version {declared} resolves to {v} in {p}, not {}; \
                             left as is and {root} is not pinned",
                            patch.version
                        ),
                    ));
                    unpinned.insert(root);
                    uncertain.insert(at);
                    continue;
                }
                let span = doc.value_span(version);
                // An earlier patch's suffixed version: its pristine value is
                // in that patch's record, which the caller carries over.
                let original =
                    (resolved == patch.version).then(|| doc.text[span.clone()].to_string());
                edits.entry(rel.to_string()).or_default().push(Edit {
                    start: span.start,
                    end: span.end,
                    text: sv.to_string(),
                    role: Role::Version { key, original },
                });
            } else if is_range(&resolved) {
                warnings.push(degraded(
                    "range",
                    format!("{at}: {ga} version {declared} is left as is, probably unpatched"),
                ));
            } else {
                warnings.push(degraded(
                    "conflicting_literal_version",
                    format!(
                        "{at}: {ga} is declared at {declared}, not {}; {root} is not pinned",
                        patch.version
                    ),
                ));
                unpinned.insert(root);
            }
        }
    }
}

impl Reactor {
    /// Warn for each declaration of `rel` named through `${...}`
    /// coordinates that is not `patch`'s g:a in `rel` itself (those
    /// `rewrite_declarations` weighs) but may be: one whose property the
    /// checkout does not define (`property_unresolved`), or one an
    /// inheritor or a combination of profiles makes it
    /// (`coordinates_overridden`, [`Self::coordinates_elsewhere`]). It is
    /// left as is, probably unpatched; one with its own version beats any
    /// pin, so its local root is not pinned. A classifier copy is its own
    /// coordinate, which no pin reaches: an executable one is warned about
    /// as `classifier_declared`, as `rewrite_declarations` does (`sources` /
    /// `javadoc` never run; `test-jar` is the `tests` copy), and any other
    /// literal `<type>` but `jar` is not the g:a's jar (a `${…}` one may be). Text that can never
    /// read the g:a, whatever its properties say ([`may_interpolate_to`]),
    /// is ruled out first, before any inheritor or profile is read.
    fn warn_property_coordinates(
        &self,
        rel: &str,
        patch: &JvmPatch<'_>,
        warnings: &mut Vec<JvmWarning>,
        unpinned: &mut BTreeSet<String>,
        uncertain: &mut BTreeSet<String>,
    ) {
        let doc = &self.poms[rel].doc;
        let resolve = |v: &str| self.interpolate(rel, v);
        let ga = format!("{}:{}", patch.group_id, patch.artifact_id);
        for dep in doc.declarations() {
            let (Some(g), Some(a)) = (
                doc.child_text(dep, "groupId"),
                doc.child_text(dep, "artifactId"),
            ) else {
                continue;
            };
            let type_text = doc.child_text(dep, "type").filter(|t| !t.is_empty());
            let classifier_text = doc.child_text(dep, "classifier").filter(|c| !c.is_empty());
            // `test-jar` is the `tests` copy ([`classpath_copy`]); the type
            // check below drops any other literal type but `jar`, even with
            // an explicit classifier.
            let classifier = classpath_copy(type_text.as_deref(), classifier_text.as_deref())
                .flatten()
                .map(str::to_string);
            if !doc.has_property_coordinate(dep)
                || doc.pin_at(dep).is_some()
                || classifier
                    .as_deref()
                    .is_some_and(|c| !is_executable_classifier(c))
                || !may_interpolate_to(&g, patch.group_id)
                || !may_interpolate_to(&a, patch.artifact_id)
                // A `${…}` type may be `jar`, as discovery reads it.
                || type_text
                    .as_deref()
                    .is_some_and(|t| t != "jar" && t != "test-jar" && !t.contains("${"))
            {
                continue;
            }
            let (here_g, here_a) = (resolve(&g), resolve(&a));
            let (reason, detail) = match (&here_g, &here_a) {
                (Some(hg), Some(ha)) if hg == patch.group_id && ha == patch.artifact_id => {
                    continue;
                }
                (Some(hg), Some(ha)) => {
                    let Some(there) = self.coordinates_elsewhere(rel, dep, &|rg, ra| {
                        may_interpolate_to(rg, patch.group_id)
                            && may_interpolate_to(ra, patch.artifact_id)
                    }) else {
                        continue;
                    };
                    (
                        "coordinates_overridden",
                        format!("{g}:{a} is {hg}:{ha} here but may be {ga} in {there}"),
                    )
                }
                _ => {
                    let could_be = |read: &Option<String>, raw: &str, want: &str| match read {
                        Some(v) => v == want,
                        None => may_interpolate_to(raw, want),
                    };
                    if !could_be(&here_g, &g, patch.group_id)
                        || !could_be(&here_a, &a, patch.artifact_id)
                    {
                        continue;
                    }
                    let unresolved: Vec<&str> = [(&g, &here_g), (&a, &here_a)]
                        .into_iter()
                        .filter(|(_, read)| read.is_none())
                        .map(|(raw, _)| raw.as_str())
                        .collect();
                    (
                        "property_unresolved",
                        format!(
                            "{g}:{a} may be {ga} but {} is not defined in the checkout",
                            unresolved.join(", ")
                        ),
                    )
                }
            };
            let at = format!("{rel}:{}", doc.line_of(doc.nodes[dep].start));
            if let Some(classifier) = classifier {
                warnings.push(degraded(
                    "classifier_declared",
                    format!(
                        "{at}: {detail}; a classifier variant ({classifier}) of {ga} bypasses \
                         the pin"
                    ),
                ));
                continue;
            }
            let versioned = doc
                .child_text(dep, "version")
                .is_some_and(|v| !v.is_empty());
            let root = self.local_root(rel);
            let unpin = if versioned {
                format!(", and {root} is not pinned")
            } else {
                String::new()
            };
            warnings.push(degraded(
                reason,
                format!("{at}: {detail}; left as is, probably unpatched{unpin}"),
            ));
            if versioned {
                unpinned.insert(root);
                uncertain.insert(at);
            }
        }
    }
}

/// Whether `raw`, with each `${...}` standing for any text, can read
/// `want`.
fn may_interpolate_to(raw: &str, want: &str) -> bool {
    let mut literals = Vec::new();
    let mut rest = raw;
    while let Some(at) = rest.find("${") {
        literals.push(&rest[..at]);
        let Some(close) = rest[at..].find('}') else {
            return false;
        };
        rest = &rest[at + close + 1..];
    }
    let Some((first, tail)) = literals.split_first() else {
        return raw == want;
    };
    let Some(mut left) = want.strip_prefix(first) else {
        return false;
    };
    for middle in tail {
        let Some(i) = left.find(middle) else {
            return false;
        };
        left = &left[i + middle.len()..];
    }
    left.ends_with(rest)
}

/// The base version, or a suffixed version of it from any patch uuid.
fn is_base_like(version: &str, base: &str) -> bool {
    version == base
        || version
            .strip_prefix(base)
            .and_then(|rest| rest.strip_prefix("-socket."))
            .is_some_and(|hex| {
                hex.len() == 8
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
}

/// `<modules>`/`<subprojects>` entries of the project and of every profile.
fn module_refs(doc: &Doc) -> Vec<String> {
    let mut out = Vec::new();
    for (i, n) in doc.nodes.iter().enumerate() {
        let item = match n.name.as_str() {
            "modules" => "module",
            "subprojects" => "subproject",
            _ => continue,
        };
        if !n.parent.is_some_and(|p| doc.is_model_root(p)) {
            continue;
        }
        out.extend(doc.children(i, item).map(|m| doc.text_of(m)));
    }
    out
}

/// The user property that turns Maven 4's subproject discovery off.
const DISCOVER_SUBPROJECTS: &str = "maven.project.discoverSubprojects";

/// Whether Maven 4 discovers the subprojects of this pom on its own
/// (`DefaultModelBuilder`, "subprojects discovery"): its model version is
/// not 4.0.0 (the `<modelVersion>`, else the POM namespace), it is
/// packaged `pom`, and it lists no top-level `<subprojects>` or
/// `<modules>` entry. Maven 3 never discovers, and reads no 4.1.0 pom.
fn discovers_subprojects(doc: &Doc) -> bool {
    let project = doc.project;
    let model = doc.child_text(project, "modelVersion").or_else(|| {
        let at = doc.masked.find(POM_NAMESPACE)? + POM_NAMESPACE.len();
        let rest = &doc.masked[at..];
        let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))?;
        Some(rest[..end].to_string())
    });
    let lists = |list: &str, item: &str| {
        doc.child(project, list)
            .is_some_and(|l| doc.children(l, item).next().is_some())
    };
    model.is_some_and(|v| v != "4.0.0")
        && doc.child_text(project, "packaging").as_deref() == Some("pom")
        && !lists("subprojects", "subproject")
        && !lists("modules", "module")
}

const POM_NAMESPACE: &str = "maven.apache.org/POM/";

/// The subprojects Maven 4 discovers under the pom at `dir`: every direct
/// subdirectory holding a `pom.xml`, hidden ones included, as
/// `<subproject>` names relative to `dir`. Probed through the listing, not
/// a read: a directory the reader refuses (`.git/`) lists as empty, where
/// reading its `pom.xml` would record a read error.
pub fn implicit_subprojects(list: ListFn<'_>, dir: &str) -> Vec<String> {
    list(dir)
        .iter()
        .filter_map(|entry| entry.strip_suffix('/'))
        .filter(|name| *name != GIT_DIR)
        .filter(|name| {
            let sub = match dir {
                "" => name.to_string(),
                _ => format!("{dir}/{name}"),
            };
            list(&sub).iter().any(|e| e == "pom.xml")
        })
        .map(str::to_string)
        .collect()
}

/// `module` of the pom at `dir` → the module pom's path and bytes.
fn resolve_module(
    read: ReadFn<'_>,
    dir: &str,
    declaring: &str,
    module: &str,
) -> Result<(String, Vec<u8>), JvmRefusal> {
    if module.is_empty() || module.contains("${") {
        return Err(shape_refusal(
            "module_path_unresolvable",
            format!("{declaring}: <module>{module}</module>; make the module a literal path"),
        ));
    }
    let Some(path) = normalize(dir, module) else {
        return Err(shape_refusal(
            "module_outside_root",
            format!("{declaring}: <module>{module}</module> leaves the project root"),
        ));
    };
    pom_candidates(path)
        .into_iter()
        .find_map(|c| read(&c).map(|bytes| (c, bytes)))
        .ok_or_else(|| {
            shape_refusal(
                "module_path_unresolvable",
                format!("{declaring}: <module>{module}</module> has no pom"),
            )
        })
}

/// Where Maven looks for the pom at the normalized `path` a `<module>` or
/// `<relativePath>` names: a directory means its `pom.xml` (`""`, from
/// `..`, is the root), else the file itself.
fn pom_candidates(path: String) -> Vec<String> {
    if path.is_empty() {
        vec!["pom.xml".to_string()]
    } else {
        vec![format!("{path}/pom.xml"), path]
    }
}

/// The local parent of `rel`: its `<parent>` file exists in the checkout
/// and names the same groupId/artifactId (and version, when both are
/// literal). Loads the parent into `poms`.
fn local_parent_of(
    read: ReadFn<'_>,
    poms: &mut BTreeMap<String, Pom>,
    rel: &str,
) -> Result<Option<String>, JvmRefusal> {
    let pom = &poms[rel];
    let Some(parent) = &pom.parent else {
        return Ok(None);
    };
    let relative = match parent.relative_path.as_deref() {
        Some("") => return Ok(None),
        Some(p) => p,
        None => "../pom.xml",
    };
    let Some(path) = normalize(&pom.dir, relative) else {
        return Ok(None);
    };
    let (want_group, want_artifact, want_version) = (
        parent.group.clone(),
        parent.artifact.clone(),
        parent.version.clone(),
    );
    // Like a `<module>`: a directory names its `pom.xml` (#534).
    let found = pom_candidates(path).into_iter().find_map(|c| {
        if poms.contains_key(&c) {
            Some((c, None))
        } else {
            read(&c).map(|bytes| (c, Some(bytes)))
        }
    });
    let Some((parent_rel, bytes)) = found else {
        return Ok(None);
    };
    if let Some(bytes) = bytes {
        let parsed = Pom::parse(&parent_rel, bytes)?;
        poms.insert(parent_rel.clone(), parsed);
    }
    let candidate = &poms[&parent_rel];
    let literal = |v: &Option<String>| {
        v.as_deref()
            .filter(|v| !v.contains("${"))
            .map(str::to_string)
    };
    let versions_agree = match (literal(&want_version), literal(&candidate.version)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    // Maven 4 (model 4.1.0) infers omitted parent coordinates from the
    // pom at the relative path.
    let infers = poms[rel].infers_parent;
    let matches = match want_group.as_deref() {
        None => infers,
        Some(g) => Some(g) == candidate.effective_group(),
    } && match want_artifact.as_deref() {
        None => infers,
        Some(a) => Some(a) == candidate.artifact.as_deref(),
    } && versions_agree;
    Ok(matches.then_some(parent_rel))
}

/// `base_dir` joined with `rel`, normalized; `None` when it leaves the
/// project root or is absolute. `""` is the root itself.
fn normalize(base_dir: &str, rel: &str) -> Option<String> {
    if rel.starts_with('/') || rel.starts_with('\\') || rel.contains(':') {
        return None;
    }
    crate::utils::relpath::resolve_rel(base_dir, rel, 0)
}

fn is_range(version: &str) -> bool {
    version.starts_with('[')
        || version.starts_with('(')
        || version == "LATEST"
        || version == "RELEASE"
}

/// Whether a pom configures the enforcer rules that forbid POM
/// repositories (by rule element or by implementation class name).
fn bans_repositories(masked: &str) -> bool {
    ["requireNoRepositories", "bannedRepositories"]
        .iter()
        .any(|rule| {
            has_open_tag(masked, rule) || {
                let mut class = rule.to_string();
                class[..1].make_ascii_uppercase();
                masked.contains(&class)
            }
        })
}

fn has_fallback_repository(doc: &Doc) -> bool {
    if doc.text.contains(BEGIN_MARKER) {
        return true;
    }
    doc.child(doc.project, "repositories").is_some_and(|r| {
        doc.children(r, "repository")
            .any(|repo| doc.child_text(repo, "id").as_deref() == Some(REPO_ID))
    })
}

// ── pom edits ───────────────────────────────────────────────────

/// Replace `text[start..end]` with `text` (an insertion when `start == end`).
#[derive(Debug)]
struct Edit {
    start: usize,
    end: usize,
    text: String,
    role: Role,
}

/// What an [`Edit`] records.
#[derive(Debug)]
enum Role {
    /// Recorded by nobody (removing a stale pin).
    Plain,
    /// The pin; `mark` is its byte range in the edit text when the edit also
    /// creates the sections around it (`pin_section`).
    Pin {
        mark: Option<Range<usize>>,
    },
    Repository,
    /// A declaration's version; `original` is `None` when it held another
    /// patch's suffixed version.
    Version {
        key: String,
        original: Option<String>,
    },
}

impl Edit {
    fn plain(start: usize, end: usize, text: &str) -> Edit {
        Edit {
            start,
            end,
            text: text.to_string(),
            role: Role::Plain,
        }
    }

    /// The fragment records of this edit of `rel` (whose old text is `old`).
    fn record(&self, rel: &str, old: &str) -> Option<Vec<WiringRecord>> {
        let replaced = &old[self.start..self.end];
        let action = if replaced.is_empty() {
            WiringAction::Added
        } else {
            WiringAction::Rewritten
        };
        match &self.role {
            Role::Plain => None,
            Role::Pin { mark } => {
                let (pin, section) = match mark {
                    Some(r) => (
                        &self.text[r.clone()],
                        Some(format!("{}{}", &self.text[..r.start], &self.text[r.end..])),
                    ),
                    None => (self.text.as_str(), None),
                };
                let key = pin_key_of(pin)?;
                let mut out = vec![fragment(
                    rel,
                    POM_FRAGMENT_KIND,
                    &key,
                    WiringAction::Added,
                    None,
                    json!({ "op": "pin", "text": pin }),
                )];
                if let Some(section) = section {
                    out.push(fragment(
                        rel,
                        POM_FRAGMENT_KIND,
                        "pin_section",
                        action,
                        None,
                        replace_op(replaced, &section),
                    ));
                }
                Some(out)
            }
            Role::Repository => Some(vec![fragment(
                rel,
                POM_FRAGMENT_KIND,
                "repository",
                action,
                None,
                replace_op(replaced, &self.text),
            )]),
            Role::Version { key, original } => Some(vec![fragment(
                rel,
                POM_FRAGMENT_KIND,
                key,
                WiringAction::Rewritten,
                original.clone(),
                json!({ "op": "version", "to": self.text }),
            )]),
        }
    }
}

/// `pin:<g>:<a>` from the pin comment inside `pin`.
fn pin_key_of(pin: &str) -> Option<String> {
    let at = pin.find(PIN_TAG)? + PIN_TAG.len();
    let rest = &pin[at..];
    let gav = rest.get(36..)?.strip_prefix(": ")?;
    let gav = &gav[..gav.find(" -->")?];
    let mut parts = gav.split(':');
    let (g, a) = (parts.next()?, parts.next()?);
    Some(format!("pin:{g}:{a}"))
}

/// Splice non-overlapping edits; insertions at one offset keep their order.
fn apply_edits(text: &str, mut edits: Vec<Edit>) -> String {
    edits.sort_by_key(|e| e.start);
    let mut out =
        String::with_capacity(text.len() + edits.iter().map(|e| e.text.len()).sum::<usize>());
    let mut at = 0;
    for e in edits {
        debug_assert!(e.start >= at, "overlapping pom edits");
        out.push_str(&text[at..e.start]);
        out.push_str(&e.text);
        at = e.end;
    }
    out.push_str(&text[at..]);
    out
}

/// Lines of the pin entry, relative to the `<dependency>` indent.
fn pin_lines(doc: &Doc, patch: &JvmPatch<'_>, sv: &str) -> Vec<String> {
    let u = &doc.unit;
    vec![
        format!(
            "{PIN_TAG}{}: {}:{}:{} -->",
            patch.uuid, patch.group_id, patch.artifact_id, patch.version
        ),
        "<dependency>".to_string(),
        format!("{u}<groupId>{}</groupId>", patch.group_id),
        format!("{u}<artifactId>{}</artifactId>", patch.artifact_id),
        format!("{u}<version>{sv}</version>"),
        "</dependency>".to_string(),
    ]
}

fn nest(unit: &str, open: &str, inner: Vec<String>, close: &str) -> Vec<String> {
    let mut lines = vec![open.to_string()];
    lines.extend(inner.into_iter().map(|l| format!("{unit}{l}")));
    lines.push(close.to_string());
    lines
}

/// The pin as the first child of the top-level
/// `<dependencyManagement><dependencies>`, creating the sections when
/// absent (before `<dependencies>`, else `<build>`, else `</project>`).
/// `true` when the edit creates (or expands) a section.
fn pin_edit(doc: &Doc, patch: &JvmPatch<'_>, sv: &str) -> (Edit, bool) {
    let u = doc.unit.as_str();
    let entry = pin_lines(doc, patch, sv);
    let n = entry.len();
    let project = doc.project;
    let Some(dm) = doc.child(project, "dependencyManagement") else {
        let lines = nest(
            u,
            "<dependencyManagement>",
            nest(u, "<dependencies>", entry, "</dependencies>"),
            "</dependencyManagement>",
        );
        let edit = match doc
            .child(project, "dependencies")
            .or_else(|| doc.child(project, "build"))
        {
            Some(anchor) => doc.insert_before(
                doc.nodes[anchor].start,
                &doc.indent_of(anchor),
                &lines,
                Some(2..2 + n),
            ),
            None => doc.insert_before(
                doc.nodes[project].inner_end,
                &doc.child_indent(project),
                &lines,
                Some(2..2 + n),
            ),
        };
        return (edit, true);
    };
    match doc.child(dm, "dependencies") {
        Some(deps) if !doc.is_self_closing(deps) => {
            (doc.insert_first_child(deps, &entry, None), false)
        }
        Some(deps) => (doc.insert_first_child(deps, &entry, Some(0..n)), true),
        None => (
            doc.insert_first_child(
                dm,
                &nest(u, "<dependencies>", entry, "</dependencies>"),
                Some(1..1 + n),
            ),
            true,
        ),
    }
}

/// An existing pin of g:a:v from another patch uuid, updated in place to
/// this patch's uuid and suffixed version.
fn pin_update(doc: &Doc, pin: &Pin, patch: &JvmPatch<'_>) -> Edit {
    let sv = patch.suffixed_version();
    let mut text = doc.text[pin.start..pin.end].to_string();
    if let Some(version) = &pin.version {
        text.replace_range(version.start - pin.start..version.end - pin.start, &sv);
    }
    let text = text.replacen(
        &format!("{PIN_TAG}{}:", pin.uuid),
        &format!("{PIN_TAG}{}:", patch.uuid),
        1,
    );
    Edit {
        start: pin.start,
        end: pin.end,
        text,
        role: Role::Pin { mark: None },
    }
}

/// The marked fallback repository, last in the top-level `<repositories>`
/// or in a new section before `</project>`.
fn repository_edit(doc: &Doc) -> Edit {
    let u = doc.unit.as_str();
    let block = vec![
        BEGIN_MARKER.to_string(),
        "<repository>".to_string(),
        format!("{u}<id>{REPO_ID}</id>"),
        format!("{u}<url>{REPO_URL}</url>"),
        format!(
            "{u}<releases><enabled>true</enabled><updatePolicy>always</updatePolicy>\
             <checksumPolicy>fail</checksumPolicy></releases>"
        ),
        format!("{u}<snapshots><enabled>false</enabled></snapshots>"),
        "</repository>".to_string(),
        END_MARKER.to_string(),
    ];
    let project = doc.project;
    let mut edit = match doc.child(project, "repositories") {
        Some(r) if doc.is_self_closing(r) => doc.insert_first_child(r, &block, None),
        Some(r) => doc.insert_before(doc.nodes[r].inner_end, &doc.child_indent(r), &block, None),
        None => doc.insert_before(
            doc.nodes[project].inner_end,
            &doc.child_indent(project),
            &nest(u, "<repositories>", block, "</repositories>"),
            None,
        ),
    };
    edit.role = Role::Repository;
    edit
}

// ── .mvn/maven.config ─────────────────────────────────

/// `config` with the offline-protocols and tail lines present, and the
/// `config` op recording what changed (`adopt` when nothing did):
/// identical lines are adopted, the last (effective) tail gets our
/// directory appended to its list, the last protocol list gets `file`.
fn merge_maven_config(config: Option<&[u8]>) -> (Vec<u8>, Value) {
    let text = config.map(String::from_utf8_lossy).unwrap_or_default();
    let nl = crate::utils::line_endings::terminator(&text);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let arg_of = |line: &str| line.trim().to_string();
    let last = |key: &str| lines.iter().rposition(|l| arg_of(l).starts_with(key));
    let (last_tail, last_offline) = (last(TAIL_KEY), last(OFFLINE_KEY));
    let mut out = String::new();
    let mut rewritten = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let body = line.trim_end_matches(['\r', '\n']);
        let ending = &line[body.len()..];
        let arg = arg_of(line);
        let extended = if Some(i) == last_tail {
            extend_list(&arg, TAIL_KEY, TAIL_DIR)
        } else if Some(i) == last_offline {
            extend_list(&arg, OFFLINE_KEY, "file")
        } else {
            None
        };
        match extended {
            Some(new_arg) => {
                let new_body = body.replacen(&arg, &new_arg, 1);
                out.push_str(&new_body);
                out.push_str(ending);
                rewritten.push(json!({ "from": body, "to": new_body }));
            }
            None => out.push_str(line),
        }
    }
    let mut appended = String::new();
    if !out.is_empty() && !out.ends_with('\n') && (last_offline.is_none() || last_tail.is_none()) {
        appended.push_str(nl);
    }
    if last_offline.is_none() {
        appended.push_str(&format!("{OFFLINE_LINE}{nl}"));
    }
    if last_tail.is_none() {
        appended.push_str(&format!("{TAIL_KEY}{TAIL_DIR}{nl}"));
    }
    out.push_str(&appended);
    let op = if rewritten.is_empty() && appended.is_empty() {
        json!({ "op": "adopt" })
    } else {
        json!({
            "op": "config",
            "created": config.is_none(),
            "appended": appended,
            "rewritten": rewritten,
        })
    };
    (out.into_bytes(), op)
}

/// `arg` (`<key><list>`) with `item` appended to its comma list, `None`
/// when already listed.
fn extend_list(arg: &str, key: &str, item: &str) -> Option<String> {
    let list = arg.strip_prefix(key)?;
    if list.split(',').any(|p| p == item) {
        return None;
    }
    let sep = if list.is_empty() { "" } else { "," };
    Some(format!("{key}{list}{sep}{item}"))
}

// ── vendored tree ───────────────────────────────────────────────────────

/// The suffixed tree of `patch` exactly as [`plan_with_config`] writes it
/// (`(tree_dir, jar_rel, writes)`), for the sbt planner, which resolves
/// the same `.socket/vendor/maven2` layout; refused when the upstream pom
/// cannot carry the suffixed version.
pub(crate) fn suffixed_tree(
    patch: &JvmPatch<'_>,
) -> Result<(String, String, Vec<FileWrite>), JvmRefusal> {
    let suffixed_pom = suffixed_pom(patch)?;
    Ok(tree_writes(patch, &patch.suffixed_version(), suffixed_pom))
}

/// `(tree_dir, jar_rel, writes)` of the version directory.
fn tree_writes(
    patch: &JvmPatch<'_>,
    sv: &str,
    suffixed_pom: String,
) -> (String, String, Vec<FileWrite>) {
    let a = patch.artifact_id;
    let dir = tree_dir(&patch.coords());
    let jar_name = format!("{a}-{sv}.jar");
    let pom_name = format!("{a}-{sv}.pom");
    let pom = suffixed_pom.into_bytes();
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(format!("{jar_name}.sha1"), sha1_hex(patch.jar).into_bytes());
    files.insert(format!("{pom_name}.sha1"), sha1_hex(&pom).into_bytes());
    files.insert(jar_name.clone(), patch.jar.to_vec());
    files.insert(pom_name, pom);

    let mut listed = serde_json::Map::new();
    for (name, bytes) in &files {
        listed.insert(
            name.clone(),
            serde_json::json!({ "sha256": sha256_hex(bytes), "size": bytes.len() }),
        );
    }
    // Keys inserted in sorted order: serde_json keeps insertion order here.
    let marker = serde_json::json!({
        "files": listed,
        "purl": format!("pkg:maven/{}/{a}@{}", patch.group_id, patch.version),
        "schema": 1,
        "tool": "maven",
        "uuid": patch.uuid,
        "version": sv,
    });
    let mut marker = serde_json::to_string_pretty(&marker).expect("marker serializes");
    marker.push('\n');
    files.insert(layout::MARKER_FILE.to_string(), marker.into_bytes());

    let writes: Vec<FileWrite> = files
        .into_iter()
        .map(|(name, bytes)| FileWrite {
            rel: format!("{dir}/{name}"),
            bytes,
            tree: true,
        })
        .collect();
    let jar_rel = format!("{dir}/{jar_name}");
    (dir, jar_rel, writes)
}

// ── XML scanning ─────────────────────────────────────────────────────────────

/// `text` with comments, CDATA sections and processing instructions blanked
/// byte-for-byte (offsets kept); `false` when one is unterminated (it is
/// blanked through EOF).
fn mask(text: &str) -> (String, bool) {
    const SPANS: [(&str, &str); 3] = [("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")];
    let mut bytes = text.as_bytes().to_vec();
    let mut complete = true;
    let mut from = 0;
    while let Some(rel) = text[from..].find('<') {
        let lt = from + rel;
        let Some((open, close)) = SPANS.iter().find(|(o, _)| text[lt..].starts_with(o)) else {
            from = lt + 1;
            continue;
        };
        let body = lt + open.len();
        let end = match text[body..].find(close) {
            Some(r) => body + r + close.len(),
            None => {
                complete = false;
                text.len()
            }
        };
        bytes[lt..end].fill(b' ');
        from = end;
    }
    let masked =
        String::from_utf8(bytes).expect("blanking whole ASCII-delimited spans keeps UTF-8");
    (masked, complete)
}

/// A real `<name …>` open tag (the next byte is a tag boundary).
fn has_open_tag(masked: &str, name: &str) -> bool {
    let needle = format!("<{name}");
    masked.match_indices(&needle).any(|(at, _)| {
        masked[at + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_whitespace())
    })
}

#[derive(Debug)]
struct Node {
    name: String,
    /// The `<` of the open tag.
    start: usize,
    /// Just past the open tag's `>`.
    inner_start: usize,
    /// The `<` of the close tag (`== inner_start` for `<x/>`).
    inner_end: usize,
    /// Just past the close tag's `>`.
    end: usize,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// A parsed pom: the original text, its masked copy and the element tree.
struct Doc {
    text: String,
    masked: String,
    nodes: Vec<Node>,
    project: usize,
    /// One indentation step, detected from the file.
    unit: String,
    /// The file's line ending.
    nl: &'static str,
}

impl Doc {
    fn parse(text: String) -> Result<Doc, String> {
        let (masked, complete) = mask(&text);
        if !complete {
            return Err("unterminated comment, CDATA section or processing instruction".into());
        }
        let bytes = masked.as_bytes();
        let mut nodes: Vec<Node> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut tops: Vec<usize> = Vec::new();
        let mut from = 0;
        while let Some(rel) = masked[from..].find('<') {
            let lt = from + rel;
            match bytes.get(lt + 1) {
                Some(b'/') => {
                    let gt = masked[lt..]
                        .find('>')
                        .map(|r| lt + r)
                        .ok_or("unterminated close tag")?;
                    let name = masked[lt + 2..gt].trim();
                    let open = stack.pop().ok_or_else(|| format!("unexpected </{name}>"))?;
                    if nodes[open].name != name {
                        return Err(format!("<{}> closed by </{name}>", nodes[open].name));
                    }
                    nodes[open].inner_end = lt;
                    nodes[open].end = gt + 1;
                    from = gt + 1;
                }
                Some(b'!') => {
                    let gt = declaration_end(&masked, lt).ok_or("unterminated <! declaration")?;
                    from = gt + 1;
                }
                _ => {
                    let gt = tag_end(&masked, lt).ok_or("unterminated open tag")?;
                    let raw = &masked[lt + 1..gt];
                    let self_closing = raw.ends_with('/');
                    let name = raw
                        .split(|c: char| c.is_whitespace() || c == '/')
                        .next()
                        .unwrap_or_default();
                    if name.is_empty() {
                        return Err(format!("malformed tag at line {}", line_at(&masked, lt)));
                    }
                    let index = nodes.len();
                    let parent = stack.last().copied();
                    nodes.push(Node {
                        name: name.to_string(),
                        start: lt,
                        inner_start: gt + 1,
                        inner_end: gt + 1,
                        end: gt + 1,
                        parent,
                        children: Vec::new(),
                    });
                    match parent {
                        Some(p) => nodes[p].children.push(index),
                        None => tops.push(index),
                    }
                    if !self_closing {
                        stack.push(index);
                    }
                    from = gt + 1;
                }
            }
        }
        if let Some(&open) = stack.last() {
            return Err(format!("unclosed <{}>", nodes[open].name));
        }
        let project = match tops.as_slice() {
            [p] if nodes[*p].name == "project" && nodes[*p].inner_start != nodes[*p].end => *p,
            _ => return Err("no single <project> element".to_string()),
        };
        let unit = indent_unit(&masked);
        let nl = crate::utils::line_endings::terminator(&text);
        Ok(Doc {
            text,
            masked,
            nodes,
            project,
            unit,
            nl,
        })
    }

    fn children<'d>(&'d self, n: usize, name: &'d str) -> impl Iterator<Item = usize> + 'd {
        self.nodes[n]
            .children
            .iter()
            .copied()
            .filter(move |&c| self.nodes[c].name == name)
    }

    fn child(&self, n: usize, name: &str) -> Option<usize> {
        self.children(n, name).next()
    }

    fn is_self_closing(&self, n: usize) -> bool {
        self.nodes[n].inner_start == self.nodes[n].end
    }

    /// Trimmed character data: comments and PIs dropped, CDATA unwrapped.
    fn text_of(&self, n: usize) -> String {
        let node = &self.nodes[n];
        let mut out = String::new();
        let mut rest = &self.text[node.inner_start..node.inner_end];
        while let Some(lt) = rest.find('<') {
            out.push_str(&rest[..lt]);
            let tail = &rest[lt..];
            let (skip_to, keep) = if let Some(body) = tail.strip_prefix("<![CDATA[") {
                let end = body.find("]]>").unwrap_or(body.len());
                (9 + end + 3, Some(&body[..end]))
            } else if let Some(body) = tail.strip_prefix("<!--") {
                (body.find("-->").map_or(tail.len(), |r| 4 + r + 3), None)
            } else if let Some(body) = tail.strip_prefix("<?") {
                (body.find("?>").map_or(tail.len(), |r| 2 + r + 2), None)
            } else {
                (1, Some("<"))
            };
            out.push_str(keep.unwrap_or_default());
            rest = tail.get(skip_to..).unwrap_or_default();
        }
        out.push_str(rest);
        out.trim().to_string()
    }

    fn child_text(&self, n: usize, name: &str) -> Option<String> {
        self.child(n, name).map(|c| self.text_of(c))
    }

    /// The span of a text element's value: the trimmed text outside
    /// comments, or the whole content when it holds CDATA (whose masked
    /// copy is blank).
    fn value_span(&self, n: usize) -> Range<usize> {
        let node = &self.nodes[n];
        if self.text[node.inner_start..node.inner_end].contains("<![CDATA[") {
            return node.inner_start..node.inner_end;
        }
        let inner = &self.masked[node.inner_start..node.inner_end];
        let lead = inner.len() - inner.trim_start().len();
        let start = node.inner_start + lead;
        start..start + inner.trim().len()
    }

    /// The `socket-patch` pin `dep` is, when a pin comment directly precedes
    /// it: its whole-line region, the tagged uuid and gav.
    fn pin_at(&self, dep: usize) -> Option<Pin> {
        let node = &self.nodes[dep];
        let before = self.text[..node.start].trim_end();
        let comment_end = before.len();
        if !before.ends_with("-->") {
            return None;
        }
        let comment_start = before.rfind("<!--")?;
        let body = before[comment_start..].strip_prefix(PIN_TAG)?;
        let uuid = body.get(..36)?.to_string();
        let gav = body.get(36..)?.strip_prefix(": ")?.strip_suffix(" -->")?;
        if uuid.contains(char::is_whitespace) || comment_end > node.start {
            return None;
        }
        let (start, end) = line_span(&self.text, comment_start, node.end);
        let version = self.child(dep, "version").map(|v| self.value_span(v));
        Some(Pin {
            start,
            end,
            uuid,
            gav: gav.to_string(),
            version,
        })
    }

    /// The top-level managed pin of `patch`'s g:a:v, from any patch uuid.
    fn pin_of_gav(&self, gav: &str) -> Option<Pin> {
        let deps = self.child(
            self.child(self.project, "dependencyManagement")?,
            "dependencies",
        )?;
        self.children(deps, "dependency")
            .filter_map(|d| self.pin_at(d))
            .find(|p| p.gav == gav)
    }

    /// The g:a declarations that are not pins, with their record key
    /// `version:<g>:<a>:<section>:<ordinal>`. `resolve` interpolates a
    /// `${...}` groupId or artifactId, which Maven does before matching.
    fn keyed_declarations(
        &self,
        g: &str,
        a: &str,
        resolve: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<(usize, String)> {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut out = Vec::new();
        for dep in self.declarations() {
            if self.coordinate(dep, "groupId", resolve).as_deref() != Some(g)
                || self.coordinate(dep, "artifactId", resolve).as_deref() != Some(a)
                || self.pin_at(dep).is_some()
            {
                continue;
            }
            // Declarations named through properties count apart, so literal
            // declarations keep the keys of records written before they
            // were matched.
            let mut section = self.section_of(dep);
            if self.has_property_coordinate(dep) {
                section.push_str(":$");
            }
            let ordinal = seen.entry(section.clone()).or_default();
            out.push((dep, format!("version:{g}:{a}:{section}:{ordinal}")));
            *ordinal += 1;
        }
        out
    }

    /// The `name` child of `dep`, interpolated through `resolve` when it
    /// holds a `${...}` expression; `None` when that is undefined.
    fn coordinate(
        &self,
        dep: usize,
        name: &str,
        resolve: &dyn Fn(&str) -> Option<String>,
    ) -> Option<String> {
        let raw = self.child_text(dep, name)?;
        if raw.contains("${") {
            resolve(&raw)
        } else {
            Some(raw)
        }
    }

    /// Whether `dep` names its groupId or artifactId through `${...}`.
    fn has_property_coordinate(&self, dep: usize) -> bool {
        ["groupId", "artifactId"]
            .iter()
            .any(|n| self.child_text(dep, n).is_some_and(|t| t.contains("${")))
    }

    /// `dependencies` / `dependencyManagement`, prefixed with
    /// `profile:<id>:` inside a profile.
    fn section_of(&self, dep: usize) -> String {
        let up = |n: usize| self.nodes[n].parent;
        let Some(owner) = up(dep).and_then(up) else {
            return String::new();
        };
        let (section, model) = if self.nodes[owner].name == "dependencyManagement" {
            ("dependencyManagement", up(owner))
        } else {
            ("dependencies", Some(owner))
        };
        match model {
            Some(m) if self.is_profile(m) => {
                let id = self.child_text(m, "id").unwrap_or_default();
                format!("profile:{id}:{section}")
            }
            _ => section.to_string(),
        }
    }

    /// `profiles/profile` directly under the project.
    fn is_profile(&self, n: usize) -> bool {
        self.nodes[n].name == "profile"
            && self.nodes[n].parent.is_some_and(|p| {
                self.nodes[p].name == "profiles" && self.nodes[p].parent == Some(self.project)
            })
    }

    /// The project or one of its profiles: where a model section lives.
    fn is_model_root(&self, n: usize) -> bool {
        n == self.project || self.is_profile(n)
    }

    /// `<dependency>` elements of the model: `dependencies` and
    /// `dependencyManagement` of the project and of each profile. Plugin
    /// dependencies and exclusions are not declarations.
    fn declarations(&self) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&i| {
                let Some(deps) = self.nodes[i].parent else {
                    return false;
                };
                let Some(owner) = self.nodes[deps].parent else {
                    return false;
                };
                self.nodes[i].name == "dependency"
                    && self.nodes[deps].name == "dependencies"
                    && (self.is_model_root(owner)
                        || (self.nodes[owner].name == "dependencyManagement"
                            && self.nodes[owner]
                                .parent
                                .is_some_and(|p| self.is_model_root(p))))
            })
            .collect()
    }

    /// Whether `dep` declares its GA's main jar (see
    /// [`crate::formats::maven::is_main_jar`]).
    fn is_main_jar(&self, dep: usize) -> bool {
        crate::formats::maven::is_main_jar(
            self.child_text(dep, "type").as_deref(),
            self.child_text(dep, "classifier").as_deref(),
        )
    }

    /// `project/dependencyManagement/dependencies/dependency`.
    fn is_top_level_managed(&self, dep: usize) -> bool {
        let up = |n: usize| self.nodes[n].parent;
        up(dep).and_then(up).is_some_and(|dm| {
            self.nodes[dm].name == "dependencyManagement" && up(dm) == Some(self.project)
        })
    }

    fn line_of(&self, pos: usize) -> usize {
        line_at(&self.text, pos)
    }

    fn line_start(&self, pos: usize) -> usize {
        self.text[..pos].rfind('\n').map_or(0, |n| n + 1)
    }

    fn starts_line(&self, pos: usize) -> bool {
        self.masked[self.line_start(pos)..pos]
            .bytes()
            .all(|b| b == b' ' || b == b'\t')
    }

    /// The blanks before `n` when it starts its line (a comment before it
    /// is not indentation), else one step deeper than its parent.
    fn indent_of(&self, n: usize) -> String {
        let start = self.nodes[n].start;
        if self.starts_line(start) {
            return self.text[self.line_start(start)..start]
                .chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .collect();
        }
        match self.nodes[n].parent {
            Some(p) => format!("{}{}", self.indent_of(p), self.unit),
            None => String::new(),
        }
    }

    /// The indentation of `n`'s children: that of its first child on a
    /// line of its own, else one step deeper than `n`.
    fn child_indent(&self, n: usize) -> String {
        self.nodes[n]
            .children
            .iter()
            .find(|&&c| self.starts_line(self.nodes[c].start))
            .map(|&c| self.indent_of(c))
            .unwrap_or_else(|| format!("{}{}", self.indent_of(n), self.unit))
    }

    /// Insert `lines` (relative to `indent`) before the element starting at
    /// `pos`: as whole lines when `pos` starts its line, else inline. `mark`
    /// (a range of `lines`) becomes the pin's byte range in the edit.
    fn insert_before(
        &self,
        pos: usize,
        indent: &str,
        lines: &[String],
        mark: Option<Range<usize>>,
    ) -> Edit {
        let nl = self.nl;
        if self.starts_line(pos) {
            let pieces: Vec<String> = lines.iter().map(|l| format!("{indent}{l}{nl}")).collect();
            let at = self.line_start(pos);
            return Edit {
                start: at,
                end: at,
                role: Role::Pin {
                    mark: mark.map(|m| byte_range(&pieces, 0, m)),
                },
                text: pieces.concat(),
            };
        }
        let pieces: Vec<String> = lines.iter().map(|l| format!("{nl}{indent}{l}")).collect();
        let mut text = pieces.concat();
        text.push_str(nl);
        text.push_str(
            &self.text[self.line_start(pos)..pos]
                .chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .collect::<String>(),
        );
        Edit {
            start: pos,
            end: pos,
            text,
            role: Role::Pin {
                mark: mark.map(|m| byte_range(&pieces, 0, m)),
            },
        }
    }

    /// Insert `lines` as the first children of `n` (expanding `<n/>`); see
    /// [`Doc::insert_before`] for `mark`.
    fn insert_first_child(&self, n: usize, lines: &[String], mark: Option<Range<usize>>) -> Edit {
        let nl = self.nl;
        let node = &self.nodes[n];
        let indent = self.child_indent(n);
        let pieces: Vec<String> = lines.iter().map(|l| format!("{nl}{indent}{l}")).collect();
        let body = pieces.concat();
        if self.is_self_closing(n) {
            let open = format!("<{}>", node.name);
            let text = format!("{open}{body}{nl}{}</{}>", self.indent_of(n), node.name);
            return Edit {
                start: node.start,
                end: node.end,
                text,
                role: Role::Pin {
                    mark: mark.map(|m| byte_range(&pieces, open.len(), m)),
                },
            };
        }
        let after = &self.masked[node.inner_start..];
        let same_line = !after
            .trim_start_matches([' ', '\t'])
            .starts_with(['\r', '\n']);
        let tail = if !same_line {
            String::new()
        } else if after.trim_start_matches([' ', '\t']).starts_with("</") {
            format!("{nl}{}", self.indent_of(n))
        } else {
            format!("{nl}{indent}")
        };
        Edit {
            start: node.inner_start,
            end: node.inner_start,
            text: format!("{body}{tail}"),
            role: Role::Pin {
                mark: mark.map(|m| byte_range(&pieces, 0, m)),
            },
        }
    }
}

/// The byte range of `pieces[lines]` in `pieces.concat()`, offset by `base`.
fn byte_range(pieces: &[String], base: usize, lines: Range<usize>) -> Range<usize> {
    let start = base + pieces[..lines.start].iter().map(String::len).sum::<usize>();
    let len: usize = pieces[lines].iter().map(String::len).sum();
    start..start + len
}

/// A `socket-patch` pin in a pom.
#[derive(Debug)]
struct Pin {
    /// The pin comment and its `<dependency>`, widened to whole lines.
    start: usize,
    end: usize,
    uuid: String,
    gav: String,
    /// The value span of its `<version>`.
    version: Option<Range<usize>>,
}

/// The pin of `patch`'s g:a:v in `doc`, from any patch uuid.
fn pin_of(doc: &Doc, patch: &JvmPatch<'_>) -> Option<Pin> {
    doc.pin_of_gav(&format!(
        "{}:{}:{}",
        patch.group_id, patch.artifact_id, patch.version
    ))
}

fn line_at(text: &str, pos: usize) -> usize {
    text[..pos].matches('\n').count() + 1
}

/// Past-the-end `>` of the open tag at `lt`, skipping quoted attributes.
fn tag_end(masked: &str, lt: usize) -> Option<usize> {
    let mut quote = None;
    for (i, b) in masked.bytes().enumerate().skip(lt + 1) {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), _) if b == q => quote = None,
            (None, b'>') => return Some(i),
            (None, b'<') => return None,
            _ => {}
        }
    }
    None
}

/// The closing `>` of a `<!DOCTYPE …>` (with an optional `[…]` subset).
fn declaration_end(masked: &str, lt: usize) -> Option<usize> {
    let gt = masked[lt..].find('>')? + lt;
    match masked[lt..gt].find('[') {
        Some(_) => masked[lt..].find("]>").map(|r| lt + r + 1),
        None => Some(gt),
    }
}

/// One indentation step: a tab when indented lines start with tabs, else
/// the smallest space indent (default two spaces).
fn indent_unit(masked: &str) -> String {
    let (mut tabs, mut spaces, mut min_spaces) = (0, 0, usize::MAX);
    for line in masked.split('\n').skip(1) {
        let ws: &str = &line[..line.len() - line.trim_start_matches([' ', '\t']).len()];
        if ws.is_empty() || !line[ws.len()..].starts_with('<') {
            continue;
        }
        if ws.starts_with('\t') {
            tabs += 1;
        } else {
            spaces += 1;
            let n = ws.bytes().take_while(|b| *b == b' ').count();
            min_spaces = min_spaces.min(n);
        }
    }
    if tabs > spaces {
        "\t".to_string()
    } else if min_spaces == usize::MAX {
        "  ".to_string()
    } else {
        " ".repeat(min_spaces)
    }
}

// ── suffixed pom: a port of depscan's `suffixMavenPom` ─────────────────

/// An element of the depscan pom scan (`maven-pom-scan.ts`).
#[derive(Debug, Clone)]
struct ScanEl {
    name: String,
    end_tag_close: usize,
    inner_start: usize,
    inner_end: usize,
    self_closing: bool,
}

/// `None`: `lt` opens a tag; `Some(None)`: the skipped construct is
/// unterminated; `Some(Some(end))`: resume at `end`.
fn scan_skip_markup(text: &str, lt: usize) -> Option<Option<usize>> {
    const SKIPPED: [(&str, &str); 3] = [("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")];
    SKIPPED
        .iter()
        .find(|(open, _)| text[lt..].starts_with(open))
        .map(|(open, close)| {
            text[lt + open.len()..]
                .find(close)
                .map(|r| lt + open.len() + r + close.len())
        })
}

fn scan_tag_name(text: &str, from: usize) -> &str {
    let rest = &text[from..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    &rest[..end]
}

fn find_from(text: &str, needle: char, from: usize) -> Option<usize> {
    text.get(from..)?.find(needle).map(|r| from + r)
}

fn byte_at(text: &str, i: usize) -> Option<u8> {
    text.as_bytes().get(i).copied()
}

/// `(inner_end, end_tag_close)` of the element whose content starts at
/// `inner_start` (depth counting, names unchecked, as in depscan).
fn scan_subtree_end(text: &str, inner_start: usize) -> Option<(usize, usize)> {
    let mut depth = 1usize;
    let mut cursor = inner_start;
    while cursor < text.len() {
        let lt = find_from(text, '<', cursor)?;
        match scan_skip_markup(text, lt) {
            Some(None) => return None,
            Some(Some(end)) => {
                cursor = end;
                continue;
            }
            None => {}
        }
        let gt = find_from(text, '>', lt)?;
        if byte_at(text, lt + 1) == Some(b'/') {
            depth -= 1;
            if depth == 0 {
                return Some((lt, gt + 1));
            }
        } else if gt == 0 || byte_at(text, gt - 1) != Some(b'/') {
            depth += 1;
        }
        cursor = gt + 1;
    }
    None
}

fn scan_children_from(text: &str, content_start: usize) -> Option<Vec<ScanEl>> {
    let mut children = Vec::new();
    let mut cursor = content_start;
    while cursor < text.len() {
        let lt = find_from(text, '<', cursor)?;
        match scan_skip_markup(text, lt) {
            Some(None) => return None,
            Some(Some(end)) => {
                cursor = end;
                continue;
            }
            None => {}
        }
        if text[lt..].starts_with("</") {
            return Some(children);
        }
        let name = scan_tag_name(text, lt + 1);
        if name.is_empty() {
            return None;
        }
        let tag_end = find_from(text, '>', lt)?;
        if byte_at(text, tag_end - 1) == Some(b'/') {
            children.push(ScanEl {
                name: name.to_string(),
                end_tag_close: tag_end + 1,
                inner_start: tag_end + 1,
                inner_end: tag_end + 1,
                self_closing: true,
            });
            cursor = tag_end + 1;
            continue;
        }
        let (inner_end, end_tag_close) = scan_subtree_end(text, tag_end + 1)?;
        children.push(ScanEl {
            name: name.to_string(),
            end_tag_close,
            inner_start: tag_end + 1,
            inner_end,
            self_closing: false,
        });
        cursor = end_tag_close;
    }
    None
}

/// The depth-1 children of the single `<project>` element.
fn scan_pom_project(text: &str) -> Option<Vec<ScanEl>> {
    let mut cursor = 0;
    while cursor < text.len() {
        let lt = find_from(text, '<', cursor)?;
        match scan_skip_markup(text, lt) {
            Some(None) => return None,
            Some(Some(end)) => {
                cursor = end;
                continue;
            }
            None => {}
        }
        if text[lt..].starts_with("<!") {
            cursor = find_from(text, '>', lt + 2)? + 1;
            continue;
        }
        if scan_tag_name(text, lt + 1) != "project" {
            return None;
        }
        let gt = find_from(text, '>', lt)?;
        if byte_at(text, gt - 1) == Some(b'/') {
            return None;
        }
        return scan_children_from(text, gt + 1);
    }
    None
}

fn scan_find<'e>(children: &'e [ScanEl], name: &str) -> Option<&'e ScanEl> {
    children.iter().find(|c| c.name == name)
}

/// Trimmed inner text of the first direct child `name` of `el`.
fn scan_child_text(text: &str, el: &ScanEl, name: &str) -> Option<String> {
    let children = if el.self_closing {
        Vec::new()
    } else {
        scan_children_from(text, el.inner_start)?
    };
    scan_find(&children, name).map(|c| text[c.inner_start..c.inner_end].trim().to_string())
}

fn literalize_project_version_refs(pom: &str, base: &str) -> String {
    let literal = pom
        .replace("${project.version}", base)
        .replace("${pom.version}", base);
    let declares_version_property = scan_pom_project(&literal)
        .and_then(|children| {
            let properties = scan_find(&children, "properties")?.clone();
            scan_child_text(&literal, &properties, "version")
        })
        .is_some();
    if declares_version_property {
        literal
    } else {
        literal.replace("${version}", base)
    }
}

/// The upstream pom rewritten to advertise `suffixed` instead of `base`, or
/// `None` to refuse: byte-for-byte the semantics of depscan's
/// `suffixMavenPom` (`workspaces/app/src/patches/maven-suffix.ts`), so an
/// offline build serves the pom the service would.
fn suffix_maven_pom(pom: &str, base: &str, suffixed: &str) -> Option<String> {
    let children = scan_pom_project(pom)?;
    if let Some(version) = scan_find(&children, "version") {
        let inner = &pom[version.inner_start..version.inner_end];
        if inner.contains("${") || inner.trim() != base {
            return None;
        }
        let spliced = format!(
            "{}{suffixed}{}",
            &pom[..version.inner_start],
            &pom[version.inner_end..]
        );
        return Some(literalize_project_version_refs(&spliced, base));
    }
    let parent = scan_find(&children, "parent")?;
    if scan_child_text(pom, parent, "version").as_deref() != Some(base) {
        return None;
    }
    let at = scan_find(&children, "artifactId")?.end_tag_close;
    let spliced = format!(
        "{}\n  <version>{suffixed}</version>{}",
        &pom[..at],
        &pom[at..]
    );
    Some(literalize_project_version_refs(&spliced, base))
}

// ── inherited version references ────────────────────────────────────────
//
// Maven (and Coursier) interpolate a pom after merging its parents into it,
// so a `${project.version}` written in a parent reads the version of the
// pom being resolved: the suffixed version, for the pom the tree serves.
// A sibling the parent manages at `${project.version}` (log4j, logback)
// would resolve at `<base>-socket.<hex8>`, which no repository has. The
// parents stay the upstream ones, so the suffixed pom declares again, at
// the base version, what it would inherit through such a reference.

/// Delimit what [`suffixed_pom`] adds to a pom for its inherited versions.
const INHERITED_BEGIN: &str = "<!-- socket-patch:inherited:begin -->";
const INHERITED_END: &str = "<!-- socket-patch:inherited:end -->";

/// The pom `patch`'s tree serves at the suffixed version: the upstream pom
/// with its own version suffixed ([`suffix_maven_pom`]) and, when the
/// parent chain was read ([`JvmPatch::upstream_parents`]), the properties,
/// managed dependencies and dependencies it inherits through a reference
/// to the pom's version declared again at the base version, so it resolves
/// exactly what the upstream pom does. Refused when that cannot be
/// expressed, and whenever the result would still resolve a suffixed
/// version the tree does not serve.
pub(crate) fn suffixed_pom(patch: &JvmPatch<'_>) -> Result<String, JvmRefusal> {
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    let sv = patch.suffixed_version();
    let suffix = |pom: Option<&str>| {
        pom.and_then(|pom| suffix_maven_pom(pom, v, &sv))
            .ok_or_else(|| JvmRefusal {
                code: UPSTREAM_UNAVAILABLE,
                detail: format!(
                    "reason: suffix_unavailable: the upstream pom of {g}:{a}:{v} computes its \
                     own version, so it cannot be served as {sv}"
                ),
            })
    };
    let upstream = std::str::from_utf8(patch.upstream_pom).ok();
    let Some(parents) = patch.upstream_parents else {
        return suffix(upstream);
    };
    let unresolvable = |why: String| JvmRefusal {
        code: UPSTREAM_UNAVAILABLE,
        detail: format!(
            "reason: inherited_version_unresolvable: {why}, so {g}:{a}:{v} cannot be served as \
             {sv}"
        ),
    };
    // A committed pom carries what an earlier run added: computed again.
    let bare = suffix(upstream.map(strip_inherited).as_deref())?;
    let c = patch.coords();
    let resolved = match Inherited::read(&bare, parents, &c) {
        Ok(chain) => chain.resolve().map_err(&unresolvable)?,
        // A pom that cannot be read hides what it defines, which is
        // harmless only when no parent names the version at all.
        Err(unreadable) => {
            if parents
                .iter()
                .any(|p| names_model_version(&String::from_utf8_lossy(p)))
            {
                return Err(unresolvable(unreadable));
            }
            bare
        }
    };
    // The invariant that protects the build: nothing the pom resolves or
    // manages may name a suffixed version the tree does not serve.
    if let Some(leak) = inherited_leaks(&resolved, parents, &c) {
        return Err(unresolvable(leak.detail));
    }
    // A committed tree is re-planned from this pom with its version put
    // back, parents or not: that must give the same bytes.
    let replanned = unsuffixed(&resolved, v, &sv).and_then(|pom| suffix_maven_pom(&pom, v, &sv));
    if replanned.as_deref() != Some(resolved.as_str()) {
        return Err(unresolvable(
            "the versions it inherits cannot be written so that the pom reads the same again"
                .to_string(),
        ));
    }
    Ok(resolved)
}

/// The literal coordinates of `pom`'s `<parent>` (`None`: it has none), as
/// Maven requires them; an error names what is wrong with them.
pub(crate) fn parent_gav(pom: &[u8]) -> Result<Option<Gav>, String> {
    let text = String::from_utf8_lossy(pom);
    let children = scan_pom_project(&text).ok_or("it is not a readable pom")?;
    let Some(parent) = scan_find(&children, "parent") else {
        return Ok(None);
    };
    let part = |name: &str| scan_child_text(&text, parent, name).filter(|t| !t.is_empty());
    let (Some(g), Some(a), Some(v)) = (part("groupId"), part("artifactId"), part("version")) else {
        return Err("its <parent> lacks a groupId, artifactId or version".to_string());
    };
    if !safe_coordinates(&g, &a, &v) {
        return Err(format!(
            "its <parent> {g}:{a}:{v} is not a literal coordinate"
        ));
    }
    Ok(Some((g, a, v)))
}

/// Why the committed pom of `c` resolves a suffixed version nothing
/// serves, given its upstream `parents` (nearest first): the tree was
/// vendored before the parent chain was read. `None` when it does not, or
/// only in management no dependency of the pom uses (which no Maven before
/// 4 applies), or when a pom cannot be read.
pub fn committed_pom_leak(read: ReadFn<'_>, c: &Coords<'_>, parents: &[Vec<u8>]) -> Option<String> {
    let pom = committed_pom(read, c)?;
    let leak = inherited_leaks(&pom, parents, c).filter(|leak| leak.hard)?;
    Some(format!(
        "the vendored pom of {}:{}:{} resolves a version nothing serves: {} (re-run \
         `socket-patch vendor` to rewrite it)",
        c.group_id,
        c.artifact_id,
        c.suffixed_version(),
        leak.detail
    ))
}

/// Whether `text` holds a reference to the model's own version, in any of
/// its spellings.
fn names_model_version(text: &str) -> bool {
    ["${project.version}", "${pom.version}", "${version}"]
        .iter()
        .any(|r| text.contains(r))
}

/// `pom` without the blocks [`suffixed_pom`] added: whole lines where a
/// block was added as lines, else the marked span alone.
fn strip_inherited(pom: &str) -> std::borrow::Cow<'_, str> {
    if !pom.contains(INHERITED_BEGIN) {
        return std::borrow::Cow::Borrowed(pom);
    }
    let mut out = String::with_capacity(pom.len());
    let mut rest = pom;
    while let Some(begin) = rest.find(INHERITED_BEGIN) {
        let Some(end) = rest[begin..]
            .find(INHERITED_END)
            .map(|r| begin + r + INHERITED_END.len())
        else {
            break;
        };
        let line = rest[..begin].rfind('\n').map_or(0, |n| n + 1);
        let indented = rest[line..begin].bytes().all(|b| b == b' ' || b == b'\t');
        let after = &rest[end..];
        match after
            .strip_prefix("\r\n")
            .or_else(|| after.strip_prefix('\n'))
        {
            Some(next) if indented => {
                out.push_str(&rest[..line]);
                rest = next;
            }
            _ => {
                out.push_str(&rest[..begin]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

/// The `${name}` references of `text`, in order.
fn refs_in(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let at = rest.find("${")?;
        let after = &rest[at + 2..];
        let close = after.find('}')?;
        rest = &after[close + 1..];
        Some(&after[..close])
    })
}

/// A dependency's management key on its raw text, as Maven merges a child
/// with its parent before interpolating:
/// `groupId:artifactId:type[:classifier]`.
type DepKey = (String, String, String, Option<String>);

/// Something a suffixed pom resolves or manages at a suffixed version.
#[derive(Debug, PartialEq, Eq)]
struct Leak {
    /// A dependency of the pom, or a BOM it imports, resolves there: the
    /// build fails. Otherwise only management, or a profile, names it.
    hard: bool,
    detail: String,
}

/// The first [`Leak`] of the suffixed pom `vendored` over its upstream
/// `parents`, a hard one first; `None` when it has none or a pom cannot be
/// read.
fn inherited_leaks(vendored: &str, parents: &[Vec<u8>], c: &Coords<'_>) -> Option<Leak> {
    let mut leaks = Inherited::read(vendored, parents, c).ok()?.leaks();
    let at = leaks.iter().position(|l| l.hard).unwrap_or(0);
    (!leaks.is_empty()).then(|| leaks.swap_remove(at))
}

/// A suffixed pom over the upstream poms it inherits from.
struct Inherited<'a> {
    c: Coords<'a>,
    sv: String,
    /// The suffixed pom, then its parents, nearest first.
    docs: Vec<Doc>,
    /// Whether the pom at that index is not UTF-8 (read lossily: its
    /// markup is ASCII, but its text cannot be copied).
    lossy: Vec<bool>,
    /// `${version}` reads the model: no pom of the chain defines a
    /// property of that name, which Maven would read first.
    bare_version: bool,
}

impl<'a> Inherited<'a> {
    fn read(suffixed: &str, parents: &[Vec<u8>], c: &Coords<'a>) -> Result<Self, String> {
        if parents.len() > MAX_EXTERNAL_DEPTH {
            return Err("its parent poms nest too deep".to_string());
        }
        let child = Doc::parse(suffixed.to_string())
            .map_err(|e| format!("its pom is not well-formed ({e})"))?;
        let (mut docs, mut lossy) = (vec![child], vec![false]);
        for bytes in parents {
            let text = String::from_utf8_lossy(bytes);
            let named = Self::parent_label(&docs[docs.len() - 1]);
            lossy.push(matches!(text, std::borrow::Cow::Owned(_)));
            docs.push(
                Doc::parse(text.into_owned())
                    .map_err(|e| format!("{named} is not well-formed ({e})"))?,
            );
        }
        let bare_version = !docs.iter().any(|doc| {
            Self::models(doc).into_iter().any(|model| {
                Self::properties(doc, model)
                    .into_iter()
                    .any(|p| doc.nodes[p].name == "version")
            })
        });
        Ok(Self {
            c: *c,
            sv: c.suffixed_version(),
            docs,
            lossy,
            bare_version,
        })
    }

    /// `the parent pom g:a:v`, as `doc` names its parent.
    fn parent_label(doc: &Doc) -> String {
        let part = |name: &str| {
            doc.child(doc.project, "parent")
                .and_then(|p| doc.child_text(p, name))
                .unwrap_or_default()
        };
        format!(
            "the parent pom {}:{}:{}",
            part("groupId"),
            part("artifactId"),
            part("version")
        )
    }

    /// `docs[i]` for a message.
    fn label(&self, i: usize) -> String {
        match i {
            0 => "the pom itself".to_string(),
            _ => Self::parent_label(&self.docs[i - 1]),
        }
    }

    fn profiles(doc: &Doc) -> Vec<usize> {
        doc.child(doc.project, "profiles")
            .into_iter()
            .flat_map(|ps| doc.children(ps, "profile"))
            .collect()
    }

    /// The project, then its profiles: where a model section lives.
    fn models(doc: &Doc) -> Vec<usize> {
        let mut models = vec![doc.project];
        models.extend(Self::profiles(doc));
        models
    }

    fn profile_id(doc: &Doc, profile: usize) -> String {
        doc.child_text(profile, "id").unwrap_or_default()
    }

    /// The elements of `model`'s `<properties>`.
    fn properties(doc: &Doc, model: usize) -> Vec<usize> {
        doc.child(model, "properties")
            .map(|p| doc.nodes[p].children.clone())
            .unwrap_or_default()
    }

    /// The `<dependency>` elements of `model`'s `<dependencies>`, or of
    /// its `<dependencyManagement>`.
    fn dependencies(doc: &Doc, model: usize, managed: bool) -> Vec<usize> {
        let owner = if managed {
            doc.child(model, "dependencyManagement")
        } else {
            Some(model)
        };
        owner
            .and_then(|o| doc.child(o, "dependencies"))
            .map(|deps| doc.children(deps, "dependency").collect())
            .unwrap_or_default()
    }

    fn repositories(doc: &Doc, model: usize) -> Vec<usize> {
        doc.child(model, "repositories")
            .map(|r| doc.children(r, "repository").collect())
            .unwrap_or_default()
    }

    /// The text of every leaf element under `n` (`n` itself when it has no
    /// child element).
    fn leaves(doc: &Doc, n: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            match doc.nodes[n].children.as_slice() {
                [] => out.push(doc.text_of(n)),
                children => stack.extend(children.iter().rev()),
            }
        }
        out
    }

    fn key(doc: &Doc, dep: usize) -> DepKey {
        (
            doc.child_text(dep, "groupId").unwrap_or_default(),
            doc.child_text(dep, "artifactId").unwrap_or_default(),
            doc.child_text(dep, "type")
                .unwrap_or_else(|| "jar".to_string()),
            doc.child_text(dep, "classifier"),
        )
    }

    fn names_version(&self, text: &str) -> bool {
        refs_in(text).any(|name| {
            matches!(name, "project.version" | "pom.version")
                || (self.bare_version && name == "version")
        })
    }

    /// Whether the element `n` of `doc` names the pom's version anywhere.
    fn reads_version(&self, doc: &Doc, n: usize) -> bool {
        Self::leaves(doc, n).iter().any(|t| self.names_version(t))
    }

    /// `text` with every reference to the pom's version made the base
    /// version, which is what it read upstream.
    fn literal(&self, text: &str) -> String {
        let base = self.c.version;
        let text = text
            .replace("${project.version}", base)
            .replace("${pom.version}", base);
        if self.bare_version {
            text.replace("${version}", base)
        } else {
            text
        }
    }

    /// The management entry of the patched artifact's own main jar at the
    /// pom's version: it reads the suffixed version, which the tree
    /// serves.
    fn is_own(&self, doc: &Doc, dep: usize) -> bool {
        let text = |name: &str| doc.child_text(dep, name).unwrap_or_default();
        let group = text("groupId");
        let version = text("version");
        (group == self.c.group_id
            || matches!(
                group.as_str(),
                "${project.groupId}" | "${pom.groupId}" | "${groupId}"
            ))
            && text("artifactId") == self.c.artifact_id
            && doc.is_main_jar(dep)
            && self.names_version(&version)
            && version.starts_with("${")
            && version.find('}') == Some(version.len() - 1)
            && Self::leaves(doc, dep)
                .iter()
                .filter(|t| self.names_version(t))
                .count()
                == 1
    }

    /// The nearest pom whose own `<properties>` define `name` (the last
    /// definition, as Maven reads a repeated one), with that element.
    fn base_definition(&self, name: &str) -> Option<(usize, usize)> {
        self.docs.iter().enumerate().find_map(|(i, doc)| {
            Self::properties(doc, doc.project)
                .into_iter()
                .rev()
                .find(|p| doc.nodes[*p].name == name)
                .map(|p| (i, p))
        })
    }

    /// Every property a dependency, a managed dependency or a repository of
    /// the chain may read, through any definition of any pom or profile:
    /// what a consumer's resolution depends on. A property only plugins
    /// read (`commons.release.version`) is not one.
    fn reachable(&self) -> BTreeSet<String> {
        let mut definitions: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut queue: Vec<String> = Vec::new();
        for doc in &self.docs {
            for model in Self::models(doc) {
                for p in Self::properties(doc, model) {
                    definitions
                        .entry(doc.nodes[p].name.as_str())
                        .or_default()
                        .push(doc.text_of(p));
                }
                let read = Self::dependencies(doc, model, false)
                    .into_iter()
                    .chain(Self::dependencies(doc, model, true))
                    .chain(Self::repositories(doc, model));
                for n in read {
                    for text in Self::leaves(doc, n) {
                        queue.extend(refs_in(&text).map(str::to_string));
                    }
                }
            }
        }
        let mut seen = BTreeSet::new();
        while let Some(name) = queue.pop() {
            let Some(texts) = definitions.get(name.as_str()) else {
                continue;
            };
            if seen.insert(name) {
                for text in texts {
                    queue.extend(refs_in(text).map(str::to_string));
                }
            }
        }
        seen
    }

    /// The suffixed pom with every version it inherits through a reference
    /// to the pom's version declared again at the base version, or why
    /// that cannot be done faithfully. A child's own property and
    /// declaration always beat a parent's, a parent profile's included, so
    /// anything a profile on the way may set instead is refused.
    fn resolve(&self) -> Result<String, String> {
        let reachable = self.reachable();
        let mut properties = Vec::new();
        for name in &reachable {
            let Some((at, node)) = self.base_definition(name) else {
                continue;
            };
            let doc = &self.docs[at];
            if at == 0 || !self.names_version(&doc.text_of(node)) {
                continue;
            }
            let redefined = (1..=at).find(|&i| {
                Self::profiles(&self.docs[i]).into_iter().any(|profile| {
                    Self::properties(&self.docs[i], profile)
                        .into_iter()
                        .any(|p| self.docs[i].nodes[p].name == *name)
                })
            });
            if let Some(i) = redefined {
                return Err(format!(
                    "{} sets the property `{name}` from the pom's own version and a profile of \
                     {} may set it instead",
                    self.label(at),
                    self.label(i)
                ));
            }
            if self.lossy[at] {
                return Err(format!("{} is not UTF-8", self.label(at)));
            }
            let n = &doc.nodes[node];
            properties.push(format!(
                "<{name}>{}</{name}>",
                self.literal(&doc.text[n.inner_start..n.inner_end])
            ));
        }
        for (i, doc) in self.docs.iter().enumerate().skip(1) {
            for profile in Self::profiles(doc) {
                let id = Self::profile_id(doc, profile);
                // A profile's definition is read ahead of every pom above
                // it, but after the poms below.
                let property = Self::properties(doc, profile).into_iter().find(|&p| {
                    let name = doc.nodes[p].name.as_str();
                    reachable.contains(name)
                        && self.names_version(&doc.text_of(p))
                        && self.base_definition(name).is_none_or(|(at, _)| at >= i)
                });
                if let Some(p) = property {
                    return Err(format!(
                        "profile `{id}` of {} sets the property `{}` from the pom's own version",
                        self.label(i),
                        doc.nodes[p].name
                    ));
                }
                let declares = [false, true].into_iter().any(|managed| {
                    Self::dependencies(doc, profile, managed)
                        .into_iter()
                        .any(|dep| self.reads_version(doc, dep))
                });
                if declares {
                    return Err(format!(
                        "profile `{id}` of {} declares a dependency at the pom's own version",
                        self.label(i)
                    ));
                }
            }
            let repository = Self::models(doc).into_iter().any(|model| {
                Self::repositories(doc, model)
                    .into_iter()
                    .any(|r| self.reads_version(doc, r))
            });
            if repository {
                return Err(format!(
                    "{} addresses a repository through the pom's own version",
                    self.label(i)
                ));
            }
        }
        let managed = self.copies(true)?;
        let dependencies = self.copies(false)?;
        self.splice(properties, managed, dependencies)
    }

    /// The parents' `<dependencies>` (or managed dependencies) the pom
    /// must declare itself, as lines: every inherited entry up to the last
    /// one naming the pom's version, in the order Maven inherits them (a
    /// nearer pom's first, one per key). Maven lists a child's own
    /// declarations ahead of the inherited ones, so declaring only the
    /// entries that name the version would reorder the others, and with
    /// them the classpath and which imported BOM wins.
    fn copies(&self, managed: bool) -> Result<Vec<String>, String> {
        let what = if managed {
            "managed dependencies"
        } else {
            "dependencies"
        };
        let child = &self.docs[0];
        let mut seen: BTreeSet<DepKey> = Self::dependencies(child, child.project, managed)
            .into_iter()
            .map(|dep| Self::key(child, dep))
            .collect();
        let mut inherited: Vec<(usize, usize)> = Vec::new();
        let mut repeated: Option<usize> = None;
        for (i, doc) in self.docs.iter().enumerate().skip(1) {
            let mut own = BTreeSet::new();
            for dep in Self::dependencies(doc, doc.project, managed) {
                let key = Self::key(doc, dep);
                if !own.insert(key.clone()) {
                    repeated.get_or_insert(i);
                }
                if seen.insert(key) {
                    inherited.push((i, dep));
                }
            }
        }
        let Some(last) = inherited.iter().rposition(|&(i, dep)| {
            self.reads_version(&self.docs[i], dep) && !self.is_own(&self.docs[i], dep)
        }) else {
            return Ok(Vec::new());
        };
        let through = inherited[last].0;
        let source = self.label(through);
        // Which of two entries with one key Maven keeps depends on where
        // they are declared.
        if let Some(i) = repeated.filter(|&i| i <= through) {
            return Err(format!(
                "{source} declares {what} at the pom's own version and {} declares one of its \
                 {what} twice",
                self.label(i)
            ));
        }
        let profiled = (0..=through).find(|&i| {
            Self::profiles(&self.docs[i])
                .into_iter()
                .any(|profile| !Self::dependencies(&self.docs[i], profile, managed).is_empty())
        });
        if let Some(i) = profiled {
            return Err(format!(
                "{source} declares {what} at the pom's own version and a profile of {} adds \
                 {what} of its own",
                self.label(i)
            ));
        }
        let mut lines = Vec::new();
        for &(i, dep) in &inherited[..=last] {
            let doc = &self.docs[i];
            let keyed = ["groupId", "artifactId", "type", "classifier"]
                .iter()
                .any(|name| {
                    doc.child_text(dep, name)
                        .is_some_and(|t| self.names_version(&t))
                });
            if keyed {
                return Err(format!(
                    "{} names one of its {what} through the pom's own version",
                    self.label(i)
                ));
            }
            let node = &doc.nodes[dep];
            let raw = &doc.text[node.start..node.end];
            if self.lossy[i] || raw.contains("socket-patch:inherited") {
                return Err(format!(
                    "{} declares {what} at the pom's own version in text that cannot be copied",
                    self.label(i)
                ));
            }
            let indent = doc.indent_of(dep);
            lines.extend(self.literal(raw).split('\n').enumerate().map(|(n, line)| {
                let line = line.trim_end_matches('\r');
                match n {
                    0 => line,
                    _ => line
                        .strip_prefix(indent.as_str())
                        .unwrap_or_else(|| line.trim_start()),
                }
                .to_string()
            }));
        }
        Ok(lines)
    }

    /// The suffixed pom with `properties`, `managed` and `dependencies`
    /// (lines) added to its own sections, each run between the markers; a
    /// section the pom lacks is added before `</project>`.
    fn splice(
        &self,
        properties: Vec<String>,
        managed: Vec<String>,
        dependencies: Vec<String>,
    ) -> Result<String, String> {
        let doc = &self.docs[0];
        let u = doc.unit.as_str();
        let project = doc.project;
        let empty = |n: usize| {
            format!(
                "its pom has an empty <{}/> the inherited versions cannot be added to",
                doc.nodes[n].name
            )
        };
        let mut inserts: Vec<(usize, String)> = Vec::new();
        let mut loose: Vec<String> = Vec::new();
        if !properties.is_empty() {
            match doc.child(project, "properties") {
                Some(p) if doc.is_self_closing(p) => return Err(empty(p)),
                Some(p) => inserts.push(self.block_in(p, properties)),
                None => loose.extend(nest(u, "<properties>", properties, "</properties>")),
            }
        }
        if !managed.is_empty() {
            let section = |lines| nest(u, "<dependencies>", lines, "</dependencies>");
            match doc.child(project, "dependencyManagement") {
                None => loose.extend(nest(
                    u,
                    "<dependencyManagement>",
                    section(managed),
                    "</dependencyManagement>",
                )),
                Some(dm) if doc.is_self_closing(dm) => return Err(empty(dm)),
                Some(dm) => match doc.child(dm, "dependencies") {
                    Some(deps) if doc.is_self_closing(deps) => return Err(empty(deps)),
                    Some(deps) => inserts.push(self.block_in(deps, managed)),
                    None => inserts.push(self.block_in(dm, section(managed))),
                },
            }
        }
        if !dependencies.is_empty() {
            match doc.child(project, "dependencies") {
                Some(deps) if doc.is_self_closing(deps) => return Err(empty(deps)),
                Some(deps) => inserts.push(self.block_in(deps, dependencies)),
                None => loose.extend(nest(u, "<dependencies>", dependencies, "</dependencies>")),
            }
        }
        if !loose.is_empty() {
            inserts.push(self.block_in(project, loose));
        }
        inserts.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
        let mut text = doc.text.clone();
        for (at, block) in inserts {
            text.insert_str(at, &block);
        }
        Ok(text)
    }

    /// `lines` between the markers as the last children of `container`:
    /// where to insert, and the text. Whole lines before a close tag that
    /// starts its line, else the marked span alone right before it, which
    /// is what [`strip_inherited`] takes out again.
    fn block_in(&self, container: usize, lines: Vec<String>) -> (usize, String) {
        let doc = &self.docs[0];
        let nl = doc.nl;
        let at = doc.nodes[container].inner_end;
        let indent = doc.child_indent(container);
        if doc.starts_line(at) {
            let block: String = std::iter::once(INHERITED_BEGIN.to_string())
                .chain(lines)
                .chain(std::iter::once(INHERITED_END.to_string()))
                .map(|l| format!("{indent}{l}{nl}"))
                .collect();
            return (doc.line_start(at), block);
        }
        let body: String = lines.iter().map(|l| format!("{nl}{indent}{l}")).collect();
        (
            at,
            format!("{INHERITED_BEGIN}{body}{nl}{indent}{INHERITED_END}"),
        )
    }

    /// What the suffixed pom resolves or manages at the suffixed version,
    /// read the way Maven does: the chain merged (a nearer pom's property
    /// and declaration first, one per raw key), then interpolated with the
    /// model's version being the suffixed one. The tree serves the patched
    /// artifact's main jar at that version and nothing else.
    fn leaks(&self) -> Vec<Leak> {
        let child = &self.docs[0];
        let sv = self.sv.as_str();
        let model = |name: &str| -> Option<String> {
            let bare = name
                .strip_prefix("project.")
                .or_else(|| name.strip_prefix("pom."))
                .unwrap_or(name);
            match bare {
                "version" => Some(sv.to_string()),
                "groupId" => Some(self.c.group_id.to_string()),
                "artifactId" => Some(self.c.artifact_id.to_string()),
                "parent.version" | "parent.groupId" | "parent.artifactId" => child
                    .child(child.project, "parent")
                    .and_then(|p| child.child_text(p, &bare["parent.".len()..])),
                _ => None,
            }
        };
        let own: Vec<BTreeMap<String, String>> = self
            .docs
            .iter()
            .map(|doc| {
                Self::properties(doc, doc.project)
                    .into_iter()
                    .map(|p| (doc.nodes[p].name.clone(), doc.text_of(p)))
                    .collect()
            })
            .collect();
        let user = BTreeMap::new();
        let lookup = |name: &str| {
            let layers = own.iter().map(|own| PomLayer {
                own,
                profiles: Vec::new(),
            });
            lookup_property(name, &model, &user, layers)
        };
        let expand = |text: String| interpolate_keeping(&text, &lookup).unwrap_or(text);
        // `(g:a[:v], expanded key, reads the suffixed version)` of a
        // declaration; the patched artifact's own main jar does not count.
        let entry = |doc: &Doc, dep: usize| -> (String, Option<String>, DepKey, bool) {
            let part = |name: &str| doc.child_text(dep, name).map(&expand);
            let (g, a) = (
                part("groupId").unwrap_or_default(),
                part("artifactId").unwrap_or_default(),
            );
            let version = part("version").filter(|v| !v.is_empty());
            let (kind, classifier) = (part("type"), part("classifier"));
            let own = g == self.c.group_id
                && a == self.c.artifact_id
                && version.as_deref() == Some(sv)
                && crate::formats::maven::is_main_jar(kind.as_deref(), classifier.as_deref());
            let reads = [
                Some(&g),
                Some(&a),
                version.as_ref(),
                kind.as_ref(),
                classifier.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|t| t.contains(sv));
            let key = (
                g.clone(),
                a.clone(),
                kind.unwrap_or_else(|| "jar".to_string()),
                classifier,
            );
            (format!("{g}:{a}"), version, key, reads && !own)
        };
        let mut leaks = Vec::new();

        // Management first: a dependency without a version takes the first
        // entry of its key; `Some` when that one reads the suffixed version.
        let mut managed: BTreeMap<DepKey, Option<(String, usize)>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (at, doc) in self.docs.iter().enumerate() {
            for dep in Self::dependencies(doc, doc.project, true) {
                if !seen.insert(Self::key(doc, dep)) {
                    continue;
                }
                let (ga, version, key, reads) = entry(doc, dep);
                let version = version.unwrap_or_default();
                if doc.child_text(dep, "scope").as_deref() != Some("import") {
                    managed
                        .entry(key)
                        .or_insert_with(|| reads.then_some((version, at)));
                } else if reads {
                    leaks.push(Leak {
                        hard: true,
                        detail: format!(
                            "the suffixed pom imports the BOM {ga}:{version}, where {} reads the \
                             pom's own version",
                            self.label(at)
                        ),
                    });
                }
            }
        }
        let mut used = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for (at, doc) in self.docs.iter().enumerate() {
            for dep in Self::dependencies(doc, doc.project, false) {
                if !seen.insert(Self::key(doc, dep)) {
                    continue;
                }
                let (ga, version, key, reads) = entry(doc, dep);
                let (version, at) = match (version, managed.get(&key)) {
                    (Some(version), _) if reads => (version, at),
                    (None, Some(Some((version, at)))) => {
                        used.insert(key.clone());
                        (version.clone(), *at)
                    }
                    _ => continue,
                };
                leaks.push(Leak {
                    hard: true,
                    detail: format!(
                        "the suffixed pom depends on {ga}:{version}, where {} reads the pom's own \
                         version",
                        self.label(at)
                    ),
                });
            }
        }
        // Only a Maven that applies a dependency's management to what it
        // pulls in (4.x) reads these.
        for (key, entry) in &managed {
            if let Some((version, at)) = entry.as_ref().filter(|_| !used.contains(key)) {
                leaks.push(Leak {
                    hard: false,
                    detail: format!(
                        "the suffixed pom manages {}:{}:{version}, where {} reads the pom's own \
                         version",
                        key.0,
                        key.1,
                        self.label(*at)
                    ),
                });
            }
        }
        let reachable = self.reachable();
        for (at, doc) in self.docs.iter().enumerate() {
            for profile in Self::profiles(doc) {
                let id = Self::profile_id(doc, profile);
                let mut soft = |what: String| {
                    leaks.push(Leak {
                        hard: false,
                        detail: format!(
                            "profile `{id}` of {} {what} through the pom's own version",
                            self.label(at)
                        ),
                    })
                };
                for is_managed in [false, true] {
                    for dep in Self::dependencies(doc, profile, is_managed) {
                        let (ga, version, key, reads) = entry(doc, dep);
                        match (version, managed.get(&key)) {
                            (Some(version), _) if reads => soft(format!("declares {ga}:{version}")),
                            (None, Some(Some((version, _)))) if !is_managed => {
                                soft(format!("depends on {ga}:{version}"))
                            }
                            _ => {}
                        }
                    }
                }
                for p in Self::properties(doc, profile) {
                    let name = doc.nodes[p].name.as_str();
                    if reachable.contains(name)
                        && self.base_definition(name).is_none_or(|(def, _)| def >= at)
                        && expand(doc.text_of(p)).contains(sv)
                    {
                        soft(format!("sets the property `{name}`"));
                    }
                }
            }
            for model in Self::models(doc) {
                for repository in Self::repositories(doc, model) {
                    if Self::leaves(doc, repository)
                        .into_iter()
                        .any(|t| expand(t).contains(sv))
                    {
                        leaks.push(Leak {
                            hard: false,
                            detail: format!(
                                "{} addresses a repository through the pom's own version",
                                self.label(at)
                            ),
                        });
                    }
                }
            }
        }
        leaks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const SV: &str = "1.10.0-socket.1d3c1fd2";
    const TREE: &str =
        ".socket/vendor/maven2/org/apache/commons/commons-text/1.10.0-socket.1d3c1fd2";
    const UPSTREAM_POM: &str = "<?xml version=\"1.0\"?>\n<project>\n  <parent>\n    \
        <groupId>org.apache.commons</groupId>\n    <artifactId>commons-parent</artifactId>\n    \
        <version>54</version>\n  </parent>\n  <artifactId>commons-text</artifactId>\n  \
        <version>1.10.0</version>\n</project>\n";

    fn patch_with(pom: &'static str) -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid: UUID,
            jar: b"PK\x03\x04patched",
            upstream_pom: pom.as_bytes(),
            upstream_parents: None,
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn patch() -> JvmPatch<'static> {
        patch_with(UPSTREAM_POM)
    }

    type Fs = BTreeMap<String, Vec<u8>>;

    fn fs(files: &[(&str, &str)]) -> Fs {
        let mut defaults = BTreeMap::from([(
            ".mvn/wrapper/maven-wrapper.properties".to_string(),
            b"distributionUrl=https://repo.maven.apache.org/apache-maven-3.9.16-bin.zip\n".to_vec(),
        )]);
        defaults.extend(
            files
                .iter()
                .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec())),
        );
        defaults
    }

    fn lister(files: &Fs) -> impl Fn(&str) -> Vec<String> + '_ {
        move |dir: &str| super::super::testing::list_of(files, dir)
    }

    fn run(files: &Fs) -> Result<JvmPlan, JvmRefusal> {
        let read = |p: &str| files.get(p).cloned();
        plan(&read, &lister(files), &patch())
    }

    fn applied(files: &Fs, plan: &JvmPlan) -> Fs {
        let mut out = files.clone();
        for w in &plan.writes {
            out.insert(w.rel.clone(), w.bytes.clone());
        }
        out
    }

    /// Plan, check that re-planning the result writes nothing, and return
    /// the post-plan files.
    fn vendor(files: &Fs) -> (JvmPlan, Fs) {
        let plan = run(files).expect("plan");
        let after = applied(files, &plan);
        let again = run(&after).expect("re-plan");
        assert!(
            again.writes.is_empty(),
            "not idempotent: {:?}",
            again.writes.iter().map(|w| &w.rel).collect::<Vec<_>>()
        );
        (plan, after)
    }

    fn text(files: &Fs, rel: &str) -> String {
        String::from_utf8(files[rel].clone()).unwrap()
    }

    fn reasons(plan: &JvmPlan) -> Vec<String> {
        plan.warnings
            .iter()
            .map(|w| {
                assert_eq!(w.code, "vendor_jvm_degraded");
                w.detail
                    .strip_prefix("reason: ")
                    .unwrap()
                    .split(':')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    fn refusal_reason(r: &JvmRefusal) -> &str {
        r.detail
            .strip_prefix("reason: ")
            .unwrap()
            .split(':')
            .next()
            .unwrap()
    }

    fn pom_rels(plan: &JvmPlan) -> Vec<&str> {
        plan.writes
            .iter()
            .filter(|w| !w.tree && w.rel.ends_with(".xml"))
            .map(|w| w.rel.as_str())
            .collect()
    }

    fn dep(version: &str) -> String {
        format!(
            "<dependency><groupId>org.apache.commons</groupId>\
             <artifactId>commons-text</artifactId><version>{version}</version></dependency>"
        )
    }

    const ROOT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>t</groupId>
  <artifactId>root</artifactId>
  <version>1-SNAPSHOT</version>
  <packaging>pom</packaging>
  <modules>
    <module>a</module>
    <module>b</module>
  </modules>
  <build>
    <plugins/>
  </build>
</project>
"#;

    // ── management from outside the checkout (#488) ──

    fn bom(artifact: &str, version: &str, managed: &str) -> Vec<u8> {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.corp</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>{managed}\
             </dependencies></dependencyManagement></project>"
        )
        .into_bytes()
    }

    fn corp(artifact: &str, version: &str) -> (String, String, String) {
        ("com.corp".into(), artifact.into(), version.into())
    }

    /// A reactor whose root carries `root_extra` (a BOM import, a parent)
    /// and whose module declares commons-text without a version.
    fn external_reactor(root_head: &str, root_extra: &str) -> Fs {
        let root = format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
             <modelVersion>4.0.0</modelVersion>\n  {root_head}\n  <groupId>com.example</groupId>\n  \
             <artifactId>root</artifactId>\n  <version>1.0.0</version>\n  \
             <packaging>pom</packaging>\n  <modules><module>a</module></modules>\n  \
             {root_extra}\n</project>\n"
        );
        let a = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
                 <groupId>com.example</groupId>\n    <artifactId>root</artifactId>\n    \
                 <version>1.0.0</version>\n  </parent>\n  <artifactId>a</artifactId>\n  \
                 <dependencies>\n    <dependency><groupId>org.apache.commons</groupId>\
                 <artifactId>commons-text</artifactId></dependency>\n  </dependencies>\n\
                 </project>\n";
        fs(&[("pom.xml", &root), ("a/pom.xml", a)])
    }

    const IMPORT_BOM: &str = "<dependencyManagement><dependencies><dependency>\
        <groupId>com.corp</groupId><artifactId>corp-bom</artifactId><version>${bom.version}</version>\
        <type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>";

    /// Fetch what the planner asks for from `repo` (absent: unavailable),
    /// then plan.
    fn run_external(
        files: &Fs,
        repo: &ExternalPoms,
    ) -> (Result<JvmPlan, JvmRefusal>, ExternalPoms) {
        let read = |p: &str| files.get(p).cloned();
        let mut known = ExternalPoms::new();
        loop {
            let need = external_poms_needed(&read, &lister(&files), &patch(), &known);
            if need.is_empty() {
                break;
            }
            for gav in need {
                let bytes = repo.get(&gav).cloned().flatten();
                known.insert(gav, bytes);
            }
        }
        (
            plan_with_external(&read, &lister(&files), &patch(), true, Some(&known)),
            known,
        )
    }

    fn root_pinned(plan: &JvmPlan, files: &Fs) -> bool {
        let after = applied(files, plan);
        text(&after, "pom.xml").contains(PIN_TAG)
    }

    #[test]
    fn imported_bom_managing_another_version_leaves_the_root_unpinned() {
        let files = external_reactor(
            "<properties><bom.version>2</bom.version></properties>",
            IMPORT_BOM,
        );
        let repo = ExternalPoms::from([(
            corp("corp-bom", "2"),
            Some(bom("corp-bom", "2", &dep("1.11.0"))),
        )]);
        let (plan, known) = run_external(&files, &repo);
        let plan = plan.unwrap();
        assert_eq!(known.keys().collect::<Vec<_>>(), [&corp("corp-bom", "2")]);
        assert!(
            reasons(&plan).contains(&"conflicting_managed_version".to_string()),
            "{:?}",
            plan.warnings
        );
        assert!(plan.warnings.iter().any(|w| w.detail.contains("1.11.0")));
        assert!(!root_pinned(&plan, &files), "the root must not be pinned");
        // Without the external weighing (the pre-#488 plan) it was pinned.
        assert!(root_pinned(&run(&files).unwrap(), &files));
    }

    #[test]
    fn imported_bom_at_the_base_version_is_pinned() {
        let files = external_reactor(
            "<properties><bom.version>1</bom.version></properties>",
            IMPORT_BOM,
        );
        let repo = ExternalPoms::from([(
            corp("corp-bom", "1"),
            Some(bom("corp-bom", "1", &dep("1.10.0"))),
        )]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(reasons(&plan).is_empty(), "{:?}", plan.warnings);
        assert!(root_pinned(&plan, &files));
    }

    #[test]
    fn a_bom_bump_after_vendoring_removes_the_pin() {
        let v1 = external_reactor(
            "<properties><bom.version>1</bom.version></properties>",
            IMPORT_BOM,
        );
        let repo = ExternalPoms::from([
            (
                corp("corp-bom", "1"),
                Some(bom("corp-bom", "1", &dep("1.10.0"))),
            ),
            (
                corp("corp-bom", "2"),
                Some(bom("corp-bom", "2", &dep("1.11.0"))),
            ),
        ]);
        let first = run_external(&v1, &repo).0.unwrap();
        let mut after = applied(&v1, &first);
        assert!(text(&after, "pom.xml").contains(PIN_TAG));
        let bumped = text(&after, "pom.xml").replace(
            "<bom.version>1</bom.version>",
            "<bom.version>2</bom.version>",
        );
        after.insert("pom.xml".into(), bumped.into_bytes());
        let again = run_external(&after, &repo).0.unwrap();
        assert!(reasons(&again).contains(&"conflicting_managed_version".to_string()));
        assert!(
            !root_pinned(&again, &after),
            "the re-run must drop the pin, not report it in sync"
        );
    }

    #[test]
    fn a_later_module_importing_another_version_leaves_the_root_unpinned() {
        // Module `a` sees the root's BOM at the base version; module `b`
        // imports its own BOM managing another one. A root pin would
        // override `b`'s management, so one agreeing module is not enough.
        let mut files = external_reactor(
            "<properties><bom.version>1</bom.version></properties>",
            IMPORT_BOM,
        );
        let root = text(&files, "pom.xml")
            .replace("<module>a</module>", "<module>a</module><module>b</module>");
        files.insert("pom.xml".into(), root.into_bytes());
        let b = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
                 <groupId>com.example</groupId>\n    <artifactId>root</artifactId>\n    \
                 <version>1.0.0</version>\n  </parent>\n  <artifactId>b</artifactId>\n  \
                 <dependencyManagement><dependencies><dependency>\
                 <groupId>com.corp</groupId><artifactId>corp-bom</artifactId><version>2</version>\
                 <type>pom</type><scope>import</scope></dependency></dependencies>\
                 </dependencyManagement>\n  \
                 <dependencies>\n    <dependency><groupId>org.apache.commons</groupId>\
                 <artifactId>commons-text</artifactId></dependency>\n  </dependencies>\n\
                 </project>\n";
        files.insert("b/pom.xml".into(), b.as_bytes().to_vec());
        let repo = ExternalPoms::from([
            (
                corp("corp-bom", "1"),
                Some(bom("corp-bom", "1", &dep("1.10.0"))),
            ),
            (
                corp("corp-bom", "2"),
                Some(bom("corp-bom", "2", &dep("1.11.0"))),
            ),
        ]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(
            reasons(&plan).contains(&"conflicting_managed_version".to_string()),
            "{:?}",
            plan.warnings
        );
        assert!(!root_pinned(&plan, &files), "the root must not be pinned");
    }

    #[test]
    fn a_profile_bom_import_is_weighed() {
        let profile = format!(
            "<profiles><profile><id>corp</id><activation><activeByDefault>true\
             </activeByDefault></activation>{IMPORT_BOM}</profile></profiles>"
        );
        let files = external_reactor(
            "<properties><bom.version>2</bom.version></properties>",
            &profile,
        );
        let repo = ExternalPoms::from([(
            corp("corp-bom", "2"),
            Some(bom("corp-bom", "2", &dep("1.11.0"))),
        )]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(
            reasons(&plan).contains(&"conflicting_managed_version".to_string()),
            "{:?}",
            plan.warnings
        );
        assert!(!root_pinned(&plan, &files), "the root must not be pinned");
    }

    #[test]
    fn a_nested_bom_import_is_followed() {
        let files = external_reactor(
            "<properties><bom.version>2</bom.version></properties>",
            IMPORT_BOM,
        );
        let outer = "<dependency><groupId>com.corp</groupId><artifactId>inner-bom</artifactId>\
            <version>7</version><type>pom</type><scope>import</scope></dependency>";
        let repo = ExternalPoms::from([
            (corp("corp-bom", "2"), Some(bom("corp-bom", "2", outer))),
            (
                corp("inner-bom", "7"),
                Some(bom("inner-bom", "7", &dep("1.11.0"))),
            ),
        ]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(reasons(&plan).contains(&"conflicting_managed_version".to_string()));
        assert!(!root_pinned(&plan, &files));
    }

    #[test]
    fn an_external_parent_managing_another_version_leaves_the_root_unpinned() {
        let parent = "<parent><groupId>com.corp</groupId><artifactId>corp-parent</artifactId>\
            <version>2</version><relativePath/></parent>";
        let files = external_reactor(parent, "");
        let repo = ExternalPoms::from([(
            corp("corp-parent", "2"),
            Some(bom("corp-parent", "2", &dep("1.11.0"))),
        )]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(reasons(&plan).contains(&"conflicting_managed_version".to_string()));
        assert!(!root_pinned(&plan, &files));
    }

    #[test]
    fn a_local_property_overriding_an_external_parents_version_is_honored() {
        // The parent manages `${ct.version}` (1.10.0 by default); the local
        // root overrides it to 1.11.0, which Maven interpolates after
        // inheritance.
        let parent = "<parent><groupId>com.corp</groupId><artifactId>corp-parent</artifactId>\
            <version>3</version><relativePath/></parent>\n  \
            <properties><ct.version>1.11.0</ct.version></properties>";
        let files = external_reactor(parent, "");
        let managed = "<dependency><groupId>org.apache.commons</groupId>\
            <artifactId>commons-text</artifactId><version>${ct.version}</version></dependency>";
        let mut parent_pom = String::from_utf8(bom("corp-parent", "3", managed)).unwrap();
        parent_pom = parent_pom.replace(
            "<packaging>pom</packaging>",
            "<packaging>pom</packaging><properties><ct.version>1.10.0</ct.version></properties>",
        );
        let repo = ExternalPoms::from([(corp("corp-parent", "3"), Some(parent_pom.into_bytes()))]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(
            reasons(&plan).contains(&"conflicting_managed_version".to_string()),
            "{:?}",
            plan.warnings
        );
        assert!(!root_pinned(&plan, &files));
    }

    #[test]
    fn unavailable_external_management_leaves_the_root_unpinned() {
        let files = external_reactor(
            "<properties><bom.version>2</bom.version></properties>",
            IMPORT_BOM,
        );
        let plan = run_external(&files, &ExternalPoms::new()).0.unwrap();
        assert!(
            reasons(&plan).contains(&"management_unresolved".to_string()),
            "{:?}",
            plan.warnings
        );
        assert!(!root_pinned(&plan, &files));
    }

    #[test]
    fn a_bom_that_does_not_manage_the_artifact_keeps_the_pin() {
        let files = external_reactor(
            "<properties><bom.version>2</bom.version></properties>",
            IMPORT_BOM,
        );
        let other = "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>\
            <version>4.13.2</version></dependency>";
        let repo = ExternalPoms::from([(corp("corp-bom", "2"), Some(bom("corp-bom", "2", other)))]);
        let plan = run_external(&files, &repo).0.unwrap();
        assert!(reasons(&plan).is_empty(), "{:?}", plan.warnings);
        assert!(root_pinned(&plan, &files));
    }

    fn module(name: &str, deps: &str) -> String {
        format!(
            "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
             <groupId>t</groupId>\n    <artifactId>root</artifactId>\n    \
             <version>1-SNAPSHOT</version>\n  </parent>\n  <artifactId>{name}</artifactId>\n  \
             <dependencies>\n    {deps}\n  </dependencies>\n</project>\n"
        )
    }

    // ── declares_modules ──

    #[test]
    fn declares_modules_masks_comments_and_cdata() {
        assert!(declares_modules(
            "<project><modules><module>a</module></modules></project>"
        ));
        assert!(declares_modules("<project><modules/></project>"));
        assert!(declares_modules(
            "<project><subprojects><subproject>a</subproject></subprojects></project>"
        ));
        assert!(declares_modules(
            "<project><profiles><profile><modules><module>a</module></modules></profile></profiles></project>"
        ));
        assert!(!declares_modules(
            "<project><!-- <modules><module>a</module></modules> --></project>"
        ));
        assert!(!declares_modules(
            "<project><description><![CDATA[<modules>]]></description></project>"
        ));
        assert!(!declares_modules("<project><modulesInfo/></project>"));
        assert!(!declares_modules("<project><!-- <modules>"));
        assert!(!declares_modules("<project></project>"));
    }

    // ── shapes ──

    #[test]
    fn reactor_with_parent_root_pins_root_and_rewrites_literal() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(plan.tree_dir, TREE);
        assert_eq!(plan.jar_rel, format!("{TREE}/commons-text-{SV}.jar"));
        assert_eq!(pom_rels(&plan), ["a/pom.xml", "pom.xml"]);

        let root = text(&after, "pom.xml");
        let expected_root = ROOT
            .replace(
                "  <build>\n",
                &format!(
                    "  <dependencyManagement>\n    <dependencies>\n      \
                 <!-- socket-patch {UUID}: org.apache.commons:commons-text:1.10.0 -->\n      \
                 <dependency>\n        <groupId>org.apache.commons</groupId>\n        \
                 <artifactId>commons-text</artifactId>\n        <version>{SV}</version>\n      \
                 </dependency>\n    </dependencies>\n  </dependencyManagement>\n  <build>\n"
                ),
            )
            .replace(
                "</project>\n",
                &format!(
                    "  <repositories>\n    {BEGIN_MARKER}\n    <repository>\n      \
                 <id>socket-patch-vendor</id>\n      <url>{REPO_URL}</url>\n      \
                 <releases><enabled>true</enabled><updatePolicy>always</updatePolicy>\
                 <checksumPolicy>fail</checksumPolicy></releases>\n      \
                 <snapshots><enabled>false</enabled></snapshots>\n    </repository>\n    \
                 {END_MARKER}\n  </repositories>\n</project>\n"
                ),
            );
        assert_eq!(root, expected_root);
        assert_eq!(
            text(&after, "a/pom.xml"),
            module("a", &dep("1.10.0")).replace("1.10.0", SV)
        );
        assert!(!plan.writes.iter().any(|w| w.rel == "b/pom.xml"));
    }

    #[test]
    fn plan_writes_tree_and_config() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        let tree: Vec<&str> = plan
            .writes
            .iter()
            .filter(|w| w.tree)
            .map(|w| w.rel.as_str())
            .collect();
        assert_eq!(
            tree,
            [
                format!("{TREE}/commons-text-{SV}.jar"),
                format!("{TREE}/commons-text-{SV}.jar.sha1"),
                format!("{TREE}/commons-text-{SV}.pom"),
                format!("{TREE}/commons-text-{SV}.pom.sha1"),
                format!("{TREE}/socket-patch.vendor.json"),
            ]
        );
        assert_eq!(
            text(&after, ".socket/vendor/maven2/.gitattributes"),
            "* -text\n"
        );
        assert!(
            plan.writes
                .iter()
                .any(|w| w.rel == GITATTRIBUTES_REL && !w.tree),
            "the shared .gitattributes is an owned file, not one patch's tree file"
        );
        let jar_sha1 = text(&after, &format!("{TREE}/commons-text-{SV}.jar.sha1"));
        assert_eq!(jar_sha1, sha1_hex(b"PK\x03\x04patched"));
        assert_eq!(jar_sha1.len(), 40);
        let pom = text(&after, &format!("{TREE}/commons-text-{SV}.pom"));
        assert_eq!(
            pom,
            UPSTREAM_POM.replace(
                "<version>1.10.0</version>",
                &format!("<version>{SV}</version>")
            )
        );
        assert_eq!(
            text(&after, &format!("{TREE}/commons-text-{SV}.pom.sha1")),
            sha1_hex(pom.as_bytes())
        );

        let marker = text(&after, &format!("{TREE}/socket-patch.vendor.json"));
        assert!(marker.ends_with("}\n"));
        let json: serde_json::Value = serde_json::from_str(&marker).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["files", "purl", "schema", "tool", "uuid", "version"]);
        assert_eq!(
            json["purl"],
            "pkg:maven/org.apache.commons/commons-text@1.10.0"
        );
        assert_eq!(json["version"], SV);
        assert_eq!(json["schema"], 1);
        assert_eq!(json["tool"], "maven");
        assert_eq!(json["uuid"], UUID);
        let jar_entry = &json["files"][format!("commons-text-{SV}.jar")];
        assert_eq!(jar_entry["size"], 11);
        assert_eq!(jar_entry["sha256"], sha256_hex(b"PK\x03\x04patched"));
        assert_eq!(json["files"].as_object().unwrap().len(), 4);
        assert!(marker.contains("\n  \"files\": {\n    \"commons-text-"));

        assert_eq!(
            text(&after, ".mvn/maven.config"),
            format!("{OFFLINE_LINE}\n{TAIL_KEY}{TAIL_DIR}\n")
        );
    }

    #[test]
    fn aggregator_with_separate_parent_pins_parent_only() {
        let aggregator = "<project>\n  <groupId>t</groupId>\n  <artifactId>agg</artifactId>\n  \
            <version>1</version>\n  <packaging>pom</packaging>\n  <modules>\n    \
            <module>parent</module>\n    <module>a</module>\n  </modules>\n</project>\n";
        let parent = "<project>\n  <groupId>t</groupId>\n  <artifactId>corp</artifactId>\n  \
            <version>1</version>\n  <packaging>pom</packaging>\n</project>\n";
        let a = format!(
            "<project>\n  <parent>\n    <groupId>t</groupId>\n    <artifactId>corp</artifactId>\n    \
             <version>1</version>\n    <relativePath>../parent/pom.xml</relativePath>\n  </parent>\n  \
             <artifactId>a</artifactId>\n  <dependencies>\n    {}\n  </dependencies>\n</project>\n",
            "<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId></dependency>"
        );
        let files = fs(&[
            ("pom.xml", aggregator),
            ("parent/pom.xml", parent),
            ("a/pom.xml", &a),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(pom_rels(&plan), ["parent/pom.xml"]);
        let p = text(&after, "parent/pom.xml");
        assert!(p.contains(&format!("<version>{SV}</version>")));
        assert!(p.contains(BEGIN_MARKER));
        assert!(p.starts_with("<project>\n  <groupId>t</groupId>"));
    }

    #[test]
    fn remote_parent_modules_are_their_own_local_roots() {
        let root = "<project>\n  <groupId>t</groupId>\n  <artifactId>agg</artifactId>\n  <version>1</version>\n  \
            <packaging>pom</packaging>\n  <modules>\n    <module>a</module>\n    <module>b</module>\n  \
            </modules>\n</project>\n";
        let boot = |name: &str, deps: &str| {
            format!(
                "<project>\n  <parent>\n    <groupId>org.springframework.boot</groupId>\n    \
                 <artifactId>spring-boot-starter-parent</artifactId>\n    <version>3.2.0</version>\n    \
                 <relativePath/>\n  </parent>\n  <groupId>t</groupId>\n  <artifactId>{name}</artifactId>\n  \
                 <properties>\n    <ct.version>1.10.0</ct.version>\n  </properties>\n  \
                 <dependencies>\n    {deps}\n  </dependencies>\n</project>\n"
            )
        };
        let files = fs(&[
            ("pom.xml", root),
            ("a/pom.xml", &boot("a", &dep("${ct.version}"))),
            ("b/pom.xml", &boot("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(pom_rels(&plan), ["a/pom.xml", "b/pom.xml"]);
        for m in ["a", "b"] {
            let t = text(&after, &format!("{m}/pom.xml"));
            assert!(t.contains("<dependencyManagement>"), "{m}");
            assert!(t.contains(BEGIN_MARKER), "{m}");
        }
        let a = text(&after, "a/pom.xml");
        assert!(
            a.contains("<ct.version>1.10.0</ct.version>"),
            "property left alone"
        );
        assert_eq!(a.matches(&format!("<version>{SV}</version>")).count(), 2);
    }

    #[test]
    fn middle_local_parent_outside_modules_is_rewritten() {
        let root = "<project>\n  <groupId>t</groupId>\n  <artifactId>root</artifactId>\n  <version>1</version>\n  \
            <packaging>pom</packaging>\n  <modules>\n    <module>x</module>\n  </modules>\n</project>\n";
        let mid = format!(
            "<project>\n  <parent>\n    <groupId>t</groupId>\n    <artifactId>root</artifactId>\n    \
             <version>1</version>\n  </parent>\n  <artifactId>mid</artifactId>\n  <packaging>pom</packaging>\n  \
             <dependencyManagement>\n    <dependencies>\n      {}\n    </dependencies>\n  \
             </dependencyManagement>\n</project>\n",
            dep("1.10.0")
        );
        let x = "<project>\n  <parent>\n    <groupId>t</groupId>\n    <artifactId>mid</artifactId>\n    \
            <version>1</version>\n    <relativePath>../mid</relativePath>\n  </parent>\n  \
            <artifactId>x</artifactId>\n</project>\n";
        let files = fs(&[("pom.xml", root), ("mid/pom.xml", &mid), ("x/pom.xml", x)]);
        let (plan, after) = vendor(&files);
        assert_eq!(pom_rels(&plan), ["mid/pom.xml", "pom.xml"]);
        assert_eq!(text(&after, "mid/pom.xml"), mid.replace("1.10.0", SV));
        assert!(text(&after, "pom.xml").contains("<dependencyManagement>"));
    }

    #[test]
    fn profile_literal_and_management_are_rewritten() {
        let a = format!(
            "<project>\n  <parent><groupId>t</groupId><artifactId>root</artifactId><version>1-SNAPSHOT</version></parent>\n  \
             <artifactId>a</artifactId>\n  <profiles>\n    <profile>\n      <id>p</id>\n      \
             <dependencies>{}</dependencies>\n      <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\n    \
             </profile>\n  </profiles>\n</project>\n",
            dep("1.10.0"),
            dep("1.10.0")
        );
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
    }

    #[test]
    fn property_resolved_through_parent_chain() {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <ct.major>1.10</ct.major>\n    <ct.version>${ct.major}.0</ct.version>\n  </properties>\n  <modules>",
        );
        let a = module("a", &dep("${ct.version}"));
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("${ct.version}", SV));
        assert!(text(&after, "pom.xml").contains("<ct.version>${ct.major}.0</ct.version>"));
    }

    #[test]
    fn maven_config_user_property_wins() {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <ct.version>1.9</ct.version>\n  </properties>\n  <modules>",
        );
        let a = module("a", &dep("${ct.version}"));
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
            (".mvn/maven.config", "-Dct.version=1.10.0\n"),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("${ct.version}", SV));
    }

    /// A module at `${ct.version}` whose pom says 1.10.0 (the patch base),
    /// vendored with `config` as `.mvn/maven.config`.
    fn vendor_with_maven_config(config: &str) -> (JvmPlan, Fs, String) {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <ct.version>1.10.0</ct.version>\n  </properties>\n  <modules>",
        );
        let a = module("a", &dep("${ct.version}"));
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
            (".mvn/maven.config", config),
        ]);
        let (plan, after) = vendor(&files);
        (plan, after, a)
    }

    // #535: Maven applies `--define=k=v`, `-D k=v` and `-D` / `k=v` on
    // separate lines, so the override must beat the pom's 1.10.0.
    #[test]
    fn maven_config_long_and_split_define_spellings_win() {
        for config in [
            "--define=ct.version=1.11.0\n",
            "-D ct.version=1.11.0\n",
            "-D\nct.version=1.11.0\n",
            "--define\nct.version=1.11.0\n",
            "-B\r\n--define=ct.version=1.11.0\r\n",
            "\"-Dct.version=1.11.0\"\n",
            // Maven 3.9+ reads the whole line as the value.
            "-Dct.version=1.10.0 # TODO bump\n",
            // Maven before 3.9 splits a line into several arguments.
            "-B -Dct.version=1.11.0\n",
            "-Dfoo=1 -Dct.version=1.11.0\n",
        ] {
            let (plan, after, a) = vendor_with_maven_config(config);
            assert_eq!(
                reasons(&plan),
                ["conflicting_literal_version"],
                "{config:?}"
            );
            assert_eq!(text(&after, "a/pom.xml"), a, "{config:?}");
        }
    }

    // #550: since Maven 3.9 a `#` line is a comment and defines nothing.
    #[test]
    fn maven_config_comment_lines_define_nothing() {
        for config in [
            "# -Dct.version=1.11.0\n",
            "#   -Dct.version=1.11.0   old pin\n",
            "  # --define=ct.version=1.11.0\n",
            "# just a note\n-B\n",
        ] {
            let (plan, after, a) = vendor_with_maven_config(config);
            assert!(plan.warnings.is_empty(), "{config:?}: {:?}", plan.warnings);
            assert_eq!(
                text(&after, "a/pom.xml"),
                a.replace("${ct.version}", SV),
                "{config:?}"
            );
        }
    }

    #[test]
    fn maven_config_user_properties_parse_like_maven() {
        let props = cli_properties(
            "# -Dgone=1\n-Da=1\n--define=b=2\n-D c=3\n-D\nd=4\n--define e=5\n-Dflag\n  -Da=6  \n\
             \"-Dq=7\"\n-Dv=1.0 # note\n-D\n-Dw=8\n--defined=x\n-B\n-T 1C -Dy=9 -Dw=0\n",
        );
        let want = [
            ("a", "6"),
            ("b", "2"),
            ("c", "3"),
            ("d", "4"),
            ("e", "5"),
            ("flag", "true"),
            ("q", "7"),
            ("v", "1.0 # note"),
            ("w", "8"),
            ("y", "9"),
        ];
        assert_eq!(
            props,
            want.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>()
        );
    }

    #[test]
    fn project_version_expression_resolves() {
        let root = ROOT.replace("<version>1-SNAPSHOT</version>", "<version>1.10.0</version>");
        let a = module("a", &dep("${project.version}")).replace("1-SNAPSHOT", "1.10.0");
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            (
                "b/pom.xml",
                &module("b", "").replace("1-SNAPSHOT", "1.10.0"),
            ),
        ]);
        let (_, after) = vendor(&files);
        assert_eq!(
            text(&after, "a/pom.xml"),
            a.replace("${project.version}", SV)
        );
    }

    #[test]
    fn unresolvable_property_and_range_warn() {
        let a = module(
            "a",
            &format!("{}\n    {}", dep("${remote.prop}"), dep("[1.9,2.0)")),
        );
        let b = module("b", &dep("LATEST"));
        let files = fs(&[("pom.xml", ROOT), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["property_unresolved", "range", "range"]);
        assert!(
            plan.warnings[0].detail.contains("a/pom.xml:10:"),
            "{}",
            plan.warnings[0].detail
        );
        assert_eq!(text(&after, "a/pom.xml"), a);
        // a's explicit `${remote.prop}` beats any pin (#513).
        assert!(!text(&after, "pom.xml").contains("<dependencyManagement>"));
    }

    #[test]
    fn conflicting_literal_unpins_local_root_but_keeps_other_rewrites() {
        let a = module("a", &dep("1.9"));
        let b = module("b", &dep("1.10.0"));
        let files = fs(&[("pom.xml", ROOT), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["conflicting_literal_version"]);
        let root = text(&after, "pom.xml");
        assert!(!root.contains("<dependencyManagement>"));
        assert!(
            root.contains(BEGIN_MARKER),
            "the repository still serves SV"
        );
        assert_eq!(text(&after, "a/pom.xml"), a);
        assert_eq!(text(&after, "b/pom.xml"), b.replace("1.10.0", SV));
    }

    /// Plugin dependencies, exclusions and other types are never
    /// rewritten. A type that carries code (`test-jar` is the `tests`
    /// classifier jar; `ejb`, `maven-plugin` and unknown types are
    /// executable too) bypasses the pin like an executable classifier
    /// copy: it warns and is not attestable. A `pom` or `java-source` type
    /// holds no code and passes silently.
    #[test]
    fn plugin_dependencies_exclusions_and_other_types_are_untouched() {
        for (type_text, executable) in [
            ("test-jar", true),
            ("ejb", true),
            ("ejb-client", true),
            ("pom", false),
            ("java-source", false),
        ] {
            let a = format!(
                "<project>\n  <parent><groupId>t</groupId><artifactId>root</artifactId><version>1-SNAPSHOT</version></parent>\n  \
                 <artifactId>a</artifactId>\n  <dependencies>\n    \
                 <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version>\
                 <exclusions><exclusion><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId></exclusion></exclusions></dependency>\n    \
                 <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.10.0</version><type>{type_text}</type></dependency>\n  \
                 </dependencies>\n  <build><plugins><plugin><artifactId>p</artifactId><dependencies>{}</dependencies></plugin></plugins></build>\n</project>\n",
                dep("1.10.0")
            );
            let files = fs(&[
                ("pom.xml", ROOT),
                ("a/pom.xml", &a),
                ("b/pom.xml", &module("b", "")),
            ]);
            let (plan, after) = vendor(&files);
            let warned: &[&str] = if executable {
                &["classifier_declared"]
            } else {
                &[]
            };
            assert_eq!(reasons(&plan), warned, "{type_text}");
            assert_eq!(text(&after, "a/pom.xml"), a, "{type_text}");
            assert!(text(&after, "pom.xml").contains(PIN_TAG), "{type_text}");
            assert_eq!(attestable(&after), (true, !executable), "{type_text}");
        }
    }

    #[test]
    fn classifier_declaration_warns() {
        let a = module(
            "a",
            "<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
             <version>1.10.0</version><classifier>sources</classifier></dependency>",
        );
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["classifier_declared"]);
        assert_eq!(text(&after, "a/pom.xml"), a);
    }

    #[test]
    fn existing_repositories_and_management_are_extended() {
        let root = ROOT.replace(
            "  <build>",
            "  <dependencyManagement>\n    <dependencies>\n      <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency>\n    </dependencies>\n  </dependencyManagement>\n  \
             <repositories>\n    <repository>\n      <id>corp</id>\n      <url>https://corp</url>\n    </repository>\n  </repositories>\n  <profiles><profile><id>p</id><repositories/></profile></profiles>\n  <build>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        let out = text(&after, "pom.xml");
        assert!(out.contains(&format!(
            "    <dependencies>\n      <!-- socket-patch {UUID}: org.apache.commons:commons-text:1.10.0 -->\n      <dependency>\n        <groupId>org.apache.commons</groupId>"
        )));
        assert!(out.contains(&format!(
            "      <url>https://corp</url>\n    </repository>\n    {BEGIN_MARKER}\n    <repository>\n      <id>socket-patch-vendor</id>"
        )));
        assert!(out.contains(&format!(
            "    {END_MARKER}\n  </repositories>\n  <profiles>"
        )));
        assert_eq!(out.matches("<repositories>").count(), 1);
    }

    #[test]
    fn existing_base_management_is_rewritten_not_duplicated() {
        let root = ROOT.replace(
            "  <build>",
            &format!("  <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\n  <build>", dep("1.10.0")),
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        let out = text(&after, "pom.xml");
        assert!(!out.contains("socket-patch 1d3c"), "no second entry");
        assert!(out.contains(&dep(SV)));
    }

    #[test]
    fn crlf_and_tabs_are_preserved() {
        let root = "<project>\r\n\t<groupId>t</groupId>\r\n\t<artifactId>root</artifactId>\r\n\t<version>1</version>\r\n\t\
            <packaging>pom</packaging>\r\n\t<!-- keep me -->\r\n\t<modules>\r\n\t\t<module>a</module>\r\n\t</modules>\r\n\t\
            <dependencies>\r\n\t</dependencies>\r\n</project>\r\n";
        let a = "<project>\r\n\t<parent>\r\n\t\t<groupId>t</groupId>\r\n\t\t<artifactId>root</artifactId>\r\n\t\t<version>1</version>\r\n\t</parent>\r\n\t\
            <artifactId>a</artifactId>\r\n\t<dependencies>\r\n\t\t<dependency>\r\n\t\t\t<groupId>org.apache.commons</groupId>\r\n\t\t\t\
            <artifactId>commons-text</artifactId>\r\n\t\t\t<version>1.10.0</version>\r\n\t\t</dependency>\r\n\t</dependencies>\r\n</project>\r\n";
        let files = fs(&[("pom.xml", root), ("a/pom.xml", a)]);
        let (_, after) = vendor(&files);
        let out = text(&after, "pom.xml");
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "only CRLF: {out:?}"
        );
        assert!(out.starts_with("<project>\r\n\t<groupId>t</groupId>\r\n\t<artifactId>root</artifactId>\r\n\t<version>1</version>\r\n\t<packaging>pom</packaging>\r\n\t<!-- keep me -->"));
        assert!(out
            .contains("\t<dependencyManagement>\r\n\t\t<dependencies>\r\n\t\t\t<!-- socket-patch"));
        assert!(
            out.contains("\t\t\t<dependency>\r\n\t\t\t\t<groupId>org.apache.commons</groupId>\r\n")
        );
        assert!(out.contains("\t</dependencyManagement>\r\n\t<dependencies>\r\n\t</dependencies>\r\n\t<repositories>\r\n\t\t<!-- socket-patch:begin -->\r\n\t\t<repository>\r\n\t\t\t<id>"));
        assert!(out.ends_with("\t</repositories>\r\n</project>\r\n"));
        assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
    }

    #[test]
    fn single_line_poms_and_self_closing_sections() {
        let root = "<project><groupId>t</groupId><artifactId>r</artifactId><version>1</version><packaging>pom</packaging>\
            <modules><module>a</module></modules><dependencyManagement/><repositories/></project>";
        let a = "<project><parent><groupId>t</groupId><artifactId>r</artifactId><version>1</version></parent><artifactId>a</artifactId></project>";
        let files = fs(&[("pom.xml", root), ("a/pom.xml", a)]);
        let (_, after) = vendor(&files);
        let out = text(&after, "pom.xml");
        let doc = Doc::parse(out.clone()).expect("well-formed");
        let dm = doc.child(doc.project, "dependencyManagement").unwrap();
        let deps = doc.child(dm, "dependencies").unwrap();
        assert_eq!(doc.children(deps, "dependency").count(), 1);
        let repos = doc.child(doc.project, "repositories").unwrap();
        assert_eq!(
            doc.child_text(doc.child(repos, "repository").unwrap(), "id")
                .as_deref(),
            Some(REPO_ID)
        );
        assert_eq!(out.matches("<repositories>").count(), 1);
    }

    #[test]
    fn enforcer_repository_ban_omits_fallback() {
        let root = ROOT.replace(
            "<plugins/>",
            "<plugins><plugin><artifactId>maven-enforcer-plugin</artifactId><configuration><rules><requireNoRepositories/></rules></configuration></plugin></plugins>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["maven_fallback_omitted"]);
        let out = text(&after, "pom.xml");
        assert!(!out.contains(BEGIN_MARKER));
        assert!(out.contains("<dependencyManagement>"));
        assert!(after.contains_key(".mvn/maven.config"));
    }

    #[test]
    fn commented_enforcer_rule_does_not_ban() {
        let root = ROOT.replace("<plugins/>", "<plugins/><!-- <bannedRepositories/> -->");
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, _) = vendor(&files);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn deployed_reactor_warns() {
        let root = ROOT.replace("  <build>", "  <distributionManagement><repository><id>r</id><url>https://r</url></repository></distributionManagement>\n  <build>");
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["publishes_suffixed_poms"]);
        let out = text(&after, "pom.xml");
        let doc = Doc::parse(out).unwrap();
        let dist = doc.child(doc.project, "distributionManagement").unwrap();
        assert!(doc.child(dist, "repository").is_some());
        assert!(
            doc.child(doc.project, "repositories").is_some(),
            "top-level repositories, not in distributionManagement"
        );
    }

    #[test]
    fn nested_modules_custom_files_and_normalized_paths() {
        let root = ROOT.replace(
            "<module>b</module>",
            "<module>./b/</module>\n    <module>c/custom.xml</module>",
        );
        let b = "<project>\n  <parent><groupId>t</groupId><artifactId>root</artifactId><version>1-SNAPSHOT</version></parent>\n  \
            <artifactId>b</artifactId>\n  <packaging>pom</packaging>\n  <modules><module>../b/inner</module></modules>\n</project>\n";
        let inner = "<project>\n  <parent><groupId>t</groupId><artifactId>b</artifactId><version>1-SNAPSHOT</version></parent>\n  \
            <artifactId>inner</artifactId>\n  <dependencies>DEPS</dependencies>\n</project>\n"
            .replace("DEPS", &dep("1.10.0"));
        let c = module("c", &dep("1.10.0")).replace(
            "<parent>",
            "<parent><relativePath>../pom.xml</relativePath>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", b),
            ("b/inner/pom.xml", &inner),
            ("c/custom.xml", &c),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(
            pom_rels(&plan),
            ["b/inner/pom.xml", "c/custom.xml", "pom.xml"]
        );
        assert_eq!(text(&after, "b/inner/pom.xml"), inner.replace("1.10.0", SV));
    }

    #[test]
    fn mismatched_or_missing_parent_is_remote() {
        let root = ROOT.to_string();
        // `a` names a parent that is not the root pom: it is its own local root.
        let a = module("a", &dep("1.10.0")).replace(
            "<artifactId>root</artifactId>",
            "<artifactId>other</artifactId>",
        );
        let b = module("b", "").replace(
            "<version>1-SNAPSHOT</version>\n  </parent>",
            "<version>2</version>\n  </parent>",
        );
        let files = fs(&[("pom.xml", &root), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
        let (plan, after) = vendor(&files);
        assert_eq!(pom_rels(&plan), ["a/pom.xml", "b/pom.xml"]);
        assert!(text(&after, "a/pom.xml").contains("<dependencyManagement>"));
        assert!(text(&after, "b/pom.xml").contains(BEGIN_MARKER));
        assert!(
            !after["pom.xml"].windows(3).any(|w| w == b"soc"),
            "aggregator untouched"
        );
    }

    #[test]
    fn inherited_group_id_counts_for_parent_match() {
        let root = ROOT.replace("<module>b</module>", "");
        let a = "<project>\n  <parent><groupId>t</groupId><artifactId>root</artifactId><version>1-SNAPSHOT</version></parent>\n  \
            <artifactId>a</artifactId>\n  <packaging>pom</packaging>\n  <modules><module>x</module></modules>\n</project>\n";
        let x = format!(
            "<project>\n  <parent><groupId>t</groupId><artifactId>a</artifactId><version>1-SNAPSHOT</version></parent>\n  \
             <artifactId>x</artifactId>\n  <dependencies>{}</dependencies>\n</project>\n",
            dep("1.10.0")
        );
        let files = fs(&[("pom.xml", &root), ("a/pom.xml", a), ("a/x/pom.xml", &x)]);
        let (plan, _) = vendor(&files);
        assert_eq!(pom_rels(&plan), ["a/x/pom.xml", "pom.xml"]);
    }

    // ── refusals ──

    fn refused(files: &[(&str, &str)]) -> JvmRefusal {
        run(&fs(files)).expect_err("refused")
    }

    #[test]
    fn refusals() {
        let with = |m: &str| ROOT.replace("<module>b</module>", &format!("<module>{m}</module>"));
        let a = module("a", "");
        let r = refused(&[("pom.xml", &with("../elsewhere")), ("a/pom.xml", &a)]);
        assert_eq!(
            (r.code, refusal_reason(&r)),
            (SHAPE_UNSUPPORTED, "module_outside_root")
        );
        let r = refused(&[("pom.xml", &with("/abs")), ("a/pom.xml", &a)]);
        assert_eq!(refusal_reason(&r), "module_outside_root");
        let r = refused(&[("pom.xml", &with("${m}")), ("a/pom.xml", &a)]);
        assert_eq!(refusal_reason(&r), "module_path_unresolvable");
        let r = refused(&[("pom.xml", &with("missing")), ("a/pom.xml", &a)]);
        assert_eq!(refusal_reason(&r), "module_path_unresolvable");
        for f in NESTED_MVN_FILES {
            let r = refused(&[
                ("pom.xml", &with("a")),
                ("a/pom.xml", &a),
                (&format!("a/.mvn/{f}"), ""),
            ]);
            assert_eq!(refusal_reason(&r), "nested_mvn_dir", "{f}");
        }
        let mut files = fs(&[("pom.xml", ROOT), ("b/pom.xml", &module("b", ""))]);
        files.insert("a/pom.xml".into(), vec![0xff, 0xfe]);
        let r = run(&files).unwrap_err();
        assert_eq!(refusal_reason(&r), "build_file_unreadable");
        let r = refused(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", "<project><a></b></project>"),
            ("b/pom.xml", &a),
        ]);
        assert_eq!(refusal_reason(&r), "build_file_unreadable");
        let r = refused(&[]);
        assert_eq!(refusal_reason(&r), "no_build_file");
    }

    #[test]
    fn root_mvn_dir_is_not_nested() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
            (".mvn/extensions.xml", "<extensions/>"),
        ]);
        vendor(&files);
    }

    #[test]
    fn suffix_unavailable_refuses() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let read = |p: &str| files.get(p).cloned();
        let r = plan(
            &read,
            &lister(&files),
            &patch_with("<project><version>${revision}</version></project>"),
        )
        .unwrap_err();
        assert_eq!(r.code, UPSTREAM_UNAVAILABLE);
        assert_eq!(refusal_reason(&r), "suffix_unavailable");
    }

    // ── maven.config ──

    fn config(before: &str) -> String {
        String::from_utf8(merge_maven_config(Some(before.as_bytes())).0).unwrap()
    }

    #[test]
    fn maven_config_merges() {
        let ours = format!("{OFFLINE_LINE}\n{TAIL_KEY}{TAIL_DIR}\n");
        assert_eq!(String::from_utf8(merge_maven_config(None).0).unwrap(), ours);
        assert_eq!(config(""), ours);
        assert_eq!(config(&ours), ours);
        assert_eq!(config("-T4\n-ntp"), format!("-T4\n-ntp\n{ours}"));
        assert_eq!(
            config("-T4\r\n"),
            format!("-T4\r\n{OFFLINE_LINE}\r\n{TAIL_KEY}{TAIL_DIR}\r\n")
        );
        // #815: a mixed file's added lines take its majority terminator
        // (`line_endings::terminator`), not "any CRLF means CRLF".
        assert_eq!(
            config("-T4\r\n-ntp\n-B\n"),
            format!("-T4\r\n-ntp\n-B\n{OFFLINE_LINE}\n{TAIL_KEY}{TAIL_DIR}\n")
        );
        assert_eq!(
            config(&format!("{TAIL_KEY}/opt/repo\n-T4\n{OFFLINE_LINE}\n")),
            format!("{TAIL_KEY}/opt/repo,{TAIL_DIR}\n-T4\n{OFFLINE_LINE}\n")
        );
        assert_eq!(
            config(&format!("{TAIL_KEY}/opt/repo,{TAIL_DIR}\n{OFFLINE_LINE}\n")),
            format!("{TAIL_KEY}/opt/repo,{TAIL_DIR}\n{OFFLINE_LINE}\n")
        );
        assert_eq!(
            config("-Daether.offline.protocols=http\n"),
            format!("-Daether.offline.protocols=http,file\n{TAIL_KEY}{TAIL_DIR}\n")
        );
        assert_eq!(config(OFFLINE_LINE), ours);
    }

    // ── suffixMavenPom port (goldens shared with depscan's maven-suffix.test.ts) ──

    const DS_SV: &str = "2.1.0-socket.3fa85f64";

    #[test]
    fn suffix_replaces_literal_version_only() {
        let pom = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
            <modelVersion>4.0.0</modelVersion>\n  <groupId>com.acme</groupId>\n  <artifactId>widget</artifactId>\n  \
            <version>2.1.0</version>\n  <packaging>jar</packaging>\n  <dependencies>\n    <dependency>\n      \
            <groupId>com.google.guava</groupId>\n      <artifactId>guava</artifactId>\n      \
            <version>32.1.3-jre</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let out = suffix_maven_pom(pom, "2.1.0", DS_SV).unwrap();
        assert_eq!(out.replace(DS_SV, "2.1.0"), pom);
        assert!(out.contains("<version>32.1.3-jre</version>"));
    }

    #[test]
    fn suffix_trims_version_whitespace() {
        let pom = "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  <version>\n    1.4.2\n  </version>\n</project>\n";
        let out = suffix_maven_pom(pom, "1.4.2", "1.4.2-socket.3fa85f64").unwrap();
        assert!(out.contains("<version>1.4.2-socket.3fa85f64</version>"));
    }

    #[test]
    fn suffix_inserts_inherited_version_after_artifact_id() {
        let pom = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
            <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>org.slf4j</groupId>\n    \
            <artifactId>slf4j-parent</artifactId>\n    <version>2.0.9</version>\n  </parent>\n  \
            <artifactId>slf4j-api</artifactId>\n  <packaging>jar</packaging>\n</project>\n";
        let sv = "2.0.9-socket.3fa85f64";
        let out = suffix_maven_pom(pom, "2.0.9", sv).unwrap();
        assert!(out.contains(&format!(
            "<artifactId>slf4j-api</artifactId>\n  <version>{sv}</version>"
        )));
        assert_eq!(
            out.replace(&format!("\n  <version>{sv}</version>"), ""),
            pom
        );
        // The inserted line is LF even in a CRLF pom, exactly as the server does.
        let crlf = pom.replace('\n', "\r\n");
        let out = suffix_maven_pom(&crlf, "2.0.9", sv).unwrap();
        assert!(out.contains(&format!("</artifactId>\n  <version>{sv}</version>\r\n")));
    }

    #[test]
    fn suffix_refusals() {
        let sv = "1.0.0-socket.3fa85f64";
        for pom in [
            "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  <version>${revision}</version>\n</project>\n",
            "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  <version>9.9.9</version>\n</project>\n",
            "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  <dependencies>\n    <dependency>\n      \
             <groupId>x</groupId>\n      <artifactId>y</artifactId>\n      <version>1.0.0</version>\n    </dependency>\n  \
             </dependencies>\n</project>\n",
            "<project>\n  <parent>\n    <groupId>g</groupId>\n    <artifactId>p</artifactId>\n    <version>1.0.0</version>\n  \
             </parent>\n  <packaging>jar</packaging>\n</project>\n",
            "<project>\n  <parent>\n    <groupId>g</groupId>\n    <artifactId>p</artifactId>\n    <version>2.0.0</version>\n  \
             </parent>\n  <artifactId>a</artifactId>\n</project>\n",
            "<notproject/>",
            "<project/>",
            "<project><version>1.0.0</version><!-- unterminated",
            "",
        ] {
            assert_eq!(suffix_maven_pom(pom, "1.0.0", sv), None, "{pom}");
        }
    }

    #[test]
    fn suffix_ignores_commented_version() {
        let pom = "<project>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  \
            <!-- old <version>0.0.1</version> for reference -->\n  <version>2.1.0</version>\n</project>\n";
        let out = suffix_maven_pom(pom, "2.1.0", DS_SV).unwrap();
        assert!(out.contains(&format!("<version>{DS_SV}</version>")));
        assert!(out.contains("<!-- old <version>0.0.1</version> for reference -->"));
    }

    #[test]
    fn suffix_literalizes_project_version_refs() {
        let sv = "1.0.0-socket.3fa85f64";
        let pom = "<project>\n  <groupId>com.example</groupId>\n  <artifactId>widget</artifactId>\n  <version>1.0.0</version>\n  \
            <properties>\n    <api.version>${pom.version}</api.version>\n  </properties>\n  <dependencies>\n    <dependency>\n      \
            <groupId>com.example</groupId>\n      <artifactId>widget-api</artifactId>\n      <version>${project.version}</version>\n    \
            </dependency>\n  </dependencies>\n</project>\n";
        assert_eq!(
            suffix_maven_pom(pom, "1.0.0", sv).unwrap(),
            pom.replace(
                "<version>1.0.0</version>",
                &format!("<version>{sv}</version>")
            )
            .replace("${pom.version}", "1.0.0")
            .replace("${project.version}", "1.0.0")
        );
        let legacy = "<project>\n  <groupId>c</groupId>\n  <artifactId>w</artifactId>\n  <version>1.0.0</version>\n  \
            <dependencies>\n    <dependency>\n      <version>${version}</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        assert_eq!(
            suffix_maven_pom(legacy, "1.0.0", sv).unwrap(),
            legacy
                .replacen(
                    "<version>1.0.0</version>",
                    &format!("<version>{sv}</version>"),
                    1
                )
                .replace("${version}", "1.0.0")
        );
        let declared = legacy.replace(
            "  <dependencies>",
            "  <properties>\n    <version>2.0.0</version>\n  </properties>\n  <dependencies>",
        );
        assert_eq!(
            suffix_maven_pom(&declared, "1.0.0", sv).unwrap(),
            declared.replacen(
                "<version>1.0.0</version>",
                &format!("<version>{sv}</version>"),
                1
            )
        );
    }

    // ── inherited `${project.version}` ──

    const ACME_UUID: &str = "deadbeef-0000-4000-8000-000000000000";
    const ACME_SV: &str = "1.0-socket.deadbeef";
    const ACME_TREE_POM: &str = ".socket/vendor/maven2/com/acme/acme-core/1.0-socket.deadbeef/\
        acme-core-1.0-socket.deadbeef.pom";
    const ACME_APP: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
        <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  <version>0.1</version>\n  \
        <dependencies>\n    <dependency>\n      <groupId>com.acme</groupId>\n      \
        <artifactId>acme-core</artifactId>\n      <version>1.0</version>\n    </dependency>\n  \
        </dependencies>\n</project>\n";
    /// The log4j-core shape: no `<version>` of its own, and a sibling whose
    /// version only the parent's management gives.
    const ACME_CORE: &str = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.acme</groupId>
    <artifactId>acme-parent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>acme-core</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>acme-api</artifactId>
    </dependency>
  </dependencies>
</project>
"#;
    const ACME_PARENT: &str = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>acme-parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.acme</groupId>
        <artifactId>acme-api</artifactId>
        <version>${project.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"#;

    fn acme(pom: &str) -> JvmPatch<'_> {
        JvmPatch {
            group_id: "com.acme",
            artifact_id: "acme-core",
            version: "1.0",
            uuid: ACME_UUID,
            jar: b"PK\x03\x04patched",
            upstream_pom: pom.as_bytes(),
            upstream_parents: None,
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    /// The pom the tree serves for `pom` over the upstream `parents`
    /// (nearest first).
    fn acme_pom(pom: &str, parents: &[&str]) -> Result<String, JvmRefusal> {
        let parents: Vec<Vec<u8>> = parents.iter().map(|p| p.as_bytes().to_vec()).collect();
        suffixed_pom(&JvmPatch {
            upstream_parents: Some(&parents),
            ..acme(pom)
        })
    }

    /// What `acme_pom` adds to the 5.1 shape of the suffixed pom: every
    /// line of each marked block, trimmed.
    fn inherited_lines(pom: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut inside = false;
        for line in pom.lines().map(str::trim) {
            match line {
                INHERITED_BEGIN => inside = true,
                INHERITED_END => inside = false,
                _ if inside => out.push(line),
                _ => {}
            }
        }
        out
    }

    /// VJ-D1: Maven interpolates after inheritance, so the parent's
    /// `${project.version}` reads the vendored child's suffixed version and
    /// the build asks for `acme-api:1.0-socket.deadbeef`, which nothing
    /// serves. The planner must write the base version instead.
    #[test]
    fn a_version_the_parent_manages_through_project_version_stays_at_the_base() {
        let files = fs(&[("pom.xml", ACME_APP)]);
        let read = |p: &str| files.get(p).cloned();
        let parents = vec![ACME_PARENT.as_bytes().to_vec()];
        let patch = JvmPatch {
            upstream_parents: Some(&parents),
            ..acme(ACME_CORE)
        };
        let plan = plan(&read, &lister(&files), &patch).expect("plan");
        let pom = text(&applied(&files, &plan), ACME_TREE_POM);
        assert!(
            pom.contains(&format!("<version>{ACME_SV}</version>")),
            "{pom}"
        );
        assert_eq!(
            inherited_lines(&pom),
            [
                "<dependencyManagement>",
                "<dependencies>",
                "<dependency>",
                "<groupId>com.acme</groupId>",
                "<artifactId>acme-api</artifactId>",
                "<version>1.0</version>",
                "</dependency>",
                "</dependencies>",
                "</dependencyManagement>",
            ],
            "{pom}"
        );
        assert_eq!(inherited_leaks(&pom, &parents, &patch.coords()), None);
        // The legacy shape is what leaks, and the check names it.
        let legacy = suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap();
        let leak = inherited_leaks(&legacy, &parents, &patch.coords()).expect("leak");
        assert!(
            leak.hard
                && leak
                    .detail
                    .contains("com.acme:acme-api:1.0-socket.deadbeef"),
            "{leak:?}"
        );
    }

    /// The parent's `<dependencies>`, a property and its management, as
    /// built with Maven 3.9.16 (`target/tmp/exp`, variant `fixed`): every
    /// inherited entry up to the last one naming the version is declared
    /// again, in the inherited order, because Maven lists a child's own
    /// declarations first.
    #[test]
    fn inherited_declarations_are_copied_in_their_inherited_order() {
        let grand =
            "<project>\n  <groupId>com.acme</groupId>\n  <artifactId>acme-grand</artifactId>\n  \
            <version>7</version>\n  <dependencies>\n    <dependency><groupId>com.acme</groupId>\
            <artifactId>acme-d</artifactId><version>1.0</version></dependency>\n  </dependencies>\n\
            </project>\n";
        let parent = r#"<project>
  <parent><groupId>com.acme</groupId><artifactId>acme-grand</artifactId><version>7</version></parent>
  <groupId>com.acme</groupId>
  <artifactId>acme-parent</artifactId>
  <version>1.0</version>
  <properties>
    <acme.c.version>${project.version}</acme.c.version>
    <unrelated>${project.version}</unrelated>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.acme</groupId>
        <artifactId>acme-c</artifactId>
        <version>${acme.c.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>com.acme</groupId><artifactId>acme-b</artifactId><version>1.0</version></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>acme-c</artifactId></dependency>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>acme-api</artifactId>
      <version>${pom.version}</version>
    </dependency>
    <dependency><groupId>com.acme</groupId><artifactId>acme-e</artifactId><version>1.0</version></dependency>
  </dependencies>
</project>
"#;
        let core = "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
            <artifactId>acme-parent</artifactId>\n    <version>1.0</version>\n  </parent>\n  \
            <artifactId>acme-core</artifactId>\n  <version>1.0</version>\n  <properties>\n    \
            <own>1</own>\n  </properties>\n</project>\n";
        let pom = acme_pom(core, &[parent, grand]).expect("resolved");
        assert_eq!(
            pom,
            format!(
                "<project>\n  <parent>\n    <groupId>com.acme</groupId>\n    \
                 <artifactId>acme-parent</artifactId>\n    <version>1.0</version>\n  </parent>\n  \
                 <artifactId>acme-core</artifactId>\n  <version>{ACME_SV}</version>\n  <properties>\n    \
                 <own>1</own>\n    {INHERITED_BEGIN}\n    <acme.c.version>1.0</acme.c.version>\n    \
                 {INHERITED_END}\n  </properties>\n  {INHERITED_BEGIN}\n  <dependencies>\n    \
                 <dependency><groupId>com.acme</groupId><artifactId>acme-b</artifactId>\
                 <version>1.0</version></dependency>\n    \
                 <dependency><groupId>${{project.groupId}}</groupId><artifactId>acme-c</artifactId>\
                 </dependency>\n    <dependency>\n      <groupId>com.acme</groupId>\n      \
                 <artifactId>acme-api</artifactId>\n      <version>1.0</version>\n    </dependency>\n  \
                 </dependencies>\n  {INHERITED_END}\n</project>\n"
            )
        );
    }

    /// A parent that names the version only where no consumer reads it
    /// (commons-parent: a release property, plugin configuration) changes
    /// nothing: the pom stays byte for byte what 5.1 wrote, so committed
    /// trees of such artifacts stay in sync.
    #[test]
    fn a_parent_naming_the_version_outside_dependency_data_changes_nothing() {
        let parent = "<project>\n  <groupId>com.acme</groupId>\n  <artifactId>acme-parent</artifactId>\n  \
            <version>1.0</version>\n  <properties>\n    \
            <release.version>${project.version}</release.version>\n  </properties>\n  <build>\n    \
            <finalName>acme-${project.version}</finalName>\n  </build>\n  <dependencyManagement>\n    \
            <dependencies>\n      <dependency><groupId>org.x</groupId><artifactId>y</artifactId>\
            <version>3</version></dependency>\n    </dependencies>\n  </dependencyManagement>\n\
            </project>\n";
        assert_eq!(
            acme_pom(ACME_CORE, &[parent]).unwrap(),
            suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap()
        );
        // The parent managing the artifact itself reads the suffixed
        // version, which the tree serves.
        let own = parent.replace(
            "<groupId>org.x</groupId><artifactId>y</artifactId><version>3</version>",
            "<groupId>${project.groupId}</groupId><artifactId>acme-core</artifactId>\
             <version>${project.version}</version>",
        );
        assert_eq!(
            acme_pom(ACME_CORE, &[&own]).unwrap(),
            suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap()
        );
        assert_eq!(
            acme_pom(ACME_CORE, &[]).unwrap(),
            suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap()
        );
    }

    /// A committed tree is re-planned from its own pom: with the parents at
    /// hand the additions are computed again, without them they are kept,
    /// and either way nothing is rewritten.
    #[test]
    fn a_committed_pom_replans_unchanged_with_or_without_its_parents() {
        for nl in ["\n", "\r\n"] {
            let app = ACME_APP.replace('\n', nl);
            let core = ACME_CORE.replace('\n', nl);
            let files = fs(&[("pom.xml", &app)]);
            let parents = vec![ACME_PARENT.as_bytes().to_vec()];
            let first = JvmPatch {
                upstream_parents: Some(&parents),
                ..acme(&core)
            };
            let plan_of = |files: &Fs, patch: &JvmPatch<'_>| {
                plan(&|p: &str| files.get(p).cloned(), &lister(files), patch).expect("plan")
            };
            let after = applied(&files, &plan_of(&files, &first));
            let pom = text(&after, ACME_TREE_POM);
            assert!(pom.contains(INHERITED_BEGIN), "{pom}");
            let (jar, upstream) = committed(&|p: &str| after.get(p).cloned(), &first.coords())
                .expect("committed tree");
            for parents in [Some(parents.as_slice()), None] {
                let again = JvmPatch {
                    jar: &jar,
                    upstream_pom: &upstream,
                    upstream_parents: parents,
                    ..acme("")
                };
                let writes = plan_of(&after, &again).writes;
                assert!(
                    writes.is_empty(),
                    "{nl:?} {:?}",
                    writes.iter().map(|w| &w.rel).collect::<Vec<_>>()
                );
            }
            // A tree vendored before the parents were read is brought up to
            // date once they are.
            let legacy = suffix_maven_pom(&core, "1.0", ACME_SV).unwrap();
            let mut old = after.clone();
            old.insert(ACME_TREE_POM.to_string(), legacy.into_bytes());
            let (jar, upstream) =
                committed(&|p: &str| old.get(p).cloned(), &first.coords()).expect("legacy tree");
            let again = JvmPatch {
                jar: &jar,
                upstream_pom: &upstream,
                upstream_parents: Some(&parents),
                ..acme("")
            };
            assert_eq!(
                text(&applied(&old, &plan_of(&old, &again)), ACME_TREE_POM),
                pom
            );
        }
    }

    #[test]
    fn strip_inherited_removes_exactly_what_was_added() {
        let grand = "<project><groupId>com.acme</groupId><artifactId>g</artifactId><version>7</version>\
            <properties><p>${project.version}</p></properties><dependencyManagement><dependencies>\
            <dependency><groupId>com.acme</groupId><artifactId>acme-api</artifactId><version>${p}</version>\
            </dependency><dependency><groupId>com.acme</groupId><artifactId>acme-b</artifactId>\
            <version>${version}</version></dependency></dependencies></dependencyManagement></project>";
        // Whole lines, and a one-line pom where the additions go inline.
        for core in [
            ACME_CORE.to_string(),
            ACME_CORE.replace('\n', "\r\n"),
            ACME_CORE.replace("\n  ", "\t").replace('\n', ""),
            ACME_CORE.replace(
                "  <dependencies>",
                "  <properties><a>1</a></properties>\n  <dependencyManagement>\n  \
                 </dependencyManagement>\n  <dependencies>",
            ),
        ] {
            let legacy = suffix_maven_pom(&core, "1.0", ACME_SV).unwrap();
            let pom = acme_pom(&core, &[grand]).expect("resolved");
            assert_eq!(
                pom.matches(INHERITED_BEGIN).count(),
                pom.matches(INHERITED_END).count()
            );
            assert!(pom.contains(INHERITED_BEGIN), "{pom}");
            assert_eq!(strip_inherited(&pom), legacy, "{pom}");
            assert!(
                pom.contains("<p>1.0</p>") && pom.contains("<artifactId>acme-b</artifactId>"),
                "{pom}"
            );
            assert!(Doc::parse(pom.clone()).is_ok(), "{pom}");
        }
        assert_eq!(strip_inherited(ACME_CORE), ACME_CORE);
    }

    /// Shapes the additions cannot express are refused, never guessed: a
    /// parent profile is active or not on the consumer's machine, and a
    /// child declaration always beats it.
    #[test]
    fn unresolvable_inherited_versions_refuse() {
        let profile = |body: &str| {
            ACME_PARENT.replace(
                "</project>",
                &format!("  <profiles><profile><id>p</id>{body}</profile></profiles>\n</project>"),
            )
        };
        let dep = "<dependency><groupId>com.acme</groupId><artifactId>acme-b</artifactId>\
            <version>${project.version}</version></dependency>";
        for (what, parent) in [
            (
                "a profile dependency naming the version",
                profile(&format!("<dependencies>{dep}</dependencies>")),
            ),
            (
                "profile management beside copied management",
                profile(
                    "<dependencyManagement><dependencies><dependency><groupId>o</groupId>\
                     <artifactId>x</artifactId><version>1</version></dependency></dependencies>\
                     </dependencyManagement>",
                ),
            ),
            (
                "a version reference in a management key",
                ACME_PARENT.replace(
                    "<version>${project.version}</version>",
                    "<classifier>${project.version}</classifier><version>1</version>",
                ),
            ),
            (
                "a repository addressed through the version",
                ACME_PARENT.replace(
                    "</project>",
                    "<repositories><repository><id>r</id><url>https://r/${project.version}</url>\
                     </repository></repositories></project>",
                ),
            ),
            (
                "a profile redefining an overridden property",
                ACME_PARENT
                    .replace(
                        "<version>${project.version}</version>",
                        "<version>${api.version}</version>",
                    )
                    .replace(
                        "<packaging>pom</packaging>",
                        "<properties><api.version>${project.version}</api.version></properties>\
                         <profiles><profile><id>p</id><properties><api.version>9</api.version>\
                         </properties></profile></profiles>",
                    ),
            ),
            ("an unparseable parent", format!("{ACME_PARENT}</oops>")),
        ] {
            let r = acme_pom(ACME_CORE, &[&parent]).expect_err(what);
            assert_eq!(r.code, UPSTREAM_UNAVAILABLE, "{what}");
            assert_eq!(
                refusal_reason(&r),
                "inherited_version_unresolvable",
                "{what}"
            );
            assert!(
                r.detail.contains("com.acme:acme-parent:1.0"),
                "{what}: {}",
                r.detail
            );
        }
        // An unparseable parent that never names the version cannot move one.
        let literal = ACME_PARENT.replace("${project.version}", "1.0");
        assert_eq!(
            acme_pom(ACME_CORE, &[&format!("{literal}</oops>")]).unwrap(),
            suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap()
        );
    }

    /// What `vendor --check` reports for a tree 5.0 / 5.1 wrote: a
    /// dependency that resolves at the suffixed version is broken for every
    /// Maven; management nothing of the pom uses (netty-parent's
    /// `netty-dev-tools`) is not, so such a tree keeps passing.
    #[test]
    fn only_a_resolved_suffixed_version_is_a_hard_leak() {
        let c = acme("").coords();
        let legacy = suffix_maven_pom(ACME_CORE, "1.0", ACME_SV).unwrap();
        let unused = ACME_PARENT.replace("acme-api", "acme-dev-tools");
        let leak = inherited_leaks(&legacy, &[unused.into_bytes()], &c).expect("soft leak");
        assert!(!leak.hard, "{leak:?}");
        let import = ACME_PARENT.replace(
            "<version>${project.version}</version>",
            "<version>${project.version}</version><type>pom</type><scope>import</scope>",
        );
        let leak = inherited_leaks(&legacy, &[import.into_bytes()], &c).expect("import");
        assert!(leak.hard, "{leak:?}");
        let literal = ACME_PARENT.replace("${project.version}", "1.0");
        assert_eq!(inherited_leaks(&legacy, &[literal.into_bytes()], &c), None);
    }

    #[test]
    fn parent_gav_reads_a_literal_parent_only() {
        assert_eq!(
            parent_gav(ACME_CORE.as_bytes()),
            Ok(Some((
                "com.acme".into(),
                "acme-parent".into(),
                "1.0".into()
            )))
        );
        assert_eq!(parent_gav(ACME_PARENT.as_bytes()), Ok(None));
        for pom in [
            "<project><parent><groupId>g</groupId><artifactId>a</artifactId>\
             <version>${revision}</version></parent></project>",
            "<project><parent><groupId>g</groupId><artifactId>a</artifactId></parent></project>",
            "<project><parent><groupId>../g</groupId><artifactId>a</artifactId><version>1</version>\
             </parent></project>",
            "<notproject/>",
        ] {
            assert!(parent_gav(pom.as_bytes()).is_err(), "{pom}");
        }
    }

    #[test]
    fn suffix_multi_module_pom_keeps_modules() {
        let pom = "<project>\n  <groupId>com.acme</groupId>\n  <artifactId>parent</artifactId>\n  <version>5.0.0</version>\n  \
            <packaging>pom</packaging>\n  <modules>\n    <module>core</module>\n  </modules>\n</project>\n";
        let out = suffix_maven_pom(pom, "5.0.0", "5.0.0-socket.3fa85f64").unwrap();
        assert!(out.contains("<version>5.0.0-socket.3fa85f64</version>"));
        assert!(out.contains("<module>core</module>"));
    }

    // ── scanner ──

    #[test]
    fn doc_parse_handles_prolog_doctype_attributes_and_cdata() {
        let doc = Doc::parse(
            "\u{feff}<?xml version=\"1.0\"?>\n<!DOCTYPE project [<!ENTITY x \"y\">]>\n<project a=\"x>y\">\
             <name><![CDATA[a <b> c]]></name><v> 1 <!-- c --> </v></project>"
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            doc.child_text(doc.project, "name").as_deref(),
            Some("a <b> c")
        );
        let v = doc.child(doc.project, "v").unwrap();
        assert_eq!(doc.text_of(v), "1");
        assert_eq!(&doc.text[doc.value_span(v)], "1");
        for bad in [
            "<project>",
            "<project></other>",
            "<a/><project></project>",
            "<project><!-- x</project>",
            "</project>",
        ] {
            assert!(Doc::parse(bad.to_string()).is_err(), "{bad}");
        }
    }

    #[test]
    fn indent_unit_detection() {
        assert_eq!(indent_unit("<p>\n    <a/>\n        <b/>\n</p>"), "    ");
        assert_eq!(indent_unit("<p>\n\t<a/>\n</p>"), "\t");
        assert_eq!(indent_unit("<p><a/></p>"), "  ");
    }

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("", "a/./b/"), Some("a/b".into()));
        assert_eq!(normalize("a", "../b"), Some("b".into()));
        assert_eq!(normalize("a", ".."), Some(String::new()));
        assert_eq!(normalize("a", "..\\b"), Some("b".into()));
        assert_eq!(normalize("", "../x"), None);
        assert_eq!(normalize("", "C:/x"), None);
        assert_eq!(normalize("", "/x"), None);
    }

    // ── revert, peers and patch updates (disk round-trips) ──

    use super::super::{testing, Shape};

    const UUID_B: &str = "abcdef01-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const UUID_2: &str = "99999999-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const SV_2: &str = "1.10.0-socket.99999999";

    fn patch_b() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.example",
            artifact_id: "lib",
            version: "2.0",
            uuid: UUID_B,
            jar: b"PK\x03\x04B",
            upstream_pom: b"<project><groupId>org.example</groupId><artifactId>lib</artifactId><version>2.0</version></project>\n",
            upstream_parents: None,
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn lib_dep(version: &str) -> String {
        format!(
            "<dependency><groupId>org.example</groupId><artifactId>lib</artifactId>\
             <version>{version}</version></dependency>"
        )
    }

    fn disk(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        testing::populate(dir.path(), files);
        dir
    }

    fn replan_writes(root: &std::path::Path, p: &JvmPatch<'_>) -> Vec<String> {
        let reader = super::super::apply::ProjectReader::new(root);
        plan(&|rel: &str| reader.read(rel), &|d: &str| reader.list(d), p)
            .unwrap()
            .writes
            .into_iter()
            .map(|w| w.rel)
            .collect()
    }

    fn all_text(root: &std::path::Path) -> String {
        testing::snapshot(root)
            .into_iter()
            .filter(|(rel, _)| rel.ends_with(".xml") || rel.ends_with(".config"))
            .map(|(_, b)| String::from_utf8(b).unwrap())
            .collect()
    }

    /// Reverting either of two patches that share the repository block,
    /// the created management section, `maven.config` and the tree
    /// `.gitattributes` leaves the other fully wired (re-planning it writes
    /// nothing); reverting both restores every byte and directory.
    #[tokio::test]
    async fn two_patches_revert_in_either_order_byte_exact() {
        for first_a in [true, false] {
            let a_pom = module("a", &format!("{}\n    {}", dep("1.10.0"), lib_dep("2.0")));
            let dir = disk(&[
                ("pom.xml", ROOT),
                ("a/pom.xml", &a_pom),
                ("b/pom.xml", &module("b", "")),
            ]);
            let root = dir.path();
            let (pristine, pristine_dirs) = (testing::snapshot(root), testing::dirs(root));
            let mut ledger = BTreeMap::new();
            let (pa, pb) = (patch(), patch_b());
            let plan_a = testing::vendor(root, Shape::MavenReactor, &pa, &mut ledger)
                .await
                .unwrap();
            let plan_b = testing::vendor(root, Shape::MavenReactor, &pb, &mut ledger)
                .await
                .unwrap();
            assert!(!plan_b.writes.iter().any(|w| w.rel == GITATTRIBUTES_REL));
            let (first, second, second_plan) = if first_a {
                (&pa, &pb, &plan_b)
            } else {
                (&pb, &pa, &plan_a)
            };
            let out = testing::revert(root, first, &mut ledger).await;
            assert!(
                out.success && out.warnings.is_empty() && !out.kept_artifact,
                "{out:?}"
            );
            assert!(
                replan_writes(root, second).is_empty(),
                "the remaining patch lost wiring: {:?}",
                replan_writes(root, second)
            );
            assert!(root.join(&second_plan.jar_rel).is_file());
            assert!(root.join(GITATTRIBUTES_REL).is_file());
            assert!(!all_text(root).contains(&first.suffixed_version()));
            let out = testing::revert(root, second, &mut ledger).await;
            assert!(out.success && out.warnings.is_empty(), "{out:?}");
            assert_eq!(testing::snapshot(root), pristine, "first_a={first_a}");
            assert_eq!(testing::dirs(root), pristine_dirs, "first_a={first_a}");
        }
    }

    /// The same on single-line poms whose sections are self-closing (every
    /// insertion is inline, and the created shells expand `<x/>`).
    #[tokio::test]
    async fn two_patches_on_single_line_poms_revert_in_either_order_byte_exact() {
        let root_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
            <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
            <modules><module>a</module></modules><dependencyManagement/><repositories/></project>";
        let a_pom = format!(
            "<project><parent><groupId>t</groupId><artifactId>root</artifactId>\
             <version>1</version></parent><artifactId>a</artifactId><dependencies>{}{}\
             </dependencies></project>",
            dep("1.10.0"),
            lib_dep("2.0")
        );
        for first_a in [true, false] {
            let dir = disk(&[("pom.xml", root_pom), ("a/pom.xml", &a_pom)]);
            let root = dir.path();
            let pristine = testing::snapshot(root);
            let mut ledger = BTreeMap::new();
            let (pa, pb) = (patch(), patch_b());
            testing::vendor(root, Shape::MavenReactor, &pa, &mut ledger)
                .await
                .unwrap();
            testing::vendor(root, Shape::MavenReactor, &pb, &mut ledger)
                .await
                .unwrap();
            let (first, second) = if first_a { (&pa, &pb) } else { (&pb, &pa) };
            let out = testing::revert(root, first, &mut ledger).await;
            assert!(out.success && out.warnings.is_empty(), "{out:?}");
            assert!(replan_writes(root, second).is_empty());
            let out = testing::revert(root, second, &mut ledger).await;
            assert!(out.success && out.warnings.is_empty(), "{out:?}");
            assert_eq!(testing::snapshot(root), pristine, "first_a={first_a}");
        }
    }

    /// A same-uuid re-run that edits a file again keeps the first run's
    /// records (carried-forward fragments), so revert still restores
    /// the pristine pom and deletes the tree only once nothing names it.
    #[tokio::test]
    async fn same_uuid_rerun_keeps_the_first_runs_originals() {
        let dir = disk(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let root = dir.path();
        let mut ledger = BTreeMap::new();
        let p = patch();
        testing::vendor(root, Shape::MavenReactor, &p, &mut ledger)
            .await
            .unwrap();
        let test_dep = dep("1.10.0").replace("<dependency>", "<dependency><scope>test</scope>");
        let added = |pom: &str| {
            pom.replace(
                "  </dependencies>",
                &format!("    {test_dep}\n  </dependencies>"),
            )
        };
        let a1 = std::fs::read_to_string(root.join("a/pom.xml")).unwrap();
        std::fs::write(root.join("a/pom.xml"), added(&a1)).unwrap();
        let run2 = testing::vendor(root, Shape::MavenReactor, &p, &mut ledger)
            .await
            .unwrap();
        assert_eq!(pom_rels(&run2), ["a/pom.xml"]);
        let out = testing::revert(root, &p, &mut ledger).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(root.join("a/pom.xml")).unwrap(),
            added(&module("a", &dep("1.10.0")))
        );
        assert_eq!(std::fs::read_to_string(root.join("pom.xml")).unwrap(), ROOT);
        assert!(!root.join(".socket").exists() && !root.join(".mvn").exists());
    }

    /// A patch update (same GAV, new uuid) re-points the pin and every
    /// rewritten declaration at the new suffixed version, sweeps the old
    /// tree, and still reverts to the pristine poms, `${p}` included.
    #[tokio::test]
    async fn patch_update_rewires_to_the_new_uuid_and_reverts_pristine() {
        let root_pom = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <ct.version>1.10.0</ct.version>\n  </properties>\n  <modules>",
        );
        let dir = disk(&[
            ("pom.xml", &root_pom),
            ("a/pom.xml", &module("a", &dep("${ct.version}"))),
            ("b/pom.xml", &module("b", &dep("1.10.0"))),
        ]);
        let root = dir.path();
        std::fs::create_dir_all(root.join(".mvn/wrapper")).unwrap();
        std::fs::write(
            root.join(".mvn/wrapper/maven-wrapper.properties"),
            "distributionUrl=https://example.test/apache-maven-3.9.16-bin.zip\n",
        )
        .unwrap();
        let pristine = testing::snapshot(root);
        let mut ledger = BTreeMap::new();
        let p1 = patch();
        let plan1 = testing::vendor(root, Shape::MavenReactor, &p1, &mut ledger)
            .await
            .unwrap();
        let mut p2 = patch();
        p2.uuid = UUID_2;
        let plan2 = testing::vendor(root, Shape::MavenReactor, &p2, &mut ledger)
            .await
            .unwrap();
        assert!(plan2.warnings.is_empty(), "{:?}", plan2.warnings);
        let poms = all_text(root);
        assert!(!poms.contains("1d3c1fd2"), "old uuid left behind:\n{poms}");
        assert_eq!(poms.matches(SV_2).count(), 3, "pin + a + b:\n{poms}");
        assert!(poms.contains(&format!("{PIN_TAG}{UUID_2}:")));
        assert!(!root.join(&plan1.tree_dir).exists(), "old tree swept");
        assert!(root.join(&plan2.jar_rel).is_file());
        assert!(replan_writes(root, &p2).is_empty());
        let out = testing::revert(root, &p2, &mut ledger).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(testing::snapshot(root), pristine);
    }

    /// Without a ledger original (the peer entry is gone), a declaration at
    /// the suffixed version reverts to the base literal.
    #[test]
    fn unplan_without_records_restores_the_base_version() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        let read = |rel: &str| after.get(rel).cloned();
        let undo = unplan(&read, &lister(&after), &patch().coords(), &[]);
        let changed: BTreeMap<String, Option<Vec<u8>>> = undo.changes.into_iter().collect();
        assert_eq!(
            changed["a/pom.xml"].as_deref(),
            Some(module("a", &dep("1.10.0")).as_bytes())
        );
        assert!(!undo.still_wired && undo.drifted.is_empty());
        // Without records nothing proves vendor created the shared lines.
        assert!(!changed.contains_key(MAVEN_CONFIG));
    }

    #[tokio::test]
    async fn revert_is_idempotent_and_a_dry_run_writes_nothing() {
        let dir = disk(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let root = dir.path();
        let pristine = testing::snapshot(root);
        let mut ledger = BTreeMap::new();
        testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
            .await
            .unwrap();
        let entry = ledger.values().next().unwrap().clone();
        let vendored = testing::snapshot(root);
        let dry =
            super::super::apply::revert(root, &entry, crate::vendor::RevertOpts::new(true)).await;
        assert!(dry.success && dry.warnings.is_empty());
        assert_eq!(testing::snapshot(root), vendored);
        for _ in 0..2 {
            let out =
                super::super::apply::revert(root, &entry, crate::vendor::RevertOpts::new(false))
                    .await;
            assert!(
                out.success && out.warnings.is_empty() && !out.kept_artifact,
                "{out:?}"
            );
            assert_eq!(testing::snapshot(root), pristine);
        }
    }

    /// A pin whose comment no longer tags a `<dependency>` is drift: the
    /// tree stays while the pom still names the suffixed version.
    #[tokio::test]
    async fn drifted_pin_keeps_the_tree() {
        let dir = disk(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let root = dir.path();
        let mut ledger = BTreeMap::new();
        let plan = testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
            .await
            .unwrap();
        let pom = std::fs::read_to_string(root.join("pom.xml")).unwrap();
        let broken = pom.replacen(
            "-->\n      <dependency>",
            "-->\n      <exclusion/><dependency>",
            1,
        );
        assert_ne!(broken, pom);
        std::fs::write(root.join("pom.xml"), &broken).unwrap();
        let out = testing::revert(root, &patch(), &mut ledger).await;
        assert!(
            out.success && out.drift_skipped() && out.kept_artifact,
            "{out:?}"
        );
        assert!(root.join(&plan.jar_rel).is_file());
        assert!(
            root.join(MAVEN_CONFIG).is_file(),
            "still referenced: shared lines stay"
        );
    }

    #[test]
    fn cdata_version_is_replaced_whole_and_restored() {
        let cdata = "<dependency><groupId>org.apache.commons</groupId>\
             <artifactId>commons-text</artifactId><version><![CDATA[1.10.0]]></version></dependency>";
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", cdata)),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(
            text(&after, "a/pom.xml"),
            module("a", &cdata.replace("<![CDATA[1.10.0]]>", SV))
        );
        let read = |rel: &str| after.get(rel).cloned();
        let undo = unplan(&read, &lister(&after), &patch().coords(), &plan.records);
        let a = undo.changes.iter().find(|(r, _)| r == "a/pom.xml").unwrap();
        assert_eq!(a.1.as_deref(), Some(module("a", cdata).as_bytes()));
    }

    #[test]
    fn property_coordinates_are_interpolated_and_restored() {
        // #655: Maven interpolates groupId/artifactId before matching, so a
        // `${ct.group}:${ct.artifact}` declaration is the patched artifact.
        let root = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <ct.group>org.apache.commons</ct.group>\n    \
             <ct.artifact>commons-text</ct.artifact>\n  </properties>\n  <modules>",
        );
        let decl = "<dependency><groupId>${ct.group}</groupId>\
             <artifactId>${ct.artifact}</artifactId><version>1.10.0</version></dependency>";
        let a = module("a", decl);
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
        let read = |rel: &str| after.get(rel).cloned();
        let undo = unplan(&read, &lister(&after), &patch().coords(), &plan.records);
        assert!(undo.drifted.is_empty(), "{:?}", undo.drifted);
        let a_undo = undo.changes.iter().find(|(r, _)| r == "a/pom.xml").unwrap();
        assert_eq!(a_undo.1.as_deref(), Some(a.as_bytes()));
    }

    #[test]
    fn unresolvable_property_coordinate_warns() {
        let decl = "<dependency><groupId>${remote.group}</groupId>\
             <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>";
        let a = module("a", decl);
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert_eq!(reasons(&plan), ["property_unresolved"]);
        assert!(
            plan.warnings[0].detail.contains("${remote.group}"),
            "{}",
            plan.warnings[0].detail
        );
        assert_eq!(text(&after, "a/pom.xml"), a);
    }

    #[test]
    fn property_coordinates_keep_literal_record_keys() {
        // Records written before #655 keyed the literal declaration as
        // ordinal 0; a `${...}` declaration ahead of it must not shift that.
        let deps = format!(
            "<dependency><groupId>${{ct.group}}</groupId>\
             <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>{}",
            dep("1.10.0")
        );
        let doc = Doc::parse(module("a", &deps)).unwrap();
        let resolve = |_: &str| Some("org.apache.commons".to_string());
        let keys: Vec<String> = doc
            .keyed_declarations("org.apache.commons", "commons-text", &resolve)
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        assert_eq!(
            keys,
            [
                "version:org.apache.commons:commons-text:dependencies:$:0",
                "version:org.apache.commons:commons-text:dependencies:0",
            ]
        );
    }

    #[test]
    fn property_coordinates_another_module_overrides_are_left_alone() {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties>\n    <lib.artifact>commons-text</lib.artifact>\n  </properties>\n  \
             <dependencyManagement><dependencies><dependency><groupId>org.apache.commons</groupId>\
             <artifactId>${lib.artifact}</artifactId><version>1.10.0</version></dependency>\
             </dependencies></dependencyManagement>\n  <modules>",
        );
        let b = module("b", "").replace(
            "  <dependencies>",
            "  <properties><lib.artifact>commons-lang3</lib.artifact></properties>\n  <dependencies>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &b),
        ]);
        let plan = run(&files).expect("plan");
        assert_eq!(reasons(&plan), ["coordinates_overridden"]);
        let after = applied(&files, &plan);
        let out = text(&after, "pom.xml");
        assert!(!out.contains(SV), "{out}");
        assert!(
            out.contains("<artifactId>${lib.artifact}</artifactId><version>1.10.0</version>"),
            "{out}"
        );
    }

    #[test]
    fn project_group_id_coordinate_resolves() {
        let root = ROOT.replace(
            "<groupId>t</groupId>",
            "<groupId>org.apache.commons</groupId>",
        );
        let decl = "<dependency><groupId>${project.groupId}</groupId>\
             <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>";
        let a = module("a", decl).replace(
            "<groupId>t</groupId>",
            "<groupId>org.apache.commons</groupId>",
        );
        let b = module("b", "").replace(
            "<groupId>t</groupId>",
            "<groupId>org.apache.commons</groupId>",
        );
        let files = fs(&[("pom.xml", &root), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
    }

    #[test]
    fn unresolvable_coordinate_of_another_artifact_does_not_warn() {
        let decls = "<dependency><groupId>org.apache.commons</groupId>\
             <artifactId>${remote.x}-lang3</artifactId><version>3.0</version></dependency>\
             <dependency><groupId>${remote.group}</groupId><artifactId>commons-text</artifactId>\
             <classifier>sources</classifier><version>1.10.0</version></dependency>";
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", decls)),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, _) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
    }

    #[test]
    fn may_interpolate_to_keeps_literal_text() {
        assert!(may_interpolate_to("${g}", "org.apache.commons"));
        assert!(may_interpolate_to("org.${x}.commons", "org.apache.commons"));
        assert!(may_interpolate_to("${a}-${b}", "commons-text"));
        assert!(!may_interpolate_to("${x}-lang3", "commons-text"));
        assert!(!may_interpolate_to("com.${x}", "org.apache.commons"));
        assert!(!may_interpolate_to("${x", "commons-text"));
    }

    #[test]
    fn a_comment_before_the_anchor_is_not_indentation() {
        let root = ROOT.replace("  <build>", "  <!-- b --><build>");
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        let out = text(&after, "pom.xml");
        assert_eq!(out.matches("<!-- b -->").count(), 1, "{out}");
        assert!(
            out.contains("\n  <dependencyManagement>\n    <dependencies>\n"),
            "{out}"
        );
        assert!(
            out.contains("</dependencyManagement>\n  <!-- b --><build>"),
            "{out}"
        );
    }

    /// Maven interpolates after inheritance: a module overriding the
    /// property keeps its own version, so the inherited `${p}` stays and
    /// the root is not pinned.
    #[test]
    fn inherited_property_overridden_by_a_module_is_left_alone() {
        let root = ROOT.replace(
            "  <build>",
            "  <properties><ct.version>1.10.0</ct.version></properties>\n  \
             <dependencyManagement>\n    <dependencies>\n      \
             <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
             <version>${ct.version}</version></dependency>\n    </dependencies>\n  \
             </dependencyManagement>\n  <build>",
        );
        let bare = "<dependency><groupId>org.apache.commons</groupId>\
                    <artifactId>commons-text</artifactId></dependency>";
        let a = module("a", bare).replace(
            "  <dependencies>",
            "  <properties><ct.version>1.12.0</ct.version></properties>\n  <dependencies>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", bare)),
        ]);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["conflicting_literal_version"]);
        assert!(
            plan.warnings[0].detail.contains("1.12.0 in a/pom.xml"),
            "{:?}",
            plan.warnings
        );
        let after = applied(&files, &plan);
        assert!(
            !text(&after, "pom.xml").contains(SV),
            "{}",
            text(&after, "pom.xml")
        );
        assert!(text(&after, "pom.xml").contains("<version>${ct.version}</version>"));
        // Without the override the inherited declaration is rewritten.
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &module("a", bare)),
            ("b/pom.xml", &module("b", bare)),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert!(text(&after, "pom.xml").contains(&format!("<version>{SV}</version></dependency>")));
    }

    // ── uncertain property versions (#513, #459) ──

    /// No pom of the reactor names the suffixed version: `vex` sees the
    /// patch as unwired.
    fn unwired(files: &Fs) -> bool {
        files
            .iter()
            .filter(|(rel, _)| rel.ends_with(".xml"))
            .all(|(_, bytes)| !String::from_utf8_lossy(bytes).contains(SV))
    }

    /// `profile` as a profile of `pom`, placed before its `<dependencies>`
    /// (or `<modules>`).
    fn with_profile(pom: &str, id: &str, props: &str) -> String {
        let profile = format!(
            "<profiles><profile><id>{id}</id><activation><activeByDefault>true\
             </activeByDefault></activation><properties>{props}</properties></profile>\
             </profiles>\n  "
        );
        let at = pom
            .find("<dependencies>")
            .or_else(|| pom.find("<modules>"))
            .unwrap();
        format!("{}{profile}{}", &pom[..at], &pom[at..])
    }

    /// #513 case 1: a property only an external parent defines keeps the
    /// module's explicit version over any pin, so the root is not pinned.
    #[test]
    fn a_property_from_an_external_parent_leaves_the_root_unpinned() {
        let parent = "<parent><groupId>com.corp</groupId><artifactId>corp-parent</artifactId>\
            <version>3</version><relativePath/></parent>";
        let mut files = external_reactor(parent, "");
        let a = text(&files, "a/pom.xml").replace(
            "</artifactId></dependency>",
            "</artifactId><version>${ct.version}</version></dependency>",
        );
        files.insert("a/pom.xml".into(), a.clone().into_bytes());
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["property_unresolved"]);
        let after = applied(&files, &plan);
        assert_eq!(text(&after, "a/pom.xml"), a);
        assert!(!root_pinned(&plan, &files));
        assert!(unwired(&after));
    }

    /// #513: a plan that leaves every declaration and root alone wires
    /// nothing, so `vendor` refuses it with the reasons instead of
    /// counting the patch as applied.
    #[test]
    fn a_plan_that_wires_nothing_is_refused() {
        let parent = "<parent><groupId>com.corp</groupId><artifactId>corp-parent</artifactId>\
            <version>3</version><relativePath/></parent>";
        let mut files = external_reactor(parent, "");
        let a = text(&files, "a/pom.xml").replace(
            "</artifactId></dependency>",
            "</artifactId><version>${ct.version}</version></dependency>",
        );
        files.insert("a/pom.xml".into(), a.into_bytes());
        let plan = run(&files).unwrap();
        let read = |p: &str| files.get(p).cloned();
        let r = refuse_unwired(&read, &lister(&files), &patch().coords(), &plan).unwrap_err();
        assert_eq!(r.code, SHAPE_UNSUPPORTED);
        assert_eq!(refusal_reason(&r), "nothing_wired");
        assert!(
            r.detail.contains("reason: property_unresolved: "),
            "{}",
            r.detail
        );
        assert!(!r.detail.contains("maven_f_outside_root"), "{}", r.detail);
        assert!(!r.detail.contains("maven_mirror_of_all"), "{}", r.detail);
    }

    /// The same check passes a plan that pins the root or rewrites a
    /// declaration, and an already vendored reactor whose re-plan writes
    /// nothing.
    #[test]
    fn a_wired_plan_is_not_refused() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        let read = |p: &str| files.get(p).cloned();
        refuse_unwired(&read, &lister(&files), &patch().coords(), &plan).unwrap();
        let again = run(&after).unwrap();
        let read = |p: &str| after.get(p).cloned();
        refuse_unwired(&read, &lister(&after), &patch().coords(), &again).unwrap();
    }

    /// #513 case 2: Maven 4.1.0 infers an empty `<parent/>` from
    /// `../pom.xml`, so the root's property resolves and is rewritten.
    #[test]
    fn a_maven_4_inferred_parent_is_local() {
        let root = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
            <modelVersion>4.1.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
            <artifactId>root</artifactId>\n  <version>1.0.0</version>\n  \
            <packaging>pom</packaging>\n  <subprojects><subproject>a</subproject></subprojects>\n  \
            <properties><ct.version>1.10.0</ct.version></properties>\n</project>\n";
        let a = format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
             <modelVersion>4.1.0</modelVersion>\n  <parent/>\n  <artifactId>a</artifactId>\n  \
             <dependencies>\n    {}\n  </dependencies>\n</project>\n",
            dep("${ct.version}")
        );
        let files = fs(&[("pom.xml", root), ("a/pom.xml", &a)]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("${ct.version}", SV));
        assert!(root_pinned(&plan, &files));
    }

    /// A Maven 4 (model 4.1.0) aggregator root that lists no subprojects.
    const IMPLICIT_ROOT: &str = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\" \
        root=\"true\">\n  <modelVersion>4.1.0</modelVersion>\n  \
        <groupId>com.example</groupId>\n  <artifactId>root</artifactId>\n  \
        <version>1.0.0</version>\n  <packaging>pom</packaging>\n</project>\n";

    fn implicit_child(artifact: &str, packaging: &str, deps: &str) -> String {
        format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
             <modelVersion>4.1.0</modelVersion>\n  <parent/>\n  \
             <artifactId>{artifact}</artifactId>\n  <packaging>{packaging}</packaging>\n  \
             <dependencies>\n    {deps}\n  </dependencies>\n</project>\n"
        )
    }

    /// #622: Maven 4 builds every child directory holding a `pom.xml` of a
    /// 4.1.0 `pom`-packaged root that lists no `<subprojects>`, so those
    /// children are the reactor: the declaring module is rewritten to the
    /// suffixed version (immune to a warm `~/.m2`) and the root pinned,
    /// instead of a reactor of one that wires nothing the modules read.
    #[test]
    fn maven_4_implicit_subprojects_are_planned_as_the_reactor() {
        let a = implicit_child("a", "jar", &dep("1.10.0"));
        let b = implicit_child(
            "b",
            "jar",
            "<dependency><groupId>com.example</groupId><artifactId>a</artifactId>\
             <version>${project.version}</version></dependency>",
        );
        let files = fs(&[
            ("pom.xml", IMPLICIT_ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &b),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
        assert_eq!(text(&after, "b/pom.xml"), b);
        assert!(root_pinned(&plan, &files));
        let c = patch().coords();
        let read = |p: &str| after.get(p).cloned();
        assert!(wired_checked(&read, &lister(&after), &c).unwrap());
        assert!(attestable_checked(&read, &lister(&after), &c).unwrap());
        // `vendor` run from a discovered module is not the build root.
        assert!(contains_module(&read, &lister(&after), "a/pom.xml"));
    }

    fn reactor_of(files: &Fs) -> Vec<String> {
        let read = |p: &str| files.get(p).cloned();
        Reactor::discover(&read, &lister(files)).unwrap().reactor
    }

    /// #622: discovery as Maven 4.0.0-rc-7 does it (`DefaultModelBuilder`),
    /// checked against `mvn validate`'s reactor: every direct subdirectory
    /// holding a `pom.xml`, hidden ones included, recursively through a
    /// discovered `pom`-packaged child; not a deeper pom nor a directory
    /// without one.
    #[test]
    fn maven_4_subproject_discovery_follows_maven() {
        let files = fs(&[
            ("pom.xml", IMPLICIT_ROOT),
            ("a/pom.xml", &implicit_child("a", "pom", "")),
            ("a/sub/pom.xml", &implicit_child("sub", "jar", "")),
            ("b/pom.xml", &implicit_child("b", "jar", "")),
            ("b/nested/pom.xml", &implicit_child("nested", "jar", "")),
            (".h/pom.xml", &implicit_child("h", "jar", "")),
            ("nopom/c/pom.xml", &implicit_child("c", "jar", "")),
            ("src/main/java/A.java", "class A {}"),
        ]);
        assert_eq!(
            reactor_of(&files),
            [
                "pom.xml",
                ".h/pom.xml",
                "a/pom.xml",
                "b/pom.xml",
                "a/sub/pom.xml"
            ]
        );
    }

    /// #622: in a git checkout, discovery lists `.git/` like any directory.
    /// Probing it must not record a read error (the reader refuses every
    /// path through `.git`), or `vex` and `vendor --check` fail on it.
    #[tokio::test]
    async fn maven_4_subproject_discovery_in_a_git_checkout_stays_readable() {
        let a = implicit_child("a", "jar", &dep("1.10.0"));
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        super::super::testing::populate(
            root,
            &[
                ("pom.xml", IMPLICIT_ROOT),
                ("a/pom.xml", &a),
                (".git/HEAD", "ref: refs/heads/main\n"),
            ],
        );
        let mut ledger = BTreeMap::new();
        let plan = super::super::testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
            .await
            .unwrap();
        assert!(plan.writes.iter().any(|w| w.rel == "a/pom.xml"));
        let entry = ledger.values().next().unwrap();
        assert_eq!(
            super::super::apply::entry_wired_checked(root, entry),
            Ok(true)
        );
    }

    /// #622: a directory symlinked outside the checkout (a `target/` on
    /// another disk) is probed for a `pom.xml` without being reported. It
    /// holds none, so Maven ignores it and so does the plan; one that holds
    /// a pom is a subproject built from outside, reported as before.
    #[cfg(unix)]
    #[tokio::test]
    async fn maven_4_subproject_discovery_through_an_outbound_symlink() {
        let a = implicit_child("a", "jar", &dep("1.10.0"));
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        super::super::testing::populate(root, &[("pom.xml", IMPLICIT_ROOT), ("a/pom.xml", &a)]);
        let outside = tempfile::tempdir().unwrap();
        super::super::testing::populate(outside.path(), &[("classes/A.class", "x")]);
        std::os::unix::fs::symlink(outside.path(), root.join("target")).unwrap();
        let mut ledger = BTreeMap::new();
        // `testing::vendor` asserts nothing escaped.
        let planned =
            super::super::testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
                .await
                .unwrap();
        assert!(planned.writes.iter().any(|w| w.rel == "a/pom.xml"));
        let entry = ledger.values().next().unwrap();
        assert_eq!(
            super::super::apply::entry_wired_checked(root, entry),
            Ok(true)
        );

        let ext = tempfile::tempdir().unwrap();
        super::super::testing::populate(
            ext.path(),
            &[("pom.xml", &implicit_child("x", "jar", ""))],
        );
        std::os::unix::fs::symlink(ext.path(), root.join("ext")).unwrap();
        let reader = super::super::apply::ProjectReader::new(root);
        let _ = plan(
            &|rel: &str| reader.read(rel),
            &|d: &str| reader.list(d),
            &patch(),
        );
        assert_eq!(reader.escaped().as_deref(), Some("ext"));
    }

    /// #622: no discovery for a 4.0.0 model, a non-`pom` packaging, a root
    /// that lists its subprojects, or `maven.project.discoverSubprojects`
    /// set to anything but `true` (Java's `Boolean.parseBoolean`). The
    /// model version may come from the namespace alone, and an empty
    /// `<subprojects/>` lists nothing, so both still discover.
    #[test]
    fn maven_4_subproject_discovery_is_gated_like_maven() {
        let a = implicit_child("a", "jar", "");
        let b = implicit_child("b", "jar", "");
        let tree = |root: &str, extra: &[(&str, &str)]| {
            let mut files = fs(&[("pom.xml", root), ("a/pom.xml", &a), ("b/pom.xml", &b)]);
            files.extend(
                extra
                    .iter()
                    .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec())),
            );
            reactor_of(&files)
        };
        let all = ["pom.xml", "a/pom.xml", "b/pom.xml"];
        let model_4_0 = IMPLICIT_ROOT
            .replace("POM/4.1.0\" root=\"true\"", "POM/4.0.0\"")
            .replace("<modelVersion>4.1.0", "<modelVersion>4.0.0");
        assert_eq!(tree(&model_4_0, &[]), ["pom.xml"]);
        let jar = IMPLICIT_ROOT.replace("<packaging>pom", "<packaging>jar");
        assert_eq!(tree(&jar, &[]), ["pom.xml"]);
        let no_packaging = IMPLICIT_ROOT.replace("  <packaging>pom</packaging>\n", "");
        assert_eq!(tree(&no_packaging, &[]), ["pom.xml"]);
        let listed = IMPLICIT_ROOT.replace(
            "</packaging>",
            "</packaging>\n  <subprojects><subproject>a</subproject></subprojects>",
        );
        assert_eq!(tree(&listed, &[]), ["pom.xml", "a/pom.xml"]);
        let empty_list = IMPLICIT_ROOT.replace("</packaging>", "</packaging>\n  <subprojects/>");
        assert_eq!(tree(&empty_list, &[]), all);
        let namespace_only = IMPLICIT_ROOT.replace("  <modelVersion>4.1.0</modelVersion>\n", "");
        assert_eq!(tree(&namespace_only, &[]), all);
        for (value, discovers) in [
            ("true", true),
            ("TRUE", true),
            ("false", false),
            ("no", false),
        ] {
            let config = format!("-Dmaven.project.discoverSubprojects={value}\n");
            let got = tree(IMPLICIT_ROOT, &[(MAVEN_CONFIG, &config)]);
            let want: &[&str] = if discovers { &all } else { &["pom.xml"] };
            assert_eq!(got, want, "{value}");
        }
    }

    /// #459: a profile of the declaring module raising the property keeps
    /// the declaration and leaves the root unpinned.
    #[test]
    fn a_profile_overriding_the_version_property_is_left_alone() {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties><ct.version>1.10.0</ct.version></properties>\n  <modules>",
        );
        let a = with_profile(
            &module("a", &dep("${ct.version}")),
            "modern-jdk",
            "<ct.version>1.11.0</ct.version>",
        );
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["conflicting_literal_version"]);
        assert!(
            plan.warnings[0].detail.contains("profile modern-jdk"),
            "{:?}",
            plan.warnings
        );
        let after = applied(&files, &plan);
        assert_eq!(text(&after, "a/pom.xml"), a);
        assert!(!root_pinned(&plan, &files));
        assert!(unwired(&after));
    }

    /// #459: the same through the parent's profile, and through a profile
    /// overriding a property the version is built from.
    #[test]
    fn a_profile_up_the_chain_or_on_a_nested_property_is_weighed() {
        let a = module("a", &dep("${ct.version}"));
        for (props, profile) in [
            (
                "<ct.version>1.10.0</ct.version>",
                "<ct.version>1.11.0</ct.version>",
            ),
            (
                "<ct.minor>10</ct.minor><ct.version>1.${ct.minor}.0</ct.version>",
                "<ct.minor>11</ct.minor>",
            ),
            // A profile pointing the property at a name the checkout
            // does not define (Bugbot on #1787).
            (
                "<ct.version>1.10.0</ct.version>",
                "<ct.version>${corp.ct.version}</ct.version>",
            ),
        ] {
            let root = with_profile(
                &ROOT.replace(
                    "  <modules>",
                    &format!("  <properties>{props}</properties>\n  <modules>"),
                ),
                "corp",
                profile,
            );
            let files = fs(&[
                ("pom.xml", &root),
                ("a/pom.xml", &a),
                ("b/pom.xml", &module("b", "")),
            ]);
            let plan = run(&files).unwrap();
            assert_eq!(reasons(&plan), ["conflicting_literal_version"], "{props}");
            let after = applied(&files, &plan);
            assert_eq!(text(&after, "a/pom.xml"), a);
            assert!(unwired(&after), "{props}");
        }
    }

    /// Profiles that move the version only when active together (one
    /// points the property at another, the other redefines that one) are
    /// weighed like a single one: VEX discovery and this planner share the
    /// combinations (`formats::maven::profile_combinations`).
    #[test]
    fn profiles_that_move_the_version_only_together_are_weighed() {
        let root = with_profile(
            &ROOT.replace(
                "  <modules>",
                "  <properties><ct.version>1.10.0</ct.version><w>1.10.0</w></properties>\n  \
                 <modules>",
            ),
            "indirect",
            "<ct.version>${w}</ct.version>",
        );
        let a = with_profile(
            &module("a", &dep("${ct.version}")),
            "raise",
            "<w>1.11.0</w>",
        );
        let files = reactor(&root, &a);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["conflicting_literal_version"]);
        let detail = &plan.warnings[0].detail;
        assert!(
            detail.contains("profile indirect") && detail.contains("profile raise"),
            "{detail}"
        );
        let after = applied(&files, &plan);
        assert_eq!(text(&after, "a/pom.xml"), a);
    }

    /// #459: a module's profile overriding the property an inherited
    /// management declaration reads keeps that declaration.
    #[test]
    fn an_inheriting_modules_profile_keeps_the_managed_property() {
        let root = ROOT.replace(
            "  <build>",
            "  <properties><ct.version>1.10.0</ct.version></properties>\n  \
             <dependencyManagement>\n    <dependencies>\n      \
             <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
             <version>${ct.version}</version></dependency>\n    </dependencies>\n  \
             </dependencyManagement>\n  <build>",
        );
        let bare = "<dependency><groupId>org.apache.commons</groupId>\
                    <artifactId>commons-text</artifactId></dependency>";
        let a = with_profile(&module("a", bare), "new", "<ct.version>1.12.0</ct.version>");
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", bare)),
        ]);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["conflicting_literal_version"]);
        assert!(unwired(&applied(&files, &plan)));
    }

    /// `root` with `<properties>{props}</properties>` and a profile `corp`
    /// whose `<properties>` are `profile` (none when empty), before its
    /// `<modules>`.
    fn root_with(props: &str, profile: &str) -> String {
        let root = ROOT.replace(
            "  <modules>",
            &format!("  <properties>{props}</properties>\n  <modules>"),
        );
        match profile {
            "" => root,
            p => with_corp_profile(&root, p),
        }
    }

    /// `root` with a profile `corp` whose `<properties>` are `props`, before
    /// its `<modules>`: also how a profile is added to a vendored reactor
    /// later.
    fn with_corp_profile(root: &str, props: &str) -> String {
        root.replace(
            "  <modules>",
            &format!(
                "  <profiles><profile><id>corp</id><properties>{props}</properties>\
                 </profile></profiles>\n  <modules>"
            ),
        )
    }

    /// The `a` / `b` reactor under `root`, module `a`'s pom being `a` and
    /// `b` declaring nothing.
    fn reactor(root: &str, a: &str) -> Fs {
        fs(&[
            ("pom.xml", root),
            ("a/pom.xml", a),
            ("b/pom.xml", &module("b", "")),
        ])
    }

    /// A declaration whose `${...}` groupId a profile redefines names
    /// another artifact whenever that profile is active, which the literal
    /// SV must not reach: it is left as is and its root unpinned, as for
    /// an inheritor that resolves it differently. A `.mvn/maven.config`
    /// user property wins over the profile's.
    #[test]
    fn a_profile_moving_the_declared_coordinates_is_left_alone() {
        let decl = "<dependency><groupId>${ct.group}</groupId>\
                    <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>";
        let a = module("a", decl);
        let props = "<ct.group>org.apache.commons</ct.group>";
        for profile in [
            "<ct.group>org.other</ct.group>",
            "<ct.group>${nope}</ct.group>",
        ] {
            let files = reactor(&root_with(props, profile), &a);
            let plan = run(&files).unwrap();
            assert_eq!(reasons(&plan), ["coordinates_overridden"], "{profile}");
            assert!(
                plan.warnings[0].detail.contains("profile corp"),
                "{:?}",
                plan.warnings
            );
            let after = applied(&files, &plan);
            assert_eq!(text(&after, "a/pom.xml"), a);
            assert!(!root_pinned(&plan, &files));
            assert!(unwired(&after), "{profile}");
        }

        // A vendored reactor a profile is added to later is not attestable.
        let files = reactor(&root_with(props, ""), &a);
        let (_, mut after) = vendor(&files);
        assert_eq!(attestable(&after), (true, true));
        let root = with_corp_profile(&text(&after, "pom.xml"), "<ct.group>org.other</ct.group>");
        after.insert("pom.xml".to_string(), root.into_bytes());
        assert_eq!(attestable(&after), (true, false));

        // The same profile, beaten by a user property, or agreeing.
        for (profile, config) in [
            (
                "<ct.group>org.other</ct.group>",
                "-Dct.group=org.apache.commons\n",
            ),
            ("<ct.group>org.apache.commons</ct.group>", ""),
        ] {
            let files = fs(&[
                ("pom.xml", &root_with(props, profile)),
                ("a/pom.xml", &a),
                ("b/pom.xml", &module("b", "")),
                (".mvn/maven.config", config),
            ]);
            let (plan, after) = vendor(&files);
            assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
            assert_eq!(text(&after, "a/pom.xml"), a.replace("1.10.0", SV));
            assert_eq!(attestable(&after), (true, true), "{profile}");
        }
    }

    /// A declaration whose `${...}` groupId names another artifact with no
    /// profile active, but the patched one under a profile, declares the
    /// patched artifact at its own version there, beating the root pin:
    /// it is left as is, warned about, and its root unpinned, so a reactor
    /// vendored before that profile was added is not attestable. Unrelated
    /// coordinate properties change nothing.
    #[test]
    fn a_profile_turning_a_declaration_into_the_patched_artifact_is_weighed() {
        let other = |v: &str| {
            format!(
                "<dependency><groupId>${{lib.group}}</groupId>\
                 <artifactId>commons-text</artifactId>{v}</dependency>"
            )
        };
        let props = "<lib.group>org.other</lib.group>";
        let a = module(
            "a",
            &format!("{}{}", dep("1.10.0"), other("<version>1.9</version>")),
        );
        for (profile, warned) in [
            ("<lib.group>org.apache.commons</lib.group>", true),
            ("<lib.group>${nope}</lib.group>", true),
            ("<lib.group>org.third</lib.group>", false),
            ("<x>org.apache.commons</x>", false),
        ] {
            let files = reactor(&root_with(props, profile), &a);
            let plan = run(&files).unwrap();
            if warned {
                assert_eq!(reasons(&plan), ["coordinates_overridden"], "{profile}");
                assert!(
                    plan.warnings[0].detail.contains("profile corp")
                        && plan.warnings[0]
                            .detail
                            .contains("org.apache.commons:commons-text"),
                    "{:?}",
                    plan.warnings
                );
                assert!(!root_pinned(&plan, &files), "{profile}");
            } else {
                assert!(plan.warnings.is_empty(), "{profile}: {:?}", plan.warnings);
                assert!(root_pinned(&plan, &files), "{profile}");
            }
        }

        // A `${…}` type may be `jar`, as discovery reads it: weighed too.
        let typed = module(
            "a",
            &format!(
                "{}{}",
                dep("1.10.0"),
                other("<version>1.9</version><type>${t}</type>")
            ),
        );
        let to_commons = "<lib.group>org.apache.commons</lib.group>";
        let files = reactor(&root_with(props, to_commons), &typed);
        let plan = run(&files).unwrap();
        assert_eq!(
            reasons(&plan),
            ["coordinates_overridden"],
            "{:?}",
            plan.warnings
        );
        assert!(!root_pinned(&plan, &files));

        // No version of its own: the pin applies, so the root stays pinned.
        let files = reactor(
            &root_with(props, to_commons),
            &module("a", &format!("{}{}", dep("1.10.0"), other(""))),
        );
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["coordinates_overridden"]);
        assert!(root_pinned(&plan, &files));

        // Vendored first, the profile added later: not attestable; a user
        // property fixing the group keeps it attestable.
        let files = reactor(&root_with(props, ""), &a);
        let (_, after) = vendor(&files);
        assert_eq!(attestable(&after), (true, true));
        let profiled = with_corp_profile(&text(&after, "pom.xml"), to_commons);
        let mut later = after.clone();
        later.insert("pom.xml".to_string(), profiled.into_bytes());
        assert_eq!(attestable(&later), (true, false));
        later.insert(
            ".mvn/maven.config".to_string(),
            b"-Dlib.group=org.other\n".to_vec(),
        );
        assert_eq!(attestable(&later), (true, true));
    }

    /// Coordinates whose text can never read the patched g:a (`${g}:guava`)
    /// are not weighed, however many profiles redefine `g`: more than are
    /// combined would otherwise fail closed and unpin the root. The same text naming commons-text does fail closed.
    #[test]
    fn many_profiles_on_an_unrelated_coordinate_are_not_weighed() {
        let profiles: String = (0..=MAX_COMBINED_PROFILES)
            .map(|i| {
                format!("<profile><id>p{i}</id><properties><g>org.g{i}</g></properties></profile>")
            })
            .collect();
        let root = ROOT.replace(
            "  <modules>",
            &format!(
                "  <properties><g>com.google.guava</g></properties>\n  \
                 <profiles>{profiles}</profiles>\n  <modules>"
            ),
        );
        let named = |artifact: &str| {
            module(
                "a",
                &format!(
                    "{}<dependency><groupId>${{g}}</groupId><artifactId>{artifact}</artifactId>\
                     <version>1</version></dependency>",
                    dep("1.10.0")
                ),
            )
        };
        let files = reactor(&root, &named("guava"));
        let plan = run(&files).unwrap();
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert!(root_pinned(&plan, &files));

        let files = reactor(&root, &named("commons-text"));
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["coordinates_overridden"]);
        assert!(!root_pinned(&plan, &files));
    }

    /// A classifier copy a profile retargets onto the patched g:a is its
    /// own coordinate, which no pin reaches: warned about as
    /// `classifier_declared`, like a literal one, without unpinning the
    /// root.
    #[test]
    fn a_profile_retargeting_a_classifier_copy_warns() {
        let classified = "<dependency><groupId>${lib.group}</groupId>\
                    <artifactId>commons-text</artifactId><version>1.10.0</version>\
                    <classifier>tests</classifier></dependency>";
        // `test-jar` is the `tests` copy too.
        let test_jar = "<dependency><groupId>${lib.group}</groupId>\
                    <artifactId>commons-text</artifactId><version>1.10.0</version>\
                    <type>test-jar</type></dependency>";
        for copy in [classified, test_jar] {
            let files = reactor(
                &root_with(
                    "<lib.group>org.other</lib.group>",
                    "<lib.group>org.apache.commons</lib.group>",
                ),
                &module("a", &format!("{}{copy}", dep("1.10.0"))),
            );
            let plan = run(&files).unwrap();
            assert_eq!(reasons(&plan), ["classifier_declared"], "{copy}");
            assert!(
                plan.warnings[0].detail.contains("profile corp"),
                "{:?}",
                plan.warnings
            );
            assert!(root_pinned(&plan, &files));
        }
    }

    fn attestable(files: &Fs) -> (bool, bool) {
        let read = |p: &str| files.get(p).cloned();
        let c = Coords {
            group_id: "org.apache.commons",
            artifact_id: "commons-text",
            version: "1.10.0",
            uuid: UUID,
        };
        (
            wired_checked(&read, &lister(&files), &c).unwrap(),
            attestable_checked(&read, &lister(&files), &c).unwrap(),
        )
    }

    /// A sibling rewritten to SV wires the patch, but a module left at an
    /// uncertain `${...}` still builds the base: not attestable.
    #[test]
    fn an_uncertain_module_beside_a_rewritten_one_is_not_attestable() {
        let profiled = with_profile(
            &module("a", &dep("${ct.version}")),
            "new",
            "<ct.version>1.11.0</ct.version>",
        );
        let root = ROOT.replace(
            "  <modules>",
            "  <properties><ct.version>1.10.0</ct.version></properties>\n  <modules>",
        );
        for (root, a) in [
            (ROOT.to_string(), module("a", &dep("${remote.prop}"))),
            (root, profiled),
        ] {
            let files = fs(&[
                ("pom.xml", &root),
                ("a/pom.xml", &a),
                ("b/pom.xml", &module("b", &dep("1.10.0"))),
            ]);
            let (_, after) = vendor(&files);
            assert_eq!(text(&after, "b/pom.xml"), module("b", &dep(SV)));
            assert_eq!(attestable(&after), (true, false), "{a}");
        }
        // Without the uncertain module the same reactor attests.
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", &dep("1.10.0"))),
        ]);
        let (_, after) = vendor(&files);
        assert_eq!(attestable(&after), (true, true));
    }

    /// A `<classifier>` copy of the GA is its own coordinate: the
    /// classifier-less pin does not retarget it and the vendored tree does
    /// not serve it, so Maven fetches the public release. An executable
    /// one (tests, a native build) keeps the unpatched code on the
    /// classpath: not attestable, as in hosted mode and VEX discovery.
    /// `sources` / `javadoc` jars never run, so they only warn.
    #[test]
    fn an_executable_classifier_copy_is_not_attestable() {
        let classified = |classifier: &str, version: &str| {
            format!(
                "<dependency><groupId>org.apache.commons</groupId>\
                 <artifactId>commons-text</artifactId><version>{version}</version>\
                 <classifier>{classifier}</classifier></dependency>"
            )
        };
        for (classifier, version, attests) in [
            ("tests", "1.10.0", false),
            ("linux-x86_64", "1.10.0", false),
            // Not the base release, but still not the patched one.
            ("tests", "1.9", false),
            // Versioned by a profile's property: the base once it is active.
            ("tests", "${ct.tests}", false),
            ("sources", "1.10.0", true),
            ("javadoc", "1.10.0", true),
        ] {
            let b = if version.starts_with("${") {
                with_profile(
                    &module("b", &classified(classifier, version)),
                    "t",
                    "<ct.tests>1.10.0</ct.tests>",
                )
            } else {
                module("b", &classified(classifier, version))
            };
            let files = fs(&[
                ("pom.xml", ROOT),
                ("a/pom.xml", &module("a", &dep("1.10.0"))),
                ("b/pom.xml", &b),
            ]);
            let (plan, after) = vendor(&files);
            assert_eq!(reasons(&plan), ["classifier_declared"], "{classifier}");
            assert_eq!(text(&after, "a/pom.xml"), module("a", &dep(SV)));
            assert_eq!(
                attestable(&after),
                (true, attests),
                "{classifier} {version}"
            );
        }
        // A classifier copy added inside a profile after vendoring.
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, mut after) = vendor(&files);
        assert_eq!(attestable(&after), (true, true));
        let b = module("b", "").replace(
            "  <dependencies>",
            &format!(
                "  <profiles><profile><id>it</id><dependencies>{}</dependencies></profile>\
                 </profiles>\n  <dependencies>",
                classified("tests", "1.10.0")
            ),
        );
        after.insert("b/pom.xml".into(), b.into_bytes());
        assert_eq!(attestable(&after), (true, false));
    }

    /// Only a declaration Maven always reads wires the patch: a
    /// `<dependencies>` / `<dependencyManagement>` entry of the GA's main
    /// jar outside `<profiles>` whose version resolves to the suffixed
    /// one. The suffixed version left in a build plugin's dependencies, a
    /// profile, an unused property or another artifact's declaration
    /// builds the base for the project's own classpath.
    #[test]
    fn a_suffixed_version_outside_the_declarations_is_not_wired() {
        let plugin = format!(
            "<build><plugins><plugin><groupId>p</groupId><artifactId>p</artifactId>\
             <dependencies>{}</dependencies></plugin></plugins></build>",
            dep(SV)
        );
        let profile = format!(
            "<profiles><profile><id>p</id><dependencies>{}</dependencies></profile></profiles>",
            dep(SV)
        );
        let property = format!("<properties><ct.version>{SV}</ct.version></properties>");
        let other = dep(SV).replace("commons-text", "commons-lang3");
        let classifier =
            dep(SV).replace("</version>", "</version><classifier>sources</classifier>");
        for extra in [plugin, profile, property, other.clone(), classifier.clone()] {
            let a = if extra.starts_with("<dependency>") {
                module("a", &extra)
            } else {
                module("a", "").replace("  <dependencies>", &format!("  {extra}\n  <dependencies>"))
            };
            let files = fs(&[
                ("pom.xml", ROOT),
                ("a/pom.xml", &a),
                ("b/pom.xml", &module("b", "")),
            ]);
            assert_eq!(attestable(&files), (false, false), "{extra}");
        }
        // A property the declaration reads, and the root's managed pin, do.
        let via_property = module("a", &dep("${ct.version}")).replace(
            "  <dependencies>",
            &format!("  <properties><ct.version>{SV}</ct.version></properties>\n  <dependencies>"),
        );
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &via_property),
            ("b/pom.xml", &module("b", "")),
        ]);
        assert_eq!(attestable(&files), (true, true));
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        assert!(text(&after, "pom.xml").contains(SV));
        assert_eq!(attestable(&after), (true, true));
    }

    /// A classifier copy whose `${...}` version reads the pin where it is
    /// declared still builds the base where an inheriting pom, or a
    /// profile, moves the property back: the same override check as the
    /// main jar's declarations.
    #[test]
    fn a_classifier_copy_a_reader_moves_back_to_the_base_is_not_attestable() {
        let copy = "<dependencies><dependency><groupId>org.apache.commons</groupId>\
                    <artifactId>commons-text</artifactId><version>${ct.tests}</version>\
                    <classifier>tests</classifier></dependency></dependencies>\n  <build>";
        let root = ROOT
            .replace(
                "  <modules>",
                &format!("  <properties><ct.tests>{SV}</ct.tests></properties>\n  <modules>"),
            )
            .replace("  <build>", &format!("  {copy}"));
        let base = "<ct.tests>1.10.0</ct.tests>";
        let b_moves = module("b", "").replace(
            "  <dependencies>",
            &format!("  <properties>{base}</properties>\n  <dependencies>"),
        );
        for (what, root, b, attests) in [
            (
                "every reader reads the pin",
                root.clone(),
                module("b", ""),
                true,
            ),
            ("an inheritor moves it", root.clone(), b_moves, false),
            (
                "a profile moves it",
                with_profile(&root, "base", base),
                module("b", ""),
                false,
            ),
        ] {
            let files = fs(&[
                ("pom.xml", &root),
                ("a/pom.xml", &module("a", &dep("1.10.0"))),
                ("b/pom.xml", &b),
            ]);
            let (_, after) = vendor(&files);
            assert_eq!(attestable(&after), (true, attests), "{what}");
        }
    }

    /// Two local roots (remote parents): one pinned, the other left
    /// unpinned because its parent's management cannot be read. The
    /// pinned root wires the patch, but a version-less declaration under
    /// the unpinned one resolves whatever that parent manages, maybe the
    /// base: not attestable.
    #[test]
    fn a_version_less_declaration_under_an_unpinned_root_is_not_attestable() {
        let agg = "<project>\n  <groupId>t</groupId>\n  <artifactId>agg</artifactId>\n  \
                   <version>1</version>\n  <packaging>pom</packaging>\n  <modules>\n    \
                   <module>a</module>\n    <module>b</module>\n  </modules>\n</project>\n";
        let child = |name: &str| {
            format!(
                "<project>\n  <parent>\n    <groupId>com.corp</groupId>\n    \
                 <artifactId>parent-{name}</artifactId>\n    <version>1</version>\n    \
                 <relativePath/>\n  </parent>\n  <groupId>t</groupId>\n  \
                 <artifactId>{name}</artifactId>\n  <dependencies>\n    \
                 <dependency><groupId>org.apache.commons</groupId>\
                 <artifactId>commons-text</artifactId></dependency>\n  </dependencies>\n\
                 </project>\n"
            )
        };
        let files = fs(&[
            ("pom.xml", agg),
            ("a/pom.xml", &child("a")),
            ("b/pom.xml", &child("b")),
        ]);
        let parent = |name: &str| {
            let a = format!("parent-{name}");
            (corp(&a, "1"), Some(bom(&a, "1", "")))
        };
        // parent-b is unavailable: b is left unpinned.
        let plan = run_external(&files, &ExternalPoms::from([parent("a")]))
            .0
            .unwrap();
        assert_eq!(reasons(&plan), ["management_unresolved"]);
        let after = applied(&files, &plan);
        assert!(text(&after, "a/pom.xml").contains(PIN_TAG));
        assert!(!text(&after, "b/pom.xml").contains(PIN_TAG));
        assert_eq!(attestable(&after), (true, false));
        // Both parents readable: both roots pinned, and it attests.
        let plan = run_external(&files, &ExternalPoms::from([parent("a"), parent("b")]))
            .0
            .unwrap();
        assert!(reasons(&plan).is_empty(), "{:?}", plan.warnings);
        assert_eq!(attestable(&applied(&files, &plan)), (true, true));
    }

    /// A version-less declaration reads its management, and an active
    /// profile overrides that: a profile that redefines the managed
    /// property, or manages g:a itself at another version, can put the
    /// base back on the classpath, so neither attests.
    #[test]
    fn a_version_less_declaration_a_profile_moves_is_not_attestable() {
        let pom = "<project>\n  <groupId>t</groupId>\n  <artifactId>app</artifactId>\n  \
                   <version>1</version>\n  <properties>\n    \
                   <ct.version>1.10.0</ct.version>\n  </properties>\n  \
                   <dependencyManagement>\n    <dependencies>\n      \
                   <dependency><groupId>org.apache.commons</groupId>\
                   <artifactId>commons-text</artifactId>\
                   <version>${ct.version}</version></dependency>\n    \
                   </dependencies>\n  </dependencyManagement>\n  <dependencies>\n    \
                   <dependency><groupId>org.apache.commons</groupId>\
                   <artifactId>commons-text</artifactId></dependency>\n  \
                   </dependencies>\n</project>\n";
        let (_, after) = vendor(&fs(&[("pom.xml", pom)]));
        assert_eq!(attestable(&after), (true, true));
        // The same pin through a property the base pom defines as SV.
        let mut by_property = after.clone();
        let t = text(&after, "pom.xml")
            .replace(
                &format!("<version>{SV}</version>"),
                "<version>${ct.version}</version>",
            )
            .replace(
                "<ct.version>1.10.0</ct.version>",
                &format!("<ct.version>{SV}</ct.version>"),
            );
        by_property.insert("pom.xml".to_string(), t.into_bytes());
        assert_eq!(attestable(&by_property), (true, true));
        let with = |base: &Fs, profile: &str| {
            let mut files = base.clone();
            let t = text(base, "pom.xml").replace(
                "</project>",
                &format!("  <profiles>\n    <profile>\n      <id>old</id>\n      {profile}\n    </profile>\n  </profiles>\n</project>"),
            );
            files.insert("pom.xml".to_string(), t.into_bytes());
            files
        };
        let property = with(
            &by_property,
            "<properties><ct.version>1.10.0</ct.version></properties>",
        );
        assert!(!attestable(&property).1);
        let managed = with(
            &after,
            "<dependencyManagement><dependencies><dependency>\
             <groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
             <version>1.10.0</version></dependency></dependencies></dependencyManagement>",
        );
        assert!(!attestable(&managed).1);
    }

    /// Maven interpolates after inheritance: a parent's managed
    /// `${ct.version}` that every module defines as the suffixed version
    /// wires the patch, so the plan is not refused as wiring nothing.
    #[test]
    fn a_parent_declaration_its_modules_resolve_to_the_pin_is_wired() {
        let managed = "<dependencyManagement><dependencies><dependency>\
                       <groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
                       <version>${ct.version}</version></dependency></dependencies>\
                       </dependencyManagement>\n  <build>";
        let root = ROOT.replace("  <build>", &format!("  {managed}"));
        let child = |name: &str| {
            module(
                name,
                "<dependency><groupId>org.apache.commons</groupId>\
                 <artifactId>commons-text</artifactId></dependency>",
            )
            .replace(
                "  <dependencies>",
                &format!(
                    "  <properties><ct.version>{SV}</ct.version></properties>\n  <dependencies>"
                ),
            )
        };
        let files = fs(&[
            ("pom.xml", &root),
            ("a/pom.xml", &child("a")),
            ("b/pom.xml", &child("b")),
        ]);
        let read = |p: &str| files.get(p).cloned();
        assert!(wired_checked(&read, &lister(&files), &patch().coords()).unwrap());
        let plan = run(&files).unwrap();
        refuse_unwired(&read, &lister(&files), &patch().coords(), &plan).unwrap();
    }

    /// `vendor --check` agrees with `vex`: an intact, wired entry that a
    /// declaration added since may keep building the base is verified
    /// (re-vendoring cannot clear an executable copy) with the reason
    /// `vex` does not attest it.
    #[tokio::test]
    async fn vendor_check_reports_an_unattestable_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        super::super::testing::populate(
            root,
            &[
                ("pom.xml", ROOT),
                ("a/pom.xml", &module("a", &dep("1.10.0"))),
                ("b/pom.xml", &module("b", "")),
            ],
        );
        let mut ledger = BTreeMap::new();
        super::super::testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
            .await
            .unwrap();
        let entry = ledger.values().next().unwrap();
        let check = || super::super::apply::check_entry(root, entry, None);
        assert_eq!(check(), Ok(None));
        let copy = "<dependency><groupId>org.apache.commons</groupId>\
                    <artifactId>commons-text</artifactId><version>1.10.0</version>\
                    <type>test-jar</type></dependency>";
        std::fs::write(root.join("b/pom.xml"), module("b", copy)).unwrap();
        let why = check().unwrap().expect("not attestable");
        assert!(why.starts_with("b/pom.xml:"), "{why}");
        assert_eq!(
            super::super::apply::entry_wired_checked(root, entry),
            Ok(false)
        );
    }

    /// #584: a module added after vendoring, or a dependency added to an
    /// existing one, that declares the base literally beats the root's
    /// pin and builds the unpatched jar: not attestable until re-vendored.
    #[test]
    fn a_base_declaration_added_after_vendoring_is_not_attestable() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        assert_eq!(attestable(&after), (true, true));

        let mut added_module = after.clone();
        added_module.insert(
            "pom.xml".into(),
            text(&after, "pom.xml")
                .replace(
                    "<module>b</module>",
                    "<module>b</module>\n    <module>c</module>",
                )
                .into_bytes(),
        );
        added_module.insert("c/pom.xml".into(), module("c", &dep("1.10.0")).into_bytes());
        let mut added_dep = after.clone();
        added_dep.insert("b/pom.xml".into(), module("b", &dep("1.10.0")).into_bytes());
        // A module still on an earlier patch's suffix builds that patch's
        // jar, not this one.
        let mut earlier_patch = after.clone();
        earlier_patch.insert(
            "b/pom.xml".into(),
            module("b", &dep("1.10.0-socket.deadbeef")).into_bytes(),
        );
        for drifted in [added_module, added_dep, earlier_patch] {
            assert_eq!(attestable(&drifted), (true, false));
            // Re-vendoring rewrites it and the reactor attests again.
            let (_, again) = vendor(&drifted);
            assert_eq!(attestable(&again), (true, true));
        }
    }

    /// #513: a possibly-matching declaration named through an undefined
    /// `${...}` groupId with its own version beats any pin.
    #[test]
    fn an_unresolved_coordinate_with_a_version_leaves_the_root_unpinned() {
        let a = module(
            "a",
            "<dependency><groupId>${ext.group}</groupId>\
             <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>",
        );
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["property_unresolved"]);
        assert!(!root_pinned(&plan, &files));
        assert!(unwired(&applied(&files, &plan)));
    }

    /// Maven 4 children also inherit the inferred parent's version, and a
    /// model 4.0.0 pom does not infer a parent.
    #[test]
    fn maven_4_parent_inference_is_4_1_only_and_carries_the_version() {
        let root = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
            <modelVersion>4.1.0</modelVersion>\n  <groupId>org.apache.commons</groupId>\n  \
            <artifactId>root</artifactId>\n  <version>1.10.0</version>\n  \
            <packaging>pom</packaging>\n  <subprojects><subproject>a</subproject></subprojects>\n\
            </project>\n";
        let a41 = format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
             <modelVersion>4.1.0</modelVersion>\n  <parent/>\n  <artifactId>a</artifactId>\n  \
             <dependencies>\n    {}\n  </dependencies>\n</project>\n",
            dep("${project.version}")
        );
        let files = fs(&[("pom.xml", root), ("a/pom.xml", &a41)]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(
            text(&after, "a/pom.xml"),
            a41.replace("${project.version}", SV)
        );
        let a40 = a41
            .replace("POM/4.1.0", "POM/4.0.0")
            .replace(">4.1.0<", ">4.0.0<");
        let files = fs(&[("pom.xml", root), ("a/pom.xml", &a40)]);
        let plan = run(&files).unwrap();
        assert_eq!(reasons(&plan), ["property_unresolved"]);
    }

    /// A profile that sets the base version (or a user property that wins
    /// over every profile) changes nothing.
    #[test]
    fn a_profile_agreeing_with_the_base_or_beaten_by_maven_config_is_rewritten() {
        let root = ROOT.replace(
            "  <modules>",
            "  <properties><ct.version>1.10.0</ct.version></properties>\n  <modules>",
        );
        let agreeing = with_profile(
            &module("a", &dep("${ct.version}")),
            "same",
            "<ct.version>1.10.0</ct.version>",
        );
        let raising = with_profile(
            &module("a", &dep("${ct.version}")),
            "new",
            "<ct.version>1.11.0</ct.version>",
        );
        for (a, config) in [(&agreeing, None), (&raising, Some("-Dct.version=1.10.0\n"))] {
            let mut files = fs(&[
                ("pom.xml", &root),
                ("a/pom.xml", a),
                ("b/pom.xml", &module("b", "")),
            ]);
            if let Some(config) = config {
                files.insert(".mvn/maven.config".into(), config.as_bytes().to_vec());
            }
            let (plan, after) = vendor(&files);
            assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
            assert_eq!(text(&after, "a/pom.xml"), a.replace("${ct.version}", SV));
        }
    }

    #[test]
    fn plugin_configuration_modules_do_not_make_a_reactor() {
        let ear = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
            <artifactId>app</artifactId><version>1</version><packaging>ear</packaging>\
            <build><plugins><plugin><artifactId>maven-ear-plugin</artifactId><configuration>\
            <modules><jarModule><groupId>x</groupId><artifactId>y</artifactId></jarModule></modules>\
            </configuration></plugin></plugins></build></project>";
        assert!(!declares_modules(ear));
        let read = |p: &str| (p == "pom.xml").then(|| ear.as_bytes().to_vec());
        let builds = super::super::detect_builds(&read, &super::super::no_list);
        assert_eq!(builds.maven, Some(super::super::MavenShape::Single));
        // A single pom is a reactor of one (#973).
        assert_eq!(builds.shape(), Shape::MavenReactor);
    }

    #[test]
    fn maven_config_extends_the_last_tail_and_protocol_lines() {
        let out = config("-Dmaven.repo.local.tail=/a\n-Daether.offline.protocols=http\n-Dmaven.repo.local.tail=/b\n-Daether.offline.protocols=https\n");
        assert_eq!(
            out,
            format!(
                "-Dmaven.repo.local.tail=/a\n-Daether.offline.protocols=http\n\
                 -Dmaven.repo.local.tail=/b,{TAIL_DIR}\n-Daether.offline.protocols=https,file\n"
            )
        );
        let (_, op) = merge_maven_config(Some(out.as_bytes()));
        assert_eq!(op_of_value(&op), "adopt");
    }

    #[test]
    fn maven_config_undo_restores_every_shape() {
        for before in [
            None,
            Some(""),
            Some("-T4"),
            Some("-T4\r\n"),
            Some("  -Dmaven.repo.local.tail=/a  \n-ntp\n"),
            Some("-Daether.offline.protocols=http\n-Dmaven.repo.local.tail=\n"),
        ] {
            let (after, op) = merge_maven_config(before.map(str::as_bytes));
            let w = fragment(
                MAVEN_CONFIG,
                CONFIG_LINE_KIND,
                "config",
                WiringAction::Added,
                None,
                op,
            );
            let undone = undo_config(&String::from_utf8(after).unwrap(), &w);
            assert_eq!(undone.as_deref(), before, "{before:?}");
        }
    }

    #[test]
    fn unsafe_coordinates_are_refused_before_any_xml_is_written() {
        for (g, a, v) in [
            ("com.ex&ample", "a", "1"),
            ("g", "a<b", "1"),
            ("g", "a", "1.0--x"),
        ] {
            let files = fs(&[("pom.xml", ROOT)]);
            let read = |rel: &str| files.get(rel).cloned();
            let p = JvmPatch {
                group_id: g,
                artifact_id: a,
                version: v,
                ..patch()
            };
            assert_eq!(
                plan(&read, &lister(&files), &p).unwrap_err().code,
                "unsafe_coordinates",
                "{g}:{a}:{v}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_module_symlinked_outside_the_checkout_is_reported() {
        let dir = disk(&[("pom.xml", ROOT), ("b/pom.xml", &module("b", ""))]);
        let outside = disk(&[("pom.xml", &module("a", &dep("1.10.0")))]);
        std::os::unix::fs::symlink(outside.path(), dir.path().join("a")).unwrap();
        let reader = super::super::apply::ProjectReader::new(dir.path());
        let _ = plan(
            &|rel: &str| reader.read(rel),
            &|d: &str| reader.list(d),
            &patch(),
        );
        assert_eq!(reader.escaped().as_deref(), Some("a"));
    }

    #[test]
    fn committed_tree_round_trips_to_an_unchanged_plan() {
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", &dep("1.10.0"))),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (_, after) = vendor(&files);
        let read = |rel: &str| after.get(rel).cloned();
        let (jar, pom) = committed(&read, &patch().coords()).unwrap();
        let p = JvmPatch {
            jar: &jar,
            upstream_pom: &pom,
            ..patch()
        };
        assert!(plan(&read, &lister(&after), &p).unwrap().writes.is_empty());
        // A parent-inherited upstream version (inserted by the suffixing).
        let parent_only = "<project>\n  <parent>\n    <groupId>org.apache.commons</groupId>\n    \
            <artifactId>commons-parent</artifactId>\n    <version>1.10.0</version>\n  </parent>\n  \
            <artifactId>commons-text</artifactId>\n</project>\n";
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &module("a", "")),
            ("b/pom.xml", &module("b", "")),
        ]);
        let first = plan(
            &|rel: &str| files.get(rel).cloned(),
            &lister(&files),
            &patch_with(parent_only),
        )
        .unwrap();
        let after = applied(&files, &first);
        let read = |rel: &str| after.get(rel).cloned();
        let (jar, pom) = committed(&read, &patch().coords()).unwrap();
        let p = JvmPatch {
            jar: &jar,
            upstream_pom: &pom,
            ..patch()
        };
        assert!(plan(&read, &lister(&after), &p).unwrap().writes.is_empty());
        assert!(committed(&|_: &str| None, &patch().coords()).is_none());
    }

    #[test]
    fn other_patch_references_are_recognised() {
        let c = patch().coords();
        let refs = |t: &str| references_other_patch(t, &mask(t).0, &c);
        assert!(!refs(&format!("<version>{SV}</version>{BEGIN_MARKER}")));
        assert!(refs("<version>2.0-socket.abcdef01</version>"));
        assert!(!refs("<!-- was 2.0-socket.abcdef01 -->"));
        assert!(refs(&format!("{PIN_TAG}{UUID_B}: g:a:1 -->")));
        assert!(!refs(&format!("{PIN_TAG}{UUID}: g:a:1 -->")));
        assert!(!refs("<version>1-socket.xyz</version>"));
    }

    /// A comment naming the suffixed version is not a reference: revert
    /// completes and deletes the tree.
    #[tokio::test]
    async fn a_comment_naming_the_suffixed_version_does_not_keep_the_tree() {
        let dir = disk(&[
            ("pom.xml", ROOT),
            (
                "a/pom.xml",
                &module(
                    "a",
                    &format!("<!-- pinned to {SV} by socket -->{}", dep("1.10.0")),
                ),
            ),
            ("b/pom.xml", &module("b", "")),
        ]);
        let root = dir.path();
        let pristine = testing::snapshot(root);
        let mut ledger = BTreeMap::new();
        testing::vendor(root, Shape::MavenReactor, &patch(), &mut ledger)
            .await
            .unwrap();
        let out = testing::revert(root, &patch(), &mut ledger).await;
        assert!(
            out.success && out.warnings.is_empty() && !out.kept_artifact,
            "{out:?}"
        );
        assert_eq!(testing::snapshot(root), pristine);
    }
}
