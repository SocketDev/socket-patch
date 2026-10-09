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

use super::super::state::{WiringAction, WiringRecord};
use super::layout::{self, safe_coordinates};
use super::{
    adopt, changes_between, finish_writes, fragment, op_of, op_str, owned_file, replace_op,
    sha1_hex, sha256_hex, undo_replace, Coords, FileWrite, JvmPatch, JvmPlan, JvmRefusal,
    JvmUnplan, JvmWarning, ReadFn, CONFIG_LINE_KIND, OWNED_FILE_KIND, POM_FRAGMENT_KIND,
    TREE_GITATTRIBUTES,
};

/// The committed maven2 tree.
use super::layout::MAVEN2_TREE as TREE_ROOT;
pub const MAVEN_CONFIG: &str = ".mvn/maven.config";
/// The tree root's `.gitattributes`, shared by every Maven patch.
pub const GITATTRIBUTES_REL: &str = ".socket/vendor/maven2/.gitattributes";
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
/// Property interpolation depth cap (Maven itself fails on cycles).
const MAX_INTERPOLATION_DEPTH: usize = 16;

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

/// The tree directory of `c`'s suffixed version.
pub fn tree_dir(c: &Coords<'_>) -> String {
    c.tree_dir(TREE_ROOT, &c.suffixed_version())
}

/// The committed tree of `c`, as the [`JvmPatch`] bytes that re-plan it
/// unchanged: `(jar, upstream pom)`, the pom un-suffixed. `None` when a
/// file is missing or the pom does not carry the suffixed version.
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<(Vec<u8>, Vec<u8>)> {
    let sv = c.suffixed_version();
    let dir = tree_dir(c);
    let a = c.artifact_id;
    let jar = read(&format!("{dir}/{a}-{sv}.jar"))?;
    let pom = String::from_utf8(read(&format!("{dir}/{a}-{sv}.pom"))?).ok()?;
    let children = scan_pom_project(&pom)?;
    let version = scan_find(&children, "version")?;
    if pom[version.inner_start..version.inner_end].trim() != sv {
        return None;
    }
    let upstream = format!(
        "{}{}{}",
        &pom[..version.inner_start],
        c.version,
        &pom[version.inner_end..]
    );
    Some((jar, upstream.into_bytes()))
}

/// Plan vendoring `patch` into the reactor rooted at `pom.xml`.
pub fn plan(read: ReadFn<'_>, patch: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
    plan_with_config(read, patch, true)
}

/// Plan with an explicit Maven config policy. A disabled policy is recorded for re-runs.
pub fn plan_with_config(
    read: ReadFn<'_>,
    patch: &JvmPatch<'_>,
    config_enabled: bool,
) -> Result<JvmPlan, JvmRefusal> {
    plan_with_external(read, patch, config_enabled, None)
}

/// [`plan_with_config`] that also weighs the management a local root's pin
/// would override from outside the checkout: imported BOMs and parents
/// resolved from a repository (#488). `external` holds those poms as the
/// caller could fetch them ([`external_poms_needed`] says which); `None`
/// skips the check (callers that plan only to probe a shape).
pub fn plan_with_external(
    read: ReadFn<'_>,
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
    let suffixed_pom = std::str::from_utf8(patch.upstream_pom)
        .ok()
        .and_then(|pom| suffix_maven_pom(pom, patch.version, &sv))
        .ok_or_else(|| JvmRefusal {
            code: UPSTREAM_UNAVAILABLE,
            detail: format!(
                "reason: suffix_unavailable: the upstream pom of {g}:{a}:{v} computes its own \
                 version, so it cannot be served as {sv}"
            ),
        })?;

    let reactor = Reactor::discover(read)?;
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
pub fn unplan(read: ReadFn<'_>, c: &Coords<'_>, records: &[WiringRecord]) -> JvmUnplan {
    let sv = c.suffixed_version();
    let mut files: BTreeSet<String> = records
        .iter()
        .filter(|w| w.kind == POM_FRAGMENT_KIND)
        .map(|w| w.file.clone())
        .collect();
    if let Ok(reactor) = Reactor::discover(read) {
        files.extend(reactor.scope);
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
        *t = restore_versions(rel, t, c, &sv, &recs, &mut drifted);
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
        let created = records.iter().any(|w| {
            w.kind == OWNED_FILE_KIND && w.file == GITATTRIBUTES_REL && op_of(w) == "create"
        });
        if created && read(GITATTRIBUTES_REL).as_deref() == Some(TREE_GITATTRIBUTES.as_bytes()) {
            before.insert(
                GITATTRIBUTES_REL.to_string(),
                Some(TREE_GITATTRIBUTES.to_string()),
            );
            after.insert(GITATTRIBUTES_REL.to_string(), None);
        }
    }
    JvmUnplan {
        changes: changes_between(&before, &after),
        drifted,
        still_wired,
    }
}

/// Whether a pom of the reactor still declares `c`'s suffixed version
/// (outside comments): the liveness proof `vex` needs for this layout.
pub fn wired(read: ReadFn<'_>, c: &Coords<'_>) -> bool {
    wired_checked(read, c).unwrap_or(false)
}

pub fn wired_checked(read: ReadFn<'_>, c: &Coords<'_>) -> Result<bool, JvmRefusal> {
    let sv = c.suffixed_version();
    Reactor::discover(read).map(|reactor| {
        reactor
            .scope
            .iter()
            .any(|rel| reactor.poms[rel].doc.masked.contains(&sv))
    })
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
/// (else the base version).
fn restore_versions(
    rel: &str,
    text: &str,
    c: &Coords<'_>,
    sv: &str,
    recs: &[&WiringRecord],
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
    let mut edits = Vec::new();
    for (dep, key) in doc.keyed_declarations(c.group_id, c.artifact_id) {
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
pub fn contains_module(read: ReadFn<'_>, rel: &str) -> bool {
    Reactor::discover(read).is_ok_and(|r| r.reactor.iter().any(|p| p == rel))
}

pub(crate) type Gav = (String, String, String);

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
    patch: &JvmPatch<'_>,
    known: &ExternalPoms,
) -> Vec<Gav> {
    let Ok(reactor) = Reactor::discover(read) else {
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

/// `${name}` interpolation through `lookup`; `None` when a name is
/// undefined or the nesting is too deep.
fn interpolate_by(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    depth: usize,
) -> Option<String> {
    if depth > MAX_INTERPOLATION_DEPTH {
        return None;
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let close = after.find('}')?;
        let raw = lookup(&after[..close])?;
        out.push_str(&interpolate_by(&raw, lookup, depth + 1)?);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Some(out)
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
                doc.keyed_declarations(g, a)
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
                interpolate_by(value, &props, 0).ok_or_else(|| {
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
            let local =
                |v: &Option<String>| v.as_deref().and_then(|v| self.interpolate(root, v, 0));
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
        Lookup::Unavailable => Err(Missing::Need(
            gav.clone(),
            format!("{named} is in no local Maven repository"),
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
            && doc
                .child_text(dep, "classifier")
                .is_none_or(|c| c.is_empty())
            && doc
                .child_text(dep, "type")
                .is_none_or(|t| t.is_empty() || t == "jar")
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
        interpolate_by(value, &props, 0).ok_or_else(|| {
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
}

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
        let mut props = BTreeMap::new();
        if let Some(p) = doc.child(project, "properties") {
            for &c in &doc.nodes[p].children {
                props.insert(doc.nodes[c].name.clone(), doc.text_of(c));
            }
        }
        Ok(Pom {
            dir: rel.rsplit_once('/').map_or("", |(d, _)| d).to_string(),
            group: doc.child_text(project, "groupId"),
            artifact: doc.child_text(project, "artifactId"),
            version: doc.child_text(project, "version"),
            packaging: doc
                .child_text(project, "packaging")
                .unwrap_or_else(|| "jar".to_string()),
            parent,
            props,
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
    /// `-Dk=v` user properties from `.mvn/maven.config`.
    cli_props: BTreeMap<String, String>,
}

impl Reactor {
    fn discover(read: ReadFn<'_>) -> Result<Reactor, JvmRefusal> {
        let root = read("pom.xml")
            .ok_or_else(|| shape_refusal("no_build_file", "no pom.xml at the project root"))?;
        let mut poms = BTreeMap::new();
        poms.insert("pom.xml".to_string(), Pom::parse("pom.xml", root)?);
        let mut reactor = vec!["pom.xml".to_string()];
        let mut next = 0;
        while next < reactor.len() {
            let rel = reactor[next].clone();
            next += 1;
            for module in module_refs(&poms[&rel].doc) {
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

        let cli_props = read(MAVEN_CONFIG)
            .map(|bytes| cli_properties(&String::from_utf8_lossy(&bytes)))
            .unwrap_or_default();
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

    /// Interpolate every `${name}` in `value` in the context of `rel`;
    /// `None` when any name is undefined in the checkout.
    fn interpolate(&self, rel: &str, value: &str, depth: usize) -> Option<String> {
        if depth > MAX_INTERPOLATION_DEPTH {
            return None;
        }
        let mut out = String::new();
        let mut rest = value;
        while let Some(at) = rest.find("${") {
            out.push_str(&rest[..at]);
            let after = &rest[at + 2..];
            let close = after.find('}')?;
            let raw = self.lookup(rel, &after[..close])?;
            out.push_str(&self.interpolate(rel, &raw, depth + 1)?);
            rest = &after[close + 1..];
        }
        out.push_str(rest);
        Some(out)
    }

    /// User properties win over model properties, as in Maven; then the
    /// model's own version expressions, then `<properties>` up the local
    /// chain.
    fn lookup(&self, rel: &str, name: &str) -> Option<String> {
        let pom = &self.poms[rel];
        match name {
            "project.version" | "pom.version" => {
                return pom.effective_version().map(str::to_string);
            }
            "project.parent.version" => return pom.parent.as_ref()?.version.clone(),
            _ => {}
        }
        if let Some(v) = self.cli_props.get(name) {
            return Some(v.clone());
        }
        if let Some(v) = self.chain(rel).find_map(|p| self.poms[p].props.get(name)) {
            return Some(v.clone());
        }
        (name == "version")
            .then(|| pom.effective_version().map(str::to_string))
            .flatten()
    }

    /// Every pom in scope that inherits from `rel` (has it on its chain).
    fn inheritors<'s>(&'s self, rel: &'s str) -> impl Iterator<Item = &'s str> + 's {
        self.scope
            .iter()
            .map(String::as_str)
            .filter(move |p| *p != rel && self.chain(p).any(|a| a == rel))
    }

    /// Rewrite the base declarations of `rel` and record the
    /// warnings, the local roots not to pin, and the local roots whose own
    /// top-level management already covers g:a.
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
    ) {
        let doc = &self.poms[rel].doc;
        let ga = format!("{}:{}", patch.group_id, patch.artifact_id);
        for (dep, key) in doc.keyed_declarations(patch.group_id, patch.artifact_id) {
            if doc
                .child_text(dep, "type")
                .is_some_and(|t| !t.is_empty() && t != "jar")
            {
                continue;
            }
            let at = format!("{rel}:{}", doc.line_of(doc.nodes[dep].start));
            if doc
                .child_text(dep, "classifier")
                .is_some_and(|c| !c.is_empty())
            {
                warnings.push(degraded(
                    "classifier_declared",
                    format!("{at}: a classifier variant of {ga} bypasses the pin"),
                ));
                continue;
            }
            let top_managed = doc.is_top_level_managed(dep);
            let root = self.local_root(rel);
            if top_managed && root == rel {
                managed_roots.insert(root.clone());
            }
            let Some(version) = doc.child(dep, "version") else {
                continue;
            };
            let declared = doc.text_of(version);
            let resolved = if declared.contains("${") {
                match self.interpolate(rel, &declared, 0) {
                    Some(v) => v,
                    None => {
                        warnings.push(degraded(
                            "property_unresolved",
                            format!(
                                "{at}: {ga} version {declared} is not defined in the checkout; \
                                 left as is, probably unpatched"
                            ),
                        ));
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
                // Maven interpolates after inheritance: a pom that inherits
                // this declaration and overrides the property must keep its
                // own version, so the literal SV cannot go here.
                let overridden = declared.contains("${").then(|| {
                    self.inheritors(rel).find_map(|p| {
                        let v = self.interpolate(p, &declared, 0)?;
                        (!is_base_like(&v, patch.version) && v != sv).then(|| (p.to_string(), v))
                    })
                });
                if let Some((p, v)) = overridden.flatten() {
                    warnings.push(degraded(
                        "conflicting_literal_version",
                        format!(
                            "{at}: {ga} version {declared} resolves to {v} in {p}, not {}; \
                             left as is and {root} is not pinned",
                            patch.version
                        ),
                    ));
                    unpinned.insert(root);
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
    let candidates = if path.is_empty() {
        vec!["pom.xml".to_string()]
    } else {
        vec![format!("{path}/pom.xml"), path]
    };
    candidates
        .into_iter()
        .find_map(|c| read(&c).map(|bytes| (c, bytes)))
        .ok_or_else(|| {
            shape_refusal(
                "module_path_unresolvable",
                format!("{declaring}: <module>{module}</module> has no pom"),
            )
        })
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
    let candidates = [
        path.clone(),
        if path.is_empty() {
            "pom.xml".to_string()
        } else {
            format!("{path}/pom.xml")
        },
    ];
    let Some(parent_rel) = candidates
        .into_iter()
        .find(|c| poms.contains_key(c) || read(c).is_some())
    else {
        return Ok(None);
    };
    if !poms.contains_key(&parent_rel) {
        let bytes = read(&parent_rel).unwrap_or_default();
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
    let matches = want_group.as_deref() == candidate.effective_group()
        && want_artifact == candidate.artifact
        && versions_agree;
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

/// `-Dk=v` tokens of a `maven.config`.
fn cli_properties(config: &str) -> BTreeMap<String, String> {
    config
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("-D")?.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
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
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    let sv = patch.suffixed_version();
    let suffixed_pom = std::str::from_utf8(patch.upstream_pom)
        .ok()
        .and_then(|pom| suffix_maven_pom(pom, v, &sv))
        .ok_or_else(|| JvmRefusal {
            code: UPSTREAM_UNAVAILABLE,
            detail: format!(
                "reason: suffix_unavailable: the upstream pom of {g}:{a}:{v} computes its own \
                 version, so it cannot be served as {sv}"
            ),
        })?;
    Ok(tree_writes(patch, &sv, suffixed_pom))
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
    /// `version:<g>:<a>:<section>:<ordinal>`.
    fn keyed_declarations(&self, g: &str, a: &str) -> Vec<(usize, String)> {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut out = Vec::new();
        for dep in self.declarations() {
            if self.child_text(dep, "groupId").as_deref() != Some(g)
                || self.child_text(dep, "artifactId").as_deref() != Some(a)
                || self.pin_at(dep).is_some()
            {
                continue;
            }
            let section = self.section_of(dep);
            let ordinal = seen.entry(section.clone()).or_default();
            out.push((dep, format!("version:{g}:{a}:{section}:{ordinal}")));
            *ordinal += 1;
        }
        out
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

    fn run(files: &Fs) -> Result<JvmPlan, JvmRefusal> {
        let read = |p: &str| files.get(p).cloned();
        plan(&read, &patch())
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
            let need = external_poms_needed(&read, &patch(), &known);
            if need.is_empty() {
                break;
            }
            for gav in need {
                let bytes = repo.get(&gav).cloned().flatten();
                known.insert(gav, bytes);
            }
        }
        (
            plan_with_external(&read, &patch(), true, Some(&known)),
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
        assert!(
            text(&after, "pom.xml").contains("<dependencyManagement>"),
            "still pinned"
        );
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

    #[test]
    fn plugin_dependencies_exclusions_and_other_types_are_untouched() {
        let a = format!(
            "<project>\n  <parent><groupId>t</groupId><artifactId>root</artifactId><version>1-SNAPSHOT</version></parent>\n  \
             <artifactId>a</artifactId>\n  <dependencies>\n    \
             <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version>\
             <exclusions><exclusion><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId></exclusion></exclusions></dependency>\n    \
             <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.10.0</version><type>test-jar</type></dependency>\n  \
             </dependencies>\n  <build><plugins><plugin><artifactId>p</artifactId><dependencies>{}</dependencies></plugin></plugins></build>\n</project>\n",
            dep("1.10.0")
        );
        let files = fs(&[
            ("pom.xml", ROOT),
            ("a/pom.xml", &a),
            ("b/pom.xml", &module("b", "")),
        ]);
        let (plan, after) = vendor(&files);
        assert!(plan.warnings.is_empty());
        assert_eq!(text(&after, "a/pom.xml"), a);
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
        plan(&|rel: &str| reader.read(rel), p)
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
        let undo = unplan(&read, &patch().coords(), &[]);
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
        let undo = unplan(&read, &patch().coords(), &plan.records);
        let a = undo.changes.iter().find(|(r, _)| r == "a/pom.xml").unwrap();
        assert_eq!(a.1.as_deref(), Some(module("a", cdata).as_bytes()));
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

    #[test]
    fn plugin_configuration_modules_do_not_make_a_reactor() {
        let ear = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
            <artifactId>app</artifactId><version>1</version><packaging>ear</packaging>\
            <build><plugins><plugin><artifactId>maven-ear-plugin</artifactId><configuration>\
            <modules><jarModule><groupId>x</groupId><artifactId>y</artifactId></jarModule></modules>\
            </configuration></plugin></plugins></build></project>";
        assert!(!declares_modules(ear));
        let read = |p: &str| (p == "pom.xml").then(|| ear.as_bytes().to_vec());
        let builds = super::super::detect_builds(&read);
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
                plan(&read, &p).unwrap_err().code,
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
        let _ = plan(&|rel: &str| reader.read(rel), &patch());
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
        assert!(plan(&read, &p).unwrap().writes.is_empty());
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
        assert!(plan(&read, &p).unwrap().writes.is_empty());
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
