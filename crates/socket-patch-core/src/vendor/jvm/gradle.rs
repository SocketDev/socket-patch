//! Gradle planner. See the module doc of [`super`] and
//! `docs/design/maven-vendoring.md`.
//!
//! The patched artifact keeps its GAV in `.socket/vendor/gradle/`,
//! listed with its sha256 in `.socket/vendor/gradle-index.tsv`. The
//! owned static script [`SCRIPT`] reads the index, checks every hash at
//! configuration time (index verification) and routes the GAV to the tree with
//! `exclusiveContent`. Each wired settings file gets one apply line, plus an
//! in-block `pluginManagement` entry when it has settings-level `plugins{}`.
//! An existing `gradle/verification-metadata.xml` gets the patched jar hash.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::super::state::{WiringAction, WiringRecord};
use super::{
    adopt, changes_between, finish_writes, fragment, op_of, op_str, owned_file, replace_op,
    sha256_hex, undo_replace, Coords, FileWrite, JvmPatch, JvmPlan, JvmRefusal, JvmUnplan,
    JvmWarning, ReadFn, OWNED_FILE_KIND, SETTINGS_FRAGMENT_KIND, VERIFICATION_FRAGMENT_KIND,
};

pub use super::safe_coordinates;

/// The owned settings script. Its bytes change only with a CLI release.
pub const SCRIPT: &str = include_str!("socket-patch.settings.gradle");
/// Where [`SCRIPT`] lives, project-relative.
pub const SCRIPT_REL: &str = ".socket/gradle/socket-patch.settings.gradle";
/// The Gradle-only artifact tree root.
pub const TREE_ROOT: &str = ".socket/vendor/gradle";
/// The tree root's `.gitattributes`, shared by every Gradle patch.
pub const GITATTRIBUTES_REL: &str = ".socket/vendor/gradle/.gitattributes";
/// The derived index the script reads.
pub const INDEX_REL: &str = ".socket/vendor/gradle-index.tsv";
pub const INDEX_HEADER: &str = "#socket-patch-gradle-index 1";
pub const VERIFICATION_REL: &str = "gradle/verification-metadata.xml";
pub const MARKER_NAME: &str = "socket-patch.vendor.json";
/// Repository name shared by the script and the in-block entry: the script
/// skips a handler that already holds it.
const REPO_NAME: &str = "socketPatchVendor";
/// Upstream poms of Gradle-published modules carry this; Gradle then follows
/// the `.module`, so vendoring the pom alone changes the graph.
const GRADLE_METADATA_MARKER: &str = "published-with-gradle-metadata";

/// The tree directory of `c` (same GAV).
pub fn tree_dir(c: &Coords<'_>) -> String {
    format!(
        "{TREE_ROOT}/{}/{}/{}",
        c.group_path(),
        c.artifact_id,
        c.version
    )
}

/// The committed tree of `c` as `(jar, pom, module)`: the tree holds the
/// upstream pom and module verbatim. `None` when the jar or pom is missing.
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<super::CommittedTree> {
    let dir = tree_dir(c);
    let (a, v) = (c.artifact_id, c.version);
    Some((
        read(&format!("{dir}/{a}-{v}.jar"))?,
        read(&format!("{dir}/{a}-{v}.pom"))?,
        read(&format!("{dir}/{a}-{v}.module")),
    ))
}

/// Plan vendoring `patch` into the Gradle build rooted at the project root.
pub fn plan(read: ReadFn<'_>, patch: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
    if super::wrapper_version(read, "gradle").is_some_and(|v| v < (6, 8, 0)) {
        return Err(shape_refusal(
            "gradle_below_6_8",
            "vendored dependencies require Gradle 6.8 or newer".into(),
        ));
    }
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    if !safe_coordinates(g, a, v) {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("unsafe gradle coordinates `{g}:{a}:{v}`"),
        });
    }
    if patch.uuid.is_empty()
        || !patch
            .uuid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("non-canonical patch uuid {:?}", patch.uuid),
        });
    }
    let pom_text = String::from_utf8_lossy(patch.upstream_pom);
    if patch.upstream_module.is_none() && pom_text.contains(GRADLE_METADATA_MARKER) {
        return Err(JvmRefusal {
            code: "vendor_jvm_upstream_unavailable",
            detail: format!(
                "reason: module_unavailable: {a}-{v}.pom declares Gradle module metadata but no \
                 {a}-{v}.module was found; run one online build (`./gradlew dependencies`)"
            ),
        });
    }
    if let Some(module) = patch.upstream_module {
        if String::from_utf8_lossy(module).contains("\"available-at\"") {
            return Err(shape_refusal(
                "android_or_kmp",
                format!("{a}-{v}.module redirects with available-at (a multiplatform module); use hosted mode"),
            ));
        }
    }

    let mut warnings = Vec::new();
    let mut writes = Vec::new();
    let mut records = Vec::new();

    let root = read_settings(read, "")?;
    let root_build = read_build_script(read, "")?;
    if let Some((rel, text)) = &root_build {
        check_android(rel, text)?;
        check_exclusive_content(rel, text, patch)?;
    }

    let mut targets = vec![root];
    if let Some(bs) = read_buildsrc(read)? {
        targets.push(bs);
    }
    // Literal includeBuild targets, found recursively from the root settings.
    let mut seen: BTreeSet<String> = targets.iter().map(|t| t.dir.clone()).collect();
    let mut i = 0;
    while i < targets.len() {
        if targets[i].dir != "buildSrc" {
            let text = targets[i].text.clone().unwrap_or_default();
            let (found, warns) = included_builds(&targets[i].rel, &targets[i].dir, &text);
            warnings.extend(warns);
            for dir in found {
                if !seen.insert(dir.clone()) {
                    continue;
                }
                match read_included(read, &dir)? {
                    Some(t) => targets.push(t),
                    None => warnings.push(degraded(
                        "unwired_build_logic",
                        format!(
                            "{}: includeBuild('{dir}') has no settings or build script in the \
                             checkout; that build stays unpatched",
                            targets[i].rel
                        ),
                    )),
                }
            }
        }
        i += 1;
    }

    for t in &targets {
        let Some(text) = &t.text else { continue };
        check_android(&t.rel, text)?;
        check_exclusive_content(&t.rel, text, patch)?;
    }

    let coords = patch.coords();
    for t in &targets {
        let prefix = prefix_of(&t.dir);
        let mut text = t.text.clone().unwrap_or_default();
        if t.text.is_some() {
            for (scope, key_prefix, section) in [
                ("pluginManagement", "in_block", "in_block_section"),
                ("buildscript", "buildscript", "buildscript_section"),
            ] {
                match scoped_in_block_entry(&text, t.kotlin, &prefix, &coords, scope) {
                    InBlock::Unneeded => {}
                    InBlock::Present => {
                        let key = format!("{key_prefix}:{g}:{a}:{v}");
                        records.push(adopt(&t.rel, SETTINGS_FRAGMENT_KIND, &key));
                        records.push(adopt(&t.rel, SETTINGS_FRAGMENT_KIND, section));
                    }
                    InBlock::Edited {
                        start,
                        end,
                        text: inserted,
                    } => {
                        let mut added = in_block_records(
                            &t.rel, &text, start, end, &inserted, t.kotlin, &prefix, &coords,
                        );
                        if scope == "buildscript" {
                            for w in &mut added {
                                w.key =
                                    w.key.as_ref().map(|k| k.replace("in_block", "buildscript"));
                            }
                        }
                        records.extend(added);
                        text = format!("{}{inserted}{}", &text[..start], &text[end..]);
                    }
                    InBlock::Unwired(why) => warnings.push(degraded(
                        "settings_plugins_unwired",
                        format!(
                            "{}: {why}; settings plugins may resolve the unpatched {g}:{a}:{v}",
                            t.rel
                        ),
                    )),
                }
            }
        }
        let line = apply_line(t.kotlin, &prefix);
        if has_apply_line(&text, &prefix) {
            records.push(adopt(&t.rel, SETTINGS_FRAGMENT_KIND, "apply"));
        } else {
            let appended = append_line(&text, &line);
            let op = match &t.text {
                None => json!({ "op": "create", "text": appended }),
                Some(_) => json!({
                    "op": "line",
                    "text": &appended[text.len()..],
                    "line": line,
                }),
            };
            records.push(fragment(
                &t.rel,
                SETTINGS_FRAGMENT_KIND,
                "apply",
                WiringAction::Added,
                None,
                op,
            ));
            text = appended;
        }
        writes.push(text_write(&t.rel, text.into_bytes()));
    }

    let tree_dir = tree_dir(&coords);
    let jar_name = format!("{a}-{v}.jar");
    let pom_name = format!("{a}-{v}.pom");
    let module_name = format!("{a}-{v}.module");
    let mut files: Vec<(&str, &[u8])> =
        vec![(&jar_name, patch.jar), (&pom_name, patch.upstream_pom)];
    if let Some(module) = patch.upstream_module {
        files.push((&module_name, module));
    }
    files.sort_by(|x, y| x.0.cmp(y.0));
    let gav = format!("{g}:{a}:{v}");
    let mut rows = Vec::new();
    for (name, bytes) in &files {
        writes.push(FileWrite {
            rel: format!("{tree_dir}/{name}"),
            bytes: bytes.to_vec(),
            tree: true,
        });
        rows.push(format!(
            "{gav}\t{}/{}/{v}/{name}\t{}\t{}",
            patch.group_path(),
            a,
            sha256_hex(bytes),
            patch.uuid
        ));
    }
    writes.push(FileWrite {
        rel: format!("{tree_dir}/{MARKER_NAME}"),
        bytes: marker_json(patch, &files).into_bytes(),
        tree: true,
    });
    let existing_index = read(INDEX_REL);
    let index = merge_index(existing_index.as_deref(), &gav, rows)?;
    records.push(created_or_adopted(INDEX_REL, existing_index.is_some()));
    writes.push(text_write(INDEX_REL, index.into_bytes()));
    records.push(created_or_adopted(SCRIPT_REL, read(SCRIPT_REL).is_some()));
    writes.push(text_write(SCRIPT_REL, SCRIPT.as_bytes().to_vec()));
    records.push(owned_file(read, GITATTRIBUTES_REL, &mut writes));

    if let Some(bytes) = read(VERIFICATION_REL) {
        let text = String::from_utf8(bytes).map_err(|_| {
            shape_refusal(
                "gradle_verification_unparseable",
                format!("{VERIFICATION_REL} is not UTF-8"),
            )
        })?;
        let hashes = ArtifactHashes {
            jar: sha256_hex(patch.jar),
            pom: sha256_hex(patch.upstream_pom),
            module: patch.upstream_module.map(sha256_hex),
        };
        let (start, end, replacement) = update_verification(&text, patch, &hashes)?;
        if unverified_parent_chain(&text, &pom_text, patch.upstream_module) {
            warnings.push(degraded(
                "verification_parent_chain_unhandled",
                format!(
                    "{VERIFICATION_REL}: {a}-{v}.pom has a parent or imported platform the file \
                     may not list, and those entries are not added; run `./gradlew --write-verification-metadata sha256 help` \
                     if verification fails"
                ),
            ));
        }
        let new = format!("{}{replacement}{}", &text[..start], &text[end..]);
        records.push(adopt(
            VERIFICATION_REL,
            VERIFICATION_FRAGMENT_KIND,
            "components_section",
        ));
        if new != text {
            // Replacing an earlier patch's hash for this GAV: the user's
            // element is in that patch's record, which the caller carries.
            let mut from =
                Some(&text[start..end]).filter(|f| !f.contains("origin=\"socket-patch\""));
            let mut replacement = replacement;
            if text[start..end].starts_with("<components") && text[start..end].ends_with("/>") {
                let nl = newline_of(&text);
                let indent = line_indent(&text, start);
                let shell = format!("<components>{nl}{indent}</components>");
                records.pop();
                records.push(fragment(
                    VERIFICATION_REL,
                    VERIFICATION_FRAGMENT_KIND,
                    "components_section",
                    WiringAction::Rewritten,
                    None,
                    replace_op(&text[start..end], &shell),
                ));
                replacement = replacement["<components>".len() + nl.len()
                    ..replacement.len() - indent.len() - "</components>".len()]
                    .to_string();
                from = Some("");
            }
            let action = if from == Some("") {
                WiringAction::Added
            } else {
                WiringAction::Rewritten
            };
            records.push(fragment(
                VERIFICATION_REL,
                VERIFICATION_FRAGMENT_KIND,
                &format!("hash:{gav}"),
                action,
                None,
                json!({ "op": "replace", "from": from, "to": replacement }),
            ));
        }
        writes.push(text_write(VERIFICATION_REL, new.into_bytes()));
    }

    Ok(JvmPlan {
        tree_files: super::tree_files(&writes),
        writes: finish_writes(read, writes),
        records,
        warnings,
        jar_rel: format!("{tree_dir}/{jar_name}"),
        tree_dir,
    })
}

/// `../` once per segment of `dir`: the script path from that build.
fn prefix_of(dir: &str) -> String {
    "../".repeat(if dir.is_empty() {
        0
    } else {
        dir.split('/').count()
    })
}

fn created_or_adopted(rel: &str, existed: bool) -> WiringRecord {
    if existed {
        adopt(rel, OWNED_FILE_KIND, "owned")
    } else {
        fragment(
            rel,
            OWNED_FILE_KIND,
            "owned",
            WiringAction::Added,
            None,
            json!({ "op": "create" }),
        )
    }
}

/// The records of an in-block insertion replacing `text[start..end]` with
/// `inserted`: the per-patch entry line, and the shell around it when the
/// insertion created one (`in_block_section`, with the rest of the lines
/// it touches as context so a lone `gradlePluginPortal()` stays unique).
#[allow(clippy::too_many_arguments)]
fn in_block_records(
    rel: &str,
    text: &str,
    start: usize,
    end: usize,
    inserted: &str,
    kotlin: bool,
    prefix: &str,
    c: &Coords<'_>,
) -> Vec<WiringRecord> {
    let entry = in_block_line(kotlin, prefix, c);
    let key = format!("in_block:{}:{}:{}", c.group_id, c.artifact_id, c.version);
    let from = &text[start..end];
    let Some(at) = inserted.find(&entry) else {
        return Vec::new();
    };
    let line_start = inserted[..at].rfind('\n').map_or(0, |n| n + 1);
    let line_end = inserted[at..]
        .find('\n')
        .map_or(inserted.len(), |n| at + n + 1);
    let shell = format!("{}{}", &inserted[..line_start], &inserted[line_end..]);
    if shell == from {
        return vec![
            fragment(
                rel,
                SETTINGS_FRAGMENT_KIND,
                &key,
                WiringAction::Added,
                None,
                json!({ "op": "in_block", "line": entry, "from": from, "to": inserted }),
            ),
            adopt(rel, SETTINGS_FRAGMENT_KIND, "in_block_section"),
        ];
    }
    let new = format!("{}{inserted}{}", &text[..start], &text[end..]);
    let ctx_start = new[..start].rfind('\n').map_or(0, |n| n + 1);
    let after = start + inserted.len();
    let ctx_end = new[after..].find('\n').map_or(new.len(), |n| after + n);
    let (left, right) = (&new[ctx_start..start], &new[after..ctx_end]);
    vec![
        fragment(
            rel,
            SETTINGS_FRAGMENT_KIND,
            &key,
            WiringAction::Added,
            None,
            json!({ "op": "in_block", "line": entry }),
        ),
        fragment(
            rel,
            SETTINGS_FRAGMENT_KIND,
            "in_block_section",
            WiringAction::Added,
            None,
            replace_op(
                &format!("{left}{from}{right}"),
                &format!("{left}{shell}{right}"),
            ),
        ),
    ]
}

/// Plan the revert of `c`'s wiring: its in-block entries, index
/// rows and verification hash go now; apply lines, the script, the index
/// and the tree `.gitattributes` once no other patch has an index row.
pub fn unplan(read: ReadFn<'_>, c: &Coords<'_>, records: &[WiringRecord]) -> JvmUnplan {
    let mut drifted = Vec::new();
    let mut files: BTreeSet<String> = records
        .iter()
        .filter(|w| {
            matches!(
                w.kind.as_str(),
                SETTINGS_FRAGMENT_KIND | VERIFICATION_FRAGMENT_KIND
            )
        })
        .map(|w| w.file.clone())
        .collect();
    files.insert(INDEX_REL.to_string());
    let mut before: BTreeMap<String, Option<String>> = files
        .into_iter()
        .filter_map(|rel| {
            let text = match read(&rel) {
                None => None,
                Some(bytes) => Some(String::from_utf8(bytes).ok()?),
            };
            Some((rel, text))
        })
        .collect();
    let mut after = before.clone();
    let recs = |rel: &str| {
        records
            .iter()
            .filter(move |w| w.file == rel && w.kind == SETTINGS_FRAGMENT_KIND)
            .collect::<Vec<_>>()
    };
    let in_block_key = format!("in_block:{}:{}:{}", c.group_id, c.artifact_id, c.version);
    for (rel, text) in after.iter_mut() {
        let Some(t) = text.as_mut() else { continue };
        if !is_settings_file(rel) {
            continue;
        }
        let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
        let entry = in_block_line(rel.ends_with(".kts"), &prefix_of(dir), c);
        for w in recs(rel) {
            if w.key.as_deref() != Some(in_block_key.as_str())
                && w.key.as_deref()
                    != Some(in_block_key.replace("in_block:", "buildscript:").as_str())
            {
                continue;
            }
            if let (Some(from), Some(to)) = (op_str(w, "from"), op_str(w, "to")) {
                if let Some(undone) = undo_replace(t, from, to) {
                    *t = undone;
                }
            }
        }
        while let Some(cut) = remove_line(t, &entry) {
            *t = cut;
        }
        for w in recs(rel) {
            if matches!(
                w.key.as_deref(),
                Some("in_block_section" | "buildscript_section")
            ) {
                if let (Some(from), Some(to)) = (op_str(w, "from"), op_str(w, "to")) {
                    if let Some(undone) = undo_replace(t, from, to) {
                        *t = undone;
                    }
                }
            }
        }
    }
    for w in records
        .iter()
        .rev()
        .filter(|w| {
            w.kind == VERIFICATION_FRAGMENT_KIND && w.key.as_deref() != Some("components_section")
        })
        .chain(records.iter().filter(|w| {
            w.kind == VERIFICATION_FRAGMENT_KIND && w.key.as_deref() == Some("components_section")
        }))
    {
        let Some(Some(t)) = after.get_mut(&w.file) else {
            continue;
        };
        let Some(to) = op_str(w, "to") else {
            continue;
        };
        let Some(from) = op_str(w, "from") else {
            if t.contains(to) {
                drifted.push(format!(
                    "{}: no pre-vendor entry is recorded for {}:{}:{}",
                    w.file, c.group_id, c.artifact_id, c.version
                ));
            }
            continue;
        };
        match undo_replace(t, from, to) {
            Some(undone) => *t = undone,
            None if t.contains(to) => drifted.push(format!(
                "{} holds the patched hash for {}:{}:{} in an unexpected shape",
                w.file, c.group_id, c.artifact_id, c.version
            )),
            None => {}
        }
    }

    let rows: Option<Vec<String>> = match after.get(INDEX_REL) {
        Some(Some(index)) => index_rows(index),
        _ => Some(Vec::new()),
    };
    let Some(rows) = rows else {
        drifted.push(format!(
            "{INDEX_REL} is malformed; its rows were left alone"
        ));
        return JvmUnplan {
            changes: changes_between(&before, &after),
            drifted,
            still_wired: true,
        };
    };
    let others: Vec<String> = rows
        .into_iter()
        .filter(|r| r.split('\t').nth(3) != Some(c.uuid))
        .collect();
    if others.is_empty() {
        after.insert(INDEX_REL.to_string(), None);
        for (rel, text) in after.iter_mut() {
            if !is_settings_file(rel) {
                continue;
            }
            for w in recs(rel)
                .into_iter()
                .filter(|w| w.key.as_deref() == Some("apply"))
            {
                let Some(t) = text.as_deref() else { break };
                let written = op_str(w, "text").unwrap_or_default();
                *text = match op_of(w) {
                    "create" if t == written => None,
                    "create" => {
                        Some(remove_line(t, written.trim()).unwrap_or_else(|| t.to_string()))
                    }
                    "line" => Some(
                        match t.strip_suffix(written).filter(|_| !written.is_empty()) {
                            Some(cut) => cut.to_string(),
                            None => remove_line(t, op_str(w, "line").unwrap_or_default())
                                .unwrap_or_else(|| t.to_string()),
                        },
                    ),
                    _ => Some(t.to_string()),
                };
            }
        }
        for rel in [SCRIPT_REL, GITATTRIBUTES_REL] {
            let created = records
                .iter()
                .any(|w| w.kind == OWNED_FILE_KIND && w.file == rel && op_of(w) == "create");
            let current = read(rel);
            let expected = if rel == SCRIPT_REL {
                SCRIPT
            } else {
                super::TREE_GITATTRIBUTES
            };
            let ours = current.as_deref() == Some(expected.as_bytes());
            if created && ours && current.is_some() {
                before.insert(rel.to_string(), Some(String::new()));
                after.insert(rel.to_string(), None);
            } else if created && current.is_some() && !ours {
                drifted.push(format!("{rel} was modified"));
            }
        }
    } else {
        let mut index = format!("{INDEX_HEADER}\n");
        for row in &others {
            index.push_str(row);
            index.push('\n');
        }
        after.insert(INDEX_REL.to_string(), Some(index));
    }
    JvmUnplan {
        changes: changes_between(&before, &after),
        drifted,
        still_wired: false,
    }
}

/// Whether the root settings file applies the script and the index lists
/// `c`'s rows: the liveness proof `vex` needs for this layout.
pub fn wired(read: ReadFn<'_>, c: &Coords<'_>) -> bool {
    let gav = format!("{}:{}:{}", c.group_id, c.artifact_id, c.version);
    let indexed = read(INDEX_REL)
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|index| index_rows(&index))
        .is_some_and(|rows| {
            rows.iter().any(|r| {
                let cols: Vec<&str> = r.split('\t').collect();
                cols.first() == Some(&gav.as_str()) && cols.get(3) == Some(&c.uuid)
            })
        });
    let applied = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .any(|rel| {
            read(rel)
                .and_then(|b| String::from_utf8(b).ok())
                .is_some_and(|text| has_apply_line(&text, ""))
        });
    indexed && applied
}

pub fn wired_checked(read: ReadFn<'_>, c: &Coords<'_>) -> Result<bool, JvmRefusal> {
    read_settings(read, "")?;
    if let Some(bytes) = read(INDEX_REL) {
        let index = std::str::from_utf8(&bytes).ok().and_then(index_rows);
        if index.is_none() {
            return Err(shape_refusal(
                "gradle_index_unreadable",
                "the vendored Gradle index is malformed".into(),
            ));
        }
    }
    Ok(wired(read, c))
}

fn is_settings_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "settings.gradle" || name == "settings.gradle.kts"
}

/// `text` without its first whole line whose trimmed body is `line`.
fn remove_line(text: &str, line: &str) -> Option<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let i = lines.iter().position(|l| l.trim() == line)?;
    Some(format!(
        "{}{}",
        lines[..i].concat(),
        lines[i + 1..].concat()
    ))
}

/// The rows of an index, `None` when it is malformed.
fn index_rows(index: &str) -> Option<Vec<String>> {
    let mut lines = index.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
    if lines.next() != Some(INDEX_HEADER) {
        return None;
    }
    let mut rows = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        if !valid_index_row(line) {
            return None;
        }
        rows.push(line.to_string());
    }
    Some(rows)
}

fn text_write(rel: &str, bytes: Vec<u8>) -> FileWrite {
    FileWrite {
        rel: rel.to_string(),
        bytes,
        tree: false,
    }
}

fn shape_refusal(reason: &str, msg: String) -> JvmRefusal {
    JvmRefusal {
        code: "vendor_jvm_shape_unsupported",
        detail: format!("reason: {reason}: {msg}"),
    }
}

fn degraded(reason: &str, msg: String) -> JvmWarning {
    JvmWarning {
        code: "vendor_jvm_degraded",
        detail: format!("reason: {reason}: {msg}"),
    }
}

// ── settings files ──────────────────────────────────────────────────────────────

/// One settings file to wire: `dir` is the build directory ("" = root).
#[derive(Debug, Clone)]
struct Target {
    dir: String,
    rel: String,
    /// Current text; `None` when vendor creates the file.
    text: Option<String>,
    kotlin: bool,
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn read_text(read: ReadFn<'_>, rel: &str) -> Result<Option<String>, JvmRefusal> {
    match read(rel) {
        None => Ok(None),
        Some(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| shape_refusal("build_file_unreadable", format!("{rel} is not UTF-8"))),
    }
}

/// Gradle's own lookup order: the Groovy name wins over the Kotlin one.
fn read_script(
    read: ReadFn<'_>,
    dir: &str,
    stem: &str,
) -> Result<Option<(String, String)>, JvmRefusal> {
    for ext in [".gradle", ".gradle.kts"] {
        let rel = join_rel(dir, &format!("{stem}{ext}"));
        if let Some(text) = read_text(read, &rel)? {
            return Ok(Some((rel, text)));
        }
    }
    Ok(None)
}

fn read_build_script(read: ReadFn<'_>, dir: &str) -> Result<Option<(String, String)>, JvmRefusal> {
    read_script(read, dir, "build")
}

/// The settings file of `dir`, or the one to create there. A created file
/// takes its DSL from the build's own build script, else `default_kotlin`.
fn settings_target(
    read: ReadFn<'_>,
    dir: &str,
    default_kotlin: bool,
) -> Result<Target, JvmRefusal> {
    if let Some((rel, text)) = read_script(read, dir, "settings")? {
        let kotlin = rel.ends_with(".kts");
        return Ok(Target {
            dir: dir.to_string(),
            rel,
            text: Some(text),
            kotlin,
        });
    }
    let kotlin = match read_build_script(read, dir)? {
        Some((rel, _)) => rel.ends_with(".kts"),
        None => default_kotlin,
    };
    Ok(Target {
        dir: dir.to_string(),
        rel: join_rel(
            dir,
            if kotlin {
                "settings.gradle.kts"
            } else {
                "settings.gradle"
            },
        ),
        text: None,
        kotlin,
    })
}

fn read_settings(read: ReadFn<'_>, dir: &str) -> Result<Target, JvmRefusal> {
    settings_target(read, dir, false)
}

fn read_buildsrc(read: ReadFn<'_>) -> Result<Option<Target>, JvmRefusal> {
    let present = [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    ]
    .iter()
    .any(|f| read(&format!("buildSrc/{f}")).is_some());
    if !present {
        return Ok(None);
    }
    settings_target(read, "buildSrc", false).map(Some)
}

/// The settings target of an included build, `None` when the directory
/// holds neither a settings nor a build script (nothing to wire, and no
/// directory is created for it).
fn read_included(read: ReadFn<'_>, dir: &str) -> Result<Option<Target>, JvmRefusal> {
    if read_script(read, dir, "settings")?.is_none() && read_build_script(read, dir)?.is_none() {
        return Ok(None);
    }
    settings_target(read, dir, false).map(Some)
}

fn apply_line(kotlin: bool, prefix: &str) -> String {
    if kotlin {
        format!("apply(from = \"{prefix}{SCRIPT_REL}\") // socket-patch")
    } else {
        format!("apply from: '{prefix}{SCRIPT_REL}' // socket-patch")
    }
}

/// Any live `apply from` naming our script at this prefix, in either DSL,
/// counts (a user who reformatted the line keeps it); one inside a comment
/// does not.
fn has_apply_line(text: &str, prefix: &str) -> bool {
    let path = format!("{prefix}{SCRIPT_REL}");
    let toks = lex(text);
    (0..toks.len()).any(|i| {
        if !is_ident(toks.get(i), "apply") {
            return false;
        }
        let mut j = i + 1;
        if is_punct(toks.get(j), b'(') {
            j += 1;
        }
        is_ident(toks.get(j), "from")
            && (is_punct(toks.get(j + 1), b':') || is_punct(toks.get(j + 1), b'='))
            && matches!(toks.get(j + 2), Some(Token { tok: Tok::Str { value, .. }, .. }) if *value == path)
    })
}

/// The newline the file already uses (CRLF when its first line ends so).
fn newline_of(text: &str) -> &'static str {
    match text.find('\n') {
        Some(i) if i > 0 && text.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

fn append_line(text: &str, line: &str) -> String {
    let nl = newline_of(text);
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(nl);
    }
    out.push_str(line);
    out.push_str(nl);
    out
}

// ── a small Groovy/Kotlin lexer ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    /// A string literal. `literal` is false when it interpolates (`$`) or
    /// uses an escape we do not decode.
    Str {
        value: String,
        literal: bool,
    },
    Punct(u8),
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
}

/// Tokenize enough of a build script to find blocks, calls and string
/// literals: comments are skipped, strings (including triple-quoted) are one
/// token, everything else is an identifier or a single punctuation byte.
/// Slashy strings are not recognised (a `/` is punctuation).
fn lex(src: &str) -> Vec<Token> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            i = src[i + 2..].find("*/").map_or(b.len(), |j| i + 2 + j + 2);
        } else if c == b'\'' || c == b'"' {
            let start = i;
            let triple = b[i..].starts_with(&[c, c, c]);
            i += if triple { 3 } else { 1 };
            let mut value = String::new();
            let mut literal = true;
            loop {
                if i >= b.len() {
                    literal = false;
                    break;
                }
                if triple {
                    if b[i..].starts_with(&[c, c, c]) {
                        i += 3;
                        break;
                    }
                } else if b[i] == c {
                    i += 1;
                    break;
                } else if b[i] == b'\n' {
                    literal = false;
                    break;
                }
                if b[i] == b'\\' && !triple {
                    match b.get(i + 1) {
                        Some(&e @ (b'\\' | b'\'' | b'"')) => value.push(e as char),
                        _ => literal = false,
                    }
                    i += 2;
                    continue;
                }
                if b[i] == b'$' && c == b'"' {
                    literal = false;
                }
                let ch = src[i..].chars().next().unwrap_or('\u{fffd}');
                value.push(ch);
                i += ch.len_utf8().max(1);
            }
            out.push(Token {
                tok: Tok::Str { value, literal },
                start,
                end: i.min(b.len()),
            });
        } else if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                i += 1;
            }
            out.push(Token {
                tok: Tok::Ident(src[start..i].to_string()),
                start,
                end: i,
            });
        } else if c.is_ascii() {
            out.push(Token {
                tok: Tok::Punct(c),
                start: i,
                end: i + 1,
            });
            i += 1;
        } else {
            i += src[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

fn is_ident(t: Option<&Token>, name: &str) -> bool {
    matches!(t, Some(Token { tok: Tok::Ident(n), .. }) if n == name)
}

fn is_punct(t: Option<&Token>, p: u8) -> bool {
    matches!(t, Some(Token { tok: Tok::Punct(c), .. }) if *c == p)
}

/// Index of the `}` matching the `{` at `open`.
fn matching_close(toks: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t.tok {
            Tok::Punct(b'{') => depth += 1,
            Tok::Punct(b'}') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// A `name {` block directly inside `toks[from..to]` (brace depth 0 there):
/// `(name index, open index, close index)`.
fn find_block(toks: &[Token], from: usize, to: usize, name: &str) -> Option<(usize, usize, usize)> {
    let mut depth = 0usize;
    let mut i = from;
    while i < to {
        match toks[i].tok {
            Tok::Punct(b'{') => depth += 1,
            Tok::Punct(b'}') => depth = depth.saturating_sub(1),
            Tok::Ident(ref n) if depth == 0 && n == name && is_punct(toks.get(i + 1), b'{') => {
                let close = matching_close(toks, i + 1)?;
                return Some((i, i + 1, close));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Every `name {` block at any depth: `(open index, close index)`.
fn all_blocks(toks: &[Token], name: &str) -> Vec<(usize, usize)> {
    (0..toks.len())
        .filter(|&i| is_ident(toks.get(i), name) && is_punct(toks.get(i + 1), b'{'))
        .filter_map(|i| matching_close(toks, i + 1).map(|c| (i + 1, c)))
        .collect()
}

fn strings(toks: &[Token]) -> impl Iterator<Item = &str> {
    toks.iter().filter_map(|t| match &t.tok {
        Tok::Str { value, .. } => Some(value.as_str()),
        _ => None,
    })
}

// ── refusals ────────────────────────────────────────────────────────────────────

fn check_android(rel: &str, text: &str) -> Result<(), JvmRefusal> {
    let toks = lex(text);
    let hit = strings(&toks)
        .find(|s| {
            s.starts_with("com.android.") || s.starts_with("org.jetbrains.kotlin.multiplatform")
        })
        .map(str::to_string)
        .or_else(|| {
            toks.windows(4).find_map(|w| {
                let kmp = is_ident(Some(&w[0]), "kotlin")
                    && is_punct(Some(&w[1]), b'(')
                    && matches!(&w[2].tok, Tok::Str { value, .. } if value == "multiplatform")
                    && is_punct(Some(&w[3]), b')');
                kmp.then(|| "kotlin(\"multiplatform\")".to_string())
            })
        });
    match hit {
        Some(id) => Err(shape_refusal(
            "android_or_kmp",
            format!("{rel} uses {id}; Android and Kotlin Multiplatform builds need hosted mode"),
        )),
        None => Ok(()),
    }
}

/// A user `exclusiveContent` that claims the patched group for another
/// repository would make ours unreachable ("Could not find").
fn check_exclusive_content(rel: &str, text: &str, patch: &JvmPatch<'_>) -> Result<(), JvmRefusal> {
    let toks = lex(text);
    for (open, close) in all_blocks(&toks, "exclusiveContent") {
        let body = &toks[open..close];
        if strings(body).any(|s| s == REPO_NAME || s.starts_with(&format!("{REPO_NAME}_"))) {
            continue;
        }
        let g = patch.group_id;
        if strings(body).any(|s| s == g || s.starts_with(&format!("{g}:"))) {
            return Err(shape_refusal(
                "gradle_exclusive_content_conflict",
                format!(
                    "{rel} has an exclusiveContent rule for {g}; drop {g}:{} from it",
                    patch.artifact_id
                ),
            ));
        }
    }
    Ok(())
}

// ── includeBuild ────────────────────────────────────────────────────────────────

/// Literal `includeBuild` targets of the settings file of `dir`, as
/// project-relative directories; non-literal or escaping ones are warned.
fn included_builds(rel: &str, dir: &str, text: &str) -> (Vec<String>, Vec<JvmWarning>) {
    let toks = lex(text);
    let mut found = Vec::new();
    let mut warns = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if !matches!(&t.tok, Tok::Ident(n) if n == "includeBuild") {
            continue;
        }
        // `x.includeBuild(…)` on anything but `settings` is not this build's.
        let prev = |k: usize| i.checked_sub(k).and_then(|p| toks.get(p));
        if is_punct(prev(1), b'.') && !is_ident(prev(2), "settings") {
            continue;
        }
        // `includeBuild('p')`, `includeBuild("p") { … }` or Groovy `includeBuild 'p'`.
        let arg = if is_punct(toks.get(i + 1), b'(') {
            match (toks.get(i + 2), toks.get(i + 3)) {
                (
                    Some(Token {
                        tok:
                            Tok::Str {
                                value,
                                literal: true,
                            },
                        ..
                    }),
                    Some(close),
                ) if is_punct(Some(close), b')') => Some(value.clone()),
                _ => None,
            }
        } else {
            match toks.get(i + 1) {
                Some(Token {
                    tok:
                        Tok::Str {
                            value,
                            literal: true,
                        },
                    ..
                }) => Some(value.clone()),
                _ => None,
            }
        };
        let snippet = &text[t.start..toks.get(i + 3).map_or(t.end, |x| x.end).min(text.len())];
        match arg.as_deref().map(|p| resolve_dir(dir, p)) {
            Some(Some(target)) if !target.is_empty() => found.push(target),
            Some(Some(_)) => {}
            Some(None) => warns.push(degraded(
                "unwired_build_logic",
                format!(
                    "{rel}: {snippet} points outside the project root; that build stays unpatched"
                ),
            )),
            None => warns.push(degraded(
                "unwired_build_logic",
                format!("{rel}: {snippet} is not a literal path; that build stays unpatched"),
            )),
        }
    }
    (found, warns)
}

/// `base` joined with the relative path `p`, normalised; `None` when `p` is
/// absolute or leaves the root.
fn resolve_dir(base: &str, p: &str) -> Option<String> {
    if p.starts_with('/') || p.contains('\\') || p.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

// ── in-block pluginManagement entry ──────────────────────────────────────

enum InBlock {
    Unneeded,
    /// The entry is already there (a re-run, or a patch update of the GAV).
    Present,
    /// Replace `text[start..end]` with `text`.
    Edited {
        start: usize,
        end: usize,
        text: String,
    },
    Unwired(String),
}

fn in_block_line(kotlin: bool, prefix: &str, c: &Coords<'_>) -> String {
    let (g, a, v) = (c.group_id, c.artifact_id, c.version);
    let suffix = &sha256_hex(format!("{g}:{a}:{v}").as_bytes())[..16];
    let name = format!("{REPO_NAME}_{suffix}");
    if kotlin {
        format!(
            "exclusiveContent {{ forRepository {{ maven {{ name = \"{name}\"; url = File(settingsDir, \"{prefix}{TREE_ROOT}\").toURI() }} }}; filter {{ includeVersion(\"{g}\", \"{a}\", \"{v}\") }} }} // socket-patch"
        )
    } else {
        format!(
            "exclusiveContent {{ forRepository {{ maven {{ name = '{name}'; url = new File(settingsDir, '{prefix}{TREE_ROOT}').toURI() }} }}; filter {{ includeVersion('{g}', '{a}', '{v}') }} }} // socket-patch"
        )
    }
}

/// Settings-level `plugins{}` resolves before the apply line runs, so the
/// patched GAV gets its own first entry in `pluginManagement.repositories`.
fn scoped_in_block_entry(
    text: &str,
    kotlin: bool,
    prefix: &str,
    patch: &Coords<'_>,
    scope: &str,
) -> InBlock {
    let toks = lex(text);
    if scope == "pluginManagement" && find_block(&toks, 0, toks.len(), "plugins").is_none() {
        return InBlock::Unneeded;
    }
    let entry = in_block_line(kotlin, prefix, patch);
    let nl = newline_of(text);
    let unit = indent_unit(text);
    let Some((pm_name, pm_open, pm_close)) = find_block(&toks, 0, toks.len(), scope) else {
        if scope == "buildscript" {
            return InBlock::Unneeded;
        }
        // pluginManagement must be the first statement: after imports only.
        let at = first_statement_offset(text, &toks);
        let block = format!(
            "pluginManagement {{{nl}{unit}repositories {{{nl}{unit}{unit}{entry}{nl}{unit}{unit}gradlePluginPortal(){nl}{unit}}}{nl}}}{nl}"
        );
        return InBlock::Edited {
            start: at,
            end: at,
            text: block,
        };
    };
    if text[toks[pm_open].end..toks[pm_close].start]
        .lines()
        .any(|l| l.trim() == entry)
    {
        return InBlock::Present;
    }
    let pm_indent = line_indent(text, toks[pm_name].start);
    let repos_ref = (pm_open + 1..pm_close).find(|&i| {
        is_ident(toks.get(i), "repositories") && depth_between(&toks, pm_open + 1, i) == 0
    });
    match repos_ref {
        Some(r) if is_punct(toks.get(r + 1), b'{') => {
            let Some(close) = matching_close(&toks, r + 1) else {
                return InBlock::Unwired(
                    "unbalanced pluginManagement.repositories block".to_string(),
                );
            };
            let r_indent = line_indent(text, toks[r].start);
            let inner = format!("{r_indent}{}", nested_unit(&r_indent, &pm_indent, unit));
            let empty = close == r + 2;
            let body = if empty && scope == "pluginManagement" {
                format!("{inner}{entry}{nl}{inner}gradlePluginPortal(){nl}")
            } else {
                format!("{inner}{entry}{nl}")
            };
            insert_after_brace(text, toks[r + 1].end, &body, &r_indent, nl)
        }
        Some(_) => {
            InBlock::Unwired("pluginManagement.repositories is not a literal block".to_string())
        }
        None => {
            let inner = format!("{pm_indent}{}", nested_unit(&pm_indent, "", unit));
            let default_repo = if scope == "pluginManagement" {
                format!("{inner}{unit}gradlePluginPortal(){nl}")
            } else {
                String::new()
            };
            let body = format!(
                "{inner}repositories {{{nl}{inner}{unit}{entry}{nl}{default_repo}{inner}}}{nl}"
            );
            insert_after_brace(text, toks[pm_open].end, &body, &pm_indent, nl)
        }
    }
}

fn depth_between(toks: &[Token], from: usize, to: usize) -> isize {
    toks[from..to].iter().fold(0, |d, t| match t.tok {
        Tok::Punct(b'{') => d + 1,
        Tok::Punct(b'}') => d - 1,
        _ => d,
    })
}

/// Insert `body` (whole lines) right after the `{` ending at `brace_end`.
/// When code follows the brace on its line, that code moves to its own line.
fn insert_after_brace(text: &str, brace_end: usize, body: &str, indent: &str, nl: &str) -> InBlock {
    let eol = text[brace_end..]
        .find('\n')
        .map_or(text.len(), |j| brace_end + j);
    let rest = text[brace_end..eol].trim_end_matches('\r').trim();
    if rest.is_empty() || rest.starts_with("//") {
        let at = if eol < text.len() { eol + 1 } else { eol };
        let lead = if eol == text.len() { nl } else { "" };
        return InBlock::Edited {
            start: at,
            end: at,
            text: format!("{lead}{body}"),
        };
    }
    let code_at = brace_end
        + (text[brace_end..].len() - text[brace_end..].trim_start_matches([' ', '\t']).len());
    let unit = indent_unit(text);
    InBlock::Edited {
        start: brace_end,
        end: code_at,
        text: format!("{nl}{body}{indent}{unit}"),
    }
}

/// The indentation step a nested block uses, from the enclosing two.
fn nested_unit<'a>(inner: &'a str, outer: &str, fallback: &'a str) -> &'a str {
    match inner.strip_prefix(outer) {
        Some(step) if !step.is_empty() => step,
        _ => fallback,
    }
}

/// The file's indentation unit: a tab when some line starts with one, else
/// the smallest non-zero leading-space run (4 when none).
fn indent_unit(text: &str) -> &'static str {
    if text.lines().any(|l| l.starts_with('\t')) {
        return "\t";
    }
    let min = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start_matches(' ').len())
        .filter(|&n| n > 0)
        .min()
        .unwrap_or(4);
    ["  ", "  ", "  ", "   ", "    "][min.clamp(2, 4)]
}

fn line_indent(text: &str, at: usize) -> String {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    text[start..at]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// Byte offset of the start of the first line holding code other than an
/// `import` (Kotlin and Groovy both require imports first).
fn first_statement_offset(text: &str, toks: &[Token]) -> usize {
    let mut i = 0;
    while is_ident(toks.get(i), "import") {
        let line_end = text[toks[i].start..]
            .find('\n')
            .map_or(text.len(), |j| toks[i].start + j);
        while i < toks.len() && toks[i].start < line_end {
            i += 1;
        }
    }
    match toks.get(i) {
        Some(t) => text[..t.start].rfind('\n').map_or(0, |j| j + 1),
        None => text.len(),
    }
}

// ── tree marker and index ───────────────────────────────────────────────────────

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// The marker: sorted keys, 2-space indent, trailing newline.
fn marker_json(patch: &JvmPatch<'_>, files: &[(&str, &[u8])]) -> String {
    let mut out = String::from("{\n  \"files\": {");
    for (n, (name, bytes)) in files.iter().enumerate() {
        out.push_str(if n == 0 { "\n" } else { ",\n" });
        out.push_str(&format!(
            "    {}: {{\n      \"sha256\": \"{}\",\n      \"size\": {}\n    }}",
            json_str(name),
            sha256_hex(bytes),
            bytes.len()
        ));
    }
    let purl = format!(
        "pkg:maven/{}/{}@{}",
        patch.group_id, patch.artifact_id, patch.version
    );
    out.push_str(&format!(
        "\n  }},\n  \"purl\": {},\n  \"schema\": 1,\n  \"tool\": \"gradle\",\n  \"uuid\": {},\n  \"version\": {}\n}}\n",
        json_str(&purl),
        json_str(patch.uuid),
        json_str(patch.version)
    ));
    out
}

/// Whether an existing index row is one the script would accept.
fn valid_index_row(row: &str) -> bool {
    let cols: Vec<&str> = row.split('\t').collect();
    let [gav, path, sha, uuid] = cols.as_slice() else {
        return false;
    };
    let parts: Vec<&str> = gav.split(':').collect();
    let [g, a, v] = parts.as_slice() else {
        return false;
    };
    let dir = format!("{}/{a}/{v}/", g.replace('.', "/"));
    safe_coordinates(g, a, v)
        && path
            .strip_prefix(&dir)
            .is_some_and(|n| n.starts_with(&format!("{a}-{v}")) && !n.contains('/'))
        && sha.len() == 64
        && sha
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && !uuid.is_empty()
        && !uuid.chars().any(char::is_whitespace)
}

/// Merge `rows` for `gav` into the existing index, replacing that GAV's
/// rows. A malformed existing index is refused rather than rewritten.
fn merge_index(
    existing: Option<&[u8]>,
    gav: &str,
    rows: Vec<String>,
) -> Result<String, JvmRefusal> {
    let bad = |why: String| {
        shape_refusal(
            "build_file_unreadable",
            format!("{INDEX_REL}: {why}; restore it from git"),
        )
    };
    let mut all: BTreeSet<String> = BTreeSet::new();
    if let Some(bytes) = existing {
        let text = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8".to_string()))?;
        let mut lines = text.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
        if lines.next() != Some(INDEX_HEADER) {
            return Err(bad("unknown header".to_string()));
        }
        for (n, line) in lines.enumerate() {
            if line.is_empty() {
                continue;
            }
            if !valid_index_row(line) {
                return Err(bad(format!("malformed row {}", n + 2)));
            }
            if line.split('\t').next() != Some(gav) {
                all.insert(line.to_string());
            }
        }
    }
    all.extend(rows);
    let mut out = format!("{INDEX_HEADER}\n");
    for row in all {
        out.push_str(&row);
        out.push('\n');
    }
    Ok(out)
}

// ── gradle/verification-metadata.xml ─────────────────────────────────────

struct ArtifactHashes {
    jar: String,
    pom: String,
    module: Option<String>,
}

/// Whether Gradle may verify metadata of the vendored pom's parent chain or
/// imported platforms that the file does not list (read from the file
/// repository, the pom is parsed before the `.module` redirect). A parent
/// the file already lists is fine; imports and platforms always warn.
pub(crate) fn verifies_metadata(verification: &str) -> bool {
    let masked = mask_xml_comments(verification);
    !xml_elements(&masked, 0, masked.len(), "verify-metadata")
        .iter()
        .any(|&(_, tag_end, end)| {
            end > tag_end && masked[tag_end..end - "</verify-metadata>".len()].trim() == "false"
        })
}

fn unverified_parent_chain(verification: &str, pom: &str, module: Option<&[u8]>) -> bool {
    let vm = mask_xml_comments(verification);
    if !verifies_metadata(&vm) {
        return false;
    }
    let masked = mask_xml_comments(pom);
    if masked.contains("<scope>import</scope>")
        || module.is_some_and(|m| String::from_utf8_lossy(m).contains("\"platform\""))
    {
        return true;
    }
    let Some(&(_, tag_end, end)) = xml_elements(&masked, 0, masked.len(), "parent").first() else {
        return false;
    };
    let child = |name: &str| {
        let (open, close) = (format!("<{name}>"), format!("</{name}>"));
        let body = &masked[tag_end..end];
        let s = body.find(&open)? + open.len();
        body[s..]
            .find(&close)
            .map(|e| body[s..s + e].trim().to_string())
    };
    let (Some(g), Some(a), Some(v)) = (child("groupId"), child("artifactId"), child("version"))
    else {
        return true;
    };
    !xml_elements(&vm, 0, vm.len(), "component")
        .iter()
        .any(|&(s, t, _)| {
            let tag = &vm[s..t];
            xml_attr(tag, "group") == Some(g.as_str())
                && xml_attr(tag, "name") == Some(a.as_str())
                && xml_attr(tag, "version") == Some(v.as_str())
        })
}

/// `text` with every `<!-- … -->` replaced by spaces (same byte offsets), so
/// commented-out elements are never matched.
fn mask_xml_comments(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut from = 0;
    while let Some(j) = text[from..].find("<!--") {
        let start = from + j;
        let end = text[start..]
            .find("-->")
            .map_or(text.len(), |k| start + k + 3);
        for b in &mut bytes[start..end] {
            if *b != b'\n' && *b != b'\r' {
                *b = b' ';
            }
        }
        from = end;
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// The value of attribute `name` in the start tag `tag`.
fn xml_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = tag;
    loop {
        let at = rest.find(name)?;
        let before = rest[..at].chars().last();
        let after = rest[at + name.len()..].trim_start();
        rest = &rest[at + name.len()..];
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(after) = after.strip_prefix('=') else {
            continue;
        };
        let after = after.trim_start();
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let body = &after[1..];
        return body.find(quote).map(|e| &body[..e]);
    }
}

/// Elements named `name` inside `masked[from..to]`: (start, end of start
/// tag, end of element). Self-closing elements end with their start tag.
fn xml_elements(masked: &str, from: usize, to: usize, name: &str) -> Vec<(usize, usize, usize)> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut i = from;
    while let Some(j) = masked[i..to].find(&open) {
        let s = i + j;
        let next = masked.as_bytes().get(s + open.len()).copied();
        if !matches!(next, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')) {
            i = s + open.len();
            continue;
        }
        let Some(tag_end) = masked[s..to].find('>').map(|k| s + k + 1) else {
            break;
        };
        let end = if masked[..tag_end].ends_with("/>") {
            tag_end
        } else {
            match masked[tag_end..to].find(&close) {
                Some(k) => tag_end + k + close.len(),
                None => break,
            }
        };
        out.push((s, tag_end, end));
        i = end;
    }
    out
}

fn artifact_element(name: &str, sha: &str, indent: &str, unit: &str, nl: &str) -> String {
    format!("<artifact name=\"{name}\">{nl}{indent}{unit}<sha256 value=\"{sha}\" origin=\"socket-patch\"/>{nl}{indent}</artifact>")
}

/// Replace the patched jar's hash in an existing verification file, or add
/// a component for the GAV, as the edit `(start, end, replacement)`.
/// Trusted artifacts and keys are never touched.
fn update_verification(
    text: &str,
    patch: &JvmPatch<'_>,
    h: &ArtifactHashes,
) -> Result<(usize, usize, String), JvmRefusal> {
    update_verification_component(text, patch, h, None)
}

fn update_verification_component(
    text: &str,
    patch: &JvmPatch<'_>,
    h: &ArtifactHashes,
    metadata_extension: Option<&str>,
) -> Result<(usize, usize, String), JvmRefusal> {
    let unparseable = |why: &str| {
        shape_refusal(
            "gradle_verification_unparseable",
            format!("{VERIFICATION_REL}: {why}"),
        )
    };
    let masked = mask_xml_comments(text);
    let nl = newline_of(text);
    const UNIT: &str = "   ";
    let (a, v) = (patch.artifact_id, patch.version);
    let jar_name = format!("{a}-{v}.{}", metadata_extension.unwrap_or("jar"));

    let Some(&(cs_start, cs_tag_end, cs_end)) =
        xml_elements(&masked, 0, masked.len(), "components").first()
    else {
        return Err(unparseable("no <components> element"));
    };
    let self_closing = cs_tag_end == cs_end;
    let comps = if self_closing {
        Vec::new()
    } else {
        xml_elements(&masked, cs_tag_end, cs_end, "component")
    };
    let key = (patch.group_id, a, v);
    for &(s, tag_end, end) in &comps {
        let tag = &masked[s..tag_end];
        let (Some(g), Some(n), Some(ver)) = (
            xml_attr(tag, "group"),
            xml_attr(tag, "name"),
            xml_attr(tag, "version"),
        ) else {
            return Err(unparseable("a <component> lacks group, name or version"));
        };
        if (g, n, ver) != key {
            continue;
        }
        if tag_end == end {
            return Err(unparseable("the patched component is empty"));
        }
        let arts = xml_elements(&masked, tag_end, end, "artifact");
        let comp_indent = line_indent(text, s);
        for &(as_, at_end, ae) in &arts {
            if xml_attr(&masked[as_..at_end], "name") == Some(jar_name.as_str()) {
                if metadata_extension.is_some() {
                    return Ok((as_, ae, text[as_..ae].to_string()));
                }
                let indent = line_indent(text, as_);
                let el = artifact_element(&jar_name, &h.jar, &indent, UNIT, nl);
                return Ok((as_, ae, el));
            }
        }
        // No jar entry: insert one in name order, as Gradle writes them.
        let indent = format!("{comp_indent}{UNIT}");
        let el = artifact_element(&jar_name, &h.jar, &indent, UNIT, nl);
        let before = arts
            .iter()
            .find(|&&(as_, at_end, _)| {
                xml_attr(&masked[as_..at_end], "name").is_some_and(|n| n > jar_name.as_str())
            })
            .map(|&(as_, _, _)| as_);
        let at = before.map_or_else(
            || line_start(text, end - "</component>".len()),
            |as_| line_start(text, as_),
        );
        return Ok((at, at, format!("{indent}{el}{nl}")));
    }

    let cs_indent = line_indent(text, cs_start);
    let comp_indent = comps.first().map_or_else(
        || format!("{cs_indent}{UNIT}"),
        |&(s, _, _)| line_indent(text, s),
    );
    let art_indent = format!("{comp_indent}{UNIT}");
    let mut arts = vec![
        (jar_name.clone(), h.jar.clone()),
        (format!("{a}-{v}.pom"), h.pom.clone()),
    ];
    if metadata_extension.is_some() {
        arts.truncate(1);
    }
    if let Some(m) = &h.module {
        arts.push((format!("{a}-{v}.module"), m.clone()));
    }
    arts.sort();
    let mut comp = format!(
        "{comp_indent}<component group=\"{}\" name=\"{a}\" version=\"{v}\">{nl}",
        patch.group_id
    );
    for (name, sha) in &arts {
        comp.push_str(&format!(
            "{art_indent}{}{nl}",
            artifact_element(name, sha, &art_indent, UNIT, nl)
        ));
    }
    comp.push_str(&format!("{comp_indent}</component>{nl}"));
    if self_closing {
        let el = format!("<components>{nl}{comp}{cs_indent}</components>");
        return Ok((cs_start, cs_end, el));
    }
    let before = comps.iter().find(|&&(s, tag_end, _)| {
        let tag = &masked[s..tag_end];
        (
            xml_attr(tag, "group").unwrap_or(""),
            xml_attr(tag, "name").unwrap_or(""),
            xml_attr(tag, "version").unwrap_or(""),
        ) > key
    });
    let at = match before {
        Some(&(s, _, _)) => line_start(text, s),
        None => line_start(text, cs_end - "</components>".len()),
    };
    Ok((at, at, comp))
}

/// One upstream parent or BOM whose metadata Gradle must verify.
pub(crate) struct MetadataArtifact {
    pub group: String,
    pub artifact: String,
    pub version: String,
    pub bytes: Vec<u8>,
    pub extension: &'static str,
}

/// A recorded parent/BOM must still have its POM verification entry. For entries
/// we inserted, require the recorded checksum; pre-existing policy stays user-owned.
pub(crate) fn metadata_record_present(text: &str, record: &WiringRecord) -> bool {
    let Some(gav) = record
        .key
        .as_deref()
        .and_then(|k| k.strip_prefix("metadata:"))
    else {
        return false;
    };
    let parts: Vec<_> = gav.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return false;
    }
    let masked = mask_xml_comments(text);
    let name = format!(
        "{}-{}.{}",
        parts[1],
        parts[2],
        parts.get(3).unwrap_or(&"pom")
    );
    xml_elements(&masked, 0, masked.len(), "component")
        .iter()
        .any(|&(start, tag_end, end)| {
            let tag = &masked[start..tag_end];
            if xml_attr(tag, "group") != Some(parts[0])
                || xml_attr(tag, "name") != Some(parts[1])
                || xml_attr(tag, "version") != Some(parts[2])
            {
                return false;
            }
            xml_elements(&masked, tag_end, end, "artifact")
                .iter()
                .any(|&(s, t, e)| {
                    if xml_attr(&masked[s..t], "name") != Some(name.as_str()) {
                        return false;
                    }
                    match op_str(record, "to") {
                        None => true,
                        Some(to) => {
                            xml_elements(to, 0, to.len(), "sha256")
                                .iter()
                                .all(|&(hs, ht, _)| {
                                    xml_attr(&to[hs..ht], "value").is_some_and(|hash| {
                                        xml_elements(&masked, t, e, "sha256").iter().any(
                                            |&(cs, ct, _)| {
                                                xml_attr(&masked[cs..ct], "value") == Some(hash)
                                            },
                                        )
                                    })
                                })
                        }
                    }
                })
        })
}

/// Add only missing parent/BOM metadata to an existing verification file.
pub(crate) fn add_verification_metadata(
    read: ReadFn<'_>,
    plan: &mut JvmPlan,
    metadata: &[MetadataArtifact],
) -> Result<(), JvmRefusal> {
    let Some(original) = read(VERIFICATION_REL) else {
        return Ok(());
    };
    let mut bytes = plan
        .writes
        .iter()
        .find(|w| w.rel == VERIFICATION_REL)
        .map(|w| w.bytes.clone())
        .unwrap_or(original);
    for m in metadata {
        let text = String::from_utf8(bytes).map_err(|_| {
            shape_refusal(
                "gradle_verification_unparseable",
                "metadata is not UTF-8".into(),
            )
        })?;
        let patch = JvmPatch {
            group_id: &m.group,
            artifact_id: &m.artifact,
            version: &m.version,
            uuid: "",
            jar: &[],
            upstream_pom: &m.bytes,
            upstream_module: None,
        };
        let sha = sha256_hex(&m.bytes);
        let h = ArtifactHashes {
            jar: sha.clone(),
            pom: sha,
            module: None,
        };
        let (start, end, to) = update_verification_component(&text, &patch, &h, Some(m.extension))?;
        let key = format!(
            "metadata:{}:{}:{}:{}",
            m.group, m.artifact, m.version, m.extension
        );
        if to == text[start..end] {
            plan.records
                .push(adopt(VERIFICATION_REL, VERIFICATION_FRAGMENT_KIND, &key));
        } else {
            plan.records.push(fragment(
                VERIFICATION_REL,
                VERIFICATION_FRAGMENT_KIND,
                &key,
                WiringAction::Added,
                None,
                replace_op(&text[start..end], &to),
            ));
        }
        bytes = format!("{}{to}{}", &text[..start], &text[end..]).into_bytes();
    }
    plan.writes.retain(|w| w.rel != VERIFICATION_REL);
    if read(VERIFICATION_REL).as_deref() != Some(bytes.as_slice()) {
        plan.writes.push(text_write(VERIFICATION_REL, bytes));
    }
    plan.warnings.retain(|w| {
        !w.detail
            .starts_with("reason: verification_parent_chain_unhandled:")
    });
    Ok(())
}

/// Start of the line holding `at`, when only whitespace precedes `at` on it;
/// else `at` itself.
fn line_start(text: &str, at: usize) -> usize {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    if text[start..at].chars().all(|c| c == ' ' || c == '\t') {
        start
    } else {
        at
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::{apply, detect, Shape};
    use super::*;

    const UUID: &str = "5e6f7081-92a3-4b4c-8d5e-6f708192a3b4";
    const GSON_POM: &[u8] =
        b"<project><parent><groupId>com.google.code.gson</groupId><artifactId>gson-parent</artifactId><version>2.10.1</version></parent></project>\n";

    fn patch() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "com.google.code.gson",
            artifact_id: "gson",
            version: "2.10.1",
            uuid: UUID,
            jar: b"PATCHED-JAR",
            upstream_pom: b"<project></project>\n",
            upstream_module: None,
        }
    }

    fn fs(files: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        files
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect()
    }

    fn run(files: &BTreeMap<String, Vec<u8>>, p: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
        let read = |rel: &str| files.get(rel).cloned();
        plan(&read, p)
    }

    /// Apply `plan` onto `files`, returning the new file map.
    fn applied(files: &BTreeMap<String, Vec<u8>>, plan: &JvmPlan) -> BTreeMap<String, Vec<u8>> {
        let mut out = files.clone();
        for w in &plan.writes {
            out.insert(w.rel.clone(), w.bytes.clone());
        }
        out
    }

    fn text_of<'a>(plan: &'a JvmPlan, rel: &str) -> &'a str {
        let w = plan
            .writes
            .iter()
            .find(|w| w.rel == rel)
            .unwrap_or_else(|| panic!("no write for {rel}"));
        std::str::from_utf8(&w.bytes).unwrap()
    }

    fn assert_idempotent(
        files: &BTreeMap<String, Vec<u8>>,
        p: &JvmPatch<'_>,
    ) -> BTreeMap<String, Vec<u8>> {
        let first = run(files, p).unwrap();
        let after = applied(files, &first);
        let again = run(&after, p).unwrap();
        assert!(
            again.writes.is_empty(),
            "re-plan wrote {:?}",
            again.writes.iter().map(|w| &w.rel).collect::<Vec<_>>()
        );
        after
    }

    fn reasons(plan: &JvmPlan) -> Vec<String> {
        plan.warnings
            .iter()
            .map(|w| w.detail.split(':').nth(1).unwrap_or("").trim().to_string())
            .collect()
    }

    #[test]
    fn script_asset_is_sane() {
        assert!(SCRIPT.starts_with("// Generated by socket-patch (vendored mode). Do not edit.\n"));
        assert!(SCRIPT.contains(&format!("'{INDEX_HEADER}'")));
        assert!(SCRIPT.contains(&format!("'{REPO_NAME}'")));
        assert!(SCRIPT.contains(&format!("'{MARKER_NAME}'")));
        assert!(SCRIPT.ends_with("}\n"));
        assert!(!SCRIPT.contains('\t') && !SCRIPT.contains('\r'));
        assert!(SCRIPT.lines().all(|l| l == l.trim_end()));
        assert_eq!(SCRIPT.matches('{').count(), SCRIPT.matches('}').count());
    }

    #[test]
    fn groovy_settings_gets_the_apply_line_and_the_tree() {
        let files = fs(&[("settings.gradle", "rootProject.name = 'x'\ninclude 'app'\n")]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "settings.gradle"),
            "rootProject.name = 'x'\ninclude 'app'\napply from: '.socket/gradle/socket-patch.settings.gradle' // socket-patch\n"
        );
        let rels: Vec<(&str, bool)> = plan
            .writes
            .iter()
            .map(|w| (w.rel.as_str(), w.tree))
            .collect();
        assert_eq!(
            rels,
            vec![
                (".socket/gradle/socket-patch.settings.gradle", false),
                (".socket/vendor/gradle-index.tsv", false),
                (".socket/vendor/gradle/.gitattributes", false),
                (".socket/vendor/gradle/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar", true),
                (".socket/vendor/gradle/com/google/code/gson/gson/2.10.1/gson-2.10.1.pom", true),
                (".socket/vendor/gradle/com/google/code/gson/gson/2.10.1/socket-patch.vendor.json", true),
                ("settings.gradle", false),
            ]
        );
        assert_eq!(
            plan.tree_dir,
            ".socket/vendor/gradle/com/google/code/gson/gson/2.10.1"
        );
        assert_eq!(plan.jar_rel, format!("{}/gson-2.10.1.jar", plan.tree_dir));
        assert_eq!(text_of(&plan, SCRIPT_REL), SCRIPT);
        assert_eq!(
            text_of(&plan, ".socket/vendor/gradle/.gitattributes"),
            "* -text\n"
        );
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
    }

    #[test]
    fn kotlin_settings_crlf_and_missing_newline_are_preserved() {
        let files = fs(&[(
            "settings.gradle.kts",
            "rootProject.name = \"x\"\r\ninclude(\"app\")",
        )]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "settings.gradle.kts"),
            "rootProject.name = \"x\"\r\ninclude(\"app\")\r\napply(from = \".socket/gradle/socket-patch.settings.gradle\") // socket-patch\r\n"
        );
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn tabs_comments_and_unrelated_content_are_untouched() {
        let src = "// apply from: '.socket/gradle/socket-patch.settings.gradle'\n\tinclude 'a' /* x */\n\n";
        let files = fs(&[("settings.gradle", src)]);
        let plan = run(&files, &patch()).unwrap();
        let out = text_of(&plan, "settings.gradle");
        assert_eq!(out, format!("{src}{}\n", apply_line(false, "")));
    }

    #[test]
    fn missing_settings_is_created_in_the_build_script_dsl() {
        let files = fs(&[("build.gradle.kts", "plugins { java }\n")]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "settings.gradle.kts"),
            format!("{}\n", apply_line(true, ""))
        );
        let files = fs(&[("build.gradle", "apply plugin: 'java'\n")]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "settings.gradle"),
            format!("{}\n", apply_line(false, ""))
        );
        assert!(!plan.writes.iter().any(|w| w.rel == "settings.gradle.kts"));
    }

    #[test]
    fn groovy_settings_wins_over_kotlin_like_gradle() {
        let files = fs(&[("settings.gradle", "x\n"), ("settings.gradle.kts", "y\n")]);
        let plan = run(&files, &patch()).unwrap();
        assert!(plan.writes.iter().any(|w| w.rel == "settings.gradle"));
        assert!(!plan.writes.iter().any(|w| w.rel == "settings.gradle.kts"));
    }

    #[test]
    fn replan_is_idempotent_and_keeps_a_reformatted_line() {
        let files = fs(&[
            ("settings.gradle", "include 'a'\n"),
            ("buildSrc/build.gradle", ""),
        ]);
        assert_idempotent(&files, &patch());
        let files = fs(&[(
            "settings.gradle",
            "apply   from: '.socket/gradle/socket-patch.settings.gradle'\ninclude 'a'\n",
        )]);
        let plan = run(&files, &patch()).unwrap();
        assert!(!plan.writes.iter().any(|w| w.rel == "settings.gradle"));
    }

    #[test]
    fn buildsrc_is_wired_with_a_parent_prefix() {
        let files = fs(&[
            ("settings.gradle", ""),
            ("buildSrc/build.gradle.kts", "plugins { `kotlin-dsl` }\n"),
        ]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "buildSrc/settings.gradle.kts"),
            "apply(from = \"../.socket/gradle/socket-patch.settings.gradle\") // socket-patch\n"
        );
        let files = fs(&[
            ("settings.gradle", ""),
            ("buildSrc/settings.gradle", "rootProject.name = 'bs'"),
        ]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "buildSrc/settings.gradle"),
            "rootProject.name = 'bs'\napply from: '../.socket/gradle/socket-patch.settings.gradle' // socket-patch\n"
        );
        let files = fs(&[("settings.gradle", "")]);
        let plan = run(&files, &patch()).unwrap();
        assert!(!plan.writes.iter().any(|w| w.rel.starts_with("buildSrc/")));
    }

    #[test]
    fn literal_include_builds_are_wired_recursively() {
        let files = fs(&[
            (
                "settings.gradle",
                "pluginManagement {\n  includeBuild('build-logic')\n}\nincludeBuild \"tools/./gen/\"\n// includeBuild('commented')\n/* includeBuild('block') */\ndef s = \"includeBuild('in-string')\"\n",
            ),
            ("build-logic/settings.gradle.kts", "includeBuild(\"../nested\")\n"),
            ("nested/build.gradle.kts", ""),
            ("tools/gen/build.gradle", ""),
        ]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(
            text_of(&plan, "build-logic/settings.gradle.kts"),
            "includeBuild(\"../nested\")\napply(from = \"../.socket/gradle/socket-patch.settings.gradle\") // socket-patch\n"
        );
        assert_eq!(
            text_of(&plan, "tools/gen/settings.gradle"),
            "apply from: '../../.socket/gradle/socket-patch.settings.gradle' // socket-patch\n"
        );
        assert_eq!(
            text_of(&plan, "nested/settings.gradle.kts"),
            format!("{}\n", apply_line(true, "../"))
        );
        for bogus in ["commented", "block", "in-string"] {
            assert!(
                !plan.writes.iter().any(|w| w.rel.starts_with(bogus)),
                "{bogus}"
            );
        }
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn non_literal_or_escaping_include_builds_warn() {
        let files = fs(&[(
            "settings.gradle.kts",
            "includeBuild(file(\"x\"))\nincludeBuild(\"$dir/y\")\nincludeBuild(\"../outside\")\nincludeBuild(\"/abs\")\nincludeBuild(\".\")\n",
        )]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(reasons(&plan), vec!["unwired_build_logic"; 4]);
        assert!(plan.warnings.iter().all(|w| w.code == "vendor_jvm_degraded"
            && w.detail.starts_with("reason: unwired_build_logic: ")));
        let wired: Vec<&str> = plan
            .writes
            .iter()
            .filter(|w| !w.rel.starts_with(".socket") && w.rel.contains("settings.gradle"))
            .map(|w| w.rel.as_str())
            .collect();
        assert_eq!(wired, vec!["settings.gradle.kts"]);
    }

    #[test]
    fn resolve_dir_normalises() {
        assert_eq!(resolve_dir("", "a/./b/"), Some("a/b".into()));
        assert_eq!(resolve_dir("x", "../y"), Some("y".into()));
        assert_eq!(resolve_dir("x", "../.."), None);
        assert_eq!(resolve_dir("", "C:/y"), None);
        assert_eq!(resolve_dir("", "a\\b"), None);
        assert_eq!(resolve_dir("", "."), Some(String::new()));
    }

    #[test]
    fn in_block_entry_goes_first_in_plugin_management_repositories() {
        let src = "pluginManagement {\n  repositories {\n    gradlePluginPortal()\n  }\n}\nplugins {\n  id 'org.gradle.toolchains.foojay-resolver-convention' version '0.8.0'\n}\n";
        let files = fs(&[("settings.gradle", src)]);
        let plan = run(&files, &patch()).unwrap();
        let expect = format!(
            "pluginManagement {{\n  repositories {{\n    {}\n    gradlePluginPortal()\n  }}\n}}\nplugins {{\n  id 'org.gradle.toolchains.foojay-resolver-convention' version '0.8.0'\n}}\n{}\n",
            in_block_line(false, "", &patch().coords()),
            apply_line(false, "")
        );
        assert_eq!(text_of(&plan, "settings.gradle"), expect);
        assert!(plan.warnings.is_empty());
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn in_block_entry_on_a_one_line_repositories_block() {
        let src = "pluginManagement {\r\n    repositories { gradlePluginPortal(); mavenCentral() }\r\n}\r\nplugins { id(\"x\") version \"1\" }\r\n";
        let files = fs(&[("settings.gradle.kts", src)]);
        let plan = run(&files, &patch()).unwrap();
        let out = text_of(&plan, "settings.gradle.kts");
        let entry = in_block_line(true, "", &patch().coords());
        assert!(
            out.starts_with(&format!(
                "pluginManagement {{\r\n    repositories {{\r\n        {entry}\r\n        gradlePluginPortal(); mavenCentral() }}\r\n}}\r\n"
            )),
            "{out}"
        );
        assert!(entry.contains("includeVersion(\"com.google.code.gson\", \"gson\", \"2.10.1\")"));
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn in_block_creates_plugin_management_after_imports() {
        let src = "import java.io.File\n\nplugins {\n  id(\"x\") version \"1\"\n}\nrootProject.name = \"r\"\n";
        let files = fs(&[("settings.gradle.kts", src)]);
        let plan = run(&files, &patch()).unwrap();
        let entry = in_block_line(true, "", &patch().coords());
        let expect = format!(
            "import java.io.File\n\npluginManagement {{\n  repositories {{\n    {entry}\n    gradlePluginPortal()\n  }}\n}}\nplugins {{\n  id(\"x\") version \"1\"\n}}\nrootProject.name = \"r\"\n{}\n",
            apply_line(true, "")
        );
        assert_eq!(text_of(&plan, "settings.gradle.kts"), expect);
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn in_block_adds_repositories_to_plugin_management_and_keeps_the_portal() {
        let src =
            "pluginManagement {\n    includeBuild('logic')\n}\nplugins { id 'a' version '1' }\n";
        let files = fs(&[("settings.gradle", src), ("logic/settings.gradle", "")]);
        let plan = run(&files, &patch()).unwrap();
        let entry = in_block_line(false, "", &patch().coords());
        assert!(text_of(&plan, "settings.gradle").starts_with(&format!(
            "pluginManagement {{\n    repositories {{\n        {entry}\n        gradlePluginPortal()\n    }}\n    includeBuild('logic')\n}}\n"
        )));
        let src = "pluginManagement { repositories { } }\nplugins { id 'a' version '1' }\n";
        let files = fs(&[("settings.gradle", src)]);
        let out = run(&files, &patch()).unwrap();
        assert!(text_of(&out, "settings.gradle").contains(&format!("{entry}\n")));
        assert!(text_of(&out, "settings.gradle").contains("gradlePluginPortal()"));
        assert_idempotent(&files, &patch());
    }

    #[test]
    fn in_block_entry_in_an_included_build_uses_its_prefix() {
        let files = fs(&[
            ("settings.gradle", "includeBuild('a/b')\n"),
            ("a/b/settings.gradle", "plugins { id 'p' version '1' }\n"),
        ]);
        let plan = run(&files, &patch()).unwrap();
        assert!(text_of(&plan, "a/b/settings.gradle")
            .contains("new File(settingsDir, '../../.socket/vendor/gradle')"));
        assert!(!text_of(&plan, "settings.gradle").contains("pluginManagement"));
    }

    #[test]
    fn project_level_or_commented_plugins_need_no_in_block_entry() {
        let files = fs(&[(
            "settings.gradle",
            "// plugins { id 'x' }\ndef s = 'plugins {'\ngradle.beforeProject { plugins { } }\n",
        )]);
        let plan = run(&files, &patch()).unwrap();
        assert!(!text_of(&plan, "settings.gradle").contains("exclusiveContent"));
    }

    #[test]
    fn non_literal_plugin_management_repositories_warn() {
        let files = fs(&[("settings.gradle", "pluginManagement { repositories.gradlePluginPortal() }\nplugins { id 'a' version '1' }\n")]);
        let plan = run(&files, &patch()).unwrap();
        assert_eq!(reasons(&plan), vec!["settings_plugins_unwired"]);
        assert!(
            text_of(&plan, "settings.gradle").ends_with(&format!("{}\n", apply_line(false, "")))
        );
    }

    #[test]
    fn index_rows_merge_sorted_and_replace_the_same_gav() {
        let other = format!("org.a:b:1\torg/a/b/1/b-1.jar\t{}\tu1", "a".repeat(64));
        let stale = format!("com.google.code.gson:gson:2.10.1\tcom/google/code/gson/gson/2.10.1/gson-2.10.1.jar\t{}\told", "b".repeat(64));
        let existing = format!("{INDEX_HEADER}\r\n{stale}\r\n\r\n{other}\r\n");
        let files = fs(&[("settings.gradle", ""), (INDEX_REL, &existing)]);
        let plan = run(&files, &patch()).unwrap();
        let idx = text_of(&plan, INDEX_REL);
        let lines: Vec<&str> = idx.lines().collect();
        assert_eq!(lines[0], INDEX_HEADER);
        assert_eq!(lines.len(), 4);
        assert!(lines[1].starts_with(
            "com.google.code.gson:gson:2.10.1\tcom/google/code/gson/gson/2.10.1/gson-2.10.1.jar\t"
        ));
        assert!(lines[1].ends_with(&format!("\t{UUID}")));
        assert!(lines[1].contains(&sha256_hex(b"PATCHED-JAR")));
        assert!(lines[2].contains("gson-2.10.1.pom"));
        assert_eq!(lines[3], other);
        assert!(!idx.contains('\r') && idx.ends_with('\n'));
        assert!(!idx.contains("\told"));
    }

    #[test]
    fn index_rows_include_the_module() {
        let p = JvmPatch {
            upstream_pom: b"<!-- do_not_remove: published-with-gradle-metadata -->",
            upstream_module: Some(b"{\"formatVersion\":\"1.1\"}"),
            ..patch()
        };
        let files = fs(&[("settings.gradle", "")]);
        let plan = run(&files, &p).unwrap();
        let idx = text_of(&plan, INDEX_REL);
        assert_eq!(idx.lines().count(), 4);
        assert!(idx.contains("gson-2.10.1.module"));
        assert!(plan
            .writes
            .iter()
            .any(|w| w.rel.ends_with("gson-2.10.1.module")
                && w.tree
                && w.bytes == b"{\"formatVersion\":\"1.1\"}"));
    }

    #[test]
    fn malformed_indexes_are_refused() {
        let sha = "c".repeat(64);
        for bad in [
            "garbage\n".to_string(),
            format!("{INDEX_HEADER}\nonly\ttwo\n"),
            format!("{INDEX_HEADER}\ng:a:1+\tg/a/1+/a-1+.jar\t{sha}\tu\n"),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/2/a-1.jar\t{sha}\tu\n"),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/1/../a-1.jar\t{sha}\tu\n"),
            format!(
                "{INDEX_HEADER}\ng:a:1\tg/a/1/a-1.jar\t{}\tu\n",
                "C".repeat(64)
            ),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/1/a-1.jar\t{sha}\t\n"),
        ] {
            let files = fs(&[("settings.gradle", ""), (INDEX_REL, &bad)]);
            let err = run(&files, &patch()).unwrap_err();
            assert_eq!(err.code, "vendor_jvm_shape_unsupported", "{bad}");
            assert!(
                err.detail.starts_with("reason: build_file_unreadable: "),
                "{bad}"
            );
        }
    }

    #[test]
    fn marker_is_sorted_pretty_json() {
        let files = fs(&[("settings.gradle", "")]);
        let plan = run(&files, &patch()).unwrap();
        let rel = format!("{}/{MARKER_NAME}", plan.tree_dir);
        let text = text_of(&plan, &rel);
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["tool"], "gradle");
        assert_eq!(v["uuid"], UUID);
        assert_eq!(v["purl"], "pkg:maven/com.google.code.gson/gson@2.10.1");
        assert_eq!(v["version"], "2.10.1");
        assert_eq!(v["files"]["gson-2.10.1.jar"]["size"], 11);
        assert_eq!(
            v["files"]["gson-2.10.1.jar"]["sha256"],
            sha256_hex(b"PATCHED-JAR")
        );
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(serde_json::to_string_pretty(&v).unwrap() + "\n", text);
    }

    #[test]
    fn unsafe_coordinates_are_refused() {
        let files = fs(&[("settings.gradle", "")]);
        for (g, a, v) in [
            ("com.google", "gson", "2.+"),
            ("com.google", "gson", "latest.release"),
            ("com.google", "gson", "[1,2)"),
            ("com.google", "gson", "1 2"),
            ("com.google", "gson", "1\t2"),
            ("com.google", "gson", "1:2"),
            ("com.google", "gson", ".."),
            ("com.google", "..", "1"),
            ("com..google", "gson", "1"),
            (".com", "gson", "1"),
            ("com/google", "gson", "1"),
            ("com.google", "gs$on", "1"),
            ("", "gson", "1"),
        ] {
            let p = JvmPatch {
                group_id: g,
                artifact_id: a,
                version: v,
                ..patch()
            };
            assert_eq!(
                run(&files, &p).unwrap_err().code,
                "unsafe_coordinates",
                "{g}:{a}:{v}"
            );
        }
        assert!(safe_coordinates(
            "org.apache_x-y",
            "commons.text-2",
            "1.0.0-rc_1+build.2"
        ));
        let p = JvmPatch {
            uuid: "a\tb",
            ..patch()
        };
        assert_eq!(run(&files, &p).unwrap_err().code, "unsafe_coordinates");
    }

    #[test]
    fn module_less_gradle_published_pom_is_refused() {
        let files = fs(&[("settings.gradle", "")]);
        let p = JvmPatch {
            upstream_pom: b"<!-- do_not_remove: published-with-gradle-metadata -->",
            ..patch()
        };
        let err = run(&files, &p).unwrap_err();
        assert_eq!(err.code, "vendor_jvm_upstream_unavailable");
        assert!(err.detail.starts_with("reason: module_unavailable: "));
        let p = JvmPatch {
            upstream_module: Some(b"{\"variants\":[{\"available-at\":{}}]}"),
            ..patch()
        };
        assert!(run(&files, &p)
            .unwrap_err()
            .detail
            .starts_with("reason: android_or_kmp: "));
    }

    #[test]
    fn android_and_kmp_are_refused() {
        for (rel, src) in [
            ("build.gradle", "plugins { id 'com.android.application' version '8.0.0' apply false }"),
            ("build.gradle.kts", "buildscript { dependencies { classpath(\"com.android.tools.build:gradle:8.0.0\") } }"),
            ("settings.gradle.kts", "plugins { kotlin(\"multiplatform\") version \"2.0.0\" apply false }"),
            ("settings.gradle", "plugins { id 'org.jetbrains.kotlin.multiplatform' version '2.0.0' }"),
        ] {
            let files = fs(&[(rel, src)]);
            let err = run(&files, &patch()).unwrap_err();
            assert_eq!(err.code, "vendor_jvm_shape_unsupported", "{rel}");
            assert!(err.detail.starts_with("reason: android_or_kmp: "), "{}", err.detail);
        }
        let files = fs(&[(
            "build.gradle",
            "// id 'com.android.application'\nplugins { id 'java' }\n",
        )]);
        assert!(run(&files, &patch()).is_ok());
    }

    #[test]
    fn user_exclusive_content_for_the_group_is_refused() {
        let files = fs(&[(
            "build.gradle",
            "repositories { exclusiveContent { forRepository { mavenCentral() }\n filter { includeGroup \"com.google.code.gson\" } } }",
        )]);
        let err = run(&files, &patch()).unwrap_err();
        assert!(
            err.detail
                .starts_with("reason: gradle_exclusive_content_conflict: "),
            "{}",
            err.detail
        );
        let files = fs(&[(
            "settings.gradle",
            "dependencyResolutionManagement { repositories { exclusiveContent { forRepository { maven { url 'x' } }; filter { includeGroup 'org.other' } } } }",
        )]);
        assert!(run(&files, &patch()).is_ok());
    }

    #[test]
    fn settings_buildscript_classpath_on_the_ga_is_wired() {
        for src in [
            "buildscript { dependencies { classpath 'com.google.code.gson:gson:2.10.1' } }",
            "buildscript { dependencies { classpath(group = \"com.google.code.gson\", name = \"gson\", version = \"2.10.1\") } }",
        ] {
            let files = fs(&[("settings.gradle", src)]);
            let plan = run(&files, &patch()).unwrap();
            assert!(text_of(&plan, "settings.gradle").contains("exclusiveContent"));
            assert_idempotent(&files, &patch());
        }
        let files = fs(&[(
            "settings.gradle",
            "buildscript { dependencies { classpath 'org.x:y:1' } }",
        )]);
        assert!(run(&files, &patch()).is_ok());
    }

    const VM_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata xmlns=\"https://schema.gradle.org/dependency-verification\">\n   <configuration>\n      <verify-metadata>true</verify-metadata>\n      <verify-signatures>false</verify-signatures>\n      <trusted-artifacts>\n         <trust group=\"com.google.code.gson\"/>\n      </trusted-artifacts>\n   </configuration>\n   <components>\n";
    const VM_TAIL: &str = "   </components>\n</verification-metadata>\n";

    fn vm_component(g: &str, a: &str, v: &str, arts: &[(&str, &str)]) -> String {
        let mut s = format!("      <component group=\"{g}\" name=\"{a}\" version=\"{v}\">\n");
        for (n, sha) in arts {
            s.push_str(&format!("         <artifact name=\"{n}\">\n            <sha256 value=\"{sha}\" origin=\"Generated by Gradle\"/>\n         </artifact>\n"));
        }
        s.push_str("      </component>\n");
        s
    }

    #[test]
    fn verification_jar_entry_is_replaced_in_canonical_form() {
        let before = format!(
            "{VM_HEAD}{}{}{}{VM_TAIL}",
            vm_component("com.google.code.gson", "gson", "2.10.1", &[("gson-2.10.1.jar", "old"), ("gson-2.10.1.pom", "pomsha")]),
            "      <!-- <component group=\"com.google.code.gson\" name=\"gson\" version=\"2.10.1\"> -->\n",
            vm_component("org.z", "z", "1", &[("z-1.jar", "zsha")]),
        );
        let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, &before)]);
        let p = JvmPatch {
            upstream_pom: GSON_POM,
            ..patch()
        };
        let plan = run(&files, &p).unwrap();
        let after = text_of(&plan, VERIFICATION_REL);
        let expect = before.replace(
            "         <artifact name=\"gson-2.10.1.jar\">\n            <sha256 value=\"old\" origin=\"Generated by Gradle\"/>\n         </artifact>",
            &format!(
                "         <artifact name=\"gson-2.10.1.jar\">\n            <sha256 value=\"{}\" origin=\"socket-patch\"/>\n         </artifact>",
                sha256_hex(b"PATCHED-JAR")
            ),
        );
        assert_ne!(expect, before);
        assert_eq!(after, expect);
        assert!(after.contains("<trust group=\"com.google.code.gson\"/>"));
        assert_eq!(reasons(&plan), vec!["verification_parent_chain_unhandled"]);
        assert_idempotent(&files, &p);
    }

    #[test]
    fn parent_chain_warning_only_when_the_file_may_lack_entries() {
        let listed = vm_component(
            "com.google.code.gson",
            "gson-parent",
            "2.10.1",
            &[("gson-parent-2.10.1.pom", "x")],
        );
        let vm = format!("{VM_HEAD}{listed}{VM_TAIL}");
        assert!(!unverified_parent_chain(
            &vm,
            std::str::from_utf8(GSON_POM).unwrap(),
            None
        ));
        let bare = format!("{VM_HEAD}{VM_TAIL}");
        assert!(unverified_parent_chain(
            &bare,
            std::str::from_utf8(GSON_POM).unwrap(),
            None
        ));
        let off = bare.replace("<verify-metadata>true", "<verify-metadata>false");
        assert!(!unverified_parent_chain(
            &off,
            std::str::from_utf8(GSON_POM).unwrap(),
            None
        ));
        assert!(unverified_parent_chain(&vm, "<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>${v}</version></parent></project>", None));
        assert!(unverified_parent_chain(
            &vm,
            "<project><dependency><scope>import</scope></dependency></project>",
            None
        ));
        assert!(unverified_parent_chain(
            &vm,
            "<project/>",
            Some(b"{\"attributes\":{\"org.gradle.category\":\"platform\"}}")
        ));
        assert!(!unverified_parent_chain(
            &vm,
            "<project><!-- <parent></parent> --></project>",
            None
        ));
    }

    #[test]
    fn verification_component_is_inserted_sorted() {
        let before = format!(
            "{VM_HEAD}{}{}{VM_TAIL}",
            vm_component("com.a", "a", "1", &[("a-1.jar", "x")]),
            vm_component("org.z", "z", "1", &[("z-1.jar", "zsha")]),
        )
        .replace('\n', "\r\n");
        let p = JvmPatch {
            upstream_pom: b"<!-- do_not_remove: published-with-gradle-metadata -->",
            upstream_module: Some(b"{}"),
            ..patch()
        };
        let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, &before)]);
        let plan = run(&files, &p).unwrap();
        let after = text_of(&plan, VERIFICATION_REL);
        let comp = vm_component(
            "com.google.code.gson",
            "gson",
            "2.10.1",
            &[
                ("gson-2.10.1.jar", &sha256_hex(b"PATCHED-JAR")),
                ("gson-2.10.1.module", &sha256_hex(b"{}")),
                ("gson-2.10.1.pom", &sha256_hex(p.upstream_pom)),
            ],
        )
        .replace("Generated by Gradle", "socket-patch")
        .replace('\n', "\r\n");
        let at = before.find("      <component group=\"org.z\"").unwrap();
        assert_eq!(after, format!("{}{comp}{}", &before[..at], &before[at..]));
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_idempotent(&files, &p);
    }

    #[test]
    fn verification_component_appended_last_or_into_empty_components() {
        let before = format!(
            "{VM_HEAD}{}{VM_TAIL}",
            vm_component("com.a", "a", "1", &[("a-1.jar", "x")])
        );
        let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, &before)]);
        let after = assert_idempotent(&files, &patch());
        let text = String::from_utf8(after[VERIFICATION_REL].clone()).unwrap();
        assert!(text.contains("      </component>\n      <component group=\"com.google.code.gson\" name=\"gson\" version=\"2.10.1\">\n         <artifact name=\"gson-2.10.1.jar\">\n"));
        assert!(text.ends_with("      </component>\n   </components>\n</verification-metadata>\n"));

        let before = "<verification-metadata>\n   <components/>\n</verification-metadata>\n";
        let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, before)]);
        let after = assert_idempotent(&files, &patch());
        let text = String::from_utf8(after[VERIFICATION_REL].clone()).unwrap();
        assert!(text.starts_with("<verification-metadata>\n   <components>\n      <component group=\"com.google.code.gson\""));
        assert!(text.ends_with("      </component>\n   </components>\n</verification-metadata>\n"));
    }

    #[test]
    fn verification_jar_entry_added_to_a_component_without_one() {
        let before = format!(
            "{VM_HEAD}{}{VM_TAIL}",
            vm_component(
                "com.google.code.gson",
                "gson",
                "2.10.1",
                &[("gson-2.10.1.pom", "p")]
            )
        );
        let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, &before)]);
        let after = assert_idempotent(&files, &patch());
        let text = String::from_utf8(after[VERIFICATION_REL].clone()).unwrap();
        let jar = text.find("gson-2.10.1.jar").unwrap();
        assert!(jar < text.find("gson-2.10.1.pom").unwrap());
        assert!(text
            .contains("         <artifact name=\"gson-2.10.1.jar\">\n            <sha256 value="));
    }

    #[test]
    fn unparseable_verification_is_refused() {
        for bad in ["<verification-metadata/>", "<verification-metadata><components><component name=\"x\"></component></components></verification-metadata>"] {
            let files = fs(&[("settings.gradle", ""), (VERIFICATION_REL, bad)]);
            let err = run(&files, &patch()).unwrap_err();
            assert!(err.detail.starts_with("reason: gradle_verification_unparseable: "), "{}", err.detail);
        }
    }

    #[test]
    fn no_verification_file_is_created() {
        let files = fs(&[("settings.gradle", "")]);
        let plan = run(&files, &patch()).unwrap();
        assert!(!plan.writes.iter().any(|w| w.rel == VERIFICATION_REL));
    }

    #[test]
    fn detect_routes_gradle_only_roots_here() {
        let files = fs(&[("build.gradle", "")]);
        let read = |rel: &str| files.get(rel).cloned();
        assert_eq!(detect(&read), Shape::Gradle);
    }

    #[test]
    fn lexer_handles_strings_comments_and_escapes() {
        let toks = lex("a '''x\n'y''' \"\\\"q\" /* } */ 'it\\'s' \"${b}\" // }\n{");
        let kinds: Vec<Tok> = toks.into_iter().map(|t| t.tok).collect();
        assert_eq!(
            kinds,
            vec![
                Tok::Ident("a".into()),
                Tok::Str {
                    value: "x\n'y".into(),
                    literal: true
                },
                Tok::Str {
                    value: "\"q".into(),
                    literal: true
                },
                Tok::Str {
                    value: "it's".into(),
                    literal: true
                },
                Tok::Str {
                    value: "${b}".into(),
                    literal: false
                },
                Tok::Punct(b'{'),
            ]
        );
    }

    #[tokio::test]
    async fn written_plan_reverts_byte_exact() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("settings.gradle"), "rootProject.name = 'x'\r\n").unwrap();
        let read = |rel: &str| apply::read_project_file(root, rel);
        let p = plan(&read, &patch()).unwrap();
        let records = apply::write_plan(root, &p).await.unwrap();
        assert!(root.join(&p.jar_rel).is_file());
        let again = plan(&read, &patch()).unwrap();
        assert!(again.writes.is_empty());
        let entry = super::super::testing::entry(&patch(), records);
        let out = apply::revert(root, &entry, crate::vendor::RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{:?}", out);
        assert_eq!(
            std::fs::read(root.join("settings.gradle")).unwrap(),
            b"rootProject.name = 'x'\r\n"
        );
        assert!(!root.join(".socket").exists());
    }

    // ── revert, peers and patch updates (disk round-trips) ──

    use super::super::testing;

    const UUID_B: &str = "abcdef01-92a3-4b4c-8d5e-6f708192a3b4";

    fn patch_b() -> JvmPatch<'static> {
        JvmPatch {
            group_id: "org.example",
            artifact_id: "lib",
            version: "2.0",
            uuid: UUID_B,
            jar: b"B-JAR",
            upstream_pom: b"<project></project>\n",
            upstream_module: None,
        }
    }

    fn replan_writes(root: &std::path::Path, p: &JvmPatch<'_>) -> Vec<String> {
        let reader = apply::ProjectReader::new(root);
        plan(&|rel: &str| reader.read(rel), p)
            .unwrap()
            .writes
            .into_iter()
            .map(|w| w.rel)
            .collect()
    }

    /// Reverting either of two patches leaves the other fully wired (apply
    /// line, script, index rows, in-block shell, `.gitattributes`: a re-plan
    /// writes nothing), and reverting both restores every byte and
    /// directory — for plain, settings-`plugins{}`, one-line
    /// `pluginManagement` and verification-file shapes.
    #[tokio::test]
    async fn two_patches_revert_in_either_order_byte_exact() {
        let vm = format!(
            "{VM_HEAD}{}{}{VM_TAIL}",
            vm_component(
                "com.google.code.gson",
                "gson",
                "2.10.1",
                &[("gson-2.10.1.jar", "old"), ("gson-2.10.1.pom", "p")]
            ),
            vm_component("org.z", "z", "1", &[("z-1.jar", "zsha")]),
        );
        let shapes: Vec<Vec<(&str, String)>> = vec![
            vec![("settings.gradle", "rootProject.name = 'x'\r\n".to_string())],
            vec![(
                "settings.gradle.kts",
                "import java.io.File\n\nplugins {\n    id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"0.8.0\"\n}\nrootProject.name = \"x\"".to_string(),
            )],
            vec![(
                "settings.gradle",
                "pluginManagement { repositories { mavenCentral() } }\nplugins { id 'x' version '1' }\n".to_string(),
            )],
            vec![
                ("settings.gradle", "plugins {\n\tid 'x' version '1'\n}\n".to_string()),
                (VERIFICATION_REL, vm.clone()),
                ("buildSrc/build.gradle.kts", String::new()),
            ],
        ];
        for files in &shapes {
            for first_a in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path();
                let borrowed: Vec<(&str, &str)> =
                    files.iter().map(|(r, b)| (*r, b.as_str())).collect();
                testing::populate(root, &borrowed);
                let (pristine, pristine_dirs) = (testing::snapshot(root), testing::dirs(root));
                let mut ledger = BTreeMap::new();
                let (pa, pb) = (patch(), patch_b());
                let plan_a = testing::vendor(root, Shape::Gradle, &pa, &mut ledger)
                    .await
                    .unwrap();
                let plan_b = testing::vendor(root, Shape::Gradle, &pb, &mut ledger)
                    .await
                    .unwrap();
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
                    "{files:?} first_a={first_a}: the remaining patch lost wiring: {:?}",
                    replan_writes(root, second)
                );
                assert!(root.join(&second_plan.jar_rel).is_file());
                let index = std::fs::read_to_string(root.join(INDEX_REL)).unwrap();
                assert!(!index.contains(first.uuid), "{index}");
                let out = testing::revert(root, second, &mut ledger).await;
                assert!(out.success && out.warnings.is_empty(), "{out:?}");
                assert_eq!(
                    testing::snapshot(root),
                    pristine,
                    "{files:?} first_a={first_a}"
                );
                assert_eq!(
                    testing::dirs(root),
                    pristine_dirs,
                    "{files:?} first_a={first_a}"
                );
            }
        }
    }

    /// A patch update (same GAV, new uuid) rewrites the tree in place, the
    /// index rows and the verification hash, keeps the wiring (the in-block
    /// shell and the user's verification element carried from the earlier
    /// entry), and reverts to pristine.
    #[tokio::test]
    async fn patch_update_keeps_the_wiring_and_reverts_pristine() {
        let vm = format!(
            "{VM_HEAD}{}{VM_TAIL}",
            vm_component(
                "com.google.code.gson",
                "gson",
                "2.10.1",
                &[("gson-2.10.1.jar", "old")]
            ),
        );
        let shapes: [&[(&str, &str)]; 3] = [
            &[("settings.gradle", "rootProject.name = 'x'\n")],
            &[("settings.gradle", "plugins {\n  id 'x' version '1'\n}\n")],
            &[("settings.gradle", ""), (VERIFICATION_REL, &vm)],
        ];
        for files in shapes {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            testing::populate(root, files);
            let pristine = testing::snapshot(root);
            let mut ledger = BTreeMap::new();
            testing::vendor(root, Shape::Gradle, &patch(), &mut ledger)
                .await
                .unwrap();
            let p2 = JvmPatch {
                uuid: UUID_B,
                jar: b"PATCHED-JAR-2",
                ..patch()
            };
            let plan2 = testing::vendor(root, Shape::Gradle, &p2, &mut ledger)
                .await
                .unwrap();
            assert_eq!(
                std::fs::read(root.join(&plan2.jar_rel)).unwrap(),
                b"PATCHED-JAR-2"
            );
            let index = std::fs::read_to_string(root.join(INDEX_REL)).unwrap();
            assert!(index.contains(UUID_B) && !index.contains(UUID), "{index}");
            assert!(replan_writes(root, &p2).is_empty());
            let out = testing::revert(root, &p2, &mut ledger).await;
            assert!(out.success && out.warnings.is_empty(), "{files:?}: {out:?}");
            assert_eq!(testing::snapshot(root), pristine, "{files:?}");
            assert!(!root.join(".socket").exists());
        }
    }

    #[test]
    fn an_apply_line_inside_a_comment_does_not_count() {
        let line = apply_line(false, "");
        for commented in [
            format!("rootProject.name = 'x'\n/*\n{line}\n*/\n"),
            format!("// {line}\n"),
            format!("def s = \"{}\"\n", line.replace('\'', "\\'")),
        ] {
            let files = fs(&[("settings.gradle", &commented)]);
            let plan = run(&files, &patch()).unwrap();
            assert!(
                text_of(&plan, "settings.gradle").ends_with(&format!("{line}\n")),
                "{commented}"
            );
        }
        for live in [
            "apply from: '.socket/gradle/socket-patch.settings.gradle'\n",
            "apply(from = \".socket/gradle/socket-patch.settings.gradle\")\n",
            "apply   from :  \".socket/gradle/socket-patch.settings.gradle\" // mine\n",
        ] {
            assert!(has_apply_line(live, ""), "{live}");
        }
        assert!(!has_apply_line(
            "apply from: '../.socket/gradle/socket-patch.settings.gradle'\n",
            ""
        ));
    }

    #[tokio::test]
    async fn an_included_build_without_build_files_is_warned_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        testing::populate(root, &[("settings.gradle", "includeBuild('missing')\n")]);
        let mut ledger = BTreeMap::new();
        let plan = testing::vendor(root, Shape::Gradle, &patch(), &mut ledger)
            .await
            .unwrap();
        assert_eq!(reasons(&plan), ["unwired_build_logic"]);
        assert!(!root.join("missing").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_included_build_symlinked_outside_the_checkout_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        testing::populate(
            dir.path(),
            &[("settings.gradle", "includeBuild('build-logic')\n")],
        );
        testing::populate(
            outside.path(),
            &[("settings.gradle", "rootProject.name = 'bl'\n")],
        );
        std::os::unix::fs::symlink(outside.path(), dir.path().join("build-logic")).unwrap();
        let reader = apply::ProjectReader::new(dir.path());
        let _ = plan(&|rel: &str| reader.read(rel), &patch());
        assert_eq!(reader.escaped().as_deref(), Some("build-logic"));
    }

    #[test]
    fn unplan_preserves_a_modified_shared_script() {
        let files = fs(&[("settings.gradle", "")]);
        let p = patch();
        let plan = run(&files, &p).unwrap();
        let mut after = applied(&files, &plan);
        after
            .get_mut(SCRIPT_REL)
            .unwrap()
            .extend_from_slice(b"// user edit\n");
        let undo = unplan(&|rel| after.get(rel).cloned(), &p.coords(), &plan.records);
        assert!(!undo.changes.iter().any(|(rel, _)| rel == SCRIPT_REL));
        assert!(undo.drifted.iter().any(|d| d.contains(SCRIPT_REL)));
    }

    #[test]
    fn unplan_leaves_a_malformed_index_and_keeps_the_tree() {
        let files = fs(&[
            ("settings.gradle", ""),
            (INDEX_REL, "#socket-patch-gradle-index 1\nnot a row\n"),
        ]);
        let read = |rel: &str| files.get(rel).cloned();
        let undo = unplan(&read, &patch().coords(), &[]);
        assert!(undo.still_wired && !undo.drifted.is_empty());
        assert!(undo.changes.is_empty(), "{:?}", undo.changes);
    }
}
