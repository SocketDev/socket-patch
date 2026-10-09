//! Hosted Gradle upstream restore: the inverse of the hosted Gradle
//! planner (`redirect::gradle`), network-free.
//!
//! Everything the planner wrote is derivable from the owned index: a pin's
//! row names its GA, base and suffixed versions. Per pin, every lock entry
//! of the GA in every build's lock files moves back from the suffixed
//! version to the base (each line keeps its own line ending), the row
//! leaves the index, and the suffixed component leaves
//! `gradle/verification-metadata.xml` when it is still exactly what the
//! planner wrote (otherwise it stays and `gradle_verification_component_left`
//! says so). Once no row is left, the index and the owned script go, every
//! build's apply line goes (a settings file whose apply line is marked
//! `created` goes too when nothing else was added to it; a file the user
//! had, even an empty one, keeps its bytes), and `.socket/gradle/.gitattributes` goes unless the
//! vendored settings script still lives beside it. While rows remain, the
//! index is rewritten and every apply line carries its new digest.
//!
//! A pin the restorer cannot unwind (no row, a row for another package)
//! is refused, and the driver restores the rest without it.

use std::collections::BTreeMap;

use super::{Ctx, FormatResult, HostedPin, View};
use crate::gradle::locks;
use crate::patch::redirect::gradle::{
    apply_line_created, apply_line_span, graph_of, has_component, index_digest, lockfile_paths,
    parse_index, render_index, settings_targets, with_apply_line, without_apply_line,
    without_component, GradleFiles, HostedRow, GITATTRIBUTES, GITATTRIBUTES_REL, HOSTED_INDEX_REL,
    HOSTED_SCRIPT, HOSTED_SCRIPT_REL, MAX_ROUNDS,
};
use crate::utils::line_endings::eol_eq;
use crate::vendor::jvm::gradle as vendored;

const VERIFICATION_REL: &str = vendored::VERIFICATION_REL;

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    _files: &[String],
    _ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let index = match view.read(HOSTED_INDEX_REL).await {
        Ok(Some(text)) => text,
        Ok(None) => {
            for pin in pins {
                result.refuse(&pin.uuid, format!("{HOSTED_INDEX_REL} is missing"));
            }
            return result;
        }
        Err(why) => {
            for pin in pins {
                result.refuse(&pin.uuid, why.clone());
            }
            return result;
        }
    };
    let rows = match parse_index(&index) {
        Ok(rows) => rows,
        Err(why) => {
            for pin in pins {
                result.refuse(&pin.uuid, why.clone());
            }
            return result;
        }
    };
    let files = read_build(view).await;
    let graph = graph_of(&files);
    let lock_paths = lockfile_paths(&graph, &files);

    let mut staged: BTreeMap<String, Option<String>> = BTreeMap::new();
    let current = |staged: &BTreeMap<String, Option<String>>, rel: &str| -> Option<String> {
        match staged.get(rel) {
            Some(text) => text.clone(),
            None => files.get(rel).cloned(),
        }
    };
    let mut remaining: Vec<HostedRow> = rows.clone();
    let mut restored: Vec<HostedRow> = Vec::new();
    for pin in pins {
        let Some(row) = rows.iter().find(|r| r.uuid == pin.uuid) else {
            result.refuse(
                &pin.uuid,
                format!("{HOSTED_INDEX_REL} has no row for patch {}", pin.uuid),
            );
            continue;
        };
        if !crate::utils::purl_key::PurlKey::same(&pin.purl, &row.purl()) {
            result.refuse(
                &pin.uuid,
                format!(
                    "{HOSTED_INDEX_REL} pins {} for patch {}, not {}",
                    row.purl(),
                    pin.uuid,
                    pin.purl
                ),
            );
            continue;
        }
        for rel in &lock_paths {
            let Some(text) = current(&staged, rel) else {
                continue;
            };
            if let Some(next) =
                locks::rewrite_entry(&text, &row.group, &row.artifact, &row.suffixed, &row.base)
            {
                staged.insert(rel.clone(), Some(next));
            }
        }
        if let Some(text) = current(&staged, VERIFICATION_REL) {
            match without_component(&text, row) {
                Some(next) => {
                    staged.insert(VERIFICATION_REL.to_string(), Some(next));
                }
                None if has_component(&text, row) => result.warnings.push((
                    "gradle_verification_component_left",
                    format!(
                        "{VERIFICATION_REL} keeps the {}:{} component, which was changed after \
                         socket-patch added it; remove it if nothing else needs it",
                        row.ga(),
                        row.suffixed
                    ),
                )),
                None => {}
            }
        }
        remaining.retain(|r| r.uuid != row.uuid);
        restored.push(row.clone());
        result.handled.insert(pin.uuid.clone());
    }
    if restored.is_empty() {
        return result;
    }

    let targets = settings_targets(&graph);
    if remaining.is_empty() {
        staged.insert(HOSTED_INDEX_REL.to_string(), None);
        if files
            .get(HOSTED_SCRIPT_REL)
            .is_some_and(|t| eol_eq(t.as_bytes(), HOSTED_SCRIPT.as_bytes()))
        {
            staged.insert(HOSTED_SCRIPT_REL.to_string(), None);
        }
        for t in targets.iter().filter(|t| t.exists) {
            let Some(text) = current(&staged, &t.rel) else {
                continue;
            };
            if apply_line_span(&text, t.dsl, &t.prefix()).is_none() {
                continue;
            }
            let created = apply_line_created(&text, t.dsl, &t.prefix());
            match without_apply_line(&text, t.dsl, &t.prefix()) {
                Some(next)
                    if created && crate::formats::text::strip_bom(&next).trim().is_empty() =>
                {
                    staged.insert(t.rel.clone(), None);
                }
                Some(next) => {
                    staged.insert(t.rel.clone(), Some(next));
                }
                None => {
                    for row in &restored {
                        result.refuse(
                            &row.uuid,
                            format!(
                                "{} applies {HOSTED_SCRIPT_REL} on a line it shares with other \
                                 code",
                                t.rel
                            ),
                        );
                    }
                    return result;
                }
            }
        }
        let vendored_script = files.contains_key(vendored::SCRIPT_REL);
        if !vendored_script
            && files
                .get(GITATTRIBUTES_REL)
                .is_some_and(|t| eol_eq(t.as_bytes(), GITATTRIBUTES.as_bytes()))
        {
            staged.insert(GITATTRIBUTES_REL.to_string(), None);
        }
    } else {
        let text = render_index(&remaining);
        let digest = index_digest(&text);
        staged.insert(HOSTED_INDEX_REL.to_string(), Some(text));
        for t in targets.iter().filter(|t| t.exists) {
            let Some(text) = current(&staged, &t.rel) else {
                continue;
            };
            if apply_line_span(&text, t.dsl, &t.prefix()).is_none() {
                continue;
            }
            if let Some(next) = with_apply_line(&text, t.dsl, &t.prefix(), &digest, false) {
                staged.insert(t.rel.clone(), Some(next));
            }
        }
    }
    for (rel, text) in staged {
        match text {
            Some(text) => view.write(&rel, text),
            None => view.remove(&rel),
        }
    }
    result
}

/// The build's scripts, catalogs and lock files, read through the staged
/// view (directories listed on disk).
async fn read_build(view: &mut View<'_>) -> BTreeMap<String, String> {
    let mut gradle = GradleFiles::default();
    for _ in 0..MAX_ROUNDS {
        let (reads, lists) = gradle.misses();
        if reads.is_empty() && lists.is_empty() {
            break;
        }
        for rel in reads {
            match view.read(&rel).await {
                Ok(Some(text)) => gradle.found(&rel, text),
                _ => gradle.absent(&rel),
            }
        }
        for dir in lists {
            let mut children = Vec::new();
            if let Ok(mut entries) = tokio::fs::read_dir(view.root().join(&dir)).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let is_dir = entry.file_type().await.is_ok_and(|t| t.is_dir());
                    children.push(if is_dir { format!("{name}/") } else { name });
                }
            }
            children.sort();
            gradle.listed(&dir, children);
        }
    }
    gradle.files
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::{restore_upstream, HostedPin, PinStatus, RestoreOptions, RestoreOutcome};
    use crate::patch::redirect::gradle::HOSTED_INDEX_REL;
    use crate::patch::redirect::{
        rewrite_registry_redirect, DepOverride, Integrity, RegistryOverride,
        RegistryOverrideIdentifiers,
    };

    const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
    const UUID2: &str = "0abcdef1-2345-4678-9abc-def012345678";
    const TOKEN: &str = "22222222-3333-4444-8555-666666666666";

    fn dep(uuid: &str, artifact: &str) -> DepOverride {
        let sfx = format!("1.10.0-socket.{}", &uuid[..8]);
        DepOverride {
            ecosystem: "maven".into(),
            name: artifact.into(),
            namespace: Some("com.socketfixture".into()),
            version: "1.10.0".into(),
            token: TOKEN.into(),
            patch_uuid: uuid.into(),
            artifact_url: "https://patch.socket.dev/patch/maven/x.jar".into(),
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: format!(
                    "https://patch.socket.dev/patch-registry/maven/{TOKEN}/{uuid}/maven2"
                ),
                identifiers: RegistryOverrideIdentifiers {
                    name: format!("com.socketfixture/{artifact}"),
                    version: "1.10.0".into(),
                    maven_group_id: Some("com.socketfixture".into()),
                    maven_artifact_id: Some(artifact.into()),
                    maven_suffixed_version: Some(sfx),
                    maven_pom_sha256: Some("b".repeat(64)),
                    maven_module_sha256: Some("d".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha256: Some("a".repeat(64)),
                ..Default::default()
            },
        }
    }

    fn pin(uuid: &str, artifact: &str) -> HostedPin {
        HostedPin {
            purl: format!("pkg:maven/com.socketfixture/{artifact}@1.10.0"),
            uuid: uuid.into(),
            files: vec![HOSTED_INDEX_REL.into()],
        }
    }

    fn tree(root: &std::path::Path) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(root).unwrap();
                out.insert(
                    rel.to_string_lossy().replace('\\', "/"),
                    std::fs::read_to_string(entry.path()).unwrap(),
                );
            }
        }
        out
    }

    /// Wire `input` for `deps`, write it to disk, restore `pins`.
    async fn round_trip(
        input: &[(&str, &str)],
        deps: &[DepOverride],
        pins: &[HostedPin],
    ) -> (
        RestoreOutcome,
        BTreeMap<String, String>,
        BTreeMap<String, String>,
    ) {
        let mut files: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let r = rewrite_registry_redirect(&files, deps);
        for d in deps {
            assert!(
                r.confirmed_gradle_uuids.contains(&d.patch_uuid),
                "{:?}",
                r.warnings
            );
        }
        files.extend(r.files);
        let tmp = tempfile::tempdir().unwrap();
        for (rel, text) in &files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let outcome = restore_upstream(
            tmp.path(),
            pins,
            &RestoreOptions {
                offline: true,
                ..RestoreOptions::default()
            },
        )
        .await;
        (outcome, files, tree(tmp.path()))
    }

    const VM: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<verification-metadata>\r\n   <components>\r\n      <component group=\"org.other\" name=\"x\" version=\"1\">\r\n         <artifact name=\"x-1.jar\">\r\n            <sha256 value=\"1111111111111111111111111111111111111111111111111111111111111111\" origin=\"Generated by Gradle\"/>\r\n         </artifact>\r\n      </component>\r\n   </components>\r\n</verification-metadata>\r\n";

    /// Wire then restore offline: every file is byte-identical again (CRLF
    /// settings and locks, a created buildSrc settings, the verification
    /// component), and the owned files are gone.
    #[tokio::test]
    async fn restore_round_trips_byte_exactly() {
        let input: &[(&str, &str)] = &[
            (
                "settings.gradle",
                "rootProject.name = 'app'\r\ninclude 'lib'\r\n",
            ),
            ("build.gradle", ""),
            (
                "lib/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "lib/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\r\nempty=\r\n",
            ),
            (
                "lib/gradle/dependency-locks/compileClasspath.lockfile",
                "com.socketfixture:victim:1.10.0\n",
            ),
            ("buildSrc/build.gradle.kts", ""),
            ("gradle/verification-metadata.xml", VM),
        ];
        let (outcome, wired, after) =
            round_trip(input, &[dep(UUID, "victim")], &[pin(UUID, "victim")]).await;
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert!(outcome.flush_error.is_none());
        assert!(wired.contains_key("buildSrc/settings.gradle.kts"));
        let want: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(after, want);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    }

    /// #646 review: plan, then discovery, then restore on a build where
    /// one project locks a release above the base. The planner confirms
    /// the pin, discovery still finds it (unattested), and the pin it
    /// names restores byte-exactly, leaving the above-base lock alone.
    #[tokio::test]
    async fn an_above_base_lock_plans_discovers_and_restores() {
        let input: &[(&str, &str)] = &[
            ("settings.gradle", "include 'a', 'b'\n"),
            ("build.gradle", ""),
            (
                "a/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "a/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            (
                "b/gradle.lockfile",
                "com.socketfixture:victim:1.11.0=runtimeClasspath\nempty=\n",
            ),
        ];
        let mut files: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let r = rewrite_registry_redirect(&files, &[dep(UUID, "victim")]);
        assert!(r.confirmed_gradle_uuids.contains(UUID), "{:?}", r.warnings);
        files.extend(r.files);
        let tmp = tempfile::tempdir().unwrap();
        for (rel, text) in &files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let found = crate::vex::discover_patched_refs(tmp.path()).await;
        let pins: Vec<HostedPin> = found
            .refs
            .iter()
            .map(|r| HostedPin {
                purl: r.purl.clone(),
                uuid: r.uuid.clone(),
                files: vec![r.source_file.to_string_lossy().into_owned()],
            })
            .collect();
        assert_eq!(pins, vec![pin(UUID, "victim")], "{:?}", found.diagnostics);
        assert_eq!(found.unattested.len(), 1, "{:?}", found.unattested);
        let outcome = restore_upstream(
            tmp.path(),
            &pins,
            &RestoreOptions {
                offline: true,
                ..RestoreOptions::default()
            },
        )
        .await;
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        let want: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(tree(tmp.path()), want);
    }

    /// A settings file the user had, even an empty or BOM-only one (an
    /// empty `settings.gradle` marks a build root), keeps its bytes; only
    /// a planner-created settings file goes.
    #[tokio::test]
    async fn an_existing_empty_settings_file_survives_the_round_trip() {
        let input: &[(&str, &str)] = &[
            ("settings.gradle", ""),
            (
                "build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            ("buildSrc/build.gradle", ""),
            ("buildSrc/settings.gradle", "\u{feff}"),
        ];
        let (outcome, wired, after) =
            round_trip(input, &[dep(UUID, "victim")], &[pin(UUID, "victim")]).await;
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert!(!wired["settings.gradle"].contains(" created"));
        let want: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(after, want);
        // A created file the user then added to keeps the addition.
        let mut files: BTreeMap<String, String> =
            BTreeMap::from([("build.gradle".to_string(), String::new())]);
        let r = rewrite_registry_redirect(&files, &[dep(UUID, "victim")]);
        files.extend(r.files);
        assert!(files["settings.gradle"].ends_with(" created\n"));
        files.insert(
            "settings.gradle".into(),
            format!("{}rootProject.name = 'x'\n", files["settings.gradle"]),
        );
        let tmp = tempfile::tempdir().unwrap();
        for (rel, text) in &files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let outcome = restore_upstream(
            tmp.path(),
            &[pin(UUID, "victim")],
            &RestoreOptions::default(),
        )
        .await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(
            tree(tmp.path())["settings.gradle"],
            "rootProject.name = 'x'\n"
        );
    }

    /// Restoring one of two pins keeps the other's row, rewrites the digest
    /// and leaves its locks alone.
    #[tokio::test]
    async fn restoring_one_of_two_pins_rewrites_the_digest() {
        let input: &[(&str, &str)] = &[
            ("settings.gradle", "rootProject.name = 'app'\n"),
            (
                "gradle.lockfile",
                "com.socketfixture:other:1.10.0=runtimeClasspath\ncom.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
        ];
        let deps = [dep(UUID, "victim"), dep(UUID2, "other")];
        let (outcome, wired, after) = round_trip(input, &deps, &[pin(UUID, "victim")]).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        let only_other = rewrite_registry_redirect(
            &input
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[dep(UUID2, "other")],
        );
        assert_eq!(after[HOSTED_INDEX_REL], only_other.files[HOSTED_INDEX_REL]);
        assert_eq!(
            after["settings.gradle"],
            only_other.files["settings.gradle"]
        );
        assert_eq!(
            after["gradle.lockfile"],
            only_other.files["gradle.lockfile"]
        );
        assert_ne!(after["settings.gradle"], wired["settings.gradle"]);
    }

    /// A changed verification component stays (with a warning); a pin the
    /// index does not name is refused.
    #[tokio::test]
    async fn edited_component_stays_and_unknown_pins_refuse() {
        let input: &[(&str, &str)] = &[
            ("build.gradle", ""),
            ("gradle/verification-metadata.xml", VM),
        ];
        let mut files: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let r = rewrite_registry_redirect(&files, &[dep(UUID, "victim")]);
        files.extend(r.files);
        let vm = files["gradle/verification-metadata.xml"].replacen(
            "origin=\"socket-patch\"/>",
            "origin=\"socket-patch\"/>\r\n            <pgp value=\"abc\"/>",
            1,
        );
        files.insert("gradle/verification-metadata.xml".into(), vm.clone());
        let tmp = tempfile::tempdir().unwrap();
        for (rel, text) in &files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let outcome = restore_upstream(
            tmp.path(),
            &[pin(UUID, "victim"), pin(UUID2, "other")],
            &RestoreOptions::default(),
        )
        .await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert!(
            matches!(&outcome.pins[1].status, PinStatus::Refused(why) if why.contains("has no row"))
        );
        let after = tree(tmp.path());
        assert_eq!(after["gradle/verification-metadata.xml"], vm);
        assert_eq!(
            outcome.warnings.iter().map(|w| w.0).collect::<Vec<_>>(),
            vec!["gradle_verification_component_left"]
        );
        assert!(!after.contains_key(HOSTED_INDEX_REL));
        assert!(
            !after.contains_key("settings.gradle"),
            "the created settings file goes"
        );
    }
}
