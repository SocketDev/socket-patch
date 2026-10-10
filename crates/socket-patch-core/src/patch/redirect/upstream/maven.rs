//! Maven upstream restore: the inverse of `rewrite_maven_pom`, no network.
//!
//! The hosted rewrite pins `<version><base>-socket.<hex8></version>` (the
//! literal, or an added `<dependencyManagement>` entry for a GA with no
//! literal version), inserts a `<repository>` with id
//! `socket-patch-<uuid>`, and — when both hashes were known — appends the
//! trusted-checksums resolver lines to `.mvn/maven.config` and the
//! suffixed jar/pom lines to `.mvn/checksums/checksums.sha256`.
//!
//! Everything but the `.mvn` provenance is derivable from the pom itself:
//! the base version is the suffix's prefix, and the added blocks have the
//! writer's exact shape. An added `<dependencyManagement>` entry is told
//! from a rewritten one of the user's by that shape and position (right
//! after the section's `<dependencies>`, only authored entries before it),
//! by being the GA's only literal version, and — when the pom declares the
//! GA directly without a version and has no `<parent>` or BOM import to
//! manage it — never (the entry is then what supplies the version, so it
//! was the user's). The `.mvn` files are removed only when they hold
//! nothing but what hosted mode writes; otherwise the resolver lines stay
//! and a warning says so (whether they pre-existed is not recorded).
//! Checksum lines keep the file's remaining order (the rewriter re-sorted
//! and dropped malformed lines; that is not recoverable).

use regex::Regex;

use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::patch::redirect::{
    generation, maven_repositories_with_id, maven_tag_inner_range, maven_tag_text_in,
    remove_maven_repository, MAVEN_DEPENDENCY_BLOCK_RE, MVN_CHECKSUMS, MVN_CONFIG, MVN_CONFIG_ARGS,
};

/// The line break and indent `insert_maven_dependency_management` writes
/// before its entry.
const DM_ENTRY_LEAD: &str = "\n      ";

/// The `<dependencyManagement>` entry `insert_maven_dependency_management`
/// writes, from its `<dependency>` tag on.
fn authored_dm_block(group: &str, artifact: &str, version: &str) -> String {
    format!(
        "<dependency>\n        <groupId>{group}</groupId>\n        <artifactId>{artifact}</artifactId>\n        <version>{version}</version>\n      </dependency>"
    )
}

/// The wrappers the rewriter authors from scratch before `</project>`, as
/// they read once every entry is gone.
const EMPTY_REPOSITORIES: &str = "  <repositories>\n  </repositories>\n</project>";
const EMPTY_DEP_MANAGEMENT: &str =
    "  <dependencyManagement>\n    <dependencies>\n    </dependencies>\n  </dependencyManagement>\n</project>";

/// One `<dependency>` block of a GA.
struct DepMatch {
    start: usize,
    end: usize,
    version: Option<(usize, usize)>,
    version_text: Option<String>,
}

fn dep_matches(pom: &str, group: &str, artifact: &str) -> Vec<DepMatch> {
    MAVEN_DEPENDENCY_BLOCK_RE
        .find_iter(pom)
        .filter(|m| {
            maven_tag_text_in(pom, "groupId", m.start(), m.end()).as_deref() == Some(group)
                && maven_tag_text_in(pom, "artifactId", m.start(), m.end()).as_deref()
                    == Some(artifact)
        })
        .map(|m| {
            let version = maven_tag_inner_range(pom, "version", m.start(), m.end());
            DepMatch {
                start: m.start(),
                end: m.end(),
                version,
                version_text: version.map(|(s, e)| pom[s..e].trim().to_string()),
            }
        })
        .collect()
}

/// Is the block at `start` in the rewriter's insertion position: right
/// after `<dependencyManagement><dependencies>`, with only authored
/// Socket-pinned entries between? `masked` is the pom with comments blanked
/// (offsets kept), so a comment between the two tags — which the rewriter
/// inserts past — reads as the whitespace it is to Maven.
fn after_dm_open(masked: &str, start: usize) -> bool {
    let pom = masked;
    let open = Regex::new(r"(?s)<dependencyManagement>\s*<dependencies>\z")
        .expect("static dependencyManagement-open regex is valid");
    let authored = Regex::new(
        r"\n      <dependency>\n        <groupId>[^<]*</groupId>\n        <artifactId>[^<]*</artifactId>\n        <version>[^<]*-socket\.[0-9a-f]{8}</version>\n      </dependency>\z",
    )
    .expect("static authored-entry regex is valid");
    let Some(mut prefix) = pom[..start].strip_suffix(DM_ENTRY_LEAD) else {
        return false;
    };
    loop {
        if open.is_match(prefix) {
            return true;
        }
        match authored.find(prefix) {
            Some(m) => prefix = &prefix[..m.start()],
            None => return false,
        }
    }
}

/// `(start, end)` of every `<dependencyManagement>` element.
fn dm_sections(pom: &str) -> Vec<(usize, usize)> {
    let re = Regex::new(r"(?s)<dependencyManagement>.*?</dependencyManagement>")
        .expect("static dependencyManagement regex is valid");
    re.find_iter(pom).map(|m| (m.start(), m.end())).collect()
}

/// Remove the `socket-patch-<uuid>` repository of `pom`: the element and
/// the line break before it (the rewriter's own insertion), when it sits
/// on lines of its own.
fn remove_repository(pom: &str, uuid: &str, ctx: &Ctx<'_>) -> Result<String, String> {
    let id = generation::hosted_pin_name(uuid);
    let (start, end) = match maven_repositories_with_id(pom, &id)[..] {
        [one] => one,
        [] => return Err(format!("pom.xml has no <repository> with id {id}")),
        _ => {
            return Err(format!(
                "pom.xml has several <repository> elements with id {id}"
            ))
        }
    };
    let url = maven_tag_text_in(pom, "url", start, end).unwrap_or_default();
    if ctx.hosted_uuid(&url).as_deref() != Some(uuid) {
        return Err(format!(
            "the pom.xml repository {id} does not point at the Socket patch server"
        ));
    }
    remove_maven_repository(pom, &id)
        .ok_or_else(|| format!("the pom.xml repository {id} is not on lines of its own"))
}

/// Restore one pin in `pom`, or say why not.
fn restore_pin(
    pom: &str,
    group: &str,
    artifact: &str,
    base: &str,
    uuid: &str,
    ctx: &Ctx<'_>,
) -> Result<String, String> {
    let suffixed = format!("{base}-socket.{}", &uuid[..8]);
    let mut text = remove_repository(pom, uuid, ctx)?;

    let matches = dep_matches(&text, group, artifact);
    if !matches
        .iter()
        .any(|m| m.version_text.as_deref() == Some(suffixed.as_str()))
    {
        return Err(format!(
            "pom.xml declares no {group}:{artifact} <version>{suffixed}</version>"
        ));
    }
    // The GA's literal versions where Maven reads them for the main jar:
    // not commented out, outside `<build>` / `<reporting>` / `<profiles>`,
    // no classifier — the same scope the rewriter decides "transitive" by.
    let versioned = match crate::formats::maven::PomScope::new(&text).and_then(|s| s.dependencies())
    {
        Ok(deps) => deps
            .iter()
            .filter(|d| {
                d.group.as_deref() == Some(group)
                    && d.artifact.as_deref() == Some(artifact)
                    && !d.in_profile
                    && d.classifier.is_none()
                    && d.version_inner.is_some()
            })
            .count(),
        Err(_) => matches.iter().filter(|m| m.version.is_some()).count(),
    };
    let sections = dm_sections(&text);
    let managed = |pos: usize| sections.iter().any(|(s, e)| pos >= *s && pos < *e);
    // A versionless direct declaration with nothing but this pom's own
    // `<dependencyManagement>` to manage it: that entry is the user's.
    let entry_is_users = matches
        .iter()
        .any(|m| m.version.is_none() && !managed(m.start))
        && !text.contains("<parent>")
        && !text.contains("<scope>import</scope>");

    let masked = crate::formats::xml::blank_non_markup(&text).unwrap_or_else(|_| text.clone());
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for m in matches
        .iter()
        .filter(|m| m.version_text.as_deref() == Some(suffixed.as_str()))
    {
        let authored = versioned == 1
            && !entry_is_users
            && text[m.start..m.end] == authored_dm_block(group, artifact, &suffixed)
            && after_dm_open(&masked, m.start);
        if authored {
            edits.push((m.start - DM_ENTRY_LEAD.len(), m.end, String::new()));
        } else {
            let (s, e) = m
                .version
                .expect("a match with a version text has its range");
            edits.push((s, e, base.to_string()));
        }
    }
    edits.sort_by(|a, b| b.0.cmp(&a.0));
    for (s, e, with) in edits {
        text.replace_range(s..e, &with);
    }

    if text.contains(&suffixed) {
        return Err(format!(
            "pom.xml still names {suffixed} outside a <dependency> version (a property or \
             plugin configuration socket-patch did not write)"
        ));
    }
    let name = generation::hosted_pin_name(uuid);
    if text.contains(&name) {
        return Err(format!("pom.xml still names {name}"));
    }
    Ok(text)
}

/// The `<module>` directories a pom lists (plain relative paths only).
fn modules(pom: &str) -> Vec<String> {
    let re = Regex::new(r"<module>\s*([^<]*?)\s*</module>").expect("static module regex is valid");
    re.captures_iter(pom)
        .map(|c| c[1].trim_end_matches('/').to_string())
        .filter(|m| {
            !m.is_empty()
                && !m.starts_with('/')
                && !m.contains('\\')
                && m.split('/')
                    .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        })
        .collect()
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(original) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let dir = rel
            .rsplit_once('/')
            .map(|(d, _)| format!("{d}/"))
            .unwrap_or_default();
        let module_poms: Vec<String> = modules(&original)
            .into_iter()
            .map(|m| {
                if m.ends_with(".xml") {
                    format!("{dir}{m}")
                } else {
                    format!("{dir}{m}/pom.xml")
                }
            })
            .collect();
        let mut text = original.clone();
        // Checksum-file path prefixes of the restored pins.
        let mut checksum_dirs: Vec<String> = Vec::new();
        let mut restored: Vec<&str> = Vec::new();
        for pin in pins.values().filter(|p| p.files.contains(rel)) {
            let Some((name, base)) = pin.name_version() else {
                result.refuse(&pin.uuid, format!("{} is not a Maven purl", pin.purl));
                continue;
            };
            let Some((group, artifact)) = name.split_once('/') else {
                result.refuse(&pin.uuid, format!("{} names no groupId", pin.purl));
                continue;
            };
            if pin.uuid.len() < 8 {
                result.refuse(&pin.uuid, format!("{} is not a patch uuid", pin.uuid));
                continue;
            }
            let suffixed = format!("{base}-socket.{}", &pin.uuid[..8]);
            let mut in_module = None;
            for module in &module_poms {
                if let Ok(Some(child)) = view.read(module).await {
                    if child.contains(&suffixed)
                        || child.contains(&generation::hosted_pin_name(&pin.uuid))
                    {
                        in_module = Some(module.clone());
                        break;
                    }
                }
            }
            if let Some(module) = in_module {
                result.refuse(
                    &pin.uuid,
                    format!(
                        "the module pom {module} also pins {group}:{artifact} {suffixed}, and \
                         socket-patch restores only the root {rel}"
                    ),
                );
                continue;
            }
            match restore_pin(&text, group, artifact, &base, &pin.uuid, ctx) {
                Ok(next) => {
                    text = next;
                    checksum_dirs.push(format!(
                        "{}/",
                        crate::vendor::jvm::layout::version_dir(group, artifact, &suffixed)
                    ));
                    restored.push(&pin.uuid);
                }
                Err(why) => result.refuse(&pin.uuid, why),
            }
        }
        // The from-scratch wrappers, once emptied (repositories come last).
        for empty in [EMPTY_REPOSITORIES, EMPTY_DEP_MANAGEMENT] {
            if text.contains(empty) && !original.contains(empty) {
                text = text.replacen(empty, "</project>", 1);
            }
        }
        if restored.is_empty() {
            continue;
        }
        if let Err(why) = crate::formats::maven::parse_pom(&text) {
            refuse_all_in(
                &pins,
                rel,
                &mut result,
                format!("restoring {rel} would not leave a readable pom: {why}"),
            );
            continue;
        }
        view.write(rel, text);
        restore_mvn(view, &dir, &checksum_dirs, &mut result).await;
        result
            .handled
            .extend(restored.into_iter().map(str::to_string));
    }
    result
}

/// Drop the restored pins' trusted-checksum lines, and the `.mvn` files
/// themselves when nothing but hosted mode's content is left.
async fn restore_mvn(
    view: &mut View<'_>,
    dir: &str,
    checksum_dirs: &[String],
    result: &mut FormatResult,
) {
    let sums_rel = format!("{dir}{MVN_CHECKSUMS}");
    let config_rel = format!("{dir}{MVN_CONFIG}");
    let Ok(Some(sums)) = view.read(&sums_rel).await else {
        return;
    };
    let path_of = |line: &str| {
        line.trim_end_matches('\r')
            .split_once("  ")
            .map(|(_, p)| p.to_string())
    };
    let kept: Vec<&str> = sums
        .split('\n')
        .filter(|line| {
            !path_of(line).is_some_and(|p| checksum_dirs.iter().any(|d| p.starts_with(d.as_str())))
        })
        .collect();
    let rest = kept.join("\n");
    if rest == sums {
        return;
    }
    let config = view.read(&config_rel).await.ok().flatten();
    let written_config = format!("{}\n", MVN_CONFIG_ARGS.join("\n"));
    let has_resolver_lines = config.as_deref().is_some_and(|c| {
        c.lines()
            .any(|l| MVN_CONFIG_ARGS.contains(&l.trim_end_matches('\r')))
    });
    if rest.trim().is_empty() {
        view.remove(&sums_rel);
        if config.as_deref() == Some(written_config.as_str()) {
            view.remove(&config_rel);
            return;
        }
    } else {
        view.write(&sums_rel, rest.clone());
    }
    let other_hosted = rest.lines().any(|l| {
        path_of(l).is_some_and(|p| {
            p.split('/')
                .any(|seg| crate::formats::maven::split_socket_version(seg).is_some())
        })
    });
    if has_resolver_lines && !other_hosted {
        result.warnings.push((
            "maven_trusted_checksums_left",
            format!(
                "{config_rel} keeps the trusted-checksums resolver lines (`-Daether.…`), which \
                 hosted mode may have added; no hosted pin needs them any more, so remove them \
                 if nothing else does"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{restore_upstream, HostedPin, PinStatus, RestoreOptions, RestoreOutcome};
    use std::collections::BTreeMap;

    const UUID: &str = "77777777-7777-7777-7777-777777777777";
    const SUFFIXED: &str = "1.7.36-socket.77777777";

    fn fixture(case: &str, side: &str, rel: &str) -> String {
        let p = format!(
            "{}/tests/fixtures/redirect/maven/pom/{case}/{side}/{rel}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(p).unwrap()
    }

    /// Restore the slf4j pin (offline: Maven needs no network) over
    /// `files`; the outcome, and the tree after.
    async fn run(files: &[(&str, String)]) -> (RestoreOutcome, BTreeMap<String, String>) {
        let tmp = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let pins = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: UUID.into(),
            files: vec!["pom.xml".into()],
        }];
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
        let mut after = BTreeMap::new();
        for entry in walkdir::WalkDir::new(tmp.path())
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(tmp.path()).unwrap();
                after.insert(
                    rel.to_string_lossy().replace('\\', "/"),
                    std::fs::read_to_string(entry.path()).unwrap(),
                );
            }
        }
        (outcome, after)
    }

    fn refusal(outcome: &RestoreOutcome) -> String {
        match &outcome.pins[0].status {
            PinStatus::Refused(why) => why.clone(),
            PinStatus::Restored => panic!("restored"),
        }
    }

    /// The scope-aware rewrites (#259, #262, #342) restore to their input:
    /// a comment, profile or classifier sibling the rewriter left alone is
    /// left alone again, and a pin added past a comment inside
    /// `<dependencyManagement>` is still recognised as the rewriter's own.
    #[tokio::test]
    async fn scoped_rewrites_round_trip() {
        for case in [
            "comment-dependency",
            "profile-repositories",
            "plugin-dependency",
            "profile-depmgmt",
            "commented-repositories",
            "classifier-sources-sibling",
            "classifier-only-transitive-main",
            "depmgmt-comment",
        ] {
            let (outcome, after) = run(&[("pom.xml", fixture(case, "expected", "pom.xml"))]).await;
            assert!(
                matches!(outcome.pins[0].status, PinStatus::Restored),
                "{case}: {:?}",
                outcome.pins[0].status
            );
            assert_eq!(
                after["pom.xml"],
                fixture(case, "input", "pom.xml"),
                "{case}"
            );
        }
    }

    /// An expanded self-closed section restores to an empty (still single)
    /// section: no Socket markup left, and a pom Maven reads.
    #[tokio::test]
    async fn expanded_self_closed_sections_restore_to_one_empty_section() {
        for (case, tag) in [
            ("self-closed-repositories", "<repositories>"),
            ("self-closed-depmgmt", "<dependencyManagement>"),
        ] {
            let (outcome, after) = run(&[("pom.xml", fixture(case, "expected", "pom.xml"))]).await;
            assert!(
                matches!(outcome.pins[0].status, PinStatus::Restored),
                "{case}: {:?}",
                outcome.pins[0].status
            );
            let pom = &after["pom.xml"];
            assert!(
                !pom.contains("-socket.") && !pom.contains("socket-patch-"),
                "{case}: {pom}"
            );
            assert_eq!(pom.matches(tag).count(), 1, "{case}: {pom}");
            crate::formats::maven::parse_pom(pom).expect("restored pom reads");
        }
    }

    #[tokio::test]
    async fn refusals_change_nothing() {
        let hosted = fixture("basic", "expected", "pom.xml");
        let with_module = hosted.replace(
            "  <packaging>jar</packaging>",
            "  <packaging>pom</packaging>\n  <modules>\n    <module>core</module>\n  </modules>",
        );
        let module_pom = format!("<project><version>{SUFFIXED}</version></project>\n");
        let with_property = hosted.replace(
            "  <packaging>jar</packaging>",
            &format!(
                "  <packaging>jar</packaging>\n  <properties>\n    <slf.v>{SUFFIXED}</slf.v>\n  </properties>"
            ),
        );
        let no_repo = fixture("basic", "input", "pom.xml").replace("1.7.36", SUFFIXED);
        let inline_repo = hosted.replace("\n    <repository>", "<repository>");
        let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
            (
                vec![("pom.xml", with_module), ("core/pom.xml", module_pom)],
                "module pom core/pom.xml also pins",
            ),
            (
                vec![("pom.xml", with_property)],
                "outside a <dependency> version",
            ),
            (vec![("pom.xml", no_repo)], "no <repository> with id"),
            (vec![("pom.xml", inline_repo)], "not on lines of its own"),
            (
                vec![(
                    "pom.xml",
                    hosted.replace(SUFFIXED, "1.7.36-socket.12345678"),
                )],
                "declares no org.slf4j:slf4j-api",
            ),
        ];
        for (files, needle) in cases {
            let (outcome, after) = run(&files).await;
            let why = refusal(&outcome);
            assert!(why.contains(needle), "{needle}: {why}");
            assert!(why.contains("git checkout -- pom.xml"), "{why}");
            for (rel, text) in &files {
                assert_eq!(after.get(*rel), Some(text), "{needle}: {rel}");
            }
        }
    }

    #[tokio::test]
    async fn crlf_pom_round_trips() {
        let input = fixture("basic", "input", "pom.xml").replace('\n', "\r\n");
        let hosted = fixture("basic", "expected", "pom.xml");
        let repos =
            &hosted[hosted.find("  <repositories>").unwrap()..hosted.find("</project>").unwrap()];
        let hosted_crlf = input
            .replace(
                "<version>1.7.36</version>",
                &format!("<version>{SUFFIXED}</version>"),
            )
            .replace("</project>", &format!("{repos}</project>"));
        let (outcome, after) = run(&[("pom.xml", hosted_crlf)]).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after["pom.xml"], input);
    }

    #[tokio::test]
    async fn managed_entry_is_removed_when_a_parent_manages_the_direct_dependency() {
        // No literal version anywhere, a <parent> to manage it: the rewriter
        // added the <dependencyManagement> pin.
        let input = fixture("transitive-depmgmt", "input", "pom.xml")
            .replace(
                "  <modelVersion>4.0.0</modelVersion>\n",
                "  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>p</groupId>\n    <artifactId>p</artifactId>\n    <version>1</version>\n  </parent>\n",
            )
            .replace(
                "  </dependencies>",
                "    <dependency>\n      <groupId>org.slf4j</groupId>\n      <artifactId>slf4j-api</artifactId>\n    </dependency>\n  </dependencies>",
            );
        let hosted = fixture("transitive-depmgmt", "expected", "pom.xml");
        let added = &hosted
            [hosted.find("  <dependencyManagement>").unwrap()..hosted.find("</project>").unwrap()];
        let hosted = input.replace("</project>", &format!("{added}</project>"));
        let (outcome, after) = run(&[("pom.xml", hosted)]).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after["pom.xml"], input);
    }

    #[tokio::test]
    async fn existing_mvn_lines_are_kept_and_warned() {
        let config = format!(
            "-Dmaven.test.skip=true\n{}\n",
            super::MVN_CONFIG_ARGS.join("\n")
        );
        let files = vec![
            ("pom.xml", fixture("basic", "expected", "pom.xml")),
            (".mvn/maven.config", config.clone()),
            (
                ".mvn/checksums/checksums.sha256",
                fixture("basic", "expected", ".mvn/checksums/checksums.sha256"),
            ),
        ];
        let (outcome, after) = run(&files).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after["pom.xml"], fixture("basic", "input", "pom.xml"));
        assert_eq!(after[".mvn/maven.config"], config);
        assert!(!after.contains_key(".mvn/checksums/checksums.sha256"));
        assert!(
            outcome
                .warnings
                .iter()
                .any(|(code, _)| *code == "maven_trusted_checksums_left"),
            "{:?}",
            outcome.warnings
        );
    }

    #[tokio::test]
    async fn other_checksum_lines_keep_their_order() {
        let other = format!(
            "{}  zz/other/1.0/other-1.0.jar\n{}  aa/first/1.0/first-1.0.jar\n",
            "e".repeat(64),
            "f".repeat(64)
        );
        let sums = format!(
            "{other}{}",
            fixture("basic", "expected", ".mvn/checksums/checksums.sha256")
        );
        let files = vec![
            ("pom.xml", fixture("basic", "expected", "pom.xml")),
            (
                ".mvn/maven.config",
                fixture("basic", "expected", ".mvn/maven.config"),
            ),
            (".mvn/checksums/checksums.sha256", sums),
        ];
        let (outcome, after) = run(&files).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after[".mvn/checksums/checksums.sha256"], other);
        assert!(after.contains_key(".mvn/maven.config"));
    }
}
