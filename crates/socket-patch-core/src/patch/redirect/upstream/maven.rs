//! Maven upstream restore: the inverse of `rewrite_maven_pom`, no network.
//!
//! The hosted rewrite pins `<version><base>-socket.<hex8></version>` (the
//! literal, or an added `<dependencyManagement>` entry for a GA with no
//! literal version), inserts a `<repository>` with id
//! `socket-patch-<uuid>`, and — when both hashes were known — appends the
//! trusted-checksums resolver lines to `.mvn/maven.config` and the
//! suffixed jar/pom lines to `.mvn/checksums/checksums.sha256`.
//!
//! In a reactor, and for a `${property}` version, the pins are the reactor
//! planner's (`maven_reactor::plan_hosted`), spread over the poms that
//! take them: a pin tagged with its patch uuid, a declaration with the
//! text it replaced recorded beside it, a property holding the suffixed
//! version. Each says what it replaced, and
//! [`unwire_hosted`](crate::vendor::jvm::maven_reactor::unwire_hosted)
//! puts it back, in every pom discovery found the pin in. What follows is
//! the single pom an earlier release pinned, which carries no such mark.
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
//! Every other checksums line keeps its bytes and place (the rewriter
//! leaves them so too; see `trusted_checksums::edit`).

use std::collections::BTreeMap;

use regex::Regex;

use super::{by_uuid, read_or_refuse, Ctx, FormatResult, HostedPin, View};
use crate::formats::maven::trusted_checksums;
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

/// Read from the pom's [`PomScope`](crate::formats::maven::PomScope)
/// dependencies when it is readable as one, so a `${property}` groupId /
/// artifactId the rewriter resolved to the GA (#683) is found again; else
/// by the raw block scan.
fn dep_matches(
    pom: &str,
    scoped: Option<&[crate::formats::maven::ScopedDep]>,
    group: &str,
    artifact: &str,
) -> Vec<DepMatch> {
    if let Some(deps) = scoped {
        return deps
            .iter()
            .filter(|d| {
                d.group.as_deref() == Some(group) && d.artifact.as_deref() == Some(artifact)
            })
            .map(|d| DepMatch {
                start: d.element.start,
                end: d.element.end,
                version: d.version_inner,
                version_text: d.version_text.clone(),
            })
            .collect();
    }
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
fn remove_repository(rel: &str, pom: &str, uuid: &str, ctx: &Ctx<'_>) -> Result<String, String> {
    let id = generation::hosted_pin_name(uuid);
    let (start, end) = match maven_repositories_with_id(pom, &id)[..] {
        [one] => one,
        [] => return Err(format!("{rel} has no <repository> with id {id}")),
        _ => {
            return Err(format!(
                "{rel} has several <repository> elements with id {id}"
            ))
        }
    };
    let url = maven_tag_text_in(pom, "url", start, end).unwrap_or_default();
    if ctx.hosted_uuid(&url).as_deref() != Some(uuid) {
        return Err(format!(
            "the {rel} repository {id} does not point at the Socket patch server"
        ));
    }
    remove_maven_repository(pom, &id)
        .ok_or_else(|| format!("the {rel} repository {id} is not on lines of its own"))
}

/// What [`restore_pin`] took out of one pom.
struct Restored {
    text: String,
    /// The pin's `<repository>` was declared here.
    repository: bool,
    /// A pin, a declaration or a property of the patch was here.
    wiring: bool,
}

/// One pin and where it is restored.
struct PinIn<'a> {
    group: &'a str,
    artifact: &'a str,
    base: &'a str,
    uuid: &'a str,
    /// The project root heads a reactor: its poms are the reactor
    /// planner's to read, none an earlier release pinned.
    reactor: bool,
}

/// Restore one pin in the pom `rel` (`pom`), or say why not.
fn restore_pin(
    rel: &str,
    pom: &str,
    user_properties: &BTreeMap<String, String>,
    pin: &PinIn<'_>,
    ctx: &Ctx<'_>,
) -> Result<Restored, String> {
    let PinIn {
        group,
        artifact,
        base,
        uuid,
        reactor,
    } = *pin;
    let suffixed = format!("{base}-socket.{}", &uuid[..8]);
    let coords = crate::vendor::jvm::Coords {
        group_id: group,
        artifact_id: artifact,
        version: base,
        uuid,
    };
    let name = generation::hosted_pin_name(uuid);
    let repository = !maven_repositories_with_id(pom, &name).is_empty();
    let mut text = match repository {
        true => remove_repository(rel, pom, uuid, ctx)?,
        false => pom.to_string(),
    };
    // What the reactor planner wrote. A pom that carries none of its marks
    // outside a reactor is one an earlier release may have pinned: there an
    // added `<dependencyManagement>` entry is told from a rewritten one
    // below, by its shape; anywhere else every suffixed declaration is a
    // rewritten one.
    let unwire = |text: &str, literals: bool| {
        crate::vendor::jvm::maven_reactor::unwire_hosted(text, &coords, false, literals)
            .map_err(|why| format!("{rel} is not readable as a pom ({why})"))
    };
    let marked = unwire(&text, false)?;
    let legacy = !reactor && marked == text;
    let unwired = match legacy {
        true => marked,
        false => unwire(&text, true)?,
    };
    let mut wiring = unwired != text;
    text = unwired;

    let scoped = crate::formats::maven::PomScope::with_user_properties(&text, user_properties)
        .and_then(|s| s.dependencies());
    let matches = dep_matches(&text, scoped.as_deref().ok(), group, artifact);
    wiring |= matches
        .iter()
        .any(|m| m.version_text.as_deref() == Some(suffixed.as_str()));
    // The GA's suffixed literals where Maven reads them for the main jar:
    // not commented out, outside `<build>` / `<reporting>` / `<profiles>`,
    // no classifier — the same scope the rewriter decides "transitive" by.
    // A lone one in the authored shape is the rewriter's own entry, even
    // beside a declaration at the base version: an earlier release added
    // that entry when it could not read a `${property}` groupId (#683).
    let sections = dm_sections(&text);
    let managed = |pos: usize| sections.iter().any(|(s, e)| pos >= *s && pos < *e);
    // In the same scope: a versionless direct declaration with nothing but
    // this pom's own `<dependencyManagement>` to manage it means that entry
    // is the user's (a commented, plugin, profile or classifier sibling is
    // not such a declaration).
    let (pinned, versionless_direct) = match &scoped {
        Ok(deps) => {
            let main = || {
                deps.iter().filter(|d| {
                    d.group.as_deref() == Some(group)
                        && d.artifact.as_deref() == Some(artifact)
                        && !d.in_profile
                        && d.classifier.is_none()
                })
            };
            (
                main()
                    .filter(|d| d.version_text.as_deref() == Some(suffixed.as_str()))
                    .count(),
                main().any(|d| d.version_inner.is_none() && !managed(d.element.start)),
            )
        }
        Err(_) => (
            matches
                .iter()
                .filter(|m| m.version_text.as_deref() == Some(suffixed.as_str()))
                .count(),
            matches
                .iter()
                .any(|m| m.version.is_none() && !managed(m.start)),
        ),
    };
    let entry_is_users =
        versionless_direct && !text.contains("<parent>") && !text.contains("<scope>import</scope>");

    let masked = crate::formats::xml::blank_non_markup(&text).unwrap_or_else(|_| text.clone());
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for m in matches
        .iter()
        .filter(|m| m.version_text.as_deref() == Some(suffixed.as_str()))
    {
        let authored = pinned == 1
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

    // A comment naming the pin (a commented-out earlier wiring) is inert.
    let live = crate::formats::xml::blank_non_markup(&text).unwrap_or_else(|_| text.clone());
    if live.contains(&suffixed) {
        return Err(format!(
            "{rel} still names {suffixed} outside a <dependency> version (a plugin \
             configuration or other text socket-patch did not write)"
        ));
    }
    if live.contains(&name) {
        return Err(format!("{rel} still names {name}"));
    }
    Ok(Restored {
        text,
        repository,
        wiring,
    })
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::vendor::jvm::maven_reactor::{declares_modules, may_discover_subprojects};
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    // The poms as they are, and as they read once the pins so far are out.
    let mut originals: BTreeMap<String, String> = BTreeMap::new();
    for rel in files {
        if let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await {
            originals.insert(rel.clone(), text);
        }
    }
    let mut texts = originals.clone();
    // `.mvn/maven.config`'s `-D` user properties, which Maven reads over
    // the pom's own when it interpolates a coordinate.
    let config = view.read(MVN_CONFIG).await.ok().flatten();
    let user_properties = config
        .as_deref()
        .map(crate::formats::maven::maven_config_properties)
        .unwrap_or_default();
    let reactor = view
        .read("pom.xml")
        .await
        .ok()
        .flatten()
        .is_some_and(|root| {
            declares_modules(&root) || may_discover_subprojects(&root, config.as_deref())
        });
    // Checksum-file path prefixes of the restored pins.
    let mut checksum_dirs: Vec<String> = Vec::new();
    let mut restored: Vec<&str> = Vec::new();
    for pin in pins.values() {
        // A file that could not be read refused the pin above.
        if pin.files.iter().any(|rel| !originals.contains_key(rel)) {
            continue;
        }
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
        let of = PinIn {
            group,
            artifact,
            base: &base,
            uuid: &pin.uuid,
            reactor,
        };
        // Every pom the pin is wired in, or none: a pin refused in one of
        // its poms is restored in none of them.
        let mut staged: BTreeMap<&String, String> = BTreeMap::new();
        let (mut repository, mut wiring) = (false, false);
        let mut refusal = None;
        for rel in &pin.files {
            let next = restore_pin(rel, &texts[rel], &user_properties, &of, ctx).and_then(|done| {
                let mut text = done.text;
                // The from-scratch wrappers, once emptied (repositories
                // come last).
                for empty in [EMPTY_REPOSITORIES, EMPTY_DEP_MANAGEMENT] {
                    if text.contains(empty) && !originals[rel].contains(empty) {
                        text = text.replacen(empty, "</project>", 1);
                    }
                }
                crate::formats::maven::parse_pom(&text).map_err(|why| {
                    format!("restoring {rel} would not leave a readable pom: {why}")
                })?;
                repository |= done.repository;
                wiring |= done.wiring;
                Ok(text)
            });
            match next {
                Ok(text) => {
                    staged.insert(rel, text);
                }
                Err(why) => {
                    refusal = Some(why);
                    break;
                }
            }
        }
        let poms = pin.files.join(", ");
        let refusal = refusal.or_else(|| {
            if !repository {
                let id = generation::hosted_pin_name(&pin.uuid);
                Some(format!("{poms} has no <repository> with id {id}"))
            } else if !wiring {
                Some(format!(
                    "{poms} declares no {group}:{artifact} <version>{suffixed}</version>"
                ))
            } else {
                None
            }
        });
        if let Some(why) = refusal {
            result.refuse(&pin.uuid, why);
            continue;
        }
        for (rel, text) in staged {
            texts.insert(rel.clone(), text);
        }
        checksum_dirs.push(format!(
            "{}/",
            crate::vendor::jvm::layout::version_dir(group, artifact, &suffixed)
        ));
        restored.push(&pin.uuid);
    }
    if restored.is_empty() {
        return result;
    }
    for (rel, text) in texts {
        if originals[&rel] != text {
            view.write(&rel, text);
        }
    }
    // The Trusted Checksums files, where the rewriter keeps them: at the
    // project root (and beside a pom an earlier release pinned on its own).
    let mut dirs: std::collections::BTreeSet<String> = originals
        .keys()
        .map(|rel| {
            rel.rsplit_once('/')
                .map(|(d, _)| format!("{d}/"))
                .unwrap_or_default()
        })
        .collect();
    dirs.insert(String::new());
    for dir in dirs {
        restore_mvn(view, &dir, &checksum_dirs, &mut result).await;
    }
    result
        .handled
        .extend(restored.into_iter().map(str::to_string));
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
    let rest = trusted_checksums::edit(
        &sums,
        |p| checksum_dirs.iter().any(|d| p.starts_with(d.as_str())),
        &[],
    );
    if rest == sums {
        return;
    }
    let config = view.read(&config_rel).await.ok().flatten();
    let written_config = format!("{}\n", MVN_CONFIG_ARGS.join("\n"));
    // Whether settings hosted mode may have written are left over, read as
    // `trusted_checksums::config_enforces` reads them but by presence: a
    // partial or switched-off set is still lines the user may want gone.
    let has_resolver_lines = config
        .as_deref()
        .is_some_and(trusted_checksums::config_has_written_settings);
    if rest.trim().is_empty() {
        view.remove(&sums_rel);
        if config.as_deref() == Some(written_config.as_str()) {
            view.remove(&config_rel);
            return;
        }
    } else {
        view.write(&sums_rel, rest.clone());
    }
    let other_hosted = trusted_checksums::entries(&rest).any(|e| {
        e.path
            .split('/')
            .any(|seg| crate::formats::maven::split_socket_version(seg).is_some())
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

    fn write_tree(root: &std::path::Path, files: &[(&str, String)]) {
        for (rel, text) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
    }

    fn read_tree(root: &std::path::Path) -> BTreeMap<String, String> {
        let mut after = BTreeMap::new();
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(root).unwrap();
                after.insert(
                    rel.to_string_lossy().replace('\\', "/"),
                    std::fs::read_to_string(entry.path()).unwrap(),
                );
            }
        }
        after
    }

    /// Restore the slf4j pin (offline: Maven needs no network) over
    /// `files`, wired in every pom among them; the outcome, and the tree
    /// after.
    async fn run(files: &[(&str, String)]) -> (RestoreOutcome, BTreeMap<String, String>) {
        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), files);
        let pins = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: UUID.into(),
            files: files
                .iter()
                .map(|(rel, _)| rel.to_string())
                .filter(|rel| rel.ends_with("pom.xml"))
                .collect(),
        }];
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
        (outcome, read_tree(tmp.path()))
    }

    fn refusal(outcome: &RestoreOutcome) -> String {
        match &outcome.pins[0].status {
            PinStatus::Refused(why) => why.clone(),
            other => panic!("{other:?}"),
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

    /// A pin the rewriter wrote on a `${property}` groupId / artifactId
    /// declaration (#683) is found and restored: the round trip gives the
    /// input pom back.
    #[tokio::test]
    async fn property_coordinate_pin_round_trips() {
        let overrides: Vec<crate::patch::redirect::DepOverride> =
            serde_json::from_str(&fixture("basic", ".", "overrides.json")).unwrap();
        for (prop, from, to) in [
            (
                "<g>org.slf4j</g>",
                "<groupId>org.slf4j</groupId>",
                "<groupId>${g}</groupId>",
            ),
            (
                "<a>slf4j-api</a>",
                "<artifactId>slf4j-api</artifactId>",
                "<artifactId>${a}</artifactId>",
            ),
        ] {
            let input = fixture("basic", "input", "pom.xml")
                .replacen(from, to, 1)
                .replacen(
                    "  <dependencies>",
                    &format!("  <properties>{prop}</properties>\n  <dependencies>"),
                    1,
                );
            let files = BTreeMap::from([("pom.xml".to_string(), input.clone())]);
            let rewritten = crate::patch::redirect::rewrite_registry_redirect(&files, &overrides);
            let pom = &rewritten.files["pom.xml"];
            assert!(
                pom.contains(&format!("<version>{SUFFIXED}</version>"))
                    && !pom.contains("<dependencyManagement>"),
                "{to}: {pom}"
            );
            let tree: Vec<(&str, String)> = rewritten
                .files
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect();
            let (outcome, after) = run(&tree).await;
            assert!(
                matches!(outcome.pins[0].status, PinStatus::Restored),
                "{to}: {:?}",
                outcome.pins[0].status
            );
            assert_eq!(after["pom.xml"], input, "{to}");
        }
    }

    /// A pin an earlier release wrote for a `${property}` groupId (#683):
    /// it could not read the declaration, so it added a
    /// `<dependencyManagement>` entry beside the base-version literal. The
    /// entry is still the rewriter's own and is removed, giving the input
    /// pom back.
    #[tokio::test]
    async fn pre_683_managed_pin_beside_a_property_declaration_is_removed() {
        let direct = "<dependency>\n      <groupId>ch.qos.logback</groupId>\n      \
                      <artifactId>logback-classic</artifactId>\n      <version>1.4.14</version>\n    \
                      </dependency>";
        let shadowed = "<dependency>\n      <groupId>${g}</groupId>\n      \
                        <artifactId>slf4j-api</artifactId>\n      <version>1.7.36</version>\n    \
                        </dependency>";
        let with = |pom: String| {
            assert!(pom.contains(direct));
            pom.replacen(direct, shadowed, 1).replacen(
                "  <dependencies>",
                "  <properties><g>org.slf4j</g></properties>\n  <dependencies>",
                1,
            )
        };
        let input = with(fixture("transitive-depmgmt", "input", "pom.xml"));
        let mut tree = vec![(
            "pom.xml",
            with(fixture("transitive-depmgmt", "expected", "pom.xml")),
        )];
        for rel in [".mvn/maven.config", ".mvn/checksums/checksums.sha256"] {
            tree.push((rel, fixture("transitive-depmgmt", "expected", rel)));
        }
        let (outcome, after) = run(&tree).await;
        assert!(
            matches!(outcome.pins[0].status, PinStatus::Restored),
            "{:?}",
            outcome.pins[0].status
        );
        assert_eq!(after["pom.xml"], input);
    }

    /// A versionless sibling Maven does not read for the main jar (in a
    /// comment, a plugin, a profile, or with a classifier) does not make the
    /// rewriter's own `<dependencyManagement>` pin look user-written: the
    /// pin is removed, not rewritten to the base version.
    #[tokio::test]
    async fn versionless_out_of_scope_siblings_keep_the_pin_authored() {
        let sibling = "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>";
        for extra in [
            format!("<!-- {sibling}</dependency> -->"),
            format!("{sibling}<classifier>sources</classifier></dependency>"),
            format!(
                "<build><plugins><plugin><artifactId>p</artifactId><dependencies>{sibling}</dependency></dependencies></plugin></plugins></build>"
            ),
            format!(
                "<profiles><profile><id>x</id><dependencies>{sibling}</dependency></dependencies></profile></profiles>"
            ),
        ] {
            // Beside the project's own (first) `</dependencies>`: inside it
            // for a dependency, right after it otherwise.
            let with = |mut pom: String| {
                let close = "  </dependencies>\n";
                let at = pom.find(close).expect("project dependencies");
                if extra.starts_with("<dependency>") {
                    pom.insert_str(at, &format!("    {extra}\n"));
                } else {
                    pom.insert_str(at + close.len(), &format!("  {extra}\n"));
                }
                pom
            };
            let input = with(fixture("transitive-depmgmt", "input", "pom.xml"));
            let expected = with(fixture("transitive-depmgmt", "expected", "pom.xml"));
            let (outcome, after) = run(&[("pom.xml", expected)]).await;
            assert!(
                matches!(outcome.pins[0].status, PinStatus::Restored),
                "{extra}: {:?}",
                outcome.pins[0].status
            );
            assert_eq!(after["pom.xml"], input, "{extra}");
        }
    }

    /// A commented-out twin of the Socket repository (an earlier wiring the
    /// user commented out) does not block rollback of the live one the
    /// rewriter wrote beside it, and stays as it is.
    #[tokio::test]
    async fn a_commented_repository_twin_does_not_block_restore() {
        let twin = |pom: String| {
            pom.replacen(
                "<id>old-mirror</id>",
                &format!("<id>socket-patch-{UUID}</id>"),
                1,
            )
        };
        let (outcome, after) = run(&[(
            "pom.xml",
            twin(fixture("commented-repositories", "expected", "pom.xml")),
        )])
        .await;
        assert!(
            matches!(outcome.pins[0].status, PinStatus::Restored),
            "{:?}",
            outcome.pins[0].status
        );
        assert_eq!(
            after["pom.xml"],
            twin(fixture("commented-repositories", "input", "pom.xml"))
        );
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
        let with_plugin = hosted.replace(
            "  <packaging>jar</packaging>",
            &format!(
                "  <packaging>jar</packaging>\n  <build>\n    <finalName>app-{SUFFIXED}</finalName>\n  </build>"
            ),
        );
        let no_repo = fixture("basic", "input", "pom.xml").replace("1.7.36", SUFFIXED);
        let inline_repo = hosted.replace("\n    <repository>", "<repository>");
        let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
            (
                vec![("core/pom.xml", module_pom), ("pom.xml", with_module)],
                "core/pom.xml still names",
            ),
            (
                vec![("pom.xml", with_plugin)],
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
            assert!(
                why.contains("git checkout -- ") && why.contains("pom.xml"),
                "{why}"
            );
            for (rel, text) in &files {
                assert_eq!(after.get(*rel), Some(text), "{needle}: {rel}");
            }
        }
    }

    /// What hosted mode writes for slf4j-api over `files` (each module
    /// selecting what `picks` says), discovered again from the tree and
    /// restored: the tree after, which must be `files`.
    async fn round_trip(
        files: &[(&str, String)],
        picks: &[(&str, Result<&str, &str>)],
    ) -> BTreeMap<String, String> {
        use crate::crawlers::maven_selection::MavenSelection;
        use crate::patch::redirect::{
            DepOverride, Integrity, RegistryOverride, RegistryOverrideIdentifiers,
        };
        let before: BTreeMap<String, String> = files
            .iter()
            .map(|(rel, text)| (rel.to_string(), text.clone()))
            .collect();
        let modules: Vec<&str> = files.iter().map(|(rel, _)| *rel).collect();
        let picks: Vec<_> = picks
            .iter()
            .map(|(pom, pick)| (*pom, "org.slf4j", "slf4j-api", *pick))
            .collect();
        let dep = DepOverride {
            ecosystem: "maven".into(),
            name: "slf4j-api".into(),
            namespace: Some("org.slf4j".into()),
            version: "1.7.36".into(),
            token: "tok".into(),
            patch_uuid: UUID.into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch/maven/org.slf4j/slf4j-api/1.7.36/tok/{UUID}/slf4j-api-1.7.36.jar"
            ),
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: format!("https://patch.socket.dev/patch-registry/maven/tok/{UUID}/maven2"),
                identifiers: RegistryOverrideIdentifiers {
                    name: "org.slf4j/slf4j-api".into(),
                    version: "1.7.36".into(),
                    maven_group_id: Some("org.slf4j".into()),
                    maven_artifact_id: Some("slf4j-api".into()),
                    maven_suffixed_version: Some(SUFFIXED.into()),
                    maven_pom_sha256: Some("d".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha256: Some("c".repeat(64)),
                ..Default::default()
            },
        };
        let written = crate::patch::redirect::rewrite_registry_redirect_with_host(
            &before,
            &[dep],
            &BTreeMap::new(),
            None,
            false,
            &std::collections::BTreeSet::new(),
            &Default::default(),
            &crate::formats::cargo::source_replacement::CratesIoSource::Registry,
            Some(&MavenSelection::answering(&modules, &picks)),
        );
        assert!(
            written.files.values().any(|text| text.contains(SUFFIXED)),
            "nothing was pinned: {:?}",
            written.warnings
        );
        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), files);
        let hosted: Vec<(&str, String)> = written
            .files
            .iter()
            .map(|(rel, text)| (rel.as_str(), text.clone()))
            .collect();
        write_tree(tmp.path(), &hosted);

        let view = crate::vendor::lock_inventory::ProjectView::Disk(tmp.path());
        let pins = HostedPin::discover(view, &[]).await;
        assert_eq!(pins.len(), 1, "{pins:?}");
        assert_eq!(
            (pins[0].purl.as_str(), pins[0].uuid.as_str()),
            ("pkg:maven/org.slf4j/slf4j-api@1.7.36", UUID)
        );
        // Every pom hosted mode wrote is one the pin is found in.
        for rel in written.files.keys().filter(|rel| rel.ends_with("pom.xml")) {
            assert!(pins[0].files.contains(rel), "{rel}: {:?}", pins[0].files);
        }
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        let after = read_tree(tmp.path());
        assert_eq!(after, before, "every file is back, and none is left over");
        after
    }

    const REACTOR_ROOT: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
        <groupId>com.example</groupId>\n  <artifactId>root</artifactId>\n  \
        <version>1.0.0</version>\n  <packaging>pom</packaging>\n  <modules>\n    \
        <module>a</module>\n    <module>b</module>\n  </modules>\n</project>\n";

    fn reactor_module(name: &str, dependencies: &str) -> String {
        format!(
            "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
             <groupId>com.example</groupId>\n    <artifactId>root</artifactId>\n    \
             <version>1.0.0</version>\n  </parent>\n  <artifactId>{name}</artifactId>\n  \
             <dependencies>\n{dependencies}  </dependencies>\n</project>\n"
        )
    }

    fn dependency(group: &str, artifact: &str, version: Option<&str>) -> String {
        let version = version.map_or(String::new(), |v| format!("\n      <version>{v}</version>"));
        format!(
            "    <dependency>\n      <groupId>{group}</groupId>\n      \
             <artifactId>{artifact}</artifactId>{version}\n    </dependency>\n"
        )
    }

    /// A reactor's wiring is spread over its poms (a pin in the module
    /// that selects the version, a declaration rewritten where it stands,
    /// the repository in the root, the checksums at the root): restoring
    /// the patch puts every file back byte for byte and leaves none behind.
    #[tokio::test]
    async fn reactor_wiring_round_trips() {
        let logback = dependency("ch.qos.logback", "logback-classic", Some("1.4.14"));
        // A pin in one module's pom; its sibling resolves another version.
        round_trip(
            &[
                ("pom.xml", REACTOR_ROOT.to_string()),
                ("a/pom.xml", reactor_module("a", &logback)),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("2.0.9"))],
        )
        .await;
        // One pin in the root both inherit, beside a declaration.
        round_trip(
            &[
                ("pom.xml", REACTOR_ROOT.to_string()),
                (
                    "a/pom.xml",
                    reactor_module("a", &dependency("org.slf4j", "slf4j-api", Some("1.7.36"))),
                ),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("1.7.36"))],
        )
        .await;
        // The root manages the version in the shape an added entry has:
        // it is the project's own, and stays.
        let managing = REACTOR_ROOT.replace(
            "</project>",
            &format!(
                "  <dependencyManagement>\n    <dependencies>\n  {}    </dependencies>\n  \
                 </dependencyManagement>\n</project>",
                dependency("org.slf4j", "slf4j-api", Some("1.7.36")).replace("\n    ", "\n      ")
            ),
        );
        round_trip(
            &[
                ("pom.xml", managing),
                (
                    "a/pom.xml",
                    reactor_module("a", &dependency("org.slf4j", "slf4j-api", None)),
                ),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("1.7.36"))],
        )
        .await;
    }

    /// A `${property}` version is put back as it was written: the
    /// property's own value, or the declaration's recorded text.
    #[tokio::test]
    async fn property_wiring_round_trips() {
        let pom = |properties: &str, more: &str| {
            format!(
                "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
                 <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  \
                 <version>1.0.0</version>\n  <properties>\n    {properties}\n  </properties>\n  \
                 <dependencies>\n{}{more}  </dependencies>\n</project>\n",
                dependency("org.slf4j", "slf4j-api", Some("${slf4j.version}"))
            )
        };
        let picks = [("pom.xml", Ok("1.7.36"))];
        // Only the patched artifact reads the property.
        round_trip(
            &[("pom.xml", pom("<slf4j.version>1.7.36</slf4j.version>", ""))],
            &picks,
        )
        .await;
        // A sibling reads it too.
        round_trip(
            &[(
                "pom.xml",
                pom(
                    "<slf4j.version>1.7.36</slf4j.version>",
                    &dependency("org.slf4j", "slf4j-simple", Some("${slf4j.version}")),
                ),
            )],
            &picks,
        )
        .await;
        // No pom of the checkout defines it (a parent from a repository).
        round_trip(
            &[(
                "pom.xml",
                pom("<other>1</other>", "").replace(
                    "  <groupId>com.example</groupId>",
                    "  <parent>\n    <groupId>corp</groupId>\n    <artifactId>parent</artifactId>\n    \
                     <version>7</version>\n    <relativePath/>\n  </parent>\n  \
                     <groupId>com.example</groupId>",
                ),
            )],
            &picks,
        )
        .await;
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

    /// The pin's lines go whatever hash a past writer left on them (an SRI
    /// or truncated digest): the unwind must not stop early and leave them.
    #[tokio::test]
    async fn checksums_unwind_drops_owned_lines_whatever_their_hash() {
        let sums = fixture("basic", "expected", ".mvn/checksums/checksums.sha256")
            .replace(&"c".repeat(64), "sha256-q83vEjRWeJA=")
            .replace(&"d".repeat(64), &"d".repeat(40));
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
        assert!(
            !after.contains_key(".mvn/checksums/checksums.sha256"),
            "{:?}",
            after.get(".mvn/checksums/checksums.sha256")
        );
        assert!(!after.contains_key(".mvn/maven.config"));
    }

    /// The unwind reads the checksums file as the rewriter does: the pin's
    /// lines go in any spelling a tool rewrote them to, every other line
    /// (one space, a `*` marker, a comment) keeps its bytes and CRLF, and
    /// a resolver switch in another spelling still counts as left behind.
    #[tokio::test]
    async fn checksums_unwind_reads_every_spelling_and_keeps_crlf() {
        let other = format!(
            "# team pins\r\n{} zz/other/1.0/other-1.0.jar\r\n{} *aa/first/1.0/first-1.0.jar\r\n",
            "e".repeat(64),
            "f".repeat(64)
        );
        let ours = fixture("basic", "expected", ".mvn/checksums/checksums.sha256")
            .replace("  ", " *")
            .replace('\n', "\r\n");
        let config = "-Daether.artifactResolver.postProcessor.trustedChecksums\r\n";
        let files = vec![
            ("pom.xml", fixture("basic", "expected", "pom.xml")),
            (".mvn/maven.config", config.to_string()),
            (".mvn/checksums/checksums.sha256", format!("{other}{ours}")),
        ];
        let (outcome, after) = run(&files).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after[".mvn/checksums/checksums.sha256"], other);
        assert_eq!(after[".mvn/maven.config"], config);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|(code, _)| *code == "maven_trusted_checksums_left"),
            "{:?}",
            outcome.warnings
        );
    }
}
