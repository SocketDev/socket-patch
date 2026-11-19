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
//! Every other checksums line keeps its bytes and place (the rewriter
//! leaves them so too; see `trusted_checksums::edit`).

use std::collections::BTreeMap;

use regex::Regex;

use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::formats::maven::declared_maven::DeclaredMaven;
use crate::formats::maven::trusted_checksums;
use crate::patch::redirect::{
    generation, heal_trade_detail, maven_repositories_with_id, maven_tag_inner_range,
    maven_tag_text_in, remove_maven_repository, MAVEN_DEPENDENCY_BLOCK_RE, MVN_CHECKSUMS,
    MVN_CONFIG, MVN_WRAPPER_PROPERTIES,
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
    user_properties: &BTreeMap<String, String>,
    group: &str,
    artifact: &str,
    base: &str,
    uuid: &str,
    ctx: &Ctx<'_>,
) -> Result<String, String> {
    let suffixed = format!("{base}-socket.{}", &uuid[..8]);
    let mut text = remove_repository(pom, uuid, ctx)?;

    let scoped = crate::formats::maven::PomScope::with_user_properties(&text, user_properties)
        .and_then(|s| s.dependencies());
    let matches = dep_matches(&text, scoped.as_deref().ok(), group, artifact);
    if !matches
        .iter()
        .any(|m| m.version_text.as_deref() == Some(suffixed.as_str()))
    {
        return Err(format!(
            "pom.xml declares no {group}:{artifact} <version>{suffixed}</version>"
        ));
    }
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
            "pom.xml still names {suffixed} outside a <dependency> version (a property or \
             plugin configuration socket-patch did not write)"
        ));
    }
    let name = generation::hosted_pin_name(uuid);
    if live.contains(&name) {
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
        // `.mvn/maven.config`'s `-D` user properties, which Maven reads over
        // the pom's own when it interpolates a coordinate.
        let user_properties = match view.read(&format!("{dir}{MVN_CONFIG}")).await {
            Ok(Some(config)) => crate::formats::maven::maven_config_properties(&config),
            _ => BTreeMap::new(),
        };
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
            match restore_pin(
                &text,
                &user_properties,
                group,
                artifact,
                &base,
                &pin.uuid,
                ctx,
            ) {
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
/// themselves when nothing but hosted mode's content is left. A config
/// that stays is healed ([`heal_mvn_config`]).
async fn restore_mvn(
    view: &mut View<'_>,
    dir: &str,
    checksum_dirs: &[String],
    result: &mut FormatResult,
) {
    let config_rel = format!("{dir}{MVN_CONFIG}");
    let config = view.read(&config_rel).await.ok().flatten();
    let removed = drop_checksums(
        view,
        dir,
        &config_rel,
        config.as_deref(),
        checksum_dirs,
        result,
    )
    .await;
    if let Some(config) = config.filter(|_| !removed) {
        heal_mvn_config(view, dir, &config_rel, &config, result).await;
    }
}

/// The checksum half of [`restore_mvn`]. Whether it removed the config.
async fn drop_checksums(
    view: &mut View<'_>,
    dir: &str,
    config_rel: &str,
    config: Option<&str>,
    checksum_dirs: &[String],
    result: &mut FormatResult,
) -> bool {
    let sums_rel = format!("{dir}{MVN_CHECKSUMS}");
    let Ok(Some(sums)) = view.read(&sums_rel).await else {
        return false;
    };
    let rest = trusted_checksums::edit(
        &sums,
        |p| checksum_dirs.iter().any(|d| p.starts_with(d.as_str())),
        &[],
    );
    if rest == sums {
        return false;
    }
    // Whether settings hosted mode may have written are left over, read as
    // `trusted_checksums::Settings` reads them but by presence: a partial
    // or switched-off set is still lines the user may want gone.
    let has_resolver_lines = config.is_some_and(trusted_checksums::config_has_written_settings);
    if rest.trim().is_empty() {
        view.remove(&sums_rel);
        // (In either spelling of the directory: the one this release
        // writes, or an earlier release's.)
        if config.is_some_and(trusted_checksums::is_written_config) {
            view.remove(config_rel);
            return true;
        }
    } else {
        view.write(&sums_rel, rest.clone());
    }
    if has_resolver_lines && !trusted_checksums::names_hosted_artifact(&rest) {
        result.warnings.push((
            "maven_trusted_checksums_left",
            format!(
                "{config_rel} keeps the trusted-checksums resolver lines (`-Daether.…`), which \
                 hosted mode may have added; no hosted pin needs them any more, so remove them \
                 if nothing else does"
            ),
        ));
    }
    false
}

/// The block hosted mode wrote into a `.mvn/maven.config` that stays
/// (`config`, at `config_rel`), respelled for the Maven the project under
/// `dir` declares ([`trusted_checksums::heal_basedir`]): the lines are left
/// in place, but the one an earlier release wrote must not go on stopping
/// Maven 3.9.2 to 3.9.8 from starting with `-f` from outside the project.
/// What that trades away on Maven 4 is said, as the scan says it. Left out
/// where the config cannot be written ([`View::write_if_writable`]).
async fn heal_mvn_config(
    view: &mut View<'_>,
    dir: &str,
    config_rel: &str,
    config: &str,
    result: &mut FormatResult,
) {
    use trusted_checksums::Basedir;
    // The cheap test first: only a config that holds a block in either
    // spelling is worth reading the wrapper and the pom for.
    if !trusted_checksums::holds_written_block(config) {
        return;
    }
    // The flush refuses a write through a symbolic link, and the whole
    // restore with it: a linked config keeps its line, as a scan keeps it.
    let path = view.root().join(config_rel);
    if crate::utils::containment::linked_level(view.root(), &path).is_some() {
        return;
    }
    let wrapper = view
        .read(&format!("{dir}{MVN_WRAPPER_PROPERTIES}"))
        .await
        .ok()
        .flatten();
    let pom = view.read(&format!("{dir}pom.xml")).await.ok().flatten();
    let declared = DeclaredMaven::of(wrapper.as_deref(), pom.as_deref());
    let Some(healed) = trusted_checksums::heal_basedir(config, Basedir::for_maven(&declared))
    else {
        return;
    };
    let trade = heal_trade_detail(&healed, &declared, dir);
    // A courtesy, never the reason a restore is refused: a config the
    // flush would not write (a symbolic link, say) keeps its line, as it
    // did before there was a heal, and the pins are restored all the same.
    if !view.write_if_writable(config_rel, healed).await {
        return;
    }
    if let Some(detail) = trade {
        result
            .warnings
            .push(("maven_trusted_checksums_maven3_only", detail));
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

    /// The `.mvn` files hosted mode wrote are removed whichever way the
    /// checksums directory is spelled: as this release writes it for a
    /// Maven 3 project, or with the session's root directory, as an
    /// earlier release wrote it and as a Maven 4 project still has it.
    #[tokio::test]
    async fn the_mvn_files_are_removed_in_either_spelling_of_the_directory() {
        use super::trusted_checksums::{
            self,
            Basedir::{Launcher, Session},
        };
        for form in [Launcher, Session] {
            let config = format!("{}\n", trusted_checksums::config_args(form).join("\n"));
            let files = vec![
                ("pom.xml", fixture("basic", "expected", "pom.xml")),
                (".mvn/maven.config", config),
                (
                    ".mvn/checksums/checksums.sha256",
                    fixture("basic", "expected", ".mvn/checksums/checksums.sha256"),
                ),
            ];
            let (outcome, after) = run(&files).await;
            assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{form:?}");
            assert_eq!(
                after.keys().collect::<Vec<_>>(),
                ["pom.xml"],
                "{form:?}: {:?}",
                outcome.warnings
            );
            assert_eq!(after["pom.xml"], fixture("basic", "input", "pom.xml"));
        }
    }

    #[tokio::test]
    async fn existing_mvn_lines_are_kept_and_warned() {
        let config = format!(
            "-Dmaven.test.skip=true\n{}\n",
            super::trusted_checksums::CONFIG_ARGS.join("\n")
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

    /// A rollback that leaves hosted mode's settings beside the user's
    /// own must not leave the line an earlier release wrote, which stops
    /// Maven 3.9.2 to 3.9.8 from starting with `-f` from outside the
    /// project: the block is respelled for the Maven the project declares,
    /// and what that trades away on Maven 4 is said.
    #[tokio::test]
    async fn a_block_the_rollback_leaves_is_healed() {
        use super::trusted_checksums::{
            self, basedir_value,
            Basedir::{Launcher, Session},
            BASEDIR_KEY,
        };
        let beside = |form| {
            format!(
                "-Dmaven.test.skip=true\n{}\n",
                trusted_checksums::config_args(form).join("\n")
            )
        };
        let wrapper = |version: &str| {
            format!(
                "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/\
                 apache-maven/{version}/apache-maven-{version}-bin.zip\n"
            )
        };
        let files = |config: String, maven: Option<&str>| {
            let mut files = vec![
                ("pom.xml", fixture("basic", "expected", "pom.xml")),
                (".mvn/maven.config", config),
                (
                    ".mvn/checksums/checksums.sha256",
                    fixture("basic", "expected", ".mvn/checksums/checksums.sha256"),
                ),
            ];
            if let Some(version) = maven {
                files.push((".mvn/wrapper/maven-wrapper.properties", wrapper(version)));
            }
            files
        };
        let codes = |outcome: &RestoreOutcome| -> Vec<&'static str> {
            outcome.warnings.iter().map(|(code, _)| *code).collect()
        };
        let (left, trade) = (
            "maven_trusted_checksums_left",
            "maven_trusted_checksums_maven3_only",
        );

        // No Maven declared: healed to the form that breaks no build, and
        // the trade is said beside the leftover-lines warning.
        let (outcome, after) = run(&files(beside(Session), None)).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after["pom.xml"], fixture("basic", "input", "pom.xml"));
        assert_eq!(after[".mvn/maven.config"], beside(Launcher));
        assert_eq!(codes(&outcome), [left, trade], "{:?}", outcome.warnings);
        let said = &outcome.warnings[1].1;
        assert!(
            said.contains("A Maven 4 build of this project no longer does")
                && said.contains(".mvn/maven.config"),
            "{said}"
        );

        // A Maven 3 named by the wrapper enforces either spelling: healed,
        // nothing traded.
        let (outcome, after) = run(&files(beside(Session), Some("3.9.9"))).await;
        assert_eq!(after[".mvn/maven.config"], beside(Launcher));
        assert_eq!(codes(&outcome), [left]);

        // A project that declares Maven 4 keeps the spelling Maven 4
        // reads, and gets it when the block is in the launcher's.
        let (outcome, after) = run(&files(beside(Session), Some("4.0.0"))).await;
        assert_eq!(after[".mvn/maven.config"], beside(Session));
        assert_eq!(codes(&outcome), [left]);
        let (outcome, after) = run(&files(beside(Launcher), Some("4.0.0"))).await;
        assert_eq!(after[".mvn/maven.config"], beside(Session));
        assert_eq!(codes(&outcome), [left]);

        // Already this project's spelling: the bytes are not touched.
        let (outcome, after) = run(&files(beside(Launcher), None)).await;
        assert_eq!(after[".mvn/maven.config"], beside(Launcher));
        assert_eq!(codes(&outcome), [left]);

        // A directory line that stands apart is the user's, and stays.
        let theirs = format!(
            "-D{BASEDIR_KEY}={}\n-Dmaven.test.skip=true\n",
            basedir_value(Session)
        );
        let (outcome, after) = run(&files(theirs.clone(), None)).await;
        assert_eq!(after[".mvn/maven.config"], theirs);
        assert_eq!(codes(&outcome), [left]);
    }

    /// A leftover block in a `.mvn/maven.config` that is a symbolic link is
    /// not healed: the flush refuses a linked file, so the heal would
    /// refuse a restore that has nothing else against it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_config_the_rollback_leaves_is_not_healed() {
        use super::trusted_checksums::{self, Basedir::Session};
        let config = format!(
            "-Dmaven.test.skip=true\n{}\n",
            trusted_checksums::config_args(Session).join("\n")
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".mvn/checksums")).unwrap();
        std::fs::create_dir_all(root.join("ci")).unwrap();
        std::fs::write(
            root.join("pom.xml"),
            fixture("basic", "expected", "pom.xml"),
        )
        .unwrap();
        std::fs::write(
            root.join(".mvn/checksums/checksums.sha256"),
            fixture("basic", "expected", ".mvn/checksums/checksums.sha256"),
        )
        .unwrap();
        std::fs::write(root.join("ci/maven.config"), &config).unwrap();
        std::os::unix::fs::symlink("../ci/maven.config", root.join(".mvn/maven.config")).unwrap();
        let pins = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: UUID.into(),
            files: vec!["pom.xml".into()],
        }];
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(root, &pins, &opts).await;
        assert_eq!(outcome.flush_error, None);
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(
            std::fs::read_to_string(root.join("pom.xml")).unwrap(),
            fixture("basic", "input", "pom.xml")
        );
        assert!(root.join(".mvn/maven.config").is_symlink());
        assert_eq!(
            std::fs::read_to_string(root.join("ci/maven.config")).unwrap(),
            config
        );
    }

    /// The same holds for anything else the flush will not write, which
    /// is all or nothing: a `.mvn` directory that does not take the write
    /// keeps the config as it is, and the pins are restored all the same,
    /// as they were before there was a heal. (Root writes anywhere, so
    /// there is nothing to see as root.)
    #[cfg(unix)]
    #[tokio::test]
    async fn a_config_the_flush_could_not_write_is_not_healed() {
        use super::trusted_checksums::{self, Basedir::Session};
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let config = format!(
            "-Dmaven.test.skip=true\n{}\n",
            trusted_checksums::config_args(Session).join("\n")
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".mvn/checksums")).unwrap();
        std::fs::write(
            root.join("pom.xml"),
            fixture("basic", "expected", "pom.xml"),
        )
        .unwrap();
        std::fs::write(
            root.join(".mvn/checksums/checksums.sha256"),
            fixture("basic", "expected", ".mvn/checksums/checksums.sha256"),
        )
        .unwrap();
        std::fs::write(root.join(".mvn/maven.config"), &config).unwrap();
        // The config's own directory is read-only; the checksums
        // directory below it still takes the removal of its file.
        let mvn = root.join(".mvn");
        std::fs::set_permissions(&mvn, std::fs::Permissions::from_mode(0o555)).unwrap();
        let pins = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: UUID.into(),
            files: vec!["pom.xml".into()],
        }];
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(root, &pins, &opts).await;
        std::fs::set_permissions(&mvn, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(outcome.flush_error, None);
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(
            std::fs::read_to_string(root.join("pom.xml")).unwrap(),
            fixture("basic", "input", "pom.xml")
        );
        assert_eq!(
            std::fs::read_to_string(root.join(".mvn/maven.config")).unwrap(),
            config
        );
        // The leftover lines are reported; no trade is claimed for a line
        // that was not changed.
        let codes: Vec<&str> = outcome.warnings.iter().map(|(code, _)| *code).collect();
        assert_eq!(codes, ["maven_trusted_checksums_left"]);
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
