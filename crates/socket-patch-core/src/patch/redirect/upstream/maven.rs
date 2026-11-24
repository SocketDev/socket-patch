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
fn remove_repository(
    rel: &str,
    pom: &str,
    uuid: &str,
    hosted_uuid: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
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
    if hosted_uuid(&url).as_deref() != Some(uuid) {
        return Err(format!(
            "the {rel} repository {id} does not point at the Socket patch server"
        ));
    }
    remove_maven_repository(pom, &id)
        .ok_or_else(|| format!("the {rel} repository {id} is not on lines of its own"))
}

/// `pom` without the `<repository>` whose id is `id`, and without the
/// `<repositories>` section the rewriter authored for it once that holds
/// nothing else; `None` unless exactly one such repository sits on lines
/// of its own. What the rewriter itself runs when it takes a repository
/// out (the last pin of a patch went, or a newer patch superseded it), so
/// a scan leaves what a rollback would.
pub(crate) fn without_repository(pom: &str, id: &str) -> Option<String> {
    let mut text = remove_maven_repository(pom, id)?;
    if text.contains(EMPTY_REPOSITORIES) && !pom.contains(EMPTY_REPOSITORIES) {
        text = text.replacen(EMPTY_REPOSITORIES, "</project>", 1);
    }
    Some(text)
}

/// What [`restore_pom`] took out of one pom.
pub(crate) struct Restored {
    pub(crate) text: String,
    /// The pin's `<repository>` was declared here.
    pub(crate) repository: bool,
    /// A pin, a declaration or a property of the patch was here.
    pub(crate) wiring: bool,
}

/// One pin and where it is restored.
pub(crate) struct PinIn<'a> {
    pub(crate) group: &'a str,
    pub(crate) artifact: &'a str,
    pub(crate) base: &'a str,
    pub(crate) uuid: &'a str,
    /// The project root heads a reactor: its poms are the reactor
    /// planner's to read, none an earlier release pinned.
    pub(crate) reactor: bool,
}

/// The pom `rel` (`pom`) as restoring `pin` leaves it, or why it cannot
/// be restored: the pin taken out ([`restore_pin`]), the wrappers the
/// rewriter authored from scratch gone once emptied, and what is left
/// still a readable pom. `hosted_uuid` says which patch a repository URL
/// serves. It reads nothing but `pom`, so the rewriter runs it over the
/// text it plans to write: an edit this would not take back is not made.
pub(crate) fn restore_pom(
    rel: &str,
    pom: &str,
    user_properties: &BTreeMap<String, String>,
    pin: &PinIn<'_>,
    hosted_uuid: &dyn Fn(&str) -> Option<String>,
) -> Result<Restored, String> {
    let mut done = restore_pin(rel, pom, user_properties, pin, hosted_uuid)?;
    // The from-scratch wrappers, once emptied (repositories come last).
    for empty in [EMPTY_REPOSITORIES, EMPTY_DEP_MANAGEMENT] {
        if done.text.contains(empty) && !pom.contains(empty) {
            done.text = done.text.replacen(empty, "</project>", 1);
        }
    }
    crate::formats::maven::parse_pom(&done.text)
        .map_err(|why| format!("restoring {rel} would not leave a readable pom: {why}"))?;
    Ok(done)
}

/// Restore one pin in the pom `rel` (`pom`), or say why not.
fn restore_pin(
    rel: &str,
    pom: &str,
    user_properties: &BTreeMap<String, String>,
    pin: &PinIn<'_>,
    hosted_uuid: &dyn Fn(&str) -> Option<String>,
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
        true => remove_repository(rel, pom, uuid, hosted_uuid)?,
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
    use crate::vendor::jvm::maven_reactor::{heads_reactor_in, read_reactor};
    use crate::vendor::lock_inventory::ProjectView;
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    // `.mvn/maven.config`'s `-D` user properties, which Maven reads over
    // the pom's own when it interpolates a coordinate.
    let config = view.read(MVN_CONFIG).await.ok().flatten();
    let user_properties = config
        .as_deref()
        .map(crate::formats::maven::maven_config_properties)
        .unwrap_or_default();
    // The reactor, read as the rewriter and discovery read it. A pin is
    // restored in every pom of it that carries part of the pin, whether or
    // not discovery listed that pom: a reactor discovery could not read
    // whole (a module pom since deleted or broken) is found by its root
    // alone, and restoring only the root would leave a module naming a
    // version nothing serves any more.
    let disk = ProjectView::Disk(view.root);
    let root_pom = view.read("pom.xml").await.ok().flatten();
    // A pom that is there but is not UTF-8 text is not a missing module:
    // it may hold part of a pin, and nothing can tell.
    let undecodable = std::sync::Mutex::new(Vec::new());
    let (reactor, reactor_poms) = match &root_pom {
        Some(root) => (
            heads_reactor_in(&disk, root, config.as_deref()).await,
            read_reactor(&disk, root, config.as_deref(), |rel| {
                let undecodable = &undecodable;
                async move {
                    match disk.read_text(&rel).await {
                        Ok(text) => Some(text),
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::InvalidData {
                                undecodable
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .push(rel);
                            }
                            None
                        }
                    }
                }
            })
            .await,
        ),
        None => (false, BTreeMap::new()),
    };
    // A pin is restored in every pom that carries part of it, or in none.
    // With a pom of the reactor unread, "every" cannot be kept: restoring
    // the others would leave that one naming a version whose repository is
    // gone. Every pin is refused, and nothing is written.
    let mut undecodable = undecodable
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    undecodable.sort();
    if let Some(rel) = undecodable.first() {
        for pin in pins.values() {
            result.refuse(
                &pin.uuid,
                format!(
                    "{rel} is there but is not UTF-8 text, so whether it holds part of the \
                     pin cannot be told; re-save it as UTF-8 and re-run"
                ),
            );
        }
        return result;
    }
    // The poms as they are, and as they read once the pins so far are out.
    let mut originals: BTreeMap<String, String> = BTreeMap::new();
    for rel in files {
        if let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await {
            originals.insert(rel.clone(), text);
        }
    }
    let mut texts = originals.clone();
    // Checksum-file path prefixes of the restored pins.
    let mut checksum_dirs: Vec<String> = Vec::new();
    let mut restored: Vec<&str> = Vec::new();
    for pin in pins.values() {
        // The poms among the pin's files. A checkout that another build
        // reads too wires the pin in a file of that build as well (the
        // sbt file, the Gradle index, the block of a Bazel hub), which is
        // its own restorer's to take out.
        let own = pin.files.iter().filter(|rel| files.contains(rel));
        let mut poms: Vec<String> = own.cloned().collect();
        // A file that could not be read refused the pin above.
        if poms.iter().any(|rel| !originals.contains_key(rel)) {
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
        let repository_id = generation::hosted_pin_name(&pin.uuid);
        let tag = format!(
            "{}{}:",
            crate::vendor::jvm::maven_reactor::PIN_TAG,
            pin.uuid
        );
        for (rel, text) in &reactor_poms {
            let carries =
                text.contains(&suffixed) || text.contains(&repository_id) || text.contains(&tag);
            if carries && !rel.contains(".mvn/") && !poms.contains(rel) {
                poms.push(rel.clone());
            }
        }
        let of = PinIn {
            group,
            artifact,
            base: &base,
            uuid: &pin.uuid,
            reactor,
        };
        // Every pom the pin is wired in, or none: a pin refused in one of
        // its poms is restored in none of them.
        let mut staged: BTreeMap<String, String> = BTreeMap::new();
        let (mut repository, mut wiring) = (false, false);
        let mut refusal = None;
        for rel in &poms {
            let current = match texts.get(rel) {
                Some(text) => text.clone(),
                None => match view.read(rel).await {
                    Ok(Some(text)) => {
                        originals.insert(rel.clone(), text.clone());
                        text
                    }
                    Ok(None) => continue,
                    Err(why) => {
                        refusal = Some(why);
                        break;
                    }
                },
            };
            let hosted_uuid = |url: &str| ctx.hosted_uuid(url);
            match restore_pom(rel, &current, &user_properties, &of, &hosted_uuid) {
                Ok(done) => {
                    repository |= done.repository;
                    wiring |= done.wiring;
                    staged.insert(rel.clone(), done.text);
                }
                Err(why) => {
                    refusal = Some(why);
                    break;
                }
            }
        }
        let named = poms.join(", ");
        let refusal = refusal.or_else(|| {
            if !repository {
                Some(format!(
                    "{named} has no <repository> with id {repository_id}"
                ))
            } else if !wiring {
                Some(format!(
                    "{named} declares no {group}:{artifact} <version>{suffixed}</version>"
                ))
            } else {
                None
            }
        });
        if let Some(why) = refusal {
            result.refuse(&pin.uuid, why);
            continue;
        }
        texts.extend(staged);
        checksum_dirs.push(format!(
            "{}/",
            crate::vendor::jvm::layout::version_dir(group, artifact, &suffixed)
        ));
        restored.push(&pin.uuid);
    }
    if restored.is_empty() {
        return result;
    }
    for (rel, text) in &texts {
        if originals.get(rel) != Some(text) {
            view.write(rel, text.clone());
        }
    }
    // The Trusted Checksums files, where the rewriter keeps them: at the
    // project root (and beside a pom an earlier release pinned on its own).
    let mut dirs: std::collections::BTreeSet<String> = texts
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
    use super::{generation, MVN_CHECKSUMS, MVN_CONFIG};
    use crate::patch::redirect::RewriteResult;
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

    /// A second patch of the same version, which supersedes [`UUID`]'s.
    const NEWER: &str = "88888888-8888-4888-8888-888888888888";

    /// What each module selects for slf4j-api (a module left out does not
    /// resolve it).
    type Picks<'a> = &'a [(&'a str, Result<&'a str, &'a str>)];

    /// One hosted scan of the tree at `root` for the slf4j-api patch
    /// `uuid`, each module selecting what `picks` says: the rewrite, with
    /// its files written.
    fn scan(root: &std::path::Path, uuid: &str, picks: Picks<'_>) -> RewriteResult {
        use crate::crawlers::maven_selection::MavenSelection;
        use crate::patch::redirect::{
            DepOverride, Integrity, RegistryOverride, RegistryOverrideIdentifiers,
        };
        let tree = read_tree(root);
        let modules: Vec<&str> = tree
            .keys()
            .map(String::as_str)
            .filter(|rel| rel.ends_with("pom.xml"))
            .collect();
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
            patch_uuid: uuid.into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch/maven/org.slf4j/slf4j-api/1.7.36/tok/{uuid}/slf4j-api-1.7.36.jar"
            ),
            npm_registry_url: None,
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: format!("https://patch.socket.dev/patch-registry/maven/tok/{uuid}/maven2"),
                identifiers: RegistryOverrideIdentifiers {
                    name: "org.slf4j/slf4j-api".into(),
                    version: "1.7.36".into(),
                    maven_group_id: Some("org.slf4j".into()),
                    maven_artifact_id: Some("slf4j-api".into()),
                    maven_suffixed_version: Some(format!("1.7.36-socket.{}", &uuid[..8])),
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
            &tree,
            &[dep],
            &BTreeMap::new(),
            None,
            false,
            &std::collections::BTreeSet::new(),
            &Default::default(),
            &crate::formats::cargo::source_replacement::CratesIoSource::Registry,
            Some(&MavenSelection::answering(&modules, &picks)),
        );
        let files: Vec<(&str, String)> = written
            .files
            .iter()
            .map(|(rel, text)| (rel.as_str(), text.clone()))
            .collect();
        write_tree(root, &files);
        written
    }

    /// The hosted pins discovery reads from the tree at `root`.
    async fn discovered(root: &std::path::Path) -> Vec<HostedPin> {
        HostedPin::discover(crate::vendor::lock_inventory::ProjectView::Disk(root), &[]).await
    }

    /// THE INVARIANT, on the tree at `root` as a build and a rollback
    /// would find it. No pom names a `-socket.<hex8>` version, and no pom
    /// declares a `socket-patch-<uuid>` repository, but as part of a pin
    /// discovery finds in that very pom (so a rollback undoes it); every
    /// pin has the checksum lines of its jar and pom; and no checksum line
    /// is left for a suffix no pin has. The pins found.
    async fn assert_invariant(case: &str, root: &std::path::Path) -> Vec<HostedPin> {
        let tree = read_tree(root);
        let pins = discovered(root).await;
        let found = |hex8: &str, rel: &str| {
            pins.iter()
                .any(|pin| pin.uuid.starts_with(hex8) && pin.files.iter().any(|f| f == rel))
        };
        for (rel, text) in &tree {
            if !rel.ends_with(".xml") || rel.contains(".mvn/") {
                continue;
            }
            let live = crate::formats::xml::blank_non_markup(text).unwrap();
            for (at, _) in live.match_indices("-socket.") {
                let hex8 = &live[at + 8..at + 16];
                assert!(
                    found(hex8, rel),
                    "{case}: {rel} names -socket.{hex8}, which no pin found there covers: \
                     {pins:?}\n{text}"
                );
            }
            for uuid in generation::named_generations(text) {
                assert!(
                    found(&uuid[..8], rel),
                    "{case}: {rel} declares the repository of {uuid}, which no pin found \
                     there uses: {pins:?}\n{text}"
                );
            }
        }
        let sums = tree.get(MVN_CHECKSUMS).cloned().unwrap_or_default();
        for line in sums.lines().filter(|line| line.contains("-socket.")) {
            assert!(
                pins.iter()
                    .any(|pin| line.contains(&format!("-socket.{}/", &pin.uuid[..8]))),
                "{case}: a checksum line is left for a suffix no pin has: {line}"
            );
        }
        for pin in &pins {
            let suffix = format!("-socket.{}/", &pin.uuid[..8]);
            assert_eq!(
                sums.lines().filter(|line| line.contains(&suffix)).count(),
                2,
                "{case}: the jar and pom checksum lines of {}: {sums}",
                pin.uuid
            );
        }
        pins
    }

    /// Roll every hosted pin of the tree at `root` back.
    async fn roll_back(case: &str, root: &std::path::Path) {
        let pins = discovered(root).await;
        if pins.is_empty() {
            return;
        }
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(root, &pins, &opts).await;
        for pin in &outcome.pins {
            assert_eq!(pin.status, PinStatus::Restored, "{case}: {}", pin.purl);
        }
    }

    /// One fixture through the life of a hosted patch, the invariant
    /// checked after every step ([`assert_invariant`]):
    ///
    /// - scanned, scanned again (which writes nothing), rolled back: the
    ///   tree is `files` again, byte for byte, with no file left over;
    /// - scanned, then scanned for a newer patch of the same version
    ///   (which takes the place of the first everywhere), then with every
    ///   module resolving another version (which takes out the pins), then
    ///   rolled back: every pom is as in `files`, and nothing of either
    ///   patch is left.
    ///
    /// `wired` is whether the scan is expected to pin the patch at all.
    async fn lifecycle(case: &str, files: &[(&str, String)], picks: Picks<'_>, wired: bool) {
        let before: BTreeMap<String, String> = files
            .iter()
            .map(|(rel, text)| (rel.to_string(), text.clone()))
            .collect();
        let suffixed_in =
            |tree: &BTreeMap<String, String>| tree.values().any(|text| text.contains("-socket."));

        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), files);
        let first = scan(tmp.path(), UUID, picks);
        assert_eq!(
            suffixed_in(&first.files),
            wired,
            "{case}: {:?}",
            first.warnings
        );
        let pins = assert_invariant(case, tmp.path()).await;
        assert_eq!(pins.len(), usize::from(wired), "{case}: {pins:?}");
        for pin in &pins {
            assert_eq!(
                (pin.purl.as_str(), pin.uuid.as_str()),
                ("pkg:maven/org.slf4j/slf4j-api@1.7.36", UUID)
            );
        }
        let again = scan(tmp.path(), UUID, picks);
        assert!(
            again.files.is_empty() && again.edits.is_empty(),
            "{case}: a second scan writes nothing: {:?} {:?}",
            again.files.keys(),
            again.edits
        );
        roll_back(case, tmp.path()).await;
        assert_eq!(
            read_tree(tmp.path()),
            before,
            "{case}: a rollback puts every file back and leaves none"
        );

        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), files);
        scan(tmp.path(), UUID, picks);
        scan(tmp.path(), NEWER, picks);
        let pins = assert_invariant(&format!("{case}, superseded"), tmp.path()).await;
        assert!(
            pins.iter().all(|pin| pin.uuid == NEWER) && pins.len() == usize::from(wired),
            "{case}: the newer patch takes the place of the first: {pins:?}"
        );
        assert!(
            !read_tree(tmp.path())
                .values()
                .any(|text| text.contains(&UUID[..8])),
            "{case}: nothing of the first patch is left: {:#?}",
            read_tree(tmp.path())
        );
        let again = scan(tmp.path(), NEWER, picks);
        assert!(again.files.is_empty(), "{case}: {:?}", again.files.keys());
        let elsewhere: Vec<(&str, Result<&str, &str>)> =
            picks.iter().map(|(pom, _)| (*pom, Ok("2.0.9"))).collect();
        scan(tmp.path(), NEWER, &elsewhere);
        assert_invariant(&format!("{case}, moved on"), tmp.path()).await;
        roll_back(case, tmp.path()).await;
        let after = read_tree(tmp.path());
        assert!(!suffixed_in(&after), "{case}: {after:#?}");
        for (rel, text) in &before {
            assert_eq!(after.get(rel), Some(text), "{case}: {rel}");
        }
        // (A scan that took out the last pin itself cannot delete the
        // `.mvn` files it once wrote: they stay, with no line of a patch.)
        for rel in after.keys().filter(|rel| !before.contains_key(*rel)) {
            assert!(
                [MVN_CONFIG, MVN_CHECKSUMS].contains(&rel.as_str()),
                "{case}: {rel} is left over"
            );
        }
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

    /// A single pom declaring slf4j-api at `${slf4j.version}`, with
    /// `properties` and `more` dependencies.
    fn property_pom(properties: &str, more: &str) -> String {
        format!(
            "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
             <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  \
             <version>1.0.0</version>\n  <properties>\n    {properties}\n  </properties>\n  \
             <dependencies>\n{}{more}  </dependencies>\n</project>\n",
            dependency("org.slf4j", "slf4j-api", Some("${slf4j.version}"))
        )
    }

    /// A reactor's wiring is spread over its poms (a pin in the module
    /// that selects the version, a declaration rewritten where it stands,
    /// the repository in the root, the checksums at the root). Through
    /// scan, re-scan, a superseding patch, pins taken out and rollback,
    /// no pom is ever left naming a version without the repository and
    /// checksum lines that serve it and a pin a rollback finds; and a
    /// rollback puts every file back byte for byte.
    #[tokio::test]
    async fn reactor_wiring_keeps_the_invariant_through_its_life() {
        let logback = dependency("ch.qos.logback", "logback-classic", Some("1.4.14"));
        let declaring = dependency("org.slf4j", "slf4j-api", Some("1.7.36"));
        let both = [("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("1.7.36"))];
        lifecycle(
            "a pin in one module, its sibling on another version",
            &[
                ("pom.xml", REACTOR_ROOT.to_string()),
                ("a/pom.xml", reactor_module("a", &logback)),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("2.0.9"))],
            true,
        )
        .await;
        lifecycle(
            "a pin in the root both inherit, beside a declaration",
            &[
                ("pom.xml", REACTOR_ROOT.to_string()),
                ("a/pom.xml", reactor_module("a", &declaring)),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &both,
            true,
        )
        .await;
        // The root manages the version in the shape an added entry has:
        // it is the project's own, and stays.
        let managing = REACTOR_ROOT.replace(
            "</project>",
            &format!(
                "  <dependencyManagement>\n    <dependencies>\n  {}    </dependencies>\n  \
                 </dependencyManagement>\n</project>",
                declaring.replace("\n    ", "\n      ")
            ),
        );
        lifecycle(
            "the root's own management",
            &[
                ("pom.xml", managing),
                (
                    "a/pom.xml",
                    reactor_module("a", &dependency("org.slf4j", "slf4j-api", None)),
                ),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &both,
            true,
        )
        .await;
        lifecycle(
            "a property of the root the modules read",
            &[
                (
                    "pom.xml",
                    REACTOR_ROOT.replace(
                        "  <packaging>pom</packaging>\n",
                        "  <packaging>pom</packaging>\n  <properties>\n    \
                         <slf4j.version>1.7.36</slf4j.version>\n  </properties>\n",
                    ),
                ),
                (
                    "a/pom.xml",
                    reactor_module(
                        "a",
                        &dependency("org.slf4j", "slf4j-api", Some("${slf4j.version}")),
                    ),
                ),
                ("b/pom.xml", reactor_module("b", &logback)),
            ],
            &both,
            true,
        )
        .await;
        // The only declaration is one Maven reads while a profile is
        // active: nothing is written at any step.
        let profiled = reactor_module("a", "").replace(
            "</project>",
            &format!(
                "  <profiles>\n    <profile>\n      <id>extra</id>\n      <dependencies>\n\
                 {declaring}      </dependencies>\n    </profile>\n  </profiles>\n</project>"
            ),
        );
        lifecycle(
            "a declaration only a profile holds",
            &[
                ("pom.xml", REACTOR_ROOT.to_string()),
                ("a/pom.xml", profiled),
                ("b/pom.xml", reactor_module("b", "")),
            ],
            &[],
            false,
        )
        .await;
    }

    /// The same for a single pom: a `${property}` version put back as it
    /// was written (the property's own value, or the declaration's
    /// recorded text), wiring that sits in a parent pom of the checkout,
    /// and the pins an earlier release's rewriter still writes.
    #[tokio::test]
    async fn single_pom_wiring_keeps_the_invariant_through_its_life() {
        let picks = [("pom.xml", Ok("1.7.36"))];
        lifecycle(
            "a property only the artifact reads",
            &[(
                "pom.xml",
                property_pom("<slf4j.version>1.7.36</slf4j.version>", ""),
            )],
            &picks,
            true,
        )
        .await;
        lifecycle(
            "a property a sibling reads too",
            &[(
                "pom.xml",
                property_pom(
                    "<slf4j.version>1.7.36</slf4j.version>",
                    &dependency("org.slf4j", "slf4j-simple", Some("${slf4j.version}")),
                ),
            )],
            &picks,
            true,
        )
        .await;
        lifecycle(
            "a property a parent from a repository defines",
            &[(
                "pom.xml",
                property_pom("<other>1</other>", "").replace(
                    "  <groupId>com.example</groupId>",
                    "  <parent>\n    <groupId>corp</groupId>\n    <artifactId>parent</artifactId>\n    \
                     <version>7</version>\n    <relativePath/>\n  </parent>\n  \
                     <groupId>com.example</groupId>",
                ),
            )],
            &picks,
            true,
        )
        .await;
        // The wiring lands in a parent pom the project lists no module
        // for: discovery and rollback must read that pom too.
        lifecycle(
            "a property a parent pom of the checkout defines",
            &[
                (
                    "pom.xml",
                    property_pom("<other>1</other>", "").replace(
                        "  <groupId>com.example</groupId>",
                        "  <parent>\n    <groupId>com.example</groupId>\n    \
                         <artifactId>parent</artifactId>\n    <version>1.0.0</version>\n    \
                         <relativePath>parent/pom.xml</relativePath>\n  </parent>\n  \
                         <groupId>com.example</groupId>",
                    ),
                ),
                (
                    "parent/pom.xml",
                    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
                     <groupId>com.example</groupId>\n  <artifactId>parent</artifactId>\n  \
                     <version>1.0.0</version>\n  <packaging>pom</packaging>\n  <properties>\n    \
                     <slf4j.version>1.7.36</slf4j.version>\n  </properties>\n</project>\n"
                        .to_string(),
                ),
            ],
            &picks,
            true,
        )
        .await;
        lifecycle(
            "a literal declaration",
            &[("pom.xml", fixture("basic", "input", "pom.xml"))],
            &picks,
            true,
        )
        .await;
        lifecycle(
            "no declaration: an added management entry",
            &[("pom.xml", fixture("transitive-depmgmt", "input", "pom.xml"))],
            &picks,
            true,
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

    /// A reactor one of whose module poms has gone missing is still read
    /// for the pins of the others: the pin in a module's pom is found with
    /// the repository in the root, and a rollback takes out both.
    #[tokio::test]
    async fn a_reactor_with_a_missing_module_is_still_rolled_back_whole() {
        let logback = dependency("ch.qos.logback", "logback-classic", Some("1.4.14"));
        let files = [
            ("pom.xml", REACTOR_ROOT.to_string()),
            ("a/pom.xml", reactor_module("a", &logback)),
            ("b/pom.xml", reactor_module("b", &logback)),
        ];
        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), &files);
        scan(
            tmp.path(),
            UUID,
            &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("2.0.9"))],
        );
        std::fs::remove_file(tmp.path().join("b/pom.xml")).unwrap();
        let pins = discovered(tmp.path()).await;
        assert_eq!(pins.len(), 1, "{pins:?}");
        assert_eq!(pins[0].files, ["a/pom.xml", "pom.xml"]);
        roll_back("a missing module", tmp.path()).await;
        let after = read_tree(tmp.path());
        assert_eq!(after["a/pom.xml"], files[1].1);
        assert_eq!(after["pom.xml"], files[0].1);
        assert!(!after.contains_key(MVN_CHECKSUMS), "{:?}", after.keys());
    }

    /// A module pom that is there but is not UTF-8 text is not a missing
    /// one. Its content is unknown, and here it holds one of the pins:
    /// restoring the poms that can be read would take the repository from
    /// under it. Discovery still finds the pin in those; the rollback
    /// refuses it, names the file, and changes nothing.
    #[tokio::test]
    async fn a_reactor_with_an_undecodable_module_is_not_rolled_back_in_part() {
        let logback = dependency("ch.qos.logback", "logback-classic", Some("1.4.14"));
        let root = REACTOR_ROOT.replace(
            "<module>b</module>",
            "<module>b</module>\n    <module>c</module>",
        );
        assert_ne!(root, REACTOR_ROOT);
        let files = [
            ("pom.xml", root),
            ("a/pom.xml", reactor_module("a", &logback)),
            ("b/pom.xml", reactor_module("b", &logback)),
            ("c/pom.xml", reactor_module("c", &logback)),
        ];
        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), &files);
        // `a` and `c` select the base version and take a pin each; `b`
        // resolves another, so the root takes none.
        scan(
            tmp.path(),
            UUID,
            &[
                ("a/pom.xml", Ok("1.7.36")),
                ("b/pom.xml", Ok("2.0.9")),
                ("c/pom.xml", Ok("1.7.36")),
            ],
        );
        // The pom of `c`, pin and all, re-saved in another encoding (a
        // Latin-1 "é" in a comment).
        let pinned = std::fs::read(tmp.path().join("c/pom.xml")).unwrap();
        assert!(String::from_utf8_lossy(&pinned).contains("-socket."));
        let mut latin1 = b"<!-- r\xe9sum\xe9 -->\n".to_vec();
        latin1.extend_from_slice(&pinned);
        std::fs::write(tmp.path().join("c/pom.xml"), &latin1).unwrap();
        let bytes = |root: &std::path::Path| -> BTreeMap<String, Vec<u8>> {
            walkdir::WalkDir::new(root)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
                .map(|entry| {
                    let rel = entry.path().strip_prefix(root).unwrap();
                    (
                        rel.to_string_lossy().replace('\\', "/"),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect()
        };
        let before = bytes(tmp.path());

        let pins = discovered(tmp.path()).await;
        assert_eq!(pins.len(), 1, "{pins:?}");
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
        let why = refusal(&outcome);
        assert!(
            why.contains("c/pom.xml") && why.contains("not UTF-8"),
            "{why}"
        );
        assert_eq!(bytes(tmp.path()), before, "nothing was written");
    }

    /// A pin is restored in every pom of the reactor that carries part of
    /// it, whatever discovery listed, or in none: restoring the root alone
    /// would take the repository from under a module that still names the
    /// suffixed version.
    #[tokio::test]
    async fn a_pin_is_restored_in_every_pom_that_carries_it_or_in_none() {
        let logback = dependency("ch.qos.logback", "logback-classic", Some("1.4.14"));
        let files = [
            ("pom.xml", REACTOR_ROOT.to_string()),
            ("a/pom.xml", reactor_module("a", &logback)),
            ("b/pom.xml", reactor_module("b", &logback)),
        ];
        let root_only = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: UUID.into(),
            files: vec!["pom.xml".into()],
        }];
        let opts = RestoreOptions {
            offline: true,
            ..RestoreOptions::default()
        };
        let wire = || {
            let tmp = tempfile::tempdir().unwrap();
            write_tree(tmp.path(), &files);
            scan(
                tmp.path(),
                UUID,
                &[("a/pom.xml", Ok("1.7.36")), ("b/pom.xml", Ok("2.0.9"))],
            );
            tmp
        };

        // The module's pin goes with the root's repository.
        let tmp = wire();
        let outcome = restore_upstream(tmp.path(), &root_only, &opts).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        let after = read_tree(tmp.path());
        for (rel, text) in &files {
            assert_eq!(after.get(*rel), Some(text), "{rel}");
        }

        // A module that still names the pin and can no longer be read as
        // a pom: nothing is restored, the root keeps its repository.
        let tmp = wire();
        let broken = read_tree(tmp.path())["a/pom.xml"].replace("</project>", "");
        std::fs::write(tmp.path().join("a/pom.xml"), &broken).unwrap();
        let wired = read_tree(tmp.path());
        let outcome = restore_upstream(tmp.path(), &root_only, &opts).await;
        let why = refusal(&outcome);
        assert!(why.contains("a/pom.xml"), "{why}");
        assert_eq!(read_tree(tmp.path()), wired, "nothing changed");
    }

    /// The fixture `sbt/redirect/pom-also-present` under `root` as a hosted
    /// scan leaves it: one pin, in `pom.xml` and in the `socket-patch.sbt`
    /// of the sbt build beside it. The tree before the scan.
    fn pom_beside_sbt(root: &std::path::Path) -> BTreeMap<String, String> {
        let case = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbt/redirect/pom-also-present");
        let before = read_tree(&case.join("input"));
        for tree in [&before, &read_tree(&case.join("expected"))] {
            let files: Vec<(&str, String)> = tree
                .iter()
                .map(|(rel, text)| (rel.as_str(), text.clone()))
                .collect();
            write_tree(root, &files);
        }
        before
    }

    /// A pin is one patch of one package in every file that wires it, and
    /// a checkout that two builds read is wired in a file of each: `pom.xml`
    /// beside the `socket-patch.sbt` of an sbt build, or beside the hosted
    /// index of a Gradle build. Each restorer takes the pin out of its own
    /// files, so the pom comes back whatever else the pin lists.
    #[tokio::test]
    async fn a_pin_another_build_wires_too_is_restored_in_its_pom() {
        let sbt = tempfile::tempdir().unwrap();
        let before_sbt = pom_beside_sbt(sbt.path());

        let gradle = tempfile::tempdir().unwrap();
        let slf4j = "org.slf4j:slf4j-api:1.7.36";
        let build = format!("dependencies {{ implementation '{slf4j}' }}\n");
        let files = [
            ("pom.xml", fixture("basic", "input", "pom.xml")),
            ("settings.gradle", "rootProject.name = 'app'\n".to_string()),
            ("build.gradle", build),
            ("gradle.lockfile", format!("{slf4j}=runtimeClasspath\n")),
        ];
        write_tree(gradle.path(), &files);
        let before_gradle = read_tree(gradle.path());
        let scanned = scan(gradle.path(), UUID, &[("pom.xml", Ok("1.7.36"))]);
        assert!(scanned.confirmed_gradle_uuids.contains(UUID));

        for (root, wired_in, before) in [
            (sbt.path(), ["pom.xml", "socket-patch.sbt"], before_sbt),
            (
                gradle.path(),
                [".socket/gradle/hosted-index.tsv", "pom.xml"],
                before_gradle,
            ),
        ] {
            let case = wired_in.join(" and ");
            let pins = discovered(root).await;
            assert_eq!(pins.len(), 1, "{case}: {pins:?}");
            assert_eq!(pins[0].files, wired_in);
            roll_back(&case, root).await;
            assert_eq!(read_tree(root), before, "{case}");
        }
    }

    /// Two restorers act on such a pin, and a pin is restored in every
    /// file that wires it or in none. Whichever of the two refuses, the
    /// pin is refused and nothing is written: not `pom.xml` and the `.mvn`
    /// files when `socket-patch.sbt` was edited, and not `socket-patch.sbt`
    /// when the pom names the patched version where no scan put it. (The
    /// pin is read before the edit: discovery does not list an edited
    /// `socket-patch.sbt`.)
    #[tokio::test]
    async fn a_pin_one_of_two_builds_refuses_is_restored_in_neither() {
        let named = "</dependencies>\n  <build>\n    <finalName>app-3.11-socket.abcdef12</finalName>\n  </build>";
        for (rel, from, to, needle) in [
            ("socket-patch.sbt", "Do not edit", "Do edit", "was edited"),
            (
                "pom.xml",
                "</dependencies>",
                named,
                "outside a <dependency> version",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            pom_beside_sbt(tmp.path());
            let pins = discovered(tmp.path()).await;
            assert_eq!(pins[0].files, ["pom.xml", "socket-patch.sbt"]);
            let edited = read_tree(tmp.path())[rel].replace(from, to);
            assert!(edited.contains(to), "{rel}");
            std::fs::write(tmp.path().join(rel), edited).unwrap();
            let wired = read_tree(tmp.path());
            let opts = RestoreOptions {
                offline: true,
                ..RestoreOptions::default()
            };
            let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
            let why = refusal(&outcome);
            assert!(why.contains(needle), "{rel}: {why}");
            assert_eq!(read_tree(tmp.path()), wired, "{rel}: nothing changed");
        }
    }

    /// An earlier release's pin is read by its shape only in a single pom.
    /// A Maven 4 root that could discover subprojects but has none is one:
    /// the entry that release added goes, as before. With a subproject
    /// beside it the root heads a reactor, where a managed entry at the
    /// suffixed version is a rewritten one of the project's and keeps its
    /// place at the base version.
    #[tokio::test]
    async fn an_earlier_pin_is_told_by_its_shape_only_in_a_single_pom() {
        let maven_4 = |pom: String| {
            pom.replace("POM/4.0.0", "POM/4.1.0")
                .replace("<modelVersion>4.0.0", "<modelVersion>4.1.0")
                .replace("<packaging>jar</packaging>", "<packaging>pom</packaging>")
        };
        let input = maven_4(fixture("transitive-depmgmt", "input", "pom.xml"));
        let hosted = maven_4(fixture("transitive-depmgmt", "expected", "pom.xml"));
        assert!(hosted.contains("<dependencyManagement>") && !input.contains("Management"));

        let (outcome, after) = run(&[("pom.xml", hosted.clone())]).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(after["pom.xml"], input, "the added entry goes");

        let child = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  <modelVersion>4.1.0</modelVersion>\n  <parent/>\n  <artifactId>child</artifactId>\n</project>\n";
        let tmp = tempfile::tempdir().unwrap();
        write_tree(
            tmp.path(),
            &[
                ("pom.xml", hosted.clone()),
                ("child/pom.xml", child.to_string()),
            ],
        );
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
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        let after = read_tree(tmp.path());
        assert!(
            after["pom.xml"].contains("<version>1.7.36</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>")
                && !after["pom.xml"].contains(SUFFIXED)
                && !after["pom.xml"].contains("socket-patch-"),
            "the managed entry stays, at the base version: {}",
            after["pom.xml"]
        );
        assert_eq!(after["child/pom.xml"], child);
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
