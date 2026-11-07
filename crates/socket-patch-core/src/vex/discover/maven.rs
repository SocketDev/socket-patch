//! Maven — the root `pom.xml`, plus `.mvn/maven.config` +
//! `.mvn/checksums/checksums.sha256` for the hosted integrity pin.
//!
//! Maven has no lockfile: both Socket wirings live in `pom.xml`, and in both
//! the `<repository>` names the patch uuid while the artifact identity comes
//! from somewhere else. The hosted version suffix ties a pin to its
//! repository by an 8-hex uuid prefix only, so a pin is attributed only
//! when exactly ONE Socket repository's uuid starts with it; anything
//! ambiguous (two matching repositories, a suffix-less pin) is not a ref.
//!
//! ## Hosted (`patch::redirect::rewrite_maven_pom`)
//!
//! The fail-closed rewrite pins the dependency's `<version>` (the literal,
//! or an added `<dependencyManagement>` entry for a transitive) to
//! `<base>-socket.<hex8>` — a version that exists ONLY on the Socket repo —
//! and inserts
//!
//! ```xml
//! <repository>
//!   <id>socket-patch-<uuid></id>
//!   <url>https://patch.socket.dev/patch-registry/maven/<token>/<uuid>/maven2</url>
//!   …
//! ```
//!
//! The `<repository>` is a DEFINITION: it ties the uuid to no artifact (the
//! module docs' rule 10). A ref needs the PIN, a dependency version whose
//! `-socket.<hex8>` suffix matches the first 8 hex of exactly ONE such
//! repository's uuid; the ref's purl is `pkg:maven/<g>/<a>@<base>` (the
//! replaced version). R6 — the tie is only 32 bits, so every ambiguity is a
//! [`DIAG_REF_UNATTRIBUTABLE`] and no ref: a pin matching zero or several
//! repositories, a repository tied to several packages, and a repository no
//! pin names (the LEGACY same-GAV fallback, fixture `no-suffix-fallback`:
//! the version stays the original and Maven may resolve it from Central).
//! The repository must carry BOTH identities, agreeing: the id
//! `socket-patch-<uuid>` ([`socket_patch_name_uuid`]) and a Socket-hosted
//! url ([`DiscoverCtx::hosted_uuid`]) — a hand-edited url whose uuid segment
//! was replaced by a placeholder would otherwise yield the uuid-shaped grant
//! token.
//!
//! A pin counts only where Maven resolves it: a direct `<dependency>`
//! literal version wins over `<dependencyManagement>`, so a managed Socket
//! pin shadowed by a direct plain version (or a GA declared with several
//! different effective versions) is diagnosed, not a ref.
//! A hosted pin in a reactor root (`<modules>` / `<subprojects>`) stays
//! a ref (rollback / remove find it) but marked unattested: a module's
//! own literal `<version>` overrides it, and only the root pom is read here
//! (the rewriter refuses such roots, #261). A `<classifier>` copy of the
//! GA is its own coordinate, which the classifier-less pin does not
//! retarget and the grant does not serve: an executable one (anything but
//! `sources` / `javadoc`), live or in a profile, that resolves any version
//! other than the pin — its own literal, a classifier-keyed managed entry,
//! or none in this pom — keeps the ref but marks it unattested. So does a
//! `<profiles>` declaration of the main jar at any version other than the
//! pin (a profile's `<dependencyManagement>` only where management governs
//! the pin): the rewriter leaves it as written, and whenever that profile
//! is active it overrides the pin (vendored mode treats every profile as
//! live and rewrites it too). A `${property}` version is resolved one
//! level from the root `<properties>` — the pin as the pom spells it — and
//! again with `.mvn/maven.config`'s `-D` user properties first, as the
//! build resolves it (Maven's order; `${project.*}` stays the model's): a
//! pin the build config moves keeps the ref but marks it unattested, and a
//! Socket version only the build config supplies is diagnosed, never a
//! ref (hosted mode never writes one; rollback / remove never edit
//! `.mvn/maven.config`).
//!
//! Integrity: when the pom sha256 was known the rewriter also writes Maven
//! Trusted Checksums — `.mvn/checksums/checksums.sha256` lines
//! `<sha256>  <g-path>/<a>/<v>/<a>-<v>.jar` under the SUFFIXED version, made
//! effective by `-Daether.artifactResolver.postProcessor.trustedChecksums=true`
//! in `.mvn/maven.config`. That jar line becomes
//! [`LockIntegrity::Sha256Hex`] only while Maven enforces the file
//! ([`crate::formats::maven::trusted_checksums::enforced`]: every setting
//! hosted writes, read as Maven 3.9+ reads `maven.config`, and no wrapper
//! pinning a Maven older than 3.9.4).
//! `integrity_required` is FALSE: the rewriter writes checksums only when
//! both hashes are known, and the suffixed version itself is the
//! fail-closed pin (no other repository serves it; the Socket repository is
//! `checksumPolicy=fail`).
//!
//! ## Vendored, pre-v5 (the retired single-pom backend)
//!
//! Ledgers written before v5 still carry this wiring until `vendor
//! --revert` (vendoring such a root is refused as `legacy_maven_root`); v5
//! vendors every pom root through the JVM planner instead, whose suffixed
//! pins are attributed through its ledger only (a suffixed pin whose tree
//! is committed under `.socket/vendor/maven2` is no ref here). The retired
//! backend inserted
//! `<id>socket-patch-vendor-<uuid></id>` +
//! `<url>file://${project.basedir}/.socket/vendor/maven/<uuid></url>` and
//! leaves the dependency at its ORIGINAL version, so the GAV lives only in
//! the committed maven2 tree: `.socket/vendor/maven/<uuid>/<g-path>/<a>/<v>/
//! <a>-<v>.jar` (via [`sweep_vendor_dirs`]; exactly one jar, else
//! unattributable). The `${project.basedir}/` (or deprecated `${basedir}/`)
//! prefix is stripped exactly before [`vendor_uuid_dir`] — an absolute or
//! `../` url is not this project's tree. The id and url uuids must agree. The
//! jar's `.sha1` sidecar must match it: the repository is
//! `checksumPolicy=fail`, so a stale or missing sidecar makes Maven skip the
//! vendored copy for the next repository ([`DIAG_REF_INVALID`], no ref). A
//! pom that pins the GA to a DIFFERENT literal version than the vendored one
//! no longer consumes the artifact → [`DIAG_REF_INVALID`], no ref.
//!
//! ## Scope
//!
//! Comments are ignored. `<repository>` elements inside
//! `<pluginRepositories>` / `<distributionManagement>` (plugin resolution,
//! deploy targets) and dependencies inside `<build>` / `<reporting>`
//! (plugin classpaths) are not project resolution and are skipped silently;
//! `<profiles>` are only read when activated, so a Socket repository or pin
//! there is diagnosed, never a ref, and a profile declaration of a pinned
//! GA at another version withholds the pin's attestation. Submodule poms
//! and parent poms are not read (root-only). Gradle builds are discovered
//! by `gradle.rs` (the hosted index) and the vendored JVM backend's own
//! probes.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    maven_purl, names_vendor_dir, socket_patch_name_uuid, vendor_ref, vendor_uuid_dir, DiscoverCtx,
    Discovery, PatchedRef, UnattestedKind, WiringMode, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
    DIAG_REF_UNATTRIBUTABLE,
};
use crate::formats::maven::{
    is_executable_variant, is_main_jar, is_maven_coordinate, is_maven_version_text, is_variant,
    maven_config_properties, may_name, may_shadow, parse_pom_with, split_socket_version,
    variant_label, Pom, PomDep, PomRepo,
};
use crate::patch::redirect::{MVN_CHECKSUMS, MVN_CONFIG, MVN_WRAPPER_PROPERTIES};
use crate::vendor::jvm::layout;
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::maven_repo::{sha1_sidecar_matches, VENDOR_REPO_URL_PREFIX};
use crate::vendor::path::{sweep_vendor_dirs, VENDOR_DIR};

const POM: &str = "pom.xml";
/// The project-root prefixes a vendored repository url may carry
/// (`vendor_maven` writes the first).
const BASEDIR_PREFIXES: &[&str] = &[
    VENDOR_REPO_URL_PREFIX,
    "file:${project.basedir}/",
    "file://${basedir}/",
    "file:${basedir}/",
];

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(raw) = ctx.read_text(POM, out).await else {
        return;
    };
    // `.mvn/maven.config`'s `-D` user properties win over the pom's own
    // when Maven interpolates a coordinate or a version.
    let config = ctx.read_text(MVN_CONFIG, out).await;
    let user_properties = match &config {
        Some(config) => maven_config_properties(config),
        None => BTreeMap::new(),
    };
    let pom = match parse_pom_with(&raw, &user_properties) {
        Ok(pom) => pom,
        Err(e) => {
            out.diag(
                DIAG_LOCKFILE_UNPARSEABLE,
                POM,
                format!("{POM} is not a readable Maven pom: {e}"),
            );
            return;
        }
    };

    let mut hosted: BTreeMap<String, String> = BTreeMap::new(); // uuid -> url
    let mut vendored: BTreeSet<String> = BTreeSet::new();
    for repo in &pom.repos {
        match classify_repo(ctx, repo, out) {
            RepoKind::Hosted { uuid, url } => {
                hosted.entry(uuid).or_insert(url);
            }
            RepoKind::Vendored { uuid } => {
                vendored.insert(uuid);
            }
            RepoKind::NotOurs => {}
        }
    }

    let gas = live_gas(&pom.deps);
    let reactor = crate::vendor::jvm::maven_reactor::declares_modules(&raw)
        || (crate::vendor::jvm::maven_reactor::may_discover_subprojects(&raw, config.as_deref())
            && !crate::vendor::jvm::maven_reactor::implicit_subprojects_in(&ctx.view)
                .await
                .is_empty());
    extract_hosted(ctx, &pom, &gas, &hosted, reactor, config.as_deref(), out).await;
    if !vendored.is_empty() {
        extract_vendored(ctx, &pom.deps, &vendored, out).await;
    }
}

// ── hosted ───────────────────────────────────────────────────────────────

async fn extract_hosted(
    ctx: &DiscoverCtx<'_>,
    pom: &Pom,
    gas: &BTreeSet<(String, String)>,
    hosted: &BTreeMap<String, String>,
    reactor: bool,
    config: Option<&str>,
    out: &mut Discovery,
) {
    // uuid -> the (purl, g, a, suffixed version) pins that tie to it.
    let mut ties: BTreeMap<&str, BTreeSet<(String, String, String, String)>> = BTreeMap::new();

    for dep in &pom.deps {
        if dep.in_profile
            && dep
                .version
                .as_deref()
                .and_then(split_socket_version)
                .is_some()
        {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: {}:{} <version>{}</version> is inside <profiles>, which Maven \
                     reads only when that profile is active",
                    dep.group,
                    dep.artifact,
                    dep.version.as_deref().unwrap_or_default()
                ),
            );
        }
    }

    // A Socket version only a `-D` user property supplies is no pom.xml
    // wiring: hosted mode never writes one, and rollback / remove never
    // edit `.mvn/maven.config`.
    let mut reported = BTreeSet::new();
    for dep in pom.deps.iter().filter(|d| !d.in_profile) {
        let Some(built) = dep
            .build_version
            .as_deref()
            .filter(|v| split_socket_version(v).is_some() && dep.version.as_deref() != Some(v))
        else {
            continue;
        };
        // A pom spelling that is itself a Socket pin is pom.xml wiring:
        // pin detection keeps its ref and reports the -D override
        // (`MavenConfigOverride`) instead.
        if dep
            .version
            .as_deref()
            .and_then(split_socket_version)
            .is_some()
        {
            continue;
        }
        // Once per GA and version: its managed entry and classifier copies
        // spell the same property.
        if !reported.insert((dep.group.clone(), dep.artifact.clone(), built.to_string())) {
            continue;
        }
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            POM,
            format!(
                "{POM}: {}:{} <version>{}</version> is the Socket version {built} only through \
                 a -D user property in {MVN_CONFIG}, which hosted mode never writes and \
                 rollback / remove never edit; it is not {POM} wiring",
                dep.group,
                dep.artifact,
                dep.version.as_deref().unwrap_or_default(),
            ),
        );
    }

    for (group, artifact) in gas {
        let versions = &ga_versions(&pom.deps, group, artifact, pom_version);
        let socket_pins: BTreeSet<&str> = versions
            .direct
            .iter()
            .chain(&versions.managed)
            .map(String::as_str)
            .filter(|v| split_socket_version(v).is_some())
            .collect();
        if socket_pins.is_empty() {
            continue;
        }
        let ga = format!("{group}:{artifact}");
        if !is_maven_coordinate(group) || !is_maven_coordinate(artifact) {
            out.diag(
                DIAG_REF_INVALID,
                POM,
                format!("{POM}: {ga:?} is not a usable Maven groupId:artifactId"),
            );
            continue;
        }
        let effective = versions.effective();
        let pinned = match effective.iter().collect::<Vec<_>>().as_slice() {
            [only] if split_socket_version(only).is_some() => (*only).clone(),
            _ => {
                out.diag(
                    DIAG_REF_INVALID,
                    POM,
                    format!(
                        "{POM}: {ga} carries the Socket {} {socket_pins:?} but Maven \
                         resolves {effective:?} (a direct <version> overrides \
                         <dependencyManagement>)",
                        if socket_pins.len() == 1 {
                            "version"
                        } else {
                            "versions"
                        },
                    ),
                );
                continue;
            }
        };
        let (base, hex8) = split_socket_version(&pinned).expect("`pinned` was matched as suffixed");
        let Some(purl) =
            maven_purl(group, artifact, base).filter(|_| is_maven_version_text(&pinned))
        else {
            out.diag(
                DIAG_REF_INVALID,
                POM,
                format!("{POM}: {ga} <version>{pinned}</version> is not a usable Maven version"),
            );
            continue;
        };
        let candidates: Vec<&str> = hosted
            .keys()
            .map(String::as_str)
            .filter(|uuid| uuid.starts_with(hex8))
            .collect();
        // A JVM-backend pin: its committed maven2 tree serves it.
        let jvm_tree = candidates.is_empty()
            && ctx
                .exists(&format!(
                    "{}/{}",
                    layout::MAVEN2_TREE,
                    layout::artifact_path(group, artifact, &pinned, None, "jar")
                ))
                .await;
        match candidates.as_slice() {
            [uuid] => {
                // A reactor root's pin stays a ref (rollback, remove and
                // list must still find it) but is never attested: a
                // module's own <version>, unread here, overrides it (#261).
                if reactor {
                    out.unattested(
                        &purl,
                        uuid,
                        POM,
                        format!(
                            "{POM} heads a multi-module reactor (<modules>/<subprojects>, or \
                             Maven 4 subproject discovery), and a module's own \
                             <version> of {ga} overrides this root pin; hosted mode reads only \
                             the root pom (re-patch the reactor with `scan --mode vendored`)"
                        ),
                        UnattestedKind::MavenReactorRoot,
                    );
                }
                for (kind, detail) in bypasses(&pom.deps, group, artifact, &pinned, Wiring::Hosted)
                {
                    out.unattested(&purl, uuid, POM, detail, kind);
                }
                ties.entry(*uuid).or_default().insert((
                    purl,
                    group.clone(),
                    artifact.clone(),
                    pinned.clone(),
                ));
            }
            [] if jvm_tree => {}
            [] => out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: {ga} <version>{pinned}</version> carries a Socket patch suffix but no \
                     socket-patch-<uuid> repository's uuid starts with {hex8}"
                ),
            ),
            several => out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: {ga} <version>{pinned}</version> matches several Socket patch \
                     repositories ({}); the 8-hex suffix cannot tell which one serves it",
                    several.join(", ")
                ),
            ),
        }
    }

    let mut checksums: Option<BTreeMap<String, String>> = None;
    for (uuid, url) in hosted {
        let Some(pins) = ties.get(uuid.as_str()) else {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: repository socket-patch-{uuid} is tied to no dependency (no \
                     <version> carries the -socket.{} suffix; a same-GAV repository cannot be \
                     attributed to an artifact)",
                    &uuid[..8]
                ),
            );
            continue;
        };
        let [(purl, group, artifact, pinned)] = pins.iter().collect::<Vec<_>>()[..] else {
            let purls: Vec<&str> = pins.iter().map(|(p, ..)| p.as_str()).collect();
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: repository socket-patch-{uuid} is pinned by several packages \
                     ({}); a Socket patch repository serves exactly one artifact",
                    purls.join(", ")
                ),
            );
            continue;
        };
        if checksums.is_none() {
            checksums = Some(trusted_checksums(ctx, config, out).await);
        }
        let jar = layout::artifact_path(group, artifact, pinned, None, "jar");
        let integrity = checksums
            .as_ref()
            .and_then(|c| c.get(&jar))
            .map(|hex| LockIntegrity::Sha256Hex(hex.clone()));
        out.push(PatchedRef::hosted(
            purl.clone(),
            uuid.clone(),
            POM,
            Some(url),
            integrity,
            false,
        ));
    }
}

/// `path -> sha256 hex` from `.mvn/checksums/checksums.sha256`, or empty
/// when Maven does not enforce it: `config` (`.mvn/maven.config`'s text,
/// read once by [`extract`]) lacks a setting it reads the file by, or the
/// Maven Wrapper pins a Maven older than 3.9.4. Judged by the hosted
/// rewriter's own rule, and only a line Maven checks attests
/// (`formats::maven::trusted_checksums`).
async fn trusted_checksums(
    ctx: &DiscoverCtx<'_>,
    config: Option<&str>,
    out: &mut Discovery,
) -> BTreeMap<String, String> {
    use crate::formats::maven::trusted_checksums::{enforced, pinned};
    let Some(config) = config else {
        return BTreeMap::new();
    };
    let wrapper = ctx.read_text(MVN_WRAPPER_PROPERTIES, out).await;
    if !enforced(config, wrapper.as_deref()) {
        return BTreeMap::new();
    }
    ctx.read_text(MVN_CHECKSUMS, out)
        .await
        .map(|text| pinned(&text))
        .unwrap_or_default()
}

// ── vendored ─────────────────────────────────────────────────────────────

async fn extract_vendored(
    ctx: &DiscoverCtx<'_>,
    deps: &[PomDep],
    vendored: &BTreeSet<String>,
    out: &mut Discovery,
) {
    // The vendored repository is a tree of jars: only a disk has one.
    let Some(root) = ctx.disk_root() else {
        return;
    };
    let swept: BTreeMap<String, Vec<String>> = sweep_vendor_dirs(root)
        .await
        .into_iter()
        .filter(|d| d.eco == "maven")
        .map(|d| (d.uuid, d.purls))
        .collect();
    for uuid in vendored {
        let dir = format!("{VENDOR_DIR}/maven/{uuid}");
        let purls = swept.get(uuid).map(Vec::as_slice).unwrap_or_default();
        let [purl] = purls else {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                POM,
                format!(
                    "{POM}: repository socket-patch-vendor-{uuid} serves {dir}, which holds {} \
                     vendored {} — exactly one is needed to name the patched artifact",
                    purls.len(),
                    if purls.len() == 1 { "jar" } else { "jars" },
                ),
            );
            continue;
        };
        let Some((group, artifact, version)) = crate::utils::purl::parse_maven_purl(purl) else {
            continue;
        };
        let (group, artifact, version) = (group.as_ref(), artifact.as_ref(), version.as_ref());
        let rel = format!(
            "{dir}/{}",
            layout::artifact_path(group, artifact, version, None, "jar")
        );
        let jar_ok = tokio::fs::symlink_metadata(root.join(&rel))
            .await
            .is_ok_and(|m| m.is_file());
        let (Some(vref), Some(purl), true) = (
            vendor_ref(&rel),
            maven_purl(group, artifact, version),
            jar_ok
                && is_maven_coordinate(group)
                && is_maven_coordinate(artifact)
                && is_maven_version_text(version),
        ) else {
            out.diag(
                DIAG_REF_INVALID,
                POM,
                format!(
                    "{POM}: repository socket-patch-vendor-{uuid}: {rel} is not a usable \
                     maven2-layout jar for {purl}"
                ),
            );
            continue;
        };
        // `checksumPolicy=fail` makes the jar's `.sha1` sidecar part of the
        // wiring: a stale or missing one fails the file:// download and
        // Maven silently resolves the NEXT repository (Central's pristine
        // jar) — the committed members still hash-verify, but the build no
        // longer consumes them.
        if !jar_sidecar_matches(ctx, &rel, out).await {
            out.diag(
                DIAG_REF_INVALID,
                POM,
                format!(
                    "{POM}: repository socket-patch-vendor-{uuid}: {rel}.sha1 is missing or \
                     does not match the jar, so Maven (checksumPolicy=fail) rejects the \
                     vendored copy and resolves {purl} from the next repository"
                ),
            );
            continue;
        }
        // The vendored repository serves the ORIGINAL GAV; a pom that now
        // pins this GA to another version no longer consumes the artifact.
        {
            let versions = ga_versions(deps, group, artifact, pom_version);
            let effective = versions.effective();
            let conflicting = !effective.is_empty()
                && !effective.contains(version)
                && effective.iter().all(|v| !v.contains("${"));
            if conflicting {
                out.diag(
                    DIAG_REF_INVALID,
                    POM,
                    format!(
                        "{POM}: {group}:{artifact} resolves {effective:?}, not the vendored \
                         {version} that repository socket-patch-vendor-{uuid} serves"
                    ),
                );
                continue;
            }
        }
        for (kind, detail) in bypasses(deps, group, artifact, version, Wiring::Vendored) {
            out.unattested(&purl, uuid, POM, detail, kind);
        }
        out.push(PatchedRef::vendored(purl, &vref, POM, None));
    }
}

/// Whether `<jar_rel>.sha1` exists and names the jar's sha1, read the way
/// maven-resolver reads a checksum file ([`sha1_sidecar_matches`]). Both
/// reads go through the guarded ctx helpers; unreadable = no match.
async fn jar_sidecar_matches(ctx: &DiscoverCtx<'_>, jar_rel: &str, out: &mut Discovery) -> bool {
    let Some(bytes) = ctx.read_bytes(jar_rel, out).await else {
        return false;
    };
    let Some(recorded) = ctx.read_text(&format!("{jar_rel}.sha1"), out).await else {
        return false;
    };
    sha1_sidecar_matches(&bytes, &recorded)
}

// ── repository classification ────────────────────────────────────────────

enum RepoKind {
    Hosted { uuid: String, url: String },
    Vendored { uuid: String },
    NotOurs,
}

/// Which Socket wiring (if any) `repo` is; a Socket-shaped repository that
/// fails validation is diagnosed and treated as [`RepoKind::NotOurs`].
fn classify_repo(ctx: &DiscoverCtx<'_>, repo: &PomRepo, out: &mut Discovery) -> RepoKind {
    let id = repo.id.as_str();
    let url = repo.url.as_str();
    let id_socket = id.starts_with(crate::patch::redirect::generation::PIN_NAME_PREFIX);
    let id_hosted = socket_patch_name_uuid(id, false);
    let id_vendored = socket_patch_name_uuid(id, true);
    let url_hosted = ctx.hosted_uuid(url);
    let url_vendor_text = names_vendor_dir(url);
    if !id_socket && url_hosted.is_none() && !url_vendor_text {
        return RepoKind::NotOurs;
    }
    // The JVM backend's one shared fallback repository names no patch; its
    // ledger entries prove their own liveness.
    if id == crate::vendor::jvm::maven_reactor::REPO_ID
        && url == crate::vendor::jvm::maven_reactor::REPO_URL
    {
        return RepoKind::NotOurs;
    }
    let invalid = |out: &mut Discovery, why: &str| {
        out.diag(
            DIAG_REF_INVALID,
            POM,
            format!("{POM}: <repository> id {id:?} url {url:?}: {why}"),
        );
        RepoKind::NotOurs
    };
    if repo.in_profile {
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            POM,
            format!(
                "{POM}: Socket <repository> {id:?} is inside <profiles>, which Maven reads only \
                 when that profile is active"
            ),
        );
        return RepoKind::NotOurs;
    }
    if let Some(expected) = id_vendored {
        let url_uuid = BASEDIR_PREFIXES
            .iter()
            .find_map(|p| url.strip_prefix(p))
            .and_then(vendor_uuid_dir)
            .filter(|(eco, _)| eco == "maven")
            .map(|(_, uuid)| uuid);
        return match url_uuid {
            Some(uuid) if uuid == expected => RepoKind::Vendored { uuid },
            Some(_) => {
                // The url is this project's vendor tree: the id is a Socket
                // identity too, rejected (discover rule 11).
                ctx.recognize_paired_name(POM, &expected, WiringMode::Vendored);
                invalid(out, "the url's .socket/vendor/maven/<uuid> is not the id's uuid")
            }
            None => invalid(
                out,
                "a vendored repository url must be file://${project.basedir}/.socket/vendor/maven/<uuid>",
            ),
        };
    }
    if let Some(expected) = id_hosted {
        return match url_hosted {
            Some(uuid) if uuid == expected => RepoKind::Hosted {
                uuid,
                url: url.to_string(),
            },
            Some(_) => {
                // The url is on the Socket host: the id's uuid is a Socket
                // identity too, and this pairing is rejected (rule 11) —
                // else the pom's `<id>` text would revive a ledger for it.
                ctx.recognize_paired_name(POM, &expected, WiringMode::Hosted);
                invalid(
                    out,
                    "the url's patch uuid is not the id's uuid (a placeholder or edited url)",
                )
            }
            None => invalid(out, "the url is not on the Socket patch server"),
        };
    }
    invalid(
        out,
        "a Socket repository needs the id socket-patch-<uuid> (hosted) or \
         socket-patch-vendor-<uuid> (vendored) with a matching url",
    )
}

// ── dependency versions ──────────────────────────────────────────────

/// Distinct versions of one `groupId:artifactId`'s main jar among the
/// declarations Maven always reads (profiles excluded), split by where
/// they are declared.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GaVersions {
    direct: BTreeSet<String>,
    managed: BTreeSet<String>,
}

impl GaVersions {
    /// Maven's own precedence: a direct literal version wins over the
    /// managed one; the managed version applies only when no direct
    /// declaration carries a version.
    fn effective(&self) -> &BTreeSet<String> {
        if self.direct.is_empty() {
            &self.managed
        } else {
            &self.direct
        }
    }
}

/// Which version of a declaration to read: as the pom spells it
/// ([`pom_version`], what the hosted rewriter writes and rolls back) or as
/// the build resolves it ([`build_version`]).
type VersionOf = fn(&PomDep) -> Option<&str>;

fn pom_version(d: &PomDep) -> Option<&str> {
    d.version.as_deref()
}

fn build_version(d: &PomDep) -> Option<&str> {
    d.build_version.as_deref()
}

/// Every GA with a versioned declaration that is not a variant
/// ([`is_variant`]) Maven always reads: the candidates for a pin.
fn live_gas(deps: &[PomDep]) -> BTreeSet<(String, String)> {
    deps.iter()
        .filter(|d| {
            !d.in_profile
                && !is_variant(d.type_text.as_deref(), d.classifier.as_deref())
                && d.version.is_some()
        })
        .map(|d| (d.group.clone(), d.artifact.clone()))
        .collect()
}

/// The declarations `in_scope` keeps that may be `group:artifact`'s main
/// jar: its own, plus every one whose groupId or artifactId is a property
/// this pom does not define and may be this GA (#683,
/// [`may_shadow`](crate::formats::maven::may_shadow)) — its version then
/// takes part in Maven's precedence, unseen under the literal key. A
/// variant ([`is_variant`]: a classifier such as `sources`, `tests` or a
/// native build, or a type such as `test-jar`) is its own artifact,
/// managed apart from the main jar: it neither pins nor shadows it
/// ([`classifier_declarations`]).
fn main_jar_declarations<'a>(
    deps: &'a [PomDep],
    group: &'a str,
    artifact: &'a str,
    in_scope: impl Fn(&PomDep) -> bool + 'a,
) -> impl Iterator<Item = &'a PomDep> + 'a {
    deps.iter().filter(move |d| {
        in_scope(d)
            && !is_variant(d.type_text.as_deref(), d.classifier.as_deref())
            && ((d.group == group && d.artifact == artifact)
                || may_shadow(
                    (&d.group, &d.artifact),
                    d.type_text.as_deref(),
                    None,
                    (group, artifact),
                ))
    })
}

/// The executable variants of `group:artifact` ([`is_variant`] and
/// [`is_executable_variant`]: tests, `test-jar`, a native or JDK-specific
/// build; not `sources` / `javadoc`) that `in_scope` keeps, with the label
/// they are reported by ([`variant_label`]). A groupId or artifactId that
/// is a property this pom does not define may be this GA ([`may_name`]),
/// so it counts too.
fn classifier_declarations<'a>(
    deps: &'a [PomDep],
    group: &'a str,
    artifact: &'a str,
    in_scope: impl Fn(&PomDep) -> bool + 'a,
) -> impl Iterator<Item = (&'a PomDep, &'a str)> + 'a {
    deps.iter()
        .filter(move |d| {
            in_scope(d) && may_name(&d.group, group) && may_name(&d.artifact, artifact)
        })
        .filter_map(|d| {
            let (t, c) = (d.type_text.as_deref(), d.classifier.as_deref());
            (is_variant(t, c) && is_executable_variant(t, c)).then(|| (d, variant_label(t, c)))
        })
}

/// What Maven may resolve for `group:artifact`'s main jar from the
/// declarations it always reads ([`main_jar_declarations`] outside
/// `<profiles>`), each read through `version_of`.
fn ga_versions(deps: &[PomDep], group: &str, artifact: &str, version_of: VersionOf) -> GaVersions {
    let mut versions = GaVersions::default();
    for dep in main_jar_declarations(deps, group, artifact, |d| !d.in_profile) {
        let Some(version) = version_of(dep) else {
            continue;
        };
        if dep.managed {
            versions.managed.insert(version.to_string());
        } else {
            versions.direct.insert(version.to_string());
        }
    }
    versions
}

/// Which wiring serves a GA's pin, for [`bypasses`].
#[derive(Debug, Clone, Copy)]
enum Wiring {
    /// The hosted `<base>-socket.<hex8>` pin: the grant serves the main
    /// jar; a classifier copy AT the pin exists nowhere, so the build fails
    /// closed rather than run unpatched code.
    Hosted,
    /// The pre-v5 single-pom vendored repository: the original GAV's main
    /// jar only, so every classifier copy comes from the next repository.
    Vendored,
}

/// Every way the build may bypass the wired `group:artifact` pin `pinned`
/// (the hosted suffixed version, or the vendored repository's original
/// one), with the [`UnattestedKind`] it is reported as: the ref stays (so
/// rollback, remove and list still find the wiring) but is not attested.
fn bypasses(
    deps: &[PomDep],
    group: &str,
    artifact: &str,
    pinned: &str,
    wiring: Wiring,
) -> Vec<(UnattestedKind, String)> {
    let ga = format!("{group}:{artifact}");
    let mut found = Vec::new();
    // `.mvn/maven.config`'s `-D` user properties, which Maven reads before
    // the pom's `<properties>`, redefine what the pin is spelled through.
    // Only a property that moves the build OFF the pin is an override: one
    // `.mvn/maven.config` alone defines, at the pinned version, is the pin.
    let spelled = ga_versions(deps, group, artifact, pom_version);
    let built = ga_versions(deps, group, artifact, build_version);
    let resolved = built.effective();
    if resolved != spelled.effective() && !(resolved.len() == 1 && resolved.contains(pinned)) {
        let listed = if resolved.is_empty() {
            "no version this pom gives".to_string()
        } else {
            resolved
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        found.push((
            UnattestedKind::MavenConfigOverride,
            format!(
                "{POM}: {ga} is wired to {pinned}, but a -D user property in {MVN_CONFIG} \
                 (which Maven reads before the pom's <properties>) makes it resolve {listed}"
            ),
        ));
    }
    if let Some(detail) = unpatched_classifier_copy(deps, group, artifact, pinned, wiring) {
        found.push((UnattestedKind::MavenClassifierUnpatched, detail));
    }
    if let Some(detail) = profile_override(deps, group, artifact, pinned, built.direct.is_empty()) {
        found.push((UnattestedKind::MavenProfileUnpatched, detail));
    }
    found
}

/// Why the first executable variant of `group:artifact`
/// ([`classifier_declarations`]) — live or inside `<profiles>` — runs code
/// the wiring does not serve, if one does. A variant is its own
/// coordinate: the main-jar pin does not retarget it. Its version is its
/// own `<version>`, else a `<dependencyManagement>` entry with the same
/// classifier and type (Maven keys management by both); a profile's entry
/// overrides the live one while that profile is active, and with no live
/// entry the version comes from outside this pom (fail closed). A hosted
/// copy is fine only at the pin itself ([`Wiring::Hosted`]); a vendored one
/// never is.
fn unpatched_classifier_copy(
    deps: &[PomDep],
    group: &str,
    artifact: &str,
    pinned: &str,
    wiring: Wiring,
) -> Option<String> {
    let served = match wiring {
        Wiring::Hosted => Some(pinned),
        Wiring::Vendored => None,
    };
    // Each entry carries whether it names `group:artifact` literally: one
    // reached only through an undefined property ([`may_name`]) may manage
    // another GA, so it never stands in for this copy's version alone.
    let ty = |d: &PomDep| -> String {
        d.type_text
            .as_deref()
            .filter(|t| !t.is_empty())
            .unwrap_or("jar")
            .to_string()
    };
    let managed = |copy: &PomDep, in_profile: bool| -> Vec<(Option<&str>, bool, bool)> {
        classifier_declarations(deps, group, artifact, move |d| {
            d.managed && d.in_profile == in_profile
        })
        .filter(|(m, _)| m.classifier == copy.classifier && ty(m) == ty(copy))
        .map(|(d, _)| {
            let literal = d.group == group && d.artifact == artifact;
            (build_version(d), in_profile, literal)
        })
        .collect()
    };
    classifier_declarations(deps, group, artifact, |d| !d.managed).find_map(|(d, classifier)| {
        let resolved: Vec<(Option<&str>, bool)> = match build_version(d) {
            Some(version) => vec![(Some(version), false)],
            None => {
                let mut live = managed(d, false);
                // Without a live entry that surely manages this GA, the
                // version may come from outside this pom: fail closed.
                if !live.iter().any(|(_, _, literal)| *literal) {
                    live.push((None, false, true));
                }
                // A profile entry with no `<version>` (scope or exclusions
                // only) overrides no version.
                live.extend(managed(d, true).into_iter().filter(|(v, _, _)| v.is_some()));
                live.into_iter().map(|(v, p, _)| (v, p)).collect()
            }
        };
        let (version, from_profile) = resolved
            .into_iter()
            .find(|(version, _)| version.is_none() || *version != served)?;
        Some(format!(
            "{POM}: {group}:{artifact}:{classifier}{} resolves <version>{}</version>, {}",
            if d.in_profile || from_profile {
                " (inside <profiles>)"
            } else {
                ""
            },
            version.unwrap_or("(none in this pom)"),
            match wiring {
                Wiring::Hosted => format!(
                    "not the patched {pinned}; the Socket patch covers only the main jar, so \
                     that classifier copy keeps the unpatched code on the classpath"
                ),
                Wiring::Vendored => "which the vendored repository does not serve (it holds \
                                     only the main jar), so Maven fetches the public \
                                     classifier jar"
                    .to_string(),
            }
        ))
    })
}

/// Why a `<profiles>` declaration of `group:artifact`'s main jar
/// ([`main_jar_declarations`]) moves it off `pinned` whenever that profile
/// is active, for the first such one: a version other than the pin. A
/// profile's `<dependencies>` merge over the pom's own, so a direct one
/// always overrides the pin; its `<dependencyManagement>` overrides only
/// what management governs, which `pin_managed` (no live direct version)
/// says. Activation is not evaluated, so every profile counts, as in
/// vendored mode. A declaration without a version takes the live one and
/// moves nothing, and a `pom` typed one carries no code (a `java-source` /
/// `javadoc` typed one is a non-executable variant, never a main jar).
fn profile_override(
    deps: &[PomDep],
    group: &str,
    artifact: &str,
    pinned: &str,
    pin_managed: bool,
) -> Option<String> {
    main_jar_declarations(deps, group, artifact, |d| d.in_profile)
        .filter(|d| is_main_jar(d.type_text.as_deref(), d.classifier.as_deref()))
        .filter(|d| !d.managed || pin_managed)
        .find_map(|d| {
            let version = build_version(d).filter(|v| *v != pinned)?;
            let section = if d.managed {
                "<dependencyManagement> "
            } else {
                ""
            };
            let literal = d.group == group && d.artifact == artifact;
            let named = if literal {
                format!("{group}:{artifact}")
            } else {
                format!(
                    "{}:{} (which may be {group}:{artifact})",
                    d.group, d.artifact
                )
            };
            Some(format!(
                "{POM}: a <profiles> {section}declaration of {named} carries \
                 <version>{version}</version>, not the patched {pinned}; whenever that profile \
                 is active Maven resolves it instead of the pin"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;
    use crate::vendor::lock_inventory::LockIntegrity;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    /// The uuid every committed maven redirect fixture uses.
    const FX_UUID: &str = "77777777-7777-7777-7777-777777777777";
    const FX_PURL: &str = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
    const FX_JAR_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn fixture(case: &str) -> Project {
        let p = Project::new();
        p.copy_fixture(&format!("redirect/maven/pom/{case}/expected"));
        p
    }

    fn hosted_repo(id: &str, url: &str) -> String {
        format!(
            "    <repository>\n      <id>{id}</id>\n      <url>{url}</url>\n      \
             <releases>\n        <enabled>true</enabled>\n        \
             <checksumPolicy>fail</checksumPolicy>\n      </releases>\n    </repository>\n"
        )
    }

    fn registry_url(uuid: &str) -> String {
        format!("https://patch.socket.dev/patch-registry/maven/{TOKEN}/{uuid}/maven2")
    }

    fn dep(g: &str, a: &str, v: Option<&str>) -> String {
        let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
        format!("<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>{v}</dependency>\n")
    }

    fn pom(body: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
             <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
             <artifactId>app</artifactId>\n  <version>1.0.0</version>\n{body}</project>\n"
        )
    }

    fn suffixed(uuid: &str) -> String {
        format!("1.7.36-socket.{}", &uuid[..8])
    }

    /// A hosted project pinning slf4j-api to `uuid`'s suffixed version.
    fn hosted_pom(uuid: &str) -> String {
        pom(&format!(
            "<dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
            dep("org.slf4j", "slf4j-api", Some(&suffixed(uuid))),
            hosted_repo(&format!("socket-patch-{uuid}"), &registry_url(uuid)),
        ))
    }

    // ── hosted: committed rewriter fixtures ─────────────────────────────

    #[tokio::test]
    async fn every_fail_closed_rewriter_fixture_yields_the_patch_uuid_not_the_token() {
        // direct literal rewrite, trusted-checksums merge into an existing
        // maven.config, an added <dependencyManagement> for a transitive, an
        // existing depMgmt + unversioned direct dep, an existing
        // <repositories> block.
        for case in [
            "basic",
            "mvn-config-merge",
            "transitive-depmgmt",
            "existing-depmgmt",
            "existing-repositories",
            // The scope-aware rewrites (#259, #262, #342): what the rewriter
            // reports redirected, VEX attests — a commented-out, profile or
            // plugin declaration and a classifier sibling left at the base
            // version neither pin nor shadow the main jar.
            "comment-dependency",
            "profile-repositories",
            "plugin-dependency",
            "profile-depmgmt",
            "commented-repositories",
            "classifier-sources-sibling",
            "classifier-only-transitive-main",
            "self-closed-repositories",
            "depmgmt-comment",
            "self-closed-depmgmt",
        ] {
            let out = run(&fixture(case)).await;
            assert_refs(&out, &[(FX_PURL, FX_UUID, WiringMode::Hosted)]);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
            let r = &out.refs[0];
            assert_eq!(r.source_file, std::path::PathBuf::from("pom.xml"), "{case}");
            // mvn-config-merge keeps the user's `originAware=true`, under
            // which Maven reads a per-repository summary file, not this one:
            // its checksums pin nothing.
            let integrity =
                (case != "mvn-config-merge").then(|| LockIntegrity::Sha256Hex(FX_JAR_SHA.into()));
            assert_eq!(r.locked_integrity, integrity, "{case}");
            assert!(!r.integrity_required, "{case}");
            assert!(r.lockfile_basis_ok(), "{case}");
            assert!(
                r.url.as_deref().is_some_and(|u| u.ends_with("/maven2")),
                "{case}: {:?}",
                r.url
            );
        }
    }

    #[tokio::test]
    async fn rerun_fixture_input_is_already_wired() {
        let p = Project::new();
        p.copy_fixture("redirect/maven/pom/rerun-noop/input");
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, FX_UUID, WiringMode::Hosted)]);
        assert!(out.refs[0].locked_integrity.is_some());
    }

    #[tokio::test]
    async fn same_gav_fallback_is_unattributable() {
        let out = run(&fixture("no-suffix-fallback")).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        assert!(out.diagnostics[0].detail.contains("pom.xml"));
        // The repository names the patch on the Socket host, so it is
        // recognized: a ledger claim for it is dead (rule 11).
        assert_eq!(out.hosted_claim(FX_PURL, FX_UUID), Some(false));
    }

    #[tokio::test]
    async fn unwired_rewriter_inputs_yield_nothing() {
        for case in [
            "basic",
            "property-version-warn",
            "version-mismatch-skip",
            "transitive-depmgmt",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/maven/pom/{case}/input"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    #[tokio::test]
    async fn checksums_without_the_resolver_switch_pin_nothing() {
        let p = fixture("basic");
        std::fs::remove_file(p.root().join(".mvn/maven.config")).expect("rm maven.config");
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, FX_UUID, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(
            out.refs[0].lockfile_basis_ok(),
            "maven never requires a pin"
        );
    }

    /// Integrity attests only what Maven enforces, judged by the hosted
    /// rewriter's own rule: every `maven.config` setting Maven reads the
    /// summary file by, each a whole-line argument (CRLF and a bare `-Dk`
    /// switch count); no wrapper Maven older than 3.9.4; and a jar line in
    /// the exact lowercase `<sha256>  <path>` shape. A tolerated spelling
    /// (one space, a `*` marker, uppercase hex) is a line Maven skips or
    /// fails on, so it pins nothing.
    #[tokio::test]
    async fn checksums_attest_only_what_maven_enforces() {
        use crate::formats::maven::trusted_checksums::{CONFIG_ARGS, SWITCH_KEY};
        let jar = "org/slf4j/slf4j-api/1.7.36-socket.77777777/slf4j-api-1.7.36-socket.77777777.jar";
        let all = CONFIG_ARGS.join("\n");
        let switch = format!("-D{SWITCH_KEY}=true");
        let wrapper = |v: &str| {
            format!("distributionUrl=https://repo/apache-maven/{v}/apache-maven-{v}-bin.zip\n")
        };
        let line = format!("{FX_JAR_SHA}  {jar}\n");
        let upper = FX_JAR_SHA.to_uppercase();
        for (config, wrapper, sums, attests) in [
            (
                CONFIG_ARGS.join("\r\n"),
                None,
                format!("{FX_JAR_SHA}  {jar}\r\n"),
                true,
            ),
            (
                all.replace(&switch, &format!("-D{SWITCH_KEY}")),
                None,
                format!("# pins\n{FX_JAR_SHA}  {jar}"),
                true,
            ),
            (all.clone(), Some(wrapper("3.9.4")), line.clone(), true),
            (all.clone(), Some(wrapper("3.9.3")), line.clone(), false),
            (switch.clone(), None, line.clone(), false),
            (
                all.replace(&switch, &format!("-B {switch}")),
                None,
                line.clone(),
                false,
            ),
            (
                all.replace("originAware=false", "originAware=true"),
                None,
                line.clone(),
                false,
            ),
            (
                format!("{all}\n-D{SWITCH_KEY}=false"),
                None,
                line.clone(),
                false,
            ),
            (all.clone(), None, format!("{FX_JAR_SHA} {jar}\n"), false),
            (all.clone(), None, format!("{FX_JAR_SHA} *{jar}\n"), false),
            (all.clone(), None, format!("{upper}  {jar}\n"), false),
        ] {
            let p = fixture("basic");
            p.write(".mvn/maven.config", config.clone());
            if let Some(props) = &wrapper {
                p.write(".mvn/wrapper/maven-wrapper.properties", props.clone());
            }
            p.write(".mvn/checksums/checksums.sha256", sums.clone());
            let out = run(&p).await;
            assert_refs(&out, &[(FX_PURL, FX_UUID, WiringMode::Hosted)]);
            assert_eq!(
                out.refs[0].locked_integrity,
                attests.then(|| LockIntegrity::Sha256Hex(FX_JAR_SHA.into())),
                "{config:?} / {wrapper:?} / {sums:?}"
            );
        }
    }

    #[tokio::test]
    async fn hosted_pin_resolved_through_a_property_and_crlf() {
        let p = Project::new();
        let text = pom(&format!(
            "<properties>\n<slf4j.version>{}</slf4j.version>\n</properties>\n\
             <dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
            suffixed(UUID_A),
            dep("org.slf4j", "slf4j-api", Some("${slf4j.version}")),
            hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
        ))
        .replace('\n', "\r\n");
        p.write("pom.xml", text);
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
    }

    /// A hosted pin in a reactor root is not attested (#261): a module that
    /// declares the GA with its own literal `<version>` overrides the root's
    /// managed pin, and discovery reads only the root pom. It stays a ref,
    /// so rollback / remove / list still find a pin an older release wrote,
    /// but is marked unattested so `vex` never says not_affected for a
    /// module that still resolves the upstream jar.
    #[tokio::test]
    async fn hosted_pin_in_a_reactor_root_is_not_attested() {
        for reactor in [
            "<modules>\n<module>child</module>\n</modules>\n",
            "<subprojects>\n<subproject>child</subproject>\n</subprojects>\n",
            "<profiles>\n<profile>\n<id>all</id>\n<modules>\n<module>child</module>\n</modules>\n</profile>\n</profiles>\n",
        ] {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "<packaging>pom</packaging>\n{reactor}<dependencyManagement>\n<dependencies>\n{}</dependencies>\n</dependencyManagement>\n<repositories>\n{}</repositories>\n",
                    dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                    hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
                )),
            );
            let out = run(&p).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.unattested.len(), 1, "{reactor}: {:?}", out.unattested);
            let u = &out.unattested[0];
            assert_eq!(u.kind, UnattestedKind::MavenReactorRoot, "{reactor}");
            assert_eq!((u.purl.as_str(), u.uuid.as_str()), (FX_PURL, UUID_A), "{reactor}");
            assert!(u.detail.contains("org.slf4j:slf4j-api"), "{}", u.detail);
        }

        // The single-module control stays attested.
        let p = Project::new();
        p.write("pom.xml", hosted_pom(UUID_A));
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
    }

    /// #1809: a Maven 4 (model 4.1.0) `pom`-packaged root listing no
    /// subprojects builds every direct subdirectory holding a `pom.xml`,
    /// so its hosted pin is a reactor root's: kept as a ref, never
    /// attested. A 4.0.0 model, no such subdirectory, or discovery turned
    /// off in `.mvn/maven.config` leaves it a single pom, attested.
    #[tokio::test]
    async fn hosted_pin_in_a_maven_4_implicit_reactor_root_is_not_attested() {
        let body = format!(
            "<packaging>pom</packaging>\n<dependencyManagement>\n<dependencies>\n{}</dependencies>\n</dependencyManagement>\n<repositories>\n{}</repositories>\n",
            dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
            hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
        );
        let model_4_1 = pom(&body)
            .replace("POM/4.0.0", "POM/4.1.0")
            .replace("<modelVersion>4.0.0", "<modelVersion>4.1.0");
        let child = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n<modelVersion>4.1.0</modelVersion>\n<parent/>\n<artifactId>child</artifactId>\n</project>\n";
        let off = "-Dmaven.project.discoverSubprojects=false\n";
        for (case, root, files, attested) in [
            (
                "implicit reactor",
                &model_4_1,
                &[("child/pom.xml", child)][..],
                false,
            ),
            ("no subproject", &model_4_1, &[][..], true),
            (
                "model 4.0.0",
                &pom(&body),
                &[("child/pom.xml", child)][..],
                true,
            ),
            (
                "discovery off",
                &model_4_1,
                &[("child/pom.xml", child), (".mvn/maven.config", off)][..],
                true,
            ),
        ] {
            let p = Project::new();
            p.write("pom.xml", root.clone());
            for (rel, text) in files {
                p.write(rel, text.to_string());
            }
            let out = run(&p).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            if attested {
                assert!(out.unattested.is_empty(), "{case}: {:?}", out.unattested);
            } else {
                assert_eq!(out.unattested.len(), 1, "{case}: {:?}", out.unattested);
                assert_eq!(out.unattested[0].kind, UnattestedKind::MavenReactorRoot);
            }
        }
    }

    /// A classifier copy is its own coordinate: the classifier-less pin
    /// does not retarget it and the grant serves only the main jar. An
    /// executable one (tests, a native build) left at another version keeps
    /// the public, unpatched jar on the classpath, so the pin stays a ref
    /// but is not attested. `sources` / `javadoc` never run and do not.
    #[tokio::test]
    async fn executable_classifier_copy_off_the_pin_is_not_attested() {
        fn classified(c: &str, v: Option<&str>) -> String {
            let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
            format!(
                "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                 {v}<classifier>{c}</classifier></dependency>\n"
            )
        }
        fn project(deps: &str, managed: &str) -> Project {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "<dependencyManagement>\n<dependencies>\n{managed}</dependencies>\n\
                     </dependencyManagement>\n<dependencies>\n{}{deps}</dependencies>\n\
                     <repositories>\n{}</repositories>\n",
                    dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                    hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
                )),
            );
            p
        }
        let pin = suffixed(UUID_A);
        let unattested = [
            // At the base release: the public classifier jar.
            (classified("tests", Some("1.7.36")), String::new()),
            (classified("natives-linux", Some("1.7.36")), String::new()),
            // Another release entirely.
            (classified("tests", Some("1.7.30")), String::new()),
            // Versioned by a classifier-keyed managed entry.
            (
                classified("tests", None),
                classified("tests", Some("1.7.36")),
            ),
            // No version this pom gives it (a parent's): fail closed.
            (classified("tests", None), String::new()),
            // A coordinate property this pom does not define may be the GA.
            (
                "<dependency><groupId>${undefined.group}</groupId>\
                 <artifactId>slf4j-api</artifactId><version>1.7.36</version>\
                 <classifier>tests</classifier></dependency>\n"
                    .to_string(),
                String::new(),
            ),
            // Version-less copy whose only managed entry reaches the GA
            // through an undefined property: it may manage another GA, so
            // the copy's version may come from outside this pom.
            (
                classified("tests", None),
                format!(
                    "<dependency><groupId>${{undefined.group}}</groupId>\
                     <artifactId>slf4j-api</artifactId><version>{pin}</version>\
                     <classifier>tests</classifier></dependency>\n"
                ),
            ),
            // A type implying an executable classifier (the vendored
            // reactor's rule): `test-jar` is the `tests` jar.
            (
                "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                 <version>1.7.36</version><type>test-jar</type></dependency>\n"
                    .to_string(),
                String::new(),
            ),
        ];
        for (deps, managed) in &unattested {
            let out = run(&project(deps, managed)).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.unattested.len(), 1, "{deps}: {:?}", out.unattested);
            let u = &out.unattested[0];
            assert_eq!(u.kind, UnattestedKind::MavenClassifierUnpatched, "{deps}");
            assert_eq!(
                (u.purl.as_str(), u.uuid.as_str()),
                (FX_PURL, UUID_A),
                "{deps}"
            );
            assert!(u.detail.contains("org.slf4j:slf4j-api:"), "{}", u.detail);
        }

        let attested = [
            // Never executed.
            (classified("sources", Some("1.7.36")), String::new()),
            (classified("javadoc", Some("1.7.36")), String::new()),
            // Already on the patched release.
            (classified("tests", Some(&pin)), String::new()),
            (classified("tests", None), classified("tests", Some(&pin))),
            // Managed only, never declared: nothing resolves it.
            (String::new(), classified("tests", Some("1.7.36"))),
            // No classifier copy at all.
            (String::new(), String::new()),
        ];
        for (deps, managed) in &attested {
            let out = run(&project(deps, managed)).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            assert!(out.unattested.is_empty(), "{deps}: {:?}", out.unattested);
            assert!(out.refs[0].lockfile_basis_ok(), "{deps}");
        }
    }

    #[tokio::test]
    async fn configured_patch_server_origin_is_hosted() {
        let origin = "http://127.0.0.1:4545";
        let p = Project::new().with_origin(origin);
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                hosted_repo(
                    &format!("socket-patch-{UUID_A}"),
                    &format!("{origin}/patch-registry/maven/{TOKEN}/{UUID_A}/maven2")
                ),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
    }

    // ── hosted: negatives ────────────────────────────────────────────────

    #[tokio::test]
    async fn non_socket_host_carrying_the_uuid_is_invalid() {
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace("https://patch.socket.dev", "https://evil.example"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        // The repository is rejected, so the pin has no candidate either.
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE]
        );
    }

    #[tokio::test]
    async fn placeholder_uuid_leaves_only_the_grant_token_and_is_rejected() {
        // The url's uuid level was templated away: the last uuid-shaped
        // segment is the GRANT TOKEN, which must never become the patch.
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace(
                &format!("/{TOKEN}/{UUID_A}/maven2"),
                &format!("/{TOKEN}/PATCH_UUID/maven2"),
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out).contains(&DIAG_REF_INVALID));

        // And a placeholder id is not a uuid either.
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace(&format!("socket-patch-{UUID_A}"), "socket-patch-<uuid>"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out).contains(&DIAG_REF_INVALID));
    }

    #[tokio::test]
    async fn socket_url_under_a_foreign_id_is_invalid() {
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace(&format!("<id>socket-patch-{UUID_A}</id>"), "<id>corp</id>"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out).contains(&DIAG_REF_INVALID));
    }

    #[tokio::test]
    async fn id_and_url_naming_different_patches_is_invalid() {
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_B)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out).contains(&DIAG_REF_INVALID));
        // BOTH patches are recognized: the url's by the sweep, the id's
        // because its element is on the Socket host (a bare name never is),
        // so the `-socket.<hex8>` pin plus the id text cannot revive a
        // ledger record for UUID_A through the raw-text fallback.
        let purl = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
        assert_eq!(out.hosted_claim(purl, UUID_A), Some(false));
        assert_eq!(out.hosted_claim(purl, UUID_B), Some(false));
        // An id on a url OUTSIDE the allowlist (a staging repository) stays
        // the ledger's call.
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                hosted_repo(
                    &format!("socket-patch-{UUID_A}"),
                    &registry_url(UUID_A)
                        .replace("https://patch.socket.dev", "https://staging.example"),
                ),
            )),
        );
        assert_eq!(run(&p).await.hosted_claim(purl, UUID_A), None);
    }

    #[tokio::test]
    async fn suffix_matching_two_repositories_is_unattributable() {
        // Two patches whose uuids share the 8-hex prefix (R6).
        let twin = format!("{}-0000-4000-8000-000000000000", &UUID_A[..8]);
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}</dependencies>\n<repositories>\n{}{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
                hosted_repo(&format!("socket-patch-{twin}"), &registry_url(&twin)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out)
            .iter()
            .all(|c| *c == DIAG_REF_UNATTRIBUTABLE));
        assert!(out.diagnostics.iter().any(|d| d.detail.contains("several")));
    }

    #[tokio::test]
    async fn one_repository_pinned_by_two_packages_is_unattributable() {
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                dep("org.slf4j", "slf4j-simple", Some(&suffixed(UUID_A))),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
    }

    #[tokio::test]
    async fn suffixed_pin_without_a_repository_is_unattributable() {
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}</dependencies>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A)))
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
    }

    #[tokio::test]
    async fn managed_pin_shadowed_by_a_direct_plain_version_is_invalid() {
        // A reverted direct version with the rewriter's depMgmt entry left
        // behind: Maven resolves the direct 1.7.36 from Central.
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencyManagement><dependencies>\n{}</dependencies></dependencyManagement>\n\
                 <dependencies>\n{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                dep("org.slf4j", "slf4j-api", Some("1.7.36")),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE]
        );
        // RECOGNIZED: a redirect ledger record for the shadowed pin is dead
        // even though pom.xml still carries the `-socket.<hex8>` pin text.
        assert_eq!(
            out.hosted_claim("pkg:maven/org.slf4j/slf4j-api@1.7.36", UUID_A),
            Some(false)
        );
    }

    #[tokio::test]
    async fn commented_plugin_profile_and_deploy_sections_are_not_wiring() {
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        let pin = dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A)));
        // Commented out, plugin repositories, deploy targets, plugin deps:
        // silently not wiring.
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<!--\n<dependencies>\n{pin}</dependencies>\n<repositories>\n{repo}</repositories>\n-->\n\
                 <pluginRepositories>\n{}</pluginRepositories>\n\
                 <distributionManagement>\n{repo}</distributionManagement>\n\
                 <build><plugins><plugin><artifactId>x</artifactId><dependencies>\n{pin}</dependencies></plugin></plugins></build>\n",
                repo.replace("repository>", "pluginRepository>"),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        // A profile is only read when activated: diagnosed, never a ref.
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<profiles><profile><id>patched</id>\n<dependencies>\n{pin}</dependencies>\n\
                 <repositories>\n{repo}</repositories>\n</profile></profiles>\n"
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(!out.diagnostics.is_empty());
        assert!(diag_codes(&out)
            .iter()
            .all(|c| *c == DIAG_REF_UNATTRIBUTABLE));
    }

    /// CDATA is character data to Maven: a vendored `<repository>` (or a
    /// hosted pin) written inside one configures nothing, so the original
    /// GAV resolves from Central — it must never read as wiring. An
    /// unterminated CDATA section makes the pom unparseable.
    #[tokio::test]
    async fn cdata_sections_are_not_wiring() {
        let p = vendored_project(UUID_A);
        let wired = std::fs::read_to_string(p.root().join("pom.xml")).expect("read pom");
        let start = wired.find("<repositories>").expect("repositories");
        let end = wired.find("</repositories>").expect("close") + "</repositories>".len();
        let hidden = format!(
            "{}<description><![CDATA[{}]]></description>{}",
            &wired[..start],
            &wired[start..end],
            &wired[end..]
        );
        p.write("pom.xml", &hidden);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            out.vendored_claim(V_PURL, UUID_A, &v_jar_rel(UUID_A)),
            Some(false),
            "the uuid is still mentioned, so a ledger claim for it is dead"
        );

        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        let pin = dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A)));
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<description><![CDATA[<dependencies>\n{pin}</dependencies>\n<repositories>\n\
                 {repo}</repositories>]]></description>\n<!-- <![CDATA[ in a comment -->\n"
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!("<description><![CDATA[never closed\n{pin}")),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
    }

    #[tokio::test]
    async fn exclusion_coordinates_are_not_the_dependency() {
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n<dependency><exclusions><exclusion><groupId>evil</groupId>\
                 <artifactId>evil</artifactId></exclusion></exclusions>\
                 <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                 <version>{}</version></dependency>\n</dependencies>\n<repositories>\n{}</repositories>\n",
                suffixed(UUID_A),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
    }

    /// A `${property}` groupId / artifactId is read through the pom's own
    /// `<properties>` (#683): a property-named direct declaration keeping
    /// the plain version shadows the managed pin (Maven resolves Central's
    /// jar), and one carrying the suffixed version is the pin.
    #[tokio::test]
    async fn property_coordinates_are_the_declared_ga() {
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        for (props, g, a) in [
            ("<g>org.slf4j</g>", "${g}", "slf4j-api"),
            ("<a>slf4j-api</a>", "org.slf4j", "${a}"),
        ] {
            let shadowed = Project::new();
            shadowed.write(
                "pom.xml",
                pom(&format!(
                    "<properties>{props}</properties>\n\
                     <dependencyManagement><dependencies>\n{}</dependencies></dependencyManagement>\n\
                     <dependencies>\n{}</dependencies>\n<repositories>\n{repo}</repositories>\n",
                    dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                    dep(g, a, Some("1.7.36")),
                )),
            );
            let out = run(&shadowed).await;
            assert_refs(&out, &[]);
            assert!(
                diag_codes(&out).contains(&DIAG_REF_INVALID),
                "{g}:{a}: {:?}",
                out.diagnostics
            );

            let pinned = Project::new();
            pinned.write(
                "pom.xml",
                pom(&format!(
                    "<properties>{props}</properties>\n<dependencies>\n{}</dependencies>\n\
                     <repositories>\n{repo}</repositories>\n",
                    dep(g, a, Some(&suffixed(UUID_A))),
                )),
            );
            let out = run(&pinned).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
        }
    }

    /// `.mvn/maven.config`'s `-D` user properties override the pom's own
    /// when Maven interpolates a coordinate: a suffixed pin on a
    /// declaration that Maven reads as another group is not this GA's.
    #[tokio::test]
    async fn coordinate_properties_read_maven_config_overrides() {
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        for (props, config, attested) in [
            ("<g>org.slf4j</g>", "-Dg=com.acme.fork\n", false),
            ("", "-Dg=org.slf4j\n", true),
        ] {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "<properties>{props}</properties>\n<dependencies>\n{}</dependencies>\n\
                     <repositories>\n{repo}</repositories>\n",
                    dep("${g}", "slf4j-api", Some(&suffixed(UUID_A))),
                )),
            );
            p.write(".mvn/maven.config", config);
            let out = run(&p).await;
            let slf4j = out.refs.iter().any(|r| r.purl == FX_PURL);
            assert_eq!(
                slf4j, attested,
                "{config}: {:?} {:?}",
                out.refs, out.diagnostics
            );
        }
    }

    /// Maven gives `.mvn/maven.config`'s `-D` user properties precedence
    /// over the pom's `<properties>` for a `<version>` too (but not over
    /// the model's own `${project.*}`). A pin the pom spells through a
    /// property the build config redefines stays a ref — rollback / remove
    /// / list must still find the pom's wiring — but is not attested: the
    /// build resolves the unpatched jar. A pin only the build config
    /// supplies is no pom.xml wiring at all (hosted mode never writes one,
    /// and rollback / remove never edit `.mvn/maven.config`): diagnosed,
    /// never a ref.
    #[tokio::test]
    async fn version_property_reads_maven_config_overrides() {
        #[derive(Debug, PartialEq)]
        enum Expect {
            Attested,
            Overridden,
            ConfigOnly,
            NoRef,
        }
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        let pin = suffixed(UUID_A);
        let by_prop = dep("org.slf4j", "slf4j-api", Some("${slf4j.version}"));
        let by_model = dep("org.slf4j", "slf4j-api", Some("${project.version}"));
        for (value, declared, config, expect) in [
            // The build config moves the pin back to the base release.
            (
                pin.as_str(),
                &by_prop,
                "-Dslf4j.version=1.7.36\n".to_string(),
                Expect::Overridden,
            ),
            (
                pin.as_str(),
                &by_prop,
                "--define slf4j.version=1.7.30\n".to_string(),
                Expect::Overridden,
            ),
            // The build config swaps one Socket pin for another: the pom's
            // pin is still pom.xml wiring, so no config-only diagnostic.
            (
                pin.as_str(),
                &by_prop,
                format!("-Dslf4j.version={}\n", suffixed(UUID_B)),
                Expect::Overridden,
            ),
            // The build config alone supplies the pin.
            (
                "1.7.36",
                &by_prop,
                format!("-Dslf4j.version={pin}\n"),
                Expect::ConfigOnly,
            ),
            // `${project.version}` is the model's (1.0.0), whatever -D says.
            (
                "1.7.36",
                &by_model,
                format!("-Dproject.version={pin}\n"),
                Expect::NoRef,
            ),
            // Unrelated user properties leave the pom's own.
            (
                pin.as_str(),
                &by_prop,
                "-Dother=1\n".to_string(),
                Expect::Attested,
            ),
        ] {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "<properties><slf4j.version>{value}</slf4j.version></properties>\n\
                     <dependencies>\n{declared}</dependencies>\n<repositories>\n{repo}</repositories>\n",
                )),
            );
            p.write(".mvn/maven.config", &config);
            let out = run(&p).await;
            let what = format!(
                "{config}: {:?} {:?} {:?}",
                out.refs, out.unattested, out.diagnostics
            );
            match expect {
                Expect::Attested | Expect::Overridden => {
                    assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
                    if expect == Expect::Attested {
                        assert!(out.unattested.is_empty(), "{what}");
                    } else {
                        assert_eq!(out.unattested.len(), 1, "{what}");
                        let u = &out.unattested[0];
                        assert_eq!(u.kind, UnattestedKind::MavenConfigOverride, "{what}");
                        assert!(u.detail.contains(".mvn/maven.config"), "{}", u.detail);
                    }
                    assert!(
                        !out.diagnostics
                            .iter()
                            .any(|d| d.detail.contains("only through")),
                        "{what}"
                    );
                }
                Expect::ConfigOnly | Expect::NoRef => {
                    assert_refs(&out, &[]);
                    assert!(out.unattested.is_empty(), "{what}");
                    assert_eq!(
                        out.diagnostics
                            .iter()
                            .any(|d| d.detail.contains(".mvn/maven.config")),
                        expect == Expect::ConfigOnly,
                        "{what}"
                    );
                }
            }
        }
    }

    /// A `<profiles>` declaration of the pinned GA applies whenever that
    /// profile is active, and the hosted rewriter leaves it as written
    /// (`redirect_maven_profile_dependency_unpatched`); vendored mode treats
    /// every profile as live. One that moves the GA's main jar off the pin
    /// keeps the ref (rollback / remove / list still find it) but is never
    /// attested: with the profile on, Maven resolves the unpatched jar. A
    /// profile's `<dependencyManagement>` moves it only where management
    /// governs (a direct literal `<version>` beats it), and an executable
    /// classifier copy — live or in a profile — is judged by the version it
    /// resolves, its own or its classifier-keyed managed one.
    #[tokio::test]
    async fn profile_declaration_off_the_pin_is_not_attested() {
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        let pin = suffixed(UUID_A);
        let ga = |v: Option<&str>| dep("org.slf4j", "slf4j-api", v);
        let extra = |tag: &str, c: &str, v: Option<&str>| {
            let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
            format!(
                "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                 {v}<{tag}>{c}</{tag}></dependency>\n"
            )
        };
        let classified = |c: &str, v: Option<&str>| extra("classifier", c, v);
        let typed = |t: &str, v: Option<&str>| extra("type", t, v);
        let deps = |d: &str| format!("<dependencies>\n{d}</dependencies>\n");
        let mgmt = |d: &str| format!("<dependencyManagement>{}</dependencyManagement>\n", deps(d));
        // The live pin: a direct literal, a managed one (governing a
        // version-less declaration), or a direct literal beside a
        // classifier-keyed managed entry at the pin.
        let direct_pin = deps(&ga(Some(&pin)));
        let managed_pin = format!("{}{}", mgmt(&ga(Some(&pin))), deps(&ga(None)));
        let classifier_managed_pin = format!(
            "{}{}",
            mgmt(&classified("tests", Some(&pin))),
            deps(&ga(Some(&pin)))
        );
        let project = |live: &str, profile: &str| {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "{live}<repositories>\n{repo}</repositories>\n\
                     <profiles><profile><id>p</id>\n{profile}</profile></profiles>\n",
                )),
            );
            p
        };
        let profile_kind = UnattestedKind::MavenProfileUnpatched;
        let classifier_kind = UnattestedKind::MavenClassifierUnpatched;
        let tests_unversioned = classified("tests", None);
        let unattested = [
            // The main jar at the base release, another release, one this
            // pom cannot resolve, another Socket pin.
            (&direct_pin, deps(&ga(Some("1.7.36"))), profile_kind),
            (&direct_pin, deps(&ga(Some("1.7.30"))), profile_kind),
            (&direct_pin, deps(&ga(Some("${undefined}"))), profile_kind),
            (
                &direct_pin,
                deps(&ga(Some("1.7.36-socket.88888888"))),
                profile_kind,
            ),
            // Management that governs: the live pin is managed too.
            (&managed_pin, mgmt(&ga(Some("1.7.36"))), profile_kind),
            // A code-carrying type is not the pin's coordinate either: it
            // is an executable variant (`test-jar` is the `tests` jar, see
            // `is_variant` / `is_executable_variant`).
            (
                &direct_pin,
                deps(&typed("test-jar", Some("1.7.36"))),
                classifier_kind,
            ),
            // An executable classifier copy off the pin: its own version,
            // none at all, or a classifier-keyed managed one.
            (
                &direct_pin,
                deps(&classified("tests", Some("1.7.36"))),
                classifier_kind,
            ),
            (&direct_pin, deps(&tests_unversioned), classifier_kind),
            (
                &direct_pin,
                format!(
                    "{}{}",
                    mgmt(&classified("tests", Some("1.7.36"))),
                    deps(&tests_unversioned)
                ),
                classifier_kind,
            ),
            // The profile's classifier management overrides the live one.
            (
                &classifier_managed_pin,
                format!(
                    "{}{}",
                    mgmt(&classified("tests", Some("1.7.36"))),
                    deps(&tests_unversioned)
                ),
                classifier_kind,
            ),
        ];
        for (live, profile, kind) in &unattested {
            let out = run(&project(live, profile)).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.unattested.len(), 1, "{profile}: {:?}", out.unattested);
            let u = &out.unattested[0];
            assert_eq!(u.kind, *kind, "{profile}");
            assert_eq!(
                (u.purl.as_str(), u.uuid.as_str()),
                (FX_PURL, UUID_A),
                "{profile}"
            );
            assert!(
                u.detail.contains("org.slf4j:slf4j-api") && u.detail.contains("<profiles>"),
                "{}",
                u.detail
            );
        }

        let attested = [
            // No version: the live pin applies.
            (&direct_pin, deps(&ga(None))),
            // The pin itself.
            (&direct_pin, deps(&ga(Some(&pin)))),
            (&managed_pin, mgmt(&ga(Some(&pin)))),
            // Management a direct literal version beats.
            (&direct_pin, mgmt(&ga(Some("1.7.36")))),
            // Another GA.
            (
                &direct_pin,
                deps(&dep("org.slf4j", "slf4j-simple", Some("1.7.36"))),
            ),
            // A non-executable classifier copy, or one on the pin.
            (&direct_pin, deps(&classified("sources", Some("1.7.36")))),
            (&direct_pin, deps(&classified("tests", Some(&pin)))),
            // Classifier management no declaration takes.
            (&direct_pin, mgmt(&classified("tests", Some("1.7.36")))),
            // A version-less classifier copy the live management pins.
            (&classifier_managed_pin, deps(&tests_unversioned)),
            // A pom-typed declaration carries no code.
            (&direct_pin, deps(&typed("pom", Some("1.7.36")))),
            // Profile properties only.
            (
                &direct_pin,
                "<properties><x>1</x></properties>\n".to_string(),
            ),
        ];
        for (live, profile) in &attested {
            let out = run(&project(live, profile)).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
            assert!(out.unattested.is_empty(), "{profile}: {:?}", out.unattested);
        }
    }

    /// A versioned declaration whose coordinate is a property this pom
    /// does not define may be the pinned GA, so the pin is not attested
    /// past it (#683).
    #[tokio::test]
    async fn undefined_coordinate_property_is_not_attested_past() {
        let repo = hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A));
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencyManagement><dependencies>\n{}</dependencies></dependencyManagement>\n\
                 <dependencies>\n{}</dependencies>\n<repositories>\n{repo}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                dep("${parent.g}", "slf4j-api", Some("1.7.36")),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(
            diag_codes(&out).contains(&DIAG_REF_INVALID),
            "{:?}",
            out.diagnostics
        );
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.detail.contains("org.slf4j:slf4j-api") && d.detail.contains("1.7.36")),
            "{:?}",
            out.diagnostics
        );

        // A placeholder that cannot be the GA (a non-jar type, or literal
        // text around the reference that differs) does not.
        for other in [
            "<dependency><groupId>${parent.g}</groupId><artifactId>${bom}</artifactId>\
             <version>3</version><type>pom</type><scope>import</scope></dependency>",
            "<dependency><groupId>${parent.g}</groupId><artifactId>${a}-core</artifactId>\
             <version>3</version></dependency>",
        ] {
            let p = Project::new();
            p.write(
                "pom.xml",
                pom(&format!(
                    "<dependencies>\n{}{other}\n</dependencies>\n<repositories>\n{repo}</repositories>\n",
                    dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_A))),
                )),
            );
            let out = run(&p).await;
            assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
        }
    }

    #[tokio::test]
    async fn unsafe_coordinates_on_a_socket_pin_are_invalid() {
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace(
                "<groupId>org.slf4j</groupId>",
                "<groupId>../../etc</groupId>",
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(diag_codes(&out).contains(&DIAG_REF_INVALID));
    }

    #[tokio::test]
    async fn registry_only_pom_yields_nothing() {
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencies>\n{}{}</dependencies>\n<repositories>\n{}</repositories>\n",
                dep("org.slf4j", "slf4j-api", Some("1.7.36")),
                dep("com.google.guava", "guava", Some("33.0.0-jre")),
                hosted_repo(
                    "corp-mirror",
                    "https://nexus.corp.example/repository/maven-public/"
                ),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn malformed_pom_is_a_diagnostic_not_a_panic() {
        for text in [
            "not xml at all".to_string(),
            "{\"project\": true}".to_string(),
            "<project><repositories><repository><id>socket-patch-x".to_string(),
            hosted_pom(UUID_A).replace("</dependency>", ""),
            hosted_pom(UUID_A).replace("</project>", ""),
            "<project>\u{00e9}<!-- \u{1F600} unterminated".to_string(),
        ] {
            let p = Project::new();
            p.write("pom.xml", &text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text}");
            assert!(out.diagnostics[0].detail.contains("pom.xml"));
        }
        // Non-UTF-8 bytes: unreadable, still no panic.
        let p = Project::new();
        p.write("pom.xml", b"<project>\xff\xfe</project>");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    /// Scanner shapes no other test reaches: an incomplete dependency, a
    /// dependency nested in another, a self-closing `<repository/>`,
    /// non-property tags in `<properties>`, profile-scoped properties — none
    /// of which disturbs the real wiring — and the scanner's three
    /// unterminated-tag refusals.
    #[tokio::test]
    async fn pom_scanner_edge_shapes() {
        let extras = "<properties><a:b>x</a:b><bad name/><v>1.0</v></properties>\n\
             <profiles><profile><properties><v>9</v></properties></profile></profiles>\n\
             <repositories><repository/></repositories>\n\
             <dependencies><dependency><groupId>g</groupId></dependency>\n\
             <dependency><groupId>o</groupId><artifactId>n</artifactId>\
             <dependency>x</dependency></dependency></dependencies>\n";
        let p = Project::new();
        p.write(
            "pom.xml",
            hosted_pom(UUID_A).replace("</project>", &format!("{extras}</project>")),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        for text in [
            pom("<properties><v</properties>\n"),
            pom("<properties><v>1</properties>\n"),
            format!("{}<dependency ", pom("")),
        ] {
            let p = Project::new();
            p.write("pom.xml", &text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text}");
        }
    }

    #[tokio::test]
    async fn no_pom_is_silent() {
        let out = run(&Project::new()).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty());
    }

    // ── vendored ─────────────────────────────────────────────────────────

    const V_PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";

    fn v_jar_rel(uuid: &str) -> String {
        format!(".socket/vendor/maven/{uuid}/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar")
    }

    fn project_pom(version: &str) -> String {
        pom(&format!(
            "  <dependencies>\n{}  </dependencies>\n",
            dep("org.apache.commons", "commons-text", Some(version))
        ))
    }

    const V_JAR: &[u8] = b"PK\x03\x04jar";

    fn v_jar_sha1() -> String {
        use sha1::{Digest as _, Sha1};
        hex::encode(Sha1::digest(V_JAR))
    }

    /// A project wired exactly as the pre-v5 single-pom backend left it (a
    /// `<repositories>` section before `</project>`), with the committed
    /// maven2 tree: VEX still reads such a legacy ledger.
    fn vendored_project(uuid: &str) -> Project {
        let p = Project::new();
        let pom = project_pom("1.10.0");
        let at = pom.rfind("</project>").expect("project close");
        let wired = format!(
            "{}  <repositories>\n    <repository>\n      <id>socket-patch-vendor-{uuid}</id>\n      \
             <url>file://${{project.basedir}}/.socket/vendor/maven/{uuid}</url>\n      \
             <releases>\n        <enabled>true</enabled>\n        \
             <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      <snapshots>\n        \
             <enabled>false</enabled>\n      </snapshots>\n    </repository>\n  </repositories>\n{}",
            &pom[..at],
            &pom[at..]
        );
        p.write("pom.xml", wired);
        let jar = v_jar_rel(uuid);
        p.write(&jar, V_JAR);
        p.write(&format!("{jar}.sha1"), v_jar_sha1());
        p.write(&jar.replace(".jar", ".pom"), b"<project/>");
        p.write(
            &format!(".socket/vendor/maven/{uuid}/socket-patch.vendor.json"),
            b"{}",
        );
        p
    }

    #[tokio::test]
    async fn vendor_backend_wiring_yields_the_committed_jar() {
        let p = vendored_project(UUID_A);
        let out = run(&p).await;
        assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        let r = &out.refs[0];
        assert_eq!(r.artifact_rel.as_deref(), Some(v_jar_rel(UUID_A).as_str()));
        assert_eq!(r.source_file, std::path::PathBuf::from("pom.xml"));
        assert_eq!(r.locked_integrity, None);
        assert!(!r.lockfile_basis_ok());
    }

    /// The retired vendored wiring serves the ORIGINAL GAV, main jar only:
    /// a profile that moves the GA to another version bypasses it whenever
    /// it is active, and an executable classifier copy (live or in a
    /// profile, at any version) resolves from the next repository — the
    /// public jar. The ref stays but is not attested.
    #[tokio::test]
    async fn vendored_ref_bypassed_by_a_profile_or_classifier_is_not_attested() {
        let classified = |c: &str, v: &str| {
            format!(
                "<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
                 <version>{v}</version><classifier>{c}</classifier></dependency>\n"
            )
        };
        let in_profile = |d: &str| {
            format!(
                "<profiles><profile><id>p</id><dependencies>\n{d}</dependencies></profile></profiles>\n"
            )
        };
        let live = |d: &str| format!("<dependencies>\n{d}</dependencies>\n");
        for (extra, kind) in [
            (
                in_profile(&dep("org.apache.commons", "commons-text", Some("1.10.1"))),
                Some(UnattestedKind::MavenProfileUnpatched),
            ),
            (
                in_profile(&dep("org.apache.commons", "commons-text", Some("1.10.0"))),
                None,
            ),
            (
                live(&classified("tests", "1.10.0")),
                Some(UnattestedKind::MavenClassifierUnpatched),
            ),
            (
                in_profile(&classified("tests", "1.10.0")),
                Some(UnattestedKind::MavenClassifierUnpatched),
            ),
            (live(&classified("sources", "1.10.0")), None),
        ] {
            let p = vendored_project(UUID_A);
            let wired = std::fs::read_to_string(p.root().join("pom.xml")).expect("read pom");
            let at = wired.rfind("</project>").expect("project close");
            p.write(
                "pom.xml",
                format!("{}{extra}{}", &wired[..at], &wired[at..]),
            );
            let out = run(&p).await;
            assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
            let kinds: Vec<_> = out.unattested.iter().map(|u| u.kind).collect();
            assert_eq!(kinds, kind.into_iter().collect::<Vec<_>>(), "{extra}");
        }
    }

    /// Review on #2005 (round 2): a `-D` property `.mvn/maven.config` alone
    /// defines AT the vendored version is the pin, not an override.
    #[tokio::test]
    async fn vendored_version_from_maven_config_at_the_pin_is_attested() {
        let p = vendored_project(UUID_A);
        let wired = std::fs::read_to_string(p.root().join("pom.xml")).expect("read pom");
        let spelled = wired.replacen(
            "<version>1.10.0</version>",
            "<version>${commons.version}</version>",
            1,
        );
        assert_ne!(spelled, wired);
        p.write("pom.xml", &spelled);
        p.write(".mvn/maven.config", "-Dcommons.version=1.10.0\n");
        let out = run(&p).await;
        assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
        p.write(".mvn/maven.config", "-Dcommons.version=1.9\n");
        let out = run(&p).await;
        let kinds: Vec<_> = out.unattested.iter().map(|u| u.kind).collect();
        assert_eq!(kinds, [UnattestedKind::MavenConfigOverride]);
        assert!(
            out.unattested[0].detail.ends_with("makes it resolve 1.9"),
            "{}",
            out.unattested[0].detail
        );
    }

    /// Review on #2005 (round 2): a profile `<dependencyManagement>` entry
    /// for a classifier copy that sets no `<version>` (scope, exclusions)
    /// overrides no version: the live managed pin still governs.
    #[tokio::test]
    async fn a_versionless_profile_management_entry_overrides_nothing() {
        let pin = suffixed(UUID_A);
        let tests = |v: Option<&str>| {
            let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
            format!(
                "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                 {v}<classifier>tests</classifier><scope>test</scope></dependency>\n"
            )
        };
        let p = Project::new();
        p.write(
            "pom.xml",
            pom(&format!(
                "<dependencyManagement>\n<dependencies>\n{}</dependencies>\n</dependencyManagement>\n\
                 <dependencies>\n{}{}</dependencies>\n\
                 <profiles><profile><id>p</id><dependencyManagement><dependencies>\n{}\
                 </dependencies></dependencyManagement></profile></profiles>\n\
                 <repositories>\n{}</repositories>\n",
                tests(Some(&pin)),
                dep("org.slf4j", "slf4j-api", Some(&pin)),
                tests(None),
                tests(None),
                hosted_repo(&format!("socket-patch-{UUID_A}"), &registry_url(UUID_A)),
            )),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(FX_PURL, UUID_A, WiringMode::Hosted)]);
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);
    }

    #[tokio::test]
    async fn vendored_url_spellings() {
        for spelled in [
            format!("file:${{project.basedir}}/.socket/vendor/maven/{UUID_A}"),
            format!("file://${{basedir}}/.socket/vendor/maven/{UUID_A}/"),
            format!("file://${{project.basedir}}/./.socket/vendor/maven/{UUID_A}"),
        ] {
            let p = vendored_project(UUID_A);
            let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
            p.write(
                "pom.xml",
                text.replace(
                    &format!("file://${{project.basedir}}/.socket/vendor/maven/{UUID_A}"),
                    &spelled,
                ),
            );
            let out = run(&p).await;
            assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
        }
    }

    #[tokio::test]
    async fn vendored_url_outside_the_project_or_traversing_is_invalid() {
        for spelled in [
            format!("file:///home/ci/.socket/vendor/maven/{UUID_A}"),
            format!("file://${{project.basedir}}/../.socket/vendor/maven/{UUID_A}"),
            format!("file://${{project.basedir}}/.socket/vendor/maven/{UUID_A}/../../../../etc"),
            format!("file://${{project.basedir}}/.socket/vendor/npm/{UUID_A}"),
            format!("file://${{project.basedir}}/.socket/vendor/maven/{UUID_B}"),
        ] {
            let p = vendored_project(UUID_A);
            let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
            p.write(
                "pom.xml",
                text.replace(
                    &format!("file://${{project.basedir}}/.socket/vendor/maven/{UUID_A}"),
                    &spelled,
                ),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{spelled}");
        }
    }

    #[tokio::test]
    async fn vendored_repository_without_exactly_one_jar_is_unattributable() {
        // Artifact dir gone.
        let p = vendored_project(UUID_A);
        std::fs::remove_dir_all(p.root().join(format!(".socket/vendor/maven/{UUID_A}")))
            .expect("rm uuid dir");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);

        // Two jars under one uuid dir.
        let p = vendored_project(UUID_A);
        p.write(
            &format!(".socket/vendor/maven/{UUID_A}/org/other/other/2.0/other-2.0.jar"),
            b"PK",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
    }

    #[tokio::test]
    async fn vendored_ga_pinned_to_another_version_is_invalid() {
        let p = vendored_project(UUID_A);
        let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
        p.write(
            "pom.xml",
            text.replace("<version>1.10.0</version>", "<version>1.11.0</version>"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);

        // Transitive (no declaration) and property-managed versions attest.
        let p = vendored_project(UUID_A);
        let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
        p.write(
            "pom.xml",
            text.replace(
                "<version>1.10.0</version>",
                "<version>${parent.managed}</version>",
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);

        // #683: a declaration whose groupId is a property this pom does not
        // define may be the GA. At the vendored version it consumes the
        // vendored jar; at another version it may not.
        for (version, attested) in [("1.10.0", true), ("1.11.0", false)] {
            let p = vendored_project(UUID_A);
            let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
            p.write(
                "pom.xml",
                text.replace(
                    "<groupId>org.apache.commons</groupId>",
                    "<groupId>${parent.g}</groupId>",
                )
                .replace(
                    "<version>1.10.0</version>",
                    &format!("<version>{version}</version>"),
                ),
            );
            let out = run(&p).await;
            if attested {
                assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
            } else {
                assert_refs(&out, &[]);
                assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{version}");
            }
        }
    }

    /// REGRESSION: the vendored repository is `checksumPolicy=fail`, so the
    /// jar's `.sha1` sidecar is part of the wiring. With it stale or gone,
    /// real Maven (3.6.3 → 4.0.0-rc-7, `e2e_vendor_maven_build`) rejects the
    /// file:// copy and silently resolves Central's pristine jar — while the
    /// committed members still hash-verify, so the ref must not attest a
    /// build that no longer consumes the patch.
    #[tokio::test]
    async fn vendored_jar_sidecar_must_match_the_jar() {
        let sidecar = format!("{}.sha1", v_jar_rel(UUID_A));
        for (label, content) in [
            ("stale", Some("0".repeat(40))),
            ("empty", Some(String::new())),
            (
                "other file's",
                Some(format!("{}  other.jar", "1".repeat(40))),
            ),
            ("missing", None),
        ] {
            let p = vendored_project(UUID_A);
            match content {
                Some(text) => {
                    p.write(&sidecar, text);
                }
                None => std::fs::remove_file(p.root().join(&sidecar)).expect("rm sidecar"),
            }
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{label}");
            // Still recognized: a ledger claim for the uuid is dead, not
            // re-derived from the pom text (rule 11).
            assert!(out.recognizes(UUID_A, WiringMode::Vendored), "{label}");
        }
        // The spellings maven-resolver accepts: uppercase hex, `sha1sum`'s
        // `<hex>  <file>` line, surrounding whitespace / a trailing newline.
        for spelled in [
            v_jar_sha1().to_ascii_uppercase(),
            format!("{}  commons-text-1.10.0.jar\n", v_jar_sha1()),
            format!("\n  {}\r\n", v_jar_sha1()),
        ] {
            let p = vendored_project(UUID_A);
            p.write(&sidecar, &spelled);
            let out = run(&p).await;
            assert_refs(&out, &[(V_PURL, UUID_A, WiringMode::Vendored)]);
        }
    }

    #[tokio::test]
    async fn vendored_id_must_match_the_url() {
        let p = vendored_project(UUID_A);
        let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
        p.write(
            "pom.xml",
            text.replace(
                &format!("<id>socket-patch-vendor-{UUID_A}</id>"),
                "<id>local</id>",
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn hosted_and_vendored_side_by_side_through_the_orchestrator() {
        let p = vendored_project(UUID_A);
        let text = std::fs::read_to_string(p.root().join("pom.xml")).expect("pom");
        let hosted = format!(
            "{}{}",
            dep("org.slf4j", "slf4j-api", Some(&suffixed(UUID_B))),
            "  </dependencies>"
        );
        let text = text.replacen("  </dependencies>", &hosted, 1).replacen(
            "  </repositories>",
            &format!(
                "{}  </repositories>",
                hosted_repo(&format!("socket-patch-{UUID_B}"), &registry_url(UUID_B))
            ),
            1,
        );
        p.write("pom.xml", text);
        let out = p.discover().await;
        assert_refs(
            &out,
            &[
                (V_PURL, UUID_A, WiringMode::Vendored),
                (FX_PURL, UUID_B, WiringMode::Hosted),
            ],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }
}
