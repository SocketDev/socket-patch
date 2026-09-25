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
//! different effective versions) is diagnosed, not a ref. A `${property}`
//! version is resolved one level from the root `<properties>`.
//!
//! Integrity: when the pom sha256 was known the rewriter also writes Maven
//! Trusted Checksums — `.mvn/checksums/checksums.sha256` lines
//! `<sha256>  <g-path>/<a>/<v>/<a>-<v>.jar` under the SUFFIXED version, made
//! effective by `-Daether.artifactResolver.postProcessor.trustedChecksums=true`
//! in `.mvn/maven.config`. That jar line becomes
//! [`LockIntegrity::Sha256Hex`] (only while the resolver switch is on).
//! `integrity_required` is FALSE: the rewriter writes checksums only when
//! both hashes are known, and the suffixed version itself is the
//! fail-closed pin (no other repository serves it; the Socket repository is
//! `checksumPolicy=fail`).
//!
//! ## Vendored (`vendor::maven_repo`)
//!
//! `vendor_maven` inserts `<id>socket-patch-vendor-<uuid></id>` +
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
//! there is diagnosed, never a ref. Submodule poms and parent poms are not
//! read (root-only). Gradle builds are out of scope (the hosted rewriter
//! only prints a manual snippet; vendoring refuses them).

use std::collections::{BTreeMap, BTreeSet};

use super::{
    maven_purl, names_vendor_dir, socket_patch_name_uuid, vendor_ref, vendor_uuid_dir, DiscoverCtx,
    Discovery, PatchedRef, WiringMode, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
    DIAG_REF_UNATTRIBUTABLE,
};
use crate::patch::redirect::{
    local_repo_artifact_path, MVN_CHECKSUMS, MVN_CONFIG, TRUSTED_CHECKSUMS_ON,
};
use crate::utils::digest::sha256_hex;
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::maven_pom::{
    is_maven_coordinate, is_maven_version_text, parse_pom, split_socket_version, Pom, PomDep,
    PomRepo,
};
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
    let pom = match parse_pom(&raw) {
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

    let gas = group_by_ga(&pom.deps);
    extract_hosted(ctx, &pom, &gas, &hosted, out).await;
    if !vendored.is_empty() {
        extract_vendored(ctx, &gas, &vendored, out).await;
    }
}

// ── hosted ───────────────────────────────────────────────────────────────

async fn extract_hosted(
    ctx: &DiscoverCtx<'_>,
    pom: &Pom,
    gas: &BTreeMap<(String, String), GaVersions>,
    hosted: &BTreeMap<String, String>,
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

    for ((group, artifact), versions) in gas {
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
        // Maven's own precedence: a direct literal version wins over the
        // managed one; the managed version applies only when no direct
        // declaration carries a version.
        let effective = if versions.direct.is_empty() {
            &versions.managed
        } else {
            &versions.direct
        };
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
        match candidates.as_slice() {
            [uuid] => {
                ties.entry(*uuid).or_default().insert((
                    purl,
                    group.clone(),
                    artifact.clone(),
                    pinned.clone(),
                ));
            }
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
            checksums = Some(trusted_checksums(ctx, out).await);
        }
        let jar = local_repo_artifact_path(group, artifact, pinned, "jar");
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
/// when `.mvn/maven.config` does not switch the trusted-checksums resolver
/// on (the file is then inert and pins nothing). Malformed lines are
/// skipped, like the rewriter's own merge.
async fn trusted_checksums(ctx: &DiscoverCtx<'_>, out: &mut Discovery) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Some(config) = ctx.read_text(MVN_CONFIG, out).await else {
        return map;
    };
    if !config
        .split_whitespace()
        .any(|arg| arg == TRUSTED_CHECKSUMS_ON)
    {
        return map;
    }
    let Some(text) = ctx.read_text(MVN_CHECKSUMS, out).await else {
        return map;
    };
    for line in text.lines() {
        let Some((hash, path)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        let path = path.trim_start().trim_start_matches('*').trim_end();
        if let Some(hash) = sha256_hex(hash).filter(|_| !path.is_empty()) {
            map.insert(path.to_string(), hash);
        }
    }
    map
}

// ── vendored ─────────────────────────────────────────────────────────────

async fn extract_vendored(
    ctx: &DiscoverCtx<'_>,
    gas: &BTreeMap<(String, String), GaVersions>,
    vendored: &BTreeSet<String>,
    out: &mut Discovery,
) {
    let swept: BTreeMap<String, Vec<String>> = sweep_vendor_dirs(ctx.root)
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
            local_repo_artifact_path(group, artifact, version, "jar")
        );
        let jar_ok = tokio::fs::symlink_metadata(ctx.root.join(&rel))
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
        if let Some(versions) = gas.get(&(group.to_string(), artifact.to_string())) {
            let effective = if versions.direct.is_empty() {
                &versions.managed
            } else {
                &versions.direct
            };
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
    let id_socket = id.starts_with("socket-patch-");
    let id_hosted = socket_patch_name_uuid(id, false);
    let id_vendored = socket_patch_name_uuid(id, true);
    let url_hosted = ctx.hosted_uuid(url);
    let url_vendor_text = names_vendor_dir(url);
    if !id_socket && url_hosted.is_none() && !url_vendor_text {
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

/// Distinct literal versions of one `groupId:artifactId`, split by where
/// they are declared (profile-scoped declarations excluded).
#[derive(Debug, Default)]
struct GaVersions {
    direct: BTreeSet<String>,
    managed: BTreeSet<String>,
}

fn group_by_ga(deps: &[PomDep]) -> BTreeMap<(String, String), GaVersions> {
    let mut map: BTreeMap<(String, String), GaVersions> = BTreeMap::new();
    for dep in deps.iter().filter(|d| !d.in_profile) {
        let Some(version) = &dep.version else {
            continue;
        };
        let entry = map
            .entry((dep.group.clone(), dep.artifact.clone()))
            .or_default();
        if dep.managed {
            entry.managed.insert(version.clone());
        } else {
            entry.direct.insert(version.clone());
        }
    }
    map
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
        ] {
            let out = run(&fixture(case)).await;
            assert_refs(&out, &[(FX_PURL, FX_UUID, WiringMode::Hosted)]);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
            let r = &out.refs[0];
            assert_eq!(r.source_file, std::path::PathBuf::from("pom.xml"), "{case}");
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sha256Hex(FX_JAR_SHA.into())),
                "{case}"
            );
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

    /// A project wired exactly as `vendor_maven` wires it (its own
    /// `build_repo_edit`), with the committed maven2 tree.
    fn vendored_project(uuid: &str) -> Project {
        let p = Project::new();
        let wired = crate::vendor::maven_repo::build_repo_edit(
            &project_pom("1.10.0"),
            &format!("socket-patch-vendor-{uuid}"),
            &format!(".socket/vendor/maven/{uuid}"),
        )
        .expect("vendor wiring edit");
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
    }

    /// REGRESSION: the vendored repository is `checksumPolicy=fail`, so the
    /// jar's `.sha1` sidecar is part of the wiring. With it stale or gone,
    /// real Maven (3.6.3 → 4.0.0-rc-6, `e2e_vendor_maven_build`) rejects the
    /// file:// copy and silently resolves Central's pristine jar — while the
    /// committed members still hash-verify, so this ref used to attest a
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
