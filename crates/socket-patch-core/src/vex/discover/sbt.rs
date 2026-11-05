//! sbt — the generated `socket-patch.sbt` (hosted) and
//! `socket-patch-vendor.sbt` (vendored) at the build root.
//!
//! A pin row ties a uuid to its GAV directly, but a row proves only that
//! the file asks for the patch: sbt may still resolve another version (a
//! project-level `dependencyOverrides :=`) or another copy (a stale Ivy
//! origin, `mavenLocal`). So every strictly parsed hosted pin is a ref
//! (the management commands restore and eject it like any other), but it
//! carries a lock pin, and is thereby attestable from the wiring, only
//! when the build's local resolution evidence (`crawlers::sbt_evidence`)
//! verifies it: every version sbt recorded for the GA is the pinned
//! `<base>-socket.<hex8>`, and every artifact file recorded for it hashes to
//! one of the pin's sha256s, the jar's among them. Otherwise the diagnostic
//! `sbt_resolution_unverified`, and the ref keeps only the installed-copy
//! basis (the suffixed copy under `.socket/sbt-hosted`, which only the
//! hosted file downloads).
//!
//! That copy proves sbt loaded the hosted file once, not that the build
//! resolves it. Where the build provably does not apply the pin
//! ([`bypass`]: a build edit dropping the generated override or resolver,
//! or current evidence resolving another version or other bytes), the ref
//! is also marked [`Unattested`] (`SbtPinBypassed`), so no basis attests
//! it.
//!
//! The check is on content, not location, like the generated file's own
//! load-time verifier: Ivy legitimately serves a second checkout from the
//! first checkout's `file:` origin (`docs/design/sbt-template-probe.md`,
//! case i), and a copy whose bytes are the pinned ones is the patch.
//!
//! Vendored pins are attested by the vendor ledger; this extractor only
//! diagnoses what would make that attestation a lie: a tree file gone or
//! changed (`vendored_tree_missing`) or an unverified resolution.
//!
//! A generated file socket-patch cannot parse strictly is
//! `sbt_owned_file_modified` (a foreign file under the name is not ours and
//! is ignored).
//!
//! [`Unattested`]: super::Unattested

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{DiscoverCtx, Discovery, PatchedRef, UnattestedKind, DIAG_REF_INVALID};
use crate::formats::sbt::owned_file::{
    parse, OwnedFileError, SbtFileMode, SbtPin, HOSTED_FILE, VENDORED_FILE, VENDORED_REPO_REL,
};
use crate::formats::sbt::JvmResolution;
use crate::utils::purl::maven_purl;
use crate::vendor::lock_inventory::LockIntegrity;

/// The generated file was edited (strict parse failed).
pub const DIAG_SBT_OWNED_FILE_MODIFIED: &str = "sbt_owned_file_modified";
/// A pin whose resolution the local evidence does not verify.
pub const DIAG_SBT_RESOLUTION_UNVERIFIED: &str = "sbt_resolution_unverified";
/// A vendored pin whose committed tree files are missing or modified.
pub const DIAG_VENDORED_TREE_MISSING: &str = "vendored_tree_missing";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let hosted = ctx.read_text(HOSTED_FILE, out).await;
    let vendored = ctx.read_text(VENDORED_FILE, out).await;
    if hosted.is_none() && vendored.is_none() {
        return;
    }
    // The resolution evidence is sbt's own output tree, and the build
    // sources are a walk: only a disk has either.
    let build = match ctx.disk_root() {
        Some(root) => build_state(root).await,
        None => BuildState::default(),
    };
    let mut hashes = Hashes::default();
    if let Some(text) = hosted {
        if let Some(pins) = strict(SbtFileMode::Hosted, &text, out) {
            for pin in pins {
                hosted_ref(ctx, &pin, &build, &mut hashes, out).await;
            }
        }
    }
    if let Some(text) = vendored {
        if let Some(pins) = strict(SbtFileMode::Vendored, &text, out) {
            let (res, blocker) = (build.res.as_ref(), build.blocker.as_deref());
            for pin in pins {
                vendored_check(ctx, &pin, res, blocker, &mut hashes, out).await;
            }
        }
    }
}

/// What the build's local state says about every pin.
#[derive(Debug, Default)]
struct BuildState {
    /// The build's resolution evidence (`None` when there is none).
    res: Option<JvmResolution>,
    /// Why the evidence cannot vouch for any pin even where it shows one
    /// ([`evidence_blocker`]).
    blocker: Option<String>,
    /// A build edit that keeps the generated pin from applying
    /// ([`edit_bypass`]), read off the build sources whether or not any
    /// evidence exists.
    edit: Option<String>,
    /// The evidence postdates every build source and the generated files,
    /// so what it records is what the build resolves now.
    current: bool,
}

/// The build's state under `root`: its sources scanned, its evidence read
/// (`sbt_evidence::discover`'s rule: no evidence file, no evidence).
async fn build_state(root: &Path) -> BuildState {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let Ok(e) = crate::crawlers::sbt_evidence::scan(&root) else {
            return BuildState::default();
        };
        let edit = edit_bypass(&crate::formats::sbt::build::scan_build_sources(
            &e.build_sources,
        ));
        if e.files.is_empty() {
            return BuildState {
                edit,
                ..BuildState::default()
            };
        }
        let res = crate::crawlers::sbt_evidence::resolution(&e);
        let blocker = res.as_ref().and_then(|res| evidence_blocker(&e, res));
        BuildState {
            res,
            blocker,
            edit,
            current: !e.stale && !e.wiring_newer,
        }
    })
    .await
    .unwrap_or_default()
}

/// The build edit under which the generated file pins nothing where the
/// edit applies, so no copy (installed, cached or resolved) shows that the
/// build uses the pinned bytes: a `dependencyOverrides` reassignment
/// replaces the generated override (the build resolves the version it
/// declares), and a `resolvers` reassignment or `sbt.override.build.repos`
/// drops the generated resolver (the pinned version resolves from another
/// repository, or not at all). The other build-wide blockers
/// ([`evidence_blocker`]) only make the evidence too old or too partial to
/// verify a pin, and a `build.sbt.lock` checks the resolution without
/// changing it: under none of them does the pin stop applying.
fn edit_bypass(findings: &crate::formats::sbt::build::BuildFindings) -> Option<String> {
    if !findings.overrides_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) `dependencyOverrides`, which replaces socket-patch's override where \
             it applies, so the build resolves the version it declares there (append with `+=` \
             instead)",
            findings.overrides_assignment.join(", ")
        ));
    }
    if !findings.resolvers_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) `resolvers`, which drops socket-patch's resolver where it applies, \
             so the pinned version does not resolve from it there (append with `+=` instead)",
            findings.resolvers_assignment.join(", ")
        ));
    }
    if !findings.override_build_repos.is_empty() {
        return Some(format!(
            "{} set(s) `sbt.override.build.repos=true`, so the launcher's repositories replace \
             the build's, socket-patch's resolver among them",
            findings.override_build_repos.join(", ")
        ));
    }
    None
}

/// Why the build provably does not use `pin`'s bytes, whatever copy is
/// installed: a build edit ([`edit_bypass`]), or current evidence
/// ([`BuildState::current`]) recording another version of the GA, or a
/// readable artifact of the pinned version whose bytes are not pinned.
/// Evidence older than a build source or the generated files proves
/// nothing either way (it may predate the pin), and neither does an
/// artifact file that is gone (an evicted cache).
async fn bypass(pin: &SbtPin, build: &BuildState, hashes: &mut Hashes) -> Option<String> {
    if let Some(edit) = &build.edit {
        return Some(edit.clone());
    }
    let res = build.res.as_ref().filter(|_| build.current)?;
    let ga = format!("{}:{}", pin.group, pin.artifact);
    if let Some(other) = res
        .versions(&pin.group, &pin.artifact)
        .into_iter()
        .find(|v| *v != pin.sv)
    {
        return Some(format!(
            "the build's current resolution evidence resolves {ga}:{other}, not the pinned {} \
             (something in the build forces that version, or a project the pin does not reach \
             resolves it)",
            pin.sv
        ));
    }
    let paths = res
        .artifacts
        .get(&(pin.group.clone(), pin.artifact.clone(), pin.sv.clone()))
        .into_iter()
        .flatten();
    for path in paths {
        if let Some(got) = hashes.of(path).await {
            if got != pin.jar_sha256 && got != pin.pom_sha256 {
                return Some(format!(
                    "the build's current resolution evidence resolves {ga}:{} to {} with \
                     sha256 {got}, which is not pinned (a copy another repository serves, \
                     such as `mavenLocal` or an Ivy-local publish)",
                    pin.sv,
                    path.display()
                ));
            }
        }
    }
    None
}

/// The build-wide conditions under which evidence showing the pin is not
/// enough (the same ones the hosted rewriter's `check_new` gate refuses a
/// new pin on): a build source newer than some project's evidence, a
/// declared project with no evidence (only part of the build resolved), a
/// project definition that cannot be read statically, a build source
/// reassigning `dependencyOverrides` (it replaces the generated override
/// where it applies) or `resolvers`, or a `build.sbt.lock`.
fn evidence_blocker(
    e: &crate::crawlers::sbt_evidence::SbtEvidence,
    res: &JvmResolution,
) -> Option<String> {
    use crate::formats::sbt::build::{declared_projects, scan_build_sources};
    if e.stale {
        return Some(
            "a build source changed after the last `sbt update`; run `sbt update`".to_string(),
        );
    }
    let Some(declared) = declared_projects(&e.build_sources) else {
        return Some(
            "the build's project definitions cannot be read statically, so its evidence may \
             not cover every project"
                .to_string(),
        );
    };
    let missing: Vec<&str> = declared
        .values()
        .filter(|dir| !res.projects_seen.contains(*dir))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Some(format!(
            "no resolution evidence for project(s) {}; run `sbt update` for the whole build",
            missing.join(", ")
        ));
    }
    let findings = scan_build_sources(&e.build_sources);
    if !findings.overrides_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) `dependencyOverrides`, which replaces the pin where it applies",
            findings.overrides_assignment.join(", ")
        ));
    }
    if !findings.resolvers_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) `resolvers`, which can drop the pin's repository",
            findings.resolvers_assignment.join(", ")
        ));
    }
    if !findings.dependency_lock.is_empty() {
        return Some(format!(
            "{} locks the build's dependencies, which rejects the pinned version",
            findings.dependency_lock.join(", ")
        ));
    }
    None
}

/// [`verify`], unless the evidence as a whole cannot vouch for a pin.
async fn verify_with(
    pin: &SbtPin,
    res: Option<&JvmResolution>,
    blocker: Option<&str>,
    hashes: &mut Hashes,
) -> Result<(), String> {
    match (res, blocker) {
        (Some(_), Some(why)) => Err(why.to_string()),
        _ => verify(pin, res, hashes).await,
    }
}

/// The pins of a generated file of `mode`, or `None` after a diagnostic.
fn strict(mode: SbtFileMode, text: &str, out: &mut Discovery) -> Option<Vec<SbtPin>> {
    match parse(mode, text) {
        Ok(file) => Some(file.pins.into_values().collect()),
        Err(OwnedFileError::Foreign) => None,
        Err(OwnedFileError::Modified(why)) => {
            out.diag(
                DIAG_SBT_OWNED_FILE_MODIFIED,
                mode.file(),
                format!(
                    "{} is not what socket-patch generated ({why}); its pins are not \
                     attested",
                    mode.file()
                ),
            );
            None
        }
    }
}

/// sha256 hex of files by absolute path, memoised (`None` = unreadable).
#[derive(Default)]
struct Hashes(BTreeMap<PathBuf, Option<String>>);

impl Hashes {
    async fn of(&mut self, path: &Path) -> Option<String> {
        if let Some(known) = self.0.get(path) {
            return known.clone();
        }
        let hex = crate::vendor::verify::file_sha256_hex(path).await;
        self.0.insert(path.to_path_buf(), hex.clone());
        hex
    }
}

/// Why the evidence does not verify `pin` (see the module doc); `Ok` when
/// it does.
async fn verify(
    pin: &SbtPin,
    res: Option<&JvmResolution>,
    hashes: &mut Hashes,
) -> Result<(), String> {
    let ga = format!("{}:{}", pin.group, pin.artifact);
    let Some(res) = res else {
        return Err(format!(
            "no sbt resolution evidence under target/ shows how {ga} resolves; run `sbt update`"
        ));
    };
    let versions = res.versions(&pin.group, &pin.artifact);
    if versions.is_empty() {
        return Err(format!(
            "the build's resolution evidence does not resolve {ga}; run `sbt update`"
        ));
    }
    if let Some(other) = versions.iter().find(|v| **v != pin.sv) {
        return Err(format!(
            "the build resolves {ga}:{other}, not the pinned {}",
            pin.sv
        ));
    }
    let paths: Vec<&PathBuf> = res
        .artifacts
        .get(&(pin.group.clone(), pin.artifact.clone(), pin.sv.clone()))
        .into_iter()
        .flatten()
        .collect();
    if paths.is_empty() {
        return Err(format!(
            "the build's resolution evidence records no artifact file for {ga}:{}",
            pin.sv
        ));
    }
    let mut jar_seen = false;
    for path in paths {
        match hashes.of(path).await {
            Some(got) if got == pin.jar_sha256 => jar_seen = true,
            Some(got) if got == pin.pom_sha256 => {}
            Some(got) => {
                return Err(format!(
                    "{ga}:{} resolved to {} with sha256 {got}, which is not pinned",
                    pin.sv,
                    path.display()
                ))
            }
            None => {
                return Err(format!(
                    "{ga}:{} resolved to {}, which cannot be read",
                    pin.sv,
                    path.display()
                ))
            }
        }
    }
    if !jar_seen {
        return Err(format!(
            "no resolved artifact of {ga}:{} is the pinned jar",
            pin.sv
        ));
    }
    Ok(())
}

async fn hosted_ref(
    ctx: &DiscoverCtx<'_>,
    pin: &SbtPin,
    build: &BuildState,
    hashes: &mut Hashes,
    out: &mut Discovery,
) {
    let index = pin.index_url.as_deref().unwrap_or_default();
    let jar_url = format!("{index}/{}", pin.repo_path("jar"));
    let named = ctx.hosted_uuid(&jar_url);
    let Some(purl) = maven_purl(&pin.group, &pin.artifact, &pin.base) else {
        out.diag(
            DIAG_REF_INVALID,
            HOSTED_FILE,
            format!(
                "{HOSTED_FILE}: {}:{}:{} is not a usable Maven coordinate",
                pin.group, pin.artifact, pin.base
            ),
        );
        return;
    };
    if named.as_deref() != Some(pin.uuid.as_str()) {
        out.diag(
            DIAG_REF_INVALID,
            HOSTED_FILE,
            format!(
                "{HOSTED_FILE}: the row for patch {} downloads from {jar_url}, which is not a \
                 Socket-hosted URL of that patch",
                pin.uuid
            ),
        );
        return;
    }
    let (res, blocker) = (build.res.as_ref(), build.blocker.as_deref());
    let locked = match verify_with(pin, res, blocker, hashes).await {
        Ok(()) => Some(LockIntegrity::Sha256Hex(pin.jar_sha256.clone())),
        Err(why) => {
            out.diag(
                DIAG_SBT_RESOLUTION_UNVERIFIED,
                HOSTED_FILE,
                format!("{HOSTED_FILE}: patch {} ({purl}): {why}", pin.uuid),
            );
            None
        }
    };
    // Unverified, the ref still attests from the installed copy; where the
    // build provably does not apply the pin, from nothing.
    if let Some(why) = bypass(pin, build, hashes).await {
        out.unattested(
            &purl,
            &pin.uuid,
            HOSTED_FILE,
            why,
            UnattestedKind::SbtPinBypassed,
        );
    }
    out.push(PatchedRef::hosted(
        purl,
        pin.uuid.clone(),
        HOSTED_FILE,
        Some(&jar_url),
        locked,
        true,
    ));
}

async fn vendored_check(
    ctx: &DiscoverCtx<'_>,
    pin: &SbtPin,
    res: Option<&JvmResolution>,
    blocker: Option<&str>,
    hashes: &mut Hashes,
    out: &mut Discovery,
) {
    for (ext, want) in [("pom", &pin.pom_sha256), ("jar", &pin.jar_sha256)] {
        let rel = format!("{VENDORED_REPO_REL}/{}", pin.repo_path(ext));
        let got = match ctx.disk_root() {
            Some(root) => hashes.of(&root.join(&rel)).await,
            None => None,
        };
        if got.as_deref() != Some(want.as_str()) {
            out.diag(
                DIAG_VENDORED_TREE_MISSING,
                VENDORED_FILE,
                format!(
                    "{VENDORED_FILE}: patch {} pins {rel}, which is {}",
                    pin.uuid,
                    if got.is_some() { "modified" } else { "missing" }
                ),
            );
            return;
        }
    }
    if let Err(why) = verify_with(pin, res, blocker, hashes).await {
        out.diag(
            DIAG_SBT_RESOLUTION_UNVERIFIED,
            VENDORED_FILE,
            format!("{VENDORED_FILE}: patch {}: {why}", pin.uuid),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    const UUID: &str = "abcdef12-0000-4000-8000-000000000001";
    const SV: &str = "3.11-socket.abcdef12";

    fn pin(jar: &str) -> SbtPin {
        SbtPin {
            uuid: UUID.into(),
            group: "org.apache.commons".into(),
            artifact: "commons-lang3".into(),
            base: "3.11".into(),
            sv: SV.into(),
            pom_sha256: "a".repeat(64),
            jar_sha256: jar.into(),
            deps_digest: "0a1b2c3d".into(),
            index_url: Some(format!(
                "https://patch.socket.dev/patch-registry/maven/t/{UUID}/maven2"
            )),
        }
    }

    fn res(versions: &[&str], artifact: Option<&Path>) -> JvmResolution {
        let mut r = JvmResolution::default();
        let ga = (
            "org.apache.commons".to_string(),
            "commons-lang3".to_string(),
        );
        for v in versions {
            r.modules
                .entry(ga.clone())
                .or_default()
                .entry(v.to_string())
                .or_default()
                .insert(format!("target/x:compile@{v}"));
        }
        if let Some(p) = artifact {
            r.artifacts
                .entry((ga.0.clone(), ga.1.clone(), SV.into()))
                .or_default()
                .insert(p.to_path_buf());
        }
        r.in_scope.insert(ga);
        r.projects_seen.insert(".".into());
        r
    }

    /// #690 review: evidence that shows the pin still cannot vouch for it
    /// when only part of the build resolved, a source changed since, or a
    /// project reassigns `dependencyOverrides`.
    #[test]
    fn evidence_blocker_mirrors_the_new_pin_gate() {
        use crate::crawlers::sbt_evidence::SbtEvidence;
        let sources = |extra: &[(&str, &str)]| {
            let mut v = vec![(
                "build.sbt".to_string(),
                "lazy val core = project\nlazy val app = project\n".to_string(),
            )];
            v.extend(extra.iter().map(|(a, b)| (a.to_string(), b.to_string())));
            v
        };
        let e = |extra: &[(&str, &str)], stale: bool| SbtEvidence {
            build_sources: sources(extra),
            stale,
            ..Default::default()
        };
        let mut all = res(&[SV], None);
        all.projects_seen = [".", "core", "app"].map(String::from).into();
        let mut core_only = all.clone();
        core_only.projects_seen.remove("app");

        assert_eq!(evidence_blocker(&e(&[], false), &all), None);
        let why = evidence_blocker(&e(&[], false), &core_only).unwrap();
        assert!(why.contains("app"), "{why}");
        let why = evidence_blocker(&e(&[], true), &all).unwrap();
        assert!(why.contains("sbt update"), "{why}");
        let overrides = [(
            "app/build.sbt",
            "dependencyOverrides := Seq(\"org.apache.commons\" % \"commons-text\" % \"1.9\")\n",
        )];
        let why = evidence_blocker(&e(&overrides, false), &all).unwrap();
        assert!(why.contains("app/build.sbt:1"), "{why}");
        let resolvers = [("app/build.sbt", "resolvers := Nil\n")];
        let why = evidence_blocker(&e(&resolvers, false), &all).unwrap();
        assert!(why.contains("`resolvers`"), "{why}");
        let lock = [("build.sbt.lock", "{}\n")];
        let why = evidence_blocker(&e(&lock, false), &all).unwrap();
        assert!(why.contains("build.sbt.lock"), "{why}");
    }

    #[tokio::test]
    async fn verify_needs_the_pinned_version_and_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let jar = tmp.path().join("x.jar");
        std::fs::write(&jar, b"patched").unwrap();
        let sha = hex::encode(Sha256::digest(b"patched"));
        let mut h = Hashes::default();
        assert_eq!(
            verify(&pin(&sha), Some(&res(&[SV], Some(&jar))), &mut h).await,
            Ok(())
        );

        let why = verify(&pin(&sha), None, &mut h).await.unwrap_err();
        assert!(why.contains("no sbt resolution evidence"), "{why}");
        let why = verify(&pin(&sha), Some(&res(&[], None)), &mut h)
            .await
            .unwrap_err();
        assert!(why.contains("does not resolve"), "{why}");
        // Shadowed: a project still resolves the base version.
        let why = verify(&pin(&sha), Some(&res(&[SV, "3.11"], Some(&jar))), &mut h)
            .await
            .unwrap_err();
        assert!(why.contains("3.11, not the pinned"), "{why}");
        let why = verify(&pin(&sha), Some(&res(&[SV], None)), &mut h)
            .await
            .unwrap_err();
        assert!(why.contains("no artifact file"), "{why}");
        // Elsewhere: another file, other bytes (ivy-local, mavenLocal).
        let other = tmp.path().join("evil.jar");
        std::fs::write(&other, b"evil").unwrap();
        let why = verify(&pin(&sha), Some(&res(&[SV], Some(&other))), &mut h)
            .await
            .unwrap_err();
        assert!(why.contains("which is not pinned"), "{why}");
        let gone = tmp.path().join("gone.jar");
        let why = verify(&pin(&sha), Some(&res(&[SV], Some(&gone))), &mut h)
            .await
            .unwrap_err();
        assert!(why.contains("cannot be read"), "{why}");
    }

    #[tokio::test]
    async fn verify_accepts_the_pinned_bytes_anywhere() {
        // Ivy serves a second checkout from the first one's origin.
        let tmp = tempfile::tempdir().unwrap();
        let jar = tmp.path().join("other-checkout.jar");
        std::fs::write(&jar, b"patched").unwrap();
        let sha = hex::encode(Sha256::digest(b"patched"));
        assert_eq!(
            verify(
                &pin(&sha),
                Some(&res(&[SV], Some(&jar))),
                &mut Hashes::default()
            )
            .await,
            Ok(())
        );
    }

    /// Only the edits that drop the generated override or resolver mean the
    /// pin is not applied; staleness, partial evidence and a lock do not.
    #[test]
    fn edit_bypass_is_the_pin_dropping_edits_only() {
        use crate::formats::sbt::build::BuildFindings;
        assert_eq!(edit_bypass(&BuildFindings::default()), None);
        let lock = BuildFindings {
            dependency_lock: vec!["build.sbt.lock".into()],
            ..Default::default()
        };
        assert_eq!(edit_bypass(&lock), None);
        for (findings, want) in [
            (
                BuildFindings {
                    overrides_assignment: vec!["a/build.sbt:1".into()],
                    ..Default::default()
                },
                "`dependencyOverrides`",
            ),
            (
                BuildFindings {
                    resolvers_assignment: vec!["build.sbt:2".into()],
                    ..Default::default()
                },
                "`resolvers`",
            ),
            (
                BuildFindings {
                    override_build_repos: vec![".sbtopts:1".into()],
                    ..Default::default()
                },
                "sbt.override.build.repos",
            ),
        ] {
            let why = edit_bypass(&findings).unwrap();
            assert!(why.contains(want), "{why}");
        }
    }

    /// The installed-copy fallback is withdrawn by an edit whatever the
    /// evidence, and by evidence only when it postdates the sources and the
    /// generated file and shows another version or other bytes.
    #[tokio::test]
    async fn bypass_needs_an_edit_or_current_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let jar = tmp.path().join("x.jar");
        std::fs::write(&jar, b"patched").unwrap();
        let sha = hex::encode(Sha256::digest(b"patched"));
        let evil = tmp.path().join("evil.jar");
        std::fs::write(&evil, b"evil").unwrap();
        let gone = tmp.path().join("gone.jar");
        let state = |res: Option<JvmResolution>, current: bool| BuildState {
            res,
            current,
            ..Default::default()
        };
        let mut h = Hashes::default();
        let p = pin(&sha);

        assert_eq!(bypass(&p, &BuildState::default(), &mut h).await, None);
        let edited = BuildState {
            edit: Some("build.sbt:1 reassign(s) `dependencyOverrides`".into()),
            ..Default::default()
        };
        let why = bypass(&p, &edited, &mut h).await.unwrap();
        assert!(why.contains("build.sbt:1"), "{why}");
        // The pinned version and bytes: nothing bypasses.
        let ok = res(&[SV], Some(&jar));
        assert_eq!(bypass(&p, &state(Some(ok), true), &mut h).await, None);
        // Another version: only current evidence counts.
        let shadowed = res(&[SV, "3.11"], Some(&jar));
        assert_eq!(
            bypass(&p, &state(Some(shadowed.clone()), false), &mut h).await,
            None
        );
        let why = bypass(&p, &state(Some(shadowed), true), &mut h)
            .await
            .unwrap();
        assert!(why.contains("3.11, not the pinned"), "{why}");
        let base_only = res(&["3.11"], None);
        assert!(bypass(&p, &state(Some(base_only), true), &mut h)
            .await
            .is_some());
        // Other bytes at the pinned version: the same.
        let elsewhere = res(&[SV], Some(&evil));
        assert_eq!(
            bypass(&p, &state(Some(elsewhere.clone()), false), &mut h).await,
            None
        );
        let why = bypass(&p, &state(Some(elsewhere), true), &mut h)
            .await
            .unwrap();
        assert!(why.contains("which is not pinned"), "{why}");
        // A recorded file that is gone, or no resolution of the GA at all,
        // proves nothing.
        let evicted = res(&[SV], Some(&gone));
        assert_eq!(bypass(&p, &state(Some(evicted), true), &mut h).await, None);
        assert_eq!(
            bypass(&p, &state(Some(res(&[], None)), true), &mut h).await,
            None
        );
    }

    /// A hosted file at the root of an sbt build with no evidence (a fresh
    /// clone), over `build_sbt`.
    fn hosted_build(build_sbt: &str) -> tempfile::TempDir {
        use crate::formats::sbt::owned_file::{render, SbtLine, SbtOwnedFile};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::write(root.join("project/build.properties"), "sbt.version=1.9.9\n").unwrap();
        std::fs::write(root.join("build.sbt"), build_sbt).unwrap();
        let file = render(&SbtOwnedFile {
            mode: SbtFileMode::Hosted,
            line: SbtLine::Sbt1,
            crlf: false,
            pins: [(UUID.to_string(), pin(&"b".repeat(64)))].into(),
        })
        .unwrap();
        std::fs::write(root.join(HOSTED_FILE), file).unwrap();
        tmp
    }

    /// A build source reassigning `dependencyOverrides` (or `resolvers`)
    /// drops the pin where it applies: the hosted ref stays (rollback,
    /// remove and list find it) but is marked unattested, so the copy sbt
    /// downloaded into `.socket/sbt-hosted` cannot attest it. Without the
    /// edit, the unverified ref keeps its installed-copy basis.
    #[tokio::test]
    async fn a_pin_dropping_edit_unattests_the_hosted_ref() {
        const PURL: &str = "pkg:maven/org.apache.commons/commons-lang3@3.11";
        let plain = hosted_build(
            "libraryDependencies += \"org.apache.commons\" % \"commons-lang3\" % \"3.11\"\n",
        );
        let out = super::super::discover_patched_refs(plain.path()).await;
        assert!(
            out.refs.iter().any(|r| r.uuid == UUID && r.purl == PURL),
            "{:?}",
            out.refs
        );
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);

        for (edit, want) in [
            (
                "dependencyOverrides := Seq(\"org.apache.commons\" % \"commons-lang3\" % \"3.11\")\n",
                "`dependencyOverrides`",
            ),
            ("resolvers := Nil\n", "`resolvers`"),
        ] {
            let edited = hosted_build(&format!(
                "libraryDependencies += \"org.apache.commons\" % \"commons-lang3\" % \"3.11\"\n{edit}"
            ));
            let out = super::super::discover_patched_refs(edited.path()).await;
            assert!(
                out.refs.iter().any(|r| r.uuid == UUID && r.purl == PURL),
                "the ref stays: {:?}",
                out.refs
            );
            let [u] = out.unattested.as_slice() else {
                panic!("{edit}: {:?}", out.unattested);
            };
            assert_eq!(
                (u.kind, u.uuid.as_str(), u.purl.as_str()),
                (UnattestedKind::SbtPinBypassed, UUID, PURL)
            );
            assert_eq!(u.file, Path::new(HOSTED_FILE));
            assert!(u.detail.contains("build.sbt:2") && u.detail.contains(want), "{}", u.detail);
        }
    }
}
