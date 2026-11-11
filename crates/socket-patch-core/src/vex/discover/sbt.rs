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
//! resolves it. Where the build provably does not use the pinned bytes
//! ([`bypass`]: a `dependencyOverrides` reassignment replacing the
//! generated override, or evidence dated after the wiring and the sources
//! still resolving the base version, or other bytes) and no such evidence
//! verifies the pin, the ref is also marked [`Unattested`]
//! (`SbtPinBypassed`), so no basis attests it.
//!
//! The check is on content, not location, like the generated file's own
//! load-time verifier: Ivy legitimately serves a second checkout from the
//! first checkout's `file:` origin (`docs/design/sbt-template-probe.md`,
//! case i), and a copy whose bytes are the pinned ones is the patch.
//!
//! Vendored pins are attested by the vendor ledger; this extractor holds
//! them to the same evidence a hosted pin needs. A tree file gone or
//! changed (`vendored_tree_missing`) or a resolution the evidence does not
//! verify (`sbt_resolution_unverified`, the hosted check and build-wide
//! blockers verbatim) is diagnosed AND marked [`Unattested`] for the pin's
//! `(purl, uuid)`, so `vex` omits the ledger entry. Its liveness is
//! untouched: the wiring is intact, and `scan --prune` must not revert a
//! pin only because `sbt update` has not run since. A memory view has no
//! committed tree to hash, so it reports none missing.
//!
//! A generated file socket-patch cannot parse strictly is
//! `sbt_owned_file_modified` (a foreign file under the name is not ours and
//! is ignored).
//!
//! [`Unattested`]: super::Unattested

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{DiscoverCtx, Discovery, PatchedRef, UnattestedKind, DIAG_REF_INVALID};
use crate::formats::sbt::build::BuildFindings;
use crate::formats::sbt::owned_file::{
    parse, OwnedFileError, SbtFileMode, SbtPin, HOSTED_FILE, HOSTED_REPO_REL, VENDORED_FILE,
    VENDORED_REPO_REL,
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
    /// A build edit dropping the generated override or installer
    /// ([`pin_dropped`]), read off the build sources whether or not any
    /// evidence exists.
    dropped: Option<String>,
    /// The hosted pin repository as sbt's evidence spells it (canonical,
    /// `<root>/.socket/sbt-hosted/maven2`).
    repo: Option<PathBuf>,
    /// The evidence files dated after the generated files and every build
    /// source: each one records what its project resolves now, with the
    /// pin in place. An older record (a project or cross build not
    /// re-resolved since) proves nothing about the pin either way.
    current: BTreeSet<String>,
    /// Every record is [`Self::current`] and every declared project has
    /// one: only then does evidence verifying a pin speak for the whole
    /// build, and so overrule a build edit dropping it ([`bypass`]).
    whole: bool,
}

/// The build's state under `root`: its sources scanned once, its evidence
/// read (`sbt_evidence::discover`'s rule: no evidence file, no evidence).
async fn build_state(root: &Path) -> BuildState {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let Ok(e) = crate::crawlers::sbt_evidence::scan(&root) else {
            return BuildState::default();
        };
        let findings = crate::formats::sbt::build::scan_build_sources(&e.build_sources);
        let dropped = pin_dropped(&findings);
        let repo = std::fs::canonicalize(&root)
            .ok()
            .map(|c| crate::crawlers::sbt_evidence::strip_verbatim(&c).join(HOSTED_REPO_REL));
        if e.files.is_empty() {
            return BuildState {
                dropped,
                repo,
                ..BuildState::default()
            };
        }
        let res = crate::crawlers::sbt_evidence::resolution(&e);
        let blocker = res
            .as_ref()
            .and_then(|res| evidence_blocker(&e, res, &findings));
        let since = e.generated.max(e.newest_source);
        let current: BTreeSet<String> = e
            .record_dates
            .iter()
            .filter(|(_, at)| since.is_none_or(|s| **at > s))
            .map(|(rel, _)| rel.clone())
            .collect();
        let whole = current.len() == e.record_dates.len()
            && res.as_ref().is_some_and(|res| {
                crate::formats::sbt::build::declared_projects(&e.build_sources).is_some_and(
                    |declared| declared.values().all(|dir| res.projects_seen.contains(dir)),
                )
            });
        BuildState {
            res,
            blocker,
            dropped,
            repo,
            current,
            whole,
        }
    })
    .await
    .unwrap_or_default()
}

/// A build edit that drops what makes the pin hold (both a blocker of the
/// evidence and, with no current evidence verifying the pin, a bypass of
/// it): a `dependencyOverrides` reassignment replaces the generated
/// override where it applies, and an `onLoad` reassignment that does not
/// keep the previous value drops the generated installer, whose `update`
/// verifier fails a build that does not resolve the pinned bytes and whose
/// resolver order serves the pin repository first. Without the installer,
/// nothing stops another repository's copy or a forced version from
/// building silently.
fn pin_dropped(findings: &BuildFindings) -> Option<String> {
    if !findings.overrides_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) `dependencyOverrides`, which replaces the pin where it applies",
            findings.overrides_assignment.join(", ")
        ));
    }
    (!findings.onload_assignment.is_empty()).then(|| {
        format!(
            "{} reassign(s) `onLoad` without keeping its previous value, which drops \
             socket-patch's load-time verifier and resolver order",
            findings.onload_assignment.join(", ")
        )
    })
}

/// `res` cut down to `pin`'s GA as the [`BuildState::current`] records
/// show it: each version by its current records only, and the pinned
/// version's artifact files only while every record resolving that version
/// is current (an artifact path names no record).
fn current_view(res: &JvmResolution, pin: &SbtPin, current: &BTreeSet<String>) -> JvmResolution {
    let ga = (pin.group.clone(), pin.artifact.clone());
    let is_current = |id: &String| {
        id.rsplit_once(':')
            .is_some_and(|(record, _)| current.contains(record))
    };
    let mut view = JvmResolution::default();
    let Some(versions) = res.modules.get(&ga) else {
        return view;
    };
    for (version, ids) in versions {
        let now: BTreeSet<String> = ids.iter().filter(|id| is_current(id)).cloned().collect();
        if !now.is_empty() {
            view.modules
                .entry(ga.clone())
                .or_default()
                .insert(version.clone(), now);
        }
    }
    let key = (pin.group.clone(), pin.artifact.clone(), pin.sv.clone());
    let pinned_ids = versions.get(&pin.sv);
    if pinned_ids.is_some_and(|ids| !ids.is_empty() && ids.iter().all(is_current)) {
        if let Some(paths) = res.artifacts.get(&key) {
            view.artifacts.insert(key, paths.clone());
        }
    }
    view
}

/// Why the build provably does not use `pin`'s bytes, whatever copy is
/// installed, or `None`. Current evidence that verifies the pin ([`verify`]
/// over [`current_view`]) wins, over a build edit too when it covers the
/// whole build ([`BuildState::whole`]): a project not re-resolved since
/// the edit may be the one it applies to. Otherwise: a build edit dropping
/// the pin ([`pin_dropped`]: the override replaced, or the load-time
/// verifier and resolver order removed), or current evidence judged
/// exactly as the hosted rewriter re-checks an existing pin
/// (`formats::sbt::gate::check_existing`): the GA's base version (the
/// override shadowed), or the pinned version from outside the pin
/// repository with bytes that are not pinned. An artifact that cannot be
/// read now proves nothing. (Another forced version is no proof to either:
/// the load-time verifier fails that `update`.)
///
/// A `resolvers` reassignment or `sbt.override.build.repos` is no bypass on
/// its own: the override still forces the Socket-only version, and the
/// load-time verifier fails `update` on any other version or unpinned
/// bytes, so such a build runs the pinned bytes or fails. (Without that
/// verifier, an `onLoad` reassignment is the bypass.)
async fn bypass(pin: &SbtPin, build: &BuildState, hashes: &mut Hashes) -> Option<String> {
    use crate::formats::sbt::gate::{check_existing, GateRefusal, GateWarning};
    let now = build
        .res
        .as_ref()
        .map(|res| current_view(res, pin, &build.current));
    if let Some(now) = &now {
        if (build.dropped.is_none() || build.whole) && verify(pin, Some(now), hashes).await.is_ok()
        {
            return None;
        }
    }
    if let Some(why) = &build.dropped {
        return Some(why.clone());
    }
    let (now, repo) = (now?, build.repo.as_deref()?);
    let key = (pin.group.clone(), pin.artifact.clone(), pin.sv.clone());
    let mut known = BTreeMap::new();
    for path in now.artifacts.get(&key).into_iter().flatten() {
        known.insert(path.clone(), hashes.of(path).await);
    }
    let pinned = |path: &Path| {
        known
            .get(path)
            .cloned()
            .flatten()
            .is_none_or(|got| got == pin.jar_sha256 || got == pin.pom_sha256)
    };
    let ga = format!("{}:{}", pin.group, pin.artifact);
    match check_existing(
        Some(&now),
        &pin.group,
        &pin.artifact,
        &pin.sv,
        repo,
        &pinned,
    ) {
        Err(GateRefusal::ResolvedElsewhere { paths }) => Some(format!(
            "the build's current resolution evidence resolves {ga}:{} from {}, outside the \
             pin repository and not the pinned bytes",
            pin.sv,
            paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Err(_) => None,
        Ok(warnings) => warnings.into_iter().find_map(|w| match w {
            GateWarning::OverrideShadowed { evidence } => Some(format!(
                "the build's current resolution evidence still resolves {ga} at its base \
                 version in {}, not the pinned {}",
                evidence.join(", "),
                pin.sv
            )),
            GateWarning::MetaBuildOnly => None,
        }),
    }
}

/// The build-wide conditions under which evidence showing the pin is not
/// enough (the same ones the hosted rewriter's `check_new` gate refuses a
/// new pin on): a build source newer than some project's evidence, a
/// declared project with no evidence (only part of the build resolved), a
/// project definition that cannot be read statically, a build source
/// dropping the pin ([`pin_dropped`]) or reassigning `resolvers`, or a
/// `build.sbt.lock`. Each reason names its own remedy (or that there is
/// none), so a reader can relay it as is.
fn evidence_blocker(
    e: &crate::crawlers::sbt_evidence::SbtEvidence,
    res: &JvmResolution,
    findings: &BuildFindings,
) -> Option<String> {
    use crate::formats::sbt::build::declared_projects;
    if e.stale {
        return Some(
            "a build source changed after the last `sbt update`; run `sbt update`".to_string(),
        );
    }
    let Some(declared) = declared_projects(&e.build_sources) else {
        return Some(
            "the build's project definitions cannot be read statically (a computed \
             `Project(...)`, `projectMatrix` or `crossProject`), so its evidence may not cover \
             every project; only a build whose projects are literal `project` / \
             `Project(\"<id>\", file(\"<dir>\"))` definitions can be verified"
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
    if let Some(why) = pin_dropped(findings) {
        let remedy = if findings.overrides_assignment.is_empty() {
            "keep its previous value (compose with `(Global / onLoad).value andThen ...`)"
        } else {
            "keep the setting's existing entries (append with `+=` / `++=`)"
        };
        return Some(format!("{why}; {remedy}"));
    }
    if !findings.resolvers_assignment.is_empty() {
        return Some(format!(
            "{} reassign(s) or transform(s) a resolver setting (`resolvers`, \
             `externalResolvers` or `fullResolvers`, with `:=` or `~=`), which can drop the \
             pin's repository; keep the setting's existing entries (append with `+=` / `++=`)",
            findings.resolvers_assignment.join(", ")
        ));
    }
    if !findings.dependency_lock.is_empty() {
        return Some(format!(
            "{} locks the build's dependencies, which rejects the pinned version; the pin \
             cannot be verified while it exists",
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
            "the build resolves {ga}:{other}, not the pinned {}; run `sbt update`, and if it \
             still does, something in the build forces that version (a `dependencyOverrides \
             +=` or `force()` of it, or a project the pin does not reach): remove it",
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
            "the build's resolution evidence records no artifact file for {ga}:{}, so it \
             cannot show which copy the build uses; run `sbt update`",
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
                    "{ga}:{} resolved to {} with sha256 {got}, which is not pinned (a copy \
                     another repository serves, such as `mavenLocal` or an Ivy-local publish, \
                     or a modified file): remove or restore it, then run `sbt update`",
                    pin.sv,
                    path.display()
                ))
            }
            None => {
                return Err(format!(
                    "{ga}:{} resolved to {}, which cannot be read; restore it or run \
                     `sbt update`",
                    pin.sv,
                    path.display()
                ))
            }
        }
    }
    if !jar_seen {
        return Err(format!(
            "no resolved artifact of {ga}:{} is the pinned jar; run `sbt update`",
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
    // build provably does not apply the pin, from nothing. A pin the
    // evidence verifies is never withdrawn.
    let bypassed = match &locked {
        Some(_) => None,
        None => bypass(pin, build, hashes).await,
    };
    if let Some(why) = bypassed {
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
    // The vendor ledger records the pin under this purl (the planner builds
    // it the same way); a coordinate it rejects was never vendored. `why`
    // is both the diagnostic's text and the mark's detail, which completes
    // "patch <uuid> is wired, but …" (the VEX note).
    let purl = maven_purl(&pin.group, &pin.artifact, &pin.base);
    let withhold = |out: &mut Discovery, code, why: String, kind| {
        out.diag(
            code,
            VENDORED_FILE,
            format!("{VENDORED_FILE}: patch {}: {why}", pin.uuid),
        );
        if let Some(purl) = &purl {
            out.unattested(purl, &pin.uuid, VENDORED_FILE, why, kind);
        }
    };
    // Only a disk holds the committed tree: a memory view has none to
    // hash, which proves nothing missing.
    if let Some(root) = ctx.disk_root() {
        for (ext, want) in [("pom", &pin.pom_sha256), ("jar", &pin.jar_sha256)] {
            let rel = format!("{VENDORED_REPO_REL}/{}", pin.repo_path(ext));
            let got = hashes.of(&root.join(&rel)).await;
            if got.as_deref() != Some(want.as_str()) {
                let state = if got.is_some() { "modified" } else { "missing" };
                withhold(
                    out,
                    DIAG_VENDORED_TREE_MISSING,
                    format!("{VENDORED_FILE} pins {rel}, which is {state}"),
                    UnattestedKind::SbtVendoredTreeMissing,
                );
                return;
            }
        }
    }
    // Without a disk there is no evidence either: unverified, exactly as a
    // hosted pin read from memory gets no lock pin (and `sbt update` cannot
    // change that, so the detail says why instead).
    let verdict = if ctx.disk_root().is_none() {
        Err(
            "the project is read from memory, which holds no sbt resolution evidence; \
             only a scan of the checkout on disk can verify the pin"
                .to_string(),
        )
    } else {
        verify_with(pin, res, blocker, hashes).await
    };
    if let Err(why) = verdict {
        withhold(
            out,
            DIAG_SBT_RESOLUTION_UNVERIFIED,
            why,
            UnattestedKind::SbtResolutionUnverified,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawlers::sbt_evidence::testing::{file_uri, set_mtime};
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
        let blocker = |e: &SbtEvidence, res: &JvmResolution| {
            let findings = crate::formats::sbt::build::scan_build_sources(&e.build_sources);
            evidence_blocker(e, res, &findings)
        };

        assert_eq!(blocker(&e(&[], false), &all), None);
        let why = blocker(&e(&[], false), &core_only).unwrap();
        assert!(why.contains("app"), "{why}");
        let why = blocker(&e(&[], true), &all).unwrap();
        assert!(why.contains("sbt update"), "{why}");
        let overrides = [(
            "app/build.sbt",
            "dependencyOverrides := Seq(\"org.apache.commons\" % \"commons-text\" % \"1.9\")\n",
        )];
        let why = blocker(&e(&overrides, false), &all).unwrap();
        assert!(why.contains("app/build.sbt:1"), "{why}");
        let resolvers = [("app/build.sbt", "resolvers := Nil\n")];
        let why = blocker(&e(&resolvers, false), &all).unwrap();
        assert!(why.contains("`resolvers`"), "{why}");
        let onload = [("app/build.sbt", "Global / onLoad := identity\n")];
        let why = blocker(&e(&onload, false), &all).unwrap();
        assert!(
            why.contains("app/build.sbt:1") && why.contains("`onLoad`"),
            "{why}"
        );
        let lock = [("build.sbt.lock", "{}\n")];
        let why = blocker(&e(&lock, false), &all).unwrap();
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

    // ── vendored pins: the hosted evidence gate, end to end ────────────

    const GSON_UUID: &str = "1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const GSON_PURL: &str = "pkg:maven/com.google.code.gson/gson@2.8.9";
    const GSON_BUILD: &str =
        "libraryDependencies += \"com.google.code.gson\" % \"gson\" % \"2.8.9\"\n";
    const EVIDENCE: &str = "target/update/update_cache/output";

    fn later(secs: u64) -> std::time::SystemTime {
        std::time::SystemTime::now() + std::time::Duration::from_secs(secs)
    }

    fn earlier(secs: u64) -> std::time::SystemTime {
        std::time::SystemTime::now() - std::time::Duration::from_secs(secs)
    }

    /// An sbt 1.9.9 build with gson vendored for real (generated file,
    /// committed tree, ledger) and, unless `evidence` is false, the record
    /// `sbt update` writes after it: the suffixed version resolved from the
    /// tree jar, newer than every build source. `(tmp, root, pin)`.
    async fn vendored_gson(evidence: bool) -> (tempfile::TempDir, PathBuf, SbtPin) {
        use crate::vendor::jvm::testing::{populate, vendor};
        use crate::vendor::jvm::{JvmPatch, Shape};
        // The raw tempdir path: a canonical Windows path is verbatim
        // (`\\?\C:\…`), which sbt never records.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        populate(
            &root,
            &[
                ("project/build.properties", "sbt.version=1.9.9\n"),
                ("build.sbt", GSON_BUILD),
            ],
        );
        let patch = JvmPatch {
            group_id: "com.google.code.gson",
            artifact_id: "gson",
            version: "2.8.9",
            uuid: GSON_UUID,
            jar: b"PK-gson",
            upstream_pom: b"<project>\n  <groupId>com.google.code.gson</groupId>\n  \
                <artifactId>gson</artifactId>\n  <version>2.8.9</version>\n</project>\n",
            upstream_parents: None,
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        };
        let mut ledger = BTreeMap::new();
        vendor(&root, Shape::Sbt, &patch, &mut ledger)
            .await
            .expect("vendor gson");
        let text = std::fs::read_to_string(root.join(VENDORED_FILE)).unwrap();
        let pin = parse(SbtFileMode::Vendored, &text)
            .unwrap()
            .pins
            .remove(GSON_UUID)
            .expect("gson pin");
        if evidence {
            let jar = root.join(VENDORED_REPO_REL).join(pin.repo_path("jar"));
            assert!(jar.is_file(), "{}", jar.display());
            let json = format!(
                r#"{{"configurations":[{{"configuration":{{"name":"compile"}},"modules":[{{"module":{{"organization":"com.google.code.gson","name":"gson","revision":"{}"}},"artifacts":[[{{"name":"gson"}},"{}"]],"evicted":false}}],"details":[]}}]}}"#,
                pin.sv,
                file_uri(&jar)
            );
            populate(&root, &[(EVIDENCE, json.as_str())]);
            set_mtime(&root.join(EVIDENCE), later(60));
        }
        (tmp, root, pin)
    }

    /// The `(purl, uuid, kind)` of every [`super::super::Unattested`] mark.
    fn marks(out: &Discovery) -> Vec<(String, String, UnattestedKind)> {
        out.unattested
            .iter()
            .map(|u| (u.purl.clone(), u.uuid.clone(), u.kind))
            .collect()
    }

    fn unverified() -> Vec<(String, String, UnattestedKind)> {
        vec![(
            GSON_PURL.to_string(),
            GSON_UUID.to_string(),
            UnattestedKind::SbtResolutionUnverified,
        )]
    }

    /// Fresh evidence resolving the pinned bytes from the tree: no
    /// diagnostic, nothing withheld (the ledger attests it).
    #[tokio::test]
    async fn vendored_pin_with_verifying_evidence_is_attestable() {
        let (_tmp, root, _) = vendored_gson(true).await;
        let out = super::super::discover_patched_refs(&root).await;
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    /// The owner rule: a vendored sbt pin needs the evidence a hosted one
    /// does, so with none (no `sbt update` since vendoring) the ledger
    /// entry is withheld from VEX, not only diagnosed.
    #[tokio::test]
    async fn vendored_pin_without_evidence_is_unattested() {
        let (_tmp, root, _) = vendored_gson(false).await;
        let out = super::super::discover_patched_refs(&root).await;
        assert_eq!(marks(&out), unverified(), "{:#?}", out.diagnostics);
        assert!(
            out.unattested[0]
                .detail
                .contains("no sbt resolution evidence"),
            "{:?}",
            out.unattested[0]
        );
    }

    /// Evidence showing the pinned bytes, but older than a build source
    /// edited since: it proves nothing about the build as it stands.
    #[tokio::test]
    async fn vendored_pin_with_stale_evidence_is_unattested() {
        let (_tmp, root, _) = vendored_gson(true).await;
        set_mtime(&root.join("build.sbt"), later(120));
        let out = super::super::discover_patched_refs(&root).await;
        assert_eq!(marks(&out), unverified(), "{:#?}", out.diagnostics);
        assert!(
            out.unattested[0].detail.contains("changed after the last"),
            "{:?}",
            out.unattested[0]
        );
    }

    /// A project reassigning `dependencyOverrides` replaces the generated
    /// override where it applies, whatever the (fresh) evidence shows.
    #[tokio::test]
    async fn vendored_pin_under_an_overrides_reassignment_is_unattested() {
        let (_tmp, root, _) = vendored_gson(true).await;
        std::fs::write(
            root.join("build.sbt"),
            format!(
                "{GSON_BUILD}dependencyOverrides := Seq(\"com.google.code.gson\" % \"gson\" % \
                 \"2.8.9\")\n"
            ),
        )
        .unwrap();
        // Every build source still older than the evidence, however slow
        // the run.
        for rel in ["build.sbt", VENDORED_FILE, "project/build.properties"] {
            set_mtime(&root.join(rel), earlier(60));
        }
        let out = super::super::discover_patched_refs(&root).await;
        assert_eq!(marks(&out), unverified(), "{:#?}", out.diagnostics);
        assert!(
            out.unattested[0].detail.contains("`dependencyOverrides`"),
            "{:?}",
            out.unattested[0]
        );
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.code == DIAG_SBT_RESOLUTION_UNVERIFIED),
            "{:#?}",
            out.diagnostics
        );
    }

    /// A tree file gone: sbt's load-time check fails the build, so no
    /// copy is the patch.
    #[tokio::test]
    async fn vendored_pin_with_a_missing_tree_file_is_unattested() {
        let (_tmp, root, pin) = vendored_gson(true).await;
        std::fs::remove_file(root.join(VENDORED_REPO_REL).join(pin.repo_path("pom"))).unwrap();
        let out = super::super::discover_patched_refs(&root).await;
        assert_eq!(
            marks(&out),
            vec![(
                GSON_PURL.to_string(),
                GSON_UUID.to_string(),
                UnattestedKind::SbtVendoredTreeMissing,
            )],
            "{:#?}",
            out.diagnostics
        );
        assert!(
            out.unattested[0].detail.ends_with(".pom, which is missing")
                && out.unattested[0].detail.starts_with(VENDORED_FILE),
            "{:?}",
            out.unattested[0]
        );
        // The diagnostic and the mark say the same thing.
        let diag = out
            .diagnostics
            .iter()
            .find(|d| d.code == DIAG_VENDORED_TREE_MISSING)
            .expect("diagnosed");
        assert!(diag.detail.ends_with(&out.unattested[0].detail), "{diag:?}");
    }

    /// A memory view holds no committed tree to hash: no tree is reported
    /// missing (a gating mark discovery cannot back), while the pin is
    /// still unverified, as a hosted pin read from memory gets no lock pin.
    #[tokio::test]
    async fn vendored_pin_over_a_memory_view_reports_no_missing_tree() {
        let (_tmp, root, _) = vendored_gson(true).await;
        let mut project = crate::vendor::lock_inventory::MemoryProject::new();
        for rel in [VENDORED_FILE, "build.sbt", "project/build.properties"] {
            project.insert_text(rel, std::fs::read_to_string(root.join(rel)).unwrap());
        }
        let out = super::super::discover_patched_refs_view(
            crate::vendor::lock_inventory::ProjectView::Memory(&project),
            &super::super::DiscoverOptions::default(),
        )
        .await;
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.code == DIAG_VENDORED_TREE_MISSING),
            "{:#?}",
            out.diagnostics
        );
        assert_eq!(marks(&out), unverified(), "{:#?}", out.diagnostics);
        // `sbt update` cannot fix a memory view: the detail says why.
        assert!(
            out.unattested[0].detail.contains("read from memory"),
            "{:?}",
            out.unattested[0]
        );
    }

    /// One record `rel` resolving lang3 at `v` (its id `rel:compile`), with
    /// `artifact` as the pinned version's file.
    fn record(r: &mut JvmResolution, rel: &str, v: &str, artifact: Option<&Path>) {
        let ga = (
            "org.apache.commons".to_string(),
            "commons-lang3".to_string(),
        );
        r.modules
            .entry(ga.clone())
            .or_default()
            .entry(v.to_string())
            .or_default()
            .insert(format!("{rel}:compile"));
        if let Some(p) = artifact {
            r.artifacts
                .entry((ga.0, ga.1, v.to_string()))
                .or_default()
                .insert(p.to_path_buf());
        }
    }

    /// The installed-copy fallback is withdrawn only on proof: a
    /// `dependencyOverrides` reassignment, or a record dated after the
    /// wiring and the sources (judged as the hosted rewriter re-checks a
    /// pin) showing the base version or other bytes, and never while such a
    /// record verifies the pin. A record older than the wiring (a project
    /// or cross build not re-resolved since) proves nothing.
    #[tokio::test]
    async fn bypass_needs_proof_from_current_records() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let jar = tmp.path().join("x.jar");
        std::fs::write(&jar, b"patched").unwrap();
        let sha = hex::encode(Sha256::digest(b"patched"));
        let evil = tmp.path().join("evil.jar");
        std::fs::write(&evil, b"evil").unwrap();
        let gone = tmp.path().join("gone.jar");
        let p = pin(&sha);
        let mut h = Hashes::default();
        let state = |res: JvmResolution, current: &[&str]| BuildState {
            res: Some(res),
            repo: Some(repo.clone()),
            current: current.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let dropped = Some("build.sbt:1 reassign(s) `dependencyOverrides`".to_string());

        assert_eq!(bypass(&p, &BuildState::default(), &mut h).await, None);
        let edited = BuildState {
            dropped: dropped.clone(),
            ..Default::default()
        };
        let why = bypass(&p, &edited, &mut h).await.unwrap();
        assert!(why.contains("build.sbt:1"), "{why}");

        // A current record verifying the pin wins over the edit when the
        // evidence covers the whole build.
        let mut verified = JvmResolution::default();
        record(&mut verified, "b/target/out", SV, Some(&jar));
        let verified_edited = BuildState {
            dropped: dropped.clone(),
            whole: true,
            ..state(verified.clone(), &["b/target/out"])
        };
        assert_eq!(bypass(&p, &verified_edited, &mut h).await, None);
        // Not when another project was not re-resolved since the edit (it
        // may be the one the edit applies to): the edit is proof.
        let mut partial = verified.clone();
        record(&mut partial, "a/target/out", "3.11", None);
        let partial_edited = BuildState {
            dropped: dropped.clone(),
            ..state(partial, &["b/target/out"])
        };
        let why = bypass(&p, &partial_edited, &mut h).await.unwrap();
        assert!(why.contains("build.sbt:1"), "{why}");
        // A stale record of another project beside it changes nothing.
        let mut mixed = verified.clone();
        record(&mut mixed, "a/target/out", "3.11", None);
        assert_eq!(
            bypass(&p, &state(mixed.clone(), &["b/target/out"]), &mut h).await,
            None
        );
        // Current, it shows the build resolving the base.
        let why = bypass(&p, &state(mixed, &["a/target/out", "b/target/out"]), &mut h)
            .await
            .unwrap();
        assert!(
            why.contains("base version") && why.contains("a/target/out"),
            "{why}"
        );
        // Another version a project forces is judged as the rewriter does:
        // no proof (sbt's load-time verifier fails that `update`).
        let mut forced = JvmResolution::default();
        record(&mut forced, "a/target/out", "3.12", None);
        assert_eq!(
            bypass(&p, &state(forced, &["a/target/out"]), &mut h).await,
            None
        );

        // Other bytes at the pinned version, outside the pin repository.
        let mut elsewhere = JvmResolution::default();
        record(&mut elsewhere, "b/target/out", SV, Some(&evil));
        let why = bypass(&p, &state(elsewhere.clone(), &["b/target/out"]), &mut h)
            .await
            .unwrap();
        assert!(why.contains("not the pinned bytes"), "{why}");
        assert_eq!(bypass(&p, &state(elsewhere, &[]), &mut h).await, None);
        // A recorded file that is gone, or no resolution of the GA, proves
        // nothing.
        let mut evicted = JvmResolution::default();
        record(&mut evicted, "b/target/out", SV, Some(&gone));
        assert_eq!(
            bypass(&p, &state(evicted, &["b/target/out"]), &mut h).await,
            None
        );
        assert_eq!(
            bypass(&p, &state(JvmResolution::default(), &[]), &mut h).await,
            None
        );
    }

    /// A hosted file pinning `ga` (`group`, `artifact`, `base`) at the root
    /// of `root`, an sbt build.
    fn write_hosted(root: &Path, group: &str, artifact: &str, base: &str) {
        use crate::formats::sbt::owned_file::{render, SbtLine, SbtOwnedFile};
        let pin = SbtPin {
            group: group.into(),
            artifact: artifact.into(),
            base: base.into(),
            sv: format!("{base}-socket.abcdef12"),
            ..pin(&"b".repeat(64))
        };
        let file = render(&SbtOwnedFile {
            mode: SbtFileMode::Hosted,
            line: SbtLine::Sbt1,
            crlf: false,
            pins: [(UUID.to_string(), pin)].into(),
        })
        .unwrap();
        std::fs::write(root.join(HOSTED_FILE), file).unwrap();
    }

    /// The build's own evidence: of the 1.9.9 test-compile build (root
    /// aggregating `a`, `b`, `c`; only `b` resolves gson 2.8.9), wired
    /// with a gson pin after `b` last resolved, and every other project
    /// re-resolved since. `b`'s record predates the pin, so its 2.8.9 is
    /// no proof, however fresh the other projects' records are; once `b`
    /// resolves again with the pin in place and still shows 2.8.9, it is.
    #[tokio::test]
    async fn a_record_older_than_the_pin_never_withdraws_it() {
        use std::time::{Duration, SystemTime};
        const PURL: &str = "pkg:maven/com.google.code.gson/gson@2.8.9";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("x");
        crate::crawlers::sbt_evidence::stage_fixture(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sbt/evidence/1.9.9/test-compile"),
            &root,
        );
        write_hosted(&root, "com.google.code.gson", "gson", "2.8.9");
        let now = SystemTime::now();
        set_mtime(&root.join(HOSTED_FILE), now - Duration::from_secs(1800));
        let output = |project: &str| {
            root.join(project)
                .join("target/scala-2.12/update/update_cache_2.12/output")
        };
        for project in ["", "a", "c"] {
            set_mtime(&output(project), now);
        }
        let out = super::super::discover_patched_refs(&root).await;
        assert!(
            out.refs.iter().any(|r| r.uuid == UUID && r.purl == PURL),
            "{:?}",
            out.refs
        );
        assert!(out.unattested.is_empty(), "{:?}", out.unattested);

        set_mtime(&output("b"), now);
        let out = super::super::discover_patched_refs(&root).await;
        let [u] = out.unattested.as_slice() else {
            panic!("{:?}", out.unattested);
        };
        assert_eq!(u.kind, UnattestedKind::SbtPinBypassed);
        assert!(u.detail.contains("b/target"), "{}", u.detail);
    }

    /// A hosted file at the root of an sbt build with no evidence (a fresh
    /// clone), over `build_sbt`.
    fn hosted_build(build_sbt: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::write(root.join("project/build.properties"), "sbt.version=1.9.9\n").unwrap();
        std::fs::write(root.join("build.sbt"), build_sbt).unwrap();
        write_hosted(root, "org.apache.commons", "commons-lang3", "3.11");
        tmp
    }

    const LANG3: &str =
        "libraryDependencies += \"org.apache.commons\" % \"commons-lang3\" % \"3.11\"\n";

    /// The unattested mark on the hosted lang3 ref discovery finds in
    /// `root`, if any (the ref itself always stays).
    async fn mark(root: &Path) -> Option<super::super::Unattested> {
        const PURL: &str = "pkg:maven/org.apache.commons/commons-lang3@3.11";
        let out = super::super::discover_patched_refs(root).await;
        assert!(
            out.refs.iter().any(|r| r.uuid == UUID && r.purl == PURL),
            "the ref stays: {:?}",
            out.refs
        );
        assert!(out.unattested.len() <= 1, "{:?}", out.unattested);
        let u = out.unattested.into_iter().next()?;
        assert_eq!(
            (u.kind, u.uuid.as_str(), u.purl.as_str(), u.file.as_path()),
            (
                UnattestedKind::SbtPinBypassed,
                UUID,
                PURL,
                Path::new(HOSTED_FILE)
            )
        );
        Some(u)
    }

    /// With no evidence, only a `dependencyOverrides` reassignment withdraws
    /// the installed-copy basis: it replaces the generated override. A
    /// `resolvers` reassignment or `sbt.override.build.repos` leaves the
    /// override forcing the Socket-only version and the load-time verifier
    /// checking its bytes, so the build runs the pinned bytes or fails.
    #[tokio::test]
    async fn only_an_overrides_reassignment_withdraws_without_evidence() {
        assert!(mark(hosted_build(LANG3).path()).await.is_none());
        let edited = hosted_build(&format!(
            "{LANG3}dependencyOverrides := Seq(\"org.apache.commons\" % \"commons-lang3\" % \"3.11\")\n"
        ));
        let u = mark(edited.path()).await.unwrap();
        assert!(
            u.detail.contains("build.sbt:2") && u.detail.contains("`dependencyOverrides`"),
            "{}",
            u.detail
        );
        let resolvers = hosted_build(&format!("{LANG3}resolvers := Nil\n"));
        assert!(mark(resolvers.path()).await.is_none());
        let repos = hosted_build(LANG3);
        std::fs::write(
            repos.path().join(".sbtopts"),
            "-Dsbt.override.build.repos=true\n",
        )
        .unwrap();
        assert!(mark(repos.path()).await.is_none());
    }

    /// An `onLoad` reassignment that drops the generated installer removes
    /// the verifier (and the resolver order) the resolver and forced-version
    /// decisions rely on: like a `dependencyOverrides` reassignment, it
    /// withdraws the installed-copy basis and blocks the lockfile basis. A
    /// composition that keeps the installer does neither.
    #[tokio::test]
    async fn an_onload_reassignment_withdraws_like_an_overrides_one() {
        let dropped = hosted_build(&format!("{LANG3}Global / onLoad := identity\n"));
        let u = mark(dropped.path()).await.unwrap();
        assert!(
            u.detail.contains("build.sbt:2") && u.detail.contains("`onLoad`"),
            "{}",
            u.detail
        );
        let kept = hosted_build(&format!(
            "{LANG3}Global / onLoad := (Global / onLoad).value andThen (s => s)\n"
        ));
        assert!(mark(kept.path()).await.is_none());
        // The same edit with a resolvers reassignment: still the onLoad one.
        let both = hosted_build(&format!(
            "{LANG3}resolvers := Nil\nonLoad in Global ~= (_ => identity)\n"
        ));
        assert!(mark(both.path())
            .await
            .unwrap()
            .detail
            .contains("build.sbt:3"));
    }

    /// A file under the vendored name that socket-patch did not write is a
    /// root definition sbt loads like any other: its reassignment counts.
    #[tokio::test]
    async fn a_foreign_generated_name_is_scanned_as_a_build_source() {
        let tmp = hosted_build(LANG3);
        std::fs::write(
            tmp.path().join(VENDORED_FILE),
            "dependencyOverrides := Seq()\n",
        )
        .unwrap();
        let u = mark(tmp.path()).await.unwrap();
        assert!(
            u.detail.contains("socket-patch-vendor.sbt:1"),
            "{}",
            u.detail
        );
    }
}
