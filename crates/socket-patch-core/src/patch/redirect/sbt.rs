//! Hosted sbt: wire granted Maven patches into an sbt build through one
//! generated root file, `socket-patch.sbt` (`formats::sbt::owned_file`),
//! never editing a user file.
//!
//! The rewriter refuses what it cannot make fail-closed (an unsupported sbt,
//! a build that reassigns `dependencyOverrides` / `resolvers`, a
//! `build.sbt.lock`, a modified or foreign generated file, a GA the
//! vendored file pins) and gates every new pin on sbt's own resolution
//! evidence (`formats::sbt::gate`), carried in from disk under
//! [`SBT_RESOLUTION_KEY`] as one [`ResolutionDoc`]. Hosted confirmation
//! of an sbt build's Maven candidates keys off
//! [`RewriteResult::confirmed_sbt_uuids`] alone.
//!
//! What a pin passes through, in order (`docs/design/sbt-support.md`):
//!
//! 1. the build: an sbt root (`project/build.properties` naming an
//!    `sbt.version`) of a supported version (0.13.18 up; 2.1 and later are
//!    wired with `redirect_sbt_version_untested`);
//! 2. the generated files: `socket-patch.sbt` must parse strictly (else
//!    every Maven uuid is refused), and `socket-patch-vendor.sbt` too (else
//!    every one is refused: a GA it pins must never be pinned twice);
//! 3. the override: a `maven2` registry override with a suffixed version,
//!    both sha256s, values safe in a Scala literal, one uuid per GA;
//! 4. an existing row for the uuid is kept and re-checked (dependency
//!    digest, [`check_existing`]); anything else is a new pin, refused by a
//!    build edit that would defeat it and gated by [`check_new`].
//!
//! Rows of uuids this run does not name are kept as they are: the rewriter
//! only adds and replaces (the last-out delete is
//! `upstream::sbt::restore`'s, via [`remove_pins`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::json;

use super::{
    bare_sha256_hex, full_name, no_maven_or_gradle, registry_override_of_kind, DepOverride,
    FileEdit, RewriteResult, RewriteWarning,
};
use crate::formats::sbt::build::{
    declared_newer, dependency_literals, files_reader, is_sbt_build_root, sbt_build_present,
    sbt_support, sbt_version, scan_build_sources, source_kind, SbtSupport, BUILD_PROPERTIES,
    BUILD_SBT,
};
use crate::formats::sbt::gate::{check_existing, check_new, GateRefusal, GateWarning};
use crate::formats::sbt::owned_file::{
    parse, render, suffixed_version, validate_values, OwnedFileError, SbtFileMode, SbtLine,
    SbtOwnedFile, SbtPin, HOSTED_FILE, HOSTED_REPO_REL, VENDORED_FILE,
};

/// The synthetic candidate-file key carrying the distilled resolution
/// evidence (`hosted::sbt_reads`) into the pure rewriter. Not a valid path
/// on any OS, so it can never collide with a project file; the engine
/// excludes it from the symlink / unreadable refusals, the confirmation
/// probe and writes.
pub const SBT_RESOLUTION_KEY: &str = "<socket-patch:sbt-resolution>";

/// The prefix every synthetic candidate key starts with.
pub const SYNTHETIC_KEY_PREFIX: &str = "<socket-patch:";

/// Whether `rel` is a synthetic candidate key, not a project file.
pub fn is_synthetic_key(rel: &str) -> bool {
    rel.starts_with(SYNTHETIC_KEY_PREFIX)
}

// ── the evidence document ────────────────────────────────────────────────

/// The one evidence document type (`formats::sbt::evidence`): what the
/// hosted engine's IO layer (`hosted::sbt_reads`, via
/// `crawlers::sbt_evidence::distill`) reads from an sbt build on disk for
/// this pure rewriter, including the build-source [`BuildFindings`] the
/// candidate-file map does not carry (`project/*.scala`, subproject
/// `build.sbt`s).
pub use crate::formats::sbt::evidence::ResolutionDoc;

// ── the rewriter ─────────────────────────────────────────────────────────

fn warn(result: &mut RewriteResult, code: &str, detail: impl Into<String>) {
    result.warnings.push(RewriteWarning {
        code: code.into(),
        detail: detail.into(),
    });
}

/// The pin `dep` asks for, or the refusal (code, detail) when its override
/// cannot drive a fail-closed sbt pin.
fn candidate_pin(dep: &DepOverride, digest: &str) -> Result<SbtPin, (&'static str, String)> {
    let name = full_name(dep);
    let Some(ov) = registry_override_of_kind(dep, "maven2") else {
        return Err((
            "redirect_sbt_missing_override",
            format!("{name} has no maven2 registry override"),
        ));
    };
    let Some(sv) = ov.identifiers.maven_suffixed_version.clone() else {
        return Err((
            "redirect_sbt_missing_override",
            format!(
                "{name} has no Socket-suffixed version; a same-GAV pin is not fail-closed on sbt, \
                 so it is not wired"
            ),
        ));
    };
    let group = ov
        .identifiers
        .maven_group_id
        .clone()
        .or_else(|| dep.namespace.clone())
        .unwrap_or_default();
    let artifact = ov
        .identifiers
        .maven_artifact_id
        .clone()
        .unwrap_or_else(|| dep.name.clone());
    let jar = dep
        .integrity
        .sha256
        .as_deref()
        .map(bare_sha256_hex)
        .filter(|h| !h.is_empty());
    let pom = ov
        .identifiers
        .maven_pom_sha256
        .as_deref()
        .map(bare_sha256_hex)
        .filter(|h| !h.is_empty());
    let (Some(jar_sha256), Some(pom_sha256)) = (jar, pom) else {
        return Err((
            "redirect_sbt_integrity_missing",
            format!(
                "{group}:{artifact}:{sv} lacks the served {} sha256; socket-patch.sbt pins both \
                 the pom and the jar",
                if dep.integrity.sha256.is_none() {
                    "jar"
                } else {
                    "pom"
                }
            ),
        ));
    };
    let pin = SbtPin {
        uuid: dep.patch_uuid.clone(),
        group,
        artifact,
        base: dep.version.clone(),
        sv,
        pom_sha256,
        jar_sha256,
        deps_digest: digest.to_string(),
        index_url: Some(ov.index_url.clone()),
    };
    let unsafe_value = |why: &str| {
        (
            "redirect_sbt_unsafe_value",
            format!(
                "{name} (patch {}): {why}; socket-patch.sbt writes values into Scala string \
                 literals unescaped, so it refuses this one",
                dep.patch_uuid
            ),
        )
    };
    validate_values(&pin).map_err(unsafe_value)?;
    if !ov.index_url.contains(&pin.uuid) {
        return Err(unsafe_value("the index URL does not name the patch uuid"));
    }
    Ok(pin)
}

/// The detail of a run-level gate stop (no evidence, incomplete, stale).
fn run_level(refusal: &GateRefusal) -> Option<(&'static str, String)> {
    Some(match refusal {
        GateRefusal::Missing => (
            "redirect_sbt_no_resolution_evidence",
            "no sbt resolution evidence under target/ (a fresh clone, `sbt clean`, or no `sbt \
             update` yet), so nothing is pinned: run `sbt update`, then re-run socket-patch"
                .to_string(),
        ),
        GateRefusal::Incomplete { missing } if missing.is_empty() => (
            "redirect_sbt_resolution_incomplete",
            "the build defines projects socket-patch cannot read statically, so it cannot tell \
             whether every project's resolution was seen; nothing is pinned"
                .to_string(),
        ),
        GateRefusal::Incomplete { missing } => (
            "redirect_sbt_resolution_incomplete",
            format!(
                "no sbt resolution evidence for the project(s) {}; run `sbt update` (all \
                 projects), then re-run socket-patch; nothing is pinned",
                missing.join(", ")
            ),
        ),
        GateRefusal::Stale => (
            "redirect_sbt_resolution_stale",
            "a build source is newer than sbt's resolution records; run `sbt update` (`sbt \
             clean update` if this persists), then re-run socket-patch; nothing is pinned"
                .to_string(),
        ),
        _ => return None,
    })
}

/// The per-pin refusal (code, detail) of a [`check_new`] stop; `None` for
/// the silent not-resolved skip.
fn pin_refusal(refusal: &GateRefusal, pin: &SbtPin) -> Option<(&'static str, String)> {
    let ga = format!("{}:{}", pin.group, pin.artifact);
    Some(match refusal {
        GateRefusal::VersionConflict { found } => (
            "redirect_sbt_version_conflict",
            format!(
                "{ga}: the build resolves {} but the patch is for {}; a build-wide pin would \
                 change the version some project resolves, so it is not wired",
                found.join(", "),
                pin.base
            ),
        ),
        GateRefusal::ScalaRuntime => (
            "redirect_sbt_scala_runtime_unsupported",
            format!("{ga} is the Scala runtime / compiler, which sbt pins itself; not wired"),
        ),
        GateRefusal::Classifier { found } => (
            "redirect_sbt_classifier_unsupported",
            format!(
                "{ga} is also resolved with the classifier(s) {}, which the patched jar does not \
                 replace; not wired",
                found.join(", ")
            ),
        ),
        GateRefusal::ResolvedElsewhere { paths } => (
            "redirect_sbt_resolved_elsewhere",
            format!(
                "{ga}:{} resolves from {}, not the socket-patch repository",
                pin.sv,
                paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        GateRefusal::NotResolved { .. }
        | GateRefusal::Missing
        | GateRefusal::Incomplete { .. }
        | GateRefusal::Stale => return None,
    })
}

/// The `socket-patch.sbt` syntax line the build's sbt version needs; the
/// refusal (code, detail) when it is not wired, plus an untested advisory.
fn build_line(
    files: &BTreeMap<String, String>,
) -> Result<(SbtLine, Option<String>), (&'static str, String)> {
    let version = files
        .get(BUILD_PROPERTIES)
        .and_then(|t| sbt_version(t))
        .unwrap_or_default();
    match sbt_support(&version) {
        SbtSupport::Supported(line) => Ok((line, None)),
        SbtSupport::Untested(line) => Ok((
            line,
            Some(format!(
                "sbt {version} is newer than the lines socket-patch has tested (0.13.18 to \
                 2.0.x); socket-patch.sbt is written for the {} syntax",
                match line {
                    SbtLine::Sbt013 => "0.13",
                    SbtLine::Sbt1 => "1.x",
                    SbtLine::Sbt2 => "2.x",
                }
            )),
        )),
        SbtSupport::Unsupported => Err((
            "redirect_sbt_unsupported_version",
            format!(
                "sbt {version:?} is not supported (0.13.18 or later); nothing is pinned. Upgrade \
                 sbt in {BUILD_PROPERTIES}"
            ),
        )),
    }
}

/// Wire the Maven `overrides` into `files`' sbt build (see the module
/// doc).
pub fn rewrite_sbt(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let maven: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "maven")
        .collect();
    let read = files_reader(files);
    if maven.is_empty() || !sbt_build_present(&read) {
        return;
    }
    let all: Vec<String> = maven.iter().map(|d| d.patch_uuid.clone()).collect();
    let refuse_all = |result: &mut RewriteResult, code: &str, detail: String| {
        warn(result, code, detail);
        result.refused_sbt_uuids.extend(all.iter().cloned());
    };

    // 1. The build.
    if !is_sbt_build_root(&read) {
        return refuse_all(
            result,
            "redirect_sbt_build_root_unknown",
            format!(
                "an sbt build is present but {BUILD_PROPERTIES} names no sbt.version here (a \
                 subproject, or a build root socket-patch cannot identify); run socket-patch at \
                 the build root"
            ),
        );
    }
    let (line, untested) = match build_line(files) {
        Ok(line) => line,
        Err((code, detail)) => return refuse_all(result, code, detail),
    };
    if let Some(detail) = untested {
        warn(result, "redirect_sbt_version_untested", detail);
    }
    if files.contains_key("pom.xml") {
        warn(
            result,
            "redirect_maven_pom_ignored_sbt_build",
            "pom.xml sits beside an sbt build, which never reads it: the sbt build is wired \
             through socket-patch.sbt, and pom.xml is also rewritten for the Maven build",
        );
    }

    // The evidence, and what the build sources say. An unreadable document
    // is the run's one no-evidence warning (the gate's own is suppressed).
    let mut run_level_warned: BTreeSet<&'static str> = BTreeSet::new();
    let doc = match files.get(SBT_RESOLUTION_KEY) {
        None => None,
        Some(text) => match ResolutionDoc::parse(text) {
            Ok(doc) => Some(doc),
            Err(why) => {
                warn(
                    result,
                    "redirect_sbt_no_resolution_evidence",
                    format!(
                        "the sbt resolution evidence could not be read ({why}), so nothing is \
                         pinned: run `sbt update`, then re-run socket-patch"
                    ),
                );
                run_level_warned.insert("redirect_sbt_no_resolution_evidence");
                None
            }
        },
    };
    let root_sources: Vec<(String, String)> = files
        .iter()
        .filter(|(rel, _)| !is_synthetic_key(rel) && source_kind(rel).is_some())
        .map(|(rel, text)| (rel.clone(), text.clone()))
        .collect();
    let mut findings = scan_build_sources(&root_sources);
    let mut declared_deps = dependency_literals(&root_sources);
    if let Some(doc) = &doc {
        declared_deps.extend(doc.declared_deps.iter().cloned());
        for (mine, theirs) in [
            (
                &mut findings.overrides_assignment,
                &doc.findings.overrides_assignment,
            ),
            (
                &mut findings.resolvers_assignment,
                &doc.findings.resolvers_assignment,
            ),
            (
                &mut findings.override_build_repos,
                &doc.findings.override_build_repos,
            ),
            (&mut findings.dependency_lock, &doc.findings.dependency_lock),
        ] {
            mine.extend(theirs.iter().cloned());
            mine.sort();
            mine.dedup();
        }
    }
    // The digest is only comparable when it covers every build source: the
    // map alone lacks `project/*.scala` and the subprojects' files.
    let digest = doc.as_ref().map(|d| d.deps_digest.clone());
    if !findings.override_build_repos.is_empty() {
        warn(
            result,
            "redirect_sbt_override_build_repos",
            format!(
                "{} set sbt.override.build.repos=true: the launcher's repositories replace the \
                 build's, socket-patch's among them, so pinned versions fail to resolve until \
                 the socket-patch repository is listed there too",
                findings.override_build_repos.join(", ")
            ),
        );
    }

    // 2. The generated files.
    let hosted_text = files.get(HOSTED_FILE);
    let existing = match hosted_text.map(|t| parse(SbtFileMode::Hosted, t)) {
        None => None,
        Some(Ok(file)) => Some(file),
        Some(Err(OwnedFileError::Modified(why))) => {
            return refuse_all(
                result,
                "redirect_sbt_owned_file_modified",
                format!(
                    "{HOSTED_FILE} was edited ({why}); socket-patch rewrites only bytes it \
                     wrote. Restore it (`git checkout -- {HOSTED_FILE}`) or delete it, then \
                     re-run socket-patch"
                ),
            );
        }
        Some(Err(OwnedFileError::Foreign)) => {
            return refuse_all(
                result,
                "redirect_sbt_owned_file_foreign",
                format!(
                    "{HOSTED_FILE} exists but socket-patch did not generate it; rename your file \
                     (socket-patch owns this name), then re-run socket-patch"
                ),
            );
        }
    };
    let vendored_gas: BTreeSet<(String, String)> = match files
        .get(VENDORED_FILE)
        .map(|t| parse(SbtFileMode::Vendored, t))
    {
        None => BTreeSet::new(),
        Some(Ok(file)) => file
            .pins
            .into_values()
            .map(|p| (p.group, p.artifact))
            .collect(),
        Some(Err(why)) => {
            return refuse_all(
                result,
                "redirect_sbt_vendored_conflict",
                format!(
                    "{VENDORED_FILE} cannot be read strictly ({}), so socket-patch cannot tell \
                     which packages it pins; nothing is pinned until it is restored or removed",
                    match why {
                        OwnedFileError::Modified(why) => why,
                        OwnedFileError::Foreign => "not generated by socket-patch".into(),
                    }
                ),
            );
        }
    };

    let crlf = existing.as_ref().map_or_else(
        || files.get(BUILD_SBT).is_some_and(|t| t.contains("\r\n")),
        |f| f.crlf,
    );
    let mut model = existing.clone().unwrap_or(SbtOwnedFile {
        mode: SbtFileMode::Hosted,
        line,
        crlf,
        pins: BTreeMap::new(),
    });
    model.line = line;

    // 3. The overrides.
    let mut candidates: Vec<SbtPin> = Vec::new();
    for dep in &maven {
        match candidate_pin(dep, digest.as_deref().unwrap_or("00000000")) {
            Ok(pin) => candidates.push(pin),
            Err((code, detail)) => {
                warn(result, code, detail);
                result.refused_sbt_uuids.insert(dep.patch_uuid.clone());
            }
        }
    }
    // One uuid per GA in a run: the file forces one version per GA.
    let mut per_ga: BTreeMap<(String, String), BTreeSet<&str>> = BTreeMap::new();
    for pin in &candidates {
        per_ga
            .entry((pin.group.clone(), pin.artifact.clone()))
            .or_default()
            .insert(pin.uuid.as_str());
    }

    let res = doc.as_ref().and_then(|d| d.resolution.as_ref());
    let wiring_newer = doc.as_ref().is_some_and(|d| d.wiring_newer);
    let stale = doc.as_ref().is_some_and(|d| d.stale);
    let read_error = doc.as_ref().and_then(|d| d.read_error.clone());
    let repo_abs = doc
        .as_ref()
        .map(|d| d.root.as_path())
        .filter(|r| !r.as_os_str().is_empty())
        .map(|root| comparable_root(root).join(HOSTED_REPO_REL));
    let build_refusal: Option<(&'static str, String)> = if !findings.overrides_assignment.is_empty()
    {
        Some((
            "redirect_sbt_overrides_assignment",
            format!(
                "{} reassign(s) dependencyOverrides (`:=`, `~=` or `--=`), which replaces \
                 socket-patch's override where it applies; use `+=` instead",
                findings.overrides_assignment.join(", ")
            ),
        ))
    } else if !findings.resolvers_assignment.is_empty() {
        Some((
            "redirect_sbt_resolvers_assignment",
            format!(
                "{} reassign(s) resolvers (`:=` or `~=`), which can drop socket-patch's \
                 repository; use `+=` instead",
                findings.resolvers_assignment.join(", ")
            ),
        ))
    } else if !findings.dependency_lock.is_empty() {
        Some((
            "redirect_sbt_dependency_lock_present",
            format!(
                "{} (sbt-dependency-lock) would reject a pinned version; socket-patch does not \
                 rewrite it. Remove the lock, or pin, then run `sbt dependencyLockWrite`",
                findings.dependency_lock.join(", ")
            ),
        ))
    } else {
        None
    };

    let mut changed = existing.as_ref().is_some_and(|f| f.line != line);
    for pin in candidates.clone() {
        let uuid = pin.uuid.clone();
        let ga = (pin.group.clone(), pin.artifact.clone());
        let ga_text = format!("{}:{}", pin.group, pin.artifact);
        let refuse = |result: &mut RewriteResult, code: &str, detail: String| {
            warn(result, code, detail);
            result.refused_sbt_uuids.insert(uuid.clone());
        };
        if per_ga.get(&ga).is_some_and(|u| u.len() > 1) {
            refuse(
                result,
                "redirect_sbt_override_conflict",
                format!(
                    "{ga_text} is granted by several patches in this run ({}); socket-patch.sbt \
                     forces one version per package, so none is wired",
                    per_ga[&ga].iter().copied().collect::<Vec<_>>().join(", ")
                ),
            );
            continue;
        }
        if vendored_gas.contains(&ga) {
            refuse(
                result,
                "redirect_sbt_vendored_conflict",
                format!(
                    "{ga_text} is pinned by {VENDORED_FILE} (vendored mode); one mode pins a \
                     package, so it is not also pinned in {HOSTED_FILE}"
                ),
            );
            continue;
        }

        // 4a. An existing row for this uuid: keep and re-check it.
        if let Some(row) = model.pins.get(&uuid).cloned() {
            let same = SbtPin {
                deps_digest: row.deps_digest.clone(),
                ..pin.clone()
            } == row;
            if same {
                // A build edit made after wiring that defeats the pin (a
                // `:=` reassignment, a lock) fails sbt's load; the row
                // stays, but socket-patch does not report it as applied.
                if let Some((code, detail)) = &build_refusal {
                    refuse(result, code, detail.clone());
                    continue;
                }
                // The build now asks for a newer version than the patch's
                // base: the build-wide override would force it back down.
                // The generated file's load-time check fails that build;
                // the row stays (a rollback removes it) and is refused.
                let newer = declared_newer(&declared_deps, &pin.group, &pin.artifact, &pin.base);
                if !newer.is_empty() {
                    refuse(
                        result,
                        "redirect_sbt_pin_declared_newer",
                        format!(
                            "{ga_text}: the build now declares {}, but {HOSTED_FILE} forces the \
                             patched {} (base {}), a downgrade sbt's load-time check refuses; \
                             roll the patch back (`socket-patch rollback`), or declare {} again",
                            newer.join(", "),
                            pin.sv,
                            pin.base,
                            pin.base
                        ),
                    );
                    continue;
                }
                let moved = digest.as_ref().is_some_and(|now| *now != row.deps_digest);
                let verdict = match (&digest, &repo_abs) {
                    (None, _) => Err((
                        "redirect_sbt_pin_unverifiable",
                        format!(
                            "{ga_text}:{} is pinned, but the build's dependencies cannot be read \
                             here (no on-disk build), so the pin is not verified",
                            pin.sv
                        ),
                    )),
                    // The dependencies changed since the pin was written:
                    // only evidence resolved after the change (fresh, newer
                    // than the generated file) can re-verify it.
                    (Some(now), _) if moved && (res.is_none() || stale || wiring_newer) => Err((
                        "redirect_sbt_pin_unverifiable",
                        format!(
                            "{ga_text}:{} was pinned when the build's dependencies were \
                             deps={}, they are now deps={now}; run `sbt update`, then re-run \
                             socket-patch to re-check the pin",
                            pin.sv, row.deps_digest
                        ),
                    )),
                    (Some(_), repo) => {
                        // Evidence older than the generated file predates
                        // the pins: it proves nothing about them either way.
                        let checked = match repo.as_ref().filter(|_| !wiring_newer) {
                            Some(repo) => check_existing(
                                res,
                                &pin.group,
                                &pin.artifact,
                                &pin.sv,
                                repo,
                                &|path: &std::path::Path| {
                                    doc.as_ref().is_some_and(|d| {
                                        d.holds_pinned_bytes(path, &pin.jar_sha256)
                                    })
                                },
                            ),
                            None => Ok(Vec::new()),
                        };
                        match checked {
                            Err(refusal) => Err(pin_refusal(&refusal, &pin).unwrap_or((
                                "redirect_sbt_pin_unverifiable",
                                format!("{ga_text}:{} could not be re-checked", pin.sv),
                            ))),
                            Ok(warnings) => match warnings.into_iter().next() {
                                Some(GateWarning::OverrideShadowed { evidence }) => Err((
                                    "redirect_sbt_override_shadowed",
                                    format!(
                                        "{ga_text} still resolves {} in {}: a project's own \
                                         dependencyOverrides or resolver setting shadows \
                                         socket-patch's pin {} (sbt's load-time check fails \
                                         the build)",
                                        pin.base,
                                        evidence.join(", "),
                                        pin.sv
                                    ),
                                )),
                                _ => Ok(()),
                            },
                        }
                    }
                };
                match verdict {
                    Ok(()) => {
                        // Re-verified against the changed build: record its
                        // digest, so the next run compares against it.
                        if let (true, Some(now)) = (moved, &digest) {
                            result.edits.push(FileEdit {
                                path: HOSTED_FILE.into(),
                                kind: "redirect_sbt_pin_rechecked".into(),
                                action: "updated".into(),
                                key: Some(ga_text.clone()),
                                original: Some(json!({ "deps": row.deps_digest })),
                                new: Some(json!({ "deps": now })),
                            });
                            if let Some(kept) = model.pins.get_mut(&uuid) {
                                kept.deps_digest = now.clone();
                            }
                            changed = true;
                        }
                        result.confirmed_sbt_uuids.insert(uuid);
                    }
                    // Not confirmed by sbt, and recorded as refused so a
                    // Gradle build beside it cannot confirm the uuid alone
                    // while sbt may still resolve the unpatched base.
                    Err((code, detail)) => {
                        warn(result, code, detail);
                        result.refused_sbt_uuids.insert(uuid);
                    }
                }
                continue;
            }
        }

        // 4b. A new pin (or a changed one for this uuid).
        if let Some((code, detail)) = &build_refusal {
            refuse(result, code, detail.clone());
            continue;
        }
        // Evidence resolved under an earlier pin shows the suffixed version
        // whatever the build declares now: check the declarations too.
        let newer = declared_newer(&declared_deps, &pin.group, &pin.artifact, &pin.base);
        if !newer.is_empty() {
            refuse(
                result,
                "redirect_sbt_version_conflict",
                format!(
                    "{ga_text}: the build declares {} but the patch is for {}; a build-wide pin \
                     would downgrade it, so it is not wired",
                    newer.join(", "),
                    pin.base
                ),
            );
            continue;
        }
        let replaced: Option<SbtPin> = model
            .pins
            .values()
            .find(|p| p.group == pin.group && p.artifact == pin.artifact && p.uuid != uuid)
            .cloned();
        if let Some(old) = &replaced {
            if old.base != pin.base {
                refuse(
                    result,
                    "redirect_sbt_override_conflict",
                    format!(
                        "{ga_text} is already pinned by patch {} at {} (base {}); this patch is \
                         for {}, and socket-patch.sbt forces one version per package",
                        old.uuid, old.sv, old.base, pin.base
                    ),
                );
                continue;
            }
        }
        let declared = doc.as_ref().and_then(|d| d.declared.as_ref());
        if let Err(refusal) = check_new(res, declared, stale, &pin.group, &pin.artifact, &pin.base)
        {
            if let Some((code, mut detail)) = run_level(&refusal) {
                if run_level_warned.insert(code) {
                    if let (GateRefusal::Missing, Some(why)) = (&refusal, &read_error) {
                        detail = format!(
                            "the sbt resolution evidence could not be read ({why}), so \
                             nothing is pinned: run `sbt update`, then re-run socket-patch"
                        );
                    }
                    warn(result, code, detail);
                }
            } else if let GateRefusal::NotResolved { meta_build_only } = refusal {
                if meta_build_only {
                    warn(
                        result,
                        "redirect_sbt_meta_build_only",
                        format!(
                            "{ga_text} is resolved only by the build definition (sbt \
                             plugins under project/), which a library pin does not reach; \
                             not wired"
                        ),
                    );
                }
            } else if let Some((code, detail)) = pin_refusal(&refusal, &pin) {
                warn(result, code, detail);
            }
            result.refused_sbt_uuids.insert(uuid);
            continue;
        }
        let previous = model.pins.remove(&uuid);
        if let Some(old) = &replaced {
            model.pins.remove(&old.uuid);
        }
        let prior = replaced.as_ref().or(previous.as_ref());
        result.edits.push(FileEdit {
            path: HOSTED_FILE.into(),
            kind: if prior.is_some() {
                "redirect_sbt_pin_updated"
            } else {
                "redirect_sbt_pin"
            }
            .into(),
            action: if prior.is_some() { "updated" } else { "added" }.into(),
            key: Some(ga_text),
            original: prior.map(|p| json!({ "uuid": p.uuid, "version": p.sv })),
            new: Some(json!({ "uuid": pin.uuid, "version": pin.sv })),
        });
        model.pins.insert(uuid.clone(), pin);
        result.confirmed_sbt_uuids.insert(uuid);
        changed = true;
    }

    // 5. Render.
    if !changed || model.pins.is_empty() {
        return;
    }
    match render(&model) {
        Ok(text) if hosted_text != Some(&text) => {
            result.files.insert(HOSTED_FILE.to_string(), text);
        }
        Ok(_) => {}
        Err(why) => {
            // Values were validated per pin; a render refusal is a bug.
            let uuids: Vec<String> = model.pins.keys().cloned().collect();
            for uuid in &uuids {
                result.confirmed_sbt_uuids.remove(uuid);
            }
            result
                .edits
                .retain(|e| !(e.path == HOSTED_FILE && e.kind.starts_with("redirect_sbt_pin")));
            refuse_all(
                result,
                "redirect_sbt_unsafe_value",
                format!("socket-patch.sbt could not be rendered ({why:?}); nothing is pinned"),
            );
        }
    }
}

/// `root` in the spelling sbt's evidence uses for paths under it: a
/// Windows `std::fs::canonicalize` result carries the verbatim prefix
/// (`\\?\C:\x`, `\\?\UNC\srv\share`), which the `file:` URIs sbt records
/// never do, and a prefixed root contains no evidence path at all.
fn comparable_root(root: &std::path::Path) -> PathBuf {
    let text = root.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        root.to_path_buf()
    }
}

/// The hosted file `text` without the pins of `uuids`: `Ok(Some(text))`
/// re-rendered, `Ok(None)` when no pin remains (delete the file), and the
/// strict parse's error otherwise. Pins `uuids` does not name stay
/// byte-identical; a uuid the file does not pin is ignored.
pub fn remove_pins(text: &str, uuids: &BTreeSet<String>) -> Result<Option<String>, OwnedFileError> {
    let mut file = parse(SbtFileMode::Hosted, text)?;
    file.pins.retain(|uuid, _| !uuids.contains(uuid));
    if file.pins.is_empty() {
        return Ok(None);
    }
    render(&file)
        .map(Some)
        .map_err(|why| OwnedFileError::Modified(format!("cannot re-render: {why:?}")))
}

/// The pins of a strictly parsed hosted file, by uuid.
pub fn hosted_pins(text: &str) -> Result<Vec<SbtPin>, OwnedFileError> {
    Ok(parse(SbtFileMode::Hosted, text)?
        .pins
        .into_values()
        .collect())
}

/// `<base>-socket.<hex8>` for `uuid` (the version a hosted pin forces).
pub fn pinned_version(base: &str, uuid: &str) -> String {
    suffixed_version(base, uuid)
}

/// The root is an sbt build the Maven pom rewriter must leave alone (its
/// `rewrite_maven_pom` early return): an sbt build root with no `pom.xml`
/// and no Gradle settings / build script beside it. A mixed root still runs
/// the Maven (and Gradle-snippet) rewriter; the sbt rewriter runs
/// regardless.
pub fn owns_maven_root(files: &BTreeMap<String, String>) -> bool {
    is_sbt_build_root(&files_reader(files)) && no_maven_or_gradle(files)
}

/// How hosted confirmation of a `pkg:maven` candidate is decided for
/// `files`' root: `None` when no sbt build (nor its generated files) is
/// present. Otherwise `Some(sbt_only)`: an sbt-confirmed uuid
/// ([`RewriteResult::confirmed_sbt_uuids`], not refused) is confirmed; any
/// other is unconfirmed when `sbt_only` (no `pom.xml` / Gradle script
/// beside the build), else left to the Maven rewriter's own proof (a mixed
/// root, whose `pom.xml` is rewritten for the Maven build).
pub fn maven_confirmation(files: &BTreeMap<String, String>) -> Option<bool> {
    sbt_build_present(&files_reader(files)).then(|| no_maven_or_gradle(files))
}

/// Whether `rel` is one of the generated sbt files, which never prove a
/// Maven pin by substring (they name the index URL whether or not the pin
/// was verified).
pub fn is_generated_file(rel: &str) -> bool {
    rel == HOSTED_FILE || rel == VENDORED_FILE
}

/// The reinstall hint for a hosted run that rewrote `files`, when one of
/// them is the generated sbt file.
pub fn next_step_hint(files: &[String]) -> Option<&'static str> {
    files
        .iter()
        .any(|f| f == HOSTED_FILE)
        .then_some(" (run `sbt update`; the first load downloads the pinned files)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::sbt::build::{deps_digest, BuildFindings};
    use crate::formats::sbt::JvmResolution;
    use std::path::Path;

    fn files(names: &[&str]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| {
                let body = if *n == "project/build.properties" {
                    "sbt.version=1.9.9\n"
                } else {
                    ""
                };
                (n.to_string(), body.to_string())
            })
            .collect()
    }

    #[test]
    fn owns_only_a_pure_sbt_root() {
        assert!(owns_maven_root(&files(&[
            "build.sbt",
            "project/build.properties"
        ])));
        assert!(owns_maven_root(&files(&["project/build.properties"])));
        assert!(!owns_maven_root(&files(&["build.sbt"])), "no build root");
        for other in ["pom.xml", "build.gradle", "settings.gradle.kts"] {
            assert!(
                !owns_maven_root(&files(&["build.sbt", "project/build.properties", other])),
                "{other}"
            );
        }
    }

    #[test]
    fn maven_confirmation_is_sbt_only_on_a_pure_root() {
        let sbt = files(&["build.sbt", "project/build.properties"]);
        assert_eq!(maven_confirmation(&sbt), Some(true));
        assert_eq!(maven_confirmation(&files(&["build.sbt"])), Some(true));
        assert_eq!(maven_confirmation(&files(&[HOSTED_FILE])), Some(true));
        assert_eq!(maven_confirmation(&files(&["pom.xml"])), None);
        assert_eq!(
            maven_confirmation(&files(&["build.sbt", "pom.xml"])),
            Some(false),
            "a mixed root: the pom proof also counts"
        );
        assert!(is_generated_file(HOSTED_FILE) && is_generated_file(VENDORED_FILE));
        assert!(!is_generated_file("build.sbt"));
        let mut result = RewriteResult::default();
        rewrite_sbt(&sbt, &[], &mut result);
        assert_eq!(result, RewriteResult::default(), "no maven override");
    }

    #[test]
    fn synthetic_key_is_no_path() {
        assert!(is_synthetic_key(SBT_RESOLUTION_KEY));
        assert!(!is_synthetic_key("build.sbt"));
        assert!(SBT_RESOLUTION_KEY.contains(['<', '>', ':']));
    }

    #[test]
    fn next_step_names_sbt_update_for_the_generated_file() {
        assert!(
            next_step_hint(&[HOSTED_FILE.to_string()]).is_some_and(|h| h.contains("sbt update"))
        );
        assert_eq!(next_step_hint(&["pom.xml".to_string()]), None);
    }

    fn resolution() -> JvmResolution {
        let mut r = JvmResolution::default();
        let ga = (
            "org.apache.commons".to_string(),
            "commons-lang3".to_string(),
        );
        r.modules
            .entry(ga.clone())
            .or_default()
            .entry("3.11".into())
            .or_default()
            .insert("target/x:compile".into());
        r.artifacts
            .entry((ga.0.clone(), ga.1.clone(), "3.11".into()))
            .or_default()
            .insert(PathBuf::from("/c/x.jar"));
        r.classifiers
            .entry(ga.clone())
            .or_default()
            .insert("sources".into());
        r.in_scope.insert(ga.clone());
        r.projects_seen.insert(".".into());
        r.meta_build.insert(("p".into(), "q".into()));
        r
    }

    #[test]
    fn resolution_doc_round_trips() {
        let doc = ResolutionDoc {
            root: PathBuf::from("/work/app"),
            resolution: Some(resolution()),
            declared: Some(BTreeSet::from([".".to_string(), "a".to_string()])),
            stale: true,
            wiring_newer: true,
            deps_digest: "0123abcd".into(),
            read_error: Some("cap".into()),
            findings: BuildFindings {
                overrides_assignment: vec!["a/build.sbt:3".into()],
                ..Default::default()
            },
            artifact_sha256: [(PathBuf::from("/c/x.jar"), "ab".repeat(32))].into(),
            declared_deps: Default::default(),
        };
        let text = doc.to_json();
        assert_eq!(ResolutionDoc::parse(&text), Ok(doc));
        let none = ResolutionDoc::default();
        assert_eq!(ResolutionDoc::parse(&none.to_json()), Ok(none));
        assert!(ResolutionDoc::parse(&text.replacen("\"v\":1", "\"v\":2", 1)).is_err());
        assert!(ResolutionDoc::parse("{}").is_err());
        assert!(ResolutionDoc::parse("[]").is_err());
        // The evidence lane's document (no `findings`) reads as no findings.
        let lane = r#"{"v":1,"root":"/r","resolution":null,"declared":["."],"stale":false,"wiring_newer":false,"deps_digest":"0123abcd","read_error":null}"#;
        let parsed = ResolutionDoc::parse(lane).unwrap();
        assert_eq!(parsed.findings, BuildFindings::default());
        assert_eq!(parsed.root, PathBuf::from("/r"));
    }

    #[test]
    fn doc_from_parts_reads_only_build_sources() {
        let sources = vec![
            (
                "build.sbt".to_string(),
                "lazy val a = project\nlibraryDependencies += \"g\" % \"a\" % \"1\"\n".to_string(),
            ),
            (
                "a/build.sbt".to_string(),
                "dependencyOverrides := Seq()\n".to_string(),
            ),
            (
                "project/build.properties".into(),
                "sbt.version=1.9.9\n".into(),
            ),
            (HOSTED_FILE.to_string(), "dependencyOverrides := x\n".into()),
            ("README.md".to_string(), "dependencyOverrides := x\n".into()),
        ];
        let doc = ResolutionDoc::from_parts(PathBuf::new(), None, &sources, false, false);
        assert_eq!(
            doc.declared,
            Some(BTreeSet::from([".".to_string(), "a".to_string()]))
        );
        assert_eq!(doc.findings.overrides_assignment, ["a/build.sbt:1"]);
        assert_eq!(doc.deps_digest, deps_digest(&sources[..3]));
    }

    #[test]
    fn remove_pins_keeps_the_rest_and_deletes_when_empty() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sbt/owned_file");
        let two = std::fs::read_to_string(format!("{dir}/hosted-1-2pin.sbt")).unwrap();
        let one = std::fs::read_to_string(format!("{dir}/hosted-1-1pin.sbt")).unwrap();
        let pins = hosted_pins(&two).unwrap();
        assert_eq!(pins.len(), 2);
        let text = pins.iter().find(|p| p.artifact == "commons-text").unwrap();
        let kept_lang3 = remove_pins(&two, &BTreeSet::from([text.uuid.clone()])).unwrap();
        assert_eq!(kept_lang3.as_deref(), Some(one.as_str()));
        let all: BTreeSet<String> = pins.iter().map(|p| p.uuid.clone()).collect();
        assert_eq!(remove_pins(&two, &all), Ok(None));
        assert_eq!(
            remove_pins(&two, &BTreeSet::new()).unwrap().as_deref(),
            Some(two.as_str())
        );
        assert!(matches!(
            remove_pins("// mine\n", &all),
            Err(OwnedFileError::Foreign)
        ));
        assert_eq!(
            pinned_version(&pins[0].base, &pins[0].uuid),
            pins[0].sv,
            "the suffix is the uuid's first 8 hex"
        );
    }

    #[test]
    fn comparable_root_drops_the_windows_verbatim_prefix() {
        assert_eq!(
            comparable_root(Path::new(r"\\?\C:\work\app")),
            PathBuf::from(r"C:\work\app")
        );
        assert_eq!(
            comparable_root(Path::new(r"\\?\UNC\srv\share\app")),
            PathBuf::from(r"\\srv\share\app")
        );
        assert_eq!(
            comparable_root(Path::new("/work/app")),
            PathBuf::from("/work/app")
        );
    }

    /// The `basic` golden case's build and override, with `doc` under the
    /// resolution key.
    fn basic_case(doc: Option<&str>) -> (BTreeMap<String, String>, Vec<DepOverride>) {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sbt/redirect/basic"
        );
        let mut files = BTreeMap::new();
        for rel in [BUILD_SBT, BUILD_PROPERTIES] {
            let text = std::fs::read_to_string(format!("{dir}/input/{rel}")).unwrap();
            files.insert(rel.to_string(), text);
        }
        if let Some(doc) = doc {
            files.insert(SBT_RESOLUTION_KEY.to_string(), doc.to_string());
        }
        let overrides = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/overrides.json")).unwrap(),
        )
        .unwrap();
        (files, overrides)
    }

    #[test]
    fn an_unreadable_document_warns_once() {
        let (files, overrides) = basic_case(Some("{not json"));
        let mut result = RewriteResult::default();
        rewrite_sbt(&files, &overrides, &mut result);
        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(codes, ["redirect_sbt_no_resolution_evidence"]);
        assert!(result.files.is_empty() && result.confirmed_sbt_uuids.is_empty());
    }

    #[test]
    fn a_windows_canonical_root_still_contains_its_pins() {
        // The evidence's artifact path is under the root sbt saw; the
        // document's root is the canonicalized (verbatim) spelling.
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sbt/redirect/basic"
        );
        let doc = ResolutionDoc::parse(
            &std::fs::read_to_string(format!("{dir}/resolution.json")).unwrap(),
        )
        .unwrap();
        let (files, overrides) = basic_case(Some(&doc.to_json()));
        let mut first = RewriteResult::default();
        rewrite_sbt(&files, &overrides, &mut first);
        let wired = first.files[HOSTED_FILE].clone();
        let pin = hosted_pins(&wired).unwrap().remove(0);
        let root = PathBuf::from(r"C:\work\app");
        let jar = root.join(HOSTED_REPO_REL).join(pin.repo_path("jar"));
        let mut res = JvmResolution::default();
        let ga = (pin.group.clone(), pin.artifact.clone());
        res.modules
            .entry(ga.clone())
            .or_default()
            .entry(pin.sv.clone())
            .or_default()
            .insert("target/x:compile".into());
        res.artifacts
            .entry((ga.0.clone(), ga.1.clone(), pin.sv.clone()))
            .or_default()
            .insert(jar);
        res.in_scope.insert(ga);
        res.projects_seen.insert(".".into());
        let after = ResolutionDoc {
            root: PathBuf::from(r"\\?\C:\work\app"),
            resolution: Some(res),
            deps_digest: pin.deps_digest.clone(),
            ..doc
        };
        let (mut files, overrides) = basic_case(Some(&after.to_json()));
        files.insert(HOSTED_FILE.to_string(), wired);
        let mut rerun = RewriteResult::default();
        rewrite_sbt(&files, &overrides, &mut rerun);
        assert!(
            rerun.warnings.is_empty() && rerun.confirmed_sbt_uuids.contains(&pin.uuid),
            "{rerun:?}"
        );
    }
}
