//! The hosted redirect engine: plan → rewrite → edits over a
//! [`ProjectView`], shared verbatim by `scan`/`get --mode hosted` (a
//! [`ProjectView::Disk`] over the checkout) and the in-memory engine
//! ([`super::memory`], a [`ProjectView::Memory`] over the host's file set).
//!
//! The stages, in the order both callers run them:
//!
//! 1. [`build_candidates`] — reference grants → rewriter overrides, each
//!    grant's fields checked for the shape the project's files take.
//! 2. [`bun_lockb_symlinked`] — the binary-lock symlink refusal.
//! 3. (caller) the apply lock and the vendored→hosted takeover.
//! 4. [`read_candidate_files`] → [`wheel_targets`] → (caller) wheel metadata,
//!    and [`yarn_berry_manifest_targets`] → (caller) served npm manifests.
//! 5. [`rewrite`] — the rewriters, the pnpm named-registry /
//!    `trustLockfile` and npm `allow-remote` auto-configs, and the
//!    per-ecosystem confirmation.
//! 6. [`guard`] — the symlink / unreadable-file refusal before any write.
//!
//! Nothing here writes, spawns, reads the environment or touches the
//! network: every host effect (locking, record fetches, the commit of the
//! rewritten files) stays with the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::api::types::PackageVendorResult;
use crate::constants::npm_family::VLT_HIDDEN_LOCK_REL;
use crate::crawlers::maven_selection::MavenSelection;
use crate::formats::cargo::source_replacement::CratesIoSource;
use crate::formats::governing_locks::PYPI_REQUIREMENTS;
use crate::formats::pnpm::RegistryRoutePins;
use crate::patch::redirect::npmrc::{
    effective_omit_lockfile_registry_resolved, effective_replace_registry_host,
    plan_npmrc_allow_remote_with, replace_registry_host_rewrites, NpmrcPlan, OuterAllowRemote,
    NPMRC_ALLOW_REMOTE_EDIT_KIND, NPMRC_REL,
};
use crate::patch::redirect::presence::groups_present;
use crate::patch::redirect::yarnrc::OuterYarnMirror;
use crate::patch::redirect::{
    artifact_url_spellings, rewrite_registry_redirect_with_host, DepOverride, FileEdit,
    RewriteResult, RewriteWarning,
};
use crate::utils::pnpm_workspace::governing_workspace_file;
use crate::utils::purl::purl_parts;
use crate::utils::redact::url_host;
use crate::vendor::lock_inventory::pnpm::{is_rush, rush_lock_rels};
use crate::vendor::lock_inventory::{bun_text_lock_drives, MemoryEntry, ProjectView};

use super::guidance::{
    npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
    npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
    npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
    npm_allow_remote_user_set_detail, npm_lock_url_needles, npm_omit_lockfile_resolved_detail,
    npm_replace_registry_host_detail, plan_workspace_trust, pnpm_heal_root, pnpm_hosted_pins,
    pnpm_is_shrinkwrap_lock, pnpm_lock_may_need_store_flag, pnpm_lock_version_major,
    pnpm_registry_already_detail, pnpm_registry_blocked_note, pnpm_registry_configured_detail,
    pnpm_registry_unrouted_note, pnpm_registry_unserved_reason,
    pnpm_root_only_workspace_breaks_add, pnpm_trust_configured_detail,
    pnpm_trust_keyless_members_detail, pnpm_trust_legacy_detail, pnpm_trust_manual_guidance,
    pnpm_trust_not_needed_detail, pnpm_trust_policy_preamble, pnpm_trust_rush_detail,
    pnpm_trust_scaffolded_detail, pnpm_trust_workspace_unreadable_detail,
    pnpm_trust_workspace_unsupported_detail, read_npmrc_for_allow_remote, read_workspace_for_trust,
    strip_cli_trust, RegistryWrite, TrustLeftover, TrustPlan, NPM_LOCKS,
    NPM_OMIT_LOCKFILE_RESOLVED_CODE, NPM_REPLACE_REGISTRY_HOST_CODE, PNPM_REGISTRY_PIN_HINT,
    PNPM_TRUST_RUSH_MIXED_NOTE, PNPM_TRUST_TRADEOFF_AND_CAUTION, PNPM_WORKSPACE_REL,
    REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND, REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND,
    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND, REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
    REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
};
use super::vlt::bun_lockb_present;

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to
/// `rewrite_registry_redirect`: the [`crate::formats::registry::HOSTED`]
/// rows of the format registry, in its read order.
pub static REDIRECT_CANDIDATE_FILES: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| {
        crate::formats::registry::paths_with(crate::formats::registry::HOSTED)
    });

/// Refusal code for a rewrite target (or a file the rewrite reads) that is
/// a symbolic link: the writers stage next to the path and rename over it,
/// which would replace the link with a detached copy.
pub const SYMLINK_REFUSAL: &str = "redirect_symlinked_file_unsupported";

/// Refusal code for a candidate file that exists but whose content the
/// in-memory host did not provide (oversize, an LFS pointer,
/// presence-only), and, on disk and in memory alike, for one that is not
/// UTF-8 text (#721): no rewriter can edit it, and reading it as absent
/// would leave its pins unpatched behind an exit-0 run.
pub const UNREADABLE_REFUSAL: &str = "candidate_file_unreadable";

/// Rush's repo-state file, whose `pnpmShrinkwrapHash` a lock edit
/// outside `rush update` desyncs.
pub const RUSH_REPO_STATE_REL: &str = "common/config/rush/repo-state.json";

/// One granted reference: the purl it was granted for plus the rewriter
/// override built from it. The purl is what the takeover, the skip records
/// and the confirmation probe key on; everything the probe needs AFTER the
/// rewrite to decide whether the dep was actually redirected (artifact
/// URL, registry index URL, fail-closed maven's suffixed version) already
/// rides the override. The single vector is filtered in place by every
/// withhold/refusal step, and the rewriters' `overrides` slice is
/// materialized from it once, after the last filter.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub purl: String,
    pub dep: DepOverride,
}

/// `(purl, uuid)` of each candidate that was granted but that nothing in
/// the project's final files pins: not in `confirmed` (purl and uuid) and
/// not already reported in `skipped` (by uuid — a skip carries its own
/// reason). Candidate order. The disk and memory paths both report these
/// as the `unpinned` rows of the `redirect` block, and the disk path's
/// human output lists them as "Not hosted".
pub fn unconfirmed_candidates(
    candidates: &[Candidate],
    confirmed: &[(String, String)],
    skipped: &[SkippedPatch],
) -> Vec<(String, String)> {
    candidates
        .iter()
        .filter(|c| {
            !confirmed
                .iter()
                .any(|(purl, uuid)| *purl == c.purl && *uuid == c.dep.patch_uuid)
        })
        .filter(|c| !skipped.iter().any(|s| s.uuid == c.dep.patch_uuid))
        .map(|c| (c.purl.clone(), c.dep.patch_uuid.clone()))
        .collect()
}

/// A selected patch that was not redirected, and why (the `skipped[]`
/// entries of the `redirect` block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedPatch {
    pub purl: String,
    pub uuid: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SkippedPatch {
    pub fn new(purl: &str, uuid: &str, reason: &str) -> Self {
        SkippedPatch {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            reason: reason.to_string(),
            detail: None,
        }
    }
}

/// A whole-project refusal: nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: String,
}

/// The refusal for a symlinked rewrite target.
pub fn symlink_refusal(linked: &str) -> Refusal {
    Refusal {
        code: SYMLINK_REFUSAL.to_string(),
        message: format!(
            "{linked} is a symbolic link; socket-patch rewrites files in place with an atomic \
             rename, which would replace the link — replace the link with a regular file (or \
             run socket-patch in the directory it points to) and re-run; nothing was written"
        ),
    }
}

/// The refusal for a candidate read through a link: the file itself
/// ([`symlink_refusal`]), or, on disk, a directory on its path that links
/// out of the repository root, so a rewrite would land outside it.
fn linked_read_refusal(view: &ProjectView<'_>, rel: &str) -> Refusal {
    if matches!(view, ProjectView::Memory(_)) || view.is_symlink(rel) {
        return symlink_refusal(rel);
    }
    Refusal {
        code: SYMLINK_REFUSAL.to_string(),
        message: format!(
            "{rel} is reached through a symbolic link that leaves the repository root; \
             socket-patch does not read or rewrite project files outside it — replace the \
             link with a regular directory (or run socket-patch in the directory it points \
             to) and re-run; nothing was written"
        ),
    }
}

/// The refusal for a symlinked `bun.lockb` (checked before any takeover
/// changes wiring).
pub fn bun_lockb_symlink_refusal() -> Refusal {
    Refusal {
        code: SYMLINK_REFUSAL.to_string(),
        message: "bun.lockb is a symbolic link; replace it with a regular file (or run \
                  socket-patch in the directory it points to) before patching; nothing was \
                  written"
            .to_string(),
    }
}

fn unreadable_refusal(rel: &str) -> Refusal {
    Refusal {
        code: UNREADABLE_REFUSAL.to_string(),
        message: format!(
            "{rel} exists but its content was not provided (too large, an LFS pointer, or \
             not fetched), so it cannot be rewritten alongside the other lockfiles; nothing \
             was written"
        ),
    }
}

/// The refusal for an unreadable `socket-patch.sbt`, the file the sbt
/// planner owns and would otherwise create over the user's bytes.
pub const SBT_OWNED_FILE_UNREADABLE: &str = "redirect_sbt_owned_file_unreadable";

fn undecodable_refusal(rel: &str) -> Refusal {
    // Keeps the sbt planner's own refusal code, and still refuses here,
    // before any vendored->hosted takeover revert.
    if rel == crate::formats::sbt::owned_file::HOSTED_FILE {
        return Refusal {
            code: SBT_OWNED_FILE_UNREADABLE.to_string(),
            message: format!(
                "{rel} is not UTF-8 text, so the hosted sbt wiring would replace it; \
                 re-save it as UTF-8 and re-run; nothing was written"
            ),
        };
    }
    Refusal {
        code: UNREADABLE_REFUSAL.to_string(),
        message: format!(
            "{rel} is not UTF-8 text (for example UTF-16, which Windows PowerShell 5.1 \
             writes for `pip freeze > requirements.txt`), so it cannot be rewritten \
             alongside the other lockfiles; re-save it as UTF-8 and re-run; nothing was \
             written"
        ),
    }
}

/// Skip reason and warning code of a grant with a field that is not in the
/// shape the project's files take verbatim (a digest of the wrong length,
/// a URL or coordinate holding a quote, whitespace or markup).
pub const GRANT_MALFORMED: &str = "redirect_grant_malformed";

/// Skip reason and warning code of a grant whose artifact or registry
/// index URL is plain `http` on an origin that is neither a loopback
/// address nor a configured patch server.
pub const GRANT_INSECURE_URL: &str = "redirect_grant_insecure_url";

/// Reference grants → candidates. A selection without a usable grant is
/// recorded in `skipped` (`not_found`, the reference status, `bad_purl`,
/// `no_url`).
///
/// This is the one place a grant's fields are checked
/// ([`grant::check`]): everything past it — the takeover, the artifact
/// fetches, every rewriter — takes a candidate's strings as safe to write.
/// A grant that fails is skipped with [`GRANT_MALFORMED`] or
/// [`GRANT_INSECURE_URL`] and one warning of the same code and detail in
/// `warnings`; the package stays as it is. `patch_server_origins` are the
/// operator's own patch servers (`--patch-server-url`), whose plain-`http`
/// URLs are accepted.
///
/// [`grant::check`]: crate::patch::redirect::grant::check
pub fn build_candidates(
    selected: &[(String, String)],
    references: &HashMap<String, PackageVendorResult>,
    patch_server_origins: &[String],
    skipped: &mut Vec<SkippedPatch>,
    warnings: &mut Vec<RewriteWarning>,
) -> Vec<Candidate> {
    use crate::patch::redirect::grant::{self, Flaw};
    let mut candidates = Vec::new();
    for (sel_purl, sel_uuid) in selected {
        let Some(reference) = references.get(sel_uuid) else {
            skipped.push(SkippedPatch::new(sel_purl, sel_uuid, "not_found"));
            continue;
        };
        if reference.status != "granted" && reference.status != "reused" {
            skipped.push(SkippedPatch::new(sel_purl, sel_uuid, &reference.status));
            continue;
        }
        let purl = reference.purl.as_deref().unwrap_or(sel_purl);
        let Some((ecosystem, name, version)) = purl_parts(purl) else {
            skipped.push(SkippedPatch::new(purl, sel_uuid, "bad_purl"));
            continue;
        };
        let Some(url) = reference.url.clone() else {
            skipped.push(SkippedPatch::new(purl, sel_uuid, "no_url"));
            continue;
        };
        let mut integrity = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "tarball")
            .map(|a| a.integrity.clone())
            .unwrap_or_default();
        // The yarn-berry cache zip carries the `yarnBerry10c0` checksum the
        // berry rewriter pins (berry verifies the zip, not the tarball).
        // Merge it in; the zip URL itself is never read.
        let berry_zip = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "yarn-berry-zip");
        if let Some(c) = berry_zip.and_then(|a| a.integrity.yarn_berry10c0.clone()) {
            integrity.yarn_berry10c0 = Some(c);
        }
        // goproxy: the hosted-Go hash pair rides the override's
        // identifiers (the tarball's dirhashH1 is the original-path
        // flavor, kept for vendor-mode verification); the golang rewriter
        // reads the normalized integrity, so merge — the gopatch-flavor zip
        // h1 REPLACES dirhashH1 here. Only both together: a half-merged
        // pair would trip the rewriter's fail-closed integrity check by
        // design.
        if let Some(ov) = reference
            .registry_override
            .as_ref()
            .filter(|o| o.kind == "goproxy")
        {
            if let (Some(zip_h1), Some(gomod_h1)) = (
                ov.identifiers.go_zip_dirhash_h1.clone(),
                ov.identifiers.go_mod_h1.clone(),
            ) {
                integrity.dirhash_h1 = Some(zip_h1);
                integrity.go_mod_h1 = Some(gomod_h1);
            }
        }
        // The grant token is never a top-level reference field — it only
        // rides the URLs the reference endpoint hands back, as the path
        // level before the patch uuid. Recover it so the rewriters'
        // rotation-idempotency guards (which wildcard the token path level
        // of a previously-written URL) don't depend on it being derivable
        // from the URL alone (with an empty token the gem guard does not
        // recognise the `source:` a previous scan wrote as its own).
        let token = reference
            .registry_override
            .as_ref()
            .and_then(|o| crate::patch::redirect::grant_token_path_segment(&o.index_url, sel_uuid))
            .or_else(|| crate::patch::redirect::grant_token_path_segment(&url, sel_uuid))
            .unwrap_or_default();
        let mut dep = DepOverride {
            ecosystem,
            name,
            namespace: None,
            version,
            token,
            patch_uuid: sel_uuid.clone(),
            artifact_url: url,
            npm_registry_url: reference.npm_registry_url.clone(),
            registry_override: reference.registry_override.clone(),
            integrity,
        };
        // A registry address pnpm could not route the artifact URL to
        // reads as not served: the pin then takes the `trustLockfile` path.
        dep.npm_registry_url = grant::npm_registry_url(&dep).map(str::to_string);
        // The served purl is printed and recorded as it is: a line break in
        // one would forge a line of the run's output.
        let checked = if purl.chars().any(|c| c.is_whitespace() || c.is_control()) {
            Err(Flaw::Malformed(
                "its package URL holds whitespace".to_string(),
            ))
        } else {
            grant::check(&dep, patch_server_origins)
        };
        if let Err(flaw) = checked {
            let (code, reason) = match flaw {
                Flaw::Malformed(reason) => (GRANT_MALFORMED, reason),
                Flaw::InsecureUrl(reason) => (GRANT_INSECURE_URL, reason),
            };
            // Keyed and worded by the selection's purl, the spelling the
            // project's own files gave: the served one is what failed.
            let detail = format!(
                "{sel_purl}: the patch server's reference for it was refused ({reason}); \
                 nothing was written for it, so it stays unpatched"
            );
            warnings.push(warning(code, detail.clone()));
            skipped.push(SkippedPatch {
                detail: Some(detail),
                ..SkippedPatch::new(sel_purl, sel_uuid, code)
            });
            continue;
        }
        candidates.push(Candidate {
            purl: purl.to_string(),
            dep,
        });
    }
    candidates
}

/// Skip reason and warning code of a patch whose ecosystem cannot be served
/// through a patch-server mirror (`--patch-mirror-url`): nothing is written
/// for it, so it stays as it is.
pub const MIRROR_UNSUPPORTED: &str = "redirect_mirror_unsupported";

/// Skip reason and warning code of a grant that cannot be moved onto the
/// run's mirror: a URL without a served path, or a mirrored URL the grant
/// gate refuses. Nothing is written for it.
pub const MIRROR_URL_REFUSED: &str = "redirect_mirror_url_refused";

/// Where each mirrored reference is served from: the URL the patch
/// server's grant named, keyed by the mirrored URL the candidate now
/// carries. The run's own downloads (a wheel's metadata, a tarball's
/// `package.json`, a gem to refresh a stale install with) read the served
/// URL: the grant token in it is all the authorization that takes, where
/// the mirror may ask for credentials the run was never given.
#[derive(Debug, Clone, Default)]
pub struct MirrorSources {
    /// The mirror's base URL (empty when the run has no mirror).
    base: String,
    /// Mirrored artifact URL -> served artifact URL.
    served: BTreeMap<String, String>,
    /// `(mirrored, served)` registry index URLs, without a trailing slash:
    /// a URL below a mirrored index is served below its served twin.
    registries: Vec<(String, String)>,
}

impl MirrorSources {
    /// The URL to download `url` from: where the patch server serves it
    /// when `url` is a mirrored artifact or lies under a mirrored registry
    /// index, else itself.
    pub fn fetch_url<'a>(&'a self, url: &'a str) -> std::borrow::Cow<'a, str> {
        use std::borrow::Cow;
        if let Some(served) = self.served.get(url) {
            return Cow::Borrowed(served);
        }
        for (mirrored, served) in &self.registries {
            if let Some(rest) = url.strip_prefix(mirrored.as_str()) {
                if rest.is_empty() || rest.starts_with('/') {
                    return Cow::Owned(format!("{served}{rest}"));
                }
            }
        }
        Cow::Borrowed(url)
    }

    /// [`Self::fetch_url`] for a candidate's own artifact URL, borrowed:
    /// the served URL of a mirrored artifact, else the URL itself.
    pub fn fetch_artifact_url<'a>(&'a self, artifact_url: &'a str) -> &'a str {
        self.served
            .get(artifact_url)
            .map_or(artifact_url, String::as_str)
    }

    /// The base URL of the mirror these references were moved onto.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The mirrored artifact URLs, in order.
    pub fn mirrored_urls(&self) -> impl Iterator<Item = &str> {
        self.served.keys().map(String::as_str)
    }

    /// The URLs the patch server serves the mirrored artifacts at.
    pub fn served_urls(&self) -> impl Iterator<Item = &str> {
        self.served.values().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.served.is_empty()
    }
}

/// Why `ecosystem`'s hosted reference cannot move onto a mirror, if it
/// cannot. A Cargo sparse index and a NuGet service index are documents the
/// patch server renders with its own absolute download URLs in them
/// (`config.json`'s `dl`, the service index's resource ids), so a client
/// reading the index through the mirror is sent straight back to the patch
/// server for the package.
fn mirror_unsupported(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "cargo" => Some(
            "a Cargo registry index names the patch server's own download URL, which a mirror \
             cannot rewrite",
        ),
        "nuget" => Some(
            "a NuGet service index names the patch server's own package URLs, which a mirror \
             cannot rewrite",
        ),
        _ => None,
    }
}

/// Move every candidate's hosted reference onto `mirror`
/// (`--patch-mirror-url`): its artifact URL and its registry index URL,
/// everything before the path swapped for the mirror's base. Run right
/// after [`build_candidates`], so the takeover, the withholds and every
/// rewriter see the URL the project's files will hold (a re-run finds its
/// own earlier pin, not a foreign one).
///
/// * A Go candidate is left alone: its pin is the module path
///   `patch.socket.dev/gopatch/<uuid>`, which names no host to fetch from
///   (GOPROXY decides that).
/// * A Cargo or NuGet candidate is skipped with [`MIRROR_UNSUPPORTED`]:
///   see [`mirror_unsupported`]. A direct pin is not written in its place,
///   because the operator configured a mirror to say installs must not
///   reach the patch server.
/// * A candidate whose mirrored URLs the grant gate refuses is skipped
///   with [`MIRROR_URL_REFUSED`].
/// * An npm candidate's registry address (`npm_registry_url`) is not
///   moved: the document the patch server answers there names the tarball
///   on the patch server itself, which a mirror cannot rewrite, so pnpm
///   could not verify a mirrored tarball against it. The mirrored tarball
///   is then no file of that address, which is what keeps the pin off the
///   pnpm registry route ([`crate::patch::redirect::grant::npm_registry_url`])
///   and on `trustLockfile`.
///
/// `patch_server_origins` must hold the mirror's base: it is how the grant
/// gate takes a plain-`http` mirror, and how every reader recognizes the
/// mirrored references afterwards.
pub fn mirror_candidates(
    candidates: Vec<Candidate>,
    mirror: &crate::patch::redirect::mirror::PatchMirror,
    patch_server_origins: &[String],
    skipped: &mut Vec<SkippedPatch>,
    warnings: &mut Vec<RewriteWarning>,
) -> (Vec<Candidate>, MirrorSources) {
    use crate::patch::redirect::grant;
    let mut sources = MirrorSources {
        base: mirror.base().to_string(),
        ..MirrorSources::default()
    };
    let mut kept = Vec::with_capacity(candidates.len());
    for mut candidate in candidates {
        let dep = &mut candidate.dep;
        if dep.ecosystem == "golang" {
            kept.push(candidate);
            continue;
        }
        let mut skip = |code: &str, why: String, purl: &str, uuid: &str| {
            // Not "it stays unpatched": an earlier run may have pinned it
            // on the patch server, which this run does not read here.
            let detail = format!("{purl}: {why}; nothing was changed for it");
            warnings.push(warning(code, detail.clone()));
            skipped.push(SkippedPatch {
                detail: Some(detail),
                ..SkippedPatch::new(purl, uuid, code)
            });
        };
        if let Some(why) = mirror_unsupported(&dep.ecosystem) {
            skip(
                MIRROR_UNSUPPORTED,
                format!(
                    "{why}, so it cannot be installed through the patch mirror; use \
                     `--mode vendored` for it"
                ),
                &candidate.purl,
                &dep.patch_uuid,
            );
            continue;
        }
        let served_artifact = dep.artifact_url.clone();
        // `None`: an index URL that cannot move; `Some(None)`: no override.
        let mirrored_index = match &dep.registry_override {
            Some(ov) => mirror.rebase(&ov.index_url).map(Some),
            None => Some(None),
        };
        let (Some(mirrored_artifact), Some(mirrored_index)) =
            (mirror.rebase(&served_artifact), mirrored_index)
        else {
            skip(
                MIRROR_URL_REFUSED,
                "the patch server's reference for it has no path to serve through the patch \
                 mirror"
                    .to_string(),
                &candidate.purl,
                &dep.patch_uuid,
            );
            continue;
        };
        dep.artifact_url = mirrored_artifact;
        let mut registry = None;
        if let (Some(ov), Some(index_url)) = (dep.registry_override.as_mut(), mirrored_index) {
            registry = Some((
                index_url.trim_end_matches('/').to_string(),
                ov.index_url.trim_end_matches('/').to_string(),
            ));
            ov.index_url = index_url;
        }
        if let Err(flaw) = grant::check(dep, patch_server_origins) {
            let reason = match flaw {
                grant::Flaw::Malformed(reason) | grant::Flaw::InsecureUrl(reason) => reason,
            };
            skip(
                MIRROR_URL_REFUSED,
                format!("its reference on the patch mirror was refused ({reason})"),
                &candidate.purl,
                &dep.patch_uuid,
            );
            continue;
        }
        sources
            .served
            .insert(dep.artifact_url.clone(), served_artifact);
        sources.registries.extend(registry);
        kept.push(candidate);
    }
    (kept, sources)
}

/// Skip reason and warning code of a patch the project already pins
/// through a host this run was not given: nothing is changed for it.
pub const PIN_ON_UNCONFIGURED_HOST: &str = "redirect_pin_on_unconfigured_host";

/// Withhold every candidate whose patch one of `files` already pins through
/// a host the run does not know as a patch server: a URL with the hosted
/// shape for the candidate's patch uuid on an origin outside
/// `accepted_origins` (and Socket's own). That is what a project wired
/// through a patch mirror looks like to a run that was not given
/// `--patch-mirror-url`, and rewriting it would move a working pin onto a
/// host the project's builds may not be able to reach. The files stay as
/// they are and the run says which host to configure.
///
/// `accepted_origins` must hold everything this run can itself write or
/// supersede: the configured origins, the mirror, and the origins of this
/// run's grants (a pin an earlier run of the same server wrote is its own).
pub fn withhold_foreign_host_pins(
    files: &BTreeMap<String, String>,
    accepted_origins: &[String],
    candidates: &mut Vec<Candidate>,
    skipped: &mut Vec<SkippedPatch>,
    warnings: &mut Vec<RewriteWarning>,
) {
    candidates.retain(|c| {
        let uuid = c.dep.patch_uuid.as_str();
        let Some((file, host)) = files.iter().find_map(|(path, text)| {
            crate::vex::discover::foreign_hosted_host_in_text(text, uuid, accepted_origins)
                .map(|host| (path.as_str(), host))
        }) else {
            return true;
        };
        let detail = format!(
            "{}: {file} already pins patch {uuid} through {host}, which this run was not given \
             as a patch mirror or patch server, so nothing was changed for it; if that host is \
             your patch mirror set --patch-mirror-url (SOCKET_PATCH_MIRROR_URL) to its base \
             URL, if it is another patch server pass --patch-server-url, and re-run",
            c.purl
        );
        warnings.push(warning(PIN_ON_UNCONFIGURED_HOST, detail.clone()));
        skipped.push(SkippedPatch {
            detail: Some(detail),
            ..SkippedPatch::new(&c.purl, uuid, PIN_ON_UNCONFIGURED_HOST)
        });
        false
    });
}

/// Whether an npm candidate would rewrite a `bun.lockb` that is a symbolic
/// link (atomic replacement cannot preserve a link; previews refuse too).
pub fn bun_lockb_symlinked(view: &ProjectView<'_>, candidates: &[Candidate]) -> bool {
    candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && !bun_text_lock_drives(view)
        && view.is_symlink("bun.lockb")
}

/// Skip reason of an npm candidate withheld because the project patches
/// that package itself ([`withhold_user_patched`]): the code the CLI's
/// consent gate reports for the same packages.
pub const USER_PATCH_CONFLICT: &str = "user_patch_conflict";

/// The pnpm and yarn locks [`withhold_user_patched`] reads when `files`
/// does not already hold them.
const USER_PATCH_LOCKS: [&str; 4] = [
    "pnpm-lock.yaml",
    "shrinkwrap.yaml",
    "yarn.lock",
    crate::constants::npm_family::RUSH_COMMON_LOCK_REL,
];

/// The locks a disk scan reads on top of the CLI consent gate's walk for
/// the user-patch gate ([`withhold_user_patched_by`]): a root
/// `shrinkwrap.yaml`, and a Rush monorepo's pnpm locks — the common lock
/// and every subspace's, through the same safe listing lockfile discovery
/// uses ([`rush_lock_rels`]). The in-memory engine reads the subspace locks
/// as candidate files, so leaving them out on disk would pin a package the
/// in-memory engine withholds. Outside Rush only the common lock path is
/// tried, as before (a missing file is simply not read).
pub async fn user_patch_supplement_lock_rels(view: ProjectView<'_>) -> Vec<String> {
    let mut rels = if is_rush(view).await {
        rush_lock_rels(view).await
    } else {
        vec![crate::constants::npm_family::RUSH_COMMON_LOCK_REL.to_string()]
    };
    rels.push("shrinkwrap.yaml".to_string());
    rels
}

/// Withhold from every rewriter each npm candidate whose package the
/// project patches itself with pnpm (`patchedDependencies`), yarn (a
/// `patch:` descriptor) or patch-package, recording each as skipped
/// ([`USER_PATCH_CONFLICT`]). The package manager applies the user's
/// diff on top of whatever tarball the lock names, so a hosted pin either
/// fails the install once the diff no longer applies or installs bytes
/// that are neither the user's package nor the Socket patch. The
/// evidence is [`UserPatchIndex::npm_family_in`], which `vex` discovery
/// reads too, over `files` (the candidate texts already read: a member's
/// own pnpm lock) and the root pnpm, yarn and Rush locks. npm's and Bun's
/// own `patchedDependencies` are not read here: their rewriters skip such
/// a package per resolution (#711, #367). `allow` is the caller's explicit
/// consent (the CLI's `--allow-patch-conflicts`): nothing is withheld.
/// Returns one [`USER_PATCH_CONFLICT`] warning per withheld candidate,
/// with the skip's detail.
///
/// [`UserPatchIndex::npm_family_in`]: crate::patch::user_patches::UserPatchIndex::npm_family_in
pub async fn withhold_user_patched(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    candidates: &mut Vec<Candidate>,
    skipped: &mut Vec<SkippedPatch>,
    allow: bool,
) -> Vec<RewriteWarning> {
    if allow || !candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        return Vec::new();
    }
    let mut read: Vec<(String, String)> = Vec::new();
    let mut unreadable: Vec<(&str, std::io::Error)> = Vec::new();
    for rel in USER_PATCH_LOCKS {
        if files.contains_key(rel) {
            continue;
        }
        match read_user_patch_lock(view, rel).await {
            Ok(Some(text)) => read.push((rel.to_string(), text)),
            Ok(None) => {}
            Err(e) => unreadable.push((rel, e)),
        }
    }
    let locks: Vec<(&str, &str)> = files
        .iter()
        .chain(read.iter().map(|(rel, text)| (rel, text)))
        .filter(|(rel, _)| {
            matches!(
                rel.rsplit('/').next(),
                Some("pnpm-lock.yaml" | "shrinkwrap.yaml" | "yarn.lock")
            )
        })
        .map(|(rel, text)| (rel.as_str(), text.as_str()))
        .collect();
    let mut index = crate::patch::user_patches::UserPatchIndex::npm_family_in(view, &locks).await;
    for (rel, e) in &unreadable {
        index.unreadable_lock(rel, e);
    }
    withhold_user_patched_by(&index, candidates, skipped)
}

/// A lock the user-patch evidence reads, as the walk's `read_view` reads
/// a project file: `None` when it is missing, or is an in-memory link (the
/// engine refuses a linked candidate on its own); one the repository bound
/// refused because its real path leaves the repository is read through
/// the link from disk (`None` when nothing is there). `Err` is a lock that
/// exists but can't be read, which protects every npm package.
async fn read_user_patch_lock(
    view: &ProjectView<'_>,
    rel: &str,
) -> std::io::Result<Option<String>> {
    let read = match view.read_text(rel).await {
        Err(e) if crate::utils::repo_root::is_refused_read(&e) => {
            match view.disk_root_reading([rel]) {
                Some(root) => crate::utils::fs::read_regular_to_string(&root.join(rel)).await,
                None => Err(e),
            }
        }
        read => read,
    };
    match read {
        Ok(text) => Ok(Some(text)),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && !crate::utils::repo_root::is_refused_read(&e) =>
        {
            Ok(None)
        }
        Err(_) if matches!(view, ProjectView::Memory(_)) && view.is_symlink(rel) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The disk flow's supplement to the CLI's consent gate: withhold each
/// npm candidate a Rush lock (the common one and every subspace's) or a
/// root `shrinkwrap.yaml` records as patched, which the gate's walk does
/// not read ([`user_patch_supplement_lock_rels`]), as
/// [`withhold_user_patched_by`] does. A lock that exists but can't be
/// read protects every npm package; a missing one is no evidence.
pub async fn withhold_user_patched_by_supplement(
    view: ProjectView<'_>,
    candidates: &mut Vec<Candidate>,
    skipped: &mut Vec<SkippedPatch>,
) -> Vec<RewriteWarning> {
    if !candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        return Vec::new();
    }
    let mut read: Vec<(String, String)> = Vec::new();
    let mut unreadable: Vec<(String, std::io::Error)> = Vec::new();
    for rel in user_patch_supplement_lock_rels(view).await {
        match read_user_patch_lock(&view, &rel).await {
            Ok(Some(text)) => read.push((rel, text)),
            Ok(None) => {}
            Err(e) => unreadable.push((rel, e)),
        }
    }
    let locks: Vec<(&str, &str)> = read
        .iter()
        .map(|(rel, text)| (rel.as_str(), text.as_str()))
        .collect();
    let mut index = crate::patch::user_patches::UserPatchIndex::from_locks(&locks);
    for (rel, e) in &unreadable {
        index.unreadable_lock(rel, e);
    }
    withhold_user_patched_by(&index, candidates, skipped)
}

/// [`withhold_user_patched`] by evidence the caller already holds: the
/// disk flow passes what its consent gate's walk did not read (a Rush
/// lock), [`UserPatchIndex::from_locks`], instead of walking the project
/// a second time.
///
/// [`UserPatchIndex::from_locks`]: crate::patch::user_patches::UserPatchIndex::from_locks
pub fn withhold_user_patched_by(
    index: &crate::patch::user_patches::UserPatchIndex,
    candidates: &mut Vec<Candidate>,
    skipped: &mut Vec<SkippedPatch>,
) -> Vec<RewriteWarning> {
    let mut warnings = Vec::new();
    if index.is_empty() {
        return warnings;
    }
    candidates.retain(|c| {
        if c.dep.ecosystem != "npm" {
            return true;
        }
        let sources = index.conflicts(&c.purl);
        if sources.is_empty() {
            return true;
        }
        let detail = user_patched_detail(&c.purl, &sources);
        warnings.push(warning(USER_PATCH_CONFLICT, detail.clone()));
        skipped.push(SkippedPatch {
            detail: Some(detail),
            ..SkippedPatch::new(&c.purl, &c.dep.patch_uuid, USER_PATCH_CONFLICT)
        });
        false
    });
    warnings
}

/// [`withhold_user_patched`]'s skip detail.
fn user_patched_detail(purl: &str, sources: &[String]) -> String {
    format!(
        "{purl}: {} declares a patch the project applies to this package itself (pnpm \
         `patchedDependencies`, a yarn `patch:` descriptor, or a patch-package patch); the \
         package manager applies it on top of whatever tarball the lock names, so pinning the \
         hosted patch would stack the two (or fail every install once the user's diff no \
         longer applies). It is left unchanged and stays without the Socket patch: fold the \
         Socket fix into your own patch, or remove the user patch and re-run (the CLI's \
         explicit `--allow-patch-conflicts` wires it anyway)",
        sources.join(", ")
    )
}

/// The project's candidate files as the rewriters read them.
#[derive(Debug, Clone, Default)]
pub struct CandidateFiles {
    /// Readable candidate texts, keyed by project-relative path.
    pub files: BTreeMap<String, String>,
    /// The Rush locks among `files` (the repo-state warning keys on them).
    pub rush_lock_keys: Vec<String>,
    /// The workspace members' own locks among `files`, read beside the
    /// root's when the workspace turned the shared lock off (#492).
    pub pnpm_member_lock_keys: Vec<String>,
    /// In memory: candidate files the disk flow reads through a symbolic
    /// link. On disk: candidate files linked out of the repository root,
    /// whose reads the bound refused. Their bytes are unknown, so a project
    /// whose candidates could rewrite one is refused like the disk symlink
    /// guard refuses the write.
    pub symlinked_reads: Vec<String>,
    /// In memory only: candidate files that exist without content; a
    /// project whose candidates could rewrite (or whose rewrite depends on)
    /// one is refused, since the rewriters would treat it as absent.
    pub unreadable_reads: Vec<String>,
    /// Candidate files that exist but are not UTF-8 text (a UTF-16
    /// requirements.txt pip reads, #721), on disk and in memory alike. They
    /// are left out of `files`; a project whose candidates could rewrite
    /// one is refused rather than read as if the file were absent.
    pub undecodable_reads: Vec<String>,
    /// Poms of the Maven reactor (a module's, or a parent's inside the
    /// checkout, whatever the file is called) that exist but are not UTF-8
    /// text. A Maven candidate could rewrite any of them, so the run is
    /// refused like for [`Self::undecodable_reads`], never planned as if
    /// the pom were missing.
    pub undecodable_maven_poms: Vec<String>,
    /// Gradle build files the script graph reached that exist but cannot be
    /// read as text (any view): the hosted Gradle planner refuses the build
    /// instead of taking them for absent (and creating a settings file over
    /// one).
    pub gradle_unreadable: BTreeSet<String>,
    /// Set when bundler is configured to load a manifest the gem rewriter
    /// cannot edit (`BUNDLE_GEMFILE`), or to fetch the patch-registry
    /// source through a mirror (`mirror.all`, #681): every gem manifest and
    /// lock was left out of `files`, and the rewrite reports this instead
    /// of a redirect.
    pub gem_refusal: Option<RewriteWarning>,
    /// Set when the root pnpm lock pins nothing pnpm installs: the
    /// workspace keeps one lock per member but the members cannot be
    /// listed (#492), `gitBranchLockfile` installs the branch from a
    /// `pnpm-lock.<branch>.yaml` (#556), or pnpm's `lockfile` setting is
    /// off so pnpm reads no lock at all (#1074). And when a pin in it would
    /// fail the Bazel build of the project ([`crate::bazel::pnpm`]). The
    /// root lock was left out of
    /// `files`, and the rewrite reports this instead of a redirect or a
    /// "no lockfile" hint.
    pub pnpm_refusal: Option<RewriteWarning>,
    /// What the Bazel workspace of the project says of its pnpm locks
    /// ([`crate::bazel::pnpm::hubs`]), asked once, here, where the files
    /// are read: whether a hub keeps the root lock out of the run (then
    /// also [`Self::pnpm_refusal`]), and whether one reads a lock, which
    /// then is not routed through a named registry. The rewrite plans
    /// from this alone and reads nothing of Bazel itself.
    pub pnpm_bazel: crate::bazel::pnpm::Hubs,
}

impl CandidateFiles {
    /// Read `rel` into `files`: `true` when it was read.
    async fn read(
        &mut self,
        view: &ProjectView<'_>,
        unreadable: &BTreeSet<String>,
        rel: &str,
    ) -> bool {
        let text = match view {
            // Every disk read goes through the FIFO-safe reader
            // (non-blocking open + fstat regular-file check), so a FIFO
            // under a candidate name is skipped like a missing file instead
            // of wedging the run in open(2).
            ProjectView::Disk(_) | ProjectView::Snapshot(_) => match view.read_text(rel).await {
                Ok(text) => Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    self.undecodable_reads.push(rel.to_string());
                    None
                }
                // A candidate whose real path leaves the repository root
                // (the file itself, or a directory on its path, is a link
                // out of it; a candidate name never climbs): the bound
                // refuses the read, but the package manager still follows
                // the link, so the guard refuses it, never takes it for
                // absent. Install state under `node_modules/` (a linked
                // `node_modules` is a common layout) is no rewrite target:
                // only a link of the file itself counts there.
                Err(e)
                    if crate::utils::repo_root::is_refused_read(&e)
                        && (view.is_symlink(rel)
                            || !rel.split('/').any(|segment| segment == "node_modules")) =>
                {
                    self.symlinked_reads.push(rel.to_string());
                    None
                }
                Err(_) => None,
            },
            ProjectView::Memory(project) => {
                if project.is_symlink(rel) {
                    self.symlinked_reads.push(rel.to_string());
                    return false;
                }
                if unreadable.contains(rel) {
                    self.unreadable_reads.push(rel.to_string());
                    return false;
                }
                // Disk reads any UTF-8 regular file and records a non-UTF-8
                // one as undecodable; so does memory.
                match project.get(rel) {
                    Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                    Some(MemoryEntry::Binary(bytes)) => match std::str::from_utf8(bytes) {
                        Ok(text) => Some(text.to_string()),
                        Err(_) => {
                            self.undecodable_reads.push(rel.to_string());
                            None
                        }
                    },
                    _ => None,
                }
            }
        };
        match text {
            Some(text) => {
                self.files.insert(rel.to_string(), text);
                true
            }
            None => false,
        }
    }
}

/// Whether `rel` is a [`PRESENCE_ONLY`](crate::formats::registry::PRESENCE_ONLY)
/// row the in-memory host lists without usable content (a symbolic link,
/// an oversize or presence-only entry). Its planners only ask whether it
/// exists — the Pipenv planner tells a live `Pipfile.lock` from an
/// abandoned one by the `Pipfile` beside it — so it is recorded as present
/// (empty) rather than dropped. Disk reads such a file through any link.
fn presence_only_present(view: &ProjectView<'_>, rel: &str) -> bool {
    let ProjectView::Memory(project) = view else {
        return false;
    };
    project.contains(rel)
        && crate::formats::registry::registry()
            .iter()
            .any(|f| f.path == rel && f.has(crate::formats::registry::PRESENCE_ONLY))
}

/// Read `rel` as advisory rewriter input: a link or an unreadable in-memory
/// entry is left out (the rewriter then keeps its conservative reading)
/// rather than refused like a file the rewrite writes.
async fn read_advisory(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    rel: &str,
) -> Option<String> {
    read_pom_text(view, unreadable, rel).await.ok().flatten()
}

/// The file `rel` is there, but is not UTF-8 text.
struct Undecodable;

/// [`read_advisory`] that tells a file which is there but is not UTF-8
/// text (`Err`) from one that is missing, linked or not readable at all
/// (`Ok(None)`): the first is a file whose content this run does not know,
/// and must never be taken for an absent one.
async fn read_pom_text(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    rel: &str,
) -> Result<Option<String>, Undecodable> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => match view.read_text(rel).await {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(Undecodable),
            Err(_) => Ok(None),
        },
        ProjectView::Memory(project) if !project.is_symlink(rel) && !unreadable.contains(rel) => {
            match project.get(rel) {
                Some(MemoryEntry::Text(text)) => Ok(Some(text.to_string())),
                Some(MemoryEntry::Binary(bytes)) => std::str::from_utf8(bytes)
                    .map(|text| Some(text.to_string()))
                    .map_err(|_| Undecodable),
                _ => Ok(None),
            }
        }
        ProjectView::Memory(_) => Ok(None),
    }
}

/// Read every file the Maven reactor planner reads for the root `pom.xml`
/// ([`read_reactor`](crate::vendor::jvm::maven_reactor::read_reactor), the
/// reader discovery and restore share, so each finds what the others
/// wrote): every pom is fetched and parsed once, however many modules.
///
/// They are advisory input: a module pom that is a symbolic link, or that
/// cannot be opened, is left out, and the planner then finds the reactor
/// incomplete and refuses it with nothing written. That is what a reactor
/// got before module poms were read at all; it never fails the run, as an
/// unreadable root candidate does. A pom that is there but is not UTF-8
/// text is another matter: its content is unknown, not absent, so it is
/// recorded ([`CandidateFiles::undecodable_maven_poms`]) and the guard
/// refuses the run for it, as for an undecodable root pom.
async fn read_maven_reactor(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    let Some(root) = out.files.get("pom.xml") else {
        return;
    };
    let config = out.files.get(crate::patch::redirect::MVN_CONFIG);
    // A pom that is there but is not UTF-8 text is not a missing module:
    // its content is unknown, so it is recorded like any other undecodable
    // candidate and the run is refused for it (`candidate_file_unreadable`),
    // instead of the reactor being reported as short of a pom it has.
    let undecodable = std::sync::Mutex::new(Vec::new());
    let read = crate::vendor::jvm::maven_reactor::read_reactor(
        view,
        root,
        config.map(String::as_str),
        |rel| {
            let undecodable = &undecodable;
            async move {
                match read_pom_text(view, unreadable, &rel).await {
                    Ok(text) => text,
                    Err(Undecodable) => {
                        undecodable
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(rel);
                        None
                    }
                }
            }
        },
    )
    .await;
    for (rel, text) in read {
        out.files.entry(rel).or_insert(text);
    }
    let mut undecodable = undecodable
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    undecodable.sort();
    out.undecodable_maven_poms = undecodable;
}

/// Hand the pom rewriter the mirrors Maven is configured with on this
/// machine
/// ([`settings_mirror_sets`](crate::crawlers::maven_crawler::settings_mirror_sets)),
/// under [`MAVEN_MIRRORS_KEY`](crate::patch::redirect::MAVEN_MIRRORS_KEY):
/// it adds no repository to a pom that one of them would take over (the
/// gem path's mirror gate, for Maven). On disk only: a memory view has no
/// machine, and so no settings to read.
fn read_maven_mirrors(
    view: &ProjectView<'_>,
    env: &(dyn crate::gradle::Env + Sync),
    out: &mut CandidateFiles,
) {
    if !out.files.contains_key("pom.xml") {
        return;
    }
    let Some(root) = view.disk_root() else {
        return;
    };
    let sets = crate::crawlers::maven_crawler::settings_mirror_sets(
        env,
        crate::gradle::Os::current(),
        None,
        root,
        out.files
            .get(crate::patch::redirect::MVN_CONFIG)
            .map(String::as_str),
    );
    if sets.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string(&sets) {
        out.files
            .insert(crate::patch::redirect::MAVEN_MIRRORS_KEY.to_string(), json);
    }
}

/// An in-memory project's Go files as the hosted engine reads them
/// ([`read_advisory`]: a link or an entry without content is unreadable,
/// but still exists).
struct AdvisoryGoFiles<'v, 'p> {
    view: &'v ProjectView<'p>,
    unreadable: &'v BTreeSet<String>,
}

impl crate::vendor::go_workspace::MemoryFiles for AdvisoryGoFiles<'_, '_> {
    async fn exists(&mut self, rel: &str) -> bool {
        self.unreadable.contains(rel) || self.view.exists_no_follow(rel).await
    }

    async fn read(&mut self, rel: &str) -> Option<String> {
        read_advisory(self.view, self.unreadable, rel).await
    }

    async fn read_sum(&mut self, rel: &str) -> Option<String> {
        read_advisory(self.view, self.unreadable, rel).await
    }

    /// Kept, as the disk loader keeps it: a member that declares the
    /// patched module, or replaces it, is still weighed (refused), never
    /// pinned over.
    fn unparseable(&mut self, _rel: &str, _problem: &str) -> bool {
        true
    }
}

/// The Go workspace in effect for the project, handed to the golang
/// rewriter under [`crate::patch::redirect::GO_WORKSPACE_KEY`]. On disk it is
/// the one go resolves (`GOWORK`, else a go.work at or above the root, with
/// members anywhere, plus a `-modfile` that GOFLAGS sets); in memory a root
/// `go.work` and its in-root members, read as discovery reads them
/// ([`crate::vendor::go_workspace::read_memory`]), whose paths every check
/// compares lexically, never probing the disk or the process's working
/// directory. A root go.work and go.work.sum are candidate files the
/// rewriter writes.
async fn read_go_workspace(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::vendor::go_workspace::{self, Loaded};
    let (root, loaded, modfile, module_graph) = match view {
        ProjectView::Memory(_) => {
            let Some(work) = read_advisory(view, unreadable, "go.work").await else {
                return;
            };
            let work = crate::vendor::go_mod_edit::normalize_for_read(&work);
            // As on disk (`go_workspace::load`): a go.work go cannot parse
            // is a workspace go refuses to build, never module mode.
            let loaded = match crate::vendor::go_mod_edit::block_structure_error(&work) {
                Some(problem) => {
                    Loaded::Invalid(format!("go.work: {problem}, so go refuses to build"))
                }
                None => {
                    let mut files = AdvisoryGoFiles { view, unreadable };
                    Loaded::Workspace(go_workspace::read_memory(&work, &mut files).await.0)
                }
            };
            (std::path::PathBuf::new(), loaded, None, None)
        }
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let Some(root) = view.disk_root_reading(std::iter::empty::<&std::path::Path>()) else {
                return;
            };
            let root = root.to_path_buf();
            let mut loaded = go_workspace::load(&root).await;
            if let Loaded::Workspace(ws) = &mut loaded {
                ws.read_graph().await;
            }
            let mut touched: Vec<std::path::PathBuf> =
                root.ancestors().map(|dir| dir.join("go.work")).collect();
            if let Loaded::Workspace(ws) = &loaded {
                touched.push(ws.work_dir().join("go.work.sum"));
                for member in &ws.members {
                    touched.push(member.dir.join("go.mod"));
                    touched.push(member.dir.join("go.sum"));
                }
            }
            // Module mode: whether a module-to-module replace is in effect
            // can turn on modules only the dependencies require (#1840),
            // and which version the build selects on a go.sum zip line a
            // downgrade may have left behind (#1862).
            let mut module_graph = None;
            if loaded == Loaded::None {
                touched.push(root.join("go.mod"));
                touched.push(root.join("go.sum"));
                let go_mod = crate::utils::fs::read_regular_to_string(&root.join("go.mod")).await;
                let go_sum = crate::utils::fs::read_regular_to_string(&root.join("go.sum"))
                    .await
                    .ok();
                if let Ok(go_mod) = go_mod {
                    let go_mod = crate::vendor::go_mod_edit::normalize_for_read(&go_mod);
                    if crate::vendor::go_build_list::may_need_module_graph(
                        &go_mod,
                        go_sum.as_deref(),
                    ) {
                        touched.extend(
                            crate::vendor::go_build_list::module_graph_reads(&go_mod)
                                .into_iter()
                                .map(|rel| root.join(rel)),
                        );
                        module_graph =
                            Some(crate::vendor::go_build_list::module_graph(&root, &go_mod).await);
                    }
                }
            }
            view.disk_root_reading(&touched);
            // `-modfile` in GOFLAGS sends the build to another go.mod (#1799).
            let modfile = go_workspace::modfile_setting(&root);
            (root, loaded, modfile, module_graph)
        }
    };
    if loaded == Loaded::None && modfile.is_none() && module_graph.is_none() {
        return;
    }
    let hosted = crate::patch::redirect::HostedGoWorkspace {
        root,
        loaded,
        modfile,
        module_graph,
    };
    if let Ok(json) = serde_json::to_string(&hosted) {
        out.files
            .insert(crate::patch::redirect::GO_WORKSPACE_KEY.to_string(), json);
    }
}

/// The files a hosted scan with nothing to redirect still reads, so that
/// the Maven rewriter can heal a `.mvn/maven.config` an earlier release
/// wrote: `None` unless that file holds the Trusted Checksums block in a
/// spelling some project is healed out of
/// ([`crate::formats::maven::trusted_checksums::heal_basedir`]), and then
/// it, the Maven Wrapper's properties and the root pom, which say which
/// spelling this project takes. The line an earlier release wrote stops
/// Maven 3.9.2 to 3.9.8 from starting with `-f` from outside the project
/// whether or not a patch still applies, so a project whose only patched
/// dependency was bumped past the patch must not keep it for ever.
pub async fn read_maven_heal_files(view: &ProjectView<'_>) -> Option<CandidateFiles> {
    use crate::formats::maven::trusted_checksums::holds_written_block;
    use crate::patch::redirect::{MVN_CONFIG, MVN_WRAPPER_PROPERTIES};
    let none = BTreeSet::new();
    let mut out = CandidateFiles::default();
    if !out.read(view, &none, MVN_CONFIG).await {
        return None;
    }
    if !holds_written_block(out.files.get(MVN_CONFIG)?) {
        return None;
    }
    for rel in [MVN_WRAPPER_PROPERTIES, "pom.xml"] {
        out.read(view, &none, rel).await;
    }
    Some(out)
}

/// Read the project's candidate files: [`REDIRECT_CANDIDATE_FILES`], the
/// Cargo workspace members (when a cargo candidate meets a root
/// `Cargo.toml`), the Python locks and their scripts, the Rush locks, and
/// the pnpm workspace members' own locks.
/// `unreadable` are the in-memory paths that exist without content.
pub async fn read_candidate_files(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    candidates: &[Candidate],
) -> CandidateFiles {
    read_candidate_files_in(
        view,
        unreadable,
        candidates,
        &crate::crawlers::gradle_cache::ProcessEnv,
    )
    .await
}

/// [`read_candidate_files`] with the environment the machine's own
/// configuration is looked up through (today: where Maven's settings
/// files are, for the mirror gate). The process environment in
/// production; a test hands in its own, so what a developer keeps in
/// `~/.m2/settings.xml` decides nothing.
pub async fn read_candidate_files_in(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    candidates: &[Candidate],
    env: &(dyn crate::gradle::Env + Sync),
) -> CandidateFiles {
    let mut out = CandidateFiles::default();
    for name in REDIRECT_CANDIDATE_FILES.iter() {
        // The binary lock is read and rewritten directly.
        if *name == "bun.lockb" {
            continue;
        }
        // The hidden lock is only the install-state sentinel, never read.
        if *name == VLT_HIDDEN_LOCK_REL {
            if super::vlt::install_state_present(view) {
                out.files.insert((*name).to_string(), String::new());
            }
            continue;
        }
        if !out.read(view, unreadable, name).await && presence_only_present(view, name) {
            out.files.insert((*name).to_string(), String::new());
        }
    }

    // A yarn berry lock is pinned through the root manifest's `resolutions`
    // (see `patch::redirect::rewrite_yarn_berry`), so beside one the
    // manifest is a rewrite target: read strictly, a link or an unreadable
    // in-memory entry refused like any other file the rewrite writes.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && out
            .files
            .get("yarn.lock")
            .is_some_and(|lock| crate::formats::yarn::is_berry_lock(lock))
    {
        out.read(view, unreadable, "package.json").await;
    // Otherwise the root manifest's `overrides` decide which git / url /
    // `file:` dependent specs npm really installs from (#490), and beside a
    // classic `yarn.lock` its `packageManager` says whether a yarn 2+ install
    // could migrate the lock and drop the hosted pins (#907). The npm lock
    // and yarn classic rewriters read it as advisory input only: no
    // rewriter edits it, so a link or an unreadable in-memory entry is left
    // out (the rewriters then keep their conservative reading) rather than
    // refused. Beside a root `pnpm-lock.yaml` / `shrinkwrap.yaml` pair its
    // `packageManager` pin decides which of the two pnpm reads
    // (`formats::pnpm::plan::planned_locks`), as vendored mode and
    // discovery read it, when no `node_modules/.modules.yaml` records the
    // installed major (a fresh clone).
    } else if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && (NPM_LOCKS.iter().any(|lock| out.files.contains_key(*lock))
            || out.files.contains_key("yarn.lock")
            || ROOT_PNPM_LOCKS
                .iter()
                .all(|lock| out.files.contains_key(*lock)))
    {
        let rel = crate::hosted::memory::select::NPM_MANIFEST_REL;
        if let Some(text) = read_advisory(view, unreadable, rel).await {
            out.files.insert(rel.to_string(), text);
        }
    }

    // A text `bun.lock` names its workspace members; each member's manifest
    // says which `workspace:` literal its inter-workspace dependencies carry,
    // which the bun rewriter restores over a member path a migrated binary
    // lock left behind (#803). Advisory input like the npm manifest above:
    // keyed `<dir>/package.json` (the root as `package.json`), never
    // rewritten, and a member dir that is not a plain relative path is
    // never read.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        if let Some(lock) = out.files.get("bun.lock") {
            let lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
            for dir in crate::vendor::bun_lock_text::workspace_member_dirs(&lines) {
                if !crate::vendor::bun_lock_text::is_plain_member_dir(&dir) {
                    continue;
                }
                let rel = if dir.is_empty() {
                    "package.json".to_string()
                } else {
                    format!("{dir}/package.json")
                };
                if out.files.contains_key(&rel) {
                    continue;
                }
                if let Some(text) = read_advisory(view, unreadable, &rel).await {
                    out.files.insert(rel, text);
                }
            }
        }
        // The root manifest's `patchedDependencies` names the packages the
        // project patches itself with `bun patch`, which the bun rewriters
        // must leave on their registry tuple (#367). Read beside either bun
        // lock, advisory too: the member walk above reaches the root only
        // through a `workspaces` section in bun's emitted shape.
        if !out.files.contains_key("package.json")
            && (out.files.contains_key("bun.lock") || super::vlt::bun_lockb_present(view))
        {
            if let Some(text) = read_advisory(view, unreadable, "package.json").await {
                out.files.insert("package.json".to_string(), text);
            }
        }
    }

    // Beside a classic yarn.lock, the yarn configs decide whether an
    // offline mirror serves the tarballs (the classic rewriter's refusal).
    // Read strictly: a link or an unreadable in-memory entry could hide a
    // mirror, so it is refused like a rewrite target.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && out
            .files
            .get("yarn.lock")
            .is_some_and(|lock| !crate::formats::yarn::is_berry_lock(lock))
    {
        out.read(view, unreadable, crate::patch::redirect::YARNRC_REL)
            .await;
        out.read(view, unreadable, NPMRC_REL).await;
        // A `file:` directory copy is locked under the DEPENDENCY name, so
        // the classic rewriter reads which package it is from the
        // directory's `package.json` (#1236), at the path vendored and VEX
        // read it from (#1951): outside the root too, never at an absolute
        // path. Advisory: never rewritten, and an unreadable one only
        // leaves that copy unnamed.
        let manifests: BTreeSet<String> = out
            .files
            .get("yarn.lock")
            .map(|lock| {
                use crate::formats::yarn::copy::{classic_copy_ref, CopyRef};
                crate::vendor::lock_inventory::yarn::classic_entries(lock)
                    .iter()
                    .filter_map(|e| match classic_copy_ref(&e.patterns, None)? {
                        copy @ CopyRef::Directory(_) => copy.read_path(),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for rel in manifests {
            if out.files.contains_key(&rel) {
                continue;
            }
            if let Some(text) = read_advisory(view, unreadable, &rel).await {
                out.files.insert(rel, text);
            }
        }
    }

    // Cargo workspace members (and in-root path dependencies) declare
    // dependencies of their own: a member's direct `cfg-if = "1"` must be
    // pinned alongside the root's, or the redirected lock entry is
    // unsatisfiable. Keyed `<dir>/Cargo.toml` for the cargo rewriter.
    let cargo = candidates.iter().any(|c| c.dep.ecosystem == "cargo");
    if out.files.contains_key("Cargo.toml") && cargo {
        for rel in crate::utils::cargo_workspace::member_manifests_in(view).await {
            out.read(view, unreadable, &rel).await;
        }
    }
    // In a Bazel workspace on disk a rules_rust hub may run cargo over
    // these files without the cargo config that defines the registry of a
    // pin. What stands against a pin is read from the checkout here and
    // rides a synthetic key to the cargo rewriter. A project in no Bazel
    // workspace, or one that no such hub is seen to read, gets none, and
    // its run is the one it was.
    if let Some(root) = view.disk_root().filter(|_| cargo) {
        use crate::bazel::cargo::{unread, KEY};
        let member = |rel: &&String| crate::patch::redirect::is_cargo_member_manifest_key(rel);
        let mut files = vec!["Cargo.lock".to_string(), "Cargo.toml".to_string()];
        files.extend(out.files.keys().filter(member).cloned());
        let config = crate::patch::redirect::cargo_config_key(&out.files);
        let root = root.to_path_buf();
        let read = crate::utils::fs::run_blocking(move || unread(&root, &files, config));
        out.files
            .extend(read.await.map(|why| (KEY.to_string(), why)));
    }

    // Go: the workspace in effect decides which version a replace must pin,
    // whether it takes effect at all, and whether it belongs in go.work.
    if candidates.iter().any(|c| c.dep.ecosystem == "golang") {
        read_go_workspace(view, unreadable, &mut out).await;
    }

    // Every pom of a Maven reactor (the modules the root lists, theirs in
    // turn, each parent pom one inherits from inside the checkout, and the
    // subprojects Maven 4 discovers, #1809): the rewriter pins a patch in
    // the poms of the modules that select it.
    if candidates.iter().any(|c| c.dep.ecosystem == "maven") {
        read_maven_reactor(view, unreadable, &mut out).await;
        read_maven_mirrors(view, env, &mut out);
    }

    // NuGet merges the user config and every parent directory's config
    // under the project's own: a catch-all mapping the rewriter creates
    // must name their sources too (#354). Disk only (the in-memory engine
    // refuses NuGet, and could not see them).
    if candidates.iter().any(|c| c.dep.ecosystem == "nuget")
        && !matches!(view, ProjectView::Memory(_))
    {
        // The configs live outside the project: read beside the view, then
        // handed to it as such reads (asking for its raw root would end a
        // re-scan read cache's recording).
        if let Some(root) = view.disk_root_reading(std::iter::empty::<&str>()) {
            let (inherited, touched) =
                crate::vendor::nuget_config::inherited_source_keys_traced(root).await;
            view.disk_root_reading(&touched);
            out.files.insert(
                crate::patch::redirect::NUGET_INHERITED_SOURCES_KEY.to_string(),
                inherited.keys.join("\n"),
            );
            if inherited.mapped {
                out.files.insert(
                    crate::patch::redirect::NUGET_INHERITED_MAPPING_KEY.to_string(),
                    String::new(),
                );
            }
            if let Some(why) = inherited.outside_refusal() {
                out.files.insert(
                    crate::patch::redirect::NUGET_INHERITED_OUTSIDE_KEY.to_string(),
                    why,
                );
            }
        }
    }

    // NuGet: the root config routes every project under the root, so each
    // project's lock is pinned with it (#353, #514). The walk's answer rides
    // a synthetic key (the lock paths, an unevaluable NuGetLockFilePath, or
    // why the tree could not be listed) and every lock is read. The project
    // files themselves stay out of the candidate texts. NuGet is disk-only
    // (the in-memory engine refuses it).
    if candidates.iter().any(|c| c.dep.ecosystem == "nuget")
        && !matches!(view, ProjectView::Memory(_))
    {
        let mut lines: Vec<String> = Vec::new();
        match crate::vendor::nuget_config::governed_locks_in(view).await {
            Ok(governed) => {
                for (project, detail) in &governed.unresolved {
                    lines.push(format!("unresolved\t{project}\t{detail}"));
                }
                for rel in governed.locks {
                    if !out.files.contains_key(&rel) {
                        out.read(view, unreadable, &rel).await;
                    }
                    lines.push(format!("lock\t{rel}"));
                }
            }
            Err(why) => lines.push(format!("error\t{why}")),
        }
        out.files.insert(
            crate::patch::redirect::NUGET_LOCKS_KEY.to_string(),
            lines.join("\n"),
        );
        // In a Bazel workspace a rules_csharp hub reads those locks, with
        // the locks of its other tags, and takes its package sources from
        // the config the rewriter writes only when a tag names it. What
        // the hub makes of the project is read from the checkout here and
        // rides a synthetic key, for the rewriter to judge each package.
        // A project in no Bazel workspace, or whose locks no tag reads,
        // gets none, and its run is the one it was. The root is the raw
        // one: which files of the workspace this reads is not known
        // beforehand, so a recording gives up instead of listing them.
        if let Some(root) = view.disk_root() {
            use crate::bazel::nuget::{withheld, WITHHELD_KEY};
            let config = crate::patch::redirect::nuget_config_path(&out.files);
            let locks = lines.iter().filter_map(|line| line.strip_prefix("lock\t"));
            let locks: Vec<String> = locks.map(String::from).collect();
            let root = root.to_path_buf();
            let read = move || withheld(&root, config, &locks);
            let read = crate::utils::fs::run_blocking(read).await;
            out.files
                .extend(read.map(|hub| (WITHHELD_KEY.to_string(), hub)));
        }
    }

    for path in view.python_lock_paths() {
        if let Some(script) = crate::utils::python_lock::script_of_lock(&path) {
            out.read(view, unreadable, script).await;
        }
        out.read(view, unreadable, &path).await;
    }

    // Beside a uv project or script lock, the project's `uv.toml` may set
    // `no-sources`, under which uv ignores the `[tool.uv.sources]` entry the
    // rewrite would add (#564), or `no-binary`, under which uv refuses the
    // patched wheel (#1603). Advisory: never rewritten, so a link or an
    // unreadable in-memory entry is left out rather than refused.
    let uv_lane = out
        .files
        .keys()
        .any(|path| path == "uv.lock" || crate::utils::python_lock::is_script_lock_name(path));
    // A PEP 751 lock is installed with `uv pip`, which refuses the patched
    // wheel under the `no-binary` settings of the root's `uv.toml` (#1603).
    let pylock_lane = out
        .files
        .keys()
        .any(|path| crate::utils::python_lock::is_pep751_lock_name(path));
    if uv_lane || pylock_lane {
        let rel = crate::utils::python_script::UV_TOML;
        if let Some(text) = read_advisory(view, unreadable, rel).await {
            out.files.insert(rel.to_string(), text);
        }
    }
    // A PEP 723 script (#1501), a project (#1545) or `uv pip` installing a
    // PEP 751 lock (#1603) also takes uv's settings from above the root
    // when the root holds none; only a disk view has an above.
    if (uv_lane || pylock_lane)
        && !crate::utils::python_script::root_governs_script(
            out.files.get("pyproject.toml").map(String::as_str),
            out.files
                .get(crate::utils::python_script::UV_TOML)
                .map(String::as_str),
        )
    {
        let files = view
            .disk_root_reading(std::iter::empty::<&std::path::Path>())
            .map(crate::utils::python_script::ancestor_uv_config_files)
            .unwrap_or_default();
        if let Some(config) = view
            .disk_root_reading(files.iter().map(|(_, path)| path))
            .and_then(crate::utils::python_script::find_ancestor_uv_config)
        {
            out.files.insert(
                crate::patch::redirect::UV_ANCESTOR_CONFIG_KEY.to_string(),
                format!("{}\n{}", config.rel, config.text),
            );
        } else if let Some(why) = view
            .disk_root_reading(std::iter::empty::<&std::path::Path>())
            .and_then(|root| crate::utils::python_script::uv_config_above_repo(root, None))
        {
            out.files.insert(
                crate::patch::redirect::UV_ANCESTOR_OUTSIDE_KEY.to_string(),
                why,
            );
        }
    }

    // Rush monorepos have no root package.json/lock pair: the single pnpm
    // source-of-truth lock lives at common/config/rush/pnpm-lock.yaml, and
    // (when subspaces are enabled) one lock per subspace under
    // common/config/subspaces/<name>/. Added under their repo-relative
    // keys — the pnpm rewriter is basename-generalized, so nested keys are
    // rewritten in place, and the write-back is path-generic.
    // The gate and the lock list are the ones lockfile discovery and the
    // lock inventory use: sorted by name, real directories only (a
    // symlinked `common/...` dir could point the write at another
    // repository), traversal-safe subspace names.
    if is_rush(*view).await {
        for key in rush_lock_rels(*view).await {
            if out.read(view, unreadable, &key).await {
                out.rush_lock_keys.push(key);
            }
        }
    } else if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        // Only a pnpm project (a root pnpm lock, or a pnpm-workspace.yaml)
        // is refused for pnpm's `lockfile` setting: an npm, yarn or bun
        // project keeps its own hints.
        let pnpm_lock = ROOT_PNPM_LOCKS.iter().any(|lock| {
            out.files.contains_key(*lock)
                || out.symlinked_reads.iter().any(|r| r == lock)
                || out.unreadable_reads.iter().any(|r| r == lock)
        });
        let pnpm_project = pnpm_lock || view.read_text(PNPM_WORKSPACE_REL).await.is_ok();
        let disabled = match pnpm_project {
            true => crate::utils::pnpm_workspace::lockfile_disabled(view, true).await,
            false => None,
        };
        if let Some(source) = disabled {
            withhold_root_pnpm_locks(&mut out, disabled_lockfile_refusal(&source, pnpm_lock));
        } else if let Some(branch) = crate::utils::pnpm_workspace::git_branch_locks(view).await {
            refuse_git_branch_locks(&mut out, &branch);
        } else {
            // A hub stands against a pin in the root lock it reads, not
            // against the members' own locks, which no hub of this answer
            // reads: they are read and pinned as without it.
            let root = out.files.contains_key(ROOT_PNPM_LOCKS[0]);
            read_pnpm_member_locks(view, unreadable, &mut out).await;
            read_pnpm_bazel(view, root, &mut out).await;
        }
    } else {
        read_pnpm_route_locks(view, unreadable, &mut out).await;
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "gem") {
        keep_bundler_loaded_gem_files(view, candidates, &mut out).await;
        read_gemspecs(view, unreadable, &mut out).await;
        // In a Bazel workspace a rules_ruby hub can hold a gem of the lock
        // to a sha256 of its own (`gem_checksums`), which a redirect leaves
        // on the upstream archive. What the calls that may read the lock
        // hold is read here and rides a synthetic key to the gem rewriter:
        // from the checkout on disk, and in memory from the files handed
        // over, where the project's directory is the Bazel root. A project
        // in no Bazel workspace, or whose lock no such call may read, gets
        // none, and its run is the one it was.
        let (_, lock) = crate::patch::redirect::gem_pair(&out.files);
        if out.files.contains_key(lock) {
            use crate::bazel::ruby::{handed, handed_on_disk, KEY};
            use crate::bazel::workspace::Entry;
            use crate::vendor::lock_inventory::MemoryEntry;
            let held = match view {
                ProjectView::Memory(project) => {
                    let file = |path: &str| match project.get(path) {
                        Some(MemoryEntry::Text(text)) => Entry::Text(text.to_string()),
                        None => Entry::Absent,
                        Some(_) => Entry::Unreadable("it was not handed over as text".into()),
                    };
                    handed(&file, lock)
                }
                _ => {
                    let root = view.disk_root().expect("a disk view has a root");
                    let root = root.to_path_buf();
                    crate::utils::fs::run_blocking(move || handed_on_disk(&root, lock)).await
                }
            };
            out.files.extend(held.map(|held| (KEY.to_string(), held)));
        }
    }
    // A Gradle build: every script, catalog and lock file its script graph
    // reaches, for the hosted Gradle planner.
    if candidates.iter().any(|c| c.dep.ecosystem == "maven")
        && crate::patch::redirect::gradle::gradle_build_present(&out.files)
    {
        read_gradle_files(view, unreadable, &mut out).await;
        // The Gradle planner refuses a build over a file it cannot read as
        // text and the scan carries on, so such a file is not a reason to
        // refuse the whole run (#721).
        let gradle_unreadable = &out.gradle_unreadable;
        out.undecodable_reads
            .retain(|rel| !gradle_unreadable.contains(rel));
    } else {
        // No readable Gradle build: the Gradle planner never runs, so a
        // stray Gradle file it would own (a lock, a nested script) is never
        // rewritten and must not refuse the rest of the run. A root build
        // or settings script still refuses: it may be the build itself,
        // unreadable, which the planner would otherwise skip silently.
        out.undecodable_reads.retain(|rel| {
            !is_gradle_owned_file(rel)
                || crate::vendor::jvm::layout::GRADLE_ROOT_FILES.contains(&rel.as_str())
        });
    }
    // In a Bazel workspace on disk a rules_jvm_external hub builds the jar
    // its lock pins. What a run may write for such a jar is read from the
    // checkout here and rides a synthetic key, with the root `MODULE.bazel`
    // beside it, which is where the hub lane writes. A project that is in
    // no Bazel workspace, or whose hubs build none of the candidates, gets
    // neither, and its run is the one it was.
    let patches = candidates.iter().map(|c| (c.purl.as_str(), &c.dep));
    let jars = crate::bazel::maven::jars(patches);
    if let Some(root) = view.disk_root().filter(|_| !jars.is_empty()) {
        use crate::bazel::maven::{site, FILE, SITE_KEY};
        let (root, module) = (root.to_path_buf(), view.read_text(FILE).await.ok());
        let (read, module) =
            crate::utils::fs::run_blocking(move || (site(&root, module.as_deref(), &jars), module))
                .await;
        if !read.is_empty() {
            out.files
                .extend(module.map(|module| (FILE.to_string(), module)));
            let read = serde_json::to_string(&read).expect("a map of strings is JSON");
            out.files.insert(SITE_KEY.to_string(), read);
        }
    }
    // An sbt build's resolution evidence rides a synthetic key (see
    // `patch::redirect::sbt::SBT_RESOLUTION_KEY`).
    if candidates.iter().any(|c| c.dep.ecosystem == "maven")
        && crate::formats::sbt::build::sbt_build_present(&crate::formats::sbt::build::files_reader(
            &out.files,
        ))
    {
        if let Some(json) = super::sbt_reads::extra_resolution(view).await {
            let key = crate::patch::redirect::sbt::SBT_RESOLUTION_KEY;
            out.files.insert(key.to_string(), json);
        }
    }
    out.symlinked_reads.sort();
    out.symlinked_reads.dedup();
    out.unreadable_reads.sort();
    out.unreadable_reads.dedup();
    out.undecodable_reads.sort();
    out.undecodable_reads.dedup();
    out
}

/// A pnpm workspace with `sharedWorkspaceLockfile: false` installs each
/// member from the member's own `pnpm-lock.yaml`; the root lock covers the
/// root project alone (pnpm 7 writes none at all). Every member lock is a
/// rewrite target, read strictly under its root-relative key: the pnpm
/// rewriter is basename-generalized and the write-back path-generic, like
/// the Rush locks above. Members whose list cannot be read leave the root
/// lock out too and refuse (see [`CandidateFiles::pnpm_refusal`]).
/// In memory too: the in-memory engine demotes each member lock into its
/// workspace root once that root's files confirm it reads them
/// (`confirm_pnpm_members` in [`super::memory`]),
/// so the root reads them here as a disk run from it does; a member lock
/// whose content was not provided refuses the project like an unreadable
/// root lock.
async fn read_pnpm_member_locks(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    let listing = crate::utils::pnpm_workspace::member_locks(view).await;
    take_pnpm_member_locks(view, unreadable, out, listing).await;
}

/// [`read_pnpm_member_locks`] for members that were listed already
/// (`listing`): the listing globs the workspace, and a run does it once.
async fn take_pnpm_member_locks(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
    listing: crate::utils::pnpm_workspace::MemberLocks,
) {
    use crate::utils::pnpm_workspace::MemberLocks;
    match listing {
        MemberLocks::Shared => {}
        MemberLocks::PerMember(keys) => {
            for key in keys {
                if out.read(view, unreadable, &key).await {
                    out.pnpm_member_lock_keys.push(key);
                    continue;
                }
                // A member lock that exists but cannot be read (a FIFO, not
                // UTF-8) still drives that member's install: pinning the
                // others would confirm the dep while it stays upstream there.
                for read in std::mem::take(&mut out.pnpm_member_lock_keys) {
                    out.files.remove(&read);
                }
                refuse_pnpm_members(
                    out,
                    format!(
                        "{key} (a workspace member's own lock under \
                         sharedWorkspaceLockfile: false) cannot be read as text"
                    ),
                );
                return;
            }
        }
        MemberLocks::Unresolved(why) => refuse_pnpm_members(out, why),
    }
}

/// For a run with no npm patch: the members' own locks and what Bazel says
/// of the pnpm locks, read as a run with a patch reads them, when the
/// project holds something of a registry route ([`pnpm_route`]). Such a
/// run still tidies what is left of a route ([`pnpm_prune`]), and every
/// lock the workspace file governs has a say in what is left. And a root
/// lock that a run with a patch leaves to a Bazel hub is not rewritten by
/// one without, so what a scan does to the files does not turn on what it
/// was granted.
///
/// Something of a route is an entry of ours in the root
/// pnpm-workspace.yaml, or a lock that keys a release by a registry of
/// ours or records an override of ours: the root lock or, in a workspace
/// that keeps one lock per member, a member's own, which can be the only
/// file that still holds any of it. Read from the bytes alone, with every
/// address of the registry's shape taken for a patch server's; what is
/// ours is settled when the route is. A project that holds none is read
/// no further, and no Bazel file is read for it.
///
/// The members are listed once, for the question and for the read, and a
/// lock is parsed only when its bytes name a route.
async fn read_pnpm_route_locks(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::formats::pnpm::named_registries::{holds_ours, Owned};
    use crate::formats::pnpm::registry_alias::holds_route;
    use crate::utils::pnpm_workspace::{member_locks, MemberLocks};

    let workspace = view.read_text(PNPM_WORKSPACE_REL).await.ok();
    let owned = Owned::of(workspace.as_deref(), &|_| true);
    let root = out.files.get(ROOT_PNPM_LOCKS[0]);
    let in_root = workspace
        .as_deref()
        .is_some_and(|text| holds_ours(text, &owned))
        || root.is_some_and(|lock| holds_route(lock, &owned));
    // Without a workspace file there are no members to list.
    let listing = match workspace {
        Some(_) => member_locks(view).await,
        None => MemberLocks::Shared,
    };
    if !in_root && !member_lock_holds_route(view, &listing, &owned).await {
        return;
    }
    let root = root.is_some();
    take_pnpm_member_locks(view, unreadable, out, listing).await;
    read_pnpm_bazel(view, root, out).await;
}

/// Whether a member's own lock of `listing` holds something of a registry
/// route. Members that cannot be listed name none: only a project whose
/// root files hold a route is told that its member locks could not be
/// read.
async fn member_lock_holds_route(
    view: &ProjectView<'_>,
    listing: &crate::utils::pnpm_workspace::MemberLocks,
    owned: &crate::formats::pnpm::named_registries::Owned,
) -> bool {
    use crate::formats::pnpm::registry_alias::holds_route;
    use crate::utils::pnpm_workspace::MemberLocks;

    let MemberLocks::PerMember(keys) = listing else {
        return false;
    };
    for key in keys {
        if view
            .read_text(key)
            .await
            .is_ok_and(|lock| holds_route(&lock, owned))
        {
            return true;
        }
    }
    false
}

/// Leave the root pnpm lock out and record why (see
/// [`CandidateFiles::pnpm_refusal`]).
fn refuse_pnpm_members(out: &mut CandidateFiles, why: String) {
    out.files.remove("pnpm-lock.yaml");
    out.pnpm_refusal = Some(RewriteWarning {
        code: PNPM_MEMBER_LOCKS_UNRESOLVED.into(),
        detail: format!(
            "{why}; no pnpm lock was rewritten — make every member lock a readable \
             file listed by plain `packages:` globs (or install the members) and re-run"
        ),
    });
}

/// `gitBranchLockfile` with a branch lock present (#556): pnpm installs
/// the branch from that lock, which hosted mode cannot pin, so the root
/// lock (stale on the branch) is left out and the run refuses every pnpm
/// pin (see [`CandidateFiles::pnpm_refusal`]).
fn refuse_git_branch_locks(
    out: &mut CandidateFiles,
    branch: &crate::utils::pnpm_workspace::GitBranchLocks,
) {
    withhold_root_pnpm_locks(out, git_branch_lock_refusal(branch));
}

/// Ask the Bazel workspace of the project about its pnpm locks, once
/// ([`CandidateFiles::pnpm_bazel`]): the root lock (`root`: whether
/// `pnpm-lock.yaml` was read, before the members' locks were) and the
/// members' own.
///
/// Where a rules_js hub keeps the root lock up to date with a pnpm that
/// would not read the `trustLockfile: true` a hosted pin needs
/// ([`crate::bazel::pnpm::Hubs::hidden`]), the build would fail on the
/// pinned lock: the root locks are left out and the run refuses every pin
/// in them (see [`withhold_root_pnpm_locks`]). That answer is about a pin
/// in the root lock, so a project without that lock gets none. Nothing of
/// Bazel is read for a project with no pnpm lock at all.
async fn read_pnpm_bazel(view: &ProjectView<'_>, root: bool, out: &mut CandidateFiles) {
    if !root && out.pnpm_member_lock_keys.is_empty() {
        return;
    }
    let mut locks = vec![ROOT_PNPM_LOCKS[0].to_string()];
    locks.extend(out.pnpm_member_lock_keys.iter().cloned());
    let mut hubs = crate::bazel::pnpm::hubs(view, &locks).await;
    if !root {
        hubs.hidden = None;
    }
    if let Some(hidden) = hubs.hidden.clone() {
        withhold_root_pnpm_locks(out, hidden);
    }
    out.pnpm_bazel = hubs;
}

/// The root pnpm locks (see [`withhold_root_pnpm_locks`]).
const ROOT_PNPM_LOCKS: [&str; 2] = ["pnpm-lock.yaml", "shrinkwrap.yaml"];

/// Leave every root pnpm lock out of the run and refuse every pnpm pin
/// with `refusal` (see [`CandidateFiles::pnpm_refusal`]): a branch lock
/// (#556), pnpm's `lockfile` setting off (#1074, where pnpm reads no
/// lock at all; member locks are never read then), or a Bazel hub that
/// would fail on a pin in the root lock ([`read_pnpm_bazel`];
/// the members' own locks are read all the same). In memory the root
/// lock is dropped from the link and unreadable lists too: it is not
/// written.
fn withhold_root_pnpm_locks(out: &mut CandidateFiles, refusal: RewriteWarning) {
    for lock in ROOT_PNPM_LOCKS {
        out.files.remove(lock);
    }
    out.symlinked_reads
        .retain(|r| !ROOT_PNPM_LOCKS.contains(&r.as_str()));
    out.unreadable_reads
        .retain(|r| !ROOT_PNPM_LOCKS.contains(&r.as_str()));
    out.pnpm_refusal = Some(refusal);
}

/// The [`PNPM_LOCKFILE_DISABLED`] warning for a `lockfile` setting turned
/// off at `source` (see [`crate::utils::pnpm_workspace::lockfile_disabled`]).
/// Vendored mode is named only when a pnpm lock exists: its pnpm backend
/// wires the lock it finds (pnpm then applies the `overrides` without
/// reading it) and refuses a project with none.
fn disabled_lockfile_refusal(source: &str, pnpm_lock: bool) -> RewriteWarning {
    let remedy = if pnpm_lock {
        "use `--mode vendored` (pnpm applies the `overrides` it wires without a lock), \
         or remove the setting, run `pnpm install` and re-run"
    } else {
        "remove the setting, run `pnpm install` so pnpm writes pnpm-lock.yaml, and re-run"
    };
    RewriteWarning {
        code: PNPM_LOCKFILE_DISABLED.into(),
        detail: format!(
            "{}; no pnpm lock was rewritten — {remedy}",
            crate::utils::pnpm_workspace::describe_lockfile_disabled(source)
        ),
    }
}

/// Refusal code for a project whose pnpm `lockfile` setting is off, so
/// pnpm never reads the lock a hosted pin goes into (#1074).
pub const PNPM_LOCKFILE_DISABLED: &str = "redirect_pnpm_lockfile_disabled";

/// The [`PNPM_GIT_BRANCH_LOCKFILE`] warning for `branch`: the hosted
/// rewrite's, and the vendored→hosted takeover's (which keeps the vendored
/// wiring rather than revert it into a lock pnpm does not install from).
pub fn git_branch_lock_refusal(
    branch: &crate::utils::pnpm_workspace::GitBranchLocks,
) -> RewriteWarning {
    RewriteWarning {
        code: PNPM_GIT_BRANCH_LOCKFILE.into(),
        detail: format!(
            "{}; no pnpm lock was rewritten — {}",
            branch.describe(),
            crate::utils::pnpm_workspace::GitBranchLocks::REMEDY
        ),
    }
}

/// Refusal code for a `sharedWorkspaceLockfile: false` workspace whose
/// member locks cannot be listed.
pub const PNPM_MEMBER_LOCKS_UNRESOLVED: &str = "redirect_pnpm_member_locks_unresolved";

/// Refusal code for a project whose `gitBranchLockfile` setting makes pnpm
/// install from a `pnpm-lock.<branch>.yaml` (#556).
pub const PNPM_GIT_BRANCH_LOCKFILE: &str = "redirect_pnpm_git_branch_lockfile";

/// Read what the hosted Gradle planner needs into `out` (see
/// [`crate::patch::redirect::gradle::GradleFiles`]): the script graph is
/// re-walked over what was read so far until it asks for nothing new
/// (bounded by its own caps and [`MAX_ROUNDS`] rounds). A missing file is
/// absent to the graph, which records it as unresolved; one that exists
/// but cannot be read as text is absent to the graph too, and listed in
/// [`CandidateFiles::gradle_unreadable`] so the planner refuses the build;
/// a directory that cannot be listed lists as empty.
///
/// [`MAX_ROUNDS`]: crate::patch::redirect::gradle::MAX_ROUNDS
async fn read_gradle_files(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::patch::redirect::gradle::{GradleFiles, MAX_ROUNDS};
    let mut gradle = GradleFiles::default();
    for (rel, text) in &out.files {
        gradle.found(rel, text.clone());
    }
    for _ in 0..MAX_ROUNDS {
        let (reads, lists) = gradle.misses();
        if reads.is_empty() && lists.is_empty() {
            break;
        }
        for rel in reads {
            match read_gradle_file(view, unreadable, out, &rel).await {
                Some(text) => gradle.found(&rel, text),
                None => gradle.absent(&rel),
            }
        }
        for dir in lists {
            let children = view
                .list_dir(&dir)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| {
                            if e.is_dir {
                                format!("{}/", e.name)
                            } else {
                                e.name
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            gradle.listed(&dir, children);
        }
    }
}

/// Read one Gradle file into `out` for [`read_gradle_files`]: its text, or
/// `None` when it is missing or cannot be read — in which case a file that
/// exists (permissions, non-UTF-8 bytes, not a regular file, content not
/// provided in memory) is recorded in `gradle_unreadable`.
async fn read_gradle_file(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
    rel: &str,
) -> Option<String> {
    let exists = match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => match view.read_text(rel).await {
            Ok(text) => {
                out.files.insert(rel.to_string(), text.clone());
                return Some(text);
            }
            Err(e) => !crate::patch::redirect::gradle::is_absent_error(&e),
        },
        ProjectView::Memory(project) => {
            if out.read(view, unreadable, rel).await {
                return out.files.get(rel).cloned();
            }
            project.get(rel).is_some()
        }
    };
    if exists {
        out.gradle_unreadable.insert(rel.to_string());
    }
    None
}

/// The Bundler manifest/lock spellings among the candidate files.
const GEM_MANIFEST_FILES: [&str; 4] = ["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"];

/// Leave only the gem manifest pair bundler loads in the candidate set
/// (see [`crate::formats::gem::manifest`]). The gem rewriter picks between
/// the two default spellings by filename alone; this narrows what it sees
/// to bundler's own choice, so it can never wire a manifest bundler
/// ignores:
///
/// - no `BUNDLE_GEMFILE`: unchanged for a lone `Gemfile` or `gems.rb`; a
///   `Gemfile` + `gems.rb` twin is withheld, since bundler 1.x loads the
///   `Gemfile`, >= 2 loads `gems.rb`, and nothing says which runs
///   ([`manifest::twin_manifest_refusal`](crate::formats::gem::manifest::twin_manifest_refusal));
/// - `BUNDLE_GEMFILE` naming the root `Gemfile` / `gems.rb`: the other
///   spelling is dropped;
/// - `BUNDLE_GEMFILE` naming anything else, or bundler 4's
///   `BUNDLE_LOCKFILE` naming a lock other than the pair's own: every
///   spelling is dropped and [`CandidateFiles::gem_refusal`] says why;
/// - a bundler mirror capturing the patch-registry source (`mirror.all`,
///   or `mirror.<source>`; see [`crate::formats::gem::mirror`]): every
///   spelling is dropped the same way (#681).
///
/// A memory view has no environment: only its own app config is read.
async fn keep_bundler_loaded_gem_files(
    view: &ProjectView<'_>,
    candidates: &[Candidate],
    out: &mut CandidateFiles,
) {
    use crate::formats::gem::manifest::{self, LoadedManifest};
    let sources: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c.dep.registry_override.as_ref())
        .filter(|ov| ov.kind == "rubygems-compact-index")
        .map(|ov| ov.index_url.as_str())
        .collect();
    let loaded = crate::crawlers::ruby_crawler::bundler_loaded_manifest_in(view).await;
    let mirror = match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let root = view.disk_root().expect("a disk view has a root");
            crate::crawlers::ruby_crawler::bundler_source_mirror(root, &sources).await
        }
        ProjectView::Memory(_) => {
            let config = view.read_text(".bundle/config").await.ok();
            crate::formats::gem::mirror::capturing_mirror(config.as_deref(), &[], &sources)
        }
    };
    let refusal = if let Some(detail) = loaded.unsupported_detail() {
        let code = match &loaded {
            LoadedManifest::UnsupportedLockfile { .. } => {
                "redirect_gem_bundle_lockfile_unsupported"
            }
            _ => "redirect_gem_bundle_gemfile_unsupported",
        };
        Some(RewriteWarning {
            code: code.into(),
            detail,
        })
    } else {
        // #681: a mirror serves the upstream gem for the redirected source,
        // so bundler would install unpatched bytes while the run (and its
        // VEX) reported the gem redirected. Refuse every gem redirect.
        mirror.map(|capture| RewriteWarning {
            code: "redirect_gem_mirror_overrides_source".into(),
            detail: format!(
                "{} routes the Socket patch-registry source to that mirror, which serves \
                 the unpatched upstream gem; no gem was redirected. To fix, {} and re-run \
                 the scan",
                capture.setting, capture.remedy
            ),
        })
    };
    // A spelling bundler sees (`File.file?`) even when this run couldn't
    // read it: a symlink, an unreadable or a non-UTF-8 file still makes the
    // project a twin, as lock inventory (`view.is_file`) already counts it.
    let present = |rel: &str| {
        out.files.contains_key(rel)
            || view.is_file(rel)
            || out.symlinked_reads.iter().any(|r| r == rel)
            || out.unreadable_reads.iter().any(|r| r == rel)
            || out.undecodable_reads.iter().any(|r| r == rel)
    };
    let is_twin = present("gems.rb") && present("Gemfile");
    let mut twin_ambiguous = None;
    let keep: &[&str] = match (&loaded, &refusal) {
        (_, Some(_))
        | (LoadedManifest::Unsupported { .. } | LoadedManifest::UnsupportedLockfile { .. }, _) => {
            &[]
        }
        // Default discovery of a twin: bundler 1.x loads the `Gemfile`
        // and >= 2 loads `gems.rb`, and nothing here says which runs, so
        // neither pair is wired (#751).
        (LoadedManifest::Default, None) if is_twin => {
            twin_ambiguous = Some(manifest::twin_manifest_refusal());
            &[]
        }
        (LoadedManifest::Default, None) => return,
        (LoadedManifest::Configured { .. }, None) => {
            let (gemfile, lock) = loaded
                .pair(out.files.contains_key("gems.rb"))
                .expect("a configured default spelling has a pair");
            &[gemfile, lock]
        }
    };
    let dropped = |rel: &str| GEM_MANIFEST_FILES.contains(&rel) && !keep.contains(&rel);
    out.files.retain(|rel, _| !dropped(rel));
    out.symlinked_reads.retain(|rel| !dropped(rel));
    out.unreadable_reads.retain(|rel| !dropped(rel));
    out.undecodable_reads.retain(|rel| !dropped(rel));
    out.gem_refusal = refusal.or(twin_ambiguous.map(|detail| RewriteWarning {
        code: "redirect_gem_twin_manifest_ambiguous".into(),
        detail,
    }));
}

/// The gemspecs the Gemfile's `gemspec` directives load: bundler 2.7+
/// folds their development dependencies into the requirement the lock
/// pins (#985). Advisory: never rewritten, carried in the
/// [`GEMSPECS_KEY`](crate::formats::gem::gemspec::GEMSPECS_KEY) entry. A
/// directive the rewriter cannot read is left for it to report.
async fn read_gemspecs(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::formats::gem::gemspec::{gemspec_directives, is_gemspec_file, GEMSPECS_KEY};
    let Some(gemfile) = ["gems.rb", "Gemfile"]
        .iter()
        .find_map(|rel| out.files.get(*rel))
    else {
        return;
    };
    let dirs: BTreeSet<String> = gemspec_directives(gemfile)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.dir)
        .collect();
    if dirs.is_empty() {
        return;
    }
    let mut listing = serde_json::Map::new();
    for dir in dirs {
        let entries = match view.list_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) => {
                listing.insert(dir, serde_json::Value::String(e.to_string()));
                continue;
            }
        };
        let mut specs = serde_json::Map::new();
        for entry in entries
            .into_iter()
            .filter(|e| !e.is_dir && is_gemspec_file(&e.name))
        {
            let rel = if dir.is_empty() {
                entry.name.clone()
            } else {
                format!("{dir}/{}", entry.name)
            };
            let text = read_advisory(view, unreadable, &rel).await;
            specs.insert(
                entry.name,
                text.map_or(serde_json::Value::Null, serde_json::Value::String),
            );
        }
        listing.insert(dir, serde_json::Value::Object(specs));
    }
    out.files.insert(
        GEMSPECS_KEY.to_string(),
        serde_json::Value::Object(listing).to_string(),
    );
}

/// The pypi wheels whose metadata a native lock rewrite needs, in
/// candidate order: `(override, sha256)` of every `.whl` artifact some
/// `uv.lock` / PEP 723 script lock would rewrite. Each native lock is
/// parsed once, on the first dep that needs the probe.
pub fn wheel_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
) -> Vec<(&'a DepOverride, &'a str)> {
    use crate::utils::python_lock::{ArtifactSource, PythonLockSession};
    let mut probes: Option<Vec<PythonLockSession>> = None;
    let mut out = Vec::new();
    for dep in candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "pypi")
    {
        let Some(sha256) = dep.integrity.sha256.as_deref() else {
            continue;
        };
        if !dep
            .artifact_url
            .split(['?', '#'])
            .next()
            .is_some_and(|path| path.ends_with(".whl"))
        {
            continue;
        }
        let native_target = probes
            .get_or_insert_with(|| {
                files
                    .iter()
                    .filter(|(path, _)| {
                        *path == "uv.lock" || crate::utils::python_lock::is_script_lock_name(path)
                    })
                    .map(|(_, text)| PythonLockSession::new(text))
                    .collect()
            })
            .iter()
            .any(|session| {
                matches!(
                    session.plan(
                        &dep.name,
                        &dep.version,
                        ArtifactSource::Url(&dep.artifact_url),
                    ),
                    Ok(Some(_))
                )
            });
        if native_target {
            out.push((dep, sha256));
        }
    }
    out
}

/// `text` about one hosted artifact made safe to show: every URL in it
/// through [`crate::utils::redact::redact_urls_in`], and then the grant
/// token of `artifact_url` wherever it is still spelled as a path level.
/// The second pass is what knowing the artifact adds: its token is the
/// level before `patch_uuid`, so a URL served under a root the shape-based
/// redactor does not recognise (a custom `--api-url` server) or with a
/// non-canonical patch id is still covered.
pub fn redact_artifact_text(text: &str, artifact_url: &str, patch_uuid: &str) -> String {
    let text = crate::utils::redact::redact_urls_in(text);
    match crate::patch::redirect::grant_token_path_segment(artifact_url, patch_uuid) {
        Some(token) if token != crate::utils::redact::REDACTED => text.replace(
            &format!("/{token}/"),
            &format!("/{}/", crate::utils::redact::REDACTED),
        ),
        _ => text.into_owned(),
    }
}

/// The skip recorded for a pypi dep whose wheel metadata could not be
/// fetched (`detail` redacted by [`redact_artifact_text`]).
pub fn wheel_metadata_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!("pkg:pypi/{}@{}", dep.name, dep.version),
        uuid: dep.patch_uuid.clone(),
        reason: "python_metadata_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
    }
}

/// The npm candidates whose yarn berry pin needs the served tarball's own
/// `package.json`, in candidate order: yarn builds a tarball entry's `bin:`
/// from that manifest, not from the registry metadata the locked `npm:`
/// entry came from, and the two spell bin paths differently (#718); only the
/// npm resolver adds an implicit `node-gyp` dependency (#737). Only an entry
/// the pin would re-key that carries a `bin:` map or that dependency needs it
/// (see `berry_pin_needs_manifest`; a fork alias never counts), so a berry
/// project with neither fetches nothing.
pub fn yarn_berry_manifest_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
) -> Vec<&'a DepOverride> {
    let Some(lock) = files
        .get("yarn.lock")
        .filter(|lock| crate::formats::yarn::is_berry_lock(lock))
    else {
        return Vec::new();
    };
    let bin_entries = crate::formats::yarn::blocks::berry_bin_entries(lock);
    if bin_entries.is_empty() {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "npm")
        .filter(|dep| crate::patch::redirect::berry_pin_needs_manifest(&bin_entries, dep))
        .filter(|dep| seen.insert(dep.artifact_url.clone()))
        .collect()
}

/// The npm deps whose yarn classic pin reads the served tarball, one per
/// distinct artifact URL: the project's `yarn.lock` is a classic lock that
/// pins the artifact already or locks the package as a registry copy, and
/// the grant carries a sha512. The tarball gives the sha1 for the
/// `resolved` fragment yarn 1 keys its cache slot on when the grant has
/// none (#558), and its own dependencies are checked against the lock
/// (#591) on every run: a pin an earlier release wrote was never checked
/// (#1462).
/// A lock the project's offline mirror refuses outright (`yarn_outer`: the
/// mirror settings outside the project files) needs none.
pub fn yarn_classic_artifact_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
    yarn_outer: &OuterYarnMirror,
) -> Vec<&'a DepOverride> {
    let Some(lock) = files
        .get("yarn.lock")
        .filter(|lock| !crate::formats::yarn::is_berry_lock(lock))
    else {
        return Vec::new();
    };
    if crate::patch::redirect::yarn_classic_hosted_refused(files, yarn_outer) {
        return Vec::new();
    }
    select_classic_artifacts(candidates, lock, classic_registry_copies)
}

/// [`yarn_classic_artifact_targets`] over a classic `lock`, reading its
/// registry copies through `read_copies`. The lock is read in one pass for
/// the artifacts it pins already; the registry-copy test reads every
/// block, so it runs after that, at most once per lock, and only when some
/// dep is not pinned yet (#1423): a rescan whose deps are all pinned
/// already never reads the blocks.
fn select_classic_artifacts<'a>(
    candidates: &'a [Candidate],
    lock: &str,
    read_copies: impl FnOnce(&str) -> HashSet<(String, String)>,
) -> Vec<&'a DepOverride> {
    let mut pinned: Option<HashSet<&str>> = None;
    let mut read_copies = Some(read_copies);
    let mut registry_copies: Option<HashSet<(String, String)>> = None;
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "npm" && dep.integrity.sha512.is_some())
        .filter(|dep| {
            pinned
                .get_or_insert_with(|| quoted_fragment_urls(lock))
                .contains(dep.artifact_url.as_str())
                || registry_copies
                    .get_or_insert_with(|| {
                        read_copies.take().map_or_else(HashSet::new, |r| r(lock))
                    })
                    .contains(&(crate::patch::redirect::full_name(dep), dep.version.clone()))
        })
        .filter(|dep| seen.insert(dep.artifact_url.clone()))
        .collect()
}

/// Every `<url>` that `text` writes as `"<url>#…`: an opening quote, then
/// text with no quote, `#` or line break, then a `#` (a `resolved` URL
/// with its fragment). One pass, so asking whether the lock pins an
/// artifact is a set lookup rather than a search of the whole lock.
fn quoted_fragment_urls(text: &str) -> HashSet<&str> {
    let mut urls = HashSet::new();
    let mut rest = text;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let end = after.find(['"', '#', '\n']).unwrap_or(after.len());
        if after[end..].starts_with('#') {
            urls.insert(&after[..end]);
        }
        rest = &after[end..];
    }
    urls
}

/// The `(name, version)` of every registry block in a classic `lock`: the
/// only copies a hosted pin rewrites (a git, `file:`, `link:` or remote
/// tarball copy is skipped by name, so it needs no served tarball). Read
/// by the blocks' real names, as the rewriter does, so `lodash` never
/// matches a `lodash.debounce` block.
fn classic_registry_copies(lock: &str) -> HashSet<(String, String)> {
    use crate::formats::yarn::blocks::{classic_field, scan_blocks};
    use crate::formats::yarn::patterns::{classic_key_real_name, split_key_patterns};
    use crate::formats::yarn::source::{classic_copy_source, CopySource};
    scan_blocks(lock)
        .iter()
        .filter_map(|block| {
            let patterns = split_key_patterns(&block.key);
            let name = classic_key_real_name(&patterns)?;
            let version = classic_field(&block.lines, "version")?;
            (classic_copy_source(&patterns, classic_field(&block.lines, "resolved"))
                == CopySource::Registry)
                .then(|| (name.to_string(), version.to_string()))
        })
        .collect()
}

/// Record what the served tarball at `url` yielded: its sha1 on every
/// candidate granted that artifact without one, and its manifest (keyed by
/// URL) for the rewriter.
pub fn record_classic_artifact(
    candidates: &mut [Candidate],
    manifests: &mut BTreeMap<String, String>,
    url: &str,
    artifact: &crate::hosted::npm_manifest::HostedClassicArtifact,
) {
    for candidate in candidates
        .iter_mut()
        .filter(|c| c.dep.artifact_url == url && c.dep.integrity.sha1.is_none())
    {
        candidate.dep.integrity.sha1 = Some(artifact.sha1.clone());
    }
    manifests.insert(url.to_string(), artifact.manifest.clone());
}

/// The skip recorded for an npm dep whose served tarball could not be
/// fetched, did not match its grant's sha512 or had no readable
/// package.json, so its yarn classic pin could not be checked (`detail`
/// redacted by [`redact_artifact_text`]).
pub fn npm_tarball_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!(
            "pkg:npm/{}@{}",
            crate::patch::redirect::full_name(dep),
            dep.version
        ),
        uuid: dep.patch_uuid.clone(),
        reason: "npm_tarball_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
    }
}

/// The skip recorded for an npm dep whose served `package.json` could not
/// be fetched (`detail` redacted by [`redact_artifact_text`]).
pub fn npm_manifest_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!(
            "pkg:npm/{}@{}",
            crate::patch::redirect::full_name(dep),
            dep.version
        ),
        uuid: dep.patch_uuid.clone(),
        reason: "npm_manifest_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
    }
}

/// Whether a pypi candidate targets an entry of the project's
/// `Pipfile.lock` (only then does the installing Pipenv's major matter).
pub fn pipenv_lock_targets(files: &BTreeMap<String, String>, candidates: &[Candidate]) -> bool {
    if !files.contains_key("Pipfile.lock") {
        return false;
    }
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    crate::patch::redirect::pipenv_lock_targets(files, &overrides)
}

/// The host-dependent inputs of [`rewrite`].
#[derive(Clone)]
pub struct RewriteOptions<'a> {
    pub dry_run: bool,
    /// Whether a pypi candidate targets `Pipfile.lock`
    /// ([`pipenv_lock_targets`]) and the installing Pipenv's major (`None`
    /// when unknown or not targeted).
    pub targets_pipenv_lock: bool,
    pub pipenv_major: Option<u32>,
    /// The `redirect_pipenv_installer_unknown` detail (the remedy names the
    /// host's own knob).
    pub pipenv_unknown_detail: String,
    /// `false` under `--no-trust-lockfile-config`.
    pub trust_lockfile_config: bool,
    /// `false` under `--no-npm-allow-remote-config`.
    pub npm_allow_remote_config: bool,
    /// The npm config layers outside the project `.npmrc`, resolved only
    /// when an npm lock carries a hosted URL.
    pub npm_outer: &'a (dyn Fn() -> OuterAllowRemote + Send + Sync),
    /// The yarn 1 config layers outside the project's `.yarnrc` / `.npmrc`,
    /// resolved only beside a classic `yarn.lock` (its offline-mirror
    /// refusal).
    pub yarn_classic_outer: &'a (dyn Fn() -> OuterYarnMirror + Send + Sync),
    /// Where the cargo configs read for a build in the project (its own,
    /// every parent directory's and `$CARGO_HOME`'s) take crates.io from,
    /// resolved only when a cargo dep is rewritten (the cargo rewriter's
    /// offline-source refusal).
    pub cargo_outer: &'a (dyn Fn() -> CratesIoSource + Send + Sync),
    /// What Maven selects in each module of the project, read from the
    /// poms the Maven local repository holds; resolved only when a maven
    /// dep is rewritten. The pom rewriter pins a patch only where Maven
    /// selects its base version already (a pin anywhere else would change
    /// the version the build resolves). `None` from a host with no local
    /// repository to read: the rewriter then pins without that check.
    pub maven_selection: &'a (dyn Fn() -> Option<MavenSelection> + Send + Sync),
    /// A variable of the environment pnpm installs the project in, by
    /// name: a `pnpm_config_trust_lockfile` there beats the
    /// pnpm-workspace.yaml key the trust auto-config writes (#1514).
    pub pnpm_env: &'a (dyn Fn(&str) -> Option<String> + Send + Sync),
    /// Run the rewriters on the blocking pool (the disk flow: pure CPU over
    /// every lock text).
    pub blocking: bool,
    /// Uuids of the run's staged vendored→hosted takeovers (wet and dry
    /// runs alike): the caller reverted their vendored wiring in the group
    /// overlay before the rewrite, so the attribution gate never drops
    /// them, and their pin keeps the rewriters' verdict (a takeover the
    /// rewriters do not pin is retracted by the caller and stays vendored).
    /// Empty for the in-memory engine, which takes nothing over.
    pub takeover_uuids: BTreeSet<String>,
    /// The operator's extra patch-server origins (`--patch-server-url`):
    /// the allowlist `vex`, `list`, `rollback`, `remove` and `vendor`
    /// discover with, so the attribution gate sees an existing pin on a
    /// configured server even when this run's grants live on another host.
    /// Empty for the in-memory engine, which has no such knob.
    pub patch_server_origins: Vec<String>,
    /// Lockfile discovery of the project exactly as this rewrite reads it,
    /// made with exactly `patch_server_origins` (the caller's pre-rewrite
    /// discovery, `None` when nothing was discovered or the project may
    /// have changed since). The attribution gate reuses it instead of
    /// discovering again when a pass writes nothing and this run's grants
    /// name no origin that `patch_server_origins` does not already count
    /// (see [`reusable_prior`]): the project it would discover is then the
    /// same, read the same way.
    pub prior_discovery: Option<&'a crate::vex::discover::Discovery>,
}

/// One project's rewrite, ready for the guard, the record fetch and the
/// commit.
#[derive(Debug)]
pub struct Rewritten {
    /// The pre-rewrite candidate texts.
    pub files: BTreeMap<String, String>,
    pub symlinked_reads: Vec<String>,
    pub unreadable_reads: Vec<String>,
    pub undecodable_reads: Vec<String>,
    /// [`CandidateFiles::undecodable_maven_poms`].
    pub undecodable_maven_poms: Vec<String>,
    /// The rewriters' override slice (the candidates' deps).
    pub overrides: Vec<DepOverride>,
    pub rewrite: RewriteResult,
    /// Every file this run writes (text and binary), sorted.
    pub rewritten: Vec<String>,
    /// `(purl, uuid)` of each candidate whose redirect is pinned by the
    /// project's final files, in candidate order.
    pub confirmed: Vec<(String, String)>,
    /// Candidates left out of the rewrite because lockfile discovery could
    /// not attribute the pin they would land (see [`rewrite`]): reported as
    /// skipped, written nowhere.
    pub unattributed: Vec<SkippedPatch>,
    /// A `bun.lockb` without a text `bun.lock` drives npm.
    pub binary_bun: bool,
    pub rush_warnings: Vec<RewriteWarning>,
    pub pnpm_warnings: Vec<RewriteWarning>,
    pub npm_warnings: Vec<RewriteWarning>,
    /// Human mode: this run touched nothing pnpm-related (no lock spliced,
    /// trust or the named registries already configured), so the full
    /// guidance shrinks to a one-line reminder.
    pub pnpm_rerun_only: bool,
    /// The run's pnpm guidance is the named-registry one: every hosted pin
    /// of the governing pnpm locks is routed through a registry
    /// pnpm-workspace.yaml declares, so `trustLockfile` is not what
    /// installs rely on.
    pub pnpm_named_registries: bool,
    /// What a routed project is told of a release the route may reach
    /// ([`crate::hosted::guidance::pnpm_registry_in_range_note`]): part of
    /// the pnpm guidance's detail, and kept apart for a caller that shows
    /// a shorter guidance on a run that changed nothing.
    pub pnpm_route_note: Option<String>,
    /// The pnpm-workspace.yaml this run writes is what is left of a file a
    /// hosted run created once nothing is routed any more: the `packages`
    /// list it was created with and nothing else. A rewrite only carries
    /// writes, so the caller deletes the file once they have landed (the
    /// CLI after its commit; the in-memory engine reports it among the
    /// deleted files instead of the changed ones).
    pub pnpm_workspace_emptied: bool,
    /// In memory only: the trust auto-config would write through a
    /// symlinked `pnpm-workspace.yaml`.
    pub(crate) workspace_symlinked: bool,
    /// The attribution gate's discovery of the project as this rewrite
    /// leaves it, when it equals a discovery made with exactly
    /// [`RewriteOptions::patch_server_origins`] (this run's grants name no
    /// other origin). `None` when the gate discovered nothing (no
    /// confirmed candidate) or counted another origin. A caller that
    /// writes exactly [`RewriteResult::files`] and
    /// [`RewriteResult::binary_files`] and nothing else may use it in place
    /// of discovering the written project again (see [`FinalDiscovery`]).
    pub final_discovery: Option<FinalDiscovery>,
}

impl Rewritten {
    /// Take the Maven rewriter's respelling of `.mvn/maven.config` back
    /// out of what this run writes and reports
    /// ([`crate::patch::redirect::withhold_maven_heal`]): for a caller that
    /// could not take the write lock.
    pub fn withhold_maven_heal(&mut self) {
        if crate::patch::redirect::withhold_maven_heal(&mut self.rewrite) {
            self.rewritten
                .retain(|rel| rel != crate::patch::redirect::MVN_CONFIG);
        }
    }
}

/// Where [`Rewritten::final_discovery`] lives.
#[derive(Debug)]
pub enum FinalDiscovery {
    /// The pass wrote nothing, and the gate reused the caller's
    /// [`RewriteOptions::prior_discovery`]: still the caller's to read.
    Prior,
    /// A discovery of the project with the pass's writes overlaid (the
    /// project read when the gate ran). Every read the view mediates sees
    /// the overlay, created files included (see
    /// [`DiskSnapshot::overlay`](crate::vendor::lock_inventory::DiskSnapshot::overlay)),
    /// so it equals a discovery of the written disk when every written file
    /// already existed, or when discovery read nothing around the view
    /// (`view_only`), or when each created file is one no such read can
    /// see ([`overlay_creation_is_invisible`]).
    Overlaid {
        discovery: Box<crate::vex::discover::Discovery>,
        /// Discovery read the project only through the overlaid view (no
        /// raw disk read: the vlt store, sbt evidence, a vendored feed).
        view_only: bool,
    },
}

/// Whether CREATING `rel` (a write over no existing regular file) leaves a
/// discovery over the overlaid project equal to one over the written disk:
/// the root config files the install-policy auto-configs create
/// ([`NPMRC_REL`], [`PNPM_WORKSPACE_REL`]), which discovery reads, if at
/// all, by path and never finds by listing a directory.
pub fn overlay_creation_is_invisible(rel: &str) -> bool {
    rel == NPMRC_REL || rel == PNPM_WORKSPACE_REL
}

/// The pnpm-workspace.yaml read, classified for the trust auto-config
/// (see [`read_workspace_for_trust`]), plus whether it is an in-memory
/// symbolic link (absent to the planner, refused by [`guard`]).
fn read_workspace(view: &ProjectView<'_>) -> (std::io::Result<Option<String>>, bool) {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            (
                read_workspace_for_trust(&cwd.join(PNPM_WORKSPACE_REL)),
                false,
            )
        }
        ProjectView::Memory(project) => match project.get(PNPM_WORKSPACE_REL) {
            None => (Ok(None), false),
            Some(MemoryEntry::Text(text)) => (Ok(Some(text.to_string())), false),
            Some(MemoryEntry::Symlink) => (Ok(None), true),
            Some(MemoryEntry::Binary(_)) => (
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stream did not contain valid UTF-8",
                )),
                false,
            ),
            Some(MemoryEntry::Present) => (
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "file content was not provided",
                )),
                false,
            ),
        },
    }
}

/// The project `.npmrc` read, classified for the allow-remote planner (see
/// [`read_npmrc_for_allow_remote`]).
fn read_npmrc(view: &ProjectView<'_>) -> Result<Option<String>, String> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            read_npmrc_for_allow_remote(&cwd.join(NPMRC_REL))
        }
        ProjectView::Memory(project) => match project.get(NPMRC_REL) {
            None => Ok(None),
            Some(MemoryEntry::Symlink) => {
                Err("is a symbolic link (socket-patch never writes through one)".into())
            }
            Some(MemoryEntry::Text(text)) => Ok(Some(text.to_string())),
            Some(MemoryEntry::Binary(_)) => {
                Err("could not be read (stream did not contain valid UTF-8)".into())
            }
            Some(MemoryEntry::Present) => {
                Err("could not be read (file content was not provided)".into())
            }
        },
    }
}

/// The repo-state.json that carries the pnpmShrinkwrapHash of the Rush lock
/// at `lock_key`: the file beside it. The common lock maps to
/// [`RUSH_REPO_STATE_REL`]; with subspaces enabled each subspace keeps its
/// own, at `common/config/subspaces/<name>/repo-state.json`.
fn rush_repo_state_for_lock(lock_key: &str) -> String {
    match lock_key.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/repo-state.json"),
        None => "repo-state.json".to_string(),
    }
}

/// Whether the Rush repo-state file `rel` is present (disk: a regular file).
fn rush_repo_state_present(view: &ProjectView<'_>, rel: &str) -> bool {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            cwd.join(rel).is_file()
        }
        ProjectView::Memory(project) => project.contains(rel),
    }
}

/// How the confirmation probe settles one candidate: a non-substring rule
/// (a transactional rewriter's own report, a refusal) decides it outright,
/// otherwise it is confirmed iff any of its needles occurs in a final text.
enum ProbeStep {
    Decided(bool),
    Needles(Vec<String>),
}

/// The substrings whose presence in a final text confirms `dep`'s redirect —
/// the override's own targets: artifact URL; per-dependency registry index
/// URL; fail-closed maven's globally-unique `-socket.<hex8>` suffixed version
/// (never the `.pom` URL).
///
/// - The artifact URL in the rewriters' own spellings
///   ([`artifact_url_spellings`], raw or the `\/`-escaped slashes an old
///   composer.lock spells them with), so a writer's spelling can never be
///   one this probe misses.
/// - The percent-encoded URL: releases up to 5.0 wrote it into a berry
///   lock's `::__archiveUrl=` binding (today's berry pin is the raw URL), so
///   a lock pinned by them carries no raw form.
/// - The registry index URL and the maven suffixed version, when present.
pub fn candidate_presence_needles(dep: &DepOverride) -> Vec<String> {
    let artifact_url = dep.artifact_url.as_str();
    let registry = dep.registry_override.as_ref();
    let mut needles: Vec<String> = artifact_url_spellings(artifact_url).into();
    needles.push(crate::utils::uri::encode_uri_component(artifact_url));
    if let Some(o) = registry {
        needles.push(o.index_url.clone());
        if let Some(sv) = o.identifiers.maven_suffixed_version.as_deref() {
            needles.push(sv.to_string());
        }
    }
    needles
}

/// Rewrite the candidate files for `candidates`, plan the install-policy
/// auto-configs, and confirm which redirects the final files pin.
///
/// `python_metadata` maps a wheel's artifact URL to its fetched METADATA.
pub async fn rewrite(
    view: &ProjectView<'_>,
    read: CandidateFiles,
    candidates: &[Candidate],
    python_metadata: BTreeMap<String, String>,
    options: RewriteOptions<'_>,
) -> Rewritten {
    // The run must never leave wiring that lockfile discovery — what `vex`,
    // `list`, `rollback`, `remove` and `vendor` read — calls contested. A
    // candidate the rewriters confirm but discovery cannot attribute to one
    // package version (another lock resolving the same version elsewhere, a
    // pin Maven never consumes) would be refused by every later command, so
    // it is dropped and the rest rewritten without it. Each pass drops at
    // least one candidate, so this ends. A staged takeover is never dropped
    // (see [`RewriteOptions::takeover_uuids`]): its vendored wiring is
    // reverted in the overlay, and its pin keeps the rewriters' verdict.
    let exempt: BTreeSet<String> = options.takeover_uuids.clone();
    let mut kept: Vec<Candidate> = candidates.to_vec();
    let mut unattributed: Vec<SkippedPatch> = Vec::new();
    loop {
        let mut done = rewrite_once(
            view,
            read.clone(),
            &kept,
            python_metadata.clone(),
            options.clone(),
        )
        .await;
        let Gated {
            vetoed,
            lockless,
            copy_left,
            copy_shadowed,
            discovery,
        } = unattributed_pins(
            view,
            &done,
            &kept,
            &exempt,
            &options.patch_server_origins,
            options.prior_discovery,
        )
        .await;
        if vetoed.is_empty() {
            let constraints = constraints_link_warnings(view, &done, &kept).await;
            done.rewrite.warnings.extend(constraints);
            done.unattributed = unattributed;
            done.rewrite.warnings.extend(lockless);
            done.rewrite.warnings.extend(copy_left);
            done.rewrite.bundled_skipped_uuids.extend(copy_shadowed);
            done.final_discovery = discovery;
            return done;
        }
        kept.retain(|c| !vetoed.iter().any(|skip| skip.uuid == c.dep.patch_uuid));
        unattributed.extend(vetoed);
    }
}

/// A `redirect_requirements_constraints_link` warning for each sibling
/// requirements file that reads the root requirements.txt as `-c`
/// constraints while a hosted pin there is a URL (#740), which pip 20.3
/// and 21.0 refuse in a constraints file. Said on every run that confirms
/// such a pin, not only the one that writes it: the hazard lasts as long
/// as the pin does.
async fn constraints_link_warnings(
    view: &ProjectView<'_>,
    done: &Rewritten,
    kept: &[Candidate],
) -> Vec<RewriteWarning> {
    let confirmed = &done.rewrite.confirmed_requirements_uuids;
    let mut pinned: Vec<&str> = kept
        .iter()
        .filter(|c| confirmed.contains(&c.dep.patch_uuid))
        .map(|c| c.dep.name.as_str())
        .collect();
    pinned.sort_unstable();
    pinned.dedup();
    if pinned.is_empty() {
        return Vec::new();
    }
    crate::vendor::pypi_requirements::constraint_readers_in(*view, &[PYPI_REQUIREMENTS.to_string()])
        .await
        .into_iter()
        .map(|found| {
            warning(
                "redirect_requirements_constraints_link",
                format!(
                "{} reads {} as a constraints file (`-c`), and the hosted pin of {} in {} is a \
                 URL; {}",
                found.reader,
                found.target,
                pinned.join(", "),
                found.target,
                crate::vendor::pypi_requirements::CONSTRAINT_LINK_REMEDY
            ),
            )
        })
        .collect()
}

/// Lockfile discovery over the project as `done` would leave it, read as
/// the management commands read it ([`HostedInventory`]): the skips for
/// the confirmed candidates whose pin would be contested wiring, a
/// [`REDIRECT_PIN_LOCKLESS`] warning per lockless pin, and a
/// [`REDIRECT_COPY_UNPATCHED`] warning per pnpm or yarn copy a pin's own
/// lock installs beside it. A lockless NuGet /
/// Cargo pin ([`UnlockedPin`]) is written as before — whether such a pin
/// may be written at all is the open hosted-rollback decision (E45) — but
/// the run says that nothing can manage it until a lockfile exists.
///
/// A deliberate partial redirect keeps its behavior too: a dep whose
/// bundled or user-patched copy the rewriters knowingly left on the
/// registry (`bundled_skipped_uuids`, a yarn `npm:` alias entry in
/// `alias_skipped_entries`, or a bundled copy in vlt's store; all are
/// warned and kept out of the in-run VEX), and a wet vendored→hosted
/// takeover whose vendored wiring the caller already reverted (in
/// `exempt`). Which unreachable copies should block a redirect is the
/// copy-source policy (audit B16), not decided here.
///
/// [`HostedInventory`]: crate::patch::redirect::upstream::HostedInventory
/// [`UnlockedPin`]: crate::vex::discover::UnlockedPin
async fn unattributed_pins(
    view: &ProjectView<'_>,
    done: &Rewritten,
    candidates: &[Candidate],
    exempt: &BTreeSet<String>,
    configured: &[String],
    prior: Option<&crate::vex::discover::Discovery>,
) -> Gated {
    if done.confirmed.is_empty() {
        return Gated::default();
    }
    // The management commands' allowlist plus the hosts this run's grants
    // name: a pin on either counts, as it will for them. A grant on
    // Socket's own server or a configured one adds nothing discovery does
    // not already count, so the discovery is then the one `configured`
    // alone makes.
    let foreign = crate::patch::redirect::upstream::foreign_dep_origins(
        candidates.iter().map(|c| &c.dep),
        configured,
    );
    let same_origins = foreign.is_empty();
    let mut origins = configured.to_vec();
    for origin in foreign {
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    let opts = crate::vex::DiscoverOptions {
        patch_server_origins: origins,
    };
    let mut written: Vec<(&str, &[u8])> = Vec::new();
    for (rel, text) in &done.rewrite.files {
        if !crate::patch::redirect::sbt::is_synthetic_key(rel) {
            written.push((rel.as_str(), text.as_bytes()));
        }
    }
    for (rel, bytes) in &done.rewrite.binary_files {
        written.push((rel.as_str(), bytes.as_slice()));
    }
    let reused = reusable_prior(prior, written.is_empty(), same_origins);
    let fresh = if reused.is_some() {
        None
    } else {
        Some(match view.disk_root() {
            None => {
                let ProjectView::Memory(project) = *view else {
                    unreachable!("only a memory view has no disk root")
                };
                let mut after = project.clone();
                for (rel, bytes) in written {
                    let entry = match std::str::from_utf8(bytes) {
                        Ok(text) => crate::vendor::lock_inventory::MemoryEntry::Text(text.into()),
                        Err(_) => crate::vendor::lock_inventory::MemoryEntry::Binary(bytes.into()),
                    };
                    after.insert(rel, entry);
                }
                let discovery = crate::vex::discover::discover_patched_refs_view(
                    ProjectView::Memory(&after),
                    &opts,
                )
                .await;
                (discovery, true)
            }
            Some(root) => {
                // Tracked only to learn whether discovery read around the
                // overlay (see `FinalDiscovery::Overlaid::view_only`).
                let after = crate::vendor::lock_inventory::DiskSnapshot::tracked(root);
                for (rel, bytes) in written {
                    after.overlay(rel, bytes);
                }
                after.begin_recording();
                let discovery = crate::vex::discover::discover_patched_refs_view(
                    ProjectView::Snapshot(&after),
                    &opts,
                )
                .await;
                (discovery, after.end_recording().is_some())
            }
        })
    };
    let discovery = match (reused, &fresh) {
        (Some(prior), _) => prior,
        (None, Some((fresh, _))) => fresh,
        (None, None) => unreachable!("a pass reuses the prior discovery or discovers afresh"),
    };
    // The management commands' own view of the result: an attributable
    // pin, or contested wiring they would refuse around.
    let inventory = crate::patch::redirect::upstream::HostedInventory::of(discovery);
    let attributed: BTreeSet<&str> = inventory.pins.iter().map(|p| p.uuid.as_str()).collect();
    let lockless: Vec<RewriteWarning> = discovery
        .unlocked_pins
        .iter()
        .filter(|pin| {
            !attributed.contains(pin.uuid.as_str())
                && done.confirmed.iter().any(|(_, uuid)| *uuid == pin.uuid)
        })
        .map(|pin| {
            let create = match pin.ecosystem.as_str() {
                "nuget" => "create packages.lock.json (`dotnet restore --use-lock-file`)",
                "cargo" => "create Cargo.lock (`cargo generate-lockfile`)",
                _ => "create the lockfile",
            };
            warning(
                REDIRECT_PIN_LOCKLESS,
                format!(
                    "{}: {} is pinned to patch {} without a lockfile that records its version, \
                     so `vex` cannot attest it and `rollback`, `remove` and `vendor` refuse it \
                     as unattributable; {create} and re-run `socket-patch scan --mode hosted` \
                     to make it manageable",
                    pin.file.display(),
                    pin.name,
                    pin.uuid
                ),
            )
        })
        .collect();
    // A pin whose own pnpm or yarn lock also installs an unpatched copy of
    // the same `name@version` is written: the registry copy is patched, and
    // discovery withholds the pin from attestation but still manages it
    // ([`Discovery::shadowed`], #828). The rewriters cannot see every such
    // copy: a pnpm `file:` directory's version lives in its own package.json
    // (#935), and yarn keys a `file:` / url / `portal:` copy by the
    // DEPENDENCY name (`lp2@file:…`), so which package it holds is read from
    // the copy itself (#939, #1236). The run names each one here, and keeps
    // the in-run VEX from assuming the uuid applied. A copy a rewriter
    // already named (the yarn classic `file:` directory skip) is not named
    // twice.
    //
    // [`Discovery::shadowed`]: crate::vex::discover::Discovery::shadowed
    let mut copy_left: Vec<RewriteWarning> = Vec::new();
    let mut copy_shadowed: BTreeSet<String> = BTreeSet::new();
    let mut named: BTreeSet<(&std::path::Path, &str, &str)> = BTreeSet::new();
    for r in &discovery.shadowed {
        if r.mode != crate::vex::discover::WiringMode::Hosted
            || !done.confirmed.iter().any(|(_, uuid)| *uuid == r.uuid)
        {
            continue;
        }
        for c in discovery.unpatched_copies.iter().filter(|c| {
            c.purl == r.purl
                && c.file == r.source_file
                && r.part.withheld_by(c.part)
                && matches!(
                    c.file.file_name().and_then(|n| n.to_str()),
                    Some("pnpm-lock.yaml" | "shrinkwrap.yaml" | "yarn.lock")
                )
        }) {
            copy_shadowed.insert(r.uuid.clone());
            if yarn_rewriter_named(&done.rewrite.warnings, &c.file, &c.key)
                || !named.insert((c.file.as_path(), c.key.as_str(), c.how.as_str()))
            {
                continue;
            }
            copy_left.push(warning(
                REDIRECT_COPY_UNPATCHED,
                format!(
                    "{}: {} is pinned to patch {}, but lock entry `{}` {}; that copy stays \
                     UNPATCHED, so `vex` attests nothing for {}. {}",
                    c.file.display(),
                    r.purl,
                    r.uuid,
                    c.key,
                    c.how,
                    r.purl,
                    c.remedy.as_deref().unwrap_or(
                        "Depend on the registry release instead of that copy to patch it"
                    ),
                ),
            ));
        }
    }
    // Contested wiring (not a lockless pin, see above) is what the run must
    // never leave behind. A pin discovery does not see at all (a file it
    // does not read, such as a pre-2.6 bundler Gemfile the next `bundle
    // install` locks) is no such wiring and keeps the rewriters' verdict.
    let contested: BTreeSet<&str> = inventory
        .contested
        .iter()
        .filter(|c| c.lockless.is_empty())
        .map(|c| c.uuid.as_str())
        .collect();
    // vlt's bundled copies live only in its installed store, which the
    // rewriters never read (the scan warns about them after the writes).
    let vlt_bundled: BTreeSet<String> = match view.disk_root() {
        Some(root) if !contested.is_empty() => crate::vendor::vlt_bundled::bundled_copies(root)
            .await
            .into_keys()
            .collect(),
        _ => BTreeSet::new(),
    };
    let vetoed = done
        .confirmed
        .iter()
        .filter(|(purl, uuid)| {
            !attributed.contains(uuid.as_str())
                && contested.contains(uuid.as_str())
                && !done.rewrite.bundled_skipped_uuids.contains(uuid)
                && !done.rewrite.alias_skipped_entries.contains_key(uuid)
                && !exempt.contains(uuid)
                && !vlt_bundled.contains(&crate::utils::purl_key::canonical_base_purl(purl))
        })
        .map(|(purl, uuid)| {
            let findings: Vec<&str> = discovery
                .diagnostics
                .iter()
                .filter(|d| d.detail.contains(uuid.as_str()) || d.detail.contains(purl.as_str()))
                .map(|d| d.detail.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let why = if findings.is_empty() {
                String::new()
            } else {
                format!(" ({})", findings.join("; "))
            };
            SkippedPatch {
                purl: purl.clone(),
                uuid: uuid.clone(),
                reason: REDIRECT_UNATTRIBUTABLE.to_string(),
                detail: Some(format!(
                    "the rewrite would wire patch {uuid} for {purl}, but lockfile discovery (what \
                     `vex`, `list`, `rollback` and `vendor` read) cannot attribute that pin to \
                     one package version{why}, so nothing was changed for it; reconcile the \
                     project's lockfiles and re-run"
                )),
            }
        })
        .collect();
    let discovery = match (same_origins, fresh) {
        (false, _) => None,
        (true, None) => Some(FinalDiscovery::Prior),
        (true, Some((fresh, view_only))) => Some(FinalDiscovery::Overlaid {
            discovery: Box::new(fresh),
            view_only,
        }),
    };
    Gated {
        vetoed,
        lockless,
        copy_left,
        copy_shadowed,
        discovery,
    }
}

/// Whether a yarn rewriter's own warning already names lock entry `key` of
/// the root `yarn.lock` (the only yarn lock the rewriters read): the yarn
/// classic `file:` directory / url / alias skips name the entry by its raw
/// key, exactly as discovery records it.
fn yarn_rewriter_named(warnings: &[RewriteWarning], file: &std::path::Path, key: &str) -> bool {
    if file != std::path::Path::new("yarn.lock") {
        return false;
    }
    let entry = format!("`{key}`");
    warnings
        .iter()
        .any(|w| w.code.starts_with("redirect_yarn_") && w.detail.contains(&entry))
}

/// What [`unattributed_pins`] decided for one pass.
#[derive(Default)]
struct Gated {
    /// The confirmed candidates whose pin would be contested wiring.
    vetoed: Vec<SkippedPatch>,
    /// A [`REDIRECT_PIN_LOCKLESS`] warning per lockless pin.
    lockless: Vec<RewriteWarning>,
    /// A [`REDIRECT_COPY_UNPATCHED`] warning per pnpm or yarn copy a pin's
    /// own lock installs beside it.
    copy_left: Vec<RewriteWarning>,
    /// The uuids of those pins, which the in-run VEX must not assume
    /// applied (joined into [`RewriteResult::bundled_skipped_uuids`]).
    copy_shadowed: BTreeSet<String>,
    /// The discovery the verdict read, for [`Rewritten::final_discovery`].
    discovery: Option<FinalDiscovery>,
}

/// The caller's pre-rewrite discovery, when it is exactly what the gate
/// would discover: the pass writes nothing (so the project is the one the
/// caller discovered) and the gate's origins (`configured` plus the
/// grants' hosts) count exactly the pins the caller's (`configured` alone)
/// did: `same_origins`, no grant on a host outside Socket's own server and
/// `configured` ([`foreign_dep_origins`]).
///
/// [`foreign_dep_origins`]: crate::patch::redirect::upstream::foreign_dep_origins
fn reusable_prior(
    prior: Option<&crate::vex::discover::Discovery>,
    nothing_written: bool,
    same_origins: bool,
) -> Option<&crate::vex::discover::Discovery> {
    prior.filter(|_| nothing_written && same_origins)
}

/// Warning: a confirmed pin no lockfile records a version for (a lockless
/// NuGet / Cargo redirect), which no later command can attribute.
pub const REDIRECT_PIN_LOCKLESS: &str = "redirect_pin_lockless";

/// Warning: a confirmed pin's own pnpm or yarn lock also installs an
/// unpatched copy of the same `name@version` from a `file:` directory or
/// tarball dependency (#935), or, in a yarn lock, from a `file:` / url /
/// berry `portal:` / `link:` dependency declared under another name (#939,
/// #1236), which no rewrite reaches.
pub const REDIRECT_COPY_UNPATCHED: &str = "redirect_copy_unpatched";

/// `skipped[].reason` of a candidate whose pin lockfile discovery would not
/// attribute (see [`rewrite`]).
pub const REDIRECT_UNATTRIBUTABLE: &str = "redirect_unattributable";

async fn rewrite_once(
    view: &ProjectView<'_>,
    read: CandidateFiles,
    candidates: &[Candidate],
    python_metadata: BTreeMap<String, String>,
    options: RewriteOptions<'_>,
) -> Rewritten {
    let CandidateFiles {
        files,
        rush_lock_keys,
        pnpm_member_lock_keys,
        symlinked_reads,
        unreadable_reads,
        undecodable_reads,
        undecodable_maven_poms,
        gradle_unreadable,
        gem_refusal,
        pnpm_refusal,
        pnpm_bazel,
    } = read;
    // The rewriters' override slice — materialized ONCE, after the last
    // candidate filter, so it can never disagree with `candidates`.
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    // Before any rewriter reads a lock: keys an unreleased build spelled
    // through a registry under one of its names are respelled.
    let mut files = files;
    // A root lock that a Bazel hub keeps out of the run records the
    // overrides of the workspace file like every other governing lock, and
    // is not written: the route is then left as it is, in the locks that
    // were read too.
    let respelled = if pnpm_bazel.hidden.is_some() {
        Respelled::default()
    } else {
        respell_earlier_route(
            view,
            &mut files,
            &pnpm_member_lock_keys,
            &rush_lock_keys,
            &overrides,
            &options,
        )
    };
    let bun_lockb = bun_lockb_present(view);
    let binary_bun = !bun_text_lock_drives(view) && bun_lockb;
    let binary_content = if binary_bun && overrides.iter().any(|o| o.ecosystem == "npm") {
        Some(
            view.read_bytes("bun.lockb")
                .await
                .map_err(|e| RewriteWarning {
                    code: "redirect_bun_lockb_invalid".into(),
                    detail: format!("cannot read bun.lockb: {e}"),
                })
                .and_then(|bytes| {
                    crate::patch::redirect::preflight_bun_binary(&bytes)?;
                    Ok(bytes)
                }),
        )
    } else {
        None
    };
    // A malformed primary lock must not cause edits to stale npm siblings.
    let rewrite_overrides: Vec<DepOverride> = overrides
        .iter()
        .filter(|o| !(binary_content.as_ref().is_some_and(Result::is_err) && o.ecosystem == "npm"))
        .cloned()
        .collect();
    let pipenv_major = options.pipenv_major;
    // The yarn config outside the project decides the classic rewriter's
    // offline-mirror refusal too: resolved only beside a classic lock.
    let yarn_outer = if rewrite_overrides.iter().any(|o| o.ecosystem == "npm")
        && files
            .get("yarn.lock")
            .is_some_and(|lock| !crate::patch::redirect::is_berry_lock(lock))
    {
        (options.yarn_classic_outer)()
    } else {
        OuterYarnMirror::default()
    };
    let cargo_outer = if rewrite_overrides.iter().any(|o| o.ecosystem == "cargo") {
        (options.cargo_outer)()
    } else {
        CratesIoSource::Registry
    };
    // Asked only when there is a pom to pin: a single one, or a reactor's.
    let maven_selection = (rewrite_overrides.iter().any(|o| o.ecosystem == "maven")
        && files.contains_key("pom.xml"))
    .then(|| (options.maven_selection)())
    .flatten();
    let (files, mut rewrite) = if options.blocking {
        // Pure CPU over every lock text (the independent rewriter groups
        // run concurrently inside), so it runs on the blocking pool rather
        // than on a runtime worker; `files` comes back for the probe below.
        tokio::task::spawn_blocking(move || {
            let rewrite = rewrite_registry_redirect_with_host(
                &files,
                &rewrite_overrides,
                &python_metadata,
                pipenv_major,
                bun_lockb,
                &gradle_unreadable,
                &yarn_outer,
                &cargo_outer,
                maven_selection.as_ref(),
            );
            (files, rewrite)
        })
        .await
        .unwrap_or_else(|e| match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("hosted rewrite task failed: {e}"),
        })
    } else {
        let rewrite = rewrite_registry_redirect_with_host(
            &files,
            &rewrite_overrides,
            &python_metadata,
            pipenv_major,
            bun_lockb,
            &gradle_unreadable,
            &yarn_outer,
            &cargo_outer,
            maven_selection.as_ref(),
        );
        (files, rewrite)
    };
    // A respelled lock is written even when no rewriter changed it since.
    for key in respelled.keys {
        if let Some(text) = files.get(&key) {
            rewrite.files.entry(key).or_insert_with(|| text.clone());
        }
    }
    rewrite.edits.splice(0..0, respelled.edits);
    // The Maven rewriter's respelling of `.mvn/maven.config` is a courtesy,
    // never the reason a run is refused or fails: where the file cannot be
    // replaced (a symbolic link, which the guard refuses for every write;
    // a directory that does not take the write) the line is left as it is.
    if crate::patch::redirect::carries_maven_heal(&rewrite) {
        let writable = match view {
            ProjectView::Disk(root) => crate::patch::redirect::maven_config_writable(root).await,
            _ => !view.is_symlink(crate::patch::redirect::MVN_CONFIG),
        };
        if !writable {
            crate::patch::redirect::withhold_maven_heal(&mut rewrite);
        }
    }
    // The gem files were withheld on purpose: say why, not "no Gemfile".
    if let Some(warning) = gem_refusal {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_gem_no_gemfile");
        rewrite.warnings.push(warning);
    }
    // The pnpm locks were withheld on purpose: say why, not "run `pnpm
    // install`" (which never writes a root lock in either layout).
    if let Some(warning) = pnpm_refusal {
        rewrite.warnings.retain(|w| {
            w.code != "redirect_pnpm_no_lockfile" && w.code != "redirect_npm_no_lockfile"
        });
        rewrite.warnings.push(warning);
    }
    if let Some(content) = binary_content {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_npm_no_lockfile");
        match content {
            Ok(bytes) => {
                // A package the project patches itself (`bun patch`) keeps
                // its registry record, loudly (#367).
                let user_patched = crate::vendor::bun_lock_text::patched_dependency_keys(
                    files.get("package.json").map(String::as_str),
                    None,
                );
                // A default-trusted package keeps its registry record
                // too, unless an earlier run already pinned it (#371): the
                // text rewriter's rule, read off the binary records. They
                // are decoded only if some override is on Bun's default
                // list, which is rare.
                let records = std::cell::OnceCell::new();
                let binary_overrides: Vec<DepOverride> = overrides
                    .iter()
                    .filter(|o| {
                        if o.ecosystem != "npm" {
                            return true;
                        }
                        let name = crate::patch::redirect::full_name(o);
                        if crate::patch::redirect::skip_bun_user_patched(
                            &user_patched,
                            &name,
                            o,
                            &mut rewrite,
                        ) {
                            return false;
                        }
                        let newly_pins = || {
                            let records = records.get_or_init(|| {
                                crate::vendor::bun_lockb::BunLockb::parse_packages(&bytes)
                                    .unwrap_or_default()
                            });
                            // A bundled-only record is never a pin.
                            let already_pinned = records.iter().any(|p| {
                                p.name == name
                                    && !p.bundled_only
                                    && (p.resolution == o.artifact_url
                                        || crate::patch::redirect::is_prior_hosted_bun_spec(
                                            &format!("{name}@{}", p.resolution),
                                            &name,
                                            &o.artifact_url,
                                        ))
                            });
                            !already_pinned
                                && records.iter().any(|p| {
                                    p.name == name
                                        && p.version.as_deref() == Some(o.version.as_str())
                                        && !p.bundled_only
                                })
                        };
                        !crate::patch::redirect::skip_bun_default_trusted(
                            files.get("package.json").map(String::as_str),
                            None,
                            &name,
                            o,
                            newly_pins,
                            &mut rewrite,
                        )
                    })
                    .cloned()
                    .collect();
                crate::patch::redirect::rewrite_bun_binary(&bytes, &binary_overrides, &mut rewrite);
                // A pinned default-trusted package loses Bun's default trust
                // (#371); the text rewriter warns the same way.
                for o in &binary_overrides {
                    let name = crate::patch::redirect::full_name(o);
                    if rewrite.confirmed_bun_binary_uuids.contains(&o.patch_uuid)
                        && crate::vendor::bun_lock_text::loses_default_trust(
                            files.get("package.json").map(String::as_str),
                            None,
                            &name,
                        )
                    {
                        rewrite
                            .warnings
                            .push(crate::patch::redirect::bun_default_trust_warning(
                                &name, &o.version,
                            ));
                    }
                }
            }
            Err(warning) => rewrite.warnings.push(warning),
        }
    }

    // Unknown installer → the modern `file` shape was chosen; say so only
    // when the lock was (or, on --dry-run, would be) rewritten.
    if options.targets_pipenv_lock
        && pipenv_major.is_none()
        && rewrite.files.contains_key("Pipfile.lock")
    {
        rewrite.warnings.push(RewriteWarning {
            code: "redirect_pipenv_installer_unknown".into(),
            detail: options.pipenv_unknown_detail.clone(),
        });
    }

    // Editing a Rush lock outside `rush update` desyncs the
    // pnpmShrinkwrapHash recorded in repo-state.json. When
    // preventManualShrinkwrapChanges is enabled, `rush install` then
    // refuses until `rush update` refreshes that hash — but the redirect
    // survives `rush update` (pnpm preserves locked resolutions for
    // unchanged specifiers). Warn only when the rewrite actually landed in
    // a Rush lock and the repo-state file that carries THAT lock's hash is
    // present: it sits beside the lock, so with subspaces enabled each
    // subspace lock pairs with its own subspace's repo-state.json (#714).
    let mut rush_warnings: Vec<RewriteWarning> = Vec::new();
    if rush_lock_keys
        .iter()
        .filter(|key| rewrite.files.contains_key(*key))
        .any(|key| rush_repo_state_present(view, &rush_repo_state_for_lock(key)))
    {
        rush_warnings.push(warning(
            "redirect_rush_repo_state_stale",
            "pnpm-lock.yaml was edited outside `rush update`; if \
                 preventManualShrinkwrapChanges is enabled, `rush install` fails until \
                 `rush update` refreshes repo-state.json (the hosted wiring survives `rush \
                 update`)",
        ));
    }

    // Settled first: the route decides the shape of the governing locks.
    let route = pnpm_route(
        view,
        &files,
        &pnpm_member_lock_keys,
        &mut rewrite,
        &rush_lock_keys,
        &overrides,
        &options,
        &pnpm_bazel,
    );
    let workspace_emptied = route.emptied;
    let PnpmTrust {
        warnings: pnpm_warnings,
        config_write: pnpm_config_write,
        rerun_only: pnpm_rerun_only,
        workspace_symlinked,
        named_registries: pnpm_named_registries,
        route_note: pnpm_route_note,
        emptied: trust_emptied,
    } = pnpm_trust(
        view,
        &files,
        &pnpm_member_lock_keys,
        &rewrite,
        &rush_lock_keys,
        &overrides,
        &options,
        route,
    );
    let (mut npm_warnings, npmrc_config_write) =
        npm_allow_remote(view, &files, &rewrite, &overrides, &options);
    npm_warnings.extend(npm_allow_scripts(&files, &rewrite, &overrides));
    // Only while the emptied file is the one this run writes.
    let pnpm_workspace_emptied =
        (workspace_emptied && pnpm_config_write.is_none()) || trust_emptied;
    if let Some((text, edits)) = pnpm_config_write {
        rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
        // Appended last, after the lock edits they serve. v5 keeps no hosted
        // ledger, so nothing replays these edits; the order is write order.
        rewrite.edits.extend(edits);
    }
    if let Some((text, edit)) = npmrc_config_write {
        rewrite.files.insert(NPMRC_REL.to_string(), text);
        // Appended after the lock edits, like the pnpm trust key above.
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .filter(|k| !crate::patch::redirect::sbt::is_synthetic_key(k))
        .cloned()
        .collect();
    let confirmed = confirm(&files, &rewrite, candidates, binary_bun);
    npm_warnings.extend(npm_deno_lock(view, &overrides, &confirmed));
    Rewritten {
        files,
        symlinked_reads,
        unreadable_reads,
        undecodable_reads,
        undecodable_maven_poms,
        overrides,
        rewrite,
        rewritten,
        confirmed,
        unattributed: Vec::new(),
        binary_bun,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
        pnpm_rerun_only,
        pnpm_named_registries,
        pnpm_route_note,
        pnpm_workspace_emptied,
        workspace_symlinked,
        final_discovery: None,
    }
}

type ConfigWrite = Option<(String, FileEdit)>;

/// What [`pnpm_trust`] settles for a run.
#[derive(Default)]
struct PnpmTrust {
    warnings: Vec<RewriteWarning>,
    /// The new pnpm-workspace.yaml and the edits that make it.
    config_write: Option<(String, Vec<FileEdit>)>,
    /// See [`Rewritten::pnpm_rerun_only`].
    rerun_only: bool,
    /// See [`Rewritten::workspace_symlinked`].
    workspace_symlinked: bool,
    /// See [`Rewritten::pnpm_named_registries`].
    named_registries: bool,
    /// See [`Rewritten::pnpm_route_note`].
    route_note: Option<String>,
    /// The run took a route out of a workspace file hosted mode created
    /// and plans no other setting for it: `config_write` is the file's
    /// bare `packages` list ([`Rewritten::pnpm_workspace_emptied`]).
    emptied: bool,
}

/// pnpm >=11 enforces a lockfile supply-chain policy: it compares each
/// resolution's tarball URL against the registry's published metadata and
/// REFUSES a lock whose URLs differ: pnpm 11 with
/// ERR_PNPM_TARBALL_URL_MISMATCH (ERR_PNPM_META_FETCH_FAIL when the
/// registry is unreachable), pnpm 12 with
/// ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION, whose own text tells users
/// to rebuild the lock — which silently discards the redirect, so the
/// warning must pre-empt that advice. The working recoveries are
/// `pnpm install --trust-lockfile` and the pnpm-workspace.yaml
/// `trustLockfile: true` key; the `.npmrc` `trust-lockfile=true` spelling
/// is IGNORED by pnpm and must never be recommended.
///
/// ZERO-TOUCH DEFAULT: when this run rewrote a GOVERNING pnpm lock (the
/// root pnpm-lock.yaml, or a workspace member's own lock under
/// `sharedWorkspaceLockfile: false`, #492) and its lockfileVersion is >= 9
/// (5.x/6.0 locks mean pnpm 7/8, which have neither the policy nor the
/// flag and get their own guidance), the run configures the root
/// pnpm-workspace.yaml, the only one pnpm reads for every member, so
/// pnpm >=11 installs the lock. The same auto-config re-engages on a run
/// that spliced NOTHING when a governing v9 lock already carries a granted
/// hosted artifact URL (HEAL-ON-RERUN).
///
/// NAMED REGISTRIES, when `route` ([`pnpm_route`]) settled on them: every
/// hosted tarball of the governing locks is routed through the patch
/// server's one-package registry of its patch, which pnpm-workspace.yaml
/// declares and overrides the release with, so pnpm's verification stays
/// on for the whole lock and a command that resolves again keeps the
/// patched package. The route has already put the locks in that shape;
/// what is left here is the workspace file and the warning.
///
/// TRUST, otherwise: the run auto-ensures `trustLockfile: true`, which
/// switches the verification off for every entry.
/// pnpm <=10 ignores the key; the per-entry sha512 pin still fails closed
/// on tampered bytes. An explicit user `trustLockfile: <non-true>` is
/// RESPECTED (never flipped), and `--no-trust-lockfile-config` opts out of
/// either write.
/// Rush common/subspace locks (`rush_lock_keys`) are excluded from the
/// write: rush runs pnpm in common/temp with a pnpm-workspace.yaml it
/// generates, which never reads the repo-root one. When every spliced lock
/// is a Rush lock the warning carries the Rush remedy instead of the
/// pnpm-only one (#713); a run that also spliced a non-Rush pnpm lock keeps
/// the generic text plus a Rush note. The warning names the host(s) the
/// lock now points at (they follow --api-url).
#[allow(clippy::too_many_arguments)]
fn pnpm_trust(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    member_lock_keys: &[String],
    rewrite: &RewriteResult,
    rush_lock_keys: &[String],
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
    route: PnpmRoute,
) -> PnpmTrust {
    use crate::formats::pnpm::named_registries::Plan;

    let mut out = PnpmTrust::default();
    // A lock the route only tidied (no hosted pin of this run in it) was
    // not spliced: it needs no trust and no warning.
    let spliced = |key: &str| rewrite.files.contains_key(key) && !route.pruned.contains(key);
    // pnpm locks spliced THIS run (any depth — the rewriter is
    // basename-generalized).
    let (spliced_keys, mut pnpm_lock_texts): (Vec<&String>, Vec<&String>) = rewrite
        .files
        .iter()
        .filter(|(key, _)| {
            spliced(key)
                && std::path::Path::new(key)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| matches!(name, "pnpm-lock.yaml" | "shrinkwrap.yaml"))
        })
        .unzip();
    // Rush locks spliced this run. The heal and takeover roots below are
    // only ever governing locks, never a Rush one.
    let mut spliced_rush = spliced_keys
        .iter()
        .filter(|key| rush_lock_keys.contains(key))
        .count();
    let governing = governing_pnpm_locks(files, member_lock_keys, rush_lock_keys);
    // HEAL-ON-RERUN: a governing v9 lock that ALREADY carries a granted
    // hosted artifact URL (spliced by an earlier run) still plans the trust
    // config even though this run spliced nothing — so a project that
    // missed the config once (opted-out first run, or a crash between the
    // lock write and the workspace write) is healed by simply re-running
    // the scan. An AlreadyTrue workspace keeps the re-run a byte-stable
    // no-op.
    let heal_locks: Vec<&String> = governing
        .iter()
        .filter_map(|key| pnpm_heal_root(spliced(key), files.get(*key), overrides))
        .collect();
    let spliced_pnpm_locks = pnpm_lock_texts.len();
    pnpm_lock_texts.extend(heal_locks.iter().copied());
    // HEAL-ON-RERUN for Rush: a common/subspace v9 lock an earlier run
    // already redirected splices nothing now, but its `rush install` still
    // needs the Rush trust remedy (#713) — nothing persists it, so it is
    // re-issued on every run. Same gate as the governing heal; never
    // configured.
    for key in rush_lock_keys {
        if let Some(text) =
            pnpm_heal_root(rewrite.files.contains_key(key), files.get(key), overrides)
        {
            pnpm_lock_texts.push(text);
            spliced_rush += 1;
        }
    }
    if pnpm_lock_texts.is_empty() {
        return out;
    }
    // Name only the hosts whose artifact URL actually landed in a touched
    // pnpm lock's final text (spliced this run, or the already-redirected
    // heal root): an npm override may have matched only a sibling lock
    // (e.g. package-lock.json), and naming its host here would point users
    // at a server the pnpm lock never references. Same needles as the
    // confirmation probe.
    let npm_overrides: Vec<_> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    let groups: Vec<Vec<String>> = npm_overrides
        .iter()
        .map(|o| npm_lock_url_needles(&o.artifact_url))
        .collect();
    let present = groups_present(&pnpm_lock_texts, &groups);
    let mut hosts: Vec<&str> = npm_overrides
        .iter()
        .zip(present)
        .filter(|(_, present)| *present)
        .filter_map(|(o, _)| url_host(&o.artifact_url))
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let server = if hosts.is_empty() {
        "the hosted patch server".to_string()
    } else {
        format!("the hosted patch server ({})", hosts.join(", "))
    };
    // Governing-lock gate: only a governing lock (never a Rush one) at
    // lockfileVersion >= 9 gets the auto-config — spliced this run, or
    // detected already-redirected (heal path).
    let is_v9 = |text: &String| pnpm_lock_version_major(text).is_some_and(|major| major >= 9);
    let governing_lock_v9 = heal_locks.iter().copied().any(is_v9)
        || governing
            .iter()
            .filter(|key| spliced(key))
            .filter_map(|key| rewrite.files.get(*key))
            .any(is_v9);
    // Every touched pnpm lock is a KNOWN legacy (5.x/6.0) format, where
    // `--trust-lockfile` is rejected as an unknown option. An unparseable
    // version stays on the manual guidance: never claim "no trust step
    // needed" for a lock whose era is unknown.
    let all_locks_legacy = pnpm_lock_texts.iter().all(|text| {
        pnpm_lock_version_major(text).is_some_and(|major| major < 9)
            || pnpm_is_shrinkwrap_lock(text)
    });
    let rush_only = spliced_rush > 0 && spliced_rush == pnpm_lock_texts.len();
    // A governing v9 lock is what either auto-config serves, and what the
    // route was settled for. In a workspace member with its own lock the
    // settings live in the workspace root's file, which this run never
    // writes.
    debug_assert_eq!(
        route.engaged,
        governing_lock_v9 && !all_locks_legacy && !rush_only
    );
    let PnpmRoute {
        member_root,
        workspace: root_workspace,
        registry,
        blocked,
        pin_hint,
        unrouted,
        kept,
        ..
    } = route;
    // What a routed project is told of a release the route may reach.
    out.route_note = registry
        .as_ref()
        .and_then(|route| crate::hosted::guidance::pnpm_registry_in_range_note(&route.also_locked));
    let detail = if all_locks_legacy {
        pnpm_trust_legacy_detail(&server)
    } else if rush_only {
        pnpm_trust_rush_detail(&server)
    } else if let Some(registry) = registry {
        let (_, symlinked) = root_workspace.unwrap_or_else(|| read_workspace(view));
        out.named_registries = true;
        out.workspace_symlinked = symlinked;
        let (text, changes, write) = match registry.plan {
            Plan::Create(text, changes) => (text, changes, RegistryWrite::Created),
            Plan::Scaffold(text, changes) => (text, changes, RegistryWrite::Scaffolded),
            Plan::Edit(text, changes) => (text, changes, RegistryWrite::Merged),
            // [`pnpm_route`] keeps a file it cannot edit on the trust path.
            Plan::InSync | Plan::Unsupported(_) => {
                (String::new(), Vec::new(), RegistryWrite::Merged)
            }
        };
        if changes.is_empty() {
            out.rerun_only = spliced_pnpm_locks == 0;
            pnpm_registry_already_detail(&server, registry.trust)
        } else {
            let mut edits = Vec::new();
            if registry.trust == TrustLeftover::Removed {
                edits.push(FileEdit {
                    path: PNPM_WORKSPACE_REL.into(),
                    kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
                    action: "removed".into(),
                    key: Some("trustLockfile".into()),
                    original: Some(serde_json::json!("true")),
                    new: None,
                });
            }
            edits.extend(workspace_route_edits(
                changes,
                write == RegistryWrite::Created,
            ));
            out.config_write = Some((text, edits));
            pnpm_registry_configured_detail(&server, write, registry.trust, options.dry_run)
        }
    } else if kept {
        // The route of an earlier run, left as it is for a Bazel hub: it
        // is what verifies the hosted entries, so the file is not written.
        let (workspace, _) = root_workspace.unwrap_or_else(|| read_workspace(view));
        let leftover = match workspace {
            Ok(Some(text))
                if matches!(plan_workspace_trust(Some(&text)), TrustPlan::AlreadyTrue) =>
            {
                TrustLeftover::Left
            }
            _ => TrustLeftover::None,
        };
        out.named_registries = true;
        out.rerun_only = spliced_pnpm_locks == 0;
        pnpm_registry_already_detail(&server, leftover)
    } else if !governing_lock_v9 || !options.trust_lockfile_config {
        pnpm_trust_manual_guidance(&server)
    } else if let Some(root_file) = member_root {
        // A workspace member with its own lock: pnpm reads `trustLockfile`
        // only from the workspace root's file, and a nested one would be
        // ignored (#880). The governing-root pre-check refused every root
        // file but these two, so nothing is written here.
        // One above the repository root is never read (the pre-check
        // refuses it; this keeps the read bounded on its own).
        let readable = view.disk_root().is_some_and(|root| {
            crate::utils::repo_root::upward_readable(
                crate::utils::repo_root::ReadScope::Workspace,
                root,
                &root_file,
            )
        });
        let root_file = root_file.display().to_string();
        if let Some(found) = pnpm_trust_env_override(view, files, options.pnpm_env) {
            pnpm_trust_env_set_detail(&server, &found.source)
        } else {
            match readable
                .then(|| read_workspace_for_trust(std::path::Path::new(&root_file)))
                .and_then(Result::ok)
                .flatten()
                .map(|text| plan_workspace_trust(Some(&text)))
            {
                Some(TrustPlan::AlreadyTrue) => {
                    out.rerun_only = spliced_pnpm_locks == 0;
                    pnpm_trust_already_true_detail(&server, &root_file)
                }
                Some(TrustPlan::UserSet(value)) => {
                    pnpm_trust_user_set_detail(&server, &root_file, &value)
                }
                _ => pnpm_trust_manual_guidance(&server),
            }
        }
    } else {
        let (workspace, symlinked) = root_workspace.unwrap_or_else(|| read_workspace(view));
        out.workspace_symlinked = symlinked;
        // An earlier run's registry routing came back out of the locks:
        // the trust key goes into the file without its two maps, and that
        // file is written whether or not the key is.
        let unrouted_file = match &unrouted {
            Some(Ok(Some(unrouted))) => Some(unrouted.clone()),
            _ => None,
        };
        // A file hosted mode created holds nothing of the user's once the
        // route is out of it: its `packages` list is the scaffold the route
        // came with. Whether the project should have a workspace file at
        // all is then decided as for a project with none (no file for one
        // pinned to pnpm 9.0–10.4, #734; none under a `trustLockfile`
        // variable of the environment).
        let created = unrouted_file
            .as_ref()
            .is_some_and(|unrouted| unrouted.created);
        let workspace = match &unrouted_file {
            Some(unrouted) => workspace.map(|_| Some(unrouted.text.clone())),
            None => workspace,
        };
        let trust_edit = |action: &str| FileEdit {
            path: PNPM_WORKSPACE_REL.into(),
            kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
            action: action.into(),
            key: Some("trustLockfile".into()),
            original: None,
            new: Some(serde_json::json!("true")),
        };
        // No workspace file (or one with no keys, which pnpm reads the
        // same) and a project pinned to pnpm 9.0–10.4: creating one would
        // make it a root-only workspace those releases refuse `pnpm add`
        // in, for a key they never read (#734, #1096).
        let pinned_pre_10_5 = match &workspace {
            Ok(text)
                if !symlinked
                    && (created
                        || text
                            .as_deref()
                            .is_none_or(crate::formats::pnpm::workspace::is_keyless)) =>
            {
                root_only_workspace_breaks_add(view)
            }
            _ => None,
        };
        // A keyless file the lock was installed from as a multi-package
        // workspace: only pnpm <= 10.4 reads one that way (every nested
        // package), and the root-only scaffold would drop those members.
        let env_override = pnpm_trust_env_override(view, files, options.pnpm_env);
        let keyless_members = pinned_pre_10_5.is_none()
            && !symlinked
            && matches!(&workspace, Ok(Some(text)) if crate::formats::pnpm::workspace::is_keyless(text))
            && lock_lists_members(view);
        let detail = match workspace {
            Ok(_) if keyless_members => pnpm_trust_keyless_members_detail(&server, options.dry_run),
            Ok(_) if pinned_pre_10_5.is_some() => pnpm_trust_not_needed_detail(
                &server,
                pinned_pre_10_5.as_deref().unwrap_or_default(),
                options.dry_run,
            ),
            // pnpm 11+ read the environment's `trustLockfile` ahead of
            // the file (#1514): an explicit setting nothing written there
            // could override.
            Ok(_) if env_override.is_some() => pnpm_trust_env_set_detail(
                &server,
                &env_override
                    .as_ref()
                    .map(|found| found.source.clone())
                    .unwrap_or_default(),
            ),
            // Present but UNREADABLE: never plan a Create (it would
            // overwrite the user's workspace file) — fall back to
            // warning-only guidance naming the file and the error.
            Err(e) => pnpm_trust_workspace_unreadable_detail(&server, &e),
            Ok(ws_existing) => match plan_workspace_trust(ws_existing.as_deref()) {
                TrustPlan::Create(text) => {
                    out.config_write = Some((text, vec![trust_edit("created")]));
                    pnpm_trust_configured_detail(&server, true, options.dry_run)
                }
                TrustPlan::Append(text) => {
                    out.config_write = Some((text, vec![trust_edit("added")]));
                    pnpm_trust_configured_detail(&server, false, options.dry_run)
                }
                TrustPlan::Scaffold(text) => {
                    out.config_write = Some((text, vec![trust_edit("added")]));
                    pnpm_trust_scaffolded_detail(&server, options.dry_run)
                }
                TrustPlan::AlreadyTrue => {
                    out.rerun_only = spliced_pnpm_locks == 0;
                    let detail = pnpm_trust_already_true_detail(&server, PNPM_WORKSPACE_REL);
                    // The root-only scaffold an earlier run created (4.x and
                    // early v5 did so whatever the pnpm), in a project pinned
                    // to a pnpm that refuses `pnpm add` there (#734).
                    match ws_existing
                        .as_deref()
                        .filter(|text| is_trust_scaffold(text))
                        .and_then(|_| root_only_workspace_breaks_add(view))
                    {
                        Some(pins) => format!("{detail} {}", pnpm_scaffold_breaks_add_note(&pins)),
                        None => detail,
                    }
                }
                TrustPlan::UserSet(value) => {
                    pnpm_trust_user_set_detail(&server, PNPM_WORKSPACE_REL, &value)
                }
                TrustPlan::Unsupported(why) => {
                    pnpm_trust_workspace_unsupported_detail(&server, &why)
                }
            },
        };
        if let Some(unrouted) = unrouted_file {
            let planned = out.config_write.take();
            // Nothing else is planned for a file the route created: what is
            // written back is its bare scaffold, the caller's to delete.
            out.emptied = unrouted.created && planned.is_none();
            let (text, mut edits) = planned.unwrap_or((unrouted.text, Vec::new()));
            edits.splice(0..0, unrouted.edits);
            out.config_write = Some((text, edits));
        }
        detail
    };
    // What a project that qualifies for the registry route is told about
    // staying on trust.
    let notes: Vec<String> = [
        (!blocked.is_empty()).then(|| match kept {
            true => crate::hosted::guidance::pnpm_registry_kept_note(&blocked),
            false => pnpm_registry_blocked_note(&blocked),
        }),
        unrouted.as_ref().map(|outcome| {
            pnpm_registry_unrouted_note(
                outcome.as_ref().map(|_| ()).map_err(String::as_str),
                options.dry_run,
            )
        }),
        pin_hint.then(|| PNPM_REGISTRY_PIN_HINT.to_string()),
        out.route_note.clone(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let detail = notes.iter().fold(detail, |detail, note| {
        format!("{}. {note}", detail.trim_end_matches('.'))
    });
    // The `--store` spelling only matters to pnpm 1–4, so it is named only
    // when a touched lock may be that old.
    let store_note = if pnpm_lock_texts
        .iter()
        .any(|text| pnpm_lock_may_need_store_flag(text))
    {
        " (pnpm 1–4 spell the option `--store`)"
    } else {
        ""
    };
    // Rush keeps its own store under common/temp and the Rush detail
    // carries its own reinstall advice; the legacy text is right for Rush on
    // pnpm 7/8 as well, so it keeps the generic tail.
    let message = if rush_only && !all_locks_legacy {
        format!("{detail}.")
    } else {
        let rush_note = if spliced_rush > 0 && !all_locks_legacy {
            format!(" {PNPM_TRUST_RUSH_MIXED_NOTE}.")
        } else {
            String::new()
        };
        format!(
            "{}. After a lock-only change, existing node_modules or a warm pnpm store \
             can still contain upstream files. For a reliable reinstall, use a clean \
             node_modules tree and an empty store with \
             `pnpm install --frozen-lockfile --store-dir <new-empty-directory>`\
             {store_note}. Do not rely on `--force`: some versions re-resolve the \
             upstream artifact. Run `socket-patch vex` after installation to verify \
             the patched files.{rush_note}",
            detail.trim_end_matches('.')
        )
    };
    out.warnings
        .push(warning("redirect_pnpm_trust_lockfile", message));
    out
}

/// The locks pnpm installs the project from: the root lock, plus each
/// member's own under `sharedWorkspaceLockfile: false` (#492). A Rush lock
/// is never one: rush installs it from common/temp. The root lock is the
/// one pnpm reads (N11): `shrinkwrap.yaml` under a pnpm 1 / 2 pin, so a
/// stray `pnpm-lock.yaml` never drives the heal or the workspace config.
/// What [`respell_earlier_route`] changed: the governing locks it
/// respelled (their new text is in the files map), and the edits.
#[derive(Default)]
struct Respelled {
    keys: Vec<String>,
    edits: Vec<FileEdit>,
}

/// MIGRATION, before any rewriter reads a lock. An unreleased build keyed
/// a routed release through a registry under another name: the whole
/// patch UUID (`left-pad@socket-patch-<uuid>:1.3.0`), or one registry for
/// the project (`left-pad@socket:1.3.0`, `socket-patch`, either with a
/// number). The lock readers take only a registry named `socket-<hex>`
/// for hosted mode's on sight; those other names are as likely a registry
/// of the project's own, whose release is not the npm one, and nothing of
/// the user's may be repointed. They are ours only where the workspace
/// file proves it ([`crate::formats::pnpm::named_registries::Owned`]): a
/// declaration at an address that build wrote, on a patch server.
///
/// With that proof, each such key of a governing lock is respelled under
/// the name its patch gives the registry today (the patch is the one the
/// entry's tarball is served for), so that every later step reads one
/// shape. The workspace file is left to the route, which replaces what is
/// ours in it. Without the proof, or when a lock cannot be respelled
/// whole, the lock is left as it is.
fn respell_earlier_route(
    view: &ProjectView<'_>,
    files: &mut BTreeMap<String, String>,
    member_lock_keys: &[String],
    rush_lock_keys: &[String],
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
) -> Respelled {
    use crate::formats::pnpm::named_registries::{is_current_alias, Address, Owned};
    use crate::formats::pnpm::registry_alias::{AliasPin, OverrideLock, Pinned};
    use crate::formats::pnpm::PnpmLock;

    let mut out = Respelled::default();
    // `--no-trust-lockfile-config` keeps the workspace file as it is, and
    // the locks with it.
    if !options.trust_lockfile_config || governing_workspace(view).is_some() {
        return out;
    }
    let (Ok(Some(workspace)), false) = read_workspace(view) else {
        return out;
    };
    let owned = Owned::of(Some(&workspace), &|origin| {
        is_patch_server(origin, overrides, options)
    });
    let governing: Vec<String> = governing_pnpm_locks(files, member_lock_keys, rush_lock_keys)
        .into_iter()
        .map(str::to_string)
        .collect();
    for key in governing {
        let Some(text) = files.get(&key).cloned() else {
            continue;
        };
        if pnpm_lock_version_major(&text) != Some(9) {
            continue;
        }
        let Ok(mut lock) = OverrideLock::parse(&text, &owned) else {
            continue;
        };
        let earlier: Vec<_> = lock
            .aliased()
            .into_iter()
            .filter(|pin| !is_current_alias(&pin.alias))
            .collect();
        if earlier.is_empty() {
            continue;
        }
        let parsed = PnpmLock::parse(&text);
        let respell = |lock: &mut OverrideLock| -> Option<Vec<FileEdit>> {
            let mut edits = Vec::new();
            for pin in &earlier {
                let entry = format!("{}@{}:{}", pin.name, pin.alias, pin.version);
                let resolution = parsed
                    .packages()
                    .iter()
                    .find(|package| package.key == entry)?
                    .resolution
                    .as_ref()?;
                let (tarball, integrity) = (resolution.tarball()?, resolution.integrity()?);
                // The patch the entry is pinned to: the one its tarball's
                // directory is named after.
                let patch = Address::parse(&tarball[..=tarball.rfind('/')?])?;
                let alias = owned.name_for(&patch.uuid, &BTreeSet::new())?;
                let pinned = lock.pin(&AliasPin {
                    name: &pin.name,
                    version: &pin.version,
                    alias: &alias,
                    integrity,
                    tarball,
                });
                if let Pinned::Rewritten { from } = pinned.ok()? {
                    edits.push(FileEdit {
                        path: key.clone(),
                        kind: REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND.into(),
                        action: "rewritten".into(),
                        key: Some(pin.key()),
                        original: Some(serde_json::Value::String(from)),
                        new: Some(serde_json::Value::String(format!(
                            "{}@{alias}:{}",
                            pin.name, pin.version
                        ))),
                    });
                }
            }
            lock.finish().ok()?;
            Some(edits)
        };
        let Some(edits) = respell(&mut lock) else {
            continue;
        };
        if let Some(respelled) = lock.render() {
            files.insert(key.clone(), respelled);
            out.keys.push(key);
            out.edits.extend(edits);
        }
    }
    out
}

fn governing_pnpm_locks<'a>(
    files: &BTreeMap<String, String>,
    member_lock_keys: &'a [String],
    rush_lock_keys: &[String],
) -> Vec<&'a str> {
    std::iter::once(crate::formats::pnpm::plan::root_lock(files))
        .chain(member_lock_keys.iter().map(String::as_str))
        .filter(|key| !rush_lock_keys.iter().any(|rush| rush == key))
        .collect()
}

/// The edits behind a pnpm-workspace.yaml change of the registry route,
/// one per entry of either map.
fn workspace_route_edits(
    changes: Vec<crate::formats::pnpm::named_registries::Change>,
    created: bool,
) -> impl Iterator<Item = FileEdit> {
    use crate::formats::pnpm::named_registries::MapKind;
    changes.into_iter().map(move |change| {
        let action = match (&change.from, &change.to) {
            _ if created => "created",
            (None, _) => "added",
            (Some(_), Some(_)) => "rewritten",
            (Some(_), None) => "removed",
        };
        FileEdit {
            path: PNPM_WORKSPACE_REL.into(),
            kind: match change.map {
                MapKind::Registry => REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                MapKind::Override => REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
            }
            .into(),
            action: action.into(),
            key: Some(change.key),
            original: change.from.map(serde_json::Value::String),
            new: change.to.map(serde_json::Value::String),
        }
    })
}

/// How a run gets the hosted pins of its governing pnpm locks past pnpm's
/// lockfile verification ([`pnpm_route`]).
#[derive(Default)]
struct PnpmRoute {
    /// A governing lockfileVersion >= 9 lock holds a granted hosted
    /// tarball (spliced by this run or an earlier one): the run configures
    /// pnpm-workspace.yaml one way or the other.
    engaged: bool,
    /// The ancestor pnpm-workspace.yaml that governs this project's pnpm
    /// settings, when the project is a workspace member with its own lock.
    member_root: Option<std::path::PathBuf>,
    /// The root pnpm-workspace.yaml as [`read_workspace`] read it, when
    /// the project's own file is the one pnpm reads.
    workspace: Option<(std::io::Result<Option<String>>, bool)>,
    /// The registry route, taken: the governing locks are in its shape.
    registry: Option<RegistryRoute>,
    /// What keeps a project the patch service offers the registry route
    /// to on `trustLockfile`, each as a clause.
    blocked: Vec<String>,
    /// Only the missing pnpm pin keeps the project on `trustLockfile`.
    pin_hint: bool,
    /// An earlier run took the registry route and this one does not: the
    /// workspace file without that route's entries (`None` when it held
    /// none), or why the governing locks could not be put back in the
    /// plain shape.
    unrouted: Option<Result<Option<Unrouted>, String>>,
    /// The governing locks a run that touches no hosted pnpm pin tidied
    /// ([`pnpm_prune`]): rewritten, but not for a pin that needs trust.
    pruned: BTreeSet<String>,
    /// That tidying left a workspace file a run created with nothing but
    /// its `packages` list ([`Rewritten::pnpm_workspace_emptied`]).
    emptied: bool,
    /// A Bazel hub keeps the root lock out of the run, so the route of an
    /// earlier run is left as it is (`unrouted` says so), and it is all
    /// the governing locks hold: every hosted tarball in them is under a
    /// key of its registry, which pnpm verifies it through. The workspace
    /// file then needs nothing from this run and is left byte for byte,
    /// without a `trustLockfile` that would switch the verification off
    /// for every entry of a project still on per-package registries.
    ///
    /// Not so where the route stays because a lock could not be converted
    /// back: that project no longer qualifies for the route (a pnpm that
    /// does not read it, say), and the trust key is what it falls back on.
    kept: bool,
}

/// Whether a governing lock (`texts`, by key, as the run leaves them)
/// records a Socket-hosted tarball under a plain key: a pin that pnpm takes
/// only with `trustLockfile`. One under a key that names a registry of
/// ours (`leaf@socket-58f14d5a:1.0.0`) is verified through that registry.
/// Read with the tolerant lock reader, so that a lock the route's edits
/// cannot read still answers.
fn holds_trust_pin(
    texts: &[(&str, &String)],
    overrides: &[DepOverride],
    owned: &crate::formats::pnpm::named_registries::Owned,
) -> bool {
    use crate::formats::pnpm::PnpmLock;

    let hosted = |tarball: &str| {
        overrides
            .iter()
            .any(|o| o.ecosystem == "npm" && o.artifact_url == tarball)
            || crate::origin::hosted_shape_uuid(tarball).is_some()
    };
    // The registry a key spells its version through, as
    // [`OverrideLock::aliased`](crate::formats::pnpm::registry_alias::OverrideLock::aliased)
    // reads it.
    let routed = |key: &str| {
        let version = key
            .get(1..)
            .and_then(|rest| rest.find('@'))
            .map(|at| at + 2);
        version
            .and_then(|at| key[at..].split_once(':'))
            .is_some_and(|(registry, _)| owned.alias(registry))
    };
    texts.iter().any(|(_, text)| {
        PnpmLock::parse(text).packages().iter().any(|package| {
            let tarball = package.resolution.as_ref().and_then(|r| r.tarball());
            tarball.is_some_and(hosted) && !routed(package.key)
        })
    })
}

/// The registry route's pnpm-workspace.yaml edit.
struct RegistryRoute {
    plan: crate::formats::pnpm::named_registries::Plan,
    /// What becomes of a `trustLockfile: true` in the file.
    trust: TrustLeftover,
    /// Routed releases a governing lock also holds a newer release of,
    /// within the routed one's caret range: `(name, version, the other
    /// versions)` ([`crate::hosted::guidance::pnpm_registry_in_range_note`]).
    also_locked: Vec<(String, String, Vec<String>)>,
}

/// pnpm-workspace.yaml once an earlier run's registry route is taken back
/// out of it.
#[derive(Clone)]
pub(crate) struct Unrouted {
    pub(crate) text: String,
    pub(crate) edits: Vec<FileEdit>,
    /// The file held nothing but what hosted mode created it with: without
    /// the route it is the `packages` scaffold alone, and a caller that
    /// deletes files deletes it.
    pub(crate) created: bool,
}

/// Why a run stays on `trustLockfile`.
enum RouteBlock {
    /// The project is not one the registry route is for, or the patch
    /// service offers it none: today's trust path, with nothing to add.
    NotEligible,
    /// Eligible but for a pnpm pin.
    Unpinned,
    /// Eligible, and `--no-trust-lockfile-config` keeps the workspace file
    /// from being written.
    OptedOut,
    /// Eligible but for what these clauses name.
    Because(Vec<String>),
}

/// Whether `origin` (`http(s)://host[:port]`) is a patch server's:
/// Socket's own, one the operator configured, or the one a grant of this
/// run is served from. A grant moved onto a patch mirror
/// ([`mirror_candidates`]) names the mirror in its artifact URL, and the
/// rest of a mirror's host is not a patch server; its registry address
/// still names the patch server it came from.
fn is_patch_server(origin: &str, overrides: &[DepOverride], options: &RewriteOptions<'_>) -> bool {
    let on = |url: &str| {
        url.strip_prefix(origin)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    crate::origin::on_patch_server_origin(origin, &options.patch_server_origins)
        || overrides.iter().any(|o| {
            o.ecosystem == "npm"
                && ((on(&o.artifact_url)
                    && !crate::origin::on_mirror(&o.artifact_url, &options.patch_server_origins))
                    || o.npm_registry_url.as_deref().is_some_and(on))
        })
}

/// Settle how the hosted pins of the governing pnpm locks get past pnpm's
/// lockfile verification, and put the locks in that route's shape.
///
/// THE REGISTRY ROUTE. The patch service answers the npm registry
/// document of each patch under the directory the patch's tarball is
/// served from: an address that is fixed for the life of the patch.
/// Declared in pnpm-workspace.yaml as a named registry (`socket-<id>`,
/// the first digits of the patch UUID), it is what pnpm verifies the lock
/// entry against; named by an override of the patched release
/// (`name@version` → `socket-<id>:version`), it is also where pnpm
/// resolves the package whenever it resolves again, so `pnpm add`,
/// `update` and `dedupe` keep the patched tarball. pnpm writes such a
/// release under its own key (`name@socket-<id>:version`) and records the
/// override in the lock, so the route rewrites every governing lock to
/// exactly what pnpm would write
/// ([`OverrideLock`](crate::formats::pnpm::registry_alias::OverrideLock)):
/// a lock that only named the patched tarball would be out of date to
/// pnpm the moment the override exists.
///
/// It is taken only when all of this holds; anything short keeps the run
/// on `trustLockfile`, the locks in the plain shape the rewriters left:
///
/// * the project's own root pnpm-workspace.yaml is the file pnpm reads
///   (not a workspace member with its own lock), and every governing lock
///   is lockfileVersion 9 (a Rush lock is never governing);
/// * every hosted tarball of those locks has a registry: this run was
///   granted it with a registry address ([`pnpm_hosted_pins`]), or an
///   earlier run routed it, this run was not granted it, and the project's
///   files still route it ([`kept_route`]), so a scan of part of a
///   project leaves the rest routed. A lock half routed would fail to
///   install. A patch service that gives no pin an address offers no
///   route, and the run is today's, byte for byte (unless an earlier run
///   routed the project, which is then told why it leaves the route);
/// * the project's pnpm pins prove pnpm 11.20 or newer
///   ([`pnpm_route_pins`]): older releases write another lock for the same
///   override. No pin at all is told what a pin would change
///   ([`PNPM_REGISTRY_PIN_HINT`]);
/// * the workspace file can be read, is not a keyless file the lock was
///   installed from as a multi-package workspace (#1096), is a shape a
///   line splice can extend, and leaves each registry a name
///   ([`Owned::name_for`](crate::formats::pnpm::named_registries::Owned::name_for));
/// * no override of the user's targets a patched package (pnpm applies one
///   override per dependency, so ours would lose or displace it), each
///   lock is one the override edits were captured against, and no package
///   version is pinned to two patches ([`release_with_two_patches`]);
/// * the workspace file may be written, or needs no write
///   (`--no-trust-lockfile-config`);
/// * no rules_js hub of a Bazel workspace reads a governing lock
///   ([`crate::bazel::pnpm::Reader`]): the pnpm such a hub runs with
///   `update_pnpm_lock` may not see the workspace file, or be too old to
///   read its registries.
///
/// Whatever keeps a project the service offers the route to off it is
/// said in the warning ([`pnpm_registry_blocked_note`]), the pins without
/// an address by name: `trustLockfile` switches the verification off for
/// the whole lock.
///
/// Nothing of the route outlives its use. A project an earlier run routed
/// and that no longer qualifies is put back whole: the locks in the plain
/// shape, the workspace file without the route's entries
/// ([`pnpm_unroute`]). And a run that touches no hosted pnpm pin at all
/// still takes out what no lock references any more ([`pnpm_prune`]); a
/// workspace file a run created is then deleted rather than left as a bare
/// `packages` list ([`Rewritten::pnpm_workspace_emptied`]).
/// Neither under `--no-trust-lockfile-config`, which leaves the file, and
/// so the locks, as they are; and neither while a Bazel hub keeps the root
/// lock out of the run ([`crate::bazel::pnpm::Hubs::hidden`]): that lock
/// records the overrides too and is not written, so the route stays as it
/// is in the file and in the locks that were read.
///
/// `bazel` is what the Bazel workspace says of these locks, read with the
/// files ([`CandidateFiles::pnpm_bazel`]): nothing of Bazel is read here.
#[allow(clippy::too_many_arguments)]
fn pnpm_route(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    member_lock_keys: &[String],
    rewrite: &mut RewriteResult,
    rush_lock_keys: &[String],
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
    bazel: &crate::bazel::pnpm::Hubs,
) -> PnpmRoute {
    use crate::formats::pnpm::named_registries::Owned;

    let root_withheld = bazel.hidden.is_some();

    let mut route = PnpmRoute::default();
    let governing = governing_pnpm_locks(files, member_lock_keys, rush_lock_keys);
    let is_v9 = |text: &String| pnpm_lock_version_major(text).is_some_and(|major| major >= 9);
    // Every governing lock as the rewriters left it.
    let texts: Vec<(&str, String)> = governing
        .iter()
        .filter_map(|key| {
            let text = rewrite.files.get(*key).or_else(|| files.get(*key))?;
            Some((*key, text.clone()))
        })
        .collect();
    if texts.is_empty() {
        return route;
    }
    // The gate of the trust auto-config (see [`pnpm_trust`]).
    route.engaged = governing.iter().any(|key| match rewrite.files.get(*key) {
        Some(text) => is_v9(text),
        None => pnpm_heal_root(false, files.get(*key), overrides).is_some(),
    });
    route.member_root = governing_workspace(view);
    if route.member_root.is_some() {
        return route;
    }
    let (workspace, symlinked) = read_workspace(view);
    let owned = Owned::of(
        workspace.as_ref().ok().and_then(|text| text.as_deref()),
        &|origin| is_patch_server(origin, overrides, options),
    );
    let put_back = |rewrite: &mut RewriteResult, cleaned: Cleaned| {
        let mut keys = BTreeSet::new();
        for (key, text) in cleaned.locks {
            keys.insert(key.clone());
            rewrite.files.insert(key, text);
        }
        rewrite.edits.extend(cleaned.lock_edits);
        (keys, cleaned.workspace)
    };
    if !route.engaged {
        // No hosted pin of this run in these locks: nothing to configure,
        // but what an earlier run routed and no lock holds any more goes.
        if let (true, false, Ok(existing)) =
            (options.trust_lockfile_config, root_withheld, &workspace)
        {
            if let Some(pruned) = pnpm_prune(&texts, existing.as_deref(), &owned) {
                let (keys, workspace) = put_back(rewrite, pruned);
                route.pruned = keys;
                if let Some(Unrouted {
                    text,
                    edits,
                    created,
                }) = workspace
                {
                    rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
                    rewrite.edits.extend(edits);
                    route.emptied = created;
                }
            }
        }
        return route;
    }
    // A project an earlier run routed is told why it leaves the route,
    // whatever the patch service offers now.
    let was_routed = {
        use crate::formats::pnpm::named_registries::holds_ours;
        use crate::formats::pnpm::registry_alias::holds_route;
        matches!(&workspace, Ok(Some(text)) if holds_ours(text, &owned))
            || texts.iter().any(|(_, text)| holds_route(text, &owned))
    };
    match pnpm_registry_route(
        view, &texts, &workspace, symlinked, &owned, was_routed, overrides, options, bazel,
    ) {
        Ok(routed) => {
            for (key, text) in routed.locks {
                rewrite.files.insert(key, text);
            }
            rewrite.edits.extend(routed.edits);
            route.registry = Some(routed.route);
        }
        Err(block) => {
            let opted_out = matches!(block, RouteBlock::OptedOut);
            match block {
                RouteBlock::NotEligible | RouteBlock::OptedOut => {}
                RouteBlock::Unpinned => route.pin_hint = options.trust_lockfile_config,
                RouteBlock::Because(why) => route.blocked = why,
            }
            if let (true, false, Ok(existing)) =
                (options.trust_lockfile_config, opted_out, &workspace)
            {
                route.unrouted = if root_withheld {
                    // The root lock is not written, so nothing of the
                    // route is taken out of the file or of the other locks.
                    was_routed.then(|| {
                        Err(crate::hosted::guidance::PNPM_REGISTRY_ROOT_WITHHELD.to_string())
                    })
                } else {
                    pnpm_unroute(view, &texts, existing.as_deref(), &owned)
                        .map(|outcome| outcome.map(|unrouted| put_back(rewrite, unrouted).1))
                };
            }
            // The project stays routed as it was (the opt-out, a workspace
            // file that cannot be read, a lock that could not be converted
            // back): a release it routes stays on the patch it is routed to.
            if !matches!(route.unrouted, Some(Ok(_))) {
                let held = hold_routed_releases(files, rewrite, &governing, &owned);
                if !held.is_empty() {
                    rewrite.warnings.push(warning(
                        REDIRECT_PNPM_REGISTRY_HELD,
                        pnpm_registry_held_detail(&held, !options.trust_lockfile_config),
                    ));
                }
                // Left as it is for a Bazel hub, and nothing else to
                // serve: no trust key.
                if root_withheld && matches!(route.unrouted, Some(Err(_))) {
                    let left: Vec<(&str, &String)> = governing
                        .iter()
                        .filter_map(|key| {
                            let text = rewrite.files.get(*key).or_else(|| files.get(*key))?;
                            Some((*key, text))
                        })
                        .collect();
                    route.kept = !holds_trust_pin(&left, overrides, &owned);
                }
            }
        }
    }
    route.workspace = Some((workspace, symlinked));
    route
}

/// Warning code: a release the project routes through its patch's registry
/// has a newer patch, which this run could not move it to because it does
/// not update pnpm-workspace.yaml. The release is left on the patch it is
/// routed to, whole.
pub const REDIRECT_PNPM_REGISTRY_HELD: &str = "redirect_pnpm_registry_held";

/// The [`REDIRECT_PNPM_REGISTRY_HELD`] detail for `releases`
/// (`name@version`, sorted); `opted_out` under
/// `--no-trust-lockfile-config`.
fn pnpm_registry_held_detail(releases: &[String], opted_out: bool) -> String {
    let (names, stays, it_is, its, it) = match releases {
        [one] => (one.clone(), "stays", "it is", "its", "it"),
        many => (many.join(", "), "stay", "they are", "their", "them"),
    };
    let why = if opted_out {
        format!(
            "--no-trust-lockfile-config keeps {PNPM_WORKSPACE_REL}, which names the registry, \
             from being updated; re-run without the flag to move {it} to the newer patch"
        )
    } else {
        format!(
            "{PNPM_WORKSPACE_REL}, which names the registry, was not updated by this run; \
             the next run that can update it moves {it} to the newer patch"
        )
    };
    format!(
        "{names} {stays} on the patch {it_is} routed to: {its} newer patch is served from \
         another registry, and {why}"
    )
}

/// Put back the resolution of every release a governing lock keys by a
/// registry of ours and whose resolution the rewriters changed in this
/// run, for a run that leaves the project routed as it was. The registry
/// in the key, the override and the workspace file's declaration are the
/// old patch's: a new patch's tarball under them is one that registry does
/// not vouch for, so pnpm refuses the lock, and its next resolve fetches
/// the old patch again. The release stays on the patch it is routed to,
/// and is not confirmed. Returns the releases held (`name@version`).
fn hold_routed_releases(
    files: &BTreeMap<String, String>,
    rewrite: &mut RewriteResult,
    governing: &[&str],
    owned: &crate::formats::pnpm::named_registries::Owned,
) -> Vec<String> {
    use crate::formats::pnpm::registry_alias::{AliasPin, OverrideLock, Pinned};
    use crate::formats::pnpm::PnpmLock;

    let mut held: BTreeSet<String> = BTreeSet::new();
    for key in governing {
        let (Some(before), Some(after)) = (files.get(*key), rewrite.files.get(*key)) else {
            continue;
        };
        let Ok(mut lock) = OverrideLock::parse(after, owned) else {
            continue;
        };
        let was = PnpmLock::parse(before);
        let mut here: Vec<String> = Vec::new();
        for pin in lock.aliased() {
            let entry = format!("{}@{}:{}", pin.name, pin.alias, pin.version);
            let Some(resolution) = was
                .packages()
                .iter()
                .find(|package| package.key == entry)
                .and_then(|package| package.resolution.as_ref())
            else {
                continue;
            };
            let (Some(tarball), Some(integrity)) = (resolution.tarball(), resolution.integrity())
            else {
                continue;
            };
            let restored = lock.pin(&AliasPin {
                name: &pin.name,
                version: &pin.version,
                alias: &pin.alias,
                integrity,
                tarball,
            });
            if matches!(restored, Ok(Pinned::Rewritten { .. })) {
                here.push(pin.key());
            }
        }
        if here.is_empty() || lock.finish().is_err() {
            continue;
        }
        match lock.render() {
            Some(text) if text != *before => {
                rewrite.files.insert((*key).to_string(), text);
            }
            _ => {
                rewrite.files.remove(*key);
            }
        }
        rewrite.edits.retain(|edit| {
            !(edit.path == *key
                && edit.kind == "redirect_pnpm_resolution"
                && edit.key.as_deref().is_some_and(|instance| {
                    here.iter().any(|release| {
                        instance
                            .strip_prefix(release.as_str())
                            .is_some_and(|rest| rest.is_empty() || rest.starts_with('('))
                    })
                }))
        });
        held.extend(here);
    }
    held.into_iter().collect()
}

/// Whether hosted mode routed the pnpm project at `project_root` through
/// the patch server's named registry, or left something of that route
/// behind: the workspace file holds an entry of ours, or a lock keys a
/// release by a registry of ours or records an override of ours (the root
/// lock, or a member's own in a workspace that keeps one lock per member).
/// A caller asks before it decides what to read and lock; what is ours is
/// settled when the route is ([`pnpm_route`]).
///
/// Asked by every command that may tidy a route, of projects that mostly
/// never had one, so it reads as little as answers: the workspace file
/// first, which settles it for a routed project; the root lock only then;
/// the members' locks, listed once, only where the workspace keeps one
/// lock per member; and no lock is parsed unless its bytes name a route.
pub async fn pnpm_route_present(project_root: &std::path::Path) -> bool {
    use crate::formats::pnpm::named_registries::{holds_ours, Owned};
    use crate::formats::pnpm::registry_alias::holds_route;
    use crate::utils::fs::read_regular_to_string;
    use crate::utils::pnpm_workspace::{member_locks, MemberLocks};

    let workspace = read_regular_to_string(&project_root.join(PNPM_WORKSPACE_REL))
        .await
        .ok();
    let owned = Owned::of(workspace.as_deref(), &|_| true);
    if workspace
        .as_deref()
        .is_some_and(|text| holds_ours(text, &owned))
    {
        return true;
    }
    let root_lock = read_regular_to_string(&project_root.join(ROOT_PNPM_LOCKS[0])).await;
    if root_lock.is_ok_and(|lock| holds_route(&lock, &owned)) {
        return true;
    }
    // Without a workspace file there are no members to list.
    if workspace.is_none() {
        return false;
    }
    let view = ProjectView::Disk(project_root);
    let listing = member_locks(&view).await;
    matches!(listing, MemberLocks::PerMember(_))
        && member_lock_holds_route(&view, &listing, &owned).await
}

/// The registry route, planned: the governing locks it changes, the edits
/// that make them, and the workspace file's.
struct Routed {
    locks: Vec<(String, String)>,
    edits: Vec<FileEdit>,
    route: RegistryRoute,
}

/// Plan the registry route over the governing locks (`texts`, by key, as
/// the rewriters left them), or say why the run stays on `trustLockfile`
/// (see [`pnpm_route`]). Nothing is written here.
#[allow(clippy::too_many_arguments)]
fn pnpm_registry_route(
    view: &ProjectView<'_>,
    texts: &[(&str, String)],
    workspace: &std::io::Result<Option<String>>,
    symlinked: bool,
    owned: &crate::formats::pnpm::named_registries::Owned,
    was_routed: bool,
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
    bazel: &crate::bazel::pnpm::Hubs,
) -> Result<Routed, RouteBlock> {
    use crate::formats::pnpm::named_registries::{self, HostedOverride, Plan, Wanted};
    use crate::formats::pnpm::registry_alias::{AliasPin, OverrideLock, Pinned};
    use crate::formats::pnpm::workspace::is_keyless;
    use crate::hosted::guidance::RoutedPin;

    if !texts
        .iter()
        .all(|(_, text)| pnpm_lock_version_major(text) == Some(9))
    {
        return Err(RouteBlock::NotEligible);
    }
    let because =
        |subject: &str, why: String| RouteBlock::Because(vec![format!("{subject} {why}")]);
    // The hosted tarballs of each lock, each with the registry it is routed
    // through: the one this run's grant names, or, for a release an earlier
    // run routed that this run was not granted, the one the workspace file
    // already declares for it ([`kept_route`]).
    let listed = workspace
        .as_ref()
        .ok()
        .and_then(|text| text.as_deref())
        .map(|text| named_registries::routes(text, owned))
        .unwrap_or_default();
    let mut pins: Vec<(&str, Vec<RoutedPin>)> = Vec::new();
    let mut kept: BTreeMap<String, String> = BTreeMap::new();
    let mut unserved: Vec<String> = Vec::new();
    // Pins on a patch mirror: no registry serves a mirrored tarball
    // ([`crate::patch::redirect::grant::npm_registry_url`]).
    let mut mirrored: Vec<String> = Vec::new();
    for (key, text) in texts {
        let hosted = pnpm_hosted_pins(text, overrides).map_err(|why| because(key, why))?;
        let mut routed = hosted.routed;
        for pin in hosted.unserved {
            match kept_route(&pin, &listed) {
                Some((alias, route)) => {
                    // The registry keeps its name, unless an unreleased
                    // build gave it: that one is renamed like a granted
                    // pin's.
                    if named_registries::is_current_alias(&alias) {
                        kept.insert(route.uuid.clone(), alias);
                    }
                    routed.push(route);
                }
                None if crate::origin::on_mirror(&pin.tarball, &options.patch_server_origins) => {
                    mirrored.push(pin.release())
                }
                None => unserved.push(pin.release()),
            }
        }
        pins.push((*key, routed));
    }
    for names in [&mut unserved, &mut mirrored] {
        names.sort();
        names.dedup();
    }
    // No pin has an address: the patch service offers this project no
    // route (or the locks hold no hosted tarball), and the run is today's.
    // Unless an earlier run routed the project: it leaves the route, and
    // is told what for.
    if pins.iter().all(|(_, routed)| routed.is_empty()) && !was_routed {
        return Err(RouteBlock::NotEligible);
    }
    let mut blocked = Vec::new();
    if !unserved.is_empty() {
        blocked.push(pnpm_registry_unserved_reason(&unserved));
    }
    if !mirrored.is_empty() {
        blocked.push(crate::hosted::guidance::pnpm_registry_mirrored_reason(
            &mirrored,
        ));
    }
    let pinned = pnpm_route_pins(view);
    if pinned == RegistryRoutePins::NotProven {
        blocked.push(
            "the project's pnpm pins (package.json `packageManager`, \
             `devEngines.packageManager`, `engines.pnpm`, and the installed \
             node_modules/.modules.yaml) do not prove pnpm 11.20 or later"
                .to_string(),
        );
    }
    // What the Bazel workspace says of these locks. A lock that a rules_js
    // hub reads keeps the pin the Bazel legs build
    // ([`crate::bazel::pnpm::Reader`]). And where a hub keeps the root lock
    // out of the run, the locks that were read are not routed either,
    // whatever was read of the hub: the overrides would have to be
    // recorded in the root lock too, and it is not written. Said only
    // here, to a project the patch service offers the route to.
    match (&bazel.reader, &bazel.hidden) {
        (Some(reader), _) => {
            blocked.push(crate::hosted::guidance::pnpm_registry_bazel_reason(reader))
        }
        (None, Some(_)) => {
            blocked.push(crate::hosted::guidance::PNPM_REGISTRY_BAZEL_WITHHELD.to_string())
        }
        (None, None) => {}
    }
    if !blocked.is_empty() {
        return Err(RouteBlock::Because(blocked));
    }
    if pins.iter().all(|(_, routed)| routed.is_empty()) {
        return Err(RouteBlock::NotEligible);
    }
    if pinned == RegistryRoutePins::Unpinned {
        return Err(RouteBlock::Unpinned);
    }
    let existing = match workspace {
        Ok(existing) => existing.as_deref(),
        Err(e) => {
            return Err(because(
                PNPM_WORKSPACE_REL,
                format!("could not be read ({e})"),
            ))
        }
    };
    // A keyless file the lock was installed from as a multi-package
    // workspace: only pnpm <= 10.4 reads one that way, and the root-only
    // scaffold would drop those members (#1096).
    if !symlinked && existing.is_some_and(is_keyless) && lock_lists_members(view) {
        return Err(because(
            PNPM_WORKSPACE_REL,
            "has no keys while pnpm-lock.yaml lists workspace members".to_string(),
        ));
    }
    let names: BTreeSet<&str> = pins
        .iter()
        .flat_map(|(_, routed)| routed.iter().map(|pin| pin.name.as_str()))
        .collect();
    if let Some(why) =
        existing.and_then(|text| named_registries::competing_override(text, owned, &names))
    {
        return Err(because(PNPM_WORKSPACE_REL, why));
    }

    if let Some(release) = release_with_two_patches(&pins) {
        return Err(RouteBlock::Because(vec![format!(
            "the pnpm locks pin {release} to more than one patch, and an override routes \
             a package version to one registry"
        )]));
    }
    // Each patch's registry, under its name: the one the file already
    // routes a release this run was not granted through, else the name
    // the patch's UUID gives it among the project's patches.
    let uuids: BTreeSet<&str> = pins
        .iter()
        .flat_map(|(_, routed)| routed.iter().map(|pin| pin.uuid.as_str()))
        .collect();
    let mut wanted = Wanted::default();
    let mut alias_of: BTreeMap<&str, String> = BTreeMap::new();
    for pin in pins.iter().flat_map(|(_, routed)| routed) {
        if alias_of.contains_key(pin.uuid.as_str()) {
            continue;
        }
        let alias = match kept.get(&pin.uuid) {
            Some(alias) => alias.clone(),
            None => owned.name_for(&pin.uuid, &uuids).ok_or_else(|| {
                because(
                    PNPM_WORKSPACE_REL,
                    format!(
                        "already declares registries of its own under every name the \
                         registry of {}@{} could take",
                        pin.name, pin.version
                    ),
                )
            })?,
        };
        wanted.registries.insert(alias.clone(), pin.address.clone());
        alias_of.insert(pin.uuid.as_str(), alias);
    }

    // The locks, in the shape pnpm writes for the overrides.
    let mut locks = Vec::new();
    let mut edits = Vec::new();
    let mut all: BTreeMap<String, HostedOverride> = BTreeMap::new();
    for ((key, text), (_, routed)) in texts.iter().zip(&pins) {
        let mut lock = OverrideLock::parse(text, owned).map_err(|why| because(key, why))?;
        for pin in routed {
            let alias = &alias_of[pin.uuid.as_str()];
            let route = HostedOverride {
                name: pin.name.clone(),
                version: pin.version.clone(),
                alias: alias.clone(),
            };
            let release = route.key();
            let pinned = lock
                .pin(&AliasPin {
                    name: &pin.name,
                    version: &pin.version,
                    alias,
                    integrity: &pin.integrity,
                    tarball: &pin.tarball,
                })
                .map_err(|why| because(key, why))?;
            match pinned {
                Pinned::InPlace => {}
                Pinned::Absent => {
                    return Err(because(
                        key,
                        format!("holds {release} under a key the registry routing cannot move"),
                    ))
                }
                Pinned::Rewritten { from } => edits.push(FileEdit {
                    path: (*key).to_string(),
                    kind: REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND.into(),
                    action: "rewritten".into(),
                    key: Some(release.clone()),
                    original: Some(serde_json::Value::String(from)),
                    new: Some(serde_json::Value::String(format!(
                        "{}@{}",
                        pin.name,
                        route.value()
                    ))),
                }),
            }
            if all.get(&release).is_some_and(|other| *other != route) {
                return Err(RouteBlock::Because(vec![format!(
                    "the pnpm locks pin {release} to different patches"
                )]));
            }
            wanted.route(&route);
            all.insert(release, route);
        }
        lock.finish().map_err(|why| because(key, why))?;
        // A release the lock keys by a registry of ours without a hosted
        // tarball to show for it is no pin of this run.
        if let Some(stray) = lock
            .aliased()
            .into_iter()
            .find(|pin| !all.contains_key(&pin.key()))
        {
            return Err(because(
                key,
                format!(
                    "routes {} through `{}` without a hosted tarball of this run",
                    stray.key(),
                    stray.alias
                ),
            ));
        }
        locks.push((*key, lock));
    }
    // pnpm records the workspace file's overrides in every lock it
    // governs, a member's own lock that holds no patched package included.
    let all: Vec<HostedOverride> = all.into_values().collect();
    for (key, lock) in &mut locks {
        let before = lock.overrides();
        lock.set_overrides(&all);
        edits.extend(lock_override_edits(key, &before, &lock.overrides()));
    }

    // The file the two maps go into: the project's, less the trust key an
    // earlier run provably wrote (when the file may be written at all).
    let untrusted = existing
        .filter(|_| options.trust_lockfile_config)
        .and_then(strip_cli_trust);
    let trust = match (
        &untrusted,
        existing.map(|text| plan_workspace_trust(Some(text))),
    ) {
        (Some(_), _) => TrustLeftover::Removed,
        (None, Some(TrustPlan::AlreadyTrue)) => TrustLeftover::Left,
        (None, _) => TrustLeftover::None,
    };
    let plan = named_registries::plan(untrusted.as_deref().or(existing), &wanted, owned);
    if let Plan::Unsupported(why) = plan {
        return Err(because(PNPM_WORKSPACE_REL, why));
    }
    if !options.trust_lockfile_config && plan != Plan::InSync {
        return Err(RouteBlock::OptedOut);
    }
    Ok(Routed {
        locks: locks
            .into_iter()
            .filter_map(|(key, lock)| Some((key.to_string(), lock.render()?)))
            .collect(),
        edits,
        route: RegistryRoute {
            plan,
            trust,
            also_locked: also_locked_in_range(texts, &all),
        },
    })
}

/// The routed releases (`routed`) a governing lock (`texts`) also holds
/// another release of on the default registry, newer and within the routed
/// release's caret range (the same major, or the same minor below 1.0):
/// `(name, version, the other versions)`, sorted. The override that routes
/// `name@version` applies to every dependency whose range admits that
/// version, which a lock does not record for a transitive dependent, so
/// the dependent locked on such a release may move to the patched one when
/// pnpm next resolves.
fn also_locked_in_range(
    texts: &[(&str, String)],
    routed: &[crate::formats::pnpm::named_registries::HostedOverride],
) -> Vec<(String, String, Vec<String>)> {
    use crate::formats::pnpm::{pnpm_registry_key, range_admits, PnpmDocument, PnpmLock};

    let mut found: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (_, text) in texts {
        let lock = PnpmLock::parse(text);
        for package in lock.packages_of(PnpmDocument::Project) {
            let Some((name, version)) = pnpm_registry_key(package.key) else {
                continue;
            };
            if routed
                .iter()
                .any(|pin| pin.name == name && pin.version == version)
            {
                continue;
            }
            for pin in routed.iter().filter(|pin| pin.name == name) {
                if range_admits(&format!("^{}", pin.version), version) == Some(true) {
                    found
                        .entry((pin.name.clone(), pin.version.clone()))
                        .or_default()
                        .insert(version.to_string());
                }
            }
        }
    }
    found
        .into_iter()
        .map(|((name, version), others)| (name, version, others.into_iter().collect()))
        .collect()
}

/// A release an earlier run routed, kept on its route by a run that was not
/// granted it: a scan of part of a project, or any grant for fewer patches
/// than the locks pin, says nothing about the others, and must not put the
/// whole lock back on `trustLockfile`.
///
/// The release keeps the registry the files already route it through, with
/// its name and address as written. That holds when the lock keys it by a
/// registry of ours (`pin.registry`), the workspace file routes it
/// (`listed`: its overrides of ours, each with the address of the registry
/// it names), and that address is the directory the pin's tarball is
/// served from. The registry is answered under the name the workspace file
/// gives it: where the lock spells another (a key respelled from an
/// unreleased build's name, [`respell_earlier_route`]), the route settles
/// on one. A pin this run WAS granted without an address is never kept:
/// the grant says the patch service serves it no registry.
fn kept_route(
    pin: &crate::hosted::guidance::UnservedPin,
    listed: &[(
        crate::formats::pnpm::named_registries::HostedOverride,
        String,
    )],
) -> Option<(String, crate::hosted::guidance::RoutedPin)> {
    use crate::formats::pnpm::named_registries::Address;

    if pin.granted {
        return None;
    }
    pin.registry.as_deref()?;
    let (route, address) = listed
        .iter()
        .find(|(route, _)| route.name == pin.name && route.version == pin.version)?;
    Address::serves(address, &pin.tarball).then_some(())?;
    Some((
        route.alias.clone(),
        crate::hosted::guidance::RoutedPin {
            name: pin.name.clone(),
            version: pin.version.clone(),
            integrity: pin.integrity.clone(),
            tarball: pin.tarball.clone(),
            uuid: Address::parse(address)?.uuid,
            address: address.clone(),
        },
    ))
}

/// The release (`name@version`) the hosted pins of the governing locks pin
/// to two different patches, if any. An override routes a package version
/// to one registry, and each registry serves one patch, so such a project
/// is not routed.
fn release_with_two_patches(
    pins: &[(&str, Vec<crate::hosted::guidance::RoutedPin>)],
) -> Option<String> {
    let mut patches: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    pins.iter()
        .flat_map(|(_, routed)| routed)
        .find(|pin| {
            let patch = patches
                .entry((pin.name.as_str(), pin.version.as_str()))
                .or_insert(pin.uuid.as_str());
            *patch != pin.uuid
        })
        .map(|pin| format!("{}@{}", pin.name, pin.version))
}

/// The edits behind a change of a pnpm lock's `overrides:` section
/// (`before` → `after`, as `(key, value)` entries).
fn lock_override_edits(
    lock: &str,
    before: &[(String, String)],
    after: &[(String, String)],
) -> Vec<FileEdit> {
    let value = |entries: &[(String, String)], key: &str| {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, value)| value.clone())
    };
    let keys: BTreeSet<&str> = before
        .iter()
        .chain(after)
        .map(|(key, _)| key.as_str())
        .collect();
    keys.into_iter()
        .filter_map(|key| {
            let (from, to) = (value(before, key), value(after, key));
            let action = match (&from, &to) {
                (None, Some(_)) => "added",
                (Some(_), None) => "removed",
                (Some(from), Some(to)) if from != to => "rewritten",
                _ => return None,
            };
            Some(FileEdit {
                path: lock.to_string(),
                kind: REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND.into(),
                action: action.into(),
                key: Some(key.to_string()),
                original: from.map(serde_json::Value::String),
                new: to.map(serde_json::Value::String),
            })
        })
        .collect()
}

/// What taking a registry route (or what is left of one) out of a project
/// changes.
pub(crate) struct Cleaned {
    pub(crate) locks: Vec<(String, String)>,
    pub(crate) lock_edits: Vec<FileEdit>,
    /// The workspace file without the route's entries; `None` when it
    /// holds none of them.
    pub(crate) workspace: Option<Unrouted>,
}

/// pnpm-workspace.yaml (`existing`) keeping, of the registry route, only
/// what the governing locks still key (`routed`). A rewrite only carries
/// writes, so a file the route created is written back as its `packages`
/// scaffold (the one the trust key goes after), and [`Unrouted::created`]
/// tells the caller, which deletes the file when nothing else goes into it
/// ([`Rewritten::pnpm_workspace_emptied`]).
fn workspace_without_route(
    existing: &str,
    owned: &crate::formats::pnpm::named_registries::Owned,
    routed: &[crate::formats::pnpm::named_registries::HostedOverride],
) -> Option<Unrouted> {
    use crate::formats::pnpm::named_registries::{self, Plan, Unwound, Wanted};
    use crate::formats::pnpm::workspace::PACKAGES_SCAFFOLD;

    let mut created = false;
    let (text, changes) = match named_registries::unwind(existing, owned, routed) {
        Unwound::Unchanged => return None,
        Unwound::Rewrite(text, changes) => (text, changes),
        Unwound::Delete => {
            created = true;
            let eol = if existing.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let scaffold = PACKAGES_SCAFFOLD
                .iter()
                .map(|line| format!("{line}{eol}"))
                .collect();
            let changes = match named_registries::plan(Some(existing), &Wanted::default(), owned) {
                Plan::Edit(_, changes) => changes,
                _ => Vec::new(),
            };
            (scaffold, changes)
        }
    };
    Some(Unrouted {
        text,
        edits: workspace_route_edits(changes, false).collect(),
        created,
    })
}

/// Put a project an earlier run routed through the patch server's
/// registry back on the plain shape, for a run that stays on
/// `trustLockfile`: every governing lock (`texts`) loses its registry
/// keys and its record of the overrides, and pnpm-workspace.yaml
/// (`existing`) the route's entries. A direct dependency's specifier
/// comes back from the importer's package.json, the only place that still
/// has it.
///
/// `None` when nothing of a route is there; `Err` (why) leaves locks and
/// file as they are, since half of the route would not install.
fn pnpm_unroute(
    view: &ProjectView<'_>,
    texts: &[(&str, String)],
    existing: Option<&str>,
    owned: &crate::formats::pnpm::named_registries::Owned,
) -> Option<Result<Cleaned, String>> {
    use crate::formats::pnpm::named_registries;
    use crate::formats::pnpm::registry_alias::{manifest_specifier, names_a_route, OverrideLock};

    let mut locks: Vec<(&str, OverrideLock)> = Vec::new();
    for (key, text) in texts {
        match OverrideLock::parse(text, owned) {
            Ok(lock) => locks.push((*key, lock)),
            // A lock these edits cannot read may still key a release by a
            // registry of ours: with the route gone from the workspace
            // file beside it, it would not install.
            Err(why) if names_a_route(text) => return Some(Err(format!("{key} {why}"))),
            Err(_) => {}
        }
    }
    let routed = locks.iter().any(|(_, lock)| lock.holds_route());
    if !routed && !existing.is_some_and(|text| named_registries::holds_ours(text, owned)) {
        return None;
    }
    let mut lock_edits = Vec::new();
    for (key, lock) in &mut locks {
        let dir = key.rfind('/').map_or("", |at| &key[..=at]);
        let specifier = |importer: &str, name: &str| {
            let importer = match importer {
                "." => String::new(),
                nested => format!("{nested}/"),
            };
            let manifest = read_advisory_text(view, &format!("{dir}{importer}package.json"))?;
            manifest_specifier(&manifest, name)
        };
        let before = lock.overrides();
        let moved = match lock.unpin(&|_| true, &specifier).and_then(|moved| {
            lock.finish()?;
            Ok(moved)
        }) {
            Ok(moved) => moved,
            Err(why) => return Some(Err(format!("{key} {why}"))),
        };
        lock.set_overrides(&[]);
        lock_edits.extend(moved.into_iter().map(|pin| FileEdit {
            path: (*key).to_string(),
            kind: REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND.into(),
            action: "rewritten".into(),
            key: Some(pin.key()),
            original: Some(serde_json::Value::String(format!(
                "{}@{}",
                pin.name,
                pin.value()
            ))),
            new: Some(serde_json::Value::String(pin.key())),
        }));
        lock_edits.extend(lock_override_edits(key, &before, &lock.overrides()));
    }
    Some(Ok(Cleaned {
        locks: locks
            .into_iter()
            .filter_map(|(key, lock)| Some((key.to_string(), lock.render()?)))
            .collect(),
        lock_edits,
        workspace: existing.and_then(|text| workspace_without_route(text, owned, &[])),
    }))
}

/// Take out what is left of a registry route that no governing lock
/// (`texts`) references any more: an override of ours for a release no
/// lock keys by a registry of ours (in the workspace file and in each
/// lock's record of it), and a registry of ours no lock key names. For a
/// run that touches no hosted pnpm pin, and for the commands that
/// reconcile a project without asking the patch service
/// ([`crate::patch::redirect::upstream::sweep_pnpm_registry_route`]): a
/// package that left the lock, an interrupted run, a workspace file that
/// is gone (`existing` is `None`). A release a lock still routes keeps its
/// override and its registry as they are.
pub(crate) fn pnpm_prune(
    texts: &[(&str, String)],
    existing: Option<&str>,
    owned: &crate::formats::pnpm::named_registries::Owned,
) -> Option<Cleaned> {
    use crate::formats::pnpm::named_registries::HostedOverride;
    use crate::formats::pnpm::registry_alias::{names_a_route, OverrideLock};

    // A lock these edits cannot read may still key a release by a registry
    // of ours, or record an override of ours: everything stays.
    let unread = |text: &String| OverrideLock::parse(text, owned).is_err() && names_a_route(text);
    if texts.iter().any(|(_, text)| unread(text)) {
        return None;
    }
    let mut locks: Vec<(&str, OverrideLock)> = texts
        .iter()
        .filter_map(|(key, text)| Some((*key, OverrideLock::parse(text, owned).ok()?)))
        .collect();
    let routed: BTreeSet<HostedOverride> =
        locks.iter().flat_map(|(_, lock)| lock.aliased()).collect();
    let routed: Vec<HostedOverride> = routed.into_iter().collect();
    let stale = |pin: &HostedOverride| !routed.iter().any(|kept| kept.key() == pin.key());
    let workspace = existing.and_then(|text| workspace_without_route(text, owned, &routed));
    let orphaned = workspace.is_some()
        || locks
            .iter()
            .any(|(_, lock)| lock.routed_overrides().iter().any(stale));
    if !orphaned {
        return None;
    }
    let mut lock_edits = Vec::new();
    for (key, lock) in &mut locks {
        let before = lock.overrides();
        lock.prune_overrides(&|pin| !stale(pin));
        lock_edits.extend(lock_override_edits(key, &before, &lock.overrides()));
    }
    Some(Cleaned {
        locks: locks
            .into_iter()
            .filter_map(|(key, lock)| Some((key.to_string(), lock.render()?)))
            .collect(),
        lock_edits,
        workspace,
    })
}

/// The trust detail for a settings file (`file`) that already carries
/// `trustLockfile: true`.
fn pnpm_trust_already_true_detail(server: &str, file: &str) -> String {
    format!(
        "{}, and {file} already carries `trustLockfile: true` — keep it committed \
         alongside the lock; installs need no extra flags. \
         {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// Whether a pnpm-workspace.yaml is exactly the root-only scaffold the
/// trust auto-config creates ([`plan_workspace_trust`] with no file), in
/// either line ending.
fn is_trust_scaffold(text: &str) -> bool {
    let TrustPlan::Create(scaffold) = plan_workspace_trust(None) else {
        return false;
    };
    text == scaffold || text == scaffold.replace('\n', "\r\n")
}

/// The note added when a project pinned to pnpm 9.0–10.4 (`pins`, as
/// prose) still carries the root-only scaffold (#734).
fn pnpm_scaffold_breaks_add_note(pins: &str) -> String {
    format!(
        "Note: {PNPM_WORKSPACE_REL} is the root-only file an earlier socket-patch run \
         created, but the project's pnpm ({pins}) does not read `trustLockfile`, and \
         in a root-only workspace pnpm 9.0–10.4 refuse `pnpm add <pkg>` \
         (ERR_PNPM_ADDING_TO_ROOT). Delete {PNPM_WORKSPACE_REL} (re-run after \
         upgrading to pnpm >= 11 to recreate it), or add dependencies with \
         `pnpm add -w <pkg>`."
    )
}

/// The trust detail for a settings file (`file`) whose explicit
/// `trustLockfile: <value>` was respected.
fn pnpm_trust_user_set_detail(server: &str, file: &str, value: &str) -> String {
    format!(
        "{}. {file} explicitly sets `trustLockfile: {value}`, which was respected \
         and left untouched — install with `pnpm install --trust-lockfile`, or set \
         `trustLockfile: true` yourself so every install accepts the patched \
         artifacts. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// A `pnpm_config_trust_lockfile` variable of the install's environment
/// (`env`) that the project's pnpm reads and that is not true (#1514). pnpm
/// 11+ read it ahead of pnpm-workspace.yaml, so it is an explicit user
/// setting a written key could not override: respected like a
/// `trustLockfile: false` in the file. The project's files are read for
/// its pnpm major only when such a variable is set.
fn pnpm_trust_env_override(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    env: &(dyn Fn(&str) -> Option<String> + Send + Sync),
) -> Option<crate::utils::pnpm_workspace::PnpmSetting> {
    use crate::utils::pnpm_workspace::{pnpm_major_from, trust_lockfile_env};
    let off = |major| trust_lockfile_env(major, env).filter(|found| found.as_bool() != Some(true));
    off(None)?;
    off(pnpm_major_from(|rel| match files.get(rel) {
        Some(text) => Some(text.clone()),
        None => read_advisory_text(view, rel),
    }))
}

/// The trust detail for a `pnpm_config_trust_lockfile` override in the
/// environment (`source`, as [`pnpm_trust_env_override`] names it).
fn pnpm_trust_env_set_detail(server: &str, source: &str) -> String {
    format!(
        "{}. {source} sets pnpm's `trustLockfile`, which was respected: pnpm >=11 \
         reads it ahead of {PNPM_WORKSPACE_REL}, so a `trustLockfile: true` there \
         would not take effect in this environment, and nothing was written — unset \
         the variable or set it to `true` wherever the project installs, or re-run \
         the scan with `--mode vendored`. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// What the project's pnpm pins say about the registry route's floor (see
/// [`crate::formats::pnpm::registry_route_pins`]), read from the files
/// [`root_only_workspace_breaks_add`] reads.
fn pnpm_route_pins(view: &ProjectView<'_>) -> RegistryRoutePins {
    let read = |rel: &str| read_advisory_text(view, rel);
    crate::formats::pnpm::registry_route_pins(
        read(crate::hosted::memory::select::NPM_MANIFEST_REL).as_deref(),
        read("node_modules/.modules.yaml").as_deref(),
    )
}

/// The pnpm pins of a project with no pnpm-workspace.yaml, when every one
/// is a release that refuses `pnpm add` in a root-only workspace (see
/// [`pnpm_root_only_workspace_breaks_add`]). Reads the root package.json
/// and the installed `node_modules/.modules.yaml`, both advisory: FIFO-safe
/// on disk, and an in-memory entry that is not text counts as absent.
fn root_only_workspace_breaks_add(view: &ProjectView<'_>) -> Option<String> {
    let read = |rel: &str| read_advisory_text(view, rel);
    pnpm_root_only_workspace_breaks_add(
        read(crate::hosted::memory::select::NPM_MANIFEST_REL).as_deref(),
        read("node_modules/.modules.yaml").as_deref(),
    )
}

/// A project text file read for advice only: FIFO-safe on disk, and an
/// in-memory entry that is not text (or is a link) counts as absent.
fn read_advisory_text(view: &ProjectView<'_>, rel: &str) -> Option<String> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            crate::utils::fs::read_regular_to_string_sync(&cwd.join(rel)).ok()
        }
        ProjectView::Memory(project) if !project.is_symlink(rel) => match project.get(rel) {
            Some(MemoryEntry::Text(text)) => Some(text.to_string()),
            _ => None,
        },
        ProjectView::Memory(_) => None,
    }
}

/// Whether the root `pnpm-lock.yaml` lists workspace members besides the
/// root: with a keyless pnpm-workspace.yaml that marks a pnpm <= 10.4
/// install (see [`crate::formats::pnpm::workspace::lock_has_member_importers`]).
fn lock_lists_members(view: &ProjectView<'_>) -> bool {
    read_advisory_text(view, "pnpm-lock.yaml")
        .is_some_and(|text| crate::formats::pnpm::workspace::lock_text_has_member_importers(&text))
}

/// The ancestor `pnpm-workspace.yaml` governing a disk project's pnpm
/// settings (see [`governing_workspace_file`]); an in-memory project has
/// no ancestors.
fn governing_workspace(view: &ProjectView<'_>) -> Option<std::path::PathBuf> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            governing_workspace_file(cwd)
        }
        ProjectView::Memory(_) => None,
    }
}

/// npm >= 12 blocks dependency install scripts unless the root
/// `package.json#allowScripts` approves them, and it matches a pinned key
/// (`"esbuild@0.19.12": true`) only against a registry-shaped `resolved`
/// URL, which a hosted redirect replaces (#1595). Warn
/// (`redirect_npm_allow_scripts`) for every package whose rewired
/// package-lock.json entry runs an install script that loses its approval.
/// The policy is the user's, so it is never rewritten: the only key npm
/// would still honor is a name-only one, which widens it. npm >= 12 never
/// reads npm-shrinkwrap.json, so a shrinkwrap pin cannot lose one.
fn npm_allow_scripts(
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    overrides: &[DepOverride],
) -> Vec<RewriteWarning> {
    use crate::patch::redirect::npm_allow_scripts::{
        lost_detail, rewired_runs_install_script, AllowScripts, HOSTED_WARNING, NPM12_LOCK,
    };
    let read = |rel: &str| rewrite.files.get(rel).or_else(|| files.get(rel));
    let Some(policy) = read("package.json").and_then(|text| AllowScripts::parse(text)) else {
        return Vec::new();
    };
    let Some(lock) =
        read(NPM12_LOCK).and_then(|text| crate::vendor::common::parse_json_text(text).ok())
    else {
        return Vec::new();
    };
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut warnings = Vec::new();
    for o in overrides.iter().filter(|o| o.ecosystem == "npm") {
        let name = crate::patch::redirect::full_name(o);
        if !seen.insert((name.clone(), o.version.clone())) {
            continue;
        }
        let Some(lost) = policy.lost(&name, &o.version) else {
            continue;
        };
        let rewired = |_: &str, entry: &serde_json::Value| {
            entry.get("resolved").and_then(serde_json::Value::as_str)
                == Some(o.artifact_url.as_str())
        };
        if !rewired_runs_install_script(&lock, &name, &o.version, rewired) {
            continue;
        }
        let target = match url_host(&o.artifact_url) {
            Some(host) => format!("the hosted patch tarball on {host}"),
            None => "the hosted patch tarball".to_string(),
        };
        warnings.push(warning(
            HOSTED_WARNING,
            lost_detail(&name, &o.version, &lost, &target),
        ));
    }
    warnings
}

/// npm >= 12 ships `allow-remote=none`: it refuses (EALLOWREMOTE) every
/// tarball whose `resolved` origin is not the configured registry — which
/// is exactly what a hosted redirect writes. npm <= 11 installs it
/// unchanged; `allow-remote=all` in the project `.npmrc` makes npm 12
/// install the patched bytes with the sha512 pins still enforced (`root`
/// only admits DIRECT dependencies, so it is not enough).
///
/// ZERO-TOUCH DEFAULT (the npm twin of the pnpm trustLockfile
/// auto-config): whenever a root npm lock ends this run carrying a granted
/// hosted artifact URL (spliced now, or already redirected by an earlier
/// run — so a missed config heals on re-run), the run ensures
/// `allow-remote=all` in the project `.npmrc` — created when absent
/// (`action: "created"`), one line appended otherwise (`"added"`), every
/// other byte preserved — and records the edit
/// (`redirect_npmrc_allow_remote`). An explicit user
/// `allow-remote=<other>` is RESPECTED (never flipped), an unreadable /
/// symlinked `.npmrc` is left alone, and `--no-npm-allow-remote-config`
/// opts out entirely; every variant still WARNS
/// (`redirect_npm_allow_remote`) with the whole-tree tradeoff. Vendored
/// mode is unaffected: its `file:.socket/vendor/…` specs are npm `file`
/// specs, gated by `allow-file` (default `all`), not `allow-remote` — an
/// explicit refusing `allow-file` is the vendored flow's own advisory
/// (`vendor_npm_allow_file`, #969).
fn npm_allow_remote(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
) -> (Vec<RewriteWarning>, ConfigWrite) {
    let mut npm_warnings: Vec<RewriteWarning> = Vec::new();
    let mut npmrc_config_write: ConfigWrite = None;
    let npm_hosts: Vec<&str> = {
        let npm_lock_texts: Vec<&String> = NPM_LOCKS
            .iter()
            .filter_map(|lock| rewrite.files.get(*lock).or_else(|| files.get(*lock)))
            .collect();
        let npm_overrides: Vec<_> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
        let groups: Vec<[String; 2]> = npm_overrides
            .iter()
            .map(|o| artifact_url_spellings(&o.artifact_url))
            .collect();
        let present = groups_present(&npm_lock_texts, &groups);
        let mut hosts: Vec<&str> = npm_overrides
            .iter()
            .zip(present)
            .filter(|(_, present)| *present)
            .filter_map(|(o, _)| url_host(&o.artifact_url))
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    };
    if npm_hosts.is_empty() {
        return (npm_warnings, npmrc_config_write);
    }
    let edit = |action: &str| FileEdit {
        path: NPMRC_REL.into(),
        kind: NPMRC_ALLOW_REMOTE_EDIT_KIND.into(),
        action: action.into(),
        key: Some("allow-remote".into()),
        original: None,
        new: Some(serde_json::json!("all")),
    };
    let npmrc = read_npmrc(view);
    let outer = (options.npm_outer)();
    let detail = match &npmrc {
        // Opt-out still reports an explicit / already-set value truthfully;
        // only the WRITE is suppressed.
        Ok(existing) => match plan_npmrc_allow_remote_with(existing.as_deref(), &outer) {
            NpmrcPlan::AlreadyAll => npm_allow_remote_already_detail(&npm_hosts),
            NpmrcPlan::UserSet(value) => npm_allow_remote_user_set_detail(&npm_hosts, &value),
            NpmrcPlan::EnvSet { var, value } => {
                npm_allow_remote_env_set_detail(&npm_hosts, &var, &value)
            }
            NpmrcPlan::OuterSet { layer, path, value } => {
                npm_allow_remote_outer_set_detail(&npm_hosts, layer, &path, &value)
            }
            NpmrcPlan::Unsupported(why) => npm_allow_remote_unreadable_detail(&npm_hosts, &why),
            _ if !options.npm_allow_remote_config => npm_allow_remote_manual_detail(&npm_hosts),
            NpmrcPlan::Create(text) => {
                npmrc_config_write = Some((text, edit("created")));
                npm_allow_remote_configured_detail(&npm_hosts, true, options.dry_run)
            }
            NpmrcPlan::Append(text) => {
                npmrc_config_write = Some((text, edit("added")));
                npm_allow_remote_configured_detail(&npm_hosts, false, options.dry_run)
            }
        },
        Err(why) => npm_allow_remote_unreadable_detail(&npm_hosts, why),
    };
    npm_warnings.push(warning("redirect_npm_allow_remote", detail));
    // #812: npm >= 8's `replace-registry-host` (`always`, or the pinned
    // host itself) rewrites the hosted pins to the configured registry,
    // so every install 404s. The setting is the user's, so it is reported
    // (from whichever layer sets it), never overridden.
    let project = npmrc.as_ref().ok().and_then(|t| t.as_deref());
    if let Some(setting) = effective_replace_registry_host(project, &outer) {
        let blocked: Vec<&str> = npm_hosts
            .iter()
            .copied()
            .filter(|host| replace_registry_host_rewrites(&setting.value, host))
            .collect();
        if !blocked.is_empty() {
            npm_warnings.push(warning(
                NPM_REPLACE_REGISTRY_HOST_CODE,
                npm_replace_registry_host_detail(&blocked, &setting),
            ));
        }
    }
    // #1871: npm >= 8's `omit-lockfile-registry-resolved` strips every
    // registry dependency's `resolved` (the hosted pins included) on the
    // next lock save, keeping the patched `integrity`. Reported, never
    // overridden, like `replace-registry-host`.
    if let Some(setting) = effective_omit_lockfile_registry_resolved(project, &outer) {
        npm_warnings.push(warning(
            NPM_OMIT_LOCKFILE_RESOLVED_CODE,
            npm_omit_lockfile_resolved_detail(&npm_hosts, &setting),
        ));
    }
    (npm_warnings, npmrc_config_write)
}

/// #406: `deno install` installs a `package.json` project's npm
/// dependencies from `deno.lock` and never reads an npm-family lock, so a
/// redirected npm package that `deno.lock` also locks at the same version
/// keeps installing the registry copy wherever Deno installs. Said once,
/// naming every such package; the redirect still stands for npm / pnpm /
/// yarn / bun installs. Advisory read: no readable `deno.lock`, nothing.
fn npm_deno_lock(
    view: &ProjectView<'_>,
    overrides: &[DepOverride],
    confirmed: &[(String, String)],
) -> Option<RewriteWarning> {
    use crate::patch::redirect::{full_name, npm_deno_lock_detail, DENO_LOCK};
    let npm: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "npm")
        .filter(|o| confirmed.iter().any(|(_, uuid)| *uuid == o.patch_uuid))
        .collect();
    if npm.is_empty() {
        return None;
    }
    let text = read_advisory_text(view, DENO_LOCK)?;
    let locked = crate::crawlers::deno_crawler::lock_text_npm_packages(&text);
    let mut packages: Vec<String> = npm
        .into_iter()
        .map(|o| format!("{}@{}", full_name(o), o.version))
        .filter(|key| locked.contains(key))
        .collect();
    packages.sort();
    packages.dedup();
    if packages.is_empty() {
        return None;
    }
    Some(warning(
        "redirect_npm_deno_lock",
        npm_deno_lock_detail(&packages, "redirected"),
    ))
}

/// A dep counts as REDIRECTED only if its hosted-artifact URL (or its
/// per-dependency registry index URL) actually landed in the project's
/// files — either written by this run or already present from an earlier
/// one. A granted reference whose rewriter found nothing to edit (e.g. no
/// lockfile) must NOT be recorded or attested: nothing pins the patch.
fn confirm(
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    candidates: &[Candidate],
    binary_bun: bool,
) -> Vec<(String, String)> {
    use crate::patch::redirect::pdm_drives;
    // A `pdm.lock` that is NOT the PyPI install driver (a `uv.lock` or
    // `poetry.lock` sits beside it) is never rewritten, yet can still carry
    // a Socket artifact URL from an earlier run. That stale text pins
    // nothing, so it must not feed the substring probe below. When pdm DOES
    // drive, pypi confirmation keys off `confirmed_pdm_uuids`, so dropping
    // the file is always safe.
    let pdm_inactive = files.contains_key("pdm.lock") && !pdm_drives(files);
    // The yarn berry pin's `package.json` `resolutions` entry is only half of
    // it — the URL-keyed `yarn.lock` entry is what installs — so a hosted URL
    // left in the manifest (an earlier run, a refused rewrite) proves
    // nothing on its own: the manifest never feeds the probe. Nor do the
    // Bun workspace members' manifests, read only as advisory input.
    fn is_npm_manifest(name: &str) -> bool {
        name == "package.json" || name.ends_with("/package.json")
    }
    // A Maven reactor root the pom rewriter refused pins nothing, so a
    // suffixed version an earlier release left in it, or in `.mvn/`,
    // proves nothing (#1809); nor do the module poms read beside a Maven 4
    // root, advisory input only.
    let maven_reactor_refused = rewrite
        .warnings
        .iter()
        .any(|w| w.code == "redirect_maven_multimodule_unsupported");
    let is_unpinned_maven = |name: &str| {
        name.ends_with("/pom.xml")
            || maven_reactor_refused && (name == "pom.xml" || name.starts_with(".mvn/"))
    };
    // A pnpm lock pnpm does not read (a `shrinkwrap.yaml` beside a
    // `pnpm-lock.yaml`, or the reverse under a pnpm 1 / 2 pin, N11) is
    // never rewritten, so a Socket URL an earlier run left in it pins
    // nothing either.
    let shadowed_pnpm = crate::formats::pnpm::plan::shadowed_locks(files);
    let final_texts: Vec<(&str, &String)> = files
        .iter()
        .filter(|(name, _)| !(pdm_inactive && name.as_str() == "pdm.lock"))
        .filter(|(name, _)| !shadowed_pnpm.contains(name))
        .filter(|(name, _)| !is_npm_manifest(name))
        .filter(|(name, _)| !is_unpinned_maven(name))
        // The block of a Bazel workspace confirms by the hub lane's own
        // report: the URL in a block that was changed by hand pins nothing.
        .filter(|(name, _)| name.as_str() != crate::bazel::maven::FILE)
        .filter(|(name, _)| !crate::patch::redirect::sbt::is_synthetic_key(name))
        .map(|(name, content)| (name.as_str(), rewrite.files.get(name).unwrap_or(content)))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name) && !is_npm_manifest(name))
                .map(|(name, content)| (name.as_str(), content)),
        )
        .filter(|(name, _)| !crate::patch::redirect::sbt::is_generated_file(name))
        .collect();
    // Gradle scripts, locks and owned files never confirm by substring: a
    // pasted snippet or a stale lock line pins nothing (the Gradle planner
    // decides its own uuids above the needles).
    let needle_texts: Vec<&String> = final_texts
        .iter()
        .filter(|(name, _)| !is_gradle_file(name))
        .map(|(_, text)| *text)
        .collect();
    // Every non-substring rule decides a candidate outright; the rest are
    // confirmed by substring presence of their needles in the final texts.
    // All needle groups are answered in ONE multi-needle pass per text
    // (`groups_present`), which is the per-candidate `any()` exactly —
    // presence does not depend on search order, and `confirmed` keeps
    // candidate order.
    let steps: Vec<ProbeStep> = candidates
        .iter()
        .map(|c| {
            let purl = c.purl.as_str();
            let uuid = c.dep.patch_uuid.as_str();
            // vlt decides before the binary-bun rule, so `bun.lockb` beside
            // a vlt-driven `vlt-lock.json` never confirms an npm purl.
            if rewrite.refused_vlt_uuids.contains(uuid)
                || rewrite.refused_bun_uuids.contains(uuid)
                || rewrite.refused_npm_uuids.contains(uuid)
            {
                return ProbeStep::Decided(false);
            }
            // An sbt build's Maven pins are confirmed by the sbt rewriter's
            // own report: the generated file names the index URL whether or
            // not the pin was verified against the build's evidence (so it
            // is never a substring proof). Beside a `pom.xml` the Maven
            // rewriter's own landing also confirms. Beside a Gradle build
            // whose planner decided the patch, both builds must pin it
            // (each build pins on its own, as a pom beside Gradle must):
            // the Gradle arm below confirms an sbt-confirmed uuid, and a
            // uuid the sbt rewriter refused is never confirmed by the
            // Gradle planner alone — the sbt build still loads upstream.
            // A jar that a rules_jvm_external hub of a Bazel workspace
            // builds is pinned once its entry is in the block of
            // `MODULE.bazel`, whatever another build of the checkout pins.
            if rewrite.confirmed_bazel_maven_uuids.contains(uuid) {
                return ProbeStep::Decided(true);
            }
            if purl.starts_with("pkg:maven/") {
                if let Some(sbt_only) = crate::patch::redirect::sbt::maven_confirmation(files) {
                    let refused_by_sbt = rewrite.refused_sbt_uuids.contains(uuid);
                    if refused_by_sbt && rewrite.gradle_uuids.contains(uuid) {
                        return ProbeStep::Decided(false);
                    }
                    let by_sbt = rewrite.confirmed_sbt_uuids.contains(uuid) && !refused_by_sbt;
                    let gradle_decides = by_sbt && rewrite.gradle_uuids.contains(uuid);
                    if (by_sbt || sbt_only) && !gradle_decides {
                        return ProbeStep::Decided(by_sbt);
                    }
                }
            }
            if rewrite.vlt_drives && purl.starts_with("pkg:npm/") {
                return ProbeStep::Decided(rewrite.confirmed_vlt_uuids.contains(uuid));
            }
            if binary_bun && purl.starts_with("pkg:npm/") {
                return ProbeStep::Decided(rewrite.confirmed_bun_binary_uuids.contains(uuid));
            }
            if rewrite.refused_pipenv_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            // pdm is transactional like cargo: a refused uuid is never
            // confirmed, and when `pdm.lock` is the PyPI install driver (no
            // `uv.lock` / `poetry.lock`) a pypi dep is confirmed ONLY by the
            // pdm rewriter's own report — the URL landing in a sibling
            // `requirements.txt` the project does not install from pins
            // nothing. When uv/poetry drive, their own lock proof below
            // still confirms them. This check precedes the hatch gate: a
            // PDM project may declare `hatchling` as its build backend,
            // which registers every pypi uuid as hatch-owned while the
            // lock's presence keeps hatch from confirming any of them.
            if rewrite.refused_pdm_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            if purl.starts_with("pkg:pypi/") && pdm_drives(files) {
                return ProbeStep::Decided(rewrite.confirmed_pdm_uuids.contains(uuid));
            }
            if rewrite.python_lock_uuids.contains(uuid) {
                return ProbeStep::Decided(
                    rewrite.confirmed_python_lock_uuids.contains(uuid)
                        && !rewrite.refused_python_lock_uuids.contains(uuid),
                );
            }
            if rewrite.hatch_uuids.contains(uuid) {
                return ProbeStep::Decided(rewrite.confirmed_hatch_uuids.contains(uuid));
            }
            // A Pipfile.lock rewrite confirms its own uuids (the sibling
            // requirements.txt rewriter may have had nothing to do).
            if purl.starts_with("pkg:pypi/") {
                return ProbeStep::Decided(
                    rewrite.confirmed_pipenv_uuids.contains(uuid)
                        || rewrite.confirmed_requirements_uuids.contains(uuid),
                );
            }
            if rewrite.refused_pnpm_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            // A yarn berry pin is the URL-keyed lock entry AND the manifest
            // `resolutions` routing to it; the URL in `yarn.lock` alone (the
            // routing removed, a refused re-pin) installs nothing, so the
            // berry rewriter's own report decides every dep its lock holds.
            // A yarn classic lock beside an offline mirror installs the
            // upstream mirror tarball whatever `resolved` says.
            if rewrite.refused_yarn_classic_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            if rewrite.yarn_berry_uuids.contains(uuid) {
                return ProbeStep::Decided(rewrite.confirmed_yarn_berry_uuids.contains(uuid));
            }
            // Cargo is transactional: the rewriter reports exactly which
            // patch uuids FULLY landed (manifest pin + lock + registry
            // block). Substring presence must never confirm a cargo dep —
            // the `[registries.…]` config block contains the index URL
            // while pinning nothing, so a config-block-only rewrite would be
            // attested with zero enforcement in any build.
            if purl.starts_with("pkg:cargo/") {
                return ProbeStep::Decided(rewrite.confirmed_cargo_uuids.contains(uuid));
            }
            // Golang likewise: the goproxy `indexUrl` is the bare
            // patch-server origin (present in any other hosted lock), and
            // the socket module's go.sum lines outlive a removed replace.
            if purl.starts_with("pkg:golang/") {
                return ProbeStep::Decided(rewrite.confirmed_golang_uuids.contains(uuid));
            }
            // A Gradle build: the hosted Gradle planner decides (a snippet
            // pasted into a build script pins nothing it can check). A
            // pom.xml beside it must pin the patch as well.
            if purl.starts_with("pkg:maven/") && rewrite.gradle_uuids.contains(uuid) {
                let gradle = rewrite.confirmed_gradle_uuids.contains(uuid)
                    && !rewrite.refused_gradle_uuids.contains(uuid);
                if !gradle || !files.contains_key("pom.xml") {
                    return ProbeStep::Decided(gradle);
                }
                if rewrite.maven_reactor_uuids.contains(uuid) {
                    return ProbeStep::Decided(
                        rewrite.confirmed_maven_reactor_uuids.contains(uuid),
                    );
                }
                let needles = candidate_presence_needles(&c.dep);
                return ProbeStep::Decided(
                    final_texts
                        .iter()
                        .filter(|(name, _)| *name == "pom.xml" || name.starts_with(".mvn/"))
                        .any(|(_, text)| needles.iter().any(|n| text.contains(n.as_str()))),
                );
            }
            // A dep the Maven reactor planner decided: its pin may sit in a
            // module pom, a property or a comment-recorded declaration, so
            // the planner's own report confirms it.
            if rewrite.maven_reactor_uuids.contains(uuid) {
                return ProbeStep::Decided(rewrite.confirmed_maven_reactor_uuids.contains(uuid));
            }
            ProbeStep::Needles(candidate_presence_needles(&c.dep))
        })
        .collect();
    let groups: Vec<&[String]> = steps
        .iter()
        .filter_map(|step| match step {
            ProbeStep::Needles(needles) => Some(needles.as_slice()),
            ProbeStep::Decided(_) => None,
        })
        .collect();
    let mut present = groups_present(&needle_texts, &groups).into_iter();
    candidates
        .iter()
        .zip(&steps)
        .filter(|(_, step)| match step {
            ProbeStep::Decided(keep) => *keep,
            ProbeStep::Needles(_) => present
                .next()
                .expect("one presence answer per needle group"),
        })
        .map(|(c, _)| (c.purl.clone(), c.dep.patch_uuid.clone()))
        .collect()
}

/// A Gradle script, lock file or hosted-Gradle owned file (the hosted
/// Gradle planner's inputs).
fn is_gradle_file(rel: &str) -> bool {
    crate::gradle::dsl::dsl_of(rel).is_some()
        || rel.ends_with(".lockfile")
        || rel.starts_with(".socket/gradle/")
        || rel == "gradle/verification-metadata.xml"
        || rel.ends_with("gradle-wrapper.properties")
}

/// The ecosystem a candidate file's rewriter belongs to (`None` for files
/// no rewriter edits), for the in-memory symlinked/unreadable-read refusal.
fn file_ecosystem(rel: &str) -> Option<&'static str> {
    if let Some(eco) = crate::formats::registry::hosted_file_ecosystem(rel) {
        return Some(eco);
    }
    // Read only beside a classic yarn.lock, for its offline-mirror gate.
    if rel == crate::patch::redirect::YARNRC_REL || rel == NPMRC_REL {
        return Some("npm");
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    // A legacy Gradle lock (`gradle/dependency-locks/<conf>.lockfile`).
    if base.ends_with(".lockfile") {
        return Some("maven");
    }
    (crate::utils::python_lock::is_python_lock_name(base) || base.ends_with(".py"))
        .then_some("pypi")
}

/// A file only the hosted Gradle planner reads or writes: a settings or
/// build script, a dependency lock, the verification metadata, the wrapper
/// properties, or the planner's own owned files.
fn is_gradle_owned_file(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base.ends_with(".gradle")
        || base.ends_with(".gradle.kts")
        || base.ends_with(".lockfile")
        || rel == "gradle/verification-metadata.xml"
        || rel == "gradle/wrapper/gradle-wrapper.properties"
        || rel.starts_with(".socket/gradle/")
}

/// The [`guard`]'s non-UTF-8 rule on its own (#721): the first of
/// `undecodable` (a [`CandidateFiles::undecodable_reads`]) whose ecosystem
/// has a candidate refuses the run. The vendored→hosted takeover runs it
/// before reverting anything, so a refusal never strands a reverted purl.
pub fn undecodable_guard(undecodable: &[String], candidates: &[Candidate]) -> Option<Refusal> {
    undecodable
        .iter()
        .find(|rel| {
            // The root manifest is read strictly only as a yarn berry
            // rewrite target (its `resolutions`); advisory reads never
            // record it, so here it is always an npm rewrite target. A root
            // Gradle script left here (no readable build beside it) may be
            // the build itself, which only maven candidates could patch.
            let eco = file_ecosystem(rel)
                .or((rel.as_str() == "package.json").then_some("npm"))
                .or(crate::vendor::jvm::layout::GRADLE_ROOT_FILES
                    .contains(&rel.as_str())
                    .then_some("maven"));
            eco.is_some_and(|eco| candidates.iter().any(|c| c.dep.ecosystem == eco))
        })
        .map(|rel| undecodable_refusal(rel))
}

/// The non-UTF-8 rule for the poms of a Maven reactor
/// ([`CandidateFiles::undecodable_maven_poms`]): with a Maven candidate,
/// the first of them refuses the run, as an undecodable root `pom.xml`
/// does. A module's pom may be a file of any name, so these are judged by
/// what read them, not by their name.
pub fn undecodable_maven_guard(poms: &[String], candidates: &[Candidate]) -> Option<Refusal> {
    poms.first()
        .filter(|_| candidates.iter().any(|c| c.dep.ecosystem == "maven"))
        .map(|rel| undecodable_refusal(rel))
}

/// SYMLINK GUARD — fail-closed, whole rewrite, before any write (hosted
/// rewrites are transactional). The writer stages next to
/// the path and renames over it, which REPLACES a symbolic link with a
/// detached regular copy: the link target goes stale and a revert restores
/// bytes but never the link. Applies to every ecosystem's files and to dry
/// runs, so a dry run predicts the refusal.
///
/// On disk and in memory: a candidate file that is not UTF-8 text, when a
/// candidate of its ecosystem could rewrite it (#721).
///
/// In memory, additionally: a candidate file read through a link (its bytes
/// are unknown) or present without content, when a candidate of its
/// ecosystem could rewrite it.
pub fn guard(
    view: &ProjectView<'_>,
    done: &Rewritten,
    candidates: &[Candidate],
) -> Option<Refusal> {
    if done.workspace_symlinked {
        return Some(symlink_refusal(PNPM_WORKSPACE_REL));
    }
    let written = || {
        done.rewrite
            .files
            .keys()
            .chain(done.rewrite.binary_files.keys())
            .filter(|k| !crate::patch::redirect::sbt::is_synthetic_key(k))
    };
    if let Some(linked) = written().find(|k| view.is_symlink(k)) {
        return Some(symlink_refusal(linked));
    }
    if let Some(refusal) = undecodable_guard(&done.undecodable_reads, candidates) {
        return Some(refusal);
    }
    if let Some(refusal) = undecodable_maven_guard(&done.undecodable_maven_poms, candidates) {
        return Some(refusal);
    }
    let candidate_ecosystems: BTreeSet<&str> = candidates
        .iter()
        .map(|c| c.dep.ecosystem.as_str())
        .collect();
    // In memory, every linked candidate; on disk, those whose real path
    // leaves the repository root, whose reads the bound refused.
    if let Some(linked) = done
        .symlinked_reads
        .iter()
        .find(|rel| file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco)))
    {
        return Some(linked_read_refusal(view, linked));
    }
    let ProjectView::Memory(project) = view else {
        return None;
    };
    done.unreadable_reads
        .iter()
        .find(|rel| {
            done.rewrite.files.contains_key(rel.as_str())
                || file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco))
        })
        .or_else(|| {
            done.rewrite
                .files
                .keys()
                .find(|k| matches!(project.get(k), Some(MemoryEntry::Present)))
        })
        .map(|rel| unreadable_refusal(rel))
}

/// A `{code, detail}` warning.
pub fn warning(code: &str, detail: impl Into<String>) -> RewriteWarning {
    RewriteWarning {
        code: code.to_string(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::npm_family::RUSH_COMMON_LOCK_REL;
    use crate::vendor::lock_inventory::MemoryProject;

    /// In memory as on disk, a go.work go cannot parse reaches the
    /// rewriter as a workspace go refuses, never as module mode.
    #[tokio::test]
    async fn memory_malformed_go_work_is_invalid() {
        use crate::vendor::go_workspace::Loaded;
        let mut p = MemoryProject::new();
        p.insert_text("go.mod", "module example.com/app\n\ngo 1.21\n");
        p.insert_text("go.work", "go 1.21\n\nuse (\n\t.\n");
        let mut out = CandidateFiles::default();
        read_go_workspace(&ProjectView::Memory(&p), &BTreeSet::new(), &mut out).await;
        let hosted: crate::patch::redirect::HostedGoWorkspace =
            serde_json::from_str(&out.files[crate::patch::redirect::GO_WORKSPACE_KEY]).unwrap();
        assert!(
            matches!(hosted.loaded, Loaded::Invalid(_)),
            "{:?}",
            hosted.loaded
        );
    }

    /// The in-memory engine's workspace is judged lexically, from the
    /// project's own files: a root module go.work doesn't `use` is "not a
    /// member", whatever the process's working directory holds. The disk
    /// checks probed `<cwd>/go.mod` instead, so with this crate's directory
    /// as the cwd (no go.mod) the rewriter called the root module-less
    /// ("nowhere to go"), and with a go.mod there it gave the member answer.
    /// A root go.mod go cannot parse, or one that cannot be read (a link),
    /// still exists: the same files, the same verdict, as discovery's
    /// `in_memory_workspace_files_are_the_files_that_exist` finds.
    #[tokio::test]
    async fn memory_go_workspace_never_probes_the_cwd() {
        use crate::patch::redirect::{
            rewrite_registry_redirect, HostedGoWorkspace, Integrity, RegistryOverride,
            RegistryOverrideIdentifiers, GO_WORKSPACE_KEY,
        };
        use crate::vendor::go_workspace::{Loaded, WorkspaceConflict};
        const MODULE: &str = "github.com/foo/bar";
        let socket = format!("patch.socket.dev/gopatch/{PATCH_UUID}");
        let hash = format!("h1:{}=", "A".repeat(43));
        let ovr = DepOverride {
            ecosystem: "golang".into(),
            name: MODULE.into(),
            version: "v1.4.2".into(),
            registry_override: Some(RegistryOverride {
                kind: "goproxy".into(),
                index_url: "https://patch.socket.dev/patch-registry/golang".into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: MODULE.into(),
                    version: "v1.4.2".into(),
                    go_module_path: Some(socket.clone()),
                    go_module_version: Some("v1.4.2-socketpatch.1".into()),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                dirhash_h1: Some(hash.clone()),
                go_mod_h1: Some(hash),
                ..Default::default()
            },
            ..grant_dep("golang", String::new())
        };
        let go_mod = format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} v1.4.2\n");
        let b = format!("module example.com/b\n\ngo 1.21\n\nrequire {MODULE} v1.4.2\n");
        let work = "go 1.21\n\nuse ./b\n";
        let ours = crate::vendor::go_mod_edit::ReplaceEntry {
            module: MODULE.into(),
            version: Some("v1.4.2".into()),
            path: None,
            rhs_module: Some(socket),
            rhs_version: Some("v1.4.2-socketpatch.1".into()),
            owner: Some(crate::vendor::go_mod_edit::ReplaceOwner::Hosted),
        };
        let unparseable = MemoryEntry::Text("module example.com/app\n\nrequire (\n".into());
        for root in [
            MemoryEntry::Text(go_mod.as_str().into()),
            unparseable,
            MemoryEntry::Symlink,
        ] {
            let mut p = MemoryProject::new();
            p.insert("go.mod", root.clone());
            p.insert_text("go.work", work);
            p.insert_text("b/go.mod", b.as_str());
            let mut out = CandidateFiles::default();
            read_go_workspace(&ProjectView::Memory(&p), &BTreeSet::new(), &mut out).await;
            let hosted: HostedGoWorkspace =
                serde_json::from_str(&out.files[GO_WORKSPACE_KEY]).unwrap();
            let Loaded::Workspace(ws) = &hosted.loaded else {
                panic!("{root:?}: {:?}", hosted.loaded);
            };
            assert_eq!(
                ws.files,
                Some(
                    ["go.mod", "go.work", "b/go.mod"]
                        .into_iter()
                        .map(std::path::PathBuf::from)
                        .collect()
                ),
                "{root:?}"
            );
            assert!(
                matches!(
                    hosted
                        .loaded
                        .conflict(&hosted.root, MODULE, "v1.4.2", &ours),
                    Some(WorkspaceConflict::NotAMember { .. })
                ),
                "{root:?}"
            );
        }
        // Review on #2031 (round 2): a member go.mod go cannot parse is
        // still weighed, as the disk loader keeps it: one declaring the
        // patched module makes every replace of it inert (refused).
        let mut p = MemoryProject::new();
        p.insert_text("go.mod", go_mod.as_str());
        p.insert_text("go.work", "go 1.21\n\nuse (\n\t.\n\t./b\n)\n");
        p.insert_text("b/go.mod", format!("module {MODULE}\n\nrequire (\n"));
        let mut out = CandidateFiles::default();
        read_go_workspace(&ProjectView::Memory(&p), &BTreeSet::new(), &mut out).await;
        let hosted: HostedGoWorkspace = serde_json::from_str(&out.files[GO_WORKSPACE_KEY]).unwrap();
        assert!(
            matches!(
                hosted
                    .loaded
                    .conflict(&hosted.root, MODULE, "v1.4.2", &ours),
                Some(WorkspaceConflict::MainModule { .. })
            ),
            "{:?}",
            hosted.loaded
        );

        // End to end through the rewriter.
        let mut p = MemoryProject::new();
        p.insert_text("go.mod", go_mod.as_str());
        p.insert_text("go.work", work);
        p.insert_text("b/go.mod", b.as_str());
        let mut read = CandidateFiles::default();
        read_go_workspace(&ProjectView::Memory(&p), &BTreeSet::new(), &mut read).await;
        let mut files = read.files;
        for (path, text) in [("go.mod", go_mod.as_str()), ("go.work", work)] {
            files.insert(path.into(), text.into());
        }
        let out = rewrite_registry_redirect(&files, std::slice::from_ref(&ovr));
        assert!(out.files.is_empty(), "{:?}", out.files);
        assert!(out.confirmed_golang_uuids.is_empty());
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert_eq!(out.warnings[0].code, "redirect_golang_workspace_conflict");
        assert!(
            out.warnings[0]
                .detail
                .contains("go.work does not `use` this module"),
            "{:?}",
            out.warnings
        );
    }

    /// A disk candidate whose real path leaves the repository root, as
    /// the file itself or through a directory link on its path, is
    /// recorded as a linked read (refused by the guard), never as absent.
    #[cfg(unix)]
    #[tokio::test]
    async fn disk_candidates_linked_out_of_the_repository_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        std::fs::write(outside.join("uv.lock"), "version = 1\n").unwrap();
        std::fs::write(outside.join("sub/package-lock.json"), "{}\n").unwrap();
        std::os::unix::fs::symlink(outside.join("uv.lock"), repo.join("uv.lock")).unwrap();
        std::os::unix::fs::symlink(outside.join("sub"), repo.join("sub")).unwrap();
        let view = ProjectView::Disk(&repo);
        let mut out = CandidateFiles::default();
        for rel in ["uv.lock", "sub/package-lock.json"] {
            assert!(!out.read(&view, &BTreeSet::new(), rel).await, "{rel}");
        }
        assert_eq!(out.symlinked_reads, ["uv.lock", "sub/package-lock.json"]);
        assert!(out.files.is_empty());
        let file = linked_read_refusal(&view, "uv.lock");
        assert_eq!(file.code, SYMLINK_REFUSAL);
        assert!(
            file.message.contains("uv.lock is a symbolic link"),
            "{}",
            file.message
        );
        let dir = linked_read_refusal(&view, "sub/package-lock.json");
        assert_eq!(dir.code, SYMLINK_REFUSAL);
        assert!(
            dir.message.contains("leaves the repository root"),
            "{}",
            dir.message
        );
    }

    fn no_maven_selection() -> Option<MavenSelection> {
        None
    }

    fn no_cargo_outer() -> CratesIoSource {
        CratesIoSource::Registry
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    const GRANT: &str = "GRANTTOKEN0123";
    const PATCH_UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";

    fn grant_dep(ecosystem: &str, artifact_url: String) -> DepOverride {
        DepOverride {
            ecosystem: ecosystem.into(),
            name: "left-pad".into(),
            namespace: None,
            version: "1.3.0".into(),
            token: GRANT.into(),
            patch_uuid: PATCH_UUID.into(),
            artifact_url,
            npm_registry_url: None,
            registry_override: None,
            integrity: crate::patch::redirect::Integrity::default(),
        }
    }

    /// A candidate of `ecosystem` on Socket's patch server, shaped the way
    /// the reference endpoint grants it, with the registry override its
    /// ecosystem carries.
    fn mirror_candidate(ecosystem: &str, name: &str, version: &str) -> Candidate {
        use crate::patch::redirect::{RegistryOverride, RegistryOverrideIdentifiers};
        const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
        let registry = |kind: &str, tail: &str| {
            Some(RegistryOverride {
                kind: kind.into(),
                index_url: format!(
                    "https://patch.socket.dev/patch-registry/{ecosystem}/{TOKEN}/{PATCH_UUID}/{tail}"
                ),
                identifiers: RegistryOverrideIdentifiers::default(),
            })
        };
        let mut dep = grant_dep(
            ecosystem,
            format!(
                "https://patch.socket.dev/patch/{ecosystem}/{name}/{version}/{TOKEN}/{PATCH_UUID}/artifact.bin"
            ),
        );
        dep.name = name.into();
        dep.version = version.into();
        dep.token = TOKEN.into();
        dep.registry_override = match ecosystem {
            "gem" => registry("rubygems-compact-index", ""),
            "maven" => registry("maven2", "maven2"),
            "cargo" => registry("cargo-sparse", "index/"),
            "nuget" => registry("nuget-v3", "index.json"),
            "golang" => registry("goproxy", ""),
            _ => None,
        };
        Candidate {
            purl: format!("pkg:{ecosystem}/{name}@{version}"),
            dep,
        }
    }

    /// `--patch-mirror-url` moves every reference a client fetches by URL
    /// onto the mirror (same path), leaves a Go module pin alone, and
    /// withholds the two registries whose index names the patch server's
    /// own host: nothing direct is written in their place.
    #[test]
    fn mirror_candidates_moves_url_references_and_withholds_what_a_mirror_cannot_carry() {
        use crate::patch::redirect::mirror::PatchMirror;
        let mirror = PatchMirror::parse("https://repo.example/artifactory/socket-patch").unwrap();
        let origins = vec![mirror.base().to_string()];
        let candidates = vec![
            mirror_candidate("npm", "left-pad", "1.3.0"),
            mirror_candidate("pypi", "urllib3", "1.26.18"),
            mirror_candidate("composer", "acme/lib", "1.0.0"),
            mirror_candidate("gem", "rack", "3.0.0"),
            mirror_candidate("maven", "org.acme/lib", "1.0.0"),
            mirror_candidate("golang", "github.com/acme/lib", "v1.0.0"),
            mirror_candidate("cargo", "serde", "1.0.0"),
            mirror_candidate("nuget", "Newtonsoft.Json", "13.0.3"),
        ];
        let served: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let (kept, sources) =
            mirror_candidates(candidates, &mirror, &origins, &mut skipped, &mut warnings);

        let ecosystems: Vec<&str> = kept.iter().map(|c| c.dep.ecosystem.as_str()).collect();
        assert_eq!(
            ecosystems,
            ["npm", "pypi", "composer", "gem", "maven", "golang"]
        );
        for (candidate, before) in kept.iter().zip(&served) {
            let dep = &candidate.dep;
            if dep.ecosystem == "golang" {
                assert_eq!(dep.artifact_url, before.artifact_url);
                assert_eq!(
                    dep.registry_override.as_ref().unwrap().index_url,
                    before.registry_override.as_ref().unwrap().index_url
                );
                assert_eq!(
                    sources.fetch_url(&dep.artifact_url),
                    dep.artifact_url.as_str()
                );
                continue;
            }
            // Same path, the mirror's base in front of it.
            let path = before
                .artifact_url
                .strip_prefix("https://patch.socket.dev")
                .unwrap();
            assert_eq!(
                dep.artifact_url,
                format!("https://repo.example/artifactory/socket-patch{path}")
            );
            // The run's own downloads still read the patch server.
            assert_eq!(
                sources.fetch_url(&dep.artifact_url),
                before.artifact_url.as_str()
            );
            if let (Some(ov), Some(before_ov)) = (&dep.registry_override, &before.registry_override)
            {
                let path = before_ov
                    .index_url
                    .strip_prefix("https://patch.socket.dev")
                    .unwrap();
                assert_eq!(
                    ov.index_url,
                    format!("https://repo.example/artifactory/socket-patch{path}")
                );
                // A file under the mirrored index is downloaded from under
                // the served one.
                let under = format!("{}/gems/x.gem", ov.index_url.trim_end_matches('/'));
                assert_eq!(
                    sources.fetch_url(&under),
                    format!("{}/gems/x.gem", before_ov.index_url.trim_end_matches('/'))
                );
            }
            // The mirrored reference names the same patch and token.
            assert_eq!(
                crate::origin::hosted_patch_uuid(&dep.artifact_url, &origins).as_deref(),
                Some(PATCH_UUID)
            );
            assert_eq!(dep.token, before.token);
        }
        assert_eq!(
            skipped
                .iter()
                .map(|s| (s.purl.as_str(), s.reason.as_str()))
                .collect::<Vec<_>>(),
            [
                ("pkg:cargo/serde@1.0.0", MIRROR_UNSUPPORTED),
                ("pkg:nuget/Newtonsoft.Json@13.0.3", MIRROR_UNSUPPORTED),
            ]
        );
        assert_eq!(warnings.len(), 2);
        for w in &warnings {
            assert_eq!(w.code, MIRROR_UNSUPPORTED);
            assert!(w.detail.contains("--mode vendored"), "{}", w.detail);
            assert!(
                !w.detail.contains("22222222-2222-4222-8222-222222222222"),
                "a skip detail never carries the grant token: {}",
                w.detail
            );
        }
    }

    /// A plain-`http` mirror is taken because the operator named it (its
    /// base is one of the run's origins); a grant that has no path to
    /// serve is withheld instead of being pinned at the mirror's root.
    #[test]
    fn mirror_candidates_takes_an_http_mirror_and_refuses_a_pathless_grant() {
        use crate::patch::redirect::mirror::PatchMirror;
        let mirror = PatchMirror::parse("http://artifactory.corp:8081/artifactory/sp").unwrap();
        let origins = vec![mirror.base().to_string()];
        let mut pathless = mirror_candidate("npm", "left-pad", "1.3.0");
        pathless.dep.artifact_url = "https://patch.socket.dev".into();
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let (kept, sources) = mirror_candidates(
            vec![mirror_candidate("npm", "left-pad", "1.3.0"), pathless],
            &mirror,
            &origins,
            &mut skipped,
            &mut warnings,
        );
        assert_eq!(kept.len(), 1);
        assert!(kept[0]
            .dep
            .artifact_url
            .starts_with("http://artifactory.corp:8081/artifactory/sp/patch/npm/left-pad/"));
        assert_eq!(sources.mirrored_urls().count(), 1);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].reason, MIRROR_URL_REFUSED);

        // Without the mirror among the origins the grant gate refuses the
        // plain-http URL, so the caller's allowlist is load-bearing.
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let (kept, _) = mirror_candidates(
            vec![mirror_candidate("npm", "left-pad", "1.3.0")],
            &mirror,
            &[],
            &mut skipped,
            &mut warnings,
        );
        assert!(kept.is_empty());
        assert_eq!(skipped[0].reason, MIRROR_URL_REFUSED);
    }

    /// A patch the project's files already pin through a host the run was
    /// not given is withheld; one pinned on an accepted origin, or not
    /// pinned at all, is not.
    #[test]
    fn a_pin_on_an_unconfigured_host_is_withheld_and_named() {
        let candidate = mirror_candidate("npm", "left-pad", "1.3.0");
        let path = candidate
            .dep
            .artifact_url
            .strip_prefix("https://patch.socket.dev")
            .unwrap()
            .to_string();
        let lock_at = |base: &str| {
            BTreeMap::from([(
                "package-lock.json".to_string(),
                format!(r#"{{"resolved": "{base}{path}", "integrity": "sha512-x"}}"#),
            )])
        };
        let run = |files: &BTreeMap<String, String>, accepted: &[String]| {
            let mut candidates = vec![candidate.clone()];
            let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
            withhold_foreign_host_pins(
                files,
                accepted,
                &mut candidates,
                &mut skipped,
                &mut warnings,
            );
            (candidates.len(), skipped, warnings)
        };
        let mirror = "https://repo.example/artifactory/socket-patch";

        // The mirror was not given: withheld, the host and the setting named.
        let (kept, skipped, warnings) = run(&lock_at(mirror), &[]);
        assert_eq!(kept, 0);
        assert_eq!(skipped[0].reason, PIN_ON_UNCONFIGURED_HOST);
        assert!(
            warnings[0].detail.contains("repo.example")
                && warnings[0].detail.contains("--patch-mirror-url")
                && warnings[0].detail.contains("package-lock.json"),
            "{}",
            warnings[0].detail
        );
        // The mirror was given: the run's own pin.
        assert_eq!(run(&lock_at(mirror), &[mirror.to_string()]).0, 1);
        // Pinned on Socket's own server, or still on the registry.
        assert_eq!(run(&lock_at("https://patch.socket.dev"), &[]).0, 1);
        let registry = BTreeMap::from([(
            "package-lock.json".to_string(),
            r#"{"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}"#
                .to_string(),
        )]);
        assert_eq!(run(&registry, &[]).0, 1);
        // A lock that spells the url inside a specifier, as bun and yarn
        // berry key a tarball dependency (`name@https://…`).
        let specifier = BTreeMap::from([(
            "yarn.lock".to_string(),
            format!("\"left-pad@{mirror}{path}\":\n  resolution: \"left-pad@{mirror}{path}\"\n"),
        )]);
        let (kept, skipped, _) = run(&specifier, &[]);
        assert_eq!(kept, 0);
        assert_eq!(skipped[0].reason, PIN_ON_UNCONFIGURED_HOST);
        assert_eq!(run(&specifier, &[mirror.to_string()]).0, 1);
        // The same text read for where it pins the patch: the mirror when
        // the mirror is a known origin, nothing when it is not, and the
        // patch server for a direct pin.
        let pinned_on = |files: &BTreeMap<String, String>, origins: &[String]| {
            files.values().find_map(|text| {
                crate::vex::discover::hosted_host_in_text(text, PATCH_UUID, origins)
            })
        };
        assert_eq!(
            pinned_on(&specifier, &[mirror.to_string()]).as_deref(),
            Some("repo.example")
        );
        assert_eq!(pinned_on(&specifier, &[]), None);
        assert_eq!(
            pinned_on(&lock_at("https://patch.socket.dev"), &[]).as_deref(),
            Some("patch.socket.dev")
        );
        // An older composer.lock escapes every slash. Pinned on Socket's
        // own server it is the run's own pin, not one on a host called
        // `https`; pinned on a mirror the run was not given, it is withheld
        // and the mirror's host is named.
        let escaped = |base: &str| {
            let url = format!("{base}{path}").replace('/', "\\/");
            BTreeMap::from([(
                "composer.lock".to_string(),
                format!(r#"{{"dist": {{"url": "{url}"}}}}"#),
            )])
        };
        assert!(escaped(mirror)["composer.lock"].contains(r"https:\/\/repo.example\/"));
        assert_eq!(run(&escaped("https://patch.socket.dev"), &[]).0, 1);
        assert_eq!(run(&escaped(mirror), &[mirror.to_string()]).0, 1);
        let (kept, _, warnings) = run(&escaped(mirror), &[]);
        assert_eq!(kept, 0);
        assert!(
            warnings[0].detail.contains("repo.example"),
            "{}",
            warnings[0].detail
        );
        assert_eq!(
            pinned_on(&escaped(mirror), &[mirror.to_string()]).as_deref(),
            Some("repo.example")
        );
        // Another repository of the mirror's host is not the mirror, once
        // the mirror is listed as one (`mirror_entry`, as the CLI lists it).
        let sibling = "https://repo.example/artifactory/team-local";
        let listed = [crate::origin::mirror_entry(mirror)];
        assert_eq!(run(&lock_at(mirror), &listed).0, 1);
        assert_eq!(run(&lock_at(sibling), &listed).0, 0);
        assert_eq!(pinned_on(&lock_at(sibling), &listed), None);
        assert_eq!(
            pinned_on(&lock_at(mirror), &listed).as_deref(),
            Some("repo.example")
        );
        // Another patch's uuid on that host says nothing about this one.
        let other = lock_at(mirror).into_iter().map(|(k, v)| {
            (
                k,
                v.replace(PATCH_UUID, "99999999-9999-4999-8999-999999999999"),
            )
        });
        assert_eq!(run(&other.collect(), &[]).0, 1);
    }

    /// The hosted skip details reach `--json`: neither the grant token nor
    /// any userinfo survives, however reqwest re-renders the URL (a
    /// trailing `/`, a different quoting) and under whatever root the
    /// server serves it (a custom `--api-url` with no `/patch/` level).
    #[test]
    fn hosted_skip_details_never_carry_the_grant_token() {
        for (url, uuid) in [
            (
                format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/{PATCH_UUID}/left-pad-1.3.0.tgz"),
                PATCH_UUID,
            ),
            (
                format!("https://u:pw@api.corp.example/serve/{GRANT}/{PATCH_UUID}/left-pad-1.3.0.tgz"),
                PATCH_UUID,
            ),
            // A non-canonical patch id: the shape-based redactor cannot
            // tell its level is a uuid, the dep can.
            (
                format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/patch-42/x.tgz"),
                "patch-42",
            ),
        ] {
            let mut dep = grant_dep("npm", url.clone());
            dep.patch_uuid = uuid.into();
            let detail = format!(
                "error sending request for url ({url}?x=1): connection refused (proxy https://p:pw@proxy:3128)"
            );
            for skip in [
                npm_manifest_unavailable(&dep, &detail),
                wheel_metadata_unavailable(&dep, &detail),
            ] {
                let got = skip.detail.unwrap();
                assert!(!got.contains(GRANT), "{url}: {got}");
                assert!(!got.contains("u:pw") && !got.contains("p:pw"), "{got}");
                assert!(got.contains("connection refused"), "{got}");
            }
        }
        let dep = grant_dep("npm", format!("https://h/serve/{GRANT}/{PATCH_UUID}/a.tgz"));
        assert_eq!(
            redact_artifact_text("no url here", &dep.artifact_url, &dep.patch_uuid),
            "no url here"
        );
    }

    fn reference(value: serde_json::Value) -> PackageVendorResult {
        serde_json::from_value(value).unwrap()
    }

    /// #558 review: the served tarball is fetched only for a lock that
    /// really locks a registry copy of the package, read by block names
    /// (`lodash` is not `lodash.debounce`) and copy source (a git or
    /// `file:` copy is never pinned).
    #[test]
    fn classic_registry_copy_is_matched_by_block_name_and_source() {
        let lock = "# yarn lockfile v1\n\n\
                    lodash.debounce@^4.0.8:\n  version \"4.17.21\"\n  \
                    resolved \"https://registry.yarnpkg.com/lodash.debounce/-/x.tgz#aa\"\n\n\
                    left-pad@git+https://github.com/x/left-pad.git:\n  version \"1.3.0\"\n  \
                    resolved \"git+https://github.com/x/left-pad.git#abc\"\n\n\
                    is-odd@^3.0.0:\n  version \"3.0.1\"\n  \
                    resolved \"https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz#bb\"\n";
        let copies = classic_registry_copies(lock);
        let has = |name: &str, version: &str| copies.contains(&(name.into(), version.into()));
        assert!(!has("lodash", "4.17.21"));
        assert!(!has("left-pad", "1.3.0"));
        assert!(!has("is-odd", "3.0.0"));
        assert!(has("is-odd", "3.0.1"));
        assert!(has("lodash.debounce", "4.17.21"));
        assert_eq!(copies.len(), 2);
    }

    fn classic_candidate(name: &str, version: &str, sha1: Option<&str>) -> Candidate {
        let url = format!("https://h/serve/{GRANT}/{name}-{version}.tgz");
        let mut dep = grant_dep("npm", url);
        dep.name = name.into();
        dep.version = version.into();
        dep.integrity.sha512 = Some("sha512-x".into());
        dep.integrity.sha1 = sha1.map(Into::into);
        Candidate {
            purl: format!("pkg:npm/{name}@{version}"),
            dep,
        }
    }

    #[test]
    fn quoted_fragment_urls_reads_each_resolved_url() {
        let lock = "a@^1:\n  resolved \"https://r/a.tgz#aa\"\n\
                    b@^1:\n  resolved \"https://r/b.tgz\"\n\
                    \"c@^1\", \"c@^2\":\n  resolved \"https://r/c.tgz#cc\"\n";
        let urls = quoted_fragment_urls(lock);
        assert_eq!(
            urls,
            HashSet::from(["https://r/a.tgz", "https://r/c.tgz"]),
            "{urls:?}"
        );
    }

    /// #1423: the served tarball is read only for a dep the lock pins to
    /// the artifact or locks as a registry copy. The lock's blocks are
    /// read at most once however many deps there are, and not at all on a
    /// rescan whose deps are all pinned already.
    #[test]
    fn classic_artifact_targets_read_the_lock_blocks_at_most_once() {
        let mut lock = String::from("# yarn lockfile v1\n\n");
        let n = 200;
        for i in 0..n {
            lock.push_str(&format!(
                "pkg-{i}@^1.0.0:\n  version \"1.0.{i}\"\n  \
                 resolved \"https://registry.yarnpkg.com/pkg-{i}/-/pkg-{i}-1.0.{i}.tgz#aa\"\n\n"
            ));
        }
        lock.push_str(
            "gitdep@git+https://github.com/x/gitdep.git:\n  version \"2.0.0\"\n  \
             resolved \"git+https://github.com/x/gitdep.git#abc\"\n",
        );
        let mut candidates: Vec<Candidate> = (0..n)
            .map(|i| classic_candidate(&format!("pkg-{i}"), &format!("1.0.{i}"), Some("s1")))
            .collect();
        let reads = std::cell::Cell::new(0);
        let counted = |lock: &str| {
            reads.set(reads.get() + 1);
            classic_registry_copies(lock)
        };

        // Every dep pinned to its artifact already: each tarball is still
        // read, since an earlier release pinned it without checking its
        // dependencies (#1462), but the blocks are never read.
        let mut pinned = lock.clone();
        for c in &candidates {
            pinned.push_str(&format!("# \"{}#s1\"\n", c.dep.artifact_url));
        }
        assert_eq!(
            select_classic_artifacts(&candidates, &pinned, counted).len(),
            n
        );
        assert_eq!(reads.get(), 0);

        // Unpinned: every registry copy is selected once per artifact; a
        // version the lock doesn't lock, a name it doesn't have, a git copy
        // and a non-npm dep never. One read of the blocks for all of them.
        candidates.push(classic_candidate("pkg-0", "9.9.9", None));
        candidates.push(classic_candidate("absent", "1.0.0", None));
        candidates.push(classic_candidate("gitdep", "2.0.0", None));
        candidates.push(classic_candidate("pkg-1", "1.0.1", Some("s1")));
        let mut pypi = classic_candidate("pkg-2", "1.0.2", None);
        pypi.dep.ecosystem = "pypi".into();
        candidates.push(pypi);
        let got: Vec<String> = select_classic_artifacts(&candidates, &lock, counted)
            .into_iter()
            .map(|d| format!("{}@{}", d.name, d.version))
            .collect();
        assert_eq!(reads.get(), 1);
        assert_eq!(got.len(), n);
        assert_eq!(got[0], "pkg-0@1.0.0");
        assert_eq!(got[n - 1], format!("pkg-{}@1.0.{}", n - 1, n - 1));

        // The public entry point selects the same deps from the files.
        let files = BTreeMap::from([("yarn.lock".to_string(), lock)]);
        let outer = OuterYarnMirror::default();
        assert_eq!(
            yarn_classic_artifact_targets(&candidates, &files, &outer).len(),
            n
        );
    }

    #[test]
    fn candidates_skip_every_unusable_reference() {
        let mut refs: HashMap<String, PackageVendorResult> = HashMap::new();
        refs.insert(
            "u-pending".into(),
            reference(serde_json::json!({"status": "pending_build"})),
        );
        refs.insert(
            "u-nourl".into(),
            reference(serde_json::json!({"status": "granted", "purl": "pkg:npm/b@1"})),
        );
        refs.insert(
            PATCH_UUID.into(),
            reference(serde_json::json!({
                "status": "reused",
                "url": format!("https://patch.example/patch/npm/c/1/tok/{PATCH_UUID}/c-1.tgz"),
                "purl": "pkg:npm/c@1",
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha512": "sha512-x"}}],
                "registryOverride": null
            })),
        );
        let selected = vec![
            ("pkg:npm/a@1".to_string(), "u-missing".to_string()),
            ("pkg:npm/p@1".to_string(), "u-pending".to_string()),
            ("pkg:npm/b@1".to_string(), "u-nourl".to_string()),
            ("pkg:npm/c@1".to_string(), PATCH_UUID.to_string()),
        ];
        let mut skipped = Vec::new();
        let mut warnings = Vec::new();
        let candidates = build_candidates(&selected, &refs, &[], &mut skipped, &mut warnings);
        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(reasons, vec!["not_found", "pending_build", "no_url"]);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].dep.token, "tok");
        assert_eq!(
            candidates[0].dep.integrity.sha512.as_deref(),
            Some("sha512-x")
        );
    }

    /// A granted reference with a field no project file takes verbatim, or
    /// a plain-http URL on some other host, never becomes a candidate: it
    /// is skipped under the selection's purl with the field named, and
    /// warned once with the same detail. A configured patch server's
    /// plain-http URL is taken.
    #[test]
    fn candidates_refuse_a_malformed_or_plain_http_grant() {
        const SEL: &str = "pkg:npm/c@1";
        let grant = |edit: fn(&mut serde_json::Value)| {
            let mut value = serde_json::json!({
                "status": "granted",
                "url": format!("https://patch.example/patch/npm/c/1/tok/{PATCH_UUID}/c-1.tgz"),
                "purl": SEL,
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {
                    "sha512": "sha512-x", "sha1": "a".repeat(40)
                }}],
                "registryOverride": null
            });
            edit(&mut value);
            HashMap::from([(PATCH_UUID.to_string(), reference(value))])
        };
        let selected = vec![(SEL.to_string(), PATCH_UUID.to_string())];
        let build = |refs: &HashMap<String, PackageVendorResult>, origins: &[String]| {
            let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
            let candidates =
                build_candidates(&selected, refs, origins, &mut skipped, &mut warnings);
            (candidates, skipped, warnings)
        };
        type Edit = fn(&mut serde_json::Value);
        let cases: [(&str, &str, Edit); 4] = [
            (GRANT_MALFORMED, "its sha1 is not 40 hex digits", |v| {
                v["artifacts"][0]["integrity"]["sha1"] =
                    format!("{}\"\n  evil \"pwned", "a".repeat(40)).into();
            }),
            (GRANT_MALFORMED, "its package name or version is not", |v| {
                v["purl"] = "pkg:npm/c%0Aevil@1".into();
            }),
            (GRANT_MALFORMED, "its package URL holds whitespace", |v| {
                v["purl"] = "pkg:npm/c@1?x=a\nb".into();
            }),
            (
                GRANT_INSECURE_URL,
                "its artifact URL is plain http on patch.example,",
                |v| {
                    let url = v["url"].as_str().unwrap().replace("https://", "http://");
                    v["url"] = url.into();
                },
            ),
        ];
        for (code, reason, edit) in cases {
            let (candidates, skipped, warnings) = build(&grant(edit), &[]);
            assert!(candidates.is_empty(), "{reason}");
            assert_eq!(skipped.len(), 1, "{reason}");
            assert_eq!(
                (skipped[0].purl.as_str(), skipped[0].uuid.as_str()),
                (SEL, PATCH_UUID)
            );
            assert_eq!(skipped[0].reason, code, "{reason}");
            let detail = skipped[0].detail.as_deref().unwrap();
            assert!(
                detail.starts_with(&format!(
                    "{SEL}: the patch server's reference for it was refused ({reason}"
                )) && detail.ends_with("nothing was written for it, so it stays unpatched"),
                "{detail}"
            );
            assert!(
                !detail.contains("pwned") && !detail.contains('\n'),
                "{detail:?}"
            );
            assert_eq!(warnings, vec![warning(code, detail.to_string())]);
        }

        // The operator's own patch server may be plain http; the selection's
        // uuid is held to the canonical shape like every other field.
        let plain_http: Edit = |v| {
            let url = v["url"].as_str().unwrap().replace("https://", "http://");
            v["url"] = url.into();
        };
        let (candidates, skipped, warnings) =
            build(&grant(plain_http), &["http://patch.example".to_string()]);
        assert_eq!(candidates.len(), 1, "{skipped:?}");
        assert!(warnings.is_empty(), "{warnings:?}");
        let mut refs = grant(|_| {});
        let reference = refs.remove(PATCH_UUID).unwrap();
        refs.insert("u-ok".to_string(), reference);
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let candidates = build_candidates(
            &[(SEL.to_string(), "u-ok".to_string())],
            &refs,
            &[],
            &mut skipped,
            &mut warnings,
        );
        assert!(candidates.is_empty());
        assert_eq!(skipped[0].reason, GRANT_MALFORMED);
        assert!(
            skipped[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("its patch uuid is not"),
            "{skipped:?}"
        );
    }

    /// One reference response answers for a whole batch. A prebuild entry
    /// that IS a platform and a checksum, but not in the shape the lock
    /// takes, fails the grant it rides in and no other: the gem is skipped
    /// with the field named, and the other package keeps its candidate.
    #[test]
    fn a_wrong_gem_prebuild_fails_only_its_own_grant() {
        const GEM: &str = "pkg:gem/nokogiri@1.18.10";
        const NPM: &str = "pkg:npm/c@1";
        const GEM_UUID: &str = "5e6f7081-92a3-4b4c-8d5e-6f708192a3b4";
        let refs = HashMap::from([
            (
                GEM_UUID.to_string(),
                reference(serde_json::json!({
                    "status": "granted",
                    "url": format!("https://patch.example/patch/gem/t/{GEM_UUID}/nokogiri-1.18.10.gem"),
                    "purl": GEM,
                    "artifacts": [{"kind": "tarball", "url": null, "integrity": {
                        "sha256": "a".repeat(64)
                    }}],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": format!("https://patch.example/patch-registry/gem/t/{GEM_UUID}/"),
                        "identifiers": {
                            "name": "nokogiri", "version": "1.18.10",
                            "gemChecksumSha256": "a".repeat(64),
                            "gemPlatforms": [
                                {"platform": "arm64-darwin", "gemChecksumSha256": "not-a-digest"}
                            ]
                        }
                    }
                })),
            ),
            (
                PATCH_UUID.to_string(),
                reference(serde_json::json!({
                    "status": "granted",
                    "url": format!("https://patch.example/patch/npm/c/1/tok/{PATCH_UUID}/c-1.tgz"),
                    "purl": NPM,
                    "artifacts": [{"kind": "tarball", "url": null, "integrity": {
                        "sha512": "sha512-x", "sha1": "a".repeat(40)
                    }}],
                    "registryOverride": null
                })),
            ),
        ]);
        let selected = vec![
            (GEM.to_string(), GEM_UUID.to_string()),
            (NPM.to_string(), PATCH_UUID.to_string()),
        ];
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let candidates = build_candidates(&selected, &refs, &[], &mut skipped, &mut warnings);
        let kept: Vec<&str> = candidates.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(kept, [NPM], "{skipped:?}");
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(
            (skipped[0].purl.as_str(), skipped[0].reason.as_str()),
            (GEM, GRANT_MALFORMED)
        );
        assert!(
            skipped[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("its gem platform checksum is not 64 hex digits"),
            "{skipped:?}"
        );
    }

    /// A granted cargo reference for `uuid` (a canonical uuid), with no
    /// registry override.
    fn cargo_reference(
        uuid: &str,
    ) -> (Vec<(String, String)>, HashMap<String, PackageVendorResult>) {
        let purl = "pkg:cargo/serde@1.0.190";
        let mut refs = HashMap::new();
        refs.insert(
            uuid.to_string(),
            reference(serde_json::json!({
                "status": "granted",
                "url": format!("https://patch.example/patch/cargo/serde/1.0.190/tok/{uuid}/serde-1.0.190.crate"),
                "purl": purl,
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha256": "ab".repeat(32)}}],
                "registryOverride": null
            })),
        );
        (vec![(purl.to_string(), uuid.to_string())], refs)
    }

    /// [`build_candidates`] with no configured patch server, for a fixture
    /// whose grants are all well formed.
    fn candidates_of(
        selected: &[(String, String)],
        refs: &HashMap<String, PackageVendorResult>,
    ) -> Vec<Candidate> {
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let candidates = build_candidates(selected, refs, &[], &mut skipped, &mut warnings);
        assert!(skipped.is_empty(), "{skipped:?}");
        candidates
    }

    /// #653: the toolchain files are the cargo planner's declared-floor
    /// input when `Cargo.toml` has no `rust-version`, so they are read
    /// (never edited, and naming no ecosystem to refuse).
    #[tokio::test]
    async fn the_cargo_toolchain_files_are_read_as_advisory_input() {
        let (selected, refs) = cargo_reference(PATCH_UUID);
        let mut p = MemoryProject::new();
        p.insert_text("Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        p.insert_text("rust-toolchain.toml", "[toolchain]\nchannel = \"1.67.1\"\n");
        p.insert_text("rust-toolchain", "1.56.0\n");
        let candidates = candidates_of(&selected, &refs);
        let view = ProjectView::Memory(&p);
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert_eq!(
            read.files.get("rust-toolchain.toml").map(String::as_str),
            Some("[toolchain]\nchannel = \"1.67.1\"\n")
        );
        assert_eq!(
            read.files.get("rust-toolchain").map(String::as_str),
            Some("1.56.0\n")
        );
        for rel in ["rust-toolchain.toml", "rust-toolchain"] {
            assert_eq!(crate::formats::registry::hosted_file_ecosystem(rel), None);
        }
    }

    #[tokio::test]
    async fn an_unreadable_candidate_file_refuses_its_ecosystem() {
        let (selected, refs) = cargo_reference(PATCH_UUID);
        let mut p = MemoryProject::new();
        p.insert_text("Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        p.insert_text(
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        p.insert_present(".cargo/config");
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = candidates_of(&selected, &refs);
        let view = ProjectView::Memory(&p);
        let unreadable = BTreeSet::from([".cargo/config".to_string()]);
        let read = read_candidate_files(&view, &unreadable, &candidates).await;
        assert_eq!(read.unreadable_reads, vec![".cargo/config"]);
        let done = rewrite(&view, read, &candidates, BTreeMap::new(), options).await;
        assert_eq!(
            guard(&view, &done, &candidates).unwrap().code,
            UNREADABLE_REFUSAL
        );

        // A non-UTF-8 file is absent to disk too: not a refusal.
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert!(read.unreadable_reads.is_empty());
    }

    /// #721: a candidate file that is not UTF-8 (a UTF-16 requirements.txt,
    /// which pip reads) is refused by name, on disk and in memory alike,
    /// when a candidate of its ecosystem could rewrite it, instead of being
    /// treated as absent (exit 0, nothing pinned, no diagnostic).
    #[tokio::test]
    async fn an_undecodable_candidate_file_refuses_its_ecosystem() {
        let purl = "pkg:pypi/six@1.16.0";
        let uuid = PATCH_UUID;
        let mut refs = HashMap::new();
        refs.insert(
            uuid.to_string(),
            reference(serde_json::json!({
                "status": "granted",
                "url": format!("https://patch.example/patch/pypi/six/1.16.0/tok/{uuid}/six-1.16.0-py2.py3-none-any.whl"),
                "purl": purl,
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha256": "ab".repeat(32)}}],
                "registryOverride": null
            })),
        );
        let selected = vec![(purl.to_string(), uuid.to_string())];
        let candidates = candidates_of(&selected, &refs);
        assert_eq!(candidates.len(), 1);
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "idna==3.7\r\nsix==1.16.0\r\n"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        let outer = OuterAllowRemote::default;
        let options = || RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("requirements.txt"), &utf16).unwrap();
        let mut memory = MemoryProject::new();
        memory.insert(
            "requirements.txt",
            MemoryEntry::Binary(utf16.clone().into()),
        );
        for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            assert_eq!(read.undecodable_reads, vec!["requirements.txt"]);
            let done = rewrite(&view, read, &candidates, BTreeMap::new(), options()).await;
            let refusal = guard(&view, &done, &candidates).expect("refused");
            assert_eq!(refusal.code, UNREADABLE_REFUSAL);
            assert!(
                refusal.message.contains("requirements.txt") && refusal.message.contains("UTF-8"),
                "{}",
                refusal.message
            );

            // Another ecosystem's run is not blocked by it.
            let (cargo_selected, cargo_refs) = cargo_reference(FIXTURE_UUID);
            let cargo = candidates_of(&cargo_selected, &cargo_refs);
            let read = read_candidate_files(&view, &BTreeSet::new(), &cargo).await;
            let done = rewrite(&view, read, &cargo, BTreeMap::new(), options()).await;
            assert!(guard(&view, &done, &cargo).is_none());
        }
    }

    /// #721 review: beside a yarn berry lock the root `package.json` is a
    /// rewrite target (its `resolutions`), so a non-UTF-8 one refuses the
    /// run instead of being taken for absent. Beside an npm lock it is
    /// advisory only and never refuses.
    #[tokio::test]
    async fn a_non_utf8_berry_manifest_refuses_the_npm_run() {
        use crate::patch::redirect::Integrity;
        let candidates = vec![Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url:
                    "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz"
                        .into(),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity::default(),
            },
        }];
        let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                     version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n";
        let latin1: &[u8] = b"{\"name\": \"Andr\xe9\"}\n";
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("yarn.lock"), berry).unwrap();
        std::fs::write(tmp.path().join("package.json"), latin1).unwrap();
        let view = ProjectView::Disk(tmp.path());
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert_eq!(read.undecodable_reads, vec!["package.json"]);
        let refusal = undecodable_guard(&read.undecodable_reads, &candidates).expect("refused");
        assert_eq!(refusal.code, UNREADABLE_REFUSAL);

        // Beside an npm lock the manifest is advisory: never refused.
        std::fs::remove_file(tmp.path().join("yarn.lock")).unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            "{\"lockfileVersion\": 3, \"packages\": {}}\n",
        )
        .unwrap();
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert!(
            read.undecodable_reads.is_empty(),
            "{:?}",
            read.undecodable_reads
        );
    }

    /// A hosted URL left in a berry project's `package.json` `resolutions`
    /// while `yarn.lock` still resolves the registry entry confirms nothing:
    /// only the lock pin installs (#404).
    #[test]
    fn a_resolutions_url_alone_does_not_confirm_a_berry_redirect() {
        use crate::patch::redirect::Integrity;
        let url = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";
        let candidate = Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: url.into(),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity::default(),
            },
        };
        let lock = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                    version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n";
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock.to_string());
        files.insert(
            "package.json".to_string(),
            format!("{{\"resolutions\": {{\"left-pad@npm:^1.3.0\": \"{url}\"}}}}"),
        );
        let none = confirm(
            &files,
            &RewriteResult::default(),
            std::slice::from_ref(&candidate),
            false,
        );
        assert!(none.is_empty(), "{none:?}");
        // The lock pin itself still confirms.
        files.insert(
            "yarn.lock".to_string(),
            lock.replace(
                "resolution: \"left-pad@npm:1.3.0\"",
                &format!("resolution: \"left-pad@{url}\""),
            ),
        );
        let confirmed = confirm(
            &files,
            &RewriteResult::default(),
            std::slice::from_ref(&candidate),
            false,
        );
        assert_eq!(confirmed.len(), 1, "{confirmed:?}");
    }

    /// Review of #465: a hosted berry pin whose `resolutions` routing was
    /// removed keeps its URL-keyed lock entry. The rewriter refuses to re-pin
    /// it (the routing is not ours to recreate silently), so nothing
    /// installs the patch — and the URL in `yarn.lock` must not confirm it
    /// (a confirmed dep feeds the in-run VEX `not_affected` exemption).
    #[test]
    fn an_orphaned_berry_lock_pin_is_not_confirmed() {
        use crate::patch::redirect::{rewrite_registry_redirect, Integrity};
        let url = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";
        let candidate = Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: url.into(),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity {
                    yarn_berry10c0: Some(format!("10c0/{}", "7".repeat(128))),
                    ..Default::default()
                },
            },
        };
        let manifest = "{\n  \"name\": \"app\"\n}\n".to_string();
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                 version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
                 languageName: node\n  linkType: hard\n",
                "3".repeat(128)
            ),
        );
        files.insert("package.json".to_string(), manifest.clone());
        let run = |files: &BTreeMap<String, String>| {
            let rewrite = rewrite_registry_redirect(files, std::slice::from_ref(&candidate.dep));
            let confirmed = confirm(files, &rewrite, std::slice::from_ref(&candidate), false);
            (rewrite, confirmed)
        };
        let (first, confirmed) = run(&files);
        assert_eq!(confirmed.len(), 1, "{:?}", first.warnings);
        let pinned_lock = first.files["yarn.lock"].clone();
        assert!(
            pinned_lock.contains(&format!("\"left-pad@{url}\":")),
            "{pinned_lock}"
        );

        // Rescan with the pin intact: still confirmed.
        let mut pinned = files.clone();
        pinned.insert("yarn.lock".to_string(), pinned_lock.clone());
        pinned.insert(
            "package.json".to_string(),
            first.files["package.json"].clone(),
        );
        assert_eq!(run(&pinned).1.len(), 1);

        // The routing removed: the URL is still in the lock, nothing installs it.
        let mut orphan = files;
        orphan.insert("yarn.lock".to_string(), pinned_lock);
        orphan.insert("package.json".to_string(), manifest);
        let (rewrite, confirmed) = run(&orphan);
        assert!(
            rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_yarn_berry_resolutions_conflict"),
            "{:?}",
            rewrite.warnings
        );
        assert!(confirmed.is_empty(), "{confirmed:?}");
    }

    /// The grant token and patch uuid of the engine fixtures' hosted urls:
    /// real uuids, so lockfile discovery recognizes the pins the rewrite
    /// lands (the engine keeps only the ones it attributes).
    const FIXTURE_TOKEN: &str = "11111111-1111-4111-8111-111111111111";
    const FIXTURE_UUID: &str = "77777777-7777-4777-8777-777777777777";

    fn left_pad_url() -> String {
        format!(
            "https://patch.test/patch/npm/left-pad/1.3.0/{FIXTURE_TOKEN}/{FIXTURE_UUID}/left-pad-1.3.0.tgz"
        )
    }

    fn left_pad_candidate() -> Candidate {
        use crate::patch::redirect::Integrity;
        Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: left_pad_url(),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity {
                    sha512: Some("sha512-PATCHED==".into()),
                    ..Default::default()
                },
            },
        }
    }

    /// The #490 lock: `pkga` depends on left-pad from git.
    const OVERRIDDEN_GIT_LOCK: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "pkga": "file:pkga-1.0.0.tgz" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    },
    "node_modules/pkga": {
      "version": "1.0.0",
      "resolved": "file:pkga-1.0.0.tgz",
      "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
    }
  }
}
"#;
    const OVERRIDING_MANIFEST: &str = r#"{"name":"app","dependencies":{"pkga":"file:pkga-1.0.0.tgz"},"overrides":{"left-pad":"1.3.0"}}"#;

    async fn npm_rewrite(
        view: &ProjectView<'_>,
        unreadable: &BTreeSet<String>,
    ) -> (CandidateFiles, Rewritten) {
        npm_rewrite_in(view, unreadable, &no_env).await
    }

    /// [`npm_rewrite`] with pnpm's environment looked up through `env`.
    async fn npm_rewrite_in(
        view: &ProjectView<'_>,
        unreadable: &BTreeSet<String>,
        env: &(dyn Fn(&str) -> Option<String> + Send + Sync),
    ) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![left_pad_candidate()];
        let read = read_candidate_files(view, unreadable, &candidates).await;
        let done = rewrite(view, read.clone(), &candidates, BTreeMap::new(), options).await;
        (read, done)
    }

    /// #1951: the hosted run reads a yarn classic `file:` directory copy's
    /// `package.json` where vendored and VEX read it
    /// ([`crate::formats::yarn::copy::CopyRef::read_path`]): from outside
    /// the root too, since yarn 1 installs `file:../ext/lpdir` all the same,
    /// but never at an absolute path a lock names (#1516).
    #[tokio::test]
    async fn issue_1951_yarn_classic_copy_manifests_read_as_vendored_reads_them() {
        let tmp = tempfile::tempdir().unwrap();
        // The repository every path of the fixture lives in.
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let root = tmp.path().join("app");
        let manifest = r#"{"name":"left-pad","version":"1.3.0"}"#;
        for dir in ["app/lpdir", "ext/lpdir", "abs/lpdir"] {
            let dir = tmp.path().join(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), manifest).unwrap();
        }
        let abs = tmp.path().join("abs/lpdir");
        let abs = abs.to_str().unwrap().replace('\\', "/");
        std::fs::write(
            root.join("yarn.lock"),
            format!(
                "# yarn lockfile v1\n\n\n\
                 left-pad@1.3.0:\n  version \"1.3.0\"\n  \
                 resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbb\"\n\n\
                 \"lp2@file:./lpdir\":\n  version \"1.3.0\"\n\n\
                 \"lp3@file:../ext/lpdir\":\n  version \"1.3.0\"\n\n\
                 \"lp4@file:{abs}\":\n  version \"1.3.0\"\n"
            ),
        )
        .unwrap();
        let candidates = vec![left_pad_candidate()];
        let read =
            read_candidate_files(&ProjectView::Disk(&root), &BTreeSet::new(), &candidates).await;
        assert_eq!(
            read.files.get("lpdir/package.json").map(String::as_str),
            Some(manifest)
        );
        assert_eq!(
            read.files
                .get("../ext/lpdir/package.json")
                .map(String::as_str),
            Some(manifest),
            "{:?}",
            read.files.keys()
        );
        assert!(
            !read.files.keys().any(|k| k.contains("abs/lpdir")),
            "{:?}",
            read.files.keys()
        );
    }

    /// N11: under a pnpm 1 / 2 pin `shrinkwrap.yaml` governs, so a
    /// stray v9 `pnpm-lock.yaml` an earlier run redirected is no heal root
    /// and plans no `trustLockfile` write for a lock pnpm never reads.
    #[tokio::test]
    async fn a_shadowed_pnpm_lock_is_no_heal_root() {
        let redirected = LEFT_PAD_V9_LOCK.replace(
            "resolution: {integrity: sha512-UPSTREAM==}",
            &format!(
                "resolution: {{integrity: sha512-PATCHED==, tarball: {}}}",
                left_pad_url()
            ),
        );
        let mut p = MemoryProject::new();
        p.insert_text("pnpm-lock.yaml", redirected.as_str());
        p.insert_text(
            "shrinkwrap.yaml",
            "shrinkwrapMinorVersion: 9\nshrinkwrapVersion: 3\n",
        );
        p.insert_text(
            "package.json",
            r#"{"name":"app","packageManager":"pnpm@2.25.7"}"#,
        );
        let (_, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
        assert!(
            !done.rewrite.files.contains_key(PNPM_WORKSPACE_REL),
            "{:?}",
            done.rewrite.files.keys()
        );

        // Without the pin, pnpm-lock.yaml governs and the heal plans it.
        p.insert_text("package.json", r#"{"name":"app"}"#);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
        assert!(
            done.rewrite.files.contains_key(PNPM_WORKSPACE_REL),
            "{:?}",
            done.rewrite.files.keys()
        );
    }

    /// N11: a shadowed `shrinkwrap.yaml` still carrying an earlier run's
    /// Socket URL confirms nothing (and so is no `redirect_unattributable`
    /// skip) when the governing `pnpm-lock.yaml` does not pin the package.
    #[tokio::test]
    async fn a_shadowed_pnpm_lock_confirms_nothing() {
        let mut p = MemoryProject::new();
        p.insert_text(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\npackages:\n  other@1.0.0:\n    \
             resolution: {integrity: sha512-OTHER==}\n",
        );
        p.insert_text(
            "shrinkwrap.yaml",
            format!(
                "shrinkwrapVersion: 3\nshrinkwrapMinorVersion: 9\npackages:\n  /left-pad/1.3.0:\n    \
                 resolution:\n      integrity: sha512-PATCHED==\n      tarball: {}\n",
                left_pad_url()
            )
            .as_str(),
        );
        let (_, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        assert!(done.unattributed.is_empty(), "{:?}", done.unattributed);
    }

    #[tokio::test]
    async fn a_pnpm_lock_pair_reads_the_package_manager_pin() {
        // pnpm 2 pinned in package.json, no install record: pnpm reads
        // shrinkwrap.yaml, so the planner must see the pin to leave the
        // stray pnpm-lock.yaml alone.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let manifest = r#"{"name":"app","packageManager":"pnpm@2.25.7"}"#;
        std::fs::write(root.join("package.json"), manifest).unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: 5.4\n").unwrap();
        std::fs::write(
            root.join("shrinkwrap.yaml"),
            "shrinkwrapMinorVersion: 9\nshrinkwrapVersion: 3\n",
        )
        .unwrap();
        let candidates = vec![left_pad_candidate()];
        let read =
            read_candidate_files(&ProjectView::Disk(root), &BTreeSet::new(), &candidates).await;
        assert_eq!(
            read.files.get("package.json").map(String::as_str),
            Some(manifest)
        );
        assert_eq!(
            crate::formats::pnpm::plan::planned_locks(&read.files),
            vec!["shrinkwrap.yaml"]
        );

        // One pnpm lock alone governs whatever the pin: no manifest read.
        std::fs::remove_file(root.join("shrinkwrap.yaml")).unwrap();
        let read =
            read_candidate_files(&ProjectView::Disk(root), &BTreeSet::new(), &candidates).await;
        assert!(!read.files.contains_key("package.json"));
    }

    #[tokio::test]
    async fn issue_490_the_root_manifest_overrides_reach_the_npm_rewriter() {
        let redirected = |done: &Rewritten| {
            done.rewrite
                .files
                .get("package-lock.json")
                .is_some_and(|lock| lock.contains(&left_pad_url()))
        };
        // In memory.
        let mut p = MemoryProject::new();
        p.insert_text("package-lock.json", OVERRIDDEN_GIT_LOCK);
        p.insert_text("package.json", OVERRIDING_MANIFEST);
        let (read, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
        assert!(read.files.contains_key("package.json"));
        assert!(redirected(&done), "{:?}", done.rewrite.warnings);
        assert!(!done.rewrite.files.contains_key("package.json"));

        // A linked or unreadable manifest is left out, not refused: the
        // rewriter keeps the conservative #326 skip.
        for linked in [true, false] {
            let mut p = MemoryProject::new();
            p.insert_text("package-lock.json", OVERRIDDEN_GIT_LOCK);
            let mut unreadable = BTreeSet::new();
            if linked {
                p.insert("package.json", MemoryEntry::Symlink);
            } else {
                p.insert_present("package.json");
                unreadable.insert("package.json".to_string());
            }
            let (read, done) = npm_rewrite(&ProjectView::Memory(&p), &unreadable).await;
            assert!(!read.files.contains_key("package.json"));
            assert!(read.symlinked_reads.is_empty() && read.unreadable_reads.is_empty());
            assert!(!redirected(&done));
            assert!(done
                .rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_npm_non_registry_entry_skipped"));
        }

        // On disk.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), OVERRIDDEN_GIT_LOCK).unwrap();
        std::fs::write(tmp.path().join("package.json"), OVERRIDING_MANIFEST).unwrap();
        let (_, done) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
        assert!(redirected(&done), "{:?}", done.rewrite.warnings);
    }

    /// REGRESSION (#406): `deno install` installs a `package.json`
    /// project's npm deps from `deno.lock` and never reads
    /// package-lock.json, so a redirect of a `name@version` that deno.lock
    /// also locks is SAID (`redirect_npm_deno_lock`), once, while the
    /// redirect still stands for npm. Another version in deno.lock, an
    /// unparseable one, or none says nothing.
    #[tokio::test]
    async fn issue_406_a_deno_lock_of_the_redirected_version_is_said() {
        const LOCK: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "left-pad": "1.3.0" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;
        let deno_lock = |key: &str| {
            format!(r#"{{"version":"5","npm":{{"{key}":{{"integrity":"sha512-X=="}}}}}}"#)
        };
        let said = |done: &Rewritten| {
            let lock = done.rewrite.files.get("package-lock.json");
            assert!(
                lock.is_some_and(|l| l.contains(&left_pad_url())),
                "{:?}",
                done.rewrite.warnings
            );
            let found: Vec<&RewriteWarning> = done
                .npm_warnings
                .iter()
                .filter(|w| w.code == "redirect_npm_deno_lock")
                .collect();
            assert!(found.len() <= 1, "{found:?}");
            found.first().map(|w| w.detail.clone())
        };
        let cases = [
            (Some(deno_lock("left-pad@1.3.0")), true),
            // Deno's peer suffix still names the same version.
            (Some(deno_lock("left-pad@1.3.0_react@18.2.0")), true),
            (Some(deno_lock("left-pad@1.2.0")), false),
            (Some("not json".to_string()), false),
            (None, false),
        ];
        for (deno, expect) in cases {
            // In memory.
            let mut p = MemoryProject::new();
            p.insert_text("package-lock.json", LOCK);
            if let Some(text) = &deno {
                p.insert_text("deno.lock", text.as_str());
            }
            let (_, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
            let detail = said(&done);
            assert_eq!(detail.is_some(), expect, "{deno:?}: {detail:?}");
            if let Some(detail) = detail {
                assert!(detail.starts_with("left-pad@1.3.0 redirected"), "{detail}");
                assert!(detail.contains("deno install"), "{detail}");
                assert!(detail.contains("--mode agent"), "{detail}");
            }
            // On disk.
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("package-lock.json"), LOCK).unwrap();
            if let Some(text) = &deno {
                std::fs::write(tmp.path().join("deno.lock"), text).unwrap();
            }
            let (_, done) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
            assert_eq!(said(&done).is_some(), expect, "disk {deno:?}");
            // deno.lock is never written.
            assert!(!done.rewrite.files.contains_key("deno.lock"));
        }
    }

    const LEFT_PAD_V9_LOCK: &str = "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:
  left-pad@1.3.0: {}
";

    #[test]
    fn rush_repo_state_pairs_with_the_lock_beside_it() {
        assert_eq!(
            rush_repo_state_for_lock(RUSH_COMMON_LOCK_REL),
            RUSH_REPO_STATE_REL
        );
        assert_eq!(
            rush_repo_state_for_lock("common/config/subspaces/tools/pnpm-lock.yaml"),
            "common/config/subspaces/tools/repo-state.json"
        );
    }

    fn pnpm_trust_detail(done: &Rewritten) -> &str {
        done.pnpm_warnings
            .iter()
            .find(|w| w.code == "redirect_pnpm_trust_lockfile")
            .map(|w| w.detail.as_str())
            .expect("redirect_pnpm_trust_lockfile")
    }

    /// #713: a run that spliced only Rush locks gets the Rush remedy (the
    /// env var rush forwards, the pnpm 11 experiment, `rush purge`), never
    /// the pnpm-only one, and writes no workspace file. The same lock at the
    /// repo root still plans the trustLockfile write, and a run that spliced
    /// both keeps the generic text plus the Rush note.
    #[tokio::test]
    async fn issue_713_rush_locks_get_the_rush_trust_remedy() {
        let mut rush = MemoryProject::new();
        rush.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rush.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        let (read, done) = npm_rewrite(&ProjectView::Memory(&rush), &BTreeSet::new()).await;
        assert_eq!(read.rush_lock_keys, [RUSH_COMMON_LOCK_REL]);
        assert!(done.rewrite.files.contains_key(RUSH_COMMON_LOCK_REL));
        assert!(!done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("pnpm_config_trust_lockfile=true rush install"),
            "{detail}"
        );
        assert!(
            detail.contains("usePnpmFrozenLockfileForRushInstall"),
            "{detail}"
        );
        assert!(detail.contains("rush purge"), "{detail}");
        assert!(
            !detail.contains("pnpm install --trust-lockfile"),
            "{detail}"
        );
        assert!(!detail.contains("--store-dir"), "{detail}");

        let mut root = MemoryProject::new();
        root.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&root), &BTreeSet::new()).await;
        assert!(done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
        assert!(!pnpm_trust_detail(&done).contains("rush"));

        let mut mixed = rush.clone();
        mixed.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&mixed), &BTreeSet::new()).await;
        assert!(done.rewrite.files.contains_key(RUSH_COMMON_LOCK_REL));
        let detail = pnpm_trust_detail(&done);
        assert!(detail.contains("--store-dir"), "{detail}");
        assert!(detail.contains(PNPM_TRUST_RUSH_MIXED_NOTE), "{detail}");
    }

    /// Hosted pins the Rush locks lockfile discovery reads
    /// (`rush_lock_rels`): a subspace dir whose name is not a safe path
    /// segment is skipped, as is every lock under a symlinked
    /// `common/config/subspaces` (it could point the write at another
    /// repository).
    #[tokio::test]
    async fn rush_locks_are_the_ones_discovery_reads() {
        let mut rush = MemoryProject::new();
        rush.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rush.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        rush.insert_text(
            "common/config/subspaces/ok/pnpm-lock.yaml",
            LEFT_PAD_V9_LOCK,
        );
        rush.insert_text(
            "common/config/subspaces/a:b/pnpm-lock.yaml",
            LEFT_PAD_V9_LOCK,
        );
        rush.insert_text(
            "common/config/subspaces/a\\b/pnpm-lock.yaml",
            LEFT_PAD_V9_LOCK,
        );
        let (read, _) = npm_rewrite(&ProjectView::Memory(&rush), &BTreeSet::new()).await;
        assert_eq!(
            read.rush_lock_keys,
            [
                RUSH_COMMON_LOCK_REL,
                "common/config/subspaces/ok/pnpm-lock.yaml"
            ]
        );

        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(outside.path().join("x")).unwrap();
            std::fs::write(outside.path().join("x/pnpm-lock.yaml"), LEFT_PAD_V9_LOCK).unwrap();
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("rush.json"), "{}").unwrap();
            std::fs::create_dir_all(tmp.path().join("common/config/rush")).unwrap();
            std::fs::write(tmp.path().join(RUSH_COMMON_LOCK_REL), LEFT_PAD_V9_LOCK).unwrap();
            std::os::unix::fs::symlink(outside.path(), tmp.path().join("common/config/subspaces"))
                .unwrap();
            let (read, _) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
            assert_eq!(read.rush_lock_keys, [RUSH_COMMON_LOCK_REL]);
        }
    }

    /// The disk scan's user-patch supplement reads every Rush subspace lock,
    /// as the in-memory engine does through its candidate files, and only
    /// the common lock path outside Rush.
    #[tokio::test]
    async fn user_patch_supplement_reads_rush_subspace_locks() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("common/config/subspaces/web")).unwrap();
        let disk = ProjectView::Disk(tmp.path());
        assert_eq!(
            user_patch_supplement_lock_rels(disk).await,
            [RUSH_COMMON_LOCK_REL, "shrinkwrap.yaml"]
        );
        std::fs::write(tmp.path().join("rush.json"), "{}").unwrap();
        assert_eq!(
            user_patch_supplement_lock_rels(disk).await,
            [
                RUSH_COMMON_LOCK_REL,
                "common/config/subspaces/web/pnpm-lock.yaml",
                "shrinkwrap.yaml"
            ]
        );
    }

    /// #713 HEAL-ON-RERUN: a Rush lock an earlier run already redirected
    /// splices nothing on a re-run, yet its `rush install` still needs the
    /// Rush remedy — the re-run re-issues it (and still writes nothing).
    /// Review (#2018): a supplement lock is read as the user-patch walk
    /// reads a project file. One that links out of the repository is read
    /// through the link; a missing one reached through a directory that
    /// links out is no evidence (not an unreadable lock, which would
    /// withhold every npm package); one that exists but can't be read is
    /// an error.
    #[cfg(unix)]
    #[tokio::test]
    async fn supplement_locks_are_read_through_links_out_of_the_repository() {
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(outer.path().join("shared/config/rush")).unwrap();
        std::fs::write(outer.path().join("shared/shrinkwrap.yaml"), "lock").unwrap();
        std::os::unix::fs::symlink(
            outer.path().join("shared/shrinkwrap.yaml"),
            repo.join("shrinkwrap.yaml"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outer.path().join("shared"), repo.join("common")).unwrap();
        let view = ProjectView::Disk(&repo);
        assert_eq!(
            read_user_patch_lock(&view, "shrinkwrap.yaml")
                .await
                .unwrap(),
            Some("lock".to_string())
        );
        assert_eq!(
            read_user_patch_lock(&view, RUSH_COMMON_LOCK_REL)
                .await
                .unwrap(),
            None
        );
        std::fs::create_dir_all(outer.path().join("shared/config/rush/pnpm-lock.yaml")).unwrap();
        assert!(read_user_patch_lock(&view, RUSH_COMMON_LOCK_REL)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn issue_713_rerun_on_a_redirected_rush_lock_keeps_the_rush_remedy() {
        let mut first = MemoryProject::new();
        first.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        first.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&first), &BTreeSet::new()).await;
        let redirected = done.rewrite.files[RUSH_COMMON_LOCK_REL].clone();

        let mut rerun = MemoryProject::new();
        rerun.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rerun.insert_text(RUSH_COMMON_LOCK_REL, redirected.as_str());
        let (_, done) = npm_rewrite(&ProjectView::Memory(&rerun), &BTreeSet::new()).await;
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(!done.pnpm_rerun_only);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("pnpm_config_trust_lockfile=true rush install"),
            "{detail}"
        );
        assert!(
            !detail.contains("pnpm install --trust-lockfile"),
            "{detail}"
        );
    }

    /// #1514: pnpm 11+ read a `pnpm_config_trust_lockfile` (or
    /// `PNPM_CONFIG_TRUST_LOCKFILE`) variable ahead of pnpm-workspace.yaml.
    /// One set to anything but true in the scan's environment is an
    /// explicit user setting: nothing is written (a key the variable
    /// overrides would not take effect) and the warning names the variable
    /// and its remedies instead of claiming installs need no extra flags.
    /// The member-lock branch respects it too; a true one, an npm-family
    /// one, and a project on pnpm 10 keep the auto-config.
    #[tokio::test]
    async fn issue_1514_a_trust_lockfile_env_override_is_respected() {
        fn off(var: &str) -> Option<String> {
            (var == "pnpm_config_trust_lockfile").then(|| "false".to_string())
        }
        fn upper_off(var: &str) -> Option<String> {
            (var == "PNPM_CONFIG_TRUST_LOCKFILE").then(|| "false".to_string())
        }
        fn on(var: &str) -> Option<String> {
            (var == "pnpm_config_trust_lockfile").then(|| "true".to_string())
        }
        fn npm_off(var: &str) -> Option<String> {
            (var == "npm_config_trust_lockfile").then(|| "false".to_string())
        }
        let mut root = MemoryProject::new();
        root.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        for (env, var) in [
            (
                off as fn(&str) -> Option<String>,
                "pnpm_config_trust_lockfile",
            ),
            (upper_off, "PNPM_CONFIG_TRUST_LOCKFILE"),
        ] {
            let (_, done) =
                npm_rewrite_in(&ProjectView::Memory(&root), &BTreeSet::new(), &env).await;
            assert!(done.rewrite.files.contains_key("pnpm-lock.yaml"));
            assert!(
                !done.rewrite.files.contains_key(PNPM_WORKSPACE_REL),
                "{:?}",
                done.rewrite.files.keys()
            );
            let detail = pnpm_trust_detail(&done);
            assert!(detail.contains(&format!("`{var}=false`")), "{detail}");
            assert!(!detail.contains("no extra flags"), "{detail}");
            assert!(detail.contains("--mode vendored"), "{detail}");
        }
        // An existing `trustLockfile: true` is overridden all the same.
        let mut trusted = root.clone();
        trusted.insert_text(
            PNPM_WORKSPACE_REL,
            "packages:\n  - '.'\ntrustLockfile: true\n",
        );
        let (_, done) =
            npm_rewrite_in(&ProjectView::Memory(&trusted), &BTreeSet::new(), &off).await;
        assert!(!done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("`pnpm_config_trust_lockfile=false`"),
            "{detail}"
        );

        // A true override, the npm spelling (no pnpm reads it) and a
        // project installed by pnpm 10 (which never verifies) keep the write.
        for env in [on as fn(&str) -> Option<String>, npm_off] {
            let (_, done) =
                npm_rewrite_in(&ProjectView::Memory(&root), &BTreeSet::new(), &env).await;
            assert!(done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
            assert!(pnpm_trust_detail(&done).contains("no extra flags"));
        }
        let mut pnpm10 = root.clone();
        pnpm10.insert_text(
            "package.json",
            r#"{"name":"app","packageManager":"pnpm@10.34.6"}"#,
        );
        let (_, done) = npm_rewrite_in(&ProjectView::Memory(&pnpm10), &BTreeSet::new(), &off).await;
        assert!(done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));

        // A workspace member's own lock (#880): the root file is not
        // written either way, and the env override is what is reported.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(PNPM_WORKSPACE_REL),
            "packages:\n  - 'app'\nsharedWorkspaceLockfile: false\ntrustLockfile: true\n",
        )
        .unwrap();
        let member = tmp.path().join("app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("pnpm-lock.yaml"), LEFT_PAD_V9_LOCK).unwrap();
        let (_, done) = npm_rewrite_in(&ProjectView::Disk(&member), &BTreeSet::new(), &off).await;
        assert!(done.rewrite.files.contains_key("pnpm-lock.yaml"));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("`pnpm_config_trust_lockfile=false`"),
            "{detail}"
        );
    }

    /// #1557: pnpm 11+ ignore a `pnpm_config_trust_lockfile` (or
    /// `PNPM_CONFIG_TRUST_LOCKFILE`) that is not exactly `true` or `false`
    /// (an unset CI variable's empty string, `null`, `undefined`) and read
    /// pnpm-workspace.yaml instead, so the scan writes `trustLockfile:
    /// true` as if the variable were unset, and the warning does not claim
    /// the variable was respected.
    #[tokio::test]
    async fn issue_1557_an_empty_trust_lockfile_variable_keeps_the_write() {
        let mut root = MemoryProject::new();
        root.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        for var in ["pnpm_config_trust_lockfile", "PNPM_CONFIG_TRUST_LOCKFILE"] {
            for value in ["", "null", "undefined"] {
                let env = move |name: &str| (name == var).then(|| value.to_string());
                let (_, done) =
                    npm_rewrite_in(&ProjectView::Memory(&root), &BTreeSet::new(), &env).await;
                assert!(done.rewrite.files.contains_key("pnpm-lock.yaml"));
                let workspace = done
                    .rewrite
                    .files
                    .get(PNPM_WORKSPACE_REL)
                    .unwrap_or_else(|| panic!("{:?}", done.rewrite.files.keys()));
                assert!(workspace.contains("trustLockfile: true"), "{workspace}");
                let detail = pnpm_trust_detail(&done);
                assert!(detail.contains("no extra flags"), "{detail}");
                assert!(!detail.contains("in the environment"), "{detail}");
            }
        }
    }

    // ── pnpm named registry ──────────────────────────────────────────────

    /// The names of the registries of the fixtures' patches: `socket-` and
    /// the first eight digits of each patch's UUID.
    const LEFT_PAD_ALIAS: &str = "socket-77777777";
    const IS_NUMBER_ALIAS: &str = "socket-88888888";

    /// The registry address of the patch served at `tarball`: the
    /// directory the tarball is in.
    fn registry_address(tarball: &str) -> String {
        tarball[..=tarball.rfind('/').expect("a tarball URL")].to_string()
    }

    /// The address the reference result of the left-pad patch carries.
    fn left_pad_registry_url() -> String {
        registry_address(&left_pad_url())
    }

    /// [`left_pad_candidate`] as a patch service that serves registry
    /// documents grants it.
    fn left_pad_registry_candidate() -> Candidate {
        let mut candidate = left_pad_candidate();
        candidate.dep.npm_registry_url = Some(left_pad_registry_url());
        candidate
    }

    const IS_NUMBER_UUID: &str = "88888888-8888-4888-8888-888888888888";

    fn is_number_url() -> String {
        format!(
            "https://patch.test/patch/npm/is-number/7.0.0/{FIXTURE_TOKEN}/{IS_NUMBER_UUID}/is-number-7.0.0.tgz"
        )
    }

    /// A second pin of the same lock; `registry` as the patch service
    /// gives it a registry address or not.
    fn is_number_candidate(registry: bool) -> Candidate {
        let mut candidate = left_pad_candidate();
        candidate.purl = "pkg:npm/is-number@7.0.0".into();
        candidate.dep.name = "is-number".into();
        candidate.dep.version = "7.0.0".into();
        candidate.dep.patch_uuid = IS_NUMBER_UUID.into();
        candidate.dep.artifact_url = is_number_url();
        candidate.dep.npm_registry_url = registry.then(|| registry_address(&is_number_url()));
        candidate
    }

    const TWO_PACKAGE_V9_LOCK: &str = "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      is-number:
        specifier: 7.0.0
        version: 7.0.0
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:
  is-number@7.0.0:
    resolution: {integrity: sha512-UPSTREAM==}

  left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:
  is-number@7.0.0: {}

  left-pad@1.3.0: {}
";

    /// The workspace file's declaration of the registry `alias` of the
    /// patch served at `tarball`.
    fn registry_line(alias: &str, tarball: &str) -> String {
        format!("  {alias}: {}", registry_address(tarball))
    }

    fn left_pad_registry_line() -> String {
        registry_line(LEFT_PAD_ALIAS, &left_pad_url())
    }

    fn is_number_registry_line() -> String {
        registry_line(IS_NUMBER_ALIAS, &is_number_url())
    }

    /// The override that routes the left-pad release to its registry, as
    /// pnpm-workspace.yaml holds it.
    const LEFT_PAD_OVERRIDE: &str = "  'left-pad@1.3.0': 'socket-77777777:1.3.0'";
    const IS_NUMBER_OVERRIDE: &str = "  'is-number@7.0.0': 'socket-88888888:7.0.0'";

    /// The workspace file a registry run creates for the left-pad pin.
    fn left_pad_routed_workspace() -> String {
        format!(
            "packages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{LEFT_PAD_OVERRIDE}\n",
            left_pad_registry_line()
        )
    }

    /// The workspace file a registry run creates for both pins.
    fn two_package_routed_workspace() -> String {
        format!(
            "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\noverrides:\n{IS_NUMBER_OVERRIDE}\n{LEFT_PAD_OVERRIDE}\n",
            left_pad_registry_line(),
            is_number_registry_line()
        )
    }

    /// [`LEFT_PAD_V9_LOCK`] as pnpm writes it for that workspace file.
    fn left_pad_routed_lock() -> String {
        format!(
            "lockfileVersion: '9.0'\n\noverrides:\n  left-pad@1.3.0: {LEFT_PAD_ALIAS}:1.3.0\n\n\
             importers:\n  .:\n    dependencies:\n      left-pad:\n        \
             specifier: {LEFT_PAD_ALIAS}:1.3.0\n        version: {LEFT_PAD_ALIAS}:1.3.0\n\n\
             packages:\n  left-pad@{LEFT_PAD_ALIAS}:1.3.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {}}}\n\n\
             snapshots:\n  left-pad@{LEFT_PAD_ALIAS}:1.3.0: {{}}\n",
            left_pad_url()
        )
    }

    /// [`TWO_PACKAGE_V9_LOCK`] with both releases routed.
    fn two_package_routed_lock() -> String {
        format!(
            "lockfileVersion: '9.0'\n\noverrides:\n  is-number@7.0.0: {IS_NUMBER_ALIAS}:7.0.0\n  \
             left-pad@1.3.0: {LEFT_PAD_ALIAS}:1.3.0\n\n\
             importers:\n  .:\n    dependencies:\n      is-number:\n        \
             specifier: {IS_NUMBER_ALIAS}:7.0.0\n        version: {IS_NUMBER_ALIAS}:7.0.0\n      left-pad:\n        \
             specifier: {LEFT_PAD_ALIAS}:1.3.0\n        version: {LEFT_PAD_ALIAS}:1.3.0\n\n\
             packages:\n  is-number@{IS_NUMBER_ALIAS}:7.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {}}}\n\n  left-pad@{LEFT_PAD_ALIAS}:1.3.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {}}}\n\n\
             snapshots:\n  is-number@{IS_NUMBER_ALIAS}:7.0.0: {{}}\n\n  left-pad@{LEFT_PAD_ALIAS}:1.3.0: {{}}\n",
            is_number_url(),
            left_pad_url()
        )
    }

    /// A manifest that proves a pnpm hosted mode routes patched packages
    /// through the registry for, and says what the project asks for.
    const PNPM_12_MANIFEST: &str = r#"{"name":"app","packageManager":"pnpm@12.22.0","dependencies":{"left-pad":"1.3.0","is-number":"7.0.0"}}"#;

    /// A project pinned to pnpm 12 whose root lock is `lock`.
    fn pnpm12_project(lock: &str) -> MemoryProject {
        let mut project = MemoryProject::new();
        project.insert_text("pnpm-lock.yaml", lock);
        project.insert_text("package.json", PNPM_12_MANIFEST);
        project
    }

    /// One pnpm rewrite of `view` for `candidates`: `config` is the trust
    /// auto-config switch (`--no-trust-lockfile-config` turns it off).
    async fn pnpm_rewrite(
        view: &ProjectView<'_>,
        candidates: &[Candidate],
        config: bool,
        dry_run: bool,
        env: &(dyn Fn(&str) -> Option<String> + Send + Sync),
    ) -> Rewritten {
        pnpm_rewrite_from(view, candidates, config, dry_run, env, Vec::new()).await
    }

    /// [`pnpm_rewrite`] for a run configured with `origins`: its patch
    /// server and, as a mirror's entry, its patch mirror.
    async fn pnpm_rewrite_from(
        view: &ProjectView<'_>,
        candidates: &[Candidate],
        config: bool,
        dry_run: bool,
        env: &(dyn Fn(&str) -> Option<String> + Send + Sync),
        origins: Vec<String>,
    ) -> Rewritten {
        let read = read_candidate_files(view, &BTreeSet::new(), candidates).await;
        pnpm_rewrite_read(view, read, candidates, config, dry_run, env, origins).await
    }

    /// [`pnpm_rewrite_from`] over files that were read already.
    #[allow(clippy::too_many_arguments)]
    async fn pnpm_rewrite_read(
        view: &ProjectView<'_>,
        read: CandidateFiles,
        candidates: &[Candidate],
        config: bool,
        dry_run: bool,
        env: &(dyn Fn(&str) -> Option<String> + Send + Sync),
        origins: Vec<String>,
    ) -> Rewritten {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: config,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: origins,
            prior_discovery: None,
        };
        rewrite(view, read, candidates, BTreeMap::new(), options).await
    }

    /// The default run over an in-memory project.
    async fn registry_rewrite(project: &MemoryProject, candidates: &[Candidate]) -> Rewritten {
        pnpm_rewrite(
            &ProjectView::Memory(project),
            candidates,
            true,
            false,
            &no_env,
        )
        .await
    }

    fn workspace_of(done: &Rewritten) -> Option<&str> {
        done.rewrite
            .files
            .get(PNPM_WORKSPACE_REL)
            .map(String::as_str)
    }

    fn lock_of(done: &Rewritten) -> Option<&str> {
        done.rewrite.files.get("pnpm-lock.yaml").map(String::as_str)
    }

    /// `(kind, action, key)` of each edit of `path`.
    fn edits_of<'d>(done: &'d Rewritten, path: &str) -> Vec<(&'d str, &'d str, Option<&'d str>)> {
        done.rewrite
            .edits
            .iter()
            .filter(|e| e.path == path)
            .map(|e| (e.kind.as_str(), e.action.as_str(), e.key.as_deref()))
            .collect()
    }

    fn workspace_edits(done: &Rewritten) -> Vec<(&str, &str, Option<&str>)> {
        edits_of(done, PNPM_WORKSPACE_REL)
    }

    /// `project` as the run left it: its files with the rewritten ones on
    /// top.
    fn after(project: &MemoryProject, done: &Rewritten) -> MemoryProject {
        let mut next = project.clone();
        for (rel, text) in &done.rewrite.files {
            next.insert_text(rel.as_str(), text.as_str());
        }
        next
    }

    /// The trust detail with `note` where a note goes: before the reinstall
    /// advice.
    fn noted(detail: &str, note: &str) -> String {
        let noted = detail.replacen(
            "After a lock-only change,",
            &format!("{note}. After a lock-only change,"),
            1,
        );
        assert_ne!(noted, detail);
        noted
    }

    /// What a trust warning says of the registry route it did not take.
    fn blocked(why: &str) -> String {
        format!(
            "Per-package registry verification was not set up because {why}; the hosted \
             patches rely on `trustLockfile` instead"
        )
    }

    const NOT_PROVEN: &str = "the project's pnpm pins (package.json `packageManager`, \
                              `devEngines.packageManager`, `engines.pnpm`, and the installed \
                              node_modules/.modules.yaml) do not prove pnpm 11.20 or later";

    /// The candidates a scan is granted for a `pnpm-registry-overrides`
    /// golden case; `registry` as the patch service gives them a registry
    /// address or not.
    fn golden_candidates(case: &str, registry: bool) -> Vec<Candidate> {
        use crate::formats::pnpm::registry_alias::fixtures;
        use crate::patch::redirect::Integrity;
        fixtures::patches(case)
            .into_iter()
            .map(|patch| {
                let (namespace, name) = match patch.name.split_once('/') {
                    Some((scope, name)) => (Some(scope.to_string()), name.to_string()),
                    None => (None, patch.name.clone()),
                };
                Candidate {
                    purl: format!(
                        "pkg:npm/{}@{}",
                        patch.name.replace('@', "%40"),
                        patch.version
                    ),
                    dep: DepOverride {
                        ecosystem: "npm".into(),
                        name,
                        namespace,
                        version: patch.version,
                        token: "22222222-2222-4222-8222-222222222222".into(),
                        patch_uuid: patch.uuid,
                        artifact_url: patch.artifact_url,
                        npm_registry_url: registry.then_some(patch.npm_registry_url),
                        registry_override: None,
                        integrity: Integrity {
                            sha512: Some(patch.sha512),
                            ..Default::default()
                        },
                    },
                }
            })
            .collect()
    }

    /// A golden case's project, as pnpm locked it before any patch, with
    /// the install record of a pnpm the registry route is taken for. On
    /// disk: a workspace's members are found there.
    fn golden_project(case: &str) -> tempfile::TempDir {
        use crate::formats::pnpm::registry_alias::fixtures;
        let project = tempfile::tempdir().unwrap();
        for (rel, text) in fixtures::project(case) {
            write_rel(project.path(), &rel, &text);
        }
        write_rel(
            project.path(),
            "node_modules/.modules.yaml",
            "packageManager: pnpm@12.22.0\n",
        );
        project
    }

    /// Write what a run rewrote.
    fn commit(root: &std::path::Path, done: &Rewritten) {
        for (rel, text) in &done.rewrite.files {
            write_rel(root, rel, text);
        }
    }

    async fn golden_rewrite(root: &std::path::Path, candidates: &[Candidate]) -> Rewritten {
        pnpm_rewrite(&ProjectView::Disk(root), candidates, true, false, &no_env).await
    }

    /// The locks of a golden case, each as `(path, pnpm's routed lock)`.
    fn golden_locks(case: &str) -> Vec<(String, String)> {
        use crate::formats::pnpm::registry_alias::fixtures;
        fixtures::locks(case)
            .into_iter()
            .map(|rel| {
                let lock = fixtures::read(case, &format!("expected/{rel}")).expect("a lock");
                (rel, lock)
            })
            .collect()
    }

    /// THE GOLDEN GATE: for every project real pnpm locked, the scan writes
    /// the pnpm-lock.yaml files and the pnpm-workspace.yaml that pnpm 11.20
    /// through 12.22 produce for the routed patches, byte for byte: from an
    /// unpatched project and from one an earlier run left on
    /// `trustLockfile`. Every pin is confirmed and attributed, and a second
    /// run changes nothing.
    #[tokio::test]
    async fn the_registry_route_writes_what_pnpm_writes() {
        use crate::formats::pnpm::registry_alias::fixtures;
        for case in fixtures::cases() {
            let candidates = golden_candidates(&case, true);
            let locks = golden_locks(&case);
            let workspace = fixtures::read(&case, "expected/pnpm-workspace.yaml").expect("ws");
            let users_file = fixtures::read(&case, "project/pnpm-workspace.yaml").is_some();
            let assert_routed = |done: &Rewritten, from: &str| {
                for (rel, lock) in &locks {
                    assert_eq!(
                        done.rewrite.files.get(rel).map(String::as_str),
                        Some(lock.as_str()),
                        "{case} {rel} ({from})"
                    );
                }
                assert!(done.pnpm_named_registries, "{case} ({from})");
                assert_eq!(done.confirmed.len(), candidates.len(), "{case} ({from})");
                assert!(
                    done.unattributed.is_empty(),
                    "{case} ({from}): {:?}",
                    done.unattributed
                );
            };

            let fresh = golden_project(&case);
            let done = golden_rewrite(fresh.path(), &candidates).await;
            assert_routed(&done, "fresh");
            assert_eq!(workspace_of(&done), Some(workspace.as_str()), "{case}");
            assert!(
                guard(&ProjectView::Disk(fresh.path()), &done, &candidates).is_none(),
                "{case}"
            );
            let detail = pnpm_trust_detail(&done);
            assert!(!detail.contains("trustLockfile"), "{case}: {detail}");
            commit(fresh.path(), &done);
            let again = golden_rewrite(fresh.path(), &candidates).await;
            assert!(
                again.rewrite.files.is_empty(),
                "{case}: a second run rewrote {:?}",
                again.rewrite.files.keys()
            );
            assert!(again.rewrite.edits.is_empty(), "{case}");
            assert!(
                again.pnpm_rerun_only && again.pnpm_named_registries,
                "{case}"
            );
            assert_eq!(again.confirmed.len(), candidates.len(), "{case}");

            // An earlier run on a patch service that gave no address.
            let trusted = golden_project(&case);
            let on_trust = golden_rewrite(trusted.path(), &golden_candidates(&case, false)).await;
            assert!(!on_trust.pnpm_named_registries, "{case}");
            assert!(
                workspace_of(&on_trust).is_some_and(|text| text.contains("trustLockfile: true")),
                "{case}"
            );
            commit(trusted.path(), &on_trust);
            let done = golden_rewrite(trusted.path(), &candidates).await;
            assert_routed(&done, "from trust");
            if users_file {
                // The key may be the user's: it stays, and the run says so.
                assert_eq!(
                    workspace_of(&done).map(|text| text.replace("trustLockfile: true\n", "")),
                    Some(workspace.clone()),
                    "{case} (from trust)"
                );
                assert!(
                    pnpm_trust_detail(&done).contains("was left untouched"),
                    "{case}"
                );
            } else {
                assert_eq!(
                    workspace_of(&done),
                    Some(workspace.as_str()),
                    "{case} (from trust)"
                );
                assert!(pnpm_trust_detail(&done).contains("was removed"), "{case}");
            }
        }
    }

    /// The shapes real pnpm does not lock as a respelling keep the run on
    /// `trustLockfile`, exactly the run a patch service with no registry
    /// gets, and the warning says which shape it was.
    #[tokio::test]
    async fn a_lock_pnpm_would_not_respell_stays_on_trust() {
        use crate::formats::pnpm::registry_alias::fixtures;
        for (case, why) in fixtures::refused() {
            let project = golden_project(&case);
            let baseline = golden_rewrite(project.path(), &golden_candidates(&case, false)).await;
            let done = golden_rewrite(project.path(), &golden_candidates(&case, true)).await;
            assert!(!done.pnpm_named_registries, "{case}");
            assert_eq!(done.rewrite.files, baseline.rewrite.files, "{case}");
            assert_eq!(done.rewrite.edits, baseline.rewrite.edits, "{case}");
            let detail = pnpm_trust_detail(&done);
            assert!(
                detail.contains("Per-package registry verification was not set up because")
                    && detail.contains(&why),
                "{case}: {detail}"
            );
        }
    }

    /// Every pin of the governing lock has a registry address: the run
    /// routes each patched release through the registry and writes no
    /// `trustLockfile`, so pnpm's verification stays on. The warning says
    /// so, keeps the cautions that are still true, and drops the
    /// whole-lock tradeoff note.
    #[tokio::test]
    async fn patched_releases_are_routed_when_every_pin_has_an_address() {
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let candidates = [left_pad_registry_candidate()];
        let done = registry_rewrite(&root, &candidates).await;
        assert_eq!(lock_of(&done), Some(left_pad_routed_lock().as_str()));
        assert_eq!(
            workspace_of(&done),
            Some(left_pad_routed_workspace().as_str())
        );
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "created",
                    Some(LEFT_PAD_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "created",
                    Some("left-pad@1.3.0")
                ),
            ]
        );
        assert_eq!(
            edits_of(&done, "pnpm-lock.yaml"),
            [
                (
                    "redirect_pnpm_resolution",
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND,
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                    "added",
                    Some("left-pad@1.3.0")
                ),
            ]
        );
        assert!(done.pnpm_named_registries);
        assert!(!done.pnpm_rerun_only);
        assert_eq!(done.confirmed.len(), 1);
        assert!(guard(&ProjectView::Memory(&root), &done, &candidates).is_none());
        let detail = pnpm_trust_detail(&done);
        for said in [
            "repointed at the hosted patch server (patch.test)",
            "a new pnpm-workspace.yaml now declares the patch server's registry of each patched package",
            "(`namedRegistries`, the `socket-<id>` entries, one per patch)",
            "(`overrides`, `<name>@<version>` to `socket-<id>:<version>`)",
            "pnpm >=11.20 verifies those entries against their registry",
            "keeps them when it resolves again (`pnpm add`, `update`, `dedupe`)",
            "commit the file alongside the lock",
            "lockfile verification stays on",
            "ERR_PNPM_TARBALL_URL_MISMATCH",
            "ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION",
            "pnpm clean --lockfile",
            "--store-dir <new-empty-directory>",
            "socket-patch vex",
        ] {
            assert!(detail.contains(said), "{said}: {detail}");
        }
        for unsaid in [
            "trustLockfile",
            "ALL lockfile entries",
            "--trust-lockfile",
            FIXTURE_TOKEN,
        ] {
            assert!(!detail.contains(unsaid), "{unsaid}: {detail}");
        }

        // A re-run over what the run wrote changes nothing.
        let written = after(&root, &done);
        let again = registry_rewrite(&written, &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
        assert!(again.rewrite.edits.is_empty(), "{:?}", again.rewrite.edits);
        assert!(again.pnpm_rerun_only && again.pnpm_named_registries);
        assert_eq!(again.confirmed.len(), 1);
        let detail = pnpm_trust_detail(&again);
        assert!(
            detail.contains("already declares the patch server's registry"),
            "{detail}"
        );
        assert!(!detail.contains("trustLockfile"), "{detail}");

        // A dry run says what it would do.
        let dry = pnpm_rewrite(
            &ProjectView::Memory(&root),
            &candidates,
            true,
            true,
            &no_env,
        )
        .await;
        assert_eq!(lock_of(&dry), lock_of(&done));
        assert!(
            pnpm_trust_detail(&dry)
                .contains("a new pnpm-workspace.yaml would declare the patch server's registry"),
            "{}",
            pnpm_trust_detail(&dry)
        );

        // Two pins: each has its own registry, and its override names it.
        let two = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let done = registry_rewrite(
            &two,
            &[left_pad_registry_candidate(), is_number_candidate(true)],
        )
        .await;
        assert_eq!(lock_of(&done), Some(two_package_routed_lock().as_str()));
        assert_eq!(
            workspace_of(&done),
            Some(two_package_routed_workspace().as_str())
        );
    }

    /// THE MIXED CASE: one pin the patch service gave no registry address
    /// keeps the whole run on `trustLockfile`, with no `namedRegistries`
    /// and no `overrides`, exactly as a run with no address at all; a lock
    /// half routed would fail to install on pnpm >= 11. The warning names
    /// the package that forced it: trust switches verification off for
    /// every entry.
    #[tokio::test]
    async fn one_pin_without_an_address_keeps_the_run_on_trust_and_is_named() {
        let root = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let before =
            registry_rewrite(&root, &[left_pad_candidate(), is_number_candidate(false)]).await;
        assert_eq!(
            workspace_of(&before),
            Some("packages:\n  - '.'\ntrustLockfile: true\n")
        );
        assert!(
            !pnpm_trust_detail(&before).contains("Per-package registry verification"),
            "a patch service that gives no pin an address says nothing of a route"
        );
        let mixed = registry_rewrite(
            &root,
            &[left_pad_registry_candidate(), is_number_candidate(false)],
        )
        .await;
        assert_eq!(mixed.rewrite.files, before.rewrite.files);
        assert_eq!(mixed.rewrite.edits, before.rewrite.edits);
        assert!(!mixed.pnpm_named_registries);
        assert_eq!(
            workspace_edits(&mixed),
            [(
                REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
                "created",
                Some("trustLockfile")
            )]
        );
        for text in mixed.rewrite.files.values() {
            assert!(
                !text.contains("namedRegistries")
                    && !text.contains("overrides:")
                    && !text.contains("@socket-"),
                "{text}"
            );
        }
        assert_eq!(
            pnpm_trust_detail(&mixed),
            noted(
                pnpm_trust_detail(&before),
                &blocked("the patch service gave no registry address for is-number@7.0.0")
            )
        );

        // A pin an earlier run left on the patch server, which this run was
        // not granted, has no address either, and is named the same way.
        let pinned = after(&root, &before);
        let mut without_trust = pinned.clone();
        without_trust.insert_text(PNPM_WORKSPACE_REL, "packages:\n  - 'apps/*'\n");
        let one = registry_rewrite(&without_trust, &[left_pad_registry_candidate()]).await;
        assert_eq!(
            workspace_of(&one),
            Some("packages:\n  - 'apps/*'\ntrustLockfile: true\n")
        );
        assert!(!one.pnpm_named_registries);
        assert!(
            pnpm_trust_detail(&one).contains(&blocked(
                "the patch service gave no registry address for is-number@7.0.0"
            )),
            "{}",
            pnpm_trust_detail(&one)
        );
        assert_eq!(
            lock_of(&one),
            None,
            "both pins are already in the trust shape"
        );
    }

    /// A patched release of the partial-grant fixtures: `(name, version,
    /// patch uuid)`. Its registry is named after the first eight digits of
    /// the patch UUID.
    type Granted = (&'static str, &'static str, &'static str);
    const DEBUG_RELEASE: Granted = ("debug", "4.3.4", "d0000000-0000-4000-8000-00000000000d");
    const MS_RELEASE: Granted = ("ms", "2.1.2", "e0000000-0000-4000-8000-00000000000e");
    const QS_RELEASE: Granted = ("qs", "6.11.0", "f0000000-0000-4000-8000-00000000000f");
    /// The patch that supersedes [`MS_RELEASE`]'s.
    const MS_REPLACEMENT: Granted = ("ms", "2.1.2", "c1111111-1111-4111-8111-11111111111c");

    fn granted_url((name, version, uuid): Granted) -> String {
        format!(
            "https://patch.test/patch/npm/{name}/{version}/{FIXTURE_TOKEN}/{uuid}/{name}-{version}.tgz"
        )
    }

    fn granted_alias((_, _, uuid): Granted) -> String {
        format!("socket-{}", &uuid[..8])
    }

    /// The grant of `release`, with its registry address.
    fn granted_candidate(release: Granted) -> Candidate {
        let (name, version, uuid) = release;
        let mut candidate = left_pad_candidate();
        candidate.purl = format!("pkg:npm/{name}@{version}");
        candidate.dep.name = name.into();
        candidate.dep.version = version.into();
        candidate.dep.patch_uuid = uuid.into();
        candidate.dep.artifact_url = granted_url(release);
        candidate.dep.npm_registry_url = Some(registry_address(&granted_url(release)));
        candidate
    }

    /// A pnpm 12 project that depends on the three releases, as a hosted
    /// scan granted all three routed it.
    async fn three_routed_releases() -> MemoryProject {
        let releases = [DEBUG_RELEASE, MS_RELEASE, QS_RELEASE];
        let mut lock =
            "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n".to_string();
        for (name, version, ..) in releases {
            lock.push_str(&format!(
                "      {name}:\n        specifier: {version}\n        version: {version}\n"
            ));
        }
        lock.push_str("\npackages:\n");
        for (name, version, ..) in releases {
            lock.push_str(&format!(
                "  {name}@{version}:\n    resolution: {{integrity: sha512-UPSTREAM==}}\n\n"
            ));
        }
        lock.push_str("snapshots:\n");
        for (name, version, ..) in releases {
            lock.push_str(&format!("  {name}@{version}: {{}}\n\n"));
        }
        let mut root = MemoryProject::new();
        root.insert_text("pnpm-lock.yaml", lock.trim_end().to_string() + "\n");
        root.insert_text(
            "package.json",
            r#"{"name":"app","packageManager":"pnpm@12.22.0","dependencies":{"debug":"4.3.4","ms":"2.1.2","qs":"6.11.0"}}"#,
        );
        let all = releases.map(granted_candidate);
        let done = registry_rewrite(&root, &all).await;
        assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        let routed = after(&root, &done);
        let workspace = routed.text(PNPM_WORKSPACE_REL).expect("a workspace file");
        for release in releases {
            assert!(
                workspace.contains(&registry_line(
                    &granted_alias(release),
                    &granted_url(release)
                )),
                "{workspace}"
            );
        }
        routed
    }

    /// A RUN GRANTED ONLY PART OF THE PROJECT'S PATCHES (a scan of one
    /// subtree of a monorepo with one root lock, any filtered grant) leaves
    /// the rest routed. The releases it was not granted keep the registry
    /// the files already route them through (its name, its address, the
    /// override), so nothing is rewritten: not a byte of the lock or of
    /// the workspace file changes, and lockfile verification stays on.
    #[tokio::test]
    async fn a_run_granted_one_package_leaves_the_others_routed() {
        let routed = three_routed_releases().await;
        for granted in [DEBUG_RELEASE, MS_RELEASE, QS_RELEASE] {
            let done = registry_rewrite(&routed, &[granted_candidate(granted)]).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{}: {:?}",
                granted.0,
                done.rewrite.files
            );
            assert!(done.rewrite.edits.is_empty(), "{:?}", done.rewrite.edits);
            assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
            assert_eq!(done.confirmed.len(), 1);
            let detail = pnpm_trust_detail(&done);
            assert!(
                !detail.contains("trustLockfile") && !detail.contains("no registry address"),
                "{detail}"
            );
        }
    }

    /// A release this run was not granted that an unreleased build routed
    /// through a registry named by the whole patch UUID stays routed, and
    /// moves to the registry's short name with the granted one: no run
    /// leaves an earlier name behind.
    #[tokio::test]
    async fn an_ungranted_release_under_an_earlier_name_is_renamed() {
        let legacy = format!("socket-patch-{FIXTURE_UUID}");
        let mut project =
            pnpm12_project(&two_package_routed_lock().replace(LEFT_PAD_ALIAS, &legacy));
        project.insert_text(
            PNPM_WORKSPACE_REL,
            two_package_routed_workspace().replace(LEFT_PAD_ALIAS, &legacy),
        );
        let granted = [is_number_candidate(true)];
        let done = registry_rewrite(&project, &granted).await;
        assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        assert_eq!(lock_of(&done), Some(two_package_routed_lock().as_str()));
        // The renamed registry goes after the one that stays.
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\noverrides:\n{IS_NUMBER_OVERRIDE}\n{LEFT_PAD_OVERRIDE}\n",
                    is_number_registry_line(),
                    left_pad_registry_line()
                )
                .as_str()
            )
        );
        let again = registry_rewrite(&after(&project, &done), &granted).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
    }

    /// The same partial run with a patch that supersedes the granted
    /// package's: only that package changes. Its registry is the new
    /// patch's, under the new patch's name, so its override, its lock keys
    /// and its tarball move to it and the replaced patch's registry goes;
    /// the other two releases, their overrides and their registries are
    /// byte for byte.
    #[tokio::test]
    async fn a_run_granted_one_replaced_patch_changes_only_that_package() {
        let routed = three_routed_releases().await;
        let done = registry_rewrite(&routed, &[granted_candidate(MS_REPLACEMENT)]).await;
        assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        let (old, new) = (granted_alias(MS_RELEASE), granted_alias(MS_REPLACEMENT));
        assert_eq!(
            lock_of(&done),
            Some(
                routed
                    .text("pnpm-lock.yaml")
                    .unwrap()
                    .replace(&granted_url(MS_RELEASE), &granted_url(MS_REPLACEMENT))
                    .replace(&format!("{old}:"), &format!("{new}:"))
                    .as_str()
            )
        );
        // The replaced patch's registry line goes and the new patch's is
        // added after the registries that stay; nothing else of the file
        // moves.
        let before = routed.text(PNPM_WORKSPACE_REL).unwrap();
        let expected = before
            .replace(
                &format!("{}\n", registry_line(&old, &granted_url(MS_RELEASE))),
                "",
            )
            .replace(
                "overrides:\n",
                &format!(
                    "{}\noverrides:\n",
                    registry_line(&new, &granted_url(MS_REPLACEMENT))
                ),
            )
            .replace(&format!("'{old}:2.1.2'"), &format!("'{new}:2.1.2'"));
        assert_eq!(workspace_of(&done), Some(expected.as_str()));
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(old.as_str())
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "added",
                    Some(new.as_str())
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "rewritten",
                    Some("ms@2.1.2")
                ),
            ]
        );
        // A re-run of the same partial grant changes nothing.
        let again =
            registry_rewrite(&after(&routed, &done), &[granted_candidate(MS_REPLACEMENT)]).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
    }

    /// THE GENUINE FALLBACK of a partial run: a routed release the run was
    /// not granted that the files no longer route (its registry's line is
    /// gone, or declared somewhere its tarball is not served from) has no
    /// address from anywhere. The project goes back to `trustLockfile`
    /// whole, and the warning names that release alone: the other
    /// ungranted release, still routed by the files, is not what forced
    /// it. A release this run WAS granted without an address is never kept
    /// either: the grant says the patch service serves it no registry.
    #[tokio::test]
    async fn an_ungranted_release_the_files_do_not_route_goes_back_to_trust() {
        let routed = three_routed_releases().await;
        let workspace = routed.text(PNPM_WORKSPACE_REL).unwrap();
        let qs_line = format!(
            "{}\n",
            registry_line(&granted_alias(QS_RELEASE), &granted_url(QS_RELEASE))
        );
        for unrouted in [
            // The registry's declaration is gone.
            workspace.replace(&qs_line, ""),
            // The override that routes the release is gone.
            workspace.replace("  'qs@6.11.0': 'socket-f0000000:6.11.0'\n", ""),
        ] {
            assert_ne!(unrouted, workspace);
            let mut project = routed.clone();
            project.insert_text(PNPM_WORKSPACE_REL, unrouted.clone());
            let done = registry_rewrite(&project, &[granted_candidate(DEBUG_RELEASE)]).await;
            assert!(!done.pnpm_named_registries, "{unrouted}");
            let written = workspace_of(&done).expect("the workspace file is rewritten");
            assert!(
                written.contains("trustLockfile: true") && !written.contains("socket-"),
                "{written}"
            );
            let lock = lock_of(&done).expect("the lock is put back");
            assert!(
                !lock.contains("@socket-") && !lock.contains("overrides:"),
                "{lock}"
            );
            for release in [DEBUG_RELEASE, MS_RELEASE, QS_RELEASE] {
                assert!(lock.contains(&granted_url(release)), "{lock}");
            }
            let detail = pnpm_trust_detail(&done);
            assert!(
                detail.contains(&blocked(
                    "the patch service gave no registry address for qs@6.11.0"
                )),
                "{detail}"
            );
            assert!(!detail.contains("ms@2.1.2"), "{detail}");
        }

        // Granted, with no address: the grant overrules what the files route.
        let mut no_address = granted_candidate(MS_RELEASE);
        no_address.dep.npm_registry_url = None;
        let done = registry_rewrite(&routed, &[no_address]).await;
        assert!(!done.pnpm_named_registries);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains(&blocked(
                "the patch service gave no registry address for ms@2.1.2"
            )),
            "{detail}"
        );
    }

    /// The base of the patch mirror of the mirror tests.
    const MIRROR_BASE: &str = "https://repo.example/artifactory/socket-patch";

    /// `candidates` as a run given `--patch-mirror-url` holds them: each
    /// tarball moved onto the mirror.
    fn onto_the_mirror(candidates: Vec<Candidate>, origins: &[String]) -> Vec<Candidate> {
        let mirror = crate::patch::redirect::mirror::PatchMirror::parse(MIRROR_BASE).unwrap();
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let (mirrored, _) =
            mirror_candidates(candidates, &mirror, origins, &mut skipped, &mut warnings);
        assert!(skipped.is_empty() && warnings.is_empty(), "{warnings:?}");
        mirrored
    }

    /// A PATCH MIRROR. A run given `--patch-mirror-url` pins each tarball
    /// on the mirror. The registry address of the grant stays the patch
    /// server's, whose document names the tarball there, so the mirrored
    /// tarball is no file of it: the pin has no registry, and the project
    /// takes `trustLockfile` exactly as before the registry route existed,
    /// with nothing said of registries.
    #[tokio::test]
    async fn a_pin_on_a_patch_mirror_has_no_registry_and_stays_on_trust() {
        let origins = vec![
            "https://patch.test".to_string(),
            crate::origin::mirror_entry(MIRROR_BASE),
        ];
        let mirrored = onto_the_mirror(vec![left_pad_registry_candidate()], &origins);
        let dep = &mirrored[0].dep;
        assert!(dep.artifact_url.starts_with(MIRROR_BASE), "{dep:?}");
        assert_eq!(
            dep.npm_registry_url.as_deref(),
            Some(left_pad_registry_url().as_str()),
            "the address is the patch server's, as granted"
        );
        assert_eq!(crate::patch::redirect::grant::npm_registry_url(dep), None);

        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let done = pnpm_rewrite_from(
            &ProjectView::Memory(&root),
            &mirrored,
            true,
            false,
            &no_env,
            origins.clone(),
        )
        .await;
        assert!(!done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        assert_eq!(done.confirmed.len(), 1);
        assert_eq!(
            workspace_of(&done),
            Some("packages:\n  - '.'\ntrustLockfile: true\n")
        );
        let lock = lock_of(&done).expect("the lock");
        assert!(
            lock.contains(&format!("tarball: {}", dep.artifact_url))
                && lock.contains("\n  left-pad@1.3.0:\n")
                && !lock.contains("overrides:"),
            "{lock}"
        );
        let detail = pnpm_trust_detail(&done);
        assert!(
            !detail.contains("registry verification") && !detail.contains("namedRegistries"),
            "{detail}"
        );
    }

    /// TURNING A MIRROR ON over a project an earlier run routed: the pins
    /// move onto the mirror, where no registry serves them, so the run
    /// takes the whole route out and the project is byte for byte the one
    /// a mirror run makes from scratch. The registries it removes are on
    /// the patch server, which the run still knows for one: as its
    /// configured server, or, when only the mirror was configured, from
    /// the registry address its grant carries. The warning names the
    /// mirror as what kept the project off the route.
    #[tokio::test]
    async fn turning_a_patch_mirror_on_takes_a_routed_project_off_the_route() {
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let routed = registry_rewrite(&root, &[left_pad_registry_candidate()]).await;
        assert!(routed.pnpm_named_registries);
        let routed = after(&root, &routed);
        for server in ["https://patch.test", "https://patch.socket.dev"] {
            let origins = vec![server.to_string(), crate::origin::mirror_entry(MIRROR_BASE)];
            let mirrored = onto_the_mirror(vec![left_pad_registry_candidate()], &origins);
            let rewrite = |project: MemoryProject| {
                let (mirrored, origins) = (mirrored.clone(), origins.clone());
                async move {
                    pnpm_rewrite_from(
                        &ProjectView::Memory(&project),
                        &mirrored,
                        true,
                        false,
                        &no_env,
                        origins,
                    )
                    .await
                }
            };
            let fresh = rewrite(root.clone()).await;
            let done = rewrite(routed.clone()).await;
            assert!(!done.pnpm_named_registries, "{server}");
            assert_eq!(done.confirmed.len(), 1, "{server}");
            assert_eq!(lock_of(&done), lock_of(&fresh), "{server}");
            assert_eq!(
                workspace_of(&done),
                Some("packages:\n  - '.'\ntrustLockfile: true\n"),
                "{server}"
            );
            let detail = pnpm_trust_detail(&done);
            assert!(
                detail.contains(
                    "Per-package registry verification was not set up because the patch \
                     mirror serves no registry for left-pad@1.3.0"
                ) && !detail.contains("gave no registry address"),
                "{server}: {detail}"
            );
            let removed: Vec<(&'static str, String)> =
                crate::hosted::guidance::pnpm_registry_entries_removed(&done.rewrite.edits)
                    .into_iter()
                    .map(|entry| (entry.kind.as_str(), entry.key))
                    .collect();
            assert!(
                removed.contains(&("registry", LEFT_PAD_ALIAS.to_string()))
                    && removed.contains(&("override", "left-pad@1.3.0".to_string())),
                "{server}: {removed:?}"
            );
            let again = rewrite(after(&routed, &done)).await;
            assert!(again.rewrite.files.is_empty(), "{server}");
        }
    }

    /// A run with a mirror configured that is granted nothing still tidies
    /// what a departed package left of a route: the registry is on the
    /// configured patch server, not under the mirror's base, and is the
    /// CLI's as before. A registry of the same shape that a person
    /// declared on the mirror's host is not on a patch server, and stays.
    #[tokio::test]
    async fn a_run_with_a_patch_mirror_still_tidies_a_route() {
        const PLAIN: &str = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      \
             is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n\npackages:\n  \
             is-number@7.0.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n\n\
             snapshots:\n  is-number@7.0.0: {}\n";
        let origins = vec![
            "https://patch.test".to_string(),
            crate::origin::mirror_entry(MIRROR_BASE),
        ];
        let users = format!(
            "  socket-99999999: {MIRROR_BASE}/patch/npm/x/1.0.0/{FIXTURE_TOKEN}/99999999-9999-4999-8999-999999999999/\n"
        );
        let mut project = pnpm12_project(&PLAIN.replace(
            "importers:\n",
            &format!("overrides:\n  left-pad@1.3.0: {LEFT_PAD_ALIAS}:1.3.0\n\nimporters:\n"),
        ));
        project.insert_text(
            PNPM_WORKSPACE_REL,
            format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n{users}{}\noverrides:\n{LEFT_PAD_OVERRIDE}\n",
                left_pad_registry_line()
            ),
        );
        let done = pnpm_rewrite_from(
            &ProjectView::Memory(&project),
            &[],
            true,
            false,
            &no_env,
            origins,
        )
        .await;
        assert_eq!(
            workspace_of(&done),
            Some(format!("packages:\n  - 'apps/*'\nnamedRegistries:\n{users}").as_str())
        );
        assert_eq!(lock_of(&done), Some(PLAIN));
    }

    /// A run that leaves the route takes it out of every governing lock
    /// and of the workspace file together, or not at all. A lock the
    /// route's edits cannot read (mixed line endings here) still keys its
    /// release by the registry: stripping the registry and the override
    /// from the workspace file beside it would leave a lock pnpm cannot
    /// install. The project stays routed, and the warning says the lock
    /// could not be converted back and why.
    #[tokio::test]
    async fn a_lock_the_edits_cannot_read_keeps_the_route_it_still_uses() {
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let routed = registry_rewrite(&root, &[left_pad_registry_candidate()]).await;
        assert!(routed.pnpm_named_registries);
        let mut project = after(&root, &routed);
        let mixed = left_pad_routed_lock().replacen('\n', "\r\n", 1);
        project.insert_text("pnpm-lock.yaml", mixed.as_str());

        // The grant lost its registry address: the run leaves the route.
        let done = registry_rewrite(&project, &[left_pad_candidate()]).await;
        let workspace = workspace_of(&done).unwrap_or(&routed.rewrite.files[PNPM_WORKSPACE_REL]);
        for kept in [left_pad_registry_line().as_str(), LEFT_PAD_OVERRIDE] {
            assert!(workspace.contains(kept), "{kept}:\n{workspace}");
        }
        assert_eq!(lock_of(&done), None, "the lock is left as it is");
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("could not be converted back")
                && detail.contains("mixes CRLF and LF line endings"),
            "{detail}"
        );
    }

    /// THE MIXED CASE ON A RE-RUN: a project in registry mode whose next
    /// scan has a pin without an address goes back to trust whole, in that
    /// run: every registry key of the lock back to the plain one, the
    /// lock's record of the overrides and both maps of the workspace file
    /// gone. What is left is byte for byte the project a trust run makes.
    #[tokio::test]
    async fn a_routed_project_goes_back_to_trust_when_a_pin_loses_its_address() {
        let root = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let trust =
            registry_rewrite(&root, &[left_pad_candidate(), is_number_candidate(false)]).await;
        let routed = registry_rewrite(
            &root,
            &[left_pad_registry_candidate(), is_number_candidate(true)],
        )
        .await;
        assert!(routed.pnpm_named_registries);
        let routed = after(&root, &routed);

        let candidates = [left_pad_registry_candidate(), is_number_candidate(false)];
        let done = registry_rewrite(&routed, &candidates).await;
        assert!(!done.pnpm_named_registries);
        assert_eq!(lock_of(&done), lock_of(&trust));
        assert_eq!(
            workspace_of(&done),
            Some("packages:\n  - '.'\ntrustLockfile: true\n")
        );
        assert_eq!(done.confirmed.len(), 2);
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(LEFT_PAD_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(IS_NUMBER_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("is-number@7.0.0")
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
                    "added",
                    Some("trustLockfile")
                ),
            ]
        );
        assert_eq!(
            edits_of(&done, "pnpm-lock.yaml"),
            [
                (
                    REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND,
                    "rewritten",
                    Some("is-number@7.0.0")
                ),
                (
                    REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND,
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("is-number@7.0.0")
                ),
                (
                    REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("left-pad@1.3.0")
                ),
            ]
        );
        let detail = pnpm_trust_detail(&done);
        for said in [
            blocked("the patch service gave no registry address for is-number@7.0.0"),
            "An earlier run routed the hosted patches through a named registry".to_string(),
            "those entries were removed and the lockfile keys that named the registry put back"
                .to_string(),
            "`trustLockfile: true` was merged into".to_string(),
        ] {
            assert!(detail.contains(&said), "{said}: {detail}");
        }
        // What is left is a trust project: a re-run changes nothing.
        let back = after(&routed, &done);
        let again = registry_rewrite(&back, &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
        assert!(!pnpm_trust_detail(&again).contains("An earlier run"));

        // A dry run reports the same removals, and the engine writes
        // nothing either way.
        let dry = pnpm_rewrite(
            &ProjectView::Memory(&routed),
            &candidates,
            true,
            true,
            &no_env,
        )
        .await;
        assert_eq!(dry.rewrite.files, done.rewrite.files);
        assert_eq!(dry.rewrite.edits, done.rewrite.edits);
        assert!(
            pnpm_trust_detail(&dry).contains("those entries would be removed"),
            "{}",
            pnpm_trust_detail(&dry)
        );

        // A user's file keeps its own lines, with the trust key after them.
        let users = "packages:\n  - 'apps/*'\nnamedRegistries:\n  corp: https://npm.corp.example/\noverrides:\n  lodash: ^4.17.21\n";
        let mut users_project = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        users_project.insert_text(PNPM_WORKSPACE_REL, users);
        let users_routed = after(
            &users_project,
            &registry_rewrite(
                &users_project,
                &[left_pad_registry_candidate(), is_number_candidate(true)],
            )
            .await,
        );
        let done = registry_rewrite(&users_routed, &candidates).await;
        assert_eq!(
            workspace_of(&done),
            Some(format!("{users}trustLockfile: true\n").as_str())
        );
        assert_eq!(lock_of(&done), lock_of(&trust));
    }

    /// `--no-trust-lockfile-config` keeps the workspace file from being
    /// written, and a lock in the routed shape installs only with the
    /// file's overrides: the run stays on the trust path, exactly as one
    /// with no address. A project already routed needs no write and is
    /// left routed.
    #[tokio::test]
    async fn the_opt_out_keeps_an_unrouted_project_on_trust() {
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let opted_out = |project: MemoryProject, candidate: Candidate| async move {
            pnpm_rewrite(
                &ProjectView::Memory(&project),
                &[candidate],
                false,
                false,
                &no_env,
            )
            .await
        };
        let done = opted_out(root.clone(), left_pad_registry_candidate()).await;
        let plain = opted_out(root.clone(), left_pad_candidate()).await;
        assert_eq!(done.rewrite.files, plain.rewrite.files);
        assert_eq!(done.rewrite.edits, plain.rewrite.edits);
        assert_eq!(done.pnpm_warnings, plain.pnpm_warnings);
        assert_eq!(workspace_of(&done), None);
        assert!(!done.pnpm_named_registries);
        assert!(pnpm_trust_detail(&done).contains("pnpm install --trust-lockfile"));
        assert!(!lock_of(&done).is_some_and(|lock| lock.contains("@socket-")));

        // Routed by an earlier run: nothing to write, nothing to undo.
        let routed = after(
            &root,
            &registry_rewrite(&root, &[left_pad_registry_candidate()]).await,
        );
        let again = opted_out(routed.clone(), left_pad_registry_candidate()).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
        assert!(again.pnpm_rerun_only && again.pnpm_named_registries);
        assert!(pnpm_trust_detail(&again).contains("already declares"));
        // A routed project the opted-out run can no longer keep routed (the
        // grant has no address now) is left as it is: the file is not the
        // run's to edit, and the lock goes with the file.
        let stuck = opted_out(routed, left_pad_candidate()).await;
        assert!(stuck.rewrite.files.is_empty(), "{:?}", stuck.rewrite.files);
        assert!(!stuck.pnpm_named_registries);
    }

    /// `--no-trust-lockfile-config` and a routed release whose patch was
    /// superseded. The new patch has a registry of its own, which the run
    /// may not declare: the file is not its to edit. Repointing the lock
    /// entry alone would leave the old patch's registry key, override and
    /// declaration over the new patch's tarball, which pnpm refuses to
    /// install (the registry does not vouch for it) and undoes at its next
    /// resolve. The release stays on the patch it is routed to, whole: no
    /// file changes, the new patch is not confirmed, and the run says how
    /// to move it.
    #[tokio::test]
    async fn the_opt_out_leaves_a_routed_release_on_the_patch_it_is_routed_to() {
        const NEXT: &str = "66666666-6666-4666-8666-666666666666";
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let routed = after(
            &root,
            &registry_rewrite(&root, &[left_pad_registry_candidate()]).await,
        );
        let mut next = left_pad_registry_candidate();
        next.dep.patch_uuid = NEXT.into();
        next.dep.artifact_url = left_pad_url().replace(FIXTURE_UUID, NEXT);
        next.dep.npm_registry_url = Some(registry_address(&next.dep.artifact_url));
        for dry_run in [true, false] {
            let done = pnpm_rewrite(
                &ProjectView::Memory(&routed),
                std::slice::from_ref(&next),
                false,
                dry_run,
                &no_env,
            )
            .await;
            assert!(
                done.rewrite.files.is_empty(),
                "dry_run={dry_run}: {:?}",
                done.rewrite.files
            );
            assert!(done.rewrite.edits.is_empty(), "{:?}", done.rewrite.edits);
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            let held: Vec<&str> = done
                .rewrite
                .warnings
                .iter()
                .filter(|w| w.code == REDIRECT_PNPM_REGISTRY_HELD)
                .map(|w| w.detail.as_str())
                .collect();
            assert_eq!(
                held,
                [
                    "left-pad@1.3.0 stays on the patch it is routed to: its newer patch is served \
                  from another registry, and --no-trust-lockfile-config keeps \
                  pnpm-workspace.yaml, which names the registry, from being updated; re-run \
                  without the flag to move it to the newer patch"
                ],
                "dry_run={dry_run}"
            );
        }
        // Without the opt-out the same grant moves the release.
        let moved = registry_rewrite(&routed, &[next]).await;
        assert!(lock_of(&moved).is_some_and(|lock| lock.contains(NEXT)));
        assert_eq!(moved.confirmed.len(), 1);
    }

    /// A workspace file hosted mode created holds nothing of the user's.
    /// When a run takes the route back out of it, what is left is the
    /// file's `packages` scaffold, and that is no file of the user's
    /// either: the run plans the project's settings as for a project with
    /// no workspace file. For a project now pinned to pnpm 9.0 to 10.4,
    /// which never read `trustLockfile` and refuse `pnpm add` in a
    /// root-only workspace, that means no file at all: the scaffold is
    /// written back bare and flagged for deletion, never topped up with a
    /// key those releases do not read.
    #[tokio::test]
    async fn leaving_the_route_does_not_keep_the_file_the_route_created() {
        let candidates = [left_pad_registry_candidate()];
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let first = registry_rewrite(&root, &candidates).await;
        assert_eq!(
            workspace_of(&first),
            Some(left_pad_routed_workspace().as_str()),
            "the route creates the file"
        );
        let routed = after(&root, &first);

        // Pinned to a pnpm that reads no `trustLockfile`.
        let mut older = routed.clone();
        older.insert_text(
            "package.json",
            r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"packageManager":"pnpm@10.2.0"}"#,
        );
        let done = registry_rewrite(&older, &candidates).await;
        assert!(!done.pnpm_named_registries);
        assert_eq!(
            workspace_of(&done),
            Some("packages:\n  - '.'\n"),
            "nothing is added to what the route created"
        );
        assert!(
            done.pnpm_workspace_emptied,
            "the created file is the caller's to delete"
        );
        let lock = lock_of(&done).expect("the lock, back in the plain shape");
        assert!(
            lock.contains("\n  left-pad@1.3.0:\n") && !lock.contains("overrides:"),
            "{lock}"
        );
        assert!(
            pnpm_trust_detail(&done).contains("does not read `trustLockfile`"),
            "{}",
            pnpm_trust_detail(&done)
        );

        // Pinned to a pnpm that needs the key: the file is the one a
        // trust run creates, and it is not flagged.
        let mut gated = routed.clone();
        gated.insert_text(
            "package.json",
            r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"packageManager":"pnpm@11.10.0"}"#,
        );
        let done = registry_rewrite(&gated, &candidates).await;
        assert_eq!(
            workspace_of(&done),
            Some("packages:\n  - '.'\ntrustLockfile: true\n")
        );
        assert!(!done.pnpm_workspace_emptied);

        // A file of the user's keeps its bytes and gets the key, whatever
        // the pin: it is theirs, and is never deleted.
        let users = "packages:\n  - 'apps/*'\n";
        let mut owned = pnpm12_project(LEFT_PAD_V9_LOCK);
        owned.insert_text(PNPM_WORKSPACE_REL, users);
        let mut routed = after(&owned, &registry_rewrite(&owned, &candidates).await);
        routed.insert_text(
            "package.json",
            r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"packageManager":"pnpm@10.2.0"}"#,
        );
        let done = registry_rewrite(&routed, &candidates).await;
        assert_eq!(
            workspace_of(&done),
            Some(format!("{users}trustLockfile: true\n").as_str())
        );
        assert!(!done.pnpm_workspace_emptied);
    }

    /// HEAL-ON-RERUN: a lock an earlier (opted-out, or interrupted) run
    /// already redirected is routed by a re-run that splices nothing.
    #[tokio::test]
    async fn a_rerun_routes_a_lock_an_earlier_run_redirected() {
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let candidates = [left_pad_registry_candidate()];
        let first = pnpm_rewrite(
            &ProjectView::Memory(&root),
            &candidates,
            false,
            false,
            &no_env,
        )
        .await;
        let redirected = after(&root, &first);
        let healed = registry_rewrite(&redirected, &candidates).await;
        assert_eq!(lock_of(&healed), Some(left_pad_routed_lock().as_str()));
        assert_eq!(
            workspace_of(&healed),
            Some(left_pad_routed_workspace().as_str())
        );
        assert!(!healed.pnpm_rerun_only);
        assert_eq!(healed.confirmed.len(), 1);
    }

    /// A `trustLockfile: true` an earlier run wrote (the file is exactly
    /// what that run creates, or a keyless file plus the lines it splices)
    /// goes in the run that routes the pins, in the file's own line
    /// ending: the project ends with pnpm's verification back on.
    #[tokio::test]
    async fn a_trust_key_an_earlier_run_wrote_is_replaced() {
        let candidates = [left_pad_registry_candidate()];
        let maps = format!(
            "namedRegistries:\n{}\noverrides:\n{LEFT_PAD_OVERRIDE}\n",
            left_pad_registry_line()
        );
        for (before, want) in [
            (
                "packages:\n  - '.'\ntrustLockfile: true\n".to_string(),
                format!("packages:\n  - '.'\n{maps}"),
            ),
            (
                "packages:\r\n  - '.'\r\ntrustLockfile: true\r\n".to_string(),
                format!("packages:\n  - '.'\n{maps}").replace('\n', "\r\n"),
            ),
            (
                "# team settings\npackages:\n  - '.'\ntrustLockfile: true\n".to_string(),
                format!("# team settings\npackages:\n  - '.'\n{maps}"),
            ),
        ] {
            let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
            root.insert_text(PNPM_WORKSPACE_REL, before.as_str());
            let done = registry_rewrite(&root, &candidates).await;
            assert_eq!(workspace_of(&done), Some(want.as_str()), "{before:?}");
            assert_eq!(
                workspace_edits(&done),
                [
                    (
                        REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
                        "removed",
                        Some("trustLockfile")
                    ),
                    (
                        REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                        "added",
                        Some(LEFT_PAD_ALIAS)
                    ),
                    (
                        REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                        "added",
                        Some("left-pad@1.3.0")
                    ),
                ],
                "{before:?}"
            );
            let detail = pnpm_trust_detail(&done);
            assert!(
                detail.contains(
                    "The `trustLockfile: true` an earlier socket-patch run wrote there was removed"
                ),
                "{detail}"
            );
            assert!(
                detail.contains("verifies the whole lockfile again"),
                "{detail}"
            );
            // What is left is the file a registry run creates or splices.
            let again = registry_rewrite(&after(&root, &done), &candidates).await;
            assert!(again.rewrite.files.is_empty(), "{before:?}");
        }
    }

    /// A `trustLockfile` the file's bytes do not prove an earlier run wrote
    /// is the user's: `true` stays, and the warning says the hosted patches
    /// no longer need it; any other value no longer stands in the way of
    /// anything. A `pnpm_config_trust_lockfile` variable is irrelevant to a
    /// routed package too.
    #[tokio::test]
    async fn a_users_trust_key_is_left_alone() {
        fn off(var: &str) -> Option<String> {
            (var == "pnpm_config_trust_lockfile").then(|| "false".to_string())
        }
        let candidates = [left_pad_registry_candidate()];
        let maps = format!(
            "namedRegistries:\n{}\noverrides:\n{LEFT_PAD_OVERRIDE}\n",
            left_pad_registry_line()
        );
        for (user, left) in [
            ("packages:\n  - 'apps/*'\ntrustLockfile: true\n", true),
            ("trustLockfile: true\npackages:\n  - '.'\n", true),
            ("packages:\n  - '.'\ntrustLockfile: false\n", false),
            ("packages:\n  - 'apps/*'\n", false),
        ] {
            for env in [no_env as fn(&str) -> Option<String>, off] {
                let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
                root.insert_text(PNPM_WORKSPACE_REL, user);
                let done =
                    pnpm_rewrite(&ProjectView::Memory(&root), &candidates, true, false, &env).await;
                assert_eq!(
                    workspace_of(&done),
                    Some(format!("{user}{maps}").as_str()),
                    "{user:?}"
                );
                let detail = pnpm_trust_detail(&done);
                assert!(
                    detail.contains("the existing pnpm-workspace.yaml now declares"),
                    "{detail}"
                );
                assert_eq!(
                    detail.contains(
                        "also sets `trustLockfile: true`, which the hosted patches no longer need"
                    ),
                    left,
                    "{user:?}: {detail}"
                );
                assert!(!detail.contains("respected"), "{detail}");
                assert!(!detail.contains("pnpm_config_trust_lockfile"), "{detail}");
            }
        }
    }

    /// CLEANUP, a package that left the lock (removed, or upgraded to a
    /// release with no patch): its override goes from the workspace file
    /// and from the lock's record, and its registry goes with it, in the
    /// run that routes the pins that remain.
    #[tokio::test]
    async fn a_package_that_left_the_lock_takes_its_route_with_it() {
        let root = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let both = [left_pad_registry_candidate(), is_number_candidate(true)];
        let routed = after(&root, &registry_rewrite(&root, &both).await);
        // The user removed is-number, and pnpm rewrote the lock: its
        // entries are gone, the override it was configured with is still
        // recorded.
        let mut removed = routed.clone();
        removed.insert_text(
            "pnpm-lock.yaml",
            left_pad_routed_lock().replace(
                "overrides:\n",
                &format!("overrides:\n  is-number@7.0.0: {IS_NUMBER_ALIAS}:7.0.0\n"),
            ),
        );
        let done = registry_rewrite(&removed, &[left_pad_registry_candidate()]).await;
        assert_eq!(lock_of(&done), Some(left_pad_routed_lock().as_str()));
        assert_eq!(
            workspace_of(&done),
            Some(left_pad_routed_workspace().as_str())
        );
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(IS_NUMBER_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("is-number@7.0.0")
                ),
            ]
        );
        assert_eq!(
            edits_of(&done, "pnpm-lock.yaml"),
            [(
                REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                "removed",
                Some("is-number@7.0.0")
            )]
        );
        assert!(done.pnpm_named_registries);
        // A dry run reports the same removals.
        let dry = pnpm_rewrite(
            &ProjectView::Memory(&removed),
            &[left_pad_registry_candidate()],
            true,
            true,
            &no_env,
        )
        .await;
        assert_eq!(dry.rewrite.files, done.rewrite.files);
        assert_eq!(dry.rewrite.edits, done.rewrite.edits);
    }

    /// CLEANUP by a run the patch service grants nothing: a release an
    /// earlier run routed stays routed (a patch missing from one search is
    /// not a withdrawn one), and what the package that left the lock had
    /// goes: its override, the lock's record of it, and its registry,
    /// which no lock key names any more. A dry run reports the same.
    #[tokio::test]
    async fn a_run_with_no_grant_still_drops_what_a_departed_package_left() {
        let workspace = |registries: &[String], overrides: &[&str]| {
            format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n{}\noverrides:\n{}\n",
                registries.join("\n"),
                overrides.join("\n")
            )
        };
        let mut root = pnpm12_project(&left_pad_routed_lock().replace(
            "overrides:\n",
            &format!("overrides:\n  is-number@7.0.0: {IS_NUMBER_ALIAS}:7.0.0\n"),
        ));
        root.insert_text(
            PNPM_WORKSPACE_REL,
            workspace(
                &[left_pad_registry_line(), is_number_registry_line()],
                &[IS_NUMBER_OVERRIDE, LEFT_PAD_OVERRIDE],
            ),
        );
        // The run is granted nothing the lock holds (the grant of a
        // package the lock dropped is what names the fixtures' patch
        // server to it).
        let granted = [is_number_candidate(true)];
        let done = registry_rewrite(&root, &granted).await;
        assert_eq!(lock_of(&done), Some(left_pad_routed_lock().as_str()));
        assert_eq!(
            workspace_of(&done),
            Some(workspace(&[left_pad_registry_line()], &[LEFT_PAD_OVERRIDE]).as_str())
        );
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(IS_NUMBER_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("is-number@7.0.0")
                ),
            ]
        );
        assert_eq!(
            edits_of(&done, "pnpm-lock.yaml"),
            [(
                REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                "removed",
                Some("is-number@7.0.0")
            )]
        );
        let entries: Vec<(&'static str, String)> =
            crate::hosted::guidance::pnpm_registry_entries_removed(&done.rewrite.edits)
                .into_iter()
                .map(|entry| (entry.kind.as_str(), entry.key))
                .collect();
        assert_eq!(
            entries,
            [
                ("lockOverride", "is-number@7.0.0".to_string()),
                ("registry", IS_NUMBER_ALIAS.to_string()),
                ("override", "is-number@7.0.0".to_string()),
            ]
        );
        assert!(done.pnpm_warnings.is_empty(), "{:?}", done.pnpm_warnings);
        let dry = pnpm_rewrite(&ProjectView::Memory(&root), &granted, true, true, &no_env).await;
        assert_eq!(dry.rewrite.files, done.rewrite.files);
        assert_eq!(dry.rewrite.edits, done.rewrite.edits);
        // Nothing is left to tidy.
        let again = registry_rewrite(&after(&root, &done), &granted).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
    }

    /// CLEANUP, with no hosted pin of this run left in the lock at all:
    /// the run still takes out what no lock references, and no trust key
    /// or warning goes in its place. A project file of the user's is back
    /// to their bytes; the file a run created is written back as its
    /// `packages` scaffold and marked emptied, which is what has the
    /// caller delete it (a rewrite carries writes only).
    #[tokio::test]
    async fn orphans_of_a_route_go_on_the_next_scan() {
        const UNROUTED: &str = "lockfileVersion: '9.0'\n\noverrides:\n  left-pad@1.3.0: socket-77777777:1.3.0\n\n\
             importers:\n  .:\n    dependencies:\n      is-number:\n        specifier: 7.0.0\n        \
             version: 7.0.0\n\npackages:\n  is-number@7.0.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n\n\
             snapshots:\n  is-number@7.0.0: {}\n";
        // left-pad was routed, then left the lock; the run is granted a
        // patch for a package the lock does not hold.
        let candidates = [left_pad_registry_candidate()];
        for (workspace, want) in [
            (left_pad_routed_workspace(), "packages:\n  - '.'\n".to_string()),
            (
                format!(
                    "packages:\n  - 'apps/*'\nnamedRegistries:\n  corp: https://npm.corp.example/\n{}\n\
                     overrides:\n  lodash: ^4.17.21\n{LEFT_PAD_OVERRIDE}\n",
                    left_pad_registry_line()
                ),
                "packages:\n  - 'apps/*'\nnamedRegistries:\n  corp: https://npm.corp.example/\n\
                 overrides:\n  lodash: ^4.17.21\n"
                    .to_string(),
            ),
        ] {
            let mut root = pnpm12_project(UNROUTED);
            root.insert_text(PNPM_WORKSPACE_REL, workspace.as_str());
            let done = registry_rewrite(&root, &candidates).await;
            assert_eq!(workspace_of(&done), Some(want.as_str()), "{workspace}");
            assert_eq!(
                done.pnpm_workspace_emptied,
                want == "packages:\n  - '.'\n",
                "only the file a run created is the caller's to delete: {workspace}"
            );
            assert_eq!(
                lock_of(&done),
                Some(
                    UNROUTED
                        .replace("overrides:\n  left-pad@1.3.0: socket-77777777:1.3.0\n\n", "")
                        .as_str()
                )
            );
            assert_eq!(
                workspace_edits(&done),
                [
                    (
                        REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                        "removed",
                        Some(LEFT_PAD_ALIAS)
                    ),
                    (
                        REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                        "removed",
                        Some("left-pad@1.3.0")
                    ),
                ]
            );
            assert!(done.pnpm_warnings.is_empty(), "{:?}", done.pnpm_warnings);
            assert!(!done.pnpm_named_registries);
            // Nothing is left to tidy.
            let again = registry_rewrite(&after(&root, &done), &candidates).await;
            assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
            // The opt-out leaves the file, and so the lock, alone.
            let opted_out = pnpm_rewrite(
                &ProjectView::Memory(&root),
                &candidates,
                false,
                false,
                &no_env,
            )
            .await;
            assert!(opted_out.rewrite.files.is_empty());
        }

        // The workspace file is gone altogether: the lock's record of the
        // override still goes.
        let mut root = pnpm12_project(UNROUTED);
        root.insert_text("package.json", PNPM_12_MANIFEST);
        let done = registry_rewrite(&root, &candidates).await;
        assert_eq!(workspace_of(&done), None);
        assert_eq!(
            lock_of(&done),
            Some(
                UNROUTED
                    .replace(
                        "overrides:\n  left-pad@1.3.0: socket-77777777:1.3.0\n\n",
                        ""
                    )
                    .as_str()
            )
        );

        // An interrupted or older run's leftovers beside live pins: a stale
        // override, a spare registry, the registries of an unreleased
        // build. The user's own entries stay byte for byte.
        let root = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let both = [left_pad_registry_candidate(), is_number_candidate(true)];
        let mut littered = after(&root, &registry_rewrite(&root, &both).await);
        littered.insert_text(
            PNPM_WORKSPACE_REL,
            format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n  corp: https://npm.corp.example/ # ours\n\
                 \x20 socket-99999999: https://patch.test/patch/npm/gone/1.0.0/tok/99999999-9999-4999-8999-999999999999/\n\
                 \x20 socket-patch-66666666-6666-4666-8666-666666666666: https://patch.test/patch/npm/old/1.0.0/tok/66666666-6666-4666-8666-666666666666/\n{}\n{}\n\
                 overrides:\n  lodash: ^4.17.21\n  'gone@1.0.0': 'socket-99999999:1.0.0'\n{IS_NUMBER_OVERRIDE}\n{LEFT_PAD_OVERRIDE}\n",
                left_pad_registry_line(),
                is_number_registry_line()
            ),
        );
        let done = registry_rewrite(&littered, &both).await;
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "packages:\n  - 'apps/*'\nnamedRegistries:\n  corp: https://npm.corp.example/ # ours\n{}\n{}\n\
                     overrides:\n  lodash: ^4.17.21\n{IS_NUMBER_OVERRIDE}\n{LEFT_PAD_OVERRIDE}\n",
                    left_pad_registry_line(),
                    is_number_registry_line()
                )
                .as_str()
            )
        );
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some("socket-99999999")
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some("socket-patch-66666666-6666-4666-8666-666666666666")
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "removed",
                    Some("gone@1.0.0")
                ),
            ]
        );
        // The lock was already as pnpm writes it: nothing to change there.
        assert_eq!(lock_of(&done), None);
        assert!(done.pnpm_named_registries);
    }

    /// CLEANUP, a patch that supersedes the one a release is routed to
    /// (a new patch uuid, so a new tarball and a new registry): the
    /// registry is the new patch's, under the new patch's name, so the
    /// override and the lock's keys are renamed to it and the old
    /// registry goes. Nothing is added beside what was there.
    #[tokio::test]
    async fn a_superseding_patch_renames_the_registry() {
        const NEXT: &str = "66666666-6666-4666-8666-666666666666";
        const NEXT_ALIAS: &str = "socket-66666666";
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let first = registry_rewrite(&root, &[left_pad_registry_candidate()]).await;
        let routed = after(&root, &first);
        let mut next = left_pad_registry_candidate();
        next.dep.patch_uuid = NEXT.into();
        next.dep.artifact_url = left_pad_url().replace(FIXTURE_UUID, NEXT);
        next.dep.npm_registry_url = Some(registry_address(&next.dep.artifact_url));
        let renamed = |text: String| {
            text.replace(FIXTURE_UUID, NEXT)
                .replace(LEFT_PAD_ALIAS, NEXT_ALIAS)
        };
        let done = registry_rewrite(&routed, &[next.clone()]).await;
        assert_eq!(
            lock_of(&done),
            Some(renamed(left_pad_routed_lock()).as_str())
        );
        assert_eq!(
            workspace_of(&done),
            Some(renamed(left_pad_routed_workspace()).as_str())
        );
        assert_eq!(
            workspace_edits(&done),
            [
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "removed",
                    Some(LEFT_PAD_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_REGISTRY_EDIT_KIND,
                    "added",
                    Some(NEXT_ALIAS)
                ),
                (
                    REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND,
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
            ]
        );
        assert_eq!(
            edits_of(&done, "pnpm-lock.yaml"),
            [
                (
                    "redirect_pnpm_resolution",
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_REGISTRY_ALIAS_EDIT_KIND,
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
                (
                    REDIRECT_PNPM_LOCK_OVERRIDE_EDIT_KIND,
                    "rewritten",
                    Some("left-pad@1.3.0")
                ),
            ]
        );
        assert_eq!(done.confirmed.len(), 1);
        // Nothing of the replaced patch is reported as cleaned up one by
        // one but its registry: the release is still routed.
        let removed: Vec<(&'static str, String)> =
            crate::hosted::guidance::pnpm_registry_entries_removed(&done.rewrite.edits)
                .into_iter()
                .map(|entry| (entry.kind.as_str(), entry.key))
                .collect();
        assert_eq!(removed, [("registry", LEFT_PAD_ALIAS.to_string())]);
        let again = registry_rewrite(&after(&routed, &done), &[next]).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
    }

    /// The one registry of a whole project, as an unreleased build
    /// addressed it.
    const EARLIER_SET_ADDRESS: &str =
        "https://patch.test/patch/npm/~/11111111111141118111.22222222222242228222/";

    /// MIGRATION: a shape an unreleased build of this feature wrote for
    /// the left-pad pin ends as the registry of the patch under its short
    /// name and the short override, with nothing of the earlier shape
    /// left, and a second run changes nothing. Once the package has left
    /// the lock, the same shape is removed whole.
    ///
    /// `alias` at `address` is the registry that build declared, `users`
    /// the registry lines of the user's own beside it, and `value` the
    /// override value it wrote (`None` for a build that wrote no override
    /// and left the lock naming only the tarball).
    async fn an_earlier_shape_is_converted_and_removed(
        alias: &str,
        address: &str,
        users: &str,
        value: Option<&str>,
    ) {
        let candidates = [left_pad_registry_candidate()];
        let registries = format!("namedRegistries:\n{users}  {alias}: {address}\n");
        let overrides = value
            .map(|value| format!("overrides:\n  'left-pad@1.3.0': '{value}'\n"))
            .unwrap_or_default();

        // The package is still locked: the shape is converted.
        let lock = match value {
            None => {
                let plain = pnpm12_project(LEFT_PAD_V9_LOCK);
                lock_of(&registry_rewrite(&plain, &[left_pad_candidate()]).await)
                    .expect("the lock that names the tarball")
                    .to_string()
            }
            Some(value) => {
                let short = format!("{LEFT_PAD_ALIAS}:1.3.0");
                left_pad_routed_lock()
                    .replace(
                        &format!("left-pad@1.3.0: {short}"),
                        &format!("left-pad@1.3.0: {value}"),
                    )
                    .replace(
                        &format!("specifier: {short}"),
                        &format!("specifier: {value}"),
                    )
                    .replace(&short, &format!("{alias}:1.3.0"))
            }
        };
        let mut project = pnpm12_project(&lock);
        project.insert_text(
            PNPM_WORKSPACE_REL,
            format!("packages:\n  - '.'\n{registries}{overrides}"),
        );
        let done = registry_rewrite(&project, &candidates).await;
        assert_eq!(
            lock_of(&done),
            Some(left_pad_routed_lock().as_str()),
            "{alias}"
        );
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "packages:\n  - '.'\nnamedRegistries:\n{users}{}\noverrides:\n{LEFT_PAD_OVERRIDE}\n",
                    left_pad_registry_line()
                )
                .as_str()
            ),
            "{alias}"
        );
        assert!(done.pnpm_named_registries, "{alias}");
        assert_eq!(done.confirmed.len(), 1, "{alias}");
        let again = registry_rewrite(&after(&project, &done), &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{alias}");

        // The package left the lock: a run that routes nothing removes
        // the shape, and the user's file is theirs again.
        const PLAIN: &str = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      \
             is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n\npackages:\n  \
             is-number@7.0.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n\n\
             snapshots:\n  is-number@7.0.0: {}\n";
        let recorded = match value {
            Some(value) => PLAIN.replace(
                "importers:\n",
                &format!("overrides:\n  left-pad@1.3.0: {value}\n\nimporters:\n"),
            ),
            None => PLAIN.to_string(),
        };
        let users_file = match users {
            "" => "packages:\n  - 'apps/*'\n".to_string(),
            users => format!("packages:\n  - 'apps/*'\nnamedRegistries:\n{users}"),
        };
        let mut project = pnpm12_project(&recorded);
        project.insert_text(
            PNPM_WORKSPACE_REL,
            format!("packages:\n  - 'apps/*'\n{registries}{overrides}"),
        );
        let done = registry_rewrite(&project, &candidates).await;
        assert_eq!(workspace_of(&done), Some(users_file.as_str()), "{alias}");
        // (A lock with no record of the route is not rewritten.)
        assert_eq!(lock_of(&done).unwrap_or(&recorded), PLAIN, "{alias}");
        assert!(!done.pnpm_named_registries, "{alias}");
        let again = registry_rewrite(&after(&project, &done), &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{alias}");
    }

    /// A registry per patch named by the whole UUID, with no override and
    /// a lock that only names the tarball.
    #[tokio::test]
    async fn an_earlier_registry_per_patch_with_no_override_is_converted() {
        an_earlier_shape_is_converted_and_removed(
            &format!("socket-patch-{FIXTURE_UUID}"),
            &left_pad_registry_url(),
            "",
            None,
        )
        .await;
    }

    /// A registry per patch named by the whole UUID, with the override
    /// value `<alias>:<version>` and the lock keyed by that registry.
    #[tokio::test]
    async fn an_earlier_registry_per_patch_with_a_short_override_is_converted() {
        let alias = format!("socket-patch-{FIXTURE_UUID}");
        an_earlier_shape_is_converted_and_removed(
            &alias,
            &left_pad_registry_url(),
            "",
            Some(&format!("{alias}:1.3.0")),
        )
        .await;
    }

    /// A registry per patch named by the whole UUID, with the override
    /// value `<alias>:<name>@<version>` and the lock keyed by that
    /// registry.
    #[tokio::test]
    async fn an_earlier_registry_per_patch_with_a_long_override_is_converted() {
        let alias = format!("socket-patch-{FIXTURE_UUID}");
        an_earlier_shape_is_converted_and_removed(
            &alias,
            &left_pad_registry_url(),
            "",
            Some(&format!("{alias}:left-pad@1.3.0")),
        )
        .await;
    }

    /// One registry for the whole project, `socket`.
    #[tokio::test]
    async fn an_earlier_project_registry_named_socket_is_converted() {
        an_earlier_shape_is_converted_and_removed(
            "socket",
            EARLIER_SET_ADDRESS,
            "",
            Some("socket:1.3.0"),
        )
        .await;
    }

    /// One registry for the whole project, `socket-patch`: the name that
    /// build took where the user had a registry `socket`, which stays.
    #[tokio::test]
    async fn an_earlier_project_registry_named_socket_patch_is_converted() {
        an_earlier_shape_is_converted_and_removed(
            "socket-patch",
            EARLIER_SET_ADDRESS,
            "  socket: https://npm.corp.example/\n",
            Some("socket-patch:1.3.0"),
        )
        .await;
    }

    /// One registry for the whole project under a numbered name
    /// (`socket-2`), beside the user's `socket` and `socket-patch`, which
    /// stay.
    #[tokio::test]
    async fn an_earlier_numbered_project_registry_is_converted() {
        an_earlier_shape_is_converted_and_removed(
            "socket-2",
            EARLIER_SET_ADDRESS,
            "  socket: https://npm.corp.example/\n  socket-patch: https://npm.work.example/\n",
            Some("socket-2:1.3.0"),
        )
        .await;
    }

    /// Two patches whose UUIDs start with the same eight digits: both
    /// registries take four more, so each name still tells its patch, and
    /// a registry of the user's under a name ours would take makes ours
    /// longer too.
    #[tokio::test]
    async fn a_registry_name_that_is_taken_gets_more_digits() {
        const SHARES: &str = "77777777-1111-4111-8111-111111111111";
        let mut twin = is_number_candidate(true);
        twin.dep.patch_uuid = SHARES.into();
        twin.dep.artifact_url = is_number_url().replace(IS_NUMBER_UUID, SHARES);
        twin.dep.npm_registry_url = Some(registry_address(&twin.dep.artifact_url));
        let root = pnpm12_project(TWO_PACKAGE_V9_LOCK);
        let candidates = [left_pad_registry_candidate(), twin.clone()];
        let done = registry_rewrite(&root, &candidates).await;
        assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\noverrides:\n  \
                     'is-number@7.0.0': 'socket-777777771111:7.0.0'\n  \
                     'left-pad@1.3.0': 'socket-777777777777:1.3.0'\n",
                    registry_line("socket-777777771111", &twin.dep.artifact_url),
                    registry_line("socket-777777777777", &left_pad_url()),
                )
                .as_str()
            )
        );
        let lock = lock_of(&done).expect("the lock");
        for key in [
            "\n  is-number@socket-777777771111:7.0.0:\n",
            "\n  left-pad@socket-777777777777:1.3.0:\n",
        ] {
            assert!(lock.contains(key), "{key}: {lock}");
        }
        let again = registry_rewrite(&after(&root, &done), &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);

        // The user's own registry under the short name.
        let users = "packages:\n  - 'apps/*'\nnamedRegistries:\n  socket-77777777: https://npm.corp.example/\n";
        let mut project = pnpm12_project(LEFT_PAD_V9_LOCK);
        project.insert_text(PNPM_WORKSPACE_REL, users);
        let done = registry_rewrite(&project, &[left_pad_registry_candidate()]).await;
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "{users}{}\noverrides:\n  'left-pad@1.3.0': 'socket-777777777777:1.3.0'\n",
                    registry_line("socket-777777777777", &left_pad_url())
                )
                .as_str()
            )
        );
        assert_eq!(
            lock_of(&done),
            Some(
                left_pad_routed_lock()
                    .replace(LEFT_PAD_ALIAS, "socket-777777777777")
                    .as_str()
            )
        );
    }

    /// ANOTHER VERSION IN RANGE. The override that routes a release is
    /// keyed `name@version`, and pnpm applies it to every dependency whose
    /// range admits that version. A lock records what a transitive
    /// dependent resolved, not the range it asked through, so the scan
    /// cannot tell a dependent locked on a newer release of the package
    /// (through `^1.0.0`) from one that must have it. It routes the patched
    /// release, leaves the other one as locked, and says what pnpm may do
    /// with it: a note in the route's guidance that names the package and
    /// both versions. Only a newer release the patched one's caret range
    /// admits is named (same major; same minor below 1.0).
    #[tokio::test]
    async fn a_newer_release_in_range_of_a_routed_one_is_noted() {
        // `pinned` asks for left-pad 1.3.0 exactly, `ranged` through a
        // range and is locked on `other`. Laid out as pnpm writes a lock.
        let lock = |other: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      \
                 pinned:\n        specifier: 1.0.0\n        version: 1.0.0\n      \
                 ranged:\n        specifier: 1.0.0\n        version: 1.0.0\n\n\
                 packages:\n\n  left-pad@1.3.0:\n    resolution: {{integrity: sha512-UPSTREAM==}}\n\n  \
                 left-pad@{other}:\n    resolution: {{integrity: sha512-OTHER==}}\n\n  \
                 pinned@1.0.0:\n    resolution: {{integrity: sha512-PINNED==}}\n\n  \
                 ranged@1.0.0:\n    resolution: {{integrity: sha512-RANGED==}}\n\n\
                 snapshots:\n\n  left-pad@1.3.0: {{}}\n\n  left-pad@{other}: {{}}\n\n  \
                 pinned@1.0.0:\n    dependencies:\n      left-pad: 1.3.0\n\n  \
                 ranged@1.0.0:\n    dependencies:\n      left-pad: {other}\n"
            )
        };
        let project = |other: &str| {
            let mut project = pnpm12_project(&lock(other));
            project.insert_text(
                "package.json",
                r#"{"name":"app","packageManager":"pnpm@12.22.0","dependencies":{"pinned":"1.0.0","ranged":"1.0.0"}}"#,
            );
            project
        };
        const NOTE: &str = "pnpm-lock.yaml also locks left-pad at 1.9.0, which a range that \
             admits 1.3.0 may admit too: a package that depends on left-pad through such a \
             range moves to the patched left-pad@1.3.0 the next time pnpm resolves (`pnpm \
             add`, `update`, `dedupe`), because the override that routes a release applies to \
             every range that admits it";
        let candidates = [left_pad_registry_candidate()];
        let root = project("1.9.0");
        let done = registry_rewrite(&root, &candidates).await;
        assert!(done.pnpm_named_registries, "{:?}", done.pnpm_warnings);
        assert_eq!(done.confirmed.len(), 1);
        let routed = lock_of(&done).expect("the routed lock");
        assert!(
            routed.contains("\n  left-pad@1.9.0:\n")
                && routed.contains("      left-pad: 1.9.0\n")
                && routed.contains("      left-pad: socket-77777777:1.3.0\n"),
            "the other release stays as locked:\n{routed}"
        );
        assert!(
            pnpm_trust_detail(&done).contains(NOTE),
            "{}",
            pnpm_trust_detail(&done)
        );
        assert_eq!(done.pnpm_route_note.as_deref(), Some(NOTE));
        // The note is the state's, not the run's: a re-run that changes
        // nothing still carries it.
        let again = registry_rewrite(&after(&root, &done), &candidates).await;
        assert!(again.rewrite.files.is_empty());
        assert_eq!(again.pnpm_route_note.as_deref(), Some(NOTE));

        // Not in the patched release's caret range: another major, an
        // older release, a prerelease.
        for other in ["2.0.0", "1.2.9", "1.4.0-beta.1"] {
            let done = registry_rewrite(&project(other), &candidates).await;
            assert!(done.pnpm_named_registries, "{other}");
            assert_eq!(done.pnpm_route_note, None, "{other}");
            assert!(!pnpm_trust_detail(&done).contains("also locks"), "{other}");
        }
    }

    /// THE USER'S OWN REGISTRY. A project may name a registry of its own
    /// `socket`, `socket-patch` or `socket-2`, and lock a release from it
    /// as `left-pad@socket:1.3.0`. That release is the user's package from
    /// the user's registry, whatever npm's left-pad@1.3.0 is: a run granted
    /// a patch for npm's release must not read the entry as that release,
    /// must not repoint it at a patched tarball, and must not confirm a
    /// pin. Not a byte of the lock or of the workspace file changes, with
    /// or without a registry address on the grant.
    #[tokio::test]
    async fn a_release_from_a_registry_of_the_users_is_never_repointed() {
        for name in ["socket", "socket-patch", "socket-2", "socket-patch-3"] {
            let lock = format!(
                "lockfileVersion: '9.0'\n\noverrides:\n  left-pad@1.3.0: {name}:1.3.0\n\n\
                 importers:\n  .:\n    dependencies:\n      left-pad:\n        \
                 specifier: {name}:1.3.0\n        version: {name}:1.3.0\n\n\
                 packages:\n  left-pad@{name}:1.3.0:\n    \
                 resolution: {{integrity: sha512-CORP==, tarball: https://npm.corp.example/left-pad/-/left-pad-1.3.0.tgz}}\n\n\
                 snapshots:\n  left-pad@{name}:1.3.0: {{}}\n"
            );
            let workspace = format!(
                "packages:\n  - '.'\nnamedRegistries:\n  {name}: https://npm.corp.example/\n\
                 overrides:\n  'left-pad@1.3.0': '{name}:1.3.0'\n"
            );
            for candidate in [left_pad_registry_candidate(), left_pad_candidate()] {
                let mut project = pnpm12_project(&lock);
                project.insert_text(PNPM_WORKSPACE_REL, workspace.as_str());
                let done = registry_rewrite(&project, &[candidate]).await;
                assert_eq!(lock_of(&done), None, "{name}: the user's entry is theirs");
                assert_eq!(workspace_of(&done), None, "{name}");
                assert!(done.confirmed.is_empty(), "{name}: {:?}", done.confirmed);
                assert!(!done.pnpm_named_registries, "{name}");
            }
        }
    }

    /// What keeps a project the patch service offers the registry route
    /// to off it is said in the warning, and the run is the trust run it
    /// would have been: an override of the user's for a patched package, a
    /// lock the override edits were not captured against, a workspace file
    /// a splice cannot extend.
    #[tokio::test]
    async fn what_blocks_the_registry_route_is_said() {
        let candidates = [left_pad_registry_candidate()];
        let trust_run = |project: MemoryProject| async move {
            registry_rewrite(&project, &[left_pad_candidate()]).await
        };

        // An override of the user's for the patched package, or a map this
        // reader cannot follow: pnpm applies one override per dependency.
        for (user, why) in [
            (
                "packages:\n  - 'apps/*'\noverrides:\n  left-pad: 1.3.0\n",
                "pnpm-workspace.yaml overrides `left-pad` itself",
            ),
            (
                "packages:\n  - 'apps/*'\noverrides:\n  'left-pad@1.3.0': 1.3.1\n",
                "pnpm-workspace.yaml overrides `left-pad@1.3.0` itself",
            ),
            (
                "packages:\n  - 'apps/*'\noverrides:\n  'app>left-pad@^1': 1.3.1\n",
                "pnpm-workspace.yaml overrides `app>left-pad@^1` itself",
            ),
            (
                "packages:\n  - 'apps/*'\noverrides: {lodash: ^4.17.21}\n",
                "pnpm-workspace.yaml sets `overrides` on one line (a flow-style map or a scalar)",
            ),
            (
                "packages:\n  - 'apps/*'\nnamedRegistries: {corp: https://npm.corp.example/}\n",
                "pnpm-workspace.yaml sets `namedRegistries` on one line (a flow-style map or a scalar)",
            ),
        ] {
            let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
            root.insert_text(PNPM_WORKSPACE_REL, user);
            let baseline = trust_run(root.clone()).await;
            let done = registry_rewrite(&root, &candidates).await;
            assert!(!done.pnpm_named_registries, "{user:?}");
            assert_eq!(done.rewrite.files, baseline.rewrite.files, "{user:?}");
            assert_eq!(done.rewrite.edits, baseline.rewrite.edits, "{user:?}");
            assert_eq!(
                workspace_of(&done),
                Some(format!("{user}trustLockfile: true\n").as_str()),
                "{user:?}"
            );
            assert_eq!(
                pnpm_trust_detail(&done),
                noted(pnpm_trust_detail(&baseline), &blocked(why)),
                "{user:?}"
            );
        }
        // An override of another package is no obstacle, nor are
        // registries of the user's: a `socket` of theirs, with an override
        // that uses it, stays theirs beside ours.
        let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let users = "packages:\n  - 'apps/*'\nnamedRegistries:\n  socket: https://npm.corp.example/\noverrides:\n  lodash: ^4.17.21\n  'theirs@2.0.0': 'socket:2.0.0'\n";
        root.insert_text(PNPM_WORKSPACE_REL, users);
        let done = registry_rewrite(&root, &candidates).await;
        assert!(done.pnpm_named_registries);
        assert_eq!(
            workspace_of(&done),
            Some(
                format!(
                    "packages:\n  - 'apps/*'\nnamedRegistries:\n  socket: https://npm.corp.example/\n{}\n\
                     overrides:\n  lodash: ^4.17.21\n  'theirs@2.0.0': 'socket:2.0.0'\n{LEFT_PAD_OVERRIDE}\n",
                    left_pad_registry_line()
                )
                .as_str()
            )
        );
        assert_eq!(lock_of(&done), Some(left_pad_routed_lock().as_str()));

        // A workspace file no splice can extend: the trust path says so
        // itself, and nothing is written.
        for (user, why) in [
            (
                "{packages: ['.']}\n",
                "pnpm-workspace.yaml is a flow-style YAML document",
            ),
            (
                "packages:\n  - '.'\n---\nother: 1\n",
                "pnpm-workspace.yaml holds more than one YAML document",
            ),
        ] {
            let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
            root.insert_text(PNPM_WORKSPACE_REL, user);
            let baseline = trust_run(root.clone()).await;
            let done = registry_rewrite(&root, &candidates).await;
            assert_eq!(workspace_of(&done), None, "{user:?}");
            assert_eq!(done.rewrite.files, baseline.rewrite.files, "{user:?}");
            let detail = pnpm_trust_detail(&done);
            assert!(detail.contains(&blocked(why)), "{why}: {detail}");
            assert!(detail.contains("it was left untouched"), "{detail}");
        }

        // A lock the override edits were not captured against. Here: the
        // importer asks for the release through a dist-tag, which pnpm
        // would not override; and a copy patched with `pnpm patch`.
        for (lock, why) in [
            (
                LEFT_PAD_V9_LOCK.replace("specifier: 1.3.0", "specifier: latest"),
                "pnpm-lock.yaml locks left-pad@1.3.0 for importer `.` through the specifier \
                 `latest`, which pnpm would not override",
            ),
            (
                LEFT_PAD_V9_LOCK.replace(
                    "  left-pad@1.3.0: {}",
                    "  left-pad@1.3.0(patch_hash=abc): {}",
                ),
                "pnpm-lock.yaml holds a patched copy of left-pad@1.3.0 \
                 (`left-pad@1.3.0(patch_hash=abc)`)",
            ),
        ] {
            let root = pnpm12_project(&lock);
            let baseline = trust_run(root.clone()).await;
            let done = registry_rewrite(&root, &candidates).await;
            assert!(!done.pnpm_named_registries, "{why}");
            assert_eq!(done.rewrite.files, baseline.rewrite.files, "{why}");
            assert_eq!(done.rewrite.edits, baseline.rewrite.edits, "{why}");
            assert_eq!(
                pnpm_trust_detail(&done),
                noted(pnpm_trust_detail(&baseline), &blocked(why)),
                "{why}"
            );
        }
    }

    /// Patched packages are routed through the registry only for a project
    /// whose pnpm pins prove pnpm 11.20 or newer: older releases write
    /// another lock for the same override. A project pinned to an older
    /// pnpm (or to a range that reaches one, or by pins that disagree) gets
    /// today's `trustLockfile` write, byte for byte, and is told its pins
    /// are why. So does a project with no pin, whose warning adds what a
    /// pin would change.
    #[tokio::test]
    async fn the_registry_route_needs_a_project_pinned_to_pnpm_11_20() {
        #[derive(Clone, Copy, PartialEq, Debug)]
        enum Want {
            Routed,
            Trust,
            TrustWithHint,
        }
        let candidates = [left_pad_registry_candidate()];
        const TRUST: &str = "packages:\n  - '.'\ntrustLockfile: true\n";
        const HINT: &str = "Pinning pnpm 11.20 or later (for example with package.json \
                            `packageManager`) and re-running the scan switches the project \
                            to per-package registry verification instead of `trustLockfile`";
        let mut unpinned = MemoryProject::new();
        unpinned.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        // A patch service that gives no address: today's run, and nothing
        // said of a route or a pin (neither would change anything).
        let baseline = registry_rewrite(&unpinned, &[left_pad_candidate()]).await;
        assert_eq!(workspace_of(&baseline), Some(TRUST));
        let baseline_detail = pnpm_trust_detail(&baseline);
        assert!(
            !baseline_detail.contains("Pinning pnpm")
                && !baseline_detail.contains("registry verification"),
            "{baseline_detail}"
        );
        let hinted_detail = noted(baseline_detail, HINT);
        let not_proven_detail = noted(baseline_detail, &blocked(NOT_PROVEN));
        for (manifest, modules_yaml, want) in [
            // No pin at all.
            (None, None, Want::TrustWithHint),
            (Some(r#"{"name":"app"}"#), None, Want::TrustWithHint),
            (
                Some(r#"{"packageManager":"npm@11.0.0"}"#),
                None,
                Want::TrustWithHint,
            ),
            // A pin below 11.20, or a range that reaches below it.
            (
                Some(r#"{"packageManager":"pnpm@11.19.0"}"#),
                None,
                Want::Trust,
            ),
            (
                Some(r#"{"packageManager":"pnpm@11.10.0"}"#),
                None,
                Want::Trust,
            ),
            (
                Some(r#"{"packageManager":"pnpm@10.34.6"}"#),
                None,
                Want::Trust,
            ),
            (Some(r#"{"engines":{"pnpm":">=11"}}"#), None, Want::Trust),
            (Some(r#"{"engines":{"pnpm":"^11"}}"#), None, Want::Trust),
            (None, Some("packageManager: pnpm@11.15.0\n"), Want::Trust),
            (
                Some(r#"{"devEngines":{"packageManager":{"name":"pnpm"}}}"#),
                None,
                Want::Trust,
            ),
            // Mixed pins: one below the floor, one above.
            (
                Some(r#"{"packageManager":"pnpm@12.4.2","engines":{"pnpm":"11"}}"#),
                None,
                Want::Trust,
            ),
            (
                Some(r#"{"packageManager":"pnpm@12.4.2"}"#),
                Some("packageManager: pnpm@11.15.0\n"),
                Want::Trust,
            ),
            // Every pin proves 11.20 or newer.
            (
                Some(r#"{"packageManager":"pnpm@11.20.0"}"#),
                None,
                Want::Routed,
            ),
            (
                Some(r#"{"packageManager":"pnpm@11.28.13"}"#),
                None,
                Want::Routed,
            ),
            (
                Some(r#"{"packageManager":"pnpm@12.0.0"}"#),
                None,
                Want::Routed,
            ),
            (
                Some(r#"{"engines":{"pnpm":"^11.20.0"}}"#),
                None,
                Want::Routed,
            ),
            (
                Some(r#"{"engines":{"pnpm":">=11.20"}}"#),
                None,
                Want::Routed,
            ),
            (Some(r#"{"engines":{"pnpm":">=12"}}"#), None, Want::Routed),
            (
                Some(r#"{"packageManager":"pnpm@13.1.0+sha512.abc"}"#),
                None,
                Want::Routed,
            ),
            (None, Some("packageManager: pnpm@12.22.0\n"), Want::Routed),
            (
                Some(r#"{"packageManager":"pnpm@11.28.13"}"#),
                Some("packageManager: pnpm@12.22.0\n"),
                Want::Routed,
            ),
        ] {
            let mut root = unpinned.clone();
            if let Some(manifest) = manifest {
                root.insert_text("package.json", manifest);
            }
            if let Some(modules_yaml) = modules_yaml {
                root.insert_text("node_modules/.modules.yaml", modules_yaml);
            }
            let done = registry_rewrite(&root, &candidates).await;
            let case = format!("{manifest:?} {modules_yaml:?}");
            assert_eq!(done.pnpm_named_registries, want == Want::Routed, "{case}");
            if want == Want::Routed {
                assert_eq!(
                    workspace_of(&done),
                    Some(left_pad_routed_workspace().as_str()),
                    "{case}"
                );
                assert_eq!(
                    lock_of(&done),
                    Some(left_pad_routed_lock().as_str()),
                    "{case}"
                );
                assert!(!pnpm_trust_detail(&done).contains("Pinning pnpm"), "{case}");
                continue;
            }
            // Exactly what a grant with no registry address gets.
            assert_eq!(done.rewrite.files, baseline.rewrite.files, "{case}");
            assert_eq!(done.rewrite.edits, baseline.rewrite.edits, "{case}");
            let detail = pnpm_trust_detail(&done);
            if want == Want::TrustWithHint {
                assert_eq!(detail, hinted_detail, "{case}");
            } else {
                assert_eq!(detail, not_proven_detail, "{case}");
            }
        }

        // The hint rides whatever the trust path says of an unpinned
        // project: here, a file that already trusts the lock.
        let mut trusted = unpinned.clone();
        trusted.insert_text(
            PNPM_WORKSPACE_REL,
            "packages:\n  - 'apps/*'\ntrustLockfile: true\n",
        );
        let done = registry_rewrite(&trusted, &candidates).await;
        assert_eq!(workspace_of(&done), None);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("already carries `trustLockfile: true`") && detail.contains(HINT),
            "{detail}"
        );
        // Nor does the opted-out run say it: it writes nothing either way.
        let opted_out = |candidate: Candidate| {
            let unpinned = unpinned.clone();
            async move {
                let done = pnpm_rewrite(
                    &ProjectView::Memory(&unpinned),
                    &[candidate],
                    false,
                    false,
                    &no_env,
                )
                .await;
                pnpm_trust_detail(&done).to_string()
            }
        };
        let detail = opted_out(left_pad_registry_candidate()).await;
        assert!(detail.contains("pnpm install --trust-lockfile"), "{detail}");
        assert_eq!(detail, opted_out(left_pad_candidate()).await);
        // One pin without an address: a pnpm pin would change nothing, so
        // nothing is said of one; and a pin below the floor is said beside
        // the missing address.
        let mut two = MemoryProject::new();
        two.insert_text("pnpm-lock.yaml", TWO_PACKAGE_V9_LOCK);
        let mixed = [left_pad_registry_candidate(), is_number_candidate(false)];
        let done = registry_rewrite(&two, &mixed).await;
        assert!(!pnpm_trust_detail(&done).contains("Pinning pnpm"));
        two.insert_text("package.json", r#"{"packageManager":"pnpm@11.10.0"}"#);
        let done = registry_rewrite(&two, &mixed).await;
        assert!(
            pnpm_trust_detail(&done).contains(&blocked(&format!(
                "the patch service gave no registry address for is-number@7.0.0, and {NOT_PROVEN}"
            ))),
            "{}",
            pnpm_trust_detail(&done)
        );

        // A project pinned to pnpm 9.0–10.4 keeps its own rule (#734): no
        // file, and the trust path's reason beside ours.
        let mut pnpm9 = unpinned.clone();
        pnpm9.insert_text("package.json", r#"{"packageManager":"pnpm@9.15.9"}"#);
        let done = registry_rewrite(&pnpm9, &candidates).await;
        assert_eq!(workspace_of(&done), None);
        assert!(!done.pnpm_named_registries);
        assert!(pnpm_trust_detail(&done).contains("does not read `trustLockfile`"));
    }

    /// A project an earlier run routed and whose pnpm pin then moved below
    /// the floor is put back on the trust path whole: the lock is the one
    /// a trust run writes, and so is the workspace file. When the lock
    /// cannot be converted, lock and file stay routed, and the warning
    /// says so.
    #[tokio::test]
    async fn a_routed_project_that_no_longer_qualifies_is_put_back() {
        let candidates = [left_pad_registry_candidate()];
        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let routed = after(&root, &registry_rewrite(&root, &candidates).await);
        let trust = registry_rewrite(&root, &[left_pad_candidate()]).await;
        let trust_lock = lock_of(&trust).expect("the trust lock");
        const TRUST: &str = "packages:\n  - '.'\ntrustLockfile: true\n";
        assert_eq!(workspace_of(&trust), Some(TRUST));
        const PUT_BACK: &str = "An earlier run routed the hosted patches through a named registry";

        let mut older = routed.clone();
        older.insert_text(
            "package.json",
            r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"packageManager":"pnpm@11.10.0"}"#,
        );
        let done = registry_rewrite(&older, &candidates).await;
        assert!(!done.pnpm_named_registries);
        assert_eq!(lock_of(&done), Some(trust_lock));
        assert_eq!(workspace_of(&done), Some(TRUST));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains(PUT_BACK)
                && detail.contains("were removed")
                && detail.contains(&blocked(NOT_PROVEN)),
            "{detail}"
        );
        assert!(
            detail.contains("`trustLockfile: true` was merged into"),
            "{detail}"
        );
        // The put-back project is a trust project: a re-run changes nothing.
        let again = registry_rewrite(&after(&older, &done), &candidates).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
        assert!(!pnpm_trust_detail(&again).contains(PUT_BACK));

        // The importer's package.json no longer says what it asked for: the
        // lock cannot be converted, so lock and file stay routed, and the
        // warning says so.
        let mut silent = routed.clone();
        silent.insert_text(
            "package.json",
            r#"{"name":"app","packageManager":"pnpm@11.10.0"}"#,
        );
        let done = registry_rewrite(&silent, &candidates).await;
        assert_eq!(lock_of(&done), None);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("the lockfile could not be converted back")
                && detail.contains("whose package.json does not say which version it asks for"),
            "{detail}"
        );
        assert_eq!(
            workspace_of(&done),
            Some(format!("{}trustLockfile: true\n", left_pad_routed_workspace()).as_str())
        );
    }

    /// The rules that keep the trust auto-config from writing a workspace
    /// file keep the registry route out too: Rush and legacy locks keep
    /// their own guidance, and a keyless file with workspace members
    /// (#1096) gets no file.
    #[tokio::test]
    async fn the_registry_route_respects_what_the_trust_write_respects() {
        let candidates = [left_pad_registry_candidate()];

        let mut rush = MemoryProject::new();
        rush.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rush.insert_text("package.json", PNPM_12_MANIFEST);
        rush.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        let done = registry_rewrite(&rush, &candidates).await;
        let lock = &done.rewrite.files[RUSH_COMMON_LOCK_REL];
        assert!(!lock.contains("socket:"), "{lock}");
        assert_eq!(workspace_of(&done), None);
        assert!(!done.pnpm_named_registries);
        assert!(pnpm_trust_detail(&done).contains("pnpm_config_trust_lockfile=true rush install"));

        let legacy = pnpm12_project(
            "lockfileVersion: 5.4\n\nspecifiers:\n  left-pad: 1.3.0\n\ndependencies:\n  left-pad: 1.3.0\n\n\
             packages:\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n    dev: false\n",
        );
        let done = registry_rewrite(&legacy, &candidates).await;
        assert!(done.rewrite.files.contains_key("pnpm-lock.yaml"));
        assert_eq!(workspace_of(&done), None);
        assert!(!done.pnpm_named_registries);
        assert!(pnpm_trust_detail(&done).contains("no trust step exists or is needed"));

        let mut keyless = pnpm12_project(&LEFT_PAD_V9_LOCK.replace(
            "\npackages:\n",
            "\n  packages/a:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n",
        ));
        keyless.insert_text(PNPM_WORKSPACE_REL, "# no keys yet\n");
        let done = registry_rewrite(&keyless, &candidates).await;
        assert_eq!(workspace_of(&done), None);
        assert!(!done.pnpm_named_registries);
        let lock = lock_of(&done).expect("the lock");
        assert!(!lock.contains("socket:"), "{lock}");
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("has no keys and pnpm-lock.yaml lists workspace members")
                && detail.contains(&blocked(
                    "pnpm-workspace.yaml has no keys while pnpm-lock.yaml lists workspace members"
                )),
            "{detail}"
        );

        // A keyless file with no members gets the scaffold with the maps.
        let mut comments = pnpm12_project(LEFT_PAD_V9_LOCK);
        comments.insert_text(PNPM_WORKSPACE_REL, "# no keys yet\n");
        let done = registry_rewrite(&comments, &candidates).await;
        assert_eq!(
            workspace_of(&done),
            Some(format!("# no keys yet\n{}", left_pad_routed_workspace()).as_str())
        );
        assert!(pnpm_trust_detail(&done).contains("with the root-only `packages: ['.']`"));

        // In memory, a symlinked workspace file is refused, not written
        // through.
        let mut linked = pnpm12_project(LEFT_PAD_V9_LOCK);
        linked.insert(PNPM_WORKSPACE_REL, MemoryEntry::Symlink);
        let done = registry_rewrite(&linked, &candidates).await;
        let refusal = guard(&ProjectView::Memory(&linked), &done, &candidates)
            .expect("a symlinked workspace file is refused");
        assert_eq!(refusal.code, SYMLINK_REFUSAL);
    }

    /// An override routes a package version to one registry, and a registry
    /// serves one patch: one release pinned to two patches (two locks
    /// pinned to different patches of it) keeps the project off the route,
    /// the release named. The same pin in several locks is one patch.
    #[test]
    fn a_release_pinned_to_two_patches_is_named() {
        use crate::hosted::guidance::RoutedPin;
        let pin = |name: &str, uuid: &str| {
            let address = format!("https://patch.test/patch/npm/{name}/1.0.0/tok/{uuid}/");
            RoutedPin {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                integrity: "sha512-X==".to_string(),
                tarball: format!("{address}{name}-1.0.0.tgz"),
                uuid: uuid.to_string(),
                address,
            }
        };
        let shared = [
            ("pnpm-lock.yaml", vec![pin("leaf", FIXTURE_UUID)]),
            (
                "packages/a/pnpm-lock.yaml",
                vec![pin("leaf", FIXTURE_UUID), pin("mid", IS_NUMBER_UUID)],
            ),
        ];
        assert_eq!(release_with_two_patches(&shared), None);
        let split = [
            ("pnpm-lock.yaml", vec![pin("leaf", FIXTURE_UUID)]),
            (
                "packages/a/pnpm-lock.yaml",
                vec![pin("mid", IS_NUMBER_UUID), pin("leaf", IS_NUMBER_UUID)],
            ),
        ];
        assert_eq!(
            release_with_two_patches(&split),
            Some("leaf@1.0.0".to_string())
        );
        assert_eq!(release_with_two_patches(&[]), None);
    }

    /// The grant → candidate step carries the registry address only when
    /// it is the directory the patch's tarball is served from, named by
    /// the patch's UUID; anything else reads as no address, and the pin
    /// takes the trust path.
    #[test]
    fn a_registry_address_is_carried_only_when_it_routes_the_artifact() {
        let url = left_pad_url();
        let selected = vec![(
            "pkg:npm/left-pad@1.3.0".to_string(),
            FIXTURE_UUID.to_string(),
        )];
        let carried = |npm_registry_url: serde_json::Value| {
            let mut refs: HashMap<String, PackageVendorResult> = HashMap::new();
            let mut grant = serde_json::json!({
                "status": "granted",
                "url": url,
                "purl": "pkg:npm/left-pad@1.3.0",
                "artifacts": [{"kind": "tarball", "url": url,
                               "integrity": {"sha512": "sha512-PATCHED=="}}],
                "registryOverride": null
            });
            if !npm_registry_url.is_null() {
                grant["npmRegistryUrl"] = npm_registry_url;
            }
            refs.insert(FIXTURE_UUID.into(), reference(grant));
            candidates_of(&selected, &refs)[0]
                .dep
                .npm_registry_url
                .clone()
        };
        let address = left_pad_registry_url();
        assert_eq!(
            address,
            format!("https://patch.test/patch/npm/left-pad/1.3.0/{FIXTURE_TOKEN}/{FIXTURE_UUID}/")
        );
        assert_eq!(carried(serde_json::json!(address)), Some(address.clone()));
        // A patch service that gives no address omits the field.
        assert_eq!(carried(serde_json::Value::Null), None);
        let without_slash = address.trim_end_matches('/').to_string();
        let above = format!("https://patch.test/patch/npm/left-pad/1.3.0/{FIXTURE_TOKEN}/");
        let other_patch = address.replace(FIXTURE_UUID, IS_NUMBER_UUID);
        for unusable in [
            "",
            "https://",
            "https://patch.test",
            "https://patch.test/",
            // The address an unreleased patch service gave a whole project.
            "https://patch.test/patch/npm/~/77777777777747778777/",
            // Not the directory of the tarball: no final `/`, a directory
            // above it, another patch's, another origin or scheme.
            without_slash.as_str(),
            above.as_str(),
            other_patch.as_str(),
            &address.replace("patch.test", "other.test"),
            &address.replace("https://", "http://"),
            &format!("{address} "),
            &address.replace("https://", "ftp://"),
        ] {
            assert_eq!(carried(serde_json::json!(unusable)), None, "{unusable:?}");
        }
        // The artifact URL itself is not a registry.
        assert_eq!(carried(serde_json::json!(url)), None);
        // Another ecosystem's grant carries none.
        let mut pypi = left_pad_registry_candidate().dep;
        pypi.ecosystem = "pypi".into();
        assert_eq!(crate::patch::redirect::grant::npm_registry_url(&pypi), None);
    }

    /// REGRESSION (#367), binary lock: a `bun.lockb`-only project's root
    /// manifest is read for its `patchedDependencies`, and a package the
    /// project patches itself with `bun patch` keeps its registry record,
    /// loudly, and is never assumed patched by the in-run VEX.
    #[tokio::test]
    async fn issue_367_bun_lockb_keeps_a_user_patched_package_on_the_registry() {
        use crate::patch::redirect::Integrity;
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bun-lockb-bundled/both");
        let candidates = vec![Candidate {
            purl: "pkg:npm/is-number@7.0.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "is-number".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "https://patch.test/patch/npm/is-number/7.0.0/{FIXTURE_TOKEN}/{FIXTURE_UUID}/is-number-7.0.0.tgz"
                ),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity {
                    sha512: Some(format!("sha512-{}==", "A".repeat(86))),
                    ..Default::default()
                },
            },
        }];
        let manifest = r#"{"name":"p","version":"1.0.0","dependencies":{"@bh/bund":"1.0.0","is-number":"7.0.0"}}"#;
        let patched_manifest = manifest.replacen(
            "}}",
            r#"},"patchedDependencies":{"is-number@7.0.0":"patches/is-number@7.0.0.patch"}}"#,
            1,
        );
        for user_patched in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::copy(fixture.join("bun.lockb"), tmp.path().join("bun.lockb")).unwrap();
            std::fs::write(
                tmp.path().join("package.json"),
                if user_patched {
                    &patched_manifest
                } else {
                    manifest
                },
            )
            .unwrap();
            let view = ProjectView::Disk(tmp.path());
            let outer = OuterAllowRemote::default;
            let options = RewriteOptions {
                dry_run: false,
                targets_pipenv_lock: false,
                pipenv_major: None,
                pipenv_unknown_detail: String::new(),
                trust_lockfile_config: true,
                npm_allow_remote_config: true,
                npm_outer: &outer,
                yarn_classic_outer: &OuterYarnMirror::default,
                cargo_outer: &no_cargo_outer,
                maven_selection: &no_maven_selection,
                pnpm_env: &no_env,
                blocking: false,
                takeover_uuids: Default::default(),
                patch_server_origins: Vec::new(),
                prior_discovery: None,
            };
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            assert!(read.files.contains_key("package.json"));
            let done = rewrite(&view, read, &candidates, BTreeMap::new(), options).await;
            let skipped = done
                .rewrite
                .warnings
                .iter()
                .find(|w| w.code == "redirect_bun_patched_dependency_skipped");
            if user_patched {
                assert!(
                    !done.rewrite.binary_files.contains_key("bun.lockb"),
                    "the user-patched record is left alone"
                );
                let skipped = skipped.expect("the skip is reported");
                assert!(
                    skipped.detail.contains("is-number@7.0.0"),
                    "{}",
                    skipped.detail
                );
                assert!(done.rewrite.bundled_skipped_uuids.contains(FIXTURE_UUID));
            } else {
                assert!(
                    done.rewrite.binary_files.contains_key("bun.lockb"),
                    "{:?}",
                    done.rewrite.warnings
                );
                assert!(skipped.is_none(), "{:?}", done.rewrite.warnings);
            }
            assert!(!done.rewrite.files.contains_key("package.json"));
        }
    }

    /// REGRESSION (#371), binary lock: a default-trusted package pinned to
    /// its hosted URL in a `bun.lockb` loses Bun 1.3.5+'s default trust, so
    /// its install scripts are silently skipped. Unless the root manifest
    /// declares `trustedDependencies`, its registry record is left alone
    /// and the run says how to patch it; a record an earlier run already
    /// pinned keeps its pin and the warning. The fixture is real Bun 1.4.2
    /// output: `simple-git-hooks` is on the default list, `is-number` is
    /// not.
    #[tokio::test]
    async fn issue_371_bun_lockb_default_trusted_package_keeps_its_registry_record() {
        use crate::patch::redirect::Integrity;
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bun-lockb-trusted");
        let candidate = |name: &str, version: &str, uuid: &str| Candidate {
            purl: format!("pkg:npm/{name}@{version}"),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: name.into(),
                namespace: None,
                version: version.into(),
                token: "tok".into(),
                patch_uuid: uuid.into(),
                artifact_url: format!("https://patch.test/{name}-{version}.tgz"),
                npm_registry_url: None,
                registry_override: None,
                integrity: Integrity {
                    sha512: Some(format!("sha512-{}==", "A".repeat(86))),
                    ..Default::default()
                },
            },
        };
        let candidates = vec![
            candidate("simple-git-hooks", "2.11.1", "uuid-hooks"),
            candidate("is-number", "7.0.0", "uuid-isn"),
        ];
        let manifest = std::fs::read_to_string(fixture.join("package.json")).unwrap();
        let declared = manifest.replacen(
            "\"private\": true,",
            "\"private\": true,\n  \"trustedDependencies\": [\"simple-git-hooks\"],",
            1,
        );
        assert_ne!(declared, manifest);
        // The lock a run under a declared trust list writes: what an
        // earlier release left behind in a project that declares none.
        let mut pinned_lock: Option<Vec<u8>> = None;
        for (trusted, already_pinned) in [(true, false), (false, false), (false, true)] {
            let tmp = tempfile::tempdir().unwrap();
            match (&pinned_lock, already_pinned) {
                (Some(bytes), true) => std::fs::write(tmp.path().join("bun.lockb"), bytes).unwrap(),
                _ => {
                    std::fs::copy(fixture.join("bun.lockb"), tmp.path().join("bun.lockb")).unwrap();
                }
            }
            std::fs::write(
                tmp.path().join("package.json"),
                if trusted { &declared } else { &manifest },
            )
            .unwrap();
            let view = ProjectView::Disk(tmp.path());
            let outer = OuterAllowRemote::default;
            let options = RewriteOptions {
                dry_run: false,
                targets_pipenv_lock: false,
                pipenv_major: None,
                pipenv_unknown_detail: String::new(),
                trust_lockfile_config: true,
                npm_allow_remote_config: true,
                npm_outer: &outer,
                yarn_classic_outer: &OuterYarnMirror::default,
                cargo_outer: &no_cargo_outer,
                maven_selection: &no_maven_selection,
                pnpm_env: &no_env,
                blocking: false,
                takeover_uuids: Default::default(),
                patch_server_origins: Vec::new(),
                prior_discovery: None,
            };
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            let done = rewrite(&view, read, &candidates, BTreeMap::new(), options).await;
            let trust_codes: Vec<&str> = done
                .rewrite
                .warnings
                .iter()
                .filter(|w| w.code.starts_with("redirect_bun_default_trust"))
                .map(|w| w.code.as_str())
                .collect();
            let confirmed: Vec<&str> = done.confirmed.iter().map(|c| c.0.as_str()).collect();
            let case = format!("trusted={trusted} already_pinned={already_pinned}");
            match (trusted, already_pinned) {
                // Declared trust: both pinned, nothing to say.
                (true, _) => {
                    assert!(
                        trust_codes.is_empty(),
                        "{case}: {:?}",
                        done.rewrite.warnings
                    );
                    assert_eq!(confirmed.len(), 2, "{case}: {confirmed:?}");
                    pinned_lock = Some(done.rewrite.binary_files["bun.lockb"].clone());
                }
                // No declared trust: the default-trusted package stays on
                // the registry; the other one is still pinned.
                (false, false) => {
                    assert_eq!(
                        trust_codes,
                        ["redirect_bun_default_trust_skipped"],
                        "{case}: {:?}",
                        done.rewrite.warnings
                    );
                    assert_eq!(confirmed, ["pkg:npm/is-number@7.0.0"], "{case}");
                    assert!(done.rewrite.refused_bun_uuids.contains("uuid-hooks"));
                    let lock = &done.rewrite.binary_files["bun.lockb"];
                    let records = crate::vendor::bun_lockb::BunLockb::parse_packages(lock).unwrap();
                    let hooks = records
                        .iter()
                        .find(|p| p.name == "simple-git-hooks")
                        .unwrap();
                    assert_eq!(hooks.version.as_deref(), Some("2.11.1"), "{hooks:?}");
                    let detail = &done
                        .rewrite
                        .warnings
                        .iter()
                        .find(|w| w.code == "redirect_bun_default_trust_skipped")
                        .unwrap()
                        .detail;
                    assert!(
                        detail.contains("simple-git-hooks@2.11.1")
                            && detail.contains("stays UNPATCHED"),
                        "{detail}"
                    );
                }
                // A pin an earlier run wrote stays, and keeps the warning.
                (false, true) => {
                    assert_eq!(
                        trust_codes,
                        ["redirect_bun_default_trust_lost"],
                        "{case}: {:?}",
                        done.rewrite.warnings
                    );
                    assert_eq!(confirmed.len(), 2, "{case}: {confirmed:?}");
                }
            }
        }
    }

    /// REGRESSION (#367), text lock: the root manifest is read beside a
    /// `bun.lock` even when the lock has no `workspaces` section to reach it
    /// through, and a package the project patches itself is never
    /// confirmed, not even when a sibling `package-lock.json` takes the
    /// hosted URL: Bun keeps installing the registry bytes.
    #[tokio::test]
    async fn issue_367_bun_lock_user_patched_package_is_never_confirmed() {
        let bun_lock = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"left-pad\": \
                        [\"left-pad@1.3.0\", \"\", {}, \"sha512-UPSTREAM==\"],\n  }\n}\n";
        let npm_lock = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "left-pad": "1.3.0" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;
        let manifest = r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"patchedDependencies":{"left-pad@1.3.0":"patches/left-pad@1.3.0.patch"}}"#;
        // Without the sibling npm lock nothing else reads the manifest.
        for with_npm_lock in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("bun.lock"), bun_lock).unwrap();
            if with_npm_lock {
                std::fs::write(tmp.path().join("package-lock.json"), npm_lock).unwrap();
            }
            std::fs::write(tmp.path().join("package.json"), manifest).unwrap();
            let (read, done) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
            assert!(read.files.contains_key("package.json"));
            assert!(
                !done.rewrite.files.contains_key("bun.lock"),
                "the user-patched entry keeps its registry tuple"
            );
            assert!(
                done.rewrite
                    .warnings
                    .iter()
                    .any(|w| w.code == "redirect_bun_patched_dependency_skipped"),
                "{:?}",
                done.rewrite.warnings
            );
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        }
    }

    /// In a Bazel workspace on disk the read of a run with a cargo
    /// candidate hands the rewriter what stands against a pin: the hub
    /// that reads the project's manifests, a member's among them, and not
    /// the config the rewriter writes, which is the legacy file where the
    /// project has one. Nothing is handed over in no Bazel workspace, for a
    /// hub that names that config, or to a run without a cargo candidate.
    #[tokio::test]
    async fn a_bazel_hub_without_the_cargo_config_rides_to_the_cargo_rewriter() {
        use crate::bazel::cargo::KEY;
        let tmp = tempfile::tempdir().unwrap();
        let write = |rel: &str, text: &str| {
            let path = tmp.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let hub = |attributes: &str| {
            format!(
                "bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\ncrate = use_extension(\
                 \"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
                 crate.from_cargo({attributes})\n"
            )
        };
        write("Cargo.toml", "[workspace]\nmembers = [\"member\"]\n");
        write(
            "member/Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        );
        let cargo = Candidate {
            purl: "pkg:cargo/serde@1.0.190".into(),
            dep: grant_dep("cargo", "https://patch.test/serde-1.0.190.crate".into()),
        };
        let view = ProjectView::Disk(tmp.path());
        let handed = |candidate: &Candidate| {
            let candidates = [candidate.clone()];
            async move {
                let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
                read.files.get(KEY).cloned()
            }
        };
        assert_eq!(handed(&cargo).await, None, "no Bazel workspace");

        write(
            "MODULE.bazel",
            &hub("manifests = [\"//member:Cargo.toml\"]"),
        );
        let why = handed(&cargo).await.expect("the hub reads a member");
        assert!(
            why.starts_with("the rules_rust hub at MODULE.bazel:3 reads"),
            "{why}"
        );
        assert!(why.contains("without .cargo/config.toml, where"), "{why}");

        let root = "manifests = [\"//:Cargo.toml\"]";
        write("MODULE.bazel", &hub(root));
        assert!(handed(&cargo).await.is_some(), "the hub reads the root");
        let lock = "cargo_lockfile = \"//:Cargo.lock\", manifests = [\"//x:Cargo.toml\"]";
        write("MODULE.bazel", &hub(lock));
        assert!(handed(&cargo).await.is_some(), "the hub reads the lock");
        write("MODULE.bazel", &hub(root));
        assert_eq!(
            handed(&left_pad_candidate()).await,
            None,
            "no cargo candidate"
        );
        let named = format!("{root}, cargo_config = \"//:.cargo/config.toml\"");
        write("MODULE.bazel", &hub(&named));
        assert_eq!(handed(&cargo).await, None, "the hub names the config");
        write(".cargo/config", "");
        let why = handed(&cargo)
            .await
            .expect("the rewriter writes the legacy file");
        assert!(
            why.contains("is not the label of .cargo/config as one string"),
            "{why}"
        );
    }

    fn gem_candidate() -> Candidate {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        Candidate {
            purl: "pkg:gem/rails@7.0.0".into(),
            dep: DepOverride {
                ecosystem: "gem".into(),
                name: "rails".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "https://patch.test/patch-registry/gem/{FIXTURE_TOKEN}/{FIXTURE_UUID}/gems/rails-7.0.0.gem"
                ),
                npm_registry_url: None,
                registry_override: Some(RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: format!(
                        "https://patch.test/patch-registry/gem/{FIXTURE_TOKEN}/{FIXTURE_UUID}/"
                    ),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "rails".into(),
                        version: "7.0.0".into(),
                        gem_checksum_sha256: Some("f".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Integrity::default(),
            },
        }
    }

    const GRADLE_UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";

    fn gradle_candidate() -> Candidate {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        let token = "22222222-3333-4444-8555-666666666666";
        Candidate {
            purl: "pkg:maven/com.socketfixture/victim@1.10.0".into(),
            dep: DepOverride {
                ecosystem: "maven".into(),
                name: "victim".into(),
                namespace: Some("com.socketfixture".into()),
                version: "1.10.0".into(),
                token: token.into(),
                patch_uuid: GRADLE_UUID.into(),
                artifact_url: format!(
                    "https://patch.socket.dev/patch/maven/com.socketfixture/victim/1.10.0/{token}/{GRADLE_UUID}/victim-1.10.0-socket.4d5e6f70.jar"
                ),
                npm_registry_url: None,
                registry_override: Some(RegistryOverride {
                    kind: "maven2".into(),
                    index_url: format!(
                        "https://patch.socket.dev/patch-registry/maven/{token}/{GRADLE_UUID}/maven2"
                    ),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "com.socketfixture/victim".into(),
                        version: "1.10.0".into(),
                        maven_group_id: Some("com.socketfixture".into()),
                        maven_artifact_id: Some("victim".into()),
                        maven_suffixed_version: Some("1.10.0-socket.4d5e6f70".into()),
                        maven_pom_sha256: Some("b".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Integrity {
                    sha256: Some("a".repeat(64)),
                    ..Default::default()
                },
            },
        }
    }

    async fn gradle_rewrite(p: &MemoryProject) -> (CandidateFiles, Rewritten) {
        gradle_rewrite_in(&ProjectView::Memory(p)).await
    }

    /// Over `view`, with no machine behind it: an empty environment, so
    /// no home, no `PATH` and no settings file of whoever runs the tests
    /// decides what a Maven project is wired to.
    async fn gradle_rewrite_in(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        gradle_rewrite_with(view, &BTreeMap::new()).await
    }

    /// [`gradle_rewrite_in`] on a machine whose environment is `env`.
    async fn gradle_rewrite_with(
        view: &ProjectView<'_>,
        env: &BTreeMap<String, String>,
    ) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![gradle_candidate()];
        let read = read_candidate_files_in(view, &BTreeSet::new(), &candidates, env).await;
        let done = rewrite(view, read.clone(), &candidates, BTreeMap::new(), options).await;
        (read, done)
    }

    /// A run with nothing to redirect: [`read_maven_heal_files`] then
    /// [`rewrite`] with no candidate.
    async fn heal_only(view: &ProjectView<'_>) -> Option<Rewritten> {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let read = read_maven_heal_files(view).await?;
        Some(rewrite(view, read, &[], BTreeMap::new(), options).await)
    }

    const PLAIN_POM: &str = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
        <modelVersion>4.0.0</modelVersion>\n  <groupId>t</groupId>\n  \
        <artifactId>app</artifactId>\n  <version>1</version>\n</project>\n";

    fn checksums_block(form: crate::formats::maven::trusted_checksums::Basedir) -> String {
        format!(
            "{}\n",
            crate::formats::maven::trusted_checksums::config_args(form).join("\n")
        )
    }

    /// A scan that redirects nothing reads the Maven files only when
    /// `.mvn/maven.config` holds a block to heal, and then heals it: on
    /// disk and in memory alike.
    #[tokio::test]
    async fn a_run_with_nothing_to_redirect_heals_the_maven_config() {
        use crate::formats::maven::trusted_checksums::Basedir::{Launcher, Session};
        use crate::patch::redirect::{MVN_CONFIG, MVN_WRAPPER_PROPERTIES};
        let wrapper_4 = "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/\
                         apache-maven/4.0.0/apache-maven-4.0.0-bin.zip\n";
        // (the config, a Maven 4 wrapper, what the heal leaves)
        for (config, maven_4, healed) in [
            (
                checksums_block(Session),
                false,
                Some(checksums_block(Launcher)),
            ),
            (
                checksums_block(Launcher),
                true,
                Some(checksums_block(Session)),
            ),
            (
                format!("-T4\n{}", checksums_block(Session)),
                false,
                Some(format!("-T4\n{}", checksums_block(Launcher))),
            ),
            // This project's own spelling, or no block: nothing to do.
            (checksums_block(Launcher), false, None),
            (checksums_block(Session), true, None),
            ("-T4\n".to_string(), false, None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let mut memory = MemoryProject::new();
            let mut put = |rel: &str, text: &str| {
                let path = tmp.path().join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
                memory.insert_text(rel, text);
            };
            put("pom.xml", PLAIN_POM);
            put(MVN_CONFIG, &config);
            if maven_4 {
                put(MVN_WRAPPER_PROPERTIES, wrapper_4);
            }
            for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
                let done = heal_only(&view).await;
                let Some(healed) = &healed else {
                    // A block in the other spelling is read, and found to
                    // be this project's; no block is not read at all.
                    assert!(
                        done.is_none_or(
                            |done| done.rewrite.files.is_empty() && done.rewrite.edits.is_empty()
                        ),
                        "{config:?} / Maven 4: {maven_4}"
                    );
                    continue;
                };
                let mut done = done.expect("a block to heal");
                assert_eq!(
                    done.rewrite.files.keys().collect::<Vec<_>>(),
                    [MVN_CONFIG],
                    "{config:?}"
                );
                assert_eq!(&done.rewrite.files[MVN_CONFIG], healed);
                assert_eq!(done.rewritten, [MVN_CONFIG]);
                assert!(done.confirmed.is_empty());
                assert!(guard(&view, &done, &[]).is_none());
                let codes: Vec<&str> = done
                    .rewrite
                    .warnings
                    .iter()
                    .map(|w| w.code.as_str())
                    .collect();
                // Only the heal that takes the session's property out of a
                // project that declares no Maven trades anything away.
                let trade: &[&str] = if maven_4 {
                    &[]
                } else {
                    &["redirect_maven_trusted_checksums_maven3_only"]
                };
                assert_eq!(codes, trade, "{config:?}");

                // A caller that cannot write withholds all of it.
                done.withhold_maven_heal();
                assert!(done.rewrite.files.is_empty());
                assert!(done.rewrite.edits.is_empty());
                assert!(done.rewrite.warnings.is_empty());
                assert!(done.rewritten.is_empty());
            }
        }
        // No config at all: nothing is read.
        let empty = tempfile::tempdir().unwrap();
        std::fs::write(empty.path().join("pom.xml"), PLAIN_POM).unwrap();
        assert!(heal_only(&ProjectView::Disk(empty.path())).await.is_none());
    }

    /// The heal is a courtesy, never the reason a run is refused. A write
    /// through a symbolic link would replace the link, which the guard
    /// refuses for every write: a `.mvn/maven.config` that is a link keeps
    /// its line, and the run goes on as if there were nothing to heal.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_maven_config_is_left_unhealed_and_refuses_nothing() {
        use crate::formats::maven::trusted_checksums::Basedir::Session;
        use crate::patch::redirect::MVN_CONFIG;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), PLAIN_POM).unwrap();
        std::fs::create_dir_all(tmp.path().join(".mvn")).unwrap();
        std::fs::create_dir_all(tmp.path().join("ci")).unwrap();
        std::fs::write(tmp.path().join("ci/maven.config"), checksums_block(Session)).unwrap();
        std::os::unix::fs::symlink("../ci/maven.config", tmp.path().join(MVN_CONFIG)).unwrap();
        let view = ProjectView::Disk(tmp.path());
        let done = heal_only(&view).await.expect("the block is read");
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.rewrite.edits.is_empty() && done.rewrite.warnings.is_empty());
        assert!(done.rewritten.is_empty());
        assert!(guard(&view, &done, &[]).is_none());

        // Control: the same file, not a link, is healed.
        std::fs::remove_file(tmp.path().join(MVN_CONFIG)).unwrap();
        std::fs::write(tmp.path().join(MVN_CONFIG), checksums_block(Session)).unwrap();
        let done = heal_only(&view).await.expect("the block is read");
        assert_eq!(done.rewritten, [MVN_CONFIG]);

        // Nor is it planned into a directory that does not take the write:
        // the commit would fail a run that had nothing else to do. (Root
        // writes anywhere, so there is nothing to see as root.)
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = tmp.path().join(".mvn");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            let done = heal_only(&view).await.expect("the block is read");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(done.rewrite.files.is_empty() && done.rewritten.is_empty());
            assert!(done.rewrite.edits.is_empty() && done.rewrite.warnings.is_empty());
        }
    }

    /// The Gradle pass reads the script graph's scripts and every build's
    /// lock files (nested ones included), and the planner pins them.
    #[tokio::test]
    async fn the_gradle_pass_reads_the_script_graph_and_its_locks() {
        let mut p = MemoryProject::new();
        p.insert_text(
            "settings.gradle",
            "include 'app'\napply from: 'gradle/more.gradle'\n",
        );
        p.insert_text("gradle/more.gradle", "include 'lib'\n");
        p.insert_text("build.gradle", "");
        p.insert_text(
            "app/build.gradle",
            "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
        );
        p.insert_text("lib/build.gradle", "");
        p.insert_text(
            "lib/gradle.lockfile",
            "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
        );
        p.insert_text(
            "samples/x/gradle.lockfile",
            "com.socketfixture:victim:1.10.0=c\n",
        );
        let (read, done) = gradle_rewrite(&p).await;
        assert!(read.files.contains_key("gradle/more.gradle"));
        assert!(read.files.contains_key("app/build.gradle"));
        assert!(read.files.contains_key("lib/gradle.lockfile"));
        assert!(!read.files.contains_key("samples/x/gradle.lockfile"));
        assert!(done.rewrite.files["lib/gradle.lockfile"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(
            done.confirmed,
            vec![(
                "pkg:maven/com.socketfixture/victim@1.10.0".to_string(),
                GRADLE_UUID.to_string()
            )]
        );
    }

    /// #646 review: a settings file that exists but cannot be read as text
    /// (Latin-1 bytes, mode 000) is not absent. The planner refuses the
    /// build instead of "creating" a one-line settings.gradle over it.
    #[tokio::test]
    async fn an_unreadable_settings_file_refuses_the_gradle_build() {
        const BUILD: &str = "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n";
        let refused = |read: &CandidateFiles, done: &Rewritten| {
            assert!(
                read.gradle_unreadable.contains("settings.gradle"),
                "{:?}",
                read.gradle_unreadable
            );
            // Only the Gradle build is refused, not the whole run (#721).
            assert!(
                !read
                    .undecodable_reads
                    .contains(&"settings.gradle".to_string()),
                "{:?}",
                read.undecodable_reads
            );
            assert!(done.rewrite.refused_gradle_uuids.contains(GRADLE_UUID));
            assert!(
                !done.rewrite.files.contains_key("settings.gradle"),
                "{:?}",
                done.rewrite.files.keys()
            );
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            assert!(
                done.rewrite.warnings.iter().any(|w| w.code
                    == crate::patch::redirect::gradle::UNREADABLE_REFUSAL_CODE
                    || w.detail
                        .contains(crate::patch::redirect::gradle::UNREADABLE_REFUSAL_CODE)),
                "{:?}",
                done.rewrite.warnings
            );
        };

        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.gradle");
        std::fs::write(
            &settings,
            b"rootProject.name = 'app'\n// Auteur: Andr\xe9\ninclude 'core'\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("build.gradle"), BUILD).unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        refused(&read, &done);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&settings, "rootProject.name = 'app'\n").unwrap();
            std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&settings).is_err() {
                let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
                refused(&read, &done);
            }
            std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        // In memory: non-UTF-8 bytes, and content the host did not provide.
        for entry in [
            MemoryEntry::Binary(b"rootProject.name = 'Andr\xe9'\n".to_vec().into()),
            MemoryEntry::Present,
        ] {
            let mut p = MemoryProject::new();
            p.insert("settings.gradle", entry);
            p.insert_text("build.gradle", BUILD);
            let (read, done) = gradle_rewrite(&p).await;
            refused(&read, &done);
        }

        // Control: a readable settings file is rewritten in place, never
        // created over.
        std::fs::write(&settings, "rootProject.name = 'app'\ninclude 'core'\n").unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        assert!(read.gradle_unreadable.is_empty());
        let text = &done.rewrite.files["settings.gradle"];
        assert!(text.contains("include 'core'"), "{text}");
    }

    /// #721 review: with no readable Gradle build the Gradle planner never
    /// runs, so a stray non-UTF-8 Gradle lock does not refuse the rest of a
    /// Maven run. A non-UTF-8 root build or settings script does: it may be
    /// the whole build, unreadable, which would otherwise be skipped
    /// silently (a Gradle-only project exiting 0 unpatched).
    #[tokio::test]
    async fn non_utf8_gradle_files_without_a_readable_build() {
        const POM: &str = "<project><dependencies><dependency><groupId>com.socketfixture</groupId><artifactId>victim</artifactId><version>1.10.0</version></dependency></dependencies></project>\n";
        let latin1: &[u8] = b"rootProject.name = 'Andr\xe9'\n";
        let candidates = vec![gradle_candidate()];

        // A stray lock beside a pom.xml: not refused.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), POM).unwrap();
        std::fs::write(tmp.path().join("gradle.lockfile"), latin1).unwrap();
        let mut memory = MemoryProject::new();
        memory.insert_text("pom.xml", POM);
        memory.insert(
            "gradle.lockfile",
            MemoryEntry::Binary(latin1.to_vec().into()),
        );
        for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
            let (read, done) = gradle_rewrite_in(&view).await;
            assert!(
                read.undecodable_reads.is_empty(),
                "{:?}",
                read.undecodable_reads
            );
            assert!(guard(&view, &done, &candidates).is_none());
        }

        // A Gradle-only project whose root scripts are all non-UTF-8:
        // refused, never skipped.
        for root in ["settings.gradle", "build.gradle", "build.gradle.kts"] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join(root), latin1).unwrap();
            let mut memory = MemoryProject::new();
            memory.insert(root, MemoryEntry::Binary(latin1.to_vec().into()));
            for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
                let (read, done) = gradle_rewrite_in(&view).await;
                assert_eq!(read.undecodable_reads, vec![root.to_string()]);
                let refusal = guard(&view, &done, &candidates).expect("refused");
                assert_eq!(refusal.code, UNREADABLE_REFUSAL);
            }
        }
    }

    /// #721 review: an unreadable `socket-patch.sbt` is refused by the
    /// run-wide check itself, which also runs before any vendored->hosted
    /// takeover revert, and keeps the sbt planner's own refusal code.
    #[tokio::test]
    async fn an_unreadable_sbt_owned_file_refuses_early_with_the_sbt_code() {
        let latin1: &[u8] = b"// Auteur: Andr\xe9\n";
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("socket-patch.sbt"), latin1).unwrap();
        let candidates = vec![gradle_candidate()];
        let read = read_candidate_files(
            &ProjectView::Disk(tmp.path()),
            &BTreeSet::new(),
            &candidates,
        )
        .await;
        assert_eq!(read.undecodable_reads, vec!["socket-patch.sbt"]);
        let refusal = undecodable_guard(&read.undecodable_reads, &candidates).expect("refused");
        assert_eq!(refusal.code, SBT_OWNED_FILE_UNREADABLE);
        assert!(
            refusal.message.contains("socket-patch.sbt"),
            "{}",
            refusal.message
        );
    }

    /// A refused Gradle build is never confirmed by a snippet pasted into a
    /// build script, though it names the suffixed version and the index url.
    #[tokio::test]
    async fn a_pasted_gradle_snippet_is_not_confirmed() {
        let c = gradle_candidate();
        let ov = c.dep.registry_override.as_ref().unwrap();
        let snippet = crate::patch::redirect::gradle::fallback_snippet(
            &[crate::gradle::dsl::Dsl::Groovy],
            &ov.index_url,
            "com.socketfixture",
            "victim",
            "1.10.0",
            Some("1.10.0-socket.4d5e6f70"),
            GRADLE_UUID,
            false,
        );
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "build.gradle",
            format!("plugins {{ id 'com.android.application' }}\n{snippet}\n").as_str(),
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.refused_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    /// A pom.xml beside a Gradle build: both must pin the patch.
    #[tokio::test]
    async fn a_mixed_pom_and_gradle_build_needs_both() {
        let pom = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text("pom.xml", pom);
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(done.confirmed.len(), 1);

        // The pom names another version: the Gradle half alone is not enough.
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "pom.xml",
            pom.replace("<version>1.10.0</version>", "<version>2.0</version>")
                .as_str(),
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    /// On disk the engine reads the mirrors of the Maven settings the
    /// build would be started with, and a project whose Socket repository
    /// one of them would take over is left alone: nothing written, nothing
    /// confirmed, the reason given, and no refusal of the run. A mirror
    /// that leaves the repository out wires as usual, and so does the
    /// same project in memory, where no machine's settings exist.
    #[tokio::test]
    async fn a_maven_project_behind_a_capturing_mirror_is_left_alone() {
        use crate::patch::redirect::MAVEN_MIRRORS_KEY;
        let pom = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        // Both settings files are named, so none of this machine's is read.
        let config = "-s\nsettings.xml\n-gs\nglobal.xml\n";
        let settings = |mirror_of: &str| {
            format!(
                "<settings>\n  <mirrors>\n    <mirror>\n      <id>corp</id>\n      \
                 <mirrorOf>{mirror_of}</mirrorOf>\n      <url>https://nexus.example/repo</url>\n    \
                 </mirror>\n  </mirrors>\n</settings>\n"
            )
        };
        let tmp = tempfile::tempdir().unwrap();
        let write = |rel: &str, text: &str| {
            let path = tmp.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("pom.xml", pom);
        write(".mvn/maven.config", config);
        write("global.xml", "<settings/>\n");
        write("settings.xml", &settings("*"));
        let view = ProjectView::Disk(tmp.path());
        let (read, done) = gradle_rewrite_in(&view).await;
        assert!(read.files.contains_key(MAVEN_MIRRORS_KEY));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        let warning = done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == "redirect_maven_mirror_captures_repository")
            .unwrap_or_else(|| panic!("{:?}", done.rewrite.warnings));
        assert!(
            warning.detail.contains("`corp`") && warning.detail.contains("settings.xml"),
            "{}",
            warning.detail
        );
        assert!(guard(&view, &done, &[gradle_candidate()]).is_none());

        // The mirror leaves the repository out.
        write(
            "settings.xml",
            &settings(&format!("*,!socket-patch-{GRADLE_UUID}")),
        );
        let (_, done) = gradle_rewrite_in(&view).await;
        assert!(done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);

        // A project an earlier run wired, on a machine whose mirror now
        // takes the repository: the pom still names the patch, and the
        // build behind that mirror cannot resolve it. Nothing is written,
        // and the patch is not confirmed by the text it still matches.
        let wired = done.rewrite.files.clone();
        for (rel, text) in &wired {
            write(rel, text);
        }
        write("settings.xml", &settings("*"));
        let (_, done) = gradle_rewrite_in(&view).await;
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(
            std::fs::read_to_string(tmp.path().join("pom.xml"))
                .unwrap()
                .contains("1.10.0-socket.4d5e6f70"),
            "the wiring is left as it is"
        );
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        assert!(done
            .rewrite
            .warnings
            .iter()
            .any(|w| w.code == "redirect_maven_mirror_captures_repository"));
        write("pom.xml", pom);

        // The settings are found through the environment the engine is
        // given, never the test process's own: a settings file named in
        // that environment's `MAVEN_ARGS` is the one read.
        std::fs::remove_file(tmp.path().join(".mvn/maven.config")).unwrap();
        write("ci/settings.xml", &settings("*"));
        let (_, done) = gradle_rewrite_in(&view).await;
        assert!(
            done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"),
            "no environment, no settings: wired"
        );
        let ci = BTreeMap::from([(
            "MAVEN_ARGS".to_string(),
            format!(
                "-s {} -gs {}",
                tmp.path().join("ci/settings.xml").display(),
                tmp.path().join("global.xml").display()
            ),
        )]);
        let (read, done) = gradle_rewrite_with(&view, &ci).await;
        assert!(read.files.contains_key(MAVEN_MIRRORS_KEY));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        write(".mvn/maven.config", config);

        // A settings path with a space, on a line of its own as Maven 3.9
        // and later read `maven.config`: the file is opened whole, and the
        // mirror in it gates the pin.
        write("team settings/settings.xml", &settings("*"));
        write(
            ".mvn/maven.config",
            "-s\nteam settings/settings.xml\n-gs\nglobal.xml\n",
        );
        write("settings.xml", &settings("central"));
        let (read, done) = gradle_rewrite_in(&view).await;
        assert!(read.files.contains_key(MAVEN_MIRRORS_KEY));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done
            .rewrite
            .warnings
            .iter()
            .any(|w| w.code == "redirect_maven_mirror_captures_repository"
                && w.detail.contains("team settings")));
        write(".mvn/maven.config", config);

        // In memory: the files are there, but no machine to read them for.
        let mut p = MemoryProject::new();
        p.insert_text("pom.xml", pom);
        p.insert_text(".mvn/maven.config", config);
        p.insert_text("settings.xml", settings("*").as_str());
        let view = ProjectView::Memory(&p);
        let (read, done) = gradle_rewrite_in(&view).await;
        assert!(!read.files.contains_key(MAVEN_MIRRORS_KEY));
        assert!(done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"));
    }

    /// #1809: a Maven 4 root whose subprojects Maven discovers (model
    /// 4.1.0, `pom` packaging, no list) is a reactor once a direct
    /// subdirectory holds a `pom.xml`. The engine reads that pom beside
    /// the root, on disk and in memory, so the pom rewriter plans both: a
    /// subproject that declares the version itself is not left behind.
    #[tokio::test]
    async fn a_maven_4_implicit_reactor_is_read_and_planned_whole() {
        let root = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  <modelVersion>4.1.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <packaging>pom</packaging>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let child = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  <modelVersion>4.1.0</modelVersion>\n  <parent/>\n  <artifactId>a</artifactId>\n</project>\n";
        let planned = |read: &CandidateFiles, done: &Rewritten| {
            assert!(
                read.files.contains_key("a/pom.xml"),
                "{:?}",
                read.files.keys()
            );
            assert!(
                done.rewrite.files["pom.xml"].contains("<version>1.10.0-socket.4d5e6f70</version>")
            );
            assert!(done.rewrite.files["pom.xml"].contains("<id>socket-patch-"));
            assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
            assert!(!done
                .rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_maven_multimodule_unsupported"));
        };

        let mut p = MemoryProject::new();
        p.insert_text("pom.xml", root);
        p.insert_text("a/pom.xml", child);
        let (read, done) = gradle_rewrite(&p).await;
        planned(&read, &done);
        assert!(!done.rewrite.files.contains_key("a/pom.xml"));

        // A subproject that declares the version itself is rewritten too.
        let declaring = child.replace(
            "</artifactId>",
            "</artifactId>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>",
        );
        let mut p = MemoryProject::new();
        p.insert_text("pom.xml", root);
        p.insert_text("a/pom.xml", declaring.as_str());
        let (read, done) = gradle_rewrite(&p).await;
        planned(&read, &done);
        assert!(done.rewrite.files["a/pom.xml"].contains("1.10.0-socket.4d5e6f70"));
        assert!(!done.rewrite.files["a/pom.xml"].contains("<repository>"));

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), root).unwrap();
        std::fs::create_dir(tmp.path().join("a")).unwrap();
        std::fs::write(tmp.path().join("a/pom.xml"), child).unwrap();
        // A directory without a pom is no subproject.
        std::fs::create_dir(tmp.path().join("src")).unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        planned(&read, &done);
        assert!(!read.files.contains_key("src/pom.xml"));

        // A reactor one of whose poms cannot be read is refused whole, and
        // a suffixed version an earlier run left in it then confirms
        // nothing: the refused root pins nothing.
        let stale = root.replace("1.10.0", "1.10.0-socket.4d5e6f70");
        for r in [root, stale.as_str()] {
            let mut p = MemoryProject::new();
            p.insert_text("pom.xml", r);
            p.insert_text("a/pom.xml", "<project>");
            let (_, done) = gradle_rewrite(&p).await;
            assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            assert!(done
                .rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_maven_multimodule_unsupported"));
        }

        // Without a subproject the root is a single pom, pinned as before.
        std::fs::remove_dir_all(tmp.path().join("a")).unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        assert!(!read.files.keys().any(|k| k.ends_with("/pom.xml")));
        assert!(done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(done.confirmed.len(), 1);
    }

    /// A reactor of hundreds of modules is read and planned whole: every
    /// module pom is a candidate file, and each one that declares the
    /// version is rewritten. (The reader learned one module per round, and
    /// stopped after 64.)
    #[tokio::test]
    async fn a_reactor_of_hundreds_of_modules_is_read_and_planned_whole() {
        let declaring = "  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n";
        let names: Vec<String> = (0..200).map(|n| format!("module-{n}")).collect();
        let listed: String = names
            .iter()
            .map(|name| format!("    <module>{name}</module>\n"))
            .collect();
        let mut p = MemoryProject::new();
        p.insert_text(
            "pom.xml",
            format!(
                "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <packaging>pom</packaging>\n  <modules>\n{listed}  </modules>\n</project>\n"
            )
            .as_str(),
        );
        for name in &names {
            p.insert_text(
                format!("{name}/pom.xml"),
                format!(
                    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>x</groupId>\n    <artifactId>y</artifactId>\n    <version>1</version>\n  </parent>\n  <artifactId>{name}</artifactId>\n{declaring}</project>\n"
                )
                .as_str(),
            );
        }
        let (read, done) = gradle_rewrite(&p).await;
        for name in &names {
            let rel = format!("{name}/pom.xml");
            assert!(read.files.contains_key(&rel), "{rel} was not read");
            assert!(
                done.rewrite.files[&rel].contains("<version>1.10.0-socket.4d5e6f70</version>"),
                "{rel} was not rewritten: {:?}",
                done.rewrite.warnings
            );
        }
        assert!(done.rewrite.files["pom.xml"].contains("<id>socket-patch-"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
    }

    /// A module pom that is a symbolic link, or that is there without
    /// readable content, is no reason to fail the run: the reactor is left
    /// as it is, with the reason, as every reactor was before module poms
    /// were read. The guard that refuses a linked or unreadable rewrite
    /// target has nothing to refuse. A module pom that is there but is not
    /// UTF-8 text is refused by name instead: it must never look absent.
    #[tokio::test]
    async fn a_reactor_with_an_unreadable_module_pom_is_left_alone_not_failed() {
        let root = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <packaging>pom</packaging>\n  <modules>\n    <module>a</module>\n  </modules>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let left_alone = |view: &ProjectView<'_>, read: &CandidateFiles, done: &Rewritten| {
            assert!(
                read.symlinked_reads.is_empty()
                    && read.unreadable_reads.is_empty()
                    && read.undecodable_reads.is_empty(),
                "{read:?}"
            );
            assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            assert!(done
                .rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_maven_multimodule_unsupported"));
            assert!(guard(view, done, &[gradle_candidate()]).is_none());
        };
        for entry in [MemoryEntry::Symlink, MemoryEntry::Present] {
            let mut p = MemoryProject::new();
            p.insert_text("pom.xml", root);
            p.insert("a/pom.xml", entry);
            let view = ProjectView::Memory(&p);
            let (read, done) = gradle_rewrite_in(&view).await;
            left_alone(&view, &read, &done);
        }

        // A pom that is there but is not UTF-8 text is not a missing one:
        // its content is unknown, so the run is refused for it by name,
        // as for an undecodable root pom, with nothing written. On disk and
        // in memory alike.
        let undecodable = |view: &ProjectView<'_>, read: &CandidateFiles, done: &Rewritten| {
            assert_eq!(read.undecodable_maven_poms, ["a/pom.xml"]);
            assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            let refusal = guard(view, done, &[gradle_candidate()]).expect("refused");
            assert_eq!(refusal.code, UNREADABLE_REFUSAL);
            assert!(refusal.message.contains("a/pom.xml"), "{}", refusal.message);
        };
        let mut p = MemoryProject::new();
        p.insert_text("pom.xml", root);
        p.insert(
            "a/pom.xml",
            MemoryEntry::Binary(vec![0xff, 0xfe, 0x00].into()),
        );
        let view = ProjectView::Memory(&p);
        let (read, done) = gradle_rewrite_in(&view).await;
        undecodable(&view, &read, &done);

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), root).unwrap();
        std::fs::create_dir(tmp.path().join("a")).unwrap();
        std::fs::write(tmp.path().join("a/pom.xml"), [0xff, 0xfe, 0x00]).unwrap();
        let view = ProjectView::Disk(tmp.path());
        let (read, done) = gradle_rewrite_in(&view).await;
        undecodable(&view, &read, &done);
        // A module pom of another name is one too.
        std::fs::write(
            tmp.path().join("pom.xml"),
            root.replace("<module>a</module>", "<module>a/build.xml</module>"),
        )
        .unwrap();
        std::fs::rename(tmp.path().join("a/pom.xml"), tmp.path().join("a/build.xml")).unwrap();
        let (read, done) = gradle_rewrite_in(&view).await;
        assert_eq!(read.undecodable_maven_poms, ["a/build.xml"]);
        assert!(guard(&view, &done, &[gradle_candidate()]).is_some());
        std::fs::rename(tmp.path().join("a/build.xml"), tmp.path().join("a/pom.xml")).unwrap();
        std::fs::write(tmp.path().join("pom.xml"), root).unwrap();
        // A link, to a pom that would otherwise be planned.
        #[cfg(unix)]
        {
            std::fs::remove_file(tmp.path().join("a/pom.xml")).unwrap();
            std::fs::write(
                tmp.path().join("real.xml"),
                "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>x</groupId>\n    <artifactId>y</artifactId>\n    <version>1</version>\n  </parent>\n  <artifactId>a</artifactId>\n</project>\n",
            )
            .unwrap();
            std::os::unix::fs::symlink(tmp.path().join("real.xml"), tmp.path().join("a/pom.xml"))
                .unwrap();
            let (read, done) = gradle_rewrite_in(&view).await;
            left_alone(&view, &read, &done);
        }
    }

    /// An sbt build beside a Gradle build: the Gradle planner pinning a
    /// uuid the sbt rewriter refused (here: no resolution evidence) does
    /// not confirm it — the sbt build still loads the upstream artifact.
    #[tokio::test]
    async fn a_mixed_sbt_and_gradle_build_needs_both() {
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "build.gradle",
            "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
        );
        p.insert_text(
            "gradle.lockfile",
            "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
        );
        // The Gradle half alone pins the patch.
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);

        p.insert_text("project/build.properties", "sbt.version=1.9.9\n");
        p.insert_text(
            "build.sbt",
            "libraryDependencies += \"com.socketfixture\" % \"victim\" % \"1.10.0\"\n",
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.rewrite.refused_sbt_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    /// The gate reuses the caller's discovery only for a pass that writes
    /// nothing and counts exactly the origins it was made with.
    #[test]
    fn the_prior_discovery_is_reused_only_unwritten_with_the_same_origins() {
        let prior = crate::vex::discover::Discovery::default();
        assert!(reusable_prior(Some(&prior), true, true).is_some());
        assert!(reusable_prior(Some(&prior), false, true).is_none());
        assert!(reusable_prior(Some(&prior), true, false).is_none());
        assert!(reusable_prior(None, true, true).is_none());
    }

    /// A registry-resolved left-pad: the hosted rewrite redirects it.
    const LEFT_PAD_LOCK: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "left-pad": "1.3.0" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;

    /// The left-pad rewrite of the project on disk at `root`, counting
    /// `configured` patch servers and handed `prior` as the caller's
    /// pre-rewrite discovery.
    async fn gated_left_pad_rewrite(
        root: &std::path::Path,
        configured: &[&str],
        prior: Option<&crate::vex::discover::Discovery>,
    ) -> Rewritten {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: configured.iter().map(|o| o.to_string()).collect(),
            prior_discovery: prior,
        };
        let view = ProjectView::Disk(root);
        let candidates = vec![left_pad_candidate()];
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        rewrite(&view, read, &candidates, BTreeMap::new(), options).await
    }

    /// Lockfile discovery of `root` as the management commands make it.
    async fn discover_configured(
        root: &std::path::Path,
        configured: &[&str],
    ) -> crate::vex::discover::Discovery {
        crate::vex::discover_patched_refs_with(
            root,
            &crate::vex::DiscoverOptions {
                patch_server_origins: configured.iter().map(|o| o.to_string()).collect(),
            },
        )
        .await
    }

    /// Write `done`'s files under `root`, as the disk flow does.
    fn write_rewrite(root: &std::path::Path, done: &Rewritten) {
        for (rel, text) in &done.rewrite.files {
            std::fs::write(root.join(rel), text).unwrap();
        }
        for (rel, bytes) in &done.rewrite.binary_files {
            std::fs::write(root.join(rel), bytes).unwrap();
        }
    }

    /// A writing pass hands back the gate's discovery over its overlaid
    /// writes, and it is the discovery of the written disk; the caller's
    /// prior discovery is never reused for a pass that writes.
    #[tokio::test]
    async fn a_writing_pass_hands_back_the_discovery_of_its_writes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let configured = ["https://patch.test"];
        let before = discover_configured(tmp.path(), &configured).await;
        let done = gated_left_pad_rewrite(tmp.path(), &configured, Some(&before)).await;
        assert!(done.rewrite.files.contains_key("package-lock.json"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        let Some(FinalDiscovery::Overlaid {
            discovery: overlaid,
            view_only,
        }) = &done.final_discovery
        else {
            panic!(
                "expected the overlaid discovery: {:?}",
                done.final_discovery
            );
        };
        assert!(*view_only, "npm discovery reads only through the view");
        write_rewrite(tmp.path(), &done);
        let after = discover_configured(tmp.path(), &configured).await;
        assert_eq!(format!("{overlaid:?}"), format!("{after:?}"));
        assert_ne!(format!("{before:?}"), format!("{after:?}"));
        assert_eq!(
            crate::patch::redirect::upstream::HostedPin::all(overlaid).len(),
            1
        );
    }

    /// A pass that writes nothing (an already-redirected project) reuses
    /// the caller's discovery and says so.
    #[tokio::test]
    async fn an_unwritten_pass_hands_back_the_prior_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let configured = ["https://patch.test"];
        let first = gated_left_pad_rewrite(tmp.path(), &configured, None).await;
        write_rewrite(tmp.path(), &first);
        let prior = discover_configured(tmp.path(), &configured).await;
        let done = gated_left_pad_rewrite(tmp.path(), &configured, Some(&prior)).await;
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert_eq!(done.confirmed.len(), 1);
        assert!(matches!(done.final_discovery, Some(FinalDiscovery::Prior)));
        // Without a prior discovery, the gate discovers the (unwritten)
        // project itself and hands that back.
        let done = gated_left_pad_rewrite(tmp.path(), &configured, None).await;
        let Some(FinalDiscovery::Overlaid {
            discovery: fresh, ..
        }) = &done.final_discovery
        else {
            panic!("expected a fresh discovery: {:?}", done.final_discovery);
        };
        assert_eq!(format!("{fresh:?}"), format!("{prior:?}"));
    }

    /// A grant on a server the caller did not configure makes the gate count
    /// another origin: its discovery is not the caller's, so the gate never
    /// reuses the prior one and hands back none.
    #[tokio::test]
    async fn a_foreign_grant_origin_hands_back_no_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let done = gated_left_pad_rewrite(tmp.path(), &[], None).await;
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        assert!(done.final_discovery.is_none());
        write_rewrite(tmp.path(), &done);
        // Unwritten now, with a prior discovery made without the grant's
        // origin: still not reused.
        let prior = discover_configured(tmp.path(), &[]).await;
        let done = gated_left_pad_rewrite(tmp.path(), &[], Some(&prior)).await;
        assert!(done.rewrite.files.is_empty());
        assert_eq!(done.confirmed.len(), 1);
        assert!(done.final_discovery.is_none());
    }

    /// Nothing confirmed: the gate discovers nothing and hands back none.
    #[tokio::test]
    async fn an_unconfirmed_rewrite_hands_back_no_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            LEFT_PAD_LOCK.replace("left-pad", "right-pad"),
        )
        .unwrap();
        let prior = discover_configured(tmp.path(), &["https://patch.test"]).await;
        let done = gated_left_pad_rewrite(tmp.path(), &["https://patch.test"], Some(&prior)).await;
        assert!(done.confirmed.is_empty());
        assert!(done.final_discovery.is_none());
    }

    /// Only the install-policy auto-configs' root config files may be
    /// created under an overlaid discovery.
    #[test]
    fn only_root_config_files_are_invisible_overlay_creations() {
        assert!(overlay_creation_is_invisible(".npmrc"));
        assert!(overlay_creation_is_invisible("pnpm-workspace.yaml"));
        for rel in [
            "package-lock.json",
            "pylock.toml",
            "pylock.dev.toml",
            "packages/a/.npmrc",
            "common/config/subspaces/a/pnpm-lock.yaml",
            "settings.gradle",
            "NuGet.Config",
        ] {
            assert!(!overlay_creation_is_invisible(rel), "{rel}");
        }
    }

    /// A lockless NuGet pin (a Socket source mapping, no
    /// `packages.lock.json`) is still written, but the run says no later
    /// command can manage it and names the lockfile that fixes that.
    #[tokio::test]
    async fn a_lockless_nuget_pin_is_written_with_the_lockless_warning() {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        let base =
            format!("https://patch.test/patch-registry/nuget/{FIXTURE_TOKEN}/{FIXTURE_UUID}");
        let candidate = Candidate {
            purl: "pkg:nuget/Newtonsoft.Json@13.0.3".into(),
            dep: DepOverride {
                ecosystem: "nuget".into(),
                name: "Newtonsoft.Json".into(),
                namespace: None,
                version: "13.0.3".into(),
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "{base}/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
                ),
                npm_registry_url: None,
                registry_override: Some(RegistryOverride {
                    kind: "nuget-v3".into(),
                    index_url: format!("{base}/index.json"),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "Newtonsoft.Json".into(),
                        version: "13.0.3".into(),
                        nuget_id_lower: Some("newtonsoft.json".into()),
                        nuget_version_norm: Some("13.0.3".into()),
                        ..Default::default()
                    },
                }),
                integrity: Integrity {
                    sha512: Some("sha512-NUGETPATCHED==".into()),
                    ..Default::default()
                },
            },
        };
        let mut p = MemoryProject::new();
        p.insert_text(
            "nuget.config",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
             <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
             </packageSources>\n</configuration>\n",
        );
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![candidate];
        let view = ProjectView::Memory(&p);
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(&view, read, &candidates, BTreeMap::new(), options).await;
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        assert!(done.unattributed.is_empty(), "{:?}", done.unattributed);
        let lockless: Vec<&RewriteWarning> = done
            .rewrite
            .warnings
            .iter()
            .filter(|w| w.code == REDIRECT_PIN_LOCKLESS)
            .collect();
        assert_eq!(lockless.len(), 1, "{:?}", done.rewrite.warnings);
        let detail = &lockless[0].detail;
        assert!(detail.contains("Newtonsoft.Json"), "{detail}");
        assert!(
            detail.contains("dotnet restore --use-lock-file"),
            "{detail}"
        );
    }

    const GEMFILE: &str = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
    const GEM_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
        PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.5.22\n";

    async fn gem_rewrite(p: &MemoryProject) -> (CandidateFiles, Rewritten) {
        gem_rewrite_in(&ProjectView::Memory(p)).await
    }

    async fn gem_rewrite_in(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        gem_rewrite_of(view, vec![gem_candidate()]).await
    }

    async fn gem_rewrite_of(
        view: &ProjectView<'_>,
        candidates: Vec<Candidate>,
    ) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(view, read.clone(), &candidates, BTreeMap::new(), options).await;
        (read, done)
    }

    /// In a Bazel workspace the read of a run with a gem candidate hands
    /// the gem rewriter what the rules_ruby calls that may read the lock
    /// hold in `gem_checksums`, from a checkout and from the same files in
    /// memory alike, and a gem that a call holds to another sha256 than the
    /// patched archive's is left as it is. In no Bazel workspace, beside a
    /// call that reads another lock and with the patched sha256 in the
    /// entry, the run is the one it is without Bazel.
    #[tokio::test]
    async fn gem_checksums_of_a_bazel_hub_ride_to_the_gem_rewriter() {
        use crate::bazel::ruby::{KEY, PINNED};
        let module = |lock: &str, sum: &str| {
            format!(
                "bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n\
                 ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
                 ruby.bundle_fetch(gemfile_lock = \"{lock}\", gem_checksums = \
                 {{\"rails-7.0.0\": \"{sum}\"}})\n"
            )
        };
        let (upstream, patched) = ("1".repeat(64), "f".repeat(64));
        // A file over the size the reader takes is read on neither side.
        let large = "#".repeat(crate::bazel::starlark::MAX_BYTES);
        let large = module("//:Gemfile.lock", &upstream) + &large;
        // The `MODULE.bazel`, whether its call is handed over, and whether
        // the gem is left as it is.
        for (module, handed, left) in [
            (None, false, false),
            (Some(module("//:Gemfile.lock", &upstream)), true, true),
            (Some(module("//:Gemfile.lock", &patched)), true, false),
            (Some(large), false, false),
            (
                Some(module("//other:Gemfile.lock", &upstream)),
                false,
                false,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let mut p = MemoryProject::new();
            let module = module.as_deref().map(|module| ("MODULE.bazel", module));
            for (rel, text) in [("Gemfile", GEMFILE), ("Gemfile.lock", GEM_LOCK)]
                .into_iter()
                .chain(module)
            {
                std::fs::write(tmp.path().join(rel), text).unwrap();
                p.insert_text(rel, text);
            }
            let (on_disk, disk) = gem_rewrite_in(&ProjectView::Disk(tmp.path())).await;
            let (in_memory, memory) = gem_rewrite(&p).await;
            let module = module.map(|(_, module)| &module[..module.len().min(200)]);
            assert_eq!(
                on_disk.files.get(KEY),
                in_memory.files.get(KEY),
                "{module:?}"
            );
            assert_eq!(on_disk.files.contains_key(KEY), handed, "{module:?}");
            assert!(disk.rewrite == memory.rewrite, "{module:?}");
            assert_eq!(disk.confirmed, memory.confirmed, "{module:?}");
            let pinned = |w: &RewriteWarning| w.code == PINNED;
            assert_eq!(disk.rewrite.warnings.iter().any(pinned), left, "{module:?}");
            assert_eq!(disk.confirmed.is_empty(), left, "{module:?}");
            assert_eq!(disk.rewrite.files.is_empty(), left, "{module:?}");
        }
        // In memory a file that was not handed over as text is there, and
        // unread: Bazel takes `WORKSPACE.bazel` before `WORKSPACE`, so the
        // call of the second is not what it builds from.
        let rule = "rb_bundle_fetch(gemfile_lock = \"//:Gemfile.lock\", gem_checksums = {})\n";
        let mut p = MemoryProject::new();
        for (rel, text) in [("Gemfile", GEMFILE), ("Gemfile.lock", GEM_LOCK)] {
            p.insert_text(rel, text);
        }
        p.insert_text("WORKSPACE", rule);
        assert!(gem_rewrite(&p).await.0.files.contains_key(KEY));
        p.insert_present("WORKSPACE.bazel");
        assert!(!gem_rewrite(&p).await.0.files.contains_key(KEY));
    }

    /// A gem locked as precompiled platform builds, with a prebuild for
    /// each: the rewrite moves every build, and lockfile discovery (what
    /// `vex`, `rollback` and `remove` read) attributes them to the one pin,
    /// so the engine confirms it instead of dropping the rewrite as
    /// unattributable. A second run over the result confirms the same pin
    /// and writes nothing.
    #[tokio::test]
    async fn gem_platform_builds_are_confirmed_as_one_pin() {
        use crate::patch::redirect::GemPlatformChecksum;
        let mut candidate = gem_candidate();
        candidate
            .dep
            .registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .gem_platforms = ["arm64-darwin", "x86_64-linux-gnu"]
            .iter()
            .zip(["a", "b"])
            .map(|(platform, digit)| GemPlatformChecksum {
                platform: platform.to_string(),
                gem_checksum_sha256: digit.repeat(64),
            })
            .collect();
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0-arm64-darwin)\n    rails \
             (7.0.0-x86_64-linux-gnu)\n\nPLATFORMS\n  arm64-darwin\n  x86_64-linux-gnu\n\nDEPENDENCIES\n  \
             rails (= 7.0.0)\n\nCHECKSUMS\n  rails (7.0.0-arm64-darwin) sha256={}\n  rails \
             (7.0.0-x86_64-linux-gnu) sha256={}\n\nBUNDLED WITH\n  4.0.15\n",
            "1".repeat(64),
            "2".repeat(64)
        );
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", lock.as_str());
        let (_, done) = gem_rewrite_of(&ProjectView::Memory(&p), vec![candidate.clone()]).await;
        assert!(done.unattributed.is_empty(), "{:?}", done.unattributed);
        assert_eq!(
            done.confirmed,
            [("pkg:gem/rails@7.0.0".to_string(), FIXTURE_UUID.to_string())]
        );
        let written = &done.rewrite.files["Gemfile.lock"];
        assert!(
            written.contains(
                "  specs:\n    rails (7.0.0-arm64-darwin)\n    rails (7.0.0-x86_64-linux-gnu)\n\nGEM\n  \
                 remote: https://rubygems.org/\n  specs:\n\nPLATFORMS"
            ),
            "{written}"
        );
        assert!(
            written.contains(&format!(
                "CHECKSUMS\n  rails (7.0.0-arm64-darwin) sha256={}\n  rails (7.0.0-x86_64-linux-gnu) \
                 sha256={}\n",
                "a".repeat(64),
                "b".repeat(64)
            )),
            "{written}"
        );

        for (rel, text) in &done.rewrite.files {
            p.insert_text(rel, text.as_str());
        }
        let (_, again) = gem_rewrite_of(&ProjectView::Memory(&p), vec![candidate]).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.edits);
        assert_eq!(again.confirmed, done.confirmed);
        assert!(again.unattributed.is_empty(), "{:?}", again.unattributed);
    }

    /// #390: `bundle config set --local gemfile Gemfile.next` makes bundler
    /// load `Gemfile.next`; the hosted redirect used to rewrite `Gemfile`
    /// (which bundler ignores) and attest the patch. Now no gem file is a
    /// candidate and the run says why.
    #[tokio::test]
    async fn bundle_gemfile_naming_another_manifest_redirects_nothing() {
        let mut p = MemoryProject::new();
        for name in ["Gemfile", "Gemfile.next"] {
            p.insert_text(name, GEMFILE);
        }
        for name in ["Gemfile.lock", "Gemfile.next.lock"] {
            p.insert_text(name, GEM_LOCK);
        }
        p.insert_text(".bundle/config", "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n");
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.keys().all(|k| !k.starts_with("Gemfile")),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes: Vec<&str> = done
            .rewrite
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect();
        assert!(
            codes.contains(&"redirect_gem_bundle_gemfile_unsupported"),
            "{codes:?}"
        );
        assert!(!codes.contains(&"redirect_gem_no_gemfile"), "{codes:?}");
    }

    fn warning_codes(done: &Rewritten) -> Vec<&str> {
        done.rewrite
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect()
    }

    /// #749: bundler 4's `BUNDLE_LOCKFILE` naming another lock leaves every
    /// gem manifest out of the candidates, and the run says why.
    #[tokio::test]
    async fn bundle_lockfile_naming_another_lock_redirects_nothing() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text("custom.lock", GEM_LOCK);
        p.insert_text(".bundle/config", "---\nBUNDLE_LOCKFILE: \"custom.lock\"\n");
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_bundle_lockfile_unsupported"),
            "{codes:?}"
        );
    }

    /// #749: a memory view has no real root, so an absolute
    /// `BUNDLE_LOCKFILE` that would land on the pair's lock if the project
    /// sat at `/` still names a file outside the project. Bundler opens
    /// that path, never the in-repo lock, so the pair stays out.
    #[tokio::test]
    async fn absolute_bundle_lockfile_redirects_nothing() {
        for (gems_rb, lock) in [(false, "/Gemfile.lock"), (true, "/gems.locked")] {
            let mut p = MemoryProject::new();
            if gems_rb {
                p.insert_text("gems.rb", GEMFILE);
                p.insert_text("gems.locked", GEM_LOCK);
            } else {
                p.insert_text("Gemfile", GEMFILE);
                p.insert_text("Gemfile.lock", GEM_LOCK);
            }
            p.insert_text(
                ".bundle/config",
                format!("---\nBUNDLE_LOCKFILE: \"{lock}\"\n").as_str(),
            );
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{lock}: {:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_bundle_lockfile_unsupported"),
                "{lock}: {codes:?}"
            );
        }
    }

    /// #751: a `Gemfile` + `gems.rb` twin is withheld whatever its locks'
    /// `BUNDLED WITH` say (which bundler wrote a lock is not which one
    /// installs it), and the run says why.
    #[tokio::test]
    async fn twin_redirects_nothing_whatever_the_locks_say() {
        let legacy = GEM_LOCK.replace("2.5.22", "1.17.3");
        for (gemfile_lock, gems_locked) in [
            (legacy.as_str(), legacy.as_str()),
            (legacy.as_str(), GEM_LOCK),
            (GEM_LOCK, GEM_LOCK),
        ] {
            let mut p = MemoryProject::new();
            p.insert_text("Gemfile", GEMFILE);
            p.insert_text("Gemfile.lock", gemfile_lock);
            p.insert_text("gems.rb", GEMFILE);
            p.insert_text("gems.locked", gems_locked);
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
                "{codes:?}"
            );
        }
    }

    /// #1688: bundler ≤ 2.1 writes ONE merged `GEM` section listing every
    /// remote, so after an earlier redirect + `bundle install` the lock's
    /// Socket remote names the earlier patch. A superseding patch (or a
    /// rotated grant) moves the Gemfile's `source … do` block to the new
    /// URL; the lock's remote must move with it, or discovery reads the
    /// pair as naming two patches and the run skips the new one as
    /// `redirect_unattributable` on every scan.
    #[tokio::test]
    async fn merged_section_supersede_moves_the_lock_remote_with_the_gemfile() {
        const OLD_UUID: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        const OLD_TOKEN: &str = "22222222-2222-4222-8222-222222222222";
        let new_url =
            format!("https://patch.test/patch-registry/gem/{FIXTURE_TOKEN}/{FIXTURE_UUID}/");
        for (label, old_url) in [
            (
                "superseding patch",
                format!("https://patch.test/patch-registry/gem/{FIXTURE_TOKEN}/{OLD_UUID}/"),
            ),
            (
                "rotated grant",
                format!("https://patch.test/patch-registry/gem/{OLD_TOKEN}/{FIXTURE_UUID}/"),
            ),
        ] {
            for eol in ["\n", "\r\n"] {
                let gemfile = format!(
                    "source \"https://rubygems.org\"\n\nsource \"{old_url}\" do\n  gem \"rails\", \"7.0.0\"\nend\n"
                )
                .replace('\n', eol);
                let lock = format!(
                    "GEM\n  remote: https://rubygems.org/\n  remote: {old_url}\n  specs:\n    \
                     rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\n\
                     BUNDLED WITH\n   2.1.4\n"
                )
                .replace('\n', eol);
                let mut p = MemoryProject::new();
                p.insert_text("Gemfile", gemfile.as_str());
                p.insert_text("Gemfile.lock", lock.as_str());
                let outer = OuterAllowRemote::default;
                let options = RewriteOptions {
                    dry_run: false,
                    targets_pipenv_lock: false,
                    pipenv_major: None,
                    pipenv_unknown_detail: String::new(),
                    trust_lockfile_config: true,
                    npm_allow_remote_config: true,
                    npm_outer: &outer,
                    yarn_classic_outer: &OuterYarnMirror::default,
                    cargo_outer: &no_cargo_outer,
                    maven_selection: &no_maven_selection,
                    pnpm_env: &no_env,
                    blocking: false,
                    takeover_uuids: Default::default(),
                    patch_server_origins: vec!["https://patch.test".to_string()],
                    prior_discovery: None,
                };
                let mut candidate = gem_candidate();
                if let Some(ov) = candidate.dep.registry_override.as_mut() {
                    ov.index_url = new_url.clone();
                }
                let candidates = vec![candidate];
                let view = ProjectView::Memory(&p);
                let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
                let done = rewrite(&view, read, &candidates, BTreeMap::new(), options).await;
                let ctx = format!("{label} ({eol:?})");
                assert!(
                    done.unattributed.is_empty(),
                    "{ctx}: {:?}",
                    done.unattributed
                );
                assert_eq!(
                    done.confirmed,
                    vec![("pkg:gem/rails@7.0.0".to_string(), FIXTURE_UUID.to_string())],
                    "{ctx}: {:?}",
                    done.rewrite.warnings
                );
                assert_eq!(
                    done.rewrite.files.get("Gemfile").map(String::as_str),
                    Some(gemfile.replace(&old_url, &new_url).as_str()),
                    "{ctx}"
                );
                assert_eq!(
                    done.rewrite.files.get("Gemfile.lock").map(String::as_str),
                    Some(lock.replace(&old_url, &new_url).as_str()),
                    "{ctx}: the merged section's Socket remote moves in place"
                );
                assert!(
                    done.rewrite.edits.iter().any(|e| {
                        e.path == "Gemfile.lock"
                            && e.kind == "redirect_gemfile_lock_source_url"
                            && e.original == Some(serde_json::Value::String(old_url.clone()))
                    }),
                    "{ctx}: {:?}",
                    done.rewrite.edits
                );
                assert!(
                    !warning_codes(&done).contains(&"redirect_gem_frozen_install"),
                    "{ctx}: the refreshed pair stays converged: {:?}",
                    done.rewrite.warnings
                );
            }
        }
    }

    /// A twin whose other spelling this run can't read (a symlink, an
    /// unreadable or a non-UTF-8 file) is still a twin: bundler's
    /// `File.file?` sees it, so neither pair is wired (Bugbot on #768).
    #[tokio::test]
    async fn twin_with_an_unreadable_spelling_redirects_nothing() {
        for (other, entry) in [
            ("gems.rb", MemoryEntry::Symlink),
            ("Gemfile", MemoryEntry::Symlink),
            (
                "gems.rb",
                MemoryEntry::Binary(vec![0xff, 0xfe, 0x00].into()),
            ),
        ] {
            let mut p = MemoryProject::new();
            for (rel, text) in [
                ("Gemfile", GEMFILE),
                ("Gemfile.lock", GEM_LOCK),
                ("gems.rb", GEMFILE),
                ("gems.locked", GEM_LOCK),
            ] {
                if rel != other {
                    p.insert_text(rel, text);
                }
            }
            p.insert(other, entry);
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{other}: {:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
                "{other}: {codes:?}"
            );
        }
    }

    /// On disk, a twin spelling that `stat`s as a regular file but can't
    /// be read (permission denied) is still a twin: bundler's `File.file?`
    /// sees it, so neither pair is wired (Bugbot on #768).
    #[cfg(unix)]
    #[tokio::test]
    async fn twin_with_an_unreadable_disk_spelling_redirects_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (rel, text) in [
            ("Gemfile", GEMFILE),
            ("Gemfile.lock", GEM_LOCK),
            ("gems.rb", GEMFILE),
            ("gems.locked", GEM_LOCK),
        ] {
            std::fs::write(root.join(rel), text).unwrap();
        }
        let gems_rb = root.join("gems.rb");
        std::fs::set_permissions(&gems_rb, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&gems_rb).is_ok() {
            // Running as root: permissions can't make the read fail.
            return;
        }
        let (_read, done) = gem_rewrite_in(&ProjectView::Disk(root)).await;
        std::fs::set_permissions(&gems_rb, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
            "{codes:?}"
        );
    }

    /// #681: `bundle config set --local mirror.all <url>` sends the
    /// patch-registry `source` block to the mirror, which serves the
    /// upstream gem. The redirect used to be written and attested; now no
    /// gem file is a candidate and the run says why.
    #[tokio::test]
    async fn bundler_mirror_all_redirects_nothing() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text(
            ".bundle/config",
            "---\nBUNDLE_MIRROR__ALL: \"https://artifactory.example/api/gems/rubygems/\"\n",
        );
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_mirror_overrides_source"),
            "{codes:?}"
        );
        assert!(!codes.contains(&"redirect_gem_no_gemfile"), "{codes:?}");
        let w = done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == "redirect_gem_mirror_overrides_source")
            .unwrap();
        assert!(!w.detail.contains("artifactory.example"), "{}", w.detail);
        assert!(
            w.detail.contains("mirror.https://rubygems.org"),
            "{}",
            w.detail
        );
    }

    /// Exact-source and hostname mirrors both refuse intake and confirmation,
    /// with sensitive mirror values excluded from the rendered warning.
    #[tokio::test]
    async fn bundler_mirror_for_the_patch_source_redirects_nothing() {
        for key in [
            format!(
                "BUNDLE_MIRROR__HTTPS://PATCH__TEST/PATCH___REGISTRY/GEM/{FIXTURE_TOKEN}/{FIXTURE_UUID}/"
            ),
            "BUNDLE_MIRROR__PATCH__TEST".to_string(),
            "BUNDLE_MIRROR__PATCH__TEST/".to_string(),
        ] {
            let mut p = MemoryProject::new();
            p.insert_text("Gemfile", GEMFILE);
            p.insert_text("Gemfile.lock", GEM_LOCK);
            p.insert_text(".bundle/config", format!("---\n{key}: \"https://review-user:review-secret@m.example/?token=review-token\"\n"));
            let (read, done) = gem_rewrite(&p).await;
            assert!(!read.files.contains_key("Gemfile"));
            assert!(!read.files.contains_key("Gemfile.lock"));
            assert!(
                done.rewrite.files.is_empty(),
                "{key}: {:?}",
                done.rewrite.files.keys()
            );
            let warning = done
                .rewrite
                .warnings
                .iter()
                .find(|warning| warning.code == "redirect_gem_mirror_overrides_source")
                .unwrap();
            for secret in ["review-user", "review-secret", "review-token"] {
                assert!(!warning.detail.contains(secret));
            }
        }
    }

    /// A mirror scoped to rubygems.org leaves the patch-registry source
    /// alone: the redirect still lands.
    #[tokio::test]
    async fn bundler_mirror_scoped_to_rubygems_org_still_redirects() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text(
            ".bundle/config",
            "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://m.example/\"\n",
        );
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("Gemfile"),
            "{:?} {:?}",
            done.rewrite.files.keys(),
            warning_codes(&done)
        );
        assert!(!warning_codes(&done).contains(&"redirect_gem_mirror_overrides_source"));
    }

    /// `BUNDLE_GEMFILE: Gemfile` beside a `gems.rb`: bundler loads the
    /// Gemfile pair, so that is the pair the redirect edits (the rewriter's
    /// own filename rule would have picked gems.rb).
    #[tokio::test]
    async fn bundle_gemfile_naming_the_gemfile_redirects_it_over_gems_rb() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text("gems.rb", GEMFILE);
        p.insert_text("gems.locked", GEM_LOCK);
        p.insert_text(".bundle/config", "---\nBUNDLE_GEMFILE: \"Gemfile\"\n");
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("Gemfile"),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(!done.rewrite.files.contains_key("gems.rb"));
        assert!(!done.rewrite.files.contains_key("gems.locked"));
    }

    /// Without `BUNDLE_GEMFILE` a lone `gems.rb` pair is still the one
    /// bundler (and the rewriter) picks; a twin is withheld
    /// ([`twin_redirects_nothing_whatever_the_locks_say`]).
    #[tokio::test]
    async fn default_discovery_wires_a_lone_gems_rb() {
        let mut p = MemoryProject::new();
        p.insert_text("gems.rb", GEMFILE);
        p.insert_text("gems.locked", GEM_LOCK);
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("gems.rb"),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(warning_codes(&done)
            .iter()
            .all(|c| !c.starts_with("redirect_gem_twin")));
    }

    /// #333: the Pipenv planner keys a live lock on the `Pipfile` beside
    /// it, so the candidate reads must carry it — read from disk, and kept
    /// as present in memory even when the host has no content for it.
    #[tokio::test]
    async fn the_pipfile_is_read_for_its_presence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Pipfile"), "[packages]\n").unwrap();
        std::fs::write(tmp.path().join("Pipfile.lock"), "{}").unwrap();
        let read =
            read_candidate_files(&ProjectView::Disk(tmp.path()), &BTreeSet::new(), &[]).await;
        assert_eq!(
            read.files.get("Pipfile").map(String::as_str),
            Some("[packages]\n")
        );

        for entry in [MemoryEntry::Symlink, MemoryEntry::Present] {
            let mut p = MemoryProject::new();
            p.insert_text("Pipfile.lock", "{}");
            p.insert("Pipfile", entry.clone());
            let unreadable = match entry {
                MemoryEntry::Present => BTreeSet::from(["Pipfile".to_string()]),
                _ => BTreeSet::new(),
            };
            let read = read_candidate_files(&ProjectView::Memory(&p), &unreadable, &[]).await;
            assert_eq!(
                read.files.get("Pipfile").map(String::as_str),
                Some(""),
                "{entry:?}"
            );
        }

        // Absent stays absent: a lone Pipfile.lock is abandoned.
        let mut p = MemoryProject::new();
        p.insert_text("Pipfile.lock", "{}");
        let read = read_candidate_files(&ProjectView::Memory(&p), &BTreeSet::new(), &[]).await;
        assert!(!read.files.contains_key("Pipfile"));
    }

    #[test]
    fn file_ecosystems_cover_the_rewrite_targets() {
        assert_eq!(file_ecosystem("package-lock.json"), Some("npm"));
        assert_eq!(
            file_ecosystem("common/config/rush/pnpm-lock.yaml"),
            Some("npm")
        );
        assert_eq!(file_ecosystem("tool.py.lock"), Some("pypi"));
        assert_eq!(file_ecosystem("crates/a/Cargo.toml"), Some("cargo"));
        assert_eq!(file_ecosystem("build.gradle"), None);
        assert_eq!(file_ecosystem("Pipfile"), None);
    }

    // ── #492: `sharedWorkspaceLockfile: false` member locks ──

    const MEMBER_UUID: &str = "492a492a-492a-4492-8492-492a492a492a";
    const MEMBER_URL: &str = "https://patch.example/patch/npm/is-number/7.0.0/tok/\
                              492a492a-492a-4492-8492-492a492a492a/is-number-7.0.0.tgz";

    fn is_number_candidates() -> Vec<Candidate> {
        let mut refs: HashMap<String, PackageVendorResult> = HashMap::new();
        refs.insert(
            MEMBER_UUID.into(),
            reference(serde_json::json!({
                "status": "granted",
                "url": MEMBER_URL,
                "purl": "pkg:npm/is-number@7.0.0",
                "artifacts": [{"kind": "tarball", "url": MEMBER_URL,
                               "integrity": {"sha512": "sha512-PATCHED=="}}],
                "registryOverride": null
            })),
        );
        let selected = vec![(
            "pkg:npm/is-number@7.0.0".to_string(),
            MEMBER_UUID.to_string(),
        )];
        candidates_of(&selected, &refs)
    }

    fn v9_member_lock(direct: bool) -> String {
        let importer = if direct {
            "      is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n"
        } else {
            "      to-regex-range:\n        specifier: 5.0.1\n        version: 5.0.1\n"
        };
        format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n{importer}\n\
             packages:\n\n  is-number@7.0.0:\n    resolution: {{integrity: sha512-UPSTREAM==}}\n\n\
             snapshots:\n\n  is-number@7.0.0: {{}}\n"
        )
    }

    const V5_MEMBER_LOCK: &str = "lockfileVersion: 5.4\n\nspecifiers:\n  is-number: 7.0.0\n\n\
        dependencies:\n  is-number: 7.0.0\n\npackages:\n\n  /is-number/7.0.0:\n    \
        resolution: {integrity: sha512-UPSTREAM==}\n    dev: false\n";

    const ROOT_ONLY_LOCK: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";

    fn write_rel(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The issue's layout: a root lock covering only `.` and one lock per
    /// member (`a` direct, `b` transitive).
    fn write_member_workspace(root: &std::path::Path, workspace: &str) {
        write_rel(root, "package.json", r#"{"name":"root","private":true}"#);
        write_rel(root, "pnpm-workspace.yaml", workspace);
        write_rel(root, "pnpm-lock.yaml", ROOT_ONLY_LOCK);
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        write_rel(root, "packages/a/pnpm-lock.yaml", &v9_member_lock(true));
        write_rel(root, "packages/b/package.json", r#"{"name":"b"}"#);
        write_rel(root, "packages/b/pnpm-lock.yaml", &v9_member_lock(false));
        // An installed copy's own lock is never a member's.
        write_rel(
            root,
            "packages/a/node_modules/x/pnpm-lock.yaml",
            &v9_member_lock(true),
        );
    }

    async fn member_rewrite(root: &std::path::Path) -> (CandidateFiles, Rewritten) {
        view_rewrite(&ProjectView::Disk(root)).await
    }

    async fn view_rewrite(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            cargo_outer: &no_cargo_outer,
            maven_selection: &no_maven_selection,
            pnpm_env: &no_env,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = is_number_candidates();
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(view, read.clone(), &candidates, BTreeMap::new(), options).await;
        (read, done)
    }

    const MEMBER_KEYS: [&str; 2] = ["packages/a/pnpm-lock.yaml", "packages/b/pnpm-lock.yaml"];

    #[tokio::test]
    async fn member_locks_are_pinned_when_the_shared_lock_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_eq!(read.pnpm_member_lock_keys, MEMBER_KEYS);
        for key in MEMBER_KEYS {
            let text = done
                .rewrite
                .files
                .get(key)
                .unwrap_or_else(|| panic!("{key} must be pinned: {:?}", done.rewrite.warnings));
            assert!(text.contains(&format!("tarball: {MEMBER_URL}")), "{text}");
        }
        assert!(!done.rewrite.files.contains_key("pnpm-lock.yaml"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        assert!(
            !warning_codes(&done).contains(&"redirect_pnpm_entry_not_found"),
            "{:?}",
            warning_codes(&done)
        );
        // pnpm reads `trustLockfile` from the root file for every member.
        assert_eq!(
            done.rewrite
                .files
                .get(PNPM_WORKSPACE_REL)
                .map(String::as_str),
            Some(format!("{ws}trustLockfile: true\n").as_str())
        );
        assert_eq!(
            done.rewrite.edits.last().map(|e| e.kind.as_str()),
            Some(REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND)
        );

        // HEAL-ON-RERUN: the member locks already pinned, the trust key
        // missing (an opted-out first run): a re-run plans it again.
        for key in MEMBER_KEYS {
            write_rel(tmp.path(), key, &done.rewrite.files[key]);
        }
        let (_, again) = member_rewrite(tmp.path()).await;
        assert!(
            MEMBER_KEYS
                .iter()
                .all(|k| !again.rewrite.files.contains_key(*k)),
            "{:?}",
            again.rewrite.files.keys()
        );
        assert_eq!(again.confirmed.len(), 1);
        assert!(again.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
    }

    /// Members' own locks are governing locks: with a registry served for
    /// the pin, the root workspace file (the one pnpm reads for every
    /// member) routes it, the user's lines intact, and no trust key goes
    /// in. pnpm records the file's overrides in every lock it governs, so
    /// the root lock, which holds no patched package, gets the record too.
    /// A re-run over routed member locks heals a missing workspace edit.
    #[tokio::test]
    async fn member_locks_are_routed_through_the_root_workspace_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            "package.json",
            r#"{"name":"root","private":true,"packageManager":"pnpm@12.22.0"}"#,
        );
        write_rel(
            tmp.path(),
            "packages/a/package.json",
            r#"{"name":"a","dependencies":{"is-number":"7.0.0"}}"#,
        );
        let registry = registry_address(MEMBER_URL);
        let mut candidates = is_number_candidates();
        candidates[0].dep.npm_registry_url = Some(registry.clone());
        let view = ProjectView::Disk(tmp.path());
        let done = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        let alias = "socket-492a492a";
        let record = "overrides:\n  is-number@7.0.0: socket-492a492a:7.0.0\n\nimporters:\n";
        for key in MEMBER_KEYS.into_iter().chain(["pnpm-lock.yaml"]) {
            let lock = done
                .rewrite
                .files
                .get(key)
                .unwrap_or_else(|| panic!("{key}: {:?}", done.rewrite.files.keys()));
            assert!(lock.contains(record), "{key}: {lock}");
        }
        for key in MEMBER_KEYS {
            let lock = &done.rewrite.files[key];
            assert!(
                lock.contains(&format!("  is-number@{alias}:7.0.0:\n")),
                "{key}: {lock}"
            );
        }
        let a = &done.rewrite.files[MEMBER_KEYS[0]];
        assert!(
            a.contains(&format!(
                "        specifier: {alias}:7.0.0\n        version: {alias}:7.0.0\n"
            )),
            "{a}"
        );
        let routed = format!(
            "{ws}namedRegistries:\n  {alias}: {registry}\noverrides:\n  \
             'is-number@7.0.0': '{alias}:7.0.0'\n"
        );
        assert_eq!(workspace_of(&done), Some(routed.as_str()));
        assert!(done.pnpm_named_registries);
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        assert_eq!(
            done.rewrite.edits.last().map(|e| e.kind.as_str()),
            Some(REDIRECT_PNPM_WORKSPACE_OVERRIDE_EDIT_KIND)
        );

        for (key, text) in &done.rewrite.files {
            if key != PNPM_WORKSPACE_REL {
                write_rel(tmp.path(), key, text);
            }
        }
        let healed = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert_eq!(
            healed.rewrite.files.keys().collect::<Vec<_>>(),
            [PNPM_WORKSPACE_REL]
        );
        assert_eq!(workspace_of(&healed), Some(routed.as_str()));
        write_rel(tmp.path(), PNPM_WORKSPACE_REL, &routed);
        let again = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert!(again.rewrite.files.is_empty(), "{:?}", again.rewrite.files);
        assert!(again.pnpm_rerun_only);

        // The project stops qualifying: every lock and the file go back.
        write_rel(
            tmp.path(),
            "package.json",
            r#"{"name":"root","private":true,"packageManager":"pnpm@10.34.6"}"#,
        );
        let back = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert_eq!(
            workspace_of(&back),
            Some(format!("{ws}trustLockfile: true\n").as_str())
        );
        for key in MEMBER_KEYS.into_iter().chain(["pnpm-lock.yaml"]) {
            let lock = &back.rewrite.files[key];
            assert!(!lock.contains("@socket-"), "{key}: {lock}");
            assert!(!lock.contains("overrides:"), "{key}: {lock}");
        }
        assert_eq!(back.rewrite.files["pnpm-lock.yaml"], ROOT_ONLY_LOCK);
        assert!(back.rewrite.files[MEMBER_KEYS[0]]
            .contains("        specifier: 7.0.0\n        version: 7.0.0\n"));
    }

    /// A Bazel hub that stands against a pin in the root lock
    /// ([`crate::bazel::pnpm`]) reads that lock alone. The members' own
    /// locks are read and pinned as without it; the root lock is left out.
    #[tokio::test]
    async fn member_locks_are_pinned_beside_a_root_lock_that_a_bazel_hub_withholds() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            "MODULE.bazel",
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True)\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n",
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        let hidden = crate::bazel::pnpm::HIDDEN;
        assert_eq!(
            read.pnpm_refusal.as_ref().map(|w| w.code.as_str()),
            Some(hidden)
        );
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        assert_eq!(read.pnpm_member_lock_keys, MEMBER_KEYS);
        for key in MEMBER_KEYS {
            let text = done
                .rewrite
                .files
                .get(key)
                .unwrap_or_else(|| panic!("{key} must be pinned: {:?}", done.rewrite.warnings));
            assert!(text.contains(&format!("tarball: {MEMBER_URL}")), "{text}");
        }
        assert!(!done.rewrite.files.contains_key("pnpm-lock.yaml"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        assert!(
            warning_codes(&done).contains(&hidden),
            "{:?}",
            warning_codes(&done)
        );
    }

    use crate::bazel::pnpm::fixtures::{rules_js_hub, HIDING_HUB_CALL};

    /// A pnpm lock that a rules_js hub of the Bazel workspace reads is not
    /// routed through a named registry, whatever the patch service offers
    /// and whatever pnpm the project pins: with `update_pnpm_lock` the hub
    /// runs a pnpm of its own, which sees pnpm-workspace.yaml only where the
    /// call lists it and may be too old to read its registries, and no
    /// Bazel leg builds a routed lock that way. The project gets the files of a
    /// run that is offered no registry, byte for byte, which the Bazel legs
    /// build, and the warning names the call. A hub that reads another lock
    /// changes nothing. A project routed before the hub was there leaves
    /// the route whole: the locks and the workspace file together.
    #[tokio::test]
    async fn a_lock_that_a_bazel_hub_reads_is_not_routed() {
        let candidates = [left_pad_registry_candidate()];
        let users = "# the project's own\npackages:\n  - '.'\n";
        let hubs = [
            // Read by the lock reader of rules_js alone.
            "pnpm_lock = \"//:pnpm-lock.yaml\"",
            // Kept up to date by a pnpm that is shown the workspace file.
            "pnpm_lock = \"//:pnpm-lock.yaml\", data = [\"//:pnpm-workspace.yaml\"], \
             update_pnpm_lock = True",
            // A lock that is not written out may be this one.
            "pnpm_lock = LOCK",
        ];
        for call in hubs {
            let mut project = pnpm12_project(LEFT_PAD_V9_LOCK);
            project.insert_text(PNPM_WORKSPACE_REL, users);
            project.insert_text("MODULE.bazel", rules_js_hub(call));
            let unoffered = registry_rewrite(&project, &[left_pad_candidate()]).await;
            let done = registry_rewrite(&project, &candidates).await;
            assert!(!done.pnpm_named_registries, "{call}");
            assert_eq!(done.rewrite.files, unoffered.rewrite.files, "{call}");
            assert_eq!(
                workspace_of(&done),
                Some(format!("{users}trustLockfile: true\n").as_str()),
                "{call}"
            );
            let lock = lock_of(&done).expect("the lock, pinned");
            assert!(
                lock.contains(&format!("tarball: {}", left_pad_url()))
                    && !lock.contains("@socket-")
                    && !lock.contains("overrides:"),
                "{call}: {lock}"
            );
            assert_eq!(done.confirmed.len(), 1, "{call}");
            assert!(
                !warning_codes(&done).contains(&crate::bazel::pnpm::HIDDEN),
                "{call}"
            );
            let detail = pnpm_trust_detail(&done);
            assert!(
                detail.contains(
                    "Per-package registry verification was not set up because a Bazel hub \
                     reads the pnpm lock (MODULE.bazel:3), and a lock that a hub reads is not \
                     routed yet: the pnpm a hub runs for `update_pnpm_lock` may not read the \
                     registries in pnpm-workspace.yaml; the hosted patches rely on \
                     `trustLockfile` instead"
                ),
                "{call}: {detail}"
            );
            // Not offered a registry, the run says nothing of the hub.
            assert!(
                !pnpm_trust_detail(&unoffered).contains("Bazel"),
                "{call}: {}",
                pnpm_trust_detail(&unoffered)
            );
        }

        let mut elsewhere = pnpm12_project(LEFT_PAD_V9_LOCK);
        elsewhere.insert_text(
            "MODULE.bazel",
            rules_js_hub("pnpm_lock = \"//tools:pnpm-lock.yaml\""),
        );
        let done = registry_rewrite(&elsewhere, &candidates).await;
        assert!(done.pnpm_named_registries);
        assert_eq!(
            workspace_of(&done),
            Some(left_pad_routed_workspace().as_str())
        );

        let mut root = pnpm12_project(LEFT_PAD_V9_LOCK);
        root.insert_text(PNPM_WORKSPACE_REL, users);
        let first = registry_rewrite(&root, &candidates).await;
        assert!(first.pnpm_named_registries);
        let mut routed = after(&root, &first);
        routed.insert_text("MODULE.bazel", rules_js_hub(hubs[0]));
        let done = registry_rewrite(&routed, &candidates).await;
        assert!(!done.pnpm_named_registries);
        assert_eq!(
            workspace_of(&done),
            Some(format!("{users}trustLockfile: true\n").as_str())
        );
        let lock = lock_of(&done).expect("the lock, back in the plain shape");
        assert!(
            lock.contains("\n  left-pad@1.3.0:\n")
                && lock.contains(&format!("tarball: {}", left_pad_url()))
                && !lock.contains("@socket-")
                && !lock.contains("overrides:"),
            "{lock}"
        );
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("a Bazel hub reads the pnpm lock (MODULE.bazel:3)")
                && detail.contains("An earlier run routed the hosted patches"),
            "{detail}"
        );
    }

    /// In a Bazel workspace the route is taken only where it is certain
    /// that no hub reads a governing lock. A hub the reader cannot see
    /// leaves that open: one a `WORKSPACE` file defines, one in a file that
    /// `MODULE.bazel` includes and that was not handed in, one behind a
    /// proxy of the extension that is handed to something else. Each keeps
    /// the project on the pin of a run that is offered no registry, and
    /// the warning names what was not read. A workspace that was read
    /// whole and has no hub of the lock is routed.
    #[tokio::test]
    async fn a_hub_the_reader_may_not_have_seen_blocks_the_route() {
        let candidates = [left_pad_registry_candidate()];
        let workspace_hub =
            "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
             npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
             update_pnpm_lock = True)\n";
        let cases: [(&str, &str, &str); 3] = [
            (
                "WORKSPACE",
                workspace_hub,
                "(WORKSPACE defines repositories of its own",
            ),
            (
                "MODULE.bazel",
                "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
                 include(\"//tools:npm.MODULE.bazel\")\n",
                "(tools/npm.MODULE.bazel: ",
            ),
            (
                "MODULE.bazel",
                "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
                 npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
                 hubs(npm)\n",
                "(MODULE.bazel:3: ",
            ),
        ];
        for (file, text, named) in cases {
            let mut project = pnpm12_project(LEFT_PAD_V9_LOCK);
            project.insert_text(file, text);
            let unoffered = registry_rewrite(&project, &[left_pad_candidate()]).await;
            let done = registry_rewrite(&project, &candidates).await;
            assert!(!done.pnpm_named_registries, "{file}: {text}");
            assert_eq!(done.rewrite.files, unoffered.rewrite.files, "{file}");
            assert_eq!(done.confirmed.len(), 1, "{file}");
            let detail = pnpm_trust_detail(&done);
            let said = format!("because a Bazel hub may read the pnpm lock {named}");
            assert!(detail.contains(&said), "{file}: {detail}");
            assert!(
                !pnpm_trust_detail(&unoffered).contains("Bazel"),
                "{file}: {}",
                pnpm_trust_detail(&unoffered)
            );
        }

        // Read whole, and no hub of this lock: a workspace with no rules_js
        // at all, and one whose `WORKSPACE` file only names it.
        let mut plain = pnpm12_project(LEFT_PAD_V9_LOCK);
        plain.insert_text(
            "MODULE.bazel",
            "bazel_dep(name = \"rules_java\", version = \"8.0.0\")\n",
        );
        plain.insert_text("WORKSPACE", "workspace(name = \"app\")\n");
        let done = registry_rewrite(&plain, &candidates).await;
        assert!(done.pnpm_named_registries);
        assert_eq!(
            workspace_of(&done),
            Some(left_pad_routed_workspace().as_str())
        );
    }

    /// A project below the root of its Bazel workspace is told where the
    /// hub's call is: in a file of that root, which a run in the project's
    /// directory has no file of that name beside. The warning says that its
    /// paths are from the root of the Bazel workspace, for a call and for
    /// what was not read alike.
    #[tokio::test]
    async fn a_project_below_the_bazel_root_is_told_where_the_hub_is() {
        let candidates = [left_pad_registry_candidate()];
        let from = ", with paths from the root of the Bazel workspace)";
        for (module, said) in [
            (
                rules_js_hub("pnpm_lock = \"//apps/web:pnpm-lock.yaml\""),
                format!("a Bazel hub reads the pnpm lock (MODULE.bazel:3{from}"),
            ),
            (
                "include(\"//tools:npm.MODULE.bazel\")\n".to_string(),
                format!(
                    "a Bazel hub may read the pnpm lock (tools/npm.MODULE.bazel: it does not \
                     exist; MODULE.bazel:1 includes it{from}"
                ),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_rel(tmp.path(), ".git/HEAD", "ref: refs/heads/main\n");
            write_rel(tmp.path(), "MODULE.bazel", &module);
            write_rel(tmp.path(), "apps/web/package.json", PNPM_12_MANIFEST);
            write_rel(tmp.path(), "apps/web/pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
            let project = tmp.path().join("apps/web");
            let done = golden_rewrite(&project, &candidates).await;
            assert!(!done.pnpm_named_registries, "{module}");
            let detail = pnpm_trust_detail(&done);
            assert!(detail.contains(&said), "{module}: {detail}");
        }
    }

    /// Where a hub hides pnpm-workspace.yaml from the pnpm 11 it runs
    /// ([`crate::bazel::pnpm::hidden`]), that answer comes first, while the
    /// files are read: the root lock is not part of the run, so nothing is
    /// pinned in it and nothing routed, with a registry offered or not.
    /// A project routed before the hub was there keeps its lock and its
    /// workspace file exactly as they are, in step with each other, on a
    /// run with its patch and on one that is granted nothing.
    #[tokio::test]
    async fn a_lock_that_a_bazel_hub_withholds_is_neither_pinned_nor_routed() {
        let candidates = [left_pad_registry_candidate()];
        let hub = rules_js_hub(HIDING_HUB_CALL);
        let mut fresh = pnpm12_project(LEFT_PAD_V9_LOCK);
        fresh.insert_text("MODULE.bazel", hub.as_str());
        let done = registry_rewrite(&fresh, &candidates).await;
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        assert!(!done.pnpm_named_registries);
        assert!(
            warning_codes(&done).contains(&crate::bazel::pnpm::HIDDEN),
            "{:?}",
            warning_codes(&done)
        );

        let root = pnpm12_project(LEFT_PAD_V9_LOCK);
        let first = registry_rewrite(&root, &candidates).await;
        assert!(first.pnpm_named_registries);
        let mut routed = after(&root, &first);
        routed.insert_text("MODULE.bazel", hub.as_str());
        for granted in [&candidates[..], &[]] {
            let done = pnpm_rewrite_from(
                &ProjectView::Memory(&routed),
                granted,
                true,
                false,
                &no_env,
                vec!["https://patch.test".to_string()],
            )
            .await;
            assert!(
                done.rewrite.files.is_empty() && done.rewrite.edits.is_empty(),
                "{} granted: {:?}",
                granted.len(),
                done.rewrite.files.keys()
            );
            assert!(!done.pnpm_workspace_emptied);
        }
    }

    /// What a run does with a lock that it leaves to a Bazel hub does not
    /// turn on whether it was granted an npm patch. The project was routed,
    /// its routed dependency left the lock, and the hub lists the
    /// pnpm-workspace.yaml the route created: a run that took the unused
    /// entries out would delete that file under the call that names it. A
    /// run with a patch for another package leaves the root lock to the
    /// hub and changes nothing; so does a run that is granted nothing.
    #[tokio::test]
    async fn a_run_granted_no_npm_patch_leaves_the_lock_to_the_hub_too() {
        const PLAIN: &str = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      \
             is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n\npackages:\n  \
             is-number@7.0.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n\n\
             snapshots:\n  is-number@7.0.0: {}\n";
        let origins = || vec!["https://patch.test".to_string()];
        let mut project = pnpm12_project(&PLAIN.replace(
            "importers:\n",
            &format!("overrides:\n  left-pad@1.3.0: {LEFT_PAD_ALIAS}:1.3.0\n\nimporters:\n"),
        ));
        project.insert_text(PNPM_WORKSPACE_REL, left_pad_routed_workspace());
        // Without a hub the unused route goes, and the file with it.
        let view = ProjectView::Memory(&project);
        let tidied = pnpm_rewrite_from(&view, &[], true, false, &no_env, origins()).await;
        assert_eq!(lock_of(&tidied), Some(PLAIN));
        assert!(tidied.pnpm_workspace_emptied);

        project.insert_text(
            "MODULE.bazel",
            rules_js_hub(
                "pnpm_lock = \"//:pnpm-lock.yaml\", data = [\"//:pnpm-workspace.yaml\"], \
                 update_pnpm_lock = True",
            ),
        );
        let view = ProjectView::Memory(&project);
        let with = [is_number_candidate(true)];
        for granted in [&with[..], &[]] {
            let done = pnpm_rewrite_from(&view, granted, true, false, &no_env, origins()).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{} granted: {:?}",
                granted.len(),
                done.rewrite.files.keys()
            );
            assert!(!done.pnpm_workspace_emptied, "{} granted", granted.len());
            assert!(
                warning_codes(&done).contains(&crate::bazel::pnpm::HIDDEN),
                "{} granted: {:?}",
                granted.len(),
                warning_codes(&done)
            );
        }
    }

    /// The members' own locks beside a root lock that a hub withholds are
    /// pinned as main pins them, on `trustLockfile`, also where the patch
    /// service offers a registry and the project pins pnpm 12: the route's
    /// overrides are recorded in every lock pnpm-workspace.yaml governs,
    /// the root lock among them, and that one is not written. The warning
    /// says a hub reads the lock. Members an earlier run routed stay routed
    /// as they were: nothing of the route leaves the workspace file or the
    /// members' locks while the root lock keeps its record of it.
    #[tokio::test]
    async fn member_locks_beside_a_root_lock_that_a_bazel_hub_withholds_are_not_routed() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            "package.json",
            r#"{"name":"root","private":true,"packageManager":"pnpm@12.22.0"}"#,
        );
        write_rel(
            tmp.path(),
            "packages/a/package.json",
            r#"{"name":"a","dependencies":{"is-number":"7.0.0"}}"#,
        );
        let mut candidates = is_number_candidates();
        candidates[0].dep.npm_registry_url = Some(registry_address(MEMBER_URL));
        let view = ProjectView::Disk(tmp.path());

        // Routed, as without Bazel.
        let routed = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert!(routed.pnpm_named_registries);
        let all = MEMBER_KEYS.into_iter().chain(["pnpm-lock.yaml"]);
        assert!(all
            .clone()
            .all(|key| routed.rewrite.files.contains_key(key)));

        // The hub, in the project as it was: pinned, not routed.
        write_rel(tmp.path(), "MODULE.bazel", &rules_js_hub(HIDING_HUB_CALL));
        let done = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert!(!done.pnpm_named_registries);
        assert!(!done.rewrite.files.contains_key("pnpm-lock.yaml"));
        for key in MEMBER_KEYS {
            let lock = &done.rewrite.files[key];
            assert!(
                lock.contains(&format!("tarball: {MEMBER_URL}"))
                    && !lock.contains("@socket-")
                    && !lock.contains("overrides:"),
                "{key}: {lock}"
            );
        }
        assert_eq!(
            workspace_of(&done),
            Some(format!("{ws}trustLockfile: true\n").as_str())
        );
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        assert!(warning_codes(&done).contains(&crate::bazel::pnpm::HIDDEN));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("a Bazel hub reads the pnpm lock (MODULE.bazel:3)"),
            "{detail}"
        );

        // The hub, in the project the first run routed: every lock and the
        // workspace file stay as that run wrote them, byte for byte. The
        // registries still verify the routed releases, so no
        // `trustLockfile` is added, which would switch that off.
        commit(tmp.path(), &routed);
        for granted in [&candidates[..], &[]] {
            let origins = vec!["https://patch.example".to_string()];
            let done = pnpm_rewrite_from(&view, granted, true, false, &no_env, origins).await;
            assert!(
                done.rewrite.files.is_empty() && done.rewrite.edits.is_empty(),
                "{} granted: {:?}",
                granted.len(),
                done.rewrite.files.keys()
            );
        }
        let done = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert!(done.pnpm_named_registries && done.pnpm_rerun_only);
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains(
                "Per-package registry verification would not be set up for this project now, \
                 because a Bazel hub reads the pnpm lock (MODULE.bazel:3)"
            ) && detail.contains("what an earlier run set up was left as it is")
                && detail.contains("could not be converted back (the root pnpm lock"),
            "{detail}"
        );
        assert!(!detail.contains("rely on `trustLockfile`"), "{detail}");

        // A new pin beside the routed one is in the plain shape, which pnpm
        // takes only with `trustLockfile`: that run writes the key, after
        // the route's entries, and leaves the routed release routed.
        write_rel(
            tmp.path(),
            "packages/b/package.json",
            r#"{"name":"b","dependencies":{"left-pad":"1.3.0"}}"#,
        );
        write_rel(tmp.path(), MEMBER_KEYS[1], LEFT_PAD_V9_LOCK);
        let mut both = candidates.clone();
        both.push(left_pad_registry_candidate());
        let origins = vec!["https://patch.example".to_string()];
        let done = pnpm_rewrite_from(&view, &both, true, false, &no_env, origins).await;
        let routed_ws = &routed.rewrite.files[PNPM_WORKSPACE_REL];
        assert_eq!(
            workspace_of(&done),
            Some(format!("{routed_ws}trustLockfile: true\n").as_str())
        );
        assert_eq!(
            done.rewrite.files.keys().collect::<Vec<_>>(),
            [MEMBER_KEYS[1], PNPM_WORKSPACE_REL]
        );
        assert!(
            done.rewrite.files[MEMBER_KEYS[1]].contains(&format!("tarball: {}", left_pad_url()))
        );
    }

    /// What is left of a route can be in a member's own lock alone, with the
    /// root pnpm-workspace.yaml and the root lock holding nothing of it (the
    /// golden workspace `member-locks`, the route taken out by hand
    /// everywhere but in one member's lock). The probe that decides whether
    /// a command looks for a route at all finds it there. A run that is
    /// granted nothing then takes out a record no lock uses any more, and
    /// leaves a release a member's lock still routes as it is; a run that
    /// is granted the patch puts the whole route back around that lock.
    #[tokio::test]
    async fn what_a_route_left_in_a_members_own_lock_is_found() {
        use crate::formats::pnpm::registry_alias::fixtures;
        const CASE: &str = "member-locks";
        const A: &str = "packages/a/pnpm-lock.yaml";
        const B: &str = "packages/b/pnpm-lock.yaml";
        let expected =
            |rel: &str| fixtures::read(CASE, &format!("expected/{rel}")).expect("a file");
        let pristine: BTreeMap<String, String> = fixtures::project(CASE).into_iter().collect();
        let origins = || vec!["https://patch.test".to_string()];
        let project = |routed: &str| {
            let project = golden_project(CASE);
            write_rel(project.path(), routed, &expected(routed));
            project
        };

        // Never routed: nothing to look for.
        let plain = golden_project(CASE);
        assert!(!pnpm_route_present(plain.path()).await);

        // A record that no lock of the workspace uses any more.
        let stale = project(B);
        assert!(pnpm_route_present(stale.path()).await);
        let view = ProjectView::Disk(stale.path());
        let done = pnpm_rewrite_from(&view, &[], true, false, &no_env, origins()).await;
        assert_eq!(
            done.rewrite.files.keys().collect::<Vec<_>>(),
            [B],
            "{:?}",
            done.rewrite.edits
        );
        assert_eq!(done.rewrite.files[B], pristine[B]);

        // A release a member's lock still routes.
        let kept = project(A);
        assert!(pnpm_route_present(kept.path()).await);
        let view = ProjectView::Disk(kept.path());
        let done = pnpm_rewrite_from(&view, &[], true, false, &no_env, origins()).await;
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let healed = golden_rewrite(kept.path(), &golden_candidates(CASE, true)).await;
        assert!(healed.pnpm_named_registries);
        commit(kept.path(), &healed);
        for rel in ["pnpm-workspace.yaml", "pnpm-lock.yaml", A, B] {
            assert_eq!(
                std::fs::read_to_string(kept.path().join(rel)).unwrap(),
                expected(rel),
                "{rel}"
            );
        }
    }

    /// The plan takes what Bazel says of the pnpm locks from the files as
    /// they were read ([`CandidateFiles::pnpm_bazel`]) and reads nothing of
    /// Bazel itself. A root lock that a hub keeps out of the run blocks the
    /// route by that alone, also where no call was read as the hub's: the
    /// members' own locks are pinned on `trustLockfile`, and the warning
    /// says the root lock is why. A pnpm refusal of another kind is no
    /// such answer.
    #[tokio::test]
    async fn a_root_lock_kept_out_of_the_run_blocks_the_route_by_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            "package.json",
            r#"{"name":"root","private":true,"packageManager":"pnpm@12.22.0"}"#,
        );
        write_rel(
            tmp.path(),
            "packages/a/package.json",
            r#"{"name":"a","dependencies":{"is-number":"7.0.0"}}"#,
        );
        let mut candidates = is_number_candidates();
        candidates[0].dep.npm_registry_url = Some(registry_address(MEMBER_URL));
        let view = ProjectView::Disk(tmp.path());
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        // No Bazel workspace: nothing was read of one.
        assert_eq!(read.pnpm_bazel, crate::bazel::pnpm::Hubs::default());
        let hidden = RewriteWarning {
            code: crate::bazel::pnpm::HIDDEN.into(),
            detail: "a hub keeps pnpm-lock.yaml up to date".into(),
        };
        let mut withheld = read.clone();
        withhold_root_pnpm_locks(&mut withheld, hidden.clone());
        withheld.pnpm_bazel.hidden = Some(hidden);
        let done = pnpm_rewrite_read(
            &view,
            withheld,
            &candidates,
            true,
            false,
            &no_env,
            Vec::new(),
        )
        .await;
        assert!(
            !done.pnpm_named_registries,
            "{:?}",
            done.rewrite.files.keys()
        );
        for key in MEMBER_KEYS {
            let lock = &done.rewrite.files[key];
            assert!(
                lock.contains(&format!("tarball: {MEMBER_URL}"))
                    && !lock.contains("@socket-")
                    && !lock.contains("overrides:"),
                "{key}: {lock}"
            );
        }
        assert_eq!(
            workspace_of(&done),
            Some(format!("{ws}trustLockfile: true\n").as_str())
        );
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains(crate::hosted::guidance::PNPM_REGISTRY_BAZEL_WITHHELD),
            "{detail}"
        );

        // The same files without that answer are routed.
        let done =
            pnpm_rewrite_read(&view, read, &candidates, true, false, &no_env, Vec::new()).await;
        assert!(done.pnpm_named_registries);
    }

    /// A run that is granted no patch tidies a route from every lock the
    /// workspace file governs. Members' own locks that still route a
    /// release keep the override and the registry they use: the root lock,
    /// which holds no patched package, is not the only one asked.
    #[tokio::test]
    async fn a_run_granted_nothing_keeps_what_the_members_own_locks_route() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            "package.json",
            r#"{"name":"root","private":true,"packageManager":"pnpm@12.22.0"}"#,
        );
        write_rel(
            tmp.path(),
            "packages/a/package.json",
            r#"{"name":"a","dependencies":{"is-number":"7.0.0"}}"#,
        );
        let mut candidates = is_number_candidates();
        candidates[0].dep.npm_registry_url = Some(registry_address(MEMBER_URL));
        let view = ProjectView::Disk(tmp.path());
        let routed = pnpm_rewrite(&view, &candidates, true, false, &no_env).await;
        assert!(routed.pnpm_named_registries);
        commit(tmp.path(), &routed);

        let origins = vec!["https://patch.example".to_string()];
        let done = pnpm_rewrite_from(&view, &[], true, false, &no_env, origins.clone()).await;
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(done.rewrite.edits.is_empty());

        // Once no member's lock routes the release, the route goes whole.
        write_rel(tmp.path(), MEMBER_KEYS[0], &v9_member_lock(true));
        write_rel(tmp.path(), MEMBER_KEYS[1], &v9_member_lock(false));
        let done = pnpm_rewrite_from(&view, &[], true, false, &no_env, origins).await;
        assert_eq!(workspace_of(&done), Some(ws));
        assert_eq!(lock_of(&done), Some(ROOT_ONLY_LOCK));
    }

    #[tokio::test]
    async fn member_locks_are_ignored_while_the_root_lock_is_shared() {
        // The default shared lock: member locks are stale leftovers.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(tmp.path(), "packages:\n  - 'packages/*'\n");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
        assert!(MEMBER_KEYS.iter().all(|k| !read.files.contains_key(*k)));
        assert!(done.confirmed.is_empty());

        // The setting says off, but the root lock lists member importers:
        // pnpm installs from it, so the member locks are still stale.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(
            tmp.path(),
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a: {}\n",
        );
        let (read, _) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
    }

    /// pnpm 7 with `shared-workspace-lockfile=false` in `.npmrc` writes no
    /// root lock at all, only the members' (lockfile 5.4).
    #[tokio::test]
    async fn npmrc_member_locks_without_a_root_lock_are_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_rel(root, "package.json", r#"{"name":"root","private":true}"#);
        write_rel(root, "pnpm-workspace.yaml", "packages:\n  - packages/*\n");
        write_rel(root, ".npmrc", "shared-workspace-lockfile=false\n");
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        write_rel(root, "packages/a/pnpm-lock.yaml", V5_MEMBER_LOCK);
        let (read, done) = member_rewrite(root).await;
        assert_eq!(
            read.pnpm_member_lock_keys,
            vec!["packages/a/pnpm-lock.yaml"]
        );
        let text = &done.rewrite.files["packages/a/pnpm-lock.yaml"];
        assert!(text.contains(MEMBER_URL), "{text}");
        assert_eq!(done.confirmed.len(), 1);
        let codes = warning_codes(&done);
        assert!(
            !codes.contains(&"redirect_pnpm_no_lockfile")
                && !codes.contains(&"redirect_npm_no_lockfile"),
            "{codes:?}"
        );
        // A legacy lock gets no trust config.
        assert!(!done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
    }

    /// Members that cannot be listed refuse instead of pinning the root
    /// lock alone (which no member installs from) and reporting success.
    #[tokio::test]
    async fn unlisted_member_locks_refuse_every_pnpm_pin() {
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages: *members\nsharedWorkspaceLockfile: false\n",
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty());
        let codes = warning_codes(&done);
        assert!(codes.contains(&PNPM_MEMBER_LOCKS_UNRESOLVED), "{codes:?}");
        assert!(!codes.contains(&"redirect_npm_no_lockfile"), "{codes:?}");

        // A member lock that cannot be read refuses the whole set.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        std::fs::write(tmp.path().join("packages/b/pnpm-lock.yaml"), [0xff, 0xfe]).unwrap();
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
        assert!(MEMBER_KEYS.iter().all(|k| !read.files.contains_key(*k)));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty());
        assert!(warning_codes(&done).contains(&PNPM_MEMBER_LOCKS_UNRESOLVED));

        // No member lock and no root lock: not "run `pnpm install`".
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_rel(root, "pnpm-workspace.yaml", "packages:\n  - packages/*\n");
        write_rel(root, ".npmrc", "shared-workspace-lockfile=false\n");
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        let (_, done) = member_rewrite(root).await;
        let codes = warning_codes(&done);
        assert!(codes.contains(&PNPM_MEMBER_LOCKS_UNRESOLVED), "{codes:?}");
        assert!(!codes.contains(&"redirect_pnpm_no_lockfile"), "{codes:?}");
    }

    const BRANCH_LOCK: &str = "pnpm-lock.feature.yaml";
    const BRANCH_WS: &str = "packages:\n  - '.'\ngitBranchLockfile: true\n";

    /// The issue's layout: `pnpm-lock.yaml` as committed on main, and the
    /// lock pnpm writes for the `feature` branch under `gitBranchLockfile`.
    fn write_branch_lock_project(root: &std::path::Path, workspace: &str, root_lock: bool) {
        write_rel(
            root,
            "package.json",
            r#"{"name":"app","dependencies":{"is-number":"7.0.0"}}"#,
        );
        write_rel(root, "pnpm-workspace.yaml", workspace);
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        if root_lock {
            write_rel(root, "pnpm-lock.yaml", &v9_member_lock(true));
        }
        write_rel(root, BRANCH_LOCK, &v9_member_lock(true));
    }

    fn assert_branch_lock_refused(read: &CandidateFiles, done: &Rewritten) {
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        let codes = warning_codes(done);
        assert!(codes.contains(&PNPM_GIT_BRANCH_LOCKFILE), "{codes:?}");
        assert!(
            !codes.contains(&"redirect_pnpm_no_lockfile")
                && !codes.contains(&"redirect_npm_no_lockfile"),
            "{codes:?}"
        );
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_GIT_BRANCH_LOCKFILE)
            .unwrap()
            .detail;
        assert!(
            detail.contains(BRANCH_LOCK) && detail.contains("--merge-git-branch-lockfiles"),
            "{detail}"
        );
    }

    /// `gitBranchLockfile` with a branch lock beside `pnpm-lock.yaml`: pnpm
    /// installs the branch from the branch lock, so pinning the stale
    /// `pnpm-lock.yaml` would confirm a pin nothing installs (#556).
    #[tokio::test]
    async fn a_git_branch_lock_refuses_the_stale_root_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), BRANCH_WS, true);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);

        // pnpm 10 and older read the setting from `.npmrc`.
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "packages:\n  - '.'\n", true);
        write_rel(tmp.path(), ".npmrc", "git-branch-lockfile=true\n");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);

        // The in-memory engine refuses the same project.
        let mut project = MemoryProject::new();
        project.insert_text("package.json", r#"{"name":"app"}"#);
        project.insert_text("pnpm-workspace.yaml", BRANCH_WS);
        project.insert_text("pnpm-lock.yaml", v9_member_lock(true));
        project.insert_text(BRANCH_LOCK, v9_member_lock(true));
        let (read, done) = view_rewrite(&ProjectView::Memory(&project)).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// Only the branch lock: not "run `pnpm install`", which just rewrites
    /// the branch lock again (#556).
    #[tokio::test]
    async fn a_lone_git_branch_lock_is_not_a_missing_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), BRANCH_WS, false);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// Under `sharedWorkspaceLockfile: false` pnpm looks for the branch
    /// lock in every member's directory too: a member whose deps changed on
    /// the branch installs from `<member>/pnpm-lock.<branch>.yaml`, so its
    /// `pnpm-lock.yaml` is stale and no member lock is pinned (#492 x #556).
    #[tokio::test]
    async fn a_member_git_branch_lock_refuses_the_stale_member_locks() {
        // pnpm 8+: the settings in the YAML, a root lock covering `.` only,
        // and no branch lock at the root.
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n\
                  gitBranchLockfile: true\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
        assert!(read.pnpm_member_lock_keys.is_empty());
        for key in MEMBER_KEYS {
            assert!(!read.files.contains_key(key), "{key}");
        }

        // pnpm 7: both settings in `.npmrc` and no root lock at all.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(tmp.path(), "packages:\n  - 'packages/*'\n");
        std::fs::remove_file(tmp.path().join("pnpm-lock.yaml")).unwrap();
        write_rel(
            tmp.path(),
            ".npmrc",
            "shared-workspace-lockfile=false\ngit-branch-lockfile=true\n",
        );
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
        assert!(read.pnpm_member_lock_keys.is_empty());

        // The setting off: the member branch lock is a stray file.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_eq!(read.pnpm_member_lock_keys, MEMBER_KEYS);
        assert!(!warning_codes(&done).contains(&PNPM_GIT_BRANCH_LOCKFILE));
    }

    /// Run from a member, the setting lives in the ancestor
    /// `pnpm-workspace.yaml` pnpm reads it from, not in the member.
    #[tokio::test]
    async fn a_member_run_reads_the_setting_from_the_governing_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n\
                  gitBranchLockfile: true\n";
        write_member_workspace(tmp.path(), ws);
        let member = tmp.path().join("packages/a");
        write_rel(&member, BRANCH_LOCK, &v9_member_lock(true));
        let (read, done) = member_rewrite(&member).await;
        assert_branch_lock_refused(&read, &done);
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_GIT_BRANCH_LOCKFILE)
            .unwrap()
            .detail;
        assert!(detail.contains("gitBranchLockfile: true"), "{detail}");

        // pnpm 10 and older: the `.npmrc` beside the ancestor file.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(tmp.path(), ".npmrc", "git-branch-lockfile=true\n");
        let member = tmp.path().join("packages/a");
        write_rel(&member, BRANCH_LOCK, &v9_member_lock(true));
        let (read, done) = member_rewrite(&member).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// The setting alone (no branch lock: main, or a branch whose deps never
    /// changed) installs from `pnpm-lock.yaml`, so it is pinned as usual; so
    /// is a stray branch lock while the setting is off.
    #[tokio::test]
    async fn the_root_lock_is_pinned_without_a_live_git_branch_lock() {
        for (workspace, branch_lock) in [
            (BRANCH_WS, false),
            ("packages:\n  - '.'\ngitBranchLockfile: false\n", true),
            ("packages:\n  - '.'\n", true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_branch_lock_project(tmp.path(), workspace, true);
            if !branch_lock {
                std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
            }
            let (_, done) = member_rewrite(tmp.path()).await;
            let text = done
                .rewrite
                .files
                .get("pnpm-lock.yaml")
                .unwrap_or_else(|| panic!("{workspace}: {:?}", done.rewrite.warnings));
            assert!(text.contains(MEMBER_URL), "{text}");
            assert_eq!(done.confirmed.len(), 1, "{workspace}");
            assert!(!warning_codes(&done).contains(&PNPM_GIT_BRANCH_LOCKFILE));
            assert!(!done.rewrite.files.contains_key(BRANCH_LOCK));
        }
    }

    fn assert_disabled_lockfile_refused(read: &CandidateFiles, done: &Rewritten, source: &str) {
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        // Neither the lock nor a `trustLockfile` key is written.
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        let codes = warning_codes(done);
        assert!(codes.contains(&PNPM_LOCKFILE_DISABLED), "{codes:?}");
        assert!(
            !codes.contains(&"redirect_pnpm_no_lockfile")
                && !codes.contains(&"redirect_npm_no_lockfile")
                && !codes.contains(&"redirect_pnpm_trust_lockfile"),
            "{codes:?}"
        );
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_LOCKFILE_DISABLED)
            .unwrap()
            .detail;
        assert!(
            detail.contains(source) && detail.contains("--mode vendored"),
            "{detail}"
        );
    }

    /// pnpm's `lockfile` setting off (#1074): pnpm never reads the
    /// committed lock and installs the upstream package, so pinning it
    /// would confirm (and VEX attest) a patch no install applies. pnpm 11+
    /// read the setting from `pnpm-workspace.yaml`, pnpm 9/10 from
    /// `.npmrc`.
    #[tokio::test]
    async fn a_disabled_lockfile_is_never_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "lockfile: false\n", true);
        std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_disabled_lockfile_refused(&read, &done, "`lockfile: false` in pnpm-workspace.yaml");

        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "packages:\n  - '.'\n", true);
        std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
        std::fs::remove_file(tmp.path().join("pnpm-workspace.yaml")).unwrap();
        write_rel(tmp.path(), ".npmrc", "lockfile=false\n");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_disabled_lockfile_refused(&read, &done, "`lockfile=false` in .npmrc");

        // The in-memory engine refuses the same project.
        let mut project = MemoryProject::new();
        project.insert_text("package.json", r#"{"name":"app"}"#);
        project.insert_text("pnpm-workspace.yaml", "lockfile: false\n");
        project.insert_text("pnpm-lock.yaml", v9_member_lock(true));
        let (read, done) = view_rewrite(&ProjectView::Memory(&project)).await;
        assert_disabled_lockfile_refused(&read, &done, "`lockfile: false` in pnpm-workspace.yaml");
    }

    /// With the lock off, pnpm reads no member's own lock either
    /// (`sharedWorkspaceLockfile: false`, #492): none is pinned.
    #[tokio::test]
    async fn a_disabled_lockfile_pins_no_member_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\nlockfile: false\n",
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
        assert!(!read.files.keys().any(|k| k.ends_with("pnpm-lock.yaml")));
        assert_disabled_lockfile_refused(&read, &done, "`lockfile: false` in pnpm-workspace.yaml");
    }

    /// The setting on (or unset) keeps the lock pinned as usual, and a
    /// YAML value pnpm's reader takes for no boolean leaves the default.
    /// With a known pnpm major only the file that major reads counts:
    /// pnpm 11+ ignores `.npmrc`'s `lockfile`, pnpm 10 and older the YAML
    /// key.
    #[tokio::test]
    async fn an_enabled_lockfile_is_pinned() {
        for (workspace, npmrc, pm) in [
            ("lockfile: true\n", None, None),
            ("packages:\n  - '.'\n", Some("lockfile=true\n"), None),
            ("lockfile: maybe\n", None, None),
            (
                "lockfile: true\n",
                Some("lockfile=false\n"),
                Some("pnpm@11.2.0"),
            ),
            ("lockfile: false\n", None, Some("pnpm@10.34.6")),
            (
                "lockfile: false\n",
                Some("lockfile=true\n"),
                Some("pnpm@9.15.9"),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_branch_lock_project(tmp.path(), workspace, true);
            std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
            if let Some(npmrc) = npmrc {
                write_rel(tmp.path(), ".npmrc", npmrc);
            }
            if let Some(pm) = pm {
                write_pinned_manifest(tmp.path(), pm);
            }
            let (_, done) = member_rewrite(tmp.path()).await;
            let text = done
                .rewrite
                .files
                .get("pnpm-lock.yaml")
                .unwrap_or_else(|| panic!("{workspace} {pm:?}: {:?}", done.rewrite.warnings));
            assert!(text.contains(MEMBER_URL), "{text}");
            assert_eq!(done.confirmed.len(), 1, "{workspace}");
            assert!(!warning_codes(&done).contains(&PNPM_LOCKFILE_DISABLED));
        }
    }

    fn write_pinned_manifest(root: &std::path::Path, pm: &str) {
        write_rel(
            root,
            "package.json",
            &format!(
                r#"{{"name":"app","packageManager":"{pm}","dependencies":{{"is-number":"7.0.0"}}}}"#
            ),
        );
    }

    /// The file the pinned major reads decides (#1074): pnpm 9 ignores a
    /// YAML `lockfile: true` and reads `.npmrc`'s `lockfile=false`; with no
    /// major known, either file turning it off refuses.
    #[tokio::test]
    async fn a_disabled_lockfile_is_read_where_the_pnpm_major_reads_it() {
        for (workspace, npmrc, pm, source) in [
            (
                "lockfile: true\n",
                "lockfile=false\n",
                Some("pnpm@9.15.9"),
                "`lockfile=false` in .npmrc",
            ),
            (
                "lockfile: true\n",
                "lockfile=false\n",
                None,
                "`lockfile=false` in .npmrc",
            ),
            (
                "lockfile: false\n",
                "lockfile=true\n",
                Some("pnpm@12.10.1"),
                "`lockfile: false` in pnpm-workspace.yaml",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_branch_lock_project(tmp.path(), workspace, true);
            std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
            write_rel(tmp.path(), ".npmrc", npmrc);
            if let Some(pm) = pm {
                write_pinned_manifest(tmp.path(), pm);
            }
            let (read, done) = member_rewrite(tmp.path()).await;
            assert_disabled_lockfile_refused(&read, &done, source);
        }
    }

    /// pnpm reads `lockfile` only when it is a boolean, else falls back to
    /// npm's `package-lock` (`useLockfile` in every pnpm 7–11): the common
    /// npm-era `package-lock=false` turns pnpm's lock off too, unless
    /// `lockfile=true` says otherwise.
    #[tokio::test]
    async fn package_lock_false_disables_the_lockfile() {
        for (npmrc, refused) in [
            ("package-lock=false\n", true),
            ("lockfile=true\npackage-lock=false\n", false),
            ("package-lock=true\n", false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_branch_lock_project(tmp.path(), "packages:\n  - '.'\n", true);
            std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
            write_rel(tmp.path(), ".npmrc", npmrc);
            write_pinned_manifest(tmp.path(), "pnpm@10.33.0");
            let (read, done) = member_rewrite(tmp.path()).await;
            if refused {
                assert_disabled_lockfile_refused(&read, &done, "`package-lock=false` in .npmrc");
            } else {
                assert!(
                    done.rewrite.files.contains_key("pnpm-lock.yaml"),
                    "{npmrc}: {:?}",
                    done.rewrite.warnings
                );
            }
        }
        // pnpm 11+ reads the YAML spelling.
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "packageLock: false\n", true);
        std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
        write_pinned_manifest(tmp.path(), "pnpm@11.28.5");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_disabled_lockfile_refused(
            &read,
            &done,
            "`packageLock: false` in pnpm-workspace.yaml",
        );
    }

    /// With no pnpm lock the remedy cannot be vendored mode (its pnpm
    /// backend needs a lock to wire), and an npm project's `.npmrc`
    /// `lockfile=false` is no pnpm setting at all: it keeps npm's hints.
    #[tokio::test]
    async fn a_disabled_lockfile_without_a_pnpm_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "lockfile: false\n", false);
        std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
        let (_, done) = member_rewrite(tmp.path()).await;
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_LOCKFILE_DISABLED)
            .unwrap_or_else(|| panic!("{:?}", done.rewrite.warnings))
            .detail;
        assert!(
            !detail.contains("--mode vendored") && detail.contains("pnpm install"),
            "{detail}"
        );

        let mut project = MemoryProject::new();
        project.insert_text("package.json", r#"{"name":"app"}"#);
        project.insert_text(".npmrc", "lockfile=false\n");
        let (_, done) = view_rewrite(&ProjectView::Memory(&project)).await;
        assert!(
            !warning_codes(&done).contains(&PNPM_LOCKFILE_DISABLED),
            "{:?}",
            done.rewrite.warnings
        );
    }
}

/// The one-pass multi-needle confirmation probe answers exactly what the
/// per-candidate `any()` oracle answers.
#[cfg(test)]
mod probe_equivalence_tests {
    use super::candidate_presence_needles;
    use crate::hosted::guidance::npm_lock_url_needles;
    use crate::patch::redirect::presence::groups_present;
    use crate::patch::redirect::{
        artifact_url_present, artifact_url_spellings, rewrite_registry_redirect, DepOverride,
    };
    use crate::utils::uri::encode_uri_component;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// The per-candidate probe [`candidate_presence_needles`] +
    /// `groups_present` replaced, kept as the equivalence oracle.
    fn candidate_present_oracle(final_texts: &[&String], dep: &DepOverride) -> bool {
        let artifact_url = dep.artifact_url.as_str();
        let registry = dep.registry_override.as_ref();
        let index_url = registry.map(|o| o.index_url.as_str());
        let suffixed_version =
            registry.and_then(|o| o.identifiers.maven_suffixed_version.as_deref());
        let encoded = encode_uri_component(artifact_url);
        final_texts.iter().any(|text| {
            artifact_url_present(text, artifact_url)
                || text.contains(encoded.as_str())
                || index_url.is_some_and(|iu| text.contains(iu))
                || suffixed_version.is_some_and(|sv| text.contains(sv))
        })
    }

    fn golden_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect")
    }

    fn cases(dir: &Path, out: &mut Vec<PathBuf>) {
        if dir.join("input").is_dir() && dir.join("overrides.json").is_file() {
            out.push(dir.to_path_buf());
            return;
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                cases(&p, out);
            }
        }
    }

    fn read_tree(base: &Path) -> BTreeMap<String, String> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if let Ok(text) = std::fs::read_to_string(&p) {
                    let rel = p.strip_prefix(base).unwrap().to_string_lossy();
                    out.insert(rel.replace('\\', "/"), text);
                }
            }
        }
        let mut out = BTreeMap::new();
        if base.is_dir() {
            walk(base, base, &mut out);
        }
        out
    }

    /// Every golden fixture (composer `\/`, berry percent-encoded, maven
    /// suffixed version, go module path, cargo index url, …): each case's
    /// final texts — input overlaid with the rewriters' own output, as the probe
    /// sees them — plus its authored `expected/` files, probed with EVERY
    /// fixture's overrides so hits and misses are both well exercised.
    #[test]
    fn multi_needle_probe_matches_per_candidate_any_on_golden_fixtures() {
        let mut dirs = Vec::new();
        cases(&golden_root(), &mut dirs);
        dirs.sort();
        assert!(dirs.len() > 50, "golden fixtures not found: {}", dirs.len());

        let mut all_overrides: Vec<DepOverride> = Vec::new();
        let mut text_sets: Vec<Vec<String>> = Vec::new();
        for case in &dirs {
            let overrides: Vec<DepOverride> = match serde_json::from_str(
                &std::fs::read_to_string(case.join("overrides.json")).unwrap(),
            ) {
                Ok(o) => o,
                Err(_) => continue,
            };
            let input = read_tree(&case.join("input"));
            let rewrite = rewrite_registry_redirect(&input, &overrides);
            let finals: Vec<String> = input
                .iter()
                .map(|(name, text)| rewrite.files.get(name).unwrap_or(text).clone())
                .chain(
                    rewrite
                        .files
                        .iter()
                        .filter(|(name, _)| !input.contains_key(*name))
                        .map(|(_, t)| t.clone()),
                )
                .collect();
            text_sets.push(finals);
            text_sets.push(read_tree(&case.join("expected")).into_values().collect());
            text_sets.push(input.into_values().collect());
            all_overrides.extend(overrides);
        }
        text_sets.push(Vec::new());
        // Texts that carry ONE needle kind and nothing else — no golden
        // fixture has the maven suffixed version or the registry index URL
        // without the artifact URL beside it, so a needle dropped from
        // `candidate_presence_needles` would otherwise go unnoticed.
        let mut lone_suffixed: Vec<usize> = Vec::new();
        for o in all_overrides
            .iter()
            .filter_map(|d| d.registry_override.as_ref())
        {
            text_sets.push(vec![format!("<url>{}</url>\n", o.index_url)]);
            if let Some(sv) = o.identifiers.maven_suffixed_version.as_deref() {
                lone_suffixed.push(text_sets.len());
                text_sets.push(vec![format!("<version>{sv}</version>\n")]);
            }
        }
        assert!(
            !lone_suffixed.is_empty(),
            "no maven suffixed-version override"
        );

        let groups: Vec<Vec<String>> = all_overrides
            .iter()
            .map(candidate_presence_needles)
            .collect();
        let (mut hits, mut misses) = (0usize, 0usize);
        for (set, texts) in text_sets.iter().enumerate() {
            let refs: Vec<&String> = texts.iter().collect();
            let fast = groups_present(&refs, &groups);
            if lone_suffixed.contains(&set) {
                assert!(
                    fast.iter().any(|hit| *hit),
                    "a lone suffixed version confirms its maven override"
                );
            }
            for (dep, got) in all_overrides.iter().zip(&fast) {
                let want = candidate_present_oracle(&refs, dep);
                assert_eq!(
                    *got, want,
                    "{}/{} / {}",
                    dep.ecosystem, dep.name, dep.artifact_url
                );
                if want {
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
        }
        assert!(hits > 100 && misses > 100, "hits={hits} misses={misses}");

        // The pnpm / npm host filters and the heal probe: the npm lock
        // spellings, and the bare `artifact_url_present` pair.
        let npm: Vec<&DepOverride> = all_overrides.iter().collect();
        let lock_groups: Vec<Vec<String>> = npm
            .iter()
            .map(|o| npm_lock_url_needles(&o.artifact_url))
            .collect();
        let pair_groups: Vec<[String; 2]> = npm
            .iter()
            .map(|o| artifact_url_spellings(&o.artifact_url))
            .collect();
        for texts in &text_sets {
            let lock_fast = groups_present(texts, &lock_groups);
            let pair_fast = groups_present(texts, &pair_groups);
            for (i, o) in npm.iter().enumerate() {
                let encoded = encode_uri_component(&o.artifact_url);
                let pair = texts
                    .iter()
                    .any(|t| artifact_url_present(t, &o.artifact_url));
                let lock = texts.iter().any(|t| {
                    artifact_url_present(t, &o.artifact_url) || t.contains(encoded.as_str())
                });
                assert_eq!(pair_fast[i], pair, "{}", o.artifact_url);
                assert_eq!(lock_fast[i], lock, "{}", o.artifact_url);
            }
        }
    }
}
