//! The CLI consent gate. --yes, --force, UUID selection and socket.yml do
//! not grant permission to combine a Socket patch with a project's own patch.

use socket_patch_core::patch::user_patches::UserPatchIndex;

use crate::args::GlobalArgs;
use crate::json_envelope::{Command, Envelope, EnvelopeError};

pub(crate) const CONFLICT: &str = "user_patch_conflict";
pub(crate) const ALLOWED: &str = "user_patch_override";

/// Ecosystems the detector reads evidence for; any other purl can't conflict.
const DETECTED: &[&str] = &["pkg:npm/", "pkg:composer/", "pkg:cargo/", "pkg:golang/"];

/// Whether any of `purls` could match project evidence, so a run with no
/// such purl (an empty or pypi-only manifest) skips discovery entirely.
fn any_detectable<'a>(common: &GlobalArgs, mut purls: impl Iterator<Item = &'a str>) -> bool {
    purls.any(|purl| {
        common.purl_ecosystem_selected(purl)
            && DETECTED.iter().any(|prefix| {
                purl.get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            })
    })
}

pub(crate) async fn inspect(common: &GlobalArgs) -> UserPatchIndex {
    if common.is_global() {
        // A local checkout does not govern a separately selected global tree.
        UserPatchIndex::default()
    } else {
        UserPatchIndex::discover(&common.cwd).await
    }
}

pub(crate) fn detail(purl: &str, sources: &[String], allowed: bool) -> String {
    let sources = sources.join(", ");
    if allowed {
        format!("{purl}: --allow-user-patches permits attempting a Socket patch alongside project patches in {sources}; review and test the combined result. Backend safety checks still apply")
    } else {
        format!("{purl}: protected by project patch/replacement metadata in {sources}; leaving this package untouched. Merge the fixes manually, or explicitly accept the conflict risk with --allow-user-patches (ordinary --yes/--force do not approve this)")
    }
}

/// Explicit-target commands fail before mutation rather than silently succeeding
/// without the requested patch. Approved overrides come back as warnings for
/// the caller to print once (see [`warn`]) and attach to its own envelope.
/// Nothing here downloads or applies the user's patch.
pub(crate) async fn check(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<(String, String)>, EnvelopeError> {
    let (warnings, conflicts) = partition(common, purls).await;
    if conflicts.is_empty() {
        Ok(warnings)
    } else {
        let mut messages: Vec<String> = conflicts.into_iter().map(|(_, m)| m).collect();
        messages.sort();
        messages.dedup();
        Err(EnvelopeError::new(CONFLICT, messages.join("\n")))
    }
}

/// [`check`]'s two outcomes kept apart: approved-override warnings, and the
/// `(purl, message)` of each refused conflict.
pub(crate) async fn partition(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let purls: Vec<String> = purls.into_iter().map(|p| p.as_ref().to_string()).collect();
    if !any_detectable(common, purls.iter().map(String::as_str)) {
        return (Vec::new(), Vec::new());
    }
    let index = inspect(common).await;
    let mut warnings = Vec::new();
    let mut conflicts = Vec::new();
    for purl in &purls {
        let purl = purl.as_str();
        if !common.purl_ecosystem_selected(purl) {
            continue;
        }
        let sources = index.conflicts(purl);
        if sources.is_empty() {
            continue;
        }
        let message = detail(purl, &sources, common.allow_user_patches);
        if common.allow_user_patches {
            warnings.push((ALLOWED.into(), message));
        } else {
            conflicts.push((purl.to_string(), message));
        }
    }
    (warnings, conflicts)
}

/// The human copy of [`check`]'s approved overrides; JSON carries them in
/// the envelope and `--silent` mutes them.
pub(crate) fn warn(common: &GlobalArgs, warnings: &[(String, String)]) {
    if !common.silent && !common.json {
        for (_, detail) in warnings {
            eprintln!("Warning: {detail}");
        }
    }
}

/// The manifest-wide gate for `apply`: rather than refuse a whole run over
/// one protected entry (a postinstall apply would fail every install), drop
/// the protected records from this run's in-memory copy and report each as
/// a `user_patch_conflict` warning. Approved overrides stay in and come back
/// as `user_patch_override` warnings. Only the caller's copy changes; the
/// manifest on disk is never rewritten here. Also returns the skipped purls:
/// they are still recorded, so nothing may reconcile them away as dropped.
pub(crate) async fn skip_protected(
    common: &GlobalArgs,
    patches: &mut std::collections::HashMap<
        String,
        socket_patch_core::manifest::schema::PatchRecord,
    >,
) -> (Vec<(String, String)>, std::collections::HashSet<String>) {
    let mut warnings = Vec::new();
    let mut skipped = std::collections::HashSet::new();
    if !any_detectable(common, patches.keys().map(String::as_str)) {
        return (warnings, skipped);
    }
    let index = inspect(common).await;
    patches.retain(|purl, _| {
        if !common.purl_ecosystem_selected(purl) {
            return true;
        }
        let sources = index.conflicts(purl);
        if sources.is_empty() {
            return true;
        }
        let message = detail(purl, &sources, common.allow_user_patches);
        if common.allow_user_patches {
            warnings.push((ALLOWED.into(), message));
            true
        } else {
            warnings.push((CONFLICT.into(), message));
            skipped.insert(purl.clone());
            false
        }
    });
    warnings.sort();
    (warnings, skipped)
}

pub(crate) fn refuse(common: &GlobalArgs, command: Command, error: EnvelopeError) -> i32 {
    if common.json {
        let mut env = Envelope::new(command);
        env.dry_run = common.dry_run;
        env.mark_error(error);
        crate::ui::print_json(&env.to_value());
    } else {
        eprintln!("Error: {}", error.message);
    }
    1
}
