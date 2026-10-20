//! The CLI consent gate. --yes, --force, UUID selection and socket.yml do
//! not grant permission to combine a Socket patch with a project's own patch.

use socket_patch_core::patch::user_patches::UserPatchIndex;

use crate::args::GlobalArgs;
use crate::json_envelope::{Command, Envelope, EnvelopeError};

pub(crate) const CONFLICT: &str = "user_patch_conflict";
pub(crate) const ALLOWED: &str = "user_patch_override";

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
/// without the requested patch. The caller may attach approved warnings to its
/// own envelope. Nothing here downloads or applies the user's patch.
pub(crate) async fn check(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<(String, String)>, EnvelopeError> {
    let index = inspect(common).await;
    let mut warnings = Vec::new();
    let mut conflicts = Vec::new();
    for purl in purls {
        let purl = purl.as_ref();
        if !common.purl_ecosystem_selected(purl) {
            continue;
        }
        let sources = index.conflicts(purl);
        if sources.is_empty() {
            continue;
        }
        let message = detail(purl, &sources, common.allow_user_patches);
        if common.allow_user_patches {
            if !common.silent && !common.json {
                eprintln!("Warning: {message}");
            }
            warnings.push((ALLOWED.into(), message));
        } else {
            conflicts.push(message);
        }
    }
    if conflicts.is_empty() {
        Ok(warnings)
    } else {
        conflicts.sort();
        conflicts.dedup();
        Err(EnvelopeError::new(CONFLICT, conflicts.join("\n")))
    }
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
