use std::borrow::Cow;
use std::collections::HashMap;

use socket_patch_core::hosted::engine::Candidate;
use socket_patch_core::patch::redirect::upstream::foreign_dep_origins;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vex::discover::{
    discover_patched_refs_with, Discovery, PatchedRef, WiringMode, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_LOCKFILE_UNREADABLE,
};
use socket_patch_core::vex::DiscoverOptions;

use crate::args::GlobalArgs;

/// `details.pinChanged` per confirmed `(purl, uuid)`. A missing key reports `null`.
pub(super) type PinChanges<'a> = HashMap<(&'a str, &'a str), bool>;

/// `prior` is scan's discovery, already checked to still describe the disk.
pub(super) async fn before_rewrite<'a>(
    common: &GlobalArgs,
    candidates: &[Candidate],
    prior: Option<&'a Discovery>,
) -> Cow<'a, Discovery> {
    let configured = crate::commands::hosted_unwind::patch_server_origins(common);
    let foreign = foreign_dep_origins(candidates.iter().map(|c| &c.dep), &configured);
    if foreign.is_empty() {
        return match prior {
            Some(discovery) => Cow::Borrowed(discovery),
            None => Cow::Owned(crate::commands::discover_wiring(common, &common.cwd).await),
        };
    }
    let opts = DiscoverOptions {
        patch_server_origins: configured.into_iter().chain(foreign).collect(),
    };
    Cow::Owned(discover_patched_refs_with(&common.cwd, &opts).await)
}

pub(super) fn unchanged(confirmed: &[(String, String)]) -> PinChanges<'_> {
    confirmed
        .iter()
        .map(|(purl, uuid)| ((purl.as_str(), uuid.as_str()), false))
        .collect()
}

fn refs_by_patch(discovery: &Discovery) -> HashMap<(PurlKey, &str), Vec<&PatchedRef>> {
    let mut pins: HashMap<_, Vec<_>> = HashMap::new();
    for pin in discovery
        .refs
        .iter()
        .filter(|pin| pin.mode == WiringMode::Hosted)
    {
        pins.entry((PurlKey::new(&pin.purl), pin.uuid.as_str()))
            .or_default()
            .push(pin);
    }
    pins
}

/// `after` is the project as this run left it (see `discovery_after_writes`).
pub(super) fn compare<'a>(
    before: Option<&Discovery>,
    after: Option<&Discovery>,
    confirmed: &'a [(String, String)],
) -> PinChanges<'a> {
    let (Some(before), Some(after)) = (before, after) else {
        return HashMap::new();
    };
    if [before, after].iter().any(|d| {
        d.diagnostics.iter().any(|diag| {
            matches!(
                diag.code,
                DIAG_LOCKFILE_UNPARSEABLE | DIAG_LOCKFILE_UNREADABLE
            )
        })
    }) {
        return HashMap::new();
    }
    let old_refs = refs_by_patch(before);
    let new_refs = refs_by_patch(after);
    confirmed
        .iter()
        .filter_map(|(purl, uuid)| {
            let key = (PurlKey::new(purl), uuid.as_str());
            let new = new_refs.get(&key)?;
            let old = old_refs.get(&key);
            if old.is_none() && before.recognizes(uuid, WiringMode::Hosted) {
                return None;
            }
            Some(((purl.as_str(), uuid.as_str()), old != Some(new)))
        })
        .collect()
}
