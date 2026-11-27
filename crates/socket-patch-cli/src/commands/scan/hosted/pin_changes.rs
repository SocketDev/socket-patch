use std::borrow::Cow;
use std::collections::HashMap;

use socket_patch_core::hosted::engine::{overlay_creation_is_invisible, Candidate, FinalDiscovery};
use socket_patch_core::patch::redirect::upstream::foreign_dep_origins;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vex::discover::{
    discover_patched_refs_with, Discovery, PatchedRef, WiringMode, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_LOCKFILE_UNREADABLE,
};
use socket_patch_core::vex::DiscoverOptions;

use crate::args::GlobalArgs;
use crate::commands::scan::rollout::Prior;

pub(super) async fn before_rewrite<'a>(
    common: &GlobalArgs,
    candidates: &[Candidate],
    prior: Option<Prior<'a>>,
) -> Cow<'a, Discovery> {
    let mut origins = crate::commands::hosted_unwind::patch_server_origins(common);
    let foreign = foreign_dep_origins(candidates.iter().map(|c| &c.dep), &origins);
    if let Some(discovery) = prior
        .filter(|_| foreign.is_empty())
        .and_then(|p| p.still_current())
    {
        return Cow::Borrowed(discovery);
    }
    origins.extend(foreign);
    let opts = DiscoverOptions {
        patch_server_origins: origins,
    };
    Cow::Owned(discover_patched_refs_with(&common.cwd, &opts).await)
}

fn refs_by_patch(discovery: &Discovery) -> HashMap<(PurlKey, &str), Vec<&PatchedRef>> {
    let mut pins = HashMap::new();
    for pin in discovery
        .refs
        .iter()
        .filter(|pin| pin.mode == WiringMode::Hosted)
    {
        pins.entry((PurlKey::new(&pin.purl), pin.uuid.as_str()))
            .or_insert_with(Vec::new)
            .push(pin);
    }
    pins
}

pub(super) fn compare<'a>(
    before: Option<&Discovery>,
    after: Option<&FinalDiscovery>,
    created_paths: &[String],
    confirmed: &'a [(String, String)],
    no_writes: bool,
) -> HashMap<(&'a str, &'a str), bool> {
    if no_writes {
        return confirmed
            .iter()
            .map(|(purl, uuid)| ((purl.as_str(), uuid.as_str()), false))
            .collect();
    }
    let (
        Some(before),
        Some(FinalDiscovery::Overlaid {
            discovery: after,
            view_only,
        }),
    ) = (before, after)
    else {
        return HashMap::new();
    };
    if !view_only
        && !created_paths
            .iter()
            .all(|path| overlay_creation_is_invisible(path))
    {
        return HashMap::new();
    }
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
