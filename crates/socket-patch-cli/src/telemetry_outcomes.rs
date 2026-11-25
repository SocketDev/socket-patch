//! What a run's telemetry says about each patch it acted on.
//!
//! Every command already describes its run as per-patch [`PatchEvent`]s
//! (the `--json` envelope's `events[]`). Telemetry reports the same
//! outcomes, reduced to what an event may carry: the patch UUID, the
//! ecosystem, the mode and what happened. Deriving the one from the other
//! keeps a run's telemetry and its `--json` output from disagreeing.

use std::collections::HashMap;

use socket_patch_core::telemetry::{
    PatchOutcome, MODE_AGENT, MODE_HOSTED, MODE_VENDORED, OUTCOME_FAILED,
};

use crate::json_envelope::{PatchAction, PatchEvent};

/// The ecosystem a purl names, as events spell it: the ecosystem's CLI
/// name (`npm`, `pypi`, … the names `scan` reports), or the purl's own
/// type for one this CLI has no ecosystem for. Empty for a key that is
/// not a purl.
pub(crate) fn ecosystem_of(purl: &str) -> String {
    match socket_patch_core::crawlers::Ecosystem::from_purl(purl) {
        Some(ecosystem) => ecosystem.cli_name().to_string(),
        None => purl
            .strip_prefix("pkg:")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("")
            .to_string(),
    }
}

/// `outcomes` with each of `more` it does not already name (by patch and
/// mode) added at the end.
pub(crate) fn with_more(
    mut outcomes: Vec<PatchOutcome>,
    more: &[PatchOutcome],
) -> Vec<PatchOutcome> {
    for outcome in more {
        if !outcomes
            .iter()
            .any(|have| have.uuid == outcome.uuid && have.mode == outcome.mode)
        {
            outcomes.push(outcome.clone());
        }
    }
    outcomes
}

/// The telemetry word for an envelope action, and how much it says about
/// the patch (lower wins when one patch has several events): a failure
/// over a change, a change over a preview, a preview over a skip. `None`
/// for an action telemetry does not report.
fn outcome_of(action: PatchAction) -> Option<(&'static str, u8)> {
    match action {
        PatchAction::Failed => Some((OUTCOME_FAILED, 0)),
        PatchAction::Applied | PatchAction::Updated => Some(("applied", 1)),
        PatchAction::RolledBack => Some(("rolled_back", 1)),
        PatchAction::Removed => Some(("removed", 1)),
        PatchAction::Downloaded => Some(("downloaded", 1)),
        PatchAction::Rebuilt => Some(("rebuilt", 1)),
        PatchAction::Verified => Some(("verified", 2)),
        PatchAction::Skipped => Some(("skipped", 3)),
        PatchAction::Discovered => None,
    }
}

/// The mode an event is tagged with (`details.mode`), else `default`.
fn mode_of(event: &PatchEvent, default: &'static str) -> &'static str {
    match event
        .details
        .as_ref()
        .and_then(|details| details.get("mode"))
        .and_then(|mode| mode.as_str())
    {
        Some(MODE_HOSTED) => MODE_HOSTED,
        Some(MODE_VENDORED) => MODE_VENDORED,
        Some(MODE_AGENT) => MODE_AGENT,
        _ => default,
    }
}

/// The patches `events` are about, one entry per patch and mode, in the
/// order the run first reached them.
///
/// * An event names its patch by `uuid`, or by a purl `uuid_of` resolves
///   (apply's events carry the purl only). One that names neither is
///   about no single patch (an artifact sweep, a lockfile write) and is
///   left out.
/// * The mode is the event's `details.mode`, else `default_mode`.
/// * Several events for one patch (one per installed copy, or a download
///   and then an apply) fold into the one that says most: see
///   [`outcome_of`]. The `code` is that event's `errorCode`, and only a
///   failure or a skip has one; a failure with a `cause` (an apply's,
///   under the generic `apply_failed`) reports the cause instead.
pub(crate) fn patch_outcomes<'a>(
    events: impl IntoIterator<Item = &'a PatchEvent>,
    default_mode: &'static str,
    uuid_of: impl Fn(&str) -> Option<String>,
) -> Vec<PatchOutcome> {
    let mut outcomes: Vec<(PatchOutcome, u8)> = Vec::new();
    let mut index: HashMap<(String, &'static str), usize> = HashMap::new();
    for event in events {
        let Some((outcome, rank)) = outcome_of(event.action) else {
            continue;
        };
        let purl = event.purl.as_deref();
        let Some(uuid) = event.uuid.clone().or_else(|| purl.and_then(&uuid_of)) else {
            continue;
        };
        let mode = mode_of(event, default_mode);
        let code = match event.action {
            PatchAction::Failed => event.cause.clone().or_else(|| event.error_code.clone()),
            PatchAction::Skipped => event.error_code.clone(),
            _ => None,
        };
        let entry = PatchOutcome {
            uuid: uuid.clone(),
            ecosystem: purl.map(ecosystem_of).unwrap_or_default(),
            mode,
            outcome,
            code,
        };
        match index.get(&(uuid.clone(), mode)) {
            Some(&at) => {
                if rank < outcomes[at].1 {
                    // Keep an ecosystem an earlier event of this patch knew.
                    let ecosystem = if entry.ecosystem.is_empty() {
                        std::mem::take(&mut outcomes[at].0.ecosystem)
                    } else {
                        entry.ecosystem.clone()
                    };
                    outcomes[at] = (PatchOutcome { ecosystem, ..entry }, rank);
                } else if outcomes[at].0.ecosystem.is_empty() {
                    outcomes[at].0.ecosystem = entry.ecosystem;
                }
            }
            None => {
                index.insert((uuid, mode), outcomes.len());
                outcomes.push((entry, rank));
            }
        }
    }
    outcomes.into_iter().map(|(outcome, _)| outcome).collect()
}

/// A purl → patch UUID lookup over `uuids`, for events that name the
/// package only. A purl with no entry of its own matches across its
/// qualifiers (`?artifact_id=…`, `?platform=…`), as long as every such
/// entry names the same patch: one event must not be credited to another
/// release's patch.
pub(crate) fn uuid_lookup(uuids: &HashMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    use socket_patch_core::utils::purl::strip_purl_qualifiers;
    move |purl| {
        if let Some(uuid) = uuids.get(purl) {
            return Some(uuid.clone());
        }
        let base = strip_purl_qualifiers(purl);
        let mut matches = uuids
            .iter()
            .filter(|(key, _)| strip_purl_qualifiers(key) == base)
            .map(|(_, uuid)| uuid);
        let first = matches.next()?;
        matches.all(|uuid| uuid == first).then(|| first.clone())
    }
}

/// [`patch_outcomes`] for events that all carry their own `uuid`.
pub(crate) fn patch_outcomes_of<'a>(
    events: impl IntoIterator<Item = &'a PatchEvent>,
    default_mode: &'static str,
) -> Vec<PatchOutcome> {
    patch_outcomes(events, default_mode, |_| None)
}

/// One outcome for each `(purl, uuid)`, all in `mode`: for a run that
/// knows which patches it was about and that they all ended the same way
/// (a removal that failed before it reached any of them).
pub(crate) fn uniform_outcomes<'a>(
    patches: impl IntoIterator<Item = (&'a str, &'a str)>,
    mode: &'static str,
    outcome: &'static str,
    code: Option<&str>,
) -> Vec<PatchOutcome> {
    let mut seen = std::collections::HashSet::new();
    patches
        .into_iter()
        .filter(|(_, uuid)| seen.insert(*uuid))
        .map(|(purl, uuid)| PatchOutcome {
            uuid: uuid.to_string(),
            ecosystem: ecosystem_of(purl),
            mode,
            outcome,
            code: code.map(str::to_string),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn entry(
        uuid: &str,
        ecosystem: &str,
        mode: &'static str,
        outcome: &'static str,
        code: Option<&str>,
    ) -> PatchOutcome {
        PatchOutcome {
            uuid: uuid.to_string(),
            ecosystem: ecosystem.to_string(),
            mode,
            outcome,
            code: code.map(str::to_string),
        }
    }

    #[test]
    fn an_event_is_named_by_its_uuid_or_by_its_resolved_purl() {
        let events = [
            PatchEvent::new(PatchAction::Applied, "pkg:npm/a@1.0.0"),
            PatchEvent::new(PatchAction::RolledBack, "pkg:pypi/b@2.0.0").with_uuid(B),
            // No uuid and a purl nothing resolves: not a patch of this run.
            PatchEvent::new(PatchAction::Applied, "pkg:npm/unknown@1.0.0"),
            // About no single patch.
            PatchEvent::artifact(PatchAction::Removed),
        ];
        let outcomes = patch_outcomes(&events, MODE_AGENT, |purl| {
            (purl == "pkg:npm/a@1.0.0").then(|| A.to_string())
        });
        assert_eq!(
            outcomes,
            [
                entry(A, "npm", MODE_AGENT, "applied", None),
                entry(B, "pypi", MODE_AGENT, "rolled_back", None),
            ]
        );
    }

    #[test]
    fn the_mode_is_the_events_own_when_it_has_one() {
        let events = [
            PatchEvent::new(PatchAction::RolledBack, "pkg:npm/a@1.0.0")
                .with_uuid(A)
                .with_details(serde_json::json!({ "mode": "vendored" })),
            PatchEvent::new(PatchAction::RolledBack, "pkg:npm/a@1.0.0")
                .with_uuid(A)
                .with_details(serde_json::json!({ "mode": "hosted" })),
            PatchEvent::new(PatchAction::RolledBack, "pkg:npm/a@1.0.0")
                .with_uuid(A)
                .with_details(serde_json::json!({ "path": "node_modules/a" })),
        ];
        let outcomes = patch_outcomes_of(&events, MODE_AGENT);
        // One patch, three modes: three entries, each its own.
        assert_eq!(
            outcomes,
            [
                entry(A, "npm", MODE_VENDORED, "rolled_back", None),
                entry(A, "npm", MODE_HOSTED, "rolled_back", None),
                entry(A, "npm", MODE_AGENT, "rolled_back", None),
            ]
        );
    }

    /// One patch installed in several places is one entry, and the event
    /// that says most about it wins: a failed copy over the restored ones,
    /// a restored copy over one that had nothing to do.
    #[test]
    fn the_events_of_one_patch_fold_into_the_one_that_says_most() {
        let copy = |action| PatchEvent::new(action, "pkg:npm/a@1.0.0").with_uuid(A);
        let events = [
            copy(PatchAction::Skipped).with_reason("already_original", "nothing to restore"),
            copy(PatchAction::RolledBack),
            copy(PatchAction::RolledBack),
            PatchEvent::new(PatchAction::Verified, "pkg:npm/b@1.0.0").with_uuid(B),
            PatchEvent::new(PatchAction::Failed, "pkg:npm/b@1.0.0")
                .with_uuid(B)
                .with_error("hash_mismatch", "the file changed"),
            PatchEvent::new(PatchAction::RolledBack, "pkg:npm/b@1.0.0").with_uuid(B),
        ];
        assert_eq!(
            patch_outcomes_of(&events, MODE_AGENT),
            [
                entry(A, "npm", MODE_AGENT, "rolled_back", None),
                entry(B, "npm", MODE_AGENT, OUTCOME_FAILED, Some("hash_mismatch")),
            ]
        );
    }

    #[test]
    fn a_skip_keeps_its_code_and_a_change_has_none() {
        let events = [
            PatchEvent::new(PatchAction::Skipped, "pkg:gem/a@1.0.0")
                .with_uuid(A)
                .with_reason("package_not_installed", "no installed copy"),
            // A change that carries a code (an advisory) reports none.
            PatchEvent::new(PatchAction::Applied, "pkg:gem/b@1.0.0")
                .with_uuid(B)
                .with_reason("gem_extension_not_rebuilt", "rebuild it"),
        ];
        assert_eq!(
            patch_outcomes_of(&events, MODE_AGENT),
            [
                entry(
                    A,
                    "gem",
                    MODE_AGENT,
                    "skipped",
                    Some("package_not_installed")
                ),
                entry(B, "gem", MODE_AGENT, "applied", None),
            ]
        );
    }

    #[test]
    fn discovered_events_are_not_outcomes() {
        let events = [PatchEvent::new(PatchAction::Discovered, "pkg:npm/a@1.0.0").with_uuid(A)];
        assert!(patch_outcomes_of(&events, MODE_AGENT).is_empty());
    }

    #[test]
    fn uniform_outcomes_name_each_patch_once() {
        let outcomes = uniform_outcomes(
            [
                ("pkg:pypi/a@1.0.0?artifact_id=x", A),
                ("pkg:pypi/a@1.0.0?artifact_id=y", A),
                ("pkg:cargo/b@1.0.0", B),
            ],
            MODE_AGENT,
            OUTCOME_FAILED,
            Some("rollback_failed"),
        );
        assert_eq!(
            outcomes,
            [
                entry(
                    A,
                    "pypi",
                    MODE_AGENT,
                    OUTCOME_FAILED,
                    Some("rollback_failed")
                ),
                entry(
                    B,
                    "cargo",
                    MODE_AGENT,
                    OUTCOME_FAILED,
                    Some("rollback_failed")
                ),
            ]
        );
    }

    #[test]
    fn a_purl_is_looked_up_across_its_qualifiers_when_that_is_unambiguous() {
        let uuids: HashMap<String, String> = [
            ("pkg:npm/a@1.0.0", A),
            ("pkg:pypi/b@1.0.0?artifact_id=wheel", B),
            ("pkg:gem/c@1.0.0?platform=x86_64-linux", A),
            ("pkg:gem/c@1.0.0?platform=arm64-darwin", B),
        ]
        .into_iter()
        .map(|(purl, uuid)| (purl.to_string(), uuid.to_string()))
        .collect();
        let lookup = uuid_lookup(&uuids);
        assert_eq!(lookup("pkg:npm/a@1.0.0").as_deref(), Some(A));
        // The base purl of one qualified record, and another qualifier of it.
        assert_eq!(lookup("pkg:pypi/b@1.0.0").as_deref(), Some(B));
        assert_eq!(
            lookup("pkg:pypi/b@1.0.0?artifact_id=sdist").as_deref(),
            Some(B)
        );
        // Two releases with different patches: the base purl names neither.
        assert_eq!(lookup("pkg:gem/c@1.0.0"), None);
        assert_eq!(
            lookup("pkg:gem/c@1.0.0?platform=arm64-darwin").as_deref(),
            Some(B)
        );
        assert_eq!(lookup("pkg:npm/unknown@1.0.0"), None);
    }

    /// Events spell an ecosystem the way `scan` reports it, so the two
    /// join: the CLI name, which is not always the purl's type.
    #[test]
    fn the_ecosystem_is_the_cli_name() {
        use socket_patch_core::crawlers::Ecosystem;
        assert_eq!(ecosystem_of("pkg:golang/example.com/m@v1.0.0"), "golang");
        for purl in [
            "pkg:npm/a@1.0.0",
            "pkg:jsr/@std/path@1.0.0",
            "pkg:gem/a@1.0.0",
        ] {
            let ecosystem = Ecosystem::from_purl(purl).expect("a known ecosystem");
            assert_eq!(ecosystem_of(purl), ecosystem.cli_name(), "{purl}");
        }
        // No ecosystem of this CLI: the purl's own type. Not a purl: none.
        assert_eq!(ecosystem_of("pkg:hex/phoenix@1.7.0"), "hex");
        assert_eq!(ecosystem_of("not-a-purl"), "");
    }

    #[test]
    fn with_more_adds_only_the_patches_not_already_named() {
        let have = vec![entry(A, "npm", MODE_VENDORED, "applied", None)];
        let more = [
            // Already named in this mode: the outcome on record stands.
            entry(A, "npm", MODE_VENDORED, OUTCOME_FAILED, Some("x")),
            entry(
                B,
                "npm",
                MODE_VENDORED,
                OUTCOME_FAILED,
                Some("download_failed"),
            ),
        ];
        assert_eq!(
            with_more(have, &more),
            [
                entry(A, "npm", MODE_VENDORED, "applied", None),
                entry(
                    B,
                    "npm",
                    MODE_VENDORED,
                    OUTCOME_FAILED,
                    Some("download_failed")
                ),
            ]
        );
    }
}
