//! Hosted mode's withdrawn-pin sweep: a lockfile pin whose patch the
//! server no longer serves is restored to its upstream registry entry.
//!
//! A hosted pin points the lockfile at the patch server's copy of one
//! patch uuid. Once that patch is unpublished the server stops serving it
//! (the download answers 410), so every fresh install of the pinned
//! lockfile fails. The rewrite never notices on its own: a withdrawn patch
//! drops out of the search results, so nothing selects it and its pin is
//! left as is.
//!
//! Before the rewrite, `scan --mode hosted` asks the reference endpoint
//! about every uuid the lockfiles pin for a package this run covered. A pin
//! whose uuid comes back `withdrawn` (unpublished) or `not_found` (no such
//! patch) is restored upstream, the way `rollback` restores it
//! ([`crate::commands::hosted_unwind::run_hosted_leg`]). If the package has
//! a replacement patch on offer, the rewrite that follows pins the
//! replacement, so the net effect is an update. Otherwise the package goes
//! back to the registry's unpatched copy.
//!
//! Only those two explicit statuses unpin. A pin that is merely missing
//! from the search results is kept: that is also what a failed search
//! batch, a fallback to the free-only public proxy, or a lapsed paid
//! entitlement looks like. A `forbidden`, `pending_build` or `build_failed`
//! answer keeps the pin too. If the reference lookup fails (the patch API
//! is down, say), every pin is kept and the run warns.
//!
//! The settled answers are kept ([`WithdrawnSweep::take_references`]): on
//! a rescan the redirect selects the same uuids the lockfiles pin, and asks
//! the endpoint only about the ones the sweep has no answer for (#1606,
//! #1607).

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use socket_patch_core::api::client::ApiClient;
use socket_patch_core::api::types::PackageVendorResult;
use socket_patch_core::patch::redirect::upstream::HostedPin;
use socket_patch_core::utils::purl_key::PurlKey;

use crate::args::GlobalArgs;
use crate::commands::agent_download::tag_mode;
use crate::json_envelope::{Envelope, PatchAction, PatchEvent};

/// `reason` code on the `rolledBack` event of a pin the sweep restored.
pub(super) const PATCH_WITHDRAWN: &str = "patch_withdrawn";

/// Warning: a withdrawn pin could not be restored upstream (the restore
/// refused it, the restored files could not be written, or the apply lock
/// was held). The pin is unchanged; the detail names the remedy.
pub(super) const REDIRECT_WITHDRAWN_RESTORE_FAILED: &str = "redirect_withdrawn_restore_failed";

/// Warning: the reference lookup for the pinned uuids failed, so the run
/// could not tell whether any pin was withdrawn. Every pin is kept.
pub(super) const REDIRECT_WITHDRAWN_CHECK_FAILED: &str = "redirect_withdrawn_check_failed";

/// Whether a reference `status` means the pinned patch is gone for good.
fn is_gone(status: &str) -> bool {
    matches!(status, "withdrawn" | "not_found")
}

/// What the sweep did, for the `--json` envelope. Human output is printed
/// as the sweep runs.
#[derive(Debug, Default)]
pub(super) struct WithdrawnSweep {
    /// `rolledBack` (`verified` on a dry run) per restored pin.
    events: Vec<PatchEvent>,
    /// `(code, detail)` run-level warnings.
    warnings: Vec<(String, String)>,
    /// The reference endpoint's answers, when the lookup succeeded.
    references: Option<KnownReferences>,
}

/// Reference answers the sweep already has, for the redirect to reuse.
/// Only settled answers are kept: a `pending_build` (or any status this
/// build does not know) may have changed by the time the redirect runs, and
/// a uuid the response left out (a 404 chunk answers nothing) is asked
/// again rather than read as `not_found`.
#[derive(Debug, Default)]
pub(crate) struct KnownReferences(HashMap<String, PackageVendorResult>);

impl KnownReferences {
    /// The settled answers in `results` for the uuids in `asked` (an
    /// answer the request did not ask for is not trusted).
    fn settled(asked: &[String], mut results: HashMap<String, PackageVendorResult>) -> Self {
        results.retain(|uuid, r| {
            asked.contains(uuid)
                && matches!(
                    r.status.as_str(),
                    "granted" | "reused" | "withdrawn" | "not_found" | "forbidden"
                )
        });
        KnownReferences(results)
    }

    /// The uuids in `uuids` with no known answer.
    pub(crate) fn unknown(&self, uuids: &[String]) -> Vec<String> {
        uuids
            .iter()
            .filter(|uuid| !self.0.contains_key(*uuid))
            .cloned()
            .collect()
    }

    /// The known answers, keyed by uuid as the reference fetch returns them.
    pub(crate) fn into_answers(self) -> HashMap<String, PackageVendorResult> {
        self.0
    }
}

impl WithdrawnSweep {
    /// The reference answers the sweep fetched, for the redirect to reuse.
    pub(super) fn take_references(&mut self) -> Option<KnownReferences> {
        self.references.take()
    }

    /// Fold the outcome into the scan envelope.
    pub(super) fn record_into(self, env: &mut Envelope) {
        for event in self.events {
            env.record(event);
        }
        for (code, detail) in self.warnings {
            env.warn(code, detail);
        }
    }

    fn warn(&mut self, common: &GlobalArgs, code: &str, detail: String) {
        // Warnings print even under --silent: a kept withdrawn pin breaks
        // the next fresh install.
        if !common.json {
            eprintln!("Warning: {detail}");
        }
        self.warnings.push((code.to_string(), detail));
    }
}

/// The pins in `pins` whose package this run covered (`covered`: the purls
/// it queried), matched by release identity, so a qualified or
/// percent-encoded spelling still names its pin.
pub(super) fn pins_in_scope(
    pins: &[HostedPin],
    covered: impl IntoIterator<Item = impl AsRef<str>>,
) -> Vec<HostedPin> {
    let covered: BTreeSet<PurlKey> = covered
        .into_iter()
        .map(|p| PurlKey::new(p.as_ref()))
        .collect();
    pins.iter()
        .filter(|pin| covered.contains(&PurlKey::new(&pin.purl)))
        .cloned()
        .collect()
}

/// Check `pins` against the reference endpoint and restore the withdrawn
/// ones upstream (see the module docs). A wet restore runs under the apply
/// lock, released before the hosted rewrite takes it again.
pub(super) async fn sweep(
    common: &GlobalArgs,
    api_client: &ApiClient,
    pins: &[HostedPin],
) -> WithdrawnSweep {
    let mut out = WithdrawnSweep::default();
    if pins.is_empty() {
        return out;
    }
    let uuids: Vec<String> = pins
        .iter()
        .map(|pin| pin.uuid.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let references = match api_client.fetch_registry_references(&uuids).await {
        Ok(references) => references,
        Err(e) => {
            out.warn(
                common,
                REDIRECT_WITHDRAWN_CHECK_FAILED,
                format!(
                    "could not check whether the hosted patches pinned in the lockfiles are \
                     still published ({e}); every pin was kept, re-run to check again"
                ),
            );
            return out;
        }
    };
    // A uuid the response leaves out is not known to be gone: kept.
    let gone: Vec<(HostedPin, String)> = pins
        .iter()
        .filter_map(|pin| {
            let status = &references.get(&pin.uuid)?.status;
            is_gone(status).then(|| (pin.clone(), status.clone()))
        })
        .collect();
    out.references = Some(KnownReferences::settled(&uuids, references));
    if gone.is_empty() {
        return out;
    }

    if !common.json && !common.silent {
        for (pin, status) in &gone {
            eprintln!(
                "Note: patch {} for {} is no longer published ({status}); restoring its \
                 upstream registry entry",
                pin.uuid, pin.purl
            );
        }
    }

    let _lock = if common.dry_run {
        None
    } else {
        let socket_dir = common.socket_dir();
        let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
        match crate::commands::lock_cli::acquire_with_status(&socket_dir, timeout) {
            Ok(guard) => Some(guard),
            Err(err) => {
                let (_, message) = crate::commands::lock_cli::lock_failure(&err, timeout);
                for (pin, status) in &gone {
                    out.warn(
                        common,
                        REDIRECT_WITHDRAWN_RESTORE_FAILED,
                        format!(
                            "{} is pinned to patch {}, which is no longer published \
                             ({status}), but it was not restored: {message}; re-run, or run \
                             `socket-patch rollback {}`",
                            pin.purl, pin.uuid, pin.purl
                        ),
                    );
                }
                return out;
            }
        }
    };

    let to_restore: Vec<HostedPin> = gone.iter().map(|(pin, _)| pin.clone()).collect();
    let leg = crate::commands::hosted_unwind::run_hosted_leg(common, &to_restore).await;

    let action = if common.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::RolledBack
    };
    for (pin, status) in &gone {
        if !leg.reverted.iter().any(|p| p == &pin.purl) {
            continue;
        }
        let verb = if common.dry_run {
            "would be restored"
        } else {
            "was restored"
        };
        out.events.push(tag_mode(
            PatchEvent::new(action, pin.purl.as_str())
                .with_uuid(pin.uuid.as_str())
                .with_reason(
                    PATCH_WITHDRAWN,
                    format!(
                        "patch {} is no longer published ({status}); the pin {verb} to the \
                         upstream registry entry",
                        pin.uuid
                    ),
                ),
            Some("hosted"),
        ));
    }
    // `run_hosted_leg` already printed each failure to stderr.
    for (purl, why) in leg.failed {
        out.warnings.push((
            REDIRECT_WITHDRAWN_RESTORE_FAILED.to_string(),
            format!("{purl}: {why}"),
        ));
    }
    for (code, detail) in leg.warnings {
        if !common.json && !common.silent {
            eprintln!("Warning: {detail}");
        }
        out.warnings.push((code, detail));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(purl: &str, uuid: &str) -> HostedPin {
        HostedPin {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            files: vec!["package-lock.json".to_string()],
        }
    }

    #[test]
    fn only_withdrawn_and_not_found_are_gone() {
        assert!(is_gone("withdrawn"));
        assert!(is_gone("not_found"));
        for kept in [
            "granted",
            "reused",
            "pending_build",
            "build_failed",
            "forbidden",
            "",
        ] {
            assert!(!is_gone(kept), "{kept} must keep the pin");
        }
    }

    #[test]
    fn scope_matches_by_release_identity() {
        let pins = vec![
            pin("pkg:npm/@scope/a@1.0.0", "u1"),
            pin("pkg:npm/b@2.0.0", "u2"),
        ];
        let in_scope = pins_in_scope(&pins, ["pkg:npm/%40scope/a@1.0.0"]);
        assert_eq!(in_scope, vec![pins[0].clone()]);
    }

    #[test]
    fn uncovered_pins_are_out_of_scope() {
        let pins = vec![pin("pkg:npm/b@2.0.0", "u2")];
        assert!(pins_in_scope(&pins, ["pkg:npm/b@2.0.1"]).is_empty());
        assert!(pins_in_scope(&pins, Vec::<String>::new()).is_empty());
    }

    #[test]
    fn only_settled_answers_are_known() {
        let answer = |status: &str| -> PackageVendorResult {
            serde_json::from_value(serde_json::json!({ "status": status })).unwrap()
        };
        // `left-out`: the response did not answer it (a 404 chunk, say).
        let uuids = ["granted", "withdrawn", "building", "failed", "left-out"].map(String::from);
        let known = KnownReferences::settled(
            &uuids,
            HashMap::from([
                ("granted".to_string(), answer("granted")),
                ("withdrawn".to_string(), answer("withdrawn")),
                ("building".to_string(), answer("pending_build")),
                ("failed".to_string(), answer("build_failed")),
                // Not asked for: dropped.
                ("unasked".to_string(), answer("granted")),
            ]),
        );
        assert_eq!(known.unknown(&uuids), ["building", "failed", "left-out"]);
        assert_eq!(known.unknown(&["unasked".to_string()]), ["unasked"]);
        let mut answers: Vec<_> = known.into_answers().into_keys().collect();
        answers.sort();
        assert_eq!(answers, ["granted", "withdrawn"]);
    }
}
