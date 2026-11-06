//! The vlt warm-tree heal shared by the hosted flow and the unwinds, with
//! its `redirect_vlt_reinstall_required` advisory: run after a hosted
//! rewrite, after rollback/remove restore the vlt pins, and after a
//! hosted→vendored takeover. A helper module, not a command: `scan`,
//! `rollback`, `remove` and `vendor` all reach it without importing each
//! other.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::constants::npm_family::{VLT_HIDDEN_LOCK_REL, VLT_LOCK};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::vlt;
use socket_patch_core::patch::redirect::vlt_heal::{
    self, classify_target, read_install_state, Expected, LedgerTarget, Target, TargetState,
};

/// What the post-rewrite heal reports back to the hosted flow: its
/// advisories, and the confirmed purls whose installed or next-installed
/// bytes are not known to be patched (withheld from in-run VEX).
#[derive(Debug, Default)]
pub(crate) struct RewriteHeal {
    pub(crate) warnings: Vec<serde_json::Value>,
    pub(crate) stale_purls: BTreeSet<String>,
    /// Set when the heal ran (it may invalidate store entries): the store's
    /// bundled copies after it, discovery's only read of the installed tree
    /// (`Discovery::vlt_bundled_copies`). `None` when nothing was healed.
    pub(crate) healed_store: Option<BTreeMap<String, String>>,
}

pub(crate) const REINSTALL_REQUIRED: &str = "redirect_vlt_reinstall_required";
/// A bundled copy of a redirected package that no rewire reaches.
pub(crate) const BUNDLED_INSTANCE_SKIPPED: &str = "redirect_vlt_bundled_instance_skipped";

/// The origins the vlt heal treats as Socket-owned in the final lock: the
/// patch server plus `--api-url`. Unlike discovery's
/// [`crate::commands::hosted_unwind::patch_server_origins`], it also counts the
/// `--api-url` origin, so a
/// setup serving the hosted tarballs from the API origin is healed too.
/// Discovery-facing code must use the `hosted_unwind` helper, not this one.
fn vlt_heal_origins(common: &crate::args::GlobalArgs) -> Vec<String> {
    common
        .patch_server_url
        .iter()
        .chain(common.api_url.iter())
        .filter(|url| !url.trim().is_empty())
        .cloned()
        .collect()
}

/// How a heal ended, for the advisory wording.
#[derive(Debug, Default, PartialEq, Eq)]
struct HealTally {
    invalidated: usize,
    stale_left: usize,
    /// Stale optional copies the heal never removes (see
    /// [`vlt_heal::reinstalls_after_removal`]).
    optional_left: usize,
    undeterminable: usize,
    stale_uuids: BTreeSet<String>,
    undeterminable_uuids: BTreeSet<String>,
}

/// Classify `targets` against `expected` and invalidate the stale ones
/// vlt reinstalls, unless cleanup is off; `(target, uuid or purl)` per
/// target.
async fn heal_targets(
    common: &crate::args::GlobalArgs,
    targets: &[(Target<'_>, &str)],
    expected: Expected,
) -> HealTally {
    let mut tally = HealTally::default();
    if targets.is_empty() {
        return tally;
    }
    let state = read_install_state(&common.cwd).await;
    let mut stale: Vec<(String, &str)> = Vec::new();
    for (target, uuid) in targets {
        match classify_target(&state, &common.cwd, target, expected).await {
            TargetState::Stale if !vlt_heal::reinstalls_after_removal(target.flags) => {
                tally.optional_left += 1;
                tally.stale_uuids.insert((*uuid).to_string());
            }
            TargetState::Stale => stale.push((target.dep_id.to_string(), uuid)),
            TargetState::Undeterminable => {
                tally.undeterminable += 1;
                tally.undeterminable_uuids.insert((*uuid).to_string());
            }
            TargetState::Healthy => {}
        }
    }
    if stale.is_empty() {
        return tally;
    }
    if common.dry_run || common.no_vlt_install_cleanup {
        tally.stale_left = stale.len();
        tally
            .stale_uuids
            .extend(stale.iter().map(|(_, uuid)| (*uuid).to_string()));
        return tally;
    }
    let ids: Vec<String> = stale.iter().map(|(id, _)| id.clone()).collect();
    let result = vlt_heal::invalidate(&common.cwd, &state, &ids).await;
    let hidden_failed = result
        .failed
        .iter()
        .any(|(id, _)| id == VLT_HIDDEN_LOCK_REL);
    for (id, uuid) in &stale {
        let removed = result.removed.contains(id);
        if removed && !hidden_failed {
            tally.invalidated += 1;
        } else {
            tally.stale_left += 1;
            tally.stale_uuids.insert((*uuid).to_string());
        }
    }
    tally
}

/// Why the heal keeps stale optional copies, and what refreshes them.
const OPTIONAL_KEPT: &str = "socket-patch does not remove them because `vlt install` does not \
     reinstall a removed optional dependency. Run `vlt ci` (or delete node_modules and run `vlt \
     install`). vlt 0.0.0-30 … 1.0.4 install no optional dependency from the lock of a \
     project that declares only optional dependencies, so there both commands remove the \
     installed copy: upgrade vlt to 1.0.5 or later first.";

/// `detail` followed by the optional copies the heal kept (`held` names
/// them), when there are any besides what `detail` reports.
fn with_optional_kept(mut detail: String, optional_left: usize, held: &str) -> String {
    if optional_left > 0 {
        detail.push_str(if detail.ends_with('.') { " " } else { ". " });
        detail.push_str(&format!(
            "node_modules also still holds {optional_left} {held}; {OPTIONAL_KEPT}"
        ));
    }
    detail
}

const VLT_UPDATE_NOTE: &str =
    " Note: `vlt update` re-resolves from the registry and drops these hosted patches.";

fn reinstall_detail(tally: &HealTally) -> String {
    let held = "unpatched copies of optional dependencies";
    if tally.stale_left > 0 {
        with_optional_kept(
            format!(
                "vlt-lock.json pins Socket-patched packages, but node_modules still holds {} \
                 unpatched copies and `vlt install` will not refresh them; run `vlt ci` (or \
                 re-run without --no-vlt-install-cleanup).",
                tally.stale_left
            ),
            tally.optional_left,
            held,
        )
    } else if tally.undeterminable > 0 {
        with_optional_kept(
            undeterminable_detail(tally.undeterminable),
            tally.optional_left,
            held,
        )
    } else if tally.invalidated > 0 {
        let mut detail = with_optional_kept(
            format!(
                "vlt-lock.json pins Socket-patched packages; socket-patch removed {} stale \
                 installed copies (node_modules/.vlt-lock.json and node_modules/.vlt entries), \
                 so node_modules is incomplete until you run `vlt install` (or `vlt ci`), which \
                 installs the patched packages.",
                tally.invalidated
            ),
            tally.optional_left,
            held,
        );
        detail.push_str(VLT_UPDATE_NOTE);
        detail
    } else if tally.optional_left > 0 {
        format!(
            "vlt-lock.json pins Socket-patched packages, but node_modules still holds {} {held}; \
             {OPTIONAL_KEPT}",
            tally.optional_left
        )
    } else {
        format!(
            "vlt-lock.json pins Socket-patched packages; fresh checkouts install them with `vlt \
             ci` or `vlt install --frozen-lockfile`.{VLT_UPDATE_NOTE}"
        )
    }
}

fn rollback_detail(tally: &HealTally, restored: usize) -> Option<String> {
    let held = "patched copies of optional dependencies";
    let detail = if tally.stale_left > 0 {
        format!(
            "restored registry pins for {restored} packages, but node_modules still holds {} \
             patched copies and `vlt install` will not refresh them; run `vlt ci` (or re-run \
             without --no-vlt-install-cleanup)",
            tally.stale_left
        )
    } else if tally.undeterminable > 0 {
        undeterminable_detail(tally.undeterminable)
    } else if tally.invalidated > 0 && tally.optional_left > 0 {
        format!(
            "restored registry pins for {restored} packages; removed {} patched installed \
             copies, so node_modules is incomplete until you run `vlt install` (or `vlt ci`)",
            tally.invalidated
        )
    } else if tally.invalidated > 0 {
        format!(
            "restored registry pins for {restored} packages; removed the patched installed \
             copies, so node_modules is incomplete until you run `vlt install` (or `vlt ci`)"
        )
    } else if tally.optional_left > 0 {
        return Some(format!(
            "restored registry pins for {restored} packages, but node_modules still holds {} \
             {held}; {OPTIONAL_KEPT}",
            tally.optional_left
        ));
    } else {
        return None;
    };
    Some(with_optional_kept(detail, tally.optional_left, held))
}

fn takeover_detail(tally: &HealTally, vendored: usize) -> Option<String> {
    let held = "installed copies of the vendored optional dependencies";
    let detail = if tally.stale_left > 0 {
        format!(
            "vendored {vendored} hosted-pinned packages, but node_modules still holds {} \
             installed copies of the vendored packages; run `vlt install` (or re-run without \
             --no-vlt-install-cleanup)",
            tally.stale_left
        )
    } else if tally.undeterminable > 0 {
        undeterminable_detail(tally.undeterminable)
    } else if tally.invalidated > 0 && tally.optional_left > 0 {
        format!(
            "vendored {vendored} hosted-pinned packages; removed {} hosted installed copies, so \
             node_modules is incomplete until you run `vlt install`",
            tally.invalidated
        )
    } else if tally.invalidated > 0 {
        format!(
            "vendored {vendored} hosted-pinned packages; removed their hosted installed copies, \
             so node_modules is incomplete until you run `vlt install`"
        )
    } else if tally.optional_left > 0 {
        return Some(format!(
            "vendored {vendored} hosted-pinned packages, but node_modules still holds {} {held}; \
             {OPTIONAL_KEPT}",
            tally.optional_left
        ));
    } else {
        return None;
    };
    Some(with_optional_kept(detail, tally.optional_left, held))
}

fn undeterminable_detail(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but socket-patch could not check {n} \
         installed copies (node_modules is a link, or no patch record was available); run \
         `vlt ci` to be sure the patched packages are installed."
    )
}

/// What this run's vlt rewrite needs from the rest of the hosted flow.
pub(crate) struct HealInputs<'a> {
    /// The final `vlt-lock.json` (as written, or as a dry run would write it).
    pub(crate) final_lock: Option<&'a str>,
    /// This run's fetched records merged with the ledger's, keyed by purl.
    pub(crate) records: &'a BTreeMap<String, PatchRecord>,
    pub(crate) confirmed: &'a [(String, String)],
    pub(crate) confirmed_vlt: &'a BTreeSet<String>,
    pub(crate) foreign: &'a BTreeSet<String>,
    pub(crate) rewrite_warning_codes: &'a [&'a str],
}

/// The heal after a hosted rewrite, the advisory, and the purls whose
/// installed or next-installed bytes are not known to be patched (removed
/// from the same run's in-run VEX attestation). A confirmed vlt uuid with
/// no heal target (a non-Socket host, a leaf that disagrees with the
/// DepID) was never checked, so it is never attested here.
pub(crate) async fn heal_after_rewrite(
    common: &crate::args::GlobalArgs,
    inputs: &HealInputs<'_>,
) -> RewriteHeal {
    let mut out = RewriteHeal::default();
    let owned: Vec<vlt_heal::OwnedInstance> = inputs
        .final_lock
        .map(|lock| vlt_heal::socket_owned_instances(lock, &vlt_heal_origins(common)))
        .unwrap_or_default()
        .into_iter()
        .filter(|i| inputs.confirmed_vlt.contains(&i.patch_uuid))
        .collect();
    let targeted: BTreeSet<&str> = owned.iter().map(|i| i.patch_uuid.as_str()).collect();
    let mut tally = HealTally::default();
    let mut healed = false;
    if !owned.is_empty() {
        let targets: Vec<(Target<'_>, &str)> = owned
            .iter()
            .map(|i| {
                let record = inputs.records.values().find(|r| r.uuid == i.patch_uuid);
                (
                    Target {
                        dep_id: &i.dep_id,
                        name: &i.name,
                        lock_sha512: i.sha512.as_deref(),
                        record,
                        flags: i.flags,
                    },
                    i.patch_uuid.as_str(),
                )
            })
            .collect();
        tally = heal_targets(common, &targets, Expected::Patched).await;
        healed = true;
        out.warnings.push(serde_json::json!({
            "code": REINSTALL_REQUIRED,
            "detail": reinstall_detail(&tally),
        }));
    }
    let lock_discards = inputs
        .rewrite_warning_codes
        .iter()
        .any(|code| vlt::DISCARDING_LOCK_CODES.contains(code));
    for (purl, uuid) in inputs.confirmed {
        if !inputs.confirmed_vlt.contains(uuid) {
            continue;
        }
        if lock_discards
            || !targeted.contains(uuid.as_str())
            || inputs.foreign.contains(uuid)
            || tally.stale_uuids.contains(uuid)
            || tally.undeterminable_uuids.contains(uuid)
        {
            out.stale_purls.insert(purl.clone());
        }
    }
    // A bundled copy of a patched package has no lock node, so the
    // redirect never reaches it: say so, and keep its purl out of the
    // in-run attestation (lockfile discovery contests it the same way).
    if inputs.final_lock.is_some() {
        let copies = socket_patch_core::vendor::vlt_bundled::bundled_copies(&common.cwd).await;
        if healed {
            out.healed_store = Some(copies.clone());
        }
        for purl in inputs.records.keys() {
            // The store's keys are decoded purls: look a `%40scope` record
            // up the way the attribution gate does.
            let base = socket_patch_core::utils::purl_key::canonical_base_purl(purl);
            let Some(location) = copies.get(&base) else {
                continue;
            };
            let Some((name, version)) = base
                .strip_prefix("pkg:npm/")
                .and_then(|rest| rest.rsplit_once('@'))
            else {
                continue;
            };
            let name = socket_patch_core::utils::purl::percent_decode_purl_component(name);
            out.warnings.push(serde_json::json!({
                "code": BUNDLED_INSTANCE_SKIPPED,
                "detail": socket_patch_core::vendor::vlt_bundled::bundled_copy_detail(
                    &name, version, location,
                ),
            }));
            out.stale_purls.insert(purl.clone());
        }
    }
    // Heal targets come from the final lock, so the block above saw it.
    debug_assert!(!healed || out.healed_store.is_some());
    out
}

/// The heal after rollback or remove restored the registry pins of
/// `targets` (the ledger's vlt nodes of the unwound purls, collected before
/// the revert): patched store copies are invalidated so the next install
/// extracts the registry bytes. Returns `(code, detail)` warnings.
pub(crate) async fn rollback_heal(
    common: &crate::args::GlobalArgs,
    targets: &[LedgerTarget],
) -> Vec<(String, String)> {
    if targets.is_empty() || common.dry_run {
        return Vec::new();
    }
    let lock = socket_patch_core::utils::fs::read_regular_to_string(&common.cwd.join(VLT_LOCK))
        .await
        .ok();
    let slots: Vec<(Option<String>, Option<u64>)> = targets
        .iter()
        .map(|t| match lock.as_deref() {
            Some(l) => (
                vlt_heal::lock_sha512(l, &t.dep_id),
                vlt_heal::lock_flags(l, &t.dep_id).or(t.flags),
            ),
            None => (None, t.flags),
        })
        .collect();
    let classified: Vec<(Target<'_>, &str)> = targets
        .iter()
        .zip(&slots)
        .map(|(t, (sha, flags))| {
            (
                Target {
                    dep_id: &t.dep_id,
                    name: &t.name,
                    lock_sha512: sha.as_deref(),
                    record: t.record.as_ref(),
                    flags: *flags,
                },
                t.purl.as_str(),
            )
        })
        .collect();
    let tally = heal_targets(common, &classified, Expected::Pristine).await;
    let restored: BTreeSet<&str> = targets.iter().map(|t| t.purl.as_str()).collect();
    rollback_detail(&tally, restored.len())
        .map(|detail| (REINSTALL_REQUIRED.to_string(), detail))
        .into_iter()
        .collect()
}

/// The hosted→vendored heal: once a purl is vendored over its reverted
/// hosted pin, the lock no longer names the registry DepID, so a store copy still holding the hosted bytes is stale
/// against the pristine expectation and is invalidated like a rollback's.
pub(crate) async fn takeover_heal(
    common: &crate::args::GlobalArgs,
    targets: &[LedgerTarget],
) -> Option<String> {
    if targets.is_empty() || common.dry_run {
        return None;
    }
    let classified: Vec<(Target<'_>, &str)> = targets
        .iter()
        .map(|t| {
            (
                Target {
                    dep_id: &t.dep_id,
                    name: &t.name,
                    lock_sha512: None,
                    record: t.record.as_ref(),
                    flags: t.flags,
                },
                t.purl.as_str(),
            )
        })
        .collect();
    let tally = heal_targets(common, &classified, Expected::Pristine).await;
    let vendored: BTreeSet<&str> = targets.iter().map(|t| t.purl.as_str()).collect();
    takeover_detail(&tally, vendored.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_variants_follow_severity_order() {
        let mut tally = HealTally::default();
        assert!(reinstall_detail(&tally).contains("fresh checkouts install them with `vlt ci`"));
        tally.invalidated = 2;
        assert!(reinstall_detail(&tally).contains("socket-patch removed 2 stale installed copies"));
        tally.undeterminable = 1;
        assert!(reinstall_detail(&tally).contains("could not check 1 installed copies"));
        tally.stale_left = 3;
        assert!(reinstall_detail(&tally).contains("still holds 3 unpatched copies and"));
    }

    #[test]
    fn kept_optional_copies_are_reported_alongside_every_variant() {
        let optional = |invalidated, stale_left, undeterminable| HealTally {
            invalidated,
            stale_left,
            optional_left: 2,
            undeterminable,
            ..HealTally::default()
        };
        let also = |held: &str| format!("node_modules also still holds 2 {held}; {OPTIONAL_KEPT}");
        let unpatched = also("unpatched copies of optional dependencies");
        let patched = also("patched copies of optional dependencies");
        let hosted = also("installed copies of the vendored optional dependencies");

        assert_eq!(
            reinstall_detail(&optional(0, 0, 0)),
            format!(
                "vlt-lock.json pins Socket-patched packages, but node_modules still holds 2 \
                 unpatched copies of optional dependencies; {OPTIONAL_KEPT}"
            )
        );
        assert_eq!(
            reinstall_detail(&optional(3, 0, 0)),
            format!(
                "vlt-lock.json pins Socket-patched packages; socket-patch removed 3 stale \
                 installed copies (node_modules/.vlt-lock.json and node_modules/.vlt entries), \
                 so node_modules is incomplete until you run `vlt install` (or `vlt ci`), which \
                 installs the patched packages. {unpatched}{VLT_UPDATE_NOTE}"
            )
        );
        assert_eq!(
            reinstall_detail(&optional(0, 1, 0)),
            format!(
                "vlt-lock.json pins Socket-patched packages, but node_modules still holds 1 \
                 unpatched copies and `vlt install` will not refresh them; run `vlt ci` (or \
                 re-run without --no-vlt-install-cleanup). {unpatched}"
            )
        );
        assert_eq!(
            reinstall_detail(&optional(0, 0, 1)),
            format!("{} {unpatched}", undeterminable_detail(1))
        );

        assert_eq!(
            rollback_detail(&optional(0, 0, 0), 1).unwrap(),
            format!(
                "restored registry pins for 1 packages, but node_modules still holds 2 patched \
                 copies of optional dependencies; {OPTIONAL_KEPT}"
            )
        );
        assert_eq!(
            rollback_detail(&optional(1, 0, 0), 2).unwrap(),
            format!(
                "restored registry pins for 2 packages; removed 1 patched installed copies, so \
                 node_modules is incomplete until you run `vlt install` (or `vlt ci`). {patched}"
            )
        );
        assert_eq!(
            rollback_detail(&optional(0, 1, 0), 2).unwrap(),
            format!(
                "restored registry pins for 2 packages, but node_modules still holds 1 patched \
                 copies and `vlt install` will not refresh them; run `vlt ci` (or re-run \
                 without --no-vlt-install-cleanup). {patched}"
            )
        );
        assert_eq!(rollback_detail(&HealTally::default(), 1), None);

        assert_eq!(
            takeover_detail(&optional(0, 0, 0), 1).unwrap(),
            format!(
                "vendored 1 hosted-pinned packages, but node_modules still holds 2 installed \
                 copies of the vendored optional dependencies; {OPTIONAL_KEPT}"
            )
        );
        assert_eq!(
            takeover_detail(&optional(1, 0, 0), 2).unwrap(),
            format!(
                "vendored 2 hosted-pinned packages; removed 1 hosted installed copies, so \
                 node_modules is incomplete until you run `vlt install`. {hosted}"
            )
        );
        assert_eq!(
            takeover_detail(&optional(0, 1, 0), 2).unwrap(),
            format!(
                "vendored 2 hosted-pinned packages, but node_modules still holds 1 installed \
                 copies of the vendored packages; run `vlt install` (or re-run without \
                 --no-vlt-install-cleanup). {hosted}"
            )
        );
        assert_eq!(takeover_detail(&HealTally::default(), 1), None);
    }
}
