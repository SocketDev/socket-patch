//! The vlt steps shared by the hosted flow and the unwinds: the artifact
//! preflight, run before any takeover or rewrite, and the warm-tree heal
//! with its `redirect_vlt_reinstall_required` advisory, run after a hosted
//! rewrite, after rollback/remove restore the vlt pins, and after a
//! hosted→vendored takeover. A helper module, not a command: `scan`,
//! `rollback`, `remove` and `vendor` all reach it without importing each
//! other.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use socket_patch_core::constants::npm_family::{VLT_HIDDEN_LOCK_REL, VLT_LOCK};
use socket_patch_core::hosted::vlt::{self as hosted_vlt, Preflight};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::vlt_heal::{
    self, classify_target, read_install_state, Expected, LedgerTarget, Target, TargetState,
};
use socket_patch_core::patch::redirect::vlt_preflight;
use socket_patch_core::patch::redirect::{vlt, DepOverride};
use socket_patch_core::vendor::lock_inventory::ProjectView;

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
    pub(crate) healed_store: Option<std::collections::BTreeMap<String, String>>,
}

pub(crate) const REINSTALL_REQUIRED: &str = "redirect_vlt_reinstall_required";
/// A bundled copy of a redirected package that no rewire reaches (#471).
pub(crate) const BUNDLED_INSTANCE_SKIPPED: &str = "redirect_vlt_bundled_instance_skipped";

/// The uuids of `deps` whose purl a vlt vendored ledger entry claims: a
/// hosted takeover reverts them to a registry node before the rewrite.
async fn vlt_vendored_uuids(cwd: &Path, deps: &[(&str, &DepOverride)]) -> BTreeSet<String> {
    let Ok(state) = socket_patch_core::vendor::load_state(cwd).await else {
        return BTreeSet::new();
    };
    deps.iter()
        .filter(|(purl, _)| {
            socket_patch_core::vendor::lookup_entry(
                &state.entries,
                socket_patch_core::utils::purl::strip_purl_qualifiers(purl),
            )
            .is_some_and(|e| e.ecosystem == "npm" && e.flavor.as_deref() == Some("vlt"))
        })
        .map(|(_, dep)| dep.patch_uuid.clone())
        .collect()
}

/// Fetch each in-scope artifact the way vlt does (once per distinct URL,
/// `offline` making no request) and decide which deps may be pinned in
/// `vlt-lock.json` ([`socket_patch_core::hosted::vlt`]). Projects without
/// `vlt-lock.json` make no request. A vlt-vendored dep is probed through
/// its vendored node, before the takeover reverts it, and a failure keeps
/// it vendored.
pub(crate) async fn artifact_preflight(
    common: &crate::args::GlobalArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    deps: &[(&str, &DepOverride)],
) -> Preflight {
    let view = ProjectView::Disk(&common.cwd);
    let files = hosted_vlt::inputs(&view).await;
    if files.is_empty() {
        return Preflight::default();
    }
    let vendored = vlt_vendored_uuids(&common.cwd, deps).await;
    let Some(plan) = hosted_vlt::plan(&view, &files, deps, &vendored) else {
        return Preflight::default();
    };
    let probes = if common.offline {
        BTreeMap::new()
    } else {
        vlt_preflight::probe_artifacts(api_client, &plan.urls()).await
    };
    hosted_vlt::judge(&plan, deps, probes)
}

/// The origins the vlt heal treats as Socket-owned in the final lock: the
/// patch server plus `--api-url`. Unlike discovery's
/// [`crate::commands::hosted_unwind::patch_server_origins`], it also counts the
/// `--api-url` origin (as it has since vlt support landed, #269), so a
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

fn cleanup_disabled(common: &crate::args::GlobalArgs) -> bool {
    common.dry_run || common.no_vlt_install_cleanup
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
    if cleanup_disabled(common) {
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
         installed copies (node_modules is a link, or no patch record or artifact was \
         available); run `vlt ci` to be sure the patched packages are installed."
    )
}

/// What this run's vlt rewrite needs from the rest of the hosted flow.
pub(crate) struct HealInputs<'a> {
    /// The final `vlt-lock.json` (as written, or as a dry run would write it).
    pub(crate) final_lock: Option<&'a str>,
    pub(crate) preflight: &'a Preflight,
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
/// DepID, an artifact no preflight verified) was never checked, so it is
/// never attested here.
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
        .filter(|i| inputs.preflight.passed.contains(&i.patch_uuid))
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
                        artifact: inputs.preflight.artifacts.get(&i.url).map(Vec::as_slice),
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
    // A bundled copy of a patched package (#471) has no lock node, so the
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
    // A heal implies a final lock, so the block above recorded the store;
    // never report a heal without it.
    if healed && out.healed_store.is_none() {
        out.healed_store =
            Some(socket_patch_core::vendor::vlt_bundled::bundled_copies(&common.cwd).await);
    }
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
                    artifact: None,
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
                    artifact: None,
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

    fn test_api() -> socket_patch_core::api::client::ApiClient {
        socket_patch_core::api::client::ApiClient::new(
            socket_patch_core::api::client::ApiClientOptions {
                api_url: "http://127.0.0.1:9".into(),
                api_token: Some("secret".into()),
                route: socket_patch_core::api::client::ApiRoute::org("org"),
            },
        )
    }

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

    fn left_pad_dep(url: &str) -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: "left-pad".into(),
            namespace: None,
            version: "1.3.0".into(),
            token: String::new(),
            patch_uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            artifact_url: url.to_string(),
            registry_override: None,
            integrity: socket_patch_core::patch::redirect::Integrity {
                sha512: Some("sha512-new".into()),
                ..Default::default()
            },
        }
    }

    const LEFT_PAD_LOCK: &str = "{\n  \"lockfileVersion\": 1,\n  \"options\": {},\n  \"nodes\": \
         {\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-old\",\
         \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"]\n  },\n  \"edges\": {}\n}\n";

    #[tokio::test]
    async fn offline_withholds_every_probed_dep_without_a_request() {
        let server = wiremock::MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let url = format!("{}/patch/npm/t/u/left-pad-1.3.0.tgz", server.uri());
        std::fs::write(tmp.path().join(VLT_LOCK), LEFT_PAD_LOCK).unwrap();
        let dep = left_pad_dep(&url);
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let api = test_api();
        let pre = artifact_preflight(&common, &api, &[("pkg:npm/left-pad@1.3.0", &dep)]).await;
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(pre.passed.is_empty());
        assert_eq!(
            pre.withheld_everywhere
                .get(&dep.patch_uuid)
                .map(String::as_str),
            Some("pkg:npm/left-pad@1.3.0")
        );
        assert_eq!(
            pre.warnings[0].detail,
            format!(
                "vlt would fail to verify {url}: offline; nothing was written for \
                 pkg:npm/left-pad@1.3.0"
            )
        );
    }

    #[tokio::test]
    async fn no_vlt_lock_makes_no_request() {
        let server = wiremock::MockServer::start().await;
        let url = format!("{}/patch/npm/t/u/left-pad-1.3.0.tgz", server.uri());
        let dep = left_pad_dep(&url);
        let api = test_api();
        for with_lock in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("package-lock.json"), "{}").unwrap();
            if with_lock {
                std::fs::write(tmp.path().join(VLT_LOCK), LEFT_PAD_LOCK).unwrap();
            }
            let common = crate::args::GlobalArgs {
                cwd: tmp.path().to_path_buf(),
                ..crate::args::GlobalArgs::default()
            };
            let pre = artifact_preflight(&common, &api, &[("pkg:npm/left-pad@1.3.0", &dep)]).await;
            let requests = server.received_requests().await.unwrap().len();
            if with_lock {
                assert_eq!(requests, 1, "the control probes the vlt lock's dep");
                assert!(pre.withheld_from_vlt.contains(&dep.patch_uuid));
            } else {
                assert_eq!(requests, 0);
                assert!(pre.passed.is_empty() && pre.warnings.is_empty());
                assert!(pre.withheld_everywhere.is_empty() && pre.withheld_from_vlt.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn a_vlt_vendored_dep_is_probed_and_withheld_everywhere() {
        let server = wiremock::MockServer::start().await;
        let url = format!("{}/patch/npm/t/u/left-pad-1.3.0.tgz", server.uri());
        let dep = left_pad_dep(&url);
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), "{}").unwrap();
        std::fs::write(
            tmp.path().join(VLT_LOCK),
            "{\n  \"lockfileVersion\": 1,\n  \"options\": {},\n  \"nodes\": {\n    \
             \"file~.socket+vendor+npm+11111111-2222-4333-8444-555555555555+left-pad-1.3.0+node__modules+left-pad\": \
             [0,\"left-pad\",null,\".socket/vendor/npm/11111111-2222-4333-8444-555555555555/left-pad-1.3.0/node_modules/left-pad\"]\n  \
             },\n  \"edges\": {}\n}\n",
        )
        .unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..crate::args::GlobalArgs::default()
        };
        let api = test_api();
        let deps = [("pkg:npm/left-pad@1.3.0", &dep)];
        let unclaimed = artifact_preflight(&common, &api, &deps).await;
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(unclaimed.warnings.is_empty());
        std::fs::create_dir_all(tmp.path().join(".socket/vendor")).unwrap();
        std::fs::write(
            tmp.path().join(".socket/vendor/state.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "entries": { "pkg:npm/left-pad@1.3.0": {
                    "ecosystem": "npm", "basePurl": "pkg:npm/left-pad@1.3.0",
                    "uuid": "11111111-2222-4333-8444-555555555555",
                    "artifact": { "path": ".socket/vendor/npm/11111111-2222-4333-8444-555555555555/left-pad-1.3.0" },
                    "wiring": [], "flavor": "vlt"
                }}
            }))
            .unwrap(),
        )
        .unwrap();
        let claimed = artifact_preflight(&common, &api, &deps).await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert!(claimed.withheld_from_vlt.is_empty());
        assert!(claimed.withheld_everywhere.contains_key(&dep.patch_uuid));
        assert_eq!(
            claimed.warnings[0].detail,
            format!("vlt would fail to verify {url}: http 404; nothing was written for pkg:npm/left-pad@1.3.0")
        );
    }
}
