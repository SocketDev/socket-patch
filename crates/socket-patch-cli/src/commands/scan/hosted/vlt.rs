//! The vlt steps of the hosted flow: the artifact preflight, run before any
//! takeover or rewrite, and the warm-tree heal with its
//! `redirect_vlt_reinstall_required` advisory, run after the writes (and by
//! rollback/remove after the vlt pins are restored).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use socket_patch_core::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, VLT_HIDDEN_LOCK_REL, VLT_LOCK, VLT_STORE_DIR,
};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::vlt_heal::{
    self, classify_target, read_install_state, Expected, LedgerTarget, Target, TargetState,
};
use socket_patch_core::patch::redirect::vlt_preflight::{self, OFFLINE_REASON};
use socket_patch_core::patch::redirect::{vlt, DepOverride};

use super::StaleInstallOutcome;

pub(super) const REINSTALL_REQUIRED: &str = "redirect_vlt_reinstall_required";
const ARTIFACT_UNVERIFIABLE: &str = "redirect_vlt_artifact_unverifiable";

/// The lock-level warnings that say vlt may discard the redirect (§3.9 (c);
/// `redirect_vlt_sibling_lockfiles` says nothing about vlt's reading of the
/// lock).
const DISCARDING_LOCK_WARNINGS: [&str; 3] = [
    "redirect_vlt_lockfile_version_missing",
    "redirect_vlt_old_lockfile_ignored",
    "redirect_vlt_scalar_registry_ignored",
];

/// Whether vlt's install state exists: the hidden lock as a regular file,
/// or the store as a real directory. Stat only; the hidden lock can be
/// megabytes and is never read into the rewriter's input.
pub(super) fn install_state_present(cwd: &Path) -> bool {
    let is = |rel: &str, dir: bool| {
        std::fs::symlink_metadata(cwd.join(rel)).is_ok_and(|m| {
            if dir {
                m.file_type().is_dir()
            } else {
                m.file_type().is_file()
            }
        })
    };
    is(VLT_HIDDEN_LOCK_REL, false) || is(VLT_STORE_DIR, true)
}

/// What the artifact preflight decided for this run's npm candidates.
#[derive(Default)]
pub(super) struct Preflight {
    /// Failed while vlt drives, or for a vlt-vendored takeover: withheld
    /// from every rewriter.
    pub(super) withheld_everywhere: BTreeMap<String, String>,
    /// Failed while another npm-family lock may drive: kept out of the vlt
    /// rewrite only.
    pub(super) withheld_from_vlt: BTreeSet<String>,
    pub(super) passed: BTreeSet<String>,
    /// Artifact bytes by URL, for the heal's no-record comparison.
    pub(super) artifacts: BTreeMap<String, Vec<u8>>,
    pub(super) warnings: Vec<serde_json::Value>,
}

/// The files `vlt_drives` and the preflight scope read: `vlt-lock.json`
/// itself, and presence-only entries for the sibling locks and vlt's
/// install state. Empty without a readable `vlt-lock.json`.
async fn vlt_inputs(cwd: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let Ok(lock) = socket_patch_core::utils::fs::read_regular_to_string(&cwd.join(VLT_LOCK)).await
    else {
        return files;
    };
    files.insert(VLT_LOCK.to_string(), lock);
    for sibling in [NPM_LOCKS[0], NPM_LOCKS[1], "yarn.lock", PNPM_LOCK, BUN_LOCK] {
        if std::fs::metadata(cwd.join(sibling)).is_ok_and(|m| m.is_file()) {
            files.insert(sibling.to_string(), String::new());
        }
    }
    if install_state_present(cwd) {
        files.insert(VLT_HIDDEN_LOCK_REL.to_string(), String::new());
    }
    files
}

fn unverifiable_detail(
    url: &str,
    reason: &str,
    purl: &str,
    already_pinned: bool,
    everywhere: bool,
) -> String {
    if already_pinned {
        format!(
            "vlt would fail to verify {url}: {reason}; {purl} was left pinned by an earlier run \
             and `vlt ci` will fail until the artifact verifies"
        )
    } else if everywhere {
        format!("vlt would fail to verify {url}: {reason}; nothing was written for {purl}")
    } else {
        format!(
            "vlt would fail to verify {url}: {reason}; vlt-lock.json was not changed for {purl}"
        )
    }
}

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
/// `vlt-lock.json`. Projects without `vlt-lock.json` make no request. A
/// vlt-vendored dep is probed through its vendored node, before the
/// takeover reverts it, and a failure keeps it vendored.
pub(super) async fn artifact_preflight(
    common: &crate::args::GlobalArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    deps: &[(&str, &DepOverride)],
) -> Preflight {
    let mut out = Preflight::default();
    let files = vlt_inputs(&common.cwd).await;
    if files.is_empty() {
        return out;
    }
    let overrides: Vec<DepOverride> = deps.iter().map(|(_, dep)| (*dep).clone()).collect();
    let vendored = vlt_vendored_uuids(&common.cwd, deps).await;
    let scope = vlt_preflight::preflight_scope(&files, &overrides, &vendored);
    if scope.is_empty() {
        return out;
    }
    let drives = vlt::vlt_drives(&files, common.cwd.join(BUN_LOCKB).exists());
    let urls: BTreeSet<String> = scope.iter().map(|d| d.artifact_url.clone()).collect();
    let probes = if common.offline {
        BTreeMap::new()
    } else {
        vlt_preflight::probe_artifacts(api_client, &urls).await
    };
    for dep in &scope {
        let reason = match probes.get(&dep.artifact_url) {
            None => Some(OFFLINE_REASON.to_string()),
            Some(probe) => probe.failure(&dep.sha512),
        };
        let Some(reason) = reason else {
            out.passed.insert(dep.patch_uuid.clone());
            if let Some(body) = probes.get(&dep.artifact_url).and_then(|p| p.body.clone()) {
                out.artifacts.insert(dep.artifact_url.clone(), body);
            }
            continue;
        };
        let purl = deps
            .iter()
            .find(|(_, d)| d.patch_uuid == dep.patch_uuid)
            .map_or("", |(purl, _)| *purl);
        let everywhere = drives || dep.vendored;
        out.warnings.push(serde_json::json!({
            "code": ARTIFACT_UNVERIFIABLE,
            "detail": unverifiable_detail(
                &dep.artifact_url,
                &reason,
                purl,
                dep.already_pinned,
                everywhere,
            ),
        }));
        if everywhere {
            out.withheld_everywhere
                .insert(dep.patch_uuid.clone(), purl.to_string());
        } else {
            out.withheld_from_vlt.insert(dep.patch_uuid.clone());
        }
    }
    out
}

/// The skip `reason` of a dep the preflight withheld from every rewriter.
pub(super) const WITHHELD_REASON: &str = ARTIFACT_UNVERIFIABLE;

fn patch_server_origins(common: &crate::args::GlobalArgs) -> Vec<String> {
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
    undeterminable: usize,
    stale_uuids: BTreeSet<String>,
    undeterminable_uuids: BTreeSet<String>,
}

/// Classify `targets` against `expected` and invalidate the stale ones
/// unless cleanup is off. `(dep_id, name, lock sha512, record, artifact,
/// uuid)` per target.
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

fn reinstall_detail(tally: &HealTally) -> String {
    if tally.stale_left > 0 {
        format!(
            "vlt-lock.json pins Socket-patched packages, but node_modules still holds {} \
             unpatched copies and `vlt install` will not refresh them; run `vlt ci` (or re-run \
             without --no-vlt-install-cleanup).",
            tally.stale_left
        )
    } else if tally.undeterminable > 0 {
        undeterminable_detail(tally.undeterminable)
    } else if tally.invalidated > 0 {
        format!(
            "vlt-lock.json pins Socket-patched packages; socket-patch removed {} stale installed \
             copies (node_modules/.vlt-lock.json and node_modules/.vlt entries), so node_modules \
             is incomplete until you run `vlt install` (or `vlt ci`), which installs the patched \
             packages. Note: `vlt update` re-resolves from the registry and drops these \
             redirects.",
            tally.invalidated
        )
    } else {
        "vlt-lock.json pins Socket-patched packages; fresh checkouts install them with `vlt ci` \
         or `vlt install --frozen-lockfile`. Note: `vlt update` re-resolves from the registry \
         and drops these redirects."
            .to_string()
    }
}

fn undeterminable_detail(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but socket-patch could not check {n} \
         installed copies (node_modules is a link, or no patch record or artifact was \
         available); run `vlt ci` to be sure the patched packages are installed."
    )
}

/// What this run's vlt rewrite needs from the rest of the hosted flow.
pub(super) struct HealInputs<'a> {
    /// The final `vlt-lock.json` (as written, or as a dry run would write it).
    pub(super) final_lock: Option<&'a str>,
    pub(super) preflight: &'a Preflight,
    /// This run's fetched records merged with the ledger's, keyed by purl.
    pub(super) records: &'a BTreeMap<String, PatchRecord>,
    pub(super) confirmed: &'a [(String, String)],
    pub(super) confirmed_vlt: &'a BTreeSet<String>,
    pub(super) foreign: &'a BTreeSet<String>,
    pub(super) rewrite_warning_codes: &'a [&'a str],
}

/// The heal after a hosted rewrite, the advisory, and the purls whose
/// installed or next-installed bytes are not known to be patched (removed
/// from the same run's in-run VEX attestation). A confirmed vlt uuid with
/// no heal target (a non-Socket host, a leaf that disagrees with the
/// DepID, an artifact no preflight verified) was never checked, so it is
/// never attested here.
pub(super) async fn heal_after_rewrite(
    common: &crate::args::GlobalArgs,
    inputs: &HealInputs<'_>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    let owned: Vec<vlt_heal::OwnedInstance> = inputs
        .final_lock
        .map(|lock| vlt_heal::socket_owned_instances(lock, &patch_server_origins(common)))
        .unwrap_or_default()
        .into_iter()
        .filter(|i| inputs.preflight.passed.contains(&i.patch_uuid))
        .collect();
    let targeted: BTreeSet<&str> = owned.iter().map(|i| i.patch_uuid.as_str()).collect();
    let mut tally = HealTally::default();
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
                    },
                    i.patch_uuid.as_str(),
                )
            })
            .collect();
        tally = heal_targets(common, &targets, Expected::Patched).await;
        out.warnings.push(serde_json::json!({
            "code": REINSTALL_REQUIRED,
            "detail": reinstall_detail(&tally),
        }));
    }
    let lock_discards = inputs
        .rewrite_warning_codes
        .iter()
        .any(|code| DISCARDING_LOCK_WARNINGS.contains(code));
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
    let shas: Vec<Option<String>> = targets
        .iter()
        .map(|t| {
            lock.as_deref()
                .and_then(|l| vlt_heal::lock_sha512(l, &t.dep_id))
        })
        .collect();
    let classified: Vec<(Target<'_>, &str)> = targets
        .iter()
        .zip(&shas)
        .map(|(t, sha)| {
            (
                Target {
                    dep_id: &t.dep_id,
                    name: &t.name,
                    lock_sha512: sha.as_deref(),
                    record: t.record.as_ref(),
                    artifact: None,
                },
                t.purl.as_str(),
            )
        })
        .collect();
    let tally = heal_targets(common, &classified, Expected::Pristine).await;
    let restored: BTreeSet<&str> = targets.iter().map(|t| t.purl.as_str()).collect();
    let detail = if tally.stale_left > 0 {
        format!(
            "restored registry pins for {} packages, but node_modules still holds {} patched \
             copies and `vlt install` will not refresh them; run `vlt ci` (or re-run without \
             --no-vlt-install-cleanup)",
            restored.len(),
            tally.stale_left
        )
    } else if tally.undeterminable > 0 {
        undeterminable_detail(tally.undeterminable)
    } else if tally.invalidated > 0 {
        format!(
            "restored registry pins for {} packages; removed the patched installed copies, so \
             node_modules is incomplete until you run `vlt install` (or `vlt ci`)",
            restored.len()
        )
    } else {
        return Vec::new();
    };
    vec![(REINSTALL_REQUIRED.to_string(), detail)]
}

/// The hosted→vendored heal (DESIGN §4.10 step 4): once a purl is
/// vendored over its reverted hosted pin, the lock no longer names the
/// registry DepID, so a store copy still holding the hosted bytes is stale
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
                },
                t.purl.as_str(),
            )
        })
        .collect();
    let tally = heal_targets(common, &classified, Expected::Pristine).await;
    let vendored: BTreeSet<&str> = targets.iter().map(|t| t.purl.as_str()).collect();
    let detail = if tally.stale_left > 0 {
        format!(
            "vendored {} hosted-pinned packages, but node_modules still holds {} copies of the \
             hosted artifacts; run `vlt install` (or re-run without --no-vlt-install-cleanup)",
            vendored.len(),
            tally.stale_left
        )
    } else if tally.undeterminable > 0 {
        undeterminable_detail(tally.undeterminable)
    } else if tally.invalidated > 0 {
        format!(
            "vendored {} hosted-pinned packages; removed their hosted installed copies, so \
             node_modules is incomplete until you run `vlt install`",
            vendored.len()
        )
    } else {
        return None;
    };
    Some(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_api() -> socket_patch_core::api::client::ApiClient {
        socket_patch_core::api::client::ApiClient::new(
            socket_patch_core::api::client::ApiClientOptions {
                api_url: "http://127.0.0.1:9".into(),
                api_token: Some("secret".into()),
                use_public_proxy: false,
                org_slug: Some("org".into()),
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
        assert!(reinstall_detail(&tally).contains("still holds 3 unpatched copies"));
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
            berry_zip_url: None,
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
            pre.warnings[0]["detail"],
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
            claimed.warnings[0]["detail"],
            format!("vlt would fail to verify {url}: http 404; nothing was written for pkg:npm/left-pad@1.3.0")
        );
    }
}
