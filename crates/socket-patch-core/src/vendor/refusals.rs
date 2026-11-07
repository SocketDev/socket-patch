//! The vendored-mode refusals a run can decide before it downloads a patch
//! or writes anything: the one answer every vendored entry point reads.
//! `scan --mode vendored` (download phase, dry-run preview and rollout
//! plan), `get … --mode vendored` (both identifier paths) and the `vendor`
//! command's record loop (before the hosted→vendored takeover reverts a
//! live pin) all call [`vendor_refusals`], so a package the engine would
//! refuse is refused everywhere with the engine's own code and detail, and
//! never has its view fetched, its download granted or its hosted pin
//! stripped.
//!
//! The checks run in the engine's order, the first one that refuses a purl
//! winning:
//!
//! 1. the npm flavor gate the router picks: Bun's project refusal (with its
//!    already-vendored exemption) or vlt's per-purl refusals, either one
//!    naming an unreadable ledger as `vendor_state_unreadable`;
//! 2. the npm package-lock project refusal (a lock that is not v2/v3);
//! 3. the lock-text refusals a hosted pnpm pin's takeover meets (#853);
//! 4. the lock-text refusals of every other npm and cargo candidate, the
//!    ones the backend raises on the lock and manifest text alone.
//!
//! Each check lives in its backend's module; this one only dispatches and
//! scopes them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use futures_util::future::BoxFuture;

use crate::crawlers::Ecosystem;
use crate::patch::redirect::upstream::HostedPin;
use crate::utils::purl_key::PurlKey;
use crate::vendor::state::{lookup_entry, VendorEntry};
use crate::vendor::{bun_lock, lock_inventory, npm_flavor, npm_lock, vlt_lock};

/// The vendor ledger as the refusals consume it: the caller's own load
/// outcome, so an UNREADABLE ledger is a refusal the run can report
/// instead of a silently empty ledger.
pub type LedgerLoad<'a> = Result<&'a HashMap<String, VendorEntry>, &'a std::io::Error>;

/// A purl the engine would refuse: its stable code and detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRefusal {
    pub code: &'static str,
    pub detail: String,
}

/// The refusals of one run, keyed by the candidate purl as given.
pub type VendorRefusals = BTreeMap<String, VendorRefusal>;

/// Which of `purls` have an installed copy on disk (the caller's crawl).
pub type InstalledLookup<'a> =
    dyn Fn(Vec<String>) -> BoxFuture<'a, HashSet<String>> + Send + Sync + 'a;

/// What the scoping of the lock-text checks needs from the caller.
pub struct RefusalScope<'a, 'b> {
    /// The project's live hosted pins: vendoring one of their purls is a
    /// hosted→vendored takeover, which restores the upstream lock entry
    /// before the backend reads it.
    pub hosted_pins: &'a [HostedPin],
    /// Asked only for lock-text refused purls the lockfile does not
    /// resolve to a verifiable registry source: such a purl reaches its
    /// backend only when it is installed.
    pub installed: &'a InstalledLookup<'b>,
}

fn is_npm(purl: &str) -> bool {
    Ecosystem::from_purl(purl) == Some(Ecosystem::Npm)
}

fn is_cargo(purl: &str) -> bool {
    Ecosystem::from_purl(purl) == Some(Ecosystem::Cargo)
}

/// Every refusal the vendor engine can decide for `candidates` (`(purl,
/// uuid)` pairs) before any download, in the engine's order (see the
/// module docs). Read-only; a candidate absent from the result is left to
/// the engine.
pub async fn vendor_refusals(
    project_root: &Path,
    candidates: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
    scope: &RefusalScope<'_, '_>,
) -> VendorRefusals {
    let mut out = VendorRefusals::new();
    let npm: Vec<(&str, &str)> = candidates
        .iter()
        .filter(|(purl, _)| is_npm(purl))
        .copied()
        .collect();
    if !npm.is_empty() {
        npm_flavor_refusals(project_root, &npm, ledger, &mut out).await;
        if let Some((code, detail)) = npm_lock::npm_lock_vendor_preflight(project_root).await {
            for (purl, _) in &npm {
                refuse(&mut out, purl, code, &detail);
            }
        }
    }
    let empty = HashMap::new();
    let entries = ledger.unwrap_or(&empty);
    let claimed: HashSet<PurlKey> = scope
        .hosted_pins
        .iter()
        .map(|pin| PurlKey::new(&pin.purl))
        .collect();
    let open = |purl: &str| !out.contains_key(purl);

    let takeovers: Vec<(&str, &str)> = npm
        .iter()
        .filter(|(purl, uuid)| {
            open(purl)
                && claimed.contains(&PurlKey::new(purl))
                && lookup_entry(entries, purl).is_none_or(|e| e.uuid != *uuid)
        })
        .copied()
        .collect();
    let takeover_refusals = if takeovers.is_empty()
        || tokio::fs::metadata(project_root.join("pnpm-lock.yaml"))
            .await
            .is_err()
    {
        HashMap::new()
    } else {
        super::pnpm_takeover_lock_text_refusals(project_root, &takeovers).await
    };

    let gated: Vec<(&str, &str)> = candidates
        .iter()
        .filter(|(purl, uuid)| {
            (is_npm(purl) || is_cargo(purl))
                && open(purl)
                && !claimed.contains(&PurlKey::new(purl))
                && !lookup_entry(entries, purl).is_some_and(|e| e.detached && e.uuid == *uuid)
        })
        .copied()
        .collect();
    let lock_text = if gated.is_empty() {
        HashMap::new()
    } else {
        let refused = super::lock_text_refusals(project_root, &gated).await;
        reaching_backend(project_root, refused, entries, scope.installed).await
    };

    for (purl, (code, detail)) in takeover_refusals.into_iter().chain(lock_text) {
        refuse(&mut out, &purl, code, &detail);
    }
    out
}

fn refuse(out: &mut VendorRefusals, purl: &str, code: &'static str, detail: &str) {
    out.entry(purl.to_string())
        .or_insert_with(|| VendorRefusal {
            code,
            detail: detail.to_string(),
        });
}

/// The npm flavor gate the router picks for this project. vlt wins the
/// router (DESIGN D2): a Bun lock beside `vlt-lock.json` is never the one
/// vendoring rewires, so a vlt-routed project is judged per purl by the vlt
/// backend's read-only checks, and any other project by Bun's
/// project-level refusal.
async fn npm_flavor_refusals(
    project_root: &Path,
    npm: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
    out: &mut VendorRefusals,
) {
    match npm_flavor::vlt_routes(project_root).await {
        Some(route) => vlt_refusals(project_root, npm, ledger, route, out).await,
        None => bun_refusals(project_root, npm, ledger, out).await,
    }
}

/// vlt's refusals, per npm purl, in the backend's order: an unreadable
/// ledger, the lock sniff, the flavor guard, then the target analysis,
/// installed store copy and gitignore checks.
async fn vlt_refusals(
    project_root: &Path,
    npm: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
    route: Result<(), (&'static str, String)>,
    out: &mut VendorRefusals,
) {
    for (purl, uuid) in npm {
        let (code, detail) = match (&route, ledger) {
            (_, Err(e)) => ("vendor_state_unreadable", e.to_string()),
            (Err((code, detail)), Ok(_)) => (*code, detail.clone()),
            (Ok(()), Ok(entries)) => match npm_flavor::vlt_flavor_change_refusal(entries, purl) {
                Some(detail) => ("vendor_flavor_changed", detail),
                None => match vlt_lock::vlt_vendor_preflight(project_root, purl, uuid).await {
                    Ok(()) => continue,
                    Err(refusal) => refusal,
                },
            },
        };
        refuse(out, purl, code, &detail);
    }
}

/// Bun's project-level refusal (a malformed binary `bun.lockb`, an
/// unreadable lock, an unsupported `lockfileVersion`, a pre-version-2
/// `workspace:` lock) applied to every npm purl, less the exempt ones.
///
/// A purl is exempt only from the workspace gate, and only when `bun.lock`
/// wires every instance of its `name@version` to one of our
/// `.socket/vendor/npm/` tuples, at any uuid
/// ([`bun_lock::wired_instances_all_ours`]): updating an already-local
/// tuple introduces no new relative path, so in-sync runs, superseding
/// patches and repairs stay supported. A matching ledger uuid alone is not
/// enough, since `rollback --preserve-state` keeps the entry after removing
/// its wiring. Every other code means `bun.lock` could not be read or
/// parsed, so nothing in it can be ours.
///
/// An unreadable ledger exempts nothing (fail closed) and becomes the
/// refusal itself, `vendor_state_unreadable` with the io/parse detail, so
/// the one refusal the run emits names the real problem rather than send
/// the operator off to re-lock `bun.lock`.
async fn bun_refusals(
    project_root: &Path,
    npm: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
    out: &mut VendorRefusals,
) {
    let Err((code, detail)) = bun_lock::preflight_vendor(project_root).await else {
        return;
    };
    if let Err(e) = ledger {
        for (purl, _) in npm {
            refuse(out, purl, "vendor_state_unreadable", &e.to_string());
        }
        return;
    }
    for (purl, _) in npm {
        let exempt = code == "vendor_bun_workspace_unsupported"
            && bun_lock::wired_instances_all_ours(project_root, purl)
                .await
                .unwrap_or(false);
        if !exempt {
            refuse(out, purl, code, &detail);
        }
    }
}

/// Keep only the lock-text refusals of packages the vendor loop would hand
/// to their backend: one the lockfile (or the ledger's recorded original)
/// resolves to a verifiable registry source, or one installed on disk. A
/// package with neither, absent from the lock and not installed, never
/// reaches its backend: the loop reports it `skipped` /
/// `package_not_installed`, and so it still does.
async fn reaching_backend(
    project_root: &Path,
    mut refused: HashMap<String, (&'static str, String)>,
    ledger: &HashMap<String, VendorEntry>,
    installed: &InstalledLookup<'_>,
) -> HashMap<String, (&'static str, String)> {
    if refused.is_empty() {
        return refused;
    }
    let inventory = lock_inventory::inventory_project(project_root).await;
    let mut unresolved: Vec<String> = Vec::new();
    for purl in refused.keys() {
        if !pristine_fetch_is_verifiable(project_root, &inventory, purl, lookup_entry(ledger, purl))
            .await
        {
            unresolved.push(purl.clone());
        }
    }
    if unresolved.is_empty() {
        return refused;
    }
    unresolved.sort();
    let installed = installed(unresolved.clone()).await;
    for purl in unresolved {
        if !installed.contains(&purl) {
            refused.remove(&purl);
        }
    }
    refused
}

/// Whether the backend can fetch `purl`'s pristine source and verify it:
/// the lockfile pins it with an integrity, or the ledger's recorded
/// original entry does.
pub async fn pristine_fetch_is_verifiable(
    project_root: &Path,
    inventory: &[lock_inventory::LockfileEntry],
    purl: &str,
    ledger_entry: Option<&VendorEntry>,
) -> bool {
    let verifiable =
        |e: &lock_inventory::LockfileEntry| e.integrity != lock_inventory::LockIntegrity::None;
    if lock_inventory::lookup(inventory, purl).is_some_and(verifiable) {
        return true;
    }
    match ledger_entry {
        Some(le) => lock_inventory::recover_lock_entry(project_root, le)
            .await
            .is_ok_and(|e| verifiable(&e)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::load_state;

    const UUID: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_UUID: &str = "33333333-3333-4333-8333-333333333333";

    fn nothing_installed(_: Vec<String>) -> BoxFuture<'static, HashSet<String>> {
        Box::pin(async { HashSet::new() })
    }

    async fn run_scoped(
        root: &Path,
        pairs: &[(&str, &str)],
        ledger: LedgerLoad<'_>,
        pins: &[HostedPin],
        installed: &InstalledLookup<'_>,
    ) -> VendorRefusals {
        vendor_refusals(
            root,
            pairs,
            ledger,
            &RefusalScope {
                hosted_pins: pins,
                installed,
            },
        )
        .await
    }

    async fn run(root: &Path, pairs: &[(&str, &str)], ledger: LedgerLoad<'_>) -> VendorRefusals {
        run_scoped(root, pairs, ledger, &[], &nothing_installed).await
    }

    /// The refusals over the ledger as it reads on disk now.
    async fn run_on_disk(root: &Path, pairs: &[(&str, &str)]) -> VendorRefusals {
        let state = load_state(root).await;
        run(root, pairs, state.as_ref().map(|s| &s.entries)).await
    }

    fn entry(json: serde_json::Value) -> VendorEntry {
        serde_json::from_value(json).unwrap()
    }

    mod bun {
        use super::*;

        const PURL: &str = "pkg:npm/covgap-bun@1.0.0";
        const PYPI: &str = "pkg:pypi/only@1.0.0";

        /// A real bun 1.3.14 lockfileVersion-1 workspace lock (matrix capture
        /// grammar) resolving `covgap-bun@1.0.0` from the registry.
        const BUN_V1_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "unit-fixture",
      "dependencies": {
        "consumer": "workspace:*",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "covgap-bun": "1.0.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer"],

    "covgap-bun": ["covgap-bun@1.0.0", "", {}, "sha512-AAAA=="],
  }
}
"#;

        fn seed_vendor_entry(root: &Path, uuid: &str) {
            let vendor = root.join(".socket/vendor");
            std::fs::create_dir_all(&vendor).unwrap();
            std::fs::write(
                vendor.join("state.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "version": 1,
                    "entries": { PURL: {
                        "ecosystem": "npm",
                        "basePurl": PURL,
                        "uuid": uuid,
                        "artifact": {
                            "path": format!(".socket/vendor/npm/{uuid}/covgap-bun-1.0.0.tgz"),
                        },
                        "wiring": [],
                        "flavor": "bun",
                    }}
                }))
                .unwrap(),
            )
            .unwrap();
        }

        /// The lock as it reads once `covgap-bun` is vendored at `uuid`.
        fn vendored_lock(uuid: &str) -> String {
            BUN_V1_WORKSPACE_LOCK.replace(
                r#"["covgap-bun@1.0.0", "", {}, "sha512-AAAA=="]"#,
                &format!(
                    r#"["covgap-bun@.socket/vendor/npm/{uuid}/covgap-bun-1.0.0.tgz", {{}}, "sha512-OURS=="]"#
                ),
            )
        }

        /// Nothing selected is npm: the Bun lock is never judged. A ledger
        /// alone never exempts; an unreadable ledger exempts nothing (fail
        /// closed) AND is reported as the real problem
        /// (`vendor_state_unreadable`), never as a Bun lock remedy.
        #[tokio::test]
        async fn scope_and_corrupt_ledger() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
            let pypi = [(
                "pkg:pypi/only@1.0.0",
                "11111111-1111-4111-8111-111111111111",
            )];
            assert!(run_on_disk(tmp.path(), &pypi).await.is_empty());

            let npm = [(PURL, UUID), (PYPI, UUID)];
            let refusals = run_on_disk(tmp.path(), &npm).await;
            assert_eq!(refusals[PURL].code, "vendor_bun_lockb_invalid");
            assert!(!refusals.contains_key(PYPI));

            // A ledger at this UUID cannot make a malformed binary lock vendorable.
            seed_vendor_entry(tmp.path(), UUID);
            let refusals = run_on_disk(tmp.path(), &npm).await;
            assert_eq!(refusals[PURL].code, "vendor_bun_lockb_invalid");

            // …but a corrupt ledger exempts nothing and names itself.
            std::fs::write(tmp.path().join(".socket/vendor/state.json"), b"{ not json").unwrap();
            let refusals = run_on_disk(tmp.path(), &npm).await;
            let refusal = &refusals[PURL];
            assert_eq!(
                refusal.code, "vendor_state_unreadable",
                "{}",
                refusal.detail
            );
            assert!(refusal.detail.contains("state.json"), "{}", refusal.detail);
            let err = std::io::Error::other("corrupt state.json: synthetic");
            let refusals = run(tmp.path(), &npm, Err(&err)).await;
            assert_eq!(refusals[PURL].code, "vendor_state_unreadable");
            assert_eq!(refusals[PURL].detail, "corrupt state.json: synthetic");
        }

        /// vlt wins the router: a Bun lock beside `vlt-lock.json`, readable
        /// or not, is never judged by Bun's refusal.
        #[tokio::test]
        async fn a_vlt_lock_takes_the_project_out_of_bun_scope() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
            let npm = [(PURL, UUID)];
            assert_eq!(
                run_on_disk(tmp.path(), &npm).await[PURL].code,
                "vendor_bun_lockb_invalid"
            );
            for vlt in ["{\n  \"lockfileVersion\": 1\n}\n", "\u{feff}{}"] {
                std::fs::write(tmp.path().join("vlt-lock.json"), vlt).unwrap();
                let refusals = run_on_disk(tmp.path(), &npm).await;
                assert!(
                    refusals
                        .get(PURL)
                        .is_none_or(|r| !r.code.starts_with("vendor_bun_")),
                    "{vlt:?}: {refusals:?}"
                );
            }
        }

        /// The lock-derived exemption: on a pre-v2 workspace lock whose every
        /// instance of the purl is already ours, a SUPERSEDING uuid (ledger at
        /// the old uuid) and a WIPED ledger are both exempt — the engine
        /// re-vendors / stays in sync — while a fresh registry instance is
        /// refused whatever the ledger says about other purls.
        #[tokio::test]
        async fn lock_derived_exemption_matches_the_engine_gate() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("bun.lock"), BUN_V1_WORKSPACE_LOCK).unwrap();
            let fresh = [(PURL, UUID)];
            let refusals = run_on_disk(tmp.path(), &fresh).await;
            assert_eq!(refusals[PURL].code, "vendor_bun_workspace_unsupported");

            // A preserved ledger does not make registry wiring exempt.
            seed_vendor_entry(tmp.path(), UUID);
            assert!(run_on_disk(tmp.path(), &fresh).await.contains_key(PURL));

            // Live vendored tuples remain exempt.
            std::fs::write(tmp.path().join("bun.lock"), vendored_lock(UUID)).unwrap();
            assert!(
                run_on_disk(tmp.path(), &fresh).await.is_empty(),
                "in-sync re-run is exempt"
            );

            // Superseding uuid: the ledger disagrees, the lock says ours → exempt.
            assert!(
                run_on_disk(tmp.path(), &[(PURL, OTHER_UUID)])
                    .await
                    .is_empty(),
                "a patch update on an already-vendored purl must not be refused"
            );

            // Wiped ledger: no entry at all, the lock alone exempts.
            std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
            assert!(
                run_on_disk(tmp.path(), &fresh).await.is_empty(),
                "a lost ledger must not turn an in-sync project into a refusal"
            );

            // A different, still-registry purl in the same lock stays refused
            // and a non-npm purl is never in scope.
            let others = [
                (PURL, OTHER_UUID),
                ("pkg:npm/other@2.0.0", OTHER_UUID),
                ("pkg:pypi/x@1.0.0", OTHER_UUID),
            ];
            let refusals = run_on_disk(tmp.path(), &others).await;
            assert!(!refusals.contains_key(PURL));
            assert_eq!(
                refusals["pkg:npm/other@2.0.0"].code,
                "vendor_bun_workspace_unsupported"
            );
            assert!(!refusals.contains_key("pkg:pypi/x@1.0.0"));
        }
    }

    mod vlt {
        use super::*;

        const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        const PURL: &str = "pkg:npm/left-pad@1.3.0";
        const PYPI: &str = "pkg:pypi/x@1.0.0";
        const PKG: &str = r#"{"dependencies":{"left-pad":"1.3.0"}}"#;

        fn lock(nodes: &[&str], edges: &[&str]) -> String {
            let block = |entries: &[&str]| {
                let lines: Vec<String> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        format!("    {e}{}", if i + 1 < entries.len() { "," } else { "" })
                    })
                    .collect();
                format!("{{\n{}\n  }}", lines.join("\n"))
            };
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {},\n  \"edges\": {}\n}}\n",
                block(nodes),
                block(edges)
            )
        }

        fn direct_lock() -> String {
            lock(
                &[r#""~npm~left-pad@1.3.0": [0,"left-pad","sha512-REG=="]"#],
                &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#],
            )
        }

        fn project(lock: &str, pkg: &str) -> tempfile::TempDir {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("vlt-lock.json"), lock).unwrap();
            std::fs::write(tmp.path().join("package.json"), pkg).unwrap();
            tmp
        }

        fn flavored(flavor: Option<&str>) -> VendorEntry {
            entry(serde_json::json!({
                "ecosystem": "npm",
                "basePurl": PURL,
                "uuid": UUID,
                "artifact": { "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz") },
                "wiring": [],
                "flavor": flavor,
            }))
        }

        async fn judge(root: &Path, ledger: LedgerLoad<'_>) -> VendorRefusals {
            run(root, &[(PURL, UUID), (PYPI, UUID)], ledger).await
        }

        #[tokio::test]
        async fn a_direct_dependency_passes_and_other_projects_are_never_judged() {
            let empty = HashMap::new();
            let tmp = project(&direct_lock(), PKG);
            assert!(judge(tmp.path(), Ok(&empty)).await.is_empty());

            let pnp = project("not json", PKG);
            std::fs::write(pnp.path().join(".pnp.cjs"), "").unwrap();
            assert!(
                judge(pnp.path(), Ok(&empty)).await.is_empty(),
                "the PnP refusal is not vlt's"
            );
        }

        #[tokio::test]
        async fn every_lock_decidable_refusal_is_reported_per_npm_purl() {
            let empty = HashMap::new();
            let cases = [
                (
                    "\u{feff}{}".to_string(),
                    PKG,
                    "vendor_lockfile_version_unsupported",
                ),
                (
                    direct_lock().replace("\"lockfileVersion\": 1", "\"lockfileVersion\": 2"),
                    PKG,
                    "vendor_lockfile_version_unsupported",
                ),
                (
                    direct_lock().replace("    \"~npm", "  \"~npm"),
                    PKG,
                    "vendor_lockfile_version_unsupported",
                ),
                (
                    direct_lock(),
                    r#"{"dependencies":{"left-pad":"^1.3.0"}}"#,
                    "vendor_vlt_lock_out_of_sync",
                ),
                (
                    direct_lock(),
                    r#"{"dependencies":{"left-pad":"1.3.0"},"devDependencies":{"left-pad":"1.3.0"}}"#,
                    "vendor_lock_entry_unsupported",
                ),
                (
                    lock(
                        &[
                            r#""~npm~has@1.0.0": [0,"has","sha512-H=="]"#,
                            r#""~npm~left-pad@1.3.0": [0,"left-pad","sha512-REG=="]"#,
                        ],
                        &[
                            r#""file~_d has": "prod 1.0.0 ~npm~has@1.0.0""#,
                            r#""~npm~has@1.0.0 left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#,
                        ],
                    ),
                    r#"{"dependencies":{"has":"1.0.0"}}"#,
                    "vendor_vlt_transitive_unsupported",
                ),
            ];
            for (lock, pkg, code) in cases {
                let tmp = project(&lock, pkg);
                let refusals = judge(tmp.path(), Ok(&empty)).await;
                assert_eq!(refusals.len(), 1, "{code}: {refusals:?}");
                assert_eq!(refusals[PURL].code, code, "{}", refusals[PURL].detail);
            }
        }

        #[tokio::test]
        async fn the_ledger_decides_before_the_lock() {
            let tmp = project(&direct_lock(), PKG);
            let err = std::io::Error::other("corrupt state.json: synthetic");
            let refusals = judge(tmp.path(), Err(&err)).await;
            assert_eq!(refusals[PURL].code, "vendor_state_unreadable");
            assert_eq!(refusals[PURL].detail, "corrupt state.json: synthetic");

            let pnpm = HashMap::from([(PURL.to_string(), flavored(Some("pnpm")))]);
            let refusals = judge(tmp.path(), Ok(&pnpm)).await;
            assert_eq!(refusals[PURL].code, "vendor_flavor_changed");
            assert!(refusals[PURL].detail.contains("`pnpm`"), "{refusals:?}");

            let vlt = HashMap::from([(PURL.to_string(), flavored(Some("vlt")))]);
            assert!(judge(tmp.path(), Ok(&vlt)).await.is_empty());
        }

        #[tokio::test]
        async fn the_installed_store_copy_is_checked() {
            let tmp = project(&direct_lock(), PKG);
            let store = tmp
                .path()
                .join("node_modules/.vlt/~npm~left-pad@1.3.0/node_modules/left-pad");
            std::fs::create_dir_all(&store).unwrap();
            let empty = HashMap::new();
            for (pkg, code) in [
                (
                    r#"{"name":"left-pad","bundleDependencies":["x"]}"#,
                    "vendor_bundled_deps_unsupported",
                ),
                (
                    r#"{"name":"left-pad","devDependencies":{},"devDependencies":{}}"#,
                    "vendor_lock_entry_unsupported",
                ),
            ] {
                std::fs::write(store.join("package.json"), pkg).unwrap();
                let refusals = judge(tmp.path(), Ok(&empty)).await;
                assert_eq!(refusals[PURL].code, code, "{refusals:?}");
            }
        }

        #[tokio::test]
        async fn a_root_socket_ignore_refuses_before_any_write() {
            let Some(git) = crate::utils::process::resolve_tool("git") else {
                eprintln!("git not found; skipping");
                return;
            };
            let tmp = project(&direct_lock(), PKG);
            let status = std::process::Command::new(git)
                .args(["init", "-q"])
                .current_dir(tmp.path())
                .status()
                .unwrap();
            assert!(status.success());
            let empty = HashMap::new();
            std::fs::write(tmp.path().join(".gitignore"), "dist/\nnode_modules\n").unwrap();
            assert!(judge(tmp.path(), Ok(&empty)).await.is_empty());
            std::fs::write(tmp.path().join(".gitignore"), ".socket/\n").unwrap();
            let refusals = judge(tmp.path(), Ok(&empty)).await;
            assert_eq!(refusals[PURL].code, "vendor_artifact_gitignored");
            assert!(
                refusals[PURL].detail.contains(".gitignore:1:.socket/"),
                "{refusals:?}"
            );
            assert!(!tmp.path().join(".socket").exists());
        }
    }

    mod package_lock {
        use super::*;

        const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
        const IS_NUMBER: &str = "pkg:npm/is-number@7.0.0";
        const CRATE: &str = "pkg:cargo/serde@1.0.0";
        const URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        const GIT: &str = "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba";

        fn write(path: &Path, text: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        /// A v3 package-lock project with a registry is-number and left-pad
        /// installed from `left_pad` (a URL with an integrity, or a git
        /// spec without one): the backend refuses left-pad on the lock text
        /// alone (`vendor_lock_entry_not_rewritable`, #1976).
        fn project(root: &Path, spec: &str, left_pad: serde_json::Value) {
            let manifest = serde_json::json!({
                "name": "app", "version": "1.0.0",
                "dependencies": { "is-number": "7.0.0", "left-pad": spec },
            });
            let lock = serde_json::json!({
                "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
                "packages": {
                    "": manifest,
                    "node_modules/is-number": {
                        "version": "7.0.0",
                        "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
                        "integrity": "sha512-AAAA=="
                    },
                    "node_modules/left-pad": left_pad,
                },
            });
            write(&root.join("package.json"), &manifest.to_string());
            write(&root.join("package-lock.json"), &lock.to_string());
        }

        fn url_project(root: &Path) {
            project(
                root,
                URL,
                serde_json::json!({ "version": "1.3.0", "resolved": URL, "integrity": "sha512-orig==" }),
            );
        }

        /// A v1 lock refuses every npm purl of the project, whatever the
        /// entry, and leaves other ecosystems to their own checks.
        #[tokio::test]
        async fn a_v1_lock_refuses_every_npm_purl() {
            let tmp = tempfile::tempdir().unwrap();
            write(
                &tmp.path().join("package.json"),
                r#"{"name":"app","version":"1.0.0","dependencies":{"is-number":"7.0.0"}}"#,
            );
            write(
                &tmp.path().join("package-lock.json"),
                r#"{"name":"app","version":"1.0.0","lockfileVersion":1,"dependencies":{}}"#,
            );
            let empty = HashMap::new();
            let refusals = run(
                tmp.path(),
                &[(LEFT_PAD, UUID), (IS_NUMBER, UUID), (CRATE, UUID)],
                Ok(&empty),
            )
            .await;
            assert_eq!(
                refusals[LEFT_PAD].code,
                "vendor_lockfile_version_unsupported"
            );
            assert_eq!(
                refusals[IS_NUMBER].code,
                "vendor_lockfile_version_unsupported"
            );
            assert!(!refusals.contains_key(CRATE), "{refusals:?}");
        }

        #[tokio::test]
        async fn a_lock_text_refusal_is_scoped_like_the_vendor_loop() {
            let tmp = tempfile::tempdir().unwrap();
            url_project(tmp.path());
            let empty = HashMap::new();
            let pairs = [(LEFT_PAD, UUID), (IS_NUMBER, UUID)];
            let refusals = run(tmp.path(), &pairs, Ok(&empty)).await;
            assert_eq!(
                refusals[LEFT_PAD].code, "vendor_lock_entry_not_rewritable",
                "{refusals:?}"
            );
            assert!(!refusals.contains_key(IS_NUMBER), "{refusals:?}");

            // A hosted pin makes it a takeover: the restore rewrites the text
            // the gate reads, so the gate is left to the vendor loop.
            let pin = HostedPin {
                purl: LEFT_PAD.to_string(),
                uuid: OTHER_UUID.to_string(),
                files: vec!["package-lock.json".to_string()],
            };
            let refusals = run_scoped(
                tmp.path(),
                &pairs,
                Ok(&empty),
                std::slice::from_ref(&pin),
                &nothing_installed,
            )
            .await;
            assert!(refusals.is_empty(), "{refusals:?}");

            // A detached ledger entry at this uuid is the idempotency skip.
            let ledger = HashMap::from([(
                LEFT_PAD.to_string(),
                entry(serde_json::json!({
                    "ecosystem": "npm",
                    "basePurl": LEFT_PAD,
                    "uuid": UUID,
                    "artifact": { "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz") },
                    "wiring": [],
                    "detached": true,
                })),
            )]);
            assert!(run(tmp.path(), &pairs, Ok(&ledger)).await.is_empty());
        }

        /// A refused package with no verifiable registry source reaches its
        /// backend only when it is installed.
        #[tokio::test]
        async fn an_unverifiable_refusal_needs_an_installed_copy() {
            let tmp = tempfile::tempdir().unwrap();
            project(
                tmp.path(),
                "github:stevemao/left-pad#v1.3.0",
                serde_json::json!({ "version": "1.3.0", "resolved": GIT }),
            );
            let empty = HashMap::new();
            let pairs = [(LEFT_PAD, UUID)];
            assert!(run(tmp.path(), &pairs, Ok(&empty)).await.is_empty());
            let left_pad_installed = |purls: Vec<String>| -> BoxFuture<'static, HashSet<String>> {
                Box::pin(async move { purls.into_iter().filter(|p| p == LEFT_PAD).collect() })
            };
            let refusals =
                run_scoped(tmp.path(), &pairs, Ok(&empty), &[], &left_pad_installed).await;
            assert_eq!(
                refusals[LEFT_PAD].code, "vendor_lock_entry_not_rewritable",
                "{refusals:?}"
            );
        }
    }

    mod pnpm_takeover {
        use super::*;

        const PURL: &str = "pkg:npm/left-pad@1.3.0";
        const PIN_UUID: &str = "11111111-2222-4333-8444-555555555555";
        /// A hosted pin: the entry's tarball is the patch server's.
        const HOSTED_V9: &str = "lockfileVersion: '9.0'\n\n\
            importers:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\n\
            packages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x==, tarball: https://patch.socket.dev/patch/npm/left-pad/1.3.0/a/11111111-2222-4333-8444-555555555555/left-pad-1.3.0.tgz}\n\n\
            snapshots:\n\n  left-pad@1.3.0: {}\n";

        /// A hosted pnpm pin's takeover meets the pnpm lock-text gates
        /// (#853); a ledger entry already at the selected uuid is in sync.
        #[tokio::test]
        async fn a_hosted_pin_meets_the_pnpm_gates_before_its_takeover() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(
                tmp.path().join("package.json"),
                r#"{"name":"c","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
            )
            .unwrap();
            std::fs::write(
                tmp.path().join("pnpm-lock.yaml"),
                HOSTED_V9.replace('\n', "\r\n"),
            )
            .unwrap();
            let pin = HostedPin {
                purl: PURL.to_string(),
                uuid: PIN_UUID.to_string(),
                files: vec!["pnpm-lock.yaml".to_string()],
            };
            let pins = std::slice::from_ref(&pin);
            let empty = HashMap::new();
            let pairs = [(PURL, UUID)];
            let refusals =
                run_scoped(tmp.path(), &pairs, Ok(&empty), pins, &nothing_installed).await;
            assert_eq!(
                refusals[PURL].code, "vendor_lockfile_crlf_unsupported",
                "{refusals:?}"
            );

            let ledger = HashMap::from([(
                PURL.to_string(),
                entry(serde_json::json!({
                    "ecosystem": "npm",
                    "basePurl": PURL,
                    "uuid": UUID,
                    "artifact": { "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz") },
                    "wiring": [],
                })),
            )]);
            assert!(
                run_scoped(tmp.path(), &pairs, Ok(&ledger), pins, &nothing_installed)
                    .await
                    .is_empty()
            );
        }
    }
}
