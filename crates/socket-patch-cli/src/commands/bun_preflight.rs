//! The Bun vendored-mode preflight shared by every path that feeds the
//! vendor engine: `scan --mode vendored`, `get … --mode vendored`, their
//! `--dry-run` previews, and the `vendor` command itself (BEFORE the
//! hosted→vendored takeover reverts anything).
//!
//! It runs [`preflight_vendor`] once, before any `/patches/view/` fetch and
//! before any write, so an incompatible Bun project never has a patch
//! downloaded, recorded, or its hosted redirect stripped, and every entry
//! point reports the same vendor code the engine would have emitted.
//!
//! [`preflight_vendor`]: socket_patch_core::vendor::bun_lock::preflight_vendor

use std::collections::{HashMap, HashSet};
use std::path::Path;

use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::vendor::load_state;
use socket_patch_core::vendor::state::VendorEntry;

/// The caller's own `load_state` outcome, so an unreadable ledger is a fact
/// the refusal can report instead of a silently-emptied exemption set.
pub(crate) type LedgerLoad<'a> = Result<&'a HashMap<String, VendorEntry>, &'a std::io::Error>;

/// The outcome of the preflight when the project is refused.
///
/// `exempt` holds the selected purls the refusal must NOT pre-empt. A purl
/// is exempt only when `bun.lock` wires every instance of its
/// `name@version` to one of our `.socket/vendor/npm/` tuples, at any UUID
/// ([`wired_instances_all_ours`]). This matches the engine's workspace
/// gate: updating an already-local tuple introduces no new relative path.
/// A matching ledger UUID alone is insufficient: `rollback --preserve-state`
/// retains the entry after removing its wiring.
///
/// An unreadable ledger exempts nothing (fail closed) and the refusal
/// becomes `vendor_state_unreadable`: the vendor step does not reliably
/// report the corrupt ledger itself (`get <uuid> --mode vendored` returns
/// before it runs), so this refusal has to name the real problem rather
/// than send the operator off to re-lock bun.lock.
///
/// [`wired_instances_all_ours`]: socket_patch_core::vendor::bun_lock::wired_instances_all_ours
pub(crate) struct BunVendorRefusal {
    /// The vendor error code the engine would have emitted, or
    /// `vendor_state_unreadable`.
    pub(crate) code: &'static str,
    pub(crate) detail: String,
    exempt: HashSet<String>,
}

impl BunVendorRefusal {
    /// npm-family only (no other ecosystem's backend consults `bun.lock`),
    /// minus the already-vendored exemption.
    pub(crate) fn applies_to(&self, purl: &str) -> bool {
        is_npm(purl) && !self.exempt.contains(purl)
    }
}

fn is_npm(purl: &str) -> bool {
    Ecosystem::from_purl(purl) == Some(Ecosystem::Npm)
}

/// The preflight for `selected`, loading the vendor ledger only once the
/// project is known to refuse, so an accepted project never touches
/// `state.json`.
pub(crate) async fn bun_vendor_preflight(
    cwd: &Path,
    selected: &[PatchSearchResult],
) -> Option<BunVendorRefusal> {
    preflight_pairs(cwd, &selection_pairs(selected), None).await
}

/// [`bun_vendor_preflight`] with the caller's ledger load.
pub(crate) async fn bun_vendor_preflight_with_ledger(
    cwd: &Path,
    selected: &[PatchSearchResult],
    ledger: LedgerLoad<'_>,
) -> Option<BunVendorRefusal> {
    preflight_pairs(cwd, &selection_pairs(selected), Some(ledger)).await
}

/// The preflight over bare `(purl, uuid)` pairs (the `vendor` command's
/// manifest records) with the caller's ledger load.
pub(crate) async fn bun_vendor_preflight_pairs(
    cwd: &Path,
    pairs: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
) -> Option<BunVendorRefusal> {
    preflight_pairs(cwd, pairs, Some(ledger)).await
}

/// `ledger` is the caller's own load, or `None` to load it here once the
/// project is known to refuse. `None` when no npm purl is selected or the
/// project is accepted.
async fn preflight_pairs(
    cwd: &Path,
    pairs: &[(&str, &str)],
    ledger: Option<LedgerLoad<'_>>,
) -> Option<BunVendorRefusal> {
    if !pairs.iter().any(|(purl, _)| is_npm(purl)) {
        return None;
    }
    // vlt wins the router (DESIGN D2): a Bun lock beside `vlt-lock.json`
    // is never the one vendoring rewires.
    if socket_patch_core::vendor::npm_flavor::vlt_routes(cwd)
        .await
        .is_some()
    {
        return None;
    }
    let (code, detail) = socket_patch_core::vendor::bun_lock::preflight_vendor(cwd)
        .await
        .err()?;
    let loaded;
    let ledger = match ledger {
        Some(ledger) => ledger,
        None => {
            loaded = load_state(cwd).await;
            loaded.as_ref().map(|s| &s.entries)
        }
    };
    if let Err(e) = ledger {
        return Some(BunVendorRefusal {
            code: "vendor_state_unreadable",
            detail: e.to_string(),
            exempt: HashSet::new(),
        });
    }
    // The exemption exists only for the workspace gate: every other code
    // means bun.lock could not be read or parsed, so nothing in it is ours.
    let mut exempt = HashSet::new();
    if code == "vendor_bun_workspace_unsupported" {
        for (purl, _) in pairs.iter().filter(|(purl, _)| is_npm(purl)) {
            if socket_patch_core::vendor::bun_lock::wired_instances_all_ours(cwd, purl)
                .await
                .unwrap_or(false)
            {
                exempt.insert((*purl).to_string());
            }
        }
    }
    Some(BunVendorRefusal {
        code,
        detail,
        exempt,
    })
}

fn selection_pairs(selected: &[PatchSearchResult]) -> Vec<(&str, &str)> {
    selected
        .iter()
        .map(|s| (s.purl.as_str(), s.uuid.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::types::VulnerabilityResponse;

    const UUID: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_UUID: &str = "33333333-3333-4333-8333-333333333333";
    const PURL: &str = "pkg:npm/covgap-bun@1.0.0";

    fn sel(uuid: &str, purl: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.into(),
            purl: purl.into(),
            published_at: "2024-01-01".into(),
            description: String::new(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: HashMap::<String, VulnerabilityResponse>::new(),
        }
    }

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

    fn seed_bun_vendor_entry(root: &Path, purl: &str, uuid: &str) {
        let vendor = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
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

    /// `bun_vendor_preflight` never reads the lock when nothing selected is
    /// npm (no needless I/O, no spurious refusal for other ecosystems);
    /// a ledger alone never exempts; an unreadable ledger exempts nothing
    /// (fail closed) AND is reported as the real problem
    /// (`vendor_state_unreadable`), never as a Bun lock remedy.
    #[tokio::test]
    async fn preflight_scope_and_corrupt_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let pypi = vec![sel(
            "11111111-1111-4111-8111-111111111111",
            "pkg:pypi/only@1.0.0",
        )];
        assert!(
            bun_vendor_preflight(tmp.path(), &pypi).await.is_none(),
            "no npm purl selected => no refusal"
        );

        let npm = vec![sel(UUID, PURL)];
        let refusal = bun_vendor_preflight(tmp.path(), &npm)
            .await
            .expect("malformed lockb project is refused");
        assert_eq!(refusal.code, "vendor_bun_lockb_invalid");
        assert!(refusal.applies_to(PURL));
        assert!(!refusal.applies_to("pkg:pypi/only@1.0.0"));

        // A ledger at this UUID cannot make a malformed binary lock vendorable.
        seed_bun_vendor_entry(tmp.path(), PURL, UUID);
        let refusal = bun_vendor_preflight(tmp.path(), &npm).await.unwrap();
        assert_eq!(refusal.code, "vendor_bun_lockb_invalid");
        assert!(refusal.applies_to(PURL), "the live lock must be compatible");

        // …but a corrupt ledger exempts nothing and names itself.
        std::fs::write(tmp.path().join(".socket/vendor/state.json"), b"{ not json").unwrap();
        let refusal = bun_vendor_preflight(tmp.path(), &npm).await.unwrap();
        assert_eq!(
            refusal.code, "vendor_state_unreadable",
            "the refusal must name the ledger, not the lock: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("state.json"),
            "the io/parse detail names the file: {}",
            refusal.detail
        );
        assert!(
            refusal.applies_to(PURL),
            "an unreadable ledger must not exempt (fail closed)"
        );
        // The ledger-passing variant reports the same.
        let err = std::io::Error::other("corrupt state.json: synthetic");
        let refusal = bun_vendor_preflight_with_ledger(tmp.path(), &npm, Err(&err))
            .await
            .unwrap();
        assert_eq!(refusal.code, "vendor_state_unreadable");
        assert_eq!(refusal.detail, "corrupt state.json: synthetic");
        assert!(refusal.applies_to(PURL));
    }

    /// vlt wins the router: a Bun lock beside `vlt-lock.json`, readable or
    /// not, is never judged by the Bun preflight.
    #[tokio::test]
    async fn a_vlt_lock_takes_the_project_out_of_bun_scope() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let npm = vec![sel(UUID, PURL)];
        assert!(bun_vendor_preflight(tmp.path(), &npm).await.is_some());
        for vlt in ["{\n  \"lockfileVersion\": 1\n}\n", "\u{feff}{}"] {
            std::fs::write(tmp.path().join("vlt-lock.json"), vlt).unwrap();
            assert!(
                bun_vendor_preflight(tmp.path(), &npm).await.is_none(),
                "{vlt:?}"
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
        let fresh = vec![sel(UUID, PURL)];
        let refusal = bun_vendor_preflight(tmp.path(), &fresh).await.unwrap();
        assert_eq!(refusal.code, "vendor_bun_workspace_unsupported");
        assert!(
            refusal.applies_to(PURL),
            "a fresh registry instance is refused"
        );

        // A preserved ledger does not make registry wiring exempt.
        seed_bun_vendor_entry(tmp.path(), PURL, UUID);
        let refusal = bun_vendor_preflight(tmp.path(), &fresh).await.unwrap();
        assert!(refusal.applies_to(PURL));

        // Live vendored tuples remain exempt.
        std::fs::write(tmp.path().join("bun.lock"), vendored_lock(UUID)).unwrap();
        let refusal = bun_vendor_preflight(tmp.path(), &fresh).await.unwrap();
        assert!(!refusal.applies_to(PURL), "in-sync re-run is exempt");

        // Superseding uuid: the ledger disagrees, the lock says ours → exempt.
        let superseding = vec![sel(OTHER_UUID, PURL)];
        let refusal = bun_vendor_preflight(tmp.path(), &superseding)
            .await
            .unwrap();
        assert_eq!(refusal.code, "vendor_bun_workspace_unsupported");
        assert!(
            !refusal.applies_to(PURL),
            "a patch update on an already-vendored purl must not be refused"
        );

        // Wiped ledger: no entry at all, the lock alone exempts.
        std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
        let refusal = bun_vendor_preflight(tmp.path(), &fresh).await.unwrap();
        assert!(
            !refusal.applies_to(PURL),
            "a lost ledger must not turn an in-sync project into a refusal"
        );

        // A different, still-registry purl in the same lock stays refused
        // and a non-npm purl is never in scope.
        let others = vec![
            sel(OTHER_UUID, "pkg:npm/other@2.0.0"),
            sel(OTHER_UUID, "pkg:pypi/x@1.0.0"),
        ];
        let refusal = bun_vendor_preflight(tmp.path(), &others).await.unwrap();
        assert!(refusal.applies_to("pkg:npm/other@2.0.0"));
        assert!(!refusal.applies_to("pkg:pypi/x@1.0.0"));

        // The pairs form (the `vendor` command's view) agrees.
        let pairs = [(PURL, OTHER_UUID), ("pkg:npm/other@2.0.0", OTHER_UUID)];
        let empty = HashMap::new();
        let refusal = bun_vendor_preflight_pairs(tmp.path(), &pairs, Ok(&empty))
            .await
            .unwrap();
        assert!(!refusal.applies_to(PURL));
        assert!(refusal.applies_to("pkg:npm/other@2.0.0"));
        assert!(
            bun_vendor_preflight_pairs(tmp.path(), &[("pkg:cargo/x@1.0.0", UUID)], Ok(&empty))
                .await
                .is_none(),
            "no npm pair => no refusal"
        );
    }
}
