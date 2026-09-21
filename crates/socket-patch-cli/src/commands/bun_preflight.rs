//! The Bun vendored-mode preflight shared by EVERY path that feeds the
//! vendor engine: `scan --mode vendored` (the manifest-tracked AND the
//! `--detached` download phases), `get … --mode vendored` (search and uuid
//! paths), their `--dry-run` previews, and the `vendor` command's engine
//! loop itself ([`crate::commands::vendor::vendor_records`], where it runs
//! BEFORE the hosted→vendored takeover reverts anything).
//!
//! One read-only [`preflight_vendor`] per run, evaluated before any
//! `/patches/view/` fetch and before any write, so an incompatible Bun
//! project (binary `bun.lockb` without a text lock, an unreadable lock, an
//! unsupported `lockfileVersion`, a pre-version-2 `workspace:` lock) never
//! has a patch downloaded on its behalf — let alone recorded in the
//! manifest, or its live hosted redirect stripped — and every entry point
//! reports the SAME vendor code the engine would have emitted.
//!
//! [`preflight_vendor`]: socket_patch_core::vendor::bun_lock::preflight_vendor

use std::collections::{HashMap, HashSet};
use std::path::Path;

use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vendor::state::VendorEntry;
use socket_patch_core::vendor::{load_state, lookup_entry};

/// The vendor ledger as the preflight consumes it: the caller's own
/// `load_state` outcome, so an UNREADABLE ledger is a fact the refusal can
/// report instead of a silently-emptied exemption set.
pub(crate) type LedgerLoad<'a> = Result<&'a HashMap<String, VendorEntry>, &'a std::io::Error>;

/// The outcome of the preflight when the project is refused.
///
/// `exempt` holds the selected purls the refusal must NOT pre-empt — they
/// flow through to the engine, which lets them in exactly as on a non-Bun
/// project. A purl is exempt when EITHER
///
/// * the vendor ledger already wires it at the SAME uuid this run selected
///   (an in-sync re-run: the engine's `already_vendored` skip), OR
/// * `bun.lock` already wires EVERY instance of its `name@version` to one
///   of our `.socket/vendor/npm/` tuples, at any uuid
///   ([`wired_instances_all_ours`]) — the engine's own criterion for
///   skipping the workspace gate: rewriting an already-local tuple to a
///   superseding uuid adds no new workspace-relative path, so a patch
///   UPDATE on a project vendored before it grew a workspace member (or
///   the same re-run after a wiped `state.json`) re-vendors in place
///   instead of dying here with a remedy Bun 1.2/1.3 teams cannot follow.
///
/// An unreadable ledger exempts nothing (fail closed) and the refusal
/// itself becomes `vendor_state_unreadable` with the io/parse detail:
/// the vendor step does NOT reliably report the corrupt ledger itself
/// (`get <uuid> --mode vendored` returns before it runs, and the
/// scan/search paths reach it only when the manifest already holds another
/// vendorable record), so the one refusal this run emits has to name the
/// real problem rather than send the operator off to re-lock bun.lock.
///
/// [`wired_instances_all_ours`]: socket_patch_core::vendor::bun_lock::wired_instances_all_ours
pub(crate) struct BunVendorRefusal {
    /// The stable vendor error code (`vendor_bun_lockb_unsupported`,
    /// `vendor_lockfile_missing`, `vendor_lockfile_version_unsupported`,
    /// `vendor_bun_workspace_unsupported`) — the same string the vendor
    /// engine would have emitted as a `failed` event — or
    /// `vendor_state_unreadable` when the ledger could not be read.
    pub(crate) code: &'static str,
    /// The engine's (or the ledger loader's) human-readable detail, relayed
    /// verbatim.
    pub(crate) detail: String,
    exempt: HashSet<String>,
}

impl BunVendorRefusal {
    /// Whether the refusal applies to `purl`: npm-family only (no other
    /// ecosystem's backend consults `bun.lock`), minus the already-vendored
    /// exemption.
    pub(crate) fn applies_to(&self, purl: &str) -> bool {
        purl.starts_with("pkg:npm/") && !self.exempt.contains(purl)
    }
}

/// Run the Bun preflight once for `selected` — only when it holds at least
/// one npm purl, since nothing else can be affected — loading the vendor
/// ledger at `cwd` for the exemption. `None` means nothing to refuse.
pub(crate) async fn bun_vendor_preflight(
    cwd: &Path,
    selected: &[PatchSearchResult],
) -> Option<BunVendorRefusal> {
    let pairs = selection_pairs(selected);
    if !pairs.iter().any(|(purl, _)| purl.starts_with("pkg:npm/")) {
        return None;
    }
    let (code, detail) = socket_patch_core::vendor::bun_lock::preflight_vendor(cwd)
        .await
        .err()?;
    // Loaded only once the project is known to refuse: an accepted project
    // never touches the ledger here (the vendor step owns it).
    let ledger = load_state(cwd).await;
    Some(
        refusal_with_exemptions(
            cwd,
            code,
            detail,
            &pairs,
            ledger.as_ref().map(|s| &s.entries),
        )
        .await,
    )
}

/// [`bun_vendor_preflight`] for callers that already loaded the ledger (the
/// detached download phase, the dry-run preview), handed the load outcome
/// so an unreadable ledger reports as such.
pub(crate) async fn bun_vendor_preflight_with_ledger(
    cwd: &Path,
    selected: &[PatchSearchResult],
    ledger: LedgerLoad<'_>,
) -> Option<BunVendorRefusal> {
    bun_vendor_preflight_pairs(cwd, &selection_pairs(selected), ledger).await
}

/// The preflight over bare `(purl, uuid)` pairs — the `vendor` command's
/// view of its selection (manifest records, not search results) — with a
/// caller-loaded ledger. `None` when no npm purl is selected or the
/// project is accepted.
pub(crate) async fn bun_vendor_preflight_pairs(
    cwd: &Path,
    pairs: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
) -> Option<BunVendorRefusal> {
    if !pairs.iter().any(|(purl, _)| purl.starts_with("pkg:npm/")) {
        return None;
    }
    let (code, detail) = socket_patch_core::vendor::bun_lock::preflight_vendor(cwd)
        .await
        .err()?;
    Some(refusal_with_exemptions(cwd, code, detail, pairs, ledger).await)
}

fn selection_pairs(selected: &[PatchSearchResult]) -> Vec<(&str, &str)> {
    selected
        .iter()
        .map(|s| (s.purl.as_str(), s.uuid.as_str()))
        .collect()
}

/// Turn the engine's project-level refusal into the per-purl verdict: the
/// ledger-or-lock exemption described on [`BunVendorRefusal`], or the
/// `vendor_state_unreadable` refusal when the ledger cannot be read.
async fn refusal_with_exemptions(
    cwd: &Path,
    code: &'static str,
    detail: String,
    pairs: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
) -> BunVendorRefusal {
    let entries = match ledger {
        Ok(entries) => entries,
        Err(e) => {
            return BunVendorRefusal {
                code: "vendor_state_unreadable",
                detail: e.to_string(),
                exempt: HashSet::new(),
            };
        }
    };
    // The lock-derived exemption exists only for the workspace gate: every
    // other preflight code means bun.lock could not be read or parsed, so
    // nothing in it can be ours and re-reading it per purl would be wasted
    // (guarded, but still) I/O.
    let lock_parsed = code == "vendor_bun_workspace_unsupported";
    let mut exempt = HashSet::new();
    for (purl, uuid) in pairs {
        if !purl.starts_with("pkg:npm/") {
            continue;
        }
        // The ledger is keyed by the manifest purl (possibly qualified) and
        // `lookup_entry` also resolves base purls; try the selected spelling
        // first, then its qualifier-free base.
        let ledger_in_sync = lookup_entry(entries, purl)
            .or_else(|| lookup_entry(entries, strip_purl_qualifiers(purl)))
            .is_some_and(|e| e.uuid == *uuid);
        let lock_all_ours = lock_parsed
            && socket_patch_core::vendor::bun_lock::wired_instances_all_ours(cwd, purl)
                .await
                .unwrap_or(false);
        if ledger_in_sync || lock_all_ours {
            exempt.insert((*purl).to_string());
        }
    }
    BunVendorRefusal {
        code,
        detail,
        exempt,
    }
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
    /// npm (no needless I/O, no spurious refusal for other ecosystems); an
    /// in-sync ledger entry exempts; an unreadable ledger exempts nothing
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
            .expect("lockb-only project is refused");
        assert_eq!(refusal.code, "vendor_bun_lockb_unsupported");
        assert!(refusal.applies_to(PURL));
        assert!(!refusal.applies_to("pkg:pypi/only@1.0.0"));

        // Exempt when the ledger wires this purl at this uuid…
        seed_bun_vendor_entry(tmp.path(), PURL, UUID);
        let refusal = bun_vendor_preflight(tmp.path(), &npm).await.unwrap();
        assert_eq!(refusal.code, "vendor_bun_lockb_unsupported");
        assert!(!refusal.applies_to(PURL), "in-sync ledger entry is exempt");

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

        // Vendored at UUID, ledger in sync: exempt (both rules agree).
        std::fs::write(tmp.path().join("bun.lock"), vendored_lock(UUID)).unwrap();
        seed_bun_vendor_entry(tmp.path(), PURL, UUID);
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
