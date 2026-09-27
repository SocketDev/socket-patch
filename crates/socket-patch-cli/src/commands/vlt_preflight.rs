//! The vlt vendored-mode preflight (DESIGN §4.6), the per-purl twin of
//! [`crate::commands::bun_preflight`]: every refusal the vlt backend can
//! decide from `vlt-lock.json`, the importer package.json files, the vendor
//! ledger and the installed store copy, evaluated read-only before any
//! `/patches/view/` fetch, any write and any hosted→vendored takeover.
//!
//! Callers: `vendor` ([`crate::commands::vendor::vendor_records`], before
//! the takeover reverts a live hosted redirect), `scan`/`get --mode
//! vendored` (the download phase and the dry-run preview's
//! `would_refuse`) and `get <uuid> --mode vendored`. Agent mode never runs
//! it. After it passes, only network and build failures remain for the
//! engine.

use std::path::Path;

use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::vendor::npm_flavor::{vlt_flavor_change_refusal, vlt_routes};
use socket_patch_core::vendor::vlt_lock::vlt_vendor_preflight;

use crate::commands::bun_preflight::LedgerLoad;

/// A purl the vlt backend would refuse: the engine's code and detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VltVendorRefusal {
    pub(crate) code: &'static str,
    pub(crate) detail: String,
}

/// The refusal (if any) the preflight recorded for `purl`.
pub(crate) fn vlt_refusal_for<'a>(
    refusals: &'a [(String, VltVendorRefusal)],
    purl: &str,
) -> Option<&'a VltVendorRefusal> {
    refusals
        .iter()
        .find_map(|(p, refusal)| (p == purl).then_some(refusal))
}

/// Run the preflight for `(purl, uuid)` pairs. Only npm purls of a project
/// the router sends to vlt are judged; every other pair passes. The order
/// matches the engine's: an unreadable ledger, the lock sniff, the flavor
/// guard, then the core target analysis, store copy and gitignore checks.
pub(crate) async fn vlt_vendor_preflight_pairs(
    project_root: &Path,
    pairs: &[(&str, &str)],
    ledger: LedgerLoad<'_>,
) -> Vec<(String, VltVendorRefusal)> {
    let npm: Vec<&(&str, &str)> = pairs
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:npm/"))
        .collect();
    if npm.is_empty() {
        return Vec::new();
    }
    let Some(route) = vlt_routes(project_root).await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (purl, uuid) in npm {
        let (code, detail) = match (&route, ledger) {
            (_, Err(e)) => ("vendor_state_unreadable", e.to_string()),
            (Err((code, detail)), Ok(_)) => (*code, detail.clone()),
            (Ok(()), Ok(entries)) => match vlt_flavor_change_refusal(entries, purl) {
                Some(detail) => ("vendor_flavor_changed", detail),
                None => match vlt_vendor_preflight(project_root, purl, uuid).await {
                    Ok(()) => continue,
                    Err(refusal) => refusal,
                },
            },
        };
        out.push(((*purl).to_string(), VltVendorRefusal { code, detail }));
    }
    out
}

/// [`vlt_vendor_preflight_pairs`] over search results (the `scan`/`get`
/// selection).
pub(crate) async fn vlt_vendor_preflight_selected(
    project_root: &Path,
    selected: &[PatchSearchResult],
    ledger: LedgerLoad<'_>,
) -> Vec<(String, VltVendorRefusal)> {
    let pairs: Vec<(&str, &str)> = selected
        .iter()
        .map(|s| (s.purl.as_str(), s.uuid.as_str()))
        .collect();
    vlt_vendor_preflight_pairs(project_root, &pairs, ledger).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use socket_patch_core::vendor::state::VendorEntry;

    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";

    fn lock(nodes: &[&str], edges: &[&str]) -> String {
        let block = |entries: &[&str]| {
            let lines: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| format!("    {e}{}", if i + 1 < entries.len() { "," } else { "" }))
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

    const PKG: &str = r#"{"dependencies":{"left-pad":"1.3.0"}}"#;

    fn entry(flavor: Option<&str>) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "basePurl": PURL,
            "uuid": UUID,
            "artifact": { "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz") },
            "wiring": [],
            "flavor": flavor,
        }))
        .unwrap()
    }

    async fn run(root: &Path, ledger: LedgerLoad<'_>) -> Vec<(String, VltVendorRefusal)> {
        vlt_vendor_preflight_pairs(root, &[(PURL, UUID), ("pkg:pypi/x@1.0.0", UUID)], ledger).await
    }

    #[tokio::test]
    async fn a_direct_dependency_passes_and_other_projects_are_never_judged() {
        let empty = HashMap::new();
        let tmp = project(&direct_lock(), PKG);
        assert!(run(tmp.path(), Ok(&empty)).await.is_empty());

        let npm = tempfile::tempdir().unwrap();
        std::fs::write(npm.path().join("package-lock.json"), "{}").unwrap();
        assert!(run(npm.path(), Ok(&empty)).await.is_empty());

        let pnp = project("not json", PKG);
        std::fs::write(pnp.path().join(".pnp.cjs"), "").unwrap();
        assert!(
            run(pnp.path(), Ok(&empty)).await.is_empty(),
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
            let refusals = run(tmp.path(), Ok(&empty)).await;
            assert_eq!(refusals.len(), 1, "{code}: {refusals:?}");
            let refusal = vlt_refusal_for(&refusals, PURL).unwrap();
            assert_eq!(refusal.code, code, "{}", refusal.detail);
            assert!(vlt_refusal_for(&refusals, "pkg:pypi/x@1.0.0").is_none());
        }
    }

    #[tokio::test]
    async fn the_ledger_decides_before_the_lock() {
        let tmp = project(&direct_lock(), PKG);
        let err = std::io::Error::other("corrupt state.json: synthetic");
        let refusals = run(tmp.path(), Err(&err)).await;
        assert_eq!(refusals[0].1.code, "vendor_state_unreadable");
        assert_eq!(refusals[0].1.detail, "corrupt state.json: synthetic");

        let pnpm = HashMap::from([(PURL.to_string(), entry(Some("pnpm")))]);
        let refusals = run(tmp.path(), Ok(&pnpm)).await;
        assert_eq!(refusals[0].1.code, "vendor_flavor_changed");
        assert!(refusals[0].1.detail.contains("`pnpm`"), "{refusals:?}");

        let vlt = HashMap::from([(PURL.to_string(), entry(Some("vlt")))]);
        assert!(run(tmp.path(), Ok(&vlt)).await.is_empty());
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
            let refusals = run(tmp.path(), Ok(&empty)).await;
            assert_eq!(refusals[0].1.code, code, "{refusals:?}");
        }
    }

    #[tokio::test]
    async fn a_root_socket_ignore_refuses_before_any_write() {
        let Some(git) = socket_patch_core::utils::process::resolve_tool("git") else {
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
        assert!(run(tmp.path(), Ok(&empty)).await.is_empty());
        std::fs::write(tmp.path().join(".gitignore"), ".socket/\n").unwrap();
        let refusals = run(tmp.path(), Ok(&empty)).await;
        assert_eq!(refusals[0].1.code, "vendor_artifact_gitignored");
        assert!(
            refusals[0].1.detail.contains(".gitignore:1:.socket/"),
            "{refusals:?}"
        );
        assert!(!tmp.path().join(".socket").exists());
    }
}
