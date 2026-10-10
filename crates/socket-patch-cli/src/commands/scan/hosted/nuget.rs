//! Read-only check of NuGet's global packages folder for hosted redirects
//! (#352).
//!
//! A hosted NuGet patch keeps the upstream id and version, and NuGet
//! restores a package already extracted into its global packages folder
//! (`NUGET_PACKAGES`, else `~/.nuget/packages`) without asking any source.
//! A copy extracted from the upstream bytes therefore shadows the Socket
//! source: without a lock the restore silently keeps the unpatched bytes,
//! with one it fails NU1403. Like the gem stale-install guard, nothing is
//! deleted: the remedy is prescribed, and the purl is withheld from the
//! same-run VEX attestation.

use socket_patch_core::crawlers::NuGetCrawler;
use socket_patch_core::patch::redirect::DepOverride;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vendor::nuget_feed::{extracted_content_hash, stale_global_package_detail};

use super::StaleInstallOutcome;

/// Warn for every confirmed NuGet redirect whose package the global
/// packages folder already holds extracted from bytes other than the
/// patched ones. A dir without `.nupkg.metadata` (a legacy `packages/`
/// folder) is never judged: there is no positive evidence.
pub(super) async fn stale_install_warnings(
    common: &crate::args::GlobalArgs,
    confirmed: &[(String, String)],
    overrides: &[DepOverride],
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    // (purl, the patched package's NuGet content hash)
    let candidates: Vec<(&String, String)> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:nuget/"))
        .filter_map(|(purl, uuid)| {
            let sha512 = overrides
                .iter()
                .find(|o| o.ecosystem == "nuget" && &o.patch_uuid == uuid)?
                .integrity
                .sha512
                .as_deref()?;
            Some((
                purl,
                sha512.strip_prefix("sha512-").unwrap_or(sha512).to_string(),
            ))
        })
        .collect();
    if candidates.is_empty() {
        return out;
    }
    let crawler = NuGetCrawler::new();
    let Ok(paths) = crawler
        .get_nuget_package_paths(&common.crawler_options())
        .await
    else {
        return out;
    };
    let purls: Vec<String> = candidates
        .iter()
        .map(|(purl, _)| strip_purl_qualifiers(purl).to_string())
        .collect();
    for path in &paths {
        let Ok(found) = crawler.find_by_purls(path, &purls).await else {
            continue;
        };
        for (purl, patched) in &candidates {
            let Some(pkg) = found.get(strip_purl_qualifiers(purl)) else {
                continue;
            };
            let Some(cached) = extracted_content_hash(&pkg.path).await else {
                continue;
            };
            if cached == *patched || out.stale_purls.contains(*purl) {
                continue;
            }
            out.warnings.push(serde_json::json!({
                "code": "redirect_nuget_stale_global_package",
                "detail": stale_global_package_detail(
                    &pkg.name,
                    &pkg.version,
                    &pkg.path,
                    "the Socket source",
                ),
            }));
            out.stale_purls.insert((*purl).clone());
        }
    }
    out
}
