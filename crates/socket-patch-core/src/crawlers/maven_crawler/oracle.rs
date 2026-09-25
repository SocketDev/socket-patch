//! The serial (walk, read and parse one POM at a time) local-repository
//! scan, kept as the equivalence oracle for the parallel scan in the parent
//! module. Verbatim but for one step: a POM at its canonical
//! `<group>/<a>/<v>/<a>-<v>.pom` path takes its coordinates from that path
//! before any read, as the scan does. Test-only; never compiled into the
//! binary.

use std::collections::HashSet;
use std::path::Path;

use super::{
    canonical_layout_coordinates, parse_path_coordinates, parse_pom_group_artifact_version,
    MavenCrawler,
};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::run_blocking;

pub(super) struct LegacyMavenCrawler;

impl LegacyMavenCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let repo_paths = MavenCrawler::new()
            .get_maven_repo_paths(options)
            .await
            .unwrap_or_default();

        for repo_path in repo_paths {
            let (found, returned_seen) = run_blocking(move || {
                let found = scan_maven_repo(&repo_path, &mut seen);
                (found, seen)
            })
            .await;
            seen = returned_seen;
            packages.extend(found);
        }

        packages
    }
}

/// The scan as it stood before MVN-1, verbatim: every POM is read and its
/// content decides, the directory path only rescuing an unparseable one.
/// On a repository whose POMs all agree with their directories it must
/// report exactly what the path-first scan reports.
pub(super) async fn crawl_all_content_first(options: &CrawlerOptions) -> Vec<CrawledPackage> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    let repo_paths = MavenCrawler::new()
        .get_maven_repo_paths(options)
        .await
        .unwrap_or_default();
    for repo_path in repo_paths {
        let (found, returned_seen) = run_blocking(move || {
            let found = scan(&repo_path, &mut seen, false);
            (found, seen)
        })
        .await;
        seen = returned_seen;
        packages.extend(found);
    }
    packages
}

fn scan_maven_repo(repo_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
    scan(repo_path, seen, true)
}

fn scan(repo_path: &Path, seen: &mut HashSet<String>, path_first: bool) -> Vec<CrawledPackage> {
    let mut results = Vec::new();

    for entry in walkdir::WalkDir::new(repo_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "pom") {
            continue;
        }

        let version_dir = match path.parent() {
            Some(p) => p,
            None => continue,
        };

        let coords = path_first
            .then(|| canonical_layout_coordinates(path, repo_path))
            .flatten()
            .or_else(|| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|content| parse_pom_group_artifact_version(&content))
                    .or_else(|| parse_path_coordinates(version_dir, repo_path))
            });

        if let Some((group_id, artifact_id, version)) = coords {
            let purl = crate::utils::purl::build_maven_purl(&group_id, &artifact_id, &version);
            if seen.insert(purl.clone()) {
                results.push(CrawledPackage {
                    name: artifact_id,
                    version,
                    namespace: Some(group_id),
                    purl,
                    path: version_dir.to_path_buf(),
                });
            }
        }
    }

    results
}
