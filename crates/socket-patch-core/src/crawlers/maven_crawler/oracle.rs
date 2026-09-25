//! The serial (walk, read and parse one POM at a time) local-repository
//! scan, kept as the equivalence oracle for the parallel scan in the parent
//! module. Verbatim but for MVN-1's path-first step, which it spells out on
//! its own (not through the parent's `canonical_layout_coordinates` /
//! `LayoutTrust`, so a bug there cannot hide on both sides): a POM at its
//! canonical `<group>/<a>/<v>/<a>-<v>.pom` path takes its coordinates from
//! that path once the first such POM of its top-level group directory whose
//! content parses has agreed with its own path. Test-only; never compiled
//! into the binary.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{
    parse_path_coordinates, parse_pom_group_artifact_version, MavenCrawler, LAYOUT_TRUST_ATTEMPTS,
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

/// The canonical-layout coordinates of `path` under `repo_path`, spelled
/// independently of the parent module: the group directories (at least
/// one, none dotted), then `<a>/<v>/`, then a file named exactly
/// `<a>-<v>.pom`.
fn canonical_gav(path: &Path, repo_path: &Path) -> Option<(String, String, String)> {
    let rel = path.strip_prefix(repo_path).ok()?;
    let mut names = Vec::new();
    for component in rel.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        names.push(name.to_str()?.to_string());
    }
    if names.len() < 4 {
        return None;
    }
    let file = names.pop()?;
    let version = names.pop()?;
    let artifact = names.pop()?;
    if file != format!("{artifact}-{version}.pom") || names.iter().any(|n| n.contains('.')) {
        return None;
    }
    Some((names.join("."), artifact, version))
}

/// Per top-level group directory: `Some(agreed)` once a POM's content
/// parsed, else how many canonical POMs were read without one parsing.
type Trust = HashMap<String, (Option<bool>, u8)>;

fn scan(repo_path: &Path, seen: &mut HashSet<String>, path_first: bool) -> Vec<CrawledPackage> {
    let mut results = Vec::new();
    let mut trust: Trust = HashMap::new();

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

        let content_first = || {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|content| parse_pom_group_artifact_version(&content))
                .or_else(|| parse_path_coordinates(version_dir, repo_path))
        };
        let canonical = path_first.then(|| canonical_gav(path, repo_path)).flatten();
        let coords = match canonical {
            None => content_first(),
            Some(gav) => {
                let top = gav.0.split('.').next().unwrap_or_default().to_string();
                let state = trust.entry(top).or_insert((None, 0));
                match *state {
                    (Some(true), _) => Some(gav),
                    (Some(false), _) => content_first(),
                    (None, read) if read >= LAYOUT_TRUST_ATTEMPTS => content_first(),
                    (None, read) => match std::fs::read_to_string(path)
                        .ok()
                        .and_then(|content| parse_pom_group_artifact_version(&content))
                    {
                        Some(content) => {
                            *state = (Some(content == gav), read);
                            Some(content)
                        }
                        None => {
                            *state = (None, read + 1);
                            parse_path_coordinates(version_dir, repo_path)
                        }
                    },
                }
            }
        };

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
