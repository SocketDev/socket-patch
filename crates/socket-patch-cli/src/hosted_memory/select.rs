//! Which repository files the in-memory engine needs: root detection plus,
//! per root, the same root-relative candidate set the disk hosted flow
//! reads (`REDIRECT_CANDIDATE_FILES`, Python lock / script pairs, Cargo
//! member manifests, Rush locks, the install-policy configs, the
//! Plug'n'Play markers and the vendored ledger), plus one
//! presence-only Maven / NuGet marker per ecosystem so a repo holding only
//! those still gets its `ecosystem_unsupported_in_memory` warning.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::constants::npm_family::{
    BUN_LOCKB, PNP_MARKERS, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR,
};
use socket_patch_core::patch::redirect::npmrc::NPMRC_REL;
use socket_patch_core::utils::python_lock::is_python_lock_name;

use socket_patch_core::policy::{
    MemoryPolicyFs, PolicyOverrides, PolicySource, Root, RootFile, SelectionPolicy, POLICY_FILE_NAMES,
    SOCKET_YML_INVALID,
};

use super::roots::{
    detect_roots, join_root, root_markers, split_path, strip_root, EXCLUDED_ROOT_SEGMENTS,
    UNSUPPORTED_MARKERS,
};
use super::types::{
    IgnoredPath, PathSelection, PolicyErrorInfo, PolicyFileInput, SelectOptions, TreeEntryInput,
};
use crate::commands::scan::hosted::{PNPM_WORKSPACE_REL, REDIRECT_CANDIDATE_FILES};

/// Most entries [`PathSelection::ignored_sample`] carries.
pub const IGNORED_SAMPLE_MAX: usize = 100;

/// Longest path accepted, in bytes.
const MAX_PATH_LEN: usize = 1024;

/// Deepest path accepted, in segments.
const MAX_PATH_DEPTH: usize = 64;

/// The vendored-mode ledger (its presence refuses a vendored takeover).
pub(crate) const VENDOR_STATE_REL: &str = ".socket/vendor/state.json";

/// Rush's repo-state file (presence feeds the stale-hash warning).
pub(crate) const RUSH_REPO_STATE_REL: &str = "common/config/rush/repo-state.json";

/// The agent-mode manifest: part of the recorded view the rollout cap
/// classifies against (a package it records is not NEW).
pub(crate) const MANIFEST_REL: &str = ".socket/manifest.json";

/// Root-relative text files read beyond `REDIRECT_CANDIDATE_FILES`.
const EXTRA_TEXT_FILES: [&str; 4] = [PNPM_WORKSPACE_REL, NPMRC_REL, VENDOR_STATE_REL, MANIFEST_REL];

/// The one directory name the disk Cargo member walk never enters (it
/// follows `members`, `exclude`, path dependencies and `[patch]` paths
/// anywhere else, `vendor/` included); which manifests it reaches depends
/// on their content, so every other `Cargo.toml` under a Cargo root is
/// fetched and the engine repeats the walk over them.
const CARGO_SKIP_SEGMENT: &str = "target";

/// The file `cargo vendor` writes into every crate it copies. The disk walk
/// reads vendored crates only when a path dependency or `[patch]` path
/// names one; without their manifests the engine fails closed
/// (`redirect_cargo_transitive_dependents`), which beats streaming
/// thousands of registry manifests into the file limits.
const CARGO_VENDOR_CHECKSUM: &str = ".cargo-checksum.json";

/// Whether `manifest_dir` (root-relative) or a directory above it, below
/// the root, holds a `cargo vendor` checksum file.
fn is_cargo_vendored(manifest_dir: &str, root_files: &BTreeSet<&str>) -> bool {
    let mut dir = manifest_dir;
    loop {
        if root_files.contains(format!("{dir}/{CARGO_VENDOR_CHECKSUM}").as_str()) {
            return true;
        }
        match dir.rsplit_once('/') {
            Some((parent, _)) => dir = parent,
            None => return false,
        }
    }
}

/// A normalized repo-relative file path, or `None` when it is unsafe:
/// absolute, `..`/`.`/empty segments, backslashes, control characters,
/// overlong or overdeep.
pub fn safe_repo_path(path: &str) -> Option<String> {
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_PATH_DEPTH
        || segments
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return None;
    }
    Some(path.to_string())
}

/// A normalized repo-relative directory (`""` is the repo root; a trailing
/// `/` is dropped), or `None` when unsafe.
pub fn safe_root_path(root: &str) -> Option<String> {
    let trimmed = root.strip_suffix('/').unwrap_or(root);
    if trimmed.is_empty() || trimmed == "." {
        return Some(String::new());
    }
    safe_repo_path(trimmed)
}

/// Whether the engine keeps `path` as raw bytes rather than UTF-8 text.
pub fn is_binary_candidate(path: &str) -> bool {
    split_path(path).1 == BUN_LOCKB
}

/// How a root-relative file is consumed, when it is a candidate at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Need {
    Text,
    Binary,
    Present,
}

fn is_rush_subspace_lock(rel: &str) -> bool {
    let Some(rest) = rel
        .strip_prefix(RUSH_SUBSPACES_DIR)
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    matches!(rest.split_once('/'), Some((name, "pnpm-lock.yaml")) if !name.is_empty())
}

/// What `rel` (relative to a root whose files are `root_files`) is needed
/// for.
fn classify(rel: &str, root_files: &BTreeSet<&str>) -> Option<Need> {
    if rel == BUN_LOCKB {
        return Some(Need::Binary);
    }
    if REDIRECT_CANDIDATE_FILES.contains(&rel) || EXTRA_TEXT_FILES.contains(&rel) {
        return Some(Need::Text);
    }
    if PNP_MARKERS.contains(&rel) || rel == "rush.json" {
        return Some(Need::Present);
    }
    if !rel.contains('/') {
        if is_python_lock_name(rel) {
            return Some(Need::Text);
        }
        if rel.ends_with(".py") && root_files.contains(format!("{rel}.lock").as_str()) {
            return Some(Need::Text);
        }
        return None;
    }
    let rush = root_files.contains("rush.json");
    if rush && (rel == RUSH_COMMON_LOCK_REL || is_rush_subspace_lock(rel)) {
        return Some(Need::Text);
    }
    if rush && rel == RUSH_REPO_STATE_REL {
        return Some(Need::Present);
    }
    if let Some(manifest_dir) = rel.strip_suffix("/Cargo.toml") {
        if root_files.contains("Cargo.toml")
            && !manifest_dir.split('/').any(|seg| seg == CARGO_SKIP_SEGMENT)
            && !is_cargo_vendored(manifest_dir, root_files)
        {
            return Some(Need::Text);
        }
    }
    None
}

/// The listed root policy files with the text the caller fetched first. A
/// listed file with no text (not passed, `missing`, or a symlink) is present
/// without content, so loading it fails closed.
fn selection_policy_fs(blobs: &BTreeMap<String, bool>, supplied: &[PolicyFileInput]) -> MemoryPolicyFs {
    let mut fs = MemoryPolicyFs::default();
    for name in POLICY_FILE_NAMES {
        let Some(&symlink) = blobs.get(name) else {
            continue;
        };
        let text = supplied
            .iter()
            .find(|f| f.path == name && !f.missing.unwrap_or(false))
            .and_then(|f| f.text.as_ref());
        let file = match text {
            Some(text) if !symlink => RootFile::Present(text.as_bytes().to_vec()),
            _ => RootFile::PresentWithoutContent,
        };
        fs.files.insert(name.to_string(), file);
        fs.root_names.push(name.to_string());
    }
    fs
}

/// The policy path selection applies, or why it cannot be honored.
fn selection_policy(
    blobs: &BTreeMap<String, bool>,
    options: &SelectOptions,
) -> Result<SelectionPolicy, PolicyErrorInfo> {
    let supplied = options.policy_files.as_deref().unwrap_or_default();
    if let Some(bad) = supplied.iter().find(|f| !POLICY_FILE_NAMES.contains(&f.path.as_str())) {
        return Err(PolicyErrorInfo {
            code: SOCKET_YML_INVALID.to_string(),
            detail: format!(
                "policyFiles entry `{}` is not a root socket.yml or socket.yaml",
                socket_patch_core::policy::sanitize(&bad.path)
            ),
        });
    }
    let overrides = PolicyOverrides {
        bypass: options.no_socket_yml.unwrap_or(false),
        min_severity: None,
    };
    SelectionPolicy::load(&selection_policy_fs(blobs, supplied), &overrides)
        .map(|(policy, _)| policy)
        .map_err(|e| PolicyErrorInfo {
            code: e.code().to_string(),
            detail: e.detail(),
        })
}

/// `selectHostedScanPaths`: roots (detected, or `options.projectRoots`)
/// that the repo's socket.yml path policy admits, plus the files to stream
/// for them. Only `blob` entries are files; mode `120000` is a symbolic link
/// and is reported, never fetched.
pub fn select_paths(entries: &[TreeEntryInput], options: &SelectOptions) -> PathSelection {
    let mut ignored: Vec<IgnoredPath> = Vec::new();
    let mut blobs: BTreeMap<String, bool> = BTreeMap::new();
    for entry in entries {
        if entry.kind != "blob" {
            continue;
        }
        match safe_repo_path(&entry.path) {
            Some(path) => {
                blobs.insert(path, entry.mode == "120000");
            }
            None => ignored.push(IgnoredPath {
                path: entry.path.chars().take(MAX_PATH_LEN).collect(),
                reason: "unsafe_path".to_string(),
            }),
        }
    }

    let policy_paths: Vec<String> = POLICY_FILE_NAMES
        .iter()
        .filter(|name| blobs.contains_key(**name))
        .map(|name| name.to_string())
        .collect();
    let policy = match selection_policy(&blobs, options) {
        Ok(policy) => policy,
        Err(error) => {
            return PathSelection {
                policy_paths,
                policy_error: Some(error),
                ..PathSelection::default()
            }
        }
    };
    let policy_sha256 = match policy.source() {
        PolicySource::File { sha256, .. } => Some(sha256.clone()),
        PolicySource::None | PolicySource::Bypassed => None,
    };

    let candidate_roots: Vec<String> = match &options.project_roots {
        Some(requested) => {
            let mut out: BTreeSet<String> = BTreeSet::new();
            for root in requested {
                match safe_root_path(root) {
                    Some(r) => {
                        out.insert(r);
                    }
                    None => ignored.push(IgnoredPath {
                        path: root.clone(),
                        reason: "invalid_project_root".to_string(),
                    }),
                }
            }
            out.into_iter().collect()
        }
        None => {
            let (found, skipped) = detect_roots(
                blobs.keys().map(String::as_str),
                options.ecosystems.as_deref(),
            );
            ignored.extend(skipped);
            found
        }
    };
    // The same root filter the session applies, so a socket.yml negation
    // of a built-in ignore brings that tree's files in here too. An
    // excluded root is reported here, not streamed: its markers would
    // count against the session's file limit.
    let explicit = options.project_roots.is_some();
    let mut roots: Vec<String> = Vec::with_capacity(candidate_roots.len());
    for root in candidate_roots {
        let markers = root_markers(&root, blobs.keys().map(String::as_str));
        match policy.admits_root(&Root {
            rel_dir: &root,
            markers: &markers,
            explicit,
        }) {
            Ok(()) => roots.push(root),
            Err(reason) => {
                let paths: Vec<String> = if markers.is_empty() {
                    vec![root.clone()]
                } else {
                    markers.iter().map(|m| join_root(&root, m)).collect()
                };
                for path in paths {
                    ignored.push(IgnoredPath {
                        path,
                        reason: reason.code().to_string(),
                    });
                }
            }
        }
    }
    let root_set: BTreeSet<&str> = roots.iter().map(String::as_str).collect();

    let mut per_root: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for path in blobs.keys() {
        let mut dir = path.as_str();
        loop {
            dir = match dir.rsplit_once('/') {
                Some((parent, _)) => parent,
                None => "",
            };
            if let Some(root) = root_set.get(dir) {
                if let Some(rel) = strip_root(root, path) {
                    per_root.entry(root).or_default().insert(rel);
                }
            }
            if dir.is_empty() {
                break;
            }
        }
    }

    let mut needs: BTreeMap<String, Need> = BTreeMap::new();
    for (root, files) in &per_root {
        for rel in files {
            let Some(need) = classify(rel, files) else {
                continue;
            };
            let full = join_root(root, rel);
            let slot = needs.entry(full).or_insert(need);
            *slot = (*slot).min(need);
        }
    }

    for (eco, markers) in UNSUPPORTED_MARKERS {
        if !options
            .ecosystems
            .as_deref()
            .is_none_or(|list| list.iter().any(|e| e == eco))
        {
            continue;
        }
        let first = blobs.keys().find(|path| {
            let (dir, base) = split_path(path);
            markers.contains(&base)
                && !dir
                    .split('/')
                    .any(|seg| EXCLUDED_ROOT_SEGMENTS.contains(&seg))
                && policy
                    .admits_root(&Root {
                        rel_dir: dir,
                        markers: &[base.to_string()],
                        explicit: false,
                    })
                    .is_ok()
        });
        if let Some(path) = first {
            needs.entry(path.clone()).or_insert(Need::Present);
        }
    }

    // The session reads the same policy text again.
    for name in &policy_paths {
        needs.entry(name.clone()).or_insert(Need::Text);
    }

    let mut selection = PathSelection {
        roots,
        policy_paths,
        policy_sha256,
        ..PathSelection::default()
    };
    for (path, need) in needs {
        if blobs.get(&path).copied().unwrap_or(false) {
            selection.symlinks.push(path);
            continue;
        }
        match need {
            Need::Text => selection.fetch_text.push(path),
            Need::Binary => selection.fetch_binary.push(path),
            Need::Present => selection.present_only.push(path),
        }
    }
    ignored.sort_by(|a, b| a.path.cmp(&b.path));
    selection.ignored_count = ignored.len() as u64;
    ignored.truncate(IGNORED_SAMPLE_MAX);
    selection.ignored_sample = ignored;
    selection
}

/// `hostedScanCandidateFiles`: the root-relative candidate names and
/// patterns, for debugging only (selection is [`select_paths`]).
pub fn candidate_files() -> Vec<String> {
    let mut out: BTreeSet<String> = REDIRECT_CANDIDATE_FILES
        .iter()
        .chain(EXTRA_TEXT_FILES.iter())
        .chain(PNP_MARKERS.iter())
        .map(|s| s.to_string())
        .collect();
    for pattern in [
        "rush.json",
        RUSH_COMMON_LOCK_REL,
        RUSH_REPO_STATE_REL,
        "common/config/subspaces/*/pnpm-lock.yaml",
        "*.py.lock",
        "*.py (beside *.py.lock)",
        "pylock.toml",
        "pylock.*.toml",
        "**/Cargo.toml (Cargo workspaces)",
    ] {
        out.insert(pattern.to_string());
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(path: &str) -> TreeEntryInput {
        TreeEntryInput {
            path: path.into(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(10),
        }
    }

    #[test]
    fn selects_root_candidates_only() {
        let mut entries = vec![
            blob("package-lock.json"),
            blob("package.json"),
            blob("src/index.js"),
            blob(".npmrc"),
            blob("bun.lockb"),
            blob(".pnp.cjs"),
            blob("tool.py.lock"),
            blob("tool.py"),
            blob("other.py"),
            blob(".socket/vendor/redirect-state.json"),
            blob("web/yarn.lock"),
            blob("web/.yarnrc.yml"),
            blob("web/node_modules/x/package-lock.json"),
        ];
        entries.push(TreeEntryInput {
            path: "pnpm-workspace.yaml".into(),
            mode: "120000".into(),
            kind: "blob".into(),
            size: None,
        });
        entries.push(TreeEntryInput {
            path: "sub".into(),
            mode: "160000".into(),
            kind: "commit".into(),
            size: None,
        });
        entries.push(blob("../escape/package-lock.json"));
        let s = select_paths(&entries, &SelectOptions::default());
        assert_eq!(s.roots, vec!["", "web"]);
        assert_eq!(
            s.fetch_text,
            vec![
                ".npmrc",
                "package-lock.json",
                "tool.py",
                "tool.py.lock",
                "web/.yarnrc.yml",
                "web/yarn.lock"
            ]
        );
        assert_eq!(s.fetch_binary, vec!["bun.lockb"]);
        assert_eq!(s.present_only, vec![".pnp.cjs"]);
        assert_eq!(s.symlinks, vec!["pnpm-workspace.yaml"]);
        assert_eq!(s.ignored_count, 2);
    }

    #[test]
    fn rush_and_cargo_members_are_fetched_under_their_root() {
        let entries = vec![
            blob("rush.json"),
            blob("common/config/rush/pnpm-lock.yaml"),
            blob("common/config/rush/repo-state.json"),
            blob("common/config/subspaces/a/pnpm-lock.yaml"),
            blob("rs/Cargo.toml"),
            blob("rs/Cargo.lock"),
            blob("rs/crates/x/Cargo.toml"),
            blob("rs/vendor/foo/Cargo.toml"),
            blob("rs/target/debug/Cargo.toml"),
            blob("rs/vendor/serde/Cargo.toml"),
            blob("rs/vendor/serde/.cargo-checksum.json"),
            blob("rs/vendor/serde/tests/ui/Cargo.toml"),
            blob("rs/third_party/.cargo-checksum.json"),
            blob("rs/third_party/Cargo.toml"),
        ];
        let s = select_paths(&entries, &SelectOptions::default());
        assert_eq!(s.roots, vec!["", "rs"]);
        assert_eq!(
            s.fetch_text,
            vec![
                "common/config/rush/pnpm-lock.yaml",
                "common/config/subspaces/a/pnpm-lock.yaml",
                "rs/Cargo.lock",
                "rs/Cargo.toml",
                "rs/crates/x/Cargo.toml",
                "rs/vendor/foo/Cargo.toml"
            ]
        );
        assert_eq!(
            s.present_only,
            vec!["common/config/rush/repo-state.json", "rush.json"]
        );
    }

    #[test]
    fn a_maven_or_nuget_only_repo_still_names_one_marker_per_ecosystem() {
        let entries = vec![
            blob("svc/b/pom.xml"),
            blob("svc/a/pom.xml"),
            blob("test/pom.xml"),
            blob("app/nuget.config"),
            blob("src/Main.java"),
        ];
        let s = select_paths(&entries, &SelectOptions::default());
        assert!(s.roots.is_empty());
        assert!(s.fetch_text.is_empty());
        assert_eq!(s.present_only, vec!["app/nuget.config", "svc/a/pom.xml"]);
        let s = select_paths(
            &entries,
            &SelectOptions {
                project_roots: None,
                ecosystems: Some(vec!["npm".into()]),
                ..SelectOptions::default()
            },
        );
        assert!(s.present_only.is_empty());
    }

    #[test]
    fn explicit_roots_override_detection() {
        let entries = vec![blob("a/package-lock.json"), blob("b/yarn.lock")];
        let s = select_paths(
            &entries,
            &SelectOptions {
                project_roots: Some(vec!["b/".into(), "../x".into()]),
                ecosystems: None,
                ..SelectOptions::default()
            },
        );
        assert_eq!(s.roots, vec!["b"]);
        assert_eq!(s.fetch_text, vec!["b/yarn.lock"]);
        assert_eq!(s.ignored_sample[0].reason, "invalid_project_root");
    }

    #[test]
    fn path_safety() {
        for bad in [
            "", "/abs", "a/../b", "a//b", "./a", "a\\b", "a\u{0}b", "a\nb",
        ] {
            assert_eq!(safe_repo_path(bad), None, "{bad:?}");
        }
        assert_eq!(safe_repo_path("a/b.json").as_deref(), Some("a/b.json"));
        assert_eq!(safe_root_path("").as_deref(), Some(""));
        assert_eq!(safe_root_path("a/").as_deref(), Some("a"));
    }

    #[test]
    fn candidate_listing_is_sorted_and_names_the_vendored_ledger_only() {
        let listed = candidate_files();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted);
        assert!(listed.iter().any(|f| f == ".socket/vendor/state.json"));
        // v5 hosted mode keeps no ledger, so the pre-v5 one is never read.
        assert!(!listed
            .iter()
            .any(|f| f == ".socket/vendor/redirect-state.json"));
        assert!(listed.iter().any(|f| f == "package-lock.json"));
    }
}
