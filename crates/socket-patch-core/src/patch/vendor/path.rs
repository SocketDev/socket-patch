//! Vendored-path layout: builders, the lockfile-string recovery parser, and
//! the leaf↔PURL round-trip used by the orphan sweep.
//!
//! ## The convention (contract-documented)
//!
//! ```text
//! .socket/vendor/<eco>/<patch-uuid>/<natural-leaf>
//! ```
//!
//! The full 36-char lowercase hyphenated patch UUID is a dedicated path level,
//! so the UUID appears verbatim in every lockfile-visible path string —
//! external tools recover "this dependency is Socket-vendored, by patch X"
//! from the lockfile alone, with no access to `.socket/manifest.json` or
//! `state.json`. Each ecosystem keeps its canonical artifact name as the leaf
//! (wheel filenames stay pip-parseable, tarballs stay npm-conventional).
//! Updating a patch changes the UUID, which changes the path, which changes
//! the lockfile — staleness is diffable by construction.
//!
//! ## Leaves per ecosystem
//!
//! | eco      | leaf                                   |
//! |----------|----------------------------------------|
//! | npm      | `[@scope/]<name>-<version>.tgz`        |
//! | cargo    | `<name>-<version>/`                    |
//! | golang   | `<module>@<version>/` (nested dirs)    |
//! | composer | `<vendor>/<name>@<version>/`           |
//! | gem      | `<name>-<version>/`                    |
//! | pypi     | `<dist>-<version>-<tags>.whl` (PEP 427)|
//! | nuget    | `<idLower>.<versionNorm>.nupkg`        |
//! | maven    | `<g-as-path>/<a>/<v>/<a>-<v>.jar`      |

use std::path::{Path, PathBuf};

use crate::crawlers::Ecosystem;
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment, is_safe_single_segment};
use crate::utils::fs::{entry_is_dir, list_dir_entries};

/// Project-relative root of all vendored artifacts.
pub(crate) const VENDOR_DIR: &str = ".socket/vendor";

/// The ecosystem directory names under [`VENDOR_DIR`]. These double as the
/// `<eco>` capture of the recovery convention and are independent of which
/// features this binary was compiled with (an orphan sweep must still
/// recognise — and report, not delete — a dir for a compiled-out ecosystem).
pub(crate) const ECOSYSTEM_DIRS: &[&str] = &[
    "npm", "cargo", "golang", "composer", "gem", "pypi", "nuget", "maven",
];

/// The vendor ecosystem-dir name for a PURL, or `None` when the ecosystem has
/// no vendor backend (jsr) or is compiled out of this binary.
///
/// The dir name is `Ecosystem::cli_name()`: both are persisted contracts
/// (cli_name in manifests/sidecars, the dir in committed vendor paths) and
/// they deliberately share one spelling — see `ECOSYSTEM_DIRS` above.
pub fn ecosystem_dir_for_purl(purl: &str) -> Option<&'static str> {
    match Ecosystem::from_purl(purl)? {
        #[cfg(feature = "deno")]
        Ecosystem::Deno => None,
        eco => Some(eco.cli_name()),
    }
}

/// The project-relative uuid dir (`.socket/vendor/<eco>/<uuid>`), validated.
///
/// SECURITY: `uuid` comes from a committed, tamper-able manifest/state file
/// and keys an on-disk directory that vendor creates and `--revert` deletes.
/// Anything that is not the exact canonical UUID grammar is rejected
/// fail-closed before any disk access.
pub fn vendor_uuid_dir_rel(eco: &str, uuid: &str) -> Option<String> {
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) {
        return None;
    }
    Some(format!("{VENDOR_DIR}/{eco}/{uuid}"))
}

/// One parsed vendored path (the output of [`parse_vendor_path`]).
#[derive(Debug)]
pub struct VendorPathParts {
    /// Ecosystem dir name (`npm`, `cargo`, …).
    pub eco: String,
    /// The 36-char canonical patch UUID.
    pub uuid: String,
    /// Everything after the uuid level, forward-slashed, no trailing slash.
    pub leaf: String,
}

/// Recover `(eco, uuid, leaf)` from any lockfile-recorded vendored path
/// string — `file:` npm specs, `./`-prefixed go.mod replace targets,
/// composer dist urls, requirement lines, backslashed Windows spellings.
/// This is the documented external-tool recovery rule; `None` means the
/// string is not a Socket-vendored path.
pub fn parse_vendor_path(s: &str) -> Option<VendorPathParts> {
    let norm = s.replace('\\', "/");
    let norm = norm.strip_prefix("file:").unwrap_or(&norm);
    let norm = norm.strip_prefix("./").unwrap_or(norm);
    // Find the `.socket/vendor/` anchor anywhere in the string (a workspace
    // sub-project may record `../.socket/vendor/...`).
    let anchor = format!("{VENDOR_DIR}/");
    let idx = norm.find(&anchor)?;
    // Anchor must sit at a path-component boundary.
    if idx > 0 && norm.as_bytes()[idx - 1] != b'/' {
        return None;
    }
    let rest = &norm[idx + anchor.len()..];
    let mut it = rest.splitn(3, '/');
    let eco = it.next()?;
    let uuid = it.next()?;
    let leaf = it.next()?.trim_end_matches('/');
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) || leaf.is_empty() {
        return None;
    }
    Some(VendorPathParts {
        eco: eco.to_string(),
        uuid: uuid.to_string(),
        leaf: leaf.to_string(),
    })
}

/// Split a `<name>-<version>` leaf at the version boundary: the version is
/// the suffix after the LAST `-` that is immediately followed by a digit
/// (versions always start with a digit; names may contain digit-bearing
/// segments like `base-64`). Returns `(name, version)`.
fn split_name_version(leaf: &str) -> Option<(&str, &str)> {
    let bytes = leaf.as_bytes();
    let mut split = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'-' && bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            split = Some(i);
        }
    }
    let i = split?;
    let (name, version) = (&leaf[..i], &leaf[i + 1..]);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Split a `<…>@<version>` leaf at the LAST `@` in its FINAL path component
/// (golang modules nest directories; composer leaves are `vendor/name@ver`).
fn split_at_version(leaf: &str) -> Option<(&str, &str)> {
    let at = leaf.rfind('@')?;
    // The `@` must be in the final component (a scope-`@` is at a component
    // start and never the last `@` of a well-formed leaf, but be strict).
    if leaf[at..].contains('/') {
        return None;
    }
    let (head, version) = (&leaf[..at], &leaf[at + 1..]);
    if head.is_empty() || version.is_empty() {
        return None;
    }
    Some((head, version))
}

/// Split a NuGet `<idLower>.<version>` leaf (already `.nupkg`-stripped) at the
/// version boundary: the version is the maximal trailing dotted run starting at
/// the FIRST `.`-delimited segment that begins with a digit (NuGet ids never
/// start a segment with a digit, versions always do — `Newtonsoft.Json.13.0.3`
/// → `("Newtonsoft.Json", "13.0.3")`, prerelease tails ride along). Heuristic
/// only; state.json is the ledger of record.
fn split_nuget_leaf(stem: &str) -> Option<(&str, &str)> {
    let mut split = None;
    for (i, _) in stem.match_indices('.') {
        if stem[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            split = Some(i);
            break;
        }
    }
    let i = split?;
    let (name, version) = (&stem[..i], &stem[i + 1..]);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Reconstruct the base PURL from a vendored leaf. This is the orphan-sweep
/// FALLBACK identification (state.json is the ledger of record); `None` means
/// "unrecognisable — report, never delete by guess".
fn leaf_to_purl(eco: &str, leaf: &str) -> Option<String> {
    match eco {
        "npm" => {
            let stem = leaf.strip_suffix(".tgz")?;
            let (name, version) = split_name_version(stem)?;
            Some(format!("pkg:npm/{name}@{version}"))
        }
        "cargo" => {
            let (name, version) = split_name_version(leaf)?;
            Some(format!("pkg:cargo/{name}@{version}"))
        }
        "gem" => {
            let (name, version) = split_name_version(leaf)?;
            Some(format!("pkg:gem/{name}@{version}"))
        }
        "golang" => {
            let (module, version) = split_at_version(leaf)?;
            if !is_safe_multi_segment(module) || !is_safe_single_segment(version) {
                return None;
            }
            Some(format!("pkg:golang/{module}@{version}"))
        }
        "composer" => {
            let (path, version) = split_at_version(leaf)?;
            let (vendor, name) = path.split_once('/')?;
            if vendor.is_empty() || name.is_empty() || name.contains('/') {
                return None;
            }
            Some(format!("pkg:composer/{vendor}/{name}@{version}"))
        }
        "pypi" => {
            // PEP 427 wheel filename: dist-version-(build-)?py-abi-plat.whl;
            // dist and version are the first two `-` segments (dist names
            // normalise `-` to `_`, so the split is unambiguous).
            let stem = leaf.strip_suffix(".whl")?;
            let mut it = stem.splitn(3, '-');
            let dist = it.next()?;
            let version = it.next()?;
            it.next()?; // tags must exist
            if dist.is_empty() || version.is_empty() {
                return None;
            }
            Some(format!("pkg:pypi/{dist}@{version}"))
        }
        "nuget" => {
            let stem = leaf.strip_suffix(".nupkg")?;
            let (name, version) = split_nuget_leaf(stem)?;
            if !is_safe_single_segment(version) {
                return None;
            }
            Some(format!("pkg:nuget/{name}@{version}"))
        }
        "maven" => {
            // maven2 layout: `<g1>/…/<gN>/<artifactId>/<version>/<a>-<v>.jar`.
            // The last three components are `<artifactId>/<version>/<file>`;
            // everything before them is the dotted groupId. The filename must
            // spell out `<artifactId>-<version>.jar` (a consistency check).
            let stem = leaf.strip_suffix(".jar")?;
            let parts: Vec<&str> = stem.split('/').collect();
            // group (≥1) + artifact + version + filename-stem = ≥4 segments.
            if parts.len() < 4 {
                return None;
            }
            let file_stem = parts[parts.len() - 1];
            let version = parts[parts.len() - 2];
            let artifact = parts[parts.len() - 3];
            let group = parts[..parts.len() - 3].join(".");
            if group.is_empty() || artifact.is_empty() || version.is_empty() {
                return None;
            }
            if file_stem != format!("{artifact}-{version}") {
                return None;
            }
            if !is_safe_multi_segment(&group.replace('.', "/"))
                || !is_safe_single_segment(artifact)
                || !is_safe_single_segment(version)
            {
                return None;
            }
            Some(format!("pkg:maven/{group}/{artifact}@{version}"))
        }
        _ => None,
    }
}

/// One swept vendored unit: the uuid dir and what could be learned about it.
#[derive(Debug)]
pub struct SweptVendorDir {
    pub eco: String,
    pub uuid: String,
    /// Absolute path of the uuid dir.
    pub dir: PathBuf,
    /// Base PURLs reconstructed from the leaves inside (may be empty when
    /// nothing inside parses — such a dir is reported, never auto-deleted
    /// unless its uuid is positively known stale).
    pub purls: Vec<String>,
}

/// Enumerate every `.socket/vendor/<eco>/<uuid>/` unit. Non-uuid-shaped dir
/// names are skipped fail-closed (we never touch what we can't positively
/// identify as ours). Used by reconcile and `--revert`'s orphan fallback.
pub async fn sweep_vendor_dirs(project_root: &Path) -> Vec<SweptVendorDir> {
    let mut out = Vec::new();
    let vendor_root = project_root.join(VENDOR_DIR);
    for eco in ECOSYSTEM_DIRS {
        let eco_root = vendor_root.join(eco);
        for entry in list_dir_entries(&eco_root).await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_canonical_uuid(&name) {
                continue;
            }
            let dir = entry.path();
            if !entry_is_dir(&entry).await {
                continue;
            }
            let purls = collect_leaf_purls(eco, &dir).await;
            out.push(SweptVendorDir {
                eco: (*eco).to_string(),
                uuid: name,
                dir,
                purls,
            });
        }
    }
    out
}

/// Reconstruct base PURLs from the leaves inside one uuid dir. Walks nested
/// directories until a component parses as a versioned leaf (the golang
/// module / composer vendor-name nesting), mirroring the go-patches walker.
async fn collect_leaf_purls(eco: &str, uuid_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(uuid_dir.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in list_dir_entries(&dir).await {
            let name = entry.file_name().to_string_lossy().into_owned();
            let leaf = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if let Some(purl) = leaf_to_purl(eco, &leaf) {
                out.push(purl);
                continue; // never recurse into a recognised unit
            }
            // Keep descending through structural levels (go module path
            // segments, composer vendor dirs, npm @scope dirs) up to a sane
            // depth bound.
            if entry_is_dir(&entry).await && leaf.matches('/').count() < 8 {
                stack.push((entry.path(), leaf));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    #[test]
    fn uuid_dir_is_validated() {
        assert_eq!(
            vendor_uuid_dir_rel("npm", UUID).as_deref(),
            Some(".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f")
        );
        assert!(vendor_uuid_dir_rel("npm", "../../escape").is_none());
        assert!(vendor_uuid_dir_rel("npm", "9F6B2C4E-1D3A-4F6B-8C2D-7E5A9B1C3D5F").is_none());
        assert!(
            vendor_uuid_dir_rel("jsr", UUID).is_none(),
            "unknown eco dir"
        );
    }

    /// `ecosystem_dir_for_purl` derives the dir from `Ecosystem::cli_name()`.
    /// The dir is an on-disk contract (committed vendor paths), so every
    /// classification must land inside `ECOSYSTEM_DIRS` — a cli_name rename
    /// must fail here rather than silently move the vendor layout. JSR stays
    /// backend-less.
    #[test]
    fn ecosystem_dir_matches_contract_dirs() {
        for eco in Ecosystem::all() {
            let purl = format!("pkg:{}/example@1.0.0", eco.cli_name());
            match ecosystem_dir_for_purl(&purl) {
                Some(dir) => {
                    assert_eq!(dir, eco.cli_name());
                    assert!(
                        ECOSYSTEM_DIRS.contains(&dir),
                        "dir {dir:?} missing from ECOSYSTEM_DIRS"
                    );
                }
                None => {
                    #[cfg(feature = "deno")]
                    assert_eq!(*eco, Ecosystem::Deno, "only deno lacks a vendor backend");
                    #[cfg(not(feature = "deno"))]
                    panic!("no vendor dir for {}", eco.cli_name());
                }
            }
        }
        assert_eq!(ecosystem_dir_for_purl("pkg:jsr/@std/path@0.220.0"), None);
        assert_eq!(ecosystem_dir_for_purl("pkg:unknown/foo@1.0"), None);
    }

    #[test]
    fn recovery_parses_every_lockfile_spelling() {
        // npm file: spec
        let p = parse_vendor_path(&format!(
            "file:.socket/vendor/npm/{UUID}/lodash-4.17.21.tgz"
        ))
        .unwrap();
        assert_eq!((p.eco.as_str(), p.uuid.as_str()), ("npm", UUID));
        assert_eq!(p.leaf, "lodash-4.17.21.tgz");

        // go.mod replace target
        let p = parse_vendor_path(&format!(
            "./.socket/vendor/golang/{UUID}/github.com/foo/bar@v1.4.2"
        ))
        .unwrap();
        assert_eq!(p.eco, "golang");
        assert_eq!(p.leaf, "github.com/foo/bar@v1.4.2");

        // composer dist url with trailing slash
        let p = parse_vendor_path(&format!(
            ".socket/vendor/composer/{UUID}/monolog/monolog@2.9.1/"
        ))
        .unwrap();
        assert_eq!(p.leaf, "monolog/monolog@2.9.1");

        // nuget flat-folder feed .nupkg
        let p = parse_vendor_path(&format!(
            ".socket/vendor/nuget/{UUID}/newtonsoft.json.13.0.3.nupkg"
        ))
        .unwrap();
        assert_eq!(p.eco, "nuget");
        assert_eq!(p.leaf, "newtonsoft.json.13.0.3.nupkg");

        // maven2 nested repo path (group as dirs → artifact → version → jar)
        let p = parse_vendor_path(&format!(
            ".socket/vendor/maven/{UUID}/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"
        ))
        .unwrap();
        assert_eq!(p.eco, "maven");
        assert_eq!(
            p.leaf,
            "org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"
        );

        // cargo config path, backslashes (Windows spelling)
        let p =
            parse_vendor_path(&format!(".socket\\vendor\\cargo\\{UUID}\\serde-1.0.190")).unwrap();
        assert_eq!(
            (p.eco.as_str(), p.leaf.as_str()),
            ("cargo", "serde-1.0.190")
        );

        // anchored mid-string (workspace-relative)
        assert!(parse_vendor_path(&format!(
            "../.socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl"
        ))
        .is_some());

        // Rejections: bad uuid, unknown eco, non-boundary anchor.
        assert!(parse_vendor_path(".socket/vendor/npm/not-a-uuid/x.tgz").is_none());
        assert!(parse_vendor_path(&format!(".socket/vendor/jsr/{UUID}/x")).is_none());
        assert!(parse_vendor_path(&format!("x.socket/vendor/npm/{UUID}/y.tgz")).is_none());
    }

    #[test]
    fn leaf_round_trips() {
        // npm, incl. scoped and digit-bearing names + prerelease versions.
        assert_eq!(
            leaf_to_purl("npm", "lodash-4.17.21.tgz").as_deref(),
            Some("pkg:npm/lodash@4.17.21")
        );
        assert_eq!(
            leaf_to_purl("npm", "@scope/pkg-1.2.3.tgz").as_deref(),
            Some("pkg:npm/@scope/pkg@1.2.3")
        );
        assert_eq!(
            leaf_to_purl("npm", "base-64-1.0.0.tgz").as_deref(),
            Some("pkg:npm/base-64@1.0.0")
        );
        assert_eq!(
            leaf_to_purl("npm", "foo-1.0.0-beta.1.tgz").as_deref(),
            Some("pkg:npm/foo@1.0.0-beta.1")
        );
        // cargo / gem
        assert_eq!(
            leaf_to_purl("cargo", "serde-1.0.190").as_deref(),
            Some("pkg:cargo/serde@1.0.190")
        );
        assert_eq!(
            leaf_to_purl("gem", "rack-3.2.6").as_deref(),
            Some("pkg:gem/rack@3.2.6")
        );
        // golang nested module
        assert_eq!(
            leaf_to_purl("golang", "github.com/foo/bar@v1.4.2").as_deref(),
            Some("pkg:golang/github.com/foo/bar@v1.4.2")
        );
        // composer
        assert_eq!(
            leaf_to_purl("composer", "monolog/monolog@2.9.1").as_deref(),
            Some("pkg:composer/monolog/monolog@2.9.1")
        );
        // pypi wheel
        assert_eq!(
            leaf_to_purl("pypi", "six-1.16.0-py2.py3-none-any.whl").as_deref(),
            Some("pkg:pypi/six@1.16.0")
        );
        // nuget nupkg: split at the first digit-leading dotted segment, so a
        // dotted id (Newtonsoft.Json) keeps its dots and the version rides the
        // trailing run.
        assert_eq!(
            leaf_to_purl("nuget", "newtonsoft.json.13.0.3.nupkg").as_deref(),
            Some("pkg:nuget/newtonsoft.json@13.0.3")
        );
        assert_eq!(
            leaf_to_purl("nuget", "contoso.widgets.2.0.0-rc1.nupkg").as_deref(),
            Some("pkg:nuget/contoso.widgets@2.0.0-rc1")
        );
        assert!(
            leaf_to_purl("nuget", "no-version-here.nupkg").is_none(),
            ".nupkg with no version-leading segment is unparseable"
        );
        // maven2 nested jar: dotted group recovered from the path dirs, the
        // version from the second-to-last component, cross-checked against the
        // filename stem.
        assert_eq!(
            leaf_to_purl(
                "maven",
                "org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"
            )
            .as_deref(),
            Some("pkg:maven/org.apache.commons/commons-text@1.10.0")
        );
        // A single-segment group still round-trips.
        assert_eq!(
            leaf_to_purl("maven", "single/app/1.0.0/app-1.0.0.jar").as_deref(),
            Some("pkg:maven/single/app@1.0.0")
        );
        // A filename that does not spell <artifact>-<version>.jar is rejected.
        assert!(
            leaf_to_purl("maven", "org/apache/commons-text/1.10.0/wrong-1.10.0.jar").is_none(),
            "filename stem must match <artifact>-<version>"
        );
        // Too few path segments (no group) is unparseable.
        assert!(leaf_to_purl("maven", "app/1.0.0/app-1.0.0.jar").is_none());
        // Unparseable leaves are None, not garbage.
        assert!(leaf_to_purl("npm", "noversion.tgz").is_none());
        assert!(leaf_to_purl("golang", "no-version-here").is_none());
        assert!(
            leaf_to_purl("pypi", "six-1.16.0.whl").is_none(),
            "tags required"
        );
    }

    #[tokio::test]
    async fn sweep_finds_units_and_skips_non_uuid_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // A recognisable npm unit, a nested golang unit, and junk.
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/npm/{UUID}")))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(format!(".socket/vendor/npm/{UUID}/lodash-4.17.21.tgz")),
            b"x",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(root.join(format!(
            ".socket/vendor/golang/{UUID}/github.com/foo/bar@v1.4.2"
        )))
        .await
        .unwrap();
        tokio::fs::create_dir_all(root.join(".socket/vendor/npm/not-a-uuid"))
            .await
            .unwrap();

        let swept = sweep_vendor_dirs(root).await;
        assert_eq!(swept.len(), 2, "junk dir skipped: {swept:?}");
        let npm = swept.iter().find(|s| s.eco == "npm").unwrap();
        assert_eq!(npm.purls, vec!["pkg:npm/lodash@4.17.21".to_string()]);
        let go = swept.iter().find(|s| s.eco == "golang").unwrap();
        assert_eq!(
            go.purls,
            vec!["pkg:golang/github.com/foo/bar@v1.4.2".to_string()]
        );
        assert_eq!(go.uuid, UUID);
    }
}
