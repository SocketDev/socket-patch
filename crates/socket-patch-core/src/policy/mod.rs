//! The repository's patch policy: the `patches` block and
//! `projectIgnorePaths` of the root `socket.yml`, plus the built-in default
//! path ignores. See `docs/configuration.md#repository-patch-policy`.
//!
//! A policy only ever **narrows** what `scan` patches (trust boundary,
//! CLI_CONTRACT.md): nothing here names an endpoint, a credential, a mode
//! or a safety switch. Because it only narrows, an unreadable or invalid
//! file fails closed ([`PolicyError`]) instead of meaning "no policy".

pub mod paths;
mod report;
pub mod socket_yml;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::api::ranking::max_severity_order;
use crate::api::types::PatchSearchResult;
use crate::crawlers::Ecosystem;
use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};

use self::paths::{PathHit, PathMatcher};
use self::socket_yml::{parse_file, ParsedFile, PatchesBlock};

pub use self::report::{canon, policy_block, FilteredEntry, RetainedEntry};
pub use self::socket_yml::MAX_FILE_BYTES;

/// Root file names, in the order they are read.
pub const POLICY_FILE_NAMES: [&str; 2] = ["socket.yml", "socket.yaml"];

/// Built-in ignores for discovered project roots (overridable with `!`).
pub const DEFAULT_IGNORE_PATHS: [&str; 5] =
    ["test/", "tests/", "fixtures/", "__fixtures__/", "testdata/"];

/// List label of [`DEFAULT_IGNORE_PATHS`] in filter details.
pub const DEFAULT_IGNORE_LIST: &str = "built-in default";

pub const SOCKET_YML_INVALID: &str = "socket_yml_invalid";
pub const SOCKET_YML_AMBIGUOUS: &str = "socket_yml_ambiguous";
pub const SOCKET_YML_IGNORED_VALUE: &str = "socket_yml_ignored_value";
pub const SOCKET_YML_NAME_CASE: &str = "socket_yml_name_case";
pub const SOCKET_YML_REPO_UNTRUSTED: &str = "socket_yml_repo_untrusted";
pub const PATCHES_DISABLED: &str = "patches_disabled";
pub const POLICY_BYPASSED: &str = "policy_bypassed";

/// Longest file-derived string copied into output.
const MAX_OUTPUT_CHARS: usize = 200;

/// Characters never copied into output: controls (terminal escapes) and
/// the invisible formatting characters that can reorder or hide text
/// (bidi overrides and isolates, zero-width characters, BOM).
fn unsafe_for_output(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// [`sanitize`] without the length cap, for whole messages.
pub fn strip_unsafe(s: &str) -> String {
    s.chars().filter(|c| !unsafe_for_output(*c)).collect()
}

/// Make a file-derived string safe to print: control and invisible
/// formatting characters dropped, at most 200 characters.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !unsafe_for_output(*c))
        .take(MAX_OUTPUT_CHARS)
        .collect()
}

/// Where the policy came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// No file, an empty file, a file-less scan (`--global`), or only a
    /// case variant of the name.
    None,
    /// A root file was read; `path` is its name relative to the repo root.
    File { path: String, sha256: String },
    /// `--no-socket-yml` / `SOCKET_NO_SOCKET_YML`.
    Bypassed,
}

impl PolicySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicySource::None => "none",
            PolicySource::File { .. } => "file",
            PolicySource::Bypassed => "bypassed",
        }
    }
}

/// Why a root, package or patch was filtered. Codes are stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterReason {
    Disabled,
    PathExcluded {
        pattern: String,
        list: &'static str,
    },
    PathNotIncluded,
    Ecosystem,
    PackageNotListed,
    PackageIgnored {
        spec: String,
    },
    Severity {
        found: Option<String>,
        floor: String,
    },
}

impl FilterReason {
    pub fn code(&self) -> &'static str {
        match self {
            FilterReason::Disabled => "policy_disabled",
            FilterReason::PathExcluded { .. } => "policy_path_excluded",
            FilterReason::PathNotIncluded => "policy_path_not_included",
            FilterReason::Ecosystem => "policy_ecosystem",
            FilterReason::PackageNotListed => "policy_package_not_listed",
            FilterReason::PackageIgnored { .. } => "policy_package_ignored",
            FilterReason::Severity { .. } => "policy_severity",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            FilterReason::Disabled => "patches.enabled is false".to_string(),
            FilterReason::PathExcluded { pattern, list } => {
                format!("{} ({list})", sanitize(pattern))
            }
            FilterReason::PathNotIncluded => "not matched by patches.includePaths".to_string(),
            FilterReason::Ecosystem => "ecosystem not in patches.ecosystems".to_string(),
            FilterReason::PackageNotListed => "not in patches.packages".to_string(),
            FilterReason::PackageIgnored { spec } => {
                format!("{} (patches.ignorePackages)", sanitize(spec))
            }
            FilterReason::Severity { found, floor } => {
                format!("{} < {floor}", found.as_deref().unwrap_or("unknown"))
            }
        }
    }
}

/// A policy file that cannot be honored. Scan fails closed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Invalid {
        file: String,
        key: String,
        message: String,
    },
    Ambiguous {
        files: [String; 2],
    },
}

impl PolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            PolicyError::Invalid { .. } => SOCKET_YML_INVALID,
            PolicyError::Ambiguous { .. } => SOCKET_YML_AMBIGUOUS,
        }
    }

    /// The message without the remedy.
    pub fn detail(&self) -> String {
        match self {
            PolicyError::Invalid { file, key, message } if key.is_empty() => {
                format!("{file}: {}", strip_unsafe(message))
            }
            PolicyError::Invalid { file, key, message } => {
                format!("{file}: {}: {}", sanitize(key), strip_unsafe(message))
            }
            PolicyError::Ambiguous { files } => format!(
                "{} and {} both exist and their `patches`/`projectIgnorePaths` differ; keep one file",
                files[0], files[1]
            ),
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (fix the file, or pass --no-socket-yml to ignore it)",
            self.detail()
        )
    }
}

impl std::error::Error for PolicyError {}

/// A root file as the policy source sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootFile {
    Absent,
    Present(Vec<u8>),
    /// Listed, but its bytes were withheld (symlink, oversize, LFS pointer,
    /// binary): never "absent", because the file may narrow the scan.
    PresentWithoutContent,
}

/// Read access to the repo root's policy files.
pub trait PolicyFs {
    /// The root file named exactly `name`, read up to `cap + 1` bytes.
    fn read_root_file(&self, name: &str, cap: usize) -> std::io::Result<RootFile>;

    /// Root entries whose names equal a policy file name only ignoring case.
    fn case_variants(&self) -> Vec<String> {
        Vec::new()
    }
}

/// [`PolicyFs`] over a directory on disk (the repo root).
pub struct DiskPolicyFs {
    root: PathBuf,
}

impl DiskPolicyFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn entry_names(&self) -> Vec<String> {
        std::fs::read_dir(&self.root)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(unix)]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the handle's
    // metadata then refuses it. O_NOFOLLOW: the path was resolved already.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn io_other(message: &str) -> std::io::Error {
    std::io::Error::other(message.to_string())
}

impl PolicyFs for DiskPolicyFs {
    fn read_root_file(&self, name: &str, cap: usize) -> std::io::Result<RootFile> {
        if !self.entry_names().iter().any(|n| n == name) {
            return Ok(RootFile::Absent);
        }
        // Resolve first, confine, then open the resolved path without
        // following a final symlink: a link swapped in after the check is
        // refused instead of followed out of the repository.
        let root = std::fs::canonicalize(&self.root)?;
        let target = std::fs::canonicalize(self.root.join(name))?;
        if !target.starts_with(&root) {
            return Err(io_other("symlink resolves outside the repository root"));
        }
        let file = open_nonblocking(&target)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io_other("not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > cap {
            return Err(io_other(&format!("larger than {} KiB", cap / 1024)));
        }
        Ok(RootFile::Present(bytes))
    }

    fn case_variants(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .entry_names()
            .into_iter()
            .filter(|n| {
                POLICY_FILE_NAMES
                    .iter()
                    .any(|p| n.eq_ignore_ascii_case(p) && n != p)
            })
            .collect();
        out.sort();
        out
    }
}

/// [`PolicyFs`] over an in-memory tree root (the hosted engine).
#[derive(Debug, Clone, Default)]
pub struct MemoryPolicyFs {
    pub files: BTreeMap<String, RootFile>,
    /// Every root entry name the tree lists, for the case-variant warning.
    pub root_names: Vec<String>,
}

impl PolicyFs for MemoryPolicyFs {
    fn read_root_file(&self, name: &str, cap: usize) -> std::io::Result<RootFile> {
        match self.files.get(name) {
            None => Ok(RootFile::Absent),
            Some(RootFile::Present(bytes)) if bytes.len() > cap => {
                Err(io_other(&format!("larger than {} KiB", cap / 1024)))
            }
            Some(file) => Ok(file.clone()),
        }
    }

    fn case_variants(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .root_names
            .iter()
            .filter(|n| {
                POLICY_FILE_NAMES
                    .iter()
                    .any(|p| n.eq_ignore_ascii_case(p) && n != p)
            })
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Which layer set a scalar override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideSource {
    Flag,
    Env,
}

/// The invoking user's overrides (trusted; they beat the file).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    /// Skip the file entirely (built-in default ignores still apply).
    pub bypass: bool,
    /// `(None, _)` is `none`: no floor, even when the file sets one.
    pub min_severity: Option<(Option<u8>, OverrideSource)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWarning {
    pub code: &'static str,
    pub detail: String,
}

/// Where the effective severity floor came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeveritySource {
    Flag,
    Env,
    File,
    Default,
}

impl SeveritySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            SeveritySource::Flag => "flag",
            SeveritySource::Env => "env",
            SeveritySource::File => "file",
            SeveritySource::Default => "default",
        }
    }
}

/// A project root, as the path filters see it.
#[derive(Debug, Clone, Copy)]
pub struct Root<'a> {
    /// Repo-relative directory, `/` separators, `""` for the repo root.
    pub rel_dir: &'a str,
    /// The lockfile/manifest files the engine reads for this root,
    /// relative to `rel_dir`.
    pub markers: &'a [String],
    /// Named by the user (never subject to the built-in default ignores).
    pub explicit: bool,
}

/// The effective selection policy of one invocation.
#[derive(Debug, Clone)]
pub struct SelectionPolicy {
    source: PolicySource,
    enabled: bool,
    ignore_discovered: PathMatcher,
    ignore_explicit: PathMatcher,
    include: Option<PathMatcher>,
    ecosystems: Option<Vec<String>>,
    packages: Option<Vec<String>>,
    ignore_packages: Vec<String>,
    min_severity: Option<u8>,
    min_severity_source: SeveritySource,
    max_new_patches: Option<u32>,
}

/// Canonical severity name of an order (`moderate` reads as `medium`).
pub fn severity_name(order: u8) -> Option<&'static str> {
    match order {
        0 => Some("critical"),
        1 => Some("high"),
        2 => Some("medium"),
        3 => Some("low"),
        _ => None,
    }
}

/// Parse a `--min-severity` / `SOCKET_MIN_SEVERITY` value: a severity
/// name, or `none` for no floor.
pub fn parse_min_severity(value: &str) -> Result<Option<u8>, String> {
    if value.trim().eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    socket_yml::parse_severity_name(value)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "invalid severity `{}`: expected critical, high, medium, moderate, low or none",
                sanitize(value)
            )
        })
}

/// The severity the floor judges a patch by: the worst severity across
/// the advisories it fixes (never `RankKey.severity`).
pub fn patch_severity_order(patch: &PatchSearchResult) -> u8 {
    max_severity_order(patch.vulnerabilities.values().map(|v| v.severity.as_str()))
}

fn defaults_list() -> Vec<String> {
    DEFAULT_IGNORE_PATHS.iter().map(|s| s.to_string()).collect()
}

/// Compile a combined list. Each list was validated on its own, but the
/// combination can still exceed the glob engine's size limit; that is an
/// error (fail closed), never an empty matcher.
fn compile(file: &str, lists: &[(&'static str, &[String])]) -> Result<PathMatcher, PolicyError> {
    PathMatcher::new(lists).map_err(|(list, _, message)| PolicyError::Invalid {
        file: file.to_string(),
        key: list.to_string(),
        message: format!("the path patterns cannot be compiled together: {message}"),
    })
}

/// The built-in defaults, compiled once (for callers that only need the
/// default path ignores, e.g. tree-listing root detection).
pub fn builtin_defaults() -> &'static SelectionPolicy {
    static DEFAULTS: std::sync::LazyLock<SelectionPolicy> = std::sync::LazyLock::new(SelectionPolicy::unrestricted);
    &DEFAULTS
}

impl SelectionPolicy {
    /// No file: only the built-in default ignores.
    pub fn unrestricted() -> Self {
        Self::from_parts("", PolicySource::None, &[], &PatchesBlock::default())
            .expect("the built-in default ignores always compile")
    }

    fn from_parts(
        file: &str,
        source: PolicySource,
        project_ignore_paths: &[String],
        block: &PatchesBlock,
    ) -> Result<Self, PolicyError> {
        let defaults = defaults_list();
        let ignore_discovered = compile(
            file,
            &[
                (DEFAULT_IGNORE_LIST, &defaults),
                ("projectIgnorePaths", project_ignore_paths),
                ("patches.ignorePaths", &block.ignore_paths),
            ],
        )?;
        let ignore_explicit = compile(
            file,
            &[
                ("projectIgnorePaths", project_ignore_paths),
                ("patches.ignorePaths", &block.ignore_paths),
            ],
        )?;
        let include = match block.include_paths.as_ref() {
            Some(list) => Some(compile(file, &[("patches.includePaths", list)])?),
            None => None,
        };
        Ok(Self {
            source,
            enabled: block.enabled.unwrap_or(true),
            ignore_discovered,
            ignore_explicit,
            include,
            ecosystems: block.ecosystems.clone(),
            packages: block.packages.clone(),
            ignore_packages: block.ignore_packages.clone(),
            min_severity: block.min_severity,
            min_severity_source: if block.min_severity.is_some() {
                SeveritySource::File
            } else {
                SeveritySource::Default
            },
            max_new_patches: block.max_new_patches,
        })
    }

    fn apply_overrides(&mut self, overrides: &PolicyOverrides) {
        if let Some((value, source)) = overrides.min_severity {
            self.min_severity = value;
            self.min_severity_source = match source {
                OverrideSource::Flag => SeveritySource::Flag,
                OverrideSource::Env => SeveritySource::Env,
            };
        }
    }

    /// Read, validate and combine the repo root's policy files (4.4-4.5).
    pub fn load(
        fs: &dyn PolicyFs,
        overrides: &PolicyOverrides,
    ) -> Result<(Self, Vec<PolicyWarning>), PolicyError> {
        let mut warnings = Vec::new();
        if overrides.bypass {
            let mut policy = Self::unrestricted();
            policy.source = PolicySource::Bypassed;
            policy.apply_overrides(overrides);
            return Ok((policy, warnings));
        }
        for variant in fs.case_variants() {
            warnings.push(PolicyWarning {
                code: SOCKET_YML_NAME_CASE,
                detail: format!(
                    "`{}` is not read: the policy file must be named exactly socket.yml or socket.yaml",
                    sanitize(&variant)
                ),
            });
        }
        let mut files: Vec<(&'static str, Vec<u8>, ParsedFile)> = Vec::new();
        for name in POLICY_FILE_NAMES {
            let invalid = |message: String| PolicyError::Invalid {
                file: name.to_string(),
                key: String::new(),
                message,
            };
            match fs.read_root_file(name, MAX_FILE_BYTES) {
                Ok(RootFile::Absent) => {}
                Ok(RootFile::PresentWithoutContent) => {
                    return Err(invalid(
                        "the file is listed but its content was not provided (symlink, oversize, LFS pointer or binary)"
                            .to_string(),
                    ))
                }
                Ok(RootFile::Present(bytes)) => {
                    if bytes.len() > MAX_FILE_BYTES {
                        return Err(invalid(format!("cannot read the file: larger than {} KiB", MAX_FILE_BYTES / 1024)));
                    }
                    let parsed = parse_file(name, &bytes, &mut warnings)?;
                    files.push((name, bytes, parsed));
                }
                Err(e) => return Err(invalid(format!("cannot read the file: {e}"))),
            }
        }
        if let [(first, _, a), (second, _, b)] = files.as_slice() {
            if !a.same_policy(b) {
                return Err(PolicyError::Ambiguous {
                    files: [first.to_string(), second.to_string()],
                });
            }
        }
        let mut policy = match files.into_iter().next() {
            Some((name, bytes, parsed)) if !parsed.empty => {
                let source = PolicySource::File {
                    path: name.to_string(),
                    sha256: hex::encode(Sha256::digest(&bytes)),
                };
                let block = parsed.patches.clone().unwrap_or_default();
                Self::from_parts(name, source, &parsed.project_ignore_paths, &block)?
            }
            _ => Self::unrestricted(),
        };
        policy.apply_overrides(overrides);
        Ok((policy, warnings))
    }

    pub fn source(&self) -> &PolicySource {
        &self.source
    }

    /// `patches.enabled`. When false nothing is written (report only).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The effective severity floor and its source.
    pub fn min_severity(&self) -> (Option<u8>, SeveritySource) {
        (self.min_severity, self.min_severity_source)
    }

    /// The file's `maxNewPatches`; `None` when there is no file, it was
    /// bypassed, or the key is absent.
    pub fn max_new_patches(&self) -> Option<u32> {
        match self.source {
            PolicySource::File { .. } => self.max_new_patches,
            _ => None,
        }
    }

    /// Path filters for one project root (4.3): ignored iff every marker
    /// is ignored; with `includePaths`, included iff any marker matches.
    pub fn admits_root(&self, root: &Root) -> Result<(), FilterReason> {
        let rel_dir = root.rel_dir.trim_matches('/');
        let subjects: Vec<(String, bool)> = if root.markers.is_empty() {
            vec![(rel_dir.to_string(), true)]
        } else {
            root.markers
                .iter()
                .map(|m| {
                    let m = m.trim_start_matches('/');
                    if rel_dir.is_empty() {
                        (m.to_string(), false)
                    } else {
                        (format!("{rel_dir}/{m}"), false)
                    }
                })
                .collect()
        };
        let ignore = if root.explicit {
            &self.ignore_explicit
        } else {
            &self.ignore_discovered
        };
        let mut first_hit: Option<PathHit> = None;
        let mut all_ignored = true;
        for (path, is_dir) in &subjects {
            match ignore.check(path, *is_dir) {
                Some(hit) => {
                    first_hit.get_or_insert(hit);
                }
                None => {
                    all_ignored = false;
                    break;
                }
            }
        }
        if all_ignored {
            if let Some(hit) = first_hit {
                return Err(FilterReason::PathExcluded {
                    pattern: sanitize(&hit.pattern),
                    list: hit.list,
                });
            }
        }
        if let Some(include) = &self.include {
            if !subjects
                .iter()
                .any(|(path, is_dir)| include.check(path, *is_dir).is_some())
            {
                return Err(FilterReason::PathNotIncluded);
            }
        }
        Ok(())
    }

    /// Ecosystem and package filters for one package (deny wins).
    pub fn admits_purl(&self, purl: &str) -> Result<(), FilterReason> {
        if let Some(ecosystems) = &self.ecosystems {
            let eco = Ecosystem::from_purl(purl).map(|e| e.cli_name());
            if !eco.is_some_and(|e| ecosystems.iter().any(|x| x == e)) {
                return Err(FilterReason::Ecosystem);
            }
        }
        if let Some(spec) = self
            .ignore_packages
            .iter()
            .find(|s| package_spec_matches(s, purl))
        {
            return Err(FilterReason::PackageIgnored {
                spec: sanitize(spec),
            });
        }
        if let Some(packages) = &self.packages {
            if !packages.iter().any(|s| package_spec_matches(s, purl)) {
                return Err(FilterReason::PackageNotListed);
            }
        }
        Ok(())
    }

    /// The severity floor for one patch (`severity_order` ranks, unknown
    /// = 4 is filtered whenever a floor is set).
    pub fn admits_severity(&self, severity_order: u8) -> Result<(), FilterReason> {
        let Some(floor) = self.min_severity else {
            return Ok(());
        };
        if severity_order <= floor && severity_name(severity_order).is_some() {
            return Ok(());
        }
        Err(FilterReason::Severity {
            found: severity_name(severity_order).map(str::to_string),
            floor: severity_name(floor).unwrap_or("unknown").to_string(),
        })
    }

    /// Split offers by the severity floor, keeping order.
    pub fn floor_filter(
        &self,
        offers: Vec<PatchSearchResult>,
    ) -> (
        Vec<PatchSearchResult>,
        Vec<(PatchSearchResult, FilterReason)>,
    ) {
        let mut admitted = Vec::with_capacity(offers.len());
        let mut filtered = Vec::new();
        for offer in offers {
            match self.admits_severity(patch_severity_order(&offer)) {
                Ok(()) => admitted.push(offer),
                Err(reason) => filtered.push((offer, reason)),
            }
        }
        (admitted, filtered)
    }
}

/// The step 5 → 7 seam: every offer per purl (after the tier filter) and
/// the winner among the floor-admitted ones.
#[derive(Debug, Clone, Default)]
pub struct Offers {
    pub unfiltered: BTreeMap<String, Vec<PatchSearchResult>>,
    pub selected: BTreeMap<String, PatchSearchResult>,
}

/// Whether a `--package` spec names the package at `purl`: a purl spec
/// matches the same purl, or any version of it when it carries none; a
/// bare spec matches the package's full name (`@scope/pkg`, `group/name`)
/// or its last segment. Qualifiers are ignored and names compare
/// case-insensitively (PyPI, NuGet and Composer names are case-insensitive;
/// npm forbids uppercase).
pub fn package_spec_matches(spec: &str, purl: &str) -> bool {
    // Versioned Composer specs name a release, including its pretty/padded
    // spellings. Compare before lowercasing: dev branch names retain case.
    if crate::utils::composer_version::composer_purl_identity(spec.trim()).is_some() {
        return crate::utils::composer_version::composer_purls_equivalent(spec.trim(), purl);
    }
    let decoded = normalize_purl(strip_purl_qualifiers(purl)).to_lowercase();
    let spec = spec.trim().to_lowercase();
    if spec.is_empty() {
        return false;
    }
    let Some(rest) = decoded.strip_prefix("pkg:") else {
        return false;
    };
    let Some((_eco, name_version)) = rest.split_once('/') else {
        return false;
    };
    let name = match name_version.rfind('@').filter(|&i| i > 0) {
        Some(at) => &name_version[..at],
        None => name_version,
    };
    if let Some(spec_rest) = spec.strip_prefix("pkg:") {
        let spec_purl =
            normalize_purl(strip_purl_qualifiers(&format!("pkg:{spec_rest}"))).to_lowercase();
        let spec_rest = &spec_purl[4..];
        let has_version = spec_rest
            .split_once('/')
            .is_some_and(|(_, nv)| nv.rfind('@').is_some_and(|i| i > 0));
        return if has_version {
            decoded == spec_purl
        } else {
            decoded
                .strip_prefix(&spec_purl)
                .is_some_and(|tail| tail.starts_with('@'))
        };
    }
    let spec = spec.replace(':', "/");
    name == spec || name.rsplit('/').next() == Some(spec.as_str())
}

fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
}

fn ceiling_dirs() -> Vec<PathBuf> {
    std::env::var_os("GIT_CEILING_DIRECTORIES")
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn trusted_owner(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|v| v.trim().parse::<u32>().ok());
    // SAFETY: geteuid has no preconditions and cannot fail.
    owner_trusted(meta.uid(), unsafe { libc::geteuid() }, sudo_uid)
}

/// `.git` is trusted when it belongs to the invoking user, to root, or
/// (under sudo) to the user sudo ran for. Root trusts every owner: a root
/// process is exposed to the whole filesystem anyway, and CI containers
/// commonly run as root over a checkout owned by another uid, where
/// distrust would silently drop the repo's policy (which only narrows).
#[cfg(unix)]
fn owner_trusted(owner: u32, euid: u32, sudo_uid: Option<u32>) -> bool {
    euid == 0 || owner == euid || owner == 0 || sudo_uid == Some(owner)
}

#[cfg(not(unix))]
fn trusted_owner(_meta: &std::fs::Metadata) -> bool {
    true
}

/// The repo root for `cwd` (4.5) with the lookup's warnings: the nearest
/// ancestor (inclusive) holding a `.git` directory or file, not walking
/// past `GIT_CEILING_DIRECTORIES` or into the home directory, and (Unix)
/// only when `.git` belongs to a trusted owner ([`owner_trusted`]).
/// Otherwise `cwd`.
pub fn find_repo_root_with_warnings(cwd: &Path) -> (PathBuf, Vec<PolicyWarning>) {
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let ceilings = ceiling_dirs();
    let home = home_dir();
    let mut warnings = Vec::new();
    let mut dir: &Path = &cwd;
    loop {
        if dir != cwd && home.as_deref() == Some(dir) {
            break;
        }
        // `metadata` follows a `.git` symlink, as git does.
        if let Ok(meta) = std::fs::metadata(dir.join(".git")) {
            if meta.is_dir() || meta.is_file() {
                if trusted_owner(&meta) {
                    return (dir.to_path_buf(), warnings);
                }
                warnings.push(PolicyWarning {
                    code: SOCKET_YML_REPO_UNTRUSTED,
                    detail: format!(
                        "{} is owned by another user; using {} as the repository root",
                        dir.join(".git").display(),
                        cwd.display()
                    ),
                });
                break;
            }
        }
        let Some(parent) = dir.parent() else { break };
        if ceilings.iter().any(|c| c == parent) {
            break;
        }
        dir = parent;
    }
    (cwd.clone(), warnings)
}

/// [`find_repo_root_with_warnings`] without the warnings.
pub fn find_repo_root(cwd: &Path) -> PathBuf {
    find_repo_root_with_warnings(cwd).0
}

/// `dir` relative to `repo_root` with `/` separators (`""` for the root
/// itself); `None` when `dir` is not inside it.
pub fn repo_relative_checked(repo_root: &Path, dir: &Path) -> Option<String> {
    let rel = dir.strip_prefix(repo_root).ok()?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// [`repo_relative_checked`], falling back to `dir` itself (with `/`
/// separators) when it is outside the root.
pub fn repo_relative(repo_root: &Path, dir: &Path) -> String {
    repo_relative_checked(repo_root, dir)
        .unwrap_or_else(|| dir.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests;
