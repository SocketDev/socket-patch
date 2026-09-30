use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::FileType;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};
use super::walk_pool::{par_map, run_walk};
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_dir_sync, read_dir_entries_sync};
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};
use crate::vendor::vlt_lock_text::decode_vlt_dep_id;

#[cfg(test)]
mod oracle;

/// Directories to skip when searching for workspace node_modules.
const SKIP_DIRS: &[&str] = &[
    "dist",
    "build",
    "coverage",
    "tmp",
    "temp",
    "__pycache__",
    "vendor",
];

// ---------------------------------------------------------------------------
// Helper: read and parse package.json
// ---------------------------------------------------------------------------

/// Minimal fields we need from package.json.
#[derive(Deserialize)]
struct PackageJsonPartial {
    name: Option<String>,
    version: Option<String>,
}

/// Read and parse a `package.json` file, returning `(name, version)` if valid.
pub async fn read_package_json(pkg_json_path: &Path) -> Option<(String, String)> {
    // The path lives inside the (untrusted) package tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for a
    // writer, wedging scan (crawl_all) and apply (find_by_purls). Read via
    // `read_regular_to_string` — non-blocking open on Unix, rejecting
    // FIFOs/devices/directories (see its docs).
    let content = crate::utils::fs::read_regular_to_string(pkg_json_path)
        .await
        .ok()?;
    parse_package_json_identity(&content)
}

/// Blocking twin of [`read_package_json`] for the walks that run whole on
/// the blocking pool: the same FIFO-safe `read_regular_to_string_sync`
/// open and the same parse.
fn read_package_json_sync(pkg_json_path: &Path) -> Option<(String, String)> {
    let content = crate::utils::fs::read_regular_to_string_sync(pkg_json_path).ok()?;
    parse_package_json_identity(&content)
}

/// `(name, version)` from package.json text, if both are present and
/// non-empty.
fn parse_package_json_identity(content: &str) -> Option<(String, String)> {
    // npm and Node both tolerate a leading UTF-8 BOM in package.json
    // (Windows-authored packages ship them), but serde_json rejects it —
    // a BOM'd install would be invisible to scan and unpatchable.
    let pkg: PackageJsonPartial =
        serde_json::from_str(crate::package_json::detect::strip_bom(content)).ok()?;
    let name = pkg.name?;
    let version = pkg.version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

// ---------------------------------------------------------------------------
// Helper: parse package name into (namespace, name)
// ---------------------------------------------------------------------------

/// Parse a full npm package name into optional namespace and bare name.
///
/// Examples:
/// - `"@types/node"` -> `(Some("@types"), "node")`
/// - `"lodash"` -> `(None, "lodash")`
pub fn parse_package_name(full_name: &str) -> (Option<String>, String) {
    if full_name.starts_with('@') {
        if let Some(slash_idx) = full_name.find('/') {
            let namespace = full_name[..slash_idx].to_string();
            let name = full_name[slash_idx + 1..].to_string();
            return (Some(namespace), name);
        }
    }
    (None, full_name.to_string())
}

// ---------------------------------------------------------------------------
// Helper: build PURL
// ---------------------------------------------------------------------------

/// Build a PURL string for an npm package.
pub fn build_npm_purl(namespace: Option<&str>, name: &str, version: &str) -> String {
    match namespace {
        Some(ns) => format!("pkg:npm/{ns}/{name}@{version}"),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

// ---------------------------------------------------------------------------
// Helper: decode a pnpm virtual-store entry directory name
// ---------------------------------------------------------------------------

/// Decode a `.pnpm` virtual-store entry directory name into the
/// `(package_name, version)` it advertises.
///
/// Store entry names follow `<escaped-name>@<version><suffix>` where:
/// - a scoped name's `/` is written as `+` (`@scope+leaf@2.0.0`),
/// - pnpm 9+ appends peer/qualifier suffixes in parentheses
///   (`foo@1.0.0(bar@2.0.0)(@babel+core@7.21.0)`),
/// - pnpm 6–8 appended peer suffixes after `_` (`foo@1.0.0_bar@2.0.0`),
/// - over-long names are truncated (the cut can land ANYWHERE, even
///   mid-name or mid-version) and end in `_<hash>`.
///
/// Returns `None` for anything that does not cleanly parse as
/// `name@X.Y.Z…`: store metadata files (`lock.yaml`), git/URL dependency
/// entries (`foo@github.com+user+repo@<sha>` — a sha is not a semver
/// triple), truncated long-name dirs, and names containing a literal `_`
/// (indistinguishable from a legacy peer suffix). Callers MUST treat
/// `None` as "identity unknowable from the dir name", not "no package
/// here", and keep such entries probeable/scannable. A `Some` can still
/// be a truncation artifact (a cut that happens to land after a
/// `name@X.Y.Z` prefix is undetectable), so the decoded pair is
/// advisory: resolution authority stays with the package.json probe.
pub fn decode_pnpm_store_entry_name(entry_name: &str) -> Option<(String, String)> {
    // pnpm 9+ peer/qualifier suffix: everything from the first `(`.
    let base = &entry_name[..entry_name.find('(').unwrap_or(entry_name.len())];
    // Legacy (pnpm 6–8) `_` peer suffix, doubling as the long-name
    // truncation hash separator. Real package names may contain `_` too
    // — those then fail the version parse below and fall to the
    // conservative `None` path, which is the safe direction.
    let base = &base[..base.find('_').unwrap_or(base.len())];

    let at = base.rfind('@')?;
    // `at == 0` would leave an empty name (`@1.0.0`).
    if at == 0 {
        return None;
    }
    let version = &base[at + 1..];
    if !is_semver_triple(version) {
        return None;
    }
    // Scope escaping: `/` in the (possibly scoped) name is written `+`.
    // `+` cannot appear in a real npm name, so a bare replace is exact.
    let name = base[..at].replace('+', "/");
    Some((name, version.to_string()))
}

/// Whether `v` starts with a numeric `MAJOR.MINOR.PATCH` triple
/// (pre-release/build tails allowed). Registry versions — the only kind
/// pnpm writes into decodable store entry names — always do; git shas
/// and URL fragments never do, so requiring the triple keeps those
/// entries on `decode_pnpm_store_entry_name`'s conservative `None` path.
fn is_semver_triple(v: &str) -> bool {
    let mut parts = v.splitn(3, '.');
    let (Some(major), Some(minor), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let patch = &rest[..rest.find(['-', '+']).unwrap_or(rest.len())];
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    all_digits(major) && all_digits(minor) && all_digits(patch)
}

// ---------------------------------------------------------------------------
// Helpers: pnpm virtual-store layout knowledge
// ---------------------------------------------------------------------------

/// Maximum directory depth probed below a *nested* virtual-store host dir.
/// pnpm 4/5 (layoutVersion 3) nest store entries by registry host —
/// `.pnpm/<registry-host>/<name>/<version>/node_modules/<name>` — and
/// pnpm <=3 (layoutVersion <=2) use the same shape directly under a hidden
/// `node_modules/.<registry-host>` dir (both confirmed against captured
/// real installs). Relative to the host dir the deepest package home is
/// `@scope/<name>/<version>` — three levels.
const NESTED_STORE_MAX_DEPTH: usize = 3;

/// Upper bound on directories visited while descending one nested-store
/// host, so a corrupted (or adversarial) tree cannot turn the bounded
/// descent into an unbounded readdir storm. A real store holds one dir per
/// scope/name and one per version — orders of magnitude below this.
/// Hitting the cap can only make the walk miss packages (fail toward "not
/// installed", the same answer the pre-descent code gave for every nested
/// entry), never patch the wrong one: the package.json probe stays the
/// authority.
const NESTED_STORE_MAX_DIRS: usize = 16_384;

/// Whether a hidden `node_modules` child is a pnpm <=3 virtual store.
/// Before the `.pnpm` dir existed (layoutVersion <=2: pnpm 1/2/3) the
/// store lived at `node_modules/.<registry-host>` — `.registry.npmjs.org`
/// for the default registry (confirmed byte-for-byte in captured pnpm
/// 1.x/2.x/3.8 trees, whose `.modules.yaml` names
/// `registries.default: https://registry.npmjs.org/`). Matching the
/// `.registry.` prefix also covers other `registry.*` hosts while never
/// mistaking unrelated hidden dirs (`.bin`, `.cache`, `.git`) for a store;
/// a custom registry on a host not starting with `registry.` would need
/// its own entry here — deliberately NOT "any hidden dir", which would
/// walk arbitrary tool caches.
fn is_legacy_pnpm_store_dir_name(name: &str) -> bool {
    name.starts_with(".registry.")
}

/// The `node_modules` child that is vlt's per-project package store.
const VLT_STORE_NAME: &str = ".vlt";

/// The `node_modules` child that is npm's `install-strategy=linked` store.
const NPM_LINKED_STORE_NAME: &str = ".store";

/// Length of the hash suffix npm's linked strategy appends to a store key:
/// the base64url of a 16-byte shake256 digest, unpadded (arborist's
/// `isolated-reifier.js` `getKey`).
const NPM_STORE_KEY_HASH_LEN: usize = 22;

/// Decode an npm linked-store key (`<name>@<version>-<hash>`, scoped
/// `@scope/<leaf>@<version>-<hash>`) into the `(package_name, version)` it
/// advertises. The hash is base64url, so it may itself hold `-`/`_`: it
/// is cut by its fixed length, never by searching for a separator.
///
/// `None` for anything else, e.g. the un-hashed `<name>@<version>` dir
/// npm extracts a shrinkwrapped dependency into, or a non-semver version.
/// Like the pnpm decoder the result is advisory: the package.json probe
/// stays the authority, and `None` means "unknowable", never "empty".
fn decode_npm_store_entry_name(entry_name: &str) -> Option<(String, String)> {
    let cut = entry_name.len().checked_sub(NPM_STORE_KEY_HASH_LEN + 1)?;
    let (key, hash) = (entry_name.get(..cut)?, entry_name.get(cut..)?);
    let hash = hash.strip_prefix('-')?;
    if !hash
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let at = key.rfind('@')?;
    if at == 0 || key[..at].ends_with('/') {
        return None;
    }
    let version = &key[at + 1..];
    if !is_semver_triple(version) {
        return None;
    }
    Some((key[..at].to_string(), version.to_string()))
}

/// The `node_modules` child in which pnpm records its install state,
/// including where the virtual store lives.
const PNPM_MODULES_YAML: &str = ".modules.yaml";

/// The `virtualStoreDir` value of a `.modules.yaml`: JSON on pnpm 10+,
/// YAML before (a top-level `virtualStoreDir:` scalar, maybe quoted).
fn parse_modules_yaml_virtual_store_dir(text: &str) -> Option<String> {
    let text = crate::package_json::detect::strip_bom(text);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return value
            .get("virtualStoreDir")?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    let raw = text
        .lines()
        .find_map(|line| line.strip_prefix("virtualStoreDir:"))?
        .trim();
    let value = if raw.starts_with('"') {
        serde_json::from_str::<String>(raw).ok()?
    } else if let Some(inner) = raw.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        inner.replace("''", "'")
    } else {
        raw.to_string()
    };
    (!value.is_empty()).then_some(value)
}

/// `path` with `.` and `..` resolved lexically (no filesystem access), so
/// a recorded `../.vstore` joins to the same spelling the walks use.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push(component);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// `store` relative to `importer`, when it names a directory strictly
/// below it by plain child names only. A bare `strip_prefix` is not
/// enough: the CLI's default `--cwd .` makes the importer the empty path,
/// which is a prefix of everything, including an absolute store (`/…`,
/// `C:\…`) or one that climbs out (`../…`).
fn path_below(importer: &Path, store: &Path) -> Option<PathBuf> {
    let below = store.strip_prefix(importer).ok()?;
    let plain = below
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    (plain && !below.as_os_str().is_empty()).then(|| below.to_path_buf())
}

/// A pnpm virtual store that `node_modules/.modules.yaml` relocates away
/// from the default `node_modules/.pnpm` (pnpm's `virtualStoreDir`
/// setting, stored relative to `node_modules`, or absolute on old pnpm).
///
/// Only a store INSIDE the importer (the directory holding `nm`) counts,
/// reached through real directories only. Anything else, notably pnpm's
/// global virtual store (`<store-dir>/v10/links`), is shared by other
/// projects on the machine: patching it would patch them too, so agent
/// mode leaves it alone. `None` also for the default location, which the
/// walks already handle by name.
fn relocated_pnpm_virtual_store_sync(nm: &Path) -> Option<PathBuf> {
    let text = crate::utils::fs::read_regular_to_string_sync(&nm.join(PNPM_MODULES_YAML)).ok()?;
    let recorded = parse_modules_yaml_virtual_store_dir(&text)?;
    let importer = normalize_lexically(nm.parent()?);
    let store = normalize_lexically(&nm.join(recorded));
    if store == normalize_lexically(&nm.join(".pnpm")) || store == normalize_lexically(nm) {
        return None;
    }
    let below = path_below(&importer, &store)?;
    let mut dir = importer;
    for component in below.components() {
        dir.push(component);
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            return None;
        }
    }
    Some(dir)
}

/// `(name, version)` a `.vlt/<DepID>` entry name advertises: the vlt store
/// decoder over the lossless name, `None` for git/file/remote/workspace
/// ids and for anything undecodable (which stays probeable). The pnpm
/// decoder must never see these names: it reads `··foo@1.0.0` as a package
/// named `··foo`, so the pending-name filter would skip the real `foo`.
fn decode_vlt_store_entry_name(entry_name: &OsStr) -> Option<(String, String)> {
    entry_name.to_str().and_then(decode_vlt_dep_id)
}

/// One virtual-store entry (pnpm or vlt): the `node_modules` holding its
/// package, and the `(name, version)` its dir name advertises. The
/// advertisement is advisory (the package.json probe is the authority), and
/// `None` means "unknowable from the name", never "empty".
struct StoreEntry {
    advertised: Option<(String, String)>,
    node_modules: PathBuf,
}

impl StoreEntry {
    fn pnpm(entries: Vec<(String, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_pnpm_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }

    fn npm(entries: Vec<(String, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_npm_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }

    fn vlt(entries: Vec<(OsString, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_vlt_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Blocking-pool walk primitives
// ---------------------------------------------------------------------------

/// One entry of a directory listing read on the blocking pool.
struct ListedEntry {
    /// The raw name — what the walks join wherever they always joined the
    /// `OsString`.
    name: OsString,
    /// The lossy UTF-8 spelling every name test (and the joins that always
    /// used it) goes through.
    name_str: String,
    /// The entry's own, symlink-unaware kind; `None` when that stat failed,
    /// which every walk treats as "skip this entry".
    file_type: Option<FileType>,
}

/// A directory listing plus whether it is known complete (see
/// [`read_dir_entries_sync`]). A directory that cannot be opened lists as
/// empty and incomplete.
#[derive(Default)]
struct Listing {
    entries: Vec<ListedEntry>,
    complete: bool,
}

impl Listing {
    fn from_entries(entries: Vec<std::fs::DirEntry>, complete: bool) -> Self {
        let entries = entries
            .into_iter()
            .map(|entry| {
                let name = entry.file_name();
                ListedEntry {
                    name_str: name.to_string_lossy().into_owned(),
                    file_type: entry.file_type().ok(),
                    name,
                }
            })
            .collect();
        Self { entries, complete }
    }
}

/// The file a [Cache Directory Tagging](https://bford.info/cachedir/)
/// cache directory carries, and the signature it must begin with.
const CACHEDIR_TAG: &str = "CACHEDIR.TAG";
const CACHEDIR_TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Whether `dir` (whose `listing` the walk already holds) is a tagged cache
/// directory: its listing names a regular `CACHEDIR.TAG` that begins with
/// the standard signature. Only a dir whose listing carries the name costs
/// a read; the name alone is not enough (the specification asks readers to
/// check the signature, so an unrelated file of that name prunes nothing).
fn is_tagged_cache_dir(dir: &Path, listing: &Listing) -> bool {
    let tagged = listing
        .entries
        .iter()
        .any(|e| e.name_str == CACHEDIR_TAG && e.file_type.is_some_and(|t| t.is_file()));
    if !tagged {
        return false;
    }
    // FIFO-safe open (a FIFO planted under the name must not wedge the
    // walk), and only the signature's bytes are read.
    let mut head = [0u8; CACHEDIR_TAG_SIGNATURE.len()];
    crate::utils::fs::open_regular_file_sync(&dir.join(CACHEDIR_TAG))
        .and_then(|(mut f, _)| std::io::Read::read_exact(&mut f, &mut head))
        .is_ok_and(|()| head == CACHEDIR_TAG_SIGNATURE)
}

/// List `path` (empty when it cannot be read — the walks' long-standing
/// tolerate-and-skip contract).
fn list_dir_sync(path: &Path) -> Listing {
    match read_dir_entries_sync(path) {
        Some((entries, complete)) => Listing::from_entries(entries, complete),
        None => Listing::default(),
    }
}

/// Whether `dir/node_modules` is a directory, following symlinks — the
/// workspace roots walk's `is_dir` probe — skipping the stat when `dir`'s
/// own listing (which the walk reads anyway) already proves the answer is
/// no: the listing is complete and holds no entry that could be
/// `node_modules`, even on a case-insensitive filesystem (APFS, NTFS; see
/// [`may_alias_ascii_name`]). The stat then could only have failed.
///
/// Every other case stats, including a listed real-directory
/// `node_modules`: a directory readable but not searchable (mode `r--`)
/// lists its entries' kinds while a stat through it still fails, so a
/// positive answer is never taken from the listing. Only the negative
/// case is common (most walked dirs have no `node_modules`).
fn has_node_modules_dir(dir: &Path, listing: &Listing) -> bool {
    if listing.complete
        && !listing
            .entries
            .iter()
            .any(|e| may_alias_ascii_name(&e.name, "node_modules"))
    {
        return false;
    }
    is_dir_sync(&dir.join("node_modules"))
}

/// Whether a directory entry called `name` could be what a lookup of the
/// plain-ASCII `target` resolves to on a case-insensitive filesystem: an
/// ASCII-case-insensitive match — or, conservatively, any name that is not
/// plain ASCII (Unicode case folding and normalization can map non-ASCII
/// spellings such as `ſ` or the Kelvin sign onto ASCII letters) or not
/// UTF-8 at all.
fn may_alias_ascii_name(name: &OsStr, target: &str) -> bool {
    match name.to_str() {
        Some(name) if name.is_ascii() => name.eq_ignore_ascii_case(target),
        _ => true,
    }
}

/// Which first path components a `nm_path.join(dir_key)` lookup could
/// resolve through, given `nm_path`'s listing — lets the resolver skip the
/// package.json probes that could only fail, instead of opening
/// `<nm>/<target>/package.json` for every pending target in every visited
/// `node_modules`.
///
/// A superset by construction: filtering is on only for a complete listing
/// whose names are all plain ASCII, and then matches
/// ASCII-case-insensitively (so APFS/NTFS case-insensitive lookups are
/// covered). Components a filesystem may resolve to a differently spelled
/// entry — non-ASCII (Unicode folding / normalization), `~` (Windows 8.3
/// short-name aliases) or a trailing `.`/space (stripped by Win32 path
/// normalization) — are always probed.
struct ProbeFilter {
    /// `None` = the listing cannot prove absence; probe everything.
    lower_names: Option<HashSet<String>>,
}

impl ProbeFilter {
    fn new(listing: &Listing) -> Self {
        let exhaustive = listing.complete
            && listing
                .entries
                .iter()
                .all(|e| e.name.to_str().is_some_and(|name| name.is_ascii()));
        let lower_names = exhaustive.then(|| {
            listing
                .entries
                .iter()
                .map(|e| e.name_str.to_ascii_lowercase())
                .collect()
        });
        Self { lower_names }
    }

    fn may_resolve(&self, component: &str) -> bool {
        let Some(lower_names) = &self.lower_names else {
            return true;
        };
        if !component.is_ascii() || component.contains('~') || component.ends_with(['.', ' ']) {
            return true;
        }
        lower_names.contains(&component.to_ascii_lowercase())
    }
}

/// The read-only result of one `find_by_purls` resolver visit (see
/// [`NpmCrawler::visit_resolver_dir`]). `matched` indexes the pending
/// targets this dir holds a copy of, in target order — sparse, because
/// every dir of a BFS level carries one of these at once.
struct ResolverVisit {
    nm_path: PathBuf,
    /// `nm_path` is a pnpm or vlt store entry's `node_modules`.
    store_entry: bool,
    matched: Vec<usize>,
    nested: Vec<NestedNodeModules>,
}

/// One contribution to the resolver's next BFS level: a nested importer
/// `node_modules`, or a virtual store's entries, still to be narrowed by
/// the pending-name filter when the visit is replayed.
enum NestedNodeModules {
    Dir(PathBuf),
    StoreEntries(Vec<StoreEntry>),
}

/// What the blocking-pool scan of one `node_modules` tree records, in the
/// exact order the sequential walk visits it;
/// [`NpmCrawler::merge_scan_events`] then replays the order-dependent
/// `seen` dedup single-threaded.
enum ScanEvent {
    /// A `check_package` candidate: the package dir, its package.json
    /// identity (`None` = unreadable/invalid), and — for a direct child of
    /// a virtual-store entry's `node_modules` only — the dir's package key
    /// (`name` or `@scope/name`), which the entry's `identity_seen` skip
    /// compares against.
    Package {
        path: PathBuf,
        identity: Option<(String, String)>,
        entry_key: Option<String>,
    },
    /// One virtual-store entry: its dir name decoded, and the events of its
    /// `node_modules` walked under the store-entry policy.
    StoreEntry {
        decoded: Option<(String, String)>,
        events: Vec<ScanEvent>,
    },
}

/// A virtual-store entry found by
/// [`NpmCrawler::list_pnpm_store_entries_sync`] or
/// [`NpmCrawler::vlt_store_entry_dirs`]: its flat (or synthesized nested)
/// name, what that name advertises under its store layout, its
/// `node_modules`, and — when the caller asked for listings and the dir
/// opened — that `node_modules`' listing.
struct StoreEntryDir {
    name: String,
    advertised: Option<(String, String)>,
    node_modules: PathBuf,
    listing: Option<Listing>,
}

// ---------------------------------------------------------------------------
// Global prefix detection helpers
// ---------------------------------------------------------------------------

use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// Get the npm global `node_modules` path via `npm root -g`.
pub fn get_npm_global_prefix() -> Result<String, String> {
    get_npm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_npm_global_prefix` that accepts an injected
/// `CommandRunner`. Tests use this with a `MockCommandRunner` to
/// exercise the success arm (binary present, stdout parsed) without
/// requiring npm on the host's PATH.
pub fn get_npm_global_prefix_with(runner: &dyn CommandRunner) -> Result<String, String> {
    parse_npm_root_output(runner.run("npm", &["root", "-g"]).as_deref().unwrap_or("")).ok_or_else(
        || {
            "Failed to determine npm global prefix. Ensure npm is installed and in PATH."
                .to_string()
        },
    )
}

/// Pure parser for `npm root -g` stdout. Returns the trimmed path or
/// `None` on empty input. Extracted so the helper logic is unit-
/// testable without shelling out.
pub fn parse_npm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Get the yarn global `node_modules` path via `yarn global dir`.
pub fn get_yarn_global_prefix() -> Option<String> {
    get_yarn_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_yarn_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_yarn_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_yarn_dir_output(
        runner
            .run("yarn", &["global", "dir"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `yarn global dir` stdout. Returns `<dir>/node_modules`
/// or `None` on empty input. Extracted so the path-derivation logic is
/// unit-testable without shelling out.
pub fn parse_yarn_dir_output(stdout: &str) -> Option<String> {
    let dir = stdout.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(dir)
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

/// Get the pnpm global `node_modules` path via `pnpm root -g`.
pub fn get_pnpm_global_prefix() -> Option<String> {
    get_pnpm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_pnpm_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_pnpm_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_pnpm_root_output(runner.run("pnpm", &["root", "-g"]).as_deref().unwrap_or(""))
}

/// Pure parser for `pnpm root -g` stdout. Returns the trimmed path or
/// `None` on empty input.
pub fn parse_pnpm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(path)
}

/// Get the bun global `node_modules` path via `bun pm bin -g`.
pub fn get_bun_global_prefix() -> Option<String> {
    get_bun_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_bun_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_bun_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_bun_bin_output(
        runner
            .run("bun", &["pm", "bin", "-g"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `bun pm bin -g` stdout. Extracted so the
/// derive-the-global-node_modules-path logic is unit-testable
/// without shelling out.
///
/// Given output like `"/Users/foo/.bun/bin\n"` returns
/// `Some("/Users/foo/.bun/install/global/node_modules")`. Returns
/// `None` on empty input or a root-only path with no parent.
pub fn parse_bun_bin_output(stdout: &str) -> Option<String> {
    let bin_path = stdout.trim().to_string();
    if bin_path.is_empty() {
        return None;
    }

    let bun_root = PathBuf::from(&bin_path);
    let bun_root = bun_root.parent()?;
    Some(
        bun_root
            .join("install")
            .join("global")
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Helpers: synchronous wildcard directory resolver
// ---------------------------------------------------------------------------

/// Resolve a path with `"*"` wildcard segments synchronously.
///
/// Each segment is either a literal directory name or `"*"` which matches any
/// directory entry. Symlinks are followed via `std::fs::metadata`.
///
/// Production callers live inside `#[cfg(target_os = "macos")]` blocks of
/// `get_global_node_modules_paths` (Homebrew/nvm/volta/fnm fallbacks).
/// `#[allow(dead_code)]` keeps the function visible to the inline
/// `#[cfg(test)] mod tests` callers on every target without tripping
/// `-D dead_code` on non-macOS clippy runs.
#[allow(dead_code)]
fn find_node_dirs_sync(base: &Path, segments: &[&str]) -> Vec<PathBuf> {
    if !base.is_dir() {
        return Vec::new();
    }
    if segments.is_empty() {
        return vec![base.to_path_buf()];
    }

    let first = segments[0];
    let rest = &segments[1..];

    if first == "*" {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                // Follow symlinks: `DirEntry::metadata()` does NOT traverse
                // symlinks (it stats the link itself), so a symlinked version
                // dir — fnm's per-version layout, nvm `default`/`current`
                // aliases — would be missed. Stat the joined path with the
                // free `std::fs::metadata`, which resolves the link target.
                let child = base.join(entry.file_name());
                let is_dir = std::fs::metadata(&child)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    results.extend(find_node_dirs_sync(&child, rest));
                }
            }
        }
        results
    } else {
        find_node_dirs_sync(&base.join(first), rest)
    }
}

// ---------------------------------------------------------------------------
// NpmCrawler
// ---------------------------------------------------------------------------

/// NPM ecosystem crawler for discovering packages in `node_modules`.
pub struct NpmCrawler;

/// One still-unresolved `find_by_purls` lookup.
///
/// `purl` is the *verbatim* caller-supplied PURL, including any
/// `?qualifiers`. The result map is keyed by this exact string: the
/// dispatcher drives npm with `passthrough_purls` + `merge_first_wins`,
/// so it looks results back up under the PURL it handed in. Keying by a
/// reconstructed/stripped PURL silently loses every qualified PURL
/// (e.g. `pkg:npm/foo@1.0.0?vcs_url=...`).
struct Target {
    namespace: Option<String>,
    name: String,
    version: String,
    purl: String,
    /// Install dir relative to a `node_modules` root
    /// (`@scope/name` or `name`) — which is also exactly what the
    /// package.json `name` field must say for this dir to BE that
    /// package.
    dir_key: String,
}

impl NpmCrawler {
    /// Create a new `NpmCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get `node_modules` paths based on options.
    ///
    /// In global mode returns well-known global paths; in local mode walks
    /// the project tree looking for `node_modules` directories (including
    /// workspace packages).
    pub async fn get_node_modules_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        let options = options.clone();
        Ok(run_walk(move || Self::node_modules_paths_sync(&options)).await)
    }

    /// Crawl all discovered `node_modules` and return every package found.
    ///
    /// The whole walk runs as ONE task on the walk pool (instead of one
    /// `spawn_blocking` round trip per readdir/stat/read; see
    /// [`super::walk_pool`]): directory I/O is
    /// gathered in parallel into per-root [`ScanEvent`] trees that record
    /// the sequential visit order, then [`Self::merge_scan_events`] replays
    /// them single-threaded so the order-dependent `seen` dedup (and the
    /// store entries' `identity_seen` decisions) see exactly the state the
    /// sequential walk would have — same packages, same paths, same order.
    ///
    /// Buffering costs memory the sequential walk did not pay: every root's
    /// events are resident before the merge starts, so peak memory scales
    /// with dirs VISITED (duplicates included) rather than with the unique
    /// packages that survive the dedup — about +18% on a depscan-sized
    /// tree. Merging each root as its gather finishes would barely help,
    /// because the tree is one root: 5,080 of depscan's 5,520 packages
    /// live in the root's virtual store, so the largest root's events —
    /// which no per-root scheme shrinks — are the peak. The resolver's
    /// per-level buffering is the one that grew without bound, and that is
    /// [`Self::visit_resolver_dir`]'s to keep sparse.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        self.crawl_all_with_roots(options).await.0
    }

    /// [`Self::crawl_all`], also handing back the `node_modules` roots it
    /// walked — exactly what [`Self::get_node_modules_paths`] returns for
    /// the same options and tree — so a caller that resolves purls against
    /// the same untouched tree later in the process can skip rediscovering
    /// them.
    pub async fn crawl_all_with_roots(
        &self,
        options: &CrawlerOptions,
    ) -> (Vec<CrawledPackage>, Vec<PathBuf>) {
        let options = options.clone();
        run_walk(move || Self::crawl_all_sync(&options)).await
    }

    fn crawl_all_sync(options: &CrawlerOptions) -> (Vec<CrawledPackage>, Vec<PathBuf>) {
        let nm_paths = Self::node_modules_paths_sync(options);
        let gathered: Vec<Vec<ScanEvent>> = par_map(&nm_paths, |nm_path| {
            Self::gather_node_modules(nm_path, None, false)
        });

        let mut packages = Vec::new();
        let mut seen = HashSet::new();
        for events in gathered {
            Self::merge_scan_events(events, None, &mut seen, &mut packages);
        }
        (packages, nm_paths)
    }

    /// Find specific packages by PURL inside a single `node_modules` tree.
    ///
    /// Returns **every** physical copy of each PURL, keyed by the verbatim
    /// input PURL. npm genuinely materializes more than one on-disk copy of
    /// a single `name@version` — a nested duplicate (npm 2's always-nested
    /// layout), a diamond dependency that cannot hoist past a conflicting
    /// top slot, or a `file:` dup — and a security tool MUST patch (and
    /// later restore) all of them: patching only one leaves a live,
    /// vulnerable copy while reporting success (a silent partial). The
    /// per-PURL `Vec` is ordered root-copy-first (breadth-first), so callers
    /// that only need one representative (`vendor`, `vex`, `setup`) can take
    /// the first and preserve the old root-preference.
    ///
    /// pnpm's and vlt's store peer-variant copies are deliberately NOT
    /// enumerated here for a copy already found in an importer tree (a
    /// symlinked direct dep): those are handled by the apply engine's
    /// [`find_store_peer_variant_copies`] fan-out. A transitive-only package
    /// that lives ONLY in the store is still resolved (its store copies are
    /// probed because no importer-tree copy was found).
    pub async fn find_by_purls(
        &self,
        node_modules_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, Vec<CrawledPackage>>, std::io::Error> {
        let mut pending: Vec<Target> = Vec::new();
        for purl in purls {
            let Some((namespace, name, version)) = Self::parse_purl_components(purl) else {
                continue;
            };

            // SECURITY: `namespace`/`name` come straight from the (untrusted)
            // manifest PURL and are joined onto `node_modules_path` below,
            // then patched in place. A real npm scope/name is a single
            // path segment, so reject any that could traverse out of the
            // tree (`pkg:npm/../../evil@1.0.0`). Fail closed — twin of the
            // deno/go/maven coordinate gates.
            let ns_safe = namespace
                .as_deref()
                .map(is_safe_npm_component)
                .unwrap_or(true);
            if !ns_safe || !is_safe_npm_component(&name) {
                continue;
            }

            let dir_key = match &namespace {
                Some(ns) => format!("{ns}/{name}"),
                None => name.clone(),
            };
            pending.push(Target {
                namespace,
                name,
                version,
                purl: purl.clone(),
                dir_key,
            });
        }

        // Both passes run as one walk-pool task: each visited dir is
        // listed once, and that listing both bounds which targets are
        // probed there and drives the descent (see
        // `resolve_pending_targets`).
        let node_modules_path = node_modules_path.to_path_buf();
        Ok(run_walk(move || {
            let mut result: HashMap<String, Vec<CrawledPackage>> = HashMap::new();

            // Pass 1 — filtered: `.pnpm` virtual-store entries are enqueued
            // only when their dir name decodes to a still-pending target's
            // name (a manifest routinely lists packages that simply aren't
            // installed here, and probing every entry of a large monorepo
            // store for them would add a readdir+stat storm to every
            // apply/rollback run).
            let pending =
                Self::resolve_pending_targets(&node_modules_path, pending, &mut result, true);

            // Pass 2 — unfiltered fallback, only for targets pass 1 could not
            // resolve: a target can physically exist ONLY inside another
            // package's store entry (a bundled dependency at
            // `.pnpm/host@1.0.0/node_modules/host/node_modules/<target>`),
            // whose entry name decodes to the HOST's name — the pass-1 filter
            // skips it, leaving an installed, scan-visible package invisible
            // to apply (fail-open: apply reported it not installed). Probe
            // every store entry for just the leftovers; the common all-
            // resolved case never reaches this pass, so its perf is intact.
            if !pending.is_empty() {
                Self::resolve_pending_targets(&node_modules_path, pending, &mut result, false);
            }

            result
        })
        .await)
    }

    /// One breadth-first resolution pass over the tree rooted at
    /// `node_modules_path`: the root `node_modules` first (so a root-level
    /// install always wins), then — only while targets remain unresolved —
    /// each nested `node_modules`. npm nests a conflicting version under
    /// the dependent package, so a patched version can exist *only*
    /// nested; CLI_CONTRACT ("Deeply nested transitive dependencies are
    /// fully supported") promises those are patched identically to direct
    /// deps, and `crawl_all` (scan) already discovers them at unbounded
    /// depth.
    ///
    /// EVERY matching physical copy of each target lands in `result`
    /// (keyed by the target's verbatim PURL, root-copy-first). Targets are
    /// kept live across the whole walk — a duplicate copy can live at any
    /// depth — so the traversal continues past the first match rather than
    /// stopping. Targets for which NO copy was found anywhere are returned
    /// (the pass-2 fallback re-probes them with the unfiltered store walk).
    /// `filter_store_entries` selects whether pnpm virtual-store entries are
    /// bounded by the still-unmatched-name filter (pass 1) or all probed
    /// (the pass-2 fallback) — see `find_by_purls`.
    ///
    /// Each visited dir is listed ONCE: a target is probed there only if
    /// the listing could hold its first path component (see
    /// [`ProbeFilter`]; a skipped probe could only have failed), and the
    /// same listing drives the descent.
    ///
    /// The walk runs level by level — exactly the FIFO queue's order, since
    /// everything a dir enqueues lands behind the rest of its level. What a
    /// visit READS depends only on the dir and the (fixed) target list, not
    /// on what earlier dirs resolved, so each level's visits are gathered
    /// in parallel ([`Self::visit_resolver_dir`]); the order-dependent part
    /// — folding matches into `result` and the unmatched-name store filter
    /// — is then replayed sequentially in queue order.
    fn resolve_pending_targets(
        node_modules_path: &Path,
        mut pending: Vec<Target>,
        result: &mut HashMap<String, Vec<CrawledPackage>>,
        filter_store_entries: bool,
    ) -> Vec<Target> {
        if pending.is_empty() {
            return pending;
        }
        // Each dir is tagged `true` when it is a pnpm or vlt store entry's
        // `node_modules`.
        let mut level: Vec<(PathBuf, bool)> = vec![(node_modules_path.to_path_buf(), false)];
        while !level.is_empty() {
            let visits: Vec<ResolverVisit> = par_map(level, |(nm_path, store_entry)| {
                Self::visit_resolver_dir(nm_path, store_entry, &pending)
            });
            let mut next_level: Vec<(PathBuf, bool)> = Vec::new();
            for visit in visits {
                let nm_path = visit.nm_path;
                for index in visit.matched {
                    let target = &pending[index];
                    let pkg_path = nm_path.join(&target.dir_key);
                    let copies = result.entry(target.purl.clone()).or_default();
                    // Record each physical copy once — a path reached twice
                    // (defensive against overlapping walks) is not
                    // double-counted, and a store copy an importer link
                    // already resolves to keeps the importer path.
                    let recorded = copies.iter().any(|c| c.path == pkg_path)
                        || (visit.store_entry && resolves_to_any_sync(&pkg_path, copies));
                    if !recorded {
                        copies.push(CrawledPackage {
                            name: target.name.clone(),
                            // The probe matched it verbatim (see
                            // `visit_resolver_dir`).
                            version: target.version.clone(),
                            namespace: target.namespace.clone(),
                            purl: target.purl.clone(),
                            path: pkg_path,
                        });
                    }
                }
                // Descend importer-tree nested `node_modules` for ALL targets
                // (a duplicate copy lives at an unknown depth), but probe the
                // pnpm virtual store only for targets NOT YET found anywhere: a
                // matched direct dep's store peer-variants are the apply
                // engine's fan-out job, and re-probing the store for it would
                // add a readdir storm. A target with no importer-tree copy
                // (transitive-only) still gets its store entries probed.
                let unmatched_names: HashSet<&str> = pending
                    .iter()
                    .filter(|t| !result.contains_key(&t.purl))
                    .map(|t| t.dir_key.as_str())
                    .collect();
                let filter = filter_store_entries.then_some(&unmatched_names);
                for nested in visit.nested {
                    match nested {
                        NestedNodeModules::Dir(dir) => next_level.push((dir, false)),
                        NestedNodeModules::StoreEntries(entries) => next_level.extend(
                            Self::pending_store_entries(entries, filter)
                                .into_iter()
                                .map(|dir| (dir, true)),
                        ),
                    }
                }
            }
            level = next_level;
        }
        // Only the targets with zero copies remain "pending" for pass 2.
        pending.retain(|t| !result.contains_key(&t.purl));
        pending
    }

    /// The read-only half of one resolver visit to `nm_path`: which of
    /// `pending` this dir holds a copy of (indices, in target order), and
    /// the nested `node_modules` the dir contributes, in listing order.
    ///
    /// Whether a probe matches depends only on the dir and the target, so
    /// it is decided HERE rather than handed to the sequential fold: a
    /// visit then carries one `usize` per MATCH instead of one probe slot
    /// per target. Every level's visits are live at once, so per-target
    /// slots made the resolver's peak memory
    /// `level_dirs × pending_targets` — hundreds of megabytes on a big
    /// pnpm store probed by pass 2, which enqueues every entry.
    ///
    /// Inside a store entry (`store_entry`) a link is a dependency edge into
    /// a sibling entry, whose own visit records that copy, so only a real
    /// directory there matches.
    fn visit_resolver_dir(nm_path: PathBuf, store_entry: bool, pending: &[Target]) -> ResolverVisit {
        let listing = list_dir_sync(&nm_path);
        let probe_filter = ProbeFilter::new(&listing);
        let matched = pending
            .iter()
            .enumerate()
            .filter(|(_, target)| {
                let first_component = target.namespace.as_deref().unwrap_or(&target.name);
                if !probe_filter.may_resolve(first_component) {
                    return false;
                }
                if store_entry && !is_real_package_dir_sync(&nm_path, &target.dir_key) {
                    return false;
                }
                // The on-disk *name* must match too: an alias install
                // (`npm i foo@npm:bar@1.0.0`) puts a different package in
                // `node_modules/foo`, so matching on version alone would
                // misidentify it and patch the wrong package's files.
                read_package_json_sync(&nm_path.join(&target.dir_key).join("package.json"))
                    .is_some_and(|(found_name, found_version)| {
                        found_name == target.dir_key && found_version == target.version
                    })
            })
            .map(|(index, _)| index)
            .collect();
        let nested = Self::collect_nested_node_modules(&nm_path, listing);
        ResolverVisit {
            nm_path,
            store_entry,
            matched,
            nested,
        }
    }

    /// The `node_modules` dirs living one level below `nm_path` (inside each
    /// of its package dirs, scoped or not), given `nm_path`'s listing.
    /// Mirrors the scan's traversal policy: hidden entries are skipped and
    /// symlinked packages are never traversed — a symlink here points into
    /// pnpm's content-addressed store or an `npm link` target outside the
    /// project. The one exception is pnpm's virtual store (see below),
    /// whose entries are returned whole: which of them get enqueued is
    /// decided by the caller's pending-name filter
    /// ([`Self::pending_store_entries`]) at replay time.
    ///
    /// Entries are examined in parallel; their contributions keep listing
    /// order.
    fn collect_nested_node_modules(nm_path: &Path, listing: Listing) -> Vec<NestedNodeModules> {
        let found: Vec<Vec<NestedNodeModules>> = par_map(listing.entries, |entry| {
            Self::nested_node_modules_of(nm_path, entry)
        });
        found.into_iter().flatten().collect()
    }

    /// What one listing entry of `nm_path` contributes to the resolver's
    /// next level (see [`Self::collect_nested_node_modules`]).
    fn nested_node_modules_of(nm_path: &Path, entry: ListedEntry) -> Vec<NestedNodeModules> {
        let name_str = entry.name_str.as_str();
        // pnpm's virtual store. Under the isolated linker the store is
        // the ONLY physical home of transitive dependencies: the
        // importer's node_modules holds symlinks for direct deps only,
        // so a transitive-only target (installed at
        // `.pnpm/<x>/node_modules/<name>`, runtime-loaded) is
        // unreachable through the symlink-free walk above — invisible
        // to apply despite being importable. Probe REAL store entries'
        // `node_modules`; the name+version match in `find_by_purls`
        // keeps aliases and multi-version store entries distinct, and
        // BFS order guarantees a root-linked install has already been
        // probed (and removed from `pending`) before these are
        // dequeued, so a package is never resolved twice.
        if name_str == ".pnpm" {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::list_pnpm_store_entries_sync(&nm_path.join(&entry.name), false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // vlt's store has the same transitive-only-home property: every
        // package lives at `.vlt/<DepID>/node_modules/<name>` and the
        // importer holds only links into it.
        if name_str == VLT_STORE_NAME {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::list_vlt_store_entries_sync(&nm_path.join(&entry.name));
            return vec![NestedNodeModules::StoreEntries(StoreEntry::vlt(entries))];
        }
        // npm's `install-strategy=linked` store: the same transitive-only
        // home, at `.store/<name>@<version>-<hash>/node_modules/<name>`.
        if name_str == NPM_LINKED_STORE_NAME {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::list_npm_store_entries_sync(&nm_path.join(&entry.name), false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // A pnpm virtual store relocated by `virtualStoreDir`, found
        // through the `.modules.yaml` pnpm writes next to it. It may sit
        // outside this `node_modules` or under a hidden name the skip
        // below would swallow.
        if name_str == PNPM_MODULES_YAML {
            if !entry.file_type.is_some_and(|ft| ft.is_file()) {
                return Vec::new();
            }
            let Some(store) = relocated_pnpm_virtual_store_sync(nm_path) else {
                return Vec::new();
            };
            let entries = Self::list_pnpm_store_entries_sync(&store, false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // pnpm <=3: the virtual store is a hidden `.<registry-host>` dir
        // (there is no `.pnpm` at all) with the same
        // transitive-only-deps property, so it gets the same probing.
        // Must run before the generic hidden-entry skip below, which
        // would otherwise swallow it — leaving every transitive-only
        // install unpatchable on those layouts.
        if is_legacy_pnpm_store_dir_name(name_str) {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::collect_nested_store_entries_sync(&nm_path.join(&entry.name));
            return vec![NestedNodeModules::StoreEntries(StoreEntry::pnpm(entries))];
        }
        if name_str.starts_with('.') || name_str == "node_modules" {
            return Vec::new();
        }
        if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
            return Vec::new();
        }
        let entry_path = nm_path.join(&entry.name);

        if name_str.starts_with('@') {
            list_dir_sync(&entry_path)
                .entries
                .into_iter()
                .filter(|scoped| {
                    !scoped.name_str.starts_with('.')
                        && scoped.file_type.is_some_and(|ft| ft.is_dir())
                })
                .map(|scoped| entry_path.join(&scoped.name).join("node_modules"))
                .filter(|nested| is_dir_sync(nested))
                .map(NestedNodeModules::Dir)
                .collect()
        } else {
            let nested = entry_path.join("node_modules");
            if is_dir_sync(&nested) {
                vec![NestedNodeModules::Dir(nested)]
            } else {
                Vec::new()
            }
        }
    }

    /// The virtual-store entries that can still hold a pending target.
    /// A manifest routinely lists packages that simply aren't installed
    /// here, and probing every entry of a large monorepo store for them
    /// would add a readdir+stat storm to every apply/rollback run. The
    /// entry name advertises the entry's package, so filter by PENDING
    /// NAME only — the version is deliberately NOT matched at this stage
    /// (dir-name versions can carry peer/build decorations; the
    /// package.json probe stays the authority). An undecodable name
    /// (truncated/hash-suffixed dirs, git/URL deps, `_`-bearing names)
    /// reveals nothing about what's inside, so it stays probeable.
    ///
    /// `pending_names = None` disables the filter entirely: the entry name
    /// only advertises the entry's OWN package, so a target present solely
    /// as a bundled dependency INSIDE another package's entry hides behind
    /// a non-matching name — `find_by_purls`' pass-2 fallback probes every
    /// entry for exactly those. Both enumerators only yield entries whose
    /// `node_modules` exists, so no re-stat here.
    fn pending_store_entries(
        entries: Vec<StoreEntry>,
        pending_names: Option<&HashSet<&str>>,
    ) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in entries {
            if let (Some(filter), Some((entry_pkg, _version))) = (pending_names, &entry.advertised)
            {
                if !filter.contains(entry_pkg.as_str()) {
                    continue;
                }
            }
            out.push(entry.node_modules);
        }
        out
    }

    // ------------------------------------------------------------------
    // Private helpers – global paths
    // ------------------------------------------------------------------

    /// Collect global `node_modules` paths from all known package managers.
    fn get_global_node_modules_paths(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();

        let mut add = |p: PathBuf| {
            if p.is_dir() && seen.insert(p.clone()) {
                paths.push(p);
            }
        };

        if let Ok(npm_path) = get_npm_global_prefix() {
            add(PathBuf::from(npm_path));
        }
        if let Some(pnpm_path) = get_pnpm_global_prefix() {
            add(PathBuf::from(pnpm_path));
        }
        if let Some(yarn_path) = get_yarn_global_prefix() {
            add(PathBuf::from(yarn_path));
        }
        if let Some(bun_path) = get_bun_global_prefix() {
            add(PathBuf::from(bun_path));
        }

        // macOS-specific fallback paths
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME").unwrap_or_default();

            // Homebrew Apple Silicon
            add(PathBuf::from("/opt/homebrew/lib/node_modules"));
            // Homebrew Intel / default npm
            add(PathBuf::from("/usr/local/lib/node_modules"));

            if !home.is_empty() {
                // nvm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".nvm/versions/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // volta
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".volta/tools/image/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // fnm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".fnm/node-versions"),
                    &["*", "installation", "lib", "node_modules"],
                ) {
                    add(p);
                }
            }
        }

        paths
    }

    // ------------------------------------------------------------------
    // Private helpers – local node_modules discovery
    // ------------------------------------------------------------------

    /// Blocking body of [`Self::get_node_modules_paths`].
    fn node_modules_paths_sync(options: &CrawlerOptions) -> Vec<PathBuf> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return vec![custom.clone()];
            }
            return NpmCrawler.get_global_node_modules_paths();
        }

        Self::find_local_node_modules_dirs(&options.cwd)
    }

    /// Find `node_modules` directories within the project root.
    /// Recursively searches for workspace `node_modules` but stays within the
    /// project.
    fn find_local_node_modules_dirs(start_path: &Path) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let listing = list_dir_sync(start_path);

        // Direct node_modules in start_path
        if has_node_modules_dir(start_path, &listing) {
            results.push(start_path.join("node_modules"));
        }

        // Recursively search for workspace node_modules
        results.extend(Self::find_workspace_node_modules(start_path, listing));

        results
    }

    /// Find `node_modules` in subdirectories (for monorepos / workspaces),
    /// at any depth, given `dir`'s own listing. Skips symlinks, hidden
    /// dirs, and well-known non-workspace dirs.
    ///
    /// The result is in the sequential depth-first order: children in
    /// listing order, each contributing its own `node_modules` first and
    /// then its subtree's. The tree is read one level at a time, each
    /// level's dirs in parallel, and the order is reassembled from the
    /// recorded child ranges afterwards — no recursion, so an arbitrarily
    /// deep directory chain cannot exhaust a thread's stack. A child whose
    /// listing (which the walk needs anyway) proves it has no
    /// `node_modules` skips the stat; see [`has_node_modules_dir`].
    fn find_workspace_node_modules(dir: &Path, listing: Listing) -> Vec<PathBuf> {
        /// One walked dir: its `node_modules` (if any) and the indices of
        /// its walked children in `nodes`.
        struct WalkedDir {
            node_modules: Option<PathBuf>,
            children: std::ops::Range<usize>,
        }

        // Dirs are numbered in visit order, level by level, so each dir's
        // children occupy a contiguous range of the next level.
        let mut nodes: Vec<WalkedDir> = Vec::new();
        let mut level = Self::workspace_children(dir, listing);
        let roots = 0..level.len();
        while !level.is_empty() {
            let visits: Vec<(Option<PathBuf>, Vec<PathBuf>)> = par_map(level, |full_path| {
                let listing = list_dir_sync(&full_path);
                // A tagged cache directory (a cargo `target/`, a tool's
                // cache) is pruned whole: neither its `node_modules` nor
                // anything below it is a workspace.
                if is_tagged_cache_dir(&full_path, &listing) {
                    return (None, Vec::new());
                }
                // Check if this subdirectory has its own node_modules
                let node_modules = has_node_modules_dir(&full_path, &listing)
                    .then(|| full_path.join("node_modules"));
                (node_modules, Self::workspace_children(&full_path, listing))
            });
            let next_base = nodes.len() + visits.len();
            let mut next_level = Vec::new();
            for (node_modules, children) in visits {
                let start = next_base + next_level.len();
                next_level.extend(children);
                nodes.push(WalkedDir {
                    node_modules,
                    children: start..next_base + next_level.len(),
                });
            }
            level = next_level;
        }

        // Pre-order emission with an explicit stack.
        let mut results = Vec::new();
        let mut stack: Vec<usize> = roots.rev().collect();
        while let Some(index) = stack.pop() {
            let node = &mut nodes[index];
            results.extend(node.node_modules.take());
            stack.extend(node.children.clone().rev());
        }
        results
    }

    /// The subdirectories of `dir` the workspace walk descends into, in
    /// listing order: real dirs only (symlinks are never followed), minus
    /// `node_modules`, hidden dirs and well-known build dirs.
    fn workspace_children(dir: &Path, listing: Listing) -> Vec<PathBuf> {
        listing
            .entries
            .into_iter()
            .filter(|entry| {
                entry.file_type.is_some_and(|ft| ft.is_dir())
                    && !(entry.name_str == "node_modules"
                        || entry.name_str.starts_with('.')
                        || SKIP_DIRS.contains(&entry.name_str.as_str()))
            })
            .map(|entry| dir.join(&entry.name))
            .collect()
    }

    // ------------------------------------------------------------------
    // Private helpers – scanning
    // ------------------------------------------------------------------

    /// Gather one `node_modules` directory's scan into [`ScanEvent`]s, in
    /// the exact order the sequential walk visits it: the directory's own
    /// entries (each package followed by its nested `node_modules`), then
    /// the deferred pnpm and vlt store(s). `listing` is the directory's
    /// listing when the caller already read it. `store_entry` selects the
    /// one policy bit distinguishing an importer/package tree from a pnpm
    /// or vlt store entry's `node_modules`:
    /// - importer trees accept both directories and symlinks (pnpm and vlt
    ///   link direct deps; `npm link` targets) but never traverse a symlink,
    ///   and a `.pnpm` (or pnpm <=3 `.<registry-host>`) or `.vlt` child is
    ///   the virtual store, walked after the loop;
    /// - a store entry accepts REAL directories only — a symlinked (or, on
    ///   Windows, junctioned) entry there is the package's dependency
    ///   pointing at a sibling store entry, inventoried via that entry, and
    ///   following it would record the same package under a path owned by a
    ///   different store entry — and its direct children carry
    ///   their package key so the merge can apply the entry's
    ///   `identity_seen` skip.
    ///
    /// Sibling packages (and their subtrees) are gathered in parallel; the
    /// results are concatenated back in listing order.
    fn gather_node_modules(
        node_modules_path: &Path,
        listing: Option<Listing>,
        store_entry: bool,
    ) -> Vec<ScanEvent> {
        let listing = listing.unwrap_or_else(|| list_dir_sync(node_modules_path));
        let mut pnpm_store: Option<PathBuf> = None;
        let mut vlt_store: Option<PathBuf> = None;
        let mut npm_store: Option<PathBuf> = None;
        let mut relocated_pnpm_store: Option<PathBuf> = None;
        let mut legacy_stores: Vec<PathBuf> = Vec::new();
        let mut children: Vec<(PathBuf, String, FileType)> = Vec::new();

        for entry in listing.entries {
            let name_str = entry.name_str;

            // pnpm's virtual store: under the isolated linker it is the
            // ONLY physical home of transitive dependencies (the
            // importer's node_modules symlinks direct deps only), so
            // skipping it as just-another-hidden-dir leaves every
            // transitive-only install invisible to scan. Deferred until
            // after this loop so root-level entries are inventoried
            // first and win the `seen` name@version dedup at their
            // importer-root paths. (A store entry's own children never
            // include a nested `.pnpm`; under the store-entry policy the
            // name falls through to the hidden-entry skip below.)
            if !store_entry && name_str == ".pnpm" {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    pnpm_store = Some(node_modules_path.join(&name_str));
                }
                continue;
            }

            // vlt's store, deferred for the same reason: importer links
            // win the `seen` dedup at their importer-root paths.
            if !store_entry && name_str == VLT_STORE_NAME {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    vlt_store = Some(node_modules_path.join(&name_str));
                }
                continue;
            }

            // npm's linked-strategy store, deferred for the same reason.
            if !store_entry && name_str == NPM_LINKED_STORE_NAME {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    npm_store = Some(node_modules_path.join(&name_str));
                }
                continue;
            }

            // A pnpm virtual store relocated by `virtualStoreDir` (see
            // `relocated_pnpm_virtual_store_sync`), deferred like `.pnpm`.
            if !store_entry && name_str == PNPM_MODULES_YAML {
                if entry.file_type.is_some_and(|ft| ft.is_file()) {
                    relocated_pnpm_store = relocated_pnpm_virtual_store_sync(node_modules_path);
                }
                continue;
            }

            // pnpm <=3 virtual store (a hidden `.<registry-host>` dir;
            // no `.pnpm` exists on those layouts): same
            // transitive-only-home property, same deferred scan so
            // root-level entries win the `seen` dedup. Must run before
            // the hidden-entry skip below, which would otherwise leave
            // every transitive-only install invisible to scan.
            if !store_entry && is_legacy_pnpm_store_dir_name(&name_str) {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    legacy_stores.push(node_modules_path.join(&name_str));
                }
                continue;
            }

            // Skip hidden files and node_modules
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }

            let Some(file_type) = entry.file_type else {
                continue;
            };
            if !Self::acceptable_package_entry(file_type, store_entry) {
                continue;
            }

            children.push((node_modules_path.join(&name_str), name_str, file_type));
        }

        let mut events: Vec<ScanEvent> = par_map(children, |(entry_path, name_str, file_type)| {
            if name_str.starts_with('@') {
                // Scoped packages
                Self::gather_scoped_packages(&entry_path, &name_str, store_entry)
            } else {
                Self::gather_package(
                    entry_path,
                    store_entry.then_some(name_str),
                    file_type.is_dir(),
                )
            }
        })
        .into_iter()
        .flatten()
        .collect();

        if let Some(store_path) = pnpm_store {
            let entries = Self::list_pnpm_store_entries_sync(&store_path, true);
            events.extend(Self::gather_store_entries(entries));
        }
        for store_path in legacy_stores {
            let entries = Self::collect_nested_store_entries_sync(&store_path)
                .into_iter()
                .map(|(name, node_modules)| StoreEntryDir {
                    advertised: decode_pnpm_store_entry_name(&name),
                    name,
                    node_modules,
                    listing: None,
                })
                .collect();
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = relocated_pnpm_store {
            let entries = Self::list_pnpm_store_entries_sync(&store_path, true);
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = vlt_store {
            let entries = Self::vlt_store_entry_dirs(&store_path);
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = npm_store {
            let entries = Self::list_npm_store_entries_sync(&store_path, true);
            events.extend(Self::gather_store_entries(entries));
        }

        events
    }

    /// Importer trees allow both directories and symlinks (pnpm links
    /// direct deps); a store entry accepts REAL dirs only (see
    /// [`Self::gather_node_modules`]).
    fn acceptable_package_entry(file_type: FileType, store_entry: bool) -> bool {
        if store_entry {
            file_type.is_dir()
        } else {
            file_type.is_dir() || file_type.is_symlink()
        }
    }

    /// One package dir: its `check_package` candidate event, then — only
    /// for a real directory (`recurse`), never a symlink, which would walk
    /// into pnpm's content-addressed store or an `npm link` target outside
    /// the project — its nested `node_modules`, always an importer-style
    /// tree. `entry_key` is set for a store entry's direct children (see
    /// [`ScanEvent::Package`]); the dir is still descended when the merge
    /// skips its package.json, because bundled dependencies are real dirs
    /// nested inside the package itself (pnpm cannot link them out),
    /// physically present only there.
    ///
    /// The identity is read even for the child the merge will skip, which
    /// the sequential walk avoided (it knew `identity_seen` as it went).
    /// The gather cannot: the skip depends on the dedup state at merge
    /// time. Deferring that one read to the merge thread would move the
    /// store's transitive-only reads — the ones that are NEVER skipped,
    /// and the bulk of a virtual store — onto the serial path, to save one
    /// open per root-linked direct dep. So the read stays here.
    fn gather_package(path: PathBuf, entry_key: Option<String>, recurse: bool) -> Vec<ScanEvent> {
        let identity = read_package_json_sync(&path.join("package.json"));
        let nested = recurse.then(|| path.join("node_modules"));
        let mut events = vec![ScanEvent::Package {
            path,
            identity,
            entry_key,
        }];
        if let Some(nested) = nested {
            events.extend(Self::gather_node_modules(&nested, None, false));
        }
        events
    }

    /// Gather a scoped packages directory (`@scope/`). `store_entry`
    /// carries the caller's traversal policy; nested `node_modules` below a
    /// scoped package are always regular importer-style trees. A store
    /// entry's `identity_seen` names the full `@scope/name`, so that is the
    /// key recorded for its direct children.
    fn gather_scoped_packages(
        scope_path: &Path,
        scope_name: &str,
        store_entry: bool,
    ) -> Vec<ScanEvent> {
        let children: Vec<(String, FileType)> = list_dir_sync(scope_path)
            .entries
            .into_iter()
            .filter_map(|entry| {
                if entry.name_str.starts_with('.') {
                    return None;
                }
                let file_type = entry.file_type?;
                Self::acceptable_package_entry(file_type, store_entry)
                    .then_some((entry.name_str, file_type))
            })
            .collect();

        par_map(children, |(name_str, file_type)| {
            Self::gather_package(
                scope_path.join(&name_str),
                store_entry.then(|| format!("{scope_name}/{name_str}")),
                file_type.is_dir(),
            )
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// Gather each virtual-store entry's `node_modules` (entries come from
    /// [`Self::list_pnpm_store_entries_sync`] or
    /// [`Self::collect_nested_store_entries_sync`]) under the store-entry
    /// policy, in parallel, preserving entry order.
    fn gather_store_entries(entries: Vec<StoreEntryDir>) -> Vec<ScanEvent> {
        par_map(entries, |entry| ScanEvent::StoreEntry {
            decoded: entry.advertised,
            events: Self::gather_node_modules(&entry.node_modules, entry.listing, true),
        })
    }

    /// Replay gathered [`ScanEvent`]s in order against `seen`, exactly as
    /// the sequential walk's `check_package` calls would have: a package
    /// is recorded only if its package.json parsed and its PURL is new.
    ///
    /// A store entry whose name decodes to a name@version already
    /// inventoried (every root-linked direct dep — the importer pass wins
    /// the `seen` dedup) gets `identity_seen` = that name, decided HERE,
    /// against the dedup state at this point of the replay: its matching
    /// direct child is skipped — its gathered identity discarded unread,
    /// the one read the parallel gather cannot avoid (see
    /// [`Self::gather_package`]); the sequential walk did not even open
    /// that package.json. Everything below the entry is still replayed.
    fn merge_scan_events(
        events: Vec<ScanEvent>,
        identity_seen: Option<&str>,
        seen: &mut HashSet<String>,
        packages: &mut Vec<CrawledPackage>,
    ) {
        for event in events {
            match event {
                ScanEvent::Package {
                    path,
                    identity,
                    entry_key,
                } => {
                    if identity_seen.is_some() && entry_key.as_deref() == identity_seen {
                        continue;
                    }
                    let Some((full_name, version)) = identity else {
                        continue;
                    };
                    let (namespace, name) = parse_package_name(&full_name);
                    let purl = build_npm_purl(namespace.as_deref(), &name, &version);
                    if !seen.insert(purl.clone()) {
                        continue;
                    }
                    packages.push(CrawledPackage {
                        name,
                        version,
                        namespace,
                        purl,
                        path,
                    });
                }
                ScanEvent::StoreEntry { decoded, events } => {
                    let identity_seen = decoded
                        .filter(|(full_name, version)| {
                            let (ns, bare) = parse_package_name(full_name);
                            seen.contains(&build_npm_purl(ns.as_deref(), &bare, version))
                        })
                        .map(|(full_name, _version)| full_name);
                    Self::merge_scan_events(events, identity_seen.as_deref(), seen, packages);
                }
            }
        }
    }

    /// Enumerate pnpm virtual-store (`node_modules/.pnpm`) entries,
    /// yielding `(entry_name, <entry>/node_modules)` for every entry whose
    /// `node_modules` actually exists. The child literally named
    /// `node_modules` is pnpm's internal hoist dir (nothing but symlinks
    /// into sibling entries) and hidden children are store metadata — both
    /// skipped. A REAL directory child with a `node_modules` of its own is
    /// a flat (pnpm 6+) entry; one *without* is the pnpm 4/5 nested layout
    /// — the child is a registry-host dir
    /// (`.pnpm/<registry-host>/<name>/<version>/node_modules/<name>`), so
    /// treating it as an empty entry silently hid every transitive-only
    /// install (apply exited 0 claiming success with nothing written) —
    /// descend it instead. Shared by the resolver
    /// (`collect_nested_node_modules`), the scan pass and the peer-variant
    /// finder so the store-layout policy lives once.
    ///
    /// Entries are probed in parallel and yielded in listing order. With
    /// `read_listings` (the scan, which lists every entry's `node_modules`
    /// next anyway) the existence probe IS that readdir: a `node_modules`
    /// that opens as a directory is one, and its listing rides along in
    /// [`StoreEntryDir::listing`]; one that does not open falls back to
    /// the `is_dir` stat so an unreadable-but-present dir keeps its
    /// flat-entry classification.
    fn list_pnpm_store_entries_sync(store_path: &Path, read_listings: bool) -> Vec<StoreEntryDir> {
        let candidates: Vec<ListedEntry> = list_dir_sync(store_path)
            .entries
            .into_iter()
            .filter(|entry| {
                !(entry.name_str.starts_with('.') || entry.name_str == "node_modules")
                    && entry.file_type.is_some_and(|ft| ft.is_dir())
            })
            .collect();

        par_map(candidates, |entry| {
            let entry_path = store_path.join(&entry.name);
            let entry_nm = entry_path.join("node_modules");
            if read_listings {
                if let Some((entries, complete)) = read_dir_entries_sync(&entry_nm) {
                    return vec![StoreEntryDir {
                        advertised: decode_pnpm_store_entry_name(&entry.name_str),
                        name: entry.name_str,
                        node_modules: entry_nm,
                        listing: Some(Listing::from_entries(entries, complete)),
                    }];
                }
            }
            if is_dir_sync(&entry_nm) {
                vec![StoreEntryDir {
                    advertised: decode_pnpm_store_entry_name(&entry.name_str),
                    name: entry.name_str,
                    node_modules: entry_nm,
                    listing: None,
                }]
            } else {
                Self::collect_nested_store_entries_sync(&entry_path)
                    .into_iter()
                    .map(|(name, node_modules)| StoreEntryDir {
                        advertised: decode_pnpm_store_entry_name(&name),
                        name,
                        node_modules,
                        listing: None,
                    })
                    .collect()
            }
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// Async `(name, node_modules)` view of
    /// [`Self::list_pnpm_store_entries_sync`] for the async callers.
    async fn list_pnpm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || {
            Self::list_pnpm_store_entries_sync(&store_path, false)
                .into_iter()
                .map(|entry| (entry.name, entry.node_modules))
                .collect()
        })
        .await
    }

    /// Enumerate vlt's store (`node_modules/.vlt`), yielding the lossless
    /// entry name and `<entry>/node_modules` for every REAL entry dir whose
    /// `node_modules` is a real dir. Skipped: dot-names (store metadata and
    /// the `.VLT.DELETE.<key>.<DepID>` rollback staging that lingers on
    /// Windows), the `node_modules` child (vlt's internal hoist dir: links
    /// plus real `@scope` dirs holding links), files (`vlt.json`) and links.
    /// The store is always flat; every entry holds exactly one real package
    /// dir named after the package (never the alias). Entries are probed in
    /// parallel and yielded in listing order.
    fn list_vlt_store_entries_sync(store_path: &Path) -> Vec<(OsString, PathBuf)> {
        let candidates: Vec<ListedEntry> = list_dir_sync(store_path)
            .entries
            .into_iter()
            .filter(|entry| {
                !(entry.name.as_encoded_bytes().starts_with(b".") || entry.name == "node_modules")
                    && entry.file_type.is_some_and(|ft| ft.is_dir())
            })
            .collect();
        par_map(candidates, |entry| {
            let entry_nm = store_path.join(&entry.name).join("node_modules");
            std::fs::symlink_metadata(&entry_nm)
                .is_ok_and(|m| m.is_dir())
                .then_some((entry.name, entry_nm))
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// [`Self::list_vlt_store_entries_sync`] as the scan's
    /// [`StoreEntryDir`]s, each with its `node_modules`' listing (the scan
    /// lists every entry's `node_modules` next anyway).
    fn vlt_store_entry_dirs(store_path: &Path) -> Vec<StoreEntryDir> {
        par_map(
            Self::list_vlt_store_entries_sync(store_path),
            |(name, node_modules)| StoreEntryDir {
                advertised: decode_vlt_store_entry_name(&name),
                name: name.to_string_lossy().into_owned(),
                listing: Some(list_dir_sync(&node_modules)),
                node_modules,
            },
        )
    }

    /// Async view of [`Self::list_vlt_store_entries_sync`].
    async fn list_vlt_store_entries(store_path: &Path) -> Vec<(OsString, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || Self::list_vlt_store_entries_sync(&store_path)).await
    }

    /// Enumerate npm's linked store (`node_modules/.store`, written by
    /// `install-strategy=linked`), yielding every REAL entry dir whose
    /// `node_modules` is a real dir, named by its store key. A scoped
    /// package's entry sits one level down (`.store/@scope/<leaf>@<v>-<h>`),
    /// so a real `@scope` dir is descended once and its entries are named
    /// `@scope/<leaf>@<v>-<h>`. Skipped: dot-names, a `node_modules` child,
    /// files and links (a link is never a store entry). Entries are probed
    /// in parallel and yielded in listing order; with `read_listings` each
    /// entry's `node_modules` listing rides along, as for pnpm.
    fn list_npm_store_entries_sync(store_path: &Path, read_listings: bool) -> Vec<StoreEntryDir> {
        let is_candidate = |entry: &ListedEntry| {
            !(entry.name_str.starts_with('.') || entry.name_str == "node_modules")
                && entry.file_type.is_some_and(|ft| ft.is_dir())
        };
        let mut candidates: Vec<(String, PathBuf)> = Vec::new();
        for entry in list_dir_sync(store_path).entries {
            if !is_candidate(&entry) {
                continue;
            }
            let path = store_path.join(&entry.name);
            if entry.name_str.starts_with('@') {
                for scoped in list_dir_sync(&path).entries {
                    if is_candidate(&scoped) && !scoped.name_str.starts_with('@') {
                        let name = format!("{}/{}", entry.name_str, scoped.name_str);
                        candidates.push((name, path.join(&scoped.name)));
                    }
                }
            } else {
                candidates.push((entry.name_str, path));
            }
        }
        par_map(candidates, |(name, entry_path)| {
            let node_modules = entry_path.join("node_modules");
            if !std::fs::symlink_metadata(&node_modules).is_ok_and(|m| m.is_dir()) {
                return None;
            }
            Some(StoreEntryDir {
                advertised: decode_npm_store_entry_name(&name),
                name,
                listing: read_listings.then(|| list_dir_sync(&node_modules)),
                node_modules,
            })
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// Async `(name, node_modules)` view of
    /// [`Self::list_npm_store_entries_sync`].
    async fn list_npm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || {
            Self::list_npm_store_entries_sync(&store_path, false)
                .into_iter()
                .map(|entry| (entry.name, entry.node_modules))
                .collect()
        })
        .await
    }

    /// Descend a *nested* virtual-store host dir, yielding
    /// `(name@version, <version-dir>/node_modules)` for each package home
    /// found. Covers the two pre-flat layouts (both confirmed against
    /// captured real installs):
    /// - pnpm 4/5: `.pnpm/<registry-host>/…` — called on a `.pnpm` child
    ///   that has no `node_modules` of its own;
    /// - pnpm <=3: `node_modules/.<registry-host>/…` — called on the
    ///   hidden store root directly.
    ///
    /// Below the host, path components are registry coordinates (`@scope`,
    /// name, version), NOT package dirs, so the importer-walk hidden-name
    /// skip does not apply here — but symlinks are never traversed (a link
    /// inside the store points at a sibling entry or out of tree, and
    /// following one could cycle), and both depth and total fan-out are
    /// bounded. Each found dir's host-relative path is synthesized into
    /// the flat `name@version` entry-name form so downstream consumers
    /// (the pending-name filter, the `identity_seen` dedup) treat nested
    /// and flat entries identically; a shape that doesn't fit stays an
    /// undecodable — always-probed — name, the conservative direction.
    ///
    /// Deliberately sequential: the `NESTED_STORE_MAX_DIRS` budget is
    /// spent in breadth-first listing order, which decides exactly which
    /// entries survive when it runs out.
    fn collect_nested_store_entries_sync(host_path: &Path) -> Vec<(String, PathBuf)> {
        let mut entries = Vec::new();
        let mut remaining = NESTED_STORE_MAX_DIRS;
        let mut queue: VecDeque<(PathBuf, String, usize)> =
            VecDeque::from([(host_path.to_path_buf(), String::new(), 0)]);
        while let Some((dir, rel, depth)) = queue.pop_front() {
            for entry in list_dir_sync(&dir).entries {
                let name_str = entry.name_str;
                // A `node_modules` here belongs to a parent entry (already
                // yielded), never a name/version coordinate.
                if name_str == "node_modules" {
                    continue;
                }
                let Some(file_type) = entry.file_type else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                if remaining == 0 {
                    return entries;
                }
                remaining -= 1;
                let child = dir.join(&entry.name);
                let child_rel = if rel.is_empty() {
                    name_str
                } else {
                    format!("{rel}/{name_str}")
                };
                let child_nm = child.join("node_modules");
                if is_dir_sync(&child_nm) {
                    // `<name>/<version>/node_modules` — a package home.
                    // Anything deeper belongs to that package's own tree,
                    // which the store-entry scan walks itself.
                    let entry_name = match child_rel.rsplit_once('/') {
                        Some((pkg, version)) => format!("{pkg}@{version}"),
                        // Directly under the host there is no name/version
                        // split; the raw component stays the entry name
                        // (undecodable ⇒ probed).
                        None => child_rel,
                    };
                    entries.push((entry_name, child_nm));
                    continue;
                }
                if depth + 1 < NESTED_STORE_MAX_DEPTH {
                    queue.push_back((child, child_rel, depth + 1));
                }
            }
        }
        entries
    }

    /// Async view of [`Self::collect_nested_store_entries_sync`], appending
    /// to `entries`.
    #[cfg(test)]
    async fn collect_nested_store_entries(host_path: &Path, entries: &mut Vec<(String, PathBuf)>) {
        let host_path = host_path.to_path_buf();
        entries.extend(run_walk(move || Self::collect_nested_store_entries_sync(&host_path)).await);
    }

    // ------------------------------------------------------------------
    // Private helpers – PURL parsing
    // ------------------------------------------------------------------

    /// Parse a PURL string to extract namespace, name, and version.
    fn parse_purl_components(purl: &str) -> Option<(Option<String>, String, String)> {
        let base = strip_purl_qualifiers(purl);

        let rest = base.strip_prefix("pkg:npm/")?;
        let at_idx = rest.rfind('@')?;
        let name_part = &rest[..at_idx];
        let version = &rest[at_idx + 1..];

        if name_part.is_empty() || version.is_empty() {
            return None;
        }

        // SECURITY: components are percent-decoded AFTER the `/`/`@` splits
        // above (so an encoded `%2f` cannot create a new path segment here)
        // and BEFORE the `is_safe_npm_component` guards in `find_by_purls`
        // (so `%2e%2e` cannot smuggle a traversal past them). The API serves
        // scoped purls as `pkg:npm/%40scope/name@version`, which must match
        // the literal `node_modules/@scope/name` install.
        let version = percent_decode_purl_component(version);

        if let Some(slash_idx) = name_part.find('/') {
            let namespace = percent_decode_purl_component(&name_part[..slash_idx]);
            let name = percent_decode_purl_component(&name_part[slash_idx + 1..]);
            // An npm namespace is always an `@scope` (checked post-decode).
            if name.is_empty() || !namespace.starts_with('@') {
                return None;
            }
            Some((
                Some(namespace.into_owned()),
                name.into_owned(),
                version.into_owned(),
            ))
        } else {
            let name = percent_decode_purl_component(name_part);
            // A bare `@scope` with no `/name` is not a package name.
            if name.starts_with('@') {
                return None;
            }
            Some((None, name.into_owned(), version.into_owned()))
        }
    }
}

impl Default for NpmCrawler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Store peer-variant duplicate discovery (used by the apply engine)
// ---------------------------------------------------------------------------

/// Which store layout a candidate store directory uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreLayout {
    Pnpm,
    Vlt,
    NpmLinked,
}

/// Find every OTHER physical copy of the package installed at `pkg_path`
/// inside the pnpm or vlt store(s) reachable from it.
///
/// Both managers materialize one store copy PER PEER (or modifier)
/// COMBINATION: `.pnpm/foo@1.0.0(react@17…)/` and `…(react@18…)/`, or
/// `.vlt/~npm~foo@1.0.0~peer.2/` and `~peer.3/` (plus vlt's modifier
/// `~_croot…` extras and the legacy `··foo@1.0.0` / `·npm·foo@1.0.0` pair),
/// are all real directories holding the same `foo@1.0.0`, each
/// runtime-loaded by whichever importer resolves to it. The purl-keyed
/// resolver hands apply exactly ONE primary path (root-install-wins), so
/// the apply engine calls this to fan every write out to the remaining
/// physical copies — patching (or restoring) only one of them would leave
/// a live vulnerable copy behind while reporting success (fail-open).
///
/// Discovery, all bounded and read-only:
/// 1. Candidate stores come from the ancestor chains of `pkg_path` AND of
///    its canonicalized form (the root-linked primary is a link into the
///    store, and in a workspace the store lives beside the ROOT
///    `node_modules`, on the canonical chain only): any ancestor named
///    `.pnpm` or `.vlt`, plus any `node_modules` ancestor's `.pnpm` and
///    `.vlt` children. Other layouts (npm/yarn trees, cargo/go/vendor dirs)
///    have neither and return early — the cheap common case. pnpm <=3
///    legacy stores are keyed by plain `name/version` and cannot hold
///    peer-variant duplicates, so they are deliberately not probed.
/// 2. pnpm entries come from the shared layout walker
///    (`list_pnpm_store_entries`, flat + nested); an entry whose name
///    decodes to a DIFFERENT name@version is skipped and an undecodable
///    name stays probeable. vlt entries come from `list_vlt_store_entries`
///    and must decode to exactly the primary's name@version: an
///    undecodable vlt id (git, remote, `file:`) is never a peer variant.
///    A matching copy inside one is still installed, and
///    `NpmCrawler::find_by_purls` returns it as a primary of its own (it
///    probes every undecodable entry), so it is patched like any other.
///    The package.json probe is the authority either way.
/// 3. Only REAL directories count (a link inside a store entry is another
///    entry's copy, already yielded via that entry), the copy `pkg_path`
///    itself canonicalizes to is excluded, and results are deduped by
///    canonical path (both sides canonicalized, so Windows `\\?\` paths
///    compare consistently).
///
/// The returned paths are the copies' package roots (each in its own
/// store entry). Callers write through the hardened per-file pipeline,
/// which breaks content-store hardlinks per copy — CoW safety holds for
/// every copy independently.
pub async fn find_store_peer_variant_copies(pkg_path: &Path) -> Vec<PathBuf> {
    // 1. Candidate stores from both ancestor chains (cheap stats only —
    //    no file reads until a store is actually found).
    let canonical_pkg = tokio::fs::canonicalize(pkg_path).await.ok();
    let mut stores: Vec<(StoreLayout, PathBuf)> = Vec::new();
    let mut seen_stores: HashSet<PathBuf> = HashSet::new();
    let chains = [Some(pkg_path), canonical_pkg.as_deref()];
    for start in chains.into_iter().flatten() {
        let mut cur = start.parent();
        while let Some(dir) = cur {
            match dir.file_name().and_then(OsStr::to_str) {
                Some(".pnpm") => {
                    if seen_stores.insert(dir.to_path_buf()) {
                        stores.push((StoreLayout::Pnpm, dir.to_path_buf()));
                    }
                }
                Some(VLT_STORE_NAME) => {
                    if seen_stores.insert(dir.to_path_buf()) {
                        stores.push((StoreLayout::Vlt, dir.to_path_buf()));
                    }
                }
                // `.store` is npm's only when it sits in a `node_modules`.
                Some(NPM_LINKED_STORE_NAME)
                    if dir.parent().and_then(Path::file_name)
                        == Some(OsStr::new("node_modules")) =>
                {
                    if seen_stores.insert(dir.to_path_buf()) {
                        stores.push((StoreLayout::NpmLinked, dir.to_path_buf()));
                    }
                }
                Some("node_modules") => {
                    for (child, layout) in [
                        (".pnpm", StoreLayout::Pnpm),
                        (VLT_STORE_NAME, StoreLayout::Vlt),
                        (NPM_LINKED_STORE_NAME, StoreLayout::NpmLinked),
                    ] {
                        let store = dir.join(child);
                        if is_dir(&store).await && seen_stores.insert(store.clone()) {
                            stores.push((layout, store));
                        }
                    }
                }
                _ => {}
            }
            cur = dir.parent();
        }
    }
    // A pnpm store relocated by `virtualStoreDir` has no fixed name; the
    // importer's `node_modules/.modules.yaml` says where it is. Only a
    // store that holds the primary itself counts (a transitive copy, or a
    // direct dep's link target on the canonical chain): an enclosing
    // project's `.modules.yaml` further up names a store this project
    // does not use. Containment is also checked canonically, so a store
    // named through a linked ancestor (macOS `/var` → `/private/var`)
    // is kept in the same spelling as the other layouts' stores.
    let canonical_start = canonical_pkg.clone();
    let candidates: Vec<(PathBuf, PathBuf)> = chains
        .into_iter()
        .flatten()
        .flat_map(|start| {
            start
                .ancestors()
                .skip(1)
                .map(move |dir| (start.to_path_buf(), dir.join("node_modules")))
        })
        .collect();
    let relocated = run_walk(move || {
        candidates
            .iter()
            .filter_map(|(start, nm)| {
                relocated_pnpm_virtual_store_sync(nm).filter(|store| {
                    start.starts_with(store)
                        || canonical_start.as_ref().is_some_and(|canon| {
                            std::fs::canonicalize(store).is_ok_and(|s| canon.starts_with(s))
                        })
                })
            })
            .collect::<Vec<_>>()
    })
    .await;
    for store in relocated {
        if seen_stores.insert(store.clone()) {
            stores.push((StoreLayout::Pnpm, store));
        }
    }
    if stores.is_empty() {
        return Vec::new();
    }

    // 2. The primary's identity — the package.json is the authority, same
    //    as the resolver. Unreadable/invalid ⇒ no safe way to identify
    //    twins ⇒ none reported (the primary itself is still handled by
    //    the caller).
    let Some((full_name, version)) = read_package_json(&pkg_path.join("package.json")).await else {
        return Vec::new();
    };

    let mut copies: Vec<PathBuf> = Vec::new();
    let mut seen_copies: HashSet<PathBuf> = HashSet::new();
    for (layout, store) in stores {
        let entries = match layout {
            StoreLayout::Pnpm => {
                StoreEntry::pnpm(NpmCrawler::list_pnpm_store_entries(&store).await)
            }
            StoreLayout::Vlt => StoreEntry::vlt(NpmCrawler::list_vlt_store_entries(&store).await),
            StoreLayout::NpmLinked => {
                StoreEntry::npm(NpmCrawler::list_npm_store_entries(&store).await)
            }
        };
        for StoreEntry {
            advertised,
            node_modules: entry_nm,
        } in entries
        {
            // Fast advertisement filter; undecodable pnpm names stay
            // probeable, undecodable vlt ids are never variants.
            match (advertised, layout) {
                (Some((n, v)), _) if n != full_name || v != version => continue,
                (None, StoreLayout::Vlt) => continue,
                _ => {}
            }
            // `full_name` may be scoped (`@s/n`) — Path::join handles the
            // two-segment relative form.
            let candidate = entry_nm.join(&full_name);
            // Real dirs only: a link here is another entry's physical
            // copy, reached via that entry.
            let Ok(meta) = tokio::fs::symlink_metadata(&candidate).await else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            match read_package_json(&candidate.join("package.json")).await {
                Some((n, v)) if n == full_name && v == version => {}
                _ => continue,
            }
            let canon = tokio::fs::canonicalize(&candidate)
                .await
                .unwrap_or_else(|_| candidate.clone());
            if canonical_pkg.as_ref() == Some(&canon) {
                continue;
            }
            if seen_copies.insert(canon) {
                copies.push(candidate);
            }
        }
    }
    copies
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Whether every component of `dir_key` (`name` or `@scope/name`) below
/// `nm_path` is a real directory: links and junctions do not count.
fn is_real_package_dir_sync(nm_path: &Path, dir_key: &str) -> bool {
    let mut path = nm_path.to_path_buf();
    for component in dir_key.split('/') {
        path.push(component);
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            return false;
        }
    }
    true
}

/// Whether `pkg_path` is the physical dir one of `copies` resolves to.
fn resolves_to_any_sync(pkg_path: &Path, copies: &[CrawledPackage]) -> bool {
    let Ok(canon) = std::fs::canonicalize(pkg_path) else {
        return false;
    };
    copies
        .iter()
        .any(|copy| std::fs::canonicalize(&copy.path).ok().as_ref() == Some(&canon))
}

/// Whether a PURL-derived path component is safe to join onto the
/// `node_modules` root. An npm package's scope (`@types`) and bare name
/// (`node`) are each a single path segment, so a real one never contains a
/// separator, a `.`/`..` segment, a backslash, a colon, or a NUL.
/// `find_by_purls` joins these straight from the (untrusted) manifest PURL
/// onto the `node_modules` root and then patches the resolved package in
/// place, so a tampered PURL like `pkg:npm/../../evil@1.0.0` would otherwise
/// read (and later write) out of tree. Delegates to
/// [`path_safety::is_safe_single_segment`], which also rejects `:` — a
/// Windows drive-relative component (`C:evil`) joins as an absolute path.
/// Fails closed. Twin of the deno (`is_safe_jsr_component`), go, and maven
/// coordinate gates.
fn is_safe_npm_component(component: &str) -> bool {
    path_safety::is_safe_single_segment(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing_of(names: &[&str], complete: bool) -> Listing {
        Listing {
            entries: names
                .iter()
                .map(|name| ListedEntry {
                    name: OsString::from(name),
                    name_str: name.to_string(),
                    file_type: None,
                })
                .collect(),
            complete,
        }
    }

    /// A complete all-ASCII listing proves plain-ASCII absence (matched
    /// ASCII-case-insensitively), but components a filesystem may resolve
    /// to a differently spelled entry — `~` (8.3 short names), a trailing
    /// `.`/space (Win32 stripping), non-ASCII (Unicode folding) — are
    /// probed even when absent.
    #[test]
    fn probe_filter_only_skips_provably_absent_plain_ascii_names() {
        let filter = ProbeFilter::new(&listing_of(&["foo", "Bar", "@scope"], true));
        assert!(filter.may_resolve("foo"));
        assert!(filter.may_resolve("FOO"));
        assert!(filter.may_resolve("bar"));
        assert!(filter.may_resolve("@Scope"));
        assert!(!filter.may_resolve("absent"));
        assert!(!filter.may_resolve("fo"));
        for alias in [
            "FOO~1",
            "absent~2",
            "absent.",
            "absent ",
            "foo.",
            "caf\u{e9}",
            "\u{212a}elvin",
        ] {
            assert!(filter.may_resolve(alias), "{alias:?} must be probed");
        }

        // An incomplete listing, or one holding a non-ASCII name, proves
        // nothing: everything is probed.
        let partial = ProbeFilter::new(&listing_of(&["foo"], false));
        assert!(partial.may_resolve("absent"));
        let unicode = ProbeFilter::new(&listing_of(&["foo", "caf\u{e9}"], true));
        assert!(unicode.may_resolve("absent"));
    }

    fn target_of(dir_key: &str, version: &str) -> Target {
        let (namespace, name) = parse_package_name(dir_key);
        Target {
            purl: build_npm_purl(namespace.as_deref(), &name, version),
            namespace,
            name,
            version: version.to_string(),
            dir_key: dir_key.to_string(),
        }
    }

    /// A resolver visit records one entry per MATCH, not one probe slot
    /// per pending target: every dir of a BFS level holds its visit at
    /// once, so per-target slots made peak memory `dirs × targets` —
    /// hundreds of megabytes on a large pnpm store, which pass 2 enqueues
    /// whole. The match itself is unchanged: the dir name, the
    /// package.json `name` and the version must all agree.
    #[test]
    fn a_resolver_visit_records_only_the_targets_it_matched() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        for (dir, name, version) in [
            ("present", "present", "1.0.0"),
            ("other-version", "other-version", "1.0.0"),
            // An alias install: a different package under this dir name.
            ("aliased", "underlying", "1.0.0"),
        ] {
            std::fs::create_dir_all(nm.join(dir)).unwrap();
            std::fs::write(
                nm.join(dir).join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let mut pending: Vec<Target> = (0..200)
            .map(|i| target_of(&format!("absent{i}"), "1.0.0"))
            .collect();
        pending.push(target_of("other-version", "2.0.0"));
        pending.push(target_of("aliased", "1.0.0"));
        pending.push(target_of("present", "1.0.0"));
        let matched_index = pending.len() - 1;

        let visit = NpmCrawler::visit_resolver_dir(nm, false, &pending);
        assert_eq!(visit.matched, vec![matched_index]);
    }

    #[test]
    fn test_parse_package_name_scoped() {
        let (ns, name) = parse_package_name("@types/node");
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
    }

    #[test]
    fn test_parse_package_name_unscoped() {
        let (ns, name) = parse_package_name("lodash");
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
    }

    #[test]
    fn test_build_npm_purl_scoped() {
        assert_eq!(
            build_npm_purl(Some("@types"), "node", "20.0.0"),
            "pkg:npm/@types/node@20.0.0"
        );
    }

    #[test]
    fn test_build_npm_purl_unscoped() {
        assert_eq!(
            build_npm_purl(None, "lodash", "4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn test_parse_purl_components_scoped() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0").unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[test]
    fn test_parse_purl_components_unscoped() {
        let (ns, name, ver) = NpmCrawler::parse_purl_components("pkg:npm/lodash@4.17.21").unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn test_parse_purl_components_invalid() {
        assert!(NpmCrawler::parse_purl_components("pkg:pypi/requests@2.0").is_none());
        assert!(NpmCrawler::parse_purl_components("not-a-purl").is_none());
    }

    /// The `?qualifier` is stripped *before* `rfind('@')` splits the
    /// version, so an `@` living inside a qualifier value
    /// (`vcs_url=git@github.com:...`) must not be mistaken for the
    /// version separator. Reordering those two steps would parse the
    /// version as `github.com:...` and break apply/rollback for any
    /// PURL whose qualifier carries an `@`.
    #[test]
    fn test_parse_purl_components_qualifier_with_at_sign() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0?vcs_url=git@github.com:x/y.git")
                .unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");

        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0?maintainer=a@b.com")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_valid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#)
            .await
            .unwrap();

        let result = read_package_json(&pkg_json).await;
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "test-pkg");
        assert_eq!(version, "1.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_missing() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_read_package_json_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, "not json").await.unwrap();
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_basic() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let pkg_dir = nm.join("foo");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.2.3"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.2.3");
        assert_eq!(packages[0].purl, "pkg:npm/foo@1.2.3");
        assert!(packages[0].namespace.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let scope_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&scope_dir).await.unwrap();
        tokio::fs::write(
            scope_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "node");
        assert_eq!(packages[0].namespace.as_deref(), Some("@types"));
        assert_eq!(packages[0].purl, "pkg:npm/@types/node@20.0.0");
    }

    #[test]
    fn test_find_node_dirs_sync_wildcard() {
        // Create an nvm-like layout: base/v18.0.0/lib/node_modules
        let dir = tempfile::tempdir().unwrap();
        let nm1 = dir.path().join("v18.0.0/lib/node_modules");
        let nm2 = dir.path().join("v20.1.0/lib/node_modules");
        std::fs::create_dir_all(&nm1).unwrap();
        std::fs::create_dir_all(&nm2).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["*", "lib", "node_modules"]);
        assert_eq!(results.len(), 2);
        assert!(results.contains(&nm1));
        assert!(results.contains(&nm2));
    }

    #[test]
    fn test_find_node_dirs_sync_empty() {
        // Non-existent base path should return empty
        let results = find_node_dirs_sync(Path::new("/nonexistent/path/xyz"), &["*", "lib"]);
        assert!(results.is_empty());
    }

    /// Regression: a wildcard segment that matches a *symlinked*
    /// directory must be followed. `DirEntry::metadata()` stats the link
    /// itself (reports `is_dir == false`), so the resolver previously
    /// skipped symlinked version dirs — exactly the layout fnm produces
    /// and the `current`/`default` aliases nvm creates. The fix stats the
    /// joined path with `std::fs::metadata`, which resolves the target.
    #[cfg(unix)]
    #[test]
    fn test_find_node_dirs_sync_follows_symlinked_segment() {
        use std::os::unix::fs::symlink;

        // Real version layout lives in its own tree, away from `base`,
        // so the only way to reach it is through the symlink.
        let real = tempfile::tempdir().unwrap();
        let real_nm = real.path().join("lib").join("node_modules");
        std::fs::create_dir_all(&real_nm).unwrap();

        // `base` holds only a symlink standing in for a version dir.
        let base = tempfile::tempdir().unwrap();
        let alias = base.path().join("current");
        symlink(real.path(), &alias).unwrap();

        let results = find_node_dirs_sync(base.path(), &["*", "lib", "node_modules"]);
        assert_eq!(
            results.len(),
            1,
            "a symlinked version dir must be followed, not skipped"
        );
        assert_eq!(results[0], alias.join("lib").join("node_modules"));
    }

    #[test]
    fn test_find_node_dirs_sync_literal() {
        // All literal segments (no wildcard)
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lib/node_modules");
        std::fs::create_dir_all(&target).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["lib", "node_modules"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], target);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_get_global_node_modules_paths_no_panic() {
        let crawler = NpmCrawler::new();
        // Should not panic, even if no package managers are installed
        let _paths = crawler.get_global_node_modules_paths();
    }

    #[tokio::test]
    async fn test_find_by_purls() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Create foo@1.0.0
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Create @types/node@20.0.0
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/foo@1.0.0".to_string(),
            "pkg:npm/@types/node@20.0.0".to_string(),
            "pkg:npm/not-installed@0.0.1".to_string(),
        ];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(result.contains_key("pkg:npm/@types/node@20.0.0"));
        assert!(!result.contains_key("pkg:npm/not-installed@0.0.1"));
    }

    /// Regression: the patches API serves scoped purls percent-encoded
    /// (`pkg:npm/%40scope/name@version`) and `scan` stores them verbatim as
    /// manifest keys. `find_by_purls` must decode the components to match
    /// the literal `node_modules/@scope/name` install — while keeping the
    /// result keyed by the *verbatim* encoded input (downstream contract).
    #[test]
    fn test_parse_purl_components_percent_encoded_scope() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/%40modelcontextprotocol/sdk@1.12.0")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@modelcontextprotocol"));
        assert_eq!(name, "sdk");
        assert_eq!(ver, "1.12.0");
        // An encoded bare scope with no `/name` is still not a package.
        assert!(NpmCrawler::parse_purl_components("pkg:npm/%40scope@1.0.0").is_none());
        // A `#subpath` without a qualifier must not bleed into the version.
        let (_, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0#lib/util").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");
    }

    #[tokio::test]
    async fn test_find_by_purls_percent_encoded_scope_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let sdk_dir = nm.join("@modelcontextprotocol").join("sdk");
        tokio::fs::create_dir_all(&sdk_dir).await.unwrap();
        tokio::fs::write(
            sdk_dir.join("package.json"),
            r#"{"name": "@modelcontextprotocol/sdk", "version": "1.12.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let encoded = "pkg:npm/%40modelcontextprotocol/sdk@1.12.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&encoded))
            .await
            .unwrap();

        assert_eq!(result.len(), 1, "encoded scope must resolve: {result:?}");
        let pkg = &result
            .get(&encoded)
            .expect("result keyed by the verbatim encoded input purl")[0];
        assert_eq!(pkg.path, sdk_dir);
        assert_eq!(pkg.name, "sdk");
        assert_eq!(pkg.namespace.as_deref(), Some("@modelcontextprotocol"));
    }

    /// SECURITY regression: percent-encoded traversal sequences must be
    /// rejected by the post-decode guards — `%2e%2e` decodes to `..` and
    /// `%2f` to `/`, so guarding the *encoded* form would be a bypass.
    #[tokio::test]
    async fn test_find_by_purls_rejects_encoded_traversal() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so a scoped traversal's kernel walk could resolve.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        // A victim package OUTSIDE node_modules, reachable only via `..`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/%2e%2e/evil@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e%2f%2e%2e%2fevil@1.0.0".to_string(),
            "pkg:npm/..%2fevil@1.0.0".to_string(),
        ];
        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert!(
            result.is_empty(),
            "encoded traversal must not escape node_modules; got {result:?}"
        );
    }

    /// Regression: a qualified PURL (carrying `?qualifiers`) must resolve and
    /// be keyed by the *verbatim* input PURL — not a reconstructed, stripped
    /// form. The dispatcher drives npm with `passthrough_purls` +
    /// `merge_first_wins`, so it looks the result back up under the exact PURL
    /// it passed in. Keying by the stripped PURL silently dropped every
    /// qualified npm PURL from apply/rollback.
    #[tokio::test]
    async fn test_find_by_purls_resolves_qualified_purl_keyed_by_input() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Scoped package with a qualifier too.
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let unscoped_q = "pkg:npm/foo@1.0.0?vcs_url=https://github.com/x/foo".to_string();
        let scoped_q = "pkg:npm/@types/node@20.0.0?repository_url=https://npmjs.org".to_string();
        let purls = vec![unscoped_q.clone(), scoped_q.clone()];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        // Keyed by the verbatim qualified input, and the stored PURL matches.
        let foo = &result
            .get(&unscoped_q)
            .expect("qualified unscoped resolved")[0];
        assert_eq!(foo.purl, unscoped_q);
        assert_eq!(foo.name, "foo");
        assert_eq!(foo.version, "1.0.0");

        let node = &result.get(&scoped_q).expect("qualified scoped resolved")[0];
        assert_eq!(node.purl, scoped_q);
        assert_eq!(node.namespace.as_deref(), Some("@types"));
        assert_eq!(node.name, "node");
    }

    /// Two distinct qualifiers over the same base package must each resolve
    /// to their own entry (the dispatcher passes them through verbatim).
    #[tokio::test]
    async fn test_find_by_purls_distinct_qualifiers_same_base() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let q1 = "pkg:npm/foo@1.0.0?a=1".to_string();
        let q2 = "pkg:npm/foo@1.0.0?b=2".to_string();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(&nm, &[q1.clone(), q2.clone()])
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&q1).unwrap()[0].path, foo_dir);
        assert_eq!(result.get(&q2).unwrap()[0].path, foo_dir);
    }

    /// SECURITY regression: a tampered manifest PURL whose *name* carries a
    /// `..` traversal must not let `find_by_purls` resolve a package outside
    /// the `node_modules` root. The crawler joins the PURL-derived directory
    /// key straight onto `node_modules_path` and the resolved path is then
    /// patched in place, so an unguarded join would read (and later write)
    /// out of tree. Twin of the deno/go/maven `is_safe_*_coordinate` gates.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_in_name() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        tokio::fs::create_dir_all(&nm).await.unwrap();

        // A victim package living OUTSIDE node_modules, reachable only via
        // `..`. `node_modules/../evil` == `<root>/evil`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` in the PURL name must not escape node_modules; got {result:?}"
        );
    }

    /// SECURITY regression: a `..` smuggled through the *name* half of a
    /// scoped PURL must also be rejected. `@x/../../evil` parses to scope
    /// `@x` + name `../../evil`; with a real `@x` dir on disk for the kernel
    /// to walk, the join climbs clean out of node_modules to `<root>/evil`.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_via_scope() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so the kernel can resolve the leading `@x` before
        // the `..` segments climb — otherwise the walk would ENOENT and the
        // test would pass vacuously.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/@x/../../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` smuggled through the scope must not escape node_modules; got {result:?}"
        );
    }

    #[test]
    fn test_is_safe_npm_component() {
        // Legitimate components.
        assert!(is_safe_npm_component("lodash"));
        assert!(is_safe_npm_component("@types"));
        assert!(is_safe_npm_component("node"));
        assert!(is_safe_npm_component("some.pkg"));

        // Traversal / separator / NUL / empty.
        assert!(!is_safe_npm_component(""));
        assert!(!is_safe_npm_component("."));
        assert!(!is_safe_npm_component(".."));
        assert!(!is_safe_npm_component("../evil"));
        assert!(!is_safe_npm_component("a/b"));
        assert!(!is_safe_npm_component("a\\b"));
        assert!(!is_safe_npm_component("a\0b"));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`.
        assert!(!is_safe_npm_component("C:evil"));
        assert!(!is_safe_npm_component("c:"));
    }

    // ── decode_pnpm_store_entry_name ───────────────────────────────

    /// Helper: decode and unwrap into owned strings for terse asserts.
    fn decoded(entry: &str) -> Option<(String, String)> {
        decode_pnpm_store_entry_name(entry)
    }

    #[test]
    fn test_decode_pnpm_store_entry_plain() {
        assert_eq!(
            decoded("mkdirp@0.5.5"),
            Some(("mkdirp".into(), "0.5.5".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_scoped_plus_escape() {
        assert_eq!(
            decoded("@scope+leaf@2.0.0"),
            Some(("@scope/leaf".into(), "2.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_v9_peer_parens() {
        // Single and stacked peer suffixes, including a scoped peer whose
        // own name carries `@`/`+` — everything from the first `(` goes.
        assert_eq!(
            decoded("foo@1.0.0(bar@2.0.0)"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("foo@1.0.0(bar@2.0.0)(@babel+core@7.21.0)"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("@scope+leaf@2.0.0(@peer+dep@3.0.0)"),
            Some(("@scope/leaf".into(), "2.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_legacy_underscore_suffix() {
        // pnpm 6–8 peer suffix — everything from the first `_` goes, even
        // when the suffix itself carries `@version` fragments that would
        // otherwise confuse the rfind('@') split.
        assert_eq!(
            decoded("foo@1.0.0_bar@2.0.0"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("@scope+name@1.0.0_@peer+dep@2.0.0"),
            Some(("@scope/name".into(), "1.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_prerelease_version() {
        assert_eq!(
            decoded("foo@1.0.0-rc.1(bar@2.0.0)"),
            Some(("foo".into(), "1.0.0-rc.1".into()))
        );
    }

    /// pnpm truncates over-long dir names ANYWHERE and appends `_<hash>`.
    /// A cut mid-name leaves no `@X.Y.Z` tail → None (conservative: the
    /// entry stays probeable). A cut that lands after a `name@X.Y.Z`
    /// prefix is an undetectable artifact — it decodes, pinned here so
    /// the contract ("decoded is advisory, probe is authority") is
    /// explicit. A cut mid-version (`@1.2`) fails the semver-triple
    /// check → None.
    #[test]
    fn test_decode_pnpm_store_entry_truncation_hash_tail() {
        assert_eq!(decoded("some-truncated-name-prefix_abc123def456"), None);
        assert_eq!(decoded("foo@1.2_abc123def456"), None);
        assert_eq!(
            decoded("foo@1.2.3_abc123def456"),
            Some(("foo".into(), "1.2.3".into())),
            "truncation after a full name@X.Y.Z prefix is indistinguishable \
             from a legacy peer suffix — decodes, and that is acceptable \
             because the package.json probe stays the authority"
        );
    }

    /// Names that are not registry package entries at all.
    #[test]
    fn test_decode_pnpm_store_entry_non_package_names() {
        // Store metadata file.
        assert_eq!(decoded("lock.yaml"), None);
        // The internal hoist dir (also skipped by the enumerator).
        assert_eq!(decoded("node_modules"), None);
        // No version at all.
        assert_eq!(decoded("foo"), None);
        // Empty name half.
        assert_eq!(decoded("@1.0.0"), None);
        // Empty version half.
        assert_eq!(decoded("foo@"), None);
    }

    /// A real npm name containing `_` is indistinguishable from a legacy
    /// peer suffix, so it must fall to the conservative None (the entry
    /// stays reachable via the fallback rule).
    #[test]
    fn test_decode_pnpm_store_entry_underscore_name_falls_back() {
        assert_eq!(decoded("lodash._baseclone@1.0.0"), None);
    }

    /// Git/URL dependency entries carry a sha or URL fragment where the
    /// version would be — not a semver triple → None → still probeable.
    #[test]
    fn test_decode_pnpm_store_entry_git_url_deps_fall_back() {
        assert_eq!(decoded("foo@github.com+user+repo@4a3b2c1d9e8f"), None);
        assert_eq!(
            decoded("foo@https+++codeload.github.com+x+tar.gz+abc"),
            None
        );
    }

    /// A PURL whose version is not the one on disk must be skipped, while a
    /// sibling PURL for the installed version is kept.
    #[tokio::test]
    async fn test_find_by_purls_skips_absent_version_keeps_present() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(
                &nm,
                &[
                    "pkg:npm/foo@1.0.0".to_string(),
                    "pkg:npm/foo@9.9.9".to_string(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(!result.contains_key("pkg:npm/foo@9.9.9"));
    }

    /// Multi-copy P0: two REAL on-disk copies of the SAME `name@version`
    /// (a root/hoisted copy and a nested duplicate) must BOTH be returned
    /// under the one PURL, root-copy-first. Returning only the root copy is
    /// the silent partial that leaves a live vulnerable copy on disk.
    #[tokio::test]
    async fn test_find_by_purls_returns_every_copy_root_first() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Root/hoisted copy.
        let root_copy = nm.join("dup");
        tokio::fs::create_dir_all(&root_copy).await.unwrap();
        tokio::fs::write(
            root_copy.join("package.json"),
            r#"{"name": "dup", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Nested duplicate under another package (npm's conflict-nesting).
        let nested_copy = nm.join("parent").join("node_modules").join("dup");
        tokio::fs::create_dir_all(&nested_copy).await.unwrap();
        tokio::fs::write(
            nested_copy.join("package.json"),
            r#"{"name": "dup", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(
            nm.join("parent").join("package.json"),
            r#"{"name": "parent", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purl = "pkg:npm/dup@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();

        let copies = result.get(&purl).expect("dup must resolve");
        assert_eq!(
            copies.len(),
            2,
            "both physical copies must be returned; got {copies:?}"
        );
        // Root-copy-first ordering (breadth-first): callers needing one
        // representative take [0] and keep the old root-preference.
        assert_eq!(copies[0].path, root_copy, "root copy must be first");
        let paths: HashSet<&Path> = copies.iter().map(|c| c.path.as_path()).collect();
        assert!(paths.contains(root_copy.as_path()));
        assert!(paths.contains(nested_copy.as_path()));
    }

    /// A single (non-duplicated) install resolves to a one-element Vec — the
    /// common case must not regress into a spurious duplicate.
    #[tokio::test]
    async fn test_find_by_purls_single_copy_is_one_element() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo = nm.join("solo");
        tokio::fs::create_dir_all(&foo).await.unwrap();
        tokio::fs::write(
            foo.join("package.json"),
            r#"{"name": "solo", "version": "2.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purl = "pkg:npm/solo@2.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        let copies = result.get(&purl).expect("solo must resolve");
        assert_eq!(copies.len(), 1, "single install must be one copy");
        assert_eq!(copies[0].path, foo);
    }

    /// The `NESTED_STORE_MAX_DIRS` cap must terminate a nested-store
    /// descent over a corrupted/adversarial tree instead of turning it
    /// into an unbounded readdir storm. Stages one more child than the
    /// cap (each shaped as a depth-1 package home so every one passes the
    /// filters and consumes cap budget) and pins that the walk stops at
    /// exactly the cap — failing toward "not installed", never patching
    /// the wrong package. Deliberately does NOT assert WHICH entries
    /// survive: readdir order is unspecified. (~16.4k staged dirs; a
    /// couple of seconds of mkdir churn is the price of firing the cap.)
    #[tokio::test]
    async fn test_collect_nested_store_entries_respects_dir_cap() {
        let host = tempfile::tempdir().unwrap();
        let over = NESTED_STORE_MAX_DIRS + 16;
        for i in 0..over {
            std::fs::create_dir_all(host.path().join(format!("d{i:05}")).join("node_modules"))
                .unwrap();
        }

        let mut entries = Vec::new();
        NpmCrawler::collect_nested_store_entries(host.path(), &mut entries).await;

        assert_eq!(
            entries.len(),
            NESTED_STORE_MAX_DIRS,
            "the walk must stop at exactly the dir cap"
        );
        // Every yielded entry is a real staged package home.
        for (name, nm) in &entries {
            assert!(name.starts_with('d'), "unexpected entry name {name:?}");
            assert_eq!(nm, &host.path().join(name).join("node_modules"));
        }
    }

    /// Save and restore an env var around a test body (drop-safe).
    #[cfg(target_os = "macos")]
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    #[cfg(target_os = "macos")]
    impl EnvGuard {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }
    #[cfg(target_os = "macos")]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Pins the literal volta (`.volta/tools/image/node/*/lib/
    /// node_modules`) and fnm (`.fnm/node-versions/*/installation/lib/
    /// node_modules`) global-install layouts on macOS — the nvm sibling
    /// loop is exercised on any nvm-carrying host, but nothing pins these
    /// two unless the dev machine happens to have the tools installed.
    /// `HOME` is process-global, hence `serial` + guard.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn test_macos_global_paths_pick_up_volta_and_fnm_layouts() {
        let home = tempfile::tempdir().unwrap();
        let volta_nm = home
            .path()
            .join(".volta/tools/image/node/v20.0.0/lib/node_modules");
        let fnm_nm = home
            .path()
            .join(".fnm/node-versions/v20.0.0/installation/lib/node_modules");
        std::fs::create_dir_all(&volta_nm).unwrap();
        std::fs::create_dir_all(&fnm_nm).unwrap();

        let _home_guard = EnvGuard::set("HOME", home.path().as_os_str());
        let paths = NpmCrawler::new().get_global_node_modules_paths();

        // `contains`, not equality: host npm/nvm/homebrew paths may also
        // appear.
        assert!(
            paths.contains(&volta_nm),
            "volta layout must be discovered under $HOME; got {paths:?}"
        );
        assert!(
            paths.contains(&fnm_nm),
            "fnm layout must be discovered under $HOME; got {paths:?}"
        );
    }

    /// The workspace roots walk is iterative: a directory chain far deeper
    /// than a small stack can recurse through completes on walk threads
    /// with only 256 KiB of stack (the recursive walk overflowed there),
    /// and still yields depth-first order — each dir's `node_modules`
    /// before anything below it.
    #[test]
    fn test_workspace_walk_deep_chain_small_stack() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        // Stay well inside macOS's 1024-byte PATH_MAX.
        let depth = 400.min(900usize.saturating_sub(root.as_os_str().len()) / 2);
        assert!(depth >= 200, "temp dir path too long: {}", root.display());

        let mut expected = vec![root.join("node_modules")];
        let mut chain = root.clone();
        for level in 1..=depth {
            chain.push("a");
            if level == depth / 2 || level == depth {
                expected.push(chain.join("node_modules"));
            }
        }
        std::fs::create_dir_all(&chain).unwrap();
        for nm in &expected {
            std::fs::create_dir_all(nm).unwrap();
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .stack_size(256 * 1024)
            .build()
            .unwrap();
        let found = pool.install(|| NpmCrawler::find_local_node_modules_dirs(&root));
        assert_eq!(found, expected);
    }

    /// A directory carrying a signed `CACHEDIR.TAG` (a cargo `target/`, a
    /// tool cache) is pruned from the workspace roots walk whole: its own
    /// `node_modules` and every workspace below it. An untagged sibling,
    /// the scan root itself, and a tag that is not a valid one (no
    /// signature, a directory, a symlink) prune nothing.
    #[tokio::test]
    async fn test_workspace_walk_prunes_tagged_cache_dirs() {
        const TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n# a cache\n";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let nm = |rel: &str| {
            let path = root.join(rel).join("node_modules");
            std::fs::create_dir_all(&path).unwrap();
            path
        };
        // The scan root is tagged too: it is still scanned.
        std::fs::write(root.join("CACHEDIR.TAG"), TAG).unwrap();
        let root_nm = nm("");
        let app = nm("apps/web");
        // Pruned: the tagged dir's own node_modules and everything below.
        nm("target");
        nm("target/debug/deps/pkg");
        std::fs::write(root.join("target/CACHEDIR.TAG"), TAG).unwrap();
        nm("apps/web/cache");
        nm("apps/web/cache/deep/ws");
        std::fs::write(root.join("apps/web/cache/CACHEDIR.TAG"), TAG).unwrap();
        // Not tags: kept.
        let unsigned = nm("libs/unsigned");
        std::fs::write(root.join("libs/unsigned/CACHEDIR.TAG"), b"not a tag\n").unwrap();
        let short = nm("libs/short");
        std::fs::write(root.join("libs/short/CACHEDIR.TAG"), &TAG[..10]).unwrap();
        let as_dir = nm("libs/as-dir");
        std::fs::create_dir_all(root.join("libs/as-dir/CACHEDIR.TAG")).unwrap();
        #[cfg(unix)]
        let linked = {
            let linked = nm("libs/linked");
            std::fs::write(root.join("real.tag"), TAG).unwrap();
            std::os::unix::fs::symlink(
                root.join("real.tag"),
                root.join("libs/linked/CACHEDIR.TAG"),
            )
            .unwrap();
            linked
        };

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let mut found = NpmCrawler::new()
            .get_node_modules_paths(&options)
            .await
            .unwrap();
        found.sort();
        let mut want = vec![root_nm, app, unsigned, short, as_dir];
        #[cfg(unix)]
        want.push(linked);
        want.sort();
        assert_eq!(found, want);

        // Removing the tag un-prunes the directory.
        std::fs::remove_file(root.join("target/CACHEDIR.TAG")).unwrap();
        let found = NpmCrawler::new()
            .get_node_modules_paths(&options)
            .await
            .unwrap();
        assert!(
            found.contains(&root.join("target/node_modules")),
            "{found:?}"
        );
        assert!(
            found.contains(&root.join("target/debug/deps/pkg/node_modules")),
            "{found:?}"
        );
    }
    /// and undecodable ids are `None` (still probed by package.json).
    #[test]
    fn test_decode_vlt_dep_id_table() {
        let some = |n: &str, v: &str| Some((n.to_string(), v.to_string()));
        let rows: &[(&str, Option<(String, String)>)] = &[
            ("··ms@2.1.3", some("ms", "2.1.3")),
            (
                "·npm·@isaacs§string-locale-compare@1.1.0",
                some("@isaacs/string-locale-compare", "1.1.0"),
            ),
            (
                "··@sindresorhus§is@4.6.0",
                some("@sindresorhus/is", "4.6.0"),
            ),
            ("·npm·u@1.0.0%2Bbuild.1", some("u", "1.0.0+build.1")),
            (
                "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
                some("ms", "2.1.3"),
            ),
            ("·npm·x@1.0.0·%E1%B9%97%3A3", some("x", "1.0.0")),
            ("~npm~@a+b@1.0.0", some("@a/b", "1.0.0")),
            ("~npm~a__b@1.0.0", some("a_b", "1.0.0")),
            ("~npm~u@1.0.0_pbuild.1", some("u", "1.0.0+build.1")),
            (
                "~npm~is-number@6.0.0~_croot_s_g_s#to-regex-range_s_g_s#is-number",
                some("is-number", "6.0.0"),
            ),
            (
                "~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
                some("react-dom", "18.2.0"),
            ),
            ("~npm~x@1.0.0~peer.2", some("x", "1.0.0")),
            ("~npm~x@1~peer.2", None),
            ("~acme~left-pad@1.3.0", some("left-pad", "1.3.0")),
            ("~http_c++127.0.0.1_c4873+~x@1.0.0", some("x", "1.0.0")),
            ("·http%3A§§127.0.0.1%3A4873§·x@1.0.0", some("x", "1.0.0")),
            (
                "~jsr~@jsr+std____semver@1.0.8",
                some("@jsr/std__semver", "1.0.8"),
            ),
            ("git~github_cisaacs+string-locale-compare~v1.1.0", None),
            ("git·github%3Aisaacs§string-locale-compare·v1.1.0", None),
            ("file~vendor+ms-2.1.2.tgz", None),
            ("file·vendor§ms-2.1.2.tgz", None),
            (
                "remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.2.0.tgz",
                None,
            ),
            ("workspace~packages+a", None),
            ("workspace·packages§a", None),
            ("··m%ZZs@1.0.0", None),
            ("·npm·ms@2.1.3·%4", None),
            ("ms@2.1.3", None),
            ("node_modules", None),
        ];
        for (id, want) in rows {
            assert_eq!(&decode_vlt_store_entry_name(OsStr::new(id)), want, "{id}");
        }
    }

    /// The hazard the separate decoders exist for: the pnpm decoder reads
    /// legacy vlt names as packages named `··foo` / `·npm·@s§p`, so a vlt
    /// entry run through it would be skipped by the pending-name filter.
    /// vlt entries are advertised through the vlt decoder only.
    #[test]
    fn test_vlt_store_entries_never_reach_the_pnpm_decoder() {
        assert_eq!(
            decode_pnpm_store_entry_name("··foo@1.0.0"),
            Some(("··foo".to_string(), "1.0.0".to_string()))
        );
        let entries = || {
            vec![
                (OsString::from("··foo@1.0.0"), PathBuf::from("a")),
                (OsString::from("·npm·@s§p@2.0.0"), PathBuf::from("b")),
                (OsString::from("~npm~@s+p@2.0.0~peer.1"), PathBuf::from("c")),
            ]
        };
        let pending: HashSet<&str> = ["foo", "@s/p"].into_iter().collect();
        assert_eq!(
            NpmCrawler::pending_store_entries(StoreEntry::vlt(entries()), Some(&pending)),
            vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")]
        );
        let as_pnpm = entries()
            .into_iter()
            .map(|(n, p)| (n.into_string().unwrap(), p))
            .collect();
        assert!(
            !NpmCrawler::pending_store_entries(StoreEntry::pnpm(as_pnpm), Some(&pending))
                .contains(&PathBuf::from("a")),
            "the pnpm decoder misreads the legacy name"
        );
    }

    #[test]
    fn test_vlt_store_is_not_a_legacy_pnpm_store() {
        for name in [".vlt", ".vlt-lock.json", ".VLT.DELETE.1.~npm~a@1.0.0"] {
            assert!(!is_legacy_pnpm_store_dir_name(name), "{name}");
        }
    }

    /// `list_vlt_store_entries` yields only real entry dirs with a real
    /// `node_modules`, keeping the raw (legacy `·`/`§`) names.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_list_vlt_store_entries_skips_hoist_meta_links_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join(".vlt");
        for dir in [
            "··ms@2.1.3/node_modules/ms",
            "~npm~a@1.0.0/node_modules/a",
            "node_modules/@scope",
            "node_modules/node_modules/hoist-decoy",
            ".VLT.DELETE.9.~npm~b@1.0.0/node_modules/b",
            "~npm~no-nm@1.0.0/no-nm",
            "elsewhere/node_modules",
            "~npm~nm-link@1.0.0",
        ] {
            std::fs::create_dir_all(store.join(dir)).unwrap();
        }
        std::fs::write(store.join("vlt.json"), "{}").unwrap();
        std::os::unix::fs::symlink(store.join("~npm~a@1.0.0"), store.join("~npm~linked@1.0.0"))
            .unwrap();
        std::os::unix::fs::symlink(
            store.join("elsewhere/node_modules"),
            store.join("~npm~nm-link@1.0.0/node_modules"),
        )
        .unwrap();

        let mut got: Vec<(OsString, PathBuf)> = NpmCrawler::list_vlt_store_entries(&store).await;
        got.sort();
        assert_eq!(
            got,
            vec![
                (
                    OsString::from("elsewhere"),
                    store.join("elsewhere/node_modules")
                ),
                (
                    OsString::from("~npm~a@1.0.0"),
                    store.join("~npm~a@1.0.0/node_modules")
                ),
                (
                    OsString::from("··ms@2.1.3"),
                    store.join("··ms@2.1.3/node_modules")
                ),
            ]
        );
    }

    fn write_pkg(dir: &Path, name: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    /// A directory link the way vlt writes it: a symlink on Unix, an
    /// absolute-target NTFS junction on Windows (vlt >= 1.0.0-rc.22).
    fn link_dir(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        {
            // Rebuilt from components so every separator is `\`: `mklink`
            // reads a `/` inside a path (`a@1/node_modules/b`) as a switch.
            let link: PathBuf = link.components().collect();
            let target: PathBuf = target.components().collect();
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .status()
                .unwrap();
            assert!(status.success(), "mklink /J failed");
        }
    }

    /// A small vlt tree on the host's own link kind (junctions on Windows):
    /// the importer link resolves at the importer root, a dependency link
    /// inside a store entry is an edge (never a second inventory entry),
    /// the legacy `·npm·@scope§bar@2.0.0` name round-trips through the
    /// filesystem, and the fan-out finds the peer twin from the link.
    #[tokio::test]
    async fn test_vlt_store_links_are_edges_on_every_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".vlt");
        let bar = store
            .join("·npm·@scope§bar@2.0.0")
            .join("node_modules")
            .join("@scope")
            .join("bar");
        write_pkg(&bar, "@scope/bar", "2.0.0");
        let foo_entry = store.join("~npm~foo@1.0.0~peer.2").join("node_modules");
        write_pkg(&foo_entry.join("foo"), "foo", "1.0.0");
        std::fs::create_dir_all(foo_entry.join("@scope")).unwrap();
        link_dir(&bar, &foo_entry.join("@scope").join("bar"));
        let twin = store
            .join("~npm~foo@1.0.0~peer.3")
            .join("node_modules")
            .join("foo");
        write_pkg(&twin, "foo", "1.0.0");
        link_dir(&foo_entry.join("foo"), &nm.join("foo"));

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let mut scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| (p.purl, p.path))
            .collect();
        scanned.sort();
        assert_eq!(
            scanned,
            vec![
                ("pkg:npm/@scope/bar@2.0.0".to_string(), bar.clone()),
                ("pkg:npm/foo@1.0.0".to_string(), nm.join("foo")),
            ]
        );

        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/foo@1.0.0".to_string()])
            .await
            .unwrap();
        let primary = &found["pkg:npm/foo@1.0.0"][0].path;
        assert_eq!(primary, &nm.join("foo"));
        assert_eq!(find_store_peer_variant_copies(primary).await, vec![twin]);
    }

    /// vlt fan-out gates: every real copy whose DepID decodes to the
    /// primary's `name@version` (peer counters, hashed peers, modifier
    /// extras, the legacy `··`/`·npm·` pair) is returned once; the primary,
    /// dependency links, the hoist dir, rollback staging, an imposter
    /// package.json and git/remote/file ids (distinct artifacts, not
    /// variants) are not.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_store_peer_variant_copies_vlt_gates() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let store = nm.join(".vlt");
        let copy = |id: &str| store.join(id).join("node_modules").join("foo");
        let primary = copy("~npm~foo@1.0.0~peer.2");
        let twins = [
            copy("~npm~foo@1.0.0~peer.3"),
            copy("~npm~foo@1.0.0~peer.dbd5ca8b03a66489"),
            copy("~npm~foo@1.0.0~_croot_s_g_s#foo"),
            copy("··foo@1.0.0"),
            copy("·npm·foo@1.0.0"),
        ];
        for dir in std::iter::once(&primary).chain(&twins) {
            write_pkg(dir, "foo", "1.0.0");
        }
        for id in [
            "git~github_cu+foo~v1.0.0",
            "remote~https_c++e.com+foo-1.0.0.tgz",
            "file~vendor+foo-1.0.0.tgz",
            ".VLT.DELETE.1.~npm~foo@1.0.0",
        ] {
            write_pkg(&copy(id), "foo", "1.0.0");
        }
        write_pkg(&copy("~npm~foo@1.0.0~peer.9"), "foo", "1.0.1");
        write_pkg(&store.join("node_modules/foo"), "foo", "1.0.0");
        let dependent = store.join("~npm~dep@1.0.0/node_modules");
        write_pkg(&dependent.join("dep"), "dep", "1.0.0");
        std::os::unix::fs::symlink(&twins[0], dependent.join("foo")).unwrap();
        std::os::unix::fs::symlink(&primary, nm.join("foo")).unwrap();

        for start in [primary.clone(), nm.join("foo")] {
            let mut got = find_store_peer_variant_copies(&start).await;
            got.sort();
            let mut want = twins.to_vec();
            want.sort();
            assert_eq!(got, want, "from {}", start.display());
        }
    }

    /// D19: a vendored copy's `.socket/vendor/npm/<uuid>/<leaf>/node_modules`
    /// is never a crawl root (hidden dirs are skipped), so the only
    /// inventory entry is the importer link that points at it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_socket_vendor_node_modules_is_never_crawled() {
        let tmp = tempfile::tempdir().unwrap();
        let vendored = tmp.path().join(
            ".socket/vendor/npm/0b6f8a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b/left-pad-1.3.0/node_modules/left-pad",
        );
        write_pkg(&vendored, "left-pad", "1.3.0");
        write_pkg(&vendored.join("node_modules/inner"), "inner", "1.0.0");
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join(".vlt")).unwrap();
        std::os::unix::fs::symlink(&vendored, nm.join("left-pad")).unwrap();
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        assert_eq!(
            NpmCrawler::new()
                .get_node_modules_paths(&options)
                .await
                .unwrap(),
            vec![nm.clone()]
        );
        let scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| (p.purl, p.path))
            .collect();
        assert_eq!(
            scanned,
            vec![("pkg:npm/left-pad@1.3.0".to_string(), nm.join("left-pad"))]
        );
    }

    fn scan_paths(root: &Path) -> impl std::future::Future<Output = Vec<(String, PathBuf)>> {
        let options = CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: None,
        };
        async move {
            let mut scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
                .crawl_all(&options)
                .await
                .into_iter()
                .map(|p| (p.purl, p.path))
                .collect();
            scanned.sort();
            scanned
        }
    }

    #[test]
    fn test_decode_npm_store_entry_name() {
        let hash = "Pqc5my552wJdjE6sp0MCIg";
        assert_eq!(
            decode_npm_store_entry_name(&format!("is-number@6.0.0-{hash}")),
            Some(("is-number".to_string(), "6.0.0".to_string()))
        );
        // The hash is base64url, so it can hold `-` and `_` itself.
        assert_eq!(
            decode_npm_store_entry_name("escape-string-regexp@1.0.5-YUOzcg-PmWvuNTSNPuN4qw"),
            Some(("escape-string-regexp".to_string(), "1.0.5".to_string()))
        );
        assert_eq!(
            decode_npm_store_entry_name(&format!("@babel/code-frame@7.0.0-beta.1-{hash}")),
            Some(("@babel/code-frame".to_string(), "7.0.0-beta.1".to_string()))
        );
        // A shrinkwrapped dependency's un-hashed `name@version` dir, a
        // missing hash, and a non-semver version stay undecodable.
        assert_eq!(decode_npm_store_entry_name("foo@1.0.0"), None);
        assert_eq!(decode_npm_store_entry_name(&format!("foo-{hash}")), None);
        assert_eq!(
            decode_npm_store_entry_name(&format!("foo@abc-{hash}")),
            None
        );
        assert_eq!(decode_npm_store_entry_name(&format!("@1.0.0-{hash}")), None);
    }

    /// #359: npm's `install-strategy=linked` keeps every package in
    /// `node_modules/.store/<name>@<version>-<hash>/node_modules/<name>`
    /// (scoped: `.store/@scope/<leaf>@…/node_modules/@scope/<leaf>`). The
    /// importer links direct deps only, so a transitive package is a real
    /// dir ONLY inside the store. Scan, the resolver and the peer-variant
    /// fan-out must all see it; dependency links inside an entry stay
    /// edges.
    #[tokio::test]
    async fn test_npm_linked_store_transitive_packages_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let odd_entry = store.join("is-odd@3.0.1-6I_Y0S8g8dpI-_3nzyUbcQ/node_modules");
        write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
        let number = store.join("is-number@6.0.0-Pqc5my552wJdjE6sp0MCIg/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        // Same name@version, different dependency graph: a second hash.
        let number_twin =
            store.join("is-number@6.0.0-AAAAAAAAAAAAAAAAAAAAAA/node_modules/is-number");
        write_pkg(&number_twin, "is-number", "6.0.0");
        link_dir(&number, &odd_entry.join("is-number"));
        let frame = store
            .join("@babel/code-frame@7.0.0-wERilBtYXgdUWVgsD7hGnw/node_modules/@babel/code-frame");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));

        let scanned = scan_paths(&root).await;
        let purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
            ],
            "{scanned:?}"
        );
        assert!(scanned.contains(&("pkg:npm/is-odd@3.0.1".to_string(), nm.join("is-odd"))));

        let targets = [
            "pkg:npm/is-number@6.0.0".to_string(),
            "pkg:npm/@babel/code-frame@7.0.0".to_string(),
        ];
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &targets)
            .await
            .unwrap();
        let mut numbers: Vec<PathBuf> = found["pkg:npm/is-number@6.0.0"]
            .iter()
            .map(|p| p.path.clone())
            .collect();
        numbers.sort();
        let mut want = vec![number.clone(), number_twin.clone()];
        want.sort();
        assert_eq!(numbers, want);
        assert_eq!(found["pkg:npm/@babel/code-frame@7.0.0"][0].path, frame);

        assert_eq!(
            find_store_peer_variant_copies(&number).await,
            vec![number_twin.clone()]
        );
    }

    /// #362: pnpm's `virtualStoreDir` moves the virtual store, and
    /// `node_modules/.modules.yaml` records where (relative to
    /// `node_modules`: JSON on pnpm 10+, YAML before). A relocated store
    /// inside the project is walked like `.pnpm`, wherever it sits.
    #[tokio::test]
    async fn test_pnpm_relocated_virtual_store_dir_is_walked() {
        for (modules_yaml, store_rel) in [
            (
                "{\n  \"layoutVersion\": 5,\n  \"virtualStoreDir\": \"../.vstore\"\n}",
                ".vstore",
            ),
            // Older pnpm wrote an absolute path.
            (
                "layoutVersion: 5\nvirtualStoreDir: \"<ROOT>/.abs-store\"\n",
                ".abs-store",
            ),
            (
                "layoutVersion: 5\nvirtualStoreDir: '.custom'\n",
                "node_modules/.custom",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let base: PathBuf = tmp.path().components().collect();
            // Reach the project through a linked ancestor, as macOS's
            // `/var` → `/private/var` temp dirs do: reported copies keep
            // the spelling the caller used.
            let real = base.join("real");
            std::fs::create_dir_all(&real).unwrap();
            let root = base.join("linked");
            link_dir(&real, &root);
            let nm = root.join("node_modules");
            let store = root.join(store_rel);
            let odd_entry = store.join("is-odd@3.0.1/node_modules");
            write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
            let number = store.join("is-number@6.0.0/node_modules/is-number");
            write_pkg(&number, "is-number", "6.0.0");
            link_dir(&number, &odd_entry.join("is-number"));
            let foo = store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");
            let foo_twin = store.join("foo@1.0.0(react@18.2.0)/node_modules/foo");
            write_pkg(&foo, "foo", "1.0.0");
            write_pkg(&foo_twin, "foo", "1.0.0");
            std::fs::create_dir_all(nm.join(".pnpm")).unwrap();
            let modules_yaml =
                modules_yaml.replace("<ROOT>", &root.display().to_string().replace('\\', "\\\\"));
            std::fs::write(nm.join(".modules.yaml"), modules_yaml).unwrap();
            link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));

            let scanned = scan_paths(&root).await;
            assert!(
                scanned.contains(&("pkg:npm/is-number@6.0.0".to_string(), number.clone())),
                "{store_rel}: {scanned:?}"
            );
            assert!(scanned.iter().any(|(p, _)| p == "pkg:npm/foo@1.0.0"));

            let found = NpmCrawler::new()
                .find_by_purls(&nm, &["pkg:npm/is-number@6.0.0".to_string()])
                .await
                .unwrap();
            assert_eq!(
                found
                    .get("pkg:npm/is-number@6.0.0")
                    .map(|c| c.iter().map(|p| p.path.clone()).collect::<Vec<_>>()),
                Some(vec![number.clone()]),
                "{store_rel}"
            );

            let mut variants = find_store_peer_variant_copies(&foo).await;
            variants.sort();
            assert_eq!(variants, vec![foo_twin.clone()], "{store_rel}");
            // From a direct dep's importer link into the store too.
            link_dir(&foo, &nm.join("foo"));
            assert_eq!(
                find_store_peer_variant_copies(&nm.join("foo")).await,
                vec![foo_twin.clone()],
                "{store_rel}"
            );
        }
    }

    /// The peer-variant fan-out only uses a relocated store that holds
    /// the primary: an ENCLOSING project's `.modules.yaml` names a store
    /// this project never loads from, and its copies are not ours to
    /// patch.
    #[tokio::test]
    async fn test_enclosing_projects_relocated_store_is_not_a_peer_variant_source() {
        let tmp = tempfile::tempdir().unwrap();
        let outer: PathBuf = tmp.path().components().collect();
        let outer_nm = outer.join("node_modules");
        std::fs::create_dir_all(&outer_nm).unwrap();
        std::fs::write(
            outer_nm.join(".modules.yaml"),
            "{\"virtualStoreDir\": \"../.vstore\"}",
        )
        .unwrap();
        write_pkg(
            &outer.join(".vstore/foo@1.0.0(react@18.2.0)/node_modules/foo"),
            "foo",
            "1.0.0",
        );

        let inner_store = outer.join("app/node_modules/.pnpm");
        let primary = inner_store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");
        let twin = inner_store.join("foo@1.0.0(react@16.14.0)/node_modules/foo");
        write_pkg(&primary, "foo", "1.0.0");
        write_pkg(&twin, "foo", "1.0.0");
        assert_eq!(find_store_peer_variant_copies(&primary).await, vec![twin]);
    }

    /// A relocated store counts only when it sits strictly below the
    /// importer by plain child names. With the CLI's default `--cwd .` the
    /// importer is the empty path, which `strip_prefix` accepts as a
    /// prefix of anything, absolute or climbing out.
    #[test]
    fn test_path_below_accepts_only_plain_children() {
        let p = Path::new;
        assert_eq!(
            path_below(p(""), p(".vstore")),
            Some(PathBuf::from(".vstore"))
        );
        assert_eq!(
            path_below(p(""), p("node_modules/.custom")),
            Some(PathBuf::from("node_modules/.custom"))
        );
        assert_eq!(
            path_below(p("/proj"), p("/proj/.vstore")),
            Some(PathBuf::from(".vstore"))
        );
        for (importer, store) in [
            ("", "/home/u/.local/share/pnpm/store/v10/links"),
            ("", "../other/.vstore"),
            ("", ""),
            ("/proj", "/proj"),
            ("/proj", "/other/.vstore"),
            ("../proj", "../other"),
        ] {
            assert_eq!(
                path_below(p(importer), p(store)),
                None,
                "{importer:?} {store:?}"
            );
        }
        #[cfg(windows)]
        assert_eq!(path_below(p(""), p(r"C:\pnpm\links")), None);
    }

    /// A `virtualStoreDir` outside the project (pnpm's global virtual
    /// store, `<store>/v10/links`, is shared by every project on the
    /// machine) is NOT walked: agent mode must not patch a shared store
    /// (#361). Nor is a link planted at the recorded path.
    #[tokio::test]
    async fn test_pnpm_virtual_store_dir_outside_project_is_ignored() {
        let outside = tempfile::tempdir().unwrap();
        let shared: PathBuf = outside.path().components().collect();
        let number = shared.join("is-number@6.0.0/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");

        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let rel = format!("{}", shared.display()).replace('\\', "\\\\");
        std::fs::write(
            nm.join(".modules.yaml"),
            format!("{{\"virtualStoreDir\": \"{rel}\"}}"),
        )
        .unwrap();
        assert!(scan_paths(&root).await.is_empty());

        // A link inside the project pointing at the shared store.
        std::fs::write(
            nm.join(".modules.yaml"),
            "{\"virtualStoreDir\": \"../.vstore\"}",
        )
        .unwrap();
        link_dir(&shared, &root.join(".vstore"));
        assert!(scan_paths(&root).await.is_empty());
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/is-number@6.0.0".to_string()])
            .await
            .unwrap();
        assert!(found.is_empty(), "{found:?}");
    }
}
