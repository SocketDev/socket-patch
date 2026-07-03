//! Read-only lockfile inventories: the dependency set a project's lockfile
//! resolves, independent of what is installed on disk.
//!
//! Two consumers:
//!
//! * `scan` supplements its installed-tree crawl with lockfile-only entries
//!   (discovery on fresh clones and partial installs), warning that those
//!   packages are not yet installed;
//! * `vendor` fetches the pristine artifact for a lockfile-resolved package
//!   with no installed copy ([`super::registry_fetch`]), verifying the bytes
//!   against the integrity the lock records — FAIL-CLOSED: an entry whose
//!   lock carries no content verifier is never fetched.
//!
//! Parsing is fail-soft per entry (a malformed entry is skipped, never an
//! error; a malformed file yields `None`) and fail-closed per value:
//! names/versions are path-safety-guarded before an entry is emitted — the
//! lockfile is committed, tamperable input that later feeds filesystem paths
//! and download URLs.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::patch::bun_lock_text;
use crate::patch::path_safety;
use crate::utils::purl::strip_purl_qualifiers;

use super::npm_common::is_safe_npm_name;
use super::npm_flavor::{detect_npm_lock_flavor, NpmLockFlavor};
use super::path::parse_vendor_path;
use super::{pnpm_lock, yarn_berry_lock, yarn_classic_lock};

/// The content verifier a lockfile records for an entry. The fetch layer
/// refuses entries whose verifier is [`LockIntegrity::None`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockIntegrity {
    /// SRI string (`sha512-<b64>`, possibly multi-hash space-separated) —
    /// npm family; verified against the raw tarball bytes.
    Sri(String),
    /// yarn classic `resolved "...#<sha1>"` fragment (40-hex) — verified
    /// against the raw tarball bytes.
    Sha1Hex(String),
    /// yarn berry cache-zip checksum (`<cacheKey>/<b64>`, e.g. `10c0/…`) —
    /// verified by rebuilding the deterministic cache zip from the fetched
    /// tarball and comparing (the lock never hashes the tarball itself).
    BerryChecksum(String),
    /// Hex sha256 of the artifact (Cargo.lock `checksum`, pypi file hashes,
    /// Gemfile.lock `CHECKSUMS`).
    Sha256Hex(String),
    /// go.sum module-zip dirhash (`h1:<b64>`).
    GoH1(String),
    /// The lock records no content verifier.
    None,
}

/// One lockfile-resolved package.
#[derive(Debug, Clone)]
pub struct LockfileEntry {
    /// Vendor-ecosystem tag (`npm`, `cargo`, `golang`, `pypi`, `gem`,
    /// `composer`) — matches `VendorEntry::ecosystem`.
    pub ecosystem: &'static str,
    /// Literal (percent-decoded) package name, e.g. `@scope/name`.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Canonical literal purl (`pkg:npm/@scope/name@1.0.0`) — the same form
    /// the crawlers emit.
    pub purl: String,
    /// Artifact URL when the lock records one (package-lock `resolved`,
    /// yarn `resolved` minus its `#sha1` fragment, pnpm `tarball:`); `None`
    /// means the fetcher constructs the conventional registry URL.
    pub resolved: Option<String>,
    pub integrity: LockIntegrity,
}

impl LockfileEntry {
    fn npm(
        name: impl Into<String>,
        version: impl Into<String>,
        resolved: Option<String>,
        integrity: LockIntegrity,
    ) -> Self {
        let (name, version) = (name.into(), version.into());
        let purl = format!("pkg:npm/{name}@{version}");
        LockfileEntry {
            ecosystem: "npm",
            name,
            version,
            purl,
            resolved,
            integrity,
        }
    }
}

/// Inventory the project's npm-family lockfile. Routes by
/// [`detect_npm_lock_flavor`] (PnP markers, bun.lockb, unsupported lock
/// versions, and a missing lockfile all yield `None`).
async fn inventory_npm_lock(project_root: &Path) -> Option<(NpmLockFlavor, Vec<LockfileEntry>)> {
    // Rush monorepos have no root package.json/lock pair; their single
    // pnpm source-of-truth lives under common/config/rush/. The flavor
    // probe (root-relative) can't see it, so fall back explicitly when the
    // root lock is absent but rush.json is present.
    let (flavor, _warnings) = match detect_npm_lock_flavor(project_root).await {
        Ok(found) => found,
        Err(_) => {
            let rush = inventory_rush_pnpm_locks(project_root).await;
            return (!rush.is_empty()).then(|| (NpmLockFlavor::Pnpm, finalize_npm(rush)));
        }
    };
    let raw = match flavor {
        NpmLockFlavor::PackageLock => inventory_package_lock(project_root).await,
        NpmLockFlavor::Pnpm => inventory_pnpm_lock(project_root).await,
        NpmLockFlavor::YarnClassic => inventory_yarn_classic(project_root).await,
        NpmLockFlavor::YarnBerry => inventory_yarn_berry(project_root).await,
        NpmLockFlavor::Bun => inventory_bun(project_root).await,
    }?;
    Some((flavor, finalize_npm(raw)))
}

/// Match a manifest/API purl (possibly percent-encoded, possibly carrying
/// qualifiers) against the inventory: components decode via
/// [`crate::utils::purl::normalize_purl`], so `pkg:npm/%40scope/x@1`
/// matches the literal entry.
pub fn lookup<'a>(entries: &'a [LockfileEntry], purl: &str) -> Option<&'a LockfileEntry> {
    let decoded = crate::utils::purl::normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (purl_type, rest) = rest.split_once('/')?;
    // purl types double as the vendor-ecosystem tags (same set the
    // dispatcher recognizes).
    let eco = match purl_type {
        "npm" | "cargo" | "golang" | "pypi" | "gem" | "composer" => purl_type,
        _ => return None,
    };
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&rest[..at], &rest[at + 1..]);
    // pypi names compare in PEP 503 normalized form.
    let name = if eco == "pypi" {
        canonicalize_pypi_name(name)
    } else {
        name.to_string()
    };
    entries
        .iter()
        .find(|e| e.ecosystem == eco && e.name == name && e.version == version)
}

/// Everything every recognized lockfile in the project resolves — the
/// union the scan supplement and the vendor auto-fetch consume.
pub async fn inventory_project(project_root: &Path) -> Vec<LockfileEntry> {
    let mut out: Vec<LockfileEntry> = Vec::new();
    if let Some((_, entries)) = inventory_npm_lock(project_root).await {
        out.extend(entries);
    }
    #[cfg(feature = "cargo")]
    if let Some(entries) = inventory_cargo_lock(project_root).await {
        out.extend(entries);
    }
    #[cfg(feature = "golang")]
    if let Some(entries) = inventory_go_sum(project_root).await {
        out.extend(entries);
    }
    #[cfg(feature = "composer")]
    if let Some(entries) = inventory_composer_lock(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_gemfile_lock(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_pypi_locks(project_root).await {
        out.extend(entries);
    }
    out
}

/// Guard + dedup the raw npm entries: unsafe names/versions are dropped
/// fail-closed; duplicate (name, version) instances collapse to one,
/// preferring the instance that carries a verifier.
fn finalize_npm(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    dedup_prefer_integrity(
        raw.into_iter()
            .filter(|e| {
                is_safe_npm_name(&e.name) && path_safety::is_safe_single_segment(&e.version)
            })
            .collect(),
    )
}

/// Collapse duplicate (name, version) instances, preferring one that
/// carries a verifier.
fn dedup_prefer_integrity(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<LockfileEntry> = Vec::new();
    for entry in raw {
        let key = (entry.name.clone(), entry.version.clone());
        match seen.get(&key) {
            Some(&i) => {
                if out[i].integrity == LockIntegrity::None && entry.integrity != LockIntegrity::None
                {
                    out[i] = entry;
                }
            }
            None => {
                seen.insert(key, out.len());
                out.push(entry);
            }
        }
    }
    out
}

// ──────────────────────────────── Cargo.lock ────────────────────────────────

/// Inventory `Cargo.lock` `[[package]]` blocks. Only crates.io-sourced
/// entries are fetchable (their `checksum` is the sha256 of the `.crate`
/// file); workspace members (no `source`) are skipped, and git/custom-
/// registry sources stay listed for discovery without a verifier.
#[cfg(feature = "cargo")]
async fn inventory_cargo_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("Cargo.lock"))
        .await
        .ok()?;
    /// One in-flight `[[package]]` block: name, version, source, checksum.
    type CargoBlock = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut out = Vec::new();
    let mut cur: Option<CargoBlock> = None;
    let flush = |cur: &mut Option<CargoBlock>, out: &mut Vec<LockfileEntry>| {
        if let Some((Some(name), Some(version), source, checksum)) = cur.take() {
            let Some(source) = source else {
                return; // workspace member
            };
            if !path_safety::is_safe_single_segment(&name)
                || !path_safety::is_safe_single_segment(&version)
            {
                return;
            }
            let crates_io = source.contains("github.com/rust-lang/crates.io-index")
                || source.contains("index.crates.io");
            let integrity = match checksum {
                Some(c) if crates_io && is_hex_of_len(&c, 64) => LockIntegrity::Sha256Hex(c),
                _ => LockIntegrity::None,
            };
            let purl = format!("pkg:cargo/{name}@{version}");
            out.push(LockfileEntry {
                ecosystem: "cargo",
                name,
                version,
                purl,
                resolved: None,
                integrity,
            });
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut cur, &mut out);
            cur = Some((None, None, None, None));
            continue;
        }
        if line.starts_with('[') {
            flush(&mut cur, &mut out);
            continue;
        }
        let Some(slot) = cur.as_mut() else { continue };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "name" => slot.0 = Some(value),
            "version" => slot.1 = Some(value),
            "source" => slot.2 = Some(value),
            "checksum" => slot.3 = Some(value),
            _ => {}
        }
    }
    flush(&mut cur, &mut out);
    Some(dedup_prefer_integrity(out))
}

// ────────────────────────────────── go.sum ──────────────────────────────────

/// Inventory `go.sum` module-zip lines (`<module> <version> h1:<b64>`); the
/// `/go.mod`-suffixed lines hash only the manifest and are skipped. go.sum
/// may list more modules than the final build graph — acceptable for
/// discovery, and the manifest decides what actually gets vendored.
#[cfg(feature = "golang")]
async fn inventory_go_sum(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("go.sum"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version), Some(hash)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if version.ends_with("/go.mod") || !hash.starts_with("h1:") {
            continue;
        }
        // SECURITY: module path segments and the version feed paths/URLs.
        if !path_safety::is_safe_multi_segment(module)
            || !path_safety::is_safe_single_segment(version)
        {
            continue;
        }
        out.push(LockfileEntry {
            ecosystem: "golang",
            name: module.to_string(),
            version: version.to_string(),
            purl: format!("pkg:golang/{module}@{version}"),
            resolved: None,
            integrity: LockIntegrity::GoH1(hash.to_string()),
        });
    }
    Some(dedup_prefer_integrity(out))
}

/// Keep a lock-recorded URL only when it is a plain http(s) artifact URL
/// (drops `git+…`, `file:…`, `link:…` — content the registry conventions
/// cannot reproduce; such entries stay listed for discovery but the fetch
/// layer's integrity rule decides fetchability).
fn http_url(raw: &str) -> Option<String> {
    (raw.starts_with("https://") || raw.starts_with("http://")).then(|| raw.to_string())
}

fn is_hex_of_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ──────────────────── package-lock.json / npm-shrinkwrap ────────────────────

async fn inventory_package_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    // Shrinkwrap wins, mirroring `npm_lock::select_lockfile`.
    let mut bytes = None;
    for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
        if let Ok(b) = tokio::fs::read(root.join(lock)).await {
            bytes = Some(b);
            break;
        }
    }
    let doc: Value = serde_json::from_slice(&bytes?).ok()?;
    // v1 legacy locks have no `packages` map — no inventory (documented).
    let packages = doc.get("packages")?.as_object()?;

    let mut out = Vec::new();
    for (key, node) in packages {
        // "" is the root project; keys without node_modules/ are workspace
        // members (mirrors npm_lock::scan_lock_matches' member rule).
        let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
            continue;
        };
        if node.get("link").and_then(Value::as_bool).unwrap_or(false)
            || node
                .get("inBundle")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            continue;
        }
        let name = node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(key_name)
            .to_string();
        let Some(version) = node.get("version").and_then(Value::as_str) else {
            continue;
        };
        let resolved_raw = node.get("resolved").and_then(Value::as_str);
        // Our own vendored spec: not a registry dependency.
        if resolved_raw.is_some_and(|r| parse_vendor_path(r).is_some()) {
            continue;
        }
        let integrity = node
            .get("integrity")
            .and_then(Value::as_str)
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(
            name,
            version,
            resolved_raw.and_then(http_url),
            integrity,
        ));
    }
    Some(out)
}

// ─────────────────────────── pnpm-lock.yaml v9 ───────────────────────────

async fn inventory_pnpm_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_at(&root.join("pnpm-lock.yaml")).await
}

/// Inventory a specific `pnpm-lock.yaml` (path given explicitly so the Rush
/// fallback can point it at `common/config/rush/…` and subspace locks).
async fn inventory_pnpm_lock_at(lock_path: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(lock_path).await.ok()?;
    let lines = pnpm_lock::split_lines(&text);
    let (start, end) = pnpm_lock::section_bounds(&lines, "packages")?;

    let mut out = Vec::new();
    let mut i = start + 1;
    while let Some(block) = pnpm_lock::next_block(&lines, i, end) {
        i = block.end;
        // Key grammar: `name@version` (name may be `@scope/name`), with
        // optional peer-dep suffixes `(peer@1.2.3)…` after the version.
        let base = match block.key.find('(') {
            Some(p) => block.key[..p].trim_end(),
            None => block.key.as_str(),
        };
        let Some(at) = base.rfind('@').filter(|&p| p > 0) else {
            continue;
        };
        let (name, version) = (&base[..at], &base[at + 1..]);
        // Only plain registry versions: `file:`/`link:`/`https:`/git specs
        // are not registry-resolvable.
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let mut integrity = LockIntegrity::None;
        let mut tarball: Option<String> = None;
        for line in &lines[block.header + 1..block.end] {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("resolution:") {
                if let Some(v) = inline_yaml_field(rest, "integrity:") {
                    integrity = LockIntegrity::Sri(v);
                }
                tarball = inline_yaml_field(rest, "tarball:");
                break;
            }
        }
        // Our own vendored spec: not a registry dependency.
        if tarball
            .as_deref()
            .is_some_and(|t| parse_vendor_path(t).is_some())
        {
            continue;
        }
        out.push(LockfileEntry::npm(
            name,
            version,
            tarball.as_deref().and_then(http_url),
            integrity,
        ));
    }
    Some(out)
}

// ─────────────────────────────── Rush monorepo ───────────────────────────────

/// Inventory a Rush monorepo's pnpm locks. Rush keeps a single
/// source-of-truth lock at `common/config/rush/pnpm-lock.yaml` and, when
/// subspaces are enabled, one lock per subspace under
/// `common/config/subspaces/<name>/pnpm-lock.yaml`. `rush install` copies
/// the source lock into common/temp and runs pnpm there.
///
/// Only called (via [`inventory_npm_lock`]) when there is NO root lock but
/// `rush.json` is present, so it never shadows a plain pnpm project. The
/// subspace directory is read sorted for deterministic output. Missing
/// files/dirs are skipped fail-soft; the caller drops the whole result when
/// it comes back empty.
async fn inventory_rush_pnpm_locks(project_root: &Path) -> Vec<LockfileEntry> {
    if tokio::fs::metadata(project_root.join("rush.json"))
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();

    // The single source-of-truth lock.
    let common_lock = project_root.join("common/config/rush/pnpm-lock.yaml");
    if let Some(entries) = inventory_pnpm_lock_at(&common_lock).await {
        out.extend(entries);
    }

    // Per-subspace locks, sorted for determinism.
    let subspaces_dir = project_root.join("common/config/subspaces");
    if let Ok(mut read_dir) = tokio::fs::read_dir(&subspaces_dir).await {
        let mut subspace_dirs: Vec<std::path::PathBuf> = Vec::new();
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                subspace_dirs.push(entry.path());
            }
        }
        subspace_dirs.sort();
        for dir in subspace_dirs {
            if let Some(entries) = inventory_pnpm_lock_at(&dir.join("pnpm-lock.yaml")).await {
                out.extend(entries);
            }
        }
    }
    out
}

// ───────────────────────────── yarn.lock (classic) ─────────────────────────────

async fn inventory_yarn_classic(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("yarn.lock"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for block in yarn_classic_lock::scan_blocks(&text) {
        // Our own vendored block: not a registry dependency.
        if yarn_classic_lock::block_points_into_vendor(&block.lines) {
            continue;
        }
        let patterns = yarn_classic_lock::split_key_patterns(&block.key);
        let Some(name) = patterns
            .first()
            .and_then(|p| yarn_classic_lock::pattern_real_name(p))
        else {
            continue;
        };
        let Some(version) = yarn_classic_lock::classic_field(&block.lines, "version") else {
            continue;
        };
        let resolved_raw = yarn_classic_lock::classic_field(&block.lines, "resolved");
        // `resolved "url#sha1hex"` — the fragment is the legacy verifier.
        let (resolved, sha1_hex) = match resolved_raw {
            Some(raw) => match raw.split_once('#') {
                Some((url, frag)) => (
                    http_url(url),
                    is_hex_of_len(frag, 40).then(|| frag.to_ascii_lowercase()),
                ),
                None => (http_url(raw), None),
            },
            None => (None, None),
        };
        let integrity = yarn_classic_lock::classic_field(&block.lines, "integrity")
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .or(sha1_hex.map(LockIntegrity::Sha1Hex))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, resolved, integrity));
    }
    Some(out)
}

// ───────────────────────────── yarn.lock (berry) ─────────────────────────────

async fn inventory_yarn_berry(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("yarn.lock"))
        .await
        .ok()?;
    let mut out = Vec::new();
    // Berry reuses classic's block grammar (same scanner the berry backend
    // imports); `__metadata` and workspace/patch/file resolutions are not
    // registry packages.
    for block in yarn_classic_lock::scan_blocks(&text) {
        if block.key.starts_with("__metadata") {
            continue;
        }
        let Some(resolution) = yarn_berry_lock::berry_field(&block.lines, "resolution") else {
            continue;
        };
        // Registry resolutions are `name@npm:<version>` (a `::binding`
        // suffix may follow). Anything else (workspace:/patch:/file:/link:)
        // is skipped — including our own vendored file: resolutions.
        let Some((name, reference)) = yarn_classic_lock::split_pattern(resolution) else {
            continue;
        };
        let Some(reference) = reference.strip_prefix("npm:") else {
            continue;
        };
        let version_from_res = reference.split("::").next().unwrap_or(reference);
        let version =
            yarn_berry_lock::berry_field(&block.lines, "version").unwrap_or(version_from_res);
        let integrity = yarn_berry_lock::berry_field(&block.lines, "checksum")
            .map(|c| LockIntegrity::BerryChecksum(c.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, None, integrity));
    }
    Some(out)
}

// ──────────────────────────────── bun.lock ────────────────────────────────

async fn inventory_bun(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("bun.lock"))
        .await
        .ok()?;
    bun_lock_text::check_lock_version(&text).ok()?;
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let entries = bun_lock_text::parse_packages_section(&lines).ok()?;

    let mut out = Vec::new();
    for entry in entries {
        // Registry entries are 4-tuples `[spec, registry, {deps}, sha512]`;
        // our vendored 3-tuples and other shapes are skipped.
        if entry.elems.len() != 4 || !entry.elems[2].starts_with('{') {
            continue;
        }
        let Some(spec) = entry
            .elems
            .first()
            .and_then(|e| bun_lock_text::decode_json_string(e))
        else {
            continue;
        };
        let Some((name, version)) = bun_lock_text::split_name_spec(&spec) else {
            continue;
        };
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(registry) = bun_lock_text::decode_json_string(&entry.elems[1]) else {
            continue;
        };
        let Some(integrity) = bun_lock_text::decode_json_string(&entry.elems[3]) else {
            continue;
        };
        // elem[1] is `""` for the default registry; a full `.tgz` URL is
        // used verbatim; any other base falls back to conventional URL
        // construction (the integrity check still gates the content).
        let resolved = (registry.ends_with(".tgz"))
            .then(|| http_url(&registry))
            .flatten();
        out.push(LockfileEntry::npm(
            name,
            version,
            resolved,
            LockIntegrity::Sri(integrity),
        ));
    }
    Some(out)
}

// ────────────────────────────── composer.lock ──────────────────────────────

/// Inventory `composer.lock` `packages`/`packages-dev`. The `dist.shasum`
/// (sha1 of the dist zip) is frequently empty — such entries stay
/// discovery-only. Names lowercase to the canonical packagist form;
/// versions drop the pretty leading `v`.
#[cfg(feature = "composer")]
async fn inventory_composer_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let bytes = tokio::fs::read(project_root.join("composer.lock"))
        .await
        .ok()?;
    let doc: Value = serde_json::from_slice(&bytes).ok()?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(list) = doc.get(section).and_then(Value::as_array) else {
            continue;
        };
        for pkg in list {
            let Some(name) = pkg.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(Value::as_str) else {
                continue;
            };
            let name = name.to_ascii_lowercase();
            let version = version
                .strip_prefix('v')
                .filter(|r| r.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .unwrap_or(version)
                .to_string();
            if !path_safety::is_safe_multi_segment(&name)
                || name.split('/').count() != 2
                || !path_safety::is_safe_single_segment(&version)
            {
                continue;
            }
            let dist = pkg.get("dist");
            let dist_url = dist
                .and_then(|d| d.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("");
            // Our own vendored entries use a path dist — skip.
            if dist
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|t| t == "path")
                || parse_vendor_path(dist_url).is_some()
            {
                continue;
            }
            let is_zip = dist
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|t| t == "zip");
            let shasum = dist
                .and_then(|d| d.get("shasum"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let integrity = if is_zip && is_hex_of_len(shasum, 40) {
                LockIntegrity::Sha1Hex(shasum.to_ascii_lowercase())
            } else {
                LockIntegrity::None
            };
            let purl = format!("pkg:composer/{name}@{version}");
            out.push(LockfileEntry {
                ecosystem: "composer",
                name,
                version,
                purl,
                resolved: is_zip.then(|| http_url(dist_url)).flatten(),
                integrity,
            });
        }
    }
    Some(dedup_prefer_integrity(out))
}

// ────────────────────────────── Gemfile.lock ──────────────────────────────

/// Inventory `Gemfile.lock`: `GEM`-section `specs:` entries (4-space
/// indent; deeper lines are dependency ranges) plus the bundler ≥ 2.6
/// `CHECKSUMS` section's sha256 values when present (older locks stay
/// discovery-only). Platform-suffixed specs (`nokogiri (1.16.5-arm64-…)`)
/// are skipped — platform gems are unsupported for vendoring anyway.
async fn inventory_gemfile_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("Gemfile.lock"))
        .await
        .ok()?;
    let mut remote: Option<String> = None;
    let mut checksums: HashMap<(String, String), String> = HashMap::new();
    let mut specs: Vec<(String, String)> = Vec::new();

    let mut section = "";
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            section = line.trim();
            in_specs = false;
            continue;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        match section {
            "GEM" => {
                if indent == 2 {
                    if let Some(r) = trimmed.strip_prefix("remote:") {
                        let r = r.trim().trim_end_matches('/');
                        if remote.is_none() && !r.is_empty() {
                            remote = Some(r.to_string());
                        }
                    }
                    in_specs = trimmed == "specs:";
                } else if in_specs && indent == 4 {
                    if let Some((name, version)) = parse_gem_spec_line(trimmed) {
                        specs.push((name, version));
                    }
                }
            }
            "CHECKSUMS" => {
                // `  name (version) sha256=hex`
                if let Some((spec_part, hash_part)) =
                    trimmed.rsplit_once(" sha256=").map(|(s, h)| (s, h.trim()))
                {
                    if let Some((name, version)) = parse_gem_spec_line(spec_part) {
                        if is_hex_of_len(hash_part, 64) {
                            checksums.insert((name, version), hash_part.to_ascii_lowercase());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if specs.is_empty() {
        return None;
    }
    let base = remote.unwrap_or_else(|| "https://rubygems.org".to_string());
    let mut out = Vec::new();
    for (name, version) in specs {
        if !path_safety::is_safe_single_segment(&name)
            || !path_safety::is_safe_single_segment(&version)
        {
            continue;
        }
        let integrity = checksums
            .get(&(name.clone(), version.clone()))
            .map(|h| LockIntegrity::Sha256Hex(h.clone()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry {
            ecosystem: "gem",
            purl: format!("pkg:gem/{name}@{version}"),
            resolved: http_url(&format!("{base}/downloads/{name}-{version}.gem")),
            name,
            version,
            integrity,
        });
    }
    Some(dedup_prefer_integrity(out))
}

/// `name (version)` → parts; platform-suffixed versions (`1.2.3-x86_64…`)
/// and dependency lines (no parens / range operators) yield `None`.
fn parse_gem_spec_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.strip_suffix(')')?;
    if name.is_empty()
        || version.is_empty()
        || version.contains(' ')
        || version.contains('-')
        || !version.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

// ─────────────────────────────── pypi locks ───────────────────────────────
// pypi purls and lock entries compare in PEP 503 normalized form
// (`Foo._Bar` → `foo-bar`) — see `canonicalize_pypi_name`.

/// Inventory the pypi lock the project carries. Fetchable resolution
/// (URL + sha256 of a pure `py3-none-any` wheel) comes from `uv.lock`;
/// `poetry.lock` and `--hash`-pinned `requirements.txt` contribute
/// DISCOVERY-only entries (no recorded URL; platform-independent wheel
/// choice is not derivable offline). Pipenv/pdm locks: not yet read.
async fn inventory_pypi_locks(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    if let Some(out) = inventory_uv_lock(project_root).await {
        return Some(out);
    }
    if let Some(out) = inventory_poetry_lock(project_root).await {
        return Some(out);
    }
    inventory_requirements_txt(project_root).await
}

/// uv.lock: TOML `[[package]]` blocks with `name`/`version` and
/// `wheels = [{ url, hash = "sha256:…" }, …]` entries.
async fn inventory_uv_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("uv.lock"))
        .await
        .ok()?;
    let mut out = Vec::new();
    // Line-oriented: uv emits `[[package]]` blocks; wheels live either as
    // inline `{ url = "…", hash = "sha256:…" }` table rows or one-line
    // arrays. A pure-python wheel ends `py3-none-any.whl`.
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut sourced_registry = true;
    let mut wheel: Option<(String, String)> = None;
    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 sourced_registry: &mut bool,
                 wheel: &mut Option<(String, String)>,
                 out: &mut Vec<LockfileEntry>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            let canonical = canonicalize_pypi_name(&n);
            if *sourced_registry
                && path_safety::is_safe_single_segment(&canonical)
                && path_safety::is_safe_single_segment(&v)
            {
                let (resolved, integrity) = match wheel.take() {
                    Some((url, sha)) => (http_url(&url), LockIntegrity::Sha256Hex(sha)),
                    None => (None, LockIntegrity::None),
                };
                out.push(LockfileEntry {
                    ecosystem: "pypi",
                    purl: format!("pkg:pypi/{canonical}@{v}"),
                    name: canonical,
                    version: v,
                    resolved,
                    integrity,
                });
            }
        }
        *sourced_registry = true;
        *wheel = None;
    };
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(
                &mut name,
                &mut version,
                &mut sourced_registry,
                &mut wheel,
                &mut out,
            );
            continue;
        }
        if let Some(v) = t.strip_prefix("name = ") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = t.strip_prefix("version = ") {
            version = Some(v.trim_matches('"').to_string());
        } else if t.starts_with("source = ") {
            // Registry packages: `source = { registry = "…" }`; editable/
            // virtual/path/git sources are not fetchable artifacts.
            sourced_registry = t.contains("registry");
        } else if wheel.is_none() && t.contains("py3-none-any.whl") {
            // `{ url = "…py3-none-any.whl", hash = "sha256:…" }`
            let url = t
                .split("url = \"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .unwrap_or("");
            let sha = t
                .split("hash = \"sha256:")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .unwrap_or("");
            if !url.is_empty() && is_hex_of_len(sha, 64) {
                wheel = Some((url.to_string(), sha.to_ascii_lowercase()));
            }
        }
    }
    flush(
        &mut name,
        &mut version,
        &mut sourced_registry,
        &mut wheel,
        &mut out,
    );
    Some(dedup_prefer_integrity(out))
}

/// poetry.lock: `[[package]]` blocks with `name`/`version` — discovery
/// only (file hashes exist but carry no URLs and no platform choice).
async fn inventory_poetry_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("poetry.lock"))
        .await
        .ok()?;
    let mut out = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            in_package = true;
            name = None;
            continue;
        }
        if t.starts_with('[') && t != "[[package]]" {
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(v) = t.strip_prefix("name = ") {
            name = Some(canonicalize_pypi_name(v.trim_matches('"')));
        } else if let Some(v) = t.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                let v = v.trim_matches('"').to_string();
                if path_safety::is_safe_single_segment(&n)
                    && path_safety::is_safe_single_segment(&v)
                {
                    out.push(LockfileEntry {
                        ecosystem: "pypi",
                        purl: format!("pkg:pypi/{n}@{v}"),
                        name: n,
                        version: v,
                        resolved: None,
                        integrity: LockIntegrity::None,
                    });
                }
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(dedup_prefer_integrity(out))
}

/// requirements.txt with exact `==` pins — discovery only.
async fn inventory_requirements_txt(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("requirements.txt"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('-') {
            continue;
        }
        // `name==version` (strip extras, env markers, hash continuations).
        let spec = t.split(';').next().unwrap_or(t).trim();
        let spec = spec.split_whitespace().next().unwrap_or(spec);
        let Some((raw_name, version)) = spec.split_once("==") else {
            continue;
        };
        let name = canonicalize_pypi_name(raw_name.split('[').next().unwrap_or(raw_name).trim());
        let version = version.trim().to_string();
        if name.is_empty()
            || !path_safety::is_safe_single_segment(&name)
            || !path_safety::is_safe_single_segment(&version)
            || !version.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        out.push(LockfileEntry {
            ecosystem: "pypi",
            purl: format!("pkg:pypi/{name}@{version}"),
            name,
            version,
            resolved: None,
            integrity: LockIntegrity::None,
        });
    }
    if out.is_empty() {
        return None;
    }
    Some(dedup_prefer_integrity(out))
}

// ──────────────── registry-fragment recovery from the ledger ────────────────

/// Recover the PRE-VENDOR registry resolution of a vendored package from its
/// ledger entry's wiring `original` fragments (and `entry.lock` for cargo),
/// as a fetchable [`LockfileEntry`].
///
/// This is the rebuild path for artifacts that are referenced by the rewired
/// lockfile but missing on disk: the live lockfile no longer carries the
/// registry resolution (it points at `.socket/vendor/...`), but `--revert`'s
/// restore data does. golang is deliberately absent — go.sum is never
/// rewired, so the standard [`inventory_project`]/[`lookup`] path covers it.
///
/// SECURITY: state.json is committed and tamper-able. Recovered URLs go
/// through the same http(s)-only gate as inventoried ones, recovered hashes
/// are shape-validated here and verified against the fetched bytes
/// fail-closed by the fetch layer — a poisoned fragment can at worst make
/// the fetch fail, never land unverified content.
pub async fn recover_lock_entry(
    project_root: &Path,
    entry: &super::state::VendorEntry,
) -> Result<LockfileEntry, String> {
    let (name, version) = parse_base_purl_coords(&entry.base_purl)
        .ok_or_else(|| format!("unparseable base purl `{}`", entry.base_purl))?;

    match entry.ecosystem.as_str() {
        "npm" => recover_npm_fragment(entry, &name, &version),
        "cargo" => {
            let checksum = entry
                .lock
                .as_ref()
                .and_then(|l| l.checksum.clone())
                .filter(|c| is_hex_of_len(c, 64))
                .ok_or_else(|| {
                    "the ledger records no pre-vendor Cargo.lock checksum".to_string()
                })?;
            Ok(LockfileEntry {
                ecosystem: "cargo",
                purl: format!("pkg:cargo/{name}@{version}"),
                name,
                version,
                resolved: None,
                integrity: LockIntegrity::Sha256Hex(checksum.to_ascii_lowercase()),
            })
        }
        "composer" => {
            let original = wiring_original(entry, &["composer_lock_package"])
                .ok_or_else(|| "no pre-vendor composer.lock fragment recorded".to_string())?;
            let dist = original
                .get("dist")
                .ok_or_else(|| "the pre-vendor composer.lock fragment has no dist".to_string())?;
            let url = dist
                .get("url")
                .and_then(serde_json::Value::as_str)
                .and_then(http_url)
                .ok_or_else(|| "the pre-vendor dist has no http(s) url".to_string())?;
            let shasum = dist
                .get("shasum")
                .and_then(serde_json::Value::as_str)
                .filter(|s| is_hex_of_len(s, 40))
                .ok_or_else(|| {
                    "the pre-vendor dist records no shasum; refusing an unverifiable fetch"
                        .to_string()
                })?;
            Ok(LockfileEntry {
                ecosystem: "composer",
                purl: format!("pkg:composer/{name}@{version}"),
                name,
                version,
                resolved: Some(url),
                integrity: LockIntegrity::Sha1Hex(shasum.to_ascii_lowercase()),
            })
        }
        "gem" => {
            let line = wiring_original(entry, &["gemfile_lock_checksum"])
                .and_then(|v| v.as_str().map(str::to_string))
                .ok_or_else(|| "no pre-vendor Gemfile.lock checksum recorded".to_string())?;
            let sha = line
                .split("sha256=")
                .nth(1)
                .map(|rest| {
                    rest.trim_end_matches(',')
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect::<String>()
                })
                .filter(|s| is_hex_of_len(s, 64))
                .ok_or_else(|| {
                    "the pre-vendor checksum line has no sha256; refusing an unverifiable fetch"
                        .to_string()
                })?;
            let base = gem_remote_base(project_root)
                .await
                .unwrap_or_else(|| "https://rubygems.org".to_string());
            Ok(LockfileEntry {
                ecosystem: "gem",
                purl: format!("pkg:gem/{name}@{version}"),
                resolved: http_url(&format!(
                    "{}/downloads/{name}-{version}.gem",
                    base.trim_end_matches('/')
                )),
                name,
                version,
                integrity: LockIntegrity::Sha256Hex(sha.to_ascii_lowercase()),
            })
        }
        "pypi" => {
            if entry.artifact.platform_locked == Some(true) {
                return Err(
                    "the vendored wheel is platform-locked (compiled); it cannot be rebuilt                      from the registry"
                        .to_string(),
                );
            }
            let unit = wiring_original(entry, &["uv_lock_package"])
                .and_then(|v| v.as_str().map(str::to_string))
                .ok_or_else(|| "no pre-vendor uv.lock fragment recorded".to_string())?;
            let (url, sha) = pure_wheel_from_uv_unit(&unit).ok_or_else(|| {
                "the pre-vendor uv.lock fragment lists no verifiable pure wheel".to_string()
            })?;
            Ok(LockfileEntry {
                ecosystem: "pypi",
                purl: format!("pkg:pypi/{name}@{version}"),
                name,
                version,
                resolved: Some(url),
                integrity: LockIntegrity::Sha256Hex(sha),
            })
        }
        other => Err(format!(
            "no ledger-based registry recovery for ecosystem `{other}`"
        )),
    }
}

/// The integrity the REWIRED npm-family lockfile records for a vendored
/// artifact at `artifact_rel` (forward-slashed, no `./` prefix). This is
/// the integrity of OUR deterministically packed tarball — the trust
/// anchor for repair's no-ledger reconstruction: a rebuilt tarball that
/// matches it is exactly what the package manager would have installed.
///
/// package-lock/shrinkwrap are parsed as JSON; the text formats (pnpm,
/// yarn classic/berry, bun) are scanned with a bounded forward window from
/// each reference line.
pub async fn wired_vendor_integrity(
    project_root: &Path,
    artifact_rel: &str,
) -> Option<LockIntegrity> {
    let rel = artifact_rel.trim_start_matches("./");

    // JSON locks: resolved == "file:<rel>" (npm writes exactly this form).
    for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
        let Ok(bytes) = tokio::fs::read(project_root.join(lock)).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(pkgs) = v.get("packages").and_then(serde_json::Value::as_object) {
            for entry in pkgs.values() {
                let resolved = entry.get("resolved").and_then(serde_json::Value::as_str);
                if resolved.is_some_and(|r| r.trim_start_matches("file:") == rel) {
                    if let Some(sri) = entry
                        .get("integrity")
                        .and_then(serde_json::Value::as_str)
                        .filter(|s| looks_like_sri(s))
                    {
                        return Some(LockIntegrity::Sri(sri.to_string()));
                    }
                }
            }
        }
    }

    // Text locks: any line referencing the artifact path, integrity within
    // a short forward window (the same block).
    for lock in ["pnpm-lock.yaml", "yarn.lock", "bun.lock"] {
        let Ok(text) = tokio::fs::read_to_string(project_root.join(lock)).await else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(rel) {
                continue;
            }
            for probe in lines.iter().take((i + 6).min(lines.len())).skip(i) {
                // pnpm `resolution: {integrity: …}` / classic `integrity …`
                // / bun tuple `"sha512-…"`.
                if let Some(v) = inline_yaml_field(probe, "integrity:") {
                    if looks_like_sri(&v) {
                        return Some(LockIntegrity::Sri(v));
                    }
                }
                if let Some(rest) = probe.trim().strip_prefix("integrity ") {
                    let v = rest.trim().trim_matches('"');
                    if looks_like_sri(v) {
                        return Some(LockIntegrity::Sri(v.to_string()));
                    }
                }
                if let Some(sri) = probe.split('"').rev().find(|tok| looks_like_sri(tok)) {
                    return Some(LockIntegrity::Sri(sri.to_string()));
                }
                // yarn berry: `checksum: 10c0/…`.
                if let Some(v) = inline_yaml_field(probe, "checksum:") {
                    if v.split_once('/')
                        .is_some_and(|(k, b)| !k.is_empty() && !b.is_empty())
                    {
                        return Some(LockIntegrity::BerryChecksum(v));
                    }
                }
            }
        }
    }
    None
}

/// `pkg:<eco>/<name>@<version>` → (name, version). The name may itself
/// contain `/` (npm scopes, go modules); the version is after the LAST `@`.
fn parse_base_purl_coords(base_purl: &str) -> Option<(String, String)> {
    let rest = base_purl.strip_prefix("pkg:")?;
    let (_, name_ver) = rest.split_once('/')?;
    let (name, version) = name_ver.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// First wiring record of one of `kinds` carrying an `original` payload.
fn wiring_original<'a>(
    entry: &'a super::state::VendorEntry,
    kinds: &[&str],
) -> Option<&'a serde_json::Value> {
    entry
        .wiring
        .iter()
        .find(|r| kinds.contains(&r.kind.as_str()) && r.original.is_some())
        .and_then(|r| r.original.as_ref())
}

/// Per-flavor npm recovery: the wiring kinds disambiguate the lock flavor,
/// each fragment yields (resolved?, integrity).
fn recover_npm_fragment(
    entry: &super::state::VendorEntry,
    name: &str,
    version: &str,
) -> Result<LockfileEntry, String> {
    let mk = |resolved: Option<String>, integrity: LockIntegrity| LockfileEntry {
        ecosystem: "npm",
        purl: format!("pkg:npm/{name}@{version}"),
        name: name.to_string(),
        version: version.to_string(),
        resolved,
        integrity,
    };

    // package-lock / shrinkwrap: the original is the full lock entry object.
    if let Some(obj) = wiring_original(entry, &["npm_lock_entry", "npm_lock_legacy_entry"]) {
        let resolved = obj
            .get("resolved")
            .and_then(serde_json::Value::as_str)
            .and_then(http_url);
        if let Some(sri) = obj
            .get("integrity")
            .and_then(serde_json::Value::as_str)
            .filter(|s| looks_like_sri(s))
        {
            return Ok(mk(resolved, LockIntegrity::Sri(sri.to_string())));
        }
    }
    // pnpm: the original is the packages block's lines; pull
    // `resolution: {integrity: …, tarball: …}`.
    if let Some(lines) = wiring_original(entry, &["pnpm_lock_package"]).and_then(lines_of) {
        let mut sri = None;
        let mut tarball = None;
        for line in &lines {
            if let Some(v) = inline_yaml_field(line, "integrity:") {
                sri = sri.or(Some(v));
            }
            if let Some(v) = inline_yaml_field(line, "tarball:") {
                tarball = tarball.or(http_url(&v));
            }
        }
        if let Some(sri) = sri.filter(|s| looks_like_sri(s)) {
            return Ok(mk(tarball, LockIntegrity::Sri(sri)));
        }
    }
    // yarn classic: block lines carry `integrity <sri>` (preferred) and/or
    // `resolved "<url>#<sha1>"`.
    if let Some(lines) = wiring_original(entry, &["yarn_lock_block"]).and_then(lines_of) {
        let mut url = None;
        let mut sha1 = None;
        let mut sri = None;
        for line in &lines {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("integrity ") {
                let v = rest.trim().trim_matches('"');
                if looks_like_sri(v) {
                    sri = Some(v.to_string());
                }
            }
            if let Some(rest) = t.strip_prefix("resolved ") {
                let v = rest.trim().trim_matches('"');
                let (u, frag) = v.split_once('#').unwrap_or((v, ""));
                url = http_url(u);
                if is_hex_of_len(frag, 40) {
                    sha1 = Some(frag.to_ascii_lowercase());
                }
            }
        }
        if let Some(sri) = sri {
            return Ok(mk(url, LockIntegrity::Sri(sri)));
        }
        if let Some(sha1) = sha1 {
            return Ok(mk(url, LockIntegrity::Sha1Hex(sha1)));
        }
    }
    // yarn berry: block lines carry `checksum: <cacheKey>/<b64>`.
    if let Some(lines) = wiring_original(entry, &["yarn_berry_lock_entry"]).and_then(lines_of) {
        for line in &lines {
            if let Some(v) = inline_yaml_field(line, "checksum:") {
                if v.split_once('/')
                    .is_some_and(|(k, b)| !k.is_empty() && !b.is_empty())
                {
                    return Ok(mk(None, LockIntegrity::BerryChecksum(v)));
                }
            }
        }
    }
    // bun: the original is the raw tuple line; the integrity is its last
    // quoted SRI string.
    if let Some(line) =
        wiring_original(entry, &["bun_lock_package"]).and_then(|v| v.as_str().map(str::to_string))
    {
        if let Some(sri) = line
            .split('"')
            .rev()
            .find(|tok| looks_like_sri(tok))
            .map(str::to_string)
        {
            return Ok(mk(None, LockIntegrity::Sri(sri)));
        }
    }
    Err("no pre-vendor npm registry fragment with a verifiable integrity recorded".to_string())
}

fn looks_like_sri(s: &str) -> bool {
    ["sha512-", "sha384-", "sha256-", "sha1-"]
        .iter()
        .any(|p| s.starts_with(p) && s.len() > p.len())
}

/// A wiring `original` recorded as an array of text lines.
fn lines_of(v: &serde_json::Value) -> Option<Vec<String>> {
    v.as_array().map(|arr| {
        arr.iter()
            .filter_map(|l| l.as_str().map(str::to_string))
            .collect()
    })
}

/// `… field: value` (optionally inside an inline `{…}` map) → value, with
/// trailing `,`/`}` and quotes stripped.
fn inline_yaml_field(line: &str, field: &str) -> Option<String> {
    let idx = line.find(field)?;
    let rest = &line[idx + field.len()..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    let v = rest[..end].trim().trim_matches(['\'', '"']).to_string();
    (!v.is_empty()).then_some(v)
}

/// The `GEM remote:` base of the (unrewired) Gemfile.lock.
async fn gem_remote_base(project_root: &Path) -> Option<String> {
    let text = tokio::fs::read_to_string(project_root.join("Gemfile.lock"))
        .await
        .ok()?;
    let mut in_gem = false;
    for line in text.lines() {
        if line.trim_end() == "GEM" {
            in_gem = true;
            continue;
        }
        if in_gem {
            if let Some(rest) = line.trim().strip_prefix("remote:") {
                return http_url(rest.trim());
            }
            if !line.starts_with(' ') && !line.trim().is_empty() {
                in_gem = false;
            }
        }
    }
    None
}

/// First `{ url = "…", hash = "sha256:…" }` wheel in a uv.lock `[[package]]`
/// unit whose filename is a PURE wheel (`-none-any.whl`).
fn pure_wheel_from_uv_unit(unit: &str) -> Option<(String, String)> {
    let mut search = unit;
    while let Some(uidx) = search.find("url = \"") {
        let after = &search[uidx + 7..];
        let uend = after.find('"')?;
        let url = &after[..uend];
        let rest = &after[uend..];
        let advance = uidx + 7 + uend;
        if url.ends_with("-none-any.whl") {
            if let Some(hidx) = rest.find("hash = \"sha256:") {
                let hafter = &rest[hidx + 15..];
                let hend = hafter.find('"')?;
                let sha = &hafter[..hend];
                if is_hex_of_len(sha, 64) {
                    if let Some(url) = http_url(url) {
                        return Some((url, sha.to_ascii_lowercase()));
                    }
                }
            }
        }
        search = &search[advance..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write(root: &Path, name: &str, content: &str) {
        tokio::fs::write(root.join(name), content).await.unwrap();
    }

    fn entry<'a>(entries: &'a [LockfileEntry], name: &str) -> &'a LockfileEntry {
        entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("no entry for {name}: {entries:?}"))
    }

    // ── package-lock ──────────────────────────────────────────────────────

    const PACKAGE_LOCK: &str = r#"{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "fixture", "version": "1.0.0" },
    "packages/member": { "name": "member", "version": "0.0.1" },
    "node_modules/member": { "resolved": "packages/member", "link": true },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-XI5MPz=="
    },
    "node_modules/@scope/pkg": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
      "integrity": "sha512-scoped=="
    },
    "node_modules/bundled-dep": {
      "version": "1.0.0",
      "inBundle": true
    },
    "node_modules/git-dep": {
      "version": "0.5.0",
      "resolved": "git+ssh://git@github.com/x/git-dep.git#abc"
    },
    "node_modules/vendored": {
      "version": "3.0.0",
      "resolved": "file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz",
      "integrity": "sha512-ours=="
    },
    "node_modules/evil": {
      "version": "../../escape",
      "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
      "integrity": "sha512-evil=="
    }
  }
}
"#;

    #[tokio::test]
    async fn package_lock_inventories_registry_entries() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::PackageLock);

        let lp = entry(&entries, "left-pad");
        assert_eq!(lp.version, "1.3.0");
        assert_eq!(lp.purl, "pkg:npm/left-pad@1.3.0");
        assert_eq!(
            lp.resolved.as_deref(),
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        );
        assert_eq!(lp.integrity, LockIntegrity::Sri("sha512-XI5MPz==".into()));

        let scoped = entry(&entries, "@scope/pkg");
        assert_eq!(scoped.purl, "pkg:npm/@scope/pkg@2.0.0");

        // git deps stay listed (discovery) but carry no fetchable URL.
        let git = entry(&entries, "git-dep");
        assert_eq!(git.resolved, None);
        assert_eq!(git.integrity, LockIntegrity::None);

        // Workspace members, links, bundled deps, our vendored spec, and
        // the unsafe-version entry are all absent.
        for absent in ["member", "fixture", "bundled-dep", "vendored", "evil"] {
            assert!(
                !entries.iter().any(|e| e.name == absent),
                "{absent} must not be inventoried: {entries:?}"
            );
        }
    }

    #[tokio::test]
    async fn shrinkwrap_wins_over_package_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;
        write(
            tmp.path(),
            "npm-shrinkwrap.json",
            r#"{ "lockfileVersion": 3, "packages": {
                 "node_modules/only-in-shrinkwrap": { "version": "9.9.9" } } }"#,
        )
        .await;

        let (_, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert!(entries.iter().any(|e| e.name == "only-in-shrinkwrap"));
        assert!(!entries.iter().any(|e| e.name == "left-pad"));
    }

    #[tokio::test]
    async fn legacy_v1_lock_without_packages_map_yields_none() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package-lock.json",
            r#"{ "lockfileVersion": 1, "dependencies": { "left-pad": { "version": "1.3.0" } } }"#,
        )
        .await;
        assert!(inventory_npm_lock(tmp.path()).await.is_none());
    }

    // ── pnpm ──────────────────────────────────────────────────────────────

    const PNPM_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPz==}

  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-scoped==}

  peer-user@4.0.0(left-pad@1.3.0):
    resolution: {integrity: sha512-peer==}

  local-thing@file:packages/local:
    resolution: {directory: packages/local, type: directory}

  vendored@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz:
    resolution: {integrity: sha512-ours==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz}

snapshots:

  left-pad@1.3.0: {}
";

    #[tokio::test]
    async fn pnpm_v9_keys_parse_with_peer_suffix_and_scoped_quoting() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Pnpm);

        assert_eq!(
            entry(&entries, "left-pad").integrity,
            LockIntegrity::Sri("sha512-XI5MPz==".into())
        );
        assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
        assert_eq!(entry(&entries, "peer-user").version, "4.0.0");
        // registry entries carry no URL in v9 — constructed at fetch time.
        assert_eq!(entry(&entries, "left-pad").resolved, None);
        for absent in ["local-thing", "vendored"] {
            assert!(!entries.iter().any(|e| e.name == absent), "{entries:?}");
        }
    }

    // ── Rush monorepo ───────────────────────────────────────────────────────

    /// Write `content` to `rel` under `root`, creating parent dirs.
    async fn write_nested(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(path, content).await.unwrap();
    }

    #[tokio::test]
    async fn rush_monorepo_inventories_common_and_subspace_locks() {
        // No root package.json/lock — only rush.json plus the generated
        // source-of-truth lock under common/config and one subspace lock.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
        write_nested(tmp.path(), "common/config/rush/pnpm-lock.yaml", PNPM_LOCK).await;
        write_nested(
            tmp.path(),
            "common/config/subspaces/frontend/pnpm-lock.yaml",
            "lockfileVersion: '9.0'

packages:

  only-in-subspace@9.9.9:
    resolution: {integrity: sha512-sub==}
",
        )
        .await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Pnpm);
        // Union across the common lock and the subspace lock.
        assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
        assert_eq!(entry(&entries, "only-in-subspace").version, "9.9.9");
    }

    #[tokio::test]
    async fn rush_json_without_any_lock_yields_none() {
        // rush.json but no common/subspace lock at all: nothing to inventory.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
        assert!(inventory_npm_lock(tmp.path()).await.is_none());
    }

    #[tokio::test]
    async fn root_pnpm_lock_wins_over_rush_fallback() {
        // A plain pnpm project that also happens to carry a stray rush.json
        // must route through the normal root-lock path, never the fallback.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
        write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;
        write_nested(
            tmp.path(),
            "common/config/rush/pnpm-lock.yaml",
            "lockfileVersion: '9.0'

packages:

  only-in-common@1.0.0:
    resolution: {integrity: sha512-common==}
",
        )
        .await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Pnpm);
        assert!(entries.iter().any(|e| e.name == "left-pad"));
        assert!(
            !entries.iter().any(|e| e.name == "only-in-common"),
            "the root lock must win; the rush fallback must not run: {entries:?}"
        );
    }

    // ── yarn classic ──────────────────────────────────────────────────────

    const YARN_CLASSIC: &str = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


\"@scope/pkg@^2.0.0\":
  version \"2.0.0\"
  resolved \"https://registry.yarnpkg.com/@scope/pkg/-/pkg-2.0.0.tgz#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
  integrity sha512-scoped==

left-pad@1.3.0, left-pad@^1.3.0:
  version \"1.3.0\"
  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"
  integrity sha512-XI5MPz==

old-school@0.1.0:
  version \"0.1.0\"
  resolved \"https://registry.yarnpkg.com/old-school/-/old-school-0.1.0.tgz#cccccccccccccccccccccccccccccccccccccccc\"

aliased@npm:real-name@^3.0.0:
  version \"3.0.0\"
  resolved \"https://registry.yarnpkg.com/real-name/-/real-name-3.0.0.tgz#dddddddddddddddddddddddddddddddddddddddd\"
  integrity sha512-alias==
";

    #[tokio::test]
    async fn yarn_classic_blocks_yield_resolved_sha1_and_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "yarn.lock", YARN_CLASSIC).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnClassic);

        let lp = entry(&entries, "left-pad");
        assert_eq!(
            lp.resolved.as_deref(),
            Some("https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"),
            "the #sha1 fragment is split off the URL"
        );
        assert_eq!(lp.integrity, LockIntegrity::Sri("sha512-XI5MPz==".into()));

        // Integrity-less old locks fall back to the sha1 fragment.
        assert_eq!(
            entry(&entries, "old-school").integrity,
            LockIntegrity::Sha1Hex("c".repeat(40))
        );

        // `alias@npm:real@range` resolves to the real name.
        assert!(entries.iter().any(|e| e.name == "real-name"));
        assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
    }

    // ── yarn berry ────────────────────────────────────────────────────────

    const YARN_BERRY: &str =
        "# This file is generated by running \"yarn install\" inside your project.
# Manifest files (package.json) are also used.

__metadata:
  version: 8
  cacheKey: 10c0

\"fixture@workspace:.\":
  version: 0.0.0-use.local
  resolution: \"fixture@workspace:.\"
  languageName: unknown
  linkType: soft

\"left-pad@npm:1.3.0\":
  version: 1.3.0
  resolution: \"left-pad@npm:1.3.0\"
  checksum: 10c0/deadbeefcafe==
  languageName: node
  linkType: hard

\"@scope/pkg@npm:^2.0.0\":
  version: 2.0.0
  resolution: \"@scope/pkg@npm:2.0.0\"
  checksum: 10c0/scopedchecksum==
  languageName: node
  linkType: hard
";

    #[tokio::test]
    async fn yarn_berry_registry_resolutions_inventory_with_checksums() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "yarn.lock", YARN_BERRY).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnBerry);

        let lp = entry(&entries, "left-pad");
        assert_eq!(lp.version, "1.3.0");
        assert_eq!(
            lp.integrity,
            LockIntegrity::BerryChecksum("10c0/deadbeefcafe==".into())
        );
        assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
        // The workspace root is not a registry package.
        assert!(!entries.iter().any(|e| e.name == "fixture"), "{entries:?}");
    }

    // ── bun ───────────────────────────────────────────────────────────────

    const BUN_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fixture", "dependencies": { "left-pad": "1.3.0" } },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPz=="],
    "@scope/pkg": ["@scope/pkg@2.0.0", "", {}, "sha512-scoped=="],
    "vendored": ["vendored@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz", {}],
    "linked": ["linked@workspace:packages/linked", {}],
  }
}
"#;

    #[tokio::test]
    async fn bun_registry_tuples_parse_and_locals_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "bun.lock", BUN_LOCK).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);

        assert_eq!(
            entry(&entries, "left-pad").integrity,
            LockIntegrity::Sri("sha512-XI5MPz==".into())
        );
        assert_eq!(entry(&entries, "left-pad").resolved, None);
        assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
        for absent in ["vendored", "linked"] {
            assert!(!entries.iter().any(|e| e.name == absent), "{entries:?}");
        }
    }

    // ── shared semantics ──────────────────────────────────────────────────

    #[tokio::test]
    async fn lookup_bridges_percent_encoded_purls() {
        let entries = vec![
            LockfileEntry::npm("@scope/pkg", "2.0.0", None, LockIntegrity::None),
            LockfileEntry::npm("left-pad", "1.3.0", None, LockIntegrity::None),
        ];
        assert!(lookup(&entries, "pkg:npm/%40scope/pkg@2.0.0").is_some());
        assert!(lookup(&entries, "pkg:npm/@scope/pkg@2.0.0").is_some());
        assert!(lookup(&entries, "pkg:npm/left-pad@1.3.0?artifact_id=x").is_some());
        assert!(lookup(&entries, "pkg:npm/left-pad@9.9.9").is_none());
        assert!(lookup(&entries, "pkg:pypi/left-pad@1.3.0").is_none());
    }

    #[tokio::test]
    async fn dedup_prefers_integrity_bearing_instance() {
        let raw = vec![
            LockfileEntry::npm("dup", "1.0.0", None, LockIntegrity::None),
            LockfileEntry::npm(
                "dup",
                "1.0.0",
                None,
                LockIntegrity::Sri("sha512-x==".into()),
            ),
            LockfileEntry::npm("dup", "1.0.0", None, LockIntegrity::None),
        ];
        let out = finalize_npm(raw);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].integrity, LockIntegrity::Sri("sha512-x==".into()));
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn cargo_lock_inventories_crates_io_entries() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.lock",
            r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"

[[package]]
name = "git-dep"
version = "0.5.0"
source = "git+https://github.com/x/git-dep?rev=abc#abc"

[[package]]
name = "sparse-crate"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .await;

        let entries = inventory_cargo_lock(tmp.path()).await.unwrap();
        let serde_entry = entry(&entries, "serde");
        assert_eq!(serde_entry.version, "1.0.200");
        assert_eq!(serde_entry.purl, "pkg:cargo/serde@1.0.200");
        assert_eq!(
            serde_entry.integrity,
            LockIntegrity::Sha256Hex(
                "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f".into()
            )
        );
        assert!(matches!(
            entry(&entries, "sparse-crate").integrity,
            LockIntegrity::Sha256Hex(_)
        ));
        // Workspace member (no source) excluded; git source unverifiable.
        assert!(!entries.iter().any(|e| e.name == "fixture"));
        assert_eq!(entry(&entries, "git-dep").integrity, LockIntegrity::None);
    }

    #[cfg(feature = "golang")]
    #[tokio::test]
    async fn go_sum_inventories_module_zip_lines() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "go.sum",
            "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n\
             github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7YrpYKXt5YId3A/Tnip5kqbEAP+KLuI3SUcPTeU=\n\
             golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n",
        )
        .await;

        let entries = inventory_go_sum(tmp.path()).await.unwrap();
        assert_eq!(entries.len(), 2, "the /go.mod line is skipped: {entries:?}");
        let gin = entry(&entries, "github.com/gin-gonic/gin");
        assert_eq!(gin.version, "v1.9.1");
        assert_eq!(gin.purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assert_eq!(
            gin.integrity,
            LockIntegrity::GoH1("h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=".into())
        );
    }

    #[tokio::test]
    async fn lookup_matches_cargo_and_golang_purls() {
        let entries = vec![
            LockfileEntry {
                ecosystem: "cargo",
                name: "serde".into(),
                version: "1.0.200".into(),
                purl: "pkg:cargo/serde@1.0.200".into(),
                resolved: None,
                integrity: LockIntegrity::None,
            },
            LockfileEntry {
                ecosystem: "golang",
                name: "github.com/x/y".into(),
                version: "v1.0.0".into(),
                purl: "pkg:golang/github.com/x/y@v1.0.0".into(),
                resolved: None,
                integrity: LockIntegrity::None,
            },
        ];
        assert!(lookup(&entries, "pkg:cargo/serde@1.0.200").is_some());
        assert!(lookup(&entries, "pkg:golang/github.com/x/y@v1.0.0").is_some());
        assert!(lookup(&entries, "pkg:cargo/serde@9.9.9").is_none());
        assert!(
            lookup(&entries, "pkg:npm/serde@1.0.200").is_none(),
            "ecosystem tags must match, not just name@version"
        );
    }

    #[cfg(feature = "composer")]
    #[tokio::test]
    async fn composer_lock_inventories_dist_entries() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "composer.lock",
            r#"{
  "packages": [
    {
      "name": "Monolog/Monolog",
      "version": "v3.5.0",
      "dist": {
        "type": "zip",
        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
        "shasum": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      }
    },
    {
      "name": "vendored/pkg",
      "version": "1.0.0",
      "dist": { "type": "path", "url": ".socket/vendor/composer/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored/pkg@1.0.0" }
    }
  ],
  "packages-dev": [
    {
      "name": "symfony/console",
      "version": "v6.4.1",
      "dist": { "type": "zip", "url": "https://example.com/console.zip", "shasum": "" }
    }
  ]
}"#,
        )
        .await;

        let entries = inventory_composer_lock(tmp.path()).await.unwrap();
        let monolog = entry(&entries, "monolog/monolog");
        assert_eq!(
            monolog.version, "3.5.0",
            "leading v dropped, name lowercased"
        );
        assert_eq!(monolog.purl, "pkg:composer/monolog/monolog@3.5.0");
        assert!(matches!(monolog.integrity, LockIntegrity::Sha1Hex(_)));
        assert!(monolog.resolved.as_deref().unwrap().contains("zipball"));
        // Empty shasum → discovery-only; path dist (ours) excluded.
        assert_eq!(
            entry(&entries, "symfony/console").integrity,
            LockIntegrity::None
        );
        assert!(!entries.iter().any(|e| e.name == "vendored/pkg"));
    }

    #[tokio::test]
    async fn gemfile_lock_inventories_specs_and_checksums() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      \
             actionpack (= 7.1.0)\n    rack (3.0.8)\n    nokogiri (1.16.5-arm64-darwin)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n\nCHECKSUMS\n  \
             rails (7.1.0) sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n\
             BUNDLED WITH\n   2.6.0\n",
        )
        .await;

        let entries = inventory_gemfile_lock(tmp.path()).await.unwrap();
        let rails = entry(&entries, "rails");
        assert_eq!(rails.version, "7.1.0");
        assert_eq!(rails.purl, "pkg:gem/rails@7.1.0");
        assert!(matches!(rails.integrity, LockIntegrity::Sha256Hex(_)));
        assert_eq!(
            rails.resolved.as_deref(),
            Some("https://rubygems.org/downloads/rails-7.1.0.gem")
        );
        // No CHECKSUMS entry → discovery-only; platform gem skipped;
        // dependency range lines never parse as specs.
        assert_eq!(entry(&entries, "rack").integrity, LockIntegrity::None);
        assert!(!entries.iter().any(|e| e.name == "nokogiri"));
        assert!(!entries.iter().any(|e| e.name == "actionpack"));
    }

    #[tokio::test]
    async fn uv_lock_inventories_pure_wheels() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "uv.lock",
            r#"version = 1

[[package]]
name = "Requests"
version = "2.28.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/aa/requests-2.28.0-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
]

[[package]]
name = "native-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/bb/native_only-1.0.0-cp312-macosx.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
]

[[package]]
name = "local-proj"
version = "0.0.1"
source = { editable = "." }
"#,
        )
        .await;

        let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
        let requests = entry(&entries, "requests");
        assert_eq!(requests.purl, "pkg:pypi/requests@2.28.0", "PEP 503 name");
        assert!(matches!(requests.integrity, LockIntegrity::Sha256Hex(_)));
        assert!(requests
            .resolved
            .as_deref()
            .unwrap()
            .ends_with("py3-none-any.whl"));
        // Platform-only wheels → discovery-only; editable sources excluded.
        assert_eq!(
            entry(&entries, "native-only").integrity,
            LockIntegrity::None
        );
        assert!(!entries.iter().any(|e| e.name == "local-proj"));
    }

    #[tokio::test]
    async fn poetry_and_requirements_are_discovery_only() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "poetry.lock",
            "[[package]]\nname = \"Flask_Login\"\nversion = \"0.6.3\"\n\n[metadata]\nlock-version = \"2.0\"\n",
        )
        .await;
        let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
        let fl = entry(&entries, "flask-login");
        assert_eq!(fl.purl, "pkg:pypi/flask-login@0.6.3");
        assert_eq!(fl.integrity, LockIntegrity::None);

        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "requirements.txt",
            "# pinned\nrequests[security]==2.28.0 --hash=sha256:abc \\\n    --hash=sha256:def\nflask>=2.0\n-e .\n",
        )
        .await;
        let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].purl, "pkg:pypi/requests@2.28.0");
    }

    #[tokio::test]
    async fn unsupported_flavors_yield_none() {
        // PnP marker wins over any lockfile.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), ".pnp.cjs", "/* pnp */").await;
        write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;
        assert!(inventory_npm_lock(tmp.path()).await.is_none());

        // pnpm v6.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '6.0'\n").await;
        assert!(inventory_npm_lock(tmp.path()).await.is_none());

        // No lockfile at all.
        let tmp = tempfile::tempdir().unwrap();
        assert!(inventory_npm_lock(tmp.path()).await.is_none());
    }
}

#[cfg(test)]
mod recover_tests {
    use super::super::state::WiringAction;
    use super::super::state::{CargoLockOriginal, VendorArtifact, VendorEntry, WiringRecord};
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn entry(eco: &str, base_purl: &str, wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            ecosystem: eco.into(),
            base_purl: base_purl.into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/{eco}/{UUID}/x"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    fn rec(kind: &str, original: serde_json::Value) -> WiringRecord {
        WiringRecord {
            file: "lock".into(),
            kind: kind.into(),
            action: WiringAction::Rewritten,
            key: Some("k".into()),
            original: Some(original),
            new: None,
        }
    }

    #[tokio::test]
    async fn npm_lock_entry_fragment_recovers_sri_and_url() {
        let tmp = tempfile::tempdir().unwrap();
        let e = entry(
            "npm",
            "pkg:npm/@scope/x@1.2.3",
            vec![rec(
                "npm_lock_entry",
                serde_json::json!({
                    "resolved": "https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz",
                    "integrity": "sha512-AAAA",
                }),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
        assert_eq!(got.ecosystem, "npm");
        assert_eq!(got.name, "@scope/x");
        assert_eq!(got.version, "1.2.3");
        assert_eq!(
            got.resolved.as_deref(),
            Some("https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz")
        );
        assert_eq!(got.integrity, LockIntegrity::Sri("sha512-AAAA".into()));
    }

    #[tokio::test]
    async fn pnpm_package_lines_recover_integrity_and_tarball() {
        let tmp = tempfile::tempdir().unwrap();
        let e = entry(
            "npm",
            "pkg:npm/left-pad@1.3.0",
            vec![rec(
                "pnpm_lock_package",
                serde_json::json!([
                    "  left-pad@1.3.0:",
                    "    resolution: {integrity: sha512-BBBB, tarball: https://npm.corp/left-pad-1.3.0.tgz}",
                ]),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sri("sha512-BBBB".into()));
        assert_eq!(
            got.resolved.as_deref(),
            Some("https://npm.corp/left-pad-1.3.0.tgz")
        );
    }

    #[tokio::test]
    async fn yarn_classic_block_prefers_sri_else_sha1() {
        let tmp = tempfile::tempdir().unwrap();
        let sha1 = "a".repeat(40);
        let with_both = entry(
            "npm",
            "pkg:npm/x@1.0.0",
            vec![rec(
                "yarn_lock_block",
                serde_json::json!([
                    "x@^1.0.0:",
                    "  version \"1.0.0\"",
                    format!("  resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#{sha1}\""),
                    "  integrity sha512-CCCC",
                ]),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &with_both).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sri("sha512-CCCC".into()));
        assert_eq!(
            got.resolved.as_deref(),
            Some("https://registry.yarnpkg.com/x/-/x-1.0.0.tgz")
        );

        let sha1_only = entry(
            "npm",
            "pkg:npm/x@1.0.0",
            vec![rec(
                "yarn_lock_block",
                serde_json::json!([format!(
                    "  resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#{sha1}\""
                )]),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &sha1_only).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sha1Hex(sha1));
    }

    #[tokio::test]
    async fn berry_checksum_and_bun_tuple_recover() {
        let tmp = tempfile::tempdir().unwrap();
        let berry = entry(
            "npm",
            "pkg:npm/x@1.0.0",
            vec![rec(
                "yarn_berry_lock_entry",
                serde_json::json!(["x@npm:1.0.0:", "  checksum: 10c0/abcdef"]),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &berry).await.unwrap();
        assert_eq!(
            got.integrity,
            LockIntegrity::BerryChecksum("10c0/abcdef".into())
        );
        assert_eq!(got.resolved, None);

        let bun = entry(
            "npm",
            "pkg:npm/x@1.0.0",
            vec![rec(
                "bun_lock_package",
                serde_json::json!("    \"x\": [\"x@1.0.0\", \"\", {}, \"sha512-DDDD\"],"),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &bun).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sri("sha512-DDDD".into()));
    }

    #[tokio::test]
    async fn cargo_recovers_from_entry_lock_checksum() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "b".repeat(64);
        let mut e = entry("cargo", "pkg:cargo/serde@1.0.0", vec![]);
        e.lock = Some(CargoLockOriginal {
            source: "registry+https://github.com/rust-lang/crates.io-index".into(),
            checksum: Some(sha.clone()),
        });
        let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
        assert_eq!(got.ecosystem, "cargo");
        assert_eq!(got.integrity, LockIntegrity::Sha256Hex(sha));
        assert_eq!(got.resolved, None);

        // No checksum recorded → unrecoverable, never an unverified fetch.
        let mut bare = entry("cargo", "pkg:cargo/serde@1.0.0", vec![]);
        bare.lock = None;
        assert!(recover_lock_entry(tmp.path(), &bare).await.is_err());
    }

    #[tokio::test]
    async fn composer_gem_uv_fragments_recover() {
        let tmp = tempfile::tempdir().unwrap();
        let sha1 = "c".repeat(40);
        let composer = entry(
            "composer",
            "pkg:composer/monolog/monolog@2.9.1",
            vec![rec(
                "composer_lock_package",
                serde_json::json!({
                    "name": "monolog/monolog",
                    "dist": {
                        "type": "zip",
                        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
                        "shasum": sha1,
                    },
                }),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &composer).await.unwrap();
        assert_eq!(got.name, "monolog/monolog");
        assert_eq!(got.integrity, LockIntegrity::Sha1Hex(sha1));

        // gem: checksum line + remote read from the unrewired Gemfile.lock.
        let sha256 = "d".repeat(64);
        tokio::fs::write(
            tmp.path().join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n",
        )
        .await
        .unwrap();
        let gem = entry(
            "gem",
            "pkg:gem/rack@3.0.0",
            vec![rec(
                "gemfile_lock_checksum",
                serde_json::json!(format!("  rack (3.0.0) sha256={sha256}")),
            )],
        );
        let got = recover_lock_entry(tmp.path(), &gem).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sha256Hex(sha256.clone()));
        assert_eq!(
            got.resolved.as_deref(),
            Some("https://rubygems.org/downloads/rack-3.0.0.gem")
        );

        // uv: the original [[package]] unit lists wheels; only the PURE one
        // is recoverable.
        let wheel_sha = "e".repeat(64);
        let unit = format!(
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nwheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/six-1.16.0-cp39-cp39-linux_x86_64.whl\", hash = \"sha256:{}\" }},\n    {{ url = \"https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{wheel_sha}\" }},\n]\n",
            "f".repeat(64)
        );
        let uv = entry(
            "pypi",
            "pkg:pypi/six@1.16.0",
            vec![rec("uv_lock_package", serde_json::json!(unit))],
        );
        let got = recover_lock_entry(tmp.path(), &uv).await.unwrap();
        assert_eq!(got.integrity, LockIntegrity::Sha256Hex(wheel_sha));
        assert!(got.resolved.unwrap().ends_with("py2.py3-none-any.whl"));

        // platform-locked wheels are explicitly unrepairable from the registry.
        let mut locked = entry("pypi", "pkg:pypi/six@1.16.0", vec![]);
        locked.artifact.platform_locked = Some(true);
        assert!(recover_lock_entry(tmp.path(), &locked).await.is_err());
    }

    #[tokio::test]
    async fn unrecoverable_fragments_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        // No wiring at all.
        let bare = entry("npm", "pkg:npm/x@1.0.0", vec![]);
        assert!(recover_lock_entry(tmp.path(), &bare).await.is_err());
        // golang routes through go.sum, never the ledger.
        let go = entry("golang", "pkg:golang/golang.org/x/text@v0.14.0", vec![]);
        assert!(recover_lock_entry(tmp.path(), &go).await.is_err());
        // Poisoned integrity shapes are rejected.
        let bad = entry(
            "npm",
            "pkg:npm/x@1.0.0",
            vec![rec(
                "npm_lock_entry",
                serde_json::json!({"resolved": "https://x/", "integrity": "lol"}),
            )],
        );
        assert!(recover_lock_entry(tmp.path(), &bad).await.is_err());
    }
}
