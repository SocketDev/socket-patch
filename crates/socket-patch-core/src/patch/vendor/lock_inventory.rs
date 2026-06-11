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

use crate::patch::path_safety;
use crate::utils::purl::strip_purl_qualifiers;

use super::npm_common::is_safe_npm_name;
use super::npm_flavor::{detect_npm_lock_flavor, NpmLockFlavor};
use super::path::parse_vendor_path;
use super::{bun_lock, pnpm_lock, yarn_berry_lock, yarn_classic_lock};

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
pub async fn inventory_npm_lock(
    project_root: &Path,
) -> Option<(NpmLockFlavor, Vec<LockfileEntry>)> {
    let (flavor, _warnings) = detect_npm_lock_flavor(project_root).await.ok()?;
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
    // purl type → vendor-ecosystem tag (same mapping the dispatcher uses).
    let eco = match purl_type {
        "npm" => "npm",
        "cargo" => "cargo",
        "golang" => "golang",
        "pypi" => "pypi",
        "gem" => "gem",
        "composer" => "composer",
        _ => return None,
    };
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&rest[..at], &rest[at + 1..]);
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
                if out[i].integrity == LockIntegrity::None
                    && entry.integrity != LockIntegrity::None
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
pub async fn inventory_cargo_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("Cargo.lock"))
        .await
        .ok()?;
    let mut out = Vec::new();
    let mut cur: Option<(Option<String>, Option<String>, Option<String>, Option<String>)> = None;
    let flush = |cur: &mut Option<(Option<String>, Option<String>, Option<String>, Option<String>)>,
                     out: &mut Vec<LockfileEntry>| {
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
                Some(c) if crates_io && c.len() == 64 && c.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    LockIntegrity::Sha256Hex(c)
                }
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
pub async fn inventory_go_sum(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(project_root.join("go.sum"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version), Some(hash)) =
            (parts.next(), parts.next(), parts.next())
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
            || node.get("inBundle").and_then(Value::as_bool).unwrap_or(false)
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

/// Extract one value from an inline YAML map fragment like
/// `{integrity: sha512-…, tarball: file:…}` (values optionally quoted).
fn inline_map_value(fragment: &str, field: &str) -> Option<String> {
    let at = fragment.find(&format!("{field}:"))?;
    let rest = fragment[at + field.len() + 1..].trim_start();
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches(['\'', '"']);
    (!value.is_empty()).then(|| value.to_string())
}

async fn inventory_pnpm_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("pnpm-lock.yaml"))
        .await
        .ok()?;
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
                if let Some(v) = inline_map_value(rest, "integrity") {
                    integrity = LockIntegrity::Sri(v);
                }
                tarball = inline_map_value(rest, "tarball");
                break;
            }
        }
        // Our own vendored spec: not a registry dependency.
        if tarball.as_deref().is_some_and(|t| parse_vendor_path(t).is_some()) {
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

// ───────────────────────────── yarn.lock (classic) ─────────────────────────────

async fn inventory_yarn_classic(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("yarn.lock")).await.ok()?;
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
                    (frag.len() == 40 && frag.bytes().all(|b| b.is_ascii_hexdigit()))
                        .then(|| frag.to_ascii_lowercase()),
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
    let text = tokio::fs::read_to_string(root.join("yarn.lock")).await.ok()?;
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
        let version = yarn_berry_lock::berry_field(&block.lines, "version")
            .unwrap_or(version_from_res);
        let integrity = yarn_berry_lock::berry_field(&block.lines, "checksum")
            .map(|c| LockIntegrity::BerryChecksum(c.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, None, integrity));
    }
    Some(out)
}

// ──────────────────────────────── bun.lock ────────────────────────────────

async fn inventory_bun(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = tokio::fs::read_to_string(root.join("bun.lock")).await.ok()?;
    bun_lock::check_lock_version(&text).ok()?;
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let entries = bun_lock::parse_packages_section(&lines).ok()?;

    let mut out = Vec::new();
    for entry in entries {
        // Registry entries are 4-tuples `[spec, registry, {deps}, sha512]`;
        // our vendored 3-tuples and other shapes are skipped.
        if entry.elems.len() != 4 || !entry.elems[2].starts_with('{') {
            continue;
        }
        let Some(spec) = entry.elems.first().and_then(|e| bun_lock::decode_json_string(e))
        else {
            continue;
        };
        let Some((name, version)) = bun_lock::split_name_spec(&spec) else {
            continue;
        };
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(registry) = bun_lock::decode_json_string(&entry.elems[1]) else {
            continue;
        };
        let Some(integrity) = bun_lock::decode_json_string(&entry.elems[3]) else {
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

    const YARN_BERRY: &str = "# This file is generated by running \"yarn install\" inside your project.
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
            LockfileEntry::npm("dup", "1.0.0", None, LockIntegrity::Sri("sha512-x==".into())),
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
