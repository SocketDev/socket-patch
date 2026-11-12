//! Emulation of `registry.npmjs.org`: package metadata and tarballs, for the rules_js
//! fixtures and the hash-miss cells where Bazel runs pnpm.
//!
//! The store is a mirror directory: every
//! `<mirror>/registry.npmjs.org/<name>/-/<leaf>-<version>.tgz` is served at the URL a
//! pnpm lock resolves that package to, so committed locks keep the production host.
//!
//! Two clients read this registry and they arrive differently. rules_js fetches each
//! tarball through Bazel's downloader, which the downloader config rewrites to the
//! fixture server. A pnpm that Bazel runs (`update_pnpm_lock` with a stale hash file)
//! opens its own connections, which no downloader config sees: a test points it at
//! [`loopback_registry`] through a declared `.npmrc`, and it then asks for the package
//! document of every dependency. The documents served here name tarball URLs under
//! that same loopback registry, so pnpm treats them as the registry's own and keeps a
//! lock without `tarball:` pins unchanged.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha512};

use super::super::fixture_server::FixtureServer;
use crate::bazel_common::snapshot::{snapshot, Entry};

/// The host a lock without `tarball:` pins resolves every package to.
pub const HOST: &str = "registry.npmjs.org";

/// One `<name>@<version>` of the mirror.
pub struct Tarball {
    /// `left-pad`, `@tootallnate/once`.
    pub name: String,
    pub version: String,
    /// `<name>/-/<leaf>-<version>.tgz`: the path under the registry root.
    pub path: String,
    pub bytes: Vec<u8>,
}

impl Tarball {
    /// The production URL: what rules_js asks Bazel's downloader for.
    pub fn url(&self) -> String {
        format!("https://{HOST}/{}", self.path)
    }
}

/// `sha512-<base64>`: the form a pnpm lock's `integrity` has.
pub fn integrity(bytes: &[u8]) -> String {
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    format!("sha512-{digest}")
}

/// The registry root a Bazel-run pnpm is pointed at (`registry=` in a declared
/// `.npmrc`), with the trailing slash pnpm expects.
pub fn loopback_registry(server: &FixtureServer) -> String {
    format!("{}/{HOST}/", server.loopback_origin())
}

/// Every tarball under `<mirror>/registry.npmjs.org`. `Err` for a file that is not at
/// `<name>/-/<leaf>-<version>.tgz`: a file this module cannot name would be served
/// nowhere while the lock that pins it looked covered.
pub fn tarballs(mirror: &Path) -> Result<Vec<Tarball>, String> {
    let root = mirror.join(HOST);
    if !root.is_dir() {
        return Err(format!("no npm mirror at {}", root.display()));
    }
    let mut out = Vec::new();
    for (path, entry) in snapshot(&root) {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        let parsed = path.split_once("/-/").and_then(|(name, file)| {
            let leaf = name.rsplit('/').next()?;
            let version = file
                .strip_prefix(leaf)?
                .strip_prefix('-')?
                .strip_suffix(".tgz")?;
            (!version.is_empty()).then(|| (name.to_string(), version.to_string()))
        });
        let Some((name, version)) = parsed else {
            return Err(format!(
                "{path} in the npm mirror is not <name>/-/<leaf>-<version>.tgz"
            ));
        };
        out.push(Tarball {
            name,
            version,
            path,
            bytes,
        });
    }
    Ok(out)
}

/// The bytes of the member `path` (`package/index.js`) of a registry tarball.
pub fn member(tarball: &[u8], path: &str) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry.path().map_err(|e| e.to_string())?.to_string_lossy() != path {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        return Ok(bytes);
    }
    Err(format!("no member {path}"))
}

/// `package/package.json` of a registry tarball.
fn manifest(tarball: &Tarball) -> Result<Value, String> {
    let what = |why: String| format!("{}: {why}", tarball.path);
    let bytes = member(&tarball.bytes, "package/package.json").map_err(what)?;
    serde_json::from_slice(&bytes).map_err(|e| what(e.to_string()))
}

/// The package document of `name` as the registry at `registry` (a root with a
/// trailing slash) serves it: each version is the tarball's own `package.json` plus
/// its `dist` block. `Err` when a tarball's manifest names another package or
/// version than its path: pnpm would then resolve something the lock does not pin.
pub fn packument(name: &str, versions: &[&Tarball], registry: &str) -> Result<Value, String> {
    let mut documents = serde_json::Map::new();
    for tarball in versions {
        let mut document = manifest(tarball)?;
        if document["name"] != name || document["version"] != tarball.version.as_str() {
            return Err(format!(
                "{} holds {}@{}",
                tarball.path, document["name"], document["version"]
            ));
        }
        document["dist"] = json!({
            "tarball": format!("{registry}{}", tarball.path),
            "integrity": integrity(&tarball.bytes),
            "shasum": hex::encode(<sha1::Sha1 as sha1::Digest>::digest(&tarball.bytes)),
        });
        documents.insert(tarball.version.clone(), document);
    }
    // The mirror holds one version per package today; with several, the last in
    // path order stands in for `latest`, which no pinned lock reads.
    let latest = versions.last().map(|tarball| tarball.version.clone());
    Ok(json!({
        "name": name,
        "dist-tags": { "latest": latest },
        "versions": documents,
    }))
}

/// Serve the mirror on `server`: every tarball at its production URL, and every
/// package document for a pnpm pointed at [`loopback_registry`] (a scoped name is
/// asked for as `@scope%2Fname`; the other spellings are served too).
///
/// Returns the URL scopes this registry owns, for the downloader config: a scope is a
/// URL without its scheme, and a trailing `*` makes it a prefix. Each package's
/// tarball directory is one scope, so a request for a version the mirror lacks is a
/// 404 from the fixture server and never reaches the real registry.
pub fn mount(server: &FixtureServer, mirror: &Path) -> Result<Vec<String>, String> {
    let tarballs = tarballs(mirror)?;
    let mut by_name: BTreeMap<&str, Vec<&Tarball>> = BTreeMap::new();
    for tarball in &tarballs {
        server.serve(&tarball.url(), tarball.bytes.clone());
        by_name.entry(&tarball.name).or_default().push(tarball);
    }
    let registry = loopback_registry(server);
    let mut scopes = Vec::new();
    for (name, versions) in by_name {
        let document = packument(name, &versions, &registry)?.to_string();
        let mut spellings = vec![name.to_string()];
        if name.starts_with('@') {
            spellings.push(name.replace('/', "%2F"));
            spellings.push(name.replace('/', "%2f"));
        }
        for spelling in spellings {
            let url = format!("https://{HOST}/{spelling}");
            server.serve_as(&url, "application/json", document.clone());
        }
        scopes.push(format!("{HOST}/{name}/-/*"));
    }
    Ok(scopes)
}
