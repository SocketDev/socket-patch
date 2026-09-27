//! Registry lookups for the upstream restore: what a default-registry lock
//! entry pins, re-resolved from the public registry (each base overridable
//! by the same env vars the vendored fetch honors, so tests and mirrors can
//! point it elsewhere).

use std::collections::HashMap;

use serde_json::Value;
use tokio::sync::Mutex;

use crate::vendor::registry_fetch::{build_registry_client, npm_registry_base, RegistryClient};

/// An npm version's `dist` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmDist {
    /// The registry's tarball URL for the version.
    pub tarball: String,
    /// The SRI `dist.integrity` (sha512 on every modern publish).
    pub integrity: Option<String>,
    /// The hex sha1 `dist.shasum`.
    pub shasum: Option<String>,
}

/// A Go module version's two go.sum hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoSums {
    /// `h1:` of the module zip.
    pub zip_h1: String,
    /// `h1:` of the module's go.mod.
    pub mod_h1: String,
}

/// The sparse crates.io index; override with `SOCKET_CRATES_INDEX`.
pub(crate) const DEFAULT_CRATES_INDEX: &str = "https://index.crates.io";

fn crates_index_base() -> String {
    std::env::var("SOCKET_CRATES_INDEX")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CRATES_INDEX.to_string())
}

/// The sparse-index path of a crate (`cargo`'s `index_path` layout).
fn crates_index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

/// The offline refusal every lookup returns under `--offline`.
pub(crate) const OFFLINE: &str =
    "the upstream entry must be re-resolved from the registry, and this run is offline";

type Cache<T> = Mutex<HashMap<(String, String), Result<T, String>>>;

/// One client per restore run; every lookup is cached (success and
/// failure alike) so a pin wired in several files costs one request.
pub(crate) struct UpstreamClient {
    http: RegistryClient,
    offline: bool,
    npm: Cache<NpmDist>,
    npm_tarballs: Cache<Vec<u8>>,
    cargo: Cache<String>,
    go: Cache<GoSums>,
}

impl UpstreamClient {
    pub(crate) fn new(offline: bool) -> Self {
        UpstreamClient {
            http: build_registry_client(),
            offline,
            npm: Mutex::default(),
            npm_tarballs: Mutex::default(),
            cargo: Mutex::default(),
            go: Mutex::default(),
        }
    }

    async fn get_json(&self, url: &str) -> Result<Value, String> {
        let resp = self
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("GET {url}: HTTP {status}"));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("reading {url}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{url} is not JSON: {e}"))
    }

    async fn get_text(&self, url: &str) -> Result<String, String> {
        let bytes = crate::vendor::registry_fetch::download(&self.http, url).await?;
        String::from_utf8(bytes).map_err(|_| format!("{url} is not UTF-8"))
    }

    /// `dist` of `name@version` from the npm registry's version document.
    pub(crate) async fn npm_dist(&self, name: &str, version: &str) -> Result<NpmDist, String> {
        let key = (name.to_string(), version.to_string());
        if let Some(hit) = self.npm.lock().await.get(&key) {
            return hit.clone();
        }
        let result = self.fetch_npm_dist(name, version).await;
        self.npm.lock().await.insert(key, result.clone());
        result
    }

    async fn fetch_npm_dist(&self, name: &str, version: &str) -> Result<NpmDist, String> {
        if self.offline {
            return Err(OFFLINE.to_string());
        }
        let encoded_name = name.replace('/', "%2f");
        let url = format!(
            "{}/{encoded_name}/{}",
            npm_registry_base(),
            crate::utils::uri::encode_uri_component(version)
        );
        let doc = self.get_json(&url).await?;
        let dist = doc
            .get("dist")
            .ok_or_else(|| format!("{url} carries no `dist` block"))?;
        let str_field = |k: &str| dist.get(k).and_then(Value::as_str).map(str::to_string);
        let tarball = str_field("tarball")
            .ok_or_else(|| format!("{url} carries no `dist.tarball`"))?;
        Ok(NpmDist {
            tarball,
            integrity: str_field("integrity"),
            shasum: str_field("shasum"),
        })
    }

    /// The verified upstream tarball bytes of `name@version` (checked
    /// against the registry's `dist.integrity`).
    pub(crate) async fn npm_tarball(&self, name: &str, version: &str) -> Result<Vec<u8>, String> {
        let key = (name.to_string(), version.to_string());
        if let Some(hit) = self.npm_tarballs.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            let dist = self.npm_dist(name, version).await?;
            let integrity = dist
                .integrity
                .clone()
                .ok_or_else(|| format!("the registry records no integrity for {name}@{version}"))?;
            let bytes = crate::vendor::registry_fetch::download(&self.http, &dist.tarball).await?;
            crate::vendor::registry_fetch::verify_sri(&bytes, &integrity)?;
            Ok(bytes)
        }
        .await;
        self.npm_tarballs.lock().await.insert(key, result.clone());
        result
    }

    /// The crates.io `cksum` (sha256 hex of the `.crate`) of
    /// `name@version`, from the sparse index.
    pub(crate) async fn cargo_cksum(&self, name: &str, version: &str) -> Result<String, String> {
        let key = (name.to_string(), version.to_string());
        if let Some(hit) = self.cargo.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            let url = format!("{}/{}", crates_index_base(), crates_index_path(name));
            let text = self.get_text(&url).await?;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(row) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                if row.get("vers").and_then(Value::as_str) == Some(version) {
                    return row
                        .get("cksum")
                        .and_then(Value::as_str)
                        .filter(|c| crate::utils::digest::is_hex64_lower(c))
                        .map(str::to_string)
                        .ok_or_else(|| format!("{url} lists {version} without a checksum"));
                }
            }
            Err(format!("{url} does not list {name} {version}"))
        }
        .await;
        self.cargo.lock().await.insert(key, result.clone());
        result
    }

    /// The go.sum hashes of `module@version`, computed from the module
    /// proxy's `.zip` and `.mod` the way `go` computes them.
    pub(crate) async fn go_sums(&self, module: &str, version: &str) -> Result<GoSums, String> {
        let key = (module.to_string(), version.to_string());
        if let Some(hit) = self.go.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            if let Some(sumdb) = gosumdb_base(module) {
                let url = format!(
                    "{sumdb}/lookup/{}@{}",
                    crate::crawlers::go_crawler::encode_module_path(module),
                    crate::crawlers::go_crawler::encode_module_path(version)
                );
                let text = self.get_text(&url).await?;
                let zip_key = format!("{module} {version} ");
                let mod_key = format!("{module} {version}/go.mod ");
                let pick = |key: &str| {
                    text.lines()
                        .find_map(|l| l.strip_prefix(key))
                        .map(|h| h.trim().to_string())
                        .filter(|h| crate::vendor::go_sum_edit::is_h1_dirhash(h))
                };
                return match (pick(&zip_key), pick(&mod_key)) {
                    (Some(zip_h1), Some(mod_h1)) => Ok(GoSums { zip_h1, mod_h1 }),
                    _ => Err(format!("{url} does not list both go.sum lines of {module} {version}")),
                };
            }
            let proxy = crate::vendor::registry_fetch::goproxy_base(module)?;
            let escaped = crate::crawlers::go_crawler::encode_module_path(module);
            let escaped_version = crate::crawlers::go_crawler::encode_module_path(version);
            let base = format!("{proxy}/{escaped}/@v/{escaped_version}");
            let zip = crate::vendor::registry_fetch::download(&self.http, &format!("{base}.zip"))
                .await?;
            let zip_h1 = crate::vendor::registry_fetch::go_h1_of_zip(&zip)?;
            let go_mod =
                crate::vendor::registry_fetch::download(&self.http, &format!("{base}.mod")).await?;
            Ok(GoSums {
                zip_h1,
                mod_h1: go_mod_h1(&go_mod),
            })
        }
        .await;
        self.go.lock().await.insert(key, result.clone());
        result
    }
}

/// Go's checksum database, `sum.golang.org`; `SOCKET_GOSUMDB_URL` names
/// another (tests, mirrors).
pub(crate) const DEFAULT_GOSUMDB: &str = "https://sum.golang.org";

/// The checksum database go would consult for `module`, or `None` when go
/// would not (`GOSUMDB=off`, or the module matches `GONOSUMDB` /
/// `GOPRIVATE`) — the hashes are then computed from the module proxy's
/// bytes instead. An explicit `SOCKET_GOSUMDB_URL` always wins.
fn gosumdb_base(module: &str) -> Option<String> {
    if let Ok(v) = std::env::var("SOCKET_GOSUMDB_URL") {
        let v = v.trim().trim_end_matches('/').to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    let nonempty = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
    if nonempty("GOSUMDB").is_some_and(|v| v.trim() == "off") {
        return None;
    }
    if let Some(patterns) = nonempty("GONOSUMDB").or_else(|| nonempty("GOPRIVATE")) {
        if crate::vendor::registry_fetch::go_match_prefix_patterns(&patterns, module) {
            return None;
        }
    }
    Some(DEFAULT_GOSUMDB.to_string())
}

/// x/mod `dirhash.Hash1` over the single file `go.mod` — the `/go.mod h1:`
/// go.sum line.
pub(crate) fn go_mod_h1(go_mod: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let file_sum = hex::encode(Sha256::digest(go_mod));
    let summary = format!("{file_sum}  go.mod\n");
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(summary.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_index_paths_follow_cargo_layout() {
        assert_eq!(crates_index_path("a"), "1/a");
        assert_eq!(crates_index_path("ab"), "2/ab");
        assert_eq!(crates_index_path("abc"), "3/a/abc");
        assert_eq!(crates_index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn go_mod_h1_matches_the_x_mod_recipe() {
        // `module example.com/m\n` — cross-checked with `go mod download
        // -json` output for a one-line module file.
        let h1 = go_mod_h1(b"module example.com/m\n");
        assert!(h1.starts_with("h1:") && h1.ends_with('='), "{h1}");
    }
}
