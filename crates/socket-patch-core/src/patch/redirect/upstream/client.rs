//! Registry lookups for the upstream restore: what a default-registry lock
//! entry pins, re-resolved from the public registry (each base overridable
//! by the same env vars the vendored fetch honors, so tests and mirrors can
//! point it elsewhere).

use std::collections::HashMap;

use serde_json::Value;
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

use crate::api::client::network_error_detail;
use crate::vendor::registry_fetch::{
    build_registry_client, npm_registry_base, pypi_json_api_base, RegistryClient,
    SecureRegistryClient,
};

/// An npm version's `dist` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmDist {
    /// The registry's tarball URL for the version.
    pub tarball: String,
    /// The SRI `dist.integrity` (sha512 on every modern publish).
    pub integrity: Option<String>,
    /// The hex sha1 `dist.shasum`.
    pub shasum: Option<String>,
    /// The version document's `bin`, as yarn reads a manifest's
    /// ([`crate::formats::yarn::berry_entry::manifest_bin`]): what yarn
    /// berry writes in the `bin:` section of the version's `npm:` entry
    /// (#1131). Empty when the document declares none.
    pub bin: std::collections::BTreeMap<String, String>,
    /// Whether yarn's npm resolver gives this version the implicit
    /// `node-gyp: "npm:latest"` dependency (see
    /// `formats::yarn::berry_entry::registry_adds_node_gyp`, #737).
    pub node_gyp: bool,
}

/// A Go module version's two go.sum hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoSums {
    /// `h1:` of the module zip.
    pub zip_h1: String,
    /// `h1:` of the module's go.mod.
    pub mod_h1: String,
}

/// One release file of a PyPI version, from the JSON API's `urls[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PypiFile {
    /// The distribution filename (`<name>-<ver>-<tags>.whl`, `.tar.gz`, …).
    pub filename: String,
    /// The file's download URL (files.pythonhosted.org on PyPI).
    pub url: String,
    /// Lowercase hex sha256 (`digests.sha256`).
    pub sha256: String,
    /// Size in bytes.
    pub size: Option<u64>,
    /// `upload_time_iso_8601` (microsecond precision, `Z`): the same instant
    /// the PEP 691 simple API reports as `upload-time`, which is what uv
    /// records.
    pub upload_time: Option<String>,
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

/// Whether crates.io can hold a crate of this name: non-empty ASCII
/// letters, digits, `-` and `_`.
pub(super) fn is_crates_io_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The sparse-index path of a crate (`cargo`'s `index_path` layout), or
/// `None` for a name crates.io cannot hold ([`is_crates_io_name`]). The
/// name here comes from a `Cargo.lock`, so anything else is refused rather
/// than cut at byte offsets (which is only sound for ASCII) or placed in a
/// URL path.
fn crates_index_path(name: &str) -> Option<String> {
    if !is_crates_io_name(name) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    Some(match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    })
}

/// The RubyGems compact index root; override with `SOCKET_RUBYGEMS_URL`.
pub(crate) const DEFAULT_RUBYGEMS: &str = "https://rubygems.org";

pub(crate) fn rubygems_base() -> String {
    std::env::var("SOCKET_RUBYGEMS_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_RUBYGEMS.to_string())
}

/// [`rubygems_base`] as the registry a gem's sha256 is read from and a gem
/// that is built or installed is downloaded from: `Err` when it is not an
/// `https` URL, nor plain `http` to this machine
/// ([`crate::utils::http::insecure_transport`]). The default is `https`, so
/// only `SOCKET_RUBYGEMS_URL` can name such a base. A checksum and an
/// archive read over plain http are whatever the network path serves: no
/// request is made, and the reason says to use an https URL.
pub(crate) fn rubygems_secure_base() -> Result<String, String> {
    secure_gem_registry(rubygems_base())
}

/// `base` when a gem and its checksum may be fetched from it
/// ([`rubygems_secure_base`]).
pub(crate) fn secure_gem_registry(base: String) -> Result<String, String> {
    match crate::utils::http::insecure_transport(&base) {
        None => Ok(base),
        Some(why) => Err(format!(
            "SOCKET_RUBYGEMS_URL is not used as the gem registry: {why}; set it to an https URL"
        )),
    }
}

/// Whether `remote` (a lock's `remote:`, a download base) is the default
/// RubyGems registry: rubygems.org, or its `SOCKET_RUBYGEMS_URL` stand-in.
/// The one test of it, shared by the upstream restore and by the source
/// gem lookup of a native-extension rebuild (`patch::gem_source`).
pub(crate) fn is_rubygems_remote(remote: &str) -> bool {
    use crate::formats::gem::same_remote;
    use crate::utils::redact::strip_url_userinfo;
    // A lock names a gem server without the credentials Bundler keeps in
    // its own config, while `SOCKET_RUBYGEMS_URL` may carry them: both
    // name one server.
    let remote = strip_url_userinfo(remote);
    same_remote(&remote, DEFAULT_RUBYGEMS)
        || same_remote(&remote, &strip_url_userinfo(&rubygems_base()))
}

/// Packagist's composer v2 metadata repository; override with
/// `SOCKET_PACKAGIST_URL`.
pub(crate) const DEFAULT_PACKAGIST: &str = "https://repo.packagist.org";

fn packagist_base() -> String {
    std::env::var("SOCKET_PACKAGIST_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PACKAGIST.to_string())
}

/// The `checksum:` (sha256 hex of the `.gem`) a compact-index `info/<name>`
/// file records for the build `token` — the value bundler writes into
/// `CHECKSUMS`. Lines are `<version>[-<platform>] <deps>|<reqs>`, the
/// requirement list carrying `checksum:<hex>`: `token` is `<version>` for
/// the ruby-platform gem and `<version>-<platform>` for a platform gem,
/// matched whole, so a version never answers for one of its platform
/// builds.
pub(crate) fn compact_index_checksum(info: &str, token: &str) -> Option<String> {
    info.lines().find_map(|line| {
        let (head, reqs) = line.split_once('|')?;
        if head.split(' ').next()? != token {
            return None;
        }
        reqs.split(',')
            .find_map(|r| r.trim().strip_prefix("checksum:"))
            .and_then(crate::utils::digest::sha256_hex)
    })
}

/// [`compact_index_checksum`] of the build `token` in the `info` document
/// read from `url` (already safe to print), or the error that names what
/// the document lacks.
fn checksum_in(url: &str, info: &str, token: &str) -> Result<String, String> {
    compact_index_checksum(info, token).ok_or_else(|| {
        let build = if token.contains('-') {
            token.to_string()
        } else {
            format!("ruby-platform {token}")
        };
        format!("{url} lists no {build} with a checksum")
    })
}

/// Expand a packagist `p2` version list. `minified: composer/2.0` documents
/// (composer's `MetadataMinifier`) list each version as the DIFF against the
/// previous expanded one: every key it carries replaces the inherited value,
/// and the string `"__unset"` removes the key.
pub(crate) fn expand_packagist_versions(versions: &[Value], minified: bool) -> Vec<Value> {
    if !minified {
        return versions.to_vec();
    }
    let mut out = Vec::with_capacity(versions.len());
    let mut current: Option<serde_json::Map<String, Value>> = None;
    for v in versions {
        let Some(obj) = v.as_object() else {
            continue;
        };
        let next = match current.take() {
            None => obj.clone(),
            Some(mut prev) => {
                for (k, val) in obj {
                    if val.as_str() == Some("__unset") {
                        prev.remove(k);
                    } else {
                        prev.insert(k.clone(), val.clone());
                    }
                }
                prev
            }
        };
        out.push(Value::Object(next.clone()));
        current = Some(next);
    }
    out
}

/// The offline refusal every lookup returns under `--offline`.
pub(crate) const OFFLINE: &str =
    "the upstream entry must be re-resolved from the registry, and this run is offline";

type Cache<T> = Mutex<HashMap<(String, String), Result<T, String>>>;

/// A compact-index `info/<name>` document with the URL it was read from
/// (credentials redacted), or why it could not be read.
type GemInfo = Result<(String, String), String>;

/// [`Cache`] keyed by (registry base, `Authorization` sent, name, version).
type RegistryCache<T> = Mutex<HashMap<(String, Option<String>, String, String), Result<T, String>>>;

/// One client per restore run; every lookup is cached (success and
/// failure alike) so a pin wired in several files costs one request.
///
/// The restorers start every pin's lookup at once (`join_all`), so the cap
/// on requests in flight lives here, at the one place they are sent: each
/// request holds a [`Self::permits`] slot from send to the end of its body
/// (#1220).
pub(crate) struct UpstreamClient {
    http: RegistryClient,
    /// The client a gem's sha256 is read with ([`Self::rubygems_sha256`]),
    /// built by the first such lookup.
    secure: std::sync::OnceLock<SecureRegistryClient>,
    /// At most [`crate::utils::concurrent::registry_concurrency`] requests
    /// in flight at once. Every request this client sends takes a slot: the
    /// public registries, a project's private registry or mirror, and the
    /// patch service's upstream checksum metadata alike.
    permits: Semaphore,
    offline: bool,
    npm: RegistryCache<NpmDist>,
    npm_berry: Cache<String>,
    cargo: Cache<String>,
    go: Cache<GoSums>,
    rubygems: Cache<String>,
    /// The compact-index `info/<name>` documents already read, by gem
    /// name, each with the URL it was read from: one lists every build of
    /// the gem, and a gem locked as platform builds asks for the sha256 of
    /// each.
    rubygems_info: Mutex<HashMap<String, GemInfo>>,
    packagist: Cache<Vec<Value>>,
    pypi: Cache<Vec<PypiFile>>,
    nuget: Cache<String>,
}

impl UpstreamClient {
    pub(crate) fn new(offline: bool) -> Self {
        Self::with_concurrency(offline, crate::utils::concurrent::registry_concurrency())
    }

    /// [`Self::new`] with at most `limit` requests in flight (0 counts as 1).
    pub(crate) fn with_concurrency(offline: bool, limit: usize) -> Self {
        UpstreamClient {
            http: build_registry_client(),
            secure: std::sync::OnceLock::new(),
            permits: Semaphore::new(limit.max(1)),
            offline,
            npm: Mutex::default(),
            npm_berry: Mutex::default(),
            cargo: Mutex::default(),
            go: Mutex::default(),
            rubygems: Mutex::default(),
            rubygems_info: Mutex::default(),
            packagist: Mutex::default(),
            pypi: Mutex::default(),
            nuget: Mutex::default(),
        }
    }

    /// A slot to send one request in. The semaphore is never closed, so
    /// the wait always ends in a permit.
    async fn permit(&self) -> SemaphorePermit<'_> {
        self.permits
            .acquire()
            .await
            .expect("the upstream request semaphore is never closed")
    }

    /// `url`'s bytes, sent under a [`Self::permit`].
    async fn download(&self, url: &str) -> Result<Vec<u8>, String> {
        let _permit = self.permit().await;
        crate::vendor::registry_fetch::download(&self.http, url).await
    }

    async fn get_json(&self, url: &str) -> Result<Value, String> {
        self.get_json_authorized(url, None).await
    }

    /// [`Self::get_json`] sending `authorization` (a private registry's
    /// credentials) as the `Authorization` header. reqwest drops the header
    /// on a redirect to another host.
    async fn get_json_authorized(
        &self,
        url: &str,
        authorization: Option<&str>,
    ) -> Result<Value, String> {
        let _permit = self.permit().await;
        let mut request = self.http.get(url).header("accept", "application/json");
        if let Some(authorization) = authorization {
            let mut value =
                reqwest::header::HeaderValue::from_str(authorization).map_err(|_| {
                    format!("GET {url}: the configured credentials are not a valid header")
                })?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| format!("GET {url}: {}", network_error_detail(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("GET {url}: HTTP {status}"));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("reading {url}: {}", network_error_detail(&e)))?;
        serde_json::from_str(&text).map_err(|e| format!("{url} is not JSON: {e}"))
    }

    async fn get_text(&self, url: &str) -> Result<String, String> {
        let bytes = self.download(url).await?;
        String::from_utf8(bytes).map_err(|_| format!("{url} is not UTF-8"))
    }

    /// `dist` of `name@version` from the default npm registry's version
    /// document.
    pub(crate) async fn npm_dist(&self, name: &str, version: &str) -> Result<NpmDist, String> {
        self.npm_dist_on(&npm_registry_base(), name, version).await
    }

    /// `dist` of `name@version` from the version document of the npm
    /// registry at `base` (a project's configured registry or mirror).
    pub(crate) async fn npm_dist_on(
        &self,
        base: &str,
        name: &str,
        version: &str,
    ) -> Result<NpmDist, String> {
        self.npm_dist_authorized(base, None, name, version).await
    }

    /// [`Self::npm_dist_on`] sending `authorization` as the `Authorization`
    /// header: the credentials the project configures for the private
    /// registry at `base` (#992).
    pub(crate) async fn npm_dist_authorized(
        &self,
        base: &str,
        authorization: Option<&str>,
        name: &str,
        version: &str,
    ) -> Result<NpmDist, String> {
        let base = base.trim_end_matches('/');
        let key = (
            base.to_string(),
            authorization.map(str::to_string),
            name.to_string(),
            version.to_string(),
        );
        if let Some(hit) = self.npm.lock().await.get(&key) {
            return hit.clone();
        }
        let result = self
            .fetch_npm_dist(base, authorization, name, version)
            .await;
        self.npm.lock().await.insert(key, result.clone());
        result
    }

    async fn fetch_npm_dist(
        &self,
        base: &str,
        authorization: Option<&str>,
        name: &str,
        version: &str,
    ) -> Result<NpmDist, String> {
        if self.offline {
            return Err(OFFLINE.to_string());
        }
        let encoded_name = name.replace('/', "%2f");
        let url = format!(
            "{base}/{encoded_name}/{}",
            crate::utils::uri::encode_uri_component(version)
        );
        let doc = self.get_json_authorized(&url, authorization).await?;
        let dist = doc
            .get("dist")
            .ok_or_else(|| format!("{url} carries no `dist` block"))?;
        let str_field = |k: &str| dist.get(k).and_then(Value::as_str).map(str::to_string);
        let tarball =
            str_field("tarball").ok_or_else(|| format!("{url} carries no `dist.tarball`"))?;
        Ok(NpmDist {
            tarball,
            integrity: str_field("integrity"),
            shasum: str_field("shasum"),
            bin: crate::formats::yarn::berry_entry::manifest_bin(&doc),
            node_gyp: crate::formats::yarn::berry_entry::registry_adds_node_gyp(&doc),
        })
    }

    pub(crate) async fn npm_berry_checksum(
        &self,
        uuid: &str,
        name: &str,
        version: &str,
        origin: &str,
    ) -> Result<String, String> {
        if self.offline {
            return Err(OFFLINE.into());
        }
        let key = (name.to_string(), version.to_string());
        if let Some(hit) = self.npm_berry.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            let url = format!("{}/upstream/npm/{uuid}.json", origin.trim_end_matches('/'));
            let metadata = self.get_json(&url).await?;
            if metadata["name"].as_str() != Some(name)
                || metadata["version"].as_str() != Some(version)
            {
                return Err("upstream checksum metadata names a different package".into());
            }
            let checksum = metadata["yarnBerry10c0"]
                .as_str()
                .filter(|c| crate::vendor::yarn_berry_lock::valid_berry_checksum(c))
                .ok_or("the patch service supplied no valid upstream Berry checksum")?;
            let integrity = metadata["integrity"]
                .as_str()
                .filter(|s| s.starts_with("sha512-"))
                .ok_or("upstream checksum metadata has no archive integrity")?;
            use base64::Engine as _;
            if !base64::engine::general_purpose::STANDARD
                .decode(&integrity[7..])
                .is_ok_and(|bytes| bytes.len() == 64)
            {
                return Err("upstream checksum metadata has invalid SHA-512 integrity".into());
            }
            let dist = self.npm_dist(name, version).await?;
            if !dist
                .integrity
                .as_deref()
                .is_some_and(|s| s.split_whitespace().any(|v| v == integrity))
            {
                let bytes = self.download(&dist.tarball).await?;
                crate::vendor::registry_fetch::verify_sri(&bytes, integrity)?;
                if let Some(sri) = dist.integrity.as_deref() {
                    crate::vendor::registry_fetch::verify_sri(&bytes, sri)?;
                } else if let Some(sha1) = dist.shasum.as_deref() {
                    if crate::utils::digest::sha1_hex_of(&bytes) != sha1 {
                        return Err("registry archive checksum mismatch".into());
                    }
                } else {
                    return Err("the registry supplied no archive integrity".into());
                }
            }
            Ok(checksum.to_string())
        }
        .await;
        self.npm_berry.lock().await.insert(key, result.clone());
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
            let path = crates_index_path(name)
                .ok_or_else(|| format!("{name:?} is not a crates.io crate name"))?;
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            let url = format!("{}/{path}", crates_index_base());
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

    /// Every release file of `name@version` from PyPI's JSON API (`GET
    /// <api>/<name>/<version>/json`, base overridable with
    /// `SOCKET_PYPI_JSON_API`), sorted by filename — the order Poetry, PDM,
    /// Pipenv and pip-compile record them in. `name` is PEP 503
    /// canonicalized first (PyPI redirects every other spelling to it).
    pub(crate) async fn pypi_files(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Vec<PypiFile>, String> {
        let name = crate::crawlers::python_crawler::canonicalize_pypi_name(name);
        let key = (name.clone(), version.to_string());
        if let Some(hit) = self.pypi.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            let url = format!(
                "{}/{name}/{}/json",
                pypi_json_api_base(),
                crate::utils::uri::encode_uri_component(version)
            );
            let doc = self.get_json(&url).await?;
            pypi_release_files(&doc).map_err(|why| format!("{url} {why}"))
        }
        .await;
        self.pypi.lock().await.insert(key, result.clone());
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
                    _ => Err(format!(
                        "{url} does not list both go.sum lines of {module} {version}"
                    )),
                };
            }
            let proxy = crate::vendor::registry_fetch::goproxy_base(module)?;
            let escaped = crate::crawlers::go_crawler::encode_module_path(module);
            let escaped_version = crate::crawlers::go_crawler::encode_module_path(version);
            let base = format!("{proxy}/{escaped}/@v/{escaped_version}");
            let zip = self.download(&format!("{base}.zip")).await?;
            let zip_h1 = crate::vendor::registry_fetch::go_h1_of_zip(&zip)?;
            let go_mod = self.download(&format!("{base}.mod")).await?;
            Ok(GoSums {
                zip_h1,
                mod_h1: go_mod_h1(&go_mod),
            })
        }
        .await;
        self.go.lock().await.insert(key, result.clone());
        result
    }

    /// The rubygems.org sha256 of one build of a gem, from the compact
    /// index bundler itself reads (`info/<name>`). `token` names the build
    /// as that index and the lock's `CHECKSUMS` do: `<version>` for the
    /// ruby-platform `name-version.gem`, `<version>-<platform>` for a
    /// platform gem.
    ///
    /// The lock's `CHECKSUMS` entry is re-pinned from it, and after an
    /// unwind the installed copy is replaced by the archive that has it
    /// (`patch::gem_refresh`), which RubyGems builds when the gem has a
    /// native extension. So it is read over a transport nobody can rewrite
    /// ([`rubygems_secure_base`], [`SecureRegistryClient`]): a registry
    /// reached over plain http is not asked.
    pub(crate) async fn rubygems_sha256(&self, name: &str, token: &str) -> Result<String, String> {
        let key = (name.to_string(), token.to_string());
        if let Some(hit) = self.rubygems.lock().await.get(&key) {
            return hit.clone();
        }
        // The document is read once per gem: the builds of one version
        // (a gem locked for several platforms) are lines of the same one.
        // A build is looked up in the cached copy where it lies.
        let lookup = |info: &GemInfo| match info {
            Ok((url, text)) => checksum_in(url, text, token),
            Err(why) => Err(why.clone()),
        };
        let cached = self.rubygems_info.lock().await.get(name).map(lookup);
        let result = match cached {
            Some(result) => result,
            None => {
                let fetched = self.rubygems_info_at(rubygems_secure_base(), name).await;
                let result = lookup(&fetched);
                self.rubygems_info
                    .lock()
                    .await
                    .insert(name.to_string(), fetched);
                result
            }
        };
        self.rubygems.lock().await.insert(key, result.clone());
        result
    }

    /// The compact-index `info/<name>` document of the registry at `base`
    /// ([`rubygems_secure_base`]: its URL, or why it is not asked), with
    /// the URL it was read from. Uncached. The base may carry a mirror's
    /// credentials: neither the URL returned nor an error repeats them.
    async fn rubygems_info_at(&self, base: Result<String, String>, name: &str) -> GemInfo {
        if self.offline {
            return Err(OFFLINE.to_string());
        }
        if !crate::formats::gem::is_plain_gem_token(name) {
            return Err(format!("{name:?} is not a plain gem name"));
        }
        let url = format!("{}/info/{name}", base?);
        let looked_up = async {
            let registry = self.secure.get_or_init(SecureRegistryClient::new);
            let bytes = {
                let _permit = self.permit().await;
                registry.download(&url).await?
            };
            String::from_utf8(bytes).map_err(|_| format!("{url} is not UTF-8"))
        };
        let redact = |text: &str| crate::utils::redact::redact_urls_in(text).into_owned();
        match looked_up.await {
            Ok(text) => Ok((redact(&url), text)),
            Err(why) => Err(redact(&why)),
        }
    }

    /// Every version packagist serves for the composer package `name`
    /// (lowercase `vendor/package`), expanded: the stable `p2/<name>.json`
    /// list, or the `~dev` one when `dev` (composer splits branches out).
    pub(crate) async fn packagist_versions(
        &self,
        name: &str,
        dev: bool,
    ) -> Result<Vec<Value>, String> {
        let key = (name.to_string(), if dev { "~dev" } else { "" }.to_string());
        if let Some(hit) = self.packagist.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            let safe = name.split('/').count() == 2
                && name.split('/').all(|p| {
                    !p.is_empty()
                        && !p.starts_with('.')
                        && p.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                        })
                });
            if !safe {
                return Err(format!("{name:?} is not a packagist package name"));
            }
            let url = format!("{}/p2/{name}{}.json", packagist_base(), key.1);
            let doc = self.get_json(&url).await?;
            let versions = doc
                .get("packages")
                .and_then(|p| p.get(name))
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{url} lists no versions of {name}"))?;
            let minified = doc.get("minified").and_then(Value::as_str) == Some("composer/2.0");
            Ok(expand_packagist_versions(versions, minified))
        }
        .await;
        self.packagist.lock().await.insert(key, result.clone());
        result
    }

    /// The `packages.lock.json` `contentHash` of `id@version` on nuget.org:
    /// NuGet's content hash of the `.nupkg` its flat container serves,
    /// which excludes the repository signature
    /// ([`crate::formats::nuget::package::package_content_hash`]). The
    /// catalog's `packageHash` is the hash of the signed file as served, so
    /// it never matches a lock's `contentHash` (#624).
    pub(crate) async fn nuget_content_hash(
        &self,
        id: &str,
        version: &str,
    ) -> Result<String, String> {
        let key = (id.to_ascii_lowercase(), version.to_ascii_lowercase());
        if let Some(hit) = self.nuget.lock().await.get(&key) {
            return hit.clone();
        }
        let result = async {
            if self.offline {
                return Err(OFFLINE.to_string());
            }
            let (id_lower, version_lower) = &key;
            let (id_seg, version_seg) = (
                crate::utils::uri::encode_uri_component(id_lower),
                crate::utils::uri::encode_uri_component(version_lower),
            );
            let url = format!(
                "{}/v3-flatcontainer/{id_seg}/{version_seg}/{id_seg}.{version_seg}.nupkg",
                nuget_api_base(),
            );
            let bytes = self.download(&url).await?;
            crate::formats::nuget::package::package_content_hash(&bytes)
                .map_err(|why| format!("{url}: {why}"))
        }
        .await;
        self.nuget.lock().await.insert(key, result.clone());
        result
    }
}

/// nuget.org's API host; `SOCKET_NUGET_URL` names another (tests, mirrors
/// serving the same `/v3-flatcontainer/` hive).
pub(crate) const DEFAULT_NUGET_API: &str = "https://api.nuget.org";

fn nuget_api_base() -> String {
    std::env::var("SOCKET_NUGET_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_NUGET_API.to_string())
}

/// The release files of a PyPI JSON API version document, sorted by
/// filename.
fn pypi_release_files(doc: &Value) -> Result<Vec<PypiFile>, String> {
    let urls = doc
        .get("urls")
        .and_then(Value::as_array)
        .ok_or("carries no `urls` list")?;
    let mut files = Vec::with_capacity(urls.len());
    for file in urls {
        let str_field = |k: &str| file.get(k).and_then(Value::as_str).map(str::to_string);
        let filename = str_field("filename")
            .filter(|f| !f.is_empty() && !f.contains(['/', '\\']))
            .ok_or("lists a file without a plain filename")?;
        let url = str_field("url").ok_or_else(|| format!("lists {filename} without a url"))?;
        let sha256 = file
            .get("digests")
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .filter(|h| crate::utils::digest::is_hex64_lower(h))
            .ok_or_else(|| format!("lists {filename} without a sha256 digest"))?;
        files.push(PypiFile {
            filename,
            url,
            sha256,
            size: file.get("size").and_then(Value::as_u64),
            upload_time: str_field("upload_time_iso_8601"),
        });
    }
    if files.is_empty() {
        return Err("lists no release files".to_string());
    }
    files.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(files)
}

/// Go's checksum database, `sum.golang.org`; `SOCKET_GOSUMDB_URL` names
/// another (tests, mirrors).
pub(crate) const DEFAULT_GOSUMDB: &str = "https://sum.golang.org";

/// The checksum database go would consult for `module`, or `None` when go
/// would not (`GOSUMDB=off`, or the module matches `GONOSUMDB` /
/// `GOPRIVATE`) — the hashes are then computed from the module proxy's
/// bytes instead. An explicit `SOCKET_GOSUMDB_URL` always wins. The Go
/// settings resolve from the environment, then the `go env -w` file
/// ([`crate::utils::go_env`]).
fn gosumdb_base(module: &str) -> Option<String> {
    if let Ok(v) = std::env::var("SOCKET_GOSUMDB_URL") {
        let v = v.trim().trim_end_matches('/').to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    let nonempty = |key: &str| crate::utils::go_env::go_env(key).filter(|v| !v.trim().is_empty());
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
    let file_sum = crate::utils::digest::sha256_hex_of(go_mod);
    let summary = format!("{file_sum}  go.mod\n");
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(summary.as_bytes()))
    )
}

#[cfg(test)]
impl UpstreamClient {
    /// Answer `rubygems_sha256(name, version)` with `sha` without a request
    /// (an offline client otherwise refuses every lookup).
    pub(crate) async fn seed_rubygems_sha256(&self, name: &str, version: &str, sha: &str) {
        self.rubygems
            .lock()
            .await
            .insert((name.to_string(), version.to_string()), Ok(sha.to_string()));
    }
}

/// A local registry that counts how many requests it holds open at once
/// (#1220). Each request is answered after a fixed delay with the same
/// JSON body, over HTTP/1.1 keep-alive, so a client that pipelines several
/// requests per connection is counted as accurately as one that opens a
/// connection per request.
#[cfg(test)]
pub(crate) mod peak_server {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) struct PeakServer {
        pub base: String,
        requests: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl PeakServer {
        pub(crate) async fn start(body: &'static str, delay: Duration) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let live = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(AtomicUsize::new(0));
            let (l, p, r) = (live.clone(), peak.clone(), requests.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let (live, peak, requests) = (l.clone(), p.clone(), r.clone());
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        loop {
                            // One request: a GET has no body, so its head
                            // ends the request.
                            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                match sock.read(&mut chunk).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                }
                            }
                            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                            buf.drain(..end + 4);
                            requests.fetch_add(1, Ordering::SeqCst);
                            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            tokio::time::sleep(delay).await;
                            live.fetch_sub(1, Ordering::SeqCst);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            if sock.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            PeakServer {
                base,
                requests,
                peak,
            }
        }

        /// How many requests the server has answered or is answering.
        pub(crate) fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }

        /// The most requests the server ever held open at once.
        pub(crate) fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1220: a client built with a cap of 1 (what a tight
    /// `RLIMIT_NOFILE` gives) sends its lookups strictly one at a time,
    /// however many the caller starts at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cap_of_one_sends_lookups_one_at_a_time() {
        let server = peak_server::PeakServer::start(
            r#"{"dist":{"tarball":"http://registry.test/x.tgz"}}"#,
            std::time::Duration::from_millis(50),
        )
        .await;
        let client = UpstreamClient::with_concurrency(false, 1);
        let names: Vec<String> = (0..10).map(|i| format!("pkg{i}")).collect();
        let lookups = names
            .iter()
            .map(|name| client.npm_dist_on(&server.base, name, "1.0.0"));
        for found in futures_util::future::join_all(lookups).await {
            found.unwrap();
        }
        assert_eq!(server.requests(), 10);
        assert_eq!(server.peak(), 1);
    }

    #[test]
    fn crates_index_paths_follow_cargo_layout() {
        let path = |name: &str| crates_index_path(name).unwrap();
        assert_eq!(path("a"), "1/a");
        assert_eq!(path("ab"), "2/ab");
        assert_eq!(path("abc"), "3/a/abc");
        assert_eq!(path("Serde"), "se/rd/serde");
        assert_eq!(path("serde_json"), "se/rd/serde_json");
        assert_eq!(path("cfg-if"), "cf/g-/cfg-if");
    }

    /// A `Cargo.lock` is a project file: a `name` crates.io cannot hold
    /// (empty, non-ASCII, or holding a path or URL character) is refused by
    /// name, never sliced into an index path or sent in a URL.
    #[tokio::test]
    async fn cargo_cksum_refuses_a_name_crates_io_cannot_hold() {
        for name in [
            "", "éa", "aé", "aéb", "日本", "a/b", "..", "a b", "a?b", "a.b",
        ] {
            assert_eq!(crates_index_path(name), None, "{name:?}");
            // Online and offline alike: the name is refused before any
            // request, so this never reaches the network.
            for offline in [false, true] {
                let why = UpstreamClient::new(offline)
                    .cargo_cksum(name, "1.0.0")
                    .await
                    .expect_err(name);
                assert_eq!(why, format!("{name:?} is not a crates.io crate name"));
            }
        }
    }

    /// A gem's checksum, and a gem that is built or installed, come from
    /// an https registry or one on this machine. Another base is refused
    /// with what to do about it, its credentials not repeated.
    #[test]
    fn a_gem_registry_reached_over_plain_http_is_refused() {
        for base in [
            DEFAULT_RUBYGEMS,
            "https://gems.example.test/mirror",
            "http://127.0.0.1:9292/upstream",
            "http://localhost:9292",
            "http://[::1]:9292",
        ] {
            assert_eq!(
                secure_gem_registry(base.to_string()).as_deref(),
                Ok(base),
                "{base}"
            );
        }
        for base in [
            "http://gems.example.test",
            "http://user:hunter2@10.1.2.3:9292/mirror",
            "gems.example.test",
            "file:///srv/gems",
        ] {
            let why = secure_gem_registry(base.to_string()).unwrap_err();
            assert!(
                why.contains("SOCKET_RUBYGEMS_URL") && why.contains("set it to an https URL"),
                "{why}"
            );
            assert!(!why.contains("hunter2"), "{why}");
        }
    }

    /// The registry's base may carry a mirror's credentials
    /// (`SOCKET_RUBYGEMS_URL=https://user:token@…`): the checksum is read
    /// with them, and no error of the lookup repeats them. A registry that
    /// is refused is not asked at all.
    #[tokio::test]
    async fn a_gem_checksum_lookup_never_repeats_the_registrys_credentials() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let sha = "a".repeat(64);
        Mock::given(method("GET"))
            .and(path("/info/rails"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!("---\n7.0.0 |checksum:{sha}\n")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/info/garbled"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff, 0xfe]))
            .mount(&server)
            .await;
        let base = server.uri().replace("http://", "http://deploy:hunter2@");
        let client = UpstreamClient::new(false);
        let at = |name: &'static str, token: &'static str| {
            let (client, base) = (&client, base.clone());
            async move {
                let (url, info) = client.rubygems_info_at(Ok(base), name).await?;
                checksum_in(&url, &info, token)
            }
        };
        assert_eq!(at("rails", "7.0.0").await, Ok(sha));
        for (name, version, expected) in [
            (
                "rails",
                "7.1.0",
                "lists no ruby-platform 7.1.0 with a checksum",
            ),
            ("rails", "7.0.0-java", "lists no 7.0.0-java with a checksum"),
            ("garbled", "1.0.0", "is not UTF-8"),
            ("absent", "1.0.0", "HTTP 404"),
        ] {
            let why = at(name, version).await.unwrap_err();
            assert!(why.contains(expected), "{why}");
            assert!(why.contains(&format!("/info/{name}")), "{why}");
            assert!(
                !why.contains("hunter2") && !why.contains("deploy:"),
                "{why}"
            );
        }

        let asked = server.received_requests().await.unwrap().len();
        let refused = secure_gem_registry("http://deploy:hunter2@gems.example.test".to_string());
        let why = client.rubygems_info_at(refused, "rails").await.unwrap_err();
        assert!(why.contains("set it to an https URL"), "{why}");
        assert!(!why.contains("hunter2"), "{why}");
        assert_eq!(server.received_requests().await.unwrap().len(), asked);
    }

    #[test]
    fn compact_index_checksum_picks_the_ruby_platform_line() {
        let sha = "a".repeat(64);
        let other = "b".repeat(64);
        let info = format!(
            "---\n1.0.0 |checksum:{other}\n1.1.0 dep:>= 0|checksum:{sha},ruby:>= 2.7\n\
             1.1.0-java |checksum:{other}\n"
        );
        assert_eq!(compact_index_checksum(&info, "1.1.0"), Some(sha));
        // A platform build is named by its whole token, and only by it.
        assert_eq!(compact_index_checksum(&info, "1.1.0-java"), Some(other));
        assert_eq!(compact_index_checksum(&info, "1.1.0-jav"), None);
        assert_eq!(compact_index_checksum(&info, "2.0.0"), None);
        assert_eq!(compact_index_checksum("1.0.0 |ruby:>= 2", "1.0.0"), None);
    }

    /// #2285: an index built with `gem generate_index` writes the sha256
    /// as base64 (rack 3.2.9's line below is the one that command wrote).
    /// Bundler reads it and pins the hex digest in `CHECKSUMS`, in the
    /// standard and the URL-safe alphabet, so both give that hex here.
    #[test]
    fn compact_index_checksum_reads_a_base64_digest_as_bundler_does() {
        const HEX: &str = "8235c1d08f0c461bedcff4413bbeba888173e5b09e1332ae951c98f0ee460dcc";
        let info = "---\n3.2.8 |checksum:AAAA\n\
                    3.2.9 |checksum:gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDcw=,ruby:>= 2.4.0\n\
                    3.2.9-java |checksum:gjXB0I8MRhvtz_RBO766iIFz5bCeEzKulRyY8O5GDcw=\n";
        assert_eq!(compact_index_checksum(info, "3.2.9").as_deref(), Some(HEX));
        assert_eq!(
            compact_index_checksum(info, "3.2.9-java").as_deref(),
            Some(HEX),
            "the URL-safe alphabet"
        );
        // What Bundler refuses as a digest is no checksum: the padding
        // missing or doubled, bits set past the 32nd byte, another length.
        for bad in [
            "gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDcw",
            "gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDcw==",
            "gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDcx=",
            "gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDc==",
            "gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5G*cw=",
            "AAAA",
        ] {
            let info = format!("3.2.9 |checksum:{bad}\n");
            assert_eq!(compact_index_checksum(&info, "3.2.9"), None, "{bad}");
        }
    }

    #[test]
    fn packagist_minified_versions_inherit_and_unset() {
        let versions = serde_json::json!([
            {"name": "a/b", "version": "2.0.0", "source": {"type": "git"}, "dist": {"url": "x"}},
            {"version": "1.0.0", "source": "__unset"},
            {"version": "0.9.0", "dist": {"url": "y"}}
        ]);
        let expanded = expand_packagist_versions(versions.as_array().unwrap(), true);
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[1]["name"], "a/b");
        assert!(expanded[1].get("source").is_none());
        assert_eq!(expanded[1]["dist"]["url"], "x");
        assert!(expanded[2].get("source").is_none());
        assert_eq!(expanded[2]["dist"]["url"], "y");
        let raw = expand_packagist_versions(versions.as_array().unwrap(), false);
        assert!(raw[1].get("name").is_none());
    }

    #[test]
    fn pypi_release_files_are_validated_and_sorted() {
        let doc = serde_json::json!({ "urls": [
            { "filename": "x-1.tar.gz", "url": "https://f/x-1.tar.gz",
              "digests": { "sha256": "B".repeat(64) }, "size": 3,
              "upload_time_iso_8601": "2023-01-01T00:00:00.123456Z" },
            { "filename": "x-1-py3-none-any.whl", "url": "https://f/x.whl",
              "digests": { "sha256": "a".repeat(64) } },
        ]});
        let files = pypi_release_files(&doc).unwrap();
        assert_eq!(files[0].filename, "x-1-py3-none-any.whl");
        assert_eq!(files[1].sha256, "b".repeat(64));
        assert_eq!(files[1].size, Some(3));
        assert!(pypi_release_files(&serde_json::json!({ "urls": [] })).is_err());
        let bad = serde_json::json!({ "urls": [{ "filename": "x.whl", "url": "u",
            "digests": { "sha256": "zz" } }] });
        assert!(pypi_release_files(&bad).unwrap_err().contains("sha256"));
    }

    #[test]
    fn go_mod_h1_matches_the_x_mod_recipe() {
        // `module example.com/m\n` — cross-checked with `go mod download
        // -json` output for a one-line module file.
        let h1 = go_mod_h1(b"module example.com/m\n");
        assert!(h1.starts_with("h1:") && h1.ends_with('='), "{h1}");
    }
    /// #1650: a failed lookup names its transport cause, not just reqwest's
    /// "error sending request for url (...)", so a refusal (and a CI flake)
    /// says whether the registry was unreachable, reset or timed out.
    #[tokio::test]
    async fn a_failed_lookup_keeps_the_transport_cause() {
        use tokio::io::AsyncReadExt;

        // A server that holds its port for the whole test (so nothing else
        // can bind it) and hangs up on every request after reading its head:
        // the client sees the connection close before any response.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/pypi/six/1.16.0/json",
            listener.local_addr().unwrap()
        );
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
            }
        });
        let client = UpstreamClient::new(false);
        let deadline = std::time::Duration::from_secs(30);
        let json = tokio::time::timeout(deadline, client.get_json(&url))
            .await
            .expect("the lookup ends once the server hangs up")
            .expect_err("the server never answers");
        let bytes = tokio::time::timeout(deadline, client.download(&url))
            .await
            .expect("the download ends once the server hangs up")
            .expect_err("the server never answers");
        for err in [json, bytes] {
            assert!(err.starts_with(&format!("GET {url}: ")), "{err}");
            assert!(
                err.contains("connection closed before message completed"),
                "the cause chain must be kept: {err}"
            );
        }
    }

    // The npm cache key reads `SOCKET_NPM_REGISTRY`, which serial tests set.
    #[tokio::test]
    #[serial_test::serial]
    async fn berry_metadata_is_registry_anchored_without_repacking() {
        use base64::Engine as _;
        use sha2::Digest as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let bytes = b"registry archive";
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
        );
        let checksum = format!("10c0/{}", "a".repeat(128));
        for (registry_sri, registry_sha1, expected_downloads) in [
            (Some(integrity.clone()), None, 0),
            (None, Some(hex::encode(sha1::Sha1::digest(bytes))), 1),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET")).and(path("/upstream/npm/uuid.json")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name":"left-pad", "version":"1.3.0", "integrity":integrity, "yarnBerry10c0":checksum
            }))).expect(1).mount(&server).await;
            Mock::given(method("GET"))
                .and(path("/archive.tgz"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.as_slice()))
                .expect(expected_downloads)
                .mount(&server)
                .await;
            let client = UpstreamClient::new(false);
            client.npm.lock().await.insert(
                (npm_registry_base(), None, "left-pad".into(), "1.3.0".into()),
                Ok(NpmDist {
                    tarball: format!("{}/archive.tgz", server.uri()),
                    integrity: registry_sri,
                    shasum: registry_sha1,
                    bin: Default::default(),
                    node_gyp: false,
                }),
            );
            for _ in 0..2 {
                assert_eq!(
                    client
                        .npm_berry_checksum("uuid", "left-pad", "1.3.0", &server.uri())
                        .await
                        .unwrap(),
                    checksum
                );
            }
        }
    }

    // The npm cache key reads `SOCKET_NPM_REGISTRY`, which serial tests set.
    #[tokio::test]
    #[serial_test::serial]
    async fn berry_metadata_refuses_wrong_identity_integrity_and_unavailable_service() {
        use base64::Engine as _;
        use sha2::Digest as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(b"expected"))
        );
        let valid = serde_json::json!({"name":"left-pad", "version":"1.3.0", "integrity":integrity, "yarnBerry10c0":format!("10c0/{}", "a".repeat(128))});
        for kind in [
            "name",
            "version",
            "integrity",
            "yarnBerry10c0",
            "unavailable",
            "registry_mismatch",
        ] {
            let server = MockServer::start().await;
            let mut body = valid.clone();
            if body.get(kind).is_some() {
                body[kind] = serde_json::json!("invalid");
            }
            Mock::given(method("GET"))
                .and(path("/upstream/npm/uuid.json"))
                .respond_with(
                    ResponseTemplate::new(if kind == "unavailable" { 503 } else { 200 })
                        .set_body_json(body),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/archive.tgz"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"different".as_slice()))
                .mount(&server)
                .await;
            let client = UpstreamClient::new(false);
            client.npm.lock().await.insert(
                (npm_registry_base(), None, "left-pad".into(), "1.3.0".into()),
                Ok(NpmDist {
                    tarball: format!("{}/archive.tgz", server.uri()),
                    integrity: Some("sha512-other".into()),
                    shasum: None,
                    bin: Default::default(),
                    node_gyp: false,
                }),
            );
            assert!(
                client
                    .npm_berry_checksum("uuid", "left-pad", "1.3.0", &server.uri())
                    .await
                    .is_err(),
                "{kind}"
            );
        }
    }
}
