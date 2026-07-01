use std::collections::HashSet;

use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::api::types::*;
use crate::constants::{
    DEFAULT_PATCH_API_PROXY_URL, DEFAULT_SOCKET_API_URL, USER_AGENT as USER_AGENT_VALUE,
};
use crate::utils::env_compat::read_env_with_legacy;

/// Check if debug mode is enabled via SOCKET_DEBUG env (falling back to the
/// legacy SOCKET_PATCH_DEBUG name with a one-shot deprecation warning).
fn is_debug_enabled() -> bool {
    match read_env_with_legacy("SOCKET_DEBUG", "SOCKET_PATCH_DEBUG") {
        Some(val) => val == "1" || val == "true",
        None => false,
    }
}

/// Log debug messages when debug mode is enabled.
fn debug_log(message: &str) {
    if is_debug_enabled() {
        eprintln!("[socket-patch debug] {}", message);
    }
}

/// Severity order for sorting (most severe = lowest number).
fn get_severity_order(severity: Option<&str>) -> u8 {
    match severity.map(|s| s.to_lowercase()).as_deref() {
        Some("critical") => 0,
        Some("high") => 1,
        // GHSA emits `moderate` for the medium tier.
        Some("medium") | Some("moderate") => 2,
        Some("low") => 3,
        _ => 4,
    }
}

/// Options for constructing an [`ApiClient`].
#[derive(Debug, Clone)]
pub struct ApiClientOptions {
    pub api_url: String,
    pub api_token: Option<String>,
    /// When true, the client will use the public patch API proxy
    /// which only provides access to free patches without authentication.
    pub use_public_proxy: bool,
    /// Organization slug for authenticated API access.
    /// Required when using authenticated API (not public proxy).
    pub org_slug: Option<String>,
}

/// HTTP client for the Socket Patch API.
///
/// Supports both the authenticated Socket API (`api.socket.dev`) and the
/// public proxy (`patches-api.socket.dev`) which serves free patches
/// without authentication.
#[derive(Debug, Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    api_url: String,
    api_token: Option<String>,
    use_public_proxy: bool,
    org_slug: Option<String>,
}

/// Body payload for the batch search POST endpoint.
#[derive(Serialize)]
struct BatchSearchBody {
    components: Vec<BatchComponent>,
}

#[derive(Serialize)]
struct BatchComponent {
    purl: String,
}

/// Body for the patch-package reference POST endpoint (`scan --redirect`).
#[derive(Serialize)]
struct RegistryReferenceBody {
    uuids: Vec<String>,
}

/// One downloadable artifact from the reference endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceArtifact {
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub integrity: crate::patch::redirect::Integrity,
}

/// One patch's resolved hosted-patch reference — mirrors the api-v0
/// `POST /v0/orgs/{org}/patches/package` (and proxy `/patch/package`) result:
/// the grant-tokenized artifact URL(s) + integrity + per-ecosystem registry
/// override that `scan --redirect` turns into a `DepOverride`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryReference {
    pub status: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<ReferenceArtifact>,
    #[serde(default)]
    pub registry_override: Option<crate::patch::redirect::RegistryOverride>,
}

#[derive(Deserialize)]
struct RegistryReferenceResponse {
    results: std::collections::HashMap<String, RegistryReference>,
}

impl ApiClient {
    /// Create a new API client from the given options.
    ///
    /// Constructs a `reqwest::Client` with proper default headers
    /// (User-Agent, Accept, and optionally Authorization).
    pub fn new(options: ApiClientOptions) -> Self {
        let api_url = options.api_url.trim_end_matches('/').to_string();

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(USER_AGENT_VALUE),
        );
        default_headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        if let Some(ref token) = options.api_token {
            if let Ok(hv) = HeaderValue::from_str(&format!("Bearer {}", token)) {
                default_headers.insert(header::AUTHORIZATION, hv);
            }
        }

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            api_url,
            api_token: options.api_token,
            use_public_proxy: options.use_public_proxy,
            org_slug: options.org_slug,
        }
    }

    /// Returns the API token, if set.
    pub fn api_token(&self) -> Option<&String> {
        self.api_token.as_ref()
    }

    /// Returns the org slug, if set.
    pub fn org_slug(&self) -> Option<&String> {
        self.org_slug.as_ref()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Internal GET that deserialises JSON. Returns `Ok(None)` on 404.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, ApiError> {
        let url = format!("{}{}", self.api_url, path);
        debug_log(&format!("GET {}", url));

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ApiError::Network(format!("Network error: {}", e)))?;

        Self::handle_json_response(resp, self.use_public_proxy).await
    }

    /// Internal POST that deserialises JSON. Returns `Ok(None)` on 404.
    async fn post_json<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Option<T>, ApiError> {
        let url = format!("{}{}", self.api_url, path);
        debug_log(&format!("POST {}", url));

        let resp = self
            .client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Network(format!("Network error: {}", e)))?;

        Self::handle_json_response(resp, self.use_public_proxy).await
    }

    /// Map an HTTP response to `Ok(Some(T))`, `Ok(None)` (404), or `Err`.
    async fn handle_json_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
        use_public_proxy: bool,
    ) -> Result<Option<T>, ApiError> {
        let status = resp.status();

        if status == StatusCode::OK {
            let body = resp
                .json::<T>()
                .await
                .map_err(|e| ApiError::Parse(format!("Failed to parse response: {}", e)))?;
            return Ok(Some(body));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if let Some(err) = classify_auth_error(status, use_public_proxy) {
            return Err(err);
        }
        let text = resp.text().await.unwrap_or_default();
        Err(ApiError::Other(format!(
            "API request failed with status {}: {}",
            status.as_u16(),
            text
        )))
    }

    // ── Public API methods ────────────────────────────────────────────

    /// Fetch a patch by UUID (full details with blob content).
    ///
    /// Returns `Ok(None)` when the patch is not found (404).
    pub async fn fetch_patch(
        &self,
        org_slug: Option<&str>,
        uuid: &str,
    ) -> Result<Option<PatchResponse>, ApiError> {
        let path = if self.use_public_proxy {
            format!("/patch/view/{}", uuid)
        } else {
            let slug = org_slug.or(self.org_slug.as_deref()).unwrap_or("default");
            format!("/v0/orgs/{}/patches/view/{}", slug, uuid)
        };
        self.get_json(&path).await
    }

    /// Shared implementation for `search_patches_by_{cve,ghsa,package}`.
    /// `route` is the `by-<x>` URL segment — the rest of the path layout
    /// is identical across the three endpoints.
    async fn search_patches_by_route(
        &self,
        org_slug: Option<&str>,
        route: &str,
        identifier: &str,
    ) -> Result<SearchResponse, ApiError> {
        let encoded = urlencoding_encode(identifier);
        let path = if self.use_public_proxy {
            format!("/patch/{route}/{encoded}")
        } else {
            let slug = org_slug.or(self.org_slug.as_deref()).unwrap_or("default");
            format!("/v0/orgs/{slug}/patches/{route}/{encoded}")
        };
        let result = self.get_json::<SearchResponse>(&path).await?;
        Ok(result.unwrap_or_else(|| SearchResponse {
            patches: Vec::new(),
            can_access_paid_patches: false,
        }))
    }

    /// Search patches by CVE ID.
    pub async fn search_patches_by_cve(
        &self,
        org_slug: Option<&str>,
        cve_id: &str,
    ) -> Result<SearchResponse, ApiError> {
        self.search_patches_by_route(org_slug, "by-cve", cve_id)
            .await
    }

    /// Search patches by GHSA ID.
    pub async fn search_patches_by_ghsa(
        &self,
        org_slug: Option<&str>,
        ghsa_id: &str,
    ) -> Result<SearchResponse, ApiError> {
        self.search_patches_by_route(org_slug, "by-ghsa", ghsa_id)
            .await
    }

    /// Search patches by package PURL.
    ///
    /// The PURL must be a valid Package URL starting with `pkg:`.
    /// Examples: `pkg:npm/lodash@4.17.21`, `pkg:pypi/django@3.2.0`
    pub async fn search_patches_by_package(
        &self,
        org_slug: Option<&str>,
        purl: &str,
    ) -> Result<SearchResponse, ApiError> {
        self.search_patches_by_route(org_slug, "by-package", purl)
            .await
    }

    /// Search patches for multiple packages (batch).
    ///
    /// For authenticated API, uses the POST `/v0/orgs/{slug}/patches/batch`
    /// endpoint. For the public proxy, POSTs `/patch/batch` (served
    /// `Cache-Control: no-store` — POST bodies are not CDN-cacheable) and
    /// only degrades to individual GET requests per PURL (concurrency 10)
    /// when the deployed proxy predates the batch endpoint.
    ///
    /// Maximum 500 PURLs per request.
    pub async fn search_patches_batch(
        &self,
        org_slug: Option<&str>,
        purls: &[String],
    ) -> Result<BatchSearchResponse, ApiError> {
        if !self.use_public_proxy {
            let slug = org_slug.or(self.org_slug.as_deref()).unwrap_or("default");
            let path = format!("/v0/orgs/{}/patches/batch", slug);
            let body = BatchSearchBody {
                components: purls
                    .iter()
                    .map(|p| BatchComponent { purl: p.clone() })
                    .collect(),
            };
            let result = self
                .post_json::<BatchSearchResponse, _>(&path, &body)
                .await?;
            return Ok(result.unwrap_or_else(|| BatchSearchResponse {
                packages: Vec::new(),
                can_access_paid_patches: false,
            }));
        }

        // Public proxy: prefer the POST /patch/batch endpoint; degrade to
        // individual per-package GET requests when the deployed proxy
        // predates it or when batch validation rejects the chunk (see
        // `proxy_batch_post` for the decision table).
        match self.proxy_batch_post(purls).await? {
            Some(response) => Ok(response),
            None => {
                self.search_patches_batch_via_individual_queries(purls)
                    .await
            }
        }
    }

    /// Resolve hosted-patch references for a set of published-patch UUIDs
    /// (`scan --redirect`). Uses the authenticated
    /// `POST /v0/orgs/{org}/patches/package` when a token+org are set, else the
    /// public proxy `POST /patch/package` (free patches only). Returns a
    /// UUID → reference map (missing/404 → empty).
    pub async fn fetch_registry_references(
        &self,
        uuids: &[String],
    ) -> Result<std::collections::HashMap<String, RegistryReference>, ApiError> {
        if uuids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let path = if self.use_public_proxy {
            "/patch/package".to_string()
        } else {
            let slug = self.org_slug.as_deref().unwrap_or("default");
            format!("/v0/orgs/{}/patches/package", slug)
        };
        let body = RegistryReferenceBody {
            uuids: uuids.to_vec(),
        };
        let resp = self
            .post_json::<RegistryReferenceResponse, _>(&path, &body)
            .await?;
        Ok(resp.map(|r| r.results).unwrap_or_default())
    }

    /// Internal: POST the batch search to the public proxy's
    /// `/patch/batch` endpoint.
    ///
    /// Returns `Ok(None)` when the caller should degrade to the legacy
    /// per-package GET path, in two situations:
    ///
    /// 1. The deployed proxy predates the batch endpoint (see
    ///    [`is_batch_unsupported`]).
    /// 2. The batch endpoint rejected the chunk with a validation `400`.
    ///    Batch validation is all-or-nothing, so a single crawled PURL of
    ///    a type the server doesn't recognize (e.g. `pkg:jsr/…` from the
    ///    Deno crawler) rejects every package in the chunk. The
    ///    per-package GET path tolerates such PURLs individually — each
    ///    failure is swallowed per-package — which is the scan semantic
    ///    that predates the batch optimization and must be preserved: one
    ///    exotic package must not turn a whole scan into an error.
    ///
    /// Auth / rate-limit statuses are classified via `classify_auth_error`
    /// exactly like the JSON transport — 401/403 keep feeding
    /// `is_fallback_candidate` and 429 stays visible — and any other
    /// failure (including over-capacity 503s) surfaces as an error.
    async fn proxy_batch_post(
        &self,
        purls: &[String],
    ) -> Result<Option<BatchSearchResponse>, ApiError> {
        let url = format!("{}/patch/batch", self.api_url);
        debug_log(&format!("POST {}", url));

        let body = BatchSearchBody {
            components: purls
                .iter()
                .map(|p| BatchComponent { purl: p.clone() })
                .collect(),
        };

        let resp = self
            .client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ApiError::Network(format!("Network error: {}", e)))?;

        let status = resp.status();

        if status == StatusCode::OK {
            let parsed = resp
                .json::<BatchSearchResponse>()
                .await
                .map_err(|e| ApiError::Parse(format!("Failed to parse response: {}", e)))?;
            return Ok(Some(parsed));
        }

        if let Some(err) = classify_auth_error(status, true) {
            return Err(err);
        }

        let text = resp.text().await.unwrap_or_default();
        let fallback_reason = if is_batch_unsupported(status, &text) {
            Some("proxy batch endpoint unavailable")
        } else if status == StatusCode::BAD_REQUEST {
            // All-or-nothing batch validation rejected the chunk; the
            // per-package path resolves the valid subset (see doc above).
            Some("proxy batch validation rejected the chunk")
        } else {
            None
        };
        if let Some(reason) = fallback_reason {
            debug_log(&format!(
                "{} (status {}: {}); falling back to individual queries",
                reason,
                status.as_u16(),
                text
            ));
            return Ok(None);
        }
        Err(ApiError::Other(format!(
            "API request failed with status {}: {}",
            status.as_u16(),
            text
        )))
    }

    /// Internal: fall back to individual GET requests per PURL when the
    /// batch endpoint is not available (public proxy mode). Since the
    /// proxy gained `POST /patch/batch`, this is the legacy path for
    /// deployments that predate it.
    ///
    /// Processes PURLs in batches of `CONCURRENCY_LIMIT` to avoid
    /// overwhelming the server while remaining efficient.
    async fn search_patches_batch_via_individual_queries(
        &self,
        purls: &[String],
    ) -> Result<BatchSearchResponse, ApiError> {
        const CONCURRENCY_LIMIT: usize = 10;

        // Collect all (purl, response) pairs
        let mut all_results: Vec<(String, Option<SearchResponse>)> = Vec::new();

        for chunk in purls.chunks(CONCURRENCY_LIMIT) {
            // Use tokio::JoinSet for concurrent execution within each chunk
            let mut join_set = tokio::task::JoinSet::new();

            for purl in chunk {
                let purl = purl.clone();
                let client = self.clone();
                join_set.spawn(async move {
                    let resp = client.search_patches_by_package(None, &purl).await;
                    match resp {
                        Ok(r) => (purl, Some(r)),
                        Err(e) => {
                            debug_log(&format!("Error fetching patches for {}: {}", purl, e));
                            (purl, None)
                        }
                    }
                });
            }

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(pair) => all_results.push(pair),
                    Err(e) => {
                        debug_log(&format!("Task join error: {}", e));
                    }
                }
            }
        }

        // Convert the individual SearchResponse results into the batch shape.
        Ok(assemble_batch_from_individual(all_results))
    }

    /// Fetch organizations accessible to the current API token.
    pub async fn fetch_organizations(
        &self,
    ) -> Result<Vec<crate::api::types::OrganizationInfo>, ApiError> {
        let path = "/v0/organizations";
        match self
            .get_json::<crate::api::types::OrganizationsResponse>(path)
            .await?
        {
            Some(resp) => Ok(resp.organizations.into_values().collect()),
            None => Ok(Vec::new()),
        }
    }

    /// Resolve the org slug from the API token by querying `/v0/organizations`.
    ///
    /// If there is exactly one org, returns its slug.
    /// If there are multiple, picks the first and prints a warning.
    /// If there are none, returns an error.
    pub async fn resolve_org_slug(&self) -> Result<String, ApiError> {
        let orgs = self.fetch_organizations().await?;
        select_org_slug(orgs)
    }

    /// Fetch a blob by its SHA-256 hash.
    ///
    /// Returns the raw binary content, or `Ok(None)` if not found.
    /// Uses the authenticated endpoint when token and org slug are
    /// available, otherwise falls back to the public proxy.
    pub async fn fetch_blob(&self, hash: &str) -> Result<Option<Vec<u8>>, ApiError> {
        // Validate hash format: SHA-256 = 64 hex characters
        if !is_valid_sha256_hex(hash) {
            return Err(ApiError::InvalidHash(format!(
                "Invalid hash format: {}. Expected SHA256 hash (64 hex characters).",
                hash
            )));
        }
        self.fetch_binary("blob", "blob", hash).await
    }

    /// Fetch a per-file diff archive (tar.gz of bsdiff deltas) by patch UUID.
    ///
    /// Returns the raw archive bytes, or `Ok(None)` if not found (404). The
    /// public proxy serves these under `/patch/diff/<uuid>`; the
    /// authenticated API serves them under `/v0/orgs/<slug>/patches/diff/<uuid>`.
    pub async fn fetch_diff(&self, uuid: &str) -> Result<Option<Vec<u8>>, ApiError> {
        if !is_valid_uuid(uuid) {
            return Err(ApiError::InvalidHash(format!(
                "Invalid patch UUID: {}",
                uuid
            )));
        }
        self.fetch_binary("diff", "diff", uuid).await
    }

    /// Fetch a per-package patch archive (tar.gz of patched files) by patch UUID.
    ///
    /// Returns the raw archive bytes, or `Ok(None)` if not found (404).
    pub async fn fetch_package(&self, uuid: &str) -> Result<Option<Vec<u8>>, ApiError> {
        if !is_valid_uuid(uuid) {
            return Err(ApiError::InvalidHash(format!(
                "Invalid patch UUID: {}",
                uuid
            )));
        }
        self.fetch_binary("package", "package", uuid).await
    }

    /// Build the URL (and an `is_authenticated` flag) for a binary fetch of
    /// `kind` (`blob` / `diff` / `package`) identified by `identifier`.
    ///
    /// Uses the authenticated `/v0/orgs/<slug>/patches/...` endpoint when a
    /// token and org slug are configured (and we're not pinned to the public
    /// proxy). Otherwise it targets the public proxy.
    ///
    /// In public-proxy mode the base is the client's own configured `api_url`
    /// — the same value the JSON endpoints (`get_json`/`post_json`) use — so an
    /// explicit `--proxy-url` / `SOCKET_PROXY_URL` override is honored for
    /// binary downloads too. Only when falling back from an *authenticated*
    /// client that lacks an org slug (so `api_url` is the auth host, not a
    /// proxy) do we re-derive the proxy base from the environment.
    fn binary_url(&self, kind: &str, identifier: &str) -> (String, bool) {
        if self.api_token.is_some() && self.org_slug.is_some() && !self.use_public_proxy {
            let slug = self.org_slug.as_deref().unwrap();
            let u = format!(
                "{}/v0/orgs/{}/patches/{}/{}",
                self.api_url, slug, kind, identifier
            );
            (u, true)
        } else {
            let base = if self.use_public_proxy {
                self.api_url.clone()
            } else {
                read_env_with_legacy("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL")
                    .unwrap_or_else(|| DEFAULT_PATCH_API_PROXY_URL.to_string())
            };
            let u = format!(
                "{}/patch/{}/{}",
                base.trim_end_matches('/'),
                kind,
                identifier
            );
            (u, false)
        }
    }

    /// Shared implementation for `fetch_blob` / `fetch_diff` / `fetch_package`.
    ///
    /// `kind` is the URL segment (`blob` / `diff` / `package`). `label` is the
    /// human-readable noun used in log + error messages. `identifier` is the
    /// hash or UUID interpolated into the URL.
    async fn fetch_binary(
        &self,
        kind: &str,
        label: &str,
        identifier: &str,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let (url, use_auth) = self.binary_url(kind, identifier);

        debug_log(&format!("GET {} {}", label, url));

        // Build the request. When fetching from the public proxy (different
        // base URL than self.api_url), we use a plain client without auth
        // headers to avoid leaking credentials to the proxy.
        let resp = if use_auth {
            self.client
                .get(&url)
                .header(header::ACCEPT, "application/octet-stream")
                .send()
                .await
        } else {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::USER_AGENT,
                HeaderValue::from_static(USER_AGENT_VALUE),
            );
            headers.insert(
                header::ACCEPT,
                HeaderValue::from_static("application/octet-stream"),
            );

            let plain_client = reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .expect("failed to build plain reqwest client");

            plain_client.get(&url).send().await
        };

        let resp = resp.map_err(|e| {
            ApiError::Network(format!(
                "Network error fetching {} {}: {}",
                label, identifier, e
            ))
        })?;

        let status = resp.status();

        if status == StatusCode::OK {
            let bytes = resp.bytes().await.map_err(|e| {
                ApiError::Network(format!(
                    "Error reading {} body for {}: {}",
                    label, identifier, e
                ))
            })?;
            return Ok(Some(bytes.to_vec()));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        // Classify 401/403/429 identically to the JSON transport path
        // (`handle_json_response`). Without this an authenticated blob/diff/
        // package fetch that 401s/403s would surface as `ApiError::Other`,
        // which `is_fallback_candidate` ignores — silently disabling the
        // auth→proxy fallback for binary downloads. `use_auth` is the
        // authenticated-endpoint flag, so `!use_auth` is the proxy case that
        // drives the paid-patch wording.
        if let Some(err) = classify_auth_error(status, !use_auth) {
            return Err(err);
        }
        let text = resp.text().await.unwrap_or_default();
        Err(ApiError::Other(format!(
            "Failed to fetch {} {}: status {} - {}",
            label,
            identifier,
            status.as_u16(),
            text,
        )))
    }

    /// Resolve a published-patch UUID into a prebuilt vendored archive +
    /// integrity from the patch.socket.dev vendoring service, then download it.
    ///
    /// Two HTTP round-trips:
    /// 1. POST the package-reference endpoint (`/v0/orgs/{slug}/patches/package`
    ///    when authenticated, else the public proxy's `/patch/package`) to mint
    ///    / reuse a download grant and learn the artifact URL + integrity.
    /// 2. GET the returned grant-tokenized serve URL for the archive bytes.
    ///
    /// `vendor_url` overrides the step-1 base host; `patch_server_url` rewrites
    /// the step-2 download host (both for staging / local-dev / testing). The
    /// returned [`FetchedVendorPackage`] carries the *unverified* bytes plus the
    /// service-reported integrity — the caller verifies before use.
    pub async fn fetch_vendor_package(
        &self,
        uuid: &str,
        free_only: bool,
        vendor_url: Option<&str>,
        patch_server_url: Option<&str>,
    ) -> VendorServiceOutcome {
        if !is_valid_uuid(uuid) {
            return VendorServiceOutcome::Failed(ApiError::InvalidHash(format!(
                "Invalid patch UUID: {uuid}"
            )));
        }

        // ── Step 1: resolve the grant URL + integrity ──────────────────────
        let result = match self.request_vendor_package(uuid, free_only, vendor_url).await {
            Ok(r) => r,
            Err(e) => return VendorServiceOutcome::Failed(e),
        };
        // Classify the build/grant status before attempting any download.
        match result.status.as_str() {
            "granted" | "reused" => {}
            "pending_build" => return VendorServiceOutcome::Pending,
            "build_failed" | "withdrawn" | "not_found" => {
                return VendorServiceOutcome::Unavailable(result.status.clone())
            }
            "forbidden" => {
                return VendorServiceOutcome::Failed(ApiError::Forbidden(
                    "Forbidden: not entitled to this patch (paid tier or no org access).".into(),
                ))
            }
            other => {
                return VendorServiceOutcome::Unavailable(format!("unknown status `{other}`"))
            }
        }

        // Select the native tarball artifact and its sha512 (the universal
        // integrity floor — every ecosystem's tarball carries it). The npm
        // yarn-berry-zip artifact is intentionally ignored here (v1).
        let Some(artifact) = result
            .artifacts
            .as_ref()
            .and_then(|arts| arts.iter().find(|a| a.kind == "tarball"))
        else {
            return VendorServiceOutcome::Unavailable("no tarball artifact in response".into());
        };
        let Some(sha512_raw) = artifact.integrity.sha512.as_deref() else {
            return VendorServiceOutcome::Unavailable(
                "tarball artifact has no sha512 integrity".into(),
            );
        };
        let integrity_sri = normalize_sha512_sri(sha512_raw);
        // The artifact's own URL wins; fall back to the top-level `url`.
        let Some(download_url) = artifact.url.as_deref().or(result.url.as_deref()) else {
            return VendorServiceOutcome::Unavailable("granted result has no download url".into());
        };
        let download_url = match patch_server_url {
            Some(base) => match rewrite_url_host(download_url, base) {
                Ok(u) => u,
                Err(e) => return VendorServiceOutcome::Failed(e),
            },
            None => download_url.to_string(),
        };

        // Surface the OTHER served artifacts (e.g. the gem path-source stub
        // gemspec) — their host-rewritten URL + normalized sha512 — so a
        // backend that needs one can download + verify it lazily. Each is
        // skipped unless it carries both a url and a sha512.
        let mut secondary_artifacts: Vec<SecondaryArtifact> = Vec::new();
        if let Some(arts) = result.artifacts.as_ref() {
            for a in arts {
                if a.kind == "tarball" {
                    continue;
                }
                let (Some(url), Some(sha512)) =
                    (a.url.as_deref(), a.integrity.sha512.as_deref())
                else {
                    continue;
                };
                let url = match patch_server_url {
                    Some(base) => match rewrite_url_host(url, base) {
                        Ok(u) => u,
                        Err(_) => continue,
                    },
                    None => url.to_string(),
                };
                secondary_artifacts.push(SecondaryArtifact {
                    kind: a.kind.clone(),
                    url,
                    integrity_sri: normalize_sha512_sri(sha512),
                });
            }
        }

        // ── Step 2: download the prebuilt archive ──────────────────────────
        match self.download_vendor_archive(&download_url).await {
            ServeDownload::Ok(bytes) => VendorServiceOutcome::Ready(FetchedVendorPackage {
                tarball: bytes,
                integrity_sri,
                sha1_hex: artifact.integrity.sha1.clone(),
                dirhash_h1: artifact.integrity.dirhash_h1.clone(),
                size_bytes: artifact.size_bytes,
                content_type: artifact.content_type.clone(),
                source_url: download_url,
                secondary_artifacts,
            }),
            ServeDownload::NotFound => {
                VendorServiceOutcome::Unavailable("serve returned 404/410".into())
            }
            ServeDownload::Pending => VendorServiceOutcome::Pending,
            ServeDownload::Failed(e) => VendorServiceOutcome::Failed(e),
        }
    }

    /// Step 1 of [`Self::fetch_vendor_package`]: POST the package-reference
    /// endpoint and return the single requested UUID's result.
    async fn request_vendor_package(
        &self,
        uuid: &str,
        free_only: bool,
        vendor_url: Option<&str>,
    ) -> Result<PackageVendorResult, ApiError> {
        let body = PackageVendorRequest {
            uuids: vec![uuid.to_string()],
            // Only send freeOnly when forcing it (the public-proxy contract);
            // the authenticated endpoint defaults to false.
            free_only: free_only.then_some(true),
        };
        // Authenticated when a token + org slug are configured and we're not
        // pinned to the public proxy — mirrors `binary_url`'s decision so a
        // bearer is never sent to the proxy.
        let use_auth =
            self.api_token.is_some() && self.org_slug.is_some() && !self.use_public_proxy;
        let base = vendor_url
            .unwrap_or(&self.api_url)
            .trim_end_matches('/')
            .to_string();

        let resp = if use_auth {
            let slug = self.org_slug.as_deref().unwrap();
            let url = format!("{base}/v0/orgs/{slug}/patches/package");
            debug_log(&format!("POST {url}"));
            self.client
                .post(&url)
                .header(header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
        } else {
            let url = format!("{base}/patch/package");
            debug_log(&format!("POST {url}"));
            // Plain (no-auth) client: never leak the bearer to the proxy.
            plain_client()
                .post(&url)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .json(&body)
                .send()
                .await
        };

        let resp = resp.map_err(|e| ApiError::Network(format!("Network error: {e}")))?;
        let status = resp.status();
        if status == StatusCode::OK {
            let parsed = resp.json::<PackageVendorResponse>().await.map_err(|e| {
                ApiError::Parse(format!("Failed to parse package response: {e}"))
            })?;
            return parsed.results.get(uuid).cloned().ok_or_else(|| {
                ApiError::Other(format!("package response missing a result for {uuid}"))
            });
        }
        if let Some(err) = classify_auth_error(status, !use_auth) {
            return Err(err);
        }
        let text = resp.text().await.unwrap_or_default();
        Err(ApiError::Other(format!(
            "package request failed with status {}: {text}",
            status.as_u16(),
        )))
    }

    /// Step 2 of [`Self::fetch_vendor_package`]: GET the grant-tokenized serve
    /// URL. The grant token in the path is the authorization, so this uses a
    /// plain (no-auth) client.
    async fn download_vendor_archive(&self, url: &str) -> ServeDownload {
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return ServeDownload::Failed(ApiError::Other(format!(
                "refusing non-http(s) artifact URL `{url}`"
            )));
        }
        debug_log(&format!("GET vendor package {url}"));
        let resp = match plain_client()
            .get(url)
            .header(header::ACCEPT, "application/octet-stream")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return ServeDownload::Failed(ApiError::Network(format!(
                    "Network error fetching vendor package: {e}"
                )))
            }
        };
        let status = resp.status();
        match status {
            StatusCode::OK => {}
            // 404 (build_failed / not stored) and 410 (withdrawn) are terminal
            // misses; the caller decides build-fallback vs hard-fail.
            StatusCode::NOT_FOUND | StatusCode::GONE => return ServeDownload::NotFound,
            // 408 = the archive is still building (Retry-After) — retryable.
            StatusCode::REQUEST_TIMEOUT => return ServeDownload::Pending,
            _ => {
                if let Some(err) = classify_auth_error(status, true) {
                    return ServeDownload::Failed(err);
                }
                let text = resp.text().await.unwrap_or_default();
                return ServeDownload::Failed(ApiError::Other(format!(
                    "vendor package download failed with status {}: {text}",
                    status.as_u16(),
                )));
            }
        }
        match read_capped(resp, MAX_VENDOR_PACKAGE_BYTES).await {
            Ok(bytes) => ServeDownload::Ok(bytes),
            Err(e) => ServeDownload::Failed(ApiError::Network(e)),
        }
    }

    /// Download a secondary artifact (e.g. the gem stub gemspec) from its
    /// grant-tokenized serve URL. Same plain-client + cap discipline as the
    /// tarball download; the caller verifies the bytes against the artifact's
    /// integrity. A 404/410/408 surfaces as an error (a secondary the
    /// reference promised should be present).
    pub async fn download_artifact(&self, url: &str) -> Result<Vec<u8>, ApiError> {
        match self.download_vendor_archive(url).await {
            ServeDownload::Ok(bytes) => Ok(bytes),
            ServeDownload::NotFound => {
                Err(ApiError::Other(format!("artifact not found: {url}")))
            }
            ServeDownload::Pending => {
                Err(ApiError::Other(format!("artifact still building: {url}")))
            }
            ServeDownload::Failed(e) => Err(e),
        }
    }
}

// ── Free functions ────────────────────────────────────────────────────

/// Cap on a single prebuilt-archive download (defensive bound against a
/// runaway / hostile serve response). Generous enough for any real package.
const MAX_VENDOR_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;

/// A prebuilt vendored archive downloaded from the patch.socket.dev service,
/// together with the service-reported integrity. The bytes are **unverified**
/// here — callers must verify against `integrity_sri` (and, for golang, the
/// `h1:` dirhash) before writing/extracting.
#[derive(Debug, Clone)]
pub struct FetchedVendorPackage {
    pub tarball: Vec<u8>,
    /// Normalized Subresource-Integrity string, always `sha512-<b64>`.
    pub integrity_sri: String,
    /// Hex sha1 of the archive, when the service reported one.
    pub sha1_hex: Option<String>,
    /// golang module-zip dirhash (`h1:<b64>`), when present.
    pub dirhash_h1: Option<String>,
    pub size_bytes: Option<u64>,
    pub content_type: Option<String>,
    /// The (possibly host-rewritten) URL the bytes were fetched from.
    pub source_url: String,
    /// The OTHER served artifacts (e.g. the gem path-source stub gemspec),
    /// each with a host-rewritten URL + normalized sha512, for a backend to
    /// download + verify lazily via [`ApiClient::download_artifact`].
    pub secondary_artifacts: Vec<SecondaryArtifact>,
}

/// A non-tarball served artifact reference (e.g. `gem-stub-gemspec`): its kind,
/// final download URL, and sha512 SRI. Bytes are fetched + verified on demand.
#[derive(Debug, Clone)]
pub struct SecondaryArtifact {
    pub kind: String,
    pub url: String,
    /// Normalized `sha512-<b64>` of the artifact bytes.
    pub integrity_sri: String,
}

/// Outcome of [`ApiClient::fetch_vendor_package`].
///
/// The vendor backends map these onto the `auto`/`service`/`build` policy:
/// `Ready` → use the service archive; `Pending`/`Unavailable`/`Failed` → fall
/// back to a local build under `auto`, or hard-fail under `service`.
#[derive(Debug)]
pub enum VendorServiceOutcome {
    /// Archive downloaded; integrity carried for the caller to verify.
    Ready(FetchedVendorPackage),
    /// The archive is still building (`pending_build` status or serve 408) —
    /// retryable.
    Pending,
    /// A terminal miss for this input (not built, withdrawn, not found, or no
    /// usable artifact). `String` is a short reason for logging.
    Unavailable(String),
    /// A request/transport/auth failure (401/403 grant, 5xx, network, malformed).
    Failed(ApiError),
}

/// Internal result of the step-2 archive GET.
enum ServeDownload {
    Ok(Vec<u8>),
    /// 404 / 410 — terminal miss.
    NotFound,
    /// 408 — still building, retryable.
    Pending,
    Failed(ApiError),
}

/// Build a plain `reqwest::Client` carrying only the User-Agent — no
/// Authorization. Used for the public-proxy POST and the grant-tokenized serve
/// GET, where sending the Socket bearer would leak it to a third party.
fn plain_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(USER_AGENT_VALUE),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("failed to build plain reqwest client")
}

/// Stream a response body into memory with a hard byte cap, rejecting both an
/// over-large declared `Content-Length` and an actual stream that exceeds the
/// cap mid-flight.
async fn read_capped(mut resp: reqwest::Response, max: u64) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max {
            return Err(format!(
                "vendor package too large: declared {len} bytes > {max} cap"
            ));
        }
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("error reading vendor package body: {e}"))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > max {
            return Err(format!("vendor package exceeded {max}-byte cap mid-stream"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Normalize a service-reported sha512 into SRI form (`sha512-<b64>`).
///
/// The service persists npm SRI form, but tolerate a bare base64 digest by
/// prefixing it — `verify_sri` (the consumer) expects the `sha512-` prefix.
fn normalize_sha512_sri(value: &str) -> String {
    let v = value.trim();
    if v.starts_with("sha512-") {
        v.to_string()
    } else {
        format!("sha512-{v}")
    }
}

/// Rewrite the scheme + host (+ port) of `original` to those of `new_base`,
/// preserving `original`'s path and query. Used to redirect a server-returned
/// serve URL at a local-dev / test host (`--patch-server-url`).
fn rewrite_url_host(original: &str, new_base: &str) -> Result<String, ApiError> {
    let orig = reqwest::Url::parse(original)
        .map_err(|e| ApiError::Other(format!("malformed serve URL `{original}`: {e}")))?;
    let mut base = reqwest::Url::parse(new_base)
        .map_err(|e| ApiError::Other(format!("malformed --patch-server-url `{new_base}`: {e}")))?;
    base.set_path(orig.path());
    base.set_query(orig.query());
    Ok(base.to_string())
}

/// Explicit overrides for environment-based API client construction.
///
/// Each `Some(value)` wins over the corresponding env var; `None` falls
/// back to env-var lookup (with the legacy `SOCKET_PATCH_*` shim where
/// applicable).
#[derive(Debug, Clone, Default)]
pub struct ApiClientEnvOverrides {
    pub api_url: Option<String>,
    pub api_token: Option<String>,
    pub org_slug: Option<String>,
    pub proxy_url: Option<String>,
}

/// Get an API client configured from environment variables.
///
/// If `SOCKET_API_TOKEN` is not set, the client will use the public patch
/// API proxy which provides free access to free-tier patches without
/// authentication.
///
/// When `SOCKET_API_TOKEN` is set but no org slug is provided (neither via
/// argument nor `SOCKET_ORG_SLUG` env var), the function will attempt to
/// auto-resolve the org slug by querying `GET /v0/organizations`.
///
/// # Environment variables
///
/// | Variable | Purpose |
/// |---|---|
/// | `SOCKET_API_URL` | Override the API URL (default `https://api.socket.dev`) |
/// | `SOCKET_API_TOKEN` | API token for authenticated access |
/// | `SOCKET_PROXY_URL` | Override the public proxy URL (default `https://patches-api.socket.dev`). Legacy: `SOCKET_PATCH_PROXY_URL`. |
/// | `SOCKET_ORG_SLUG` | Organization slug |
///
/// Returns `(client, use_public_proxy)`.
pub async fn get_api_client_from_env(org_slug: Option<&str>) -> (ApiClient, bool) {
    get_api_client_with_overrides(ApiClientEnvOverrides {
        org_slug: org_slug.map(String::from),
        ..ApiClientEnvOverrides::default()
    })
    .await
}

/// Like [`get_api_client_from_env`] but with explicit overrides for every
/// env-driven knob. Each `Some(value)` in `overrides` wins over the
/// corresponding env var. Used by CLI commands that expose `--api-url`,
/// `--api-token`, `--org`, `--proxy-url` flags via [`crate::utils`] in the
/// CLI crate.
pub async fn get_api_client_with_overrides(overrides: ApiClientEnvOverrides) -> (ApiClient, bool) {
    let api_token = overrides
        .api_token
        .or_else(|| std::env::var("SOCKET_API_TOKEN").ok())
        .filter(|t| !t.is_empty());
    let resolved_org_slug = overrides
        .org_slug
        .or_else(|| std::env::var("SOCKET_ORG_SLUG").ok())
        // Treat an empty slug as "not provided" (mirroring the api_token
        // handling above). Otherwise `SOCKET_ORG_SLUG=""` would be taken as
        // an explicit slug, skip auto-resolution, and build broken
        // `/v0/orgs//patches/...` URLs with an empty slug segment.
        .filter(|s| !s.is_empty());

    if api_token.is_none() {
        let proxy_url = overrides.proxy_url.unwrap_or_else(|| {
            read_env_with_legacy("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL")
                .unwrap_or_else(|| DEFAULT_PATCH_API_PROXY_URL.to_string())
        });
        eprintln!("No SOCKET_API_TOKEN set. Using public patch API proxy (free patches only).");
        let client = ApiClient::new(ApiClientOptions {
            api_url: proxy_url,
            api_token: None,
            use_public_proxy: true,
            org_slug: None,
        });
        return (client, true);
    }

    // Shape check the configured token before the network round-trip so
    // a "you set the hash, not the token" mistake is loud and immediate.
    if let Some(ref t) = api_token {
        if let Some(msg) = validate_token_shape(t) {
            eprintln!("{msg}");
        }
    }

    let api_url = overrides
        .api_url
        .or_else(|| std::env::var("SOCKET_API_URL").ok())
        .unwrap_or_else(|| DEFAULT_SOCKET_API_URL.to_string());

    // Auto-resolve org slug if not provided
    let final_org_slug = if resolved_org_slug.is_some() {
        resolved_org_slug
    } else {
        let temp_client = ApiClient::new(ApiClientOptions {
            api_url: api_url.clone(),
            api_token: api_token.clone(),
            use_public_proxy: false,
            org_slug: None,
        });
        match temp_client.resolve_org_slug().await {
            Ok(slug) => Some(slug),
            Err(e) => {
                eprintln!("Warning: Could not auto-detect organization: {e}");
                if matches!(e, ApiError::Unauthorized(_)) {
                    if let Some(ref t) = api_token {
                        if looks_like_token_hash(t) {
                            eprintln!(
                                "  Hint: SOCKET_API_TOKEN starts with `{}-` \
                                 which is the stored hash format. Set it to \
                                 the raw `sktsec_..._api` value instead.",
                                t.split('-').next().unwrap_or("sha512")
                            );
                        }
                    }
                }
                None
            }
        }
    };

    let client = ApiClient::new(ApiClientOptions {
        api_url,
        api_token,
        use_public_proxy: false,
        org_slug: final_org_slug,
    });
    (client, false)
}

/// Build a public-proxy `ApiClient` from the same overrides used by
/// [`get_api_client_with_overrides`], ignoring any API token.
///
/// Used by `scan` and `get` to retry against the public proxy after
/// the authenticated endpoint returns 401/403 — a stale/revoked token
/// shouldn't block access to free patches. The auth header is
/// deliberately dropped (`api_token: None`).
pub fn build_proxy_fallback_client(overrides: &ApiClientEnvOverrides) -> ApiClient {
    let proxy_url = overrides.proxy_url.clone().unwrap_or_else(|| {
        read_env_with_legacy("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL")
            .unwrap_or_else(|| DEFAULT_PATCH_API_PROXY_URL.to_string())
    });
    ApiClient::new(ApiClientOptions {
        api_url: proxy_url,
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
    })
}

/// Return `true` when the configured token value looks like an
/// SRI-format hash (`sha512-<base64>` etc.) rather than a raw API
/// token. The server stores tokens *as* this hash; the CLI sometimes
/// gets configured with the storage representation by mistake (users
/// copy what they see in the dashboard). Surfacing this as a hint
/// short-circuits a confusing 401 round-trip.
pub fn looks_like_token_hash(token: &str) -> bool {
    matches!(
        token.split_once('-'),
        Some(("sha256" | "sha384" | "sha512", _))
    )
}

/// Inspect a configured `SOCKET_API_TOKEN` value and return a
/// human-readable warning when the value doesn't match the canonical
/// Socket API token shape (`sktsec_<44 chars>_api`). Returns `None`
/// when the token looks valid, so the caller can ignore the result
/// without checking length.
///
/// The validation is intentionally a non-authoritative shape check —
/// the server's regex is the source of truth. We only flag values
/// that are *obviously* wrong (e.g. the storage hash, an empty
/// prefix/suffix) so a benign typo at the server's regex boundary
/// doesn't generate noise.
///
/// The returned message redacts the middle of the token (first 8 +
/// last 4 chars) so a real token doesn't leak into stderr if a user
/// pastes one with a wrong suffix.
pub fn validate_token_shape(token: &str) -> Option<String> {
    let has_prefix = token.starts_with("sktsec_");
    let has_suffix = token.ends_with("_api") || token.ends_with("_agent");
    // Measure in characters, not bytes: the preview/length reporting below
    // counts characters (and the message literally says "chars"), so a
    // multi-byte token must be sized the same way. Using `token.len()` here
    // would over-count the length and mis-slice the redaction tail.
    let len = token.chars().count();
    let plausible_len = len >= 55;
    if has_prefix && has_suffix && plausible_len {
        return None;
    }
    let head: String = token.chars().take(8).collect();
    let tail_start = len.saturating_sub(4);
    let tail: String = token.chars().skip(tail_start).collect();
    let preview = if len <= 12 {
        token.to_string()
    } else {
        format!("{head}...{tail}")
    };
    let hash_hint = if looks_like_token_hash(token) {
        "\n  That value looks like an SRI-format hash (sha###-<base64>) — \
         the server stores the *hash* of your token, not what you should \
         set here. Use the raw `sktsec_..._api` value shown when the token \
         was generated."
    } else {
        ""
    };
    Some(format!(
        "Warning: SOCKET_API_TOKEN does not look like a Socket API token \
         (expected `sktsec_<44 chars>_api`).{hash_hint}\n  \
         Got: {preview} ({len} chars). Continuing anyway; the server may \
         reject this with 401."
    ))
}

/// Classify an [`ApiError`] as a candidate for the auth → proxy
/// fallback. We only re-route on 401/403 (the stale-credentials
/// signals). Network errors, rate limits, 404s, and 5xx surface as-is
/// so they remain visible to the operator.
pub fn is_fallback_candidate(err: &ApiError) -> bool {
    matches!(err, ApiError::Unauthorized(_) | ApiError::Forbidden(_))
}

/// Map the well-known auth / rate-limit HTTP statuses (401 / 403 / 429) to
/// their tailored [`ApiError`] variant. Returns `None` for any other status,
/// leaving `OK` / `404` / fallthrough handling to the caller.
///
/// Shared by both transport paths — the JSON [`ApiClient::handle_json_response`]
/// *and* the binary [`ApiClient::fetch_binary`] — so a 401/403 is classified
/// identically regardless of whether the body is JSON or octet-stream. This is
/// what [`is_fallback_candidate`] keys on to reroute auth→proxy: a binary
/// download that buried these statuses under [`ApiError::Other`] would silently
/// skip the fallback (and lose the operator-facing message).
///
/// `use_public_proxy` selects the 403 wording (paid-subscriber hint vs.
/// org-access hint).
fn classify_auth_error(status: StatusCode, use_public_proxy: bool) -> Option<ApiError> {
    match status {
        StatusCode::UNAUTHORIZED => Some(ApiError::Unauthorized(
            "Unauthorized: Invalid API token".into(),
        )),
        StatusCode::FORBIDDEN => {
            let msg = if use_public_proxy {
                "Forbidden: This patch is only available to paid subscribers. \
                 Sign up at https://socket.dev to access paid patches."
            } else {
                "Forbidden: Access denied. This may be a paid patch or \
                 you may not have access to this organization."
            };
            Some(ApiError::Forbidden(msg.into()))
        }
        StatusCode::TOO_MANY_REQUESTS => Some(ApiError::RateLimited(
            "Rate limit exceeded. Please try again later.".into(),
        )),
        _ => None,
    }
}

/// Decide whether a public-proxy response to `POST /patch/batch` means the
/// endpoint is unsupported on that deployment, in which case
/// [`ApiClient::search_patches_batch`] degrades to per-package GETs (which
/// every proxy supports and which are CDN-cacheable).
///
/// The `"Unsupported endpoint"` marker is a cross-repo contract with the
/// depscan firewall-api-proxy: its catch-all answers unknown routes with
/// `400 {"error":"Unsupported endpoint",...}`. Batch validation failures
/// use different wording and are deliberately NOT matched here — the
/// caller (`proxy_batch_post`) still degrades them to the per-package
/// path, but logs them as a chunk-validation rejection rather than a
/// missing endpoint. For 503, only the "Patch API is not configured"
/// body (patch endpoints disabled) degrades — an over-capacity 503
/// ("Service temporarily over capacity") surfaces rather than amplifying
/// load tenfold via the per-package fallback.
fn is_batch_unsupported(status: StatusCode, body: &str) -> bool {
    match status {
        StatusCode::BAD_REQUEST => body.contains("Unsupported endpoint"),
        StatusCode::SERVICE_UNAVAILABLE => body.contains("Patch API is not configured"),
        // A deployment / CDN layer with no route for POST /patch/batch.
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => true,
        _ => false,
    }
}

/// Choose an org slug from the list returned by `/v0/organizations`.
///
/// Returns an error when the list is empty, the sole slug when there is
/// exactly one, and the first slug (with a warning) when there are several.
///
/// `fetch_organizations` collects from a `HashMap`, so the upstream order is
/// not stable across runs. We sort by slug first so the chosen org *and* the
/// warning text are deterministic — otherwise a token with multiple orgs
/// could silently operate against a different org on each invocation.
fn select_org_slug(mut orgs: Vec<crate::api::types::OrganizationInfo>) -> Result<String, ApiError> {
    orgs.sort_by(|a, b| a.slug.cmp(&b.slug));
    match orgs.len() {
        0 => Err(ApiError::Other(
            "No organizations found for this API token.".into(),
        )),
        1 => Ok(orgs.into_iter().next().unwrap().slug),
        _ => {
            let slugs: Vec<_> = orgs.iter().map(|o| o.slug.as_str()).collect();
            let first = orgs[0].slug.clone();
            eprintln!(
                "Multiple organizations found: {}. Using \"{}\". \
                 Pass --org to select a different one.",
                slugs.join(", "),
                first
            );
            Ok(first)
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Percent-encode a string for use in URL path segments.
fn urlencoding_encode(input: &str) -> String {
    // Encode everything that is not unreserved per RFC 3986.
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
        }
    }
    out
}

/// Truncate a string to at most `max_chars` characters, appending "..." if truncated.
/// Unlike byte slicing (`&s[..n]`), this is safe for multi-byte UTF-8 characters.
fn truncate_to_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{}...", truncated)
}

/// Validate that a string is a 64-character hex string (SHA-256).
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate the standard 8-4-4-4-12 UUID hex grouping.
fn is_valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lengths = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(lengths.iter())
        .all(|(part, &want)| part.len() == want && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Convert a `PatchSearchResult` into a `BatchPatchInfo`, extracting
/// CVE/GHSA IDs and computing the highest severity.
fn convert_search_result_to_batch_info(patch: PatchSearchResult) -> BatchPatchInfo {
    let mut cve_ids: Vec<String> = Vec::new();
    let mut ghsa_ids: Vec<String> = Vec::new();
    let mut highest_severity: Option<String> = None;
    let mut title = String::new();

    let mut seen_cves: HashSet<String> = HashSet::new();

    // `vulnerabilities` is a HashMap, so iterate in a stable (GHSA-id) order.
    // Otherwise the chosen `title` (first non-empty summary) — and the
    // first-seen tie-break for equal severities — would vary across runs.
    let mut entries: Vec<(&String, &VulnerabilityResponse)> =
        patch.vulnerabilities.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    for (ghsa_id, vuln) in entries {
        ghsa_ids.push(ghsa_id.clone());

        for cve in &vuln.cves {
            if seen_cves.insert(cve.clone()) {
                cve_ids.push(cve.clone());
            }
        }

        // Track highest severity (lower order number = higher severity)
        let current_order = get_severity_order(highest_severity.as_deref());
        let vuln_order = get_severity_order(Some(&vuln.severity));
        if vuln_order < current_order {
            highest_severity = Some(vuln.severity.clone());
        }

        // Use first non-empty summary as title
        if title.is_empty() && !vuln.summary.is_empty() {
            title = truncate_to_chars(&vuln.summary, 97);
        }
    }

    // Use description as fallback title
    if title.is_empty() && !patch.description.is_empty() {
        title = truncate_to_chars(&patch.description, 97);
    }

    cve_ids.sort();
    ghsa_ids.sort();

    BatchPatchInfo {
        uuid: patch.uuid,
        purl: patch.purl,
        tier: patch.tier,
        cve_ids,
        ghsa_ids,
        severity: highest_severity,
        title,
    }
}

/// Assemble a [`BatchSearchResponse`] from the per-PURL [`SearchResponse`]s
/// gathered by the public-proxy fallback (one GET per package).
///
/// A `None` entry is a query that errored and is skipped. The
/// `can_access_paid_patches` capability is OR-aggregated across **every**
/// successful response — independent of whether that response carried any
/// patches — because it is a global capability signal, not a per-package
/// one. The empty-patches check only governs whether a package is added to
/// the `packages` list (an empty package would be noise), so it must run
/// *after* the flag is observed; folding it into the same skip would drop a
/// `canAccessPaidPatches: true` that arrived alongside an empty patch list.
fn assemble_batch_from_individual(
    results: Vec<(String, Option<SearchResponse>)>,
) -> BatchSearchResponse {
    let mut packages: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;

    for (purl, response) in results {
        let Some(response) = response else { continue };

        if response.can_access_paid_patches {
            can_access_paid_patches = true;
        }

        if response.patches.is_empty() {
            continue;
        }

        let batch_patches: Vec<BatchPatchInfo> = response
            .patches
            .into_iter()
            .map(convert_search_result_to_batch_info)
            .collect();

        packages.push(BatchPackagePatches {
            purl,
            patches: batch_patches,
        });
    }

    BatchSearchResponse {
        packages,
        can_access_paid_patches,
    }
}

// ── Error type ────────────────────────────────────────────────────────

/// Errors returned by [`ApiClient`] methods.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Network(String),

    #[error("{0}")]
    Parse(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    RateLimited(String),

    #[error("{0}")]
    InvalidHash(String),

    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_urlencoding_basic() {
        assert_eq!(urlencoding_encode("hello"), "hello");
        assert_eq!(urlencoding_encode("a b"), "a%20b");
        assert_eq!(
            urlencoding_encode("pkg:npm/lodash@4.17.21"),
            "pkg%3Anpm%2Flodash%404.17.21"
        );
    }

    #[test]
    fn test_is_valid_sha256_hex() {
        let valid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(is_valid_sha256_hex(valid));

        // Too short
        assert!(!is_valid_sha256_hex("abcdef"));
        // Non-hex
        assert!(!is_valid_sha256_hex(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_severity_order() {
        assert!(get_severity_order(Some("critical")) < get_severity_order(Some("high")));
        assert!(get_severity_order(Some("high")) < get_severity_order(Some("medium")));
        assert!(get_severity_order(Some("medium")) < get_severity_order(Some("low")));
        assert!(get_severity_order(Some("low")) < get_severity_order(None));
        assert_eq!(
            get_severity_order(Some("unknown")),
            get_severity_order(None)
        );
    }

    #[test]
    fn test_severity_order_moderate_is_medium_tier() {
        // Regression: GHSA emits `moderate` for the medium tier (the same
        // convention output.rs `format_severity` and get.rs `severity_rank`
        // already follow). The moderate-blind ordering lumped it in with
        // "unknown" (rank 4), ranking it *below* low.
        assert_eq!(
            get_severity_order(Some("moderate")),
            get_severity_order(Some("medium"))
        );
        assert!(get_severity_order(Some("moderate")) < get_severity_order(Some("low")));
        // Case-insensitive like every other tier.
        assert_eq!(
            get_severity_order(Some("MODERATE")),
            get_severity_order(Some("medium"))
        );
    }

    #[test]
    fn test_convert_search_result_to_batch_info() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1234-5678-9abc".to_string(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-0001".into()],
                summary: "Test vulnerability".into(),
                severity: "high".into(),
                description: "A test vuln".into(),
            },
        );

        let patch = PatchSearchResult {
            uuid: "uuid-1".into(),
            purl: "pkg:npm/test@1.0.0".into(),
            published_at: "2024-01-01".into(),
            description: "A patch".into(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: vulns,
        };

        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.uuid, "uuid-1");
        assert_eq!(info.cve_ids, vec!["CVE-2024-0001"]);
        assert_eq!(info.ghsa_ids, vec!["GHSA-1234-5678-9abc"]);
        assert_eq!(info.severity, Some("high".into()));
        assert_eq!(info.title, "Test vulnerability");
    }

    #[tokio::test]
    async fn test_get_api_client_from_env_no_token() {
        // Clear token to ensure public proxy mode
        std::env::remove_var("SOCKET_API_TOKEN");
        let (client, is_public) = get_api_client_from_env(None).await;
        assert!(is_public);
        assert!(client.use_public_proxy);
    }

    #[tokio::test]
    async fn empty_org_slug_override_does_not_become_empty_slug() {
        // Regression: an empty org slug (override or `SOCKET_ORG_SLUG=""`)
        // must be treated as "not provided" and trigger auto-resolution —
        // not be taken verbatim as an explicit slug, which would build broken
        // `/v0/orgs//patches/...` URLs. Auto-resolution here targets an
        // unreachable URL, so it fails and leaves the slug `None` (never
        // `Some("")`). The buggy code skipped resolution and yielded `Some("")`.
        std::env::remove_var("SOCKET_ORG_SLUG");
        std::env::remove_var("SOCKET_API_URL");
        let (client, is_public) = get_api_client_with_overrides(ApiClientEnvOverrides {
            api_url: Some("http://127.0.0.1:1".to_string()),
            api_token: Some("sktsec_token_placeholder_value".to_string()),
            org_slug: Some(String::new()),
            proxy_url: None,
        })
        .await;
        assert!(!is_public, "a token was provided, so not public-proxy mode");
        assert_ne!(
            client.org_slug().map(String::as_str),
            Some(""),
            "empty slug must never propagate as an explicit org segment"
        );
        assert!(
            client.org_slug().is_none(),
            "failed auto-resolution should leave the slug unset, got {:?}",
            client.org_slug()
        );
    }

    // ── Group 6: convert_search_result_to_batch_info edge cases ──────

    fn make_vuln(summary: &str, severity: &str, cves: Vec<&str>) -> VulnerabilityResponse {
        VulnerabilityResponse {
            cves: cves.into_iter().map(String::from).collect(),
            summary: summary.into(),
            severity: severity.into(),
            description: "desc".into(),
        }
    }

    fn make_patch(
        vulns: HashMap<String, VulnerabilityResponse>,
        description: &str,
    ) -> PatchSearchResult {
        PatchSearchResult {
            uuid: "uuid-1".into(),
            purl: "pkg:npm/test@1.0.0".into(),
            published_at: "2024-01-01".into(),
            description: description.into(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: vulns,
        }
    }

    #[test]
    fn test_convert_no_vulnerabilities() {
        let patch = make_patch(HashMap::new(), "A patch description");
        let info = convert_search_result_to_batch_info(patch);
        assert!(info.cve_ids.is_empty());
        assert!(info.ghsa_ids.is_empty());
        assert_eq!(info.title, "A patch description");
        assert!(info.severity.is_none());
    }

    #[test]
    fn test_convert_multiple_vulns_picks_highest_severity() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("Medium vuln", "medium", vec!["CVE-2024-0001"]),
        );
        vulns.insert(
            "GHSA-2222".into(),
            make_vuln("Critical vuln", "critical", vec!["CVE-2024-0002"]),
        );
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.severity, Some("critical".into()));
    }

    #[test]
    fn test_convert_all_moderate_vulns_report_moderate_severity() {
        // Regression: a patch whose vulns are all GHSA-`moderate` reported
        // `severity: None` — the moderate-blind order gave it rank 4, equal
        // to the `None` starting point, so the highest-severity tracker
        // never fired. Tokenless `scan` (public-proxy batch fallback) then
        // showed these patches with no severity at all.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("Moderate vuln", "MODERATE", vec!["CVE-2024-0001"]),
        );
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(
            info.severity,
            Some("MODERATE".into()),
            "all-moderate patch must report moderate, not None"
        );
    }

    #[test]
    fn test_convert_moderate_outranks_low() {
        // Regression: `moderate` (GHSA medium tier) used to rank below
        // `low`, so a moderate+low patch reported `low` as its highest
        // severity.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("Low vuln", "low", vec!["CVE-2024-0001"]),
        );
        vulns.insert(
            "GHSA-2222".into(),
            make_vuln("Moderate vuln", "moderate", vec!["CVE-2024-0002"]),
        );
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.severity, Some("moderate".into()));
    }

    #[test]
    fn test_convert_duplicate_cves_deduplicated() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("Vuln A", "high", vec!["CVE-2024-0001"]),
        );
        vulns.insert(
            "GHSA-2222".into(),
            make_vuln("Vuln B", "high", vec!["CVE-2024-0001"]),
        );
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        // Same CVE in both vulns should only appear once
        let cve_count = info
            .cve_ids
            .iter()
            .filter(|c| *c == "CVE-2024-0001")
            .count();
        assert_eq!(cve_count, 1);
    }

    #[test]
    fn test_convert_title_truncated_at_100() {
        let long_summary = "x".repeat(150);
        let mut vulns = HashMap::new();
        vulns.insert("GHSA-1111".into(), make_vuln(&long_summary, "high", vec![]));
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        // Should be 97 chars + "..." = 100 chars
        assert_eq!(info.title.len(), 100);
        assert!(info.title.ends_with("..."));
    }

    #[test]
    fn test_convert_title_unicode_truncation() {
        // Create a summary with multi-byte chars that would panic with byte slicing
        // Each emoji is 4 bytes, so 30 emojis = 120 bytes but only 30 chars
        let emoji_summary = "\u{1F600}".repeat(30);
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln(&emoji_summary, "high", vec![]),
        );
        let patch = make_patch(vulns, "desc");
        // This should NOT panic (validates the UTF-8 truncation fix)
        let info = convert_search_result_to_batch_info(patch);
        assert!(!info.title.is_empty());

        // Also test with description fallback
        let patch2 = make_patch(HashMap::new(), &"\u{1F600}".repeat(120));
        let info2 = convert_search_result_to_batch_info(patch2);
        assert!(info2.title.ends_with("..."));
    }

    #[test]
    fn test_convert_title_falls_back_to_description() {
        let mut vulns = HashMap::new();
        vulns.insert("GHSA-1111".into(), make_vuln("", "high", vec![]));
        let patch = make_patch(vulns, "Fallback desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.title, "Fallback desc");
    }

    #[test]
    fn test_convert_empty_summary_and_description() {
        let mut vulns = HashMap::new();
        vulns.insert("GHSA-1111".into(), make_vuln("", "high", vec![]));
        let patch = make_patch(vulns, "");
        let info = convert_search_result_to_batch_info(patch);
        assert!(info.title.is_empty());
    }

    #[test]
    fn test_convert_cves_and_ghsas_sorted() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-cccc".into(),
            make_vuln("V1", "high", vec!["CVE-2024-0003"]),
        );
        vulns.insert(
            "GHSA-aaaa".into(),
            make_vuln("V2", "high", vec!["CVE-2024-0001"]),
        );
        vulns.insert(
            "GHSA-bbbb".into(),
            make_vuln("V3", "high", vec!["CVE-2024-0002"]),
        );
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        // Both should be sorted alphabetically
        let mut sorted_cves = info.cve_ids.clone();
        sorted_cves.sort();
        assert_eq!(info.cve_ids, sorted_cves);
        let mut sorted_ghsas = info.ghsa_ids.clone();
        sorted_ghsas.sort();
        assert_eq!(info.ghsa_ids, sorted_ghsas);
    }

    // ── Group 7: urlencoding + SHA256 edge cases ─────────────────────

    #[test]
    fn test_urlencoding_unicode() {
        // Multi-byte UTF-8: 'é' = 0xC3 0xA9
        let encoded = urlencoding_encode("café");
        assert_eq!(encoded, "caf%C3%A9");
    }

    #[test]
    fn test_urlencoding_empty() {
        assert_eq!(urlencoding_encode(""), "");
    }

    #[test]
    fn test_urlencoding_all_safe_chars() {
        // Unreserved chars should pass through
        let safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
        assert_eq!(urlencoding_encode(safe), safe);
    }

    #[test]
    fn test_urlencoding_slash_and_at() {
        assert_eq!(urlencoding_encode("/"), "%2F");
        assert_eq!(urlencoding_encode("@"), "%40");
    }

    #[test]
    fn test_sha256_uppercase_valid() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(is_valid_sha256_hex(upper));
    }

    #[test]
    fn test_sha256_65_chars_invalid() {
        let too_long = "a".repeat(65);
        assert!(!is_valid_sha256_hex(&too_long));
    }

    #[test]
    fn test_sha256_63_chars_invalid() {
        let too_short = "a".repeat(63);
        assert!(!is_valid_sha256_hex(&too_short));
    }

    #[test]
    fn test_sha256_empty_invalid() {
        assert!(!is_valid_sha256_hex(""));
    }

    #[test]
    fn test_sha256_mixed_case_valid() {
        let mixed = "aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF01234567";
        assert_eq!(mixed.len(), 64);
        assert!(is_valid_sha256_hex(mixed));
    }

    // ── UUID validation tests ───────────────────────────────────────

    #[test]
    fn test_is_valid_uuid_accepts_standard_form() {
        assert!(is_valid_uuid("80630680-4da6-45f9-bba8-b888e0ffd58c"));
        assert!(is_valid_uuid("00000000-0000-0000-0000-000000000000"));
        // Uppercase hex is acceptable.
        assert!(is_valid_uuid("ABCDEF01-2345-6789-ABCD-EF0123456789"));
    }

    #[test]
    fn test_is_valid_uuid_rejects_malformed() {
        assert!(!is_valid_uuid(""));
        assert!(!is_valid_uuid("not-a-uuid"));
        // Wrong segment count.
        assert!(!is_valid_uuid("80630680-4da6-45f9-bba8"));
        // Wrong length on first segment.
        assert!(!is_valid_uuid("8063068-4da6-45f9-bba8-b888e0ffd58c"));
        // Non-hex character.
        assert!(!is_valid_uuid("80630680-4da6-45f9-bba8-b888e0ffd58z"));
        // No dashes.
        assert!(!is_valid_uuid("80630680xxxxx"));
    }

    // ── fetch_diff / fetch_package validation tests ─────────────────
    //
    // These tests cover input validation only — they intentionally do
    // NOT hit the network. The shared `fetch_binary` helper handles the
    // transport, and `fetch_blob` already has integration coverage via
    // the e2e_npm test.

    #[tokio::test]
    async fn test_fetch_diff_rejects_invalid_uuid() {
        std::env::remove_var("SOCKET_API_TOKEN");
        let (client, _) = get_api_client_from_env(None).await;
        let result = client.fetch_diff("not-a-uuid").await;
        assert!(matches!(result, Err(ApiError::InvalidHash(_))));
    }

    #[tokio::test]
    async fn test_fetch_package_rejects_invalid_uuid() {
        std::env::remove_var("SOCKET_API_TOKEN");
        let (client, _) = get_api_client_from_env(None).await;
        let result = client.fetch_package("xxx").await;
        assert!(matches!(result, Err(ApiError::InvalidHash(_))));
    }

    // ── Token shape validation ─────────────────────────────────────────

    #[test]
    fn validate_token_shape_accepts_canonical_api_token() {
        // 7-char prefix + 44 random chars + 4-char `_api` suffix = 55 chars,
        // matching the server's SOCKET_TOKEN_REGEXP.
        let raw = format!("sktsec_{}_api", "x".repeat(44));
        assert_eq!(raw.len(), 55);
        assert!(validate_token_shape(&raw).is_none());
    }

    #[test]
    fn validate_token_shape_accepts_agent_token() {
        let raw = format!("sktsec_{}_agent", "x".repeat(44));
        assert!(validate_token_shape(&raw).is_none());
    }

    #[test]
    fn validate_token_shape_flags_sha512_hash() {
        let hash = "sha512-7aegAloeNsCqF1mpNL2J9MJ2dpIxQEwgKvXPml8XY2rrV2Za+\
                    bfj0yhG7RcqvqqLZ4iAH/drJjHjOqFkTGhddg==";
        let msg = validate_token_shape(hash).expect("hash must be flagged");
        assert!(
            msg.contains("does not look like a Socket API token"),
            "missing core warning; got: {msg}"
        );
        assert!(
            msg.contains("SRI-format hash"),
            "missing sha-hash hint; got: {msg}"
        );
        assert!(
            msg.contains("sktsec_"),
            "warning must point users at the correct prefix; got: {msg}"
        );
        // Token preview must not leak the whole value.
        assert!(
            !msg.contains("7RcqvqqLZ4iAH"),
            "middle of the value must be redacted; got: {msg}"
        );
    }

    #[test]
    fn validate_token_shape_flags_too_short() {
        let msg = validate_token_shape("sktsec_abc_api").expect("short token must be flagged");
        assert!(msg.contains("does not look like a Socket API token"));
        assert!(!msg.contains("SRI-format hash"));
    }

    #[test]
    fn validate_token_shape_flags_missing_suffix() {
        let raw = format!("sktsec_{}", "x".repeat(50));
        assert!(validate_token_shape(&raw).is_some());
    }

    #[test]
    fn validate_token_shape_redacts_by_chars_not_bytes() {
        // Regression: the preview tail and the "(N chars)" count must be
        // measured in *characters*, not bytes. A multi-byte token used to be
        // sized with `token.len()` (bytes), which over-reported the length
        // and mis-sliced the "last 4 chars" tail.
        //
        // 1 multi-byte char ('é', 2 bytes) + 16 ASCII + "WXYZ" = 21 chars /
        // 22 bytes. Correct redaction keeps the last 4 chars ("WXYZ") and
        // reports 21 chars; the byte-based bug yielded "XYZ" and "22 chars".
        let token = format!("é{}WXYZ", "0123456789012345");
        assert_eq!(token.chars().count(), 21);
        assert_ne!(token.len(), token.chars().count(), "must be multi-byte");

        let msg = validate_token_shape(&token).expect("non-canonical token must be flagged");
        assert!(
            msg.contains("(21 chars)"),
            "length must be reported in characters; got: {msg}"
        );
        assert!(
            msg.contains("...WXYZ"),
            "redaction tail must be the last 4 *characters*; got: {msg}"
        );
        assert!(
            !msg.contains("(22 chars)"),
            "byte count must not leak into the char-labeled message; got: {msg}"
        );
    }

    // ── classify_auth_error: shared 401/403/429 classification ──────────
    //
    // Regression: `fetch_binary` used to fold *every* non-OK/404 status into
    // `ApiError::Other`, so an authenticated blob/diff/package fetch that
    // 401'd/403'd was never recognized by `is_fallback_candidate` and the
    // auth→proxy fallback silently never fired. Both transport paths now route
    // through this shared classifier; these pin its contract directly.

    #[test]
    fn classify_auth_error_maps_401_to_unauthorized() {
        let err = classify_auth_error(StatusCode::UNAUTHORIZED, false).expect("401 must classify");
        assert!(matches!(err, ApiError::Unauthorized(_)));
        assert!(
            is_fallback_candidate(&err),
            "401 must drive the proxy fallback"
        );
    }

    #[test]
    fn classify_auth_error_maps_403_to_forbidden_with_proxy_wording() {
        // Proxy path (use_public_proxy = true) → paid-subscriber hint.
        let proxy = classify_auth_error(StatusCode::FORBIDDEN, true).expect("403 classifies");
        assert!(matches!(proxy, ApiError::Forbidden(_)));
        assert!(
            is_fallback_candidate(&proxy),
            "403 must drive the proxy fallback"
        );
        assert!(
            proxy.to_string().contains("paid subscribers"),
            "proxy 403 must carry the paid-subscriber hint; got: {proxy}"
        );

        // Authenticated path (use_public_proxy = false) → org-access wording.
        let auth = classify_auth_error(StatusCode::FORBIDDEN, false).expect("403 classifies");
        assert!(
            auth.to_string().contains("organization"),
            "authenticated 403 must carry the org-access wording; got: {auth}"
        );
    }

    #[test]
    fn classify_auth_error_maps_429_to_rate_limited() {
        let err =
            classify_auth_error(StatusCode::TOO_MANY_REQUESTS, false).expect("429 must classify");
        assert!(matches!(err, ApiError::RateLimited(_)));
        // Rate limits are intentionally *not* a fallback candidate — they
        // surface as-is so the operator sees them.
        assert!(!is_fallback_candidate(&err));
    }

    #[test]
    fn classify_auth_error_returns_none_for_other_statuses() {
        // OK / 404 / 5xx are handled by the caller, not this classifier.
        assert!(classify_auth_error(StatusCode::OK, false).is_none());
        assert!(classify_auth_error(StatusCode::NOT_FOUND, false).is_none());
        assert!(classify_auth_error(StatusCode::INTERNAL_SERVER_ERROR, false).is_none());
        assert!(classify_auth_error(StatusCode::BAD_GATEWAY, true).is_none());
    }

    // ── is_batch_unsupported: legacy-proxy detection for POST /patch/batch ──
    //
    // The proxy-mode batch POST degrades to per-package GETs only when the
    // deployed proxy predates the endpoint. These pin the exact decision
    // table — the 400/503 body markers are a cross-repo contract with the
    // depscan firewall-api-proxy (see `is_batch_unsupported` docs).

    #[test]
    fn is_batch_unsupported_falls_back_on_legacy_catch_all_400() {
        assert!(is_batch_unsupported(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Unsupported endpoint","message":"Endpoint POST /patch/batch is not supported."}"#,
        ));
    }

    #[test]
    fn is_batch_unsupported_does_not_match_validation_400() {
        // Validation 400s are not "endpoint missing" — the caller still
        // degrades them to the per-package path (all-or-nothing batch
        // validation must not fail a whole scan over one exotic PURL),
        // but via the chunk-validation branch with its own log line.
        assert!(!is_batch_unsupported(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Invalid PURL format"}"#,
        ));
        assert!(!is_batch_unsupported(StatusCode::BAD_REQUEST, ""));
    }

    #[test]
    fn is_batch_unsupported_falls_back_on_patch_api_disabled_503() {
        assert!(is_batch_unsupported(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"Service Unavailable","message":"Patch API is not configured on this server"}"#,
        ));
        // Over-capacity 503s surface instead of amplifying load via the
        // 10-concurrent per-package fallback.
        assert!(!is_batch_unsupported(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service temporarily over capacity",
        ));
    }

    #[test]
    fn is_batch_unsupported_falls_back_on_missing_route_statuses() {
        assert!(is_batch_unsupported(StatusCode::NOT_FOUND, ""));
        assert!(is_batch_unsupported(StatusCode::METHOD_NOT_ALLOWED, ""));
    }

    #[test]
    fn is_batch_unsupported_never_matches_other_statuses() {
        for status in [
            StatusCode::OK,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
        ] {
            assert!(
                !is_batch_unsupported(status, "Unsupported endpoint"),
                "{status} must never trigger the legacy fallback"
            );
        }
    }

    #[test]
    fn batch_search_body_serializes_to_components_shape() {
        // Wire-contract pin: both the authenticated batch endpoint and the
        // proxy's POST /patch/batch expect the CycloneDX-style shape.
        let body = BatchSearchBody {
            components: vec![BatchComponent {
                purl: "pkg:npm/a@1".into(),
            }],
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"components":[{"purl":"pkg:npm/a@1"}]}"#
        );
    }

    #[test]
    fn looks_like_token_hash_recognizes_sri_prefixes() {
        assert!(looks_like_token_hash("sha256-abc"));
        assert!(looks_like_token_hash("sha384-abc"));
        assert!(looks_like_token_hash("sha512-abc"));
        assert!(!looks_like_token_hash("sktsec_xxx_api"));
        assert!(!looks_like_token_hash("hello"));
        assert!(!looks_like_token_hash(""));
    }

    // ── binary_url: proxy override must reach blob/diff/package fetches ──
    //
    // Regression: `fetch_binary` used to re-derive the proxy base from
    // `SOCKET_PROXY_URL`/default instead of the client's configured
    // `api_url`, so a `--proxy-url` override (which sets `api_url` but no env
    // var) was honored for searches yet silently ignored for downloads.

    fn proxy_client(api_url: &str) -> ApiClient {
        ApiClient::new(ApiClientOptions {
            api_url: api_url.into(),
            api_token: None,
            use_public_proxy: true,
            org_slug: None,
        })
    }

    #[test]
    fn binary_url_proxy_uses_configured_api_url() {
        let client = proxy_client("https://custom.proxy.example");
        let (url, use_auth) = client.binary_url("blob", "deadbeef");
        assert!(!use_auth);
        assert_eq!(url, "https://custom.proxy.example/patch/blob/deadbeef");
    }

    #[test]
    fn binary_url_proxy_covers_diff_and_package() {
        let client = proxy_client("https://custom.proxy.example");
        assert_eq!(
            client.binary_url("diff", "uuid-1").0,
            "https://custom.proxy.example/patch/diff/uuid-1"
        );
        assert_eq!(
            client.binary_url("package", "uuid-1").0,
            "https://custom.proxy.example/patch/package/uuid-1"
        );
    }

    #[test]
    fn binary_url_proxy_trims_trailing_slash() {
        // `new()` trims the trailing slash on api_url; binary_url also trims
        // defensively so the path never ends up with a doubled separator.
        let client = proxy_client("https://custom.proxy.example/");
        assert_eq!(
            client.binary_url("blob", "x").0,
            "https://custom.proxy.example/patch/blob/x"
        );
    }

    #[test]
    fn binary_url_authenticated_uses_org_path() {
        let client = ApiClient::new(ApiClientOptions {
            api_url: "https://api.socket.dev".into(),
            api_token: Some("sktsec_x_api".into()),
            use_public_proxy: false,
            org_slug: Some("my-org".into()),
        });
        let (url, use_auth) = client.binary_url("diff", "uuid-123");
        assert!(use_auth);
        assert_eq!(
            url,
            "https://api.socket.dev/v0/orgs/my-org/patches/diff/uuid-123"
        );
    }

    // ── select_org_slug: deterministic org selection ────────────────────

    fn org(slug: &str) -> crate::api::types::OrganizationInfo {
        crate::api::types::OrganizationInfo {
            id: format!("id-{slug}"),
            name: Some(slug.to_string()),
            image: None,
            plan: "free".into(),
            slug: slug.into(),
        }
    }

    #[test]
    fn select_org_slug_errors_when_empty() {
        assert!(matches!(select_org_slug(vec![]), Err(ApiError::Other(_))));
    }

    #[test]
    fn select_org_slug_returns_sole_org() {
        assert_eq!(select_org_slug(vec![org("acme")]).unwrap(), "acme");
    }

    #[test]
    fn select_org_slug_is_deterministic_for_multiple() {
        // Regardless of the (HashMap-derived) input order, the
        // lexicographically-first slug is chosen so repeated runs agree.
        let a = select_org_slug(vec![org("zeta"), org("alpha"), org("mid")]).unwrap();
        let b = select_org_slug(vec![org("mid"), org("zeta"), org("alpha")]).unwrap();
        assert_eq!(a, "alpha");
        assert_eq!(b, "alpha");
    }

    // ── assemble_batch_from_individual: proxy-fallback aggregation ──────

    fn search_response(
        purl: &str,
        can_access_paid_patches: bool,
        patch_uuids: &[&str],
    ) -> SearchResponse {
        SearchResponse {
            patches: patch_uuids
                .iter()
                .map(|uuid| PatchSearchResult {
                    uuid: (*uuid).into(),
                    purl: purl.into(),
                    published_at: "2024-01-01".into(),
                    description: "desc".into(),
                    license: "MIT".into(),
                    tier: "free".into(),
                    vulnerabilities: HashMap::new(),
                })
                .collect(),
            can_access_paid_patches,
        }
    }

    #[test]
    fn assemble_batch_collects_patches_per_purl() {
        let results = vec![
            (
                "pkg:npm/a@1".to_string(),
                Some(search_response("pkg:npm/a@1", false, &["uuid-a"])),
            ),
            (
                "pkg:npm/b@1".to_string(),
                Some(search_response(
                    "pkg:npm/b@1",
                    false,
                    &["uuid-b1", "uuid-b2"],
                )),
            ),
        ];
        let batch = assemble_batch_from_individual(results);
        assert_eq!(batch.packages.len(), 2);
        assert!(!batch.can_access_paid_patches);
        let a = batch
            .packages
            .iter()
            .find(|p| p.purl == "pkg:npm/a@1")
            .unwrap();
        assert_eq!(a.patches.len(), 1);
        let b = batch
            .packages
            .iter()
            .find(|p| p.purl == "pkg:npm/b@1")
            .unwrap();
        assert_eq!(b.patches.len(), 2);
    }

    #[test]
    fn assemble_batch_skips_errored_and_empty_responses() {
        // None = query errored; an empty patch list contributes no package.
        let results = vec![
            ("pkg:npm/err@1".to_string(), None),
            (
                "pkg:npm/empty@1".to_string(),
                Some(search_response("pkg:npm/empty@1", false, &[])),
            ),
            (
                "pkg:npm/ok@1".to_string(),
                Some(search_response("pkg:npm/ok@1", false, &["uuid-ok"])),
            ),
        ];
        let batch = assemble_batch_from_individual(results);
        // Only the package with at least one patch is listed.
        assert_eq!(batch.packages.len(), 1);
        assert_eq!(batch.packages[0].purl, "pkg:npm/ok@1");
    }

    #[test]
    fn assemble_batch_aggregates_paid_flag_across_all_responses() {
        // OR-aggregation: any response with the flag set flips the aggregate.
        let results = vec![
            (
                "pkg:npm/a@1".to_string(),
                Some(search_response("pkg:npm/a@1", false, &["uuid-a"])),
            ),
            (
                "pkg:npm/b@1".to_string(),
                Some(search_response("pkg:npm/b@1", true, &["uuid-b"])),
            ),
        ];
        let batch = assemble_batch_from_individual(results);
        assert!(batch.can_access_paid_patches);
    }

    #[test]
    fn assemble_batch_keeps_paid_flag_from_empty_patch_response() {
        // Regression: the capability flag must survive even when the response
        // that carries it has *no* patches. The empty-patch response must not
        // be listed as a package, but its `canAccessPaidPatches: true` must
        // still flip the aggregate flag — a fused skip would have dropped it.
        let results = vec![
            (
                "pkg:npm/free@1".to_string(),
                Some(search_response("pkg:npm/free@1", false, &["uuid-free"])),
            ),
            (
                "pkg:npm/paid-only@1".to_string(),
                Some(search_response("pkg:npm/paid-only@1", true, &[])),
            ),
        ];
        let batch = assemble_batch_from_individual(results);
        assert!(
            batch.can_access_paid_patches,
            "paid-access flag from an empty-patch response was dropped"
        );
        // The empty-patch package must not appear in the listing.
        assert_eq!(batch.packages.len(), 1);
        assert_eq!(batch.packages[0].purl, "pkg:npm/free@1");
    }

    // ── convert: title selection is deterministic ───────────────────────

    #[test]
    fn test_convert_title_deterministic_across_iteration_order() {
        // Two vulns, each with a non-empty summary. The title must always be
        // drawn from the lexicographically-first GHSA id so the value is
        // stable across runs (HashMap iteration order is not).
        let mut vulns = HashMap::new();
        vulns.insert("GHSA-zzzz".into(), make_vuln("Z summary", "high", vec![]));
        vulns.insert("GHSA-aaaa".into(), make_vuln("A summary", "high", vec![]));
        let patch = make_patch(vulns, "desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.title, "A summary");
    }
}

#[cfg(test)]
mod vendor_package_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    const UUID: &str = "11111111-1111-1111-1111-111111111111";
    const SERVE_PATH: &str = "/patch/npm/lodash/4.17.21/tok/uuid/lodash-4.17.21.tgz";
    const TARBALL: &[u8] = b"prebuilt deterministic tarball bytes";

    /// Matches a request that carries NO `Authorization` header — proves the
    /// proxy POST and the grant-tokenized serve GET never leak the bearer.
    struct NoAuthorizationHeader;
    impl Match for NoAuthorizationHeader {
        fn matches(&self, request: &Request) -> bool {
            !request.headers.contains_key("authorization")
        }
    }

    fn auth_client(uri: String) -> ApiClient {
        ApiClient::new(ApiClientOptions {
            api_url: uri,
            api_token: Some("sktsec_token_placeholder_value_api".into()),
            use_public_proxy: false,
            org_slug: Some("acme".into()),
        })
    }

    fn proxy_client(uri: String) -> ApiClient {
        ApiClient::new(ApiClientOptions {
            api_url: uri,
            api_token: None,
            use_public_proxy: true,
            org_slug: None,
        })
    }

    /// A `granted` body whose tarball artifact points at `serve_url`.
    fn granted_body(serve_url: &str, sha512: &str) -> serde_json::Value {
        json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "purl": "pkg:npm/lodash@4.17.21",
                    "artifacts": [{
                        "kind": "tarball",
                        "url": serve_url,
                        "contentType": "application/gzip",
                        "sizeBytes": TARBALL.len(),
                        "integrity": { "sha512": sha512, "sha1": "deadbeef" }
                    }]
                }
            }
        })
    }

    async fn mount_status(server: &MockServer, status: &str) {
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn granted_authenticated_downloads_and_returns_bytes() {
        let server = MockServer::start().await;
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .and(body_partial_json(json!({ "uuids": [UUID] })))
            .respond_with(ResponseTemplate::new(200).set_body_json(granted_body(&serve_url, "sha512-ABC123==")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .and(NoAuthorizationHeader)
            .respond_with(ResponseTemplate::new(200).set_body_bytes(TARBALL.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        match outcome {
            VendorServiceOutcome::Ready(pkg) => {
                assert_eq!(pkg.tarball, TARBALL);
                assert_eq!(pkg.integrity_sri, "sha512-ABC123==");
                assert_eq!(pkg.sha1_hex.as_deref(), Some("deadbeef"));
                assert_eq!(pkg.source_url, serve_url);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn proxy_path_posts_to_patch_route_without_auth_and_forces_free_only() {
        let server = MockServer::start().await;
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/patch/package"))
            .and(NoAuthorizationHeader)
            .and(body_partial_json(json!({ "uuids": [UUID], "freeOnly": true })))
            .respond_with(ResponseTemplate::new(200).set_body_json(granted_body(&serve_url, "sha512-ZZ==")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(TARBALL.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        // free_only=true (public-proxy contract).
        let outcome = proxy_client(server.uri())
            .fetch_vendor_package(UUID, true, None, None)
            .await;
        assert!(matches!(outcome, VendorServiceOutcome::Ready(_)));
    }

    #[tokio::test]
    async fn bare_sha512_is_normalized_to_sri() {
        let server = MockServer::start().await;
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(granted_body(&serve_url, "BAREB64==")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(TARBALL.to_vec()))
            .mount(&server)
            .await;

        match auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await
        {
            VendorServiceOutcome::Ready(pkg) => assert_eq!(pkg.integrity_sri, "sha512-BAREB64=="),
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn patch_server_url_rewrites_the_download_host() {
        let server = MockServer::start().await;
        // The server bakes an UNREACHABLE host into the URL; --patch-server-url
        // redirects the GET at the mock while preserving the path.
        let baked = format!("https://patch.socket.dev{SERVE_PATH}");
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(granted_body(&baked, "sha512-AA==")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(TARBALL.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, Some(&server.uri()))
            .await;
        match outcome {
            VendorServiceOutcome::Ready(pkg) => {
                assert!(pkg.source_url.starts_with(&server.uri()), "host rewritten");
                assert!(pkg.source_url.ends_with(SERVE_PATH), "path preserved");
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pending_build_status_skips_download_and_is_pending() {
        let server = MockServer::start().await;
        mount_status(&server, "pending_build").await;
        // No GET mock mounted: a download attempt would 404 the server's
        // catch-all (no mock) — but more importantly we never get there.
        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        assert!(matches!(outcome, VendorServiceOutcome::Pending));
    }

    #[tokio::test]
    async fn serve_408_is_pending() {
        let server = MockServer::start().await;
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(granted_body(&serve_url, "sha512-AA==")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(408))
            .mount(&server)
            .await;
        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        assert!(matches!(outcome, VendorServiceOutcome::Pending));
    }

    #[tokio::test]
    async fn terminal_statuses_are_unavailable() {
        for status in ["build_failed", "withdrawn", "not_found"] {
            let server = MockServer::start().await;
            mount_status(&server, status).await;
            let outcome = auth_client(server.uri())
                .fetch_vendor_package(UUID, false, None, None)
                .await;
            assert!(
                matches!(outcome, VendorServiceOutcome::Unavailable(_)),
                "status {status} must be Unavailable",
            );
        }
    }

    #[tokio::test]
    async fn forbidden_status_is_failed() {
        let server = MockServer::start().await;
        mount_status(&server, "forbidden").await;
        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        assert!(matches!(
            outcome,
            VendorServiceOutcome::Failed(ApiError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn serve_404_and_403_and_5xx_map_correctly() {
        // 404 → Unavailable
        for (code, expect_failed) in [(404u16, false), (410, false), (403, true), (503, true)] {
            let server = MockServer::start().await;
            let serve_url = format!("{}{SERVE_PATH}", server.uri());
            Mock::given(method("POST"))
                .and(path("/v0/orgs/acme/patches/package"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(granted_body(&serve_url, "sha512-AA==")),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(SERVE_PATH))
                .respond_with(ResponseTemplate::new(code))
                .mount(&server)
                .await;
            let outcome = auth_client(server.uri())
                .fetch_vendor_package(UUID, false, None, None)
                .await;
            if expect_failed {
                assert!(
                    matches!(outcome, VendorServiceOutcome::Failed(_)),
                    "serve {code} must be Failed",
                );
            } else {
                assert!(
                    matches!(outcome, VendorServiceOutcome::Unavailable(_)),
                    "serve {code} must be Unavailable",
                );
            }
        }
    }

    #[tokio::test]
    async fn no_tarball_artifact_is_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": null,
                    "artifacts": [{ "kind": "yarn-berry-zip", "url": "https://x/y.zip",
                                    "integrity": { "yarnBerry10c0": "10c0/abc" } }]
                }}
            })))
            .mount(&server)
            .await;
        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        assert!(matches!(outcome, VendorServiceOutcome::Unavailable(_)));
    }

    #[tokio::test]
    async fn tarball_without_sha512_is_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": "https://x/y.tgz",
                    "artifacts": [{ "kind": "tarball", "url": "https://x/y.tgz",
                                    "integrity": { "sha1": "deadbeef" } }]
                }}
            })))
            .mount(&server)
            .await;
        let outcome = auth_client(server.uri())
            .fetch_vendor_package(UUID, false, None, None)
            .await;
        assert!(matches!(outcome, VendorServiceOutcome::Unavailable(_)));
    }

    #[tokio::test]
    async fn invalid_uuid_is_failed_without_network() {
        // No server: an early UUID-shape rejection must not make any request.
        let client = auth_client("http://127.0.0.1:1".into());
        let outcome = client
            .fetch_vendor_package("not-a-uuid", false, None, None)
            .await;
        assert!(matches!(
            outcome,
            VendorServiceOutcome::Failed(ApiError::InvalidHash(_))
        ));
    }
}
