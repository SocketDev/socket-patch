use std::collections::HashSet;

use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::Serialize;

use crate::api::types::*;
use crate::constants::{
    DEFAULT_PATCH_API_PROXY_URL, DEFAULT_SOCKET_API_URL, USER_AGENT as USER_AGENT_VALUE,
};

/// Check if debug mode is enabled via SOCKET_PATCH_DEBUG env.
fn is_debug_enabled() -> bool {
    match std::env::var("SOCKET_PATCH_DEBUG") {
        Ok(val) => val == "1" || val == "true",
        Err(_) => false,
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
        Some("medium") => 2,
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
        default_headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );

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

        match status {
            StatusCode::OK => {
                let body = resp
                    .json::<T>()
                    .await
                    .map_err(|e| ApiError::Parse(format!("Failed to parse response: {}", e)))?;
                Ok(Some(body))
            }
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::UNAUTHORIZED => {
                Err(ApiError::Unauthorized("Unauthorized: Invalid API token".into()))
            }
            StatusCode::FORBIDDEN => {
                let msg = if use_public_proxy {
                    "Forbidden: This patch is only available to paid subscribers. \
                     Sign up at https://socket.dev to access paid patches."
                } else {
                    "Forbidden: Access denied. This may be a paid patch or \
                     you may not have access to this organization."
                };
                Err(ApiError::Forbidden(msg.into()))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                Err(ApiError::RateLimited(
                    "Rate limit exceeded. Please try again later.".into(),
                ))
            }
            _ => {
                let text = resp.text().await.unwrap_or_default();
                Err(ApiError::Other(format!(
                    "API request failed with status {}: {}",
                    status.as_u16(),
                    text
                )))
            }
        }
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
            let slug = org_slug
                .or(self.org_slug.as_deref())
                .unwrap_or("default");
            format!("/v0/orgs/{}/patches/view/{}", slug, uuid)
        };
        self.get_json(&path).await
    }

    /// Search patches by CVE ID.
    pub async fn search_patches_by_cve(
        &self,
        org_slug: Option<&str>,
        cve_id: &str,
    ) -> Result<SearchResponse, ApiError> {
        let encoded = urlencoding_encode(cve_id);
        let path = if self.use_public_proxy {
            format!("/patch/by-cve/{}", encoded)
        } else {
            let slug = org_slug
                .or(self.org_slug.as_deref())
                .unwrap_or("default");
            format!("/v0/orgs/{}/patches/by-cve/{}", slug, encoded)
        };
        let result = self.get_json::<SearchResponse>(&path).await?;
        Ok(result.unwrap_or_else(|| SearchResponse {
            patches: Vec::new(),
            can_access_paid_patches: false,
        }))
    }

    /// Search patches by GHSA ID.
    pub async fn search_patches_by_ghsa(
        &self,
        org_slug: Option<&str>,
        ghsa_id: &str,
    ) -> Result<SearchResponse, ApiError> {
        let encoded = urlencoding_encode(ghsa_id);
        let path = if self.use_public_proxy {
            format!("/patch/by-ghsa/{}", encoded)
        } else {
            let slug = org_slug
                .or(self.org_slug.as_deref())
                .unwrap_or("default");
            format!("/v0/orgs/{}/patches/by-ghsa/{}", slug, encoded)
        };
        let result = self.get_json::<SearchResponse>(&path).await?;
        Ok(result.unwrap_or_else(|| SearchResponse {
            patches: Vec::new(),
            can_access_paid_patches: false,
        }))
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
        let encoded = urlencoding_encode(purl);
        let path = if self.use_public_proxy {
            format!("/patch/by-package/{}", encoded)
        } else {
            let slug = org_slug
                .or(self.org_slug.as_deref())
                .unwrap_or("default");
            format!("/v0/orgs/{}/patches/by-package/{}", slug, encoded)
        };
        let result = self.get_json::<SearchResponse>(&path).await?;
        Ok(result.unwrap_or_else(|| SearchResponse {
            patches: Vec::new(),
            can_access_paid_patches: false,
        }))
    }

    /// Search patches for multiple packages (batch).
    ///
    /// For authenticated API, uses the POST `/patches/batch` endpoint.
    /// For the public proxy (which cannot cache POST bodies on CDN), falls
    /// back to individual GET requests per PURL with a concurrency limit of
    /// 10.
    ///
    /// Maximum 500 PURLs per request.
    pub async fn search_patches_batch(
        &self,
        org_slug: Option<&str>,
        purls: &[String],
    ) -> Result<BatchSearchResponse, ApiError> {
        if !self.use_public_proxy {
            let slug = org_slug
                .or(self.org_slug.as_deref())
                .unwrap_or("default");
            let path = format!("/v0/orgs/{}/patches/batch", slug);
            let body = BatchSearchBody {
                components: purls
                    .iter()
                    .map(|p| BatchComponent { purl: p.clone() })
                    .collect(),
            };
            let result = self.post_json::<BatchSearchResponse, _>(&path, &body).await?;
            return Ok(result.unwrap_or_else(|| BatchSearchResponse {
                packages: Vec::new(),
                can_access_paid_patches: false,
            }));
        }

        // Public proxy: fall back to individual per-package GET requests
        self.search_patches_batch_via_individual_queries(purls).await
    }

    /// Internal: fall back to individual GET requests per PURL when the
    /// batch endpoint is not available (public proxy mode).
    ///
    /// Processes PURLs in batches of `CONCURRENCY_LIMIT` to avoid
    /// overwhelming the server while remaining efficient.
    async fn search_patches_batch_via_individual_queries(
        &self,
        purls: &[String],
    ) -> Result<BatchSearchResponse, ApiError> {
        const CONCURRENCY_LIMIT: usize = 10;

        let mut packages: Vec<BatchPackagePatches> = Vec::new();
        let mut can_access_paid_patches = false;

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

        // Convert individual SearchResponse results to BatchSearchResponse format
        for (purl, response) in all_results {
            let response = match response {
                Some(r) if !r.patches.is_empty() => r,
                _ => continue,
            };

            if response.can_access_paid_patches {
                can_access_paid_patches = true;
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

        Ok(BatchSearchResponse {
            packages,
            can_access_paid_patches,
        })
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

        let (url, use_auth) =
            if self.api_token.is_some() && self.org_slug.is_some() && !self.use_public_proxy {
                // Authenticated endpoint
                let slug = self.org_slug.as_deref().unwrap();
                let u = format!("{}/v0/orgs/{}/patches/blob/{}", self.api_url, slug, hash);
                (u, true)
            } else {
                // Public proxy
                let proxy_url = std::env::var("SOCKET_PATCH_PROXY_URL")
                    .unwrap_or_else(|_| DEFAULT_PATCH_API_PROXY_URL.to_string());
                let u = format!("{}/patch/blob/{}", proxy_url.trim_end_matches('/'), hash);
                (u, false)
            };

        debug_log(&format!("GET blob {}", url));

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
            ApiError::Network(format!("Network error fetching blob {}: {}", hash, e))
        })?;

        let status = resp.status();

        match status {
            StatusCode::OK => {
                let bytes = resp.bytes().await.map_err(|e| {
                    ApiError::Network(format!("Error reading blob body for {}: {}", hash, e))
                })?;
                Ok(Some(bytes.to_vec()))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let text = resp.text().await.unwrap_or_default();
                Err(ApiError::Other(format!(
                    "Failed to fetch blob {}: status {} - {}",
                    hash,
                    status.as_u16(),
                    text,
                )))
            }
        }
    }
}

// ── Free functions ────────────────────────────────────────────────────

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
/// | `SOCKET_PATCH_PROXY_URL` | Override the public proxy URL (default `https://patches-api.socket.dev`) |
/// | `SOCKET_ORG_SLUG` | Organization slug |
///
/// Returns `(client, use_public_proxy)`.
pub async fn get_api_client_from_env(org_slug: Option<&str>) -> (ApiClient, bool) {
    let api_token = std::env::var("SOCKET_API_TOKEN").ok();
    let resolved_org_slug = org_slug
        .map(String::from)
        .or_else(|| std::env::var("SOCKET_ORG_SLUG").ok());

    if api_token.is_none() {
        let proxy_url = std::env::var("SOCKET_PATCH_PROXY_URL")
            .unwrap_or_else(|_| DEFAULT_PATCH_API_PROXY_URL.to_string());
        eprintln!(
            "No SOCKET_API_TOKEN set. Using public patch API proxy (free patches only)."
        );
        let client = ApiClient::new(ApiClientOptions {
            api_url: proxy_url,
            api_token: None,
            use_public_proxy: true,
            org_slug: None,
        });
        return (client, true);
    }

    let api_url =
        std::env::var("SOCKET_API_URL").unwrap_or_else(|_| DEFAULT_SOCKET_API_URL.to_string());

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

/// Convert a `PatchSearchResult` into a `BatchPatchInfo`, extracting
/// CVE/GHSA IDs and computing the highest severity.
fn convert_search_result_to_batch_info(patch: PatchSearchResult) -> BatchPatchInfo {
    let mut cve_ids: Vec<String> = Vec::new();
    let mut ghsa_ids: Vec<String> = Vec::new();
    let mut highest_severity: Option<String> = None;
    let mut title = String::new();

    let mut seen_cves: HashSet<String> = HashSet::new();

    for (ghsa_id, vuln) in &patch.vulnerabilities {
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
        assert_eq!(get_severity_order(Some("unknown")), get_severity_order(None));
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
        let cve_count = info.cve_ids.iter().filter(|c| *c == "CVE-2024-0001").count();
        assert_eq!(cve_count, 1);
    }

    #[test]
    fn test_convert_title_truncated_at_100() {
        let long_summary = "x".repeat(150);
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln(&long_summary, "high", vec![]),
        );
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
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("", "high", vec![]),
        );
        let patch = make_patch(vulns, "Fallback desc");
        let info = convert_search_result_to_batch_info(patch);
        assert_eq!(info.title, "Fallback desc");
    }

    #[test]
    fn test_convert_empty_summary_and_description() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-1111".into(),
            make_vuln("", "high", vec![]),
        );
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
}
