//! GitHub-release metadata for self-update: resolving the latest version
//! and mapping our compiled target triple to a release asset.
//!
//! Latest-version resolution is a two-step ladder:
//!
//! 1. **Redirect probe** (primary): `GET {base}/SocketDev/socket-patch/
//!    releases/latest` with redirects disabled; GitHub answers 302 with a
//!    `Location` ending in `/releases/tag/v<X.Y.Z>`. Same host as the
//!    asset downloads (one proxy/allowlist story), no API rate limits,
//!    zero-byte body.
//! 2. **API fallback**: `GET {api}/repos/SocketDev/socket-patch/releases/
//!    latest` (`tag_name` from JSON). Unauthenticated (60 req/h/IP) — fine
//!    for a fallback that only fires when the redirect shape drifts.
//!
//! All fetch sizes are capped and every request carries an explicit
//! timeout: a hung self-update is strictly worse than a hung scan, so this
//! module does not inherit the API client's no-timeout posture.

use std::time::Duration;

use super::UpdateError;
use crate::utils::http::read_capped;

/// GitHub org/repo path segment for release URLs. One constant so the
/// redirect probe, API fallback, and download URLs can never disagree.
pub(crate) const RELEASE_REPO: &str = "SocketDev/socket-patch";

/// Default web base for release URLs (redirect probe + asset downloads).
pub const DEFAULT_UPDATE_BASE_URL: &str = "https://github.com";

/// Default API base for the JSON fallback.
const DEFAULT_UPDATE_API_BASE_URL: &str = "https://api.github.com";

/// Metadata (redirect probe / SHA256SUMS / API JSON) responses are tiny;
/// anything above this is a misbehaving or hostile server.
const METADATA_CAP_BYTES: u64 = 1024 * 1024;

/// Resolved base URLs for one update run.
///
/// `SOCKET_UPDATE_BASE_URL` (internal, test/mirror support — same posture
/// as `SOCKET_NPM_REGISTRY`) points BOTH the web-style and API-style routes
/// at one server, so a wiremock fixture can serve the whole flow. When it
/// is set, [`UpdateEndpoints::is_default`] turns false and the downloaded
/// binary's version self-check downgrades from hard-fail to warning (a
/// mirror may repackage; the override is already a total-trust knob).
#[derive(Debug, Clone)]
pub struct UpdateEndpoints {
    pub web_base: String,
    pub api_base: String,
    is_default: bool,
}

impl UpdateEndpoints {
    pub fn from_env() -> Self {
        match std::env::var("SOCKET_UPDATE_BASE_URL")
            .ok()
            .filter(|v| !v.is_empty())
        {
            Some(base) => {
                let base = base.trim_end_matches('/').to_string();
                UpdateEndpoints {
                    web_base: base.clone(),
                    api_base: base,
                    is_default: false,
                }
            }
            None => UpdateEndpoints {
                web_base: DEFAULT_UPDATE_BASE_URL.to_string(),
                api_base: DEFAULT_UPDATE_API_BASE_URL.to_string(),
                is_default: true,
            },
        }
    }

    /// True when talking to real GitHub (no `SOCKET_UPDATE_BASE_URL`).
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// `{web_base}/SocketDev/socket-patch/releases/download/v<ver>/<file>`
    pub fn download_url(&self, version: &semver::Version, file: &str) -> String {
        format!(
            "{}/{}/releases/download/v{version}/{file}",
            self.web_base, RELEASE_REPO
        )
    }

    fn latest_probe_url(&self) -> String {
        format!("{}/{}/releases/latest", self.web_base, RELEASE_REPO)
    }

    fn latest_api_url(&self) -> String {
        format!("{}/repos/{}/releases/latest", self.api_base, RELEASE_REPO)
    }
}

/// Timeouts for one update run. `from_env` honors the internal
/// `SOCKET_UPDATE_TIMEOUT_MS` override (tests need millisecond-scale
/// timeouts; slow links may need more than the defaults).
#[derive(Debug, Clone, Copy)]
pub struct UpdateTimeouts {
    pub connect: Duration,
    /// Whole-request budget for metadata fetches (probe, API JSON, SHA256SUMS).
    pub metadata: Duration,
    /// Whole-request budget for the archive download.
    pub download: Duration,
}

impl Default for UpdateTimeouts {
    fn default() -> Self {
        UpdateTimeouts {
            connect: Duration::from_secs(10),
            metadata: Duration::from_secs(30),
            download: Duration::from_secs(300),
        }
    }
}

impl UpdateTimeouts {
    pub fn from_env() -> Self {
        let default = UpdateTimeouts::default();
        match std::env::var("SOCKET_UPDATE_TIMEOUT_MS")
            .ok()
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<u64>().ok())
        {
            Some(ms) => {
                let budget = Duration::from_millis(ms);
                UpdateTimeouts {
                    connect: budget.min(default.connect),
                    metadata: budget,
                    download: budget,
                }
            }
            None => default,
        }
    }
}

/// True when `candidate` is strictly newer than `current` by semver
/// *precedence* (build metadata ignored). The `semver` crate's `Ord` is a
/// total order that tiebreaks on build metadata, which would make
/// `3.4.0+hotfix` look "newer" than an installed `3.4.0` — precedence
/// comparison is the update-decision semantic.
pub fn is_newer(candidate: &semver::Version, current: &semver::Version) -> bool {
    candidate.cmp_precedence(current) == std::cmp::Ordering::Greater
}

/// The version currently compiled into this binary.
pub fn current_version() -> semver::Version {
    // CARGO_PKG_VERSION is always valid semver — cargo enforces it.
    semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("CARGO_PKG_VERSION is valid semver by construction")
}

/// Map a compiled target triple to its release asset filename.
///
/// Release CI packages every non-Windows target as `socket-patch-
/// <triple>.tar.gz` and the three `*-pc-windows-msvc` targets as `.zip`
/// (see `.github/workflows/release.yml`). The triple arrives as a
/// parameter (the CLI passes its `build.rs`-embedded `SOCKET_PATCH_TARGET`)
/// so core stays testable across all fourteen triples from one host.
pub fn asset_name_for_target(target_triple: &str) -> String {
    if target_triple.ends_with("-pc-windows-msvc") {
        format!("socket-patch-{target_triple}.zip")
    } else {
        format!("socket-patch-{target_triple}.tar.gz")
    }
}

/// Parse a release tag (`v3.4.0` or `3.4.0`, surrounding whitespace
/// tolerated) into a semver version.
pub fn parse_release_tag(tag: &str) -> Result<semver::Version, UpdateError> {
    let trimmed = tag.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    semver::Version::parse(bare)
        .map_err(|e| UpdateError::CheckFailed(format!("unparseable release tag {trimmed:?}: {e}")))
}

/// Extract the version from a `releases/latest` redirect `Location` header
/// (`…/releases/tag/v<X.Y.Z>`).
pub(crate) fn version_from_location(location: &str) -> Result<semver::Version, UpdateError> {
    let tag = location
        .rsplit_once("/releases/tag/")
        .map(|(_, tag)| tag)
        .ok_or_else(|| {
            UpdateError::CheckFailed(format!(
                "release redirect Location {location:?} does not contain /releases/tag/"
            ))
        })?;
    // Strip any query/fragment noise a proxy might append.
    let tag = tag.split(['?', '#']).next().unwrap_or(tag);
    parse_release_tag(tag)
}

/// Look up `file`'s SHA-256 in a `SHA256SUMS` body (`<hex>  <name>` per
/// line, `*<name>` binary-mode marker tolerated, CRLF tolerated —
/// the same grammar install.sh consumes).
pub fn sha256sums_entry(sums: &str, file: &str) -> Result<String, UpdateError> {
    let mut found: Option<String> = None;
    for line in sums.lines() {
        let line = line.trim_end_matches('\r');
        let mut parts = line.split_whitespace();
        let (Some(hex_digest), Some(name)) = (parts.next(), parts.next()) else {
            continue; // blank or malformed line: skip, absence still errors below
        };
        let name = name.strip_prefix('*').unwrap_or(name);
        if name != file {
            continue;
        }
        if hex_digest.len() != 64 || !hex_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UpdateError::ChecksumMismatch {
                asset: file.to_string(),
                detail: format!("malformed SHA256SUMS digest {hex_digest:?}"),
            });
        }
        let digest = hex_digest.to_ascii_lowercase();
        // Two entries for the same file that disagree means the sums file
        // itself is unreliable — refuse rather than pick one.
        if let Some(prev) = &found {
            if *prev != digest {
                return Err(UpdateError::ChecksumMismatch {
                    asset: file.to_string(),
                    detail: "conflicting duplicate entries in SHA256SUMS".to_string(),
                });
            }
        }
        found = Some(digest);
    }
    found.ok_or_else(|| UpdateError::ChecksumMismatch {
        asset: file.to_string(),
        detail: "no entry in SHA256SUMS".to_string(),
    })
}

/// The redirect policy for every update-related request that follows
/// redirects: on the default (real GitHub) endpoints any non-HTTPS hop is
/// refused — GitHub bounces to CDNs, and one `http://` hop would let a
/// MITM tamper with whichever leg it captures (the SHA256SUMS leg is the
/// integrity root, so it needs this exactly as much as the archive leg).
/// Overridden bases (wiremock fixtures, mirrors) are plain-`http` loopback
/// by design, so there the policy is only hop-count-limited.
pub(crate) fn follow_redirect_policy(
    endpoints: &UpdateEndpoints,
) -> reqwest::redirect::Policy {
    if endpoints.is_default() {
        reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("refusing insecure (non-HTTPS) redirect for release metadata")
            } else {
                attempt.follow()
            }
        })
    } else {
        reqwest::redirect::Policy::limited(10)
    }
}

/// Build the reqwest client used for metadata fetches. Credential-free by
/// construction (mirrors `plain_client`: only a User-Agent — the Socket
/// bearer must never reach GitHub or a mirror).
fn metadata_client(
    timeouts: &UpdateTimeouts,
    redirects: reqwest::redirect::Policy,
) -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .user_agent(crate::constants::USER_AGENT)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.metadata)
        .redirect(redirects)
        .build()
        .map_err(|e| UpdateError::Network(format!("failed to build HTTP client: {e}")))
}

/// Resolve the latest released version: redirect probe first, API fallback
/// second (see module docs).
pub async fn fetch_latest_version(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
) -> Result<semver::Version, UpdateError> {
    let probe_err = match probe_latest_redirect(endpoints, timeouts).await {
        Ok(version) => return Ok(version),
        Err(e) => e,
    };
    match fetch_latest_via_api(endpoints, timeouts).await {
        Ok(version) => Ok(version),
        Err(api_err) => Err(UpdateError::CheckFailed(format!(
            "could not determine the latest release: {probe_err}; API fallback: {api_err}"
        ))),
    }
}

async fn probe_latest_redirect(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
) -> Result<semver::Version, UpdateError> {
    let client = metadata_client(timeouts, reqwest::redirect::Policy::none())?;
    let url = endpoints.latest_probe_url();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("GET {url}: {e}")))?;
    if !resp.status().is_redirection() {
        return Err(UpdateError::CheckFailed(format!(
            "GET {url} returned {} (expected a redirect to the latest tag)",
            resp.status()
        )));
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            UpdateError::CheckFailed(format!("GET {url}: redirect without a Location header"))
        })?;
    version_from_location(location)
}

async fn fetch_latest_via_api(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
) -> Result<semver::Version, UpdateError> {
    let client = metadata_client(timeouts, follow_redirect_policy(endpoints))?;
    let url = endpoints.latest_api_url();
    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(UpdateError::CheckFailed(format!(
            "GET {url} returned {status}"
        )));
    }
    let body = read_capped(resp, METADATA_CAP_BYTES, "release metadata")
        .await
        .map_err(UpdateError::Network)?;
    let json: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| UpdateError::CheckFailed(format!("GET {url}: invalid JSON: {e}")))?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            UpdateError::CheckFailed(format!("GET {url}: response has no tag_name"))
        })?;
    parse_release_tag(tag)
}

/// Fetch and parse the `SHA256SUMS` published with `version`, returning the
/// digest recorded for `file`.
pub async fn fetch_sha256sums_entry(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
    version: &semver::Version,
    file: &str,
) -> Result<String, UpdateError> {
    let client = metadata_client(timeouts, follow_redirect_policy(endpoints))?;
    let url = endpoints.download_url(version, "SHA256SUMS");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(UpdateError::CheckFailed(format!(
            "release v{version} publishes no SHA256SUMS ({url} is 404) — cannot verify a download"
        )));
    }
    if !status.is_success() {
        return Err(UpdateError::Network(format!("GET {url} returned {status}")));
    }
    let body = read_capped(resp, METADATA_CAP_BYTES, "SHA256SUMS")
        .await
        .map_err(UpdateError::Network)?;
    let text = String::from_utf8_lossy(&body);
    sha256sums_entry(&text, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- version parsing ----------

    #[test]
    fn tag_parse_strips_v_prefix_and_whitespace() {
        for raw in ["v3.4.0", "3.4.0", " v3.4.0 ", "v3.4.0\r\n"] {
            assert_eq!(
                parse_release_tag(raw).unwrap(),
                semver::Version::new(3, 4, 0),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn tag_parse_rejects_garbage_without_panicking() {
        for raw in ["", "v", "not-a-version", "3.4", "v3.4.0.1"] {
            assert!(parse_release_tag(raw).is_err(), "{raw:?} should not parse");
        }
    }

    #[test]
    fn prerelease_orders_below_release() {
        // A 4.0.0-rc.1 dev build must treat released 4.0.0 as newer, and a
        // 4.0.0 install must NOT be offered 4.1.0-rc.1 as an "update" if a
        // prerelease tag ever leaks into releases/latest.
        let rc = parse_release_tag("v4.0.0-rc.1").unwrap();
        let ga = parse_release_tag("v4.0.0").unwrap();
        assert!(rc < ga);
    }

    #[test]
    fn build_metadata_does_not_affect_update_decisions() {
        // semver::Version's Ord tiebreaks on build metadata, so the update
        // decision must go through is_newer (cmp_precedence), where
        // 3.4.0+build.5 is NOT an update over 3.4.0.
        let plain = parse_release_tag("v3.4.0").unwrap();
        let meta = parse_release_tag("v3.4.0+build.5").unwrap();
        assert!(!is_newer(&meta, &plain));
        assert!(!is_newer(&plain, &meta));
        let newer = parse_release_tag("v3.4.1").unwrap();
        assert!(is_newer(&newer, &plain));
        assert!(!is_newer(&plain, &newer));
    }

    #[test]
    fn prerelease_is_newer_than_nothing_older() {
        // A 4.0.0-rc.1 dev build sees released 4.0.0 as an update, and a
        // 4.0.0 install never sees 4.0.0-rc.1 as one.
        let rc = parse_release_tag("v4.0.0-rc.1").unwrap();
        let ga = parse_release_tag("v4.0.0").unwrap();
        assert!(is_newer(&ga, &rc));
        assert!(!is_newer(&rc, &ga));
    }

    #[test]
    fn current_version_matches_crate() {
        assert_eq!(current_version().to_string(), env!("CARGO_PKG_VERSION"));
    }

    // ---------- Location parsing ----------

    #[test]
    fn location_parse_accepts_absolute_and_relative() {
        for loc in [
            "https://github.com/SocketDev/socket-patch/releases/tag/v3.4.0",
            "/SocketDev/socket-patch/releases/tag/v3.4.0",
            "https://github.com/SocketDev/socket-patch/releases/tag/v3.4.0?ref=probe",
        ] {
            assert_eq!(
                version_from_location(loc).unwrap(),
                semver::Version::new(3, 4, 0),
                "{loc}"
            );
        }
    }

    #[test]
    fn location_parse_rejects_shapes_without_tag_segment() {
        for loc in [
            "https://github.com/SocketDev/socket-patch/releases",
            "https://github.com/login?return_to=…",
            "",
        ] {
            assert!(version_from_location(loc).is_err(), "{loc:?}");
        }
    }

    // ---------- asset mapping ----------

    #[test]
    fn asset_names_match_release_workflow_matrix() {
        // The exact 14 targets release.yml builds, with their archive kinds.
        let expected = [
            ("aarch64-apple-darwin", "tar.gz"),
            ("x86_64-apple-darwin", "tar.gz"),
            ("x86_64-unknown-linux-gnu", "tar.gz"),
            ("x86_64-unknown-linux-musl", "tar.gz"),
            ("aarch64-unknown-linux-gnu", "tar.gz"),
            ("aarch64-unknown-linux-musl", "tar.gz"),
            ("x86_64-pc-windows-msvc", "zip"),
            ("i686-pc-windows-msvc", "zip"),
            ("aarch64-pc-windows-msvc", "zip"),
            ("aarch64-linux-android", "tar.gz"),
            ("arm-unknown-linux-gnueabihf", "tar.gz"),
            ("arm-unknown-linux-musleabihf", "tar.gz"),
            ("i686-unknown-linux-gnu", "tar.gz"),
            ("i686-unknown-linux-musl", "tar.gz"),
        ];
        for (triple, kind) in expected {
            assert_eq!(
                asset_name_for_target(triple),
                format!("socket-patch-{triple}.{kind}")
            );
        }
    }

    // ---------- SHA256SUMS parsing ----------

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn sums_two_space_format_parses() {
        let sums = format!("{DIGEST_A}  socket-patch-x.tar.gz\n{DIGEST_B}  other.zip\n");
        assert_eq!(
            sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap(),
            DIGEST_A
        );
    }

    #[test]
    fn sums_binary_mode_star_prefix_tolerated() {
        let sums = format!("{DIGEST_A} *socket-patch-x.tar.gz\n");
        assert_eq!(
            sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap(),
            DIGEST_A
        );
    }

    #[test]
    fn sums_crlf_endings_tolerated() {
        let sums = format!("{DIGEST_A}  socket-patch-x.tar.gz\r\n");
        assert_eq!(
            sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap(),
            DIGEST_A
        );
    }

    #[test]
    fn sums_digest_compare_is_case_insensitive() {
        let sums = format!(
            "{}  socket-patch-x.tar.gz\n",
            DIGEST_A.to_ascii_uppercase()
        );
        assert_eq!(
            sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap(),
            DIGEST_A,
            "digests must normalize to lowercase for comparison"
        );
    }

    #[test]
    fn sums_missing_entry_is_specific_error() {
        let sums = format!("{DIGEST_A}  other.tar.gz\n");
        let err = sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap_err();
        assert!(err.to_string().contains("no entry"), "{err}");
    }

    #[test]
    fn sums_empty_file_is_error() {
        assert!(sha256sums_entry("", "socket-patch-x.tar.gz").is_err());
    }

    #[test]
    fn sums_conflicting_duplicates_refused() {
        let sums = format!(
            "{DIGEST_A}  socket-patch-x.tar.gz\n{DIGEST_B}  socket-patch-x.tar.gz\n"
        );
        let err = sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap_err();
        assert!(err.to_string().contains("conflicting"), "{err}");
        // Agreeing duplicates are harmless.
        let sums = format!(
            "{DIGEST_A}  socket-patch-x.tar.gz\n{DIGEST_A}  socket-patch-x.tar.gz\n"
        );
        assert_eq!(
            sha256sums_entry(&sums, "socket-patch-x.tar.gz").unwrap(),
            DIGEST_A
        );
    }

    #[test]
    fn sums_malformed_digest_refused() {
        let sums = "zznotahexdigest  socket-patch-x.tar.gz\n";
        assert!(sha256sums_entry(sums, "socket-patch-x.tar.gz").is_err());
        let sums = format!("{}  socket-patch-x.tar.gz\n", &DIGEST_A[..40]);
        assert!(sha256sums_entry(&sums, "socket-patch-x.tar.gz").is_err());
    }

    #[test]
    fn sums_unparseable_lines_skipped_but_absence_still_errs() {
        let sums = format!("# comment line\n\n{DIGEST_A}  present.tar.gz\ngarbage\n");
        assert_eq!(sha256sums_entry(&sums, "present.tar.gz").unwrap(), DIGEST_A);
        assert!(sha256sums_entry(&sums, "absent.tar.gz").is_err());
    }

    // ---------- endpoints ----------

    #[test]
    fn default_base_urls_are_https_github() {
        // The default constants are the security boundary: overriding them
        // (SOCKET_UPDATE_BASE_URL) relaxes the version self-check, so the
        // defaults themselves must always be the real HTTPS GitHub hosts.
        assert_eq!(DEFAULT_UPDATE_BASE_URL, "https://github.com");
        assert_eq!(DEFAULT_UPDATE_API_BASE_URL, "https://api.github.com");
    }

    #[test]
    fn download_url_shape_matches_install_sh() {
        let endpoints = UpdateEndpoints {
            web_base: DEFAULT_UPDATE_BASE_URL.to_string(),
            api_base: DEFAULT_UPDATE_API_BASE_URL.to_string(),
            is_default: true,
        };
        assert_eq!(
            endpoints.download_url(&semver::Version::new(3, 4, 0), "SHA256SUMS"),
            "https://github.com/SocketDev/socket-patch/releases/download/v3.4.0/SHA256SUMS"
        );
    }
}
