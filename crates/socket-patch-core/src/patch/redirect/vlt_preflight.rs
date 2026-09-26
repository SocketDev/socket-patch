//! The hosted vlt artifact preflight (`redirect_vlt_artifact_unverifiable`).
//!
//! vlt always sends `accept-encoding: gzip`, and it hashes the bytes it
//! received, so a server that re-gzips the archive makes every install fail
//! `EINTEGRITY`. Before a vlt lock is pinned to a hosted artifact, the
//! artifact is fetched the way vlt fetches it and hashed raw: the workspace
//! reqwest is built without gzip/brotli, so bodies are never decoded.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest, Sha512};

use super::{vlt, DepOverride};
use crate::api::client::{ApiClient, MAX_VENDOR_PACKAGE_BYTES};
use crate::constants::npm_family::VLT_LOCK;
use crate::utils::http::{read_capped_typed, ReadCappedError};

/// The `accept-encoding` vlt sends for registry tarballs.
pub const VLT_ACCEPT_ENCODING: &str = "gzip;q=1.0, identity;q=0.5";

/// The failure reason for a run that may not touch the network.
pub const OFFLINE_REASON: &str = "offline";

const MAX_CONCURRENT_PROBES: usize = 4;
const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_TIMEOUT: Duration = Duration::from_secs(300);

/// What fetching one artifact URL as vlt does returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactProbe {
    pub status: Option<u16>,
    pub content_encoding: Option<String>,
    /// SRI form (`sha512-<base64>`) of the raw body.
    pub sha512: Option<String>,
    /// The raw body, kept for the warm-tree heal's no-record comparison.
    pub body: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl ArtifactProbe {
    /// Why vlt would fail to verify this artifact against `sha512`, or
    /// `None` when it passes.
    pub fn failure(&self, sha512: &str) -> Option<String> {
        if let Some(error) = &self.error {
            return Some(format!("fetch error {error}"));
        }
        match self.status {
            Some(200) => {}
            Some(status) => return Some(format!("http {status}")),
            None => return Some("fetch error no response".to_string()),
        }
        if let Some(encoding) = self
            .content_encoding
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("identity"))
        {
            return Some(format!("content-encoding {encoding}"));
        }
        if self.sha512.as_deref() != Some(sha512) {
            return Some("sha512 mismatch".to_string());
        }
        None
    }
}

/// The SRI form of `bytes`' sha512.
pub fn sha512_sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn fetch_error(error: impl Into<String>) -> ArtifactProbe {
    ArtifactProbe {
        error: Some(error.into()),
        ..ArtifactProbe::default()
    }
}

/// `GET url` with vlt's `accept-encoding` (and reqwest's default
/// `Accept: */*`), following up to ten redirects, the body capped like
/// every other artifact download.
pub async fn fetch_artifact_probe(client: &reqwest::Client, url: &str) -> ArtifactProbe {
    fetch_capped(client, url, MAX_VENDOR_PACKAGE_BYTES).await
}

async fn fetch_capped(client: &reqwest::Client, url: &str, max: u64) -> ArtifactProbe {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return fetch_error("refusing a non-http(s) artifact URL");
    }
    let sent = tokio::time::timeout(
        HEADERS_TIMEOUT,
        client
            .get(url)
            .header(reqwest::header::ACCEPT_ENCODING, VLT_ACCEPT_ENCODING)
            .send(),
    )
    .await;
    let resp = match sent {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return fetch_error(e.without_url().to_string()),
        Err(_) => return fetch_error(format!("no response within {HEADERS_TIMEOUT:?}")),
    };
    let status = resp.status().as_u16();
    let content_encoding = resp
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    if status != 200 {
        return ArtifactProbe {
            status: Some(status),
            content_encoding,
            ..ArtifactProbe::default()
        };
    }
    let body = tokio::time::timeout(
        BODY_TIMEOUT,
        read_capped_typed(resp, max, "hosted artifact"),
    )
    .await
    .unwrap_or_else(|_| {
        Err(ReadCappedError::Truncated(format!(
            "hosted artifact body not received within {BODY_TIMEOUT:?}"
        )))
    });
    match body {
        Ok(bytes) => ArtifactProbe {
            status: Some(status),
            content_encoding,
            sha512: Some(sha512_sri(&bytes)),
            body: Some(bytes),
            error: None,
        },
        Err(e) => ArtifactProbe {
            status: Some(status),
            content_encoding,
            error: Some(e.to_string()),
            ..ArtifactProbe::default()
        },
    }
}

/// Probe every distinct URL in `urls` through `api`'s plain client (no
/// `Authorization`: the grant token is in the URL), at most four at a time.
pub async fn probe_artifacts(
    api: &ApiClient,
    urls: &BTreeSet<String>,
) -> BTreeMap<String, ArtifactProbe> {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut tasks = tokio::task::JoinSet::new();
    for url in urls {
        let client = api.plain_http().clone();
        let semaphore = semaphore.clone();
        let url = url.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let probe = fetch_artifact_probe(&client, &url).await;
            (url, probe)
        });
    }
    let mut out = BTreeMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((url, probe)) = joined {
            out.insert(url, probe);
        }
    }
    for url in urls {
        out.entry(url.clone())
            .or_insert_with(|| fetch_error("probe task failed"));
    }
    out
}

/// One override the preflight must probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightDep {
    pub patch_uuid: String,
    pub artifact_url: String,
    pub sha512: String,
    /// Every default-registry instance already carries this URL and sha512
    /// (an earlier run pinned it).
    pub already_pinned: bool,
}

/// The npm overrides the preflight probes: `vlt-lock.json` passes the
/// lock-level parse, the override has a sha512, and it has at least one
/// default-registry instance in the lock. Nothing is probed without a
/// `vlt-lock.json`.
pub fn preflight_scope(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
) -> Vec<PreflightDep> {
    let Some(text) = files.get(VLT_LOCK) else {
        return Vec::new();
    };
    let Ok(lock) = vlt::parse_hosted_lock(text) else {
        return Vec::new();
    };
    overrides
        .iter()
        .filter(|dep| dep.ecosystem == "npm")
        .filter_map(|dep| {
            let sha512 = dep.integrity.sha512.as_deref().filter(|s| !s.is_empty())?;
            let ids = vlt::default_instances(&lock, dep);
            if ids.is_empty() {
                return None;
            }
            let already_pinned =
                vlt::every_instance_pinned(text, &ids, sha512, &dep.artifact_url).is_some();
            Some(PreflightDep {
                patch_uuid: dep.patch_uuid.clone(),
                artifact_url: dep.artifact_url.clone(),
                sha512: sha512.to_string(),
                already_pinned,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::ApiClientOptions;
    use crate::patch::redirect::Integrity;
    use std::io::Write as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const BODY: &[u8] = b"patched tarball bytes";

    fn api(token: Option<&str>) -> ApiClient {
        ApiClient::new(ApiClientOptions {
            api_url: "http://127.0.0.1:9".to_string(),
            api_token: token.map(str::to_string),
            use_public_proxy: false,
            org_slug: Some("org".to_string()),
        })
    }

    async fn probe_of(server: &MockServer, route: &str) -> ArtifactProbe {
        fetch_artifact_probe(api(None).plain_http(), &format!("{}{route}", server.uri())).await
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[tokio::test]
    async fn identity_body_with_the_granted_sha512_passes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
            .mount(&server)
            .await;
        let probe = probe_of(&server, "/a.tgz").await;
        assert_eq!(probe.failure(&sha512_sri(BODY)), None);
        assert_eq!(probe.body.as_deref(), Some(BODY));
    }

    #[tokio::test]
    async fn an_explicit_identity_encoding_passes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "identity")
                    .set_body_bytes(BODY),
            )
            .mount(&server)
            .await;
        assert_eq!(
            probe_of(&server, "/a.tgz").await.failure(&sha512_sri(BODY)),
            None
        );
    }

    #[tokio::test]
    async fn every_failure_reason() {
        let server = MockServer::start().await;
        let gz = gzip(BODY);
        Mock::given(method("GET"))
            .and(path("/gz.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gz.clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/other.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"other".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing.tgz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/broken.tgz"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let expected = sha512_sri(BODY);

        let gz_probe = probe_of(&server, "/gz.tgz").await;
        assert_eq!(
            gz_probe.failure(&expected).as_deref(),
            Some("content-encoding gzip")
        );
        assert_eq!(
            gz_probe.sha512,
            Some(sha512_sri(&gz)),
            "the body is hashed as received, never decoded"
        );
        assert_eq!(
            probe_of(&server, "/other.tgz")
                .await
                .failure(&expected)
                .as_deref(),
            Some("sha512 mismatch")
        );
        assert_eq!(
            probe_of(&server, "/missing.tgz")
                .await
                .failure(&expected)
                .as_deref(),
            Some("http 404")
        );
        assert_eq!(
            probe_of(&server, "/broken.tgz")
                .await
                .failure(&expected)
                .as_deref(),
            Some("http 500")
        );
        let refused =
            fetch_artifact_probe(api(None).plain_http(), "http://127.0.0.1:9/a.tgz").await;
        assert!(
            refused
                .failure(&expected)
                .is_some_and(|r| r.starts_with("fetch error ")),
            "{refused:?}"
        );
        let scheme = fetch_artifact_probe(api(None).plain_http(), "file:///etc/passwd").await;
        assert!(scheme
            .failure(&expected)
            .is_some_and(|r| r.starts_with("fetch error ")));
    }

    #[tokio::test]
    async fn sends_vlt_accept_encoding_and_no_authorization() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
            .expect(1)
            .mount(&server)
            .await;
        let urls: BTreeSet<String> = [format!("{}/a.tgz", server.uri())].into();
        let probes = probe_artifacts(&api(Some("sktsec_secret_token")), &urls).await;
        assert_eq!(probes.len(), 1);
        let requests: Vec<Request> = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]
                .headers
                .get("accept-encoding")
                .map(|v| v.as_bytes()),
            Some(VLT_ACCEPT_ENCODING.as_bytes())
        );
        assert!(requests[0].headers.get("authorization").is_none());
        assert!(requests[0]
            .headers
            .get("accept")
            .is_none_or(|v| v.as_bytes() == b"*/*"));
    }

    #[tokio::test]
    async fn redirect_chains_of_ten_pass_and_eleven_fail() {
        let server = MockServer::start().await;
        for hop in 0..11 {
            Mock::given(method("GET"))
                .and(path(format!("/r{hop}")))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("{}/r{}", server.uri(), hop + 1)),
                )
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/r11"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
            .mount(&server)
            .await;
        let expected = sha512_sri(BODY);
        assert_eq!(probe_of(&server, "/r1").await.failure(&expected), None);
        assert!(probe_of(&server, "/r0")
            .await
            .failure(&expected)
            .is_some_and(|r| r.starts_with("fetch error ")));
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_a_fetch_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
            .mount(&server)
            .await;
        let url = format!("{}/big.tgz", server.uri());
        let probe = fetch_capped(api(None).plain_http(), &url, 4).await;
        assert!(
            probe
                .failure(&sha512_sri(BODY))
                .is_some_and(|r| r.starts_with("fetch error ") && r.contains("too large")),
            "{probe:?}"
        );
        assert_eq!(probe.body, None);
    }

    #[tokio::test]
    async fn one_request_per_distinct_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY))
            .mount(&server)
            .await;
        let urls: BTreeSet<String> = (0..6)
            .map(|i| format!("{}/u{}.tgz", server.uri(), i % 3))
            .collect();
        let probes = probe_artifacts(&api(None), &urls).await;
        assert_eq!(probes.len(), 3);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    fn dep(name: &str, sha512: Option<&str>) -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: name.into(),
            namespace: None,
            version: "1.0.0".into(),
            token: String::new(),
            patch_uuid: format!("uuid-{name}"),
            artifact_url: format!("https://patch.socket.dev/patch/npm/t/u/{name}-1.0.0.tgz"),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: sha512.map(str::to_string),
                ..Integrity::default()
            },
        }
    }

    fn lock(nodes: &[&str]) -> BTreeMap<String, String> {
        let body = nodes
            .iter()
            .map(|n| format!("    {n}"))
            .collect::<Vec<_>>()
            .join(",\n");
        [(
            VLT_LOCK.to_string(),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n{body}\n  }},\n  \"edges\": {{}}\n}}\n"
            ),
        )]
        .into()
    }

    #[test]
    fn scope_needs_a_parsed_lock_a_sha512_and_a_default_instance() {
        let files = lock(&[
            r#""~npm~a@1.0.0": [0,"a","sha512-old","https://registry.npmjs.org/a/-/a-1.0.0.tgz"]"#,
            r#""~npm~b@1.0.0": [0,"b","sha512-B","https://patch.socket.dev/patch/npm/t/u/b-1.0.0.tgz"]"#,
            r#""~custom~c@1.0.0": [0,"c"]"#,
        ]);
        let deps = [
            dep("a", Some("sha512-A")),
            dep("b", Some("sha512-B")),
            dep("c", Some("sha512-C")),
            dep("d", Some("sha512-D")),
            dep("a", None),
        ];
        let scope = preflight_scope(&files, &deps);
        let got: Vec<(&str, bool)> = scope
            .iter()
            .map(|d| (d.patch_uuid.as_str(), d.already_pinned))
            .collect();
        assert_eq!(got, [("uuid-a", false), ("uuid-b", true)]);
        assert!(preflight_scope(&BTreeMap::new(), &deps).is_empty());
        let mut bom = files.clone();
        bom.insert(VLT_LOCK.into(), format!("\u{feff}{}", files[VLT_LOCK]));
        assert!(preflight_scope(&bom, &deps).is_empty());
    }
}
