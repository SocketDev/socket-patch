//! Shared tooling for the source-flip / outage tests of the
//! archive-shaped backends.

use std::io::{Read as _, Write as _};
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha512};

use crate::api::client::{ApiClient, ApiClientOptions};
use crate::patch::apply::ApplyResult;
use crate::vendor::state::{load_state, save_state, VendorEntry};
use crate::vendor::{VendorOutcome, VendorServiceConfig, VendorSource, VendorWarning};

pub(crate) const PACKAGE_PATH: &str = "/v0/orgs/acme/patches/package";

/// Re-gzip at `Compression::fast`: identical members, different bytes
/// (and so a different sha512) — the stand-in for the service's
/// prebuilt encoding of the same patched package.
pub(crate) fn regzip(tgz: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(tgz)
        .read_to_end(&mut raw)
        .unwrap();
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(&raw).unwrap();
    let out = enc.finish().unwrap();
    assert_ne!(out, tgz, "regzip must change the bytes");
    out
}

pub(crate) fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// A service config against `server_uri` (org `acme`, authenticated).
pub(crate) fn service_cfg(
    server_uri: &str,
    source: VendorSource,
    offline: bool,
) -> VendorServiceConfig {
    VendorServiceConfig {
        source,
        client: Some(ApiClient::new(ApiClientOptions {
            api_url: server_uri.to_string(),
            api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
            use_public_proxy: false,
            org_slug: Some("acme".into()),
        })),
        use_public_proxy: false,
        vendor_url: None,
        patch_server_url: None,
        offline,
    }
}

/// Mount a granted package reference for `uuid` serving `bytes` (file
/// name `leaf`) with a matching SRI.
pub(crate) async fn mount_granted(
    server: &wiremock::MockServer,
    uuid: &str,
    leaf: &str,
    bytes: &[u8],
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let serve_path = format!("/serve/{uuid}/{leaf}");
    let url = format!("{}{serve_path}", server.uri());
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { uuid: {
                "status": "granted",
                "url": url,
                "artifacts": [{ "kind": "tarball", "url": url,
                                "integrity": { "sha512": sri(bytes) } }]
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(serve_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(server)
        .await;
}

/// Mount a 503 on the package-reference POST (the outage).
pub(crate) async fn mount_503(server: &wiremock::MockServer) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .mount(server)
        .await;
}

pub(crate) async fn request_count(server: &wiremock::MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

pub(crate) fn expect_done(
    outcome: VendorOutcome,
) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
    match outcome {
        VendorOutcome::Done {
            result,
            entry,
            warnings,
        } => (result, entry, warnings),
        VendorOutcome::Refused { code, detail } => {
            panic!("expected Done, got Refused {code}: {detail}")
        }
    }
}

/// Persist `entry` under `key` the way the CLI does after a successful
/// vendor (carry-forward included), so the next run sees the ledger.
pub(crate) async fn persist(root: &Path, key: &str, mut entry: VendorEntry) {
    let mut state = load_state(root).await.unwrap();
    if let Some(prev) = state.entries.get(key) {
        crate::vendor::carry_forward_wiring(prev, &mut entry);
    }
    state.entries.insert(key.to_string(), entry);
    save_state(root, &state).await.unwrap();
}

pub(crate) fn has_warning(warnings: &[VendorWarning], code: &str) -> bool {
    warnings.iter().any(|w| w.code == code)
}
