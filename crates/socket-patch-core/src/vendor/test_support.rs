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
    regzip_at(tgz, flate2::Compression::fast())
}

/// [`regzip`] at an explicit level (`best` re-encodes a `fast` archive).
pub(crate) fn regzip_at(tgz: &[u8], level: flate2::Compression) -> Vec<u8> {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(tgz)
        .read_to_end(&mut raw)
        .unwrap();
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), level);
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

/// A vendoring fixture the shared npm-family flip suite
/// ([`npm_flip_suite`]) can drive.
pub(crate) trait FlipFixture {
    fn flip_root(&self) -> &Path;
    /// The ledger key the CLI would persist the entry under (the purl).
    fn flip_key(&self) -> String;
    fn flip_uuid(&self) -> String;
    /// Project-relative path of the canonical committed artifact.
    fn flip_artifact_rel(&self) -> String;
    /// Every other committed file the wiring may touch (the lock plus any
    /// mirrors), project-relative.
    fn flip_files(&self) -> Vec<String>;
}

/// `(path, bytes)` for the artifact and every wired file (`None` = absent).
pub(crate) type Snapshot = Vec<(String, Option<Vec<u8>>)>;

pub(crate) async fn snapshot(fx: &impl FlipFixture) -> Snapshot {
    let mut out = Vec::new();
    for rel in std::iter::once(fx.flip_artifact_rel()).chain(fx.flip_files()) {
        let bytes = tokio::fs::read(fx.flip_root().join(&rel)).await.ok();
        out.push((rel, bytes));
    }
    out
}

pub(crate) fn artifact_leaf(fx: &impl FlipFixture) -> String {
    fx.flip_artifact_rel()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

/// The npm-family source-flip suite: one module of tests per flavor, each
/// asserting that a re-run after a service ↔ local source flip (or under
/// an outage) is a true no-op — lock and artifact byte-identical, entry
/// `None` (the CLI's `already_vendored`), zero service requests, and no
/// outage warning.
///
/// `$suite`: the generated module's name; `$fixture`: `async fn() -> $fx`; `$run`:
/// `async fn(&$fx, Option<&VendorServiceConfig>) -> VendorOutcome`;
/// `$fx: FlipFixture`. All three resolve in the invoking module.
macro_rules! npm_flip_suite {
    ($suite:ident, $fx:ident, $fixture:ident, $run:ident) => {
        mod $suite {
            use super::{$fixture, $run};
            use crate::vendor::test_support::{self as ts, FlipFixture as _};
            use crate::vendor::VendorSource;

            use super::$fx as Fx;

            /// The deterministic local build's bytes (from a throwaway copy).
            async fn local_bytes() -> Vec<u8> {
                let probe = $fixture().await;
                let (r, e, _) = ts::expect_done($run(&probe, None).await);
                assert!(r.success && e.is_some(), "{:?}", r.error);
                tokio::fs::read(probe.flip_root().join(probe.flip_artifact_rel()))
                    .await
                    .unwrap()
            }

            async fn mount(fx: &Fx, server: &wiremock::MockServer, serve: Option<&[u8]>) {
                server.reset().await;
                match serve {
                    Some(bytes) => {
                        ts::mount_granted(server, &fx.flip_uuid(), &ts::artifact_leaf(fx), bytes)
                            .await
                    }
                    None => ts::mount_503(server).await,
                }
            }

            /// Run 1: wires, and persists the entry the way the CLI would.
            async fn first_run(
                fx: &Fx,
                server: &wiremock::MockServer,
                source: VendorSource,
                serve: Option<&[u8]>,
            ) -> ts::Snapshot {
                mount(fx, server, serve).await;
                let cfg = ts::service_cfg(&server.uri(), source, false);
                let (r, e, w) = ts::expect_done($run(fx, Some(&cfg)).await);
                assert!(r.success, "run 1: {:?}", r.error);
                assert_eq!(
                    ts::has_warning(&w, "vendor_prebuilt_downloaded"),
                    serve.is_some(),
                    "run 1 source: {w:?}"
                );
                ts::persist(fx.flip_root(), &fx.flip_key(), e.expect("run 1 wires")).await;
                ts::snapshot(fx).await
            }

            /// Run 2 must be a true no-op with no network.
            async fn assert_noop_rerun(
                fx: &Fx,
                server: &wiremock::MockServer,
                source: VendorSource,
                offline: bool,
                serve: Option<&[u8]>,
                before: &ts::Snapshot,
            ) {
                mount(fx, server, serve).await;
                let cfg = ts::service_cfg(&server.uri(), source, offline);
                let (r, e, w) = ts::expect_done($run(fx, Some(&cfg)).await);
                assert!(r.success, "run 2: {:?}", r.error);
                assert!(e.is_none(), "run 2 must be already_vendored (entry None)");
                assert!(w.is_empty(), "run 2 carries no advisory: {w:?}");
                assert_eq!(
                    &ts::snapshot(fx).await,
                    before,
                    "lock + artifact byte-identical"
                );
                assert_eq!(ts::request_count(server).await, 0, "run 2 makes no request");
            }

            #[tokio::test]
            async fn service_then_outage_rerun_is_in_sync() {
                let alt = ts::regzip(&local_bytes().await);
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Auto, Some(&alt)).await;
                assert_eq!(
                    before[0].1.as_deref(),
                    Some(alt.as_slice()),
                    "run 1 used the service bytes"
                );
                assert_noop_rerun(&fx, &server, VendorSource::Auto, false, None, &before).await;
            }

            #[tokio::test]
            async fn outage_then_service_rerun_is_in_sync() {
                let local = local_bytes().await;
                let alt = ts::regzip(&local);
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Auto, None).await;
                assert_eq!(
                    before[0].1.as_deref(),
                    Some(local.as_slice()),
                    "run 1 built locally"
                );
                assert_noop_rerun(&fx, &server, VendorSource::Auto, false, Some(&alt), &before)
                    .await;
            }

            #[tokio::test]
            async fn outage_then_outage_rerun_is_in_sync_and_quiet() {
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Auto, None).await;
                assert_noop_rerun(&fx, &server, VendorSource::Auto, false, None, &before).await;
            }

            #[tokio::test]
            async fn service_mode_in_sync_rerun_survives_outage_and_offline() {
                let alt = ts::regzip(&local_bytes().await);
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Service, Some(&alt)).await;
                assert_noop_rerun(&fx, &server, VendorSource::Service, false, None, &before).await;
                assert_noop_rerun(&fx, &server, VendorSource::Service, true, None, &before).await;
            }

            /// F3: a healthy service is not re-contacted, and the committed
            /// artifact is not even rewritten (mtime unchanged).
            #[tokio::test]
            async fn service_then_service_rerun_skips_the_service() {
                let alt = ts::regzip(&local_bytes().await);
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Auto, Some(&alt)).await;
                let art = fx.flip_root().join(fx.flip_artifact_rel());
                let mtime = std::fs::metadata(&art).unwrap().modified().unwrap();
                assert_noop_rerun(&fx, &server, VendorSource::Auto, false, Some(&alt), &before)
                    .await;
                assert_eq!(std::fs::metadata(&art).unwrap().modified().unwrap(), mtime);
            }

            /// F5: `--vendor-source build` reuses (it never contacts the
            /// service, and reuse contacts nothing).
            #[tokio::test]
            async fn build_rerun_after_service_keeps_the_service_bytes() {
                let alt = ts::regzip(&local_bytes().await);
                let server = wiremock::MockServer::start().await;
                let fx = $fixture().await;
                let before = first_run(&fx, &server, VendorSource::Auto, Some(&alt)).await;
                assert_noop_rerun(
                    &fx,
                    &server,
                    VendorSource::Build,
                    false,
                    Some(&alt),
                    &before,
                )
                .await;
            }
        }
    };
}
pub(crate) use npm_flip_suite;

/// Every regular file under `root` (relative path → bytes), for the
/// whole-tree byte-identity oracle of the directory-shaped backends.
pub(crate) fn tree_snapshot(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}
