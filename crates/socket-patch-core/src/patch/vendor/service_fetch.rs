//! Shared download-and-verify for the patch.socket.dev vendoring service.
//!
//! Every ecosystem's service path funnels through [`fetch_verified_archive`]:
//! it calls the two-step package-reference + download flow on the API client,
//! then integrity-verifies the bytes BEFORE they are ever written/extracted.
//! Verification is fail-closed — a byte/hash mismatch is always a hard error
//! (`IntegrityMismatch`), never a silent fallback to a wrong artifact. The
//! per-ecosystem backends own the placement (Tier A: write the archive; Tier B:
//! extract it into the vendor directory) and the build-vs-service policy.

use crate::api::client::{SecondaryArtifact, VendorServiceOutcome};
use crate::patch::vendor::lock_inventory::LockIntegrity;
use crate::patch::vendor::registry_fetch::{artifact_matches_integrity, verify_go_h1};
use crate::patch::vendor::VendorServiceConfig;
use crate::patch::vendor::{common::refused, VendorOutcome, VendorWarning};

/// A service archive whose bytes have passed integrity verification.
///
/// Deliberately minimal: every consumer recomputes the hashes it needs from
/// `bytes` (so a service-downloaded artifact describes itself byte-identically
/// to a local build), so the service-reported sha1/md5/size are not re-carried.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedArchive {
    /// The verified archive bytes (npm `.tgz`, pypi `.whl`/sdist, cargo
    /// `.crate`, golang/composer `.zip`, gem `.gem`, …).
    pub bytes: Vec<u8>,
    /// Normalized sha512 SRI (`sha512-<b64>`) of the bytes — what npm/pypi/etc.
    /// lockfiles that key on sha512 embed verbatim.
    pub integrity_sri: String,
    /// The (possibly host-rewritten) URL the bytes came from — for logging.
    pub source_url: String,
    /// The OTHER served artifacts (e.g. gem's path-source stub gemspec), still
    /// unverified — a backend that needs one calls [`fetch_verified_secondary`]
    /// to download + integrity-verify it on demand.
    pub secondary: Vec<SecondaryArtifact>,
}

/// Result of attempting a service download for one patch UUID.
///
/// The backends map this onto the `auto` / `service` policy: `Ready` → use it;
/// `Pending` / `Unavailable` / `Failed` → fall back to a local build under
/// `auto` (or hard-fail under `service`); `IntegrityMismatch` → ALWAYS a hard
/// error regardless of mode.
#[derive(Debug)]
pub(crate) enum ServiceArtifact {
    Ready(VerifiedArchive),
    /// Archive still building (retryable).
    Pending,
    /// Terminal miss for this input (not built / withdrawn / not found / no
    /// usable artifact / service not configured). `String` is a log reason.
    Unavailable(String),
    /// Request / transport / auth failure. `String` is a log reason.
    Failed(String),
    /// Bytes downloaded but failed integrity verification — never fall back.
    IntegrityMismatch(String),
}

/// Download and integrity-verify the prebuilt archive for `uuid`.
///
/// `verify_name` is only consulted for the (npm) yarn-berry checksum kind,
/// which v1 never verifies here — pass the package's bare name for forward
/// compatibility. Verification always checks the sha512 floor and, when the
/// service supplied a golang `h1:` dirhash, that too (it covers the zip's
/// contents, which `go mod verify` relies on).
pub(crate) async fn fetch_verified_archive(
    cfg: &VendorServiceConfig,
    uuid: &str,
    verify_name: &str,
) -> ServiceArtifact {
    let Some(client) = cfg.client.as_ref() else {
        return ServiceArtifact::Unavailable("vendor service not configured".to_string());
    };

    let outcome = client
        .fetch_vendor_package(
            uuid,
            cfg.use_public_proxy,
            cfg.vendor_url.as_deref(),
            cfg.patch_server_url.as_deref(),
        )
        .await;

    let pkg = match outcome {
        VendorServiceOutcome::Ready(pkg) => pkg,
        VendorServiceOutcome::Pending => return ServiceArtifact::Pending,
        VendorServiceOutcome::Unavailable(reason) => return ServiceArtifact::Unavailable(reason),
        VendorServiceOutcome::Failed(err) => return ServiceArtifact::Failed(err.to_string()),
    };

    // sha512 floor — every ecosystem's tarball carries it.
    if let Err(e) = artifact_matches_integrity(
        &pkg.tarball,
        verify_name,
        &LockIntegrity::Sri(pkg.integrity_sri.clone()),
    ) {
        return ServiceArtifact::IntegrityMismatch(e);
    }
    // golang module-zip dirhash, when supplied (verifies CONTENTS, not just
    // bytes). Ecosystem-agnostic: only runs when the service reported one.
    if let Some(h1) = pkg.dirhash_h1.as_deref() {
        if let Err(e) = verify_go_h1(&pkg.tarball, h1) {
            return ServiceArtifact::IntegrityMismatch(e);
        }
    }

    ServiceArtifact::Ready(VerifiedArchive {
        bytes: pkg.tarball,
        integrity_sri: pkg.integrity_sri,
        source_url: pkg.source_url,
        secondary: pkg.secondary_artifacts,
    })
}

/// Outcome of attempting to materialise a single-file artifact from the patch
/// service (the Tier-A backends — maven `.jar`, nuget `.nupkg` — where the
/// verified archive bytes ARE the vendored artifact, written verbatim).
pub(crate) enum ServiceCopy {
    /// The prebuilt patched bytes (write them verbatim).
    Used(Vec<u8>),
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to the local rebuild.
    FallBack,
}

/// Download + integrity-verify the prebuilt patched archive for the Tier-A
/// backends, mapping each service outcome onto the `auto` / `service` fallback
/// policy. `noun` is the artifact kind used in messages (".jar" / ".nupkg").
pub(crate) async fn service_archive_copy(
    service: Option<&VendorServiceConfig>,
    uuid: &str,
    name: &str,
    noun: &str,
    warnings: &mut Vec<VendorWarning>,
) -> ServiceCopy {
    let Some(cfg) = service else {
        return ServiceCopy::FallBack;
    };
    if !cfg.service_enabled() {
        return ServiceCopy::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> ServiceCopy {
        ServiceCopy::HardFail(Box::new(refused(code, detail)))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            ServiceCopy::FallBack
        }
    };
    match fetch_verified_archive(cfg, uuid, name).await {
        ServiceArtifact::Ready(archive) => {
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {name} from the patch service ({})",
                    archive.source_url
                ),
            ));
            ServiceCopy::Used(archive.bytes)
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt {noun} failed integrity ({reason})"),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            format!("prebuilt {noun} is still building"),
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt {noun} unavailable: {reason}"),
                )
            } else {
                ServiceCopy::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// Outcome of fetching + verifying a named secondary artifact.
pub(crate) enum SecondaryArtifactResult {
    /// Bytes downloaded and sha512-verified.
    Ready(Vec<u8>),
    /// No artifact of this kind was served (e.g. a native-extension gem emits
    /// no stub, or an old row predates the rebuild) — a terminal miss.
    Absent,
    /// Request / transport / auth failure. `String` is a log reason.
    Failed(String),
    /// Bytes downloaded but failed integrity verification — never fall back.
    IntegrityMismatch(String),
}

/// Download + integrity-verify the secondary artifact of `kind` (e.g.
/// `gem-stub-gemspec`) referenced by a [`VerifiedArchive`].
///
/// `verify_name` is the package's bare name (only consulted by the yarn-berry
/// checksum kind, which never reaches here). The bytes are verified against the
/// artifact's own sha512 SRI, fail-closed like the primary archive. Returns
/// `Absent` when the archive referenced no artifact of this kind — the caller
/// treats that as a miss (fall back under `auto`, refuse under `service`).
pub(crate) async fn fetch_verified_secondary(
    cfg: &VendorServiceConfig,
    archive: &VerifiedArchive,
    kind: &str,
    verify_name: &str,
) -> SecondaryArtifactResult {
    let Some(client) = cfg.client.as_ref() else {
        return SecondaryArtifactResult::Failed("vendor service not configured".to_string());
    };
    let Some(artifact) = archive.secondary.iter().find(|a| a.kind == kind) else {
        return SecondaryArtifactResult::Absent;
    };

    let bytes = match client.download_artifact(&artifact.url).await {
        Ok(bytes) => bytes,
        Err(e) => return SecondaryArtifactResult::Failed(e.to_string()),
    };

    if let Err(e) = artifact_matches_integrity(
        &bytes,
        verify_name,
        &LockIntegrity::Sri(artifact.integrity_sri.clone()),
    ) {
        return SecondaryArtifactResult::IntegrityMismatch(e);
    }
    SecondaryArtifactResult::Ready(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::patch::vendor::npm_pack::PackedTarball;
    use crate::patch::vendor::VendorSource;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "22222222-2222-2222-2222-222222222222";
    const SERVE_PATH: &str = "/patch/npm/x/1.0.0/tok/uuid/x-1.0.0.tgz";

    fn cfg_for(server: &MockServer) -> VendorServiceConfig {
        VendorServiceConfig {
            source: VendorSource::Service,
            client: Some(ApiClient::new(ApiClientOptions {
                api_url: server.uri(),
                api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                use_public_proxy: false,
                org_slug: Some("acme".into()),
            })),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        }
    }

    async fn mount_granted(server: &MockServer, sha512: &str, body: &[u8]) {
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": { "sha512": sha512 } }]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(server)
            .await;
    }

    /// The verify floor accepts bytes whose sha512 matches the service SRI.
    #[tokio::test]
    async fn ready_when_sha512_matches() {
        let server = MockServer::start().await;
        let body = b"verified archive bytes";
        let sri = PackedTarball::from_bytes(body).integrity;
        mount_granted(&server, &sri, body).await;

        match fetch_verified_archive(&cfg_for(&server), UUID, "x").await {
            ServiceArtifact::Ready(v) => {
                assert_eq!(v.bytes, body);
                assert_eq!(v.integrity_sri, sri);
                assert!(v.source_url.ends_with(SERVE_PATH));
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// Fail-closed: bytes whose sha512 disagrees with the service SRI are an
    /// IntegrityMismatch (never silently used / fallen back from here).
    #[tokio::test]
    async fn integrity_mismatch_when_sha512_wrong() {
        let server = MockServer::start().await;
        let body = b"the real bytes";
        let wrong = PackedTarball::from_bytes(b"completely different bytes").integrity;
        mount_granted(&server, &wrong, body).await;

        assert!(matches!(
            fetch_verified_archive(&cfg_for(&server), UUID, "x").await,
            ServiceArtifact::IntegrityMismatch(_)
        ));
    }

    /// A config without a client is a quiet Unavailable, not a panic.
    #[tokio::test]
    async fn unavailable_when_client_absent() {
        let cfg = VendorServiceConfig {
            source: VendorSource::Auto,
            client: None,
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        };
        assert!(matches!(
            fetch_verified_archive(&cfg, UUID, "x").await,
            ServiceArtifact::Unavailable(_)
        ));
    }
}
