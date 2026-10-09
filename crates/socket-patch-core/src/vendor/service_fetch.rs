//! Shared download-and-verify for the patch.socket.dev vendoring service.
//!
//! Every ecosystem's service path funnels through [`fetch_verified_archive`]:
//! it calls the two-step package-reference + download flow on the API client,
//! then integrity-verifies the bytes BEFORE they are ever written/extracted.
//! Verification is fail-closed — a byte/hash mismatch is always a hard error
//! (`IntegrityMismatch`), never a silent fallback to a wrong artifact. The
//! backends own the placement: write the archive or extract it into a directory.

use crate::api::client::{SecondaryArtifact, VendorServiceOutcome};
use crate::manifest::schema::PatchRecord;
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::registry_fetch::{artifact_matches_integrity, verify_go_h1};
use crate::vendor::VendorServiceConfig;
use crate::vendor::{
    common::{refused, service_offline_conflict, zip_bytes_match_after_hashes},
    VendorOutcome, VendorWarning,
};

pub(crate) fn required() -> VendorOutcome {
    refused(
        "vendor_prebuilt_required",
        "vendoring requires a verified artifact from the patch service".to_string(),
    )
}

pub(crate) async fn preview_service(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    extract: impl FnOnce(&[u8], &std::path::Path) -> Result<(), String> + Send + 'static,
) -> Result<(), Box<VendorOutcome>> {
    if let Some(outcome) = service_offline_conflict(service) {
        return Err(Box::new(outcome));
    }
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(required()))?;
    let policy = ServicePolicy::Refused;
    let archive = policy.settle(
        fetch_verified_archive(cfg, &record.uuid).await,
        "archive",
        &record.uuid,
    )?;
    let stage = tempfile::tempdir()
        .map_err(|e| Box::new(refused("vendor_prebuilt_extract_failed", e.to_string())))?;
    super::registry_fetch::extract_on_blocking_pool(archive.bytes, stage.path(), extract)
        .await
        .map_err(|e| Box::new(refused("vendor_prebuilt_extract_failed", e)))?;
    if !super::common::copy_matches_after_hashes(stage.path(), &record.files).await {
        return Err(Box::new(refused(
            "vendor_prebuilt_layout_mismatch",
            format!(
                "prebuilt archive for {} does not carry its patched files",
                record.uuid
            ),
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct VerifiedArchive {
    pub yarn_berry10c0: Option<String>,
    /// The verified archive bytes (npm `.tgz`, pypi `.whl`/sdist, cargo
    /// `.crate`, golang/composer `.zip`, gem `.gem`, …).
    pub bytes: Vec<u8>,
    /// Normalized sha512 SRI (`sha512-<b64>`) of the bytes — what npm/pypi/etc.
    /// lockfiles that key on sha512 embed verbatim.
    pub integrity_sri: String,
    /// Hex sha256 of the same bytes — the pin a pypi lock records for the
    /// vendored wheel. Taken on FIRST READ: pypi is the only backend that
    /// asks for it, and the other seven download through this same path, so
    /// digesting every archive here would charge them all for a walk none of
    /// them makes.
    sha256_hex: std::sync::OnceLock<String>,
    /// The (possibly host-rewritten) URL the bytes came from — for logging.
    pub source_url: String,
    /// The OTHER served artifacts (e.g. gem's path-source stub gemspec), still
    /// unverified — a backend that needs one calls [`fetch_verified_secondary`]
    /// to download + integrity-verify it on demand.
    pub secondary: Vec<SecondaryArtifact>,
    /// What the vendor prefetch plan already did with these bytes ahead of
    /// the backend: an extracted tree to claim, an afterHash verdict (see
    /// [`crate::vendor::prestage`]).
    pub prestaged: crate::vendor::prestage::Prestaged,
}

impl VerifiedArchive {
    /// Hex sha256 of [`Self::bytes`], digested once on first ask.
    pub(crate) fn sha256_hex(&self) -> &str {
        self.sha256_hex
            .get_or_init(|| crate::utils::digest::sha256_hex_of(&self.bytes))
    }
}

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
/// Verification always checks the sha512 floor and, when the service supplied
/// a golang `h1:` dirhash, that too (it covers the zip's contents, which
/// `go mod verify` relies on).
pub(crate) async fn fetch_verified_archive(
    cfg: &VendorServiceConfig,
    uuid: &str,
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

    // sha512 floor — every ecosystem's tarball carries it. The name arg only
    // feeds the yarn-berry checksum recipe; the Sri verifier ignores it.
    if let Err(e) = artifact_matches_integrity(
        &pkg.tarball,
        "",
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
        yarn_berry10c0: pkg.yarn_berry10c0,
        bytes: pkg.tarball,
        integrity_sri: pkg.integrity_sri,
        sha256_hex: std::sync::OnceLock::new(),
        source_url: pkg.source_url,
        secondary: pkg.secondary_artifacts,
        prestaged: pkg.prestaged,
    })
}

/// Move the tree the download plan pre-staged from `archive`'s bytes (see
/// [`crate::vendor::prestage`]) into `stage`, the backend's stage for
/// `copy_dir`, where the backend would otherwise extract them. `false` —
/// nothing pre-staged, or the move failed — and the backend extracts live.
pub(crate) async fn claim_prestaged(
    archive: &mut VerifiedArchive,
    stage: &std::path::Path,
    copy_dir: &std::path::Path,
) -> bool {
    match archive.prestaged.tree.take() {
        Some(tree) => tree.claim_into(stage, copy_dir).await,
        None => false,
    }
}

/// How a backend reports a terminal service failure.
#[derive(Clone, Copy)]
pub(crate) enum ServicePolicy<'a> {
    Refused,
    /// npm reports a failed `Done` for this purl.
    Failure(&'a str),
}

impl ServicePolicy<'_> {
    pub(crate) fn hard(&self, code: &'static str, detail: String) -> Box<VendorOutcome> {
        Box::new(match self {
            Self::Refused => refused(code, detail),
            Self::Failure(purl) => super::npm_common::done_failure(purl, detail),
        })
    }

    /// npm must distinguish unserved patches from failures so the vendor loop
    /// can keep an older vendored patch of the same package (#954).
    fn unserved(&self, code: &'static str, detail: String) -> Box<VendorOutcome> {
        match self {
            Self::Refused => self.miss(detail),
            Self::Failure(purl) => {
                let warning = VendorWarning::new(code, detail.clone());
                Box::new(super::common::done(
                    super::common::failed_result(purl, std::path::Path::new(""), detail),
                    None,
                    vec![warning],
                ))
            }
        }
    }

    pub(crate) fn miss(&self, reason: String) -> Box<VendorOutcome> {
        self.hard("vendor_prebuilt_required", reason)
    }

    /// `noun` names the artifact kind; `subject` identifies it in error messages.
    pub(crate) fn settle(
        &self,
        artifact: ServiceArtifact,
        noun: &str,
        subject: &str,
    ) -> Result<VerifiedArchive, Box<VendorOutcome>> {
        match artifact {
            ServiceArtifact::Ready(archive) => Ok(archive),
            ServiceArtifact::IntegrityMismatch(reason) => Err(self.hard(
                "vendor_prebuilt_integrity_mismatch",
                format!(
                    "prebuilt {subject} failed integrity verification ({reason}); \
                     refusing to fall back to a local build on tampered bytes"
                ),
            )),
            ServiceArtifact::Pending => Err(self.unserved(
                super::VENDOR_PREBUILT_PENDING,
                format!("prebuilt {noun} is still building"),
            )),
            ServiceArtifact::Unavailable(reason) => Err(self.unserved(
                super::VENDOR_PREBUILT_UNAVAILABLE,
                format!("prebuilt {noun} unavailable: {reason}"),
            )),
            ServiceArtifact::Failed(reason) => {
                Err(self.miss(format!("patch service request failed ({reason})")))
            }
        }
    }
}

/// Download + integrity-verify the prebuilt patched archive for the Tier-A
/// backends. `noun` is the artifact kind used in messages (".jar" / ".nupkg").
pub(crate) async fn service_archive_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    noun: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<Vec<u8>, Box<VendorOutcome>> {
    // The maven/nuget flows have no earlier guard, so the fail-closed
    // `--vendor-source=service` refusals (`--offline`, no API client) live
    // here (the other backends check the same helper at their entry points).
    if let Some(refusal) = service_offline_conflict(service) {
        return Err(Box::new(refusal));
    }
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(super::service_fetch::required()))?;
    let policy = ServicePolicy::Refused;
    let fetched = fetch_verified_archive(cfg, &record.uuid).await;
    let archive = policy.settle(fetched, noun, noun)?;
    // The SRI proves the download is intact, not that it carries the
    // patch: the bytes are written verbatim and reported AlreadyPatched,
    // so every patched member must hash to its afterHash first (the
    // extracted-tree check). A mismatching artifact always fails closed.
    if !archive
        .prestaged
        .zip_verdict(&record.files)
        .unwrap_or_else(|| zip_bytes_match_after_hashes(&archive.bytes, &record.files))
    {
        return Err(policy.miss(format!(
            "prebuilt {noun} for {name} does not carry the patched files at their \
                 recorded paths"
        )));
    }
    warnings.push(VendorWarning::new(
        "vendor_prebuilt_downloaded",
        format!(
            "vendored {name} from the patch service ({})",
            archive.source_url
        ),
    ));
    Ok(archive.bytes)
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
/// The bytes are verified against the artifact's own sha512 SRI, fail-closed
/// like the primary archive. Returns `Absent` when no artifact of this kind
/// was referenced.
pub(crate) async fn fetch_verified_secondary(
    cfg: &VendorServiceConfig,
    archive: &VerifiedArchive,
    kind: &str,
) -> SecondaryArtifactResult {
    let Some(client) = cfg.client.as_ref() else {
        return SecondaryArtifactResult::Failed("vendor service not configured".to_string());
    };
    let Some(artifact) = archive.secondary.iter().find(|a| a.kind == kind) else {
        return SecondaryArtifactResult::Absent;
    };

    // A download the vendor prefetch plan already made stands in for the
    // live request (its debug lines print here, where this call's would).
    let downloaded = match artifact.prefetched.as_ref().and_then(|p| p.take()) {
        Some(held) => held.release(),
        None => client.download_artifact(&artifact.url).await,
    };
    let bytes = match downloaded {
        Ok(bytes) => bytes,
        Err(e) => return SecondaryArtifactResult::Failed(e.to_string()),
    };

    // As above: the Sri verifier never reads the name arg.
    if let Err(e) = artifact_matches_integrity(
        &bytes,
        "",
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
    use crate::vendor::npm_pack::PackedTarball;
    use crate::vendor::VendorSource;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "22222222-2222-2222-2222-222222222222";
    const SERVE_PATH: &str = "/patch/npm/x/1.0.0/tok/uuid/x-1.0.0.tgz";

    /// A files-less record for [`UUID`]: the Tier-A afterHash gate then only
    /// requires the served bytes to be a readable zip.
    fn record() -> PatchRecord {
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: std::collections::HashMap::new(),
            vulnerabilities: std::collections::HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// An empty (member-less) zip — passes the afterHash gate of a
    /// files-less [`record`].
    fn empty_zip() -> Vec<u8> {
        zip::ZipWriter::new(std::io::Cursor::new(Vec::new()))
            .finish()
            .unwrap()
            .into_inner()
    }

    fn cfg_for(server: &MockServer) -> VendorServiceConfig {
        VendorServiceConfig {
            maven_config: None,
            source: VendorSource::Service,
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: server.uri(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    route: crate::api::client::ApiRoute::org("acme"),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none()),
            ),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        }
    }

    async fn mount_granted(server: &MockServer, sha512: &str, body: &[u8]) {
        mount_granted_with_dirhash(server, sha512, None, body).await;
    }

    async fn mount_granted_with_dirhash(
        server: &MockServer,
        sha512: &str,
        dirhash_h1: Option<&str>,
        body: &[u8],
    ) {
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        let mut integrity = json!({ "sha512": sha512 });
        if let Some(h1) = dirhash_h1 {
            integrity["dirhashH1"] = serde_json::Value::from(h1);
        }
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": integrity }]
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

    /// Mount a package-reference response with a non-`granted` status (no
    /// artifacts) — mirrors golang.rs's `mount_go_status`.
    async fn mount_status(server: &MockServer, status: &str) {
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
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

        match fetch_verified_archive(&cfg_for(&server), UUID).await {
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
            fetch_verified_archive(&cfg_for(&server), UUID).await,
            ServiceArtifact::IntegrityMismatch(_)
        ));
    }

    /// Tampered bytes must be refused before extraction.
    #[tokio::test]
    async fn service_copy_integrity_mismatch_hard_fails() {
        let server = MockServer::start().await;
        let body = b"the real bytes";
        let wrong = PackedTarball::from_bytes(b"completely different bytes").integrity;
        mount_granted(&server, &wrong, body).await;
        let cfg = cfg_for(&server);
        let mut warnings = Vec::new();
        match service_archive_copy(Some(&cfg), &record(), "x", ".jar", &mut warnings).await {
            Err(outcome) => match *outcome {
                VendorOutcome::Refused { code, .. } => {
                    assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
                }
                other => panic!("expected Refused, got {other:?}"),
            },
            Ok(_) => panic!("tampered bytes must never be used"),
        }
    }

    #[tokio::test]
    async fn service_copy_offline_conflict_hard_fails() {
        let server = MockServer::start().await;
        let mut cfg = cfg_for(&server);
        cfg.offline = true;
        let mut warnings = Vec::new();
        match service_archive_copy(Some(&cfg), &record(), "x", ".jar", &mut warnings).await {
            Err(outcome) => match *outcome {
                VendorOutcome::Refused { code, .. } => {
                    assert_eq!(code, "vendor_service_offline_conflict");
                }
                other => panic!("expected Refused, got {other:?}"),
            },
            Ok(_) => panic!("offline run must not download"),
        }
        assert!(warnings.is_empty(), "the refusal needs no advisory");
    }

    /// A config without a client is a quiet Unavailable, not a panic.
    #[tokio::test]
    async fn unavailable_when_client_absent() {
        let cfg = VendorServiceConfig {
            maven_config: None,
            source: VendorSource::Service,
            client: None,
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        };
        assert!(matches!(
            fetch_verified_archive(&cfg, UUID).await,
            ServiceArtifact::Unavailable(_)
        ));
    }

    /// The h1-dirhash verify's SUCCESS continuation: a service archive whose
    /// golang `h1:` dirhash matches its zip contents passes through to Ready.
    #[tokio::test]
    async fn ready_when_golang_h1_dirhash_matches() {
        let server = MockServer::start().await;
        let entry_name = "m@v1.0.0/a.go";
        let content: &[u8] = b"package a\n";
        // One-file module zip (the go zip layout: `module@version/` prefix).
        let zip_bytes = {
            use std::io::Write as _;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file(entry_name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(content).unwrap();
            zw.finish().unwrap().into_inner()
        };
        // Independent spec mirror of dirhash Hash1 (single entry, so no sort):
        // h1 = base64(sha256("{hex(sha256(content))}  {name}\n")).
        let h1 = {
            use base64::Engine as _;
            use sha2::{Digest as _, Sha256};
            let line = format!("{}  {entry_name}\n", hex::encode(Sha256::digest(content)));
            format!(
                "h1:{}",
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(line.as_bytes()))
            )
        };
        let sri = PackedTarball::from_bytes(&zip_bytes).integrity;
        mount_granted_with_dirhash(&server, &sri, Some(&h1), &zip_bytes).await;

        match fetch_verified_archive(&cfg_for(&server), UUID).await {
            ServiceArtifact::Ready(v) => assert_eq!(v.bytes, zip_bytes),
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// Tier-A happy path: a granted, integrity-verified archive comes back as
    /// bytes plus exactly one `vendor_prebuilt_downloaded` advisory
    /// naming the package and the serve URL.
    #[tokio::test]
    async fn service_copy_ready_returns_used_bytes_with_downloaded_note() {
        let server = MockServer::start().await;
        let body = &empty_zip()[..];
        let sri = PackedTarball::from_bytes(body).integrity;
        mount_granted(&server, &sri, body).await;
        let mut warnings = Vec::new();
        match service_archive_copy(
            Some(&cfg_for(&server)),
            &record(),
            "x",
            ".jar",
            &mut warnings,
        )
        .await
        {
            Ok(bytes) => assert_eq!(bytes, body),
            Err(outcome) => panic!("expected archive bytes, got {outcome:?}"),
        }
        assert_eq!(warnings.len(), 1, "exactly one downloaded advisory");
        assert_eq!(warnings[0].code, "vendor_prebuilt_downloaded");
        assert!(
            warnings[0]
                .detail
                .contains("vendored x from the patch service"),
            "{}",
            warnings[0].detail
        );
        assert!(
            warnings[0].detail.ends_with(&format!("{SERVE_PATH})")),
            "advisory names the serve URL: {}",
            warnings[0].detail
        );
    }

    #[tokio::test]
    async fn service_copy_pending_service_hard_fails() {
        let server = MockServer::start().await;
        mount_status(&server, "pending_build").await;
        let mut warnings = Vec::new();
        match service_archive_copy(
            Some(&cfg_for(&server)),
            &record(),
            "x",
            ".jar",
            &mut warnings,
        )
        .await
        {
            Err(outcome) => match *outcome {
                VendorOutcome::Refused { code, detail } => {
                    assert_eq!(code, "vendor_prebuilt_required");
                    assert!(detail.contains("is still building"), "{detail}");
                }
                other => panic!("expected Refused, got {other:?}"),
            },
            Ok(_) => panic!("pending build must not yield bytes"),
        }
        assert!(warnings.is_empty(), "the hard-fail path must not warn");
    }

    /// Unavailable under `--vendor-source=service`: hard refusal with the
    /// terminal-miss reason verbatim.
    #[tokio::test]
    async fn service_copy_unavailable_service_hard_fails() {
        let server = MockServer::start().await;
        mount_status(&server, "not_found").await;
        let mut warnings = Vec::new();
        match service_archive_copy(
            Some(&cfg_for(&server)),
            &record(),
            "x",
            ".jar",
            &mut warnings,
        )
        .await
        {
            Err(outcome) => match *outcome {
                VendorOutcome::Refused { code, detail } => {
                    assert_eq!(code, "vendor_prebuilt_required");
                    assert_eq!(detail, "prebuilt .jar unavailable: not_found");
                }
                other => panic!("expected Refused, got {other:?}"),
            },
            Ok(_) => panic!("unavailable archive must not yield bytes"),
        }
        assert!(warnings.is_empty(), "the hard-fail path must not warn");
    }

    #[tokio::test]
    async fn service_copy_failed_service_hard_fails() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut warnings = Vec::new();
        match service_archive_copy(
            Some(&cfg_for(&server)),
            &record(),
            "x",
            ".jar",
            &mut warnings,
        )
        .await
        {
            Err(outcome) => match *outcome {
                VendorOutcome::Refused { code, detail } => {
                    assert_eq!(code, "vendor_prebuilt_required");
                    assert!(
                        detail.starts_with("patch service request failed ("),
                        "{detail}"
                    );
                }
                other => panic!("expected Refused, got {other:?}"),
            },
            Ok(_) => panic!("a failed request must not yield bytes"),
        }
        assert!(warnings.is_empty(), "the hard-fail path must not warn");
    }

    /// A transport failure downloading a PRESENT secondary artifact is
    /// `Failed` (never `Absent` — the kind is referenced — and never a panic).
    #[tokio::test]
    async fn secondary_failed_when_download_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stub"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let archive = VerifiedArchive {
            yarn_berry10c0: None,
            bytes: Vec::new(),
            integrity_sri: String::new(),
            sha256_hex: std::sync::OnceLock::new(),
            source_url: String::new(),
            secondary: vec![SecondaryArtifact {
                prefetched: None,
                kind: "gem-stub-gemspec".into(),
                url: format!("{}/stub", server.uri()),
                integrity_sri: PackedTarball::from_bytes(b"x").integrity,
            }],
            prestaged: Default::default(),
        };
        match fetch_verified_secondary(&cfg_for(&server), &archive, "gem-stub-gemspec").await {
            SecondaryArtifactResult::Failed(reason) => {
                assert!(reason.contains("500"), "{reason}");
            }
            SecondaryArtifactResult::Ready(_) => panic!("a 500 must not yield bytes"),
            SecondaryArtifactResult::Absent => {
                panic!("the kind IS referenced — a download failure must be Failed, not Absent")
            }
            SecondaryArtifactResult::IntegrityMismatch(m) => {
                panic!("expected Failed, got IntegrityMismatch({m})")
            }
        }
    }

    /// Valid transfer integrity cannot substitute for the record's patched bytes.
    #[tokio::test]
    async fn service_copy_ready_failing_after_hashes_is_rejected() {
        use crate::hash::git_sha256::compute_git_sha256_from_bytes;
        use crate::manifest::schema::PatchFileInfo;
        let body = {
            use std::io::Write as _;
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zw.start_file("lib/x.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"unpatched").unwrap();
            zw.finish().unwrap().into_inner()
        };
        let mut rec = record();
        rec.files.insert(
            "lib/x.txt".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"unpatched"),
                after_hash: compute_git_sha256_from_bytes(b"patched"),
            },
        );
        for source in [VendorSource::Service] {
            let server = MockServer::start().await;
            let sri = PackedTarball::from_bytes(&body).integrity;
            mount_granted(&server, &sri, &body).await;
            let mut cfg = cfg_for(&server);
            cfg.source = source;
            let mut warnings = Vec::new();
            let copy = service_archive_copy(Some(&cfg), &rec, "x", ".jar", &mut warnings).await;
            match (source, copy) {
                (VendorSource::Service, Err(outcome)) => match *outcome {
                    VendorOutcome::Refused { code, detail } => {
                        assert_eq!(code, "vendor_prebuilt_required");
                        assert!(
                            detail.contains("does not carry the patched files"),
                            "{detail}"
                        );
                    }
                    other => panic!("expected Refused, got {other:?}"),
                },
                (source, Ok(_)) => {
                    panic!("{source:?}: unpatched service bytes were accepted")
                }
            }
            assert!(
                !warnings
                    .iter()
                    .any(|w| w.code == "vendor_prebuilt_downloaded"),
                "{warnings:?}"
            );
        }
    }
}
