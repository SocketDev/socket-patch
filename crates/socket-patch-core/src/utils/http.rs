//! Small shared HTTP primitives.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// The one constructor behind every production `reqwest::Client`.
///
/// Trust roots are the bundled webpki (Mozilla) roots **plus** the
/// platform roots ([`load_configured_roots`]): the OS trust store, or the
/// bundle that `SSL_CERT_FILE` / `SSL_CERT_DIR` name. That is the rule
/// curl, npm, pip and cargo already follow, so a TLS-inspecting corporate
/// proxy whose CA the OS (or `SSL_CERT_FILE`) trusts works here too.
/// Certificate verification is never relaxed: an issuer neither set
/// trusts still fails the handshake ([`BundledThenPlatform`]).
///
/// The TLS config is built once per process and shared, so a client costs
/// no more to build than reqwest's own default. Callers add their own
/// headers, timeouts and redirect policy. A text ratchet test
/// (`no_client_is_built_outside_client_builder`) fails if production code
/// builds a client any other way.
pub fn client_builder() -> reqwest::ClientBuilder {
    static CONFIG: OnceLock<rustls::ClientConfig> = OnceLock::new();
    let config = CONFIG.get_or_init(|| tls_config(Box::new(load_configured_roots)));
    reqwest::Client::builder().use_preconfigured_tls(config.clone())
}

type RootLoader = Box<dyn Fn() -> Vec<CertificateDer<'static>> + Send + Sync>;

/// The rustls config every client shares: ring (the provider reqwest's
/// `rustls-tls` already builds), TLS 1.2 and 1.3, HTTP/1.1 ALPN (reqwest is
/// built without HTTP/2), and the [`BundledThenPlatform`] verifier.
fn tls_config(platform_roots: RootLoader) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = BundledThenPlatform::new(provider.clone(), platform_roots);
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Full webpki verification against the bundled roots first and, only
/// when that fails with `UnknownIssuer`, against the platform roots. The
/// result is the union of both trust sets, while the platform store (a
/// keychain query, or a few hundred PEM files on Linux) is read only by a
/// run that actually meets a certificate the bundled roots don't know, and
/// then once per process. Every other verification failure (expiry, wrong
/// host, bad signature) is returned unchanged.
struct BundledThenPlatform {
    provider: Arc<CryptoProvider>,
    bundled: Arc<WebPkiServerVerifier>,
    platform: OnceLock<Option<Arc<WebPkiServerVerifier>>>,
    platform_roots: RootLoader,
}

impl std::fmt::Debug for BundledThenPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundledThenPlatform")
            .field("platform_loaded", &self.platform.get().is_some())
            .finish_non_exhaustive()
    }
}

impl BundledThenPlatform {
    fn new(provider: Arc<CryptoProvider>, platform_roots: RootLoader) -> Self {
        let bundled = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        BundledThenPlatform {
            bundled: verifier_for(bundled, &provider)
                .expect("the bundled webpki roots form a valid verifier"),
            provider,
            platform: OnceLock::new(),
            platform_roots,
        }
    }

    /// The platform-root verifier, loaded on first use. Native stores often
    /// carry a few certificates rustls can't parse; those are skipped. An
    /// empty or unreadable store yields `None` (bundled roots only).
    fn platform(&self) -> Option<&WebPkiServerVerifier> {
        self.platform
            .get_or_init(|| {
                let mut store = RootCertStore::empty();
                store.add_parsable_certificates((self.platform_roots)());
                if store.is_empty() {
                    return None;
                }
                verifier_for(store, &self.provider)
            })
            .as_deref()
    }
}

fn verifier_for(
    roots: RootCertStore,
    provider: &Arc<CryptoProvider>,
) -> Option<Arc<WebPkiServerVerifier>> {
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .ok()
}

impl ServerCertVerifier for BundledThenPlatform {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verify = |v: &WebPkiServerVerifier| {
            v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        };
        match verify(&self.bundled) {
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
                match self.platform() {
                    Some(platform) => verify(platform),
                    None => Err(rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    )),
                }
            }
            verdict => verdict,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Read the platform trust store through `rustls-native-certs`, which uses
/// `SSL_CERT_FILE` / `SSL_CERT_DIR` when set and the OS store (keychain on
/// macOS, the system store on Windows, the distro bundle on Linux)
/// otherwise. A store that can't be read leaves the bundled roots only.
fn load_configured_roots() -> Vec<CertificateDer<'static>> {
    rustls_native_certs::load_native_certs().certs
}

/// Why [`read_capped_typed`] gave up — typed so a caller can tell a body cut
/// off mid-transfer (a transport failure, worth a retry) from a cap breach
/// (the same bytes would breach it again) without matching on wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadCappedError {
    /// The body stream failed before it ended (connection reset, timeout,
    /// truncated `Content-Length`, …).
    Truncated(String),
    /// The declared or streamed size exceeded the cap.
    CapExceeded(String),
}

impl std::fmt::Display for ReadCappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(m) | Self::CapExceeded(m) => f.write_str(m),
        }
    }
}

/// Stream a response body into memory with a hard byte cap, rejecting both
/// an over-large declared `Content-Length` and an actual stream that
/// exceeds the cap mid-flight. `what` names the payload in error messages
/// ("vendor package", "release archive", …).
pub(crate) async fn read_capped(
    resp: reqwest::Response,
    max: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    read_capped_typed(resp, max, what)
        .await
        .map_err(|e| e.to_string())
}

/// [`read_capped`] with a typed error.
pub(crate) async fn read_capped_typed(
    mut resp: reqwest::Response,
    max: u64,
    what: &str,
) -> Result<Vec<u8>, ReadCappedError> {
    if let Some(len) = resp.content_length() {
        if len > max {
            return Err(ReadCappedError::CapExceeded(format!(
                "{what} too large: declared {len} bytes > {max} cap"
            )));
        }
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ReadCappedError::Truncated(format!("error reading {what} body: {e}")))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > max {
            return Err(ReadCappedError::CapExceeded(format!(
                "{what} exceeded {max}-byte cap mid-stream"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve one raw HTTP/1.1 response on loopback and return a response
    /// whose body is still unread.
    async fn respond_raw(raw: &'static [u8]) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match tcp.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tcp.write_all(raw).await;
            let _ = tcp.shutdown().await;
        });
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn declared_content_length_over_cap_is_refused() {
        let resp =
            respond_raw(b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\nconnection: close\r\n\r\n")
                .await;
        assert_eq!(
            read_capped_typed(resp, 16, "test payload").await,
            Err(ReadCappedError::CapExceeded(
                "test payload too large: declared 64 bytes > 16 cap".into()
            ))
        );
    }

    /// A chunked body declares no length, so only the streamed count
    /// catches it.
    #[tokio::test]
    async fn streamed_body_over_cap_is_refused_mid_stream() {
        let resp = respond_raw(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n\
              a\r\n0123456789\r\na\r\n0123456789\r\n0\r\n\r\n",
        )
        .await;
        assert_eq!(resp.content_length(), None);
        assert_eq!(
            read_capped_typed(resp, 16, "test payload").await,
            Err(ReadCappedError::CapExceeded(
                "test payload exceeded 16-byte cap mid-stream".into()
            ))
        );
    }

    #[tokio::test]
    async fn body_cut_short_of_its_content_length_is_truncated() {
        let resp =
            respond_raw(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nhello")
                .await;
        let err = read_capped_typed(resp, 16, "test payload")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ReadCappedError::Truncated(m) if m.starts_with("error reading test payload body: ")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn body_within_cap_reads_fully() {
        let resp =
            respond_raw(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello")
                .await;
        assert_eq!(
            read_capped(resp, 16, "test payload").await.unwrap(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn exact_cap_boundary_is_allowed() {
        let resp = respond_raw(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n\
              10\r\n0123456789abcdef\r\n0\r\n\r\n",
        )
        .await;
        assert_eq!(
            read_capped_typed(resp, 16, "test payload").await.unwrap(),
            b"0123456789abcdef"
        );
    }

    // `tests/tls-ca/` holds a private CA (`ca.pem`) and a leaf for
    // 127.0.0.1 it signed (`leaf.pem` + `leaf.key`, P-256, valid for a
    // century): the shape of a TLS-inspecting proxy's re-signed traffic.

    const TLS_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls-ca");

    fn pem_blocks(pem: &str) -> Vec<Vec<u8>> {
        use base64::Engine as _;
        let mut out = Vec::new();
        let mut body: Option<String> = None;
        for line in pem.lines() {
            let line = line.trim();
            if line.starts_with("-----BEGIN") {
                body = Some(String::new());
            } else if line.starts_with("-----END") {
                let b = body.take().expect("END without BEGIN");
                out.push(base64::engine::general_purpose::STANDARD.decode(b).unwrap());
            } else if let Some(b) = body.as_mut() {
                b.push_str(line);
            }
        }
        out
    }

    /// Serve `ok` over TLS with the CA-signed leaf on 127.0.0.1; returns
    /// the base URL.
    async fn spawn_tls_server() -> String {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls;

        let read = |name: &str| std::fs::read_to_string(format!("{TLS_FIXTURES}/{name}")).unwrap();
        let certs = pem_blocks(&read("leaf.pem"))
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect::<Vec<_>>();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(pem_blocks(&read("leaf.key")).remove(0).into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        format!("https://{addr}/")
    }

    /// Run `f` with `SSL_CERT_FILE` set to `file` and `SSL_CERT_DIR`
    /// cleared, restoring both afterwards.
    fn with_cert_env<T>(file: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let saved = (
            std::env::var_os("SSL_CERT_FILE"),
            std::env::var_os("SSL_CERT_DIR"),
        );
        std::env::set_var("SSL_CERT_FILE", file);
        std::env::remove_var("SSL_CERT_DIR");
        let out = f();
        match saved.0 {
            Some(v) => std::env::set_var("SSL_CERT_FILE", v),
            None => std::env::remove_var("SSL_CERT_FILE"),
        }
        if let Some(v) = saved.1 {
            std::env::set_var("SSL_CERT_DIR", v);
        }
        out
    }

    /// A client using the shared verifier design with `roots` standing in
    /// for the platform store; `loads` counts platform-store reads.
    fn client_with(
        roots: Vec<CertificateDer<'static>>,
        loads: Arc<std::sync::atomic::AtomicUsize>,
    ) -> reqwest::Client {
        let config = tls_config(Box::new(move || {
            loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            roots.clone()
        }));
        // `no_proxy`: a sandbox HTTPS_PROXY must not intercept loopback.
        reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .no_proxy()
            .build()
            .unwrap()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn client_trusts_a_private_ca_named_by_ssl_cert_file() {
        let url = spawn_tls_server().await;
        let ca = std::path::Path::new(TLS_FIXTURES).join("ca.pem");
        let roots = with_cert_env(&ca, load_configured_roots);
        assert_eq!(roots.len(), 1, "SSL_CERT_FILE's one CA is loaded");
        let loads = Arc::default();
        let client = client_with(roots, Arc::clone(&loads));
        for _ in 0..2 {
            let resp = client.get(&url).send().await.unwrap();
            assert_eq!(resp.status(), 200);
            assert_eq!(resp.text().await.unwrap(), "ok");
        }
        assert_eq!(
            loads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the platform store is read once, on the first unknown issuer"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn client_without_the_private_ca_fails_with_unknown_issuer() {
        let url = spawn_tls_server().await;
        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let roots = with_cert_env(&empty, load_configured_roots);
        assert!(roots.is_empty());
        let err = client_with(roots, Arc::default())
            .get(&url)
            .send()
            .await
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("UnknownIssuer"),
            "verification must stay on: {err:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn unparsable_platform_roots_are_skipped_not_fatal() {
        let url = spawn_tls_server().await;
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle.pem");
        let ca = std::fs::read_to_string(format!("{TLS_FIXTURES}/ca.pem")).unwrap();
        // A syntactically valid PEM block whose DER is not a certificate.
        std::fs::write(
            &bundle,
            format!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{ca}"),
        )
        .unwrap();
        let roots = with_cert_env(&bundle, load_configured_roots);
        let resp = client_with(roots, Arc::default())
            .get(&url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "the usable root still verifies");
    }

    /// reqwest refuses a rustls config from a different rustls build at
    /// `build()`, so this fails if the shared config stops matching.
    #[test]
    fn production_builder_accepts_the_shared_tls_config() {
        client_builder().build().unwrap();
        client_builder().build().unwrap();
    }

    /// Ratchet: production code builds every `reqwest::Client` through
    /// [`client_builder`], so each one gets the same trust roots.
    #[test]
    fn no_client_is_built_outside_client_builder() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let forbidden = regex::Regex::new(
            r"(^|[^A-Za-z0-9_])(Client::builder|Client::new|ClientBuilder::new)\(",
        )
        .unwrap();
        let mut offenders = Vec::new();
        for krate in ["socket-patch-core", "socket-patch-cli", "socket-patch-node"] {
            let src = crates.join(krate).join("src");
            for entry in walkdir::WalkDir::new(&src) {
                let entry = entry.unwrap();
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy();
                if path.extension().is_none_or(|e| e != "rs")
                    || name == "tests.rs"
                    || name.ends_with("_tests.rs")
                    || path.components().any(|c| {
                        let c = c.as_os_str();
                        c == "tests" || c == "test_support"
                    })
                    || path.ends_with("utils/http.rs")
                {
                    continue;
                }
                let text = std::fs::read_to_string(path).unwrap();
                let mut in_test_mod = false;
                let mut prev_cfg_test = false;
                for (i, line) in text.lines().enumerate() {
                    if in_test_mod {
                        if line == "}" {
                            in_test_mod = false;
                        }
                        continue;
                    }
                    if prev_cfg_test && line.starts_with("mod ") && line.ends_with('{') {
                        in_test_mod = true;
                        continue;
                    }
                    prev_cfg_test = line.trim() == "#[cfg(test)]";
                    if forbidden.is_match(line) {
                        offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "build reqwest clients with utils::http::client_builder():\n{}",
            offenders.join("\n")
        );
    }
}
