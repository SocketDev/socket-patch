//! Small shared HTTP primitives.

use std::sync::OnceLock;

/// The one constructor behind every production `reqwest::Client`.
///
/// Trust roots are reqwest's bundled webpki (Mozilla) roots **plus** the
/// configured platform roots ([`configured_roots`]): the OS trust store, or
/// the bundle that `SSL_CERT_FILE` / `SSL_CERT_DIR` name. That is the rule
/// curl, npm, pip and cargo already follow, so a TLS-inspecting corporate
/// proxy whose CA the OS (or `SSL_CERT_FILE`) trusts works here too.
/// Certificate verification is never relaxed: an issuer neither set
/// trusts still fails the handshake.
///
/// Callers add their own headers, timeouts and redirect policy. A text
/// ratchet test (`no_client_is_built_outside_client_builder`) fails if
/// production code builds a client any other way.
pub fn client_builder() -> reqwest::ClientBuilder {
    with_roots(reqwest::Client::builder(), configured_roots())
}

fn with_roots(
    mut builder: reqwest::ClientBuilder,
    roots: &[reqwest::Certificate],
) -> reqwest::ClientBuilder {
    for cert in roots {
        builder = builder.add_root_certificate(cert.clone());
    }
    builder
}

/// The platform roots, loaded once per process: the native store is read
/// from disk / the keychain, which is too slow to repeat for every client.
fn configured_roots() -> &'static [reqwest::Certificate] {
    static ROOTS: OnceLock<Vec<reqwest::Certificate>> = OnceLock::new();
    ROOTS.get_or_init(load_configured_roots)
}

/// Read the platform trust store through `rustls-native-certs`, which uses
/// `SSL_CERT_FILE` / `SSL_CERT_DIR` when set and the OS store (keychain on
/// macOS, the system store on Windows, the distro bundle on Linux)
/// otherwise. Native stores often carry a few certificates rustls can't
/// parse; each root is screened on its own and an unusable one is skipped,
/// since reqwest would otherwise refuse to build the whole client. A store
/// that can't be read at all leaves only the bundled webpki roots.
fn load_configured_roots() -> Vec<reqwest::Certificate> {
    let loaded = rustls_native_certs::load_native_certs();
    if crate::utils::env_compat::is_debug_enabled() {
        for err in &loaded.errors {
            eprintln!("[socket-patch] could not read platform trust roots: {err}");
        }
    }
    loaded
        .certs
        .into_iter()
        .filter(|der| {
            let mut probe = rustls::RootCertStore::empty();
            probe.add(der.clone()).is_ok()
        })
        .filter_map(|der| reqwest::Certificate::from_der(der.as_ref()).ok())
        .collect()
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
///
/// Hoisted from `api/client.rs` so the self-update downloader shares the
/// exact cap semantics the vendor/artifact fetches already have.
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn get(server: &MockServer, route: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}{route}", server.uri()))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn declared_content_length_over_cap_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 64]))
            .mount(&server)
            .await;
        let resp = get(&server, "/big").await;
        let err = read_capped(resp, 16, "test payload").await.unwrap_err();
        assert!(err.contains("too large"), "{err}");
        assert!(err.contains("test payload"), "{err}");
    }

    #[tokio::test]
    async fn body_within_cap_reads_fully() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
            .mount(&server)
            .await;
        let resp = get(&server, "/ok").await;
        assert_eq!(
            read_capped(resp, 16, "test payload").await.unwrap(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn exact_cap_boundary_is_allowed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/edge"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 16]))
            .mount(&server)
            .await;
        let resp = get(&server, "/edge").await;
        assert_eq!(
            read_capped(resp, 16, "test payload").await.unwrap().len(),
            16
        );
    }

    // ── Trust roots (#1107) ───────────────────────────────────────────
    //
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

    fn client_with(roots: &[reqwest::Certificate]) -> reqwest::Client {
        // `no_proxy`: a sandbox HTTPS_PROXY must not intercept loopback.
        with_roots(reqwest::Client::builder(), roots)
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
        let resp = client_with(&roots).get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
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
        let err = client_with(&roots).get(&url).send().await.unwrap_err();
        assert!(
            format!("{err:?}").contains("UnknownIssuer"),
            "verification must stay on: {err:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn unparsable_platform_roots_are_skipped_not_fatal() {
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
        assert_eq!(roots.len(), 1, "only the usable root survives");
        client_with(&roots);
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
