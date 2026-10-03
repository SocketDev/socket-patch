//! Transport bounds on the patch API (`socket_patch_core::api::retry::
//! ApiTimeouts`), end to end against a local TCP server that accepts a
//! connection, reads the request and never answers (#570).
//!
//! Each former unbounded path — the JSON calls (`fetch_patch`, the batch
//! search) and the blob/diff downloads, on the authenticated client and on
//! the plain public-proxy client — must fail as `ApiError::Network` within
//! the client's (shortened) read bound instead of hanging. A body that keeps
//! streaming for longer than the bound must still arrive whole: the bound is
//! on silence, not on the total transfer.

use std::time::{Duration, Instant};

use socket_patch_core::api::client::{ApiClient, ApiClientOptions, ApiError};
use socket_patch_core::api::retry::{
    ApiRetryPolicy, ApiTimeouts, RetryHooks, API_CONNECT_TIMEOUT, API_READ_TIMEOUT,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const UUID: &str = "11111111-2222-4333-8444-555555555555";

/// The test bound on one silent read.
const READ: Duration = Duration::from_millis(300);
/// How long a bounded call may take in total before the test calls it a
/// hang (generous: CI runners are slow, an unbounded call never returns).
const GUARD: Duration = Duration::from_secs(20);

/// A server that accepts every connection, reads what the client sends and
/// never writes a byte. Returns its base URL.
async fn stalled_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Drain the request, then hold the connection open, silent.
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    format!("http://{addr}")
}

/// Send successful JSON headers and a partial body, then keep the socket
/// open. This stalls after `send()` has returned, while `json()` reads.
async fn stalled_json_body_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                if sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{")
                    .await
                    .is_err()
                {
                    return;
                }
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    format!("http://{addr}")
}

/// A server that answers `200` with a `total`-byte body, sent in `chunks`
/// pieces `gap` apart (each gap shorter than [`READ`], the sum longer).
async fn trickling_server(total: usize, chunks: usize, gap: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                     content-length: {total}\r\nconnection: close\r\n\r\n"
                );
                if sock.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let piece = total / chunks;
                for i in 0..chunks {
                    tokio::time::sleep(gap).await;
                    let len = if i + 1 == chunks {
                        total - piece * i
                    } else {
                        piece
                    };
                    if sock.write_all(&vec![b'x'; len]).await.is_err() {
                        return;
                    }
                }
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// A client on `uri` (authenticated, or the public proxy) with the short
/// test read bound and JSON retries off.
fn client(uri: &str, proxy: bool) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: uri.to_string(),
        api_token: (!proxy).then(|| "tok".to_string()),
        use_public_proxy: proxy,
        org_slug: (!proxy).then(|| "org".to_string()),
    })
    .with_api_retry(ApiRetryPolicy::none(), RetryHooks::default())
    .with_api_timeouts(ApiTimeouts {
        connect: Duration::from_secs(5),
        read: READ,
    })
}

/// Run `call`, asserting it fails as `ApiError::Network` after the read
/// bound and well before [`GUARD`].
async fn assert_stall_is_network<T: std::fmt::Debug>(
    what: &str,
    call: impl std::future::Future<Output = Result<T, ApiError>>,
) {
    let started = Instant::now();
    let result = tokio::time::timeout(GUARD, call)
        .await
        .unwrap_or_else(|_| panic!("{what} still pending after {GUARD:?}: unbounded"));
    let elapsed = started.elapsed();
    match result {
        Err(ApiError::Network(msg)) => {
            assert!(
                elapsed >= READ,
                "{what} failed after {elapsed:?}, before the {READ:?} bound: {msg}"
            );
        }
        other => panic!("{what}: expected ApiError::Network, got {other:?}"),
    }
}

#[tokio::test]
async fn authenticated_calls_fail_as_network_on_a_stalled_server() {
    let api = client(&stalled_server().await, false);
    assert_stall_is_network("fetch_patch", api.fetch_patch(UUID)).await;
    assert_stall_is_network(
        "search_patches_batch",
        api.search_patches_batch(&["pkg:npm/left-pad@1.3.0".to_string()]),
    )
    .await;
    assert_stall_is_network("fetch_blob", api.fetch_blob(HASH)).await;
    assert_stall_is_network("fetch_diff", api.fetch_diff(UUID)).await;
}

#[tokio::test]
async fn public_proxy_calls_fail_as_network_on_a_stalled_server() {
    // The proxy client sends on the plain (header-free) client, so this
    // covers the second reqwest client.
    let api = client(&stalled_server().await, true);
    assert_stall_is_network("fetch_patch", api.fetch_patch(UUID)).await;
    assert_stall_is_network(
        "search_patches_batch",
        api.search_patches_batch(&["pkg:npm/left-pad@1.3.0".to_string()]),
    )
    .await;
    assert_stall_is_network("fetch_blob", api.fetch_blob(HASH)).await;
    assert_stall_is_network("fetch_diff", api.fetch_diff(UUID)).await;
}

#[tokio::test]
async fn stalled_json_bodies_are_network_errors_on_both_clients() {
    let uri = stalled_json_body_server().await;
    let mut errors = Vec::new();
    for proxy in [false, true] {
        let api = client(&uri, proxy);
        let patch = tokio::time::timeout(GUARD, api.fetch_patch(UUID))
            .await
            .expect("stalled patch body must time out")
            .expect_err("partial patch body must fail");
        errors.push((format!("fetch_patch proxy={proxy}"), patch));
        let batch = tokio::time::timeout(
            GUARD,
            api.search_patches_batch(&["pkg:npm/left-pad@1.3.0".to_string()]),
        )
        .await
        .expect("stalled batch body must time out")
        .expect_err("partial batch body must fail");
        errors.push((format!("search_patches_batch proxy={proxy}"), batch));
    }
    assert!(
        errors.iter().all(|(_, error)| matches!(
            error,
            ApiError::Network(message) if message.contains("timed out")
        )),
        "stalled JSON bodies must retain the timeout cause as network errors: {errors:?}"
    );
}

#[tokio::test]
async fn completed_malformed_json_remains_a_parse_error() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    for proxy in [false, true] {
        let api = client(&server.uri(), proxy);
        assert!(matches!(
            api.fetch_patch(UUID).await,
            Err(ApiError::Parse(_))
        ));
        assert!(matches!(
            api.search_patches_batch(&["pkg:npm/left-pad@1.3.0".to_string()])
                .await,
            Err(ApiError::Parse(_))
        ));
    }
}

#[tokio::test]
async fn a_body_that_keeps_streaming_past_the_bound_still_arrives() {
    // 8 chunks 150 ms apart: every silence is under the 300 ms bound, the
    // whole transfer (~1.2 s) is four times it.
    let total = 64 * 1024;
    for proxy in [false, true] {
        let api = client(
            &trickling_server(total, 8, Duration::from_millis(150)).await,
            proxy,
        );
        let started = Instant::now();
        let body = tokio::time::timeout(GUARD, api.fetch_blob(HASH))
            .await
            .expect("trickled blob still pending")
            .expect("a streaming body must not time out")
            .expect("200 is a blob");
        assert_eq!(body.len(), total, "proxy={proxy}");
        assert!(
            started.elapsed() > READ * 3,
            "proxy={proxy}: the body trickled"
        );
    }
}

#[test]
fn default_bounds_are_the_named_constants() {
    let t = ApiTimeouts::default();
    assert_eq!(t.connect, API_CONNECT_TIMEOUT);
    assert_eq!(t.read, API_READ_TIMEOUT);
    assert_eq!(API_CONNECT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(API_READ_TIMEOUT, Duration::from_secs(60));
}
