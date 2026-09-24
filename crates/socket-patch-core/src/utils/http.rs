//! Small shared HTTP primitives.

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
}
