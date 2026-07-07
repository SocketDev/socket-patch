/// Default path for the patch manifest file relative to the project root.
pub const DEFAULT_PATCH_MANIFEST_PATH: &str = ".socket/manifest.json";

/// Default public patch API URL for free patches (no auth required).
pub const DEFAULT_PATCH_API_PROXY_URL: &str = "https://patches-api.socket.dev";

/// Default Socket API URL for authenticated access.
pub const DEFAULT_SOCKET_API_URL: &str = "https://api.socket.dev";

/// User-Agent header value for API requests.
///
/// The version segment is derived from the crate version at compile time so it
/// tracks the published release (currently `3.x`) instead of drifting from a
/// hardcoded literal. Server-side analytics and any minimum-version gating rely
/// on this reporting the real version.
pub(crate) const USER_AGENT: &str = concat!("SocketPatchCLI/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_reports_real_crate_version() {
        // Regression: USER_AGENT was pinned to "SocketPatchCLI/1.0" while the
        // crate shipped 3.x, so every API request / telemetry beacon misreported
        // the version. It must carry the actual compiled crate version.
        let expected = format!("SocketPatchCLI/{}", env!("CARGO_PKG_VERSION"));
        assert_eq!(USER_AGENT, expected);
        assert!(USER_AGENT.starts_with("SocketPatchCLI/"));
        assert!(
            !USER_AGENT.ends_with("/1.0"),
            "USER_AGENT must not be stuck at the stale 1.0 version"
        );
        // The version segment must be non-empty.
        let version = USER_AGENT.trim_start_matches("SocketPatchCLI/");
        assert!(!version.is_empty(), "version segment must not be empty");
    }

    #[test]
    fn api_urls_are_https_without_trailing_slash() {
        for url in [DEFAULT_PATCH_API_PROXY_URL, DEFAULT_SOCKET_API_URL] {
            assert!(url.starts_with("https://"), "{url} must use https");
            assert!(
                !url.ends_with('/'),
                "{url} must not end with a trailing slash"
            );
        }
        // The proxy and authenticated API are distinct hosts; swapping them
        // would silently send authed traffic to the public proxy (or vice versa).
        assert_ne!(DEFAULT_PATCH_API_PROXY_URL, DEFAULT_SOCKET_API_URL);
        assert_eq!(
            DEFAULT_PATCH_API_PROXY_URL,
            "https://patches-api.socket.dev"
        );
        assert_eq!(DEFAULT_SOCKET_API_URL, "https://api.socket.dev");
    }

    #[test]
    fn manifest_path_is_under_dot_socket() {
        assert_eq!(DEFAULT_PATCH_MANIFEST_PATH, ".socket/manifest.json");
    }
}
