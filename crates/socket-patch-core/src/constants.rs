/// Default path for the patch manifest file relative to the project root.
pub const DEFAULT_PATCH_MANIFEST_PATH: &str = ".socket/manifest.json";

/// Default public patch API URL for free patches (no auth required).
pub const DEFAULT_PATCH_API_PROXY_URL: &str = "https://patches-api.socket.dev";

/// Default Socket API URL for authenticated access.
pub const DEFAULT_SOCKET_API_URL: &str = "https://api.socket.dev";

/// User-Agent header value for API requests.
pub const USER_AGENT: &str = "SocketPatchCLI/1.0";
