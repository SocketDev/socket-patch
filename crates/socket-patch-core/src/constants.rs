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

/// The npm-family package managers' shared file-name knowledge.
///
/// npm, pnpm, yarn (classic and berry) and bun spell their lockfiles and
/// layout markers across several subsystems — the vendor flavor probe
/// (`vendor::npm_flavor`), the hosted-redirect candidate list (the CLI's
/// `scan::hosted`), the crawler layout probe (`crawlers::pkg_managers`) and
/// setup's PM detection (`package_json::find`). Those sites accept
/// INTENTIONALLY divergent subsets: hosted redirect deliberately omits
/// `bun.lockb` (it auto-migrates it to `bun.lock` before rewriting), and the
/// `pnpm-lock.yml` spelling is accepted only by setup detection. This table
/// encodes each divergence once, visibly, instead of homogenizing them.
///
/// What is actually guard-tested (equality against the flagged rows):
/// `vendor::npm_flavor`'s wiring-family list, `scan::hosted`'s
/// REDIRECT_CANDIDATE_FILES npm subset, and `package_json::find`'s pnpm
/// markers (plus a hardcoded pin so the table and its consumers cannot
/// shrink together). NOT table-guarded: `crawlers::pkg_managers`' own
/// bun/yarn lockfile literals and `npm_flavor`'s probe decision literals —
/// those are pinned behaviorally by their unit tests instead; only
/// PNP_MARKERS is shared with the crawler.
pub mod npm_family {
    /// One file-name row and the roles in which consumers accept it.
    pub struct FileRow {
        pub name: &'static str,
        /// `vendor::npm_flavor`'s probe recognizes it (wiring family member).
        pub vendor_probe: bool,
        /// `scan::hosted` hands it to `rewrite_registry_redirect`.
        pub redirect_candidate: bool,
        /// `package_json::find::detect_package_manager` treats it as a pnpm
        /// marker.
        pub detects_pnpm: bool,
    }

    pub const FILES: &[FileRow] = &[
        FileRow {
            name: "package-lock.json",
            vendor_probe: true,
            redirect_candidate: true,
            detects_pnpm: false,
        },
        FileRow {
            name: "npm-shrinkwrap.json",
            vendor_probe: true,
            redirect_candidate: true,
            detects_pnpm: false,
        },
        FileRow {
            name: "pnpm-lock.yaml",
            vendor_probe: true,
            redirect_candidate: true,
            detects_pnpm: true,
        },
        // Setup-detection-only spellings: the vendor probe and redirect
        // rewriters have never accepted these, and widening them there is a
        // behavior change to make deliberately, not by table accident.
        FileRow {
            name: "pnpm-lock.yml",
            vendor_probe: false,
            redirect_candidate: false,
            detects_pnpm: true,
        },
        FileRow {
            name: "pnpm-workspace.yaml",
            vendor_probe: false,
            redirect_candidate: false,
            detects_pnpm: true,
        },
        FileRow {
            name: "yarn.lock",
            vendor_probe: true,
            redirect_candidate: true,
            detects_pnpm: false,
        },
        // Berry's cache-config gate: read by the redirect rewriters only.
        FileRow {
            name: ".yarnrc.yml",
            vendor_probe: false,
            redirect_candidate: true,
            detects_pnpm: false,
        },
        FileRow {
            name: "bun.lock",
            vendor_probe: true,
            redirect_candidate: true,
            detects_pnpm: false,
        },
        // The legacy binary lock: the vendor probe knows it (to refuse with
        // the migration hint); hosted redirect deliberately does NOT list it
        // as a candidate — it auto-migrates to bun.lock first.
        FileRow {
            name: "bun.lockb",
            vendor_probe: true,
            redirect_candidate: false,
            detects_pnpm: false,
        },
        // deno.lock is deliberately absent: deno is its own ecosystem
        // (JSR-crawled); no npm-family vendor/redirect/detection path treats
        // deno.lock as an npm lock today. Adding it here is a feature
        // decision, not a spelling fix.
    ];

    /// The names of every row `pick` flags — consumer guard tests compare
    /// their local lists against this.
    pub fn names_with(pick: impl Fn(&FileRow) -> bool) -> Vec<&'static str> {
        FILES.iter().filter(|r| pick(r)).map(|r| r.name).collect()
    }

    /// Yarn Plug'n'Play loader files — any one present means "packages are
    /// not on disk" (crawler must refuse; vendor probe refuses). Yarn 3+
    /// emits `.pnp.cjs`, Yarn 2.x emitted `.pnp.js`, newer installs may add
    /// the ESM `.pnp.loader.mjs`.
    pub const PNP_MARKERS: [&str; 3] = [".pnp.cjs", ".pnp.js", ".pnp.loader.mjs"];

    /// Rush monorepos keep the single pnpm source-of-truth lock here,
    /// relative to the repo root (no root package.json/lock pair).
    pub const RUSH_COMMON_LOCK_REL: &str = "common/config/rush/pnpm-lock.yaml";
}
