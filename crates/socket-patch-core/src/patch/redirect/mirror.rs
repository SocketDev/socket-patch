//! A mirror of Socket's patch server: the base URL of a caching proxy the
//! operator runs in front of it (an Artifactory or Nexus remote repository,
//! a reverse proxy), given with `--patch-mirror-url`.
//!
//! The mirror serves the patch server's own paths under its base, so a
//! hosted reference moves onto it by swapping everything before the path:
//!
//! ```text
//! https://patch.socket.dev/patch/npm/left-pad/1.3.0/<token>/<uuid>/left-pad-1.3.0.tgz
//! https://repo.example/artifactory/socket-patch/patch/npm/left-pad/1.3.0/<token>/<uuid>/left-pad-1.3.0.tgz
//! ```
//!
//! The path, and with it the grant token and the patch uuid, is unchanged,
//! which is what lets every reader recover the patch from a mirrored
//! reference exactly as from a direct one (`crate::origin`), once the
//! mirror's origin is one of the run's configured patch-server origins.
//!
//! The base is operator configuration (a flag or an environment variable),
//! never repository content: it names where every later install fetches
//! from, and which host's references `vex` attests.

/// The base URL of a patch-server mirror, validated and without a trailing
/// slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchMirror {
    base: String,
}

/// Bound on the base: a mirrored URL is the base plus a served path, and
/// the whole must stay inside the grant gate's URL bound.
const MAX_BASE: usize = 1024;

impl PatchMirror {
    /// Parse the operator's base URL. It is spliced in front of served
    /// paths and written into files the project commits, so it is held to
    /// the same character set as a grant's URLs (`grant::is_url_char`) and
    /// may carry neither credentials, a query nor a fragment: a lockfile is
    /// no place for a password, and a query or fragment would end up in the
    /// middle of the mirrored URL.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let base = trimmed.trim_end_matches('/');
        if base.is_empty() {
            return Err("it is empty".to_string());
        }
        if base.len() > MAX_BASE {
            return Err(format!("it is longer than {MAX_BASE} bytes"));
        }
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err("it is not an http(s) URL".to_string());
        }
        if !base.chars().all(super::grant::is_url_char) {
            return Err(
                "it holds a character that cannot be written into a lockfile URL".to_string(),
            );
        }
        if base.contains('?') {
            return Err("it carries a query string".to_string());
        }
        // A percent-encoded `/` or `\` in the base would end up in every
        // mirrored URL, and no reader takes such a URL as a hosted
        // reference (`origin::hosted_patch_uuid`).
        let lower = base.to_ascii_lowercase();
        if lower.contains("%2f") || lower.contains("%5c") {
            return Err("it holds a percent-encoded slash".to_string());
        }
        // The authority as written: the URL parser skips extra slashes
        // after an `http(s)` scheme, so `https:///x` would name host `x`.
        let authority = base
            .split_once("://")
            .map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
        let parsed = reqwest::Url::parse(base).map_err(|_| "it is not a valid URL".to_string())?;
        if authority.is_empty() || parsed.host_str().is_none_or(str::is_empty) {
            return Err("it names no host".to_string());
        }
        if authority.contains('@') || !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(
                "it carries credentials; a mirrored URL is committed with the lockfile".to_string(),
            );
        }
        // The parser reads `\` as `/` and drops tabs; the character check
        // above already refused both, so the text is what the parser saw.
        Ok(PatchMirror {
            base: base.to_string(),
        })
    }

    /// The base URL, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `url` moved onto the mirror: the base in place of its scheme and
    /// authority, its path (and query) byte for byte. `None` for anything
    /// but an `http(s)` URL with a path.
    pub fn rebase(&self, url: &str) -> Option<String> {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let path_at = rest.find('/')?;
        let (authority, path) = rest.split_at(path_at);
        if authority.is_empty() || path.len() < 2 {
            return None;
        }
        Some(format!("{}{path}", self.base))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVED: &str = "https://patch.socket.dev/patch/npm/@scope/pkg/1.0.0/\
        11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/pkg-1.0.0.tgz";

    #[test]
    fn a_base_is_kept_without_its_trailing_slashes() {
        let mirror = PatchMirror::parse(" https://repo.example/artifactory/socket-patch// ")
            .expect("valid base");
        assert_eq!(
            mirror.base(),
            "https://repo.example/artifactory/socket-patch"
        );
        // A bare origin is a base too (a reverse proxy at the root).
        assert_eq!(
            PatchMirror::parse("http://127.0.0.1:8081/")
                .expect("valid")
                .base(),
            "http://127.0.0.1:8081"
        );
    }

    #[test]
    fn a_base_that_cannot_prefix_a_committed_url_is_refused() {
        for (raw, why) in [
            ("", "empty"),
            ("   ", "empty"),
            ("repo.example/artifactory", "http(s)"),
            ("ftp://repo.example/x", "http(s)"),
            ("https://user:secret@repo.example/x", "credentials"),
            ("https://user@repo.example/x", "credentials"),
            ("https://@repo.example/x", "credentials"),
            ("https://repo.example/a%2Fb", "percent-encoded"),
            ("https://repo.example/a%5cb", "percent-encoded"),
            ("https://repo.example/x?repo=y", "query"),
            ("https://repo.example/x#frag", "character"),
            ("https://repo.example/a b", "character"),
            ("https://repo.example/${HOME}", "character"),
            ("https://repo.example/\"x", "character"),
            ("https:///x", "host"),
        ] {
            let err = PatchMirror::parse(raw).expect_err(raw);
            assert!(err.contains(why), "{raw:?}: {err}");
        }
        assert!(PatchMirror::parse(&format!("https://h/{}", "a".repeat(MAX_BASE))).is_err());
    }

    #[test]
    fn rebase_swaps_everything_before_the_path_and_nothing_after_it() {
        let mirror = PatchMirror::parse("https://repo.example/artifactory/socket-patch").unwrap();
        assert_eq!(
            mirror.rebase(SERVED).as_deref(),
            Some(
                "https://repo.example/artifactory/socket-patch/patch/npm/@scope/pkg/1.0.0/\
                 11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/\
                 pkg-1.0.0.tgz"
            )
        );
        // The path is copied, never re-encoded; a port and a plain-http
        // served origin make no difference.
        assert_eq!(
            mirror
                .rebase("http://127.0.0.1:4026/patch-registry/gem/t/u/info/%40x?y=1")
                .as_deref(),
            Some("https://repo.example/artifactory/socket-patch/patch-registry/gem/t/u/info/%40x?y=1")
        );
        // A registry base with a trailing slash keeps it.
        assert_eq!(
            mirror
                .rebase("https://patch.socket.dev/patch-registry/gem/t/u/")
                .as_deref(),
            Some("https://repo.example/artifactory/socket-patch/patch-registry/gem/t/u/")
        );
    }

    #[test]
    fn rebase_refuses_what_is_not_a_served_url() {
        let mirror = PatchMirror::parse("https://repo.example/m").unwrap();
        for url in [
            "",
            "patch.socket.dev/patch/npm/x",
            "sparse+https://patch.socket.dev/patch-registry/cargo/t/u/index/",
            "https://patch.socket.dev",
            "https://patch.socket.dev/",
            "https:///patch/npm/x",
            "file:.socket/vendor/npm/u/x-1.0.0.tgz",
        ] {
            assert_eq!(mirror.rebase(url), None, "{url:?}");
        }
    }

    #[test]
    fn a_rebased_reference_names_the_same_patch_on_the_mirror_origin() {
        let mirror = PatchMirror::parse("https://repo.example/artifactory/socket-patch").unwrap();
        let mirrored = mirror.rebase(SERVED).unwrap();
        let origins = [mirror.base().to_string()];
        assert_eq!(
            crate::origin::hosted_patch_uuid(&mirrored, &origins).as_deref(),
            Some("22222222-2222-4222-8222-222222222222")
        );
        // Without the mirror among the run's origins it is no reference.
        assert_eq!(crate::origin::hosted_patch_uuid(&mirrored, &[]), None);
        assert_eq!(
            super::super::grant_token_path_segment(
                &mirrored,
                "22222222-2222-4222-8222-222222222222"
            )
            .as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
    }
}
