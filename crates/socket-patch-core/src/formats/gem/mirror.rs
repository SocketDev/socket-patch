//! Whether a Bundler mirror setting captures the per-dep patch-registry
//! `source` block the hosted gem redirect writes (#681).
//!
//! `Bundler::Settings::Mirrors#for(uri)` returns the `mirror.all` mirror
//! for EVERY source when one is set, else the mirror configured for that
//! exact (trailing-slash normalized) source URI. A mirror (an Artifactory
//! or Nexus rubygems proxy, say) serves the upstream gem for the same
//! name and version, so a captured redirect installs the unpatched bytes
//! (or fails the lock's `CHECKSUMS`) while the run would report the gem
//! redirected. The hosted intake refuses the gem redirect instead.
//!
//! Settings are read the way `Bundler::Settings` reads them: the app
//! config file (`BUNDLE_MIRROR__ALL:`, or the key `bundle config set
//! --local mirror.<uri> <url>` writes) outranks the environment's
//! `BUNDLE_MIRROR__ALL`. The model is pure: the disk and environment reads
//! live in [`crate::crawlers::ruby_crawler::bundler_source_mirror`].

use crate::crawlers::ruby_crawler::{bundle_config_setting, unquote_bundle_config_value};

/// The app config key for `mirror.all`.
const MIRROR_ALL_KEY: &str = "BUNDLE_MIRROR__ALL";

/// The app config key Bundler stores `mirror.<source>` under
/// (`Bundler::Settings.key_for`: the URI normalized to end in `/`, `.` as
/// `__`, `-` as `___`, upcased).
fn mirror_key_for(source: &str) -> String {
    let mut uri = source.to_string();
    if !uri.ends_with('/') {
        uri.push('/');
    }
    format!(
        "BUNDLE_MIRROR__{}",
        uri.replace('.', "__").replace('-', "___").to_uppercase()
    )
}

/// Whether `contents` sets the per-source mirror key for `source` to a
/// non-empty value. The key itself holds `:` (`HTTPS://…`), so a line
/// matches only when the exact key is followed by the YAML separator.
fn config_mirrors_source(contents: &str, source: &str) -> bool {
    let key = mirror_key_for(source);
    let mut found = false;
    for line in contents.lines() {
        if let Some(rest) = line
            .strip_prefix(key.as_str())
            .and_then(|r| r.strip_prefix(':'))
        {
            if rest.is_empty() || rest.starts_with([' ', '\t']) {
                found = !unquote_bundle_config_value(rest).is_empty();
            }
        }
    }
    found
}

/// The mirror setting that captures one of `sources`, described for the
/// refusal's detail; `None` when Bundler fetches every source directly.
///
/// `config` is the app config file's text (`None` when absent or ignored
/// via `BUNDLE_IGNORE_CONFIG`), `env_all` the environment's
/// `BUNDLE_MIRROR__ALL`.
pub fn capturing_mirror(
    config: Option<&str>,
    env_all: Option<&str>,
    sources: &[&str],
) -> Option<String> {
    if let Some(url) = config.and_then(|text| bundle_config_setting(text, MIRROR_ALL_KEY)) {
        return Some(format!(
            "bundler's `mirror.all` ({url}) in the project's bundler config"
        ));
    }
    if let Some(url) = env_all.map(str::trim).filter(|v| !v.is_empty()) {
        return Some(format!(
            "bundler's `mirror.all` ({url}) from the BUNDLE_MIRROR__ALL environment variable"
        ));
    }
    let text = config?;
    sources
        .iter()
        .find(|source| config_mirrors_source(text, source))
        .map(|source| {
            format!("a bundler `mirror.{source}` setting in the project's bundler config")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "https://patch.socket.dev/gem/tok-1/0a1b-2c/";

    #[test]
    fn mirror_all_in_the_app_config_captures_every_source() {
        let cfg = "---\nBUNDLE_MIRROR__ALL: \"https://artifactory.example/api/gems/rubygems/\"\n";
        let d = capturing_mirror(Some(cfg), None, &[SRC]).unwrap();
        assert!(d.contains("mirror.all"), "{d}");
        assert!(d.contains("artifactory.example"), "{d}");
        // Even with no gem source to compare: `all` matches any URI.
        assert!(capturing_mirror(Some(cfg), None, &[]).is_some());
    }

    #[test]
    fn mirror_all_from_the_environment_captures_every_source() {
        let d = capturing_mirror(None, Some("https://nexus.example/rubygems/"), &[SRC]).unwrap();
        assert!(d.contains("BUNDLE_MIRROR__ALL"), "{d}");
        // An empty value is unset.
        assert_eq!(capturing_mirror(None, Some(""), &[SRC]), None);
    }

    #[test]
    fn a_mirror_scoped_to_rubygems_org_leaves_the_patch_registry_alone() {
        let cfg = "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://mirror.example/\"\n\
                   BUNDLE_MIRROR__ALL__FALLBACK_TIMEOUT: \"3\"\n";
        assert_eq!(capturing_mirror(Some(cfg), None, &[SRC]), None);
        assert_eq!(capturing_mirror(None, None, &[SRC]), None);
    }

    #[test]
    fn a_mirror_for_the_patch_registry_source_captures_it() {
        let key = mirror_key_for(SRC);
        assert_eq!(
            key,
            "BUNDLE_MIRROR__HTTPS://PATCH__SOCKET__DEV/GEM/TOK___1/0A1B___2C/"
        );
        let cfg = format!("---\n{key}: \"https://mirror.example/\"\n");
        let d = capturing_mirror(Some(&cfg), None, &[SRC]).unwrap();
        assert!(d.contains(SRC), "{d}");
        // Bundler normalizes the URI to end in `/`.
        let bare = SRC.trim_end_matches('/');
        assert!(capturing_mirror(Some(&cfg), None, &[bare]).is_some());
        // A longer key sharing the prefix (the fallback timeout) is not it.
        let cfg = format!(
            "---\n{}FALLBACK_TIMEOUT: \"3\"\n",
            key.trim_end_matches('/')
        );
        assert_eq!(capturing_mirror(Some(&cfg), None, &[SRC]), None);
    }

    #[test]
    fn the_app_config_outranks_the_environment_in_the_detail() {
        let cfg = "---\nBUNDLE_MIRROR__ALL: \"https://a.example/\"\n";
        let d = capturing_mirror(Some(cfg), Some("https://b.example/"), &[SRC]).unwrap();
        assert!(d.contains("a.example"), "{d}");
    }
}
