//! Composer reinstall hints for the human output of vendored and hosted runs.
//!
//! Both modes rewire `composer.lock` only: the installed `vendor/` tree keeps
//! the unpatched bytes until Composer reinstalls the package. Composer 2
//! reinstalls a locked package whose dist changed on the next `composer
//! install`; Composer 1 does not, so its `vendor/<vendor>/<name>` must be
//! removed first.

use serde_json::Value;

const VENDOR_PREFIX: &str = ".socket/vendor/composer/";

/// The `<vendor>/<name>` of every composer.lock package (`packages` and
/// `packages-dev`) whose dist is a vendored `path` copy, sorted and
/// de-duplicated. An unparseable lock yields nothing.
pub(crate) fn vendored_composer_packages(lock_text: &str) -> Vec<String> {
    let Ok(lock) = serde_json::from_str::<Value>(lock_text) else {
        return Vec::new();
    };
    let mut names: Vec<String> = ["packages", "packages-dev"]
        .iter()
        .filter_map(|section| lock.get(section)?.as_array())
        .flatten()
        .filter(|entry| {
            let dist = &entry["dist"];
            dist["type"].as_str() == Some("path")
                && dist["url"].as_str().is_some_and(|url| {
                    let url = url.replace('\\', "/");
                    let url = url.strip_prefix("file:").unwrap_or(&url);
                    url.strip_prefix("./")
                        .unwrap_or(url)
                        .starts_with(VENDOR_PREFIX)
                })
        })
        .filter_map(|entry| Some(entry["name"].as_str()?.to_lowercase()))
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The lines to print after a vendored run that left `packages` wired, or
/// nothing when none are.
pub(crate) fn vendored_reinstall_hints(packages: &[String]) -> Vec<String> {
    if packages.is_empty() {
        return Vec::new();
    }
    let dirs: Vec<String> = packages.iter().map(|p| format!("vendor/{p}")).collect();
    vec![
        "Run `composer install` to update vendor/ — vendoring rewires composer.lock only, so \
         the installed vendor/ tree keeps the unpatched bytes until Composer reinstalls it."
            .to_string(),
        format!(
            "Composer 1 does not reinstall a locked package whose dist changed: remove {} \
             first, then run `composer install`.",
            dirs.join(", ")
        ),
    ]
}

/// The reinstall example for a hosted run's next steps when it rewrote
/// `composer.lock`.
pub(crate) fn hosted_reinstall_hint(files: &[String]) -> Option<&'static str> {
    files.iter().any(|f| f == "composer.lock").then_some(
        " (e.g. `composer install`; on Composer 1 first remove the patched packages' \
         vendor/<vendor>/<name> directories)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn lock() -> String {
        serde_json::json!({
            "packages": [
                {"name": "Psr/Log", "version": "3.0.2", "dist": {
                    "type": "path",
                    "url": format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2"),
                    "reference": UUID}},
                {"name": "acme/own", "version": "1.0.0", "dist": {
                    "type": "path", "url": "packages/own"}},
                {"name": "acme/zip", "version": "1.0.0", "dist": {
                    "type": "zip",
                    "url": format!("https://x/.socket/vendor/composer/{UUID}/a")}},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "10.0.0", "dist": {
                    "type": "path",
                    "url": format!("file:./.socket\\vendor\\composer\\{UUID}\\phpunit/phpunit@10.0.0")}},
            ],
        })
        .to_string()
    }

    #[test]
    fn only_vendored_path_dists_are_listed() {
        assert_eq!(
            vendored_composer_packages(&lock()),
            vec!["phpunit/phpunit".to_string(), "psr/log".to_string()]
        );
        assert!(vendored_composer_packages("not json").is_empty());
        assert!(vendored_composer_packages("{}").is_empty());
    }

    #[test]
    fn vendored_hints_name_every_package_dir() {
        assert!(vendored_reinstall_hints(&[]).is_empty());
        let hints = vendored_reinstall_hints(&["a/b".to_string(), "c/d".to_string()]);
        assert_eq!(hints.len(), 2);
        assert!(
            hints[0].starts_with("Run `composer install`"),
            "{}",
            hints[0]
        );
        assert!(
            hints[1].contains("remove vendor/a/b, vendor/c/d first"),
            "{}",
            hints[1]
        );
    }

    #[test]
    fn hosted_hint_needs_a_rewritten_composer_lock() {
        assert!(hosted_reinstall_hint(&["package-lock.json".to_string()]).is_none());
        let hint = hosted_reinstall_hint(&["composer.lock".to_string()]).unwrap();
        assert!(hint.contains("composer install") && hint.contains("Composer 1"));
    }
}
