//! Composer reinstall hints for the human output of vendored and hosted runs.
//!
//! Both modes rewire `composer.lock` only: the installed `vendor/` tree keeps
//! the unpatched bytes until Composer reinstalls the package. Composer 2
//! reinstalls a locked package on the next `composer install` only when its
//! version, dist reference or source reference changed. Vendoring sets the
//! dist reference to the patch uuid; a hosted redirect keeps it and drops
//! the entry's `source`, so an entry that had no `source` changes nothing
//! Composer compares. Composer 1 never reinstalls a changed package. In both
//! cases `<vendor-dir>/<vendor>/<name>` must be removed first, where
//! `<vendor-dir>` is the directory Composer installs into
//! (`COMPOSER_VENDOR_DIR`, else `config.vendor-dir`, else the user-level
//! `$COMPOSER_HOME/config.json` `vendor-dir`, else `vendor`): a hint
//! naming `vendor/` in a project that relocated it sends the user to delete
//! a path that does not exist, and `composer install` then leaves the
//! package unpatched.

use std::path::Path;

use serde_json::{Map, Value};
use socket_patch_core::patch::redirect::FileEdit;

/// The project's Composer vendor directory as the hints print it: relative
/// to `cwd` with `/` separators when it lies inside the project (`vendor`,
/// `lib`, `deps/php`), else the absolute path `COMPOSER_VENDOR_DIR` or the
/// user-level config named. A `config.vendor-dir` the crawler refuses
/// (absolute, home-relative, or climbing out of the project) prints as the
/// `<vendor-dir>` placeholder rather than a directory that would be wrong.
pub(crate) fn vendor_dir_label(cwd: &Path) -> String {
    let Some(dir) =
        socket_patch_core::crawlers::composer_crawler::resolve_local_vendor_dir_sync(cwd)
    else {
        return "<vendor-dir>".to_string();
    };
    match dir.strip_prefix(cwd) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        _ => dir.display().to_string(),
    }
}

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
/// `vendor_dir` is the [`vendor_dir_label`] the package dirs are under.
pub(crate) fn vendored_reinstall_hints(packages: &[String], vendor_dir: &str) -> Vec<String> {
    if packages.is_empty() {
        return Vec::new();
    }
    let dirs: Vec<String> = packages
        .iter()
        .map(|p| format!("{vendor_dir}/{p}"))
        .collect();
    vec![
        format!(
            "Run `composer install` to update {vendor_dir}/ — vendoring rewires composer.lock \
             only, so the installed {vendor_dir}/ tree keeps the unpatched bytes until Composer \
             reinstalls it."
        ),
        format!(
            "Composer 1 does not reinstall a locked package whose dist changed: remove {} \
             first, then run `composer install`.",
            dirs.join(", ")
        ),
    ]
}

/// The reinstall example for a hosted run's next steps when it rewrote
/// `composer.lock`. `edits` are the run's rewrite edits: a redirected entry
/// whose edit removed no `source` must have its vendor dir removed on every
/// Composer version. `vendor_dir` is the [`vendor_dir_label`] the package
/// dirs are under.
pub(crate) fn hosted_reinstall_hint(
    files: &[String],
    edits: &[FileEdit],
    vendor_dir: &str,
) -> Option<String> {
    if !files.iter().any(|f| f == "composer.lock") {
        return None;
    }
    let mut unchanged: Vec<String> = edits
        .iter()
        .filter(|e| e.path == "composer.lock" && e.kind == "redirect_composer_dist")
        .filter(|e| !removes_source(e))
        .filter_map(|e| Some(format!("{vendor_dir}/{}", e.key.as_deref()?.to_lowercase())))
        .collect();
    unchanged.sort_unstable();
    unchanged.dedup();
    if unchanged.is_empty() {
        return Some(format!(
            " (e.g. `composer install`; on Composer 1 first remove the patched packages' \
             {vendor_dir}/<vendor>/<name> directories)"
        ));
    }
    Some(format!(
        " (e.g. `composer install`; first remove {} — Composer does not reinstall a package \
         whose lock entry has no `source` when only its dist url changes — and on Composer 1 \
         every other patched package's {vendor_dir}/<vendor>/<name> directory)",
        unchanged.join(", ")
    ))
}

/// Whether a composer dist edit dropped the entry's `source` object, which
/// changes the source reference Composer 2 compares. The recorded fragments
/// are runs of whole entry members, so each parses as an object's body.
fn removes_source(edit: &FileEdit) -> bool {
    let members = |fragment: Option<&Value>| -> Option<Map<String, Value>> {
        serde_json::from_str(&format!("{{{}}}", fragment?.as_str()?)).ok()
    };
    let had = members(edit.original.as_ref())
        .is_some_and(|m| m.get("source").is_some_and(Value::is_object));
    let has = members(edit.new.as_ref()).is_none_or(|m| m.contains_key("source"));
    had && !has
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
        assert!(vendored_reinstall_hints(&[], "vendor").is_empty());
        assert_eq!(
            vendored_reinstall_hints(&["a/b".to_string(), "c/d".to_string()], "vendor"),
            vec![
                "Run `composer install` to update vendor/ — vendoring rewires composer.lock \
                 only, so the installed vendor/ tree keeps the unpatched bytes until Composer \
                 reinstalls it."
                    .to_string(),
                "Composer 1 does not reinstall a locked package whose dist changed: remove \
                 vendor/a/b, vendor/c/d first, then run `composer install`."
                    .to_string(),
            ]
        );
    }

    #[test]
    fn hosted_hint_needs_a_rewritten_composer_lock() {
        assert!(hosted_reinstall_hint(&["package-lock.json".to_string()], &[], "vendor").is_none());
        assert_eq!(
            hosted_reinstall_hint(&["composer.lock".to_string()], &[], "vendor").as_deref(),
            Some(
                " (e.g. `composer install`; on Composer 1 first remove the patched packages' \
                 vendor/<vendor>/<name> directories)"
            )
        );
    }

    fn dist_edit(key: &str, original: &str, new: &str) -> FileEdit {
        FileEdit {
            path: "composer.lock".into(),
            kind: "redirect_composer_dist".into(),
            action: "rewritten".into(),
            key: Some(key.into()),
            original: Some(Value::String(original.into())),
            new: Some(Value::String(new.into())),
        }
    }

    const OLD_DIST: &str =
        r#""dist": {"type": "zip", "url": "https://x/a.zip", "reference": "abc"}"#;
    const NEW_DIST: &str = r#""dist": {"type": "zip", "url": "https://patch/a.zip", "reference": "abc", "shasum": "1111111111111111111111111111111111111111"}"#;

    /// Composer 2 reinstalls a redirected entry because dropping its
    /// `source` changes the source reference; a dist-only entry changes
    /// nothing it compares, so its vendor dir is named for every version.
    #[test]
    fn hosted_hint_names_dist_only_entries_for_every_composer() {
        let files = ["composer.lock".to_string()];
        let with_source = dist_edit(
            "psr/log",
            &format!(r#""source": {{"type": "git", "url": "u", "reference": "abc"}}, {OLD_DIST}"#),
            NEW_DIST,
        );
        let source_after_extra = dist_edit(
            "psr/log",
            &format!(r#"{OLD_DIST}, "extra": {{"source": {{}}}}, "source": {{"type": "git"}}"#),
            &format!(r#"{NEW_DIST}, "extra": {{"source": {{}}}}"#),
        );
        // An edit that drops `source` names no dir beyond the Composer 1 note.
        let composer1_only = hosted_reinstall_hint(&files, &[], "vendor");
        for edits in [vec![with_source.clone()], vec![source_after_extra]] {
            assert_eq!(
                hosted_reinstall_hint(&files, &edits, "vendor"),
                composer1_only
            );
        }

        let dist_only = dist_edit("Acme/Lib", OLD_DIST, NEW_DIST);
        let removing = |dir: &str| {
            format!(
                " (e.g. `composer install`; first remove {dir}/acme/lib — Composer does not \
                 reinstall a package whose lock entry has no `source` when only its dist url \
                 changes — and on Composer 1 every other patched package's \
                 {dir}/<vendor>/<name> directory)"
            )
        };
        let edits = [with_source, dist_only];
        assert_eq!(
            hosted_reinstall_hint(&files, &edits, "vendor"),
            Some(removing("vendor"))
        );
        // A relocated vendor dir is the one named.
        assert_eq!(
            hosted_reinstall_hint(&files, &edits, "lib"),
            Some(removing("lib"))
        );
    }

    /// With `config.vendor-dir: lib` the vendored hints name
    /// `lib/<vendor>/<name>`, the directory Composer installed into.
    #[test]
    fn vendored_hints_name_a_relocated_vendor_dir() {
        let hints = vendored_reinstall_hints(&["acme/tool".to_string()], "lib");
        assert!(
            hints[0].starts_with("Run `composer install` to update lib/ —"),
            "{}",
            hints[0]
        );
        assert!(
            hints[1].ends_with(": remove lib/acme/tool first, then run `composer install`."),
            "{}",
            hints[1]
        );
        assert!(!hints.join("\n").contains("vendor/"), "{hints:?}");
    }

    /// The label follows Composer's own resolution: `config.vendor-dir`
    /// (normalized, `/`-separated) else `vendor`; a refused value prints a
    /// placeholder instead of a wrong path. `COMPOSER_VENDOR_DIR` is left
    /// unset by the test environment, as everywhere in this crate.
    #[test]
    fn vendor_dir_label_follows_config_vendor_dir() {
        let label = |json: Option<&str>| {
            let dir = tempfile::tempdir().unwrap();
            if let Some(json) = json {
                std::fs::write(dir.path().join("composer.json"), json).unwrap();
            }
            vendor_dir_label(dir.path())
        };
        assert_eq!(label(None), "vendor");
        assert_eq!(label(Some("{}")), "vendor");
        assert_eq!(label(Some(r#"{"config":{"vendor-dir":"lib"}}"#)), "lib");
        assert_eq!(
            label(Some(r#"{"config":{"vendor-dir":"./deps\\php/"}}"#)),
            "deps/php"
        );
        assert_eq!(
            label(Some(r#"{"config":{"vendor-dir":"../outside"}}"#)),
            "<vendor-dir>"
        );
        // Composer would expand `~/`: the literal `<cwd>/~/deps` is wrong.
        assert_eq!(
            label(Some(r#"{"config":{"vendor-dir":"~/deps"}}"#)),
            "<vendor-dir>"
        );
    }
}
