pub mod cargo_crawler;
pub mod composer_crawler;
pub mod coursier_cache;
pub mod deno_crawler;
pub mod fuzzy_match;
pub mod go_crawler;
pub mod gradle_cache;
pub mod hatch_env;
pub mod ivy_cache;
pub mod jvm_cache;
mod listing;
pub mod maven_crawler;
#[cfg(test)]
mod maven_pom_equivalence_tests;
pub(crate) mod maven_scope;
pub mod npm_crawler;
pub mod nuget_crawler;
#[cfg(test)]
pub(crate) mod oracle_support;
pub mod pkg_managers;
pub(crate) mod pnpm_layout;
pub mod python_crawler;
pub mod ruby_crawler;
pub mod sbt_evidence;
pub mod scala_evidence;
pub mod types;
pub mod walk_pool;

pub use cargo_crawler::CargoCrawler;
pub use composer_crawler::ComposerCrawler;
pub use deno_crawler::DenoCrawler;
pub use go_crawler::GoCrawler;
pub use maven_crawler::MavenCrawler;
pub use npm_crawler::{bun_uses_global_store, NpmCrawler};
pub use nuget_crawler::NuGetCrawler;
pub use pkg_managers::{detect_npm_pkg_manager, NpmPkgManager, YarnPnpLoader};
pub use python_crawler::PythonCrawler;
pub use ruby_crawler::RubyCrawler;
pub use types::*;

/// ARCHITECTURE GUARD (#592): crawlers read project-tree files only through
/// the FIFO-safe `utils::fs::read_regular_*` readers, so a FIFO planted in a
/// checkout can never wedge `scan`, `get` or `apply` in open(2).
#[cfg(test)]
mod architecture_tests {
    use std::path::Path;

    const BARE_READS: [&str; 3] = ["fs::read_to_string(", "fs::read(", "File::open("];

    /// Reads of the machine-wide Maven repository (not the project tree),
    /// out of scope for #592: file name and number of allowed bare reads.
    const ALLOWED: [(&str, usize); 1] = [("maven_crawler.rs", 2)];

    #[test]
    fn crawlers_read_project_files_fifo_safely() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/crawlers");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read crawlers dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            // A Windows (core.autocrlf) checkout has CRLF lines; normalize so
            // the `\n`-joined test-module markers below still match.
            let src = std::fs::read_to_string(&path)
                .expect("read crawler source")
                .replace("\r\n", "\n");
            // Production code ends at the first in-file test module
            // (`mod tests`, or this guard in `mod.rs`); earlier
            // `#[cfg(test)] mod oracle;` declarations are only one line.
            let prod_end = [
                "#[cfg(test)]\nmod tests",
                "#[cfg(test)]\nmod architecture_tests",
            ]
            .iter()
            .filter_map(|marker| src.find(marker))
            .min()
            .unwrap_or(src.len());
            let prod = &src[..prod_end];
            let bare = prod
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .filter(|l| BARE_READS.iter().any(|r| l.contains(r)))
                .count();
            let allowed = ALLOWED
                .iter()
                .find(|(file, _)| *file == name)
                .map_or(0, |(_, n)| *n);
            assert_eq!(
                bare, allowed,
                "{name} has {bare} bare file reads in production code (allowed {allowed}); \
                 use utils::fs::read_regular_to_string{{,_sync}} instead"
            );
            checked += 1;
        }
        assert!(checked >= 10, "only {checked} crawler files found");
    }
}
