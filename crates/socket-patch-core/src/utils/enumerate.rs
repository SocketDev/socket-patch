use std::path::Path;

use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::crawlers::NpmCrawler;

/// Type alias for backward compatibility with the TypeScript codebase.
pub type EnumeratedPackage = CrawledPackage;

/// Enumerate all packages in a `node_modules` directory.
///
/// This is a convenience wrapper around `NpmCrawler::crawl_all` that creates
/// a crawler with default options rooted at the given `cwd`.
pub async fn enumerate_node_modules(cwd: &Path) -> Vec<CrawledPackage> {
    let crawler = NpmCrawler::new();
    let options = CrawlerOptions {
        cwd: cwd.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    };
    crawler.crawl_all(&options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enumerate_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let packages = enumerate_node_modules(dir.path()).await;
        assert!(packages.is_empty());
    }

    #[tokio::test]
    async fn test_enumerate_with_packages() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Create a simple package
        let pkg_dir = nm.join("test-pkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "test-pkg", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Create a scoped package
        let scoped_dir = nm.join("@scope").join("my-lib");
        tokio::fs::create_dir_all(&scoped_dir).await.unwrap();
        tokio::fs::write(
            scoped_dir.join("package.json"),
            r#"{"name": "@scope/my-lib", "version": "2.0.0"}"#,
        )
        .await
        .unwrap();

        let packages = enumerate_node_modules(dir.path()).await;
        assert_eq!(packages.len(), 2);

        let purls: Vec<&str> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains(&"pkg:npm/test-pkg@1.0.0"));
        assert!(purls.contains(&"pkg:npm/@scope/my-lib@2.0.0"));
    }

    #[tokio::test]
    async fn test_enumerate_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Create package at top level
        let pkg1 = nm.join("foo");
        tokio::fs::create_dir_all(&pkg1).await.unwrap();
        tokio::fs::write(
            pkg1.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Create same package nested inside another
        let pkg2 = nm.join("bar");
        tokio::fs::create_dir_all(&pkg2).await.unwrap();
        tokio::fs::write(
            pkg2.join("package.json"),
            r#"{"name": "bar", "version": "2.0.0"}"#,
        )
        .await
        .unwrap();
        let nested_foo = pkg2.join("node_modules").join("foo");
        tokio::fs::create_dir_all(&nested_foo).await.unwrap();
        tokio::fs::write(
            nested_foo.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let packages = enumerate_node_modules(dir.path()).await;
        // foo@1.0.0 should be deduplicated
        let foo_count = packages
            .iter()
            .filter(|p| p.purl == "pkg:npm/foo@1.0.0")
            .count();
        assert_eq!(foo_count, 1);
    }
}
