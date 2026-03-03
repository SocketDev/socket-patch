use std::path::PathBuf;

/// Represents a package discovered during crawling.
#[derive(Debug, Clone)]
pub struct CrawledPackage {
    /// Package name (without scope).
    pub name: String,
    /// Package version.
    pub version: String,
    /// Package scope/namespace (e.g., "@types") - None for unscoped packages.
    pub namespace: Option<String>,
    /// Full PURL string (e.g., "pkg:npm/@types/node@20.0.0").
    pub purl: String,
    /// Absolute path to the package directory.
    pub path: PathBuf,
}

/// Options for package crawling.
#[derive(Debug, Clone)]
pub struct CrawlerOptions {
    /// Working directory to start from.
    pub cwd: PathBuf,
    /// Use global packages instead of local node_modules.
    pub global: bool,
    /// Custom path to global node_modules (overrides auto-detection).
    pub global_prefix: Option<PathBuf>,
    /// Batch size for yielding packages (default: 100).
    pub batch_size: usize,
}

impl Default for CrawlerOptions {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_default(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        }
    }
}
