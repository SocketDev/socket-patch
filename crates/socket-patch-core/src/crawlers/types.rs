use std::path::PathBuf;

/// Identifies a supported package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
    #[cfg(feature = "cargo")]
    Cargo,
}

impl Ecosystem {
    /// All enabled ecosystems.
    pub fn all() -> &'static [Ecosystem] {
        &[
            Ecosystem::Npm,
            Ecosystem::Pypi,
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo,
        ]
    }

    /// Match a PURL string to its ecosystem.
    pub fn from_purl(purl: &str) -> Option<Self> {
        #[cfg(feature = "cargo")]
        if purl.starts_with("pkg:cargo/") {
            return Some(Ecosystem::Cargo);
        }
        if purl.starts_with("pkg:npm/") {
            return Some(Ecosystem::Npm)
        } else if purl.starts_with("pkg:pypi/") {
            return Some(Ecosystem::Pypi)
        } else {
            None
        }
    }

    /// The PURL prefix for this ecosystem (e.g. `"pkg:npm/"`).
    pub fn purl_prefix(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "pkg:npm/",
            Ecosystem::Pypi => "pkg:pypi/",
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo => "pkg:cargo/",
        }
    }

    /// Name used in the `--ecosystems` CLI flag (e.g. `"npm"`, `"pypi"`, `"cargo"`).
    pub fn cli_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo => "cargo",
        }
    }

    /// Human-readable name for user-facing messages.
    pub fn display_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "python",
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo => "cargo",
        }
    }
}

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
    /// Use global packages instead of local packages.
    pub global: bool,
    /// Custom path to global package directory (overrides auto-detection).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_purl_npm() {
        assert_eq!(
            Ecosystem::from_purl("pkg:npm/lodash@4.17.21"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:npm/@types/node@20.0.0"),
            Some(Ecosystem::Npm)
        );
    }

    #[test]
    fn test_from_purl_pypi() {
        assert_eq!(
            Ecosystem::from_purl("pkg:pypi/requests@2.28.0"),
            Some(Ecosystem::Pypi)
        );
    }

    #[test]
    fn test_from_purl_unknown() {
        assert_eq!(Ecosystem::from_purl("pkg:unknown/foo@1.0"), None);
        assert_eq!(Ecosystem::from_purl("not-a-purl"), None);
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_from_purl_cargo() {
        assert_eq!(
            Ecosystem::from_purl("pkg:cargo/serde@1.0.200"),
            Some(Ecosystem::Cargo)
        );
    }

    #[test]
    fn test_all_count() {
        let all = Ecosystem::all();
        #[cfg(not(feature = "cargo"))]
        assert_eq!(all.len(), 2);
        #[cfg(feature = "cargo")]
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_cli_name() {
        assert_eq!(Ecosystem::Npm.cli_name(), "npm");
        assert_eq!(Ecosystem::Pypi.cli_name(), "pypi");
    }

    #[test]
    fn test_display_name() {
        assert_eq!(Ecosystem::Npm.display_name(), "npm");
        assert_eq!(Ecosystem::Pypi.display_name(), "python");
    }

    #[test]
    fn test_purl_prefix() {
        assert_eq!(Ecosystem::Npm.purl_prefix(), "pkg:npm/");
        assert_eq!(Ecosystem::Pypi.purl_prefix(), "pkg:pypi/");
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_cargo_properties() {
        assert_eq!(Ecosystem::Cargo.cli_name(), "cargo");
        assert_eq!(Ecosystem::Cargo.display_name(), "cargo");
        assert_eq!(Ecosystem::Cargo.purl_prefix(), "pkg:cargo/");
    }
}
