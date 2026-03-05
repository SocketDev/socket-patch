use std::path::PathBuf;

/// Identifies a supported package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
    #[cfg(feature = "cargo")]
    Cargo,
    #[cfg(feature = "gem")]
    Gem,
    #[cfg(feature = "golang")]
    Golang,
    #[cfg(feature = "maven")]
    Maven,
    #[cfg(feature = "composer")]
    Composer,
    #[cfg(feature = "nuget")]
    Nuget,
}

impl Ecosystem {
    /// All enabled ecosystems.
    pub fn all() -> &'static [Ecosystem] {
        &[
            Ecosystem::Npm,
            Ecosystem::Pypi,
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo,
            #[cfg(feature = "gem")]
            Ecosystem::Gem,
            #[cfg(feature = "golang")]
            Ecosystem::Golang,
            #[cfg(feature = "maven")]
            Ecosystem::Maven,
            #[cfg(feature = "composer")]
            Ecosystem::Composer,
            #[cfg(feature = "nuget")]
            Ecosystem::Nuget,
        ]
    }

    /// Match a PURL string to its ecosystem.
    pub fn from_purl(purl: &str) -> Option<Self> {
        #[cfg(feature = "cargo")]
        if purl.starts_with("pkg:cargo/") {
            return Some(Ecosystem::Cargo);
        }
        #[cfg(feature = "gem")]
        if purl.starts_with("pkg:gem/") {
            return Some(Ecosystem::Gem);
        }
        #[cfg(feature = "golang")]
        if purl.starts_with("pkg:golang/") {
            return Some(Ecosystem::Golang);
        }
        #[cfg(feature = "maven")]
        if purl.starts_with("pkg:maven/") {
            return Some(Ecosystem::Maven);
        }
        #[cfg(feature = "composer")]
        if purl.starts_with("pkg:composer/") {
            return Some(Ecosystem::Composer);
        }
        #[cfg(feature = "nuget")]
        if purl.starts_with("pkg:nuget/") {
            return Some(Ecosystem::Nuget);
        }
        if purl.starts_with("pkg:npm/") {
            Some(Ecosystem::Npm)
        } else if purl.starts_with("pkg:pypi/") {
            Some(Ecosystem::Pypi)
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
            #[cfg(feature = "gem")]
            Ecosystem::Gem => "pkg:gem/",
            #[cfg(feature = "golang")]
            Ecosystem::Golang => "pkg:golang/",
            #[cfg(feature = "maven")]
            Ecosystem::Maven => "pkg:maven/",
            #[cfg(feature = "composer")]
            Ecosystem::Composer => "pkg:composer/",
            #[cfg(feature = "nuget")]
            Ecosystem::Nuget => "pkg:nuget/",
        }
    }

    /// Name used in the `--ecosystems` CLI flag (e.g. `"npm"`, `"pypi"`, `"cargo"`).
    pub fn cli_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo => "cargo",
            #[cfg(feature = "gem")]
            Ecosystem::Gem => "gem",
            #[cfg(feature = "golang")]
            Ecosystem::Golang => "golang",
            #[cfg(feature = "maven")]
            Ecosystem::Maven => "maven",
            #[cfg(feature = "composer")]
            Ecosystem::Composer => "composer",
            #[cfg(feature = "nuget")]
            Ecosystem::Nuget => "nuget",
        }
    }

    /// Human-readable name for user-facing messages.
    pub fn display_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "python",
            #[cfg(feature = "cargo")]
            Ecosystem::Cargo => "cargo",
            #[cfg(feature = "gem")]
            Ecosystem::Gem => "ruby",
            #[cfg(feature = "golang")]
            Ecosystem::Golang => "go",
            #[cfg(feature = "maven")]
            Ecosystem::Maven => "maven",
            #[cfg(feature = "composer")]
            Ecosystem::Composer => "php",
            #[cfg(feature = "nuget")]
            Ecosystem::Nuget => "nuget",
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
        #[allow(unused_mut)]
        let mut expected = 2;
        #[cfg(feature = "cargo")]
        {
            expected += 1;
        }
        #[cfg(feature = "gem")]
        {
            expected += 1;
        }
        #[cfg(feature = "golang")]
        {
            expected += 1;
        }
        #[cfg(feature = "maven")]
        {
            expected += 1;
        }
        #[cfg(feature = "composer")]
        {
            expected += 1;
        }
        #[cfg(feature = "nuget")]
        {
            expected += 1;
        }
        assert_eq!(all.len(), expected);
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

    #[cfg(feature = "gem")]
    #[test]
    fn test_from_purl_gem() {
        assert_eq!(
            Ecosystem::from_purl("pkg:gem/rails@7.1.0"),
            Some(Ecosystem::Gem)
        );
    }

    #[cfg(feature = "gem")]
    #[test]
    fn test_gem_properties() {
        assert_eq!(Ecosystem::Gem.cli_name(), "gem");
        assert_eq!(Ecosystem::Gem.display_name(), "ruby");
        assert_eq!(Ecosystem::Gem.purl_prefix(), "pkg:gem/");
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_from_purl_maven() {
        assert_eq!(
            Ecosystem::from_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some(Ecosystem::Maven)
        );
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_maven_properties() {
        assert_eq!(Ecosystem::Maven.cli_name(), "maven");
        assert_eq!(Ecosystem::Maven.display_name(), "maven");
        assert_eq!(Ecosystem::Maven.purl_prefix(), "pkg:maven/");
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_from_purl_golang() {
        assert_eq!(
            Ecosystem::from_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
            Some(Ecosystem::Golang)
        );
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_golang_properties() {
        assert_eq!(Ecosystem::Golang.cli_name(), "golang");
        assert_eq!(Ecosystem::Golang.display_name(), "go");
        assert_eq!(Ecosystem::Golang.purl_prefix(), "pkg:golang/");
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_from_purl_composer() {
        assert_eq!(
            Ecosystem::from_purl("pkg:composer/monolog/monolog@3.5.0"),
            Some(Ecosystem::Composer)
        );
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_composer_properties() {
        assert_eq!(Ecosystem::Composer.cli_name(), "composer");
        assert_eq!(Ecosystem::Composer.display_name(), "php");
        assert_eq!(Ecosystem::Composer.purl_prefix(), "pkg:composer/");
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_from_purl_nuget() {
        assert_eq!(
            Ecosystem::from_purl("pkg:nuget/Newtonsoft.Json@13.0.3"),
            Some(Ecosystem::Nuget)
        );
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_nuget_properties() {
        assert_eq!(Ecosystem::Nuget.cli_name(), "nuget");
        assert_eq!(Ecosystem::Nuget.display_name(), "nuget");
        assert_eq!(Ecosystem::Nuget.purl_prefix(), "pkg:nuget/");
    }
}
