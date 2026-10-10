use std::path::PathBuf;

/// Identifies a supported package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
    Cargo,
    Gem,
    Golang,
    Maven,
    Composer,
    Nuget,
    /// Deno's JSR registry. PURL form
    /// `pkg:jsr/<scope>/<name>@<version>`. Note: Deno's `deno install`
    /// flow also produces standard `node_modules/` trees full of
    /// `pkg:npm/...` packages — those route through `Ecosystem::Npm`
    /// unchanged. Only JSR (the deno-native registry) gets its own
    /// variant.
    Deno,
}

impl Ecosystem {
    /// All enabled ecosystems.
    pub fn all() -> &'static [Ecosystem] {
        &[
            Ecosystem::Npm,
            Ecosystem::Pypi,
            Ecosystem::Cargo,
            Ecosystem::Gem,
            Ecosystem::Golang,
            Ecosystem::Maven,
            Ecosystem::Composer,
            Ecosystem::Nuget,
            Ecosystem::Deno,
        ]
    }

    /// Match a PURL string to its ecosystem.
    pub fn from_purl(purl: &str) -> Option<Self> {
        Some(match purl.strip_prefix("pkg:")?.split_once('/')?.0 {
            "npm" => Self::Npm,
            "pypi" => Self::Pypi,
            "cargo" => Self::Cargo,
            "gem" => Self::Gem,
            "golang" => Self::Golang,
            "maven" => Self::Maven,
            "composer" => Self::Composer,
            "nuget" => Self::Nuget,
            "jsr" => Self::Deno,
            _ => return None,
        })
    }

    /// Name used in the `--ecosystems` CLI flag (e.g. `"npm"`, `"pypi"`, `"cargo"`).
    pub fn cli_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Gem => "gem",
            Ecosystem::Golang => "golang",
            Ecosystem::Maven => "maven",
            Ecosystem::Composer => "composer",
            Ecosystem::Nuget => "nuget",
            Ecosystem::Deno => "deno",
        }
    }

    /// Whether this ecosystem can have multiple release/distribution
    /// variants per `package@version`, each a distinct downloadable
    /// artifact distinguished by a PURL qualifier:
    ///
    /// * PyPI — `?artifact_id=` (wheel / sdist),
    /// * RubyGems — `?platform=` (e.g. `x86_64-linux`, `arm64-darwin`),
    /// * Maven — `?classifier=&ext=` (e.g. native `-linux-x86_64` jars).
    ///
    /// Single-artifact ecosystems (npm, cargo, go, composer, nuget, deno)
    /// return false: they ship exactly one tarball/zip per version, and
    /// any platform split lives under separate package *names* rather
    /// than as variants of one coordinate. Callers use this to decide
    /// whether to dedupe qualified PURLs to a base and fan results back
    /// out to every variant (release-variant ecosystems) or to match
    /// PURLs 1:1 (everything else).
    pub fn supports_release_variants(&self) -> bool {
        matches!(self, Ecosystem::Pypi | Ecosystem::Gem | Ecosystem::Maven)
    }

    /// Human-readable name for user-facing messages.
    pub fn display_name(&self) -> &'static str {
        match self {
            Ecosystem::Pypi => "python",
            Ecosystem::Gem => "ruby",
            Ecosystem::Golang => "go",
            Ecosystem::Composer => "php",
            _ => self.cli_name(),
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
}

impl Default for CrawlerOptions {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_default(),
            global: false,
            global_prefix: None,
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

    /// The matcher keys on `pkg:<type>/` with the trailing slash. A type that
    /// merely *starts with* a known type name (e.g. `npmlock`, `gemfire`) must
    /// not be misclassified, and a type with no trailing slash is not a package
    /// coordinate. This guards against someone loosening the prefix check.
    #[test]
    fn test_from_purl_requires_exact_type_with_slash() {
        // Near-miss types that share a prefix with a real type.
        assert_eq!(Ecosystem::from_purl("pkg:npmlock/foo@1.0"), None);
        assert_eq!(Ecosystem::from_purl("pkg:gemfire/foo@1.0"), None);
        assert_eq!(Ecosystem::from_purl("pkg:pypiserver/foo@1.0"), None);
        // Type present but no trailing slash → not a coordinate.
        assert_eq!(Ecosystem::from_purl("pkg:npm"), None);
        assert_eq!(Ecosystem::from_purl("pkg:pypi"), None);
        // Empty / scheme-only inputs.
        assert_eq!(Ecosystem::from_purl(""), None);
        assert_eq!(Ecosystem::from_purl("pkg:"), None);
    }

    /// PURLs frequently carry qualifiers (`?artifact_id=`, `?platform=`,
    /// `?classifier=&ext=`, `?repository_url=`). Classification keys off the
    /// type prefix and must ignore anything after the coordinate.
    #[test]
    fn test_from_purl_ignores_qualifiers() {
        assert_eq!(
            Ecosystem::from_purl("pkg:npm/lodash@4.17.21?foo=bar"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            Ecosystem::from_purl(
                "pkg:pypi/requests@2.28.0?artifact_id=requests-2.28.0-py3-none-any.whl"
            ),
            Some(Ecosystem::Pypi)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:gem/nokogiri@1.16.0?platform=x86_64-linux"),
            Some(Ecosystem::Gem)
        );
    }

    /// cli_name (the `--ecosystems` token) and display_name (user-facing)
    /// intentionally diverge for several ecosystems. Lock the divergence so a
    /// future "cleanup" can't accidentally collapse the two.
    #[test]
    fn test_cli_name_display_name_divergence() {
        assert_eq!(Ecosystem::Pypi.cli_name(), "pypi");
        assert_eq!(Ecosystem::Pypi.display_name(), "python");
        assert_eq!(Ecosystem::Gem.cli_name(), "gem");
        assert_eq!(Ecosystem::Gem.display_name(), "ruby");
        {
            assert_eq!(Ecosystem::Golang.cli_name(), "golang");
            assert_eq!(Ecosystem::Golang.display_name(), "go");
        }
        {
            assert_eq!(Ecosystem::Composer.cli_name(), "composer");
            assert_eq!(Ecosystem::Composer.display_name(), "php");
        }
    }

    /// Every entry returned by `all()` must round-trip through `cli_name()` →
    /// `from_purl(...)` so the dispatch tables can never drift apart silently.
    #[test]
    fn test_all_ecosystems_self_consistent() {
        for eco in Ecosystem::all() {
            // Names are non-empty and stable.
            assert!(!eco.cli_name().is_empty());
            assert!(!eco.display_name().is_empty());
            // A synthetic PURL built from the type re-classifies to itself.
            // Deno is the one type whose PURL token (`jsr`) differs from its
            // cli_name (`deno`), so it is exercised separately below.
            if *eco == Ecosystem::Deno {
                continue;
            }
            let purl = format!("pkg:{}/example@1.0.0", eco.cli_name());
            assert_eq!(
                Ecosystem::from_purl(&purl),
                Some(*eco),
                "round-trip failed for {}",
                eco.cli_name()
            );
        }
    }

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
        let mut expected = 3;
        {
            expected += 1;
        }
        {
            expected += 1;
        }
        {
            expected += 1;
        }
        {
            expected += 1;
        }
        {
            expected += 1;
        }
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
    fn test_cargo_properties() {
        assert_eq!(Ecosystem::Cargo.cli_name(), "cargo");
        assert_eq!(Ecosystem::Cargo.display_name(), "cargo");
    }

    #[test]
    fn test_supports_release_variants() {
        // Multi-artifact ecosystems.
        assert!(Ecosystem::Pypi.supports_release_variants());
        assert!(Ecosystem::Gem.supports_release_variants());
        assert!(Ecosystem::Maven.supports_release_variants());
        // Single-artifact ecosystems.
        assert!(!Ecosystem::Npm.supports_release_variants());
        assert!(!Ecosystem::Cargo.supports_release_variants());
        assert!(!Ecosystem::Nuget.supports_release_variants());
        assert!(!Ecosystem::Golang.supports_release_variants());
        assert!(!Ecosystem::Composer.supports_release_variants());
        assert!(!Ecosystem::Deno.supports_release_variants());
    }

    #[test]
    fn test_from_purl_deno_jsr() {
        // JSR packages use the `pkg:jsr/` type but route to Ecosystem::Deno.
        assert_eq!(
            Ecosystem::from_purl("pkg:jsr/@std/path@0.220.0"),
            Some(Ecosystem::Deno)
        );
        // There is no `pkg:deno/` type; deno's npm-layout packages stay npm.
        assert_eq!(
            Ecosystem::from_purl("pkg:npm/chalk@5.3.0"),
            Some(Ecosystem::Npm)
        );
    }

    #[test]
    fn test_deno_properties() {
        assert_eq!(Ecosystem::Deno.cli_name(), "deno");
        assert_eq!(Ecosystem::Deno.display_name(), "deno");
    }

    #[test]
    fn test_from_purl_gem() {
        assert_eq!(
            Ecosystem::from_purl("pkg:gem/rails@7.1.0"),
            Some(Ecosystem::Gem)
        );
    }

    #[test]
    fn test_gem_properties() {
        assert_eq!(Ecosystem::Gem.cli_name(), "gem");
        assert_eq!(Ecosystem::Gem.display_name(), "ruby");
    }

    #[test]
    fn test_from_purl_maven() {
        assert_eq!(
            Ecosystem::from_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some(Ecosystem::Maven)
        );
    }

    #[test]
    fn test_maven_properties() {
        assert_eq!(Ecosystem::Maven.cli_name(), "maven");
        assert_eq!(Ecosystem::Maven.display_name(), "maven");
    }

    #[test]
    fn test_from_purl_golang() {
        assert_eq!(
            Ecosystem::from_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
            Some(Ecosystem::Golang)
        );
    }

    #[test]
    fn test_golang_properties() {
        assert_eq!(Ecosystem::Golang.cli_name(), "golang");
        assert_eq!(Ecosystem::Golang.display_name(), "go");
    }

    #[test]
    fn test_from_purl_composer() {
        assert_eq!(
            Ecosystem::from_purl("pkg:composer/monolog/monolog@3.5.0"),
            Some(Ecosystem::Composer)
        );
    }

    #[test]
    fn test_composer_properties() {
        assert_eq!(Ecosystem::Composer.cli_name(), "composer");
        assert_eq!(Ecosystem::Composer.display_name(), "php");
    }

    #[test]
    fn test_from_purl_nuget() {
        assert_eq!(
            Ecosystem::from_purl("pkg:nuget/Newtonsoft.Json@13.0.3"),
            Some(Ecosystem::Nuget)
        );
    }

    #[test]
    fn test_nuget_properties() {
        assert_eq!(Ecosystem::Nuget.cli_name(), "nuget");
        assert_eq!(Ecosystem::Nuget.display_name(), "nuget");
    }

    /// `partition_purls` filters by `from_purl(p).cli_name()` against the
    /// `--ecosystems` tokens. Deno is the one variant whose PURL type
    /// (`jsr`) differs from its cli_name (`deno`), so the
    /// classify→cli_name chain must still land on `"deno"` or
    /// `--ecosystems deno` would silently drop every JSR package. The
    /// existing tests pin the two halves separately; this pins the join.
    #[test]
    fn test_jsr_purl_classifies_to_deno_cli_token() {
        assert_eq!(
            Ecosystem::from_purl("pkg:jsr/@std/path@0.220.0").map(|e| e.cli_name()),
            Some("deno")
        );
    }

    /// `test_from_purl_ignores_qualifiers` only exercises npm/pypi/gem.
    /// The remaining ecosystems carry qualifiers in the wild too
    /// (`?repository_url=` for jsr/maven, `?classifier=&ext=` for maven,
    /// version-suffixed module paths for go), and classification must
    /// still key off the type prefix alone.
    #[test]
    fn test_from_purl_ignores_qualifiers_other_ecosystems() {
        assert_eq!(
            Ecosystem::from_purl("pkg:cargo/serde@1.0.200?foo=bar"),
            Some(Ecosystem::Cargo)
        );
        assert_eq!(
            Ecosystem::from_purl(
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0?classifier=sources&ext=jar"
            ),
            Some(Ecosystem::Maven)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:golang/github.com/go-redis/cache/v9@v9.0.0?foo=bar"),
            Some(Ecosystem::Golang)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:composer/monolog/monolog@3.5.0?dev=true"),
            Some(Ecosystem::Composer)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:nuget/Newtonsoft.Json@13.0.3?foo=bar"),
            Some(Ecosystem::Nuget)
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:jsr/@std/path@0.220.0?repository_url=https://jsr.io"),
            Some(Ecosystem::Deno)
        );
    }

    /// Every enabled ecosystem must have a *unique* `cli_name`: the
    /// `--ecosystems` flag parses these tokens, so two ecosystems sharing
    /// one token would make the flag ambiguous and silently route or drop
    /// packages. A copy-paste in the `cli_name` match arm is exactly the
    /// kind of regression this guards.
    #[test]
    fn test_all_cli_names_unique() {
        let mut seen = std::collections::HashSet::new();
        for eco in Ecosystem::all() {
            assert!(
                seen.insert(eco.cli_name()),
                "duplicate cli_name {:?}",
                eco.cli_name()
            );
        }
    }

    /// `all()` is a hand-maintained list parallel to the enum; an accidental
    /// duplicate entry would inflate counts and double-crawl. Pin uniqueness.
    #[test]
    fn test_all_has_no_duplicate_variants() {
        let mut seen = std::collections::HashSet::new();
        for eco in Ecosystem::all() {
            assert!(seen.insert(*eco), "duplicate variant {:?} in all()", eco);
        }
    }

    /// Defaults must describe a local (non-global) crawl with no prefix
    /// override, so a caller that forgets to set the flags gets the safe
    /// project-local behavior.
    #[test]
    fn test_crawler_options_defaults() {
        let opts = CrawlerOptions::default();
        assert!(!opts.global);
        assert!(opts.global_prefix.is_none());
    }
}

/// One map from purl type to ecosystem (#747): production code asks
/// [`Ecosystem::from_purl`] instead of spelling `starts_with("pkg:<type>/")`.
#[cfg(test)]
mod purl_type_tests {
    use super::Ecosystem;
    use std::path::{Path, PathBuf};

    /// Each former inline prefix and the ecosystem its caller now matches.
    const PREFIXES: [(&str, Ecosystem); 9] = [
        ("pkg:npm/", Ecosystem::Npm),
        ("pkg:pypi/", Ecosystem::Pypi),
        ("pkg:cargo/", Ecosystem::Cargo),
        ("pkg:gem/", Ecosystem::Gem),
        ("pkg:golang/", Ecosystem::Golang),
        ("pkg:maven/", Ecosystem::Maven),
        ("pkg:composer/", Ecosystem::Composer),
        ("pkg:nuget/", Ecosystem::Nuget),
        ("pkg:jsr/", Ecosystem::Deno),
    ];

    /// `from_purl(p) == Some(eco)` holds exactly when `p` starts with that
    /// ecosystem's prefix, so every migrated check keeps its answer,
    /// including on the near misses an inline prefix test also rejects.
    #[test]
    fn from_purl_matches_each_former_inline_prefix() {
        let inputs = [
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/@types/node@20.0.0",
            "pkg:npm/",
            "pkg:npm",
            "pkg:NPM/lodash@1.0.0",
            "pkg:npmx/a@1",
            "npm/lodash@1",
            " pkg:npm/a@1",
            "pkg:pypi/requests@2.31.0?artifact_id=x.whl",
            "pkg:pypi",
            "pkg:PyPI/requests@2.31.0",
            "pkg:cargo/serde@1.0.0",
            "pkg:gem/rails@7.1.0?platform=x86_64-linux",
            "pkg:golang/github.com/a/b@v1.0.0",
            "pkg:golang",
            "pkg:maven/org.a/b@1.0?classifier=c&ext=jar",
            "pkg:maven:org.a/b@1.0",
            "pkg:composer/vendor/pkg@1.0.0",
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "pkg:jsr/@std/path@1.0.0",
            "pkg:deno/x@1",
            "pkg:generic/x@1",
            "",
        ];
        for purl in inputs {
            for (prefix, eco) in PREFIXES {
                assert_eq!(
                    Ecosystem::from_purl(purl) == Some(eco),
                    purl.starts_with(prefix),
                    "{purl:?} against {prefix:?}"
                );
            }
        }
    }

    /// Files that still spell a purl-type prefix inline, waiting on #747's
    /// next slice (open PRs change them). The guard is one-sided: it fails
    /// only on a file outside this list, so a PR that migrates one of
    /// these can't turn `main` red. Drop the entry when you migrate it.
    const PENDING_INLINE_PREFIXES: &[&str] = &[
        "cli/src/commands/get.rs",
        "cli/src/commands/rollback.rs",
        "cli/src/commands/scan/hosted.rs",
        "cli/src/commands/scan/hosted/python.rs",
        "cli/src/commands/scan/mod.rs",
        "cli/src/commands/scan/vendor_flow.rs",
        "cli/src/commands/vendor.rs",
        "cli/src/commands/vex.rs",
        "cli/src/ecosystem_dispatch.rs",
        "core/src/api/client.rs",
        "core/src/hosted/engine.rs",
        "core/src/hosted/memory/stages.rs",
        "core/src/patch/apply.rs",
        "core/src/patch/jvm_jar.rs",
        "core/src/patch/rollback.rs",
        "core/src/patch/store_copies.rs",
    ];

    /// The production part of a source file: everything before its first
    /// in-file test module (a one-line `#[cfg(test)] mod x;` doesn't count).
    fn production(text: &str) -> &str {
        let marker =
            regex::Regex::new(r"(?m)^#\[cfg\(test\)\]\n(?:pub(?:\(crate\))? )?mod \w+ \{").unwrap();
        marker.find(text).map_or(text, |m| &text[..m.start()])
    }

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn production_code_classifies_purls_through_from_purl() {
        let inline = regex::Regex::new(r#"starts_with\("pkg:[A-Za-z0-9.+-]+/"\)"#).unwrap();
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut offenders = Vec::new();
        for (krate, label) in [("socket-patch-core", "core"), ("socket-patch-cli", "cli")] {
            let src = crates.join(krate).join("src");
            // The CLI crate is absent from a packaged core crate.
            if !src.is_dir() {
                continue;
            }
            let mut files = Vec::new();
            walk(&src, &mut files);
            for path in files {
                let rel = format!(
                    "{label}/src/{}",
                    path.strip_prefix(&src)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/")
                );
                // The type map itself, the purl parsers, and test-only files.
                if rel == "core/src/crawlers/types.rs"
                    || rel == "core/src/utils/purl.rs"
                    || rel.ends_with("tests.rs")
                    || rel.contains("test_support")
                    || rel.contains("oracle")
                {
                    continue;
                }
                // Windows CI checks out with CRLF.
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("\r\n", "\n");
                if inline.is_match(production(&text))
                    && !PENDING_INLINE_PREFIXES.contains(&rel.as_str())
                {
                    offenders.push(rel);
                }
            }
        }
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these files test a purl type with an inline \
             `starts_with(\"pkg:<type>/\")`: {offenders:?}. Use \
             `Ecosystem::from_purl(purl) == Some(Ecosystem::X)` \
             (crates/socket-patch-core/src/crawlers/types.rs) instead."
        );
    }
}
