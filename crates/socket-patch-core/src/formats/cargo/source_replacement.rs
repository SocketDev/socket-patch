//! Cargo's source replacement: where a project's crates.io dependencies
//! actually come from.
//!
//! A `cargo vendor` project builds from a directory, not from the registry
//! cache, because a cargo config says so:
//!
//! ```toml
//! [source.crates-io]
//! replace-with = "vendored-sources"
//!
//! [source.vendored-sources]
//! directory = "third_party"
//! ```
//!
//! [`crates_io_source`] follows that `replace-with` chain over the config
//! layers cargo reads, highest precedence first, and reports the source it
//! ends on. Each key is taken from the first layer that sets it, which is
//! how cargo merges config tables. A relative `directory` resolves against
//! the layer's [`ConfigLayer::base`]: the parent of the `.cargo/` directory
//! (or of `$CARGO_HOME`) holding the file, as cargo resolves config paths.
//!
//! Pure: the callers own the reads ([`config_layer_paths`] lists the files).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item};

/// One cargo config file's text, and the directory its relative paths
/// resolve against.
pub struct ConfigLayer<'a> {
    pub base: &'a Path,
    pub text: &'a str,
}

/// Where cargo takes crates.io packages from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CratesIoSource {
    /// crates.io itself (no replacement, or a chain that cargo would
    /// reject, such as a cycle).
    Registry,
    /// A directory source (`cargo vendor`): the resolved directory.
    Directory(PathBuf),
    /// Some other replacement (a registry mirror, a local registry, git),
    /// by source name.
    Other(String),
}

/// Follow `[source.crates-io] replace-with` through `layers` (highest
/// precedence first). A layer that is not valid TOML is skipped.
pub fn crates_io_source(layers: &[ConfigLayer<'_>]) -> CratesIoSource {
    let docs: Vec<(&Path, DocumentMut)> = layers
        .iter()
        .filter_map(|l| {
            let text = l.text.strip_prefix('\u{feff}').unwrap_or(l.text);
            text.parse::<DocumentMut>().ok().map(|d| (l.base, d))
        })
        .collect();
    let lookup = |name: &str, key: &str| -> Option<(&Path, String)> {
        docs.iter().find_map(|(base, doc)| {
            let value = doc
                .get("source")
                .and_then(Item::as_table_like)
                .and_then(|s| s.get(name))
                .and_then(Item::as_table_like)
                .and_then(|t| t.get(key))
                .and_then(Item::as_str)?;
            Some((*base, value.to_string()))
        })
    };

    let mut name = "crates-io".to_string();
    let mut seen = HashSet::from([name.clone()]);
    while let Some((_, next)) = lookup(&name, "replace-with") {
        if !seen.insert(next.clone()) {
            return CratesIoSource::Registry;
        }
        name = next;
    }
    if name == "crates-io" {
        return CratesIoSource::Registry;
    }
    match lookup(&name, "directory") {
        Some((base, dir)) => CratesIoSource::Directory(base.join(dir)),
        None => CratesIoSource::Other(name),
    }
}

/// The cargo config files cargo reads for a build in `cwd`, highest
/// precedence first, each with its [`ConfigLayer::base`]: every ancestor's
/// `.cargo/config` (cargo prefers the legacy extensionless file when both
/// exist) or `.cargo/config.toml`, deepest first, then `$CARGO_HOME`'s when
/// no ancestor already named it. `exists` is the caller's file probe.
pub fn config_layer_paths(
    cwd: &Path,
    cargo_home: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> Vec<(PathBuf, PathBuf)> {
    let pick = |dir: &Path| -> Option<PathBuf> {
        ["config", "config.toml"]
            .iter()
            .map(|f| dir.join(f))
            .find(|p| exists(p))
    };
    let mut layers = Vec::new();
    let mut dirs_seen: Vec<PathBuf> = Vec::new();
    for ancestor in cwd.ancestors() {
        let dot_cargo = ancestor.join(".cargo");
        if let Some(file) = pick(&dot_cargo) {
            layers.push((file, ancestor.to_path_buf()));
        }
        dirs_seen.push(dot_cargo);
    }
    if let Some(home) = cargo_home {
        if !dirs_seen.iter().any(|d| d == home) {
            if let Some(file) = pick(home) {
                let base = home.parent().unwrap_or(home).to_path_buf();
                layers.push((file, base));
            }
        }
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer<'a>(base: &'a Path, text: &'a str) -> ConfigLayer<'a> {
        ConfigLayer { base, text }
    }

    const VENDORED: &str = "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n\
                            [source.vendored-sources]\ndirectory = \"third_party\"\n";

    #[test]
    fn no_config_is_the_registry() {
        assert_eq!(crates_io_source(&[]), CratesIoSource::Registry);
        let base = Path::new("/p");
        assert_eq!(
            crates_io_source(&[layer(base, "[build]\njobs = 2\n")]),
            CratesIoSource::Registry
        );
    }

    #[test]
    fn directory_source_resolves_against_the_layer_base() {
        let base = Path::new("/p");
        assert_eq!(
            crates_io_source(&[layer(base, VENDORED)]),
            CratesIoSource::Directory(PathBuf::from("/p/third_party"))
        );
        let abs = "[source.crates-io]\nreplace-with = \"v\"\n[source.v]\ndirectory = \"/abs/v\"\n";
        assert_eq!(
            crates_io_source(&[layer(base, abs)]),
            CratesIoSource::Directory(PathBuf::from("/abs/v"))
        );
    }

    #[test]
    fn dotted_and_crlf_spellings_parse() {
        let base = Path::new("/p");
        let text =
            "\u{feff}source.crates-io.replace-with = \"v\"\r\nsource.v.directory = \"vendor\"\r\n";
        assert_eq!(
            crates_io_source(&[layer(base, text)]),
            CratesIoSource::Directory(PathBuf::from("/p/vendor"))
        );
    }

    #[test]
    fn chain_spans_layers_and_each_key_takes_the_first_layer() {
        // The member sets replace-with; the workspace root defines the
        // directory, resolved against the root's base.
        let member = Path::new("/ws/m");
        let root = Path::new("/ws");
        let layers = [
            layer(member, "[source.crates-io]\nreplace-with = \"v\"\n"),
            layer(root, "[source.v]\ndirectory = \"vendor\"\n"),
        ];
        assert_eq!(
            crates_io_source(&layers),
            CratesIoSource::Directory(PathBuf::from("/ws/vendor"))
        );
        // A deeper layer's directory wins over a shallower one's.
        let root_text = VENDORED.replace("vendored-sources", "v");
        let layers = [
            layer(member, "[source.v]\ndirectory = \"near\"\n"),
            layer(root, &root_text),
        ];
        assert_eq!(
            crates_io_source(&layers),
            CratesIoSource::Directory(PathBuf::from("/ws/m/near"))
        );
    }

    #[test]
    fn multi_hop_chain_is_followed() {
        let base = Path::new("/p");
        let text = "[source.crates-io]\nreplace-with = \"a\"\n[source.a]\nreplace-with = \"b\"\n\
                    [source.b]\ndirectory = \"vendor\"\n";
        assert_eq!(
            crates_io_source(&[layer(base, text)]),
            CratesIoSource::Directory(PathBuf::from("/p/vendor"))
        );
    }

    #[test]
    fn non_directory_and_cyclic_replacements() {
        let base = Path::new("/p");
        let mirror = "[source.crates-io]\nreplace-with = \"mirror\"\n\
                      [source.mirror]\nregistry = \"sparse+https://m.test/\"\n";
        assert_eq!(
            crates_io_source(&[layer(base, mirror)]),
            CratesIoSource::Other("mirror".into())
        );
        let cycle =
            "[source.crates-io]\nreplace-with = \"a\"\n[source.a]\nreplace-with = \"crates-io\"\n";
        assert_eq!(
            crates_io_source(&[layer(base, cycle)]),
            CratesIoSource::Registry
        );
    }

    #[test]
    fn invalid_layer_is_skipped() {
        let base = Path::new("/p");
        assert_eq!(
            crates_io_source(&[layer(base, "[[["), layer(base, VENDORED)]),
            CratesIoSource::Directory(PathBuf::from("/p/third_party"))
        );
    }

    #[test]
    fn layer_paths_are_deepest_first_then_cargo_home() {
        let present = [
            "/ws/m/.cargo/config.toml",
            "/ws/.cargo/config",
            "/ws/.cargo/config.toml",
            "/home/u/.cargo/config.toml",
        ];
        let exists = |p: &Path| present.iter().any(|q| Path::new(q) == p);
        let got = config_layer_paths(
            Path::new("/ws/m"),
            Some(Path::new("/home/u/.cargo")),
            exists,
        );
        assert_eq!(
            got,
            vec![
                (
                    PathBuf::from("/ws/m/.cargo/config.toml"),
                    PathBuf::from("/ws/m")
                ),
                (PathBuf::from("/ws/.cargo/config"), PathBuf::from("/ws")),
                (
                    PathBuf::from("/home/u/.cargo/config.toml"),
                    PathBuf::from("/home/u")
                ),
            ]
        );
        // $CARGO_HOME inside the ancestor chain is read once.
        let got = config_layer_paths(
            Path::new("/home/u/proj"),
            Some(Path::new("/home/u/.cargo")),
            exists,
        );
        assert_eq!(
            got,
            vec![(
                PathBuf::from("/home/u/.cargo/config.toml"),
                PathBuf::from("/home/u")
            )]
        );
    }
}
