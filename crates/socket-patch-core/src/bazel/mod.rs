//! Bazel builds: one pure layer in front of every writer and attester.
//!
//! Bazel is not an ecosystem here. It is a set of build shapes inside the
//! registry ecosystems: a ruleset reads a lock file and fetches packages
//! from the registries the native tools use. So this module adds no
//! `Ecosystem` variant and writes nothing. From committed files alone it
//! answers which lock Bazel reads in a project, and whether the next build
//! would consume an edit to it or break on it:
//!
//! ```text
//! path classifier -> workspace model -> governance -> lane gate -> derived state -> typed write plan
//! ```
//!
//! The facade every seam calls: [`probe`] finds the Bazel roots above a
//! project, [`detect()`] reads one root into a [`model::BazelWorkspace`],
//! [`gate()`] decides one patch in one mode and [`governed`] says which
//! ecosystems Bazel builds in a project.
//!
//! Nothing here touches the filesystem, the environment or the network,
//! and nothing spawns Bazel: files arrive through [`model::FileView`]. The
//! IO lives in `crawlers::bazel_*`, `utils::bazel_root_writes` and
//! `hosted::bazel_reads`; `probe` is re-exported from the first of those
//! because it is the one entry that stats the disk. An architecture test
//! below enforces the rule, as `formats` does for the lock models.
//!
//! A ruleset family is patched only once its lane has landed with a
//! real-Bazel proof. Until then its lane refuses (`lane_not_enabled`),
//! which is the state of every lane in this skeleton.

pub mod attest;
pub mod codes;
pub mod consent;
pub mod derived;
pub mod detect;
pub mod diff;
pub mod downloader_cfg;
pub mod evidence;
pub mod gate;
pub mod govern;
pub mod ignore;
pub mod inventory;
pub mod java_hash;
pub mod label;
pub mod lanes;
pub mod model;
pub mod module_file;
pub mod module_lock;
pub mod output_tree;
pub mod owned_index;
pub mod owned_segment;
pub mod rc;
pub mod remedy;
pub mod rje_lock;
pub mod ruleset_version;
pub mod rulesets;
pub mod starlark;
pub mod version;
pub mod workspace_file;

pub use crate::crawlers::bazel_root::probe;
pub use detect::detect;
pub use gate::{gate, governed};

/// ARCHITECTURE GUARD (module docs): the Bazel layer does no I/O, reads no
/// environment, spawns nothing and applies no host policy; and every file
/// in it is compiled.
#[cfg(test)]
mod architecture_tests {
    use std::path::{Path, PathBuf};

    const IMPURE: [&str; 14] = [
        "tokio::fs",
        "std::fs",
        "read_regular_",
        "File::open",
        "OpenOptions",
        // The host policy (`crate::origin`): a lane takes Socket identity
        // from the caller, never from a URL it parses itself.
        "hosted_patch_uuid",
        "hosted_patch_url_uuids",
        "hosted_uuid(",
        "OriginPolicy",
        "SOCKET_PATCH_SERVER_HOST",
        "async fn",
        ".await",
        // Machine-level state never steers what is committed, and
        // socket-patch never runs Bazel or a ruleset tool.
        "env::var",
        "Command::new",
    ];

    /// File-name words that trigger another ecosystem's compatibility
    /// workflow (`crates/*/src/**/*<word>*` in `.github/workflows`).
    const FOREIGN_GLOB_WORDS: [&str; 12] = [
        "composer", "coursier", "golang", "ivy", "npm", "pdm", "pipenv", "pnpm", "poetry", "sbt",
        "scala", "vlt",
    ];

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read bazel dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    fn sources() -> Vec<PathBuf> {
        let mut files = Vec::new();
        rs_files(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bazel"),
            &mut files,
        );
        assert!(files.len() >= 70, "only {} Bazel files found", files.len());
        files
    }

    /// `src` up to its first inline test module. A `#[cfg(test)]` on a
    /// `use` line or on a `mod name;` declaration does not end the
    /// production code, so it cannot hide what follows it.
    fn production(src: &str) -> &str {
        let marker = "#[cfg(test)]\n";
        let mut from = 0;
        while let Some(at) = src[from..].find(marker).map(|i| from + i) {
            let next = src[at + marker.len()..].lines().next().unwrap_or_default();
            if next.contains("mod ") && next.trim_end().ends_with('{') {
                return &src[..at];
            }
            from = at + marker.len();
        }
        src
    }

    #[test]
    fn the_bazel_layer_is_pure() {
        for path in sources() {
            // A Windows checkout with core.autocrlf has CRLF lines.
            let src = std::fs::read_to_string(&path)
                .expect("read source")
                .replace("\r\n", "\n");
            let code: String = production(&src)
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let used: Vec<&str> = IMPURE
                .iter()
                .copied()
                .filter(|n| code.contains(n))
                .collect();
            assert!(
                used.is_empty(),
                "{}: the Bazel layer uses {used:?}; it is pure (module docs)",
                path.display()
            );
        }
    }

    #[test]
    fn the_purity_scan_stops_only_at_an_inline_test_module() {
        let src = "#[cfg(test)]\nuse a::B;\n#[cfg(test)]\nmod x;\nfn f() {}\n\
                   #[cfg(test)]\nmod tests {\n    use std::fs;\n}\n";
        assert_eq!(
            production(src),
            "#[cfg(test)]\nuse a::B;\n#[cfg(test)]\nmod x;\nfn f() {}\n"
        );
        assert_eq!(production("fn f() {}\n"), "fn f() {}\n");
    }

    /// A file with no `mod` line is not compiled: its code and its tests
    /// would silently not exist. Later packages replace whole files and
    /// never edit a module list, so the lists must already be complete.
    #[test]
    fn every_file_is_a_declared_module_with_a_neutral_name() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bazel");
        for path in sources() {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            let dir = path.parent().unwrap();
            let (name, declarer) = if stem != "mod" {
                (stem, dir.join("mod.rs"))
            } else if dir == root {
                continue;
            } else {
                let name = dir.file_name().unwrap().to_string_lossy().into_owned();
                (name, dir.parent().unwrap().join("mod.rs"))
            };
            let list = std::fs::read_to_string(&declarer).expect("read module list");
            assert!(
                list.lines().any(|l| l.trim() == format!("pub mod {name};")),
                "{} is not declared in {}",
                path.display(),
                declarer.display()
            );
            let fired: Vec<&str> = FOREIGN_GLOB_WORDS
                .iter()
                .copied()
                .filter(|w| name.contains(w))
                .collect();
            assert!(
                fired.is_empty(),
                "{}: the name fires the {fired:?} compatibility workflow; \
                 name Bazel files by ruleset",
                path.display()
            );
        }
    }
}
