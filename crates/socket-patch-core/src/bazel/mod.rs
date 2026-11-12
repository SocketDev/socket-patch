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

    const IMPURE: [&str; 21] = [
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
        // Machine-level state never steers what is committed.
        "env::var",
        "std::env",
        "std::net",
        // socket-patch never runs Bazel or a ruleset tool: not directly,
        // and not through `utils::process`, the one place core may spawn
        // from.
        "Command::new",
        "std::process",
        "utils::process",
        "command_for(",
        "output_within(",
        "resolve_tool(",
    ];

    /// The modules behind those names. `use std::{fs, env};` spells none
    /// of the names above, so these are also banned as a path segment: in
    /// any `use` declaration, and anywhere else when `::` follows.
    const IMPURE_MODULES: [&str; 4] = ["fs", "env", "process", "net"];

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

    /// `src` without its inline test modules. A `#[cfg(test)]` on a `use`
    /// line or on a `mod name;` declaration is not one, and code after a
    /// test module is production code, so neither can hide what follows
    /// it. A module whose closing brace is not found is kept and scanned.
    fn production(src: &str) -> String {
        let marker = "#[cfg(test)]\n";
        let (mut out, mut rest) = (String::new(), src);
        while let Some(at) = rest.find(marker) {
            let body = &rest[at + marker.len()..];
            let head = body.lines().next().unwrap_or_default();
            let inline = head.contains("mod ") && head.trim_end().ends_with('{');
            let end = head.rfind('{').filter(|_| inline);
            match end.and_then(|open| block_end(body, open)) {
                Some(end) => {
                    out.push_str(&rest[..at]);
                    rest = &body[end..];
                }
                None => {
                    out.push_str(&rest[..at + marker.len()]);
                    rest = body;
                }
            }
        }
        out + rest
    }

    /// The offset just past the `}` that closes the block opening at
    /// `src[open]`. Braces in string and char literals and in comments do
    /// not count: a JSON fixture in a test has a `}` in column 0, and a
    /// scan that stopped there would take the rest of the tests for
    /// production code.
    fn block_end(src: &str, open: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        let (mut at, mut depth) = (open, 0usize);
        while at < bytes.len() {
            let rest = &bytes[at..];
            at += match rest[0] {
                b'/' if rest.starts_with(b"//") => rest.iter().position(|b| *b == b'\n')?,
                b'/' if rest.starts_with(b"/*") => block_comment_len(rest)?,
                b'"' => string_len(bytes, at)?,
                b'\'' => quote_len(&src[at..]),
                b'{' => {
                    depth += 1;
                    1
                }
                b'}' if depth == 1 => return Some(at + 1),
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    1
                }
                _ => 1,
            };
        }
        None
    }

    /// The length of the block comment `rest` starts with; they nest.
    fn block_comment_len(rest: &[u8]) -> Option<usize> {
        let (mut at, mut depth) = (0, 0usize);
        while at < rest.len() {
            if rest[at..].starts_with(b"/*") {
                depth += 1;
                at += 2;
            } else if rest[at..].starts_with(b"*/") {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Some(at);
                }
            } else {
                at += 1;
            }
        }
        None
    }

    /// The length of the string literal whose opening quote is
    /// `bytes[at]`. A raw string (`r"`, `br#"`) ends at a quote followed
    /// by its hashes and has no escapes.
    fn string_len(bytes: &[u8], at: usize) -> Option<usize> {
        let hashes = bytes[..at].iter().rev().take_while(|b| **b == b'#').count();
        let body = &bytes[at + 1..];
        if bytes[..at - hashes].last() == Some(&b'r') {
            let close = [&b"\""[..], &b"#".repeat(hashes)].concat();
            let end = body.windows(close.len()).position(|w| w == close)?;
            return Some(1 + end + close.len());
        }
        let mut end = 0;
        loop {
            match body.get(end)? {
                b'\\' => end += 2,
                b'"' => return Some(end + 2),
                _ => end += 1,
            }
        }
    }

    /// The length of the char literal `rest` starts with, or 1 when the
    /// quote starts a lifetime or a label.
    fn quote_len(rest: &str) -> usize {
        let mut chars = rest[1..].chars();
        match chars.next() {
            Some('\\') => {
                let escaped = 2 + chars.next().map_or(0, char::len_utf8);
                let close = rest.get(escaped..).and_then(|tail| tail.find('\''));
                close.map_or(rest.len(), |i| escaped + i + 1)
            }
            Some(c) if chars.next() == Some('\'') => c.len_utf8() + 2,
            _ => 1,
        }
    }

    /// Every `use` declaration in `code`, up to its `;`.
    fn use_declarations(code: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut start = 0;
        for line in code.split_inclusive('\n') {
            let head = line.trim_start();
            let scoped = head.strip_prefix("pub(").and_then(|h| h.split_once(") "));
            let head = scoped.map_or(head.strip_prefix("pub ").unwrap_or(head), |(_, h)| h);
            if head.starts_with("use ") {
                let end = code[start..].find(';').map_or(code.len(), |i| start + i);
                out.push(&code[start..end]);
            }
            start += line.len();
        }
        out
    }

    /// The banned names `code` uses. `code` is production code with its
    /// comment lines removed.
    fn impure_uses(code: &str) -> Vec<&'static str> {
        let word = |c: char| c.is_alphanumeric() || c == '_';
        // Whether `module` is a whole path segment somewhere in `text`;
        // with `path_head`, only where `::` follows it.
        let segment = |text: &str, module: &str, path_head: bool| {
            text.match_indices(module).any(|(at, _)| {
                let (before, after) = (&text[..at], &text[at + module.len()..]);
                let whole = !before.ends_with(word) && !after.starts_with(word);
                whole && (after.starts_with("::") || !path_head)
            })
        };
        let imports = use_declarations(code);
        let imported = |module: &str| imports.iter().any(|u| segment(u, module, false));
        let names = IMPURE.iter().copied().filter(|n| code.contains(n));
        let modules = IMPURE_MODULES.iter().copied();
        names
            .chain(modules.filter(|m| segment(code, m, true) || imported(m)))
            .collect()
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
            let used = impure_uses(&code);
            assert!(
                used.is_empty(),
                "{}: the Bazel layer uses {used:?}; it is pure (module docs)",
                path.display()
            );
        }
    }

    #[test]
    fn the_purity_scan_skips_inline_test_modules_and_nothing_else() {
        let src = "#[cfg(test)]\nuse a::B;\n#[cfg(test)]\nmod x;\nfn f() {}\n\
                   #[cfg(test)]\nmod tests {\n    use std::fs;\n}\n";
        assert_eq!(
            production(src),
            "#[cfg(test)]\nuse a::B;\n#[cfg(test)]\nmod x;\nfn f() {}\n\n"
        );
        assert_eq!(production("fn f() {}\n"), "fn f() {}\n");

        // Code after a test module is scanned. The module ends at its own
        // brace, whatever braces its strings, chars and comments hold.
        let tests = "#[cfg(test)]\nmod tests {\n    const LOCK: &str = \"{\n}\n\";\n    \
                     const RAW: &str = r#\"}\"}\"#;\n    // }\n    /* } /* } */ } */\n    \
                     fn f<'a>(s: &'a str) -> bool { s.contains(['}', '\\'', '\\u{7d}']) || b'}' == 0 }\n}\n";
        let late = "fn late() { let _ = std::fs::read(\"x\"); }\n";
        assert_eq!(
            production(&format!("fn f() {{}}\n{tests}{late}")),
            format!("fn f() {{}}\n\n{late}")
        );
        assert_eq!(impure_uses(late), ["std::fs", "fs"]);
        // Two test modules, and one that never closes: that one is kept.
        assert_eq!(
            production(&format!("{tests}{tests}{late}")),
            format!("\n\n{late}")
        );
        let open = "#[cfg(test)]\nmod tests {\n    use std::fs;\n";
        assert_eq!(production(open), open);
    }

    #[test]
    fn the_purity_scan_knows_each_way_to_reach_the_machine() {
        for (code, name) in [
            ("let text = std::fs::read(path);", "std::fs"),
            // The one sanctioned way for core to spawn.
            (
                "use crate::utils::process::{command_for, output_within};",
                "utils::process",
            ),
            (
                "let out = output_within(command_for(tool), budget);",
                "command_for(",
            ),
            (
                "let out = output_within(command, budget);",
                "output_within(",
            ),
            ("let tool = resolve_tool(\"bazel\");", "resolve_tool("),
            // A grouped import spells no `std::fs`.
            ("use std::{fs, env};", "fs"),
            ("use std::{fs, env};", "env"),
            (
                "pub(crate) use std::{\n    collections::BTreeMap,\n    process,\n};",
                "process",
            ),
            ("    use std::os::unix::fs::symlink;", "fs"),
            ("let text = fs::read_to_string(path);", "fs"),
            ("let dir = env::current_dir();", "env"),
            (
                "let stream = std::net::TcpStream::connect(addr);",
                "std::net",
            ),
            ("let pid = std::process::id();", "std::process"),
            ("for arg in std::env::args() {}", "std::env"),
        ] {
            let used = impure_uses(code);
            assert!(used.contains(&name), "{code:?}: {name} not in {used:?}");
        }
        // The module names are banned as path segments only.
        for code in [
            "use std::collections::BTreeMap;\nuse super::model::{Files, Site};",
            "fn process(env: &str, fs: usize) -> usize { net(env) + fs }",
            "let offsets = reuse (process, env);",
            "let profile = cfg.env;\nlet subprocess::Kind = kind;",
        ] {
            assert_eq!(impure_uses(code), [""; 0], "{code:?}");
        }
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
