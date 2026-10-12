//! One `binary()` and one `git_sha256` for every CLI test target (#824).
//!
//! `common/oracle.rs` owns both helpers and `common/mod.rs` re-exports
//! them; `common`'s own tests pin `git_sha256` to the canonical Git-blob
//! hash and to production's `compute_git_sha256_from_bytes` (the two
//! shapes the per-file copies took). Shared modules whose includers don't
//! all declare `mod common` pull `common/oracle.rs` in on its own and
//! re-export it. This check keeps new private copies out.

use std::path::Path;

/// Every `.rs` file under `tests/`, as (`/`-joined relative path, text).
fn test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((rel, text));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out
}

/// Whether `text` defines a `binary()` or `git_sha256(..)` of its own.
fn defines_private_helper(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        let line = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub "))
            .unwrap_or(line);
        line.starts_with("fn binary()") || line.starts_with("fn git_sha256(")
    })
}

#[test]
fn no_new_private_binary_or_git_sha256() {
    let unexpected: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| !rel.starts_with("common/") && defines_private_helper(text))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        unexpected.is_empty(),
        "these test files define their own binary() or git_sha256: {unexpected:?}. \
         Use `common::binary` / `common::git_sha256` instead (declare \
         `#[path = \"common/mod.rs\"] mod common;`, `use crate::common::..` in a \
         directory test binary, or re-export them from `common/oracle.rs` in a \
         shared module)."
    );
}

#[test]
fn the_detector_sees_every_former_copy_shape() {
    for copy in [
        "fn binary() -> PathBuf {\n    env!(\"CARGO_BIN_EXE_socket-patch\").into()\n}",
        "fn binary() -> &'static str {\n    env!(\"CARGO_BIN_EXE_socket-patch\")\n}",
        "    fn binary() -> PathBuf {",
        "pub fn git_sha256(bytes: &[u8]) -> String {",
        "fn git_sha256(content: &[u8]) -> String {",
    ] {
        assert!(defines_private_helper(copy), "missed: {copy}");
    }
    for not_a_copy in [
        "use common::{binary, git_sha256};",
        "let bin = binary();",
        "pub fn git_sha256_file(path: &Path) -> String {",
    ] {
        assert!(
            !defines_private_helper(not_a_copy),
            "false positive: {not_a_copy}"
        );
    }
}
