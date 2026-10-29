//! npm's install-time rewrite of a `bin` file's Windows shebang.
//!
//! npm's `bin-links` runs `fixBin` on every file a package lists in
//! `bin` (`lib/fix-bin.js`), on Windows too, after writing the cmd-shim
//! (`lib/shim-bin.js`): when the first 2048 bytes
//! match `^#![^\n]+\r\n`, it rewrites the file with that first `\r\n`
//! turned into `\n` (`dos2Unix`). pnpm links bins through the same
//! module. So an untouched install of a bin published from Windows
//! differs from the tarball, and from a patch's `beforeHash` /
//! `afterHash`, by exactly one byte (#1756).
//!
//! The hash checks accept that form of the recorded content, and the
//! writers keep it, so the shebang stays one `env` can run.

use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_bytes;

/// The bytes `fixBin` inspects.
const PROBE_LEN: usize = 2048;

/// What `fixBin` leaves on disk for `bytes`, or `None` when it leaves the
/// file alone (no `#!…\r\n` first line within its 2048-byte probe).
///
/// Also `None` for bytes that are not valid UTF-8: `dos2Unix` reads and
/// writes the file as UTF-8, so npm would replace them with U+FFFD, and
/// that form can't be traced back to the recorded hash. Such a file is
/// written as recorded.
pub(crate) fn fix_bin(bytes: &[u8]) -> Option<Vec<u8>> {
    let cr = first_newline(bytes)?.checked_sub(1)?;
    // `[^\n]+` needs one byte between `#!` and the `\r\n`.
    if cr < 3 || bytes[cr] != b'\r' || std::str::from_utf8(bytes).is_err() {
        return None;
    }
    let mut out = bytes.to_vec();
    out.remove(cr);
    Some(out)
}

/// The bytes to write for `content` (verified to hash to `expected_hash`
/// first, as `apply_file_patch_at` would) in `fixBin`'s form, and their
/// hash. `Ok(None)` when [`fix_bin`] leaves `content` alone.
pub(crate) fn fixed_for_write(
    content: &[u8],
    expected_hash: &str,
) -> Result<Option<(Vec<u8>, String)>, std::io::Error> {
    let Some(fixed) = fix_bin(content) else {
        return Ok(None);
    };
    let content_hash = compute_git_sha256_from_bytes(content);
    if content_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hash verification failed before patch. Expected: {expected_hash}, Got: {content_hash}"
            ),
        ));
    }
    let hash = compute_git_sha256_from_bytes(&fixed);
    Ok(Some((fixed, hash)))
}

/// The bytes to write over `normalized` (a safe path relative to
/// `pkg_path`) for `content` (recorded as `expected_hash`), and their
/// hash: `content` in `fixBin`'s form when the file is a bin npm
/// installed, else `content` as recorded. Writing a CRLF shebang there
/// would leave a bin `env` can't run.
///
/// The file is taken for an npm-installed bin when its npm package lists
/// it in `bin` and npm linked it ([`is_linked_bin`]), whatever shebang is
/// on disk now (a release before #1756 wrote the CRLF one, #1791). A bin
/// npm didn't link (`bin-links=false`, or a `directories.bin` file of a
/// non-registry install) keeps its published shebang, so it is written as
/// recorded (#1804). Without that evidence, when the file now on disk has
/// an LF shebang and either
/// belongs to an npm package, or hashes, in npm's original form, to
/// `installed_source` (the content this write replaces).
pub(crate) async fn form_for_write<'a>(
    package_key: &str,
    pkg_path: &Path,
    normalized: &str,
    installed_source: &str,
    content: std::borrow::Cow<'a, [u8]>,
    expected_hash: &str,
) -> Result<(std::borrow::Cow<'a, [u8]>, String), std::io::Error> {
    let as_recorded = |content| Ok((content, expected_hash.to_string()));
    // Content `fixBin` leaves alone needs no evidence read from disk.
    if fix_bin(&content).is_none() {
        return as_recorded(content);
    }
    let path = pkg_path.join(normalized);
    let lf_shebang = read_prefix(&path)
        .await
        .is_some_and(|prefix| has_lf_shebang(&prefix));
    let npm_installed = (lf_shebang
        && (is_npm(package_key)
            || (!installed_source.is_empty()
                && source_hash(&path).await.as_deref() == Some(installed_source))))
        || is_linked_bin(package_key, pkg_path, normalized).await;
    if !npm_installed {
        return as_recorded(content);
    }
    match fixed_for_write(&content, expected_hash)? {
        Some((fixed, hash)) => Ok((std::borrow::Cow::Owned(fixed), hash)),
        None => as_recorded(content),
    }
}

fn is_npm(package_key: &str) -> bool {
    crate::crawlers::Ecosystem::from_purl(package_key) == Some(crate::crawlers::Ecosystem::Npm)
}

/// Whether `normalized` (a safe path relative to `pkg_path`) is a file
/// the npm package `package_key` lists as a bin in its `package.json` and
/// npm linked: a file npm's `bin-links` ran `fixBin` on.
///
/// npm rewrites only the bins it links, so the listing alone is not
/// enough: with `bin-links=false`, or for a `directories.bin` file of a
/// package installed from a tarball or folder (npm expands that field
/// only in registry packuments), the file keeps its published shebang
/// (#1804). The link is a `.bin/<name>` entry in the `node_modules` the
/// package sits in, where npm links it, or a global prefix's
/// `bin/<name>` or `<name>.cmd`: a symlink resolving to this file, or a
/// cmd or shell shim naming it. A package in a virtual store (pnpm's
/// `.pnpm` or a relocated `virtualStoreDir`, npm's linked `.store`, vlt,
/// Bun, Yarn's `pnpmStoreFolder`) has its bins linked into each
/// dependent's `.bin`, wherever that is, so there the listing alone is
/// taken for the link, as before.
pub(crate) async fn is_linked_bin(package_key: &str, pkg_path: &Path, normalized: &str) -> bool {
    if !is_npm(package_key) {
        return false;
    }
    let Ok(manifest) =
        crate::utils::fs::read_regular_to_bytes(&pkg_path.join("package.json")).await
    else {
        return false;
    };
    let names = bin_names(&manifest, normalized);
    if names.is_empty() {
        return false;
    }
    let file = pkg_path.join(normalized);
    let pkg_path = pkg_path.to_path_buf();
    crate::utils::fs::run_blocking(move || has_bin_link(&pkg_path, &file, &names)).await
}

/// Whether an entry named one of `names` links the bin `file` of the
/// package at `pkg_path`, in the places [`is_linked_bin`] lists.
fn has_bin_link(pkg_path: &Path, file: &Path, names: &[String]) -> bool {
    let mut ancestors = pkg_path.ancestors().skip(1);
    // npm installs every package under a `node_modules`; a copy outside
    // one is in a relocated store.
    let Some(node_modules) = ancestors
        .by_ref()
        .find(|dir| dir.file_name().is_some_and(|n| n == "node_modules"))
    else {
        return true;
    };
    if in_virtual_store(node_modules) {
        return true;
    }
    // A shim names the file by its path below `node_modules`, from
    // wherever it is (`..\crlfbin\cli.js`, `node_modules/crlfbin/cli.js`).
    let Some(below) = file
        .strip_prefix(node_modules)
        .ok()
        .and_then(Path::to_str)
        .map(|p| p.replace('\\', "/"))
    else {
        return false;
    };
    let target = std::fs::canonicalize(file).ok();
    let links = |entry: &Path| match std::fs::symlink_metadata(entry) {
        Ok(meta) if meta.file_type().is_symlink() => {
            target.is_some() && std::fs::canonicalize(entry).ok() == target
        }
        Ok(meta) if meta.is_file() => shim_names(entry, &below),
        _ => false,
    };
    let in_dir = |dir: &Path, suffix: &str| {
        names
            .iter()
            .any(|name| links(&dir.join(format!("{name}{suffix}"))))
    };
    if in_dir(&node_modules.join(".bin"), "") {
        return true;
    }
    let Some(prefix) = node_modules.parent() else {
        return false;
    };
    // Windows global: `<prefix>/node_modules`, shims in `<prefix>`.
    in_dir(prefix, ".cmd")
        // Unix global: `<prefix>/lib/node_modules`, links in `<prefix>/bin`.
        || (prefix.file_name().is_some_and(|n| n == "lib")
            && prefix.parent().is_some_and(|p| in_dir(&p.join("bin"), "")))
}

/// Whether `node_modules` (the one a package sits in) is inside a virtual
/// store: below a dot folder of a `node_modules` (`.pnpm`, `.store`,
/// `.vlt`, `.bun`), or in a `<name>@<version>` store entry, which no
/// project folder is (a relocated pnpm `virtualStoreDir`).
fn in_virtual_store(node_modules: &Path) -> bool {
    let entry = node_modules.parent();
    entry.is_some_and(|entry| {
        entry
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.get(1..).is_some_and(|rest| rest.contains('@')))
            && !entry.join("package.json").exists()
    }) || node_modules.ancestors().skip(1).any(|dir| {
        dir.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'))
            && dir
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n == "node_modules")
    })
}

/// Whether the shim at `path` (a cmd-shim or shell script) names the
/// file at `below`, its `/`-separated path below `node_modules`.
fn shim_names(path: &Path, below: &str) -> bool {
    use std::io::Read as _;
    let Ok((file, _)) = crate::utils::fs::open_regular_file_sync(path) else {
        return false;
    };
    let mut text = Vec::new();
    if file.take(8192).read_to_end(&mut text).is_err() {
        return false;
    }
    String::from_utf8_lossy(&text)
        .replace('\\', "/")
        .contains(below)
}

/// Whether the file at `normalized` holds exactly the recorded content
/// `expected_hash`, in bytes `fixBin` would change (a CRLF shebang npm
/// never leaves in a bin), and is a bin of the npm package `package_key`:
/// the state a release before #1756 left by writing the recorded bytes
/// over npm's form, which `env` can't run (#1791).
pub(crate) async fn needs_fix(
    package_key: &str,
    pkg_path: &Path,
    normalized: &str,
    expected_hash: &str,
) -> bool {
    if !is_npm(package_key) {
        return false;
    }
    let path = pkg_path.join(normalized);
    // Cheap probe first: only a `#!…\r\n` first line can need it.
    if !read_prefix(&path).await.is_some_and(|prefix| {
        first_newline(&prefix).is_some_and(|lf| lf >= 4 && prefix[lf - 1] == b'\r')
    }) {
        return false;
    }
    if !is_linked_bin(package_key, pkg_path, normalized).await {
        return false;
    }
    crate::utils::fs::read_regular_to_bytes(&path)
        .await
        .is_ok_and(|bytes| {
            fix_bin(&bytes).is_some() && compute_git_sha256_from_bytes(&bytes) == expected_hash
        })
}

/// The names npm links `normalized` under when the `package.json` bytes
/// `manifest` list it as a bin, as npm's `normalize-package-bin` and
/// `directories.bin` step read them: a `bin` path (a string, linked under
/// the unscoped package `name`, an object's values under their keys, or
/// an array's entries under their file names) or, when `bin` is missing
/// or empty, a non-hidden file under `directories.bin`, under its file
/// name. Paths are resolved as npm does (`./` and `..` folded, never
/// above the package). Empty when the file is not a listed bin.
fn bin_names(manifest: &[u8], normalized: &str) -> Vec<String> {
    use serde_json::Value;
    let Ok(json) = serde_json::from_slice::<Value>(manifest) else {
        return Vec::new();
    };
    let target = clean_path(normalized);
    let Some(file_name) = target.last().map(|n| n.to_string()) else {
        return Vec::new();
    };
    // npm keeps only a key's last segment, `\` and `:` taken for `/`.
    let link_name = |key: &str| {
        key.trim_end_matches(['/', '\\', ':'])
            .rsplit(['/', '\\', ':'])
            .next()
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
            .map(str::to_string)
    };
    match json.get("bin") {
        Some(Value::String(bin)) if !bin.is_empty() => json
            .get("name")
            .and_then(Value::as_str)
            .filter(|_| clean_path(bin) == target)
            .and_then(link_name)
            .into_iter()
            .collect(),
        Some(Value::Object(bins)) => bins
            .iter()
            .filter(|(_, bin)| bin.as_str().is_some_and(|bin| clean_path(bin) == target))
            .filter_map(|(key, _)| link_name(key))
            .collect(),
        Some(Value::Array(bins)) => {
            let listed = bins
                .iter()
                .filter_map(Value::as_str)
                .any(|bin| clean_path(bin) == target);
            if listed {
                vec![file_name]
            } else {
                Vec::new()
            }
        }
        Some(Value::String(_) | Value::Null | Value::Bool(false)) | None => {
            let listed = json
                .get("directories")
                .and_then(|d| d.get("bin"))
                .and_then(serde_json::Value::as_str)
                .map(clean_path)
                .is_some_and(|dir| {
                    !dir.is_empty()
                        && target.len() > dir.len()
                        && target.starts_with(&dir[..])
                        && !target[dir.len()..].iter().any(|seg| seg.starts_with('.'))
                });
            if listed {
                vec![file_name]
            } else {
                Vec::new()
            }
        }
        Some(_) => Vec::new(),
    }
}

/// `path`'s segments with `.`, empty segments and `..` folded, rooted at
/// the package as npm's `path.join('/', …)` roots it.
fn clean_path(path: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            seg => out.push(seg),
        }
    }
    out
}

/// The content `fixBin` turned into `bytes`, or `None` when `bytes` is not
/// something `fixBin` writes (a `#!` first line of at least one byte,
/// ending in `\n` early enough that its `\r\n` original fit the probe).
pub(crate) fn unfix_bin(bytes: &[u8]) -> Option<Vec<u8>> {
    let lf = first_newline(bytes)?;
    if lf < 3 || lf + 1 >= PROBE_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(&bytes[..lf]);
    out.push(b'\r');
    out.extend_from_slice(&bytes[lf..]);
    Some(out)
}

/// Whether `bytes` starts with a `#!` line that ends in a bare `\n`: the
/// shebang shape npm installs a bin with.
pub(crate) fn has_lf_shebang(bytes: &[u8]) -> bool {
    matches!(first_newline(bytes), Some(lf) if lf >= 3 && bytes[lf - 1] != b'\r')
}

/// The hash of the content npm installed as the file at `path`, when the
/// file is in `fixBin`'s form ([`unfix_bin`]). `None` when it is not, or
/// it can't be read. Only a file whose first bytes qualify is read whole,
/// so a mismatched jar or wheel is not read twice.
pub(crate) async fn source_hash(path: &Path) -> Option<String> {
    let path = path.to_path_buf();
    crate::utils::fs::run_blocking(move || source_hash_sync(&path)).await
}

/// Blocking twin of [`source_hash`].
pub(crate) fn source_hash_sync(path: &Path) -> Option<String> {
    unfix_bin(&read_prefix_sync(path)?)?;
    let bytes = crate::utils::fs::read_regular_to_bytes_sync(path).ok()?;
    source_hash_of(&bytes)
}

/// The first [`PROBE_LEN`] bytes of the regular file at `path`.
async fn read_prefix(path: &Path) -> Option<Vec<u8>> {
    let path = path.to_path_buf();
    crate::utils::fs::run_blocking(move || read_prefix_sync(&path)).await
}

fn read_prefix_sync(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let (file, _) = crate::utils::fs::open_regular_file_sync(path).ok()?;
    let mut prefix = Vec::with_capacity(PROBE_LEN);
    file.take(PROBE_LEN as u64).read_to_end(&mut prefix).ok()?;
    Some(prefix)
}

/// [`source_hash`] of bytes already read.
pub(crate) fn source_hash_of(bytes: &[u8]) -> Option<String> {
    unfix_bin(bytes).map(|src| compute_git_sha256_from_bytes(&src))
}

/// The index of the first `\n` of a file that starts with `#!`, within
/// the probe.
fn first_newline(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let probe = &bytes[..bytes.len().min(PROBE_LEN)];
    probe.iter().position(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_bin_drops_only_the_first_lines_cr() {
        assert_eq!(
            fix_bin(b"#!/usr/bin/env node\r\na();\r\n").as_deref(),
            Some(&b"#!/usr/bin/env node\na();\r\n"[..])
        );
        // The greedy `[^\n]+` keeps an earlier `\r`.
        assert_eq!(fix_bin(b"#!x\r\r\n").as_deref(), Some(&b"#!x\r\n"[..]));
    }

    #[test]
    fn fix_bin_leaves_what_bin_links_leaves() {
        for bytes in [
            &b"#!/usr/bin/env node\na();\r\n"[..],
            b"#!\r\n",
            b"// #!x\r\n",
            b"#!/usr/bin/env node",
            b"",
        ] {
            assert_eq!(fix_bin(bytes), None, "{bytes:?}");
        }
        // The `\r\n` must fall within the 2048-byte probe.
        let mut long = b"#!".to_vec();
        long.extend(vec![b'x'; 2044]);
        long.extend_from_slice(b"\r\n");
        assert_eq!(long.len(), 2048);
        assert!(fix_bin(&long).is_some());
        long.insert(2, b'x');
        assert_eq!(fix_bin(&long), None);
    }

    #[test]
    fn fix_bin_keeps_bytes_npm_would_mangle() {
        // npm would write U+FFFD for the 0xff, which nothing can trace
        // back to the recorded hash.
        assert_eq!(fix_bin(b"#!node\r\n\xff\n"), None);
    }

    #[test]
    fn fixed_for_write_checks_the_content_first() {
        let content = b"#!/usr/bin/env node\r\nx\r\n";
        let hash = compute_git_sha256_from_bytes(content);
        let (fixed, fixed_hash) = fixed_for_write(content, &hash).unwrap().unwrap();
        assert_eq!(fixed, b"#!/usr/bin/env node\nx\r\n");
        assert_eq!(fixed_hash, compute_git_sha256_from_bytes(&fixed));
        let err = fixed_for_write(content, &"0".repeat(64)).unwrap_err();
        assert!(
            err.to_string().contains("Hash verification failed"),
            "{err}"
        );
        assert!(fixed_for_write(b"x\r\n", &"0".repeat(64))
            .unwrap()
            .is_none());
    }

    #[test]
    fn unfix_bin_inverts_fix_bin() {
        for src in [
            &b"#!/usr/bin/env node\r\na();\r\n"[..],
            b"#!x\r\n",
            b"#!x\r\r\n",
        ] {
            let fixed = fix_bin(src).unwrap();
            assert_eq!(unfix_bin(&fixed).as_deref(), Some(src), "{src:?}");
        }
        for bytes in [&b"#!\n"[..], b"a\n", b"#!x"] {
            assert_eq!(unfix_bin(bytes), None, "{bytes:?}");
        }
        // Its original's `\r\n` would not have fit the probe.
        let mut long = b"#!".to_vec();
        long.extend(vec![b'x'; 2045]);
        long.push(b'\n');
        assert_eq!(unfix_bin(&long), None);
    }

    #[test]
    fn has_lf_shebang_wants_a_bare_lf() {
        assert!(has_lf_shebang(b"#!/bin/sh\necho\n"));
        assert!(!has_lf_shebang(b"#!/bin/sh\r\necho\n"));
        assert!(!has_lf_shebang(b"#!\n"));
        assert!(!has_lf_shebang(b"echo\n"));
    }

    #[test]
    fn lists_bin_reads_every_bin_shape() {
        let listed = |manifest: &str, file: &str| !bin_names(manifest.as_bytes(), file).is_empty();
        assert!(listed(r#"{"name":"x","bin":"cli.js"}"#, "cli.js"));
        assert!(listed(r#"{"name":"x","bin":"./bin/../cli.js"}"#, "cli.js"));
        assert!(listed(
            r#"{"bin":{"a":"x.js","b":"./bin/cli.js"}}"#,
            "bin/cli.js"
        ));
        assert!(listed(
            r#"{"directories":{"bin":"./bin"}}"#,
            "bin/sub/cli.js"
        ));
        // `bin` wins over `directories.bin`, as in npm's normalize.
        assert!(!listed(
            r#"{"bin":{"a":"x.js"},"directories":{"bin":"bin"}}"#,
            "bin/cli.js"
        ));
        assert!(!listed(r#"{"bin":{"a":"x.js"}}"#, "cli.js"));
        assert!(listed(r#"{"bin":["x.js","./cli.js"]}"#, "cli.js"));
        // npm drops a string `bin` of a package with no name.
        assert!(!listed(r#"{"bin":"cli.js"}"#, "cli.js"));
        // A missing or empty `bin` falls back to `directories.bin`, whose
        // glob skips hidden files.
        for bin in ["\"\"", "null"] {
            let manifest = format!(r#"{{"bin":{bin},"directories":{{"bin":"bin"}}}}"#);
            assert!(listed(&manifest, "bin/cli.js"), "{manifest}");
        }
        assert!(!listed(
            r#"{"directories":{"bin":"bin"}}"#,
            "bin/.hidden/cli.js"
        ));
        assert!(!listed(r#"{"name":"x"}"#, "cli.js"));
        assert!(!listed(r#"{"directories":{"bin":"."}}"#, "cli.js"));
        assert!(!listed("not json", "cli.js"));
    }

    #[test]
    fn bin_names_are_npms_link_names() {
        let names = |manifest: &str, file: &str| bin_names(manifest.as_bytes(), file);
        assert_eq!(names(r#"{"name":"@s/x","bin":"cli.js"}"#, "cli.js"), ["x"]);
        assert_eq!(
            names(
                r#"{"bin":{"a":"cli.js","b":"other.js","c":"./cli.js"}}"#,
                "cli.js"
            ),
            ["a", "c"]
        );
        assert_eq!(names(r#"{"bin":{"../../a":"cli.js"}}"#, "cli.js"), ["a"]);
        assert_eq!(names(r#"{"bin":{"a/":"cli.js"}}"#, "cli.js"), ["a"]);
        assert_eq!(names(r#"{"bin":["bin/cli.js"]}"#, "bin/cli.js"), ["cli.js"]);
        assert_eq!(
            names(r#"{"directories":{"bin":"bin"}}"#, "bin/sub/run"),
            ["run"]
        );
        assert!(names(r#"{"bin":{"a":"x.js"}}"#, "cli.js").is_empty());
    }

    /// `node_modules/<name>/cli.js` under `root`, its package.json listing
    /// it as the bin `crlfbin`. Returns the package dir.
    fn installed_bin(root: &Path, under: &str) -> std::path::PathBuf {
        let pkg = root.join(under).join("crlfbin");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            br#"{"name":"crlfbin","bin":{"crlfbin":"cli.js"}}"#,
        )
        .unwrap();
        std::fs::write(pkg.join("cli.js"), b"#!/usr/bin/env node\r\n").unwrap();
        pkg
    }

    /// A cmd-shim at `path` running `target` (relative to the shim).
    fn shim_to(path: std::path::PathBuf, target: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = target.replace('/', "\\");
        std::fs::write(path, format!("@\"%dp0%\\{target}\" %*\r\n")).unwrap();
    }

    fn shim(path: std::path::PathBuf) {
        shim_to(path, "../crlfbin/cli.js");
    }

    const PURL: &str = "pkg:npm/crlfbin@1.0.0";

    /// Regression (#1804): npm runs `fixBin` only on bins it links, so a
    /// listed bin without a link (`bin-links=false`) is not npm's form.
    #[tokio::test]
    async fn is_linked_bin_wants_npms_link() {
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules");
        assert!(
            !is_linked_bin(PURL, &pkg, "cli.js").await,
            "bin-links=false"
        );
        shim(root.path().join("node_modules/.bin/other"));
        assert!(!is_linked_bin(PURL, &pkg, "cli.js").await, "another bin");
        shim(root.path().join("node_modules/.bin/crlfbin"));
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
        assert!(!is_linked_bin("pkg:pypi/crlfbin@1.0.0", &pkg, "cli.js").await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn is_linked_bin_follows_a_symlink_to_this_file() {
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules");
        let bin = root.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(pkg.join("other.js"), b"x").unwrap();
        std::os::unix::fs::symlink("../crlfbin/other.js", bin.join("crlfbin")).unwrap();
        assert!(
            !is_linked_bin(PURL, &pkg, "cli.js").await,
            "links elsewhere"
        );
        std::fs::remove_file(bin.join("crlfbin")).unwrap();
        std::os::unix::fs::symlink("../crlfbin/cli.js", bin.join("crlfbin")).unwrap();
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
    }

    #[tokio::test]
    async fn is_linked_bin_finds_global_and_pnpm_links() {
        // Unix global prefix.
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "lib/node_modules");
        assert!(!is_linked_bin(PURL, &pkg, "cli.js").await);
        shim(root.path().join("bin/crlfbin"));
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
        // Windows global prefix.
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules");
        shim(root.path().join("crlfbin.cmd"));
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
        // A virtual-store copy, whose bins are linked into its dependents'.
        for store in [
            "node_modules/.pnpm/crlfbin@1.0.0/node_modules",
            "node_modules/.store/crlfbin@1.0.0/node_modules",
        ] {
            let root = tempfile::tempdir().unwrap();
            let pkg = installed_bin(root.path(), store);
            assert!(is_linked_bin(PURL, &pkg, "cli.js").await, "{store}");
        }
    }

    /// npm links a nested copy's bins into its own `node_modules/.bin`, so
    /// the top-level copy's link says nothing about it.
    #[tokio::test]
    async fn is_linked_bin_looks_only_where_npm_links_the_copy() {
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules/a/node_modules");
        shim(root.path().join("node_modules/.bin/crlfbin"));
        assert!(!is_linked_bin(PURL, &pkg, "cli.js").await);
        shim(root.path().join("node_modules/a/node_modules/.bin/crlfbin"));
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
        // Scoped: `node_modules/@s/crlfbin` links into `node_modules/.bin`.
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules/@s");
        shim_to(
            root.path().join("node_modules/.bin/crlfbin"),
            "../@s/crlfbin/cli.js",
        );
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
    }

    /// A file that merely has a bin's name, where a global prefix would
    /// keep its shim, is not npm's link unless it runs this file.
    #[tokio::test]
    async fn is_linked_bin_wants_the_shim_to_run_this_file() {
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "node_modules");
        shim_to(root.path().join("crlfbin.cmd"), "scripts/crlfbin.js");
        shim_to(
            root.path().join("node_modules/.bin/crlfbin"),
            "../other/cli.js",
        );
        assert!(!is_linked_bin(PURL, &pkg, "cli.js").await);
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "lib/node_modules");
        shim_to(root.path().join("bin/crlfbin"), "../tools/crlfbin");
        assert!(!is_linked_bin(PURL, &pkg, "cli.js").await);
    }

    /// Stores outside a `node_modules` dot folder: a relocated pnpm
    /// `virtualStoreDir`, and Yarn's `pnpmStoreFolder` (`<slug>/package`).
    #[tokio::test]
    async fn is_linked_bin_takes_the_listing_in_relocated_stores() {
        let root = tempfile::tempdir().unwrap();
        let pkg = installed_bin(root.path(), "vstore/crlfbin@1.0.0/node_modules");
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("store/crlfbin-npm-1.0.0-abc/package");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            br#"{"name":"crlfbin","bin":{"crlfbin":"cli.js"}}"#,
        )
        .unwrap();
        assert!(is_linked_bin(PURL, &pkg, "cli.js").await);
    }

    #[tokio::test]
    async fn source_hash_is_the_tarball_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.js");
        tokio::fs::write(&path, b"#!/usr/bin/env node\nx\r\n")
            .await
            .unwrap();
        assert_eq!(
            source_hash(&path).await,
            Some(compute_git_sha256_from_bytes(
                b"#!/usr/bin/env node\r\nx\r\n"
            ))
        );
        tokio::fs::write(&path, b"x\n").await.unwrap();
        assert_eq!(source_hash(&path).await, None);
        assert_eq!(source_hash(&dir.path().join("missing")).await, None);
    }
}
