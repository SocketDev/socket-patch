//! Invalidate cargo's compiled artifacts for crates whose sources an
//! in-place (agent-mode) apply or rollback just rewrote (#387).
//!
//! Cargo treats registry and directory-source (`cargo vendor`) packages as
//! immutable: their build fingerprint is keyed on the package id, never on
//! the source files' mtimes or contents. A project built before `apply`
//! therefore keeps linking the pre-patch `lib<crate>-*.rlib` from `target/`
//! — and after `rollback`, keeps linking the patched one. Deleting the
//! crate's fingerprint directories (`<build-dir>/[<triple>/]<profile>/
//! .fingerprint/<crate>-<16 hex>/`) makes the unit dirty, so the next build
//! recompiles it from the bytes on disk, and every dependent relinks
//! because the rebuilt output is newer than theirs.
//!
//! Only build directories reachable from the project are known here: the
//! `CARGO_TARGET_DIR` / `CARGO_BUILD_TARGET_DIR` / `CARGO_BUILD_BUILD_DIR`
//! overrides, `build.target-dir` / `build.build-dir` in the `.cargo/config`
//! files cargo reads for the project, and `<workspace root>/target`. Every
//! version of the crate's name is invalidated (the fingerprint directory
//! does not record which version it built): a spurious rebuild is cheap,
//! linking stale code is not.

use std::path::{Path, PathBuf};

/// The build directories of the project at `cwd`, and the config values
/// naming one this module cannot resolve (a `{workspace-path-hash}`
/// template) — the caller tells the user to clean those by hand.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BuildDirs {
    /// Existing directories, deduplicated, in discovery order.
    pub dirs: Vec<PathBuf>,
    /// Configured build directories that could not be resolved.
    pub unresolved: Vec<String>,
}

/// What [`invalidate`] did.
#[derive(Debug, Default)]
pub struct Invalidation {
    /// Fingerprint directories removed.
    pub removed: Vec<PathBuf>,
    /// Fingerprint directories that could not be removed, with the error.
    pub failed: Vec<(PathBuf, String)>,
}

/// The project's build directories, reading the process environment.
pub fn build_dirs(cwd: &Path) -> BuildDirs {
    build_dirs_with(cwd, &|k| std::env::var(k).ok(), cargo_home().as_deref())
}

fn cargo_home() -> Option<PathBuf> {
    match std::env::var("CARGO_HOME") {
        Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v)),
        _ => crate::utils::fs::home_dir().map(|h| h.join(".cargo")),
    }
}

/// [`build_dirs`] with an injected environment and `CARGO_HOME`.
pub fn build_dirs_with(
    cwd: &Path,
    env: &dyn Fn(&str) -> Option<String>,
    cargo_home: Option<&Path>,
) -> BuildDirs {
    let env = |k: &str| env(k).filter(|v| !v.trim().is_empty());
    let ws_root = workspace_root(cwd);
    let config = ConfigDirs::read(cwd, cargo_home);

    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut unresolved = Vec::new();

    // target-dir: env beats config beats the default.
    let target_dir = env("CARGO_TARGET_DIR")
        .or_else(|| env("CARGO_BUILD_TARGET_DIR"))
        .map(|v| cwd.join(v))
        .or_else(|| config.target_dir.clone())
        .unwrap_or_else(|| ws_root.join("target"));
    candidates.push(target_dir.clone());

    // build-dir (cargo 1.91+): where the fingerprints live; defaults to
    // the target dir.
    let build_dir = env("CARGO_BUILD_BUILD_DIR")
        .map(|v| (v, cwd.to_path_buf()))
        .or_else(|| config.build_dir.clone());
    if let Some((raw, base)) = build_dir {
        match expand_build_dir(&raw, &ws_root, cargo_home) {
            Some(p) => candidates.push(base.join(p)),
            None => unresolved.push(raw),
        }
    }

    // The defaults too, in case a build ran without the override this
    // process sees (a shell profile vs. CI env): over-invalidating only
    // costs a recompile.
    candidates.push(ws_root.join("target"));
    candidates.push(cwd.join("target"));

    let mut dirs: Vec<PathBuf> = Vec::new();
    for c in candidates {
        let c = std::fs::canonicalize(&c).unwrap_or(c);
        if c.is_dir() && !dirs.contains(&c) {
            dirs.push(c);
        }
    }
    BuildDirs { dirs, unresolved }
}

/// `{workspace-root}` / `{cargo-cache-home}` substituted; `None` for a
/// template naming anything else (`{workspace-path-hash}`).
fn expand_build_dir(raw: &str, ws_root: &Path, cargo_home: Option<&Path>) -> Option<PathBuf> {
    let mut s = raw.replace("{workspace-root}", &ws_root.to_string_lossy());
    if s.contains("{cargo-cache-home}") {
        s = s.replace("{cargo-cache-home}", &cargo_home?.to_string_lossy());
    }
    if s.contains('{') {
        return None;
    }
    Some(PathBuf::from(s))
}

/// The nearest ancestor of `cwd` holding a `Cargo.lock` (cargo writes it
/// beside the workspace root manifest), else the nearest one holding a
/// `[workspace]` manifest, else `cwd`.
fn workspace_root(cwd: &Path) -> PathBuf {
    for dir in cwd.ancestors() {
        if dir.join("Cargo.lock").is_file() {
            return dir.to_path_buf();
        }
    }
    for dir in cwd.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if text
                .parse::<toml_edit::DocumentMut>()
                .is_ok_and(|d| d.contains_key("workspace"))
            {
                return dir.to_path_buf();
            }
        }
    }
    cwd.to_path_buf()
}

/// `build.target-dir` / `build.build-dir` from the config files cargo
/// reads for `cwd`: `.cargo/config.toml` (or legacy `.cargo/config`) in
/// `cwd` and every ancestor, then `$CARGO_HOME/config.toml`; the deepest
/// file that sets a key wins. A relative value resolves against the
/// directory holding the `.cargo` directory.
#[derive(Default)]
struct ConfigDirs {
    target_dir: Option<PathBuf>,
    /// The raw value and the base its relative form resolves against.
    build_dir: Option<(String, PathBuf)>,
}

impl ConfigDirs {
    fn read(cwd: &Path, cargo_home: Option<&Path>) -> Self {
        let mut files: Vec<(PathBuf, PathBuf)> = cwd
            .ancestors()
            .map(|d| (d.join(".cargo"), d.to_path_buf()))
            .collect();
        if let Some(home) = cargo_home {
            let base = home.parent().map(Path::to_path_buf).unwrap_or_default();
            files.push((home.to_path_buf(), base));
        }
        let mut out = ConfigDirs::default();
        for (dot_cargo, base) in files {
            let text = ["config.toml", "config"]
                .iter()
                .find_map(|f| std::fs::read_to_string(dot_cargo.join(f)).ok());
            let Some(doc) = text.and_then(|t| t.parse::<toml_edit::DocumentMut>().ok()) else {
                continue;
            };
            let Some(build) = doc.get("build") else {
                continue;
            };
            if out.target_dir.is_none() {
                if let Some(v) = build.get("target-dir").and_then(|v| v.as_str()) {
                    out.target_dir = Some(base.join(v));
                }
            }
            if out.build_dir.is_none() {
                if let Some(v) = build.get("build-dir").and_then(|v| v.as_str()) {
                    out.build_dir = Some((v.to_string(), base.clone()));
                }
            }
        }
        out
    }
}

/// Crate names compare the way crates.io does: ASCII case-insensitive,
/// `-` and `_` equivalent.
fn same_crate(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes().zip(b.bytes()).all(|(x, y)| {
            let n = |c: u8| {
                if c == b'_' {
                    b'-'
                } else {
                    c.to_ascii_lowercase()
                }
            };
            n(x) == n(y)
        })
}

/// Whether `dir_name` is a fingerprint directory of `crate_name`:
/// `<name>-<16 lowercase hex>`.
fn is_fingerprint_of(dir_name: &str, crate_name: &str) -> bool {
    let Some((name, hash)) = dir_name.rsplit_once('-') else {
        return false;
    };
    hash.len() == 16
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && same_crate(name, crate_name)
}

/// Every `.fingerprint` directory under `build_dir`: `<profile>/` and
/// `<triple>/<profile>/`.
fn fingerprint_dirs(build_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let subdirs = |p: &Path| -> Vec<PathBuf> {
        std::fs::read_dir(p)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect()
    };
    for level1 in subdirs(build_dir) {
        let fp = level1.join(".fingerprint");
        if fp.is_dir() {
            out.push(fp);
            continue;
        }
        for level2 in subdirs(&level1) {
            let fp = level2.join(".fingerprint");
            if fp.is_dir() {
                out.push(fp);
            }
        }
    }
    out.sort();
    out
}

/// Remove every fingerprint directory of `crate_names` under `dirs`.
pub fn invalidate(dirs: &[PathBuf], crate_names: &[String]) -> Invalidation {
    let mut out = Invalidation::default();
    if crate_names.is_empty() {
        return out;
    }
    for dir in dirs {
        for fp in fingerprint_dirs(dir) {
            let Ok(entries) = std::fs::read_dir(&fp) else {
                continue;
            };
            let mut hits: Vec<PathBuf> = entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    crate_names.iter().any(|c| is_fingerprint_of(&name, c))
                })
                .map(|e| e.path())
                .collect();
            hits.sort();
            for hit in hits {
                match std::fs::remove_dir_all(&hit) {
                    Ok(()) => out.removed.push(hit),
                    Err(e) => out.failed.push((hit, e.to_string())),
                }
            }
        }
    }
    out
}

/// The run-warning code for a crate whose compiled copy could not be
/// invalidated: the next build may link the stale one.
pub const STALE_WARNING: &str = "cargo_build_cache_stale";

/// Invalidate the project's compiled copies of the cargo crates in
/// `purls` (non-cargo purls are ignored). Returns the run warnings
/// `(code, detail)` for what could not be invalidated, each naming the
/// `cargo clean -p` remedy.
pub fn invalidate_project<'a>(
    cwd: &Path,
    purls: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, String)> {
    let mut names: Vec<String> = purls
        .into_iter()
        .filter_map(cargo_purl_name)
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Vec::new();
    }
    let dirs = build_dirs(cwd);
    let inv = invalidate(&dirs.dirs, &names);
    let mut warnings = Vec::new();
    for (path, err) in &inv.failed {
        warnings.push((
            STALE_WARNING.to_string(),
            format!(
                "could not invalidate cargo's compiled copy at {} ({err}); the next build may \
                 link the stale code. Run `cargo clean -p <crate>` for: {}",
                path.display(),
                names.join(", ")
            ),
        ));
    }
    for raw in &dirs.unresolved {
        warnings.push((
            STALE_WARNING.to_string(),
            format!(
                "cargo build-dir `{raw}` could not be resolved, so its compiled copies were not \
                 invalidated; the next build may link the stale code. Run `cargo clean -p \
                 <crate>` for: {}",
                names.join(", ")
            ),
        ));
    }
    warnings
}

/// The crate name of a `pkg:cargo/<name>@<version>` purl.
pub fn cargo_purl_name(purl: &str) -> Option<&str> {
    let rest = purl.strip_prefix("pkg:cargo/")?;
    let end = rest.find(['@', '?', '#']).unwrap_or(rest.len());
    let name = &rest[..end];
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkfp(root: &Path, rel: &str) -> PathBuf {
        let p = root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("lib-x.json"), "{}").unwrap();
        p
    }

    #[test]
    fn invalidates_only_the_named_crate_in_every_profile_and_triple() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        let a = mkfp(&target, "debug/.fingerprint/cfg-if-0123456789abcdef");
        let b = mkfp(&target, "release/.fingerprint/cfg-if-fedcba9876543210");
        let c = mkfp(
            &target,
            "x86_64-unknown-linux-gnu/debug/.fingerprint/cfg_if-00000000000000aa",
        );
        let keep1 = mkfp(&target, "debug/.fingerprint/cfg-if-extra-0123456789abcdef");
        let keep2 = mkfp(&target, "debug/.fingerprint/app-0123456789abcdef");
        let keep3 = mkfp(&target, "debug/.fingerprint/cfg-if-notahash");
        let inv = invalidate(&[target.clone()], &["cfg-if".to_string()]);
        assert!(inv.failed.is_empty());
        assert_eq!(inv.removed.len(), 3, "{:?}", inv.removed);
        for p in [a, b, c] {
            assert!(!p.exists(), "{p:?} must be removed");
        }
        for p in [keep1, keep2, keep3] {
            assert!(p.exists(), "{p:?} must be kept");
        }
    }

    #[test]
    fn build_dirs_honours_env_config_and_workspace_root() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("ws");
        let member = root.join("member");
        std::fs::create_dir_all(member.join("target")).unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("Cargo.lock"), "").unwrap();
        let none = |_: &str| None;
        let d = build_dirs_with(&member, &none, None);
        let canon = |p: PathBuf| std::fs::canonicalize(p).unwrap();
        assert_eq!(
            d.dirs,
            vec![canon(root.join("target")), canon(member.join("target"))]
        );

        // build.target-dir in an ancestor config, relative to its base.
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::create_dir_all(root.join("out")).unwrap();
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"out\"\nbuild-dir = \"{workspace-root}/bd\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("bd")).unwrap();
        let d = build_dirs_with(&member, &none, None);
        assert_eq!(d.dirs[0], canon(root.join("out")));
        assert_eq!(d.dirs[1], canon(root.join("bd")));

        // The env beats the config.
        let ext = t.path().join("ext");
        std::fs::create_dir_all(&ext).unwrap();
        let ext_s = ext.to_string_lossy().to_string();
        let env = move |k: &str| (k == "CARGO_TARGET_DIR").then(|| ext_s.clone());
        let d = build_dirs_with(&member, &env, None);
        assert_eq!(d.dirs[0], canon(ext.clone()));

        // An unresolvable template is reported.
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[build]\nbuild-dir = \"{cargo-cache-home}/b/{workspace-path-hash}\"\n",
        )
        .unwrap();
        let d = build_dirs_with(&member, &none, Some(t.path()));
        assert_eq!(
            d.unresolved,
            vec!["{cargo-cache-home}/b/{workspace-path-hash}"]
        );
    }

    #[test]
    fn purl_name() {
        assert_eq!(cargo_purl_name("pkg:cargo/cfg-if@1.0.0"), Some("cfg-if"));
        assert_eq!(cargo_purl_name("pkg:cargo/a?x=1"), Some("a"));
        assert_eq!(cargo_purl_name("pkg:npm/a@1"), None);
    }
}
