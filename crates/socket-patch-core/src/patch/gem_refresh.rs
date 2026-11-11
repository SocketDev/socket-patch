//! Bring a stale gem materialization in line with a verified `.gem`.
//!
//! Bundler never refetches a gem it already holds: after a hosted redirect
//! (or its unwind) rewrites `Gemfile.lock`, an installed `name-version` and
//! the archives beside it keep the bytes of the source the lock named
//! before, and `bundle install` reports success over them (the "Gem
//! stale-install guard" section of CLI_CONTRACT.md has the full account).
//! This module replaces such a materialization with the gem the lock now
//! pins:
//!
//! * an installed copy, `<home>/gems/<leaf>` with `<home>/cache/<leaf>.gem`
//!   and, for a gem that builds a native extension, its
//!   `<home>/extensions/<platform>/<abi>/<leaf>` ([`Target::Installed`]);
//! * an archive in Bundler's cache dir, `vendor/cache/<leaf>.gem`
//!   ([`Target::CacheArchive`]).
//!
//! The rules it keeps:
//!
//! * The only source is the `.gem` archive whose sha256 is one the caller
//!   names ([`Wanted::sha256`]: what the lock or the grant pins). It is
//!   taken from disk when a copy there verifies, else downloaded and
//!   verified, before any byte of it is used. With no verified archive
//!   nothing is changed.
//! * The archive must be the gem the materialization holds (its metadata's
//!   name, version and platform) and agree with the installed gemspec on
//!   whether the gem builds extensions; when the archive the copy was
//!   installed from is still in the home's `cache/`, both must carry the
//!   same gemspec, since the installed `specifications/` entry is kept.
//! * The new state is built in a stage dir inside the gem home and renamed
//!   into place, with an atomic exchange where the platform has one
//!   (`swap_into`), so the gem dir is never missing. A step that fails
//!   puts the earlier ones back.
//! * A gem that builds a native extension is installed into a stage home
//!   by RubyGems itself, with the Ruby that owns the installed copy
//!   (`gem_ext::install_staged`), and its
//!   gem dir and extension dir are swapped in together: sources and
//!   compiled code always match. Without such a Ruby, or with
//!   `--no-gem-native-rebuild`, the copy is left as it is.
//! * The installed copy's cache archive is replaced with it, never without
//!   it: that archive is what later runs judge the copy by.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::patch::gem_ext::RubyEnv;
use crate::utils::digest::sha256_hex_of;

/// The stage dir a refresh builds in, inside the gem home (the same
/// filesystem as what it replaces, so every move is a rename).
const STAGE_DIR: &str = ".socket-patch-refresh";

/// The gunzipped size cap of a `.gem`'s `metadata.gz` (a gemspec as YAML).
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// Where the wanted archive is downloaded from when no copy on disk
/// verifies.
pub enum Source<'a> {
    /// The patch server's serve routes.
    PatchServer(&'a crate::api::client::ApiClient),
    /// A public gem registry.
    Registry,
    /// `--offline`: only what is already on disk.
    DiskOnly,
}

/// The archive a gem's stale materializations are refreshed from.
#[derive(Debug, Clone)]
pub struct Wanted {
    /// `<name>-<version>[-<platform>]`, as the gem dir and the archive are
    /// named.
    pub leaf: String,
    /// `patched` or `upstream`, for the messages.
    pub kind: &'static str,
    /// The sha256 (lowercase hex) of every archive that may be used.
    pub sha256: BTreeSet<String>,
    /// Where to download it, tried in order.
    pub urls: Vec<String>,
    /// Archives on disk that may already be it.
    pub on_disk: Vec<PathBuf>,
}

/// One stale materialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// An installed copy, `<home>/gems/<leaf>`.
    Installed(PathBuf),
    /// An archive in Bundler's cache dir.
    CacheArchive(PathBuf),
}

impl Target {
    pub fn path(&self) -> &Path {
        match self {
            Target::Installed(path) | Target::CacheArchive(path) => path,
        }
    }
}

/// A verified archive, read once per gem.
struct Archive {
    bytes: Vec<u8>,
    /// Its gemspec (`metadata.gz`, gunzipped).
    metadata: Vec<u8>,
    /// The gemspec declares extensions RubyGems builds at install time.
    native: bool,
}

/// Refresh every target from the archive `wanted` names: one outcome per
/// target, in order. `Err` is why that target is as it was.
pub async fn refresh(
    wanted: &Wanted,
    targets: &[Target],
    source: &Source<'_>,
    ruby: &RubyEnv,
) -> Vec<Result<(), String>> {
    if targets.is_empty() {
        return Vec::new();
    }
    let archive = match obtain(wanted, source).await {
        Ok(bytes) => inspect(bytes, wanted),
        Err(why) => Err(why),
    };
    let archive = match archive {
        Ok(archive) => Arc::new(archive),
        Err(why) => return targets.iter().map(|_| Err(why.clone())).collect(),
    };
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        out.push(match target {
            Target::CacheArchive(path) => replace_cache_archive(path, archive.clone()).await,
            Target::Installed(dir) => refresh_installed(dir, wanted, archive.clone(), ruby).await,
        });
    }
    out
}

/// The wanted archive's bytes, sha256-verified: a copy on disk, else a
/// download.
async fn obtain(wanted: &Wanted, source: &Source<'_>) -> Result<Vec<u8>, String> {
    let kind = wanted.kind;
    for path in &wanted.on_disk {
        if let Some(bytes) = read_archive(path).await {
            if wanted.sha256.contains(&sha256_hex_of(&bytes)) {
                return Ok(bytes);
            }
        }
    }
    // The first failure is the one reported, except that bytes that failed
    // the sha256 outrank a download that failed.
    let (mut mismatch, mut unreachable) = (None, None);
    for url in &wanted.urls {
        let fetched = match source {
            Source::DiskOnly => break,
            Source::PatchServer(api) => api
                .download_artifact(url)
                .await
                .map_err(|e| crate::utils::redact::redact_urls_in(&e.to_string()).into_owned()),
            Source::Registry => {
                let client = crate::vendor::registry_fetch::build_registry_client();
                crate::vendor::registry_fetch::download(&client, url).await
            }
        };
        match fetched {
            Ok(bytes) if wanted.sha256.contains(&sha256_hex_of(&bytes)) => return Ok(bytes),
            Ok(_) => {
                mismatch.get_or_insert_with(|| {
                    format!("the {kind} gem the server sent does not have the pinned sha256")
                });
            }
            Err(e) => {
                unreachable
                    .get_or_insert_with(|| format!("the {kind} gem could not be downloaded: {e}"));
            }
        }
    }
    Err(mismatch.or(unreachable).unwrap_or_else(|| match source {
        Source::DiskOnly => {
            format!("this run is offline and no verified copy of the {kind} gem is on disk")
        }
        _ => format!("nothing says where to download the {kind} gem"),
    }))
}

/// A regular file's bytes, when it is small enough to be a gem.
async fn read_archive(path: &Path) -> Option<Vec<u8>> {
    let meta = tokio::fs::symlink_metadata(path).await.ok()?;
    if !meta.is_file() || meta.len() > crate::vendor::registry_fetch::MAX_DOWNLOAD_BYTES {
        return None;
    }
    crate::utils::fs::read_regular_to_bytes(path).await.ok()
}

/// Check that `bytes` is the gem `wanted` names and read what the refresh
/// needs of its gemspec.
fn inspect(bytes: Vec<u8>, wanted: &Wanted) -> Result<Archive, String> {
    let kind = wanted.kind;
    let metadata = gem_metadata(&bytes)
        .ok_or_else(|| format!("the {kind} gem carries no readable gemspec"))?;
    let facts = parse_metadata(&String::from_utf8_lossy(&metadata))
        .ok_or_else(|| format!("the {kind} gem's gemspec names no gem and version"))?;
    if facts.full_name != wanted.leaf {
        return Err(format!(
            "the {kind} gem is {}, not {}",
            facts.full_name, wanted.leaf
        ));
    }
    Ok(Archive {
        bytes,
        metadata,
        native: facts.native,
    })
}

/// A `.gem`'s `metadata.gz` member, gunzipped: the gemspec as YAML.
fn gem_metadata(gem_bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut archive = tar::Archive::new(gem_bytes);
    for entry in archive.entries().ok()? {
        let entry = entry.ok()?;
        if !entry.path().is_ok_and(|p| p.as_os_str() == "metadata.gz") {
            continue;
        }
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(entry)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut out)
            .ok()?;
        return (out.len() as u64 <= MAX_METADATA_BYTES).then_some(out);
    }
    None
}

/// What a gemspec's YAML says that the refresh acts on.
#[derive(Debug, PartialEq, Eq)]
struct SpecFacts {
    /// `<name>-<version>`, plus `-<platform>` for a platform gem.
    full_name: String,
    /// `extensions` lists at least one build script.
    native: bool,
}

/// A top-level `key:` line of a gemspec's YAML and the rest of that line.
fn top_level_key(line: &str) -> Option<(&str, &str)> {
    let (key, rest) = line.split_once(':')?;
    let named = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (named && (rest.is_empty() || rest.starts_with(' '))).then_some((key, rest.trim()))
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// Read the name, version, platform and extensions out of a gemspec's YAML
/// (`Gem::Specification#to_yaml`, the shape every `.gem` carries): the
/// top-level keys of one mapping, each followed by its indented block or
/// its sequence items. `None` when the name or version cannot be read, or
/// the platform is not a plain string.
fn parse_metadata(yaml: &str) -> Option<SpecFacts> {
    let lines: Vec<&str> = yaml.lines().collect();
    let (mut name, mut version, mut platform, mut native) = (None, None, None, false);
    let mut i = 0;
    while i < lines.len() {
        let Some((key, value)) = top_level_key(lines[i]) else {
            i += 1;
            continue;
        };
        let end = (i + 1..lines.len())
            .find(|j| top_level_key(lines[*j]).is_some())
            .unwrap_or(lines.len());
        let block = &lines[i + 1..end];
        match key {
            "name" => name = Some(unquote(value).to_string()),
            // `version: !ruby/object:Gem::Version` over an indented
            // `version: 1.2.3`.
            "version" if value.is_empty() || value.starts_with('!') => {
                version = block
                    .iter()
                    .find_map(|l| l.trim().strip_prefix("version:"))
                    .map(|v| unquote(v).to_string())
            }
            "version" => version = Some(unquote(value).to_string()),
            "platform" if value.is_empty() || value.starts_with('!') => return None,
            "platform" => platform = Some(unquote(value).to_string()),
            "extensions" => {
                native = (!value.is_empty() && value != "[]")
                    || block.iter().any(|l| l.trim_start().starts_with('-'))
            }
            _ => {}
        }
        i = end;
    }
    let (name, version) = (name?, version?);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let full_name = match platform.as_deref() {
        None | Some("") | Some("ruby") => format!("{name}-{version}"),
        Some(platform) => format!("{name}-{version}-{platform}"),
    };
    Some(SpecFacts { full_name, native })
}

/// An installed copy's paths.
#[derive(Debug, Clone)]
struct Install {
    home: PathBuf,
    leaf: String,
    gem_dir: PathBuf,
}

impl Install {
    fn of(gem_dir: &Path) -> Option<Install> {
        let gem_dir = if gem_dir.has_root() {
            gem_dir.to_path_buf()
        } else {
            crate::utils::relpath::absolute_lexically(gem_dir)
        };
        let leaf = gem_dir.file_name()?.to_str()?.to_string();
        let gems = gem_dir.parent()?;
        if gems.file_name()? != "gems" {
            return None;
        }
        Some(Install {
            home: gems.parent()?.to_path_buf(),
            leaf,
            gem_dir,
        })
    }

    fn spec(&self) -> PathBuf {
        self.home
            .join("specifications")
            .join(format!("{}.gemspec", self.leaf))
    }

    fn cache_archive(&self) -> PathBuf {
        self.home.join("cache").join(format!("{}.gem", self.leaf))
    }

    fn stage(&self) -> PathBuf {
        self.home.join(STAGE_DIR).join(&self.leaf)
    }
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Replace the installed copy at `gem_dir` with the archive's gem.
async fn refresh_installed(
    gem_dir: &Path,
    wanted: &Wanted,
    archive: Arc<Archive>,
    ruby: &RubyEnv,
) -> Result<(), String> {
    let kind = wanted.kind;
    let install = Install::of(gem_dir)
        .filter(|install| install.leaf == wanted.leaf)
        .ok_or_else(|| format!("{} is not a RubyGems install of it", gem_dir.display()))?;
    // What can be read without changing anything.
    let checked = {
        let (install, archive) = (install.clone(), archive.clone());
        crate::utils::fs::run_blocking(move || -> Result<(), String> {
            if !is_real_dir(&install.gem_dir) {
                return Err(format!("{} is not a directory", install.gem_dir.display()));
            }
            // The stage is emptied and written under the gem home. A link
            // planted where it goes would move both somewhere else.
            for dir in [install.home.join(STAGE_DIR), install.stage()] {
                if std::fs::symlink_metadata(&dir).is_ok_and(|meta| !meta.is_dir()) {
                    return Err(format!(
                        "its stage directory {} is not a directory",
                        dir.display()
                    ));
                }
            }
            let spec = crate::utils::fs::read_regular_to_string_sync(&install.spec())
                .map_err(|e| format!("its installed gemspec is unreadable: {e}"))?;
            if crate::vendor::gem::gemspec_declares_extensions(&spec) != archive.native {
                return Err(format!(
                    "its installed gemspec and the {kind} gem disagree on native extensions"
                ));
            }
            // The archive RubyGems installed the copy from, when it is still
            // there: the `specifications/` entry written from it is kept, so
            // the new archive must carry the same gemspec.
            let installed_from =
                crate::utils::fs::read_regular_to_bytes_sync(&install.cache_archive())
                    .ok()
                    .and_then(|bytes| gem_metadata(&bytes));
            match installed_from {
                Some(metadata) if metadata != archive.metadata => Err(format!(
                    "the {kind} gem's gemspec differs from the installed one"
                )),
                _ => Ok(()),
            }
        })
        .await
    };
    checked?;

    let stage = install.stage();
    let staged_archive = stage.join(format!("{}.gem", install.leaf));
    // The stage: emptied of anything an interrupted run left, then the
    // archive, which a native build installs from and which replaces the
    // home's cached one.
    {
        let (stage, staged_archive, archive) =
            (stage.clone(), staged_archive.clone(), archive.clone());
        crate::utils::fs::run_blocking(move || -> std::io::Result<()> {
            crate::patch::copy_tree::force_remove_dir_all(&stage)?;
            std::fs::create_dir_all(&stage)?;
            std::fs::write(&staged_archive, &archive.bytes)
        })
        .await
        .map_err(|e| format!("could not stage it in {}: {e}", install.home.display()))?;
    }

    // The `(staged, live)` pairs swapped in together: the gem dir, then a
    // native gem's extension dir.
    let built: Result<Vec<(PathBuf, PathBuf)>, String> = if archive.native {
        if !ruby.rebuild {
            Err("it builds a native extension, and --no-gem-native-rebuild is set".to_string())
        } else {
            crate::patch::gem_ext::install_staged(
                &install.gem_dir,
                &staged_archive,
                &stage.join("home"),
                ruby,
            )
            .await
            .map(|staged| {
                vec![
                    (staged.gem_dir, install.gem_dir.clone()),
                    (staged.extension_dir, staged.installed_extension_dir),
                ]
            })
            .map_err(|why| format!("its native extension could not be rebuilt: {why}"))
        }
    } else {
        let (archive, dest) = (archive.clone(), stage.join("gem"));
        let swaps = vec![(dest.clone(), install.gem_dir.clone())];
        crate::utils::fs::run_blocking(move || {
            crate::vendor::registry_fetch::extract_gem_data_strict(&archive.bytes, &dest)
                .map(|()| swaps)
                .map_err(|why| format!("the {kind} gem could not be unpacked: {why}"))
        })
        .await
    };
    let live_archive = install.cache_archive();
    let committed = match built {
        Err(why) => Err(why),
        Ok(mut swaps) => {
            let stage = stage.clone();
            crate::utils::fs::run_blocking(move || {
                // The home's cached archive last, and only when there is
                // one: it is replaced, never added to a pruned cache.
                if is_real_file(&live_archive) {
                    copy_mode(&live_archive, &staged_archive);
                    swaps.push((staged_archive, live_archive));
                }
                swap_all(&swaps, &stage.join("old"))
                    .map_err(|e| format!("it could not be moved into place: {e}"))
            })
            .await
        }
    };
    // What is left in the stage: the previous copy after a swap, the unused
    // new one after a failure.
    let home = install.home.clone();
    let _ = crate::utils::fs::run_blocking(move || {
        let removed = crate::patch::copy_tree::force_remove_dir_all(&stage);
        let _ = std::fs::remove_dir(home.join(STAGE_DIR));
        removed
    })
    .await;
    committed
}

/// Give `to` the permission bits of `from` (best effort).
fn copy_mode(from: &Path, to: &Path) {
    if let Ok(meta) = std::fs::metadata(from) {
        let _ = std::fs::set_permissions(to, meta.permissions());
    }
}

/// Swap every `(staged, live)` pair in, in order; the previous `live` of
/// pair `n` ends up under `parked/<n>`. All or nothing: a swap that fails
/// puts the earlier ones back.
fn swap_all(swaps: &[(PathBuf, PathBuf)], parked: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(parked)?;
    // Where each swapped-out original now is.
    let mut done: Vec<(PathBuf, &Path)> = Vec::new();
    for (index, (staged, live)) in swaps.iter().enumerate() {
        // A fresh dir takes the mode of the one it replaces.
        if is_real_dir(live) {
            copy_mode(live, staged);
        }
        match swap_into(staged, live, &parked.join(index.to_string())) {
            Ok(old) => done.push((old, live)),
            Err(e) => {
                for (undo, (old, live)) in done.iter().enumerate().rev() {
                    let _ = swap_into(old, live, &parked.join(format!("undone-{undo}")));
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Put `incoming` at `live` and return where what was at `live` now is.
/// One atomic exchange where the platform has it, so `live` always names
/// one of the two; otherwise two renames (`live` → `parked`, `incoming` →
/// `live`), the first undone when the second fails.
fn swap_into(incoming: &Path, live: &Path, parked: &Path) -> std::io::Result<PathBuf> {
    if exchange(incoming, live).is_ok() {
        return Ok(incoming.to_path_buf());
    }
    std::fs::rename(live, parked)?;
    match std::fs::rename(incoming, live) {
        Ok(()) => Ok(parked.to_path_buf()),
        Err(e) => {
            let _ = std::fs::rename(parked, live);
            Err(e)
        }
    }
}

/// Atomically exchange two paths on one filesystem (`renameat2` with
/// `RENAME_EXCHANGE`, `renamex_np` with `RENAME_SWAP`). `Err` wherever
/// that is not available: another platform, a filesystem without it.
fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
        };
        let (a, b) = (c(a)?, c(b)?);
        // SAFETY: both arguments are NUL-terminated paths that outlive the
        // call, which touches nothing else.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (a, b);
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Replace the archive at `path` in Bundler's cache dir with the verified
/// one: staged beside it and renamed over it, so a reader sees the whole
/// old or the whole new file.
async fn replace_cache_archive(path: &Path, archive: Arc<Archive>) -> Result<(), String> {
    let path = path.to_path_buf();
    crate::utils::fs::run_blocking(move || {
        if !is_real_file(&path) {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let leaf = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stage = path.with_file_name(format!(".{leaf}.socket-patch-new"));
        let written = std::fs::write(&stage, &archive.bytes).and_then(|()| {
            copy_mode(&path, &stage);
            std::fs::rename(&stage, &path)
        });
        written.map_err(|e| {
            let _ = std::fs::remove_file(&stage);
            format!("{} could not be replaced: {e}", path.display())
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn tar_of(members: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, bytes, mode) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            tar.append_data(&mut header, name, *bytes).unwrap();
        }
        tar.into_inner().unwrap()
    }

    /// The gemspec YAML RubyGems writes for `name`-`version`.
    fn metadata(name: &str, version: &str, extensions: &[&str]) -> String {
        let extensions = if extensions.is_empty() {
            "extensions: []\n".to_string()
        } else {
            let items: String = extensions.iter().map(|e| format!("- {e}\n")).collect();
            format!("extensions:\n{items}")
        };
        format!(
            "--- !ruby/object:Gem::Specification\nname: {name}\nversion: \
             !ruby/object:Gem::Version\n  version: {version}\nplatform: ruby\nauthors:\n- \
             lab\nbindir: bin\ndependencies:\n- !ruby/object:Gem::Dependency\n  name: \
             other\n  version_requirements: !ruby/object:Gem::Requirement\n    \
             requirements:\n    - - \">=\"\n      - !ruby/object:Gem::Version\n        \
             version: '0'\nexecutables: []\n{extensions}files:\n- lib/a.rb\nrequire_paths:\n- \
             lib\nrubygems_version: 3.6.9\n"
        )
    }

    fn gem(name: &str, version: &str, files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        gem_with(&metadata(name, version, &[]), files)
    }

    fn gem_with(metadata: &str, files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        tar_of(&[
            ("metadata.gz", &gz(metadata.as_bytes()), 0o444),
            ("data.tar.gz", &gz(&tar_of(files)), 0o444),
        ])
    }

    fn sha(bytes: &[u8]) -> String {
        sha256_hex_of(bytes)
    }

    /// A gem home holding `rack-2.2.3` installed from `archive`.
    fn install(home: &Path, lib: &str, archive: &[u8]) -> PathBuf {
        let gem_dir = home.join("gems").join("rack-2.2.3");
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("rack.rb"), lib).unwrap();
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(home.join("cache").join("rack-2.2.3.gem"), archive).unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications").join("rack-2.2.3.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \
             \"2.2.3\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n",
        )
        .unwrap();
        gem_dir
    }

    fn wanted(archive: &[u8], on_disk: &[&Path]) -> Wanted {
        Wanted {
            leaf: "rack-2.2.3".to_string(),
            kind: "patched",
            sha256: BTreeSet::from([sha(archive)]),
            urls: Vec::new(),
            on_disk: on_disk.iter().map(|p| p.to_path_buf()).collect(),
        }
    }

    fn ruby(cwd: &Path) -> RubyEnv {
        RubyEnv {
            cwd: cwd.to_path_buf(),
            rebuild: true,
        }
    }

    const UPSTREAM_LIB: &[u8] = b"VULNERABLE\n";
    const PATCHED_LIB: &[u8] = b"PATCHED\n";

    fn upstream() -> Vec<u8> {
        gem("rack", "2.2.3", &[("lib/rack.rb", UPSTREAM_LIB, 0o644)])
    }

    fn patched() -> Vec<u8> {
        gem(
            "rack",
            "2.2.3",
            &[
                ("lib/rack.rb", PATCHED_LIB, 0o644),
                ("bin/rackup", b"#!/usr/bin/env ruby\n", 0o755),
            ],
        )
    }

    #[test]
    fn metadata_names_the_gem_and_its_extensions() {
        assert_eq!(
            parse_metadata(&metadata("rack", "2.2.3", &[])),
            Some(SpecFacts {
                full_name: "rack-2.2.3".to_string(),
                native: false
            })
        );
        assert_eq!(
            parse_metadata(&metadata("puma", "4.3.5", &["ext/puma_http11/extconf.rb"])),
            Some(SpecFacts {
                full_name: "puma-4.3.5".to_string(),
                native: true
            })
        );
        // A platform gem, quoted scalars, an indented sequence.
        let platform = "--- !ruby/object:Gem::Specification\nname: \"nokogiri\"\nversion: \
                        !ruby/object:Gem::Version\n  version: '1.19.7'\nplatform: \
                        arm64-darwin\nextensions:\n  - ext/x/extconf.rb\n";
        assert_eq!(
            parse_metadata(platform),
            Some(SpecFacts {
                full_name: "nokogiri-1.19.7-arm64-darwin".to_string(),
                native: true
            })
        );
        // A dependency's nested name and version are not the gem's.
        assert_eq!(
            parse_metadata("dependencies:\n- name: x\n  version: 1\n"),
            None
        );
        assert_eq!(
            parse_metadata("name: a\nversion: 1\nplatform: !ruby/object:X\n"),
            None
        );
    }

    #[tokio::test]
    async fn an_installed_copy_and_its_archive_become_the_verified_gem() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        std::fs::write(gem_dir.join("leftover.o"), b"build product").unwrap();
        let source = tmp.path().join("patched.gem");
        std::fs::write(&source, patched()).unwrap();

        let out = refresh(
            &wanted(&patched(), &[&source]),
            &[Target::Installed(gem_dir.clone())],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        assert_eq!(out, vec![Ok(())]);
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            PATCHED_LIB
        );
        assert!(gem_dir.join("bin/rackup").is_file());
        // The tree is the archive's, not the old one patched over.
        assert!(!gem_dir.join("leftover.o").exists());
        assert_eq!(
            sha(&std::fs::read(home.join("cache/rack-2.2.3.gem")).unwrap()),
            sha(&patched())
        );
        assert!(home.join("specifications/rack-2.2.3.gemspec").is_file());
        assert!(!home.join(STAGE_DIR).exists(), "the stage is cleaned up");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| {
                std::fs::metadata(gem_dir.join(p))
                    .unwrap()
                    .permissions()
                    .mode()
            };
            assert_eq!(mode("bin/rackup") & 0o111, 0o111);
            assert_eq!(mode("lib/rack.rb") & 0o111, 0);
        }
    }

    /// A link planted where the stage directory goes would move the
    /// staging, and the removal of an interrupted run's leftovers, out of
    /// the gem home: the refresh refuses and touches nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_stage_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        let archive = tmp.path().join("patched.gem");
        std::fs::write(&archive, patched()).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(outside.join("rack-2.2.3")).unwrap();
        std::fs::write(outside.join("rack-2.2.3/keep"), b"mine").unwrap();
        std::os::unix::fs::symlink(&outside, home.join(STAGE_DIR)).unwrap();

        let out = refresh(
            &wanted(&patched(), &[&archive]),
            &[Target::Installed(gem_dir.clone())],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        let why = out[0].clone().expect_err("a linked stage is refused");
        assert!(why.contains("is not a directory"), "{why}");
        assert_eq!(
            std::fs::read(outside.join("rack-2.2.3/keep")).unwrap(),
            b"mine",
            "nothing outside the gem home is removed"
        );
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            UPSTREAM_LIB
        );
    }

    #[tokio::test]
    async fn an_unverified_archive_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        // The only copy on disk is not the pinned one, and the run is offline.
        let other = tmp.path().join("other.gem");
        std::fs::write(
            &other,
            gem("rack", "2.2.3", &[("lib/rack.rb", b"EVIL\n", 0o644)]),
        )
        .unwrap();
        let cache = tmp.path().join("vendor/cache/rack-2.2.3.gem");
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, upstream()).unwrap();

        let out = refresh(
            &wanted(&patched(), &[&other]),
            &[
                Target::Installed(gem_dir.clone()),
                Target::CacheArchive(cache.clone()),
            ],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        assert_eq!(out.len(), 2);
        for outcome in &out {
            let why = outcome.as_ref().unwrap_err();
            assert!(why.contains("offline"), "{why}");
        }
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            UPSTREAM_LIB
        );
        assert_eq!(std::fs::read(&cache).unwrap(), upstream());
        assert_eq!(
            std::fs::read(home.join("cache/rack-2.2.3.gem")).unwrap(),
            upstream()
        );
    }

    #[tokio::test]
    async fn a_cache_dir_archive_is_replaced_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("vendor/cache/rack-2.2.3.gem");
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, upstream()).unwrap();
        let source = tmp.path().join("patched.gem");
        std::fs::write(&source, patched()).unwrap();
        let out = refresh(
            &wanted(&patched(), &[&source]),
            &[Target::CacheArchive(cache.clone())],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        assert_eq!(out, vec![Ok(())]);
        assert_eq!(std::fs::read(&cache).unwrap(), patched());
        let left: Vec<_> = std::fs::read_dir(cache.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("rack-2.2.3.gem")]);
    }

    #[tokio::test]
    async fn an_archive_of_another_gem_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        let wrong = gem("rack", "2.2.4", &[("lib/rack.rb", PATCHED_LIB, 0o644)]);
        let source = tmp.path().join("wrong.gem");
        std::fs::write(&source, &wrong).unwrap();
        let out = refresh(
            &wanted(&wrong, &[&source]),
            &[Target::Installed(gem_dir.clone())],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        assert_eq!(
            out,
            vec![Err(
                "the patched gem is rack-2.2.4, not rack-2.2.3".to_string()
            )]
        );
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            UPSTREAM_LIB
        );
    }

    #[tokio::test]
    async fn a_gem_with_another_gemspec_or_a_link_inside_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        let run = |archive: Vec<u8>| {
            let (gem_dir, tmp) = (gem_dir.clone(), tmp.path().to_path_buf());
            async move {
                let source = tmp.join("candidate.gem");
                std::fs::write(&source, &archive).unwrap();
                refresh(
                    &wanted(&archive, &[&source]),
                    &[Target::Installed(gem_dir)],
                    &Source::DiskOnly,
                    &ruby(&tmp),
                )
                .await
                .remove(0)
            }
        };
        // Another gemspec than the one the installed copy was written from.
        let respecced = gem_with(
            &metadata("rack", "2.2.3", &[]).replace("- lib\n", "- lib\n- extra\n"),
            &[("lib/rack.rb", PATCHED_LIB, 0o644)],
        );
        let why = run(respecced).await.unwrap_err();
        assert!(why.contains("gemspec differs"), "{why}");
        // A native gem over a copy whose gemspec builds nothing.
        let native = gem_with(
            &metadata("rack", "2.2.3", &["ext/rack/extconf.rb"]),
            &[("lib/rack.rb", PATCHED_LIB, 0o644)],
        );
        let why = run(native).await.unwrap_err();
        assert!(why.contains("disagree on native extensions"), "{why}");
        // A symlink member: RubyGems would create it, the extraction would not.
        let mut data = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        data.append_link(&mut header, "lib/link.rb", "rack.rb")
            .unwrap();
        let linked = tar_of(&[
            (
                "metadata.gz",
                &gz(metadata("rack", "2.2.3", &[]).as_bytes()),
                0o444,
            ),
            ("data.tar.gz", &gz(&data.into_inner().unwrap()), 0o444),
        ]);
        let why = run(linked).await.unwrap_err();
        assert!(why.contains("could not be unpacked"), "{why}");

        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            UPSTREAM_LIB
        );
        assert_eq!(
            std::fs::read(home.join("cache/rack-2.2.3.gem")).unwrap(),
            upstream()
        );
        assert!(!home.join(STAGE_DIR).exists());
    }

    /// A later swap fails after the gem dir went in: the gem dir comes
    /// back, so the copy and the archive it is judged by never disagree.
    #[test]
    fn a_failed_swap_puts_the_earlier_ones_back() {
        let pair = |root: &Path| {
            let (staged, live) = (root.join("staged"), root.join("live"));
            for (dir, content) in [(&staged, "new"), (&live, "old")] {
                std::fs::create_dir_all(dir).unwrap();
                std::fs::write(dir.join("f"), content).unwrap();
            }
            (staged, live)
        };
        let tmp = tempfile::tempdir().unwrap();
        let (staged, live) = pair(tmp.path());
        // The second pair's staged side does not exist, so its swap fails.
        let swaps = vec![
            (staged, live.clone()),
            (tmp.path().join("missing"), tmp.path().join("also-missing")),
        ];
        assert!(swap_all(&swaps, &tmp.path().join("parked")).is_err());
        assert_eq!(std::fs::read_to_string(live.join("f")).unwrap(), "old");

        let tmp = tempfile::tempdir().unwrap();
        let (staged, live) = pair(tmp.path());
        assert!(swap_all(&[(staged, live.clone())], &tmp.path().join("parked")).is_ok());
        assert_eq!(std::fs::read_to_string(live.join("f")).unwrap(), "new");
    }

    #[tokio::test]
    async fn a_pruned_cache_is_not_refilled() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gem_dir = install(&home, "VULNERABLE\n", &upstream());
        std::fs::remove_file(home.join("cache/rack-2.2.3.gem")).unwrap();
        let source = tmp.path().join("patched.gem");
        std::fs::write(&source, patched()).unwrap();
        let out = refresh(
            &wanted(&patched(), &[&source]),
            &[Target::Installed(gem_dir.clone())],
            &Source::DiskOnly,
            &ruby(tmp.path()),
        )
        .await;
        assert_eq!(out, vec![Ok(())]);
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            PATCHED_LIB
        );
        assert!(!home.join("cache/rack-2.2.3.gem").exists());
    }

    #[tokio::test]
    async fn a_native_gem_is_left_alone_without_a_rebuild() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let native_meta = metadata("rack", "2.2.3", &["ext/rack/extconf.rb"]);
        let old = gem_with(&native_meta, &[("lib/rack.rb", UPSTREAM_LIB, 0o644)]);
        let new = gem_with(&native_meta, &[("lib/rack.rb", PATCHED_LIB, 0o644)]);
        let gem_dir = install(&home, "VULNERABLE\n", &old);
        std::fs::write(
            home.join("specifications/rack-2.2.3.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.extensions = \
             [\"ext/rack/extconf.rb\".freeze]\nend\n",
        )
        .unwrap();
        let source = tmp.path().join("patched.gem");
        std::fs::write(&source, &new).unwrap();
        let out = refresh(
            &wanted(&new, &[&source]),
            &[Target::Installed(gem_dir.clone())],
            &Source::DiskOnly,
            &RubyEnv {
                cwd: tmp.path().to_path_buf(),
                rebuild: false,
            },
        )
        .await;
        let why = out[0].as_ref().unwrap_err();
        assert!(why.contains("--no-gem-native-rebuild"), "{why}");
        assert_eq!(
            std::fs::read(gem_dir.join("lib/rack.rb")).unwrap(),
            UPSTREAM_LIB
        );
        assert_eq!(
            std::fs::read(home.join("cache/rack-2.2.3.gem")).unwrap(),
            old
        );
        assert!(!home.join(STAGE_DIR).exists());
    }
}
