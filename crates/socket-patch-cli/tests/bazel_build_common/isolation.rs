//! The per-test temp root every Bazel write must stay inside, and the
//! checks that it did.
//!
//! One [`Scratch`] holds one workspace copy and one output user root (so
//! one output base and one server). Nothing a test runs may write outside
//! it: not the developer's `~/.cache/bazel`, not the shared system temp
//! directory, not the default bazelisk home.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::env::{self, Version};

/// The temp root of one test (`<T>` in the design), with fixed places for
/// everything a Bazel run writes.
pub struct Scratch {
    /// `<T>`, canonical (macOS temp directories sit behind a symlink, and
    /// Bazel prints resolved paths).
    pub root: PathBuf,
    /// The workspace copy Bazel runs in.
    pub workspace: PathBuf,
    /// `--output_user_root`: `<T>/root`, or a directory under
    /// [`env::OUTPUT_ROOT`] when a short path is needed (Windows).
    pub output_user_root: PathBuf,
    /// `java.io.tmpdir` of the server JVM, and `TMPDIR` of every child.
    pub tmp: PathBuf,
    /// `HOME` / `USERPROFILE` of every child.
    pub home: PathBuf,
    /// `--repository_cache`.
    pub repository_cache: PathBuf,
    /// `BAZELISK_HOME` when the launcher is bazelisk.
    pub bazelisk_home: PathBuf,
    /// Holds `<T>` until drop; removal goes through [`remove_tree`] first.
    _dir: tempfile::TempDir,
}

impl Scratch {
    /// A new temp root. The repository cache is the persistent one under
    /// [`env::CACHE_ROOT`] when that is set, else an empty `<T>/cache`.
    pub fn new() -> Scratch {
        Self::create(env::var(env::CACHE_ROOT).map(|root| PathBuf::from(root).join("repos")))
    }

    /// A new temp root whose repository cache is empty whatever
    /// [`env::CACHE_ROOT`] says. A tamper or withdrawal twin, and any
    /// assertion about what the fixture host received, must run on one:
    /// with a warm cache the same URL and checksum pass with zero requests.
    pub fn cold() -> Scratch {
        Self::create(None)
    }

    fn create(shared_cache: Option<PathBuf>) -> Scratch {
        let dir = tempfile::Builder::new()
            .prefix("sp-bazel-")
            .tempdir()
            .expect("create the scratch root");
        let root = dir.path().canonicalize().expect("canonical scratch root");
        let root = strip_verbatim(root);
        let output_user_root = match env::var(env::OUTPUT_ROOT) {
            Some(short) => {
                let name = root.file_name().expect("scratch root has a name");
                PathBuf::from(short).join(name)
            }
            None => root.join("root"),
        };
        // A directory named by the environment may be relative; Bazel would
        // resolve it against the workspace copy.
        let absolute = |dir: PathBuf| {
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
            strip_verbatim(dir.canonicalize().expect("canonical directory"))
        };
        let scratch = Scratch {
            workspace: absolute(root.join("ws")),
            tmp: absolute(root.join("tmp")),
            home: absolute(root.join("home")),
            repository_cache: absolute(shared_cache.unwrap_or_else(|| root.join("cache"))),
            bazelisk_home: root.join("bazelisk"),
            output_user_root: absolute(output_user_root),
            root,
            _dir: dir,
        };
        // 9.3.2 exits 2 when its contents cache (a child of the repository
        // cache) lies inside the main repository.
        assert!(
            !scratch.repository_cache.starts_with(&scratch.workspace),
            "the repository cache {} must lie outside the workspace copy {}",
            scratch.repository_cache.display(),
            scratch.workspace.display()
        );
        scratch
    }

    /// Fail fast on a workspace path this Bazel cannot run in, instead of
    /// on whatever error the server prints first.
    pub fn assert_path_supported(&self, version: &Version) {
        for path in [&self.workspace, &self.output_user_root] {
            if let Err(why) = check_path(version, path) {
                panic!("{why}");
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Bazel marks the install base and fetched repositories read-only.
        remove_tree(&self.output_user_root);
        remove_tree(&self.root);
    }
}

/// Bazel 7.2.0 and earlier refuse to run in a path with a space, and 7.7.2
/// and earlier in one with a non-ASCII byte.
pub fn check_path(version: &Version, path: &Path) -> Result<(), String> {
    let text = path.to_string_lossy();
    if text.contains(' ') && !version.at_least(7, 2, 1) {
        return Err(format!(
            "Bazel {} does not run in a path with a space: {text}",
            version.text
        ));
    }
    if !text.is_ascii() && !version.at_least(7, 7, 3) {
        return Err(format!(
            "Bazel {} does not run in a path with a non-ASCII byte: {text}",
            version.text
        ));
    }
    Ok(())
}

/// `\\?\C:\x` → `C:\x`: Bazel and the JVM reject the extended Windows
/// paths `canonicalize` returns. Identity elsewhere.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(rest) = path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        if !rest.starts_with("UNC") {
            return rest.into();
        }
    }
    path
}

/// Make everything under `dir` writable, then remove it. Best effort and
/// silent: this runs from `Drop`, where a panic would abort the test binary.
pub fn remove_tree(dir: &Path) {
    fn make_writable(path: &Path) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if meta.file_type().is_symlink() {
            return;
        }
        let mut perms = meta.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(perms.mode() | 0o700);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
                make_writable(&entry.path());
            }
        }
    }
    if dir.exists() {
        make_writable(dir);
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The directories a Bazel or bazelisk that escaped isolation writes: the
/// default output user roots of every line and OS, and bazelisk's default
/// home. Read from the test process's own environment, which is the
/// developer's or the runner's real one.
pub fn default_locations() -> Vec<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    let mut out = Vec::new();
    let user = var("USER").or_else(|| var("USERNAME"));
    if let Some(home) = var("HOME")
        .or_else(|| var("USERPROFILE"))
        .map(PathBuf::from)
    {
        out.push(home.join(".cache").join("bazel"));
        out.push(home.join(".cache").join("bazelisk"));
        out.push(home.join("Library").join("Caches").join("bazel"));
        out.push(home.join("Library").join("Caches").join("bazelisk"));
        if let Some(user) = &user {
            // Windows: the output user root is `%USERPROFILE%\_bazel_<user>`.
            out.push(home.join(format!("_bazel_{}", user.to_string_lossy())));
        }
    }
    if let Some(user) = &user {
        let name = format!("_bazel_{}", user.to_string_lossy());
        out.push(PathBuf::from("/private/var/tmp").join(&name));
        out.push(PathBuf::from("/var/tmp").join(name));
    }
    if let Some(cache) = var("XDG_CACHE_HOME").map(PathBuf::from) {
        out.push(cache.join("bazel"));
        out.push(cache.join("bazelisk"));
    }
    if let Some(local) = var("LOCALAPPDATA").map(PathBuf::from) {
        out.push(local.join("bazelisk"));
    }
    out.sort();
    out.dedup();
    out
}

/// What [`default_locations`] looked like at one moment: whether each
/// exists and, two levels deep, the modification time of every entry. Two
/// levels reach `<root>/_bazel_<user>/<md5 of the workspace>` and
/// `<bazelisk home>/downloads/<kind>`, which a stray run creates.
pub struct OutsideState(Vec<(PathBuf, Fingerprint)>);

/// A directory and its entries two levels down, each with its
/// modification time.
type Fingerprint = Vec<(PathBuf, Option<SystemTime>)>;

impl OutsideState {
    pub fn capture() -> OutsideState {
        Self::capture_of(&default_locations())
    }

    pub fn capture_of(locations: &[PathBuf]) -> OutsideState {
        OutsideState(
            locations
                .iter()
                .map(|dir| (dir.clone(), fingerprint(dir)))
                .collect(),
        )
    }

    /// One line per entry that appeared, vanished or changed since capture.
    pub fn changes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (dir, before) in &self.0 {
            let after = fingerprint(dir);
            for (path, time) in &after {
                match before.iter().find(|(p, _)| p == path) {
                    None => out.push(format!("created: {}", path.display())),
                    Some((_, old)) if old != time => {
                        out.push(format!("changed: {}", path.display()));
                    }
                    Some(_) => {}
                }
            }
            for (path, _) in before {
                if !after.iter().any(|(p, _)| p == path) {
                    out.push(format!("removed: {}", path.display()));
                }
            }
        }
        out
    }

    /// Nothing outside the scratch root was created or changed. A failure
    /// can also come from another Bazel on the same machine that runs
    /// without isolation; the message names the paths so a reader can tell.
    pub fn assert_untouched(&self, when: &str) {
        let changes = self.changes();
        assert!(
            changes.is_empty(),
            "{when}: a default Bazel or bazelisk location outside the scratch root was written:\n{}",
            changes.join("\n")
        );
    }
}

/// The [`Fingerprint`] of `dir`; empty when it does not exist.
fn fingerprint(dir: &Path) -> Fingerprint {
    fn visit(path: &Path, depth: u32, out: &mut Fingerprint) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        out.push((path.to_path_buf(), meta.modified().ok()));
        if depth > 0 && meta.is_dir() {
            for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
                visit(&entry.path(), depth - 1, out);
            }
        }
    }
    let mut out = Vec::new();
    visit(dir, 2, &mut out);
    out.sort();
    out
}

/// The arguments the server JVM of `output_base` was started with
/// (`server/cmdline`, NUL-separated). Empty when no server ever ran there.
pub fn server_cmdline(output_base: &Path) -> Vec<String> {
    let raw = std::fs::read(output_base.join("server").join("cmdline")).unwrap_or_default();
    raw.split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// The per-process files a JVM writes into the shared temp directory when
/// `-XX:-UsePerfData` did not reach it: `hsperfdata_<user>/<pid>`, under
/// `/tmp` and under this process's own temp directory (on macOS the JVM
/// ignores `TMPDIR` and uses the per-user directory). Keyed by pid, so
/// another server on the same machine cannot cause a false alarm.
pub fn stray_perf_data(server_pid: u32) -> Vec<PathBuf> {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let name = format!("hsperfdata_{user}");
    let mut dirs = vec![PathBuf::from("/tmp"), std::env::temp_dir()];
    dirs.dedup();
    dirs.into_iter()
        .map(|dir| dir.join(&name).join(server_pid.to_string()))
        .filter(|path| path.exists())
        .collect()
}
