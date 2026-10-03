//! What the two real-sbt drivers share (`sbt_build_common` for the hosted
//! capstones, `sbt_vendor_build_common` for the vendored ones): one
//! environment contract, one warm-cache layout, one hermetic native sbt
//! command ([`native_command`]: the scrub, the per-test home and every sbt
//! location pinned) with its group-killing timeout ([`wait_or_kill_group`]),
//! the path spelling Java accepts ([`java_path`], [`file_url`]), one
//! `export` classpath parser. Each driver keeps its fixture shapes (and the
//! hosted one its Docker runner); anything both must agree on lives here,
//! so the two suites can never run sbt two ways.
//!
//! `scripts/sbt-compat-matrix.sh` drives both through this contract
//! (`docs/testing/sbt-compatibility.md`).

#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// The sbt launcher script to run (`<dir>/bin/sbt`, or a launcher
/// directory for the Docker runner); unset = `sbt` on `PATH`.
pub const SBT_ENV: &str = "SOCKET_PATCH_SBT_E2E_SBT";
/// An image with a JDK to run sbt in (hosted driver only).
pub const DOCKER_ENV: &str = "SOCKET_PATCH_SBT_E2E_DOCKER";
/// The `sbt.version` every fixture pins.
pub const VERSION_ENV: &str = "SOCKET_PATCH_SBT_E2E_VERSION";
/// Non-empty: a missing toolchain or an unreachable warm-up is a failure.
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_SBT_E2E_REQUIRED";
/// A warm cache ([`Seed`]); never required.
pub const SEED_ENV: &str = "SOCKET_PATCH_SBT_E2E_SEED";
/// The default `sbt.version`.
pub const DEFAULT_VERSION: &str = "1.13.0";
/// The hard limit on one sbt run.
pub const TIMEOUT: Duration = Duration::from_secs(300);

/// What no sbt child inherits (plus every `COURSIER_*`).
pub const SCRUB: &[&str] = &[
    "SBT_OPTS",
    "JAVA_OPTS",
    "JVM_OPTS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "SBT_NATIVE_CLIENT",
    "CI",
    "GITHUB_ACTIONS",
    "CIRCLECI",
    "WORKSPACE",
    "TEAMCITY_VERSION",
    "TRAVIS",
    "BUILD_NUMBER",
];

/// `path` as Java accepts it: Windows' verbatim prefix (`\\?\C:\x`,
/// `\\?\UNC\srv\share`), which `std::fs::canonicalize` returns there, is
/// dropped (Java NIO rejects it: `InvalidPathException`).
pub fn java_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// `path` canonicalized (a symlinked macOS temp dir resolved, so the
/// evidence sbt writes names the paths the CLI reads), in Java's spelling.
pub fn canonical(path: &Path) -> PathBuf {
    java_path(&std::fs::canonicalize(path).expect("canonicalize"))
}

/// The `file:` URL of the directory `dir`: `file:///C:/x` on Windows (a
/// drive letter is no host, and backslashes are no URL), `file:///x`
/// elsewhere.
pub fn file_url(dir: &Path) -> String {
    let text = java_path(dir).to_string_lossy().replace('\\', "/");
    if let Some(unc) = text.strip_prefix("//") {
        format!("file://{unc}")
    } else if text.starts_with('/') {
        format!("file://{text}")
    } else {
        format!("file:///{text}")
    }
}

/// Where one test's sbt state lives: every location sbt (and the JVM's
/// `user.home`, which `Resolver.mavenLocal` and `~/.sbt/repositories`
/// follow) would otherwise take from the machine.
#[derive(Debug, Clone)]
pub struct Locations {
    /// `HOME`, `USERPROFILE` and `-Duser.home`; `mavenLocal` is
    /// `<home>/.m2/repository` (also `-Dmaven.repo.local`).
    pub home: PathBuf,
    pub global_base: PathBuf,
    pub boot: PathBuf,
    pub ivy_home: PathBuf,
    /// `COURSIER_CACHE`, the only Coursier location.
    pub coursier: PathBuf,
}

/// The launcher and JVM flags pinning sbt to `loc` (no server, batch,
/// plain logs), for sbt `version`; both runners pass them.
pub fn hermetic_args(loc: &Locations, version: &str) -> Vec<String> {
    let d = |k: &str, v: &Path| format!("-D{k}={}", java_path(v).display());
    let mut out = vec![
        "-batch".to_string(),
        "-no-colors".to_string(),
        d("user.home", &loc.home),
        d("maven.repo.local", &loc.home.join(".m2").join("repository")),
        d("sbt.global.base", &loc.global_base),
        d("sbt.boot.directory", &loc.boot),
        d("sbt.ivy.home", &loc.ivy_home),
        "-Dsbt.server.autostart=false".to_string(),
        "-Dsbt.supershell=false".to_string(),
        "-Dsbt.log.noformat=true".to_string(),
    ];
    // sbt 2 otherwise starts a client against a server.
    if line(version) == "2" {
        out.push("--server".to_string());
    }
    out
}

/// `sbt` (the launcher) in `cwd`, hermetic: the [`SCRUB`] list, every
/// `COURSIER_*` and `SOCKET_*` variable removed, `HOME` / `USERPROFILE` /
/// `COURSIER_CACHE` and [`hermetic_args`] pinned to `loc`, and (on Unix) its
/// own process group so [`wait_or_kill_group`] kills the JVM the launcher
/// script forks too. The caller adds the sbt commands and the stdio.
pub fn native_command(sbt: &OsStr, cwd: &Path, loc: &Locations, version: &str) -> Command {
    let mut cmd = Command::new(sbt);
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy();
        if k.starts_with("COURSIER_") || k.starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    for key in SCRUB {
        cmd.env_remove(key);
    }
    cmd.current_dir(cwd)
        .env("HOME", java_path(&loc.home))
        .env("USERPROFILE", java_path(&loc.home))
        .env("COURSIER_CACHE", java_path(&loc.coursier))
        .args(hermetic_args(loc, version));
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    cmd
}

/// Wait for `child`; past `limit` kill its whole process group (Unix; the
/// child alone elsewhere) and return `None`.
pub fn wait_or_kill_group(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait sbt") {
            return Some(status);
        }
        if started.elapsed() > limit {
            #[cfg(unix)]
            // SAFETY: signals the group `process_group(0)` made.
            unsafe {
                libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `key`'s value when set and not blank.
pub fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Whether [`REQUIRED_ENV`] is set (CI legs: never skip).
pub fn required() -> bool {
    env_value(REQUIRED_ENV).is_some()
}

/// The `sbt.version` under test ([`VERSION_ENV`], default
/// [`DEFAULT_VERSION`]).
pub fn version() -> String {
    env_value(VERSION_ENV).unwrap_or_else(|| DEFAULT_VERSION.to_string())
}

/// The syntax line of `version`: `0.13`, `1` or `2`.
pub fn line(version: &str) -> &'static str {
    if version.starts_with("0.13") {
        "0.13"
    } else if version.starts_with("2.") {
        "2"
    } else {
        "1"
    }
}

/// Whether `version` resolves through Ivy (0.13, 1.0–1.2).
pub fn uses_ivy(version: &str) -> bool {
    line(version) == "0.13"
        || ["1.0.", "1.1.", "1.2."]
            .iter()
            .any(|p| version.starts_with(p))
}

/// The warm cache [`SEED_ENV`] names, in either layout:
///
/// - a home directory (`.cache/coursier/v1`, `.ivy2`, `.sbt/boot`), such as
///   `/root` in `tests/docker/Dockerfile.sbt`, whose image bakes warm
///   caches there;
/// - a flat cache directory (`coursier/v1`, `ivy2`, `boot`).
///
/// A layout part that does not exist is `None`.
#[derive(Debug, Clone, Default)]
pub struct Seed {
    pub coursier: Option<PathBuf>,
    pub ivy: Option<PathBuf>,
    pub boot: Option<PathBuf>,
}

impl Seed {
    pub fn from_env() -> Option<Self> {
        env_value(SEED_ENV).map(|s| Self::at(Path::new(&s)))
    }

    pub fn at(seed: &Path) -> Self {
        let first = |rels: &[&str]| rels.iter().map(|rel| seed.join(rel)).find(|p| p.is_dir());
        Seed {
            coursier: first(&[".cache/coursier/v1", "coursier/v1"]),
            ivy: first(&[".ivy2", "ivy2"]),
            boot: first(&[".sbt/boot", "boot"]),
        }
    }
}

/// Hard-link every file of `from` into `to` (copy where linking fails).
pub fn link_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let ty = entry.file_type().unwrap();
        if ty.is_dir() {
            link_tree(&src, &dst);
        } else if ty.is_file() && !dst.exists() && std::fs::hard_link(&src, &dst).is_err() {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

/// The jar paths an `export <classpath>` printed in `output`: sbt 0.13 /
/// 1.x print one `:`-joined (`;` on Windows) path list, sbt 2 prints
/// `List(a, b)` with the virtual roots `${BASE}` (the build at `base`) and
/// `${CSR_CACHE}` (the Coursier cache `cs`). Log lines (`[info] …`) are
/// skipped.
pub fn export_classpath(output: &str, base: &Path, cs: &Path) -> Vec<PathBuf> {
    let output = output
        .replace("${BASE}", &base.to_string_lossy())
        .replace("${CSR_CACHE}", &cs.to_string_lossy());
    let sep: &[char] = if cfg!(windows) {
        &[';', ',']
    } else {
        &[':', ';', ',']
    };
    output
        .lines()
        .filter(|l| !l.starts_with('[') && l.contains(".jar"))
        .map(|l| {
            l.trim()
                .strip_prefix("List(")
                .and_then(|l| l.strip_suffix(')'))
                .unwrap_or(l.trim())
                .to_string()
        })
        .flat_map(|l| {
            l.split(sep)
                .map(|p| p.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|p| p.ends_with(".jar") && Path::new(p).is_absolute())
        .map(PathBuf::from)
        .collect()
}

/// Run in each binary that includes this module.
mod tests {
    use super::*;

    #[test]
    fn export_classpath_reads_every_line_shape() {
        // This OS's absolute spelling and classpath separator (`C:/…`, `;`
        // on Windows, where `/a` is not absolute).
        let (d, sep) = if cfg!(windows) {
            ("C:", ";")
        } else {
            ("", ":")
        };
        let abs = |p: &str| PathBuf::from(format!("{d}{p}"));
        let base = abs("/w/p");
        let cs = abs("/h/cs");
        let one = format!("[info] loading\n{d}/a/x.jar{sep}{d}/b/y.jar\n");
        assert_eq!(
            export_classpath(&one, &base, &cs),
            [abs("/a/x.jar"), abs("/b/y.jar")]
        );
        let two = "List(${BASE}/lib/z.jar, ${CSR_CACHE}/https/r/y.jar)\n";
        assert_eq!(
            export_classpath(two, &base, &cs),
            [abs("/w/p/lib/z.jar"), abs("/h/cs/https/r/y.jar")]
        );
    }

    #[test]
    fn java_spellings_drop_the_verbatim_prefix() {
        assert_eq!(
            java_path(Path::new(r"\\?\C:\t\x")),
            PathBuf::from(r"C:\t\x")
        );
        assert_eq!(
            java_path(Path::new(r"\\?\UNC\srv\share\x")),
            PathBuf::from(r"\\srv\share\x")
        );
        assert_eq!(java_path(Path::new("/t/x")), PathBuf::from("/t/x"));
        assert_eq!(file_url(Path::new("/t/central")), "file:///t/central");
        assert_eq!(
            file_url(Path::new(r"\\?\C:\t\central")),
            "file:///C:/t/central"
        );
        assert_eq!(file_url(Path::new(r"\\srv\share\c")), "file://srv/share/c");
    }

    #[test]
    fn hermetic_args_pin_every_location() {
        let loc = Locations {
            home: PathBuf::from("/w/home"),
            global_base: PathBuf::from("/w/g"),
            boot: PathBuf::from("/w/boot"),
            ivy_home: PathBuf::from("/w/ivy"),
            coursier: PathBuf::from("/w/cs"),
        };
        let args = hermetic_args(&loc, "1.13.0");
        for want in [
            "-Duser.home=/w/home",
            "-Dsbt.global.base=/w/g",
            "-Dsbt.boot.directory=/w/boot",
            "-Dsbt.ivy.home=/w/ivy",
        ] {
            assert!(args.iter().any(|a| a == want), "{want}: {args:?}");
        }
        assert!(args
            .iter()
            .any(|a| a.starts_with("-Dmaven.repo.local=") && a.ends_with("repository")));
        assert!(!args.contains(&"--server".to_string()));
        assert!(hermetic_args(&loc, "2.0.9").contains(&"--server".to_string()));
    }

    #[test]
    fn seed_reads_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        for rel in [".cache/coursier/v1", ".ivy2", ".sbt/boot"] {
            std::fs::create_dir_all(home.join(rel)).unwrap();
        }
        let s = Seed::at(&home);
        assert_eq!(s.coursier, Some(home.join(".cache/coursier/v1")));
        assert_eq!(s.boot, Some(home.join(".sbt/boot")));
        let flat = tmp.path().join("flat");
        for rel in ["coursier/v1", "ivy2"] {
            std::fs::create_dir_all(flat.join(rel)).unwrap();
        }
        let s = Seed::at(&flat);
        assert_eq!(s.ivy, Some(flat.join("ivy2")));
        assert_eq!(s.boot, None);
    }
}
