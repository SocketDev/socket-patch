//! Real-sbt plumbing for the vendored sbt capstones (`e2e_sbt_vendor_build`).
//!
//! Toolchain selection, mirroring the Maven capstones' `SOCKET_PATCH_MAVEN_E2E_*`:
//!
//! * `SOCKET_PATCH_SBT_E2E_SBT` — the sbt launcher to drive (any launcher
//!   runs any `sbt.version`); unset/empty = `sbt` on `PATH`.
//! * `SOCKET_PATCH_SBT_E2E_VERSION` — the `sbt.version` every fixture pins
//!   in `project/build.properties` (default 1.13.0); the build must report
//!   exactly it (`sbtVersion`).
//! * `SOCKET_PATCH_SBT_E2E_REQUIRED` — when set and non-empty, a missing
//!   launcher or an unreachable Maven Central (the warm-up `update`) is a
//!   hard failure instead of a printed SKIP.
//! * `SOCKET_PATCH_SBT_E2E_SEED` — an optional warm cache in either layout
//!   `sbt_e2e_shared::Seed` reads (a home with `.sbt/boot`, `.ivy2`,
//!   `.cache/coursier/v1`, or a flat `boot`, `ivy2`, `coursier/v1`): its
//!   Coursier and Ivy caches hard-linked (copied when linking fails) into
//!   each test's home, never written through; its boot directory shared
//!   (sbt locks it), so a line the seed lacks boots once per run, not once
//!   per test.
//!
//! The environment contract is shared with the hosted driver
//! (`sbt_e2e_shared`); unlike it, this driver runs sbt natively only (the
//! matrix script runs the whole test binary inside `Dockerfile.sbt`).
//!
//! Every sbt run is hermetic (`sbt_e2e_shared::native_command`, shared with
//! the hosted driver): a per-test home passed explicitly (`HOME`,
//! `-Duser.home`, `-Dmaven.repo.local`, `-Dsbt.global.base`,
//! `-Dsbt.boot.directory`, `-Dsbt.ivy.home`, and `COURSIER_CACHE` as the
//! only Coursier location), `-batch -no-colors`, no sbt server (`--server`
//! on 2.x, which otherwise starts a client), `SBT_OPTS` / `JAVA_OPTS` /
//! `JAVA_TOOL_OPTIONS` / `COURSIER_*` / `SOCKET_*` and the CI markers
//! scrubbed, and a hard timeout that kills the whole process group.

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

#[path = "../sbt_e2e_shared/mod.rs"]
pub mod shared;
pub use shared::{line, required, version, REQUIRED_ENV, SBT_ENV, TIMEOUT};

/// Skip (println) locally; fail when the leg is required.
pub fn skip(suite: &str, why: &str) {
    assert!(
        !required(),
        "{suite}: {REQUIRED_ENV} is set but the sbt capstone cannot run: {why}"
    );
    println!("SKIP {suite}: {why}");
}

/// The isolated home of one test: caches and global base live here.
pub struct SbtHome {
    pub root: PathBuf,
    /// The seed's boot directory (shared), else the home's own.
    boot: PathBuf,
}

impl SbtHome {
    /// A fresh home under `dir`, seeded from [`SEED_ENV`] when set.
    pub fn new(dir: &Path) -> Self {
        let root = dir.join("sbt-home");
        std::fs::create_dir_all(&root).unwrap();
        let mut home = Self {
            boot: root.join(".sbt/boot"),
            root,
        };
        // Either seed layout (`shared::Seed`): the caches linked into this
        // home's, the boot directory shared.
        if let Some(seed) = shared::Seed::from_env() {
            for (src, to) in [
                (&seed.coursier, home.coursier_cache()),
                (&seed.ivy, home.ivy_home()),
            ] {
                if let Some(src) = src {
                    shared::link_tree(src, &to);
                }
            }
            if let Some(boot) = &seed.boot {
                home.boot = shared::canonical(boot);
            }
        }
        std::fs::create_dir_all(&home.boot).unwrap();
        home
    }

    pub fn boot(&self) -> PathBuf {
        self.boot.clone()
    }

    pub fn global_base(&self, version: &str) -> PathBuf {
        let series = match line(version) {
            "0.13" => "0.13",
            "2" => "2",
            _ => "1.0",
        };
        self.root.join(".sbt").join(series)
    }

    pub fn ivy_home(&self) -> PathBuf {
        self.root.join(".ivy2")
    }

    pub fn coursier_cache(&self) -> PathBuf {
        self.root.join(".cache/coursier/v1")
    }

    /// The pristine `<a>-<v>.{jar,pom}` of `g:a:v` as sbt cached it
    /// (Coursier, then Ivy's `jars/` + `ivy-<v>.xml.original`).
    pub fn cached(&self, g: &str, a: &str, v: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let gpath = g.replace('.', "/");
        let cs = self
            .coursier_cache()
            .join("https/repo1.maven.org/maven2")
            .join(&gpath)
            .join(a)
            .join(v);
        let pair =
            |jar: PathBuf, pom: PathBuf| Some((std::fs::read(jar).ok()?, std::fs::read(pom).ok()?));
        pair(
            cs.join(format!("{a}-{v}.jar")),
            cs.join(format!("{a}-{v}.pom")),
        )
        .or_else(|| {
            let ivy = self.ivy_home().join("cache").join(g).join(a);
            pair(
                ivy.join("jars").join(format!("{a}-{v}.jar")),
                ivy.join(format!("ivy-{v}.xml.original")),
            )
        })
    }
}

/// The selected launcher.
pub struct Sbt {
    program: OsString,
    pub version: String,
}

impl Sbt {
    /// Probe the launcher (`sbt --script-version`). `None` = skipped.
    pub fn detect(suite: &str) -> Option<Sbt> {
        let program: OsString = std::env::var_os(SBT_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| if cfg!(windows) { "sbt.bat" } else { "sbt" }.into());
        match Command::new(&program)
            .arg("--script-version")
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => Some(Sbt {
                program,
                version: version(),
            }),
            Ok(out) => {
                skip(
                    suite,
                    &format!("`{}` failed: {}", program.to_string_lossy(), dump(&out)),
                );
                None
            }
            Err(e) => {
                skip(
                    suite,
                    &format!("`{}` did not run: {e}", program.to_string_lossy()),
                );
                None
            }
        }
    }

    /// `sbt <commands…>` in `cwd` with `home`'s caches; `extra` are more
    /// `-D` / launcher flags.
    pub fn run(&self, cwd: &Path, home: &SbtHome, extra: &[&str], commands: &[&str]) -> Output {
        let loc = shared::Locations {
            home: home.root.clone(),
            global_base: home.global_base(&self.version),
            boot: home.boot(),
            ivy_home: home.ivy_home(),
            coursier: home.coursier_cache(),
        };
        let mut cmd = shared::native_command(&self.program, cwd, &loc, &self.version);
        cmd.args(extra).args(commands);
        run_with_timeout(cmd, TIMEOUT)
    }

    /// The `export` command for the compile dependency classpath.
    pub fn classpath_command(&self, project: Option<&str>) -> String {
        let key = if line(&self.version) == "2" {
            "Compile/dependencyClasspath"
        } else {
            "compile:dependencyClasspath"
        };
        match project {
            Some(p) => format!("export {p}/{key}"),
            None => format!("export {key}"),
        }
    }

    /// The jars on the exported classpath in `out` (the last line naming
    /// `.jar` files). sbt 2 prints `List(${BASE}/…, ${CSR_CACHE}/…)`: the
    /// virtual roots resolve against the build at `base` and `home`'s
    /// Coursier cache.
    pub fn classpath(out: &Output, base: &Path, home: &SbtHome) -> Vec<PathBuf> {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The last line naming jars is the export's.
        let Some(last) = stdout
            .lines()
            .rev()
            .find(|l| l.contains(".jar") && !l.starts_with('['))
        else {
            return Vec::new();
        };
        shared::export_classpath(last, base, &home.coursier_cache())
    }
}

/// Run `cmd` (a [`shared::native_command`], its own process group),
/// killing the whole group after `limit`.
pub fn run_with_timeout(mut cmd: Command, limit: Duration) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn sbt");
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut buf).ok();
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stderr, &mut buf).ok();
        buf
    });
    let Some(status) = shared::wait_or_kill_group(&mut child, limit) else {
        panic!("sbt exceeded {}s and was killed", limit.as_secs());
    };
    Output {
        status,
        stdout: out_reader.join().unwrap(),
        stderr: err_reader.join().unwrap(),
    }
}

pub fn ok(out: &Output) -> bool {
    out.status.success()
}

pub fn dump(out: &Output) -> String {
    format!(
        "exit={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// How an sbt run reports a failed fetch from Maven Central: Coursier
/// (`Error downloading g:a:v` / `not found: https://…`), Ivy on 0.13 /
/// 1.0–1.2 (`Server access error`, `unresolved dependency`) and the
/// launcher booting a line (`Error retrieving required libraries`).
const FETCH_ERRORS: &[&str] = &[
    "Error downloading",
    "download error",
    "Server access error",
    "unresolved dependency",
    "Error retrieving required libraries",
];

/// The warm-up `sbt sbtVersion update` in `proj`, the one run that
/// fetches from Maven Central (the fixture's GAs are not in the image's
/// warm seed). On a CI runner Central blips: a CDN 404 or reset for an
/// artifact it serves, which failed every test of a leg at once
/// (`Error downloading org.apache.commons:commons-text:1.10.0 / Not
/// found`). A run that failed with a fetch error is retried from a fresh
/// home (Coursier and Ivy can remember a miss) and no build outputs, after
/// a backoff; any other failure returns at once.
pub fn warm_up(sbt: &Sbt, proj: &Path, home: &mut SbtHome) -> Output {
    const ATTEMPTS: u64 = 3;
    let mut attempt = 1;
    loop {
        let out = sbt.run(proj, home, &[], &["sbtVersion", "update"]);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if ok(&out) || attempt == ATTEMPTS || !FETCH_ERRORS.iter().any(|e| text.contains(e)) {
            return out;
        }
        eprintln!("warm-up `sbt update` attempt {attempt} failed fetching; retrying");
        std::thread::sleep(Duration::from_secs(10 * attempt));
        let dir = home.root.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&home.root).unwrap();
        for rel in BUILD_OUTPUT_DIRS.iter().chain(&["project/target"]) {
            let _ = std::fs::remove_dir_all(proj.join(rel));
        }
        *home = SbtHome::new(&dir);
        attempt += 1;
    }
}

/// Directories sbt writes that a checkout never carries.
pub const BUILD_OUTPUT_DIRS: &[&str] = &["target", ".bsp", ".bloop", ".metals", "project/project"];

/// A Java-only sbt build at `root` depending on `deps` (`"g" % "a" % "v"`
/// literals), with `subprojects` aggregated below it.
pub fn write_build(root: &Path, version: &str, deps: &[&str], subprojects: &[&str]) {
    std::fs::create_dir_all(root.join("project")).unwrap();
    std::fs::write(
        root.join("project/build.properties"),
        format!("sbt.version={version}\n"),
    )
    .unwrap();
    let deps = deps.join(", ");
    let mut build =
        String::from("ThisBuild / autoScalaLibrary := false\nThisBuild / crossPaths := false\n");
    if line(version) == "0.13" {
        build = "autoScalaLibrary in ThisBuild := false\ncrossPaths in ThisBuild := false\n".into();
    }
    build.push_str(&format!("libraryDependencies ++= Seq({deps})\n"));
    for sub in subprojects {
        build.push_str(&format!(
            "lazy val {sub} = project\nlazy val root = (project in file(\".\")).aggregate({sub})\n"
        ));
    }
    std::fs::write(root.join("build.sbt"), build).unwrap();
}
