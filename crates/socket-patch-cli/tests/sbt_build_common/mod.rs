//! Real-sbt plumbing for the host build capstones (`e2e_sbt_build`).
//!
//! Toolchain selection (`SOCKET_PATCH_SBT_E2E_*`):
//!
//! * `SBT` — the sbt launcher script to run (`<sbt>/bin/sbt`); unset/empty
//!   = `sbt` on `PATH`.
//! * `DOCKER` — an image with a JDK (`socket-patch-test-sbt`, or a plain
//!   `eclipse-temurin:<jdk>-jdk`): sbt runs inside it, with the launcher
//!   (`SBT`, required then: a launcher directory on the host) and every
//!   test directory bind-mounted at its own host path, so the evidence sbt
//!   writes names paths the host CLI can read. Each run is `--rm -m 2g`,
//!   reaches the host's patch-server stand-in as `host.docker.internal`,
//!   and is killed after the timeout.
//! * `VERSION` — the `sbt.version` the fixture builds pin (default
//!   `1.13.0`); the launcher fetches it.
//! * `REQUIRED` — when non-empty, a missing toolchain is a failure, not a
//!   printed SKIP.
//! * `SEED` — a warm cache in either layout `sbt_e2e_shared::Seed` reads
//!   (a home with `.cache/coursier/v1`, `.ivy2`, `.sbt/boot`, or a flat
//!   `coursier/v1`, `ivy2`, `boot`). The Coursier cache and Ivy home are
//!   hard-linked into every test's own caches (read-only use: Coursier and
//!   Ivy only add files); the boot directory is shared. Without it every
//!   test resolves from the network.
//!
//! Every run is hermetic (`sbt_e2e_shared::native_command`, the same flags
//! for the Docker runner): `COURSIER_CACHE=<test>/cs` (and nothing else
//! naming a Coursier location), `HOME` / `-Duser.home=<test>/home` (so
//! `mavenLocal` is `<test>/home/.m2/repository`, also
//! `-Dmaven.repo.local`), `-Dsbt.global.base`, `-Dsbt.ivy.home`,
//! `-Dsbt.boot.directory`, `-Dsbt.server.autostart=false`, `-batch`,
//! `-no-colors`; `SBT_OPTS`, `JAVA_OPTS`, `JAVA_TOOL_OPTIONS`,
//! `COURSIER_*`, `SOCKET_*` and the CI markers scrubbed. A hard timeout
//! (300 s) kills every spawn.
//!
//! The fixture is Java-only (`autoScalaLibrary := false`): a local
//! `file:` maven2 repository (`<test>/central`) serves `dev.socket.fixture`
//! jars built here, so no project dependency touches the network.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

#[path = "../sbt_e2e_shared/mod.rs"]
pub mod shared;
pub use shared::{env_value, DOCKER_ENV, REQUIRED_ENV, SBT_ENV, TIMEOUT};

/// The fixture group every test's artifacts live under.
pub const GROUP: &str = "dev.socket.fixture";

/// How sbt runs.
#[derive(Debug, Clone)]
pub enum Runner {
    /// On the host.
    Native { sbt: PathBuf },
    /// In `image`, the launcher directory `launcher` mounted at its path.
    Docker { image: String, launcher: PathBuf },
}

/// The selected sbt toolchain.
#[derive(Debug, Clone)]
pub struct Sbt {
    pub runner: Runner,
    pub version: String,
    pub seed: Option<shared::Seed>,
}

impl Sbt {
    /// The configured toolchain, or `None` (printed SKIP) when none is
    /// usable and `REQUIRED` is unset.
    pub fn detect(suite: &str) -> Option<Self> {
        let required = env_value(REQUIRED_ENV).is_some();
        let skip = |why: String| -> Option<Self> {
            assert!(!required, "{suite}: {REQUIRED_ENV} is set but {why}");
            eprintln!("SKIP {suite}: {why}");
            None
        };
        let version = shared::version();
        let seed = shared::Seed::from_env();
        let runner = match env_value(DOCKER_ENV) {
            Some(image) => {
                let Some(launcher) = env_value(SBT_ENV).map(PathBuf::from) else {
                    return skip(format!("{DOCKER_ENV} needs {SBT_ENV} (a launcher dir)"));
                };
                let launcher = if launcher.ends_with("bin/sbt") {
                    launcher.parent().unwrap().parent().unwrap().to_path_buf()
                } else {
                    launcher
                };
                if !launcher.join("bin/sbt").is_file() {
                    return skip(format!("no {}/bin/sbt", launcher.display()));
                }
                let ok = Command::new("docker")
                    .args(["image", "inspect", &image])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if !ok {
                    return skip(format!("docker image {image} is not available"));
                }
                Runner::Docker { image, launcher }
            }
            None => {
                let sbt = env_value(SBT_ENV).map_or_else(|| PathBuf::from("sbt"), PathBuf::from);
                let ok = Command::new(&sbt)
                    .arg("--script-version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if !ok {
                    return skip(format!("{} is not runnable", sbt.display()));
                }
                Runner::Native { sbt }
            }
        };
        Some(Sbt {
            runner,
            version,
            seed,
        })
    }

    /// The sbt line of [`Self::version`]: `0.13`, `1` or `2`.
    pub fn line(&self) -> &'static str {
        shared::line(&self.version)
    }

    /// Whether this sbt resolves through Ivy (0.13, 1.0–1.2).
    pub fn ivy(&self) -> bool {
        shared::uses_ivy(&self.version)
    }

    /// The host name sbt reaches the test's loopback servers by.
    pub fn host_from_sbt(&self) -> &'static str {
        match self.runner {
            Runner::Native { .. } => "127.0.0.1",
            Runner::Docker { .. } => "host.docker.internal",
        }
    }

    /// The task path of a project's dependency classpath on this line.
    pub fn classpath_task(&self, project: &str) -> String {
        match self.line() {
            "0.13" => format!("{project}/compile:dependencyClasspath"),
            _ => format!("{project}/Compile/dependencyClasspath"),
        }
    }

    /// Run sbt `commands` in `ws.project` (each one an sbt command line
    /// argument).
    pub fn run(&self, ws: &Workspace, commands: &[&str]) -> SbtRun {
        let loc = ws.locations();
        let cs = ws.coursier_cache();
        let started = Instant::now();
        let (mut cmd, container) = match &self.runner {
            Runner::Native { sbt } => {
                let mut cmd =
                    shared::native_command(sbt.as_os_str(), &ws.project, &loc, &self.version);
                cmd.args(commands);
                (cmd, None)
            }
            Runner::Docker { image, launcher } => {
                let name = format!(
                    "socket-patch-sbt-e2e-{}-{}",
                    std::process::id(),
                    started.elapsed().as_nanos() ^ rand_suffix()
                );
                let mut cmd = Command::new("docker");
                cmd.args(["run", "--rm", "-m", "2g", "--name", &name])
                    .args(["--add-host", "host.docker.internal:host-gateway"])
                    .arg("-v")
                    .arg(format!("{0}:{0}", ws.root.display()))
                    .arg("-v")
                    .arg(format!("{0}:{0}:ro", launcher.display()))
                    .arg("-v")
                    .arg(format!("{0}:{0}", ws.boot.display()))
                    .arg("-w")
                    .arg(&ws.project)
                    .arg("-e")
                    .arg(format!("COURSIER_CACHE={}", cs.display()))
                    .arg("-e")
                    .arg(format!("HOME={}", loc.home.display()))
                    .arg(image)
                    .arg(launcher.join("bin/sbt"))
                    .args(shared::hermetic_args(&loc, &self.version))
                    .args(commands);
                (cmd, Some(name))
            }
        };
        let log_path = ws.root.join(format!("sbt-{}.log", ws.next_log()));
        let log = std::fs::File::create(&log_path).expect("sbt log");
        cmd.stdin(Stdio::null())
            .stdout(log.try_clone().expect("log"))
            .stderr(log);
        let mut child = cmd.spawn().expect("spawn sbt");
        let code = match shared::wait_or_kill_group(&mut child, TIMEOUT) {
            Some(status) => status.code(),
            None => {
                // The docker client died with its group; the container
                // outlives it.
                if let Some(name) = &container {
                    let _ = Command::new("docker")
                        .args(["kill", name])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                None
            }
        };
        let output = std::fs::read_to_string(&log_path).unwrap_or_default();
        SbtRun {
            code,
            output,
            commands: commands.iter().map(|c| c.to_string()).collect(),
        }
    }
}

fn rand_suffix() -> u128 {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0);
    h.finish() as u128
}

/// One sbt run's outcome.
#[derive(Debug)]
pub struct SbtRun {
    /// `None` = killed by the timeout.
    pub code: Option<i32>,
    pub output: String,
    pub commands: Vec<String>,
}

impl SbtRun {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// Panic with the log unless the run succeeded.
    pub fn expect_ok(&self, what: &str) -> &Self {
        assert!(
            self.ok(),
            "{what}: sbt {:?} exited {:?}\n{}",
            self.commands,
            self.code,
            tail(&self.output)
        );
        self
    }

    /// Panic with the log unless the run failed with `needle` in its log.
    pub fn expect_failure(&self, what: &str, needle: &str) -> &Self {
        assert!(
            !self.ok() && self.output.contains(needle),
            "{what}: expected sbt {:?} to fail with {needle:?}, exit {:?}\n{}",
            self.commands,
            self.code,
            tail(&self.output)
        );
        self
    }

    /// The jar paths an `export <classpath>` printed.
    /// sbt 0.13 / 1.x print a `:`-joined path; sbt 2 prints `List(a, b)`.
    pub fn classpath_jars(&self) -> Vec<PathBuf> {
        Self::jars_in(&self.output)
    }

    /// [`Self::classpath_jars`] with sbt 2's virtual roots (`${BASE}` = the
    /// build root, `${CSR_CACHE}` = the Coursier cache) spelled out.
    pub fn classpath_jars_in(&self, ws: &Workspace) -> Vec<PathBuf> {
        shared::export_classpath(&self.output, &ws.project, &ws.coursier_cache())
    }

    fn jars_in(output: &str) -> Vec<PathBuf> {
        shared::export_classpath(output, Path::new("/"), Path::new("/"))
    }
}

fn tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(80)..].join("\n")
}

/// One test's directories: the project, its caches and the fixture
/// repository, under a canonical temp root (so container and host agree on
/// every path).
pub struct Workspace {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub project: PathBuf,
    pub central: PathBuf,
    pub boot: PathBuf,
    log_counter: std::cell::Cell<u32>,
}

impl Workspace {
    pub fn new(sbt: &Sbt) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("sbt-e2e-")
            .tempdir()
            .expect("tempdir");
        // Canonical (macOS symlinks its temp dir), in the spelling Java
        // accepts (no Windows verbatim prefix).
        let root = shared::canonical(tmp.path());
        let project = root.join("project");
        let central = root.join("central");
        for d in [
            &project,
            &central,
            &root.join("home"),
            &root.join("sbt-global"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Coursier and Ivy caches are hard-linked in (both only add
        // files); the boot directory is shared (sbt locks it).
        let boot = match &sbt.seed {
            Some(seed) => {
                for (src, to) in [(&seed.coursier, "cs"), (&seed.ivy, "ivy2")] {
                    if let Some(src) = src {
                        shared::link_tree(src, &root.join(to));
                    }
                }
                match &seed.boot {
                    Some(boot) => shared::canonical(boot),
                    None => root.join("boot"),
                }
            }
            None => root.join("boot"),
        };
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::create_dir_all(root.join("cs")).unwrap();
        Workspace {
            _tmp: tmp,
            root,
            project,
            central,
            boot,
            log_counter: std::cell::Cell::new(0),
        }
    }

    fn next_log(&self) -> u32 {
        let n = self.log_counter.get() + 1;
        self.log_counter.set(n);
        n
    }

    pub fn coursier_cache(&self) -> PathBuf {
        self.root.join("cs")
    }

    /// Every sbt location of this workspace (`home` holds `mavenLocal`).
    pub fn locations(&self) -> shared::Locations {
        shared::Locations {
            home: self.root.join("home"),
            global_base: self.root.join("sbt-global"),
            boot: self.boot.clone(),
            ivy_home: self.ivy_home(),
            coursier: self.coursier_cache(),
        }
    }

    /// `mavenLocal` as sbt sees it in this workspace.
    pub fn maven_local(&self) -> PathBuf {
        self.root.join("home/.m2/repository")
    }

    pub fn ivy_home(&self) -> PathBuf {
        self.root.join("ivy2")
    }

    /// Write `rel` under the project.
    pub fn write(&self, rel: &str, text: &str) {
        let path = self.project.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// Publish `artifact:version` into the fixture repository: a jar
    /// holding one `marker` entry, and a pom declaring `deps`.
    pub fn publish(&self, artifact: &str, version: &str, marker: &str, deps: &[(&str, &str)]) {
        let dir = self
            .central
            .join(GROUP.replace('.', "/"))
            .join(artifact)
            .join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{artifact}-{version}.jar")), jar(marker)).unwrap();
        std::fs::write(
            dir.join(format!("{artifact}-{version}.pom")),
            pom(artifact, version, deps),
        )
        .unwrap();
    }

    /// The fixture's `file:` repository URL (`file:///C:/…` on Windows).
    pub fn central_url(&self) -> String {
        shared::file_url(&self.central)
    }
}

/// A jar (zip) with the single entry `marker`.
pub fn jar(marker: &str) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default());
        zip.start_file(marker, opts).unwrap();
        zip.write_all(marker.as_bytes()).unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

/// A pom for `GROUP:artifact:version` depending on `deps`.
pub fn pom(artifact: &str, version: &str, deps: &[(&str, &str)]) -> String {
    let deps: String = deps
        .iter()
        .map(|(a, v)| {
            format!(
                "<dependency><groupId>{GROUP}</groupId><artifactId>{a}</artifactId>\
                 <version>{v}</version></dependency>"
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\
         <modelVersion>4.0.0</modelVersion><groupId>{GROUP}</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version><packaging>jar</packaging><dependencies>{deps}</dependencies></project>\n"
    )
}

/// One fixture project: `(id, base directory, (artifact, version) deps)`.
pub type ProjectSpec<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

/// The sbt build text for `projects` (`(id, dir, deps)`; dir `.` is the
/// root, which aggregates the rest), Java-only, resolving from the
/// fixture repository, plus `extra` lines.
pub fn build_sbt(sbt: &Sbt, ws: &Workspace, projects: &[ProjectSpec<'_>], extra: &str) -> String {
    let resolver = if sbt.line() == "0.13" {
        format!(
            "resolvers in ThisBuild += \"fixture-central\" at \"{}\"",
            ws.central_url()
        )
    } else {
        format!(
            "ThisBuild / resolvers += \"fixture-central\" at \"{}\"",
            ws.central_url()
        )
    };
    let mut out = format!("{resolver}\n");
    let aggregated: Vec<&str> = projects
        .iter()
        .filter(|(_, dir, _)| *dir != ".")
        .map(|(id, _, _)| *id)
        .collect();
    for (id, dir, deps) in projects {
        let deps: Vec<String> = deps
            .iter()
            .map(|(a, v)| format!("\"{GROUP}\" % \"{a}\" % \"{v}\""))
            .collect();
        let aggregate = if *dir == "." && !aggregated.is_empty() {
            format!(".aggregate({})", aggregated.join(", "))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "lazy val {id} = (project in file(\"{dir}\")){aggregate}.settings(autoScalaLibrary := false, libraryDependencies ++= Seq({}))\n",
            deps.join(", ")
        ));
    }
    out.push_str(extra);
    out
}

/// sha256 hex of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}
