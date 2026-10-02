//! Real-Gradle plumbing shared by the Gradle capstones
//! (`e2e_vendor_jvm_build`'s multi-project leg and the `e2e_gradle_*` /
//! `e2e_*_gradle_build` suites).
//!
//! Toolchain selection (the version-matrix lever, mirroring
//! `maven_build_common`'s `SOCKET_PATCH_MAVEN_E2E_*` trio):
//!
//! * `SOCKET_PATCH_GRADLE_E2E_GRADLE` — the launcher to drive (an unpacked
//!   `gradle-<v>/bin/gradle`); unset/empty = `gradle` on `PATH`.
//! * `SOCKET_PATCH_GRADLE_E2E_VERSION` — when set and non-empty, the
//!   launcher's `--version` banner MUST report exactly this version.
//! * `SOCKET_PATCH_GRADLE_E2E_REQUIRED` — when set and non-empty, a missing
//!   toolchain or an unreachable origin is a hard failure, not a SKIP.
//! * `SOCKET_PATCH_GRADLE_E2E_PROBE_DIR` — where [`probe_report`] writes the
//!   per-cell JSON (default `<CARGO_TARGET_TMPDIR>/gradle-probe`).
//! * `SOCKET_PATCH_GRADLE_E2E_ARGS` — extra whitespace-separated arguments
//!   for every Gradle run (the CI grid's `--configuration-cache` and
//!   Isolated Projects cells).
//!
//! Every Gradle run is hermetic: a per-test `GRADLE_USER_HOME`, no daemon,
//! plain console, and the ambient JVM / Gradle options ([`AMBIENT_ENV`]) and
//! CI markers ([`CI_DETECTOR_ENV`]) scrubbed. Repositories are redirected to
//! the fake origins by a test-only init script ([`mirror_init_script`]);
//! production code has no test override.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const GRADLE_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_GRADLE";
pub const GRADLE_VERSION_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_VERSION";
pub const GRADLE_REQUIRED_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_REQUIRED";
pub const GRADLE_PROBE_DIR_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_PROBE_DIR";
pub const GRADLE_ARGS_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_ARGS";

/// Ambient settings that would change what a Gradle child resolves or where
/// it caches: JVM options (a `-Dgradle.user.home` there beats the per-test
/// home), the user home itself, the read-only dependency cache and an
/// installation's `init.d`.
pub const AMBIENT_ENV: &[&str] = &[
    "GRADLE_OPTS",
    "JAVA_OPTS",
    "GRADLE_USER_HOME",
    "GRADLE_RO_DEP_CACHE",
    "GRADLE_HOME",
];

/// The CI markers `maven_build_common` scrubs, scrubbed here too so a leg
/// logs what a developer's terminal run logs.
pub const CI_DETECTOR_ENV: &[&str] = &[
    "CI",
    "GITHUB_ACTIONS",
    "CIRCLECI",
    "WORKSPACE",
    "TEAMCITY_VERSION",
    "TRAVIS",
];

/// Directories a build writes that a checkout never carries.
pub const BUILD_OUTPUT_DIRS: &[&str] = &["target", "build", ".gradle", ".kotlin"];

/// The line prefix [`print_cp_task`] prints before each classpath entry.
pub const CP_MARKER: &str = "SOCKET-CP ";

pub fn gradle_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// CI legs set `SOCKET_PATCH_GRADLE_E2E_REQUIRED`: never skip there.
pub fn gradle_required() -> bool {
    gradle_flag(GRADLE_REQUIRED_ENV)
}

/// Skip (println) locally; fail when the leg is required.
pub fn gradle_skip(suite: &str, why: &str) {
    assert!(
        !gradle_required(),
        "{suite}: {GRADLE_REQUIRED_ENV} is set but the Gradle capstone cannot run: {why}"
    );
    println!("SKIP {suite}: {why}");
}

/// Java rejects the extended Windows paths returned by canonicalize.
/// Keep a canonical root for symlinked macOS temp directories, but use the
/// ordinary drive/UNC spelling when handing paths to Maven and Gradle.
pub fn fixture_root(tmp: &tempfile::TempDir) -> PathBuf {
    strip_verbatim(tmp.path().canonicalize().unwrap())
}

/// `\\?\C:\x` → `C:\x` and `\\?\UNC\h\s` → `\\h\s`; identity elsewhere.
pub fn strip_verbatim(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}").into();
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.into();
        }
    }
    path
}

pub fn ok(out: &Output) -> bool {
    out.status.success()
}

pub fn dump(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── the launcher ────────────────────────────────────────────────────────

/// The selected Gradle launcher, run hermetically: a per-test
/// `GRADLE_USER_HOME`, no daemon, plain console, ambient options scrubbed.
pub struct Gradle {
    pub program: OsString,
    /// What the `Gradle <v>` banner line reports, e.g. `8.14.3`.
    pub version: String,
    /// What the `JVM:` banner line reports, e.g. `21.0.8 (Eclipse Adoptium 21.0.8+9-LTS)`.
    pub jvm: String,
    /// Arguments every [`Gradle::run`] passes first (see
    /// [`Gradle::with_isolated_projects`]).
    pub extra_args: Vec<String>,
}

impl Gradle {
    pub fn command(program: &OsString, home: Option<&Path>) -> Command {
        let mut cmd = Command::new(program);
        for key in AMBIENT_ENV.iter().chain(CI_DETECTOR_ENV) {
            cmd.env_remove(key);
        }
        if let Some(home) = home {
            cmd.env("GRADLE_USER_HOME", home);
        }
        cmd
    }

    /// Probe the launcher (`gradle --version`). `None` = skipped (message
    /// printed; a hard failure on required legs).
    pub fn detect(suite: &str, home: &Path) -> Option<Gradle> {
        let program: OsString = std::env::var_os(GRADLE_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "gradle.bat"
                } else {
                    "gradle"
                }
                .into()
            });
        let out = match Self::command(&program, Some(home))
            .args(["--version", "--no-daemon"])
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                gradle_skip(
                    suite,
                    &format!("`{}` did not run: {e}", program.to_string_lossy()),
                );
                return None;
            }
        };
        let banner = String::from_utf8_lossy(&out.stdout).into_owned();
        let Some(version) = banner.lines().find_map(|l| {
            l.trim()
                .strip_prefix("Gradle ")
                .map(|v| v.trim().to_string())
        }) else {
            gradle_skip(
                suite,
                &format!(
                    "`{} --version` printed no `Gradle <v>` banner:\n{}{}",
                    program.to_string_lossy(),
                    banner,
                    String::from_utf8_lossy(&out.stderr)
                ),
            );
            return None;
        };
        if let Some(pin) = std::env::var(GRADLE_VERSION_ENV)
            .ok()
            .filter(|v| !v.is_empty())
        {
            assert_eq!(
                version,
                pin,
                "{GRADLE_VERSION_ENV} pins Gradle {pin} but `{}` is Gradle {version}",
                program.to_string_lossy()
            );
        }
        let jvm = jvm_banner(&banner).unwrap_or_default();
        let extra_args: Vec<String> = std::env::var(GRADLE_ARGS_ENV)
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        println!(
            "{suite}: driving Gradle {version} on JVM {jvm} ({}) {extra_args:?}",
            program.to_string_lossy()
        );
        Some(Gradle {
            program,
            version,
            jvm,
            extra_args,
        })
    }

    /// The major version (`6` for `6.9.4`).
    pub fn major(&self) -> u32 {
        version_part(&self.version, 0)
    }

    pub fn minor(&self) -> u32 {
        version_part(&self.version, 1)
    }

    /// `self.version >= major.minor`.
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        (self.major(), self.minor()) >= (major, minor)
    }

    /// The JVM's feature release (`21` for `21.0.8`, `8` for `1.8.0_412`).
    pub fn jdk_major(&self) -> Option<u32> {
        jdk_feature(&self.jvm)
    }

    /// Every later [`Gradle::run`] enables Isolated Projects. Meaningful on
    /// 9.x (and late 8.x); older releases ignore the unknown property.
    pub fn with_isolated_projects(mut self) -> Self {
        self.extra_args
            .push("-Dorg.gradle.unsafe.isolated-projects=true".into());
        self
    }

    pub fn run(&self, cwd: &Path, home: &Path, args: &[&str]) -> Output {
        self.run_env(cwd, home, args, &[])
    }

    /// [`Gradle::run`] plus child-only environment (applied last).
    pub fn run_env(
        &self,
        cwd: &Path,
        home: &Path,
        args: &[&str],
        env: &[(&str, &std::ffi::OsStr)],
    ) -> Output {
        let mut cmd = Self::command(&self.program, Some(home));
        cmd.current_dir(cwd)
            .args(["--no-daemon", "--console=plain", "--stacktrace"])
            .args(&self.extra_args)
            .args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().expect("spawn gradle")
    }
}

fn version_part(version: &str, index: usize) -> u32 {
    version
        .split(['.', '-'])
        .nth(index)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// The `JVM:` line of a `gradle --version` banner (`Launcher JVM:` on
/// Gradle >= 9, which also prints a `Daemon JVM:` line).
pub fn jvm_banner(banner: &str) -> Option<String> {
    banner.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("JVM:")
            .or_else(|| l.strip_prefix("Launcher JVM:"))
            .map(|v| v.trim().to_string())
    })
}

/// `21.0.8 (…)` → 21; `1.8.0_412 (…)` → 8; `11 (…)` → 11.
pub fn jdk_feature(jvm: &str) -> Option<u32> {
    let version = jvm.split_whitespace().next()?;
    let mut parts = version.split(['.', '_', '+', '-']);
    let first: u32 = parts.next()?.parse().ok()?;
    if first == 1 {
        parts.next()?.parse().ok()
    } else {
        Some(first)
    }
}

// ── build scripts ───────────────────────────────────────────────────────

/// The two build-script dialects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dsl {
    Groovy,
    Kotlin,
}

impl Dsl {
    pub const ALL: [Dsl; 2] = [Dsl::Groovy, Dsl::Kotlin];

    pub fn name(self) -> &'static str {
        match self {
            Dsl::Groovy => "groovy",
            Dsl::Kotlin => "kotlin",
        }
    }

    /// `.gradle` / `.gradle.kts`.
    pub fn ext(self) -> &'static str {
        match self {
            Dsl::Groovy => ".gradle",
            Dsl::Kotlin => ".gradle.kts",
        }
    }

    pub fn settings_file(self) -> String {
        format!("settings{}", self.ext())
    }

    pub fn build_file(self) -> String {
        format!("build{}", self.ext())
    }
}

/// Run `f` once per DSL, labelling the output so a failure names its DSL.
pub fn for_each_dsl(mut f: impl FnMut(Dsl)) {
    for dsl in Dsl::ALL {
        println!("── {} DSL ──", dsl.name());
        f(dsl);
    }
}

/// Write `files` (`(relative path, body)`) under `proj`.
pub fn write_project(proj: &Path, files: &[(&str, &str)]) {
    for (rel, body) in files {
        let path = proj.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
}

/// The same project in both DSLs, under `root/groovy` and `root/kotlin`.
/// `files(dsl)` returns that DSL's `(relative path, body)` list.
pub fn write_both_dsls(
    root: &Path,
    files: impl Fn(Dsl) -> Vec<(String, String)>,
) -> [(Dsl, PathBuf); 2] {
    Dsl::ALL.map(|dsl| {
        let proj = root.join(dsl.name());
        let owned = files(dsl);
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(rel, body)| (rel.as_str(), body.as_str()))
            .collect();
        write_project(&proj, &borrowed);
        (dsl, proj)
    })
}

/// A `printRuntimeClasspath` task (configuration-cache safe: it captures a
/// file collection, not the project) printing one [`CP_MARKER`] line per
/// resolved file of `configuration`.
pub fn print_cp_task(dsl: Dsl, configuration: &str) -> String {
    match dsl {
        Dsl::Groovy => format!(
            "def socketCp = files(configurations.named('{configuration}'))\n\
             tasks.register('printRuntimeClasspath') {{\n    \
             doLast {{ socketCp.files.each {{ println('{CP_MARKER}' + it.absolutePath) }} }}\n\
             }}\n"
        ),
        Dsl::Kotlin => format!(
            "val socketCp = files(configurations.named(\"{configuration}\"))\n\
             tasks.register(\"printRuntimeClasspath\") {{\n    \
             doLast {{ socketCp.files.forEach {{ println(\"{CP_MARKER}\" + it.absolutePath) }} }}\n\
             }}\n"
        ),
    }
}

/// The [`CP_MARKER`] lines a `printRuntimeClasspath` run printed.
pub fn gradle_classpath(out: &Output) -> Vec<PathBuf> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix(CP_MARKER))
        .map(PathBuf::from)
        .collect()
}

/// [`gradle_classpath`] with the build's own success asserted.
pub fn print_cp(out: &Output, what: &str) -> Vec<PathBuf> {
    assert!(ok(out), "{what}:\n{}", dump(out));
    gradle_classpath(out)
}

/// The one classpath entry named `<artifact>-…`; its `member` must be
/// exactly `want`. Returns the entry: what Gradle actually consumed.
pub fn assert_patched(
    out: &Output,
    artifact: &str,
    member: &str,
    want: &[u8],
    what: &str,
) -> PathBuf {
    let cp = print_cp(out, what);
    let prefix = format!("{artifact}-");
    let hits: Vec<&PathBuf> = cp
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".jar"))
        })
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{what}: exactly one `{artifact}` jar on the classpath:\n{cp:?}"
    );
    let jar = std::fs::read(hits[0]).unwrap();
    let got = jar_member(&jar, member)
        .unwrap_or_else(|| panic!("{what}: {} has no {member}", hits[0].display()));
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(want),
        "{what}: {member} of the consumed {} is not the expected bytes",
        hits[0].display()
    );
    hits[0].clone()
}

/// One member's bytes from a jar.
pub fn jar_member(jar: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).ok()?;
    let mut entry = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    Some(buf)
}

// ── init scripts ────────────────────────────────────────────────────────

/// Write an init script into `dir` and return the `--init-script` args.
pub fn init_script(dir: &Path, name: &str, body: &str) -> [String; 2] {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    ["--init-script".into(), path.to_string_lossy().into_owned()]
}

/// A Groovy init script that points every Maven repository of the build —
/// settings `pluginManagement` / `buildscript` / `dependencyResolutionManagement`
/// and each project's (+ buildscript) repositories, including ones declared
/// later — at the fake origins: `https://patch.socket.dev/<path>` at
/// `hosted` + `<path>` when given, everything else except `file:` at
/// `central`. Plain-http origins need `allowInsecureProtocol`. Projects are
/// reached through `gradle.lifecycle.beforeProject` on Gradle ≥ 8.8
/// (Isolated Projects compatible), `gradle.beforeProject` below that.
pub fn mirror_init_script(central: &str, hosted: Option<&str>) -> String {
    let central = central.trim_end_matches('/');
    let hosted = hosted.unwrap_or("").trim_end_matches('/');
    format!(
        r#"// socket-patch e2e harness: route every repository to the fake origins.
def socketCentral = '{central}/'
def socketHosted = '{hosted}'
def socketMirror = {{ repos ->
    repos.configureEach {{ repo ->
        if (repo instanceof org.gradle.api.artifacts.repositories.MavenArtifactRepository) {{
            def url = repo.url.toString()
            if (url.startsWith('file:')) return
            if (socketHosted && url.startsWith('https://patch.socket.dev/')) {{
                repo.url = socketHosted + url.substring('https://patch.socket.dev'.length())
            }} else {{
                repo.url = socketCentral
            }}
            repo.allowInsecureProtocol = true
        }}
    }}
}}
gradle.beforeSettings {{ settings ->
    socketMirror(settings.pluginManagement.repositories)
    socketMirror(settings.buildscript.repositories)
    socketMirror(settings.dependencyResolutionManagement.repositories)
}}
def socketProject = {{ project ->
    socketMirror(project.buildscript.repositories)
    socketMirror(project.repositories)
}}
if (org.gradle.util.GradleVersion.current() >= org.gradle.util.GradleVersion.version('8.8')) {{
    gradle.lifecycle.beforeProject(socketProject)
}} else {{
    gradle.beforeProject(socketProject)
}}
"#
    )
}

// ── files ───────────────────────────────────────────────────────────────

/// Every committable file under `root` (build output skipped), keyed by its
/// forward-slash relative path.
pub fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                if !BUILD_OUTPUT_DIRS.contains(&name.as_str()) && name != ".git" {
                    walk(root, &path, out);
                }
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, std::fs::read(&path).unwrap());
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Every Gradle lockfile under `root`: `<project>/gradle.lockfile` on 7+,
/// `<project>/gradle/dependency-locks/<configuration>.lockfile` on 6.x.
pub fn lockfiles(root: &Path) -> BTreeMap<String, Vec<u8>> {
    snapshot(root)
        .into_iter()
        .filter(|(rel, _)| rel.ends_with(".lockfile"))
        .collect()
}

/// `git` with the ambient repository / config environment scrubbed.
fn git(cwd: &Path) -> Command {
    let mut cmd = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(&key);
        }
    }
    // No system or global config (a developer's commit signing, hooks or
    // autocrlf must not change the fixture): an empty global file.
    let global = std::env::temp_dir().join("socket-patch-e2e-empty.gitconfig");
    if !global.is_file() {
        let _ = std::fs::write(&global, "");
    }
    cmd.current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &global)
        .args(["-c", "user.name=socket-patch-e2e"])
        .args(["-c", "user.email=e2e@socket.invalid"])
        .args(["-c", "init.defaultBranch=main"]);
    cmd
}

fn git_ok(cmd: &mut Command, what: &str) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: git: {e}"));
    assert!(ok(&out), "{what}:\n{}", dump(&out));
}

/// Commit `src`'s tree (LF, as written) and clone it to `dst` with
/// `core.autocrlf=true`: the working tree a Windows developer checks out,
/// on every OS. Text files arrive with CRLF unless `.gitattributes` says
/// otherwise. Returns `dst`.
pub fn git_autocrlf_clone(src: &Path, dst: &Path) -> PathBuf {
    if !src.join(".git").exists() {
        git_ok(git(src).args(["init", "-q"]), "git init");
    }
    git_ok(
        git(src).args(["-c", "core.autocrlf=false", "add", "-A"]),
        "git add",
    );
    git_ok(
        git(src).args([
            "-c",
            "core.autocrlf=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "fixture",
        ]),
        "git commit",
    );
    let parent = dst.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    git_ok(
        git(parent).args([
            "-c",
            "core.autocrlf=true",
            "clone",
            "-q",
            "--config",
            "core.autocrlf=true",
            &src.to_string_lossy(),
            &dst.to_string_lossy(),
        ]),
        "git clone",
    );
    dst.to_path_buf()
}

// ── probe reports ───────────────────────────────────────────────────────

/// Where [`probe_report`] writes.
pub fn probe_dir() -> PathBuf {
    std::env::var_os(GRADLE_PROBE_DIR_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("gradle-probe"))
}

/// Write one cell's JSON probe report (`<probe dir>/<cell>.json`, the cell
/// name reduced to `[A-Za-z0-9._-]`) and return its path. The CI grid
/// uploads the directory, so a cell's measured Gradle behaviour survives
/// the run.
pub fn probe_report(cell: &str, json: &serde_json::Value) -> PathBuf {
    let dir = probe_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let name: String = cell
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(json).unwrap()).unwrap();
    println!("probe report: {}", path.display());
    path
}

// ── self-tests (pure; integration crates get no cfg(test)) ──────────────

mod gradle_build_common_selftests {
    use super::*;

    #[test]
    fn jdk_feature_reads_both_version_schemes() {
        assert_eq!(
            jdk_feature("21.0.8 (Eclipse Adoptium 21.0.8+9-LTS)"),
            Some(21)
        );
        assert_eq!(jdk_feature("11.0.24 (Homebrew 11.0.24+0)"), Some(11));
        assert_eq!(jdk_feature("1.8.0_412 (Temurin 25.412-b08)"), Some(8));
        assert_eq!(jdk_feature("17 (x)"), Some(17));
        assert_eq!(jdk_feature(""), None);
        let banner = "\n------\nGradle 8.14.3\n------\n\nKotlin: 2.0.21\nJVM:          21.0.8 (Eclipse Adoptium 21.0.8+9-LTS)\nOS: Linux\n";
        assert_eq!(
            jvm_banner(banner).as_deref(),
            Some("21.0.8 (Eclipse Adoptium 21.0.8+9-LTS)")
        );
        let nine = "Gradle 9.8.0\nLauncher JVM:  21.0.12.1 (Homebrew 21.0.12.1)\n\
                    Daemon JVM:    /x (no Daemon JVM specified)\n";
        assert_eq!(
            jvm_banner(nine).as_deref(),
            Some("21.0.12.1 (Homebrew 21.0.12.1)")
        );
        assert_eq!(jdk_feature(&jvm_banner(nine).unwrap()), Some(21));
    }

    #[test]
    fn version_parts_and_ordering() {
        let g = |v: &str| Gradle {
            program: "gradle".into(),
            version: v.into(),
            jvm: String::new(),
            extra_args: Vec::new(),
        };
        assert_eq!((g("6.9.4").major(), g("6.9.4").minor()), (6, 9));
        assert_eq!((g("9.0-rc-1").major(), g("9.0-rc-1").minor()), (9, 0));
        assert!(g("8.14.3").at_least(8, 8) && !g("8.7").at_least(8, 8));
        assert!(g("9.8.0").at_least(8, 8) && !g("7.6.6").at_least(8, 0));
        let ip = g("9.8.0").with_isolated_projects();
        assert_eq!(
            ip.extra_args,
            vec!["-Dorg.gradle.unsafe.isolated-projects=true".to_string()]
        );
    }

    #[test]
    fn mirror_init_script_redirects_both_origins() {
        let script = mirror_init_script("http://127.0.0.1:1/", Some("http://127.0.0.1:2"));
        assert!(script.contains("def socketCentral = 'http://127.0.0.1:1/'"));
        assert!(script.contains("def socketHosted = 'http://127.0.0.1:2'"));
        assert!(script.contains("gradle.beforeSettings"));
        assert!(script.contains("gradle.lifecycle.beforeProject"));
        assert!(script.contains("repo.allowInsecureProtocol = true"));
        assert!(mirror_init_script("http://h", None).contains("def socketHosted = ''"));
    }

    /// LF as committed, CRLF in the autocrlf clone; `-text` files stay LF.
    #[test]
    fn git_autocrlf_clone_checks_out_crlf() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        write_project(
            &src,
            &[
                ("settings.gradle", "include 'app'\nrootProject.name = 'x'\n"),
                (".gitattributes", "*.bin -text\n"),
                ("data.bin", "a\nb\n"),
            ],
        );
        let dst = git_autocrlf_clone(&src, &tmp.path().join("clone"));
        assert_eq!(
            std::fs::read(dst.join("settings.gradle")).unwrap(),
            b"include 'app'\r\nrootProject.name = 'x'\r\n"
        );
        assert_eq!(std::fs::read(dst.join("data.bin")).unwrap(), b"a\nb\n");
        assert_eq!(
            std::fs::read(src.join("settings.gradle")).unwrap(),
            b"include 'app'\nrootProject.name = 'x'\n"
        );
    }

    #[test]
    fn print_cp_task_per_dsl() {
        assert!(print_cp_task(Dsl::Groovy, "runtimeClasspath")
            .contains("files(configurations.named('runtimeClasspath'))"));
        assert!(print_cp_task(Dsl::Kotlin, "compileClasspath")
            .contains("files(configurations.named(\"compileClasspath\"))"));
        assert_eq!(Dsl::Kotlin.settings_file(), "settings.gradle.kts");
        assert_eq!(Dsl::Groovy.build_file(), "build.gradle");
    }
}
