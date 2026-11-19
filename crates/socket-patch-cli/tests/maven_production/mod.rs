//! Maven against production: the hosted leg of `e2e_hosted_production` and
//! the vendored and agent legs of `e2e_vendored_production`.
//!
//! Production's one free Maven patch (published 2026-10-23) fixes
//! GHSA-qr7j-h6gg-jmgc / CVE-2018-11307 in `jackson-databind` 2.7.9.2. It
//! replaces one class, `SubTypeValidator`, whose deny list gains the iBatis
//! gadget classes. Every mode delivers the patch service's build of the
//! whole jar: hosted and vendored as `2.7.9.2-socket.<hex8>`, agent in
//! place of the cached jar.
//!
//! [`delivery`] runs one mode end to end with real Maven, nothing mocked:
//!
//!   1. A project that depends on the package is built from Maven Central
//!      (`compile` + `dependency:build-classpath`) and its own class
//!      ([`PROBE`]) is run on the classpath Maven resolved: the class comes
//!      from the upstream jar and the fix is absent.
//!   2. `get <uuid> --mode <mode>` applies the patch. Maven builds again
//!      (hosted and vendored from a fresh checkout of the committable
//!      files, vendored offline, agent with `-C -U`). The build must
//!      resolve the same artifacts as before, byte for byte, except the
//!      patched one; that jar must differ from the original in exactly the
//!      members the patch record names, each hashing to the record's
//!      `afterHash`; and the JVM must load the patched class from it, with
//!      the fix active.
//!   3. The drop-in check ([`drop_in`]): on every JDK the run provides,
//!      every class of the original jar and of the applied jar is loaded
//!      and linked beside the same dependency jars. The two reports must
//!      be identical, and each replaced class must keep the class-file
//!      version of the class it replaces.
//!   4. `rollback` must restore every file byte for byte, and Maven must
//!      resolve the original artifacts again.
//!   5. `scan --package <purl> --mode <mode>` followed by `remove <uuid>`
//!      must end in the same restored state.
//!
//! Toolchain: the Maven that `maven_build_common` selects
//! (`SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}`) and the JDKs of
//! [`JAVA_ENV`]. [`delivery`] returns `Err` when it cannot run at all: no
//! Maven, no JDK, or an upstream build that could not resolve from Maven
//! Central. The suites turn that into their soft skip, a hard failure under
//! their STRICT flag. Every other failure panics, the upstream build's
//! included.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[allow(clippy::duplicate_mod)]
#[path = "../common/envelope.rs"]
mod envelope;
#[allow(clippy::duplicate_mod)]
#[path = "../common/hermetic.rs"]
mod hermetic;
#[allow(clippy::duplicate_mod)]
#[path = "../common/jvm_env.rs"]
mod jvm_env;
#[allow(clippy::duplicate_mod)]
#[path = "../maven_build_common/mod.rs"]
mod maven_build_common;
#[allow(clippy::duplicate_mod)]
#[path = "../common/oracle.rs"]
mod oracle;
#[allow(clippy::duplicate_mod)]
#[path = "../common/patch_view.rs"]
mod patch_view;

use maven_build_common::{dump, ok, sha1_hex, sha256_hex, Mvn, DEPENDENCY_PLUGIN};

/// The free public patch proxy. Hard-coded, like the suites' own constant:
/// these legs exist to exercise production.
const PROXY: &str = "https://patches-api.socket.dev";

pub const PURL: &str = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.7.9.2";
/// The one free patch production publishes for [`PURL`]. The full check
/// applies it by UUID, so another patch published for the same release
/// cannot change what is tested.
pub const UUID: &str = "8e82692a-a5bd-40ac-97a7-4f1483449fd6";

const GROUP_PATH: &str = "com/fasterxml/jackson/core";
const ARTIFACT: &str = "jackson-databind";
const VERSION: &str = "2.7.9.2";

/// What the patch changes at run time: the static collection
/// `SubTypeValidator.DEFAULT_NO_DESER_CLASS_NAMES` holds this iBatis gadget
/// class only in the patched jar.
const PROBE: [&str; 3] = [
    "com.fasterxml.jackson.databind.jsontype.impl.SubTypeValidator",
    "DEFAULT_NO_DESER_CLASS_NAMES",
    "org.apache.ibatis.parsing.XPathParser",
];

/// The Java feature releases the drop-in check must run on, comma
/// separated (`8,11,17,21,25`). Each is taken from `JAVA_HOME_<n>_<arch>`,
/// the variables GitHub's runner images and `actions/setup-java` export; a
/// missing one fails the leg. Unset or empty: every `JAVA_HOME_<n>_<arch>`
/// in the environment, `JAVA_HOME` and the JDK Maven runs on.
pub const JAVA_ENV: &str = "SOCKET_PATCH_MAVEN_E2E_JAVA";

const PROBE_JAVA: &str = include_str!("Probe.java");
const DROP_IN_JAVA: &str = include_str!("DropIn.java");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Hosted,
    Vendored,
    Agent,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Hosted => "hosted",
            Mode::Vendored => "vendored",
            Mode::Agent => "agent",
        }
    }
}

// ── Toolchain ───────────────────────────────────────────────────────────

/// One JDK: its home, the version `java -version` reports and the feature
/// release that version belongs to (`1.8.0_472` is 8).
struct Jdk {
    home: PathBuf,
    version: String,
    feature: u32,
}

impl Jdk {
    fn tool(&self, name: &str) -> PathBuf {
        tool(&self.home, name)
    }

    /// The JDK at `home`. Maven on Java 8 reports the JDK's `jre`
    /// directory as its runtime; the compiler is one level up.
    fn at(home: &Path) -> Result<Jdk, String> {
        let home = if !tool(home, "javac").is_file()
            && home.file_name().is_some_and(|n| n == "jre")
            && home.parent().is_some_and(|p| tool(p, "javac").is_file())
        {
            home.parent().unwrap()
        } else {
            home
        };
        for name in ["java", "javac"] {
            if !tool(home, name).is_file() {
                return Err(format!("{} has no bin/{name}", home.display()));
            }
        }
        let out = Command::new(tool(home, "java"))
            .arg("-version")
            .output()
            .map_err(|e| format!("{}: `java -version` did not run: {e}", home.display()))?;
        let banner = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let version = java_version(&banner).ok_or_else(|| {
            format!(
                "{}: no version in `java -version`:\n{banner}",
                home.display()
            )
        })?;
        let feature = java_feature(&version)
            .ok_or_else(|| format!("{}: unreadable Java version {version:?}", home.display()))?;
        Ok(Jdk {
            home: home.to_path_buf(),
            version,
            feature,
        })
    }
}

fn tool(home: &Path, name: &str) -> PathBuf {
    home.join("bin")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// The quoted version of a `java -version` banner
/// (`openjdk version "17.0.21" 2026-10-20`).
fn java_version(banner: &str) -> Option<String> {
    let line = banner.lines().find(|l| l.contains(" version \""))?;
    let rest = &line[line.find('"')? + 1..];
    Some(rest[..rest.find('"')?].to_string())
}

/// The feature release of a Java version string: `1.6.0-119` is 6,
/// `1.8.0_472` is 8, `17.0.21` is 17.
fn java_feature(version: &str) -> Option<u32> {
    let mut numbers = version
        .split(|c: char| !c.is_ascii_digit())
        .map(|n| n.parse::<u32>().ok());
    match numbers.next()?? {
        1 => numbers.next()?,
        feature => Some(feature),
    }
}

#[test]
fn java_versions_map_to_their_feature_release() {
    for (banner, version, feature) in [
        (
            "openjdk version \"1.6.0-119\"\nOpenJDK Runtime Environment (Zulu 6.22.0.3)",
            "1.6.0-119",
            6,
        ),
        ("java version \"1.7.0_352\"", "1.7.0_352", 7),
        (
            "Picked up JAVA_TOOL_OPTIONS: -Dx=y\nopenjdk version \"1.8.0_472\"",
            "1.8.0_472",
            8,
        ),
        ("openjdk version \"17.0.21\" 2026-10-20", "17.0.21", 17),
        ("openjdk version \"25\" 2025-09-16", "25", 25),
        ("openjdk version \"26.0.1\" 2026-04-21", "26.0.1", 26),
    ] {
        assert_eq!(java_version(banner).as_deref(), Some(version), "{banner}");
        assert_eq!(java_feature(version), Some(feature), "{version}");
    }
    assert_eq!(java_version("no such thing"), None);
    assert_eq!(java_feature("unknown"), None);
}

/// `JAVA_HOME_<feature>_<arch>` variables of the environment, as
/// `(feature, home)`, lowest feature first.
fn java_home_variables() -> Vec<(u32, PathBuf)> {
    let mut homes: Vec<(u32, PathBuf)> = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.to_string_lossy().into_owned();
            let feature = key.strip_prefix("JAVA_HOME_")?.split('_').next()?;
            (!value.is_empty()).then_some((feature.parse().ok()?, PathBuf::from(value)))
        })
        .collect();
    homes.sort();
    homes
}

/// The JDKs the drop-in check runs on (see [`JAVA_ENV`]), lowest feature
/// release first. `Err` when the environment offers none.
fn drop_in_jdks(leg: &str, maven_java: &Path) -> Result<Vec<Jdk>, String> {
    let variables = java_home_variables();
    let required = std::env::var(JAVA_ENV).unwrap_or_default();
    let required: Vec<&str> = required
        .split([',', ' '])
        .filter(|f| !f.is_empty())
        .collect();
    if !required.is_empty() {
        return Ok(required
            .iter()
            .map(|wanted| {
                let feature: u32 = wanted
                    .parse()
                    .unwrap_or_else(|_| panic!("{JAVA_ENV}: `{wanted}` is not a Java feature release"));
                let (_, home) = variables.iter().find(|(f, _)| *f == feature).unwrap_or_else(|| {
                    panic!(
                        "{leg}: {JAVA_ENV} requires Java {feature}, but no JAVA_HOME_{feature}_<arch> \
                         is set (found: {variables:?})"
                    )
                });
                let jdk = Jdk::at(home).unwrap_or_else(|e| panic!("{leg}: Java {feature}: {e}"));
                assert_eq!(
                    jdk.feature,
                    feature,
                    "{leg}: JAVA_HOME_{feature}_<arch> = {} is Java {}",
                    home.display(),
                    jdk.version
                );
                jdk
            })
            .collect());
    }
    let mut jdks: Vec<Jdk> = Vec::new();
    let candidates = variables
        .into_iter()
        .map(|(_, home)| home)
        .chain(std::env::var_os("JAVA_HOME").map(PathBuf::from))
        .chain([maven_java.to_path_buf()]);
    for home in candidates {
        match Jdk::at(&home) {
            Ok(jdk) => {
                let same = |other: &Jdk| {
                    other.home.canonicalize().ok() == jdk.home.canonicalize().ok()
                        || other.version == jdk.version
                };
                if !jdks.iter().any(same) {
                    jdks.push(jdk);
                }
            }
            Err(why) => println!("{leg}: not a usable JDK: {why}"),
        }
    }
    if jdks.is_empty() {
        return Err("no JDK with a compiler (JAVA_HOME, JAVA_HOME_<n>_<arch>, Maven's own)".into());
    }
    jdks.sort_by_key(|jdk| jdk.feature);
    Ok(jdks)
}

// ── Fixture ─────────────────────────────────────────────────────────────

struct Fixture {
    leg: String,
    mode: Mode,
    _tmp: tempfile::TempDir,
    root: PathBuf,
    /// The home directory of the CLI and of Maven: empty, never the
    /// developer's (no `~/.m2`, no `~/.mavenrc`).
    home: PathBuf,
    /// The Maven local repository, this run's own.
    m2: PathBuf,
    settings: PathBuf,
    proj: PathBuf,
    mvn: Mvn,
    /// The `java` Maven runs on: it runs the project's own class.
    java: PathBuf,
}

fn pom() -> String {
    let (group, artifact) = (GROUP_PATH.replace('/', "."), ARTIFACT);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
<modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
<artifactId>maven-production-e2e</artifactId>\n  <version>1.0.0</version>\n  \
<packaging>jar</packaging>\n  <properties>\n    \
<maven.compiler.source>8</maven.compiler.source>\n    \
<maven.compiler.target>8</maven.compiler.target>\n    \
<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n  </properties>\n  \
<dependencies>\n    <dependency>\n      <groupId>{group}</groupId>\n      \
<artifactId>{artifact}</artifactId>\n      <version>{VERSION}</version>\n    \
</dependency>\n  </dependencies>\n</project>\n"
    )
}

impl Fixture {
    /// `mvn` with this run's home, settings and local repository.
    fn mvn(&self, cwd: &Path, settings: &Path, args: &[&str]) -> Output {
        self.mvn.run_with(cwd, &self.m2, settings, args, |cmd| {
            maven_env(cmd, &self.home)
        })
    }

    /// Compile the project in `cwd` and write the classpath Maven resolved
    /// for it to `target/classpath.txt`.
    fn build(&self, cwd: &Path, settings: &Path, extra: &[&str]) -> Output {
        let goal = format!("{DEPENDENCY_PLUGIN}:build-classpath");
        let output = format!(
            "-Dmdep.outputFile={}",
            cwd.join("target/classpath.txt").display()
        );
        let mut args: Vec<&str> = extra.to_vec();
        args.extend(["compile", goal.as_str(), output.as_str()]);
        self.mvn(cwd, settings, &args)
    }

    /// [`Self::build`], which must succeed; returns what Maven resolved.
    fn build_ok(&self, cwd: &Path, what: &str, extra: &[&str]) -> Resolved {
        let out = self.build(cwd, &self.settings, extra);
        assert!(ok(&out), "{}: {what} failed:\n{}", self.leg, dump(&out));
        Resolved::read(cwd)
    }

    /// `socket-patch <args>` on the anonymous free tier against production,
    /// with the Maven ecosystem only. Returns the run and its envelope.
    fn socket(&self, args: &[&str]) -> (Output, serde_json::Value) {
        let mut cmd = hermetic::command(&oracle::binary());
        hermetic::scrub_crawler_inputs(&mut cmd);
        jvm_env::isolate_cli(&mut cmd);
        let out = cmd
            .current_dir(&self.proj)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GRADLE_USER_HOME", self.home.join(".gradle"))
            .env("MAVEN_REPO_LOCAL", &self.m2)
            .args(args)
            .args([
                "--json",
                "--yes",
                "--ecosystems",
                "maven",
                "--proxy-url",
                PROXY,
            ])
            .output()
            .expect("failed to execute socket-patch binary");
        let envelope = envelope::output_envelope(&out);
        (out, envelope)
    }

    /// [`Self::socket`], which must exit 0 with `"status": "success"` and
    /// no failed event.
    fn socket_ok(&self, args: &[&str]) -> serde_json::Value {
        let (out, envelope) = self.socket(args);
        assert!(
            out.status.success() && envelope["status"] == "success",
            "{}: `socket-patch {}` failed (exit {:?}).\nenvelope:\n{envelope:#}\nstderr:\n{}",
            self.leg,
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !envelope::events(&envelope)
                .iter()
                .any(|e| e["action"] == "failed"),
            "{}: `socket-patch {}` reported a failure:\n{envelope:#}",
            self.leg,
            args.join(" ")
        );
        envelope
    }

    /// Run the project's own class (`Probe.java`) on the classpath Maven
    /// resolved in `cwd`.
    fn probe(&self, cwd: &Path, resolved: &Resolved) -> Loaded {
        let classpath = std::env::join_paths(
            std::iter::once(cwd.join("target/classes"))
                .chain(resolved.artifacts.iter().map(|a| a.path.clone())),
        )
        .expect("classpath");
        let out = Command::new(&self.java)
            .arg("-cp")
            .arg(classpath)
            .arg("Probe")
            .args(PROBE)
            .output()
            .unwrap_or_else(|e| panic!("{}: {}: {e}", self.leg, self.java.display()));
        assert!(
            ok(&out),
            "{}: the project's class did not run on the resolved classpath:\n{}",
            self.leg,
            dump(&out)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let field = |key: &str| {
            stdout
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_else(|| {
                    panic!("{}: Probe printed no `{key}`:\n{}", self.leg, dump(&out))
                })
                .to_string()
        };
        assert_eq!(
            field("parsed"),
            "42",
            "{}: the dependency must still work",
            self.leg
        );
        Loaded {
            from: field("loaded-from"),
            class_sha256: field("class-sha256"),
            fixed: field("probe") == "true",
        }
    }

    /// `<m2>/<group>/<artifact>/<version>`.
    fn repo_dir(&self, version: &str) -> PathBuf {
        self.m2.join(GROUP_PATH).join(ARTIFACT).join(version)
    }

    fn report(&self, step: &str, detail: &str) {
        println!(
            "MAVEN-PROD mode={} maven={} step={step} pass ({detail})",
            self.mode.as_str(),
            self.mvn.version
        );
    }
}

/// Give a Maven child `home` as its home directory, the way
/// `jvm_env::isolate_cli` does for the CLI: no ambient Maven or JVM options,
/// and the version-manager roots (asdf, mise, SDKMAN, …) carried over, so a
/// `mvn` or `java` that is a shim still resolves once `HOME` moves.
fn maven_env(cmd: &mut Command, home: &Path) {
    jvm_env::isolate_cli(cmd);
    cmd.env("HOME", home).env("USERPROFILE", home);
    // `user.home` is where Maven itself looks for `~/.m2`; the JVM takes it
    // from the account, not from $HOME. MAVEN_OPTS is split on whitespace by
    // the launcher, so a path with a space keeps the account's home (the
    // settings file and the local repository are still this run's own).
    let home = home.to_string_lossy();
    if !home.contains(char::is_whitespace) {
        cmd.env("MAVEN_OPTS", format!("-Duser.home={home}"));
    }
}

#[test]
fn maven_env_moves_home_and_keeps_what_the_cli_isolation_carries() {
    let home = Path::new("/nonexistent/maven-production-home");
    let mut maven = Command::new("mvn");
    maven_env(&mut maven, home);
    let env: BTreeMap<_, _> = maven.get_envs().collect();
    for key in ["HOME", "USERPROFILE"] {
        assert_eq!(
            env[std::ffi::OsStr::new(key)],
            Some(home.as_os_str()),
            "{key}"
        );
    }
    assert_eq!(
        env[std::ffi::OsStr::new("MAVEN_OPTS")],
        Some(std::ffi::OsStr::new(
            "-Duser.home=/nonexistent/maven-production-home"
        ))
    );
    // A real Maven reads `MAVEN_ARGS` and refuses to start on a settings
    // file named there that does not exist; it must be started with none,
    // and with the settings its own command line names.
    assert_eq!(
        env.get(std::ffi::OsStr::new("MAVEN_ARGS")),
        Some(&None),
        "a Maven child is started with no MAVEN_ARGS"
    );
    // Everything else the CLI's isolation sets or removes (the
    // version-manager roots among it) reaches Maven unchanged.
    let mut cli = Command::new("socket-patch");
    jvm_env::isolate_cli(&mut cli);
    for (key, value) in cli.get_envs() {
        if !["HOME", "USERPROFILE", "MAVEN_OPTS"]
            .iter()
            .any(|k| key == *k)
        {
            assert_eq!(env.get(key), Some(&value), "{key:?}");
        }
    }
}

/// The Maven launcher, the `java` it runs on and the drop-in JDKs.
fn toolchain(leg: &str) -> Result<(Mvn, PathBuf, Vec<Jdk>), String> {
    let mvn =
        Mvn::detect(leg).ok_or("Maven is not available (see the SKIP line above)".to_string())?;
    let runtime = mvn
        .runtime
        .clone()
        .ok_or("`mvn -v` names no Java runtime".to_string())?;
    let java = tool(&runtime, "java");
    if !java.is_file() {
        return Err(format!("Maven's Java runtime has no {}", java.display()));
    }
    let jdks = drop_in_jdks(leg, &runtime)?;
    Ok((mvn, java, jdks))
}

// ── What Maven resolved ─────────────────────────────────────────────────

/// What a JVM running the project's class loaded for [`PROBE`]'s class.
#[derive(Debug)]
struct Loaded {
    /// The jar the class came from (the URL path of its code source).
    from: String,
    /// sha256 of the class file the class loader serves.
    class_sha256: String,
    /// Whether the fix is active (see [`PROBE`]).
    fixed: bool,
}

impl Loaded {
    fn is_from(&self, jar: &Artifact) -> bool {
        self.from.ends_with(&format!("/{}", jar.name))
    }
}

struct Artifact {
    path: PathBuf,
    name: String,
    sha256: String,
}

impl Artifact {
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap_or_else(|e| panic!("read {}: {e}", self.path.display()))
    }
}

/// The classpath `dependency:build-classpath` wrote for one build.
struct Resolved {
    artifacts: Vec<Artifact>,
}

impl Resolved {
    fn read(cwd: &Path) -> Resolved {
        let file = cwd.join("target/classpath.txt");
        let list =
            std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let artifacts = std::env::split_paths(list.trim())
            .filter(|p| !p.as_os_str().is_empty())
            .map(|path| {
                let bytes =
                    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                Artifact {
                    name: path.file_name().unwrap().to_string_lossy().into_owned(),
                    sha256: sha256_hex(&bytes),
                    path,
                }
            })
            .collect();
        Resolved { artifacts }
    }

    /// The one resolved jar of the package under test.
    fn subject(&self, leg: &str) -> &Artifact {
        let hits: Vec<&Artifact> = self
            .artifacts
            .iter()
            .filter(|a| a.name.starts_with(&format!("{ARTIFACT}-")))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "{leg}: the build must resolve exactly one {ARTIFACT} jar: {:?}",
            self.names()
        );
        hits[0]
    }

    /// Every other resolved artifact: file name → sha256.
    fn others(&self) -> BTreeMap<&str, &str> {
        self.artifacts
            .iter()
            .filter(|a| !a.name.starts_with(&format!("{ARTIFACT}-")))
            .map(|a| (a.name.as_str(), a.sha256.as_str()))
            .collect()
    }

    fn names(&self) -> Vec<&str> {
        self.artifacts.iter().map(|a| a.name.as_str()).collect()
    }
}

// ── Jars and trees ──────────────────────────────────────────────────────

/// A jar's file members (directory entries left out): name → bytes.
fn members(jar: &[u8], what: &str) -> BTreeMap<String, Vec<u8>> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar))
        .unwrap_or_else(|e| panic!("{what} is not a jar: {e}"));
    let mut out = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        if entry.is_dir() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        out.insert(entry.name().to_string(), bytes);
    }
    out
}

/// How many directory entries a jar carries.
fn directory_entries(jar: &[u8]) -> usize {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).expect("jar");
    (0..archive.len())
        .filter(|i| archive.by_index(*i).is_ok_and(|e| e.is_dir()))
        .count()
}

/// `(major, minor)` of a class file: 50 is Java 6, 52 is Java 8.
fn class_version(class: &[u8]) -> Option<(u16, u16)> {
    (class.len() >= 8 && class[..4] == [0xCA, 0xFE, 0xBA, 0xBE]).then(|| {
        (
            u16::from_be_bytes([class[6], class[7]]),
            u16::from_be_bytes([class[4], class[5]]),
        )
    })
}

#[test]
fn class_version_reads_the_class_file_header() {
    assert_eq!(
        class_version(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 50, 0, 0x95]),
        Some((50, 0))
    );
    assert_eq!(
        class_version(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 3, 0, 45]),
        Some((45, 3))
    );
    assert_eq!(class_version(b"PK\x03\x04 not a class"), None);
    assert_eq!(class_version(&[0xCA, 0xFE]), None);
}

/// The files the production record of [`UUID`] replaces, as
/// `(jar member, beforeHash, afterHash)` (git-blob sha256).
fn patch_record(leg: &str) -> Vec<(String, String, String)> {
    let record = patch_view::record_blocking(PROXY, UUID);
    let files: Vec<(String, String, String)> = patch_view::files(&record)
        .into_iter()
        .map(|(path, before, after)| match (before, after) {
            (Some(before), Some(after)) => (path, before, after),
            _ => panic!("{leg}: {path} is not a replaced file of {UUID}:\n{record:#}"),
        })
        .collect();
    assert!(
        !files.is_empty(),
        "{leg}: the production record of {UUID} names no files:\n{record:#}"
    );
    files
}

/// The applied jar is the original with exactly the record's members
/// replaced: the same file members, each one the record names going from
/// its `beforeHash` to its `afterHash` at an unchanged class-file version,
/// and every other member byte for byte the original's.
fn assert_patched_jar(
    leg: &str,
    original: &[u8],
    applied: &[u8],
    record: &[(String, String, String)],
) {
    let before = members(original, "the original jar");
    let after = members(applied, "the applied jar");
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "{leg}: the applied jar must hold the same file members as the original"
    );
    for (member, before_hash, after_hash) in record {
        let (old, new) = match (before.get(member), after.get(member)) {
            (Some(old), Some(new)) => (old, new),
            _ => panic!("{leg}: the record's {member} is not a member of the jar"),
        };
        assert_ne!(
            before_hash, after_hash,
            "{leg}: {member}: the record changes nothing"
        );
        assert_eq!(
            &oracle::git_sha256(old),
            before_hash,
            "{leg}: {member} of the upstream jar is not the bytes the patch was made for"
        );
        assert_eq!(
            &oracle::git_sha256(new),
            after_hash,
            "{leg}: {member} of the applied jar is not the patched bytes"
        );
        if member.ends_with(".class") {
            let version = class_version(old);
            assert!(version.is_some(), "{leg}: {member} is not a class file");
            assert_eq!(
                class_version(new),
                version,
                "{leg}: {member}: the patched class must keep the class-file version \
                 (major, minor) of the class it replaces"
            );
        }
    }
    let drifted: Vec<&String> = before
        .iter()
        .filter(|(name, bytes)| {
            !record.iter().any(|(member, _, _)| member == *name) && after.get(*name) != Some(*bytes)
        })
        .map(|(name, _)| name)
        .collect();
    assert!(
        drifted.is_empty(),
        "{leg}: members the patch record does not name differ from the original: {drifted:?}"
    );
    // Packaging is reported, not asserted: the load-and-link check below is
    // what decides whether the jar still works.
    let (dirs_before, dirs_after) = (directory_entries(original), directory_entries(applied));
    if dirs_before != dirs_after {
        println!(
            "NOTE {leg}: the applied jar carries {dirs_after} directory entries, the original \
             {dirs_before} (file members are identical apart from the patched ones)"
        );
    }
}

/// Every file under `dir` (relative, `/`-separated) with its sha256,
/// leaving out the top-level entries named in `skip`.
fn tree(dir: &Path, skip: &[&str]) -> BTreeMap<String, String> {
    fn walk(base: &Path, dir: &Path, skip: &[&str], out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            if dir == base
                && skip
                    .iter()
                    .any(|s| path.file_name().is_some_and(|n| n == *s))
            {
                continue;
            }
            if path.is_dir() {
                walk(base, &path, skip, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy();
                out.insert(
                    rel.replace('\\', "/"),
                    sha256_hex(&std::fs::read(&path).unwrap()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, skip, &mut out);
    out
}

/// The differences between two [`tree`]s: `+added`, `-removed`, `~changed`.
fn tree_diff(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<String> {
    let mut diff = Vec::new();
    for (path, hash) in before {
        match after.get(path) {
            None => diff.push(format!("-{path}")),
            Some(now) if now != hash => diff.push(format!("~{path}")),
            Some(_) => {}
        }
    }
    diff.extend(
        after
            .keys()
            .filter(|path| !before.contains_key(*path))
            .map(|path| format!("+{path}")),
    );
    diff
}

#[test]
fn tree_diff_names_what_was_added_removed_and_changed() {
    let files = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(path, hash)| (path.to_string(), hash.to_string()))
            .collect()
    };
    let before = files(&[("pom.xml", "a"), ("src/Probe.java", "b"), ("gone", "c")]);
    assert_eq!(tree_diff(&before, &before), Vec::<String>::new());
    let after = files(&[
        ("pom.xml", "A"),
        ("src/Probe.java", "b"),
        (".mvn/maven.config", "d"),
    ]);
    assert_eq!(
        tree_diff(&before, &after),
        ["-gone", "~pom.xml", "+.mvn/maven.config"]
    );
}

// ── The drop-in check ───────────────────────────────────────────────────

/// Run `DropIn.java` on `jdk` over `<dir>/<which>/subject.jar`; returns its
/// report: the comparable lines and the last line's `probe` verdict.
fn drop_in_report(
    leg: &str,
    jdk: &Jdk,
    dir: &Path,
    which: &str,
    dependencies: &std::ffi::OsStr,
    classes: &[String],
) -> (Vec<String>, bool) {
    // Both jars are named `subject.jar` and addressed relative to the
    // working directory, so nothing in a report can differ by path.
    let out = Command::new(jdk.tool("java"))
        .current_dir(dir.join(which))
        .arg("-cp")
        .arg(dir.join(format!("classes-{}", jdk.feature)))
        .args(["DropIn", "subject.jar"])
        .arg(dependencies)
        .args(PROBE)
        .args(classes)
        .output()
        .unwrap_or_else(|e| panic!("{leg}: java {}: {e}", jdk.version));
    assert!(
        ok(&out),
        "{leg}: Java {}: the load-and-link run over the {which} jar failed:\n{}",
        jdk.version,
        dump(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<String> = stdout
        .lines()
        .filter(|l| !l.starts_with("# "))
        .map(str::to_string)
        .collect();
    let probe = match lines.pop().as_deref() {
        Some("probe true") => true,
        Some("probe false") => false,
        _ => panic!(
            "{leg}: Java {}: no probe verdict:\n{}",
            jdk.version,
            dump(&out)
        ),
    };
    (lines, probe)
}

/// The drop-in check: on each of `jdks`, load and link every class of the
/// original jar and of the applied jar beside the same `dependencies`, and
/// require identical reports (which classes link, which fail and with what
/// error, that each replaced class initializes, and its public and
/// protected members). Only the fix may differ: [`PROBE`] is false on the
/// original and true on the applied jar.
///
/// Each JDK compiles the harness itself, so a JDK older than any current
/// compiler's oldest target can still run it.
fn drop_in(
    fx: &Fixture,
    jdks: &[Jdk],
    original: &[u8],
    applied: &[u8],
    dependencies: &[PathBuf],
    record: &[(String, String, String)],
) {
    let leg = &fx.leg;
    let dir = fx.root.join("drop-in");
    for (which, jar) in [("original", original), ("applied", applied)] {
        std::fs::create_dir_all(dir.join(which)).unwrap();
        std::fs::write(dir.join(which).join("subject.jar"), jar).unwrap();
    }
    std::fs::write(dir.join("DropIn.java"), DROP_IN_JAVA).unwrap();
    let dependencies = std::env::join_paths(dependencies).expect("dependency classpath");
    let classes: Vec<String> = record
        .iter()
        .filter_map(|(member, _, _)| member.strip_suffix(".class"))
        .map(|class| class.replace('/', "."))
        .collect();
    let total = members(original, "the original jar")
        .keys()
        .filter(|name| {
            name.ends_with(".class")
                && !name.starts_with("META-INF/")
                && !name.ends_with("module-info.class")
        })
        .count();

    for jdk in jdks {
        let out_dir = dir.join(format!("classes-{}", jdk.feature));
        std::fs::create_dir_all(&out_dir).unwrap();
        let javac = Command::new(jdk.tool("javac"))
            .current_dir(&dir)
            .arg("-d")
            .arg(&out_dir)
            .arg(dir.join("DropIn.java"))
            .output()
            .unwrap_or_else(|e| panic!("{leg}: javac {}: {e}", jdk.version));
        assert!(
            ok(&javac),
            "{leg}: Java {} could not compile DropIn.java:\n{}",
            jdk.version,
            dump(&javac)
        );
        let (before, before_probe) =
            drop_in_report(leg, jdk, &dir, "original", &dependencies, &classes);
        let (after, after_probe) =
            drop_in_report(leg, jdk, &dir, "applied", &dependencies, &classes);
        assert_eq!(
            before, after,
            "{leg}: Java {}: the applied jar does not load and link like the original",
            jdk.version
        );
        let linked = format!(" of {total}");
        let summary = after
            .iter()
            .find(|l| l.starts_with("linked ") && l.ends_with(&linked))
            .unwrap_or_else(|| {
                panic!(
                    "{leg}: Java {}: the run must cover all {total} classes:\n{after:#?}",
                    jdk.version
                )
            });
        assert_ne!(
            summary,
            &format!("linked 0{linked}"),
            "{leg}: Java {} linked nothing",
            jdk.version
        );
        for class in &classes {
            let initialized = format!("init {class}: ok, from subject.jar");
            assert!(
                after.contains(&initialized),
                "{leg}: Java {}: the patched {class} must initialize from the jar under \
                 test:\n{after:#?}",
                jdk.version
            );
        }
        assert!(
            !before_probe && after_probe,
            "{leg}: Java {}: the fix must be absent from the original jar and active in the \
             applied one (original: {before_probe}, applied: {after_probe})",
            jdk.version
        );
        let failures: Vec<&str> = after
            .iter()
            .filter_map(|l| l.strip_prefix("link-fail "))
            .collect();
        let failures = if failures.is_empty() {
            "no link failure".to_string()
        } else {
            format!("the same link failure in both: {}", failures.join("; "))
        };
        fx.report(
            "drop-in",
            &format!(
                "java={} {summary} in both jars, {failures}, fix absent -> active",
                jdk.version
            ),
        );
    }
}

// ── The leg ─────────────────────────────────────────────────────────────

/// Whether `event` is about the package under test (agent and vendored
/// events carry the record's `?ext=jar` qualifier).
fn names_package(event: &serde_json::Value) -> bool {
    event["purl"]
        .as_str()
        .is_some_and(|purl| purl == PURL || purl.starts_with(&format!("{PURL}?")))
}

/// The UUID of the patch a `get` / `scan` run delivered for the package:
/// the one on its `applied` event, which must exist. Vendored mode names
/// the patch on the `downloaded` event instead, so that is read next.
fn delivered_uuid(leg: &str, envelope: &serde_json::Value) -> String {
    let about: Vec<&serde_json::Value> = envelope::events(envelope)
        .iter()
        .filter(|e| names_package(e))
        .collect();
    let uuid_of = |action: &str| {
        about
            .iter()
            .filter(|e| e["action"] == action)
            .find_map(|e| e["uuid"].as_str())
    };
    assert!(
        about.iter().any(|e| e["action"] == "applied"),
        "{leg}: no `applied` event for {PURL}. The patch is published and the package is \
         resolved, so discovery or delivery broke:\n{envelope:#}"
    );
    uuid_of("applied")
        .or_else(|| uuid_of("downloaded"))
        .unwrap_or_else(|| panic!("{leg}: no event names the delivered patch:\n{envelope:#}"))
        .to_string()
}

/// What the undo of each mode must leave: the project as it was before the
/// patch, and (agent mode) the Maven local repository as it was.
struct Pristine {
    proj: BTreeMap<String, String>,
    /// The local repository, hashed only where a mode writes to it.
    m2: Option<BTreeMap<String, String>>,
}

impl Pristine {
    fn of(fx: &Fixture) -> Pristine {
        Pristine {
            proj: tree(&fx.proj, &["target"]),
            m2: (fx.mode == Mode::Agent).then(|| tree(&fx.m2, &[])),
        }
    }

    /// Every file the patch touched is back, byte for byte.
    fn assert_restored(&self, fx: &Fixture, original: &Artifact, undo: &str) {
        let leg = &fx.leg;
        let mut diff = tree_diff(&self.proj, &tree(&fx.proj, &["target"]));
        if let Some(m2) = &self.m2 {
            // Agent mode keeps its (now empty) manifest and the original
            // jar it backed up; `jvm_jar` never deletes that backup.
            let manifest = fx.proj.join(".socket/manifest.json");
            let patches: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
            assert_eq!(
                patches["patches"],
                serde_json::json!({}),
                "{leg}: {undo} must leave no patch in the manifest"
            );
            let backup = format!(".socket/jvm-originals/{}.jar", original.sha256);
            assert_eq!(
                sha256_hex(&std::fs::read(fx.proj.join(&backup)).unwrap()),
                original.sha256,
                "{leg}: the kept backup must be the original jar"
            );
            diff.retain(|d| *d != "+.socket/manifest.json" && *d != format!("+{backup}"));
            // The local repository: the artifact's directory holds the
            // same files with the same bytes, and nothing else Maven had
            // cached changed. (Files a later Maven run added elsewhere are
            // Maven's own.)
            let artifact_dir = format!("{GROUP_PATH}/{ARTIFACT}/{VERSION}/");
            let changed: Vec<String> = tree_diff(m2, &tree(&fx.m2, &[]))
                .into_iter()
                .filter(|d| !d.starts_with('+') || d[1..].starts_with(&artifact_dir))
                .collect();
            assert_eq!(
                changed,
                Vec::<String>::new(),
                "{leg}: {undo} must restore the local repository byte for byte (+added, \
                 -removed, ~changed)"
            );
        }
        assert_eq!(
            diff,
            Vec::<String>::new(),
            "{leg}: {undo} must restore the project byte for byte (+added, -removed, ~changed)"
        );
    }
}

/// Maven resolves the original artifacts again, and the project's class
/// loads the unpatched class from the upstream jar.
fn assert_resolves_original(
    fx: &Fixture,
    before: &Resolved,
    original_class_sha256: &str,
    undo: &str,
) {
    let leg = &fx.leg;
    let after = fx.build_ok(&fx.proj, &format!("the build after {undo}"), &[]);
    let pairs = |r: &Resolved| -> Vec<(String, String)> {
        r.artifacts
            .iter()
            .map(|a| (a.path.display().to_string(), a.sha256.clone()))
            .collect()
    };
    assert_eq!(
        pairs(&after),
        pairs(before),
        "{leg}: after {undo}, Maven must resolve exactly the artifacts it resolved before the \
         patch"
    );
    let loaded = fx.probe(&fx.proj, &after);
    assert!(
        !loaded.fixed && loaded.class_sha256 == original_class_sha256,
        "{leg}: after {undo}, the JVM must load the unpatched class again: {loaded:?}"
    );
    fx.report(
        undo,
        "every file restored byte for byte; Maven resolves the original again",
    );
}

/// One mode, end to end (see the module docs). `Err(why)` when the leg
/// cannot run at all.
pub fn delivery(mode: Mode) -> Result<(), String> {
    let leg = format!("maven_{}_jackson_databind_delivery", mode.as_str());
    let (mvn, java, jdks) = toolchain(&leg)?;
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().canonicalize().expect("canonical tempdir");
    let fx = Fixture {
        mode,
        home: root.join("home"),
        m2: root.join("m2"),
        settings: root.join("settings.xml"),
        proj: root.join("proj"),
        root,
        _tmp: tmp,
        mvn,
        java,
        leg,
    };
    let leg = &fx.leg;
    std::fs::create_dir_all(&fx.home).unwrap();
    // asdf and mise read the global tool versions from `$HOME/.tool-versions`
    // and take no path to it from the environment, so a `mvn` shim needs the
    // file in the moved home too.
    if let Some(real) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let _ = std::fs::copy(
            Path::new(&real).join(".tool-versions"),
            fx.home.join(".tool-versions"),
        );
    }
    std::fs::create_dir_all(fx.proj.join("src/main/java")).unwrap();
    std::fs::write(fx.proj.join("pom.xml"), pom()).unwrap();
    std::fs::write(fx.proj.join("src/main/java/Probe.java"), PROBE_JAVA).unwrap();
    maven_build_common::write_settings(&fx.settings, &[]);
    println!(
        "{leg}: drop-in check on Java {}",
        jdks.iter()
            .map(|jdk| jdk.version.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // 1. The upstream build. Only fixed, long-published releases are asked
    // of Maven Central, so a resolution failure here is not the CLI's.
    let out = maven_build_common::with_central_fallback(
        leg,
        "the upstream build",
        &fx.settings,
        |settings, extra| fx.build(&fx.proj, settings, extra),
    );
    if !ok(&out) {
        // Only Maven Central (and its mirror) failing to serve the fixture
        // is a reason not to run. Anything else is this leg's own failure.
        assert!(
            maven_build_common::is_resolution_failure(&out),
            "{leg}: the upstream build failed, and not on resolving from Maven Central:\n{}",
            dump(&out)
        );
        return Err(format!(
            "the upstream build could not resolve from Maven Central:\n{}",
            dump(&out)
        ));
    }
    let before = Resolved::read(&fx.proj);
    let original = before.subject(leg);
    assert_eq!(
        original.name,
        format!("{ARTIFACT}-{VERSION}.jar"),
        "{leg}: fixture"
    );
    assert!(
        !before.others().is_empty(),
        "{leg}: the fixture must resolve other artifacts too, or `nothing else moved` is \
         vacuous: {:?}",
        before.names()
    );
    let original_jar = original.bytes();
    let record = patch_record(leg);
    let class_member = PROBE[0].replace('.', "/") + ".class";
    let class_sha256 = |jar: &[u8], what: &str| {
        sha256_hex(
            members(jar, what)
                .get(&class_member)
                .unwrap_or_else(|| panic!("{leg}: {what} has no {class_member}")),
        )
    };
    let original_class = class_sha256(&original_jar, "the original jar");
    // Anti-vacuity: before the patch the JVM loads the upstream class and
    // the fix is absent.
    let loaded = fx.probe(&fx.proj, &before);
    assert!(
        !loaded.fixed && loaded.class_sha256 == original_class && loaded.is_from(original),
        "{leg}: the upstream build must load the unpatched class from {}: {loaded:?}",
        original.name
    );
    let pristine = Pristine::of(&fx);

    // 2. Apply the pinned patch.
    let envelope = fx.socket_ok(&["get", UUID, "--mode", mode.as_str()]);
    assert_eq!(
        delivered_uuid(leg, &envelope),
        UUID,
        "{leg}: `get {UUID}` delivered another patch:\n{envelope:#}"
    );
    let suffixed = format!("{VERSION}-socket.{}", &UUID[..8]);
    let suffixed_jar = format!("{ARTIFACT}-{suffixed}.jar");
    let after = match mode {
        Mode::Hosted => {
            let wired = std::fs::read_to_string(fx.proj.join("pom.xml")).unwrap();
            assert!(
                wired.contains(&format!("<version>{suffixed}</version>"))
                    && wired.contains("https://patch.socket.dev/")
                    && wired.contains(&format!("<id>socket-patch-{UUID}</id>")),
                "{leg}: pom.xml must pin {suffixed} on the Socket repository:\n{wired}"
            );
            assert!(
                !fx.repo_dir(&suffixed).exists(),
                "{leg}: hosted mode must leave the download to Maven"
            );
            let fresh = fx.root.join("fresh");
            maven_build_common::fresh_checkout(&fx.proj, &fresh);
            // The suffixed version exists only on the Socket repository, so
            // a build that resolves it fetched it from production.
            let after = fx.build_ok(&fresh, "the build of the hosted checkout", &[]);
            let subject = after.subject(leg);
            assert_eq!(
                subject.path,
                fx.repo_dir(&suffixed).join(&suffixed_jar),
                "{leg}: Maven must resolve the patched version it downloaded"
            );
            let pins = std::fs::read_to_string(fresh.join(".mvn/checksums/checksums.sha256"))
                .unwrap_or_else(|e| panic!("{leg}: no Trusted Checksums file: {e}"));
            assert!(
                pins.contains(&subject.sha256),
                "{leg}: the jar Maven downloaded must be the one hosted mode pinned:\n{pins}"
            );
            after
        }
        Mode::Vendored => {
            let committed =
                format!(".socket/vendor/maven2/{GROUP_PATH}/{ARTIFACT}/{suffixed}/{suffixed_jar}");
            assert!(
                fx.proj.join(&committed).is_file()
                    && fx.proj.join(".socket/vendor/state.json").is_file(),
                "{leg}: no vendored artifact at {committed}:\n{envelope:#}"
            );
            let fresh = fx.root.join("fresh");
            maven_build_common::fresh_checkout(&fx.proj, &fresh);
            // Offline: the committed jar needs no Socket service and no
            // registry (the other artifacts are in the local repository).
            // Maven before 3.9.2 has no repository tail to read it from
            // offline, so it builds online through the file repository.
            let offline: &[&str] = if fx.mvn.numeric() >= vec![3, 9, 2] {
                &["-o"]
            } else {
                &[]
            };
            let after = fx.build_ok(&fresh, "the build of the vendored checkout", offline);
            let subject = after.subject(leg);
            assert_eq!(subject.name, suffixed_jar, "{leg}: {:?}", after.names());
            assert_eq!(
                subject.sha256,
                sha256_hex(&std::fs::read(fresh.join(&committed)).unwrap()),
                "{leg}: Maven must consume the committed jar"
            );
            after
        }
        Mode::Agent => {
            // Strict checksums and a forced update check: Maven must keep
            // the jar the CLI put in its local repository.
            let after = fx.build_ok(&fx.proj, "the build after the agent apply", &["-C", "-U"]);
            let subject = after.subject(leg);
            assert_eq!(
                subject.path, original.path,
                "{leg}: the cached jar is patched in place"
            );
            assert_eq!(
                std::fs::read_to_string(subject.path.with_extension("jar.sha1"))
                    .unwrap()
                    .trim(),
                sha1_hex(&subject.bytes()),
                "{leg}: the cached jar's .sha1 must describe the applied jar"
            );
            after
        }
    };
    let subject = after.subject(leg);
    assert_ne!(
        subject.sha256, original.sha256,
        "{leg}: the build still resolves the original"
    );
    assert_eq!(
        after.others(),
        before.others(),
        "{leg}: apart from {ARTIFACT}, the build must resolve the artifacts it resolved before \
         the patch, byte for byte"
    );
    let applied_jar = subject.bytes();
    assert_patched_jar(leg, &original_jar, &applied_jar, &record);
    fx.report(
        "build-resolves-patched-jar",
        &format!(
            "{}, {} other artifact(s) unchanged",
            subject.name,
            after.others().len()
        ),
    );

    let cwd = if mode == Mode::Agent {
        fx.proj.clone()
    } else {
        fx.root.join("fresh")
    };
    let loaded = fx.probe(&cwd, &after);
    let applied_class = class_sha256(&applied_jar, "the applied jar");
    assert_ne!(
        applied_class, original_class,
        "{leg}: the patched class is unchanged"
    );
    assert!(
        loaded.fixed && loaded.class_sha256 == applied_class && loaded.is_from(subject),
        "{leg}: the JVM must load the patched class from {}, with the fix active: {loaded:?}",
        subject.name
    );
    fx.report(
        "jvm-loads-patched-class",
        &format!("{} from {}", PROBE[0], subject.name),
    );

    // 3. The drop-in check, beside the dependencies both builds resolved.
    let dependencies: Vec<PathBuf> = after
        .artifacts
        .iter()
        .filter(|a| a.path != subject.path)
        .map(|a| a.path.clone())
        .collect();
    drop_in(
        &fx,
        &jdks,
        &original_jar,
        &applied_jar,
        &dependencies,
        &record,
    );

    // 4. Undo with `rollback`.
    let envelope = fx.socket_ok(&["rollback"]);
    assert!(
        envelope::events(&envelope)
            .iter()
            .any(|e| names_package(e) && e["action"] == "rolledBack"),
        "{leg}: rollback did not restore {PURL}:\n{envelope:#}"
    );
    pristine.assert_restored(&fx, original, "rollback");
    assert_resolves_original(&fx, &before, &original_class, "rollback");

    // 5. The other way in and out: `scan` selects the patch itself, and
    // `remove` undoes it. A patch production publishes later for the same
    // release may outrank the pinned one; that is the catalog's business,
    // so it is reported and the undo is still held to the same standard.
    let envelope = fx.socket_ok(&["scan", "--package", PURL, "--mode", mode.as_str()]);
    let selected = delivered_uuid(leg, &envelope);
    if selected != UUID {
        println!(
            "NOTE {leg}: scan selected patch {selected} for {PURL}, not the pinned {UUID}. \
             Production published another patch for this release: verify it and consider \
             pinning it (docs/testing/hosted-production-e2e.md)."
        );
    }
    let delivered = match mode {
        // The cached jar is swapped again.
        Mode::Agent => sha256_hex(&original.bytes()) != original.sha256,
        // The pom is wired again.
        Mode::Hosted | Mode::Vendored => {
            tree(&fx.proj, &["target"]).get("pom.xml") != pristine.proj.get("pom.xml")
        }
    };
    assert!(
        delivered,
        "{leg}: scan reported `applied` but wrote nothing:\n{envelope:#}"
    );
    let envelope = fx.socket_ok(&["remove", &selected]);
    assert!(
        envelope::events(&envelope)
            .iter()
            .any(|e| names_package(e) && e["action"] == "removed"),
        "{leg}: remove did not remove {PURL}:\n{envelope:#}"
    );
    pristine.assert_restored(&fx, original, "remove");
    assert_resolves_original(&fx, &before, &original_class, "remove");
    Ok(())
}
