//! Hermetic sbt / Coursier / Ivy fixtures shared by the sbt suites
//! (`e2e_sbt`, `e2e_vex_lockfile::{sbt, sbt_vendored}`): no sbt, no JVM, no
//! network. Each helper writes the on-disk shape the real tool leaves, so
//! the CLI's crawlers, sbt planners and VEX extractor read exactly what
//! they would read after a real `sbt update`.
//!
//! Every child run gets [`isolated_env`]: `HOME`, the Coursier cache
//! (`COURSIER_CACHE`, `XDG_CACHE_HOME`, `LOCALAPPDATA`), the Maven local
//! repository and the JVM option variables (`SBT_OPTS`, `JAVA_OPTS`) all
//! point into the test's temp dir, so the developer's real caches are never
//! crawled and never patched.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Where a test's isolated caches live, below its temp dir.
pub struct SbtHome {
    pub root: PathBuf,
}

impl SbtHome {
    pub fn new(tmp: &Path) -> Self {
        let root = tmp.join("sbt-home");
        std::fs::create_dir_all(&root).expect("create sbt home");
        Self { root }
    }

    /// `$HOME`.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// `$COURSIER_CACHE` (the cache directory itself: `<it>/https/<host>/…`).
    pub fn coursier_cache(&self) -> PathBuf {
        self.root.join("coursier")
    }

    /// The Ivy cache sbt <= 1.2 uses (`-Dsbt.ivy.home=<ivy home>`).
    pub fn ivy_home(&self) -> PathBuf {
        self.root.join("ivy2")
    }

    /// `$MAVEN_REPO_LOCAL`.
    pub fn m2(&self) -> PathBuf {
        self.root.join("m2")
    }

    /// The child env pinning every cache location into this home.
    pub fn isolated_env(&self) -> Vec<(String, String)> {
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        vec![
            ("HOME".into(), s(self.home())),
            ("USERPROFILE".into(), s(self.home())),
            ("COURSIER_CACHE".into(), s(self.coursier_cache())),
            ("XDG_CACHE_HOME".into(), s(self.root.join("xdg-cache"))),
            ("LOCALAPPDATA".into(), s(self.root.join("localappdata"))),
            ("MAVEN_REPO_LOCAL".into(), s(self.m2())),
            ("SBT_OPTS".into(), String::new()),
            ("JAVA_OPTS".into(), String::new()),
        ]
    }
}

/// A Maven coordinate.
#[derive(Debug, Clone, Copy)]
pub struct Gav<'a> {
    pub group: &'a str,
    pub artifact: &'a str,
    pub version: &'a str,
}

impl Gav<'_> {
    pub fn group_path(&self) -> String {
        self.group.replace('.', "/")
    }

    pub fn purl(&self) -> String {
        format!(
            "pkg:maven/{}/{}@{}",
            self.group, self.artifact, self.version
        )
    }

    /// A minimal pom naming exactly this GAV.
    pub fn pom(&self) -> String {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
             <artifactId>{}</artifactId><version>{}</version></project>\n",
            self.group, self.artifact, self.version
        )
    }
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, bytes).expect("write");
}

/// Write `gav`'s pom and `jar` into the Coursier cache under
/// `https/<host>/<repo path>/…` with Coursier's checksum sidecars
/// (`.<file>__sha1`, lowercase hex, no newline); the version directory.
pub fn write_coursier_artifact(cache: &Path, host_repo: &str, gav: Gav<'_>, jar: &[u8]) -> PathBuf {
    let dir = cache
        .join("https")
        .join(host_repo)
        .join(gav.group_path())
        .join(gav.artifact)
        .join(gav.version);
    let stem = format!("{}-{}", gav.artifact, gav.version);
    for (name, bytes) in [
        (format!("{stem}.pom"), gav.pom().into_bytes()),
        (format!("{stem}.jar"), jar.to_vec()),
    ] {
        write(&dir.join(&name), &bytes);
        let sha1 = {
            use sha1::{Digest as _, Sha1};
            hex::encode(Sha1::digest(&bytes))
        };
        write(&dir.join(format!(".{name}__sha1")), sha1.as_bytes());
    }
    dir
}

/// Write `gav` into an Ivy cache (`<ivy home>/cache/<org>/<module>/…`):
/// `ivy-<rev>.xml`, its `.original` pom and `jars/<module>-<rev>.jar`; the
/// artifact directory.
pub fn write_ivy_artifact(ivy_home: &Path, gav: Gav<'_>, jar: &[u8]) -> PathBuf {
    let module = ivy_home.join("cache").join(gav.group).join(gav.artifact);
    let ivy = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ivy-module version=\"2.0\">\
         <info organisation=\"{}\" module=\"{}\" revision=\"{}\"/></ivy-module>\n",
        gav.group, gav.artifact, gav.version
    );
    write(
        &module.join(format!("ivy-{}.xml", gav.version)),
        ivy.as_bytes(),
    );
    write(
        &module.join(format!("ivy-{}.xml.original", gav.version)),
        gav.pom().as_bytes(),
    );
    let jars = module.join("jars");
    write(
        &jars.join(format!("{}-{}.jar", gav.artifact, gav.version)),
        jar,
    );
    jars
}

/// A minimal sbt build at `root`: `project/build.properties` naming
/// `sbt_version` and a `build.sbt` with `build_sbt`.
pub fn write_sbt_build(root: &Path, sbt_version: &str, build_sbt: &str) {
    write(
        &root.join("project/build.properties"),
        format!("sbt.version={sbt_version}\n").as_bytes(),
    );
    write(&root.join("build.sbt"), build_sbt.as_bytes());
}

/// The committed evidence fixture of `version` / `scenario`
/// (`crates/socket-patch-core/tests/fixtures/sbt/evidence/`).
pub fn evidence_fixture(version: &str, scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/sbt/evidence")
        .join(version)
        .join(scenario)
}

/// Copy an evidence fixture's tree into `root` (the build and its
/// `target/` records), so a test runs over real sbt output.
pub fn copy_evidence(version: &str, scenario: &str, root: &Path) {
    fn copy(from: &Path, to: &Path) {
        for entry in std::fs::read_dir(from).expect("read fixture dir") {
            let entry = entry.expect("entry");
            let (src, dst) = (entry.path(), to.join(entry.file_name()));
            if entry.file_type().expect("type").is_dir() {
                copy(&src, &dst);
            } else {
                write(&dst, &std::fs::read(&src).expect("read fixture"));
            }
        }
    }
    copy(&evidence_fixture(version, scenario), root);
}

/// What `sbt update` records once a pin is wired: every `update` record
/// under `root` that resolved `gav` from the committed evidence's Coursier
/// cache (`file:///root/.cache/coursier/v1/https/repo1.maven.org/maven2/…`)
/// now resolves the suffixed `sv` with its jar at `jar` (absolute), and
/// every file under a `target/` is dated `at` (after the generated file, so
/// the evidence postdates the wiring). Returns how many records changed.
pub fn record_pinned_resolution(
    root: &Path,
    pins: &[(Gav<'_>, String, PathBuf)],
    at: std::time::SystemTime,
) -> usize {
    fn walk(dir: &Path, in_target: bool, out: &mut Vec<(PathBuf, bool)>) {
        for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            let in_target = in_target || entry.file_name() == "target";
            if entry.file_type().expect("type").is_dir() {
                walk(&path, in_target, out);
            } else {
                out.push((path, in_target));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, false, &mut files);
    let mut changed = 0;
    for (path, in_target) in files {
        if !in_target {
            continue;
        }
        if path.file_name().is_some_and(|n| n == "output") {
            let text = std::fs::read_to_string(&path).expect("read record");
            let mut wired = text.clone();
            for (gav, sv, jar) in pins {
                let (g, a, v) = (gav.group, gav.artifact, gav.version);
                let cached = format!(
                    "file:///root/.cache/coursier/v1/https/repo1.maven.org/maven2/{}/{a}/{v}/{a}-{v}.jar",
                    gav.group_path()
                );
                wired = wired
                    .replace(&cached, &format!("file://{}", jar.display()))
                    .replace(
                        &format!("\"organization\":\"{g}\",\"name\":\"{a}\",\"revision\":\"{v}\""),
                        &format!("\"organization\":\"{g}\",\"name\":\"{a}\",\"revision\":\"{sv}\""),
                    );
            }
            if wired != text {
                write(&path, wired.as_bytes());
                changed += 1;
            }
        }
        let f = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open record");
        f.set_modified(at).expect("date record");
    }
    changed
}
