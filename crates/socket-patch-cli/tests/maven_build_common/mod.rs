//! Real-Maven plumbing shared by the host build capstones
//! (`e2e_redirect_maven_build` — hosted, `e2e_vendor_maven_build` —
//! vendored).
//!
//! Toolchain selection (the version-matrix lever, mirroring the bun
//! capstones' `SOCKET_PATCH_BUN_E2E_*` pair):
//!
//! * `SOCKET_PATCH_MAVEN_E2E_MVN` — the `mvn` launcher to drive (an
//!   unpacked `apache-maven-<v>/bin/mvn`); unset/empty = `mvn` on `PATH`.
//! * `SOCKET_PATCH_MAVEN_E2E_VERSION` — when set and non-empty, the
//!   launcher's `mvn -v` banner MUST report exactly this version (a leg
//!   can never go green on the wrong Maven).
//! * `SOCKET_PATCH_MAVEN_E2E_REQUIRED` — when set and non-empty, a missing
//!   toolchain or an unreachable Maven Central (fixture warm-up) is a hard
//!   failure instead of a printed SKIP.
//!
//! Every Maven run is hermetic: a per-test local repository
//! (`-Dmaven.repo.local`), a per-test user `settings.xml` (`-s`, so the
//! developer's `~/.m2/settings.xml` mirrors/proxies never apply), batch
//! mode, `MAVEN_ARGS` / `MAVEN_OPTS` / `MAVEN_CONFIG` scrubbed, and the CI
//! markers Maven 4 sniffs ([`CI_DETECTOR_ENV`]) removed, so a leg logs
//! exactly what a developer's terminal run logs. The
//! dependency plugin is pinned so every Maven line resolves with the same
//! plugin (the default bound version differs per Maven release).

#![allow(dead_code)]

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const MVN_ENV: &str = "SOCKET_PATCH_MAVEN_E2E_MVN";
pub const VERSION_ENV: &str = "SOCKET_PATCH_MAVEN_E2E_VERSION";
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_MAVEN_E2E_REQUIRED";

/// What Maven 4's `CIDetector`s key on (4.0.0-rc-6 `cisupport`: generic
/// `CI`, GitHub `GITHUB_ACTIONS`, CircleCI, Jenkins `WORKSPACE`, TeamCity,
/// Travis). When one is set, Maven 4 swaps in the `QuietMavenTransferListener`
/// even under `-B` — no "Downloading from …" lines and, crucially, no
/// "Checksum validation failed" warning for a rejected `checksumPolicy=fail`
/// download, which is the evidence the vendored TAMPER probe asserts. On a
/// GitHub runner every Maven 4 leg would otherwise log differently from the
/// same run on a laptop. Maven 3 reads none of these, so scrubbing them is a
/// no-op there. (`--force-interactive` also disables the detection, but it
/// flips the run interactive and Maven 3 rejects the flag.)
pub const CI_DETECTOR_ENV: &[&str] = &[
    "CI",
    "GITHUB_ACTIONS",
    "CIRCLECI",
    "WORKSPACE",
    "TEAMCITY_VERSION",
    "TRAVIS",
];

/// `mvn` with the ambient Maven configuration and CI markers scrubbed.
fn mvn_command(program: &OsString) -> Command {
    let mut cmd = Command::new(program);
    for key in [
        "MAVEN_ARGS",
        "MAVEN_OPTS",
        "MAVEN_CONFIG",
        "M2_HOME",
        "MAVEN_REPO_LOCAL",
    ]
    .into_iter()
    .chain(CI_DETECTOR_ENV.iter().copied())
    {
        cmd.env_remove(key);
    }
    cmd
}

/// Pinned so 3.6 → 4.x all run the same goal implementation (3.6.1 still
/// supports Maven 3.2.5+, so the oldest line in the matrix can load it).
pub const DEPENDENCY_PLUGIN: &str = "org.apache.maven.plugins:maven-dependency-plugin:3.6.1";

/// The real Maven Central artifact both capstones patch: it has ONE
/// transitive dependency (commons-lang3) and a parent pom, so a served /
/// vendored pom that dropped either would break the consumer's resolve.
pub const GROUP: &str = "org.apache.commons";
pub const ARTIFACT: &str = "commons-text";
pub const VERSION: &str = "1.10.0";
pub const GROUP_PATH: &str = "org/apache/commons";
pub const TRANSITIVE_JAR: &str = "commons-lang3-3.12.0.jar";
/// The jar member the patch rewrites (a text file, so the marker is
/// greppable after extraction).
pub const MEMBER: &str = "META-INF/NOTICE.txt";
pub const MARKER: &str = "SOCKET-PATCH-MAVEN-E2E-MARKER";

pub fn purl() -> String {
    format!("pkg:maven/{GROUP}/{ARTIFACT}@{VERSION}")
}

fn flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// CI legs set `SOCKET_PATCH_MAVEN_E2E_REQUIRED`: never skip there.
pub fn required() -> bool {
    flag(REQUIRED_ENV)
}

/// Skip (println) locally; fail when the leg is required.
pub fn skip(suite: &str, why: &str) {
    assert!(
        !required(),
        "{suite}: {REQUIRED_ENV} is set but the Maven capstone cannot run: {why}"
    );
    println!("SKIP {suite}: {why}");
}

/// The selected Maven launcher + its reported version.
pub struct Mvn {
    program: OsString,
    pub version: String,
}

impl Mvn {
    /// Probe the launcher (`mvn -v`). `None` = skipped (message printed).
    pub fn detect(suite: &str) -> Option<Mvn> {
        let program: OsString = std::env::var_os(MVN_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| if cfg!(windows) { "mvn.cmd" } else { "mvn" }.into());
        let out = match mvn_command(&program).args(["-v", "-B"]).output() {
            Ok(out) => out,
            Err(e) => {
                skip(
                    suite,
                    &format!("`{}` did not run: {e}", program.to_string_lossy()),
                );
                return None;
            }
        };
        let banner = String::from_utf8_lossy(&out.stdout).into_owned();
        let Some(version) = banner.lines().find_map(|l| {
            // `Apache Maven 3.9.16 (2bdd…)`, possibly wrapped in ANSI bold.
            let l = l.replace("\u{1b}[1m", "").replace("\u{1b}[m", "");
            l.trim()
                .strip_prefix("Apache Maven ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_string)
        }) else {
            skip(
                suite,
                &format!(
                    "`{} -v` printed no `Apache Maven <v>` banner (no JDK?):\n{}{}",
                    program.to_string_lossy(),
                    banner,
                    String::from_utf8_lossy(&out.stderr)
                ),
            );
            return None;
        };
        if let Some(pin) = std::env::var(VERSION_ENV).ok().filter(|v| !v.is_empty()) {
            assert_eq!(
                version,
                pin,
                "{VERSION_ENV} pins Maven {pin} but `{}` is Maven {version}",
                program.to_string_lossy()
            );
        }
        println!(
            "{suite}: driving Maven {version} ({})",
            program.to_string_lossy()
        );
        Some(Mvn { program, version })
    }

    fn numeric(&self) -> Vec<u32> {
        self.version
            .split(['.', '-'])
            .take(3)
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    }

    pub fn major(&self) -> u32 {
        self.numeric()[0]
    }

    /// Maven ≥ 3.9 (resolver ≥ 1.9) enforces the trusted-checksums summary
    /// file the hosted rewriter commits under `.mvn/checksums/`; older
    /// lines ignore the `aether.*` properties and only the transport
    /// `checksumPolicy=fail` sidecar check protects the download.
    pub fn enforces_trusted_checksums(&self) -> bool {
        let v = self.numeric();
        v[0] > 3 || (v[0] == 3 && v[1] >= 9)
    }

    /// `mvn -B <args>` in `cwd` against the local repository `m2`, with the
    /// user settings file `settings`.
    pub fn run(&self, cwd: &Path, m2: &Path, settings: &Path, args: &[&str]) -> Output {
        mvn_command(&self.program)
            .current_dir(cwd)
            .arg("-B")
            .arg("-s")
            .arg(settings)
            .arg(format!("-Dmaven.repo.local={}", m2.display()))
            .arg("-Dstyle.color=never")
            .arg("-Dmaven.test.skip=true")
            .args(args)
            .output()
            .expect("spawn mvn")
    }

    /// Resolve the project's dependencies into `<cwd>/<out_rel>` (the
    /// consumption proof: what Maven fetched is what the build links).
    pub fn copy_dependencies(
        &self,
        cwd: &Path,
        m2: &Path,
        settings: &Path,
        out_rel: &str,
    ) -> Output {
        let _ = std::fs::remove_dir_all(cwd.join(out_rel));
        self.run(
            cwd,
            m2,
            settings,
            &[
                &format!("{DEPENDENCY_PLUGIN}:copy-dependencies"),
                &format!("-DoutputDirectory={out_rel}"),
            ],
        )
    }
}

/// A user `settings.xml` with the given `(mirrorOf, url)` mirrors (none =
/// an empty settings file that just shields the run from `~/.m2`).
pub fn write_settings(path: &Path, mirrors: &[(&str, &str)]) {
    let mut body =
        String::from("<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">\n  <mirrors>\n");
    for (i, (of, url)) in mirrors.iter().enumerate() {
        body.push_str(&format!(
            "    <mirror>\n      <id>e2e-mirror-{i}</id>\n      <mirrorOf>{of}</mirrorOf>\n      \
             <url>{url}</url>\n    </mirror>\n"
        ));
    }
    body.push_str("  </mirrors>\n</settings>\n");
    std::fs::write(path, body).unwrap();
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

/// The consumer project's `pom.xml` depending on the fixture artifact at
/// `version`.
pub fn consumer_pom(version: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
<modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
<artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <packaging>jar</packaging>\n  \
<dependencies>\n    <dependency>\n      <groupId>{GROUP}</groupId>\n      \
<artifactId>{ARTIFACT}</artifactId>\n      <version>{version}</version>\n    \
</dependency>\n  </dependencies>\n</project>\n"
    )
}

/// `<m2>/<g>/<a>/<v>/`.
pub fn repo_dir(m2: &Path, version: &str) -> PathBuf {
    m2.join(GROUP_PATH).join(ARTIFACT).join(version)
}

/// Warm a fresh local repository with the fixture (+ its transitive and
/// the plugin machinery) by resolving the pristine consumer pom. Returns
/// the cached pristine `(jar, pom)` bytes, or `None` when Maven Central is
/// unreachable (skip printed; a hard failure on required legs).
pub fn warm_fixture(
    suite: &str,
    mvn: &Mvn,
    proj: &Path,
    m2: &Path,
    settings: &Path,
) -> Option<(Vec<u8>, Vec<u8>)> {
    std::fs::create_dir_all(proj).unwrap();
    std::fs::write(proj.join("pom.xml"), consumer_pom(VERSION)).unwrap();
    let out = mvn.copy_dependencies(proj, m2, settings, "target/warm");
    if !ok(&out) {
        skip(
            suite,
            &format!(
                "fixture warm-up against Maven Central failed:\n{}",
                dump(&out)
            ),
        );
        return None;
    }
    let warm = proj.join("target/warm");
    assert!(
        warm.join(format!("{ARTIFACT}-{VERSION}.jar")).is_file()
            && warm.join(TRANSITIVE_JAR).is_file(),
        "warm-up must copy the fixture and its transitive: {:?}",
        std::fs::read_dir(&warm).map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
    );
    std::fs::remove_dir_all(proj.join("target")).unwrap();
    let dir = repo_dir(m2, VERSION);
    let jar = std::fs::read(dir.join(format!("{ARTIFACT}-{VERSION}.jar"))).unwrap();
    let pom = std::fs::read(dir.join(format!("{ARTIFACT}-{VERSION}.pom"))).unwrap();
    assert!(
        String::from_utf8_lossy(&pom).contains("commons-lang3"),
        "the upstream pom must declare the commons-lang3 transitive (fixture wrong)"
    );
    Some((jar, pom))
}

// ── jar (zip) surgery ───────────────────────────────────────────────────

/// One member's bytes from a jar.
pub fn jar_member(jar: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).ok()?;
    let mut entry = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// A copy of `jar` with `name` replaced by `bytes` (every other member
/// byte-identical, in the original order).
pub fn jar_with_member(jar: &[u8], name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).expect("jar is a zip");
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut out);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut replaced = false;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let entry_name = entry.name().to_string();
            if entry.is_dir() {
                writer.add_directory(entry_name, opts).unwrap();
                continue;
            }
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            if entry_name == name {
                content = bytes.to_vec();
                replaced = true;
            }
            writer.start_file(entry_name, opts).unwrap();
            writer.write_all(&content).unwrap();
        }
        assert!(replaced, "{name} is not a member of the jar");
        writer.finish().unwrap();
    }
    out.into_inner()
}

/// The pristine and patched bytes of [`MEMBER`] (the patched copy carries
/// [`MARKER`] + `tag`).
pub fn patched_member(pristine_jar: &[u8], tag: &str) -> (Vec<u8>, Vec<u8>) {
    let orig = jar_member(pristine_jar, MEMBER).expect("NOTICE.txt in the upstream jar");
    assert!(
        !String::from_utf8_lossy(&orig).contains(MARKER),
        "the pristine member must not carry the marker"
    );
    let mut patched = orig.clone();
    patched.extend_from_slice(format!("\n{MARKER} {tag}\n").as_bytes());
    (orig, patched)
}

pub fn assert_jar_patched(jar: &[u8], patched_member: &[u8], what: &str) {
    let got = jar_member(jar, MEMBER).unwrap_or_else(|| panic!("{what}: no {MEMBER}"));
    assert_eq!(
        got, patched_member,
        "{what}: {MEMBER} is not the patched bytes"
    );
}

// ── digests ─────────────────────────────────────────────────────────────

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(bytes))
}

// ── files ───────────────────────────────────────────────────────────────

pub fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// A "fresh checkout" of `proj` in `dst`: only the committable files —
/// `pom.xml`, `.mvn/` and `.socket/` (never `target/`).
pub fn fresh_checkout(proj: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    std::fs::copy(proj.join("pom.xml"), dst.join("pom.xml")).unwrap();
    for dir in [".mvn", ".socket"] {
        if proj.join(dir).is_dir() {
            copy_dir_recursive(&proj.join(dir), &dst.join(dir));
        }
    }
    assert!(!dst.join("target").exists());
}
