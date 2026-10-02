//! Agent mode over Gradle caches through the real CLI, hermetic: a
//! temp-dir `GRADLE_USER_HOME` (and `~/.m2`, read-only cache) fabricated in
//! Gradle's `files-2.1` layout, the JVM environment scrubbed
//! (`common/jvm_env.rs`), no network but the in-test patch service.
//!
//! Pins the agent-mode contract for Maven purls (#551, #264): every copy a
//! build consumes is patched (each hash dir of each Gradle cache, `~/.m2`
//! only when the build reads it), member-keyed records swap the whole jar
//! and roll back byte for byte, and each Gradle hazard refuses or degrades
//! under its own code.
//!
//! Designated #551 regression test: [`m2_only_gradle_project_refuses`].

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha1::Digest as _;

const GROUP: &str = "com.example";
const ARTIFACT: &str = "victim";
const VERSION: &str = "1.0";
const PURL: &str = "pkg:maven/com.example/victim@1.0";
const UUID: &str = "5a1e0c2d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const JAR: &str = "victim-1.0.jar";
const POM: &str = "victim-1.0.pom";
const NOTICE: &str = "META-INF/NOTICE.txt";
const GAV: &str = "com.example:victim:1.0";

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(bytes))
}

/// A stored jar of `members`, deterministic.
fn jar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default());
    for (name, bytes) in members {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// The pristine jar: its sha1 starts with `0`, so Gradle releases that
/// drop leading zeros name its hash dir differently (both spellings are
/// fabricated where a test needs two copies of the same bytes).
fn pristine_jar() -> Vec<u8> {
    for n in 0u32.. {
        let pad = format!("pad {n}\n");
        let bytes = jar(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
            (NOTICE, b"pristine\n"),
            ("pad.txt", pad.as_bytes()),
        ]);
        if sha1_hex(&bytes).starts_with('0') {
            return bytes;
        }
    }
    unreachable!()
}

/// The pristine jar with `NOTICE` patched: what the patch service builds
/// for the member-keyed record (every other member unchanged).
fn service_jar() -> Vec<u8> {
    let pristine = pristine_jar();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&pristine)).unwrap();
    let mut members = Vec::new();
    for i in 0..archive.len() {
        use std::io::Read as _;
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        let name = entry.name().to_string();
        let buf = if name == NOTICE {
            b"patched\n".to_vec()
        } else {
            buf
        };
        members.push((name, buf));
    }
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    jar(&refs)
}

/// The whole-file patched jar of the leaf record.
fn patched_jar() -> Vec<u8> {
    jar(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
        (NOTICE, b"patched by socket\n"),
    ])
}

const PRISTINE_POM: &[u8] = b"<project><groupId>com.example</groupId><artifactId>victim</artifactId><version>1.0</version></project>\n";
const PATCHED_POM: &[u8] = b"<project><groupId>com.example</groupId><artifactId>victim</artifactId><version>1.0</version><!-- patched --></project>\n";

/// One test's world: a Gradle project, a Gradle user home, an `~/.m2`.
struct Fx {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    proj: PathBuf,
    /// The Gradle user home (named `.gradle` so `--global-prefix` takes it).
    home: PathBuf,
    m2: PathBuf,
    ro: PathBuf,
    use_ro: bool,
}

/// A Gradle project whose build script's `repositories` block is `repos`.
fn fx(repos: &str) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(proj.join("settings.gradle"), "rootProject.name = 'app'\n").unwrap();
    std::fs::write(
        proj.join("build.gradle"),
        format!(
            "plugins {{ id 'java' }}\nrepositories {{\n{repos}}}\ndependencies {{\n    \
             implementation '{GAV}'\n}}\n"
        ),
    )
    .unwrap();
    let home = root.join(".gradle");
    std::fs::create_dir_all(&home).unwrap();
    let m2 = root.join("m2");
    std::fs::create_dir_all(&m2).unwrap();
    Fx {
        _tmp: tmp,
        proj,
        home,
        m2,
        ro: root.join("ro"),
        use_ro: false,
        root,
    }
}

impl Fx {
    /// Lay `files` out in the user home's `files-2.1`; returns the version dir.
    fn gradle(&self, files: &[(&str, &[u8])]) -> PathBuf {
        prebuilt_common::fabricate_files21(&self.home, GAV, files)
    }

    /// The same, with the hash dirs named without leading zeros.
    fn gradle_unpadded(&self, files: &[(&str, &[u8])]) -> PathBuf {
        prebuilt_common::fabricate_files21_unpadded(&self.home, GAV, files)
    }

    /// Lay `files` out in the read-only cache (`GRADLE_RO_DEP_CACHE`).
    fn read_only(&mut self, files: &[(&str, &[u8])]) -> PathBuf {
        self.use_ro = true;
        let dir = self
            .ro
            .join(prebuilt_common::RO_FILES21)
            .join(GROUP)
            .join(ARTIFACT)
            .join(VERSION);
        for (leaf, bytes) in files {
            let hash = dir.join(sha1_hex(bytes));
            std::fs::create_dir_all(&hash).unwrap();
            std::fs::write(hash.join(leaf), bytes).unwrap();
        }
        dir
    }

    /// Lay `files` out in `~/.m2`; returns the version dir.
    fn m2(&self, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = self.m2.join("com/example/victim/1.0");
        std::fs::create_dir_all(&dir).unwrap();
        for (leaf, bytes) in files {
            std::fs::write(dir.join(leaf), bytes).unwrap();
        }
        dir
    }

    /// Write the manifest: one record per `(purl, files)`, each file
    /// `(key, before, after)`, with every blob committed.
    fn manifest(&self, records: &[(&str, &[(&str, &[u8], &[u8])])]) {
        let mut patches = serde_json::Map::new();
        for (purl, files) in records {
            let mut entries = serde_json::Map::new();
            for (key, before, after) in *files {
                // Both sides committed: apply reads the afterHash blob,
                // an offline rollback the beforeHash one.
                for bytes in [before, after] {
                    std::fs::write(
                        self.proj.join(".socket/blobs").join(git_sha256(bytes)),
                        bytes,
                    )
                    .unwrap();
                }
                entries.insert(
                    key.to_string(),
                    serde_json::json!({
                        "beforeHash": git_sha256(before),
                        "afterHash": git_sha256(after),
                    }),
                );
            }
            patches.insert(
                purl.to_string(),
                serde_json::json!({
                    "uuid": UUID,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": entries,
                    "vulnerabilities": { "GHSA-gr4d-1e55-0001": {
                        "cves": ["CVE-2026-0551"], "summary": "s",
                        "severity": "high", "description": "d"
                    } },
                    "description": "gradle agent fixture",
                    "license": "MIT",
                    "tier": "free",
                }),
            );
        }
        std::fs::write(
            self.proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
        )
        .unwrap();
    }

    /// The jar + pom leaf record (whole-file jar and pom patches).
    fn leaf_manifest(&self) {
        let pristine = pristine_jar();
        let patched = patched_jar();
        self.manifest(&[(
            PURL,
            &[
                (&format!("package/{JAR}"), &pristine, &patched),
                (&format!("package/{POM}"), PRISTINE_POM, PATCHED_POM),
            ],
        )]);
    }

    /// The member-keyed record (#264).
    fn member_manifest(&self) {
        self.manifest(&[(PURL, &[(NOTICE, b"pristine\n", b"patched\n")])]);
    }

    /// `socket-patch <args> --json --cwd <proj>` under the fixture's caches.
    fn run(&self, args: &[&str]) -> Out {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Out {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("SOCKET_") {
                cmd.env_remove(&k);
            }
        }
        prebuilt_common::jvm_env::isolate_cli(&mut cmd);
        cmd.args(args)
            .args(["--json", "--cwd", self.proj.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("GRADLE_USER_HOME", &self.home)
            .env("MAVEN_REPO_LOCAL", &self.m2)
            .env_remove("M2_HOME");
        if self.use_ro {
            cmd.env("GRADLE_RO_DEP_CACHE", &self.ro);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let json = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{args:?}: stdout is not one JSON document ({e})\n{stdout}\n{stderr}")
        });
        Out {
            code: out.status.code(),
            json,
            stderr,
        }
    }

    /// Every file under the caches and the project (`.socket/manifest.json`
    /// and blobs, and the `vex` output, excluded) by path relative to the
    /// fixture root, with its sha1.
    fn snapshot(&self) -> BTreeMap<String, String> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel.ends_with(".socket/manifest.json")
                    || rel.ends_with(".socket/blobs")
                    || rel == "vex.json"
                {
                    continue;
                }
                if path.is_dir() {
                    walk(base, &path, out);
                } else {
                    out.insert(rel, sha1_hex(&std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }

    /// `vex -O <file>`: the envelope and the statement count (0 when the
    /// command wrote no document).
    fn vex(&self, extra: &[&str]) -> (Out, usize) {
        let doc = self.root.join("vex.json");
        let _ = std::fs::remove_file(&doc);
        let mut args = vec![
            "vex",
            "-O",
            doc.to_str().unwrap(),
            "--product",
            "pkg:maven/com.example/app@1.0",
        ];
        args.extend_from_slice(extra);
        let out = self.run(&args);
        let statements = std::fs::read(&doc)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|d| d["statements"].as_array().map(Vec::len))
            .unwrap_or(0);
        (out, statements)
    }
}

struct Out {
    code: Option<i32>,
    json: serde_json::Value,
    stderr: String,
}

impl Out {
    fn warning_codes(&self) -> Vec<String> {
        let mut codes: Vec<String> = self.json["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|w| w["code"].as_str().map(str::to_string))
            .collect();
        codes.extend(
            self.json["vex"]["warnings"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|w| w["code"].as_str().map(str::to_string)),
        );
        codes
    }

    fn ok(&self) -> &Self {
        assert_eq!(self.code, Some(0), "{}\n{}", self.json, self.stderr);
        self
    }

    fn failed(&self) -> &Self {
        assert_ne!(self.code, Some(0), "{}\n{}", self.json, self.stderr);
        self
    }

    fn has(&self, code: &str) -> &Self {
        assert!(
            self.warning_codes().iter().any(|c| c == code),
            "missing warning {code}: {}\n{}",
            self.json,
            self.stderr
        );
        self
    }
}

/// The file `leaf` in every hash dir of a version dir.
fn hash_copies(version_dir: &Path, leaf: &str) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(version_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().join(leaf).is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path().join(leaf)).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn pristine_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![(JAR, pristine_jar()), (POM, PRISTINE_POM.to_vec())]
}

fn as_refs<'a>(files: &'a [(&'static str, Vec<u8>)]) -> Vec<(&'static str, &'a [u8])> {
    files.iter().map(|(l, b)| (*l, b.as_slice())).collect()
}

const CENTRAL: &str = "    mavenCentral()\n";

// ── fan-out ─────────────────────────────────────────────────────────────

/// Every hash dir holding the jar is patched — here the same pristine jar
/// under its padded and its zero-dropped sha1 — and the pom in its own
/// hash dir; rollback puts every file back to the bytes its hash dir
/// names.
#[test]
fn every_hash_copy_is_patched_and_rollback_restores_hash_eq() {
    let f = fx(CENTRAL);
    let files = pristine_files();
    let version = f.gradle(&as_refs(&files));
    f.gradle_unpadded(&[(JAR, &pristine_jar())]);
    f.leaf_manifest();

    let out = f.run(&["apply", "--offline"]);
    out.ok();
    let jars = hash_copies(&version, JAR);
    assert_eq!(jars.len(), 2, "{jars:?}");
    for (_, bytes) in &jars {
        assert_eq!(bytes, &patched_jar());
    }
    assert_eq!(hash_copies(&version, POM)[0].1, PATCHED_POM);
    assert!(out.json["sidecars"]
        .to_string()
        .contains("gradle_refresh_reverts"));

    f.run(&["rollback", "--offline"]).ok();
    for leaf in [JAR, POM] {
        for (dir, bytes) in hash_copies(&version, leaf) {
            assert!(
                socket_patch_core::crawlers::gradle_cache::pristine(&dir, &bytes),
                "{leaf} in {dir} does not hash to its dir after rollback"
            );
        }
    }
}

/// #551 regression: a Gradle-only build that never declares mavenLocal()
/// does not read `~/.m2`. A GAV installed only there is not patched and the
/// run fails (`gradle_build_ignores_m2`); `vex` attests nothing.
#[test]
fn m2_only_gradle_project_refuses() {
    let f = fx(CENTRAL);
    let m2 = f.m2(&as_refs(&pristine_files()));
    f.leaf_manifest();
    let before = f.snapshot();

    f.run(&["apply", "--offline"])
        .failed()
        .has("gradle_build_ignores_m2");
    assert_eq!(f.snapshot(), before, "nothing may be written");
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), pristine_jar());

    let (out, statements) = f.vex(&[]);
    assert_eq!(statements, 0, "{}", out.json);
}

/// The #551 tree: the GAV in both `~/.m2` and the Gradle cache of a build
/// without mavenLocal(): only the Gradle copy is patched.
#[test]
fn tree_551_patches_only_gradle() {
    let f = fx(CENTRAL);
    let files = pristine_files();
    let m2 = f.m2(&as_refs(&files));
    let version = f.gradle(&as_refs(&files));
    f.leaf_manifest();

    f.run(&["apply", "--offline"]).ok();
    assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar());
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), pristine_jar());
    let (out, statements) = f.vex(&[]);
    out.ok();
    assert!(statements > 0);
}

/// mavenLocal() declared — before or after mavenCentral() — patches the
/// `~/.m2` copy too, and its `.sha1` (which described the pristine jar)
/// follows the patched bytes; rollback restores it exactly.
#[test]
fn maven_local_declared_patches_m2_and_gradle_in_both_orders() {
    for repos in [
        "    mavenLocal()\n    mavenCentral()\n",
        "    mavenCentral()\n    mavenLocal()\n",
    ] {
        let f = fx(repos);
        let files = pristine_files();
        let m2 = f.m2(&as_refs(&files));
        let sha1_text = format!("{}  {JAR}\n", sha1_hex(&pristine_jar()));
        std::fs::write(m2.join(format!("{JAR}.sha1")), &sha1_text).unwrap();
        let version = f.gradle(&as_refs(&files));
        f.leaf_manifest();
        let before = f.snapshot();

        f.run(&["apply", "--offline"]).ok();
        assert_eq!(
            std::fs::read(m2.join(JAR)).unwrap(),
            patched_jar(),
            "{repos}"
        );
        assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar(), "{repos}");
        assert_eq!(
            std::fs::read_to_string(m2.join(format!("{JAR}.sha1"))).unwrap(),
            format!("{}  {JAR}\n", sha1_hex(&patched_jar()))
        );
        let (out, statements) = f.vex(&[]);
        out.ok();
        assert!(statements > 0);

        f.run(&["rollback", "--offline"]).ok();
        assert_eq!(f.snapshot(), before, "{repos}: rollback must be byte-exact");
    }
}

/// mavenLocal() declared only in a user-home init script still makes the
/// build read `~/.m2`: the m2 copy is patched.
#[test]
fn maven_local_in_init_d_patches_m2() {
    let f = fx(CENTRAL);
    std::fs::create_dir_all(f.home.join("init.d")).unwrap();
    std::fs::write(
        f.home.join("init.d/local.gradle"),
        "allprojects {\n    repositories {\n        mavenLocal()\n    }\n}\n",
    )
    .unwrap();
    let m2 = f.m2(&as_refs(&pristine_files()));
    f.leaf_manifest();
    f.run(&["apply", "--offline"]).ok();
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), patched_jar());
}

/// Dependency verification (key trust only — no component entry for the
/// GAV) still refuses agent mode for the build, with nothing written.
#[test]
fn verification_metadata_refuses_and_writes_nothing() {
    let f = fx("    mavenLocal()\n    mavenCentral()\n");
    let files = pristine_files();
    f.m2(&as_refs(&files));
    f.gradle(&as_refs(&files));
    std::fs::create_dir_all(f.proj.join("gradle")).unwrap();
    std::fs::write(
        f.proj.join("gradle/verification-metadata.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>true</verify-signatures>
      <trusted-keys>
         <trusted-key id="DD0CDDD2B4838EC95727B94B4C77A9C911D46A19" group="com.example"/>
      </trusted-keys>
   </configuration>
   <components/>
</verification-metadata>
"#,
    )
    .unwrap();
    f.leaf_manifest();
    let before = f.snapshot();
    f.run(&["apply", "--offline"])
        .failed()
        .has("gradle_verification_metadata_present");
    assert_eq!(f.snapshot(), before);
}

/// A copy in the read-only cache is never written and fails the run
/// (`gradle_ro_cache_shadows`); the writable copy is still patched.
#[test]
fn read_only_copy_shadows() {
    let mut f = fx(CENTRAL);
    let files = pristine_files();
    let rw = f.gradle(&as_refs(&files));
    let ro = f.read_only(&as_refs(&files));
    f.leaf_manifest();
    f.run(&["apply", "--offline"])
        .failed()
        .has("gradle_ro_cache_shadows");
    assert_eq!(hash_copies(&rw, JAR)[0].1, patched_jar());
    assert_eq!(hash_copies(&ro, JAR)[0].1, pristine_jar());
    let (_, statements) = f.vex(&[]);
    assert_eq!(
        statements, 0,
        "a pristine read-only copy withholds the statement"
    );
}

/// A copy Gradle derived from the pristine jar outside `files-2.1`
/// (`caches/transforms-*`) keeps serving the old bytes: the apply fails
/// with `gradle_transform_copy_stale` and VEX withholds, naming the copy.
#[test]
fn stale_transform_copy_fails_apply_and_vex_withholds() {
    let f = fx(CENTRAL);
    f.gradle(&as_refs(&pristine_files()));
    let stale = f
        .home
        .join("caches/transforms-4/0f1e2d3c/transformed")
        .join(JAR);
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, pristine_jar()).unwrap();
    f.leaf_manifest();

    f.run(&["apply", "--offline"])
        .failed()
        .has("gradle_transform_copy_stale");
    let (out, statements) = f.vex(&[]);
    assert_eq!(statements, 0);
    out.has("vex_gradle_unpatched_copy");
    assert!(
        out.json.to_string().contains("transforms-4"),
        "{}",
        out.json
    );

    // Cleared: the next apply is clean and VEX attests.
    std::fs::remove_dir_all(f.home.join("caches/transforms-4")).unwrap();
    f.run(&["apply", "--offline"]).ok();
    let (out, statements) = f.vex(&[]);
    out.ok();
    assert!(statements > 0);
}

/// A hash dir whose file is the pristine download of OTHER bytes than the
/// record expects is left alone (`gradle_copy_unexpected_bytes`) and fails
/// the run: the build may load it, unpatched. The other hash dir is still
/// patched.
#[test]
fn unexpected_pristine_bytes_are_left_alone() {
    let f = fx(CENTRAL);
    let version = f.gradle(&as_refs(&pristine_files()));
    let other = jar(&[(NOTICE, b"some other build\n")]);
    f.gradle(&[(JAR, &other)]);
    f.leaf_manifest();
    f.run(&["apply", "--offline"])
        .failed()
        .has("gradle_copy_unexpected_bytes");
    let jars = hash_copies(&version, JAR);
    assert!(jars.iter().any(|(_, b)| *b == other));
    assert!(jars.iter().any(|(_, b)| *b == patched_jar()));
}

/// The only hash dir holds the genuine download of other bytes: the copy is
/// installed and consumed, so the run fails with the code instead of
/// calling the patch `package_not_installed`.
#[test]
fn unexpected_bytes_in_the_only_copy_fail_the_run() {
    let f = fx(CENTRAL);
    let other = jar(&[(NOTICE, b"some other build\n")]);
    let version = f.gradle(&[(JAR, &other), (POM, PRISTINE_POM)]);
    f.leaf_manifest();
    let out = f.run(&["apply", "--offline"]);
    out.failed().has("gradle_copy_unexpected_bytes");
    assert!(
        !out.json.to_string().contains("package_not_installed"),
        "{}",
        out.json
    );
    assert_eq!(hash_copies(&version, JAR)[0].1, other);
}

/// A qualified manifest key (`?ext=jar`) turns on the release-variant gate
/// even for one variant: a hash dir holding the jar with bytes the variant
/// was not made for is still a consumed, unpatched copy — the run fails
/// (`gradle_copy_unexpected_bytes`), it is not `package_not_installed`.
#[test]
fn qualified_variant_mismatch_fails_the_run() {
    let f = fx(CENTRAL);
    let other = jar(&[(NOTICE, b"some other build\n")]);
    let version = f.gradle(&[(JAR, &other)]);
    let pristine = pristine_jar();
    let patched = patched_jar();
    f.manifest(&[(
        &format!("{PURL}?ext=jar"),
        &[(&format!("package/{JAR}"), &pristine, &patched)],
    )]);
    let out = f.run(&["apply", "--offline"]);
    out.failed().has("gradle_copy_unexpected_bytes");
    assert!(
        !out.json.to_string().contains("package_not_installed"),
        "{}",
        out.json
    );
    assert_eq!(hash_copies(&version, JAR)[0].1, other);
}

/// A Gradle version dir holding none of a record's files (here only the
/// pom of a jar patch) is not an install of it: that patch is
/// `package_not_installed`, the other one applies, and the run succeeds.
#[test]
fn gradle_copy_without_the_patched_file_is_not_installed() {
    let f = fx(CENTRAL);
    let version = f.gradle(&as_refs(&pristine_files()));
    let other_pom: &[u8] = b"<project><artifactId>other</artifactId></project>\n";
    prebuilt_common::fabricate_files21(
        &f.home,
        "com.example:other:1.0",
        &[("other-1.0.pom", other_pom)],
    );
    let pristine = pristine_jar();
    let patched = patched_jar();
    f.manifest(&[
        (PURL, &[(&format!("package/{JAR}"), &pristine, &patched)]),
        (
            "pkg:maven/com.example/other@1.0",
            &[("package/other-1.0.jar", b"other jar", b"patched other jar")],
        ),
    ]);
    let out = f.run(&["apply", "--offline"]);
    out.ok();
    assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar());
    assert!(
        out.json.to_string().contains("package_not_installed"),
        "{}",
        out.json
    );
    // VEX agrees: the pom-only dir is no copy of the patch.
    let (out, statements) = f.vex(&[]);
    assert!(statements > 0, "{}", out.json);
    assert!(
        !out.warning_codes()
            .iter()
            .any(|c| c == "vex_gradle_unpatched_copy"),
        "{}",
        out.json
    );
}

// ── derived copies ──────────────────────────────────────────────────────

/// Set `path`'s mtime `secs` seconds into the past.
fn age(path: &Path, secs: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs))
        .unwrap();
}

/// An instrumented build-logic copy (never byte-equal to its input) left
/// from BEFORE the apply withholds the statement; one Gradle made AFTER
/// the apply was made from the patched jar and does not — so clearing the
/// old one and rebuilding leads to a statement.
#[test]
fn instrumented_copy_made_after_the_apply_does_not_withhold() {
    let f = fx(CENTRAL);
    f.gradle(&as_refs(&pristine_files()));
    let old = f
        .home
        .join("caches/jars-9/0a1b2c3d4e5f60718293a4b5c6d7e8f9")
        .join(JAR);
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(&old, b"instrumented from the pristine jar").unwrap();
    age(&old, 3600);
    f.leaf_manifest();

    f.run(&["apply", "--offline"])
        .ok()
        .has("gradle_transform_copy_unverified");
    let (out, statements) = f.vex(&[]);
    assert_eq!(statements, 0, "{}", out.json);
    out.has("vex_gradle_unpatched_copy");

    // Cleared and rebuilt: Gradle instruments the patched jar anew.
    std::fs::remove_file(&old).unwrap();
    let new = f
        .home
        .join("caches/8.14.3/transforms/fedcba98765432100123456789abcdef/transformed")
        .join(format!("instrumented-{JAR}"));
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    std::fs::write(&new, b"instrumented from the patched jar").unwrap();
    let (out, statements) = f.vex(&[]);
    out.ok();
    assert!(statements > 0, "{}", out.json);
}

// ── rollback scope and checks ───────────────────────────────────────────

/// A Gradle-only build's rollback restores only what its apply wrote: the
/// `~/.m2` copy another (Maven) build patched stays patched.
#[test]
fn rollback_leaves_an_m2_copy_the_build_never_reads() {
    let f = fx(CENTRAL);
    let m2 = f.m2(&[(JAR, &patched_jar()), (POM, PATCHED_POM)]);
    let version = f.gradle(&as_refs(&pristine_files()));
    f.leaf_manifest();
    f.run(&["apply", "--offline"]).ok();
    assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar());
    f.run(&["rollback", "--offline"]).ok();
    assert_eq!(hash_copies(&version, JAR)[0].1, pristine_jar());
    assert_eq!(
        std::fs::read(m2.join(JAR)).unwrap(),
        patched_jar(),
        "another build's ~/.m2 copy must stay patched"
    );
}

/// A before-blob that does not hash to the Gradle hash dir it is restored
/// into fails the rollback (`gradle_rollback_hash_mismatch`).
#[test]
fn rollback_before_blob_not_matching_the_hash_dir_fails() {
    let f = fx(CENTRAL);
    let downloaded = pristine_jar();
    let before = jar(&[(NOTICE, b"what the record calls pristine\n")]);
    let patched = patched_jar();
    let dir = f
        .home
        .join(prebuilt_common::GRADLE_FILES21)
        .join(GROUP)
        .join(ARTIFACT)
        .join(VERSION)
        .join(sha1_hex(&downloaded));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(JAR), &patched).unwrap();
    f.manifest(&[(PURL, &[(&format!("package/{JAR}"), &before, &patched)])]);
    let out = f.run(&["rollback", "--offline"]);
    out.failed();
    assert!(
        out.json
            .to_string()
            .contains("gradle_rollback_hash_mismatch"),
        "{}",
        out.json
    );
}

// ── member-keyed records (#264) ─────────────────────────────────────────

/// Offline, a member-keyed record cannot get the service-built jar:
/// refused with nothing written anywhere.
#[test]
fn offline_member_record_writes_nothing() {
    let f = fx(CENTRAL);
    f.gradle(&[(JAR, &pristine_jar())]);
    f.member_manifest();
    let before = f.snapshot();
    f.run(&["apply", "--offline"])
        .failed()
        .has("jvm_agent_service_required");
    assert_eq!(f.snapshot(), before);
    assert!(!f.proj.join(".socket/jvm-originals").exists());
}

/// A service jar carrying a member the installed jar does not have is not
/// the installed jar plus the patch: refused, nothing written, no backup.
#[test]
fn tampered_service_jar_writes_nothing() {
    let f = fx("    mavenLocal()\n    mavenCentral()\n");
    f.m2(&as_refs(&pristine_files()));
    f.gradle(&as_refs(&pristine_files()));
    f.member_manifest();
    let before = f.snapshot();
    let mut tampered = zip::ZipArchive::new(std::io::Cursor::new(service_jar())).unwrap();
    let mut members = Vec::new();
    for i in 0..tampered.len() {
        use std::io::Read as _;
        let mut entry = tampered.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        members.push((entry.name().to_string(), buf));
    }
    members.push(("com/example/Backdoor.class".to_string(), b"evil".to_vec()));
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let (_rt, server) = service(&jar(&refs));
    f.run(&["apply", "--vendor-url", &server.uri()]).failed();
    assert_eq!(f.snapshot(), before);
    assert!(!f.proj.join(".socket/jvm-originals").exists());
}

/// A swap is one transaction across every consumed copy: when the write of
/// one copy fails, the copies already swapped are put back — `~/.m2` and
/// the Gradle cache alike — whichever copy is written first.
#[cfg(target_os = "macos")]
#[test]
fn failed_swap_restores_every_copy() {
    for locked_m2 in [false, true] {
        let f = fx("    mavenLocal()\n    mavenCentral()\n");
        let m2 = f.m2(&as_refs(&pristine_files()));
        let version = f.gradle(&as_refs(&pristine_files()));
        f.member_manifest();
        let before = f.snapshot();
        let (_rt, server) = service(&service_jar());
        // A user-immutable jar: the rename over it fails with EPERM.
        let locked = if locked_m2 {
            m2.join(JAR)
        } else {
            version.join(&hash_copies(&version, JAR)[0].0).join(JAR)
        };
        let flag = |f: &str| {
            assert!(Command::new("chflags")
                .args([f, locked.to_str().unwrap()])
                .status()
                .unwrap()
                .success())
        };
        flag("uchg");
        let out = f.run(&["apply", "--vendor-url", &server.uri()]);
        flag("nouchg");
        out.failed();
        let after: BTreeMap<String, String> = f
            .snapshot()
            .into_iter()
            .filter(|(k, _)| !k.contains(".socket/jvm-originals"))
            .collect();
        assert_eq!(after, before, "locked_m2={locked_m2}: every copy restored");
    }
}

/// Windows: a hash-dir jar held open without delete sharing (how a Gradle
/// daemon's `JarFile` holds it) refuses the write with
/// `gradle_jar_locked_by_daemon` — the rename fails with
/// `ERROR_ACCESS_DENIED`, not a sharing violation.
#[cfg(windows)]
#[test]
fn windows_held_jar_reports_daemon_lock() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let f = fx(CENTRAL);
    let version = f.gradle(&as_refs(&pristine_files()));
    f.leaf_manifest();
    let jar_path = version.join(&hash_copies(&version, JAR)[0].0).join(JAR);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1) // FILE_SHARE_READ only
        .open(&jar_path)
        .unwrap();
    let out = f.run(&["apply", "--offline"]);
    drop(held);
    out.failed().has("gradle_jar_locked_by_daemon");
    f.run(&["apply", "--offline"]).ok();
    assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar());
}

/// A patch service answering the vendoring route with `jar`.
fn service(jar: &[u8]) -> (tokio::runtime::Runtime, wiremock::MockServer) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = wiremock::MockServer::start().await;
        prebuilt_common::mount_download(&server, PURL, UUID, JAR, jar).await;
        server
    });
    (rt, server)
}

/// apply swaps the service jar into every copy (m2 and Gradle, mavenLocal
/// declared) and keeps the original under `.socket/jvm-originals/`;
/// `repair` (blob GC) leaves it; rollback restores every copy byte for
/// byte; VEX attests in between.
#[test]
fn member_record_apply_repair_rollback_is_byte_exact() {
    let f = fx("    mavenLocal()\n    mavenCentral()\n");
    let m2 = f.m2(&as_refs(&pristine_files()));
    let version = f.gradle(&as_refs(&pristine_files()));
    f.member_manifest();
    let before = f.snapshot();
    let (_rt, server) = service(&service_jar());

    f.run(&["apply", "--vendor-url", &server.uri()]).ok();
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), service_jar());
    assert_eq!(hash_copies(&version, JAR)[0].1, service_jar());
    let backup = f.proj.join(".socket/jvm-originals").join(format!(
        "{}.jar",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(pristine_jar()))
    ));
    assert_eq!(std::fs::read(&backup).unwrap(), pristine_jar());
    let (out, statements) = f.vex(&[]);
    out.ok();
    assert!(statements > 0);

    f.run(&["repair", "--offline"]).ok();
    assert!(backup.is_file(), "repair must keep the jar originals");

    f.run(&["rollback", "--offline"]).ok();
    let after: BTreeMap<String, String> = f
        .snapshot()
        .into_iter()
        .filter(|(k, _)| !k.contains(".socket/jvm-originals"))
        .collect();
    assert_eq!(
        after, before,
        "rollback must restore every copy byte for byte"
    );
}

// ── global prefix ───────────────────────────────────────────────────────

/// `--global-prefix` naming the Gradle user home (`.gradle`) or its
/// `caches/modules-2` reaches the `files-2.1` copies for apply, vex and
/// rollback alike.
#[test]
fn global_prefix_apply_vex_rollback() {
    for prefix in ["", "caches/modules-2"] {
        let f = fx(CENTRAL);
        let version = f.gradle(&as_refs(&pristine_files()));
        f.leaf_manifest();
        let p = if prefix.is_empty() {
            f.home.clone()
        } else {
            f.home.join(prefix)
        };
        let p = p.to_str().unwrap();
        f.run(&["apply", "--offline", "--global-prefix", p]).ok();
        assert_eq!(hash_copies(&version, JAR)[0].1, patched_jar(), "{prefix}");
        let (out, statements) = f.vex(&["--global-prefix", p]);
        out.ok();
        assert!(statements > 0, "{prefix}");
        f.run(&["rollback", "--offline", "--global-prefix", p]).ok();
        assert_eq!(hash_copies(&version, JAR)[0].1, pristine_jar(), "{prefix}");
    }
}

// ── remove ──────────────────────────────────────────────────────────────

/// `remove` (rollback + drop) restores every copy it patched: `~/.m2` and
/// each Gradle hash dir.
#[test]
fn gradle_agent_remove_restores_all_copies() {
    let f = fx("    mavenLocal()\n    mavenCentral()\n");
    let files = pristine_files();
    f.m2(&as_refs(&files));
    f.gradle(&as_refs(&files));
    f.gradle_unpadded(&[(JAR, &pristine_jar())]);
    f.leaf_manifest();
    let before = f.snapshot();
    f.run(&["apply", "--offline"]).ok();
    assert_ne!(f.snapshot(), before);
    f.run(&["remove", PURL, "--offline"]).ok();
    assert_eq!(f.snapshot(), before);
}

// ── get narrowing ───────────────────────────────────────────────────────

/// `get` keeps the release variant whose classifier jar sits in the Gradle
/// cache (`files-2.1` hash dirs are expanded) and drops the other.
#[test]
fn get_narrowing_picks_the_classifier_in_files21() {
    let f = fx(CENTRAL);
    let linux = jar(&[(NOTICE, b"linux\n")]);
    let osx = jar(&[(NOTICE, b"osx\n")]);
    f.gradle(&[("victim-1.0-linux.jar", &linux), (POM, PRISTINE_POM)]);
    let variants = [
        ("11111111-1111-4111-8111-111111111111", "linux", &linux),
        ("22222222-2222-4222-8222-222222222222", "osx", &osx),
    ];
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let listed: Vec<serde_json::Value> = variants
            .iter()
            .map(|(uuid, c, _)| {
                serde_json::json!({
                    "uuid": uuid, "purl": format!("{PURL}?classifier={c}&ext=jar"),
                    "publishedAt": "2024-01-01T00:00:00Z", "description": "x",
                    "license": "MIT", "tier": "free", "vulnerabilities": {}
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path_regex("^/v0/orgs/test-org/patches/by-package/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": listed, "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        for (uuid, c, before) in &variants {
            let after = [before.as_slice(), b"patched"].concat();
            use base64::Engine as _;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid, "purl": format!("{PURL}?classifier={c}&ext=jar"),
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "files": { format!("package/victim-1.0-{c}.jar"): {
                        "beforeHash": git_sha256(before),
                        "afterHash": git_sha256(&after),
                        "blobContent": base64::engine::general_purpose::STANDARD.encode(&after),
                    } },
                    "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
                })))
                .mount(&server)
                .await;
        }
        server
    });
    let out = f.run(&[
        "get",
        PURL,
        "--save-only",
        "--yes",
        "--api-url",
        &server.uri(),
        "--api-token",
        "fake-token-for-tests",
        "--org",
        "test-org",
    ]);
    out.ok();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.proj.join(".socket/manifest.json")).unwrap())
            .unwrap();
    let keys: Vec<&String> = manifest["patches"].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [&format!("{PURL}?classifier=linux&ext=jar")],
        "{}",
        out.json
    );
}

// ── vendored ────────────────────────────────────────────────────────────

/// A vendored Gradle entry's pristine `files-2.1` copy is a sibling the
/// vendored build never reads: `vex` attests from the committed tree and
/// does not flag it `vendored_tree_out_of_sync`.
#[test]
fn vendored_gradle_entry_is_not_out_of_sync() {
    let f = fx(CENTRAL);
    let files = pristine_files();
    f.m2(&as_refs(&files));
    f.gradle(&as_refs(&files));
    f.member_manifest();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    let home = f.home.to_string_lossy().into_owned();
    let m2 = f.m2.to_string_lossy().into_owned();
    let _server = prebuilt_common::prepare_command(
        &mut cmd,
        &f.proj,
        &["vendor"],
        &[("GRADLE_USER_HOME", &home), ("MAVEN_REPO_LOCAL", &m2)],
    );
    let out = cmd
        .args(["--json", "--cwd", f.proj.to_str().unwrap()])
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", &f.m2)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let (out, statements) = f.vex(&[]);
    out.ok();
    assert!(statements > 0, "{}", out.json);
    assert!(
        !out.warning_codes()
            .iter()
            .any(|c| c == "vendored_tree_out_of_sync"),
        "{}",
        out.json
    );
}

/// The shapes these tests rely on.
#[test]
fn fixture_self_check() {
    assert!(sha1_hex(&pristine_jar()).starts_with('0'));
    let services: HashMap<&str, Vec<u8>> = HashMap::from([("service", service_jar())]);
    assert_ne!(services["service"], pristine_jar());
}
