//! Agent mode against real Gradle: Gradle resolves the deterministic fake
//! Central (`jvm_fixture_repo`) into a per-test user home, `socket-patch`
//! patches the cache in place, and every assertion is on the bytes Gradle
//! then CONSUMES — the `printRuntimeClasspath` marker task's jar, never only
//! the CLI's report.
//!
//! Every test is `#[ignore]` and prefixed `gradle_agent_` (the CI filter
//! contract, `scripts/ci-e2e-bundle.py`); toolchain selection is
//! `gradle_build_common`'s `SOCKET_PATCH_GRADLE_E2E_*` knobs. The canary
//! test records how each Gradle major actually treats its cache
//! (hash-dir naming, `--offline` reuse, `--refresh-dependencies`, daemons,
//! classifier jars, build logic, the build cache, the read-only cache) in a
//! JSON probe report per cell.

#[path = "common/mod.rs"]
mod common;
use common::envelope::codes_in;
use common::git_sha256;

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "gradle_build_common/mod.rs"]
mod gradle_build_common;

#[path = "jvm_fixture_repo/mod.rs"]
mod jvm_fixture_repo;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Output;

use gradle_build_common::{
    assert_patched, dump, fixture_root, init_script, jar_member, mirror_init_script, ok, print_cp,
    print_cp_task, probe_report, Dsl, Gradle,
};
use jvm_fixture_repo::{
    notice, repo_path, victim_class, victim_marker, FakeCentral, GROUP, NOTICE, VICTIM,
    VICTIM_CLASS_MEMBER, VICTIM_VERSION,
};
use sha1::Digest as _;

const SUITE: &str = "e2e_gradle_agent_build";
const UUID: &str = "26400000-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const PRODUCT: &str = "pkg:maven/com.example/app@1.0";

fn purl() -> String {
    jvm_fixture_repo::victim_purl(VICTIM_VERSION)
}

fn jar_leaf() -> String {
    format!("{VICTIM}-{VICTIM_VERSION}.jar")
}

fn coordinate() -> String {
    format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}")
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(bytes))
}

/// The fake Central's file at `path`.
fn central_file(path: &str) -> Vec<u8> {
    jvm_fixture_repo::repository()
        .remove(path)
        .unwrap_or_else(|| panic!("the fixture serves no {path}"))
}

fn pristine_jar() -> Vec<u8> {
    central_file(&repo_path(VICTIM, VICTIM_VERSION, None, "jar"))
}

fn patched_notice() -> Vec<u8> {
    notice(&coordinate(), "patched").into_bytes()
}

/// `jar` with NOTICE and `Victim.class` patched, every other member kept:
/// both the leaf record's whole-file patch and the patch service's build of
/// the member-keyed record.
fn patch_jar(jar: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).unwrap();
    let mut members = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        let name = entry.name().to_string();
        let buf = if name == NOTICE {
            patched_notice()
        } else if name == VICTIM_CLASS_MEMBER {
            victim_class(VICTIM_VERSION, "patched")
        } else {
            buf
        };
        members.push((name, buf));
    }
    jvm_fixture_repo::jar(&members)
}

fn patched_jar() -> Vec<u8> {
    patch_jar(&pristine_jar())
}

/// One real-Gradle cell: a project depending on `victim:1.10.0`, its own
/// Gradle user home (`<root>/.gradle`), `~/.m2` and fake Central.
struct Cell {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    proj: PathBuf,
    home: PathBuf,
    m2: PathBuf,
    /// `GRADLE_RO_DEP_CACHE` for Gradle and the CLI, when set.
    ro: Option<PathBuf>,
    gradle: Gradle,
    central: FakeCentral,
    init: [String; 2],
}

/// A cell whose build script declares `repos` (one per line) and appends
/// `extra`. `None`: no Gradle (skipped).
fn cell(repos: &str, extra: &str) -> Option<Cell> {
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let home = root.join(".gradle");
    std::fs::create_dir_all(&home).unwrap();
    let gradle = Gradle::detect(SUITE, &home)?;
    let central = FakeCentral::start();
    let init = init_script(
        &root.join("init"),
        "mirror.gradle",
        &mirror_init_script(&central.uri(), None),
    );
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(proj.join("settings.gradle"), "rootProject.name = 'app'\n").unwrap();
    std::fs::write(
        proj.join("build.gradle"),
        format!(
            "plugins {{ id 'java' }}\nrepositories {{\n{repos}}}\n\
             dependencies {{ implementation '{}' }}\n{}{extra}",
            coordinate(),
            print_cp_task(Dsl::Groovy, "runtimeClasspath")
        ),
    )
    .unwrap();
    let m2 = root.join("m2");
    std::fs::create_dir_all(&m2).unwrap();
    Some(Cell {
        _tmp: tmp,
        root,
        proj,
        home,
        m2,
        ro: None,
        gradle,
        central,
        init,
    })
}

const CENTRAL: &str = "    mavenCentral()\n";
const LOCAL_FIRST: &str = "    mavenLocal()\n    mavenCentral()\n";

impl Cell {
    fn gradle_env(&self) -> Vec<(&'static str, &OsStr)> {
        self.ro
            .iter()
            .map(|ro| ("GRADLE_RO_DEP_CACHE", ro.as_os_str()))
            .collect()
    }

    /// `-Dmaven.repo.local=<m2>`: what Gradle's mavenLocal() reads (it does
    /// not honor `MAVEN_REPO_LOCAL`, which the CLI reads).
    fn m2_property(&self) -> String {
        format!("-Dmaven.repo.local={}", self.m2.display())
    }

    /// `gradle <extra> printRuntimeClasspath` (mirror init script first).
    fn build(&self, extra: &[&str]) -> Output {
        let m2 = self.m2_property();
        let mut args: Vec<&str> = vec![&self.init[0], &self.init[1], &m2];
        args.extend_from_slice(extra);
        args.push("printRuntimeClasspath");
        self.gradle
            .run_env(&self.proj, &self.home, &args, &self.gradle_env())
    }

    /// The victim jar the build consumes, and its NOTICE.
    fn consumed(&self, extra: &[&str], what: &str) -> (PathBuf, Vec<u8>) {
        let out = self.build(extra);
        let cp = print_cp(&out, what);
        let jar = cp
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == jar_leaf().as_str()))
            .unwrap_or_else(|| panic!("{what}: no {} on the classpath: {cp:?}", jar_leaf()))
            .clone();
        let bytes = std::fs::read(&jar).unwrap();
        (jar, jar_member(&bytes, NOTICE).unwrap())
    }

    /// The build consumes the patched victim.
    fn assert_consumes_patched(&self, extra: &[&str], what: &str) -> PathBuf {
        assert_patched(&self.build(extra), VICTIM, NOTICE, &patched_notice(), what)
    }

    /// The build consumes the pristine victim.
    fn assert_consumes_pristine(&self, extra: &[&str], what: &str) -> PathBuf {
        let pristine = notice(&coordinate(), "pristine").into_bytes();
        assert_patched(&self.build(extra), VICTIM, NOTICE, &pristine, what)
    }

    /// The `files-2.1` version dir of the victim.
    fn version_dir(&self) -> PathBuf {
        self.home
            .join(prebuilt_common::GRADLE_FILES21)
            .join(GROUP)
            .join(VICTIM)
            .join(VICTIM_VERSION)
    }

    /// Every hash dir of the version dir holding the victim jar.
    fn hash_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(self.version_dir())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join(jar_leaf()).is_file())
            .collect();
        dirs.sort();
        dirs
    }

    /// Copy the victim's pom, module and jar into `~/.m2`.
    fn seed_m2(&self) -> PathBuf {
        let dir = self
            .m2
            .join("com/socketfixture/victim")
            .join(VICTIM_VERSION);
        std::fs::create_dir_all(&dir).unwrap();
        for ext in ["pom", "module", "jar"] {
            let path = repo_path(VICTIM, VICTIM_VERSION, None, ext);
            std::fs::write(
                dir.join(path.rsplit('/').next().unwrap()),
                central_file(&path),
            )
            .unwrap();
        }
        dir
    }

    /// Write the manifest with `files` (`(key, before, after)`), every blob
    /// committed.
    fn manifest(&self, purl: &str, files: &[(String, Vec<u8>, Vec<u8>)]) {
        // A rollback may have swept `.socket/` away.
        std::fs::create_dir_all(self.proj.join(".socket/blobs")).unwrap();
        let mut entries = serde_json::Map::new();
        for (key, before, after) in files {
            for bytes in [before, after] {
                std::fs::write(
                    self.proj.join(".socket/blobs").join(git_sha256(bytes)),
                    bytes,
                )
                .unwrap();
            }
            entries.insert(
                key.clone(),
                serde_json::json!({
                    "beforeHash": git_sha256(before), "afterHash": git_sha256(after),
                }),
            );
        }
        std::fs::write(
            self.proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": { purl: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": entries,
                "vulnerabilities": { "GHSA-gr4d-1e55-0264": {
                    "cves": ["CVE-2026-0264"], "summary": "s",
                    "severity": "high", "description": "d"
                } },
                "description": "gradle agent e2e", "license": "MIT", "tier": "free",
            } } }))
            .unwrap(),
        )
        .unwrap();
    }

    /// The leaf record: the whole victim jar.
    fn leaf_manifest(&self) {
        self.manifest(
            &purl(),
            &[(
                format!("package/{}", jar_leaf()),
                pristine_jar(),
                patched_jar(),
            )],
        );
    }

    /// The member-keyed record (#264): NOTICE and `Victim.class`.
    fn member_manifest(&self) {
        self.manifest(
            &purl(),
            &[
                (
                    NOTICE.to_string(),
                    notice(&coordinate(), "pristine").into_bytes(),
                    patched_notice(),
                ),
                (
                    VICTIM_CLASS_MEMBER.to_string(),
                    victim_class(VICTIM_VERSION, "pristine"),
                    victim_class(VICTIM_VERSION, "patched"),
                ),
            ],
        );
    }

    /// `socket-patch <args> --json --cwd <proj>` under the cell's caches.
    fn socket(&self, args: &[&str]) -> (Option<i32>, serde_json::Value) {
        let mut cmd = hermetic::command(Path::new(env!("CARGO_BIN_EXE_socket-patch")));
        prebuilt_common::jvm_env::isolate_cli(&mut cmd);
        cmd.args(args)
            .args(["--json", "--cwd", self.proj.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("GRADLE_USER_HOME", &self.home)
            .env("MAVEN_REPO_LOCAL", &self.m2)
            .env("SOCKET_MAVEN_REGISTRY", self.central.uri())
            .env_remove("M2_HOME");
        if let Some(ro) = &self.ro {
            cmd.env("GRADLE_RO_DEP_CACHE", ro);
        }
        let out = cmd.output().expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let json = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "{args:?}: not one JSON document ({e})\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), json)
    }

    fn socket_ok(&self, args: &[&str]) -> serde_json::Value {
        let (code, json) = self.socket(args);
        assert_eq!(code, Some(0), "{args:?}: {json}");
        json
    }

    /// `vex`: the statement count (0 when no document was written) and the
    /// envelope.
    fn vex(&self, extra: &[&str]) -> (usize, serde_json::Value) {
        let doc = self.root.join("vex.json");
        let _ = std::fs::remove_file(&doc);
        let mut args = vec!["vex", "-O", doc.to_str().unwrap(), "--product", PRODUCT];
        args.extend_from_slice(extra);
        let (_, json) = self.socket(&args);
        let statements = std::fs::read(&doc)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|d| d["statements"].as_array().map(Vec::len))
            .unwrap_or(0);
        (statements, json)
    }

    fn cell_name(&self, test: &str) -> String {
        format!(
            "{SUITE}-{test}-gradle-{}-{}",
            self.gradle.version,
            std::env::consts::OS
        )
    }
}

fn has(json: &serde_json::Value, code: &str) -> bool {
    codes_in(&json["warnings"]).iter().any(|c| c == code)
}

/// Every file under `dir` with its sha1 (the cache trees a rollback must
/// restore byte for byte).
fn tree(dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for entry in walkdir(dir) {
        let rel = entry
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        out.insert(rel, sha1_hex(&std::fs::read(&entry).unwrap()));
    }
    out
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                pending.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A patch service granting the member-keyed record: its jar is served by
/// the fake Central's patched-jar route, the grant by a mock of the
/// vendoring endpoint (its `uri()` is the `--vendor-url`).
fn patch_service(
    central: &FakeCentral,
    jar: &[u8],
) -> (tokio::runtime::Runtime, wiremock::MockServer) {
    use base64::Engine as _;
    use sha2::Digest as _;
    let url = central.serve_patched_jar(UUID, VICTIM, VICTIM_VERSION, jar);
    let sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(jar))
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/patch/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted", "purl": purl(), "url": url,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha512": sri } }]
                } }
            })))
            .mount(&server)
            .await;
        server
    });
    (rt, server)
}

// ── #551 ────────────────────────────────────────────────────────────────

/// #551: a build without mavenLocal() consumes the Gradle cache copy; agent
/// mode patches exactly that (the pristine `~/.m2` copy beside it is not
/// read and not touched), and VEX attests.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_551_patches_consumed_jar() {
    let Some(c) = cell(CENTRAL, "") else { return };
    let m2 = c.seed_m2();
    c.assert_consumes_pristine(&[], "first build");
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    let consumed = c.assert_consumes_patched(&[], "after apply");
    assert!(
        consumed.starts_with(c.version_dir()),
        "{}",
        consumed.display()
    );
    assert_eq!(std::fs::read(m2.join(jar_leaf())).unwrap(), pristine_jar());
    let (statements, json) = c.vex(&[]);
    assert!(statements > 0, "{json}");
}

/// Control: with mavenLocal() first, Gradle consumes the `~/.m2` copy, and
/// agent mode patches it (and the Gradle copy, when there is one).
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_551_mavenlocal_control() {
    let Some(c) = cell(LOCAL_FIRST, "") else {
        return;
    };
    let m2 = c.seed_m2();
    let consumed = c.assert_consumes_pristine(&[], "first build");
    assert!(consumed.starts_with(&c.m2), "{}", consumed.display());
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    c.assert_consumes_patched(&[], "after apply");
    assert_eq!(std::fs::read(m2.join(jar_leaf())).unwrap(), patched_jar());
    let (statements, json) = c.vex(&[]);
    assert!(statements > 0, "{json}");
}

/// mavenLocal() from a user-home init script: the build consumes `~/.m2`,
/// and agent mode sees the declaration and patches it.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_551_initd_mavenlocal() {
    let Some(c) = cell(CENTRAL, "") else { return };
    std::fs::create_dir_all(c.home.join("init.d")).unwrap();
    std::fs::write(
        c.home.join("init.d/local.gradle"),
        "allprojects {\n    repositories {\n        mavenLocal()\n    }\n}\n",
    )
    .unwrap();
    let m2 = c.seed_m2();
    c.assert_consumes_pristine(&[], "first build");
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    assert_eq!(std::fs::read(m2.join(jar_leaf())).unwrap(), patched_jar());
    c.assert_consumes_patched(&[], "after apply");
}

// ── #264 ────────────────────────────────────────────────────────────────

/// A member-keyed record swaps in the patch service's whole jar: the build
/// consumes the patched members, the original is kept under
/// `.socket/jvm-originals/`, and rollback restores the cache byte for byte.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_264_member_record_whole_jar() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    let before = tree(&c.version_dir());
    c.member_manifest();
    let (_rt, service) = patch_service(&c.central, &patched_jar());
    c.socket_ok(&["apply", "--vendor-url", &service.uri()]);
    let consumed = c.assert_consumes_patched(&[], "after the swap");
    assert_eq!(std::fs::read(&consumed).unwrap(), patched_jar());
    let backup = c.proj.join(".socket/jvm-originals").join(format!(
        "{}.jar",
        jvm_fixture_repo::sha256_hex(&pristine_jar())
    ));
    assert_eq!(std::fs::read(&backup).unwrap(), pristine_jar());
    let (statements, json) = c.vex(&[]);
    assert!(statements > 0, "{json}");

    c.socket_ok(&["rollback", "--offline"]);
    assert_eq!(tree(&c.version_dir()), before);
    c.assert_consumes_pristine(&[], "after rollback");

    // Offline with no service: nothing is written. (Rollback dropped the
    // manifest record; put it back.)
    c.member_manifest();
    let (code, json) = c.socket(&["apply", "--offline"]);
    assert_ne!(code, Some(0), "{json}");
    assert!(has(&json, "jvm_agent_service_required"), "{json}");
    assert_eq!(tree(&c.version_dir()), before);
}

// ── rollback / remove ───────────────────────────────────────────────────

/// apply → rollback leaves the Gradle cache byte-identical, and the build
/// consumes the pristine jar again.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_rollback_byte_exact() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    let before = tree(&c.version_dir());
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    c.assert_consumes_patched(&[], "after apply");
    c.socket_ok(&["rollback", "--offline"]);
    assert_eq!(tree(&c.version_dir()), before);
    for dir in c.hash_dirs() {
        let name = dir.file_name().unwrap().to_str().unwrap().to_string();
        let jar = std::fs::read(dir.join(jar_leaf())).unwrap();
        assert!(socket_patch_core::crawlers::gradle_cache::pristine(
            &name, &jar
        ));
    }
    c.assert_consumes_pristine(&[], "after rollback");
}

/// `remove` restores every copy it patched — the Gradle cache and, with
/// mavenLocal() declared, `~/.m2` — byte for byte.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_remove_restores_all_copies() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "populate the Gradle cache");
    // Now read ~/.m2 too: both copies are consumed.
    let script = std::fs::read_to_string(c.proj.join("build.gradle")).unwrap();
    std::fs::write(
        c.proj.join("build.gradle"),
        script.replace(CENTRAL, LOCAL_FIRST),
    )
    .unwrap();
    let m2 = c.seed_m2();
    let gradle_before = tree(&c.version_dir());
    let m2_before = tree(&m2);
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    assert_ne!(tree(&c.version_dir()), gradle_before);
    assert_ne!(tree(&m2), m2_before);
    c.assert_consumes_patched(&[], "after apply");
    c.socket_ok(&["remove", &purl(), "--offline"]);
    assert_eq!(tree(&c.version_dir()), gradle_before);
    assert_eq!(tree(&m2), m2_before);
    c.assert_consumes_pristine(&[], "after remove");
}

// ── refusals ────────────────────────────────────────────────────────────

/// Dependency verification with key trust only (no component entry for the
/// victim) still refuses agent mode: nothing is written and the build
/// keeps consuming the pristine jar.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_verification_metadata_refuses() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    let before = tree(&c.home.join("caches/modules-2/files-2.1"));
    std::fs::create_dir_all(c.proj.join("gradle")).unwrap();
    std::fs::write(
        c.proj.join("gradle/verification-metadata.xml"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>true</verify-signatures>
      <trusted-keys>
         <trusted-key id="{}" group="{GROUP}"/>
      </trusted-keys>
   </configuration>
   <components/>
</verification-metadata>
"#,
            jvm_fixture_repo::KEY_FINGERPRINT
        ),
    )
    .unwrap();
    c.leaf_manifest();
    let (code, json) = c.socket(&["apply", "--offline"]);
    assert_ne!(code, Some(0), "{json}");
    assert!(has(&json, "gradle_verification_metadata_present"), "{json}");
    assert_eq!(tree(&c.home.join("caches/modules-2/files-2.1")), before);
    std::fs::remove_file(c.proj.join("gradle/verification-metadata.xml")).unwrap();
    c.assert_consumes_pristine(&[], "after the refusal");
}

/// The read-only cache (`GRADLE_RO_DEP_CACHE`) is never written: a copy
/// there fails the run (`gradle_ro_cache_shadows`). Records whether Gradle
/// resolves from it before the user home.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_ro_cache_shadows() {
    let Some(mut c) = cell(CENTRAL, "") else {
        return;
    };
    c.assert_consumes_pristine(&[], "populate a cache to freeze");
    // Freeze it as the read-only cache, then start the user home over.
    let ro = c.root.join("ro");
    copy_tree(&c.home.join("caches/modules-2"), &ro.join("modules-2"));
    std::fs::remove_dir_all(c.home.join("caches")).unwrap();
    c.ro = Some(ro.clone());
    let (consumed, _) = c.consumed(&[], "build over the read-only cache");
    let from_ro = consumed.starts_with(&ro);
    let ro_before = tree(&ro);
    c.leaf_manifest();
    let (code, json) = c.socket(&["apply", "--offline"]);
    assert_ne!(code, Some(0), "{json}");
    assert!(has(&json, "gradle_ro_cache_shadows"), "{json}");
    assert_eq!(
        tree(&ro),
        ro_before,
        "the read-only cache must never be written"
    );
    let (statements, _) = c.vex(&[]);
    assert_eq!(statements, 0);
    probe_report(
        &c.cell_name("ro"),
        &serde_json::json!({
            "gradle": c.gradle.version, "jvm": c.gradle.jvm,
            "consumedFromReadOnly": from_ro,
            "consumed": consumed,
        }),
    );
}

// ── global prefix ───────────────────────────────────────────────────────

/// `--global-prefix` naming the user home or its `caches/modules-2`
/// reaches the cache for apply, vex and rollback.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_global_prefix() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    for prefix in [c.home.clone(), c.home.join("caches/modules-2")] {
        // Each rollback drops the manifest record: write it per round.
        c.leaf_manifest();
        let p = prefix.to_str().unwrap();
        c.socket_ok(&["apply", "--offline", "--global-prefix", p]);
        c.assert_consumes_patched(&[], "after a global-prefix apply");
        let (statements, json) = c.vex(&["--global-prefix", p]);
        assert!(statements > 0, "{json}");
        c.socket_ok(&["rollback", "--offline", "--global-prefix", p]);
        c.assert_consumes_pristine(&[], "after a global-prefix rollback");
    }
}

// ── refresh ─────────────────────────────────────────────────────────────

/// `--refresh-dependencies` after an apply: whatever Gradle does to the
/// cache (overwrite in place, keep, or a new hash dir), VEX re-hashes the
/// disk and attests exactly when the consumed bytes are patched.
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_refresh_vex_matches_disk() {
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    c.leaf_manifest();
    c.socket_ok(&["apply", "--offline"]);
    c.assert_consumes_patched(&[], "after apply");
    let dirs_before = c.hash_dirs();
    let (consumed, notice_bytes) = c.consumed(&["--refresh-dependencies"], "refresh");
    let consumed_patched = notice_bytes == patched_notice();
    let dirs_after = c.hash_dirs();
    let behaviour = if dirs_after.len() > dirs_before.len() {
        "new_dir"
    } else if consumed_patched {
        "keep"
    } else {
        "overwrite"
    };
    let every_copy_patched = dirs_after.iter().all(|d| {
        jar_member(&std::fs::read(d.join(jar_leaf())).unwrap(), NOTICE).as_deref()
            == Some(patched_notice().as_slice())
    });
    let (statements, json) = c.vex(&[]);
    assert_eq!(
        statements > 0,
        every_copy_patched,
        "VEX must attest exactly when every copy on disk is patched ({behaviour}): {json}"
    );
    if !consumed_patched {
        assert_eq!(statements, 0, "the build consumes an unpatched jar: {json}");
    }
    probe_report(
        &c.cell_name("refresh"),
        &serde_json::json!({
            "gradle": c.gradle.version, "jvm": c.gradle.jvm,
            "refresh": behaviour,
            "consumedPatched": consumed_patched,
            "consumed": consumed,
            "hashDirsBefore": dirs_before.len(),
            "hashDirsAfter": dirs_after.len(),
            "vexStatements": statements,
        }),
    );
}

// ── Windows ─────────────────────────────────────────────────────────────

/// Windows: a jar held open without delete sharing (what a Gradle daemon
/// does) refuses the write with `gradle_jar_locked_by_daemon`.
#[cfg(windows)]
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_windows_daemon_lock() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let Some(c) = cell(CENTRAL, "") else { return };
    c.assert_consumes_pristine(&[], "first build");
    c.leaf_manifest();
    let jar = c.hash_dirs()[0].join(jar_leaf());
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1) // FILE_SHARE_READ only: no rename / delete over it
        .open(&jar)
        .unwrap();
    let (code, json) = c.socket(&["apply", "--offline"]);
    drop(held);
    assert_ne!(code, Some(0), "{json}");
    assert!(has(&json, "gradle_jar_locked_by_daemon"), "{json}");
    c.socket_ok(&["apply", "--offline"]);
    c.assert_consumes_patched(&[], "after the lock is released");
}

// ── canaries ────────────────────────────────────────────────────────────

/// How this Gradle major treats its cache, recorded in the probe report
/// (and asserted where agent mode depends on it):
///
/// * (a) hash-dir naming — the victim jar's sha1 starts with `0`;
/// * (b) `--offline` reuses the patched cache without re-hashing it;
/// * (c) what `--refresh-dependencies` does (see the refresh test);
/// * (d) a daemon that ran before the apply, and after `--stop`;
/// * (e) a classifier jar gets its own hash dir and its own patch;
/// * (f) the buildscript classpath (`BuildLogic` prints `Victim.marker()`);
/// * (g) a `--build-cache` jar task picks up the patched member;
/// * (h) read-only cache precedence (see the read-only test).
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_cache_semantics_canaries() {
    let buildlogic = format!(
        "{GROUP}:{}:{}",
        jvm_fixture_repo::BUILDLOGIC,
        jvm_fixture_repo::BUILDLOGIC_VERSION
    );
    let extra = format!(
        "dependencies {{ testImplementation '{}:tests' }}\n\
         tasks.register('printTestClasspath') {{\n    \
         def cp = files(configurations.named('testRuntimeClasspath'))\n    \
         doLast {{ cp.files.each {{ println('SOCKET-TCP ' + it.absolutePath) }} }}\n}}\n\
         tasks.register('fatJar', Jar) {{\n    \
         archiveFileName = 'fat.jar'\n    \
         def cp = files(configurations.named('runtimeClasspath'))\n    \
         from({{ cp.collect {{ zipTree(it) }} }})\n    \
         duplicatesStrategy = DuplicatesStrategy.EXCLUDE\n}}\n\
         tasks.register('buildLogicMarker') {{\n    \
         doLast {{ {}.print() }}\n}}\n",
        coordinate(),
        jvm_fixture_repo::BUILDLOGIC_CLASS
    );
    let Some(c) = cell(CENTRAL, &extra) else {
        return;
    };
    // Build logic: the buildlogic plugin (which depends on the victim) on the
    // buildscript classpath.
    let script = std::fs::read_to_string(c.proj.join("build.gradle")).unwrap();
    std::fs::write(
        c.proj.join("build.gradle"),
        format!(
            "buildscript {{\n    repositories {{ mavenCentral() }}\n    \
             dependencies {{ classpath '{buildlogic}' }}\n}}\n{script}"
        ),
    )
    .unwrap();
    let mut report = serde_json::Map::new();
    report.insert("gradle".into(), c.gradle.version.clone().into());
    report.insert("jvm".into(), c.gradle.jvm.clone().into());

    let m2_property = c.m2_property();
    let run = |args: &[&str]| -> Output {
        let mut all: Vec<&str> = vec![&c.init[0], &c.init[1], &m2_property];
        all.extend_from_slice(args);
        c.gradle.run(&c.proj, &c.home, &all)
    };
    let marker = |out: &Output| -> Option<String> {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix(jvm_fixture_repo::BUILDLOGIC_MARKER))
            .map(str::to_string)
    };

    // Populate: classpath, build logic, the fat jar into the build cache.
    let first = run(&[
        "--build-cache",
        "printRuntimeClasspath",
        "printTestClasspath",
        "buildLogicMarker",
        "fatJar",
    ]);
    assert!(ok(&first), "first build:\n{}", dump(&first));
    assert_eq!(
        marker(&first).as_deref(),
        Some(victim_marker(VICTIM_VERSION, "pristine").as_str())
    );

    // (a) hash-dir naming.
    let dirs = c.hash_dirs();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let name = dirs[0].file_name().unwrap().to_str().unwrap().to_string();
    let sha1 = sha1_hex(&pristine_jar());
    assert!(sha1.starts_with('0'));
    assert!(socket_patch_core::crawlers::gradle_cache::hash_eq(
        &name, &sha1
    ));
    report.insert("a_hashDir".into(), name.clone().into());
    report.insert("a_leadingZeroDropped".into(), (name.len() < 40).into());

    // Patch the main jar and the tests classifier together (two records).
    let tests_path = repo_path(VICTIM, VICTIM_VERSION, Some("tests"), "jar");
    let tests_pristine = central_file(&tests_path);
    let tests_leaf = tests_path.rsplit('/').next().unwrap().to_string();
    let tests_patched = patch_jar(&tests_pristine);
    let main_files = [(
        format!("package/{}", jar_leaf()),
        pristine_jar(),
        patched_jar(),
    )];
    c.manifest(&purl(), &main_files);
    let manifest_path = c.proj.join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let mut tests_record = manifest["patches"][purl()].clone();
    tests_record["uuid"] = "26400000-7b4e-4c1a-9f0e-2a3b4c5d6e80".into();
    tests_record["files"] = serde_json::json!({ format!("package/{tests_leaf}"): {
        "beforeHash": git_sha256(&tests_pristine), "afterHash": git_sha256(&tests_patched),
    } });
    for bytes in [&tests_pristine, &tests_patched] {
        std::fs::write(c.proj.join(".socket/blobs").join(git_sha256(bytes)), bytes).unwrap();
    }
    let main_record = manifest["patches"][purl()].clone();
    manifest["patches"] = serde_json::json!({
        format!("{}?ext=jar", purl()): main_record,
        format!("{}?classifier=tests&ext=jar", purl()): tests_record,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // (d) a daemon that resolved the pristine jar before the apply. Not on
    // Windows: a live daemon holds the cached jars open there, which is
    // `gradle_agent_windows_daemon_lock`'s subject.
    let use_daemon = !cfg!(windows);
    let daemon = |args: &[&str]| -> Output {
        let mut cmd = Gradle::command(&c.gradle.program, Some(&c.home));
        cmd.current_dir(&c.proj)
            .args(["--daemon", "--console=plain", &m2_property])
            .args(&c.init)
            .args(args);
        cmd.output().unwrap()
    };
    if use_daemon {
        let warm = daemon(&["buildLogicMarker"]);
        report.insert("d_daemonStarted".into(), ok(&warm).into());
    }

    let (code, json) = c.socket(&["apply", "--offline"]);
    let stale = has(&json, "gradle_transform_copy_stale");
    report.insert("f_applyReportsStaleTransforms".into(), stale.into());
    report.insert("applyExit".into(), code.into());
    report.insert("applyWarnings".into(), codes_in(&json["warnings"]).into());
    assert!(
        code == Some(0) || stale,
        "apply may only fail over derived copies it names: {json}"
    );
    // The warm daemon is the measured hazard; `gradle_daemon_stale` is its
    // only mitigation, so the apply must say it.
    if use_daemon {
        let daemon_stale = json["sidecars"].to_string().contains("gradle_daemon_stale");
        report.insert("d_applyReportsDaemonStale".into(), daemon_stale.into());
        assert!(
            daemon_stale,
            "(d) a daemon was running: apply must report gradle_daemon_stale: {json}"
        );
    }

    // (d) the warm daemon, then after --stop.
    if use_daemon {
        let warm_after = daemon(&["buildLogicMarker", "printRuntimeClasspath"]);
        report.insert(
            "d_daemonBuildLogicMarker".into(),
            marker(&warm_after).unwrap_or_default().into(),
        );
        let warm_notice = gradle_build_common::gradle_classpath(&warm_after)
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == jar_leaf().as_str()))
            .and_then(|p| jar_member(&std::fs::read(p).ok()?, NOTICE));
        report.insert(
            "d_daemonClasspathPatched".into(),
            (warm_notice.as_deref() == Some(patched_notice().as_slice())).into(),
        );
        let _ = daemon(&["--stop"]);
    }

    // (b) --offline reuse without a re-hash.
    let offline = c.assert_consumes_patched(&["--offline"], "(b) --offline after apply");
    report.insert("b_offlineReuse".into(), true.into());
    report.insert(
        "b_consumed".into(),
        offline.to_string_lossy().into_owned().into(),
    );

    // (e) the classifier jar: its own hash dir, its own patch, consumed.
    let tests_out = run(&["--offline", "printTestClasspath"]);
    assert!(ok(&tests_out), "{}", dump(&tests_out));
    let consumed_tests = String::from_utf8_lossy(&tests_out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix("SOCKET-TCP "))
        .map(PathBuf::from)
        .find(|p| p.file_name().is_some_and(|n| n == tests_leaf.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "no {tests_leaf} on the test classpath:\n{}",
                dump(&tests_out)
            )
        });
    assert_eq!(std::fs::read(&consumed_tests).unwrap(), tests_patched);
    let tests_dirs: Vec<PathBuf> = std::fs::read_dir(c.version_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join(&tests_leaf).is_file())
        .collect();
    assert_eq!(tests_dirs.len(), 1, "{tests_dirs:?}");
    assert_ne!(tests_dirs[0], dirs[0]);
    let tests_now = std::fs::read(tests_dirs[0].join(&tests_leaf)).unwrap();
    assert_eq!(
        tests_now, tests_patched,
        "(e) the classifier jar must be patched"
    );
    report.insert("e_classifierHashDir".into(), true.into());

    // (f) build logic after the apply (a fresh, daemon-less build).
    let logic = run(&["--offline", "buildLogicMarker"]);
    let logic_marker = marker(&logic).unwrap_or_default();
    let logic_patched = logic_marker == victim_marker(VICTIM_VERSION, "patched");
    report.insert("f_buildLogicMarker".into(), logic_marker.clone().into());
    report.insert("f_buildLogicPatched".into(), logic_patched.into());
    assert!(
        logic_patched || stale,
        "(f) build logic still runs the pristine class but apply did not report the stale \
         derived copy: {logic_marker}"
    );

    // (g) the fat jar from the build cache carries the patched member.
    let fat = run(&["--offline", "--build-cache", "fatJar"]);
    assert!(ok(&fat), "{}", dump(&fat));
    let fat_jar = std::fs::read(c.proj.join("build/libs/fat.jar")).unwrap();
    let fat_notice = jar_member(&fat_jar, NOTICE).unwrap_or_default();
    report.insert(
        "g_buildCacheFatJarPatched".into(),
        (fat_notice == patched_notice()).into(),
    );
    assert_eq!(
        String::from_utf8_lossy(&fat_notice),
        String::from_utf8_lossy(&patched_notice()),
        "(g) the build-cache jar task must pick up the patched member"
    );

    // (f) VEX over the build-logic copies. Gradle instrumented the
    // buildscript jar before the apply; that copy, left in its derived
    // cache, may withhold the statement — but clearing the derived caches
    // (what the warning says) and rebuilding must lead to one: Gradle
    // instruments the patched jar anew.
    let (statements, vex_json) = c.vex(&[]);
    report.insert("f_vexStatementsBeforeClear".into(), statements.into());
    report.insert(
        "f_vexWarningsBeforeClear".into(),
        codes_in(&vex_json["warnings"]).into(),
    );
    let caches = c.home.join("caches");
    for entry in std::fs::read_dir(&caches).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name.starts_with("jars-") || name.starts_with("transforms-") {
            std::fs::remove_dir_all(&path).unwrap();
        } else if name.starts_with(|c: char| c.is_ascii_digit()) && path.join("transforms").is_dir()
        {
            std::fs::remove_dir_all(path.join("transforms")).unwrap();
        }
    }
    let rebuilt = run(&["--offline", "buildLogicMarker", "printRuntimeClasspath"]);
    assert!(ok(&rebuilt), "{}", dump(&rebuilt));
    assert_eq!(
        marker(&rebuilt).as_deref(),
        Some(victim_marker(VICTIM_VERSION, "patched").as_str())
    );
    let (statements, vex_json) = c.vex(&[]);
    report.insert("f_vexStatementsAfterClear".into(), statements.into());
    report.insert(
        "f_vexWarningsAfterClear".into(),
        codes_in(&vex_json["warnings"]).into(),
    );
    assert!(
        statements > 0 && !has(&vex_json, "vex_gradle_unpatched_copy"),
        "(f) VEX must attest every record once the derived caches are rebuilt from the patched \
         jar: {vex_json}"
    );

    probe_report(&c.cell_name("canaries"), &serde_json::Value::Object(report));
}

/// `src` copied to `dst`, recursively.
fn copy_tree(src: &Path, dst: &Path) {
    for file in walkdir(src) {
        let target = dst.join(file.strip_prefix(src).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }
}

/// Pure checks of the fixture this suite builds on (run everywhere).
#[test]
fn gradle_agent_fixture_self_check() {
    let pristine = pristine_jar();
    assert!(sha1_hex(&pristine).starts_with('0'));
    let patched = patched_jar();
    assert_eq!(jar_member(&patched, NOTICE).unwrap(), patched_notice());
    // Only the two patched members differ.
    for member in ["META-INF/MANIFEST.MF", jvm_fixture_repo::PAD_MEMBER] {
        assert_eq!(jar_member(&patched, member), jar_member(&pristine, member));
    }
}
