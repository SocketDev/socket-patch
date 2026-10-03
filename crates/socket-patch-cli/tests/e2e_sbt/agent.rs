//! Agent mode (`apply` / `rollback` / `scan` in place) over the caches sbt,
//! Mill and scala-cli resolve into: Coursier's (sbt 1.3+, with its hidden
//! checksum sidecars resynced) and Ivy's (sbt <= 1.2, or
//! `useCoursier := false`). Agent scans are not scoped to the build: the
//! whole cache is queried, as for `~/.m2`. Whole-file patch keys only
//! (`<a>-<v>.jar`), the same parity as `~/.m2` today.

use std::path::{Path, PathBuf};

use serde_json::Value;
use sha1::{Digest as _, Sha1};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::common;
use super::sbt_common::{
    write_coursier_artifact, write_ivy_artifact, write_sbt_build, Gav, SbtHome,
};

const SLF4J: Gav<'static> = Gav {
    group: "org.slf4j",
    artifact: "slf4j-api",
    version: "1.7.36",
};

const GSON: Gav<'static> = Gav {
    group: "com.google.code.gson",
    artifact: "gson",
    version: "2.8.9",
};

const JAR: &str = "slf4j-api-1.7.36.jar";
const ORIGINAL: &[u8] = b"PK\x03\x04 pristine slf4j-api 1.7.36\n";
const PATCHED: &[u8] = b"PK\x03\x04 socket-patched slf4j-api 1.7.36\n";
const CENTRAL: &str = "repo1.maven.org/maven2";

/// One test's isolated home and an sbt build depending on slf4j only.
struct Fixture {
    _tmp: tempfile::TempDir,
    home: SbtHome,
    project: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = tmp.path().join("project");
    write_sbt_build(
        &project,
        "1.9.9",
        "libraryDependencies += \"org.slf4j\" % \"slf4j-api\" % \"1.7.36\"\n",
    );
    Fixture {
        _tmp: tmp,
        home,
        project,
    }
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

/// A manifest patching `gav`'s jar as a whole file (`ORIGINAL` →
/// `PATCHED`), with both blobs staged so apply and rollback run offline.
fn stage_manifest(project: &Path, gav: Gav<'_>) {
    let before = common::git_sha256(ORIGINAL);
    let after = common::git_sha256(PATCHED);
    let manifest = serde_json::json!({
        "patches": {
            gav.purl(): {
                "uuid": "5b7a0000-0000-4000-8000-000000000001",
                "exportedAt": "2026-10-02T00:00:00Z",
                "files": {
                    format!("{}-{}.jar", gav.artifact, gav.version): {
                        "beforeHash": before,
                        "afterHash": after,
                    }
                },
                "vulnerabilities": {},
                "description": "sbt agent fixture",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    let socket = project.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&before), ORIGINAL).unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED).unwrap();
}

/// Run the CLI in the project under the fixture's isolated env, `extra`
/// overriding it; `(exit code, JSON envelope, stderr)`.
fn run(fx: &Fixture, args: &[&str], extra: &[(&str, String)]) -> (i32, Value, String) {
    let mut env = fx.home.isolated_env();
    for (key, value) in extra {
        env.retain(|(k, _)| k != key);
        env.push((key.to_string(), value.clone()));
    }
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (code, stdout, stderr) = common::run_with_env(&fx.project, args, &env);
    let envelope = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{args:?}: envelope must parse ({e})\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, envelope, stderr)
}

fn maven_sidecars(envelope: &Value) -> Vec<Value> {
    envelope["sidecars"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .filter(|r| r["ecosystem"] == "maven")
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn hidden(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!(".{JAR}{suffix}"))
}

#[test]
fn agent_apply_patches_a_coursier_cache_copy_and_resyncs_its_sidecars() {
    let fx = fixture();
    let dir = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    // The rest of what Coursier leaves: the cached digest, md5, `.checked`.
    std::fs::write(hidden(&dir, "__sha1.computed"), Sha1::digest(ORIGINAL)).unwrap();
    std::fs::write(hidden(&dir, "__md5"), "00000000000000000000000000000000").unwrap();
    std::fs::write(hidden(&dir, ".checked"), b"").unwrap();
    stage_manifest(&fx.project, SLF4J);

    let (code, env, stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(std::fs::read(dir.join(JAR)).unwrap(), PATCHED);
    assert_eq!(
        std::fs::read_to_string(hidden(&dir, "__sha1")).unwrap(),
        sha1_hex(PATCHED)
    );
    assert_eq!(
        std::fs::read(hidden(&dir, "__sha1.computed")).unwrap(),
        Sha1::digest(PATCHED).to_vec()
    );
    assert!(
        !hidden(&dir, "__md5").exists(),
        "md5 is deleted, not rewritten"
    );
    assert!(hidden(&dir, ".checked").exists(), ".checked is left alone");
    // The pom was not patched, so its sidecar is untouched.
    let pom = ".slf4j-api-1.7.36.pom__sha1";
    assert_eq!(
        std::fs::read_to_string(dir.join(pom)).unwrap(),
        sha1_hex(SLF4J.pom().as_bytes())
    );
    let records = maven_sidecars(&env);
    assert_eq!(records.len(), 1, "{env}");
    assert_eq!(records[0]["purl"], SLF4J.purl());
    let files = records[0]["files"].as_array().unwrap();
    for (path, action) in [
        (format!(".{JAR}__sha1"), "rewritten"),
        (format!(".{JAR}__sha1.computed"), "rewritten"),
        (format!(".{JAR}__md5"), "deleted"),
    ] {
        assert!(
            files
                .iter()
                .any(|f| f["path"] == path && f["action"] == action),
            "{path} {action}: {}",
            records[0]
        );
    }

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    assert_eq!(std::fs::read(dir.join(JAR)).unwrap(), ORIGINAL);
    assert_eq!(
        std::fs::read_to_string(hidden(&dir, "__sha1")).unwrap(),
        sha1_hex(ORIGINAL),
        "rollback resyncs the sidecars to the restored bytes"
    );
    assert_eq!(
        std::fs::read(hidden(&dir, "__sha1.computed")).unwrap(),
        Sha1::digest(ORIGINAL).to_vec()
    );
}

#[test]
fn agent_apply_patches_an_ivy_cache_copy() {
    let fx = fixture();
    let jars = write_ivy_artifact(&fx.home.ivy_home(), SLF4J, ORIGINAL);
    let module = jars.parent().unwrap().to_path_buf();
    let ivy_xml = std::fs::read(module.join("ivy-1.7.36.xml")).unwrap();
    stage_manifest(&fx.project, SLF4J);
    let sbt_opts = (
        "SBT_OPTS",
        format!("-Dsbt.ivy.home={}", fx.home.ivy_home().display()),
    );

    let (code, env, stderr) = run(
        &fx,
        &["apply", "--offline", "--json"],
        std::slice::from_ref(&sbt_opts),
    );
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(std::fs::read(jars.join(JAR)).unwrap(), PATCHED);
    assert_eq!(
        std::fs::read(module.join("ivy-1.7.36.xml")).unwrap(),
        ivy_xml
    );
    assert!(
        maven_sidecars(&env).is_empty(),
        "Ivy keeps no sidecars: {env}"
    );

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[sbt_opts]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    assert_eq!(std::fs::read(jars.join(JAR)).unwrap(), ORIGINAL, "{env}");
}

#[test]
fn agent_m2_checksum_files_are_not_coursier_sidecars() {
    let fx = fixture();
    let dir = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(JAR), ORIGINAL).unwrap();
    std::fs::write(dir.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    std::fs::write(dir.join(format!("{JAR}.sha1")), sha1_hex(ORIGINAL)).unwrap();
    std::fs::write(dir.join("_remote.repositories"), b"#x\n").unwrap();
    stage_manifest(&fx.project, SLF4J);

    let (code, env, stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(std::fs::read(dir.join(JAR)).unwrap(), PATCHED);
    // The `~/.m2` checksum file follows the patched bytes (the Maven
    // sidecar arm), and no Coursier `.<file>__<algo>` sidecar is made.
    assert_eq!(
        std::fs::read_to_string(dir.join(format!("{JAR}.sha1"))).unwrap(),
        sha1_hex(PATCHED)
    );
    assert!(!hidden(&dir, "__sha1").exists());
    let files: Vec<String> = maven_sidecars(&env)
        .iter()
        .flat_map(|r| r["files"].as_array().cloned().unwrap_or_default())
        .filter_map(|f| f["path"].as_str().map(str::to_string))
        .collect();
    assert!(files.iter().all(|f| !f.contains("__")), "{env}");
}

/// A Coursier sidecar that cannot be resynced (here a directory squatting
/// `__sha1`) leaves the patch on disk with a `sidecar_fixup_failed`
/// advisory; once the obstacle is gone, the next apply (every file already
/// patched, nothing written) still resyncs the sidecars.
#[test]
fn agent_retry_resyncs_after_a_failed_fixup() {
    let fx = fixture();
    let dir = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    std::fs::write(hidden(&dir, "__sha1.computed"), Sha1::digest(ORIGINAL)).unwrap();
    std::fs::remove_file(hidden(&dir, "__sha1")).unwrap();
    std::fs::create_dir(hidden(&dir, "__sha1")).unwrap();
    stage_manifest(&fx.project, SLF4J);

    let (_code, env, _stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(std::fs::read(dir.join(JAR)).unwrap(), PATCHED, "{env}");
    let records = maven_sidecars(&env);
    assert_eq!(records.len(), 1, "{env}");
    assert_eq!(
        records[0]["advisory"]["code"], "sidecar_fixup_failed",
        "{env}"
    );
    // The stale digest is still there: Coursier keeps the patch meanwhile.
    assert_eq!(
        std::fs::read(hidden(&dir, "__sha1.computed")).unwrap(),
        Sha1::digest(ORIGINAL).to_vec()
    );

    std::fs::remove_dir(hidden(&dir, "__sha1")).unwrap();
    let (code, env, stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "retry: {env}\n{stderr}");
    let records = maven_sidecars(&env);
    assert_eq!(records.len(), 1, "{env}");
    assert!(
        records[0].get("advisory").is_none_or(Value::is_null),
        "{env}"
    );
    assert_eq!(
        std::fs::read_to_string(hidden(&dir, "__sha1")).unwrap(),
        sha1_hex(PATCHED)
    );
    assert_eq!(
        std::fs::read(hidden(&dir, "__sha1.computed")).unwrap(),
        Sha1::digest(PATCHED).to_vec()
    );
}

/// A rollback that finds a Coursier copy already original (never patched)
/// leaves Coursier's own consistent sidecars, md5 included, byte for byte,
/// and reports no sidecar record.
#[test]
fn agent_rollback_of_a_pristine_coursier_copy_touches_nothing() {
    let fx = fixture();
    let dir = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    std::fs::write(hidden(&dir, "__sha1.computed"), Sha1::digest(ORIGINAL)).unwrap();
    std::fs::write(hidden(&dir, "__md5"), "00000000000000000000000000000000").unwrap();
    stage_manifest(&fx.project, SLF4J);
    let snapshot = || {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                (name, std::fs::read(e.path()).unwrap())
            })
            .collect();
        files.sort();
        files
    };
    let before = snapshot();

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    assert_eq!(snapshot(), before, "{env}");
    assert!(maven_sidecars(&env).is_empty(), "{env}");
}

/// No scoping: the build declares slf4j only, yet the scan queries every
/// GAV in the caches it found (gson in Coursier, slf4j in Ivy), the same
/// whole-cache behavior as `~/.m2`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_scan_queries_every_cached_gav() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    let fx = fixture();
    write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, GSON, b"gson");
    write_ivy_artifact(&fx.home.ivy_home(), SLF4J, ORIGINAL);
    let sbt_opts = (
        "SBT_OPTS",
        format!("-Dsbt.ivy.home={}", fx.home.ivy_home().display()),
    );
    let uri = server.uri();
    let (code, env, stderr) = tokio::task::spawn_blocking(move || {
        let out = run(&fx, &["scan", "--json", "--proxy-url", &uri], &[sbt_opts]);
        drop(fx);
        out
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "scan: {env}\n{stderr}");
    assert_eq!(env["scannedPackages"], 2, "{env}");
    let bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    let all = bodies.join("\n");
    for purl in [SLF4J.purl(), GSON.purl()] {
        assert!(all.contains(&purl), "batch must carry {purl}: {all}");
    }
}

/// One GAV cached three times (`~/.m2`, a Coursier cache, an Ivy cache):
/// sbt reads whichever its resolver picks, so apply patches EVERY copy and
/// rollback restores every copy. Patching only the first root would leave
/// the copy the build loads vulnerable while reporting success.
#[test]
fn agent_apply_and_rollback_cover_every_cached_copy() {
    let fx = fixture();
    let m2 = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m2.join(JAR), ORIGINAL).unwrap();
    std::fs::write(m2.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    let coursier = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    let ivy = write_ivy_artifact(&fx.home.ivy_home(), SLF4J, ORIGINAL);
    let copies = [m2.join(JAR), coursier.join(JAR), ivy.join(JAR)];
    stage_manifest(&fx.project, SLF4J);
    let sbt_opts = (
        "SBT_OPTS",
        format!("-Dsbt.ivy.home={}", fx.home.ivy_home().display()),
    );

    let (code, env, stderr) = run(
        &fx,
        &["apply", "--offline", "--json"],
        std::slice::from_ref(&sbt_opts),
    );
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    for copy in &copies {
        assert_eq!(
            std::fs::read(copy).unwrap(),
            PATCHED,
            "{} not patched: {env}",
            copy.display()
        );
    }
    // The Coursier copy's sidecars follow its bytes.
    assert_eq!(
        std::fs::read_to_string(hidden(&coursier, "__sha1")).unwrap(),
        sha1_hex(PATCHED)
    );
    // A re-run finds every copy patched.
    let (code, env, stderr) = run(
        &fx,
        &["apply", "--offline", "--json"],
        std::slice::from_ref(&sbt_opts),
    );
    assert_eq!(code, 0, "re-apply: {env}\n{stderr}");

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[sbt_opts]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    for copy in &copies {
        assert_eq!(
            std::fs::read(copy).unwrap(),
            ORIGINAL,
            "{} not restored: {env}",
            copy.display()
        );
    }
    assert_eq!(
        std::fs::read_to_string(hidden(&coursier, "__sha1")).unwrap(),
        sha1_hex(ORIGINAL)
    );
}

/// A Coursier version directory holding only the pom (a version Coursier
/// considered and evicted) is no copy: apply patches `~/.m2`'s jar and
/// exits 0, rollback restores it, instead of failing on a missing jar.
#[test]
fn agent_a_pom_only_coursier_directory_is_no_target() {
    let fx = fixture();
    let m2 = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m2.join(JAR), ORIGINAL).unwrap();
    std::fs::write(m2.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    let coursier = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    std::fs::remove_file(coursier.join(JAR)).unwrap();
    std::fs::remove_file(hidden(&coursier, "__sha1")).unwrap();
    stage_manifest(&fx.project, SLF4J);
    for (args, want) in [
        (&["apply", "--offline", "--json"][..], PATCHED),
        (&["apply", "--offline", "--json", "--strict"][..], PATCHED),
        (&["rollback", "--offline", "--json"][..], ORIGINAL),
    ] {
        let (code, env, stderr) = run(&fx, args, &[]);
        assert_eq!(code, 0, "{args:?}: {env}\n{stderr}");
        assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), want, "{args:?}");
        assert!(!coursier.join(JAR).exists(), "{args:?}");
    }
}

/// A Maven (pom.xml) project never reads the Coursier or Ivy caches, so a
/// local apply leaves their copies alone.
#[test]
fn agent_a_maven_project_leaves_the_scala_caches_alone() {
    let fx = fixture();
    let maven = fx.project.parent().unwrap().join("maven-project");
    std::fs::create_dir_all(&maven).unwrap();
    std::fs::write(maven.join("pom.xml"), "<project/>\n").unwrap();
    let m2 = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m2.join(JAR), ORIGINAL).unwrap();
    std::fs::write(m2.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    let coursier = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    stage_manifest(&maven, SLF4J);
    let fx = Fixture {
        _tmp: fx._tmp,
        home: fx.home,
        project: maven,
    };
    let (code, env, stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), PATCHED);
    assert_eq!(std::fs::read(coursier.join(JAR)).unwrap(), ORIGINAL);
}

/// Classifier variants of one GAV in two caches: `~/.m2` holds only the
/// plain jar, the Coursier copy the `tests` classifier jar too. Each copy
/// narrows its variants on its own bytes, so rollback restores the
/// classifier jar in the Coursier cache (it is never narrowed away by the
/// `~/.m2` copy that lacks it) and the manifest keeps nothing behind.
#[test]
fn agent_rollback_narrows_classifier_variants_per_copy() {
    const TESTS_JAR: &str = "slf4j-api-1.7.36-tests.jar";
    const TESTS_ORIGINAL: &[u8] = b"PK\x03\x04 pristine slf4j-api tests\n";
    const TESTS_PATCHED: &[u8] = b"PK\x03\x04 socket-patched slf4j-api tests\n";
    let fx = fixture();
    let m2 = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m2.join(JAR), ORIGINAL).unwrap();
    std::fs::write(m2.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    let coursier = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    std::fs::write(coursier.join(TESTS_JAR), TESTS_ORIGINAL).unwrap();
    let record = |uuid: &str, file: &str, before: &[u8], after: &[u8]| {
        serde_json::json!({
            "uuid": uuid,
            "exportedAt": "2026-10-02T00:00:00Z",
            "files": { file: {
                "beforeHash": common::git_sha256(before),
                "afterHash": common::git_sha256(after),
            } },
            "vulnerabilities": {},
            "description": "sbt agent classifier fixture",
            "license": "MIT",
            "tier": "free",
        })
    };
    let manifest = serde_json::json!({ "patches": {
        SLF4J.purl(): record("5b7a0000-0000-4000-8000-000000000001", JAR, ORIGINAL, PATCHED),
        format!("{}?classifier=tests", SLF4J.purl()):
            record("5b7a0000-0000-4000-8000-000000000002", TESTS_JAR, TESTS_ORIGINAL, TESTS_PATCHED),
    } });
    let socket = fx.project.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    for bytes in [ORIGINAL, PATCHED, TESTS_ORIGINAL, TESTS_PATCHED] {
        std::fs::write(socket.join("blobs").join(common::git_sha256(bytes)), bytes).unwrap();
    }

    let (code, env, stderr) = run(&fx, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), PATCHED);
    assert_eq!(std::fs::read(coursier.join(JAR)).unwrap(), PATCHED);
    assert_eq!(
        std::fs::read(coursier.join(TESTS_JAR)).unwrap(),
        TESTS_PATCHED
    );

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    assert_eq!(std::fs::read(m2.join(JAR)).unwrap(), ORIGINAL, "{env}");
    assert_eq!(
        std::fs::read(coursier.join(JAR)).unwrap(),
        ORIGINAL,
        "{env}"
    );
    assert_eq!(
        std::fs::read(coursier.join(TESTS_JAR)).unwrap(),
        TESTS_ORIGINAL,
        "the classifier jar is restored where it lives: {env}"
    );
}

/// `vex -O <doc>` in the fixture's project: the statement count (0 when no
/// document was written) and the envelope.
fn vex_statements(fx: &Fixture, extra: &[(&str, String)]) -> (usize, Value) {
    let doc = fx.project.join("vex.json");
    let _ = std::fs::remove_file(&doc);
    let (_, env, _) = run(
        fx,
        &[
            "vex",
            "-O",
            doc.to_str().unwrap(),
            "--product",
            "pkg:maven/com.example/app@1.0",
            "--offline",
            "--json",
        ],
        extra,
    );
    let statements = std::fs::read(&doc)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|d| d["statements"].as_array().map(Vec::len))
        .unwrap_or(0);
    (statements, env)
}

/// VEX judges every copy an sbt build may load: with `~/.m2`, Coursier and
/// Ivy all patched it attests; one copy put back to its pristine bytes
/// (a re-download, say) withholds the statement.
#[test]
fn agent_vex_rehashes_every_cached_copy() {
    let fx = fixture();
    let m2 = fx.home.m2().join("org/slf4j/slf4j-api/1.7.36");
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m2.join(JAR), ORIGINAL).unwrap();
    std::fs::write(m2.join("slf4j-api-1.7.36.pom"), SLF4J.pom()).unwrap();
    let coursier = write_coursier_artifact(&fx.home.coursier_cache(), CENTRAL, SLF4J, ORIGINAL);
    let ivy = write_ivy_artifact(&fx.home.ivy_home(), SLF4J, ORIGINAL);
    stage_manifest(&fx.project, SLF4J);
    // VEX attests only a record with vulnerability metadata.
    let manifest_path = fx.project.join(".socket/manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["patches"][SLF4J.purl()]["vulnerabilities"] = serde_json::json!({
        "GHSA-5b7a-0000-0001": {
            "cves": ["CVE-2026-0001"], "summary": "s",
            "severity": "high", "description": "d"
        }
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let sbt_opts = (
        "SBT_OPTS",
        format!("-Dsbt.ivy.home={}", fx.home.ivy_home().display()),
    );
    let (code, env, stderr) = run(
        &fx,
        &["apply", "--offline", "--json"],
        std::slice::from_ref(&sbt_opts),
    );
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    let (statements, env) = vex_statements(&fx, std::slice::from_ref(&sbt_opts));
    assert!(statements > 0, "every copy patched: {env}");
    for copy in [coursier.join(JAR), ivy.join(JAR)] {
        std::fs::write(&copy, ORIGINAL).unwrap();
        let (statements, env) = vex_statements(&fx, std::slice::from_ref(&sbt_opts));
        assert_eq!(statements, 0, "{} pristine: {env}", copy.display());
        std::fs::write(&copy, PATCHED).unwrap();
    }
}

/// An Ivy module keeps a sources jar under `srcs/`, beside the `jars/`
/// directory the crawler reports: a `?classifier=sources` record is
/// patched and restored there.
#[test]
fn agent_an_ivy_sources_jar_under_srcs_is_patched_and_restored() {
    const SOURCES_JAR: &str = "slf4j-api-1.7.36-sources.jar";
    const SOURCES_ORIGINAL: &[u8] = b"PK\x03\x04 pristine slf4j-api sources\n";
    const SOURCES_PATCHED: &[u8] = b"PK\x03\x04 socket-patched slf4j-api sources\n";
    let fx = fixture();
    let jars = write_ivy_artifact(&fx.home.ivy_home(), SLF4J, ORIGINAL);
    let srcs = jars.parent().unwrap().join("srcs");
    std::fs::create_dir_all(&srcs).unwrap();
    std::fs::write(srcs.join(SOURCES_JAR), SOURCES_ORIGINAL).unwrap();
    let record = |uuid: &str, file: &str, before: &[u8], after: &[u8]| {
        serde_json::json!({
            "uuid": uuid,
            "exportedAt": "2026-10-02T00:00:00Z",
            "files": { file: {
                "beforeHash": common::git_sha256(before),
                "afterHash": common::git_sha256(after),
            } },
            "vulnerabilities": {},
            "description": "sbt agent Ivy sources fixture",
            "license": "MIT",
            "tier": "free",
        })
    };
    let manifest = serde_json::json!({ "patches": {
        SLF4J.purl(): record("5b7a0000-0000-4000-8000-000000000001", JAR, ORIGINAL, PATCHED),
        format!("{}?classifier=sources", SLF4J.purl()): record(
            "5b7a0000-0000-4000-8000-000000000003",
            SOURCES_JAR,
            SOURCES_ORIGINAL,
            SOURCES_PATCHED,
        ),
    } });
    let socket = fx.project.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    for bytes in [ORIGINAL, PATCHED, SOURCES_ORIGINAL, SOURCES_PATCHED] {
        std::fs::write(socket.join("blobs").join(common::git_sha256(bytes)), bytes).unwrap();
    }
    let sbt_opts = (
        "SBT_OPTS",
        format!("-Dsbt.ivy.home={}", fx.home.ivy_home().display()),
    );

    let (code, env, stderr) = run(
        &fx,
        &["apply", "--offline", "--json"],
        std::slice::from_ref(&sbt_opts),
    );
    assert_eq!(code, 0, "apply: {env}\n{stderr}");
    assert_eq!(std::fs::read(jars.join(JAR)).unwrap(), PATCHED, "{env}");
    assert_eq!(
        std::fs::read(srcs.join(SOURCES_JAR)).unwrap(),
        SOURCES_PATCHED,
        "{env}"
    );

    let (code, env, stderr) = run(&fx, &["rollback", "--offline", "--json"], &[sbt_opts]);
    assert_eq!(code, 0, "rollback: {env}\n{stderr}");
    assert_eq!(std::fs::read(jars.join(JAR)).unwrap(), ORIGINAL, "{env}");
    assert_eq!(
        std::fs::read(srcs.join(SOURCES_JAR)).unwrap(),
        SOURCES_ORIGINAL,
        "{env}"
    );
}
