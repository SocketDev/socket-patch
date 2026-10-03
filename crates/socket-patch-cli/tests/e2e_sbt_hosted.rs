//! Hermetic hosted sbt (`get <uuid> --mode hosted` / `vex` / `rollback`
//! over an sbt build): the real binary against a wiremock patch API, no
//! sbt, no JVM. Evidence is real sbt output (the committed
//! `tests/fixtures/sbt/evidence/1.9.9/test-compile` tree: a root
//! aggregating `a`, `b`, `c`, where only `b` resolves gson 2.8.9), copied
//! into the project with its records made newer than the build sources.
//!
//! - `hosted_no_evidence_*`: a fresh clone (no `target/`) wires nothing,
//!   warns once and exits 0.
//! - `hosted_grant_*`: with evidence, the grant writes exactly
//!   `socket-patch.sbt` (byte-identical to the core renderer's output for
//!   the pin), confirms the uuid, and a re-run is a no-op.
//! - `hosted_version_conflict_*`: commons-text resolves 1.9 and 1.10.0
//!   across projects, so a 1.9 patch is refused.
//! - `hosted_vex_*`: manifest-less VEX keeps the pin as a reference but
//!   attests it only when post-wiring evidence resolves the pinned version
//!   to the pinned bytes.
//! - `hosted_rollback_*`: `rollback --offline` deletes the file (its only
//!   pin), the downloads stay.
//!
//! Every child gets `sbt_common::SbtHome::isolated_env`, so no developer
//! cache is crawled.

#[path = "common/mod.rs"]
mod common;
#[path = "sbt_common/mod.rs"]
mod sbt_common;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sbt_common::{copy_evidence, record_pinned_resolution, write_sbt_build, Gav, SbtHome};
use socket_patch_core::formats::sbt::owned_file::{
    render, SbtFileMode, SbtLine, SbtOwnedFile, SbtPin, HOSTED_FILE, HOSTED_REPO_REL,
};
use socket_patch_core::patch::redirect::sbt::ResolutionDoc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const TOKEN: &str = "11111111-1111-4111-8111-111111111111";
const UUID: &str = "abcdef12-0000-4000-8000-0000000000a1";
const GROUP: &str = "com.google.code.gson";
const ARTIFACT: &str = "gson";
const BASE: &str = "2.8.9";
const SV: &str = "2.8.9-socket.abcdef12";
const TEXT_UUID: &str = "12345678-0000-4000-8000-0000000000b2";
const JAR: &[u8] = b"PK\x03\x04 patched gson jar";
const POM: &[u8] = b"<project><version>2.8.9-socket.abcdef12</version></project>\n";

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn index_url(uuid: &str) -> String {
    format!("https://patch.socket.dev/patch-registry/maven/{TOKEN}/{uuid}/maven2")
}

/// A wiremock patch API with its own runtime (the CLI runs as a blocking
/// child process on the test thread).
struct Api {
    server: MockServer,
    rt: tokio::runtime::Runtime,
}

impl Api {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        Api { server, rt }
    }

    /// The view and the hosted reference grant for one Maven patch.
    fn grant(&self, uuid: &str, group: &str, artifact: &str, base: &str) {
        let purl = format!("pkg:maven/{group}/{artifact}@{base}");
        let sv = format!("{base}-socket.{}", &uuid[..8]);
        let url = format!(
            "https://patch.socket.dev/patch/maven/{group}/{artifact}/{base}/{TOKEN}/{uuid}/{artifact}-{sv}.jar"
        );
        let view = serde_json::json!({
            "uuid": uuid, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                format!("{artifact}-{base}.jar"): {
                    "beforeHash": common::git_sha256(b"before"),
                    "afterHash": common::git_sha256(JAR),
                }
            },
            "vulnerabilities": { "GHSA-sbtt-test-xxxx": {
                "cves": ["CVE-2026-0001"], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "sbt hosted fixture", "license": "MIT", "tier": "free",
        });
        let reference = serde_json::json!({ "results": { uuid: {
            "status": "granted", "url": url, "purl": purl,
            "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": sha256(JAR) } }],
            "registryOverride": {
                "kind": "maven2",
                "indexUrl": index_url(uuid),
                "identifiers": {
                    "name": format!("{group}/{artifact}"), "version": base,
                    "mavenGroupId": group, "mavenArtifactId": artifact,
                    "mavenSuffixedVersion": sv, "mavenPomSha256": sha256(POM),
                }
            }
        } } });
        self.rt.block_on(async {
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(view))
                .mount(&self.server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(reference))
                .mount(&self.server)
                .await;
        });
    }
}

/// `socket-patch <args>` over `project` with the isolated sbt home.
fn socket(home: &SbtHome, project: &Path, args: &[&str]) -> (i32, serde_json::Value, String) {
    let env = home.isolated_env();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (code, stdout, stderr) = common::run_bin_with_env(&common::binary(), project, args, &env);
    // The arguments carry the patch uuid: name the subcommand only, never
    // print the uuid (CodeQL rust/cleartext-logging).
    let sub = args.first().copied().unwrap_or_default();
    let json = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("socket-patch {sub}: not JSON ({e})\n{stdout}\n{stderr}"));
    (code, json, stderr)
}

fn get_hosted(home: &SbtHome, project: &Path, api: &Api, uuid: &str) -> (i32, serde_json::Value) {
    let uri = api.server.uri();
    let (code, json, stderr) = socket(
        home,
        project,
        &[
            "get",
            uuid,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            project.to_str().unwrap(),
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert!(
        code == 0,
        "get --mode hosted exited {code}\n{json}\n{stderr}"
    );
    (code, json)
}

/// The warning codes anywhere in an envelope.
fn codes(json: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if k == "code" || k == "errorCode" {
                        if let Some(s) = v.as_str() {
                            out.push(s.to_string());
                        }
                    }
                    walk(v, out);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    walk(json, &mut out);
    out
}

/// The test-compile evidence build, its records touched newer than every
/// build source (copying sets every mtime to "now", in copy order).
fn evidence_project(tmp: &Path) -> PathBuf {
    let project = tmp.join("project");
    copy_evidence("1.9.9", "test-compile", &project);
    fn touch_records(dir: &Path, in_target: bool, later: SystemTime) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let in_target = in_target || entry.file_name() == "target";
            if entry.file_type().unwrap().is_dir() {
                touch_records(&path, in_target, later);
            } else if in_target {
                let f = std::fs::File::options().write(true).open(&path).unwrap();
                f.set_modified(later).unwrap();
            }
        }
    }
    touch_records(&project, false, SystemTime::now() + Duration::from_secs(60));
    project
}

/// The file the rewriter must write for the gson pin over `project`.
fn expected_file(project: &Path) -> String {
    let doc = socket_patch_core::crawlers::sbt_evidence::distill(project);
    let pin = SbtPin {
        uuid: UUID.into(),
        group: GROUP.into(),
        artifact: ARTIFACT.into(),
        base: BASE.into(),
        sv: SV.into(),
        pom_sha256: sha256(POM),
        jar_sha256: sha256(JAR),
        deps_digest: doc.deps_digest,
        index_url: Some(index_url(UUID)),
    };
    render(&SbtOwnedFile {
        mode: SbtFileMode::Hosted,
        line: SbtLine::Sbt1,
        crlf: false,
        pins: [(UUID.to_string(), pin)].into(),
    })
    .unwrap()
}

#[test]
fn hosted_no_evidence_warns_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = tmp.path().join("project");
    write_sbt_build(
        &project,
        "1.9.9",
        "libraryDependencies += \"com.google.code.gson\" % \"gson\" % \"2.8.9\"\n",
    );
    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);
    let (_, json) = get_hosted(&home, &project, &api, UUID);
    assert!(
        codes(&json).contains(&"redirect_sbt_no_resolution_evidence".to_string()),
        "{json}"
    );
    assert!(!project.join(HOSTED_FILE).exists(), "nothing is wired");
    assert!(!project.join(".socket").exists(), "nothing under .socket/");
}

/// A mixed root (`pom.xml` beside an sbt build): the sbt rewriter refuses
/// (no evidence) while the Maven rewriter pins `pom.xml`. That pom pin is
/// what the run wrote, so the patch is reported redirected, not dropped.
#[test]
fn hosted_mixed_root_confirms_the_pom_pin_when_sbt_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = tmp.path().join("project");
    write_sbt_build(
        &project,
        "1.9.9",
        "libraryDependencies += \"com.google.code.gson\" % \"gson\" % \"2.8.9\"\n",
    );
    std::fs::write(
        project.join("pom.xml"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>dev.socket.test</groupId>\n  \
         <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    \
         <dependency>\n      <groupId>com.google.code.gson</groupId>\n      \
         <artifactId>gson</artifactId>\n      <version>2.8.9</version>\n    </dependency>\n  \
         </dependencies>\n</project>\n",
    )
    .unwrap();
    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);
    let (_, json) = get_hosted(&home, &project, &api, UUID);
    assert!(
        codes(&json).contains(&"redirect_sbt_no_resolution_evidence".to_string()),
        "{json}"
    );
    assert!(
        !project.join(HOSTED_FILE).exists(),
        "the sbt build is not wired"
    );
    let pom = std::fs::read_to_string(project.join("pom.xml")).unwrap();
    assert!(pom.contains(SV), "{pom}");
    assert_eq!(json["redirect"]["redirected"], 1, "{json}");
}

#[test]
fn hosted_grant_writes_the_owned_file_and_reruns_idempotently() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = evidence_project(tmp.path());
    let build_sbt = std::fs::read(project.join("build.sbt")).unwrap();
    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);

    let (_, json) = get_hosted(&home, &project, &api, UUID);
    let written = std::fs::read_to_string(project.join(HOSTED_FILE))
        .unwrap_or_else(|e| panic!("socket-patch.sbt not written ({e}): {json}"));
    assert_eq!(written, expected_file(&project));
    assert_eq!(std::fs::read(project.join("build.sbt")).unwrap(), build_sbt);
    assert!(
        !project.join(".socket").exists(),
        "hosted writes only socket-patch.sbt (sbt downloads at load)"
    );
    let redirect = &json["redirect"];
    assert_eq!(redirect["redirected"], 1, "{json}");
    assert!(
        redirect["rewrittenFiles"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f == HOSTED_FILE)),
        "{json}"
    );

    // Re-run before any `sbt update`: the evidence predates the generated
    // file (the fixture's records were touched into the future, so move
    // the file past them), so the pin is kept and still confirmed.
    std::fs::File::options()
        .write(true)
        .open(project.join(HOSTED_FILE))
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(600))
        .unwrap();
    let (_, again) = get_hosted(&home, &project, &api, UUID);
    assert_eq!(
        std::fs::read_to_string(project.join(HOSTED_FILE)).unwrap(),
        written
    );
    assert_eq!(again["redirect"]["redirected"], 1, "{again}");
}

#[test]
fn hosted_version_conflict_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = evidence_project(tmp.path());
    let api = Api::start();
    api.grant(TEXT_UUID, "org.apache.commons", "commons-text", "1.9");
    let (_, json) = get_hosted(&home, &project, &api, TEXT_UUID);
    assert!(
        codes(&json).contains(&"redirect_sbt_version_conflict".to_string()),
        "{json}"
    );
    assert!(!project.join(HOSTED_FILE).exists());
    assert_eq!(json["redirect"]["redirected"], 0, "{json}");
}

/// A committed `socket-patch.sbt` pinning gson, no evidence of it.
fn committed_project(tmp: &Path) -> PathBuf {
    let project = tmp.join("project");
    write_sbt_build(
        &project,
        "1.9.9",
        "libraryDependencies += \"com.google.code.gson\" % \"gson\" % \"2.8.9\"\n",
    );
    let file = expected_file(&project);
    std::fs::write(project.join(HOSTED_FILE), file).unwrap();
    project
}

fn vex(home: &SbtHome, project: &Path, api_uri: &str) -> (i32, serde_json::Value) {
    let out = project.join("vex.json");
    let (code, json, _) = socket(
        home,
        project,
        &[
            "vex",
            "--cwd",
            project.to_str().unwrap(),
            "--json",
            "--output",
            out.to_str().unwrap(),
            "--product",
            "pkg:maven/dev.socket.test/app@1.0.0",
            "--api-url",
            api_uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    (code, json)
}

#[test]
fn hosted_vex_without_evidence_is_unverified() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = committed_project(tmp.path());
    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);
    let (_, json) = vex(&home, &project, &api.server.uri());
    assert!(
        codes(&json).contains(&"sbt_resolution_unverified".to_string()),
        "{json}"
    );
    let doc = std::fs::read_to_string(project.join("vex.json")).unwrap_or_default();
    assert!(
        !doc.contains("\"not_affected\""),
        "nothing attested without evidence: {doc}"
    );
}

/// What `sbt update` records after wiring: `b` resolves the pinned version,
/// its jar at `jar` (absolute), dated after the generated file.
fn post_update_evidence(project: &Path, jar: &Path) {
    let gav = Gav {
        group: GROUP,
        artifact: ARTIFACT,
        version: BASE,
    };
    let changed = record_pinned_resolution(
        project,
        &[(gav, SV.to_string(), jar.to_path_buf())],
        SystemTime::now() + Duration::from_secs(120),
    );
    assert!(changed > 0, "no record resolved {GROUP}:{ARTIFACT}");
    let doc = ResolutionDoc::parse(
        &socket_patch_core::crawlers::sbt_evidence::distill(project).to_json(),
    )
    .unwrap();
    assert!(
        doc.resolution
            .as_ref()
            .is_some_and(|r| r.versions(GROUP, ARTIFACT) == [SV]),
        "the synthesized evidence must parse: {doc:?}"
    );
}

/// A re-run after `sbt update` re-checks the existing pin on content: the
/// pinned version served from outside the pin repository (Ivy's second
/// checkout reads the first checkout's cached copy) is confirmed when the
/// bytes are the pin's, and `redirect_sbt_resolved_elsewhere` otherwise.
#[test]
fn hosted_rerun_checks_the_pin_by_content_not_location() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = evidence_project(tmp.path());
    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);
    get_hosted(&home, &project, &api, UUID);
    assert_eq!(
        std::fs::read_to_string(project.join(HOSTED_FILE)).unwrap(),
        expected_file(&project)
    );
    let ivy = std::fs::canonicalize(tmp.path())
        .unwrap()
        .join("other-checkout-ivy/cache/com.google.code.gson/gson/jars");
    std::fs::create_dir_all(&ivy).unwrap();
    let jar = ivy.join(format!("gson-{SV}.jar"));
    std::fs::write(&jar, JAR).unwrap();
    post_update_evidence(&project, &jar);

    let (_, json) = get_hosted(&home, &project, &api, UUID);
    assert_eq!(json["redirect"]["redirected"], 1, "{json}");
    assert!(
        !codes(&json).iter().any(|c| c.starts_with("redirect_sbt_")),
        "{json}"
    );

    std::fs::write(&jar, b"other bytes").unwrap();
    let (_, json) = get_hosted(&home, &project, &api, UUID);
    assert!(
        codes(&json).contains(&"redirect_sbt_resolved_elsewhere".to_string()),
        "{json}"
    );
}

#[test]
fn hosted_vex_attests_with_post_wiring_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = evidence_project(tmp.path());
    std::fs::write(project.join(HOSTED_FILE), expected_file(&project)).unwrap();
    // What `sbt update` leaves after wiring: b resolves the pinned version
    // from the pin repository, which holds the pinned bytes.
    let repo = project
        .join(HOSTED_REPO_REL)
        .join("com/google/code/gson/gson")
        .join(SV);
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(format!("gson-{SV}.jar")), JAR).unwrap();
    std::fs::write(repo.join(format!("gson-{SV}.pom")), POM).unwrap();
    post_update_evidence(
        &project,
        &std::fs::canonicalize(&repo)
            .unwrap()
            .join(format!("gson-{SV}.jar")),
    );

    let api = Api::start();
    api.grant(UUID, GROUP, ARTIFACT, BASE);
    let (_, json) = vex(&home, &project, &api.server.uri());
    assert!(
        !codes(&json).contains(&"sbt_resolution_unverified".to_string()),
        "{json}"
    );
    let vex = std::fs::read_to_string(project.join("vex.json")).unwrap();
    assert!(vex.contains(UUID) || vex.contains("gson"), "{vex}");
}

#[test]
fn hosted_rollback_deletes_the_owned_file_offline() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let project = committed_project(tmp.path());
    let build_sbt = std::fs::read(project.join("build.sbt")).unwrap();
    // The downloads sbt made at load stay (gitignored, inert).
    let download = project.join(HOSTED_REPO_REL).join("x.jar");
    std::fs::create_dir_all(download.parent().unwrap()).unwrap();
    std::fs::write(&download, b"x").unwrap();
    let (code, json, stderr) = socket(
        &home,
        &project,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            project.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{json}\n{stderr}");
    assert!(!project.join(HOSTED_FILE).exists(), "{json}");
    assert_eq!(std::fs::read(project.join("build.sbt")).unwrap(), build_sbt);
    assert!(download.exists());
}
