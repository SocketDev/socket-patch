//! Real-sbt hosted capstones (`sbt_hosted_*`): the real binary wires a
//! real sbt build through `socket-patch.sbt`, and sbt itself proves the
//! wiring patches, fails closed and unwinds.
//!
//! The fixture (`sbt_build_common`) is a Java-only build over a local
//! `file:` repository: the root aggregates `a` (and, per test, more
//! projects); the root depends on `top:1.0.0`, which depends on
//! `lib:1.0.0` (so the root reaches `lib` only transitively), and `a`
//! depends on `lib:1.0.0` directly. The patch replaces `lib:1.0.0`; a
//! wiremock stand-in serves the patch API and the hosted maven2
//! repository at the production-shaped
//! `/patch-registry/maven/<token>/<uuid>/maven2` path.
//!
//! Every test first runs `sbt update` (the resolution evidence the hosted
//! gate reads), then `get <uuid> --mode hosted`, then drives sbt again.
//!
//! `#[ignore]`: needs sbt (see `sbt_build_common` for the
//! `SOCKET_PATCH_SBT_E2E_*` selection, including running sbt in docker).

#[path = "common/mod.rs"]
mod common;
#[path = "sbt_build_common/mod.rs"]
mod sbt_build_common;

use std::path::{Path, PathBuf};

use common::envelope::all_codes;
use sbt_build_common::*;
use socket_patch_core::formats::sbt::owned_file::{HOSTED_FILE, HOSTED_REPO_REL};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SUITE: &str = "e2e_sbt_build";
const ORG: &str = "test-org";
const TOKEN: &str = "11111111-1111-4111-8111-111111111111";
const UUID: &str = "5b6c7d8e-0000-4000-8000-0000000000c1";
const UUID2: &str = "9a8b7c6d-0000-4000-8000-0000000000c2";
const UUID_UTIL: &str = "4e3d2c1b-0000-4000-8000-0000000000c3";
const BASE: &str = "1.0.0";

fn sv(uuid: &str, base: &str) -> String {
    format!("{base}-socket.{}", &uuid[..8])
}

/// The patch-server stand-in, on its own runtime.
struct Server {
    server: MockServer,
    rt: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // Docker reaches the host's loopback through host.docker.internal.
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let server = rt.block_on(MockServer::builder().listener(listener).start());
        Server { server, rt }
    }

    fn port(&self) -> u16 {
        self.server.address().port()
    }

    fn api(&self) -> String {
        format!("http://127.0.0.1:{}", self.port())
    }

    /// The origin sbt fetches pins from (and the CLI's `--patch-server-url`).
    fn origin(&self, sbt: &Sbt) -> String {
        format!("http://{}:{}", sbt.host_from_sbt(), self.port())
    }

    fn reset(&self) {
        self.rt.block_on(self.server.reset());
    }

    fn mount(&self, m: Mock) {
        self.rt.block_on(m.mount(&self.server));
    }

    /// Grant `uuid` for `artifact:base`, serving `jar` (and the suffixed
    /// pom) from the hosted repository.
    fn grant(&self, sbt: &Sbt, uuid: &str, artifact: &str, base: &str, jar: &[u8], served: &[u8]) {
        let purl = format!("pkg:maven/{GROUP}/{artifact}@{base}");
        let sv = sv(uuid, base);
        let repo = format!("/patch-registry/maven/{TOKEN}/{uuid}/maven2");
        let index = format!("{}{repo}", self.origin(sbt));
        let rel = format!(
            "{}/{artifact}/{sv}/{artifact}-{sv}",
            GROUP.replace('.', "/")
        );
        let pom = pom(artifact, &sv, &[]);
        self.mount(
            Mock::given(method("GET"))
                .and(path(format!("{repo}/{rel}.jar")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(served.to_vec())),
        );
        self.mount(
            Mock::given(method("GET"))
                .and(path(format!("{repo}/{rel}.pom")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(pom.clone().into_bytes())),
        );
        let url = format!("{index}/{rel}.jar");
        let view = serde_json::json!({
            "uuid": uuid, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
            "files": { format!("{artifact}-{base}.jar"): {
                "beforeHash": common::git_sha256(&jar_bytes("ORIGINAL")),
                "afterHash": common::git_sha256(jar),
            } },
            "vulnerabilities": { "GHSA-sbtb-uild-xxxx": {
                "cves": ["CVE-2026-0002"], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "sbt capstone", "license": "MIT", "tier": "free",
        });
        self.mount(
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(view)),
        );
        self.mount(
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .and(wiremock::matchers::body_string_contains(uuid))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { uuid: {
                        "status": "granted", "url": url, "purl": purl,
                        "artifacts": [{ "kind": "tarball", "url": url,
                            "integrity": { "sha256": sha256(jar) } }],
                        "registryOverride": { "kind": "maven2", "indexUrl": index,
                            "identifiers": {
                                "name": format!("{GROUP}/{artifact}"), "version": base,
                                "mavenGroupId": GROUP, "mavenArtifactId": artifact,
                                "mavenSuffixedVersion": sv, "mavenPomSha256": sha256(pom.as_bytes()),
                            } }
                    } }
                }))),
        );
    }
}

fn jar_bytes(marker: &str) -> Vec<u8> {
    jar(marker)
}

/// `socket-patch <args>` (JSON envelope) with the caches pinned into `ws`.
fn socket(ws: &Workspace, args: &[&str]) -> (i32, serde_json::Value, String) {
    let home = ws.root.join("home");
    let cs = ws.coursier_cache();
    let m2 = home.join(".m2/repository");
    let env = [
        ("HOME", home.to_str().unwrap()),
        ("COURSIER_CACHE", cs.to_str().unwrap()),
        ("MAVEN_REPO_LOCAL", m2.to_str().unwrap()),
        ("SBT_OPTS", ""),
        ("JAVA_OPTS", ""),
    ];
    let (code, stdout, stderr) =
        common::run_bin_with_env(&common::binary(), &ws.project, args, &env);
    let json = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
    (code, json, format!("{stdout}\n{stderr}"))
}

fn get_hosted(ws: &Workspace, server: &Server, uuid: &str) -> serde_json::Value {
    let api = server.api();
    let (code, json, out) = socket(
        ws,
        &[
            "get",
            uuid,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            ws.project.to_str().unwrap(),
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(code, 0, "get --mode hosted:\n{out}");
    json
}

/// The standard fixture: `top` → `lib`, the root on `top`, `a` on `lib`,
/// plus `projects` / `extra` build lines; `sbt update` run.
fn fixture(sbt: &Sbt, extra_projects: &[ProjectSpec<'_>], extra: &str) -> Workspace {
    let ws = Workspace::new(sbt);
    ws.publish("lib", BASE, "ORIGINAL", &[]);
    ws.publish("lib", "1.1.0", "NEWER", &[]);
    ws.publish("top", "1.0.0", "TOP", &[("lib", BASE)]);
    ws.publish("util", "1.0.0", "UTIL", &[]);
    ws.publish("other", "1.0.0", "OTHER", &[]);
    let mut projects: Vec<ProjectSpec<'_>> = vec![
        ("root", ".", &[("top", "1.0.0")]),
        ("a", "a", &[("lib", BASE)]),
    ];
    projects.extend_from_slice(extra_projects);
    ws.write("build.sbt", &build_sbt(sbt, &ws, &projects, extra));
    ws.write(
        "project/build.properties",
        &format!("sbt.version={}\n", sbt.version),
    );
    sbt.run(&ws, &["update"]).expect_ok("initial sbt update");
    ws
}

/// The resolved `lib` jars of `projects`' compile classpaths.
fn lib_jars(sbt: &Sbt, ws: &Workspace, projects: &[&str]) -> Vec<std::path::PathBuf> {
    let tasks: Vec<String> = projects
        .iter()
        .map(|p| format!("export {}", sbt.classpath_task(p)))
        .collect();
    let tasks: Vec<&str> = tasks.iter().map(String::as_str).collect();
    let run = sbt.run(ws, &tasks);
    run.expect_ok("export classpath");
    let jars: Vec<std::path::PathBuf> = run
        .classpath_jars_in(ws)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("lib-"))
        })
        .collect();
    assert!(
        !jars.is_empty(),
        "lib not on the classpath:\n{}",
        run.output
    );
    jars
}

fn patched() -> Vec<u8> {
    jar_bytes("PATCHED")
}

/// Wire the standard fixture's `lib` patch; `(sbt, ws, server)` back.
fn wired(extra: &str) -> Option<(Sbt, Workspace, Server)> {
    let sbt = Sbt::detect(SUITE)?;
    let ws = fixture(&sbt, &[], extra);
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        ws.project.join(HOSTED_FILE).is_file(),
        "socket-patch.sbt not written: {json}"
    );
    assert_eq!(json["redirect"]["redirected"], 1, "{json}");
    Some((sbt, ws, server))
}

fn assert_patched(sbt: &Sbt, ws: &Workspace) {
    let jars = lib_jars(sbt, ws, &["root", "a"]);
    assert!(!jars.is_empty(), "lib not on the classpath");
    for jar in &jars {
        let name = jar.file_name().unwrap().to_string_lossy();
        assert_eq!(name, format!("lib-{}.jar", sv(UUID, BASE)), "{jar:?}");
        assert!(
            jar.starts_with(ws.project.join(HOSTED_REPO_REL)),
            "resolved from the pin repository: {jar:?}"
        );
        assert_eq!(std::fs::read(jar).unwrap(), patched(), "{jar:?}");
    }
}

fn pin_repo_jar(ws: &Workspace, uuid: &str) -> std::path::PathBuf {
    let sv = sv(uuid, BASE);
    ws.project
        .join(HOSTED_REPO_REL)
        .join(GROUP.replace('.', "/"))
        .join("lib")
        .join(&sv)
        .join(format!("lib-{sv}.jar"))
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_pins_transitive_fail_closed() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    // The root reaches lib only through top; both projects get the pin.
    assert_patched(&sbt, &ws);
    let gitignore = ws.project.join(".socket/sbt-hosted/.gitignore");
    assert_eq!(std::fs::read_to_string(gitignore).unwrap(), "*\n");
    // A fresh clone with the patch server unreachable fails closed.
    std::fs::remove_dir_all(ws.project.join(".socket")).unwrap();
    server.reset();
    sbt.run(&ws, &["update"])
        .expect_failure("fresh clone, server down", "socket-patch: cannot download");
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_server_tamper_fails_load() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    // Nothing downloaded yet (no load since the wiring): a fresh clone.
    assert!(!ws.project.join(".socket").exists());
    server.reset();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &jar_bytes("EVIL"));
    sbt.run(&ws, &["update"])
        .expect_failure("tampered server", "served sha256");
    assert!(
        !pin_repo_jar(&ws, UUID).exists(),
        "the tampered jar is never kept"
    );
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_cache_tamper_heals() {
    let Some((sbt, ws, _server)) = wired("") else {
        return;
    };
    assert_patched(&sbt, &ws);
    std::fs::write(pin_repo_jar(&ws, UUID), jar_bytes("EVIL")).unwrap();
    // The load-time check re-downloads the pinned bytes.
    assert_patched(&sbt, &ws);
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_rollback_restores_without_clean() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    assert_patched(&sbt, &ws);
    let origin = server.origin(&sbt);
    let (code, json, out) = socket(
        &ws,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            ws.project.to_str().unwrap(),
            "--patch-server-url",
            &origin,
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(!ws.project.join(HOSTED_FILE).exists(), "{json}");
    let jars = lib_jars(&sbt, &ws, &["root", "a"]);
    assert!(!jars.is_empty());
    for jar in jars {
        assert_eq!(
            std::fs::read(&jar).unwrap(),
            jar_bytes("ORIGINAL"),
            "{jar:?}"
        );
    }
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_no_evidence_noop() {
    let Some(sbt) = Sbt::detect(SUITE) else {
        return;
    };
    let ws = Workspace::new(&sbt);
    ws.publish("lib", BASE, "ORIGINAL", &[]);
    ws.write(
        "build.sbt",
        &build_sbt(&sbt, &ws, &[("root", ".", &[("lib", BASE)])], ""),
    );
    ws.write(
        "project/build.properties",
        &format!("sbt.version={}\n", sbt.version),
    );
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        all_codes(&json).contains(&"redirect_sbt_no_resolution_evidence".to_string()),
        "{json}"
    );
    assert!(!ws.project.join(HOSTED_FILE).exists());
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_version_conflict_refused() {
    let Some(sbt) = Sbt::detect(SUITE) else {
        return;
    };
    let ws = fixture(&sbt, &[("b", "b", &[("lib", "1.1.0")])], "");
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        all_codes(&json).contains(&"redirect_sbt_version_conflict".to_string()),
        "{json}"
    );
    assert!(!ws.project.join(HOSTED_FILE).exists());
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_zz_override_assignment_refused() {
    let Some(sbt) = Sbt::detect(SUITE) else {
        return;
    };
    let ws = fixture(&sbt, &[], "");
    let line = if sbt.line() == "0.13" {
        "dependencyOverrides in ThisBuild := Set.empty\n"
    } else {
        "ThisBuild / dependencyOverrides := Seq.empty\n"
    };
    ws.write("zz.sbt", line);
    sbt.run(&ws, &["update"]).expect_ok("update with zz.sbt");
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        all_codes(&json).contains(&"redirect_sbt_overrides_assignment".to_string()),
        "{json}"
    );
    assert!(!ws.project.join(HOSTED_FILE).exists());
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_shadow_at_load_fails() {
    let Some((sbt, ws, _server)) = wired("") else {
        return;
    };
    let line = if sbt.line() == "0.13" {
        format!("\ndependencyOverrides in a := Set(\"{GROUP}\" % \"lib\" % \"{BASE}\")\n")
    } else {
        format!("\na / dependencyOverrides := Seq(\"{GROUP}\" % \"lib\" % \"{BASE}\")\n")
    };
    let build = std::fs::read_to_string(ws.project.join("build.sbt")).unwrap();
    ws.write("build.sbt", &format!("{build}{line}"));
    sbt.run(&ws, &["update"])
        .expect_failure("user override after wiring", "socket-patch:");
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_vex_attests_after_update() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    let origin = server.origin(&sbt);
    let api = server.api();
    let vex_path = ws.root.join("vex.json");
    let vex = |what: &str| {
        let (code, json, out) = socket(
            &ws,
            &[
                "vex",
                "--json",
                "--cwd",
                ws.project.to_str().unwrap(),
                "--output",
                vex_path.to_str().unwrap(),
                "--product",
                "pkg:maven/dev.socket.test/app@1.0.0",
                "--patch-server-url",
                &origin,
                "--api-url",
                &api,
                "--org",
                ORG,
                "--api-token",
                "fake",
            ],
        );
        eprintln!("{what}: vex exit {code}");
        (code, json, out)
    };
    // Before the post-wiring update: the pin is not verified.
    let (_, json, _) = vex("before update");
    assert!(
        all_codes(&json).contains(&"sbt_resolution_unverified".to_string()),
        "{json}"
    );
    sbt.run(&ws, &["update"]).expect_ok("post-wiring update");
    let (code, json, out) = vex("after update");
    assert!(
        !all_codes(&json).contains(&"sbt_resolution_unverified".to_string()),
        "{out}"
    );
    assert_eq!(code, 0, "{out}");
    let doc = std::fs::read_to_string(&vex_path).unwrap();
    assert!(
        doc.contains("pkg:maven/dev.socket.fixture/lib@1.0.0"),
        "{doc}"
    );
}

/// A dependency edit after wiring: until sbt resolves again the pin is
/// unverifiable; after `sbt update` a re-run re-verifies it against the new
/// evidence and records the build's new dependency digest, so the warning
/// clears.
#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_dep_edit_rechecks_after_update() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    sbt.run(&ws, &["update"]).expect_ok("post-wiring update");
    // Past the evidence's mtime granularity (a bind mount may keep whole
    // seconds), so the edit is newer than every record.
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let build = std::fs::read_to_string(ws.project.join("build.sbt")).unwrap();
    ws.write(
        "build.sbt",
        &build.replace(
            &format!("\"{GROUP}\" % \"top\" % \"1.0.0\""),
            &format!("\"{GROUP}\" % \"top\" % \"1.0.0\", \"{GROUP}\" % \"other\" % \"1.0.0\""),
        ),
    );
    let before = std::fs::read(ws.project.join(HOSTED_FILE)).unwrap();
    // Edited, not resolved yet.
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        all_codes(&json).contains(&"redirect_sbt_pin_unverifiable".to_string()),
        "{json}"
    );
    assert_eq!(std::fs::read(ws.project.join(HOSTED_FILE)).unwrap(), before);
    sbt.run(&ws, &["update"]).expect_ok("update after the edit");
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        !all_codes(&json).contains(&"redirect_sbt_pin_unverifiable".to_string()),
        "{json}"
    );
    assert_eq!(json["redirect"]["redirected"], 1, "{json}");
    let after = std::fs::read(ws.project.join(HOSTED_FILE)).unwrap();
    assert_ne!(after, before, "the row's digest is refreshed");
    // ...and the next run is quiet.
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        !all_codes(&json).contains(&"redirect_sbt_pin_unverifiable".to_string()),
        "{json}"
    );
    assert_eq!(std::fs::read(ws.project.join(HOSTED_FILE)).unwrap(), after);
    assert_patched(&sbt, &ws);
}

/// A project that now declares the pinned GA newer than the patch's base
/// (a developer or Scala Steward bump): the build-wide override would force
/// it back down, so the load-time check fails `update` and a re-run
/// refuses the pin.
#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_declared_bump_fails_closed() {
    let Some((sbt, ws, server)) = wired("") else {
        return;
    };
    assert_patched(&sbt, &ws);
    let build = std::fs::read_to_string(ws.project.join("build.sbt")).unwrap();
    let bumped = build.replace(
        &format!("\"{GROUP}\" % \"lib\" % \"{BASE}\""),
        &format!("\"{GROUP}\" % \"lib\" % \"1.1.0\""),
    );
    assert_ne!(bumped, build);
    ws.write("build.sbt", &bumped);
    sbt.run(&ws, &["update"])
        .expect_failure("declared bump", "declares dev.socket.fixture:lib:1.1.0");
    let json = get_hosted(&ws, &server, UUID);
    assert!(
        all_codes(&json).contains(&"redirect_sbt_pin_declared_newer".to_string()),
        "{json}"
    );
    assert_eq!(json["redirect"]["redirected"], 0, "{json}");
    // Declaring the base again is fine.
    ws.write("build.sbt", &build);
    assert_patched(&sbt, &ws);
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_two_patches_and_update_uuid() {
    let Some(sbt) = Sbt::detect(SUITE) else {
        return;
    };
    let ws = fixture(&sbt, &[("u", "u", &[("util", "1.0.0")])], "");
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    server.grant(
        &sbt,
        UUID_UTIL,
        "util",
        "1.0.0",
        &jar_bytes("UTILP"),
        &jar_bytes("UTILP"),
    );
    get_hosted(&ws, &server, UUID);
    get_hosted(&ws, &server, UUID_UTIL);
    let file = std::fs::read_to_string(ws.project.join(HOSTED_FILE)).unwrap();
    assert!(file.contains(UUID) && file.contains(UUID_UTIL), "{file}");
    assert_patched(&sbt, &ws);
    // A newer patch for lib at the same base replaces the old pin.
    server.grant(
        &sbt,
        UUID2,
        "lib",
        BASE,
        &jar_bytes("PATCHED2"),
        &jar_bytes("PATCHED2"),
    );
    sbt.run(&ws, &["update"]).expect_ok("post-wiring update");
    let json = get_hosted(&ws, &server, UUID2);
    assert!(
        json.to_string().contains("redirect_sbt_pin_updated")
            || std::fs::read_to_string(ws.project.join(HOSTED_FILE))
                .unwrap()
                .contains(UUID2),
        "{json}"
    );
    let file = std::fs::read_to_string(ws.project.join(HOSTED_FILE)).unwrap();
    assert!(
        !file.contains(UUID) && file.contains(UUID2) && file.contains(UUID_UTIL),
        "{file}"
    );
    let jars = lib_jars(&sbt, &ws, &["a"]);
    assert_eq!(
        jars.iter()
            .map(|j| std::fs::read(j).unwrap())
            .collect::<Vec<_>>(),
        [jar_bytes("PATCHED2")]
    );
}

/// An evil `lib:<sv>` in the `mavenLocal` sbt reads in `ws`.
fn poison_maven_local(ws: &Workspace, sv: &str) {
    let dir = ws
        .maven_local()
        .join(GROUP.replace('.', "/"))
        .join("lib")
        .join(sv);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("lib-{sv}.jar")), jar_bytes("EVIL")).unwrap();
    std::fs::write(dir.join(format!("lib-{sv}.pom")), pom("lib", sv, &[])).unwrap();
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_maven_local_poison_fails() {
    let line = |sbt: &Sbt| {
        if sbt.line() == "0.13" {
            "resolvers in ThisBuild += Resolver.mavenLocal\n"
        } else {
            "ThisBuild / resolvers += Resolver.mavenLocal\n"
        }
    };
    let Some(sbt) = Sbt::detect(SUITE) else {
        return;
    };
    let extra = line(&sbt);
    let sv = sv(UUID, BASE);
    // Control: without socket-patch.sbt, a build depending on the suffixed
    // GAV resolves the poisoned bytes, so the poison sits where this sbt
    // reads mavenLocal (the test could otherwise pass vacuously).
    let control = Workspace::new(&sbt);
    poison_maven_local(&control, &sv);
    control.write(
        "build.sbt",
        &build_sbt(&sbt, &control, &[("root", ".", &[("lib", &sv)])], extra),
    );
    control.write(
        "project/build.properties",
        &format!("sbt.version={}\n", sbt.version),
    );
    let jars = lib_jars(&sbt, &control, &["root"]);
    assert_eq!(
        jars.iter()
            .map(|j| std::fs::read(j).unwrap())
            .collect::<Vec<_>>(),
        [jar_bytes("EVIL")],
        "the control resolves mavenLocal's copy: {jars:?}"
    );

    let ws = fixture(&sbt, &[], extra);
    let server = Server::start();
    server.grant(&sbt, UUID, "lib", BASE, &patched(), &patched());
    get_hosted(&ws, &server, UUID);
    // X3: an evil copy of the suffixed GAV in mavenLocal.
    poison_maven_local(&ws, &sv);
    let run = sbt.run(&ws, &["update"]);
    if run.ok() {
        // Our resolver won: the evil copy was never used, so the bytes
        // must be the pinned ones.
        assert_patched(&sbt, &ws);
    } else {
        run.expect_failure("mavenLocal poison", "which is not pinned");
    }
}

#[test]
#[ignore = "real sbt; run with --ignored (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_hosted_ivy_local_poison_fails() {
    let Some((sbt, ws, _server)) = wired("") else {
        return;
    };
    // X4: an evil suffixed GAV published to ~/.ivy2/local (first in sbt's
    // default resolver chain).
    let sv = sv(UUID, BASE);
    let dir = ws
        .ivy_home()
        .join("local")
        .join(GROUP)
        .join("lib")
        .join(&sv);
    std::fs::create_dir_all(dir.join("jars")).unwrap();
    std::fs::create_dir_all(dir.join("ivys")).unwrap();
    std::fs::write(dir.join("jars/lib.jar"), jar_bytes("EVIL")).unwrap();
    std::fs::write(
        dir.join("ivys/ivy.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ivy-module version=\"2.0\">\
             <info organisation=\"{GROUP}\" module=\"lib\" revision=\"{sv}\" status=\"release\"/>\
             <configurations><conf name=\"compile\"/><conf name=\"default\" extends=\"compile\"/></configurations>\
             <publications><artifact name=\"lib\" type=\"jar\" ext=\"jar\" conf=\"compile\"/></publications>\
             </ivy-module>\n"
        ),
    )
    .unwrap();
    std::fs::remove_dir_all(ws.project.join(".socket")).ok();
    let run = sbt.run(&ws, &["update"]);
    if run.ok() {
        assert_patched(&sbt, &ws);
    } else {
        run.expect_failure("ivy-local poison", "which is not pinned");
    }
}

/// The driver's own pieces, without sbt.
#[test]
fn sbt_build_common_writes_a_resolvable_fixture() {
    let sbt = Sbt {
        runner: Runner::Native { sbt: "sbt".into() },
        version: "1.13.0".into(),
        seed: None,
    };
    let ws = Workspace::new(&sbt);
    ws.publish("lib", BASE, "ORIGINAL", &[("x", "1")]);
    let dir = ws.central.join("dev/socket/fixture/lib/1.0.0");
    let jar = std::fs::read(dir.join("lib-1.0.0.jar")).unwrap();
    assert_eq!(&jar[..2], b"PK");
    assert_eq!(jar, jar_bytes("ORIGINAL"), "deterministic jars");
    assert!(std::fs::read_to_string(dir.join("lib-1.0.0.pom"))
        .unwrap()
        .contains("<artifactId>x</artifactId>"));
    let text = build_sbt(
        &sbt,
        &ws,
        &[("root", ".", &[("top", "1.0.0")]), ("a", "a", &[])],
        "",
    );
    assert!(text.contains(".aggregate(a)") && text.contains("autoScalaLibrary := false"));
    assert!(ws.root.is_absolute() && Path::new(&ws.root).exists());
    // This OS's absolute spelling and classpath separator.
    let (d, sep) = if cfg!(windows) {
        ("C:", ";")
    } else {
        ("", ":")
    };
    assert_eq!(
        SbtRun {
            code: Some(0),
            output: format!("[info] x\n{d}/a/b/lib-1.0.0.jar{sep}{d}/c/top-1.0.0.jar\n"),
            commands: vec![],
        }
        .classpath_jars()
        .len(),
        2
    );
    assert_eq!(
        SbtRun {
            code: Some(0),
            output: format!("List({d}/a/lib-1.0.0.jar, {d}/c/top-1.0.0.jar)\n"),
            commands: vec![],
        }
        .classpath_jars(),
        [
            PathBuf::from(format!("{d}/a/lib-1.0.0.jar")),
            PathBuf::from(format!("{d}/c/top-1.0.0.jar"))
        ]
    );
    let base = SbtRun {
        code: Some(0),
        output: "List(${BASE}/.socket/x/lib-1.jar, ${CSR_CACHE}/https/h/top-1.0.0.jar)\n".into(),
        commands: vec![],
    }
    .classpath_jars_in(&ws);
    assert_eq!(
        base,
        [
            ws.project.join(".socket/x/lib-1.jar"),
            ws.coursier_cache().join("https/h/top-1.0.0.jar")
        ]
    );
}
