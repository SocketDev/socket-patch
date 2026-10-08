//! Hosted mode (`scan --mode hosted`) against real Gradle: Gradle resolves
//! the deterministic fake Central (`jvm_fixture_repo`), `socket-patch`
//! wires the owned hosted settings script, its index and the lock files,
//! and every assertion is on the bytes Gradle then CONSUMES (the
//! `printRuntimeClasspath` marker task's jar), never only the CLI's report.
//!
//! The Socket repository is served by the same fake Central under the
//! production path (`/patch-registry/maven/<token>/<uuid>/maven2/…`): the
//! test-only mirror init script maps `https://patch.socket.dev/…` (what the
//! committed index names) onto it, and every other repository onto the
//! fake Central. The suffixed artifacts are the patched jar, the upstream
//! pom re-versioned to the suffixed version and — like the patch service
//! (depscan) — the upstream `.module` with its component version and jar
//! file entry rewritten to the suffixed, patched jar.
//!
//! Every test is `#[ignore]` and prefixed `gradle_hosted_` (the CI filter
//! contract, `scripts/ci-e2e-bundle.py`), and runs both DSLs unless the
//! case is DSL-specific; toolchain selection is `gradle_build_common`'s
//! `SOCKET_PATCH_GRADLE_E2E_*` knobs.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "gradle_build_common/mod.rs"]
mod gradle_build_common;

#[path = "jvm_fixture_repo/mod.rs"]
mod jvm_fixture_repo;

#[path = "hosted_maven_common/mod.rs"]
mod hosted_maven_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use gradle_build_common::{
    configuration_reused, dump, fixture_root, for_each_dsl, gradle_classpath, init_script,
    jar_member, lockfiles, mirror_init_script, ok, print_cp_task, probe_report, snapshot, Dsl,
    Gradle,
};
use hosted_maven_common::{Hosted, Server};
use jvm_fixture_repo::{
    md5_hex, notice, repo_path, sha1_hex, sha256_hex, sha512_hex, victim_class, FakeCentral,
    CONSUMER, CONSUMER_RANGE, CONSUMER_VERSION, GROUP, NOTICE, VICTIM, VICTIM_CLASS_MEMBER,
    VICTIM_OLD, VICTIM_VERSION,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SUITE: &str = "e2e_redirect_gradle_build";
const ORG: &str = "test-org";
const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
const HEX8: &str = "4d5e6f70";
const TOKEN: &str = "22222222-3333-4444-8555-666666666666";
const GHSA: &str = "GHSA-gr4d-h057-0347";
const CVE: &str = "CVE-2026-0347";
const PRODUCT: &str = "pkg:maven/com.example/app@1.0";
const SCRIPT_REL: &str = ".socket/gradle/socket-patch.hosted.settings.gradle";
const INDEX_REL: &str = ".socket/gradle/hosted-index.tsv";

const HOSTED: Hosted = Hosted {
    org: ORG,
    uuid: UUID,
    hex8: HEX8,
    token: TOKEN,
    ghsa: GHSA,
    cve: CVE,
    group: GROUP,
    artifact: VICTIM,
    version: VICTIM_VERSION,
    title: "gradle hosted e2e",
};

fn sfx() -> String {
    HOSTED.suffixed()
}

fn coordinate() -> String {
    format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}")
}

fn purl() -> String {
    jvm_fixture_repo::victim_purl(VICTIM_VERSION)
}

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

fn central_file(path: &str) -> Vec<u8> {
    jvm_fixture_repo::repository()
        .remove(path)
        .unwrap_or_else(|| panic!("the fixture serves no {path}"))
}

fn pristine_jar() -> Vec<u8> {
    central_file(&repo_path(VICTIM, VICTIM_VERSION, None, "jar"))
}

fn pristine_notice() -> Vec<u8> {
    notice(&coordinate(), "pristine").into_bytes()
}

fn patched_notice() -> Vec<u8> {
    notice(&coordinate(), "patched").into_bytes()
}

/// The pristine victim with NOTICE and `Victim.class` patched.
fn patched_jar() -> Vec<u8> {
    use std::io::Read as _;
    let jar = pristine_jar();
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

/// The Socket repository path of the suffixed `ext` (no leading `/`).
fn socket_path(ext: &str) -> String {
    HOSTED.served_path(ext).trim_start_matches('/').to_string()
}

/// The upstream `.module` as the patch service serves it: the suffixed
/// component version, the jar entry renamed to the suffixed jar with its
/// size and digests, and the variants shipping any other file dropped.
fn served_module(jar: &[u8]) -> Vec<u8> {
    let upstream = central_file(&repo_path(VICTIM, VICTIM_VERSION, None, "module"));
    let mut module: serde_json::Value = serde_json::from_slice(&upstream).unwrap();
    module["component"]["version"] = sfx().into();
    let base_jar = format!("{VICTIM}-{VICTIM_VERSION}.jar");
    let sfx_jar = format!("{VICTIM}-{}.jar", sfx());
    let variants: Vec<serde_json::Value> = module["variants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| {
            v["files"]
                .as_array()
                .is_none_or(|fs| fs.iter().all(|f| f["url"] == base_jar.as_str()))
        })
        .cloned()
        .map(|mut v| {
            for f in v["files"].as_array_mut().into_iter().flatten() {
                f["name"] = sfx_jar.clone().into();
                f["url"] = sfx_jar.clone().into();
                f["size"] = jar.len().into();
                f["sha512"] = sha512_hex(jar).into();
                f["sha256"] = sha256_hex(jar).into();
                f["sha1"] = sha1_hex(jar).into();
                f["md5"] = md5_hex(jar).into();
            }
            v
        })
        .collect();
    module["variants"] = variants.into();
    (serde_json::to_string_pretty(&module).unwrap() + "\n").into_bytes()
}

/// What the Socket repository serves for the patch.
struct Served {
    jar: Vec<u8>,
    pom: Vec<u8>,
    /// `None`: the `.module` 404s (a service that predates serving it).
    module: Option<Vec<u8>>,
}

impl Served {
    fn new(module: bool) -> Self {
        let jar = patched_jar();
        let upstream_pom = central_file(&repo_path(VICTIM, VICTIM_VERSION, None, "pom"));
        Served {
            pom: HOSTED.served_pom(&upstream_pom),
            module: module.then(|| served_module(&jar)),
            jar,
        }
    }
}

/// One real-Gradle cell: a project, its own Gradle user home, the fake
/// Central (which also serves the Socket repository) and the fake API.
struct Cell {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    proj: PathBuf,
    home: PathBuf,
    gradle: Gradle,
    central: FakeCentral,
    api: Server,
    init: [String; 2],
    dsl: Dsl,
}

/// Start a cell (`None`: no Gradle, skipped) with the project `files`.
fn cell(dsl: Dsl, files: &[(String, String)]) -> Option<Cell> {
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let home = root.join(".gradle");
    std::fs::create_dir_all(&home).unwrap();
    let gradle = Gradle::detect(SUITE, &home)?;
    let central = FakeCentral::start();
    let init = init_script(
        &root.join("init"),
        "mirror.gradle",
        &mirror_init_script(&central.uri(), Some(&central.uri())),
    );
    let proj = root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(rel, body)| (rel.as_str(), body.as_str()))
        .collect();
    gradle_build_common::write_project(&proj, &borrowed);
    Some(Cell {
        _tmp: tmp,
        root,
        proj,
        home,
        gradle,
        central,
        api: Server::start(),
        init,
        dsl,
    })
}

/// A plain single-project build: `java`, Central, `deps` (dependency
/// notations, one per line, in the DSL's spelling) and the classpath task.
fn single(dsl: Dsl, deps: &[&str], extra: &str) -> Vec<(String, String)> {
    let deps: String = deps.iter().map(|d| format!("    {d}\n")).collect();
    let (settings, build) = match dsl {
        Dsl::Groovy => (
            "rootProject.name = 'app'\n".to_string(),
            format!(
                "plugins {{ id 'java' }}\nrepositories {{ mavenCentral() }}\ndependencies {{\n{deps}}}\n{extra}{}",
                print_cp_task(dsl, "runtimeClasspath")
            ),
        ),
        Dsl::Kotlin => (
            "rootProject.name = \"app\"\n".to_string(),
            format!(
                "plugins {{ java }}\nrepositories {{ mavenCentral() }}\ndependencies {{\n{deps}}}\n{extra}{}",
                print_cp_task(dsl, "runtimeClasspath")
            ),
        ),
    };
    vec![(dsl.settings_file(), settings), (dsl.build_file(), build)]
}

/// `implementation '<notation>'` in the DSL's spelling.
fn implementation(dsl: Dsl, notation: &str) -> String {
    match dsl {
        Dsl::Groovy => format!("implementation '{notation}'"),
        Dsl::Kotlin => format!("implementation(\"{notation}\")"),
    }
}

impl Cell {
    /// Serve the patch: the Socket repository's suffixed files, the grant
    /// (with `mavenModuleSha256` when the `.module` is served) and the
    /// patch view (`files`: `(record key, after bytes)`).
    fn serve(&self, served: &Served, files: &[(String, Vec<u8>)]) {
        self.central.put(&socket_path("jar"), &served.jar);
        self.central.put(&socket_path("pom"), &served.pom);
        match &served.module {
            Some(m) => self.central.put(&socket_path("module"), m),
            None => self.central.remove(&socket_path("module")),
        }
        mount_api(&self.api, served, files);
    }

    /// The leaf record: the whole jar.
    fn serve_leaf(&self, served: &Served) {
        let key = format!("{VICTIM}-{VICTIM_VERSION}.jar");
        self.serve(served, &[(key, served.jar.clone())]);
    }

    /// `gradle <task>` with the mirror init script.
    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.proj, args)
    }

    fn run_in(&self, dir: &Path, args: &[&str]) -> Output {
        let mut all: Vec<&str> = vec![&self.init[0], &self.init[1]];
        all.extend_from_slice(args);
        self.gradle.run(dir, &self.home, &all)
    }

    /// `printRuntimeClasspath` (plus `extra` first).
    fn build(&self, extra: &[&str]) -> Output {
        let mut args = extra.to_vec();
        args.push("printRuntimeClasspath");
        self.run(&args)
    }

    /// The victim jar on the classpath of a successful run, and its NOTICE.
    fn victim_on(&self, out: &Output, what: &str) -> (PathBuf, Vec<u8>) {
        assert!(ok(out), "{what}:\n{}", dump(out));
        let cp = gradle_classpath(out);
        let hits: Vec<&PathBuf> = cp
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&format!("{VICTIM}-")) && n.ends_with(".jar"))
            })
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "{what}: one victim jar on {cp:?}\n{}",
            dump(out)
        );
        let bytes = std::fs::read(hits[0]).unwrap();
        (hits[0].clone(), jar_member(&bytes, NOTICE).unwrap())
    }

    /// The build consumes the suffixed, patched victim.
    fn assert_patched(&self, out: &Output, what: &str) -> PathBuf {
        let (jar, got) = self.victim_on(out, what);
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&patched_notice()),
            "{what}: {} is not the patched jar\n{}",
            jar.display(),
            dump(out)
        );
        assert_eq!(
            jar.file_name().unwrap().to_string_lossy(),
            format!("{VICTIM}-{}.jar", sfx()),
            "{what}: the suffixed version resolves"
        );
        jar
    }

    fn assert_pristine(&self, out: &Output, what: &str) {
        let (jar, got) = self.victim_on(out, what);
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&pristine_notice()),
            "{what}: {} is not the pristine jar",
            jar.display()
        );
    }

    /// A failed run that never consumed the unpatched victim.
    fn assert_fails_loud(&self, out: &Output, what: &str) {
        assert!(!ok(out), "{what}: the build must fail:\n{}", dump(out));
        for p in gradle_classpath(out) {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(&format!("{VICTIM}-1")) || name.contains("-socket."),
                "{what}: an unpatched victim was consumed: {name}"
            );
        }
    }

    /// Resolve the project once so the base version is in the cache (the
    /// installed GAV scan finds), consuming the pristine jar.
    fn warm(&self) {
        let out = self.build(&[]);
        self.assert_pristine(&out, "warm (before the scan)");
    }

    /// `socket-patch <args> --json --cwd <dir>` under the cell's Gradle
    /// home, with the fake API.
    fn socket_in(&self, dir: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
        let mut cmd = hermetic::command(Path::new(env!("CARGO_BIN_EXE_socket-patch")));
        prebuilt_common::jvm_env::isolate_cli(&mut cmd);
        cmd.args(args)
            .args(["--json", "--cwd", dir.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("GRADLE_USER_HOME", &self.home)
            .env_remove("M2_HOME");
        let out = cmd.output().expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let json = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{args:?}: not one JSON document ({e})\n{stdout}\n{stderr}")
        });
        (out.status.code(), json, stderr)
    }

    /// `socket-patch vendor …` (or `repair`) with the vendor fixture
    /// server serving the Gradle cache (`prebuilt_common::prepare_command`).
    /// `fixture` is the project the fixture server serves its records
    /// from (the cell's own project when `None`).
    fn vendor_cmd(
        &self,
        fixture: Option<&Path>,
        extra: &[&str],
    ) -> (Option<i32>, serde_json::Value) {
        let mut cmd = hermetic::command(Path::new(env!("CARGO_BIN_EXE_socket-patch")));
        let proj = self.proj.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec!["vendor"];
        args.extend_from_slice(extra);
        args.extend(["--json", "--cwd", &proj]);
        let _fixture = prebuilt_common::prepare_command(
            &mut cmd,
            fixture.unwrap_or(&self.proj),
            &args,
            &[("GRADLE_USER_HOME", self.home.to_str().unwrap())],
        );
        let out = cmd
            .current_dir(&self.proj)
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env_remove("MAVEN_REPO_LOCAL")
            .env_remove("M2_HOME")
            .output()
            .expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let json = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "vendor {extra:?}: not JSON ({e})\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), json)
    }

    fn api_args(&self) -> Vec<String> {
        vec![
            "--api-url".into(),
            self.api.uri(),
            "--org".into(),
            ORG.into(),
            "--api-token".into(),
            "fake".into(),
        ]
    }

    /// `scan --mode hosted --yes` (plus `extra`).
    fn scan_in(&self, dir: &Path, extra: &[&str]) -> (Option<i32>, serde_json::Value) {
        let api = self.api_args();
        let mut args: Vec<&str> = vec!["scan", "--mode", "hosted", "--yes"];
        args.extend(api.iter().map(String::as_str));
        args.extend_from_slice(extra);
        let (code, json, stderr) = self.socket_in(dir, &args);
        let _ = stderr;
        (code, json)
    }

    /// A successful hosted scan that redirected the victim.
    fn scan_ok(&self) -> serde_json::Value {
        let (code, json) = self.scan_in(&self.proj, &[]);
        assert_eq!(code, Some(0), "scan --mode hosted: {json}");
        assert_eq!(json["redirect"]["mode"], "hosted", "{json}");
        assert_eq!(json["redirect"]["redirected"], 1, "{json}");
        json
    }

    /// `vex` (org-scoped against the fake API): the statement count and
    /// the envelope.
    fn vex(&self, extra: &[&str]) -> (usize, serde_json::Value) {
        let doc = self.root.join("vex.json");
        let _ = std::fs::remove_file(&doc);
        let api = self.api_args();
        let mut args = vec!["vex", "-O", doc.to_str().unwrap(), "--product", PRODUCT];
        args.extend(api.iter().map(String::as_str));
        args.extend_from_slice(extra);
        let (_, json, _) = self.socket_in(&self.proj, &args);
        let statements = std::fs::read(&doc)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|d| d["statements"].as_array().map(Vec::len))
            .unwrap_or(0);
        (statements, json)
    }

    /// Drop the cached victim (base and suffixed), so the next build must
    /// download it.
    fn purge_cache(&self) {
        let dir = self
            .home
            .join(prebuilt_common::GRADLE_FILES21)
            .join(GROUP)
            .join(VICTIM);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(self.home.join("caches/modules-2/metadata-2.97"));
        for entry in std::fs::read_dir(self.home.join("caches/modules-2"))
            .into_iter()
            .flatten()
            .flatten()
        {
            if entry.file_name().to_string_lossy().starts_with("metadata-") {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }

    fn file(&self, rel: &str) -> String {
        std::fs::read_to_string(self.proj.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn cell_name(&self, test: &str) -> String {
        format!(
            "{SUITE}-{test}-{}-gradle-{}-{}",
            self.dsl.name(),
            self.gradle.version,
            std::env::consts::OS
        )
    }
}

/// The grant, the patch view and the discovery routes `scan` drives.
fn mount_api(s: &Server, served: &Served, files: &[(String, Vec<u8>)]) {
    mount_grants(s, &[(&HOSTED, served, files)]);
}

/// One hosted patch for [`mount_grants`]: the patch, what the Socket
/// repository serves and the patch view's files.
type Grant<'a> = (&'a Hosted, &'a Served, &'a [(String, Vec<u8>)]);

/// [`mount_api`] for several hosted patches at once.
fn mount_grants(s: &Server, grants: &[Grant<'_>]) {
    let mut packages = Vec::new();
    let mut results = serde_json::Map::new();
    let mut by_package = Vec::new();
    let mut views = Vec::new();
    for (h, served, files) in grants {
        let purl = h.purl();
        let uuid = h.uuid;
        let artifact_url = format!(
            "https://patch.socket.dev/patch/maven/{}/{}/{}/{TOKEN}/{uuid}/{}-{}.jar",
            h.group,
            h.artifact,
            h.version,
            h.artifact,
            h.suffixed()
        );
        let mut identifiers = serde_json::json!({
            "name": format!("{}/{}", h.group, h.artifact),
            "version": h.version,
            "mavenGroupId": h.group,
            "mavenArtifactId": h.artifact,
            "mavenSuffixedVersion": h.suffixed(),
            "mavenPomSha256": sha256_hex(&served.pom),
        });
        if let Some(m) = &served.module {
            identifiers["mavenModuleSha256"] = sha256_hex(m).into();
        }
        let view_files: serde_json::Map<String, serde_json::Value> = files
            .iter()
            .map(|(key, after)| {
                (
                    key.clone(),
                    serde_json::json!({ "beforeHash": "a".repeat(64), "afterHash": git_sha256(after) }),
                )
            })
            .collect();
        let vulnerabilities = serde_json::json!({
            GHSA: { "cves": [CVE], "summary": "s", "severity": "high", "description": "d" }
        });
        let view = serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
            "files": view_files,
            "vulnerabilities": vulnerabilities.clone(),
            "description": h.title,
            "license": "MIT",
            "tier": "free",
        });
        packages.push(serde_json::json!({ "purl": purl, "patches": [{
            "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [CVE],
            "ghsaIds": [GHSA], "severity": "high", "title": h.title
        }] }));
        results.insert(
            uuid.to_string(),
            serde_json::json!({
                "status": "granted",
                "url": artifact_url,
                "purl": purl,
                "artifacts": [{
                    "kind": "tarball",
                    "url": artifact_url,
                    "integrity": { "sha1": sha1_hex(&served.jar), "sha256": sha256_hex(&served.jar) }
                }],
                "registryOverride": {
                    "kind": "maven2",
                    "indexUrl": h.prod_index_url(),
                    "identifiers": identifiers,
                }
            }),
        );
        // One patch answers every by-package lookup (as before); several
        // answer by artifact.
        let route = if grants.len() == 1 {
            format!("^/v0/orgs/{ORG}/patches/by-package/.+$")
        } else {
            format!("^/v0/orgs/{ORG}/patches/by-package/.*{}.*$", h.artifact)
        };
        by_package.push((
            route,
            serde_json::json!({
                "patches": [{
                    "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "d", "license": "MIT", "tier": "free",
                    "vulnerabilities": vulnerabilities
                }],
                "canAccessPaidPatches": false,
            }),
        ));
        views.push((uuid, view));
    }
    s.rt.block_on(async {
        s.server.reset().await;
        let mut mocks = vec![
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": packages,
                    "canAccessPaidPatches": false,
                }))),
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "results": results })),
                ),
        ];
        for (route, body) in by_package {
            mocks.push(
                Mock::given(method("GET"))
                    .and(path_regex(route))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body)),
            );
        }
        for (uuid, view) in views {
            mocks.push(
                Mock::given(method("GET"))
                    .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(view)),
            );
        }
        for m in mocks {
            m.mount(&s.server).await;
        }
    });
}

/// The warning codes of an envelope's `redirect` block and top level.
fn codes(json: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for list in [&json["warnings"], &json["redirect"]["warnings"]] {
        for w in list.as_array().into_iter().flatten() {
            if let Some(c) = w["code"].as_str() {
                out.push(c.to_string());
            }
        }
    }
    out
}

fn has(json: &serde_json::Value, code: &str) -> bool {
    codes(json).iter().any(|c| c == code)
}

/// The common run of a hosted cell: warm, serve, scan, and the build
/// consumes the patched jar. Returns the scan envelope.
fn wire_and_build(c: &Cell, served: &Served, what: &str) -> serde_json::Value {
    c.warm();
    c.serve_leaf(served);
    let json = c.scan_ok();
    let out = c.build(&[]);
    c.assert_patched(&out, what);
    json
}

// ── the tests ───────────────────────────────────────────────────────────

/// A direct dependency: the owned files are written, the build resolves
/// the suffixed patched jar (its `.module` served), and a second scan
/// changes nothing and still confirms.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_direct() {
    for_each_dsl(|dsl| {
        let files = single(dsl, &[&implementation(dsl, &coordinate())], "");
        let Some(c) = cell(dsl, &files) else { return };
        let json = wire_and_build(&c, &Served::new(true), "direct");
        assert!(
            !has(&json, "redirect_gradle_module_metadata_unavailable"),
            "{json}"
        );
        assert_eq!(
            c.file(SCRIPT_REL),
            socket_patch_core::patch::redirect::gradle::HOSTED_SCRIPT
        );
        assert!(c.file(INDEX_REL).contains(&format!("\t{UUID}\n")));
        let settings = c.file(&dsl.settings_file());
        assert!(settings.contains("// socket-patch-hosted "), "{settings}");
        let before = snapshot(&c.proj);
        let (code, again) = c.scan_in(&c.proj, &[]);
        assert_eq!(code, Some(0), "{again}");
        assert_eq!(
            again["redirect"]["redirected"], 1,
            "rescan still confirms: {again}"
        );
        assert_eq!(snapshot(&c.proj), before, "a rescan writes nothing");
    });
}

/// A service that does not serve the suffixed `.module` yet: the scan
/// warns and Gradle falls back to the pom.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_module_metadata_unavailable_falls_back_to_the_pom() {
    let dsl = Dsl::Groovy;
    let files = single(dsl, &[&implementation(dsl, &coordinate())], "");
    let Some(c) = cell(dsl, &files) else { return };
    let json = wire_and_build(&c, &Served::new(false), "pom fallback");
    assert!(
        has(&json, "redirect_gradle_module_metadata_unavailable"),
        "{json}"
    );
}

/// The Groovy selector port in the hosted script agrees with the golden
/// tables (themselves checked against Gradle's own comparator by
/// [`gradle_hosted_selector_golden_tables_match_real_gradle`]) on this
/// Gradle major.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_selector_port_matches_golden_tables() {
    use socket_patch_core::gradle::selector::{
        GOLDEN_ADMITS, GOLDEN_ADMITS_BY_MAJOR, GOLDEN_ORDERING, GOLDEN_ORDERING_BY_MAJOR,
    };
    use std::cmp::Ordering;
    let script = socket_patch_core::patch::redirect::gradle::HOSTED_SCRIPT;
    let begin = script.find("// ---- socket-patch selector begin").unwrap();
    let end = script
        .find("// ---- socket-patch selector end ----")
        .unwrap();
    let port = &script[begin..end];
    let groovy = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let mut probe = String::from(port);
    probe.push_str("def socketRows = [\n");
    let mut want: Vec<String> = Vec::new();
    let Some(c) = cell(Dsl::Groovy, &[("settings.gradle".into(), String::new())]) else {
        return;
    };
    let major = c.gradle.major();
    let ord = |o: Ordering| match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    for (a, b, o) in GOLDEN_ORDERING {
        probe.push_str(&format!("  ['ORD', {}, {}],\n", groovy(a), groovy(b)));
        want.push(format!("ORD\t{a}\t{b}\t{}", ord(*o)));
    }
    for (a, b, six, later) in GOLDEN_ORDERING_BY_MAJOR {
        probe.push_str(&format!("  ['ORD', {}, {}],\n", groovy(a), groovy(b)));
        let o = if major < 7 { six } else { later };
        want.push(format!("ORD\t{a}\t{b}\t{}", ord(*o)));
    }
    let adm = |o: &Option<bool>| o.map_or("null".to_string(), |b| b.to_string());
    for (s, v, o) in GOLDEN_ADMITS {
        probe.push_str(&format!("  ['ADM', {}, {}],\n", groovy(s), groovy(v)));
        want.push(format!("ADM\t{s}\t{v}\t{}", adm(o)));
    }
    for (s, v, six, later) in GOLDEN_ADMITS_BY_MAJOR {
        probe.push_str(&format!("  ['ADM', {}, {}],\n", groovy(s), groovy(v)));
        let o = if major < 7 { six } else { later };
        want.push(format!("ADM\t{s}\t{v}\t{}", adm(o)));
    }
    probe.push_str("]\nsocketRows.each { r ->\n  if (r[0] == 'ORD') { println \"ORD\\t${r[1]}\\t${r[2]}\\t${socketCmp(r[1], r[2])}\" }\n  else { println \"ADM\\t${r[1]}\\t${r[2]}\\t${socketAdmits(r[1], r[2])}\" }\n}\n");
    std::fs::write(c.proj.join("settings.gradle"), probe).unwrap();
    let out = c.run(&["help", "-q"]);
    assert!(ok(&out), "{}", dump(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let got: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("ORD\t") || l.starts_with("ADM\t"))
        .collect();
    let mismatches: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w.as_str() != **g)
        .map(|(w, g)| format!("want {w:?}, got {g:?}"))
        .collect();
    assert_eq!(got.len(), want.len(), "{}", dump(&out));
    assert!(
        mismatches.is_empty(),
        "Gradle {}: {mismatches:#?}",
        c.gradle.version
    );
}

/// The `gradle::selector` golden tables, and the Rust port itself, agree
/// with real Gradle's own version comparator and selector scheme (its
/// internal `VersionParser`, `DefaultVersionComparator` and
/// `DefaultVersionSelectorScheme`, stable from 6.9 through 9.x). Both
/// selector ports (Rust and the hosted script's Groovy) are checked against
/// these tables, so this is the check that keeps the tables themselves
/// honest; it runs in every hosted cell.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_selector_golden_tables_match_real_gradle() {
    use socket_patch_core::gradle::selector::{
        admits_for, gradle_version_cmp_for, parse_selector, GOLDEN_ADMITS, GOLDEN_ADMITS_BY_MAJOR,
        GOLDEN_ORDERING, GOLDEN_ORDERING_BY_MAJOR,
    };
    let groovy = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let mut ords: Vec<(&str, &str)> = GOLDEN_ORDERING.iter().map(|(a, b, _)| (*a, *b)).collect();
    ords.extend(GOLDEN_ORDERING_BY_MAJOR.iter().map(|(a, b, _, _)| (*a, *b)));
    let mut adm: Vec<(&str, &str)> = GOLDEN_ADMITS.iter().map(|(s, v, _)| (*s, *v)).collect();
    adm.extend(GOLDEN_ADMITS_BY_MAJOR.iter().map(|(s, v, _, _)| (*s, *v)));
    let list = |rows: &[(&str, &str)]| {
        rows.iter()
            .map(|(a, b)| format!("  [{}, {}],", groovy(a), groovy(b)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let probe = format!(
        r#"import org.gradle.api.internal.artifacts.ivyservice.ivyresolve.strategy.*
def parser = new VersionParser()
def cmp = new DefaultVersionComparator()
def scheme = new DefaultVersionSelectorScheme(cmp, parser)
def ords = [
{}
]
def adm = [
{}
]
for (r in ords) {{
  int c = Integer.signum(cmp.asVersionComparator().compare(parser.transform(r[0]), parser.transform(r[1])))
  println "ORD\t${{r[0]}}\t${{r[1]}}\t${{c}}"
}}
for (r in adm) {{
  def sel = scheme.parseSelector(r[0])
  def got = sel.requiresMetadata() ? 'None' : String.valueOf(sel.accept(r[1]))
  println "ADM\t${{r[0]}}\t${{r[1]}}\t${{got}}"
}}
"#,
        list(&ords),
        list(&adm)
    );
    let Some(c) = cell(
        Dsl::Groovy,
        &[
            (
                "settings.gradle".into(),
                "rootProject.name = 'probe'\n".into(),
            ),
            ("build.gradle".into(), probe),
        ],
    ) else {
        return;
    };
    let major = c.gradle.major();
    let out = c.run(&["help", "-q"]);
    assert!(ok(&out), "{}", dump(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut mismatches = Vec::new();
    let mut ord_rows = 0;
    let mut adm_rows = 0;
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        match cols.as_slice() {
            ["ORD", a, b, n] => {
                ord_rows += 1;
                let gradle = n.parse::<i32>().expect("signum").cmp(&0);
                let table = GOLDEN_ORDERING
                    .iter()
                    .find(|(x, y, _)| x == a && y == b)
                    .map(|(_, _, o)| *o)
                    .or_else(|| {
                        GOLDEN_ORDERING_BY_MAJOR
                            .iter()
                            .find(|(x, y, _, _)| x == a && y == b)
                            .map(|(_, _, six, later)| if major < 7 { *six } else { *later })
                    })
                    .expect("row");
                let port = gradle_version_cmp_for(a, b, major);
                if gradle != table || gradle != port {
                    mismatches.push(format!(
                        "order {a} vs {b}: gradle {gradle:?}, table {table:?}, port {port:?}"
                    ));
                }
            }
            ["ADM", sel, v, got] => {
                adm_rows += 1;
                let gradle = match *got {
                    "None" => None,
                    "true" => Some(true),
                    _ => Some(false),
                };
                let table = GOLDEN_ADMITS
                    .iter()
                    .find(|(s, x, _)| s == sel && x == v)
                    .map(|(_, _, w)| *w)
                    .or_else(|| {
                        GOLDEN_ADMITS_BY_MAJOR
                            .iter()
                            .find(|(s, x, _, _)| s == sel && x == v)
                            .map(|(_, _, six, later)| if major < 7 { *six } else { *later })
                    })
                    .expect("row");
                let port = admits_for(&parse_selector(sel), v, major);
                if gradle != table || gradle != port {
                    mismatches.push(format!(
                        "{sel:?} admits {v}: gradle {gradle:?}, table {table:?}, port {port:?}"
                    ));
                }
            }
            _ => {}
        }
    }
    assert_eq!(ord_rows, ords.len(), "{}", dump(&out));
    assert_eq!(adm_rows, adm.len(), "{}", dump(&out));
    assert!(
        mismatches.is_empty(),
        "Gradle {} disagrees:\n{}",
        c.gradle.version,
        mismatches.join("\n")
    );
}

// ── more project shapes ────────────────────────────────────────────────

/// A `print<Name>` task printing [`gradle_build_common::CP_MARKER`] lines
/// for the files of `files_expr` (a `FileCollection` expression evaluated
/// at configuration time, captured task-locally: configuration-cache safe).
fn print_task(dsl: Dsl, name: &str, files_expr: &str) -> String {
    let marker = gradle_build_common::CP_MARKER;
    match dsl {
        Dsl::Groovy => format!(
            "tasks.register('{name}') {{\n    def socketFiles = {files_expr}\n    \
             doLast {{ socketFiles.files.each {{ println('{marker}' + it.absolutePath) }} }}\n}}\n"
        ),
        Dsl::Kotlin => format!(
            "tasks.register(\"{name}\") {{\n    val socketFiles: FileCollection = {files_expr}\n    \
             doLast {{ socketFiles.files.forEach {{ println(\"{marker}\" + it.absolutePath) }} }}\n}}\n"
        ),
    }
}

/// `dependencyLocking { lockAllConfigurations(); lockMode = <mode> }`.
fn locking(dsl: Dsl, mode: Option<&str>) -> String {
    let mode = mode
        .map(|m| format!("    lockMode.set(LockMode.{m})\n"))
        .unwrap_or_default();
    match dsl {
        Dsl::Groovy | Dsl::Kotlin => {
            format!("dependencyLocking {{\n    lockAllConfigurations()\n{mode}}}\n")
        }
    }
}

/// The lock files of the project as text.
fn lock_texts(proj: &Path) -> BTreeMap<String, String> {
    lockfiles(proj)
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8(v).unwrap()))
        .collect()
}

/// Every lock file holding the victim locks it at the suffixed version.
fn assert_locks_suffixed(proj: &Path, what: &str) {
    let locks = lock_texts(proj);
    let holding: Vec<(&String, &String)> = locks
        .iter()
        .filter(|(_, t)| t.contains(&format!("{GROUP}:{VICTIM}:")))
        .collect();
    assert!(
        !holding.is_empty(),
        "{what}: no lock holds the victim: {locks:?}"
    );
    for (rel, text) in holding {
        assert!(
            text.contains(&format!("{GROUP}:{VICTIM}:{}", sfx()))
                && !text.contains(&format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}=")),
            "{what}: {rel} is not pinned:\n{text}"
        );
    }
}

/// A transitive request of the base (`consumer:2.0` → `victim:1.10.0`)
/// next to a direct `victim:1.9` (#347): the base request is pinned to
/// the suffixed version, which wins conflict resolution over 1.9.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_347_transitive_base() {
    for_each_dsl(|dsl| {
        let deps = [
            implementation(dsl, &format!("{GROUP}:{VICTIM}:{VICTIM_OLD}")),
            implementation(dsl, &format!("{GROUP}:{CONSUMER}:{CONSUMER_VERSION}")),
        ];
        let deps: Vec<&str> = deps.iter().map(String::as_str).collect();
        let Some(c) = cell(dsl, &single(dsl, &deps, "")) else {
            return;
        };
        wire_and_build(
            &c,
            &Served::new(true),
            "#347 transitive base over a direct 1.9",
        );
    });
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_transitive_only() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &format!("{GROUP}:{CONSUMER}:{CONSUMER_VERSION}"));
        let Some(c) = cell(dsl, &single(dsl, &[&dep], "")) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), "transitive only");
    });
}

/// Dependency locking (#396): the lock entry moves to the suffixed
/// version and the locked build consumes the patched jar.
fn locked_case(mode: Option<&str>, what: &str) {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, mode))) else {
            return;
        };
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the locks");
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        assert_locks_suffixed(&c.proj, what);
        let out = c.build(&[]);
        c.assert_patched(&out, what);
    });
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_396_lock_default() {
    locked_case(None, "#396 default lock mode");
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_396_lock_strict() {
    locked_case(Some("STRICT"), "#396 strict lock mode");
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_396_lock_lenient() {
    locked_case(Some("LENIENT"), "#396 lenient lock mode");
}

/// Gradle 6's default per-configuration lock files
/// (`gradle/dependency-locks/<conf>.lockfile`).
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_396_legacy_locks_6x() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        if c.gradle.major() != 6 {
            println!("SKIP: legacy lock files are Gradle 6's default only");
            return;
        }
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the legacy locks");
        assert!(
            lock_texts(&c.proj)
                .keys()
                .any(|k| k.starts_with("gradle/dependency-locks/")),
            "Gradle 6 writes legacy locks: {:?}",
            lock_texts(&c.proj)
        );
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        assert_locks_suffixed(&c.proj, "legacy locks");
        let out = c.build(&[]);
        c.assert_patched(&out, "legacy locks");
    });
}

/// #348: a Kotlin DSL build is wired with the Kotlin apply line.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_348_kotlin() {
    let dsl = Dsl::Kotlin;
    let Some(c) = cell(
        dsl,
        &single(dsl, &[&implementation(dsl, &coordinate())], ""),
    ) else {
        return;
    };
    wire_and_build(&c, &Served::new(true), "#348 Kotlin DSL");
    let settings = c.file("settings.gradle.kts");
    assert!(
        settings.contains(&format!(
            "apply(from = \"{SCRIPT_REL}\") // socket-patch-hosted "
        )),
        "{settings}"
    );
}

/// A version-catalog declaration (Gradle 7.4+: stable catalogs).
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_catalog() {
    for_each_dsl(|dsl| {
        let dep = match dsl {
            Dsl::Groovy => "implementation libs.victim",
            Dsl::Kotlin => "implementation(libs.victim)",
        };
        let mut files = single(dsl, &[dep], "");
        files.push((
            "gradle/libs.versions.toml".into(),
            format!("[libraries]\nvictim = \"{}\"\n", coordinate()),
        ));
        let Some(c) = cell(dsl, &files) else { return };
        if !c.gradle.at_least(7, 4) {
            println!("SKIP: version catalogs are stable from Gradle 7.4");
            return;
        }
        wire_and_build(&c, &Served::new(true), "catalog");
    });
}

/// A project buildscript classpath is pinned (the hook reaches
/// `buildscript.configurations`).
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_buildscript_classpath() {
    for_each_dsl(|dsl| {
        let (settings, build) = match dsl {
            Dsl::Groovy => (
                "rootProject.name = 'app'\n".to_string(),
                format!(
                    "buildscript {{\n    repositories {{ mavenCentral() }}\n    dependencies {{ classpath '{}' }}\n}}\n{}",
                    coordinate(),
                    print_task(dsl, "printRuntimeClasspath", "files(buildscript.configurations.named('classpath'))")
                ),
            ),
            Dsl::Kotlin => (
                "rootProject.name = \"app\"\n".to_string(),
                format!(
                    "buildscript {{\n    repositories {{ mavenCentral() }}\n    dependencies {{ classpath(\"{}\") }}\n}}\n{}",
                    coordinate(),
                    print_task(dsl, "printRuntimeClasspath", "files(buildscript.configurations.named(\"classpath\"))")
                ),
            ),
        };
        let files = vec![(dsl.settings_file(), settings), (dsl.build_file(), build)];
        let Some(c) = cell(dsl, &files) else { return };
        wire_and_build(&c, &Served::new(true), "buildscript classpath");
    });
}

/// Settings with `pluginManagement` and a `plugins {}` block: the hosted
/// script never touches the settings classpath, so nothing throws.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_settings_plugins_block_no_throw() {
    for_each_dsl(|dsl| {
        let mut files = single(dsl, &[&implementation(dsl, &coordinate())], "");
        files[0].1 = format!(
            "pluginManagement {{ repositories {{ mavenCentral() }} }}\nplugins {{ }}\n{}",
            files[0].1
        );
        let Some(c) = cell(dsl, &files) else { return };
        wire_and_build(&c, &Served::new(true), "settings plugins block");
    });
}

/// `dependencyResolutionManagement` repositories in the given mode.
fn repos_mode_case(mode: &str, project_repos: bool) {
    for_each_dsl(|dsl| {
        let mut files = single(dsl, &[&implementation(dsl, &coordinate())], "");
        let drm = format!(
            "dependencyResolutionManagement {{\n    repositoriesMode.set(RepositoriesMode.{mode})\n    repositories {{ mavenCentral() }}\n}}\n"
        );
        files[0].1 = format!("{}{drm}", files[0].1);
        if !project_repos {
            files[1].1 = files[1].1.replace("repositories { mavenCentral() }\n", "");
        }
        let Some(c) = cell(dsl, &files) else { return };
        wire_and_build(&c, &Served::new(true), mode);
    });
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_repos_mode_fail_on_project() {
    repos_mode_case("FAIL_ON_PROJECT_REPOS", false);
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_repos_mode_prefer_settings() {
    repos_mode_case("PREFER_SETTINGS", true);
}

/// A multi-project build with `buildSrc` and an included build that locks
/// its dependencies: every build is wired, every lock moves, and the
/// subproject, the included build and `buildSrc` all consume the patch.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_multiproject_buildsrc_includebuild() {
    for_each_dsl(|dsl| {
        let (q, plugins) = match dsl {
            Dsl::Groovy => ("'", "plugins { id 'java' }"),
            Dsl::Kotlin => ("\"", "plugins { java }"),
        };
        let include = match dsl {
            Dsl::Groovy => "include 'app'\nincludeBuild 'tools'\n".to_string(),
            Dsl::Kotlin => "include(\"app\")\nincludeBuild(\"tools\")\n".to_string(),
        };
        let dep = implementation(dsl, &coordinate());
        let app = format!(
            "{plugins}\nrepositories {{ mavenCentral() }}\ndependencies {{ {dep} }}\n{}",
            print_cp_task(dsl, "runtimeClasspath")
        );
        let tools = format!(
            "{plugins}\nrepositories {{ mavenCentral() }}\ndependencies {{ {dep} }}\n{}{}",
            locking(dsl, None),
            print_cp_task(dsl, "runtimeClasspath")
        );
        let bsrc_print = match dsl {
            Dsl::Groovy => "configurations.runtimeClasspath.files.each { println('SOCKET-BSRC ' + it.name) }\n",
            Dsl::Kotlin => "configurations.getByName(\"runtimeClasspath\").files.forEach { println(\"SOCKET-BSRC \" + it.name) }\n",
        };
        let bsrc = format!(
            "{plugins}\nrepositories {{ mavenCentral() }}\ndependencies {{ {dep} }}\n{bsrc_print}"
        );
        let files = vec![
            (
                dsl.settings_file(),
                format!("rootProject.name = {q}root{q}\n{include}"),
            ),
            (dsl.build_file(), String::new()),
            (format!("app/{}", dsl.build_file()), app),
            (
                format!("tools/{}", dsl.settings_file()),
                format!("rootProject.name = {q}tools{q}\n"),
            ),
            (format!("tools/{}", dsl.build_file()), tools),
        ];
        let Some(c) = cell(dsl, &files) else { return };
        // Gradle before 8.0 applies no init script to buildSrc, so the test
        // mirror cannot reach it: there buildSrc only proves its settings
        // are wired (and still evaluate).
        let bsrc_resolves = c.gradle.at_least(8, 0);
        let bsrc = if bsrc_resolves {
            bsrc
        } else {
            format!("{plugins}\n")
        };
        std::fs::create_dir_all(c.proj.join("buildSrc")).unwrap();
        std::fs::write(c.proj.join("buildSrc").join(dsl.build_file()), bsrc).unwrap();
        let out = c.run(&[":app:printRuntimeClasspath"]);
        c.assert_pristine(&out, "warm app");
        let out = c.run_in(
            &c.proj.join("tools"),
            &["printRuntimeClasspath", "--write-locks"],
        );
        c.assert_pristine(&out, "warm and lock tools");
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        for rel in [
            dsl.settings_file(),
            format!("tools/{}", dsl.settings_file()),
            format!("buildSrc/{}", dsl.settings_file()),
        ] {
            assert!(
                c.file(&rel).contains("// socket-patch-hosted "),
                "{rel} wired"
            );
        }
        assert_locks_suffixed(&c.proj.join("tools"), "the included build's locks");
        let out = c.run(&[":app:printRuntimeClasspath"]);
        c.assert_patched(&out, "subproject");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !bsrc_resolves || stdout.contains(&format!("SOCKET-BSRC {VICTIM}-{}.jar", sfx())),
            "buildSrc consumes the patch:\n{}",
            dump(&out)
        );
        let out = c.run(&[":tools:printRuntimeClasspath"]);
        c.assert_patched(&out, "included build");
    });
}

/// An existing `gradle/verification-metadata.xml` gets the suffixed
/// component, and Gradle verifies the patched jar, pom and module with it.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_verification_metadata() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        let out = c.build(&["--write-verification-metadata", "sha256"]);
        c.assert_pristine(&out, "write verification metadata");
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let vm = c.file("gradle/verification-metadata.xml");
        assert!(vm.contains(&format!("version=\"{}\"", sfx())), "{vm}");
        let out = c.build(&[]);
        c.assert_patched(&out, "verified");
    });
}

/// A Gradle platform whose variants `require` the base: patched.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_platform_require_patched() {
    platform_case("fixture-platform", false);
}

/// A non-enforced Maven BOM import: patched.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_bom_import_patched() {
    platform_case("fixture-bom", false);
}

/// An ENFORCED BOM (a `strictly` constraint on the base): the build may
/// fail loudly, but never consumes the unpatched base.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_bom_strict_fails_loud() {
    platform_case("fixture-bom", true);
}

fn platform_case(platform: &str, enforced: bool) {
    for_each_dsl(|dsl| {
        let kind = if enforced {
            "enforcedPlatform"
        } else {
            "platform"
        };
        let notation = format!("{GROUP}:{platform}:1.0");
        let deps = match dsl {
            Dsl::Groovy => [
                format!("implementation {kind}('{notation}')"),
                format!("implementation '{GROUP}:{VICTIM}'"),
            ],
            Dsl::Kotlin => [
                format!("implementation({kind}(\"{notation}\"))"),
                format!("implementation(\"{GROUP}:{VICTIM}\")"),
            ],
        };
        let deps: Vec<&str> = deps.iter().map(String::as_str).collect();
        let Some(c) = cell(dsl, &single(dsl, &deps, "")) else {
            return;
        };
        c.warm();
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let out = c.build(&[]);
        if enforced && !ok(&out) {
            c.assert_fails_loud(&out, "enforced BOM");
            return;
        }
        c.assert_patched(&out, &format!("{kind} {platform}"));
    });
}

/// #511: a dynamic prefix admitting the base.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_511_dynamic_prefix() {
    selector_case("1.+");
}

/// #511: an open range admitting the base.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_511_open_range() {
    selector_case("[1.9,)");
}

fn selector_case(selector: &str) {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &format!("{GROUP}:{VICTIM}:{selector}"));
        let Some(c) = cell(dsl, &single(dsl, &[&dep], "")) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), selector);
    });
}

/// #511: `consumer-range:2.0`'s pom requests `[1.9,1.11)`: the patched
/// jar, never 1.9.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_511_pom_transitive_range() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &format!("{GROUP}:{CONSUMER_RANGE}:{CONSUMER_VERSION}"));
        let Some(c) = cell(dsl, &single(dsl, &[&dep], "")) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), "pom transitive range");
    });
}

/// The Socket repository goes away: a fresh cache fails the build
/// instead of falling back to the unpatched base.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_outage_fails_build() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), "before the outage");
        for ext in ["jar", "pom", "module"] {
            c.central.remove(&socket_path(ext));
        }
        c.purge_cache();
        let out = c.build(&["--refresh-dependencies"]);
        c.assert_fails_loud(&out, "outage");
    });
}

/// The Socket repository serves other bytes than the pinned jar: the
/// script's tripwire fails the build.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_tamper_fails() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), "before the tamper");
        let mut tampered = patched_jar();
        tampered.extend_from_slice(b"TAMPER");
        c.central.put(&socket_path("jar"), &tampered);
        c.purge_cache();
        let out = c.build(&["--refresh-dependencies"]);
        assert!(
            !ok(&out),
            "a tampered jar must fail the build:\n{}",
            dump(&out)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("socket-patch:")
                || String::from_utf8_lossy(&out.stdout).contains("socket-patch:"),
            "the failure names socket-patch:\n{}",
            dump(&out)
        );
    });
}

/// A lock rolled back to the base after the scan: the locked build fails
/// rather than consuming the unpatched base, and discovery stops naming
/// the pin. A build after the scan installs the suffixed jar first, so the
/// attestation is withheld by discovery's lock check, not by missing
/// installed evidence.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_stale_lock_fails() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the locks");
        let pristine_locks = lock_texts(&c.proj);
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let out = c.build(&[]);
        c.assert_patched(&out, "the scanned locks");
        let (statements, json) = c.vex(&[]);
        assert_eq!(statements, 1, "attested while the locks pin: {json}");
        for (rel, text) in &pristine_locks {
            std::fs::write(c.proj.join(rel), text).unwrap();
        }
        let out = c.build(&[]);
        c.assert_fails_loud(&out, "stale lock");
        let (statements, json) = c.vex(&[]);
        assert_eq!(statements, 0, "a stale lock is not attested: {json}");
        assert!(
            json.to_string().contains("patched_ref_invalid")
                && json
                    .to_string()
                    .contains(&format!("locks {GROUP}:{VICTIM} at {VICTIM_VERSION}")),
            "discovery names the stale lock: {json}"
        );
    });
}

/// The second hosted patch: `consumer:2.0` (which requests the victim
/// base transitively).
const UUID2: &str = "0abcdef1-2345-4678-9abc-def012345678";
const HOSTED2: Hosted = Hosted {
    org: ORG,
    uuid: UUID2,
    hex8: "0abcdef1",
    token: TOKEN,
    ghsa: GHSA,
    cve: CVE,
    group: GROUP,
    artifact: CONSUMER,
    version: CONSUMER_VERSION,
    title: "gradle hosted e2e consumer",
};
/// The member the patched consumer jar adds.
const CONSUMER_PATCHED_MEMBER: &str = "META-INF/socket-consumer-patched.txt";

/// The consumer as its Socket repository serves it: the upstream jar plus
/// a marker member, the upstream pom re-versioned, no `.module`.
fn served_consumer() -> Served {
    use std::io::Read as _;
    let upstream = central_file(&repo_path(CONSUMER, CONSUMER_VERSION, None, "jar"));
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(upstream)).unwrap();
    let mut members = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        members.push((entry.name().to_string(), buf));
    }
    members.push((CONSUMER_PATCHED_MEMBER.to_string(), b"patched\n".to_vec()));
    let upstream_pom = central_file(&repo_path(CONSUMER, CONSUMER_VERSION, None, "pom"));
    Served {
        jar: jvm_fixture_repo::jar(&members),
        pom: HOSTED2.served_pom(&upstream_pom),
        module: None,
    }
}

/// The configuration cache: a stored entry with one hosted row is
/// invalidated when a second row lands (the digest on the apply line
/// changes), and both GAs then resolve their suffixed, patched jars from
/// their own Socket repositories; the restore invalidates it again.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_config_cache_second_row() {
    for_each_dsl(|dsl| {
        let deps = [
            implementation(dsl, &coordinate()),
            implementation(dsl, &format!("{GROUP}:{CONSUMER}:{CONSUMER_VERSION}")),
        ];
        let deps: Vec<&str> = deps.iter().map(String::as_str).collect();
        let Some(c) = cell(dsl, &single(dsl, &deps, "")) else {
            return;
        };
        if !c.gradle.at_least(8, 1) {
            println!("SKIP: the configuration cache is stable from Gradle 8.1");
            return;
        }
        let cc = "--configuration-cache";
        c.warm();
        // Row one: the victim.
        let victim = Served::new(true);
        c.serve_leaf(&victim);
        c.scan_ok();
        let out = c.build(&[cc]);
        c.assert_patched(&out, "one row: store");
        let out = c.build(&[cc]);
        assert!(
            configuration_reused(&out),
            "one row: reused\n{}",
            dump(&out)
        );
        c.assert_patched(&out, "one row: reused");

        // Row two: the consumer, served from its own Socket repository.
        let consumer = served_consumer();
        c.central.put(
            HOSTED2.served_path("jar").trim_start_matches('/'),
            &consumer.jar,
        );
        c.central.put(
            HOSTED2.served_path("pom").trim_start_matches('/'),
            &consumer.pom,
        );
        let victim_files = [(format!("{VICTIM}-{VICTIM_VERSION}.jar"), victim.jar.clone())];
        let consumer_files = [(
            format!("{CONSUMER}-{CONSUMER_VERSION}.jar"),
            consumer.jar.clone(),
        )];
        mount_grants(
            &c.api,
            &[
                (&HOSTED, &victim, &victim_files),
                (&HOSTED2, &consumer, &consumer_files),
            ],
        );
        let (code, json) = c.scan_in(&c.proj, &[]);
        assert_eq!(code, Some(0), "second scan: {json}");
        let index = c.file(INDEX_REL);
        assert_eq!(index.lines().count(), 3, "two rows: {index}");
        let out = c.build(&[cc]);
        assert!(
            !configuration_reused(&out),
            "the second row invalidates the entry\n{}",
            dump(&out)
        );
        c.assert_patched(&out, "two rows");
        let consumer_jar = format!("{CONSUMER}-{}.jar", HOSTED2.suffixed());
        let hit = gradle_classpath(&out)
            .into_iter()
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy() == consumer_jar)
            })
            .unwrap_or_else(|| panic!("{consumer_jar} resolves:\n{}", dump(&out)));
        assert_eq!(
            jar_member(&std::fs::read(&hit).unwrap(), CONSUMER_PATCHED_MEMBER).as_deref(),
            Some(&b"patched\n"[..]),
            "the patched consumer resolves"
        );
        let out = c.build(&[cc]);
        assert!(
            configuration_reused(&out),
            "two rows: reused\n{}",
            dump(&out)
        );

        let (code, json, _) = c.socket_in(&c.proj, &["rollback", "--yes"]);
        assert_eq!(code, Some(0), "rollback: {json}");
        let out = c.build(&[cc]);
        assert!(
            !configuration_reused(&out),
            "the restore invalidates the entry"
        );
        c.assert_pristine(&out, "after the restore");
    });
}

/// Detached configurations are outside the pin (documented); this records
/// what each Gradle major resolves for one.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_detached_config_records_behaviour() {
    for_each_dsl(|dsl| {
        let detached = match dsl {
            Dsl::Groovy => format!(
                "files(configurations.detachedConfiguration(dependencies.create('{}')))",
                coordinate()
            ),
            Dsl::Kotlin => format!(
                "files(configurations.detachedConfiguration(dependencies.create(\"{}\")))",
                coordinate()
            ),
        };
        let extra = print_task(dsl, "printDetached", &detached);
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], &extra),
        ) else {
            return;
        };
        wire_and_build(&c, &Served::new(true), "the project configuration");
        let out = c.run(&["printDetached"]);
        let resolved: Vec<String> = gradle_classpath(&out)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        println!(
            "detached configuration resolved {resolved:?} (ok: {})",
            ok(&out)
        );
        probe_report(
            &c.cell_name("detached"),
            &serde_json::json!({
                "gradle": c.gradle.version,
                "jvm": c.gradle.jvm,
                "dsl": dsl.name(),
                "detachedBuildOk": ok(&out),
                "detachedResolved": resolved,
            }),
        );
    });
}

/// A second scan changes nothing and still confirms.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_rescan_idempotent() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the locks");
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let before = snapshot(&c.proj);
        let again = c.scan_ok();
        assert_eq!(
            snapshot(&c.proj),
            before,
            "a rescan writes nothing: {again}"
        );
    });
}

/// `rollback` restores every file byte for byte (locks, settings, the
/// verification file) and removes the owned files.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_restore_byte_exact() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        let out = c.build(&["--write-locks", "--write-verification-metadata", "sha256"]);
        c.assert_pristine(&out, "write the locks and verification metadata");
        let before = snapshot(&c.proj);
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        assert_ne!(snapshot(&c.proj), before);
        let (code, json, _) = c.socket_in(&c.proj, &["rollback", "--yes", "--offline"]);
        assert_eq!(code, Some(0), "rollback: {json}");
        assert_eq!(snapshot(&c.proj), before, "byte-exact restore: {json}");
        let out = c.build(&[]);
        c.assert_pristine(&out, "after the restore");
    });
}

/// `remove <purl>` restores the lock and the settings.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_remove_restores_lock_and_settings() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the locks");
        let before = snapshot(&c.proj);
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let (code, json, _) = c.socket_in(&c.proj, &["remove", &purl(), "--yes", "--offline"]);
        assert_eq!(code, Some(0), "remove: {json}");
        assert_eq!(snapshot(&c.proj), before, "remove restores: {json}");
    });
}

/// #429: the wired project committed and cloned with `core.autocrlf`
/// (CRLF settings and locks; the owned files stay LF through their
/// `.gitattributes`) builds patched, and a rescan of the clone changes
/// nothing.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_429_autocrlf_clone() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &coordinate());
        let Some(c) = cell(dsl, &single(dsl, &[&dep], &locking(dsl, None))) else {
            return;
        };
        let out = c.build(&["--write-locks"]);
        c.assert_pristine(&out, "write the locks");
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let clone = gradle_build_common::git_autocrlf_clone(&c.proj, &c.root.join("clone"));
        let settings = std::fs::read(clone.join(dsl.settings_file())).unwrap();
        assert!(settings.windows(2).any(|w| w == b"\r\n"), "CRLF settings");
        let script = std::fs::read(clone.join(SCRIPT_REL)).unwrap();
        assert!(!script.contains(&b'\r'), "the owned script stays LF");
        let out = c.run_in(&clone, &["printRuntimeClasspath"]);
        c.assert_patched(&out, "autocrlf clone");
        let before = snapshot(&clone);
        let (code, json) = c.scan_in(&clone, &[]);
        assert_eq!(code, Some(0), "{json}");
        assert_eq!(json["redirect"]["redirected"], 1, "{json}");
        assert_eq!(
            snapshot(&clone),
            before,
            "a rescan of the clone writes nothing"
        );
    });
}

/// #646 review: a settings.gradle that is not UTF-8 (a Latin-1 comment)
/// is not absent. The scan refuses the build
/// (`redirect_gradle_build_file_unreadable`) and leaves the settings file
/// byte-identical, instead of replacing it with a one-line apply file.
/// Gradle still builds the untouched project.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_non_utf8_settings_refused_untouched() {
    let dsl = Dsl::Groovy;
    let Some(c) = cell(
        dsl,
        &single(dsl, &[&implementation(dsl, &coordinate())], ""),
    ) else {
        return;
    };
    let settings = c.proj.join("settings.gradle");
    let latin1: &[u8] = b"rootProject.name = 'app'\n// Auteur: Andr\xe9\n";
    std::fs::write(&settings, latin1).unwrap();
    c.warm();
    c.serve_leaf(&Served::new(true));
    let (code, json) = c.scan_in(&c.proj, &[]);
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["redirect"]["redirected"], 0, "{json}");
    assert!(
        has(&json, "redirect_gradle_build_file_unreadable"),
        "{json}"
    );
    assert_eq!(std::fs::read(&settings).unwrap(), latin1, "{json}");
    let out = c.build(&[]);
    c.assert_pristine(&out, "refused build");
}

/// A build the planner refuses (a declared classifier) with the fallback
/// snippet pasted in: the build consumes the patch, but nothing attests
/// it.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_pasted_snippet_not_attested() {
    let dsl = Dsl::Groovy;
    let tests = format!("testImplementation '{}:tests'", coordinate());
    let Some(c) = cell(
        dsl,
        &single(dsl, &[&implementation(dsl, &coordinate()), &tests], ""),
    ) else {
        return;
    };
    c.warm();
    c.serve_leaf(&Served::new(true));
    let (code, json) = c.scan_in(&c.proj, &[]);
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["redirect"]["redirected"], 0, "{json}");
    assert!(has(&json, "redirect_gradle_classifier_declared"), "{json}");
    let snippet = snippet_code(&json);
    let build = c.proj.join("build.gradle");
    let text = std::fs::read_to_string(&build).unwrap();
    std::fs::write(&build, format!("{text}\n{snippet}\n")).unwrap();
    let out = c.build(&[]);
    c.assert_patched(&out, "pasted snippet");
    let (statements, _) = c.vex(&[]);
    assert_eq!(statements, 0, "a pasted snippet is never attested");
}

/// The code of the fallback snippet a refusal printed.
fn snippet_code(json: &serde_json::Value) -> String {
    let detail = json["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(json["warnings"].as_array().into_iter().flatten())
        .find(|w| w["code"] == "redirect_gradle_manual_snippet")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("no fallback snippet: {json}"))
        .to_string();
    let code = detail
        .split_once(":\n")
        .expect("the snippet follows its intro")
        .1;
    code.split("\nThen re-lock").next().unwrap().to_string()
}

/// A member-keyed record (`NOTICE` and `Victim.class`) attests once the
/// build installed the suffixed copy.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_vex_member_record_attests() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        c.warm();
        let served = Served::new(true);
        c.serve(
            &served,
            &[
                (NOTICE.to_string(), patched_notice()),
                (
                    VICTIM_CLASS_MEMBER.to_string(),
                    victim_class(VICTIM_VERSION, "patched"),
                ),
            ],
        );
        c.scan_ok();
        let out = c.build(&[]);
        c.assert_patched(&out, "member record");
        let (statements, json) = c.vex(&[]);
        assert_eq!(statements, 1, "attested: {json}");
    });
}

/// Before any build fetched the suffixed jar, VEX has no evidence: no
/// statement (a Gradle pin never takes the lockfile basis).
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_vex_before_build_no_statement() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        c.warm();
        c.serve_leaf(&Served::new(true));
        c.scan_ok();
        let (statements, json) = c.vex(&[]);
        assert_eq!(statements, 0, "no installed suffixed copy yet: {json}");
        let out = c.build(&[]);
        c.assert_patched(&out, "build");
        let (statements, json) = c.vex(&[]);
        assert_eq!(statements, 1, "attested after the build: {json}");
    });
}

/// Whether a failed run failed in a pasted script rather than in
/// dependency resolution: a Groovy or Kotlin compile error, or an
/// evaluation error in the build script.
fn script_error(out: &Output) -> bool {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.contains("Script compilation error")
        || text.contains("Could not compile build file")
        || text.lines().any(|l| l.starts_with("e: "))
        || text.contains("A problem occurred evaluating root project")
}

/// The request a [`fallback_case`] pastes the snippet over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Request {
    Direct,
    Transitive,
    /// A rich version with only `prefer` (#646 review): its
    /// `requested.version` is empty, so only the snippet's dependency
    /// substitution on the version constraint rewrites it.
    PreferOnly,
}

/// The fallback snippet compiles in each DSL and pins the patch. A direct
/// (or `prefer`-only) request must resolve the suffixed, patched jar; a
/// transitive-only one (`consumer:2.0` → the base) resolves it or fails in
/// resolution, never in the pasted script, and never resolves the
/// unpatched base.
fn fallback_case(dsl: Dsl, kind: Request) {
    let what = match kind {
        Request::Direct => "direct",
        Request::Transitive => "transitive",
        Request::PreferOnly => "prefer-only",
    };
    let direct = kind != Request::Transitive;
    let tests = match dsl {
        Dsl::Groovy => format!("testImplementation '{}:tests'", coordinate()),
        Dsl::Kotlin => format!("testImplementation(\"{}:tests\")", coordinate()),
    };
    let request = match (kind, dsl) {
        (Request::Direct, _) => implementation(dsl, &coordinate()),
        (Request::Transitive, _) => {
            implementation(dsl, &format!("{GROUP}:{CONSUMER}:{CONSUMER_VERSION}"))
        }
        (Request::PreferOnly, Dsl::Groovy) => format!(
            "implementation('{GROUP}:{VICTIM}') {{ version {{ prefer '{VICTIM_VERSION}' }} }}"
        ),
        (Request::PreferOnly, Dsl::Kotlin) => format!(
            "implementation(\"{GROUP}:{VICTIM}\") {{ version {{ prefer(\"{VICTIM_VERSION}\") }} }}"
        ),
    };
    let deps = [request, tests];
    let deps: Vec<&str> = deps.iter().map(String::as_str).collect();
    let Some(c) = cell(dsl, &single(dsl, &deps, "")) else {
        return;
    };
    c.warm();
    c.serve_leaf(&Served::new(true));
    let (code, json) = c.scan_in(&c.proj, &[]);
    assert_eq!(code, Some(0), "{json}");
    assert!(has(&json, "redirect_gradle_classifier_declared"), "{json}");
    let snippet = snippet_code(&json);
    let build = c.proj.join(dsl.build_file());
    // The classifier request the snippet's pin cannot serve goes; the
    // request of the base stays.
    let text = std::fs::read_to_string(&build)
        .unwrap()
        .replace(deps[1], "");
    std::fs::write(&build, format!("{text}\n{snippet}\n")).unwrap();
    let out = c.build(&[]);
    assert!(
        !script_error(&out),
        "{what}: the pasted snippet does not compile:\n{snippet}\n{}",
        dump(&out)
    );
    if direct || ok(&out) {
        c.assert_patched(&out, &format!("fallback snippet ({what})"));
    } else {
        c.assert_fails_loud(&out, &format!("fallback snippet ({what})"));
    }
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_fallback_snippet_compiles_groovy() {
    fallback_case(Dsl::Groovy, Request::Direct);
    fallback_case(Dsl::Groovy, Request::Transitive);
    fallback_case(Dsl::Groovy, Request::PreferOnly);
}

#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_fallback_snippet_compiles_kotlin() {
    fallback_case(Dsl::Kotlin, Request::Direct);
    fallback_case(Dsl::Kotlin, Request::Transitive);
    fallback_case(Dsl::Kotlin, Request::PreferOnly);
}

/// #646 review: `latest.release` is refused (`redirect_gradle_latest_selector`)
/// with nothing written, and the build keeps resolving as before. Pinning
/// it would break it: with every upstream version at or below the base
/// rejected and none listed by the Socket repository, no version matches.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_latest_selector_refused() {
    for_each_dsl(|dsl| {
        let dep = implementation(dsl, &format!("{GROUP}:{VICTIM}:latest.release"));
        let Some(c) = cell(dsl, &single(dsl, &[&dep], "")) else {
            return;
        };
        c.warm();
        c.serve_leaf(&Served::new(true));
        let before = snapshot(&c.proj);
        let (code, json) = c.scan_in(&c.proj, &[]);
        assert_eq!(code, Some(0), "{json}");
        assert!(has(&json, "redirect_gradle_latest_selector"), "{json}");
        assert!(
            !has(&json, "redirect_gradle_dynamic_selector_pinned"),
            "{json}"
        );
        assert!(has(&json, "redirect_gradle_manual_snippet"), "{json}");
        assert_eq!(snapshot(&c.proj), before, "a refusal writes nothing");
        let out = c.build(&[]);
        c.assert_pristine(&out, "latest.release, refused");
    });
}

/// The agent-mode record `vendor` builds from: `Victim.class` patched.
fn stage_manifest(proj: &Path) {
    stage_manifest_as(proj, "patched");
}

/// [`stage_manifest`] with `Victim.class` in `state`.
fn stage_manifest_as(proj: &Path, state: &str) {
    let before = victim_class(VICTIM_VERSION, "pristine");
    let after = victim_class(VICTIM_VERSION, state);
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(proj.join(".socket/blobs").join(git_sha256(&after)), &after).unwrap();
    let manifest = serde_json::json!({ "patches": { purl(): {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { VICTIM_CLASS_MEMBER: {
            "beforeHash": git_sha256(&before),
            "afterHash": git_sha256(&after),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "gradle hosted takeover",
        "license": "MIT",
        "tier": "free",
    } } });
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// A vendored Gradle build switched to hosted (the vendored wiring is
/// reverted first, then the hosted wiring lands), and ejected back.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_vendored_takeover_and_eject() {
    for_each_dsl(|dsl| {
        let Some(c) = cell(
            dsl,
            &single(dsl, &[&implementation(dsl, &coordinate())], ""),
        ) else {
            return;
        };
        c.warm();
        stage_manifest(&c.proj);
        let (code, json) = c.vendor_cmd(None, &[]);
        assert_eq!(code, Some(0), "vendor: {json}");
        assert!(c.proj.join(".socket/vendor/gradle-index.tsv").is_file());
        // The vendored checkout: no manifest, no blobs.
        std::fs::remove_file(c.proj.join(".socket/manifest.json")).unwrap();
        std::fs::remove_dir_all(c.proj.join(".socket/blobs")).unwrap();
        let out = c.build(&[]);
        let (_, notice) = c.victim_on(&out, "vendored");
        assert_eq!(
            notice,
            pristine_notice(),
            "the vendored record patches the class only"
        );

        // The hosted record matches the vendored one (`Victim.class`), so the
        // eject below can vendor it from the same prebuilt.
        let served = Served::new(true);
        c.serve(
            &served,
            &[(
                VICTIM_CLASS_MEMBER.to_string(),
                victim_class(VICTIM_VERSION, "patched"),
            )],
        );
        let json = c.scan_ok();
        assert!(has(&json, "redirect_takeover_reverted_vendored"), "{json}");
        assert!(!c.proj.join(".socket/vendor/gradle-index.tsv").exists());
        let out = c.build(&[]);
        c.assert_patched(&out, "after the takeover");

        // The eject: the patch service (the vendor fixture server) builds
        // the prebuilt from the same record.
        let records = c.root.join("records");
        std::fs::create_dir_all(&records).unwrap();
        stage_manifest(&records);
        let api = c.api_args();
        let mut args: Vec<&str> = api.iter().map(String::as_str).collect();
        args.push("--yes");
        let (code, json) = c.vendor_cmd(Some(&records), &args);
        assert_eq!(code, Some(0), "eject: {json}");
        assert!(!c.proj.join(INDEX_REL).exists(), "the hosted index is gone");
        assert!(c.proj.join(".socket/vendor/gradle-index.tsv").is_file());
        let out = c.build(&[]);
        let (jar, _) = c.victim_on(&out, "ejected");
        assert!(
            jar.to_string_lossy()
                .replace('\\', "/")
                .contains(".socket/vendor/gradle/"),
            "the vendored jar: {}",
            jar.display()
        );
        let class = jar_member(&std::fs::read(&jar).unwrap(), VICTIM_CLASS_MEMBER).unwrap();
        assert_eq!(class, victim_class(VICTIM_VERSION, "patched"));
    });
}

/// A vendored Gradle build the hosted planner would refuse (a custom
/// `lockFile`): `scan --mode hosted` stages the vendored revert in memory,
/// the planner refuses the pin, and the takeover is retracted before
/// anything reaches the disk (the tree's jars included), so the vendored
/// patch keeps working.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_takeover_refusal_keeps_vendored() {
    // `lockFile = file(..)` is an assignment only the Groovy DSL takes on
    // every supported Gradle.
    let dsl = Dsl::Groovy;
    let custom = "dependencyLocking { lockFile = file('locks/custom.lockfile') }\n";
    let Some(c) = cell(
        dsl,
        &single(dsl, &[&implementation(dsl, &coordinate())], custom),
    ) else {
        return;
    };
    c.warm();
    stage_manifest(&c.proj);
    let (code, json) = c.vendor_cmd(None, &[]);
    assert_eq!(code, Some(0), "vendor: {json}");
    std::fs::remove_file(c.proj.join(".socket/manifest.json")).unwrap();
    std::fs::remove_dir_all(c.proj.join(".socket/blobs")).unwrap();
    let before = snapshot(&c.proj);
    c.serve(
        &Served::new(true),
        &[(
            VICTIM_CLASS_MEMBER.to_string(),
            victim_class(VICTIM_VERSION, "patched"),
        )],
    );
    let (_, json) = c.scan_in(&c.proj, &[]);
    assert!(
        has(&json, "redirect_gradle_lock_location_unknown"),
        "{json}"
    );
    assert!(!has(&json, "redirect_takeover_reverted_vendored"), "{json}");
    assert_eq!(json["redirect"]["redirected"], 0, "{json}");
    assert_eq!(snapshot(&c.proj), before, "nothing was reverted or written");
    let out = c.build(&[]);
    let (jar, _) = c.victim_on(&out, "still vendored");
    assert!(
        jar.to_string_lossy()
            .replace('\\', "/")
            .contains(".socket/vendor/gradle/"),
        "the vendored jar still resolves: {}",
        jar.display()
    );
}

/// An eject whose vendor step fails after the upstream restore rolls the
/// whole multi-build project back: the included build's and buildSrc's
/// settings (buildSrc's created by the planner) and the included build's
/// lock are byte-identical to the hosted checkout.
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_hosted_eject_rollback_multi_build() {
    for_each_dsl(|dsl| {
        let q = match dsl {
            Dsl::Groovy => "'",
            Dsl::Kotlin => "\"",
        };
        let mut files = single(dsl, &[&implementation(dsl, &coordinate())], "");
        files[0].1.push_str(&match dsl {
            Dsl::Groovy => "includeBuild 'tools'\n".to_string(),
            Dsl::Kotlin => "includeBuild(\"tools\")\n".to_string(),
        });
        files.push((
            format!("tools/{}", dsl.settings_file()),
            format!("rootProject.name = {q}tools{q}\n"),
        ));
        files.push((format!("tools/{}", dsl.build_file()), String::new()));
        files.push((
            "tools/gradle.lockfile".to_string(),
            format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}=runtimeClasspath\nempty=\n"),
        ));
        files.push((format!("buildSrc/{}", dsl.build_file()), String::new()));
        let Some(c) = cell(dsl, &files) else { return };
        c.warm();
        let served = Served::new(true);
        c.serve(
            &served,
            &[(
                VICTIM_CLASS_MEMBER.to_string(),
                victim_class(VICTIM_VERSION, "patched"),
            )],
        );
        c.scan_ok();
        let bsrc_settings = format!("buildSrc/{}", dsl.settings_file());
        assert!(c.file(&bsrc_settings).contains(" created"), "created");
        assert!(c.file("tools/gradle.lockfile").contains(&sfx()));
        let hosted = snapshot(&c.proj);
        // The prebuilt the fixture serves is not the record's patch, so
        // the vendor step fails after the restore.
        let records = c.root.join("records");
        std::fs::create_dir_all(&records).unwrap();
        stage_manifest_as(&records, "tampered");
        let api = c.api_args();
        let mut args: Vec<&str> = api.iter().map(String::as_str).collect();
        args.push("--yes");
        let (code, json) = c.vendor_cmd(Some(&records), &args);
        assert_ne!(code, Some(0), "the eject fails: {json}");
        assert!(has(&json, "eject_rolled_back"), "{json}");
        let after = snapshot(&c.proj);
        let changed: Vec<&String> = hosted
            .keys()
            .chain(after.keys())
            .filter(|k| hosted.get(*k) != after.get(*k))
            .collect();
        assert!(
            changed.is_empty(),
            "the rollback is byte-exact: {changed:?}"
        );
    });
}
