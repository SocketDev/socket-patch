//! Real-Maven hosted-mode (`scan --mode hosted`) capstone, ending in
//! manifest-less VEX — the maven twin of `e2e_redirect_cargo_build`.
//!
//! Maven's hosted redirect is fail-closed: the reference grant carries a
//! `maven2` registry override with a SUFFIXED version
//! (`<base>-socket.<first 8 hex of the patch uuid>`) that only the Socket
//! repository serves, so the rewriter pins the dependency to it, injects a
//! `socket-patch-<uuid>` `<repository>` (`checksumPolicy=fail`) and commits
//! the patched jar's + served pom's sha256 as Maven trusted checksums
//! (`.mvn/checksums/checksums.sha256` + `.mvn/maven.config`). This test
//! proves every link against a REAL Maven:
//!
//!   1. A consumer depending on `commons-text:1.10.0` (a parent pom + one
//!      transitive, commons-lang3) is resolved from Maven Central into a
//!      per-test local repository — the ACTUAL registry bytes.
//!   2. The patched jar (`META-INF/NOTICE.txt` + a marker) and the served
//!      pom (the upstream pom re-versioned to the suffixed version, so the
//!      transitive survives) are served from wiremock at the
//!      production-shaped `…/patch-registry/maven/<token>/<uuid>/maven2`
//!      path, next to the discovery / reference / view API mocks.
//!   3. `scan --mode hosted --json --vex …` (the real binary) rewires the
//!      three files, writes the ledger, and attests in-run `(redirected)`.
//!   4. FRESH CHECKOUT: only `pom.xml` + `.mvn/` + `.socket/` travel, the
//!      fixture is purged from the local repository, and Maven resolves
//!      with a user `settings.xml` mirroring ONLY `socket-patch-<uuid>`
//!      onto the wiremock origin (the pom keeps the real
//!      `https://patch.socket.dev` url — the committed shape manifest-less
//!      discovery must recognise). The resolved jar is byte-identical to the
//!      patched jar and the commons-lang3 transitive resolves.
//!   5. TAMPER probes: a stale `.sha1` is rejected by `checksumPolicy=fail`
//!      on every Maven line; a jar re-signed with a MATCHING `.sha1` is
//!      rejected by the trusted-checksums summary on Maven ≥ 3.9 (older
//!      lines ignore the `aether.*` properties — asserted, so a change in
//!      either direction is noticed).
//!   6. MANIFEST-LESS VEX over the fresh checkout (`vex_e2e_common`):
//!      * the ledger present, online → the installed suffixed copy
//!        hash-verifies, attested `(redirected)`; `--offline` → attested
//!        from the ledger's record;
//!      * the ledgers deleted, online → attested from the pom wiring +
//!        the API record; `--offline` → `record_unavailable`, ZERO
//!        requests;
//!      * embedded `apply --vex` with no manifest attests the same;
//!      * a tampered installed jar → `hash_mismatch`;
//!      * the pom reverted to the registry version (ledgers, `.mvn/` and
//!        the installed suffixed copy left behind) → `redirect_unwired`,
//!        with and without `--no-verify`.
//!
//! Gated like the other real-toolchain capstones: `#[ignore]` (network to
//! Maven Central for the fixture), toolchain selection and the
//! `SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}` gates in
//! `maven_build_common`.

#[path = "maven_build_common/mod.rs"]
mod maven_build_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::path::{Path, PathBuf};
use std::process::Command;

use maven_build_common::*;
use vex_e2e_common::*;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SUITE: &str = "e2e_redirect_maven_build";
const ORG: &str = "test-org";
/// Canonical lowercase patch uuid; its first 8 hex are the version suffix.
const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
const HEX8: &str = "4d5e6f70";
/// Grant-token path level of the hosted urls (uuid-shaped, like prod).
const TOKEN: &str = "22222222-3333-4444-8555-666666666666";
const GHSA: &str = "GHSA-redirect-maven-real";
const CVE: &str = "CVE-2026-7201";
const PRODUCT: &str = "pkg:maven/com.example/app@1.0.0";

fn suffixed() -> String {
    format!("{VERSION}-socket.{HEX8}")
}

/// The Socket repository path (mirror target and index url path).
fn repo_path() -> String {
    format!("/patch-registry/maven/{TOKEN}/{UUID}/maven2")
}

fn prod_index_url() -> String {
    format!("https://patch.socket.dev{}", repo_path())
}

/// `<repo>/<g>/<a>/<sfx>/<a>-<sfx>.<ext>` under the Socket repository.
fn served_path(ext: &str) -> String {
    let sfx = suffixed();
    format!(
        "{}/{GROUP_PATH}/{ARTIFACT}/{sfx}/{ARTIFACT}-{sfx}.{ext}",
        repo_path()
    )
}

/// The record's file key: the version-dir jar name (the consumed copy is
/// the suffixed dir's renamed jar — `vex_consumed::maven_copies`).
fn jar_key() -> String {
    format!("{ARTIFACT}-{VERSION}.jar")
}

/// The upstream pom re-versioned to the suffixed version (the project's
/// own `<version>` right after `</parent>`; the parent and the
/// dependencies — the transitive — are untouched).
fn served_pom(upstream: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(upstream.to_vec()).expect("utf-8 pom");
    let after_parent = text.find("</parent>").expect("commons-text has a parent") + 9;
    let needle = format!("<version>{VERSION}</version>");
    let at = after_parent + text[after_parent..].find(&needle).expect("project version");
    let mut out = text.clone();
    out.replace_range(
        at..at + needle.len(),
        &format!("<version>{}</version>", suffixed()),
    );
    assert!(out.contains("commons-lang3"), "transitive kept");
    out.into_bytes()
}

/// A wiremock server with its own runtime (the CLI and Maven run as
/// blocking child processes on the test thread).
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
        let server = rt.block_on(MockServer::start());
        Server { server, rt }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn get(&self, route: &str, status: u16, body: Vec<u8>) {
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(route.to_string()))
                .respond_with(ResponseTemplate::new(status).set_body_bytes(body))
                .mount(&self.server),
        );
    }

    /// Serve `jar` + `pom` (and `.sha1` sidecars: `jar_sha1` overrides the
    /// jar's) as the Socket repository's suffixed GAV.
    fn serve_repo(&self, jar: &[u8], pom: &[u8], jar_sha1: Option<String>) {
        self.get(&served_path("jar"), 200, jar.to_vec());
        self.get(
            &format!("{}.sha1", served_path("jar")),
            200,
            jar_sha1.unwrap_or_else(|| sha1_hex(jar)).into_bytes(),
        );
        self.get(&served_path("pom"), 200, pom.to_vec());
        self.get(
            &format!("{}.sha1", served_path("pom")),
            200,
            sha1_hex(pom).into_bytes(),
        );
    }

    fn paths(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

/// The API `scan --mode hosted` drives: batch discovery, the by-package
/// listing, the reference grant (maven2 override, production-shaped urls)
/// and the patch view.
fn mount_api(s: &Server, jar: &[u8], pom: &[u8], view: &serde_json::Value) {
    let purl = purl();
    let artifact_url = format!(
        "https://patch.socket.dev/patch/maven/{GROUP}/{ARTIFACT}/{VERSION}/{TOKEN}/{UUID}/{ARTIFACT}-{}.jar",
        suffixed()
    );
    let mounts = [
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [{ "purl": purl, "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free", "cveIds": [CVE],
                    "ghsaIds": [GHSA], "severity": "high", "title": "maven hosted capstone"
                }] }],
                "canAccessPaidPatches": false,
            }))),
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": UUID, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "d", "license": "MIT", "tier": "free",
                    "vulnerabilities": view["vulnerabilities"].clone()
                }],
                "canAccessPaidPatches": false,
            }))),
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/package")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": artifact_url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": artifact_url,
                        "integrity": { "sha1": sha1_hex(jar), "sha256": sha256_hex(jar) }
                    }],
                    "registryOverride": {
                        "kind": "maven2",
                        "indexUrl": prod_index_url(),
                        "identifiers": {
                            "name": format!("{GROUP}/{ARTIFACT}"),
                            "version": VERSION,
                            "mavenGroupId": GROUP,
                            "mavenArtifactId": ARTIFACT,
                            "mavenSuffixedVersion": suffixed(),
                            "mavenPomSha256": sha256_hex(pom),
                        }
                    }
                } }
            }))),
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view.clone())),
    ];
    for m in mounts {
        s.rt.block_on(m.mount(&s.server));
    }
}

/// `socket-patch <args>` with ambient `SOCKET_*` scrubbed and the per-test
/// local repository as the crawler's maven repo.
fn socket(cwd: &Path, m2: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", m2)
        .env_remove("M2_HOME")
        .env_remove("VIRTUAL_ENV")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e})\n{stdout}\n{stderr}"));
    (out.status.code(), env, stderr)
}

/// Purge every copy of the fixture GAV (base + suffixed) from `m2` so the
/// next resolve must fetch it.
fn purge(m2: &Path) {
    let dir = m2.join(GROUP_PATH).join(ARTIFACT);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

fn vex_run(m2: &Path) -> VexRun {
    VexRun {
        product: Some(PRODUCT.to_string()),
        ..VexRun::default()
    }
    .env("MAVEN_REPO_LOCAL", m2.as_os_str())
}

fn vulns() -> [(&'static str, &'static [&'static str]); 1] {
    [(GHSA, &[CVE])]
}

#[test]
#[ignore = "real Maven + Maven Central (fixture); run with --ignored"]
fn maven_scan_hosted_fresh_checkout_install_and_manifestless_vex() {
    let Some(mvn) = Mvn::detect(SUITE) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().canonicalize().unwrap();
    let m2 = root.join("m2");
    let proj = root.join("proj");
    let plain = root.join("settings-plain.xml");
    write_settings(&plain, &[]);

    // 1. The ACTUAL registry bytes.
    let Some((jar, pom)) = warm_fixture(SUITE, &mvn, &proj, &m2, &plain) else {
        return;
    };
    let pristine_pom = std::fs::read_to_string(proj.join("pom.xml")).unwrap();

    // 2. Patched jar + served pom + the record (real before/after hashes).
    let (_orig, patched) = patched_member(&jar, UUID);
    let patched_jar = jar_with_member(&jar, MEMBER, &patched);
    let sfx_pom = served_pom(&pom);
    let view = patch_view(
        UUID,
        &purl(),
        &[(&jar_key(), &git_sha256(&patched_jar))],
        &vulns(),
    );
    let server = Server::start();
    mount_api(&server, &patched_jar, &sfx_pom, &view);
    server.serve_repo(&patched_jar, &sfx_pom, None);

    // 3. The real writer: three-file rewrite + ledger + in-run VEX.
    let (code, env, stderr) = socket(
        &proj,
        &m2,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            "embedded.vex.json",
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(code, Some(0), "scan --mode hosted: {env}\n{stderr}");
    assert_eq!(env["redirect"]["mode"], "hosted", "{env}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env}");
    assert_eq!(env["vex"]["statements"], 1, "{env}");
    let embedded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("embedded.vex.json")).unwrap()).unwrap();
    assert_attested(&embedded, &purl(), UUID, Marker::Redirected, &vulns());
    let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
    assert!(
        wired.contains(&format!("<version>{}</version>", suffixed()))
            && wired.contains(&format!("<id>socket-patch-{UUID}</id>"))
            && wired.contains(&prod_index_url())
            && wired.contains("<checksumPolicy>fail</checksumPolicy>"),
        "fail-closed hosted pom:\n{wired}"
    );
    let checksums = std::fs::read_to_string(proj.join(".mvn/checksums/checksums.sha256")).unwrap();
    assert!(
        checksums.contains(&sha256_hex(&patched_jar)) && checksums.contains(&sha256_hex(&sfx_pom)),
        "trusted checksums pin the jar and the served pom:\n{checksums}"
    );
    assert!(proj.join(".socket/vendor/redirect-state.json").is_file());
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "hosted mode never writes the manifest"
    );

    // 4. Fresh checkout + real resolve through the Socket repository.
    let fresh = root.join("fresh");
    fresh_checkout(&proj, &fresh);
    strip_manifest(&fresh);
    let _ = std::fs::remove_file(fresh.join("embedded.vex.json"));
    let mirrored = root.join("settings-socket.xml");
    let mirror_url = format!("{}{}", server.uri(), repo_path());
    write_settings(&mirrored, &[(&format!("socket-patch-{UUID}"), &mirror_url)]);

    // 5a. TAMPER (transport): a mutated jar with its stale `.sha1`.
    let bad = Server::start();
    let mut tampered = patched_jar.clone();
    tampered.extend_from_slice(b"TAMPER");
    bad.serve_repo(&tampered, &sfx_pom, Some(sha1_hex(&patched_jar)));
    let bad_settings = root.join("settings-bad.xml");
    let bad_url = format!("{}{}", bad.uri(), repo_path());
    write_settings(
        &bad_settings,
        &[(&format!("socket-patch-{UUID}"), &bad_url)],
    );
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &bad_settings, "target/tamper");
    assert!(!ok(&out), "stale .sha1 must be rejected:\n{}", dump(&out));
    assert!(
        dump(&out).to_ascii_lowercase().contains("checksum"),
        "a checksum failure:\n{}",
        dump(&out)
    );

    // 5b. TAMPER (trusted checksums): the mutated jar re-signed with a
    // MATCHING `.sha1` passes transport validation; only the committed
    // sha256 summary can catch it.
    let resigned = Server::start();
    resigned.serve_repo(&tampered, &sfx_pom, None);
    let resigned_settings = root.join("settings-resigned.xml");
    let resigned_url = format!("{}{}", resigned.uri(), repo_path());
    write_settings(
        &resigned_settings,
        &[(&format!("socket-patch-{UUID}"), &resigned_url)],
    );
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &resigned_settings, "target/resigned");
    if mvn.enforces_trusted_checksums() {
        assert!(
            !ok(&out),
            "Maven {} must reject a re-signed jar against .mvn/checksums:\n{}",
            mvn.version,
            dump(&out)
        );
        let log = dump(&out).to_ascii_lowercase();
        assert!(
            log.contains("checksum") && log.contains(&sha256_hex(&patched_jar)),
            "the rejection must be the trusted sha256 pin, not an unrelated failure:\n{}",
            dump(&out)
        );
        eprintln!(
            "trusted-checksums rejection (Maven {}):\n{}",
            mvn.version,
            dump(&out)
        );
    } else {
        assert!(
            ok(&out),
            "Maven {} predates trusted checksums; the transport check alone passes a \
             re-signed jar (documented):\n{}",
            mvn.version,
            dump(&out)
        );
    }
    let _ = std::fs::remove_dir_all(fresh.join("target"));

    // 4 (cont). GREEN: the Socket repository is the only source of the
    // suffixed GAV; the transitive resolves too.
    purge(&m2);
    let before = server.paths().len();
    let out = mvn.copy_dependencies(&fresh, &m2, &mirrored, "target/dep");
    assert!(ok(&out), "fresh resolve failed:\n{}", dump(&out));
    let sfx = suffixed();
    let resolved = std::fs::read(fresh.join(format!("target/dep/{ARTIFACT}-{sfx}.jar"))).unwrap();
    assert_eq!(resolved, patched_jar, "the resolved jar is the patched jar");
    assert_jar_patched(&resolved, &patched, "resolved jar");
    assert!(
        fresh.join(format!("target/dep/{TRANSITIVE_JAR}")).is_file(),
        "the served pom's transitive must resolve"
    );
    assert!(
        server.paths()[before..]
            .iter()
            .any(|p| p == &served_path("jar")),
        "Maven fetched the jar from the Socket repository: {:?}",
        &server.paths()[before..]
    );
    let installed = repo_dir(&m2, &sfx).join(format!("{ARTIFACT}-{sfx}.jar"));
    assert_eq!(std::fs::read(&installed).unwrap(), patched_jar);
    std::fs::remove_dir_all(fresh.join("target")).unwrap();

    // 6. MANIFEST-LESS VEX.
    let api = PatchApi::start(vec![(UUID.to_string(), view.clone())]);
    let run = vex_run(&m2);

    // Ledger present, online: the installed suffixed copy hash-verifies.
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Redirected, &vulns());
    // ...and offline from the ledger's embedded record.
    let quiet = PatchApi::empty();
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            offline: true,
            proxy_url: Some(quiet.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Redirected, &vulns());
    quiet.assert_no_requests();

    // Ledgers gone: the pom wiring + the API record.
    let ledger = std::fs::read(fresh.join(".socket/vendor/redirect-state.json")).unwrap();
    strip_ledgers(&fresh);
    let before = api.view_requests(UUID);
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Redirected, &vulns());
    assert!(
        api.view_requests(UUID) > before,
        "the record came from the API"
    );
    // --no-verify: the same attestation, hashing skipped.
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            no_verify: true,
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Redirected, &vulns());

    // Offline, no ledgers: record_unavailable with zero network.
    let quiet = PatchApi::empty();
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            offline: true,
            proxy_url: Some(quiet.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, &purl(), "record_unavailable");
    quiet.assert_no_requests();

    // Embedded `apply --vex` with no manifest (no patches to apply; the
    // manifest-less VEX leg attests the wiring).
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            via: VexVia::Apply,
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(out.envelope["status"], "noManifest", "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Redirected, &vulns());

    // A tampered installed copy: the installed evidence wins.
    std::fs::write(&installed, &tampered).unwrap();
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, &purl(), "hash_mismatch");
    std::fs::write(&installed, &patched_jar).unwrap();

    // Reverted to the registry version, ledger + `.mvn/` + the installed
    // suffixed copy left behind: dead, with and without --no-verify.
    std::fs::write(fresh.join("pom.xml"), &pristine_pom).unwrap();
    std::fs::write(fresh.join(".socket/vendor/redirect-state.json"), &ledger).unwrap();
    for no_verify in [false, true] {
        let quiet = PatchApi::empty();
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                offline: true,
                no_verify,
                proxy_url: Some(quiet.uri()),
                ..run.clone()
            },
        );
        assert_eq!(out.code, Some(1), "reverted no_verify={no_verify}: {out}");
        assert_not_attested(&out.envelope, &purl(), "redirect_unwired");
        assert_absent(out.doc.as_ref(), &purl());
    }
    // ...and with the ledger gone too there is nothing to attest at all.
    strip_ledgers(&fresh);
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(2), "{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
}
