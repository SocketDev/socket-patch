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
//!      three files (v5: NO redirect ledger — the pom is the hosted state)
//!      and attests in-run `(redirected)`.
//!   4. FRESH CHECKOUT: only `pom.xml` + `.mvn/` + `.socket/` travel, the
//!      fixture is purged from the local repository, and Maven resolves
//!      with a user `settings.xml` mirroring ONLY `socket-patch-<uuid>`
//!      onto the wiremock origin (the pom keeps the real
//!      `https://patch.socket.dev` url — the committed shape manifest-less
//!      discovery must recognise). The resolved jar is byte-identical to the
//!      patched jar and the commons-lang3 transitive resolves.
//!   5. TAMPER probes: a stale `.sha1` is rejected by `checksumPolicy=fail`
//!      on every Maven line; a jar re-signed with a MATCHING `.sha1` is
//!      rejected by the trusted-checksums summary on Maven ≥ 3.9.4 (older
//!      lines do not read it: asserted, so a change in either direction
//!      is noticed). Both hold when the build is started with
//!      `-f <checkout>/pom.xml` from outside the project, which every
//!      Maven must survive: the line naming the checksums directory once
//!      stopped Maven 3.9.2 to 3.9.8 from starting there. The project's
//!      Maven Wrapper pins the Maven under test, so on Maven 4 the
//!      directory is spelled the one way Maven 4 reads. The same checkout
//!      without that pin is then scanned again: it takes the default
//!      spelling, the scan says what that trades away on Maven 4, and the
//!      Maven under test must start and resolve against it (on Maven 4,
//!      without enforcing the pin: asserted).
//!   6. MANIFEST-LESS VEX over the fresh checkout (`vex_e2e_common`):
//!      * online → attested from the pom wiring + the API record (the
//!        installed suffixed copy hash-verifies, `(redirected)`);
//!        `--offline` → `record_unavailable`, ZERO requests (hosted mode
//!        keeps no local record);
//!      * embedded `apply --vex` with no manifest attests the same;
//!      * a tampered installed jar → `hash_mismatch`;
//!      * the pom reverted to the registry version (`.mvn/` and the
//!        installed suffixed copy left behind) → nothing names the patch,
//!        with and without `--no-verify`.
//!   7. ROLLBACK (`--offline`: Maven restores with no network) returns the
//!      original project's pom byte-for-byte to its registry version and
//!      drops the `.mvn/` provenance hosted mode wrote.
//!
//! Gated like the other real-toolchain capstones: `#[ignore]` (network to
//! Maven Central for the fixture), toolchain selection and the
//! `SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}` gates in
//! `maven_build_common`.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "common/rollback_json.rs"]
mod rollback_json;

#[path = "hosted_maven_common/mod.rs"]
mod hosted_maven_common;
#[path = "maven_build_common/mod.rs"]
mod maven_build_common;
#[path = "maven_mediation_common/mod.rs"]
mod maven_mediation_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::path::{Path, PathBuf};

use hosted_maven_common::{Hosted, Server};
use maven_build_common::*;
use vex_e2e_common::*;

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

const HOSTED: Hosted = Hosted {
    org: ORG,
    uuid: UUID,
    hex8: HEX8,
    token: TOKEN,
    ghsa: GHSA,
    cve: CVE,
    group: GROUP,
    artifact: ARTIFACT,
    version: VERSION,
    title: "maven hosted capstone",
};

fn suffixed() -> String {
    HOSTED.suffixed()
}

/// The Socket repository path (mirror target and index url path).
fn repo_path() -> String {
    HOSTED.repo_path()
}

fn prod_index_url() -> String {
    HOSTED.prod_index_url()
}

/// `<repo>/<g>/<a>/<sfx>/<a>-<sfx>.<ext>` under the Socket repository.
fn served_path(ext: &str) -> String {
    HOSTED.served_path(ext)
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
    let out = HOSTED.served_pom(upstream);
    assert!(
        String::from_utf8_lossy(&out).contains("commons-lang3"),
        "transitive kept"
    );
    out
}

fn mount_api(s: &Server, jar: &[u8], pom: &[u8], view: &serde_json::Value) {
    hosted_maven_common::mount_api(s, &HOSTED, jar, pom, view);
}

/// `socket-patch <args>` in the hermetic environment
/// (`tests/common/hermetic.rs`) with the per-test local repository as the
/// crawler's maven repo.
fn socket(cwd: &Path, m2: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("MAVEN_REPO_LOCAL", m2)
        .env_remove("M2_HOME")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e})\n{stdout}\n{stderr}"));
    (out.status.code(), env, stderr)
}

/// Purge every suffixed copy of the fixture from `m2` so the next resolve
/// must fetch it. The base version stays: the project only asks for the
/// suffixed one, and `maven-dependency-plugin` itself depends on
/// commons-text 1.10.0, so purging it sends every later resolve back to
/// Central (CI run 37909555148).
fn purge(m2: &Path) {
    let Ok(versions) = std::fs::read_dir(m2.join(GROUP_PATH).join(ARTIFACT)) else {
        return;
    };
    for entry in versions.flatten() {
        if entry.file_name() != VERSION && entry.path().is_dir() {
            std::fs::remove_dir_all(entry.path()).unwrap();
        }
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
    // The project pins the Maven under test through the Maven Wrapper, so
    // the rewriter's "your Maven ignores the Trusted Checksums pin" warning
    // is judged against the same release that step 5b drives (#258).
    std::fs::create_dir_all(proj.join(".mvn/wrapper")).unwrap();
    std::fs::write(
        proj.join(".mvn/wrapper/maven-wrapper.properties"),
        format!(
            "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/\
             apache-maven/{v}/apache-maven-{v}-bin.zip\n",
            v = mvn.version
        ),
    )
    .unwrap();

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
    server.serve_repo(&HOSTED, &patched_jar, &sfx_pom, None);

    // 3. The real writer: three-file rewrite + in-run VEX, no ledger.
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
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(env["vex"]["statements"], 1, "{env}");
    let unenforced = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|w| w["code"] == "redirect_maven_trusted_checksums_unenforced");
    assert_eq!(
        unenforced,
        !mvn.enforces_trusted_checksums(),
        "Maven {}: the unenforced-pin warning must match what step 5b proves: {env}",
        mvn.version
    );
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
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode must not write the redirect ledger"
    );
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
    bad.serve_repo(&HOSTED, &tampered, &sfx_pom, Some(sha1_hex(&patched_jar)));
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
    resigned.serve_repo(&HOSTED, &tampered, &sfx_pom, None);
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

    // 4b. FROM OUTSIDE THE PROJECT: `mvn -f <checkout>/pom.xml` started in
    // another directory, as CI jobs commonly do. The line that names the
    // checksums directory must not stop any Maven from starting: spelled
    // with `${session.rootDirectory}`, as releases up to 5.1.0 wrote it,
    // Maven 3.9.2 to 3.9.8 refuse to start here (`Illegal use of undefined
    // property`). And where the pin is enforced it is enforced from here
    // too: the re-signed jar is rejected by the same Mavens as in 5b.
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let fresh_pom = fresh.join("pom.xml");
    let goal = format!("{DEPENDENCY_PLUGIN}:copy-dependencies");
    let from_outside = |settings: &Path, out_dir: &Path| {
        purge(&m2);
        let out_arg = format!("-DoutputDirectory={}", out_dir.display());
        mvn.run(
            &elsewhere,
            &m2,
            settings,
            &["-f", fresh_pom.to_str().unwrap(), &goal, &out_arg],
        )
    };
    let outside = root.join("outside-dep");
    let out = from_outside(&mirrored, &outside);
    assert!(
        ok(&out),
        "Maven {} started with -f from outside the project:\n{}",
        mvn.version,
        dump(&out)
    );
    assert_eq!(
        std::fs::read(outside.join(format!("{ARTIFACT}-{sfx}.jar"))).unwrap(),
        patched_jar,
        "and it resolves the patched jar"
    );
    let out = from_outside(&resigned_settings, &root.join("outside-resigned"));
    assert_eq!(
        !ok(&out),
        mvn.enforces_trusted_checksums(),
        "Maven {}: the re-signed jar, with -f from outside the project:\n{}",
        mvn.version,
        dump(&out)
    );
    if !ok(&out) {
        let log = dump(&out).to_ascii_lowercase();
        assert!(
            log.contains("checksum") && log.contains(&sha256_hex(&patched_jar)),
            "the rejection is the trusted sha256 pin, not the line itself:\n{}",
            dump(&out)
        );
    }
    let _ = std::fs::remove_dir_all(fresh.join("target"));

    // 4c. NO MAVEN DECLARED: the same checkout without the Maven Wrapper
    // pin, so nothing in it says which Maven builds it, scanned again. It
    // then takes the default spelling, the one that stops no Maven 3 from
    // starting, which Maven 4 does not read. So on the Maven 4 leg this is
    // Maven 4 run against the default spelling: the scan respells the
    // line and says what that trades away, the build starts and resolves
    // the patched jar, and the re-signed jar is no longer rejected. On a
    // Maven 3 leg the line already has that spelling and nothing changes.
    let undeclared = root.join("undeclared");
    fresh_checkout(&fresh, &undeclared);
    std::fs::remove_file(undeclared.join(".mvn/wrapper/maven-wrapper.properties")).unwrap();
    let config_before = std::fs::read_to_string(undeclared.join(".mvn/maven.config")).unwrap();
    let launcher_line = "basedir=${maven.multiModuleProjectDirectory}/.mvn/checksums";
    let session_line = "basedir=${session.rootDirectory}/.mvn/checksums";
    assert_eq!(
        config_before.contains(session_line),
        mvn.major() >= 4,
        "the wrapper pinned Maven {}:\n{config_before}",
        mvn.version
    );
    let (code, env, stderr) = socket(
        &undeclared,
        &m2,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            undeclared.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(code, Some(0), "rescan without a wrapper: {env}\n{stderr}");
    let config_after = std::fs::read_to_string(undeclared.join(".mvn/maven.config")).unwrap();
    assert!(
        config_after.contains(launcher_line) && !config_after.contains(session_line),
        "a project that declares no Maven takes the default spelling:\n{config_after}"
    );
    let warned = |code: &str| {
        env["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|w| w["code"] == code)
    };
    assert_eq!(
        warned("redirect_maven_trusted_checksums_maven3_only"),
        mvn.major() >= 4,
        "Maven {}: the scan says so when it trades the pin's enforcement on Maven 4 \
         away, and only then: {env}",
        mvn.version
    );
    assert!(
        !warned("redirect_maven_trusted_checksums_unenforced"),
        "no Maven is named, so none is said to ignore the pin: {env}"
    );
    assert_eq!(
        std::fs::read(undeclared.join("pom.xml")).unwrap(),
        std::fs::read(fresh.join("pom.xml")).unwrap(),
        "the pin itself is untouched"
    );
    let undeclared_pom = undeclared.join("pom.xml");
    let undeclared_from_outside = |settings: &Path, out_dir: &Path| {
        purge(&m2);
        let out_arg = format!("-DoutputDirectory={}", out_dir.display());
        mvn.run(
            &elsewhere,
            &m2,
            settings,
            &["-f", undeclared_pom.to_str().unwrap(), &goal, &out_arg],
        )
    };
    let outside = root.join("undeclared-dep");
    let out = undeclared_from_outside(&mirrored, &outside);
    assert!(
        ok(&out),
        "Maven {} against the default spelling, with -f from outside the project:\n{}",
        mvn.version,
        dump(&out)
    );
    assert_eq!(
        std::fs::read(outside.join(format!("{ARTIFACT}-{sfx}.jar"))).unwrap(),
        patched_jar,
        "and it resolves the patched jar"
    );
    purge(&m2);
    let out = mvn.copy_dependencies(&undeclared, &m2, &mirrored, "target/dep");
    assert!(ok(&out), "and from the project root:\n{}", dump(&out));
    // Enforced by Maven 3.9.4 and later 3.x, as the warning says: a Maven
    // 4 build of a project that does not declare Maven 4 runs as if the
    // pin were not there. (If a later Maven 4 starts reading the
    // launcher's property, this is where it shows.)
    let out = undeclared_from_outside(&resigned_settings, &root.join("undeclared-resigned"));
    assert_eq!(
        !ok(&out),
        mvn.enforces_trusted_checksums() && mvn.major() < 4,
        "Maven {}: the re-signed jar against the default spelling:\n{}",
        mvn.version,
        dump(&out)
    );
    let _ = std::fs::remove_dir_all(undeclared.join("target"));

    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &mirrored, "target/dep");
    assert!(ok(&out), "{}", dump(&out));
    std::fs::remove_dir_all(fresh.join("target")).unwrap();

    // 6. MANIFEST-LESS VEX.
    let api = PatchApi::start(vec![(UUID.to_string(), view.clone())]);
    let run = vex_run(&m2);

    // Online: the pom wiring + the API record; the installed suffixed copy
    // hash-verifies.
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

    // Offline: no local record (hosted mode keeps none) → record_unavailable
    // with zero network.
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

    // Reverted to the registry version, `.mvn/` + the installed suffixed
    // copy left behind: nothing names the patch any more, with and without
    // --no-verify.
    std::fs::write(fresh.join("pom.xml"), &pristine_pom).unwrap();
    for no_verify in [false, true] {
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                proxy_url: Some(api.uri()),
                no_verify,
                ..run.clone()
            },
        );
        assert_eq!(out.code, Some(2), "reverted no_verify={no_verify}: {out}");
        assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
        assert_absent(out.doc.as_ref(), &purl());
    }

    // 7. ROLLBACK of the original project: Maven's restore needs no
    // network, so `--offline` returns the pom byte-for-byte to its registry
    // version and drops the `.mvn/` provenance.
    let (code, env, stderr) = socket(
        &proj,
        &m2,
        &[
            "rollback",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "rollback --offline: {env}\n{stderr}");
    assert_eq!(
        rollback_json::hosted_reverted(&env),
        serde_json::json!([purl()]),
        "rollback restores the hosted pin: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("pom.xml")).unwrap(),
        pristine_pom,
        "rollback restores the pom byte-for-byte"
    );
    for rel in [".mvn/checksums/checksums.sha256", ".mvn/maven.config"] {
        assert!(
            !proj.join(rel).exists(),
            "rollback removes the {rel} hosted mode wrote"
        );
    }
    assert!(!proj.join(".socket/vendor/redirect-state.json").exists());
}

// ── a pin follows the version Maven selects ─────────────────────────────

mod mediation {
    use super::maven_mediation_common::{self as fixture, Shape};
    use super::*;

    const UUID: &str = "6f708192-a3b4-4c5d-8e6f-708192a3b4c5";
    const PATCH: Hosted = Hosted {
        org: ORG,
        uuid: UUID,
        hex8: "6f708192",
        token: "33333333-4444-4555-8666-777777777777",
        ghsa: "GHSA-mediation-maven-hosted",
        cve: "CVE-2026-7203",
        group: fixture::GROUP,
        artifact: fixture::VICTIM,
        version: fixture::BASE,
        title: "maven mediation capstone",
    };

    fn warning<'e>(env: &'e serde_json::Value, code: &str) -> Option<&'e serde_json::Value> {
        env["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|w| w["code"] == code)
    }

    /// A hosted scan never changes which version of an artifact a Maven
    /// build resolves. For each shape of the bug (a nearer version, an
    /// excluded path, a declaration of another version, a range, with the
    /// patch's base version elsewhere in the graph or only in the local
    /// repository) the scan leaves the project byte for byte as it was,
    /// exits 0 and says which version Maven selects; the jars Maven
    /// resolves afterwards are the jars it resolved before. Where the base
    /// version is the one selected, two levels down, the scan pins it and
    /// Maven resolves the patched jar in its place.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_pins_follow_the_version_maven_selects() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().canonicalize().unwrap();
        let m2 = root.join("m2");
        let plain = root.join("settings-plain.xml");
        write_settings(&plain, &[]);

        let server = Server::start();
        fixture::publish(&server);
        let patched_jar = fixture::patched_victim_jar();
        let suffixed = PATCH.suffixed();
        let served_pom = fixture::served_victim_pom(&suffixed).into_bytes();
        let view = patch_view(
            UUID,
            &fixture::purl(),
            &[(
                &fixture::victim_jar_name(fixture::BASE),
                &git_sha256(&patched_jar),
            )],
            &[(PATCH.ghsa, &[PATCH.cve])],
        );
        hosted_maven_common::mount_api(&server, &PATCH, &patched_jar, &served_pom, &view);
        fixture::answer_lookups_only_for(&server, ORG, &fixture::purl()["pkg:maven/".len()..]);
        server.serve_repo(&PATCH, &patched_jar, &served_pom, None);
        let scan = |proj: &Path| {
            socket(
                proj,
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
                ],
            )
        };

        // The base version is not the one selected: nothing may move. The
        // first shape runs against a local repository that holds nothing
        // else, where Maven reads the base version's pom and never fetches
        // its jar (the table's V5).
        let unselected = |shape: Shape| -> Option<()> {
            let proj = root.join(shape.name());
            fixture::write_project(&proj, shape, &server);
            let before = fixture::resolve(SUITE, &mvn, &proj, &m2, &plain, "target/before")?;
            assert!(
                before.contains_key(&fixture::victim_jar_name(shape.selects())),
                "{shape:?}: Maven selects {}: {:?}",
                shape.selects(),
                before.keys()
            );
            let pristine = fixture::snapshot(&proj);
            let (code, env, stderr) = scan(&proj);
            assert_eq!(code, Some(0), "{shape:?}: {env}\n{stderr}");
            assert_eq!(
                fixture::snapshot(&proj),
                pristine,
                "{shape:?}: the scan must write nothing: {env}"
            );
            // The line is owed whenever the scan saw the base version, which
            // it does once Maven has cached its pom.
            let base_pom = fixture::victim_dir(&m2, fixture::BASE).join(format!(
                "{}-{}.pom",
                fixture::VICTIM,
                fixture::BASE
            ));
            if base_pom.is_file() {
                let line = warning(&env, "redirect_maven_version_not_selected")
                    .unwrap_or_else(|| panic!("{shape:?}: no not-selected line: {env}"));
                let detail = line["detail"].as_str().unwrap_or_default();
                assert!(
                    detail.contains(&format!(
                        "Maven selects {}:{} {}",
                        fixture::GROUP,
                        fixture::VICTIM,
                        shape.selects()
                    )) && detail.contains(&format!("not {}", fixture::BASE)),
                    "{shape:?}: the line names the selected version: {detail}"
                );
            }
            assert_eq!(env["summary"]["failed"], 0, "{shape:?}: {env}");
            let after = fixture::resolve_warm(&mvn, &proj, &m2, &plain, "target/after", &[]);
            assert_eq!(
                after, before,
                "{shape:?}: Maven resolves what it resolved before"
            );
            Some(())
        };
        if unselected(Shape::NearerNewer).is_none() {
            return;
        }
        let base_dir = fixture::victim_dir(&m2, fixture::BASE);
        assert!(
            !base_dir
                .join(fixture::victim_jar_name(fixture::BASE))
                .exists(),
            "Maven never fetched the jar of the version that lost: {:?}",
            std::fs::read_dir(&base_dir)
                .map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
        );
        for shape in [Shape::NearerOlder, Shape::DirectOther, Shape::Excluded] {
            unselected(shape).expect("the local repository is warm");
        }

        // The base version is the one selected: the patched build takes its
        // place, and nothing else moves.
        let proj = root.join(Shape::Selected.name());
        fixture::write_project(&proj, Shape::Selected, &server);
        let before = fixture::resolve(SUITE, &mvn, &proj, &m2, &plain, "target/before")
            .expect("the local repository is warm");
        assert!(before.contains_key(&fixture::victim_jar_name(fixture::BASE)));
        let (code, env, stderr) = scan(&proj);
        assert_eq!(code, Some(0), "selected: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert!(
            warning(&env, "redirect_maven_version_not_selected").is_none(),
            "{env}"
        );
        let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
        assert!(
            wired.contains(&format!("<version>{suffixed}</version>"))
                && wired.contains(&format!("<id>socket-patch-{UUID}</id>")),
            "the pinned pom:\n{wired}"
        );
        let mirrored = root.join("settings-socket.xml");
        let mirror_url = format!("{}{}", server.uri(), PATCH.repo_path());
        write_settings(&mirrored, &[(&format!("socket-patch-{UUID}"), &mirror_url)]);
        let after = fixture::resolve_warm(&mvn, &proj, &m2, &mirrored, "target/after", &[]);
        assert_eq!(
            fixture::unsuffixed(after.keys()),
            before.keys().cloned().collect(),
            "the same artifacts, the victim in its patched build"
        );
        assert_eq!(
            after.get(&fixture::victim_jar_name(&suffixed)),
            Some(&patched_jar),
            "Maven resolves the patched jar: {:?}",
            after.keys()
        );
        for (name, bytes) in &before {
            if *name != fixture::victim_jar_name(fixture::BASE) {
                assert_eq!(after.get(name), Some(bytes), "{name} is untouched");
            }
        }
        // A second scan finds its pin and changes nothing.
        let pinned = fixture::snapshot(&proj);
        let (code, env, stderr) = scan(&proj);
        assert_eq!(code, Some(0), "rescan: {env}\n{stderr}");
        assert_eq!(
            fixture::snapshot(&proj),
            pinned,
            "a rescan is a no-op: {env}"
        );

        // The base version now sits in the local repository, jar and all,
        // and no pom of this project names it: a range selects another.
        unselected(Shape::Ranged).expect("the local repository is warm");
    }
}
