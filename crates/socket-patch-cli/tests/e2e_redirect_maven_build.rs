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
    socket_with(cwd, m2, args, &[])
}

/// [`socket`] with `env` on top. Unless `env` says otherwise, the Maven
/// settings the CLI reads are the harness's empty ones
/// (`hermetic::neutral_maven_args`: `MAVEN_ARGS` is where the CLI looks
/// for the `-s` / `-gs` Maven would be started with): the mirrors of
/// whoever runs the suite must not decide a scan.
fn socket_with(
    cwd: &Path,
    m2: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("MAVEN_REPO_LOCAL", m2)
        .env_remove("M2_HOME")
        .env_remove("MAVEN_HOME")
        .envs(env.iter().copied())
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
    let filter = format!(".mvn/socket-patch/prefixes-socket-patch-{UUID}.txt");
    for rel in [
        ".mvn/checksums/checksums.sha256",
        ".mvn/maven.config",
        filter.as_str(),
    ] {
        assert!(
            !proj.join(rel).exists(),
            "rollback removes the {rel} hosted mode wrote"
        );
    }
    assert!(!proj.join(".socket/vendor/redirect-state.json").exists());
}

// ── a pin follows the version Maven selects ─────────────────────────────

mod mediation {
    use std::collections::BTreeMap;

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
    /// What a hosted mediation test runs against: the fixture repository,
    /// the patch API and the Socket repository of [`PATCH`] on one server,
    /// a cold local repository, and Maven settings without and with the
    /// Socket repository mirrored to that server.
    struct Bench {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        m2: PathBuf,
        plain: PathBuf,
        mirrored: PathBuf,
        server: Server,
        patched_jar: Vec<u8>,
        suffixed: String,
        view: serde_json::Value,
    }

    impl Bench {
        fn new() -> Bench {
            let tmp = tempfile::tempdir().unwrap();
            let root: PathBuf = tmp.path().canonicalize().unwrap();
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
            let mirrored = root.join("settings-socket.xml");
            let mirror_url = format!("{}{}", server.uri(), PATCH.repo_path());
            write_settings(&mirrored, &[(&format!("socket-patch-{UUID}"), &mirror_url)]);
            Bench {
                m2: root.join("m2"),
                _tmp: tmp,
                root,
                plain,
                mirrored,
                server,
                patched_jar,
                suffixed,
                view,
            }
        }

        fn scan(&self, proj: &Path) -> (Option<i32>, serde_json::Value, String) {
            self.scan_with(proj, &[])
        }

        /// [`Self::scan`] with extra environment for the CLI.
        fn scan_with(
            &self,
            proj: &Path,
            env: &[(&str, &str)],
        ) -> (Option<i32>, serde_json::Value, String) {
            socket_with(
                proj,
                &self.m2,
                &[
                    "scan",
                    "--mode",
                    "hosted",
                    "--json",
                    "--yes",
                    "--cwd",
                    proj.to_str().unwrap(),
                    "--api-url",
                    &self.server.uri(),
                    "--org",
                    ORG,
                    "--api-token",
                    "fake",
                ],
                env,
            )
        }

        /// Roll the project back (Maven's restore needs no network), and
        /// check that it is the hosted pin of the victim that went.
        fn rollback(&self, proj: &Path) {
            let (code, env, stderr) = socket(
                proj,
                &self.m2,
                &[
                    "rollback",
                    "--json",
                    "--offline",
                    "--cwd",
                    proj.to_str().unwrap(),
                ],
            );
            assert_eq!(code, Some(0), "rollback: {env}\n{stderr}");
            assert_eq!(
                rollback_json::hosted_reverted(&env),
                serde_json::json!([fixture::purl()]),
                "rollback restores the hosted pin: {env}"
            );
        }

        /// A second scan finds the wiring of the first and writes nothing.
        fn assert_rescan_is_a_no_op(&self, proj: &Path) {
            let pinned = fixture::snapshot(proj);
            let (code, env, stderr) = self.scan(proj);
            assert_eq!(code, Some(0), "rescan: {env}\n{stderr}");
            assert_eq!(
                fixture::snapshot(proj),
                pinned,
                "a rescan is a no-op: {env}"
            );
        }

        /// The invariant: `after` holds the artifacts of `before`, the
        /// base victim in its patched build and every other jar as it was.
        fn assert_only_the_victim_is_patched(
            &self,
            what: &str,
            before: &BTreeMap<String, Vec<u8>>,
            after: &BTreeMap<String, Vec<u8>>,
        ) {
            assert_eq!(
                fixture::unsuffixed(after.keys()),
                before.keys().cloned().collect(),
                "{what}: the same artifacts, the victim in its patched build"
            );
            assert_eq!(
                after.get(&fixture::victim_jar_name(&self.suffixed)),
                Some(&self.patched_jar),
                "{what}: Maven resolves the patched jar: {:?}",
                after.keys()
            );
            for (name, bytes) in before {
                if *name != fixture::victim_jar_name(fixture::BASE) {
                    assert_eq!(after.get(name), Some(bytes), "{what}: {name} is untouched");
                }
            }
        }
    }

    /// A `${property}` version is patched in hosted mode, with pom edits
    /// only, and no artifact that shares the property is moved:
    ///
    /// - a property only the patched artifact reads is rewritten itself;
    /// - a property a sibling artifact reads too stays as it is, and the
    ///   one declaration takes the patched version, the text it replaced
    ///   recorded beside it;
    /// - so does a declaration whose property a parent pom resolved from a
    ///   repository defines.
    ///
    /// In each, Maven resolves what it resolved before but for the patched
    /// build of the victim, a second scan writes nothing, and a rollback
    /// restores every file byte for byte and leaves none behind.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_patches_a_property_version_and_rolls_back_clean() {
        use fixture::Property;
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let bench = Bench::new();
        let suffixed = &bench.suffixed;
        for property in [Property::Own, Property::Shared, Property::OfParent] {
            let what = property.name();
            let proj = bench.root.join(what);
            std::fs::create_dir_all(&proj).unwrap();
            std::fs::write(
                proj.join("pom.xml"),
                fixture::property_pom(property, &bench.server),
            )
            .unwrap();
            let Some(before) =
                fixture::resolve(SUITE, &mvn, &proj, &bench.m2, &bench.plain, "target/before")
            else {
                return;
            };
            assert!(
                before.contains_key(&fixture::victim_jar_name(fixture::BASE)),
                "{what}: {:?}",
                before.keys()
            );
            let pristine = fixture::snapshot(&proj);

            let (code, env, stderr) = bench.scan(&proj);
            assert_eq!(code, Some(0), "{what}: {env}\n{stderr}");
            assert_eq!(env["summary"]["applied"], 1, "{what}: {env}");
            let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
            let reference = property.reference();
            match property {
                Property::Own => assert!(
                    wired.contains(&format!("<victim.version>{suffixed}</victim.version>"))
                        && wired.contains(&format!("<version>{reference}</version>")),
                    "the property takes the patched version, the declaration keeps its \
                     text:\n{wired}"
                ),
                Property::Shared | Property::OfParent => assert!(
                    wired.contains(&format!(
                        "<version>{suffixed}</version><!-- socket-patch:version {reference} -->"
                    )),
                    "{what}: the declaration takes the patched version, and says what it \
                     replaced:\n{wired}"
                ),
            }
            if property == Property::Shared {
                assert!(
                    wired.contains(&format!(
                        "<fixture.version>{}</fixture.version>",
                        fixture::BASE
                    )) && wired.contains(&fixture::dependency(fixture::SIBLING, &reference, "")),
                    "the property and the sibling that reads it are as they were:\n{wired}"
                );
            }
            assert!(
                wired.contains(&format!("<id>socket-patch-{UUID}</id>")),
                "{what}:\n{wired}"
            );

            let after =
                fixture::resolve_warm(&mvn, &proj, &bench.m2, &bench.mirrored, "target/after", &[]);
            bench.assert_only_the_victim_is_patched(what, &before, &after);
            bench.assert_rescan_is_a_no_op(&proj);

            bench.rollback(&proj);
            assert_eq!(
                fixture::snapshot(&proj),
                pristine,
                "{what}: rollback restores every file byte for byte and leaves none behind"
            );
        }
    }

    /// A multi-module reactor is patched in hosted mode module by module
    /// (the table's V3): the module that reaches the base version through
    /// another artifact gets the pin in its own pom, the module that
    /// declares it has that declaration rewritten, and the module that
    /// resolves a newer version is not touched and resolves what it
    /// resolved before. The repository and the Trusted Checksums sit at
    /// the root every module inherits, so a Maven started in a module
    /// directory resolves the patched jar too. `vex` attests the patch
    /// while every module that resolves the base version is wired, and
    /// withholds it, naming the module, once one is not. A rollback
    /// restores every pom byte for byte and removes what the scan created.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_patches_a_reactor_module_by_module_and_rolls_back_clean() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let bench = Bench::new();
        let suffixed = &bench.suffixed;
        let proj = bench.root.join("reactor");
        fixture::write_reactor(&proj, &bench.server);
        let Some(before) =
            fixture::resolve_reactor(SUITE, &mvn, &proj, &bench.m2, &bench.plain, "target/before")
        else {
            return;
        };
        let pristine = fixture::snapshot(&proj);
        let was = |rel: &str| String::from_utf8(pristine[rel].clone()).unwrap();
        let now = |rel: &str| std::fs::read_to_string(proj.join(rel)).unwrap();

        let (code, env, stderr) = bench.scan(&proj);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert!(
            warning(&env, "redirect_maven_multimodule_unsupported").is_none(),
            "{env}"
        );
        let a = now("a/pom.xml");
        assert!(
            a.contains(&format!(
                "<!-- socket-patch {UUID}: {}:{}:{} -->",
                fixture::GROUP,
                fixture::VICTIM,
                fixture::BASE
            )) && a.contains(&format!("<version>{suffixed}</version>")),
            "a reaches the base version through another artifact, and is pinned:\n{a}"
        );
        assert_eq!(
            now("c/pom.xml"),
            was("c/pom.xml").replace(
                &format!("<version>{}</version>", fixture::BASE),
                &format!("<version>{suffixed}</version>")
            ),
            "c declares the base version, and only that version text changes"
        );
        assert_eq!(
            now("b/pom.xml"),
            was("b/pom.xml"),
            "b resolves another version and is not touched"
        );
        let root = now("pom.xml");
        assert!(
            root.contains(&format!("<id>socket-patch-{UUID}</id>")) && !root.contains(suffixed),
            "the root takes the repository every module inherits, and no pin:\n{root}"
        );
        assert!(proj.join(".mvn/checksums/checksums.sha256").is_file());
        for module in ["a", "b", "c"] {
            assert!(
                !proj.join(module).join(".mvn").exists(),
                "{module}: the Trusted Checksums are the root's"
            );
        }

        let after = fixture::resolve_reactor(
            SUITE,
            &mvn,
            &proj,
            &bench.m2,
            &bench.mirrored,
            "target/after",
        )
        .expect("the local repository is warm");
        for (module, selects, ..) in fixture::REACTOR_MODULES {
            if selects == fixture::BASE {
                bench.assert_only_the_victim_is_patched(module, &before[module], &after[module]);
            } else {
                assert_eq!(
                    after[module], before[module],
                    "{module} resolves what it resolved before"
                );
            }
        }
        // Started in a module directory, Maven reads the parent pom for the
        // repository and the root's `.mvn` for the checksums.
        let from_module = fixture::resolve_warm(
            &mvn,
            &proj.join("a"),
            &bench.m2,
            &bench.mirrored,
            "target/from-module",
            &[],
        );
        bench.assert_only_the_victim_is_patched(
            "a, from its directory",
            &before["a"],
            &from_module,
        );
        bench.assert_rescan_is_a_no_op(&proj);

        // VEX: attested while every module that resolves the base version
        // is wired.
        let api = PatchApi::start(vec![(UUID.to_string(), bench.view.clone())]);
        let run = VexRun {
            proxy_url: Some(api.uri()),
            ..vex_run(&bench.m2)
        };
        let out = run_vex(&binary(), &proj, &run);
        assert_eq!(out.code, Some(0), "{out}");
        assert_attested(
            out.doc(),
            &fixture::purl(),
            UUID,
            Marker::Redirected,
            &[(PATCH.ghsa, &[PATCH.cve])],
        );
        // A module that comes to declare the base version itself builds the
        // unpatched jar, whatever its siblings are wired to.
        let wired_b = now("b/pom.xml");
        std::fs::write(
            proj.join("b/pom.xml"),
            fixture::module_pom("b", fixture::VICTIM, fixture::BASE),
        )
        .unwrap();
        let out = run_vex(&binary(), &proj, &run);
        assert_omitted(
            &out,
            &fixture::purl(),
            "vex_maven_reactor_root",
            "a module that builds the unpatched version",
        );
        assert!(
            out.envelope.to_string().contains("b/pom.xml"),
            "the note names the module: {out}"
        );
        std::fs::write(proj.join("b/pom.xml"), wired_b).unwrap();

        bench.rollback(&proj);
        assert_eq!(
            fixture::snapshot(&proj),
            pristine,
            "rollback restores every pom byte for byte and removes what the scan created"
        );
    }

    /// A declaration Maven reads only while a profile is active is not
    /// rewritten on its own: the scan would leave a version with no
    /// repository to serve it, which a build with that profile could not
    /// resolve and no rollback could find. The scan exits 0, says why, and
    /// writes nothing; the build with the profile resolves what it did.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_leaves_a_declaration_only_a_profile_holds() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let bench = Bench::new();
        let proj = bench.root.join("profile-only");
        std::fs::create_dir_all(proj.join("a")).unwrap();
        std::fs::create_dir_all(proj.join("b")).unwrap();
        std::fs::write(
            proj.join("pom.xml"),
            fixture::reactor_root_pom(&["a", "b"], &bench.server),
        )
        .unwrap();
        let profiled = fixture::module_pom("a", "lib-old", "1.0").replace(
            "</project>",
            &format!(
                "  <profiles>\n    <profile>\n      <id>with-victim</id>\n      \
                 <dependencies>\n{}      </dependencies>\n    </profile>\n  </profiles>\n</project>",
                fixture::dependency(fixture::VICTIM, fixture::BASE, "")
            ),
        );
        std::fs::write(proj.join("a/pom.xml"), profiled).unwrap();
        std::fs::write(
            proj.join("b/pom.xml"),
            fixture::module_pom("b", "lib-new", "1.0"),
        )
        .unwrap();
        // Warm the local repository (the dependency plugin, and the base
        // version the profile brings in).
        if fixture::resolve(
            SUITE,
            &mvn,
            &proj.join("b"),
            &bench.m2,
            &bench.plain,
            "target/warm",
        )
        .is_none()
        {
            return;
        }
        let with_profile = |out: &str| {
            fixture::resolve_warm(
                &mvn,
                &proj.join("a"),
                &bench.m2,
                &bench.plain,
                out,
                &["-Pwith-victim"],
            )
        };
        let before = with_profile("target/before");
        assert!(
            before.contains_key(&fixture::victim_jar_name(fixture::BASE)),
            "{:?}",
            before.keys()
        );
        let pristine = fixture::snapshot(&proj);

        let (code, env, stderr) = bench.scan(&proj);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(
            fixture::snapshot(&proj),
            pristine,
            "the scan writes nothing: {env}"
        );
        assert!(
            warning(&env, "redirect_maven_profile_dependency_unpatched").is_some(),
            "the scan says why: {env}"
        );
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        assert_eq!(
            with_profile("target/after"),
            before,
            "the profile's build resolves what it did"
        );
    }

    /// A single pom that inherits from a parent pom inside the checkout
    /// (no `<modules>`), its version a property that parent defines: the
    /// property and the repository are written in the parent's pom, where
    /// `rollback` finds them. Maven resolves the patched jar, and the
    /// rollback restores both poms byte for byte.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_patches_through_a_parent_pom_of_the_checkout() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let bench = Bench::new();
        let suffixed = &bench.suffixed;
        let proj = bench.root.join("local-parent");
        std::fs::create_dir_all(proj.join("parent")).unwrap();
        let property = format!(
            "  <properties>\n    <victim.version>{}</victim.version>\n  </properties>\n",
            fixture::BASE
        );
        let child = fixture::property_pom(fixture::Property::Own, &bench.server)
            .replace(&property, "")
            .replace(
                "  <groupId>com.example</groupId>\n",
                "  <parent>\n    <groupId>com.example</groupId>\n    \
                 <artifactId>base</artifactId>\n    <version>1.0.0</version>\n    \
                 <relativePath>parent/pom.xml</relativePath>\n  </parent>\n  \
                 <groupId>com.example</groupId>\n",
            );
        assert!(!child.contains("<properties>"), "{child}");
        std::fs::write(proj.join("pom.xml"), &child).unwrap();
        std::fs::write(
            proj.join("parent/pom.xml"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
                 <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
                 <artifactId>base</artifactId>\n  <version>1.0.0</version>\n  \
                 <packaging>pom</packaging>\n{property}</project>\n"
            ),
        )
        .unwrap();
        let Some(before) =
            fixture::resolve(SUITE, &mvn, &proj, &bench.m2, &bench.plain, "target/before")
        else {
            return;
        };
        let pristine = fixture::snapshot(&proj);

        let (code, env, stderr) = bench.scan(&proj);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        let parent = std::fs::read_to_string(proj.join("parent/pom.xml")).unwrap();
        assert!(
            parent.contains(&format!("<victim.version>{suffixed}</victim.version>"))
                && parent.contains(&format!("<id>socket-patch-{UUID}</id>")),
            "the parent takes the property and the repository:\n{parent}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("pom.xml")).unwrap(),
            child,
            "the pom that declares it keeps its text"
        );
        let after =
            fixture::resolve_warm(&mvn, &proj, &bench.m2, &bench.mirrored, "target/after", &[]);
        bench.assert_only_the_victim_is_patched("a local parent", &before, &after);
        bench.assert_rescan_is_a_no_op(&proj);

        bench.rollback(&proj);
        assert_eq!(
            fixture::snapshot(&proj),
            pristine,
            "rollback restores both poms byte for byte and leaves no file behind"
        );
    }

    /// A newer patch of the same version takes the place of an earlier
    /// one only where the poms let it. A module that still reads the
    /// earlier patch's version (through a property a profile may redefine,
    /// which no scan rewrites) keeps resolving it: the earlier patch's
    /// repository and checksum lines stay for as long as any pom of the
    /// reactor names it, so Maven resolves both modules.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_keeps_an_earlier_patch_served_while_a_module_names_it() {
        const NEWER_UUID: &str = "8192a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b";
        const NEWER: Hosted = Hosted {
            org: ORG,
            uuid: NEWER_UUID,
            hex8: "8192a3b4",
            token: "44444444-5555-4666-8777-888888888888",
            ghsa: "GHSA-mediation-maven-newer",
            cve: "CVE-2026-7204",
            group: fixture::GROUP,
            artifact: fixture::VICTIM,
            version: fixture::BASE,
            title: "maven mediation capstone, superseding",
        };
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let bench = Bench::new();
        let earlier = &bench.suffixed;
        let proj = bench.root.join("superseded");
        std::fs::create_dir_all(proj.join("a")).unwrap();
        std::fs::create_dir_all(proj.join("b")).unwrap();
        std::fs::write(
            proj.join("pom.xml"),
            fixture::reactor_root_pom(&["a", "b"], &bench.server),
        )
        .unwrap();
        std::fs::write(
            proj.join("a/pom.xml"),
            fixture::module_pom("a", "lib-deep", "1.0"),
        )
        .unwrap();
        let b = fixture::module_pom("b", fixture::VICTIM, "${victim.version}").replace(
            "  <dependencies>\n",
            &format!(
                "  <properties>\n    <victim.version>{}</victim.version>\n  </properties>\n  \
                 <dependencies>\n",
                fixture::BASE
            ),
        );
        std::fs::write(proj.join("b/pom.xml"), b).unwrap();
        let resolve_module = |module: &str, settings: &Path, out: &str| {
            fixture::resolve_warm(&mvn, &proj.join(module), &bench.m2, settings, out, &[])
        };
        if fixture::resolve(
            SUITE,
            &mvn,
            &proj.join("a"),
            &bench.m2,
            &bench.plain,
            "target/before",
        )
        .is_none()
        {
            return;
        }
        resolve_module("b", &bench.plain, "target/before");

        // The earlier patch: both modules resolve its build.
        let (code, env, stderr) = bench.scan(&proj);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        let read = |rel: &str| std::fs::read_to_string(proj.join(rel)).unwrap();
        assert!(
            read("b/pom.xml").contains(&format!("<victim.version>{earlier}</victim.version>")),
            "{}",
            read("b/pom.xml")
        );
        for module in ["a", "b"] {
            let jars = resolve_module(module, &bench.mirrored, "target/earlier");
            assert!(
                jars.contains_key(&fixture::victim_jar_name(earlier)),
                "{module}: {:?}",
                jars.keys()
            );
        }
        // b's property comes to be redefined by a profile: from here on no
        // scan may rewrite it, since that profile's build keeps its own.
        let profiled = read("b/pom.xml").replace(
            "</project>",
            &format!(
                "  <profiles>\n    <profile>\n      <id>older</id>\n      <properties>\n        \
                 <victim.version>{}</victim.version>\n      </properties>\n    </profile>\n  \
                 </profiles>\n</project>",
                fixture::OLDER
            ),
        );
        std::fs::write(proj.join("b/pom.xml"), &profiled).unwrap();

        // The newer patch, from its own server.
        let server = Server::start();
        let patched_jar = fixture::patched_victim_jar();
        let newer = NEWER.suffixed();
        let served_pom = fixture::served_victim_pom(&newer).into_bytes();
        let view = patch_view(
            NEWER_UUID,
            &fixture::purl(),
            &[(
                &fixture::victim_jar_name(fixture::BASE),
                &git_sha256(&patched_jar),
            )],
            &[(NEWER.ghsa, &[NEWER.cve])],
        );
        hosted_maven_common::mount_api(&server, &NEWER, &patched_jar, &served_pom, &view);
        fixture::answer_lookups_only_for(&server, ORG, &fixture::purl()["pkg:maven/".len()..]);
        server.serve_repo(&NEWER, &patched_jar, &served_pom, None);
        let (code, env, stderr) = socket(
            &proj,
            &bench.m2,
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
        );
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(read("b/pom.xml"), profiled, "b is left as it is: {env}");
        assert!(
            read("a/pom.xml").contains(&newer) || read("pom.xml").contains(&newer),
            "a moves to the newer patch: {env}"
        );
        let root = read("pom.xml");
        assert!(
            root.contains(&format!("<id>socket-patch-{UUID}</id>"))
                && root.contains(&format!("<id>socket-patch-{NEWER_UUID}</id>")),
            "both patches are still served: {root}"
        );
        let sums = read(".mvn/checksums/checksums.sha256");
        assert!(
            sums.contains(earlier.as_str()) && sums.contains(&newer),
            "both patches keep their checksum lines:\n{sums}"
        );

        // Maven resolves both modules, each from the repository of the
        // patch its pom names; the earlier one is fetched afresh.
        let _ = std::fs::remove_dir_all(fixture::victim_dir(&bench.m2, earlier));
        let both = bench.root.join("settings-both.xml");
        write_settings(
            &both,
            &[
                (
                    &format!("socket-patch-{UUID}"),
                    &format!("{}{}", bench.server.uri(), PATCH.repo_path()),
                ),
                (
                    &format!("socket-patch-{NEWER_UUID}"),
                    &format!("{}{}", server.uri(), NEWER.repo_path()),
                ),
            ],
        );
        let a = resolve_module("a", &both, "target/newer");
        assert!(
            a.contains_key(&fixture::victim_jar_name(&newer)),
            "a builds the newer patch: {:?}",
            a.keys()
        );
        let b = resolve_module("b", &both, "target/newer");
        assert!(
            b.contains_key(&fixture::victim_jar_name(earlier)),
            "b still builds the earlier patch, from its repository: {:?}",
            b.keys()
        );
    }

    /// Every file under `from`, copied into the new directory `to`.
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// A pom's `<repository>` is asked, before Maven Central, for every
    /// artifact and parent pom the local repository does not hold yet. The
    /// hosted scan therefore commits, with each pin, the prefix file that
    /// limits its Socket repository to the pinned version
    /// (`.mvn/socket-patch/prefixes-socket-patch-<uuid>.txt`) and the two
    /// resolver lines that make Maven read it.
    ///
    /// For a single pom and for a reactor, on a local repository that
    /// holds none of the project's artifacts:
    ///
    /// - Maven 3.9.2 and later (Maven 4 too) ask the Socket repository for
    ///   the patched version's jar and pom and their checksums, and for
    ///   nothing else;
    /// - an older Maven reads no such file and asks it for the rest too,
    ///   and still builds (asserted, so a change either way is noticed);
    /// - without the file (the wiring of an earlier release) every Maven
    ///   asks for the rest, which also shows the repository was cold;
    /// - a rollback takes the file and the lines out again, byte for byte.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_asks_the_socket_repository_only_for_the_patched_version() {
        use std::collections::BTreeSet;
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let b = Bench::new();
        // The prefix file is read by repository id, and a mirror gives a
        // repository its own: this one keeps the id the pom declares, as
        // the repository has on a machine that reaches patch.socket.dev.
        let id = format!("socket-patch-{UUID}");
        let settings = b.root.join("settings-socket-id.xml");
        let mirror_url = format!("{}{}", b.server.uri(), PATCH.repo_path());
        write_settings_with_ids(&settings, &[(&id, &id, &mirror_url)]);
        let repo = format!("{}/", PATCH.repo_path());
        let victim: BTreeSet<String> = ["jar", "jar.sha1", "pom", "pom.sha1"]
            .iter()
            .map(|ext| PATCH.served_path(ext)[repo.len()..].to_string())
            .collect();
        // What Maven asked of the Socket repository since request `mark`.
        let asked = |mark: usize| -> BTreeSet<String> {
            b.server.paths()[mark..]
                .iter()
                .filter_map(|path| path.strip_prefix(repo.as_str()).map(str::to_string))
                .collect()
        };

        for reactor in [false, true] {
            let name = if reactor { "reactor" } else { "single" };
            let proj = b.root.join(name);
            if reactor {
                fixture::write_reactor(&proj, &b.server);
            } else {
                fixture::write_project(&proj, Shape::Selected, &b.server);
            }
            // Warm the dependency plugin, and resolve what the scan reads
            // the selection from.
            let warmed = if reactor {
                fixture::resolve_reactor(SUITE, &mvn, &proj, &b.m2, &b.plain, "target/before")
                    .is_some()
            } else {
                fixture::resolve(SUITE, &mvn, &proj, &b.m2, &b.plain, "target/before").is_some()
            };
            if !warmed {
                return;
            }
            // The wired project, resolved into the local repository `m2`
            // (no fallback: nothing here may reach beyond the test's server).
            let resolve = |m2: &Path, what: &str| {
                let out = mvn.copy_dependencies(&proj, m2, &settings, "target/after");
                assert!(ok(&out), "{name}, {what}:\n{}", dump(&out));
                let _ = std::fs::remove_dir_all(proj.join("target"));
                for (module, ..) in fixture::REACTOR_MODULES {
                    let _ = std::fs::remove_dir_all(proj.join(module).join("target"));
                }
            };
            let pristine = fixture::snapshot(&proj);

            let (code, env, stderr) = b.scan(&proj);
            assert_eq!(code, Some(0), "{name}: {env}\n{stderr}");
            assert_eq!(env["summary"]["applied"], 1, "{name}: {env}");
            let filter = proj.join(format!(".mvn/socket-patch/prefixes-{id}.txt"));
            let listed = std::fs::read_to_string(&filter)
                .unwrap_or_else(|e| panic!("{name}: {}: {e}", filter.display()));
            assert_eq!(
                listed.lines().last(),
                Some(
                    format!(
                        "/{}/{}/{}",
                        fixture::GROUP_PATH,
                        fixture::VICTIM,
                        b.suffixed
                    )
                    .as_str()
                ),
                "{name}: {listed}"
            );
            assert!(
                warning(&env, "redirect_maven_repository_filter_conflict").is_none(),
                "{name}: {env}"
            );

            // A local repository with the dependency plugin and none of
            // the project's artifacts.
            let cold = |tag: &str| -> PathBuf {
                let m2 = b.root.join(format!("m2-{name}-{tag}"));
                copy_tree(&b.m2, &m2);
                std::fs::remove_dir_all(m2.join("com").join("socketfixture")).unwrap();
                m2
            };
            let rest = |asked: &BTreeSet<String>| -> Vec<String> {
                asked.difference(&victim).cloned().collect()
            };

            let mark = b.server.paths().len();
            resolve(&cold("filtered"), "with the prefix file");
            let filtered = asked(mark);
            assert!(
                filtered.is_superset(&victim),
                "{name}: the patched version comes from the Socket repository: {filtered:?}"
            );
            if mvn.filters_repositories() {
                assert_eq!(
                    rest(&filtered),
                    Vec::<String>::new(),
                    "{name}: Maven {} asks the Socket repository for nothing else",
                    mvn.version
                );
            } else {
                assert!(
                    !rest(&filtered).is_empty(),
                    "{name}: Maven {} reads no prefix file: {filtered:?}",
                    mvn.version
                );
            }

            std::fs::remove_file(&filter).unwrap();
            let mark = b.server.paths().len();
            resolve(&cold("unfiltered"), "without the prefix file");
            let unfiltered = asked(mark);
            assert!(
                unfiltered.is_superset(&victim) && !rest(&unfiltered).is_empty(),
                "{name}: without the file every Maven asks for the rest: {unfiltered:?}"
            );
            std::fs::write(&filter, listed).unwrap();

            b.rollback(&proj);
            let after = fixture::snapshot(&proj);
            // (Maven 4 keeps copies of the reactor's poms, as it last built
            // them, in a project-local repository under `.mvn/target/`.)
            let differ: BTreeSet<&String> = after
                .keys()
                .chain(pristine.keys())
                .filter(|rel| !rel.starts_with(".mvn/target/"))
                .filter(|rel| after.get(*rel) != pristine.get(*rel))
                .collect();
            assert!(
                differ.is_empty(),
                "{name}: a rollback takes the filter and its lines out again; these differ: \
                 {differ:?}"
            );
        }
    }

    /// A company's `<mirrorOf>*</mirrorOf>` sends every repository to its
    /// repository manager, the Socket one included, and the manager does
    /// not hold the patched version:
    ///
    /// - a project wired where no such mirror is configured no longer
    ///   builds behind it (the bug);
    /// - a scan that finds the mirror in the settings Maven would be
    ///   started with writes nothing, exits 0 and says why, naming the
    ///   mirror, its settings file and the two ways forward, and the
    ///   project builds behind the mirror as it did;
    /// - once the mirror leaves the Socket repository out, the same scan
    ///   wires the project, and it builds behind the mirror with the
    ///   patched jar.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_hosted_is_not_wired_behind_a_mirror_that_takes_every_repository() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let b = Bench::new();
        let proj = b.root.join("guarded");
        fixture::write_project(&proj, Shape::Selected, &b.server);
        let Some(before) = fixture::resolve(SUITE, &mvn, &proj, &b.m2, &b.plain, "target/before")
        else {
            return;
        };
        let pristine = fixture::snapshot(&proj);
        // The company's repository manager serves what the fixture
        // repository serves. (It keeps the id `central`, so the dependency
        // plugin the local repository holds is not fetched again.)
        let id = format!("socket-patch-{UUID}");
        let manager = format!("{}{}", b.server.uri(), fixture::REPO_ROUTE);
        let corp = b.root.join("settings-corp.xml");
        write_settings_with_ids(&corp, &[("central", "*", &manager)]);
        let maven_args = |settings: &Path| format!("-s {}", settings.display());
        // A local repository with the dependency plugin and none of the
        // project's artifacts: what a build behind the mirror starts from.
        // (Maven only probes, with a HEAD the test's server does not
        // answer, for an artifact it holds from another repository id.)
        let cold = |tag: &str| -> PathBuf {
            let m2 = b.root.join(format!("m2-{tag}"));
            copy_tree(&b.m2, &m2);
            std::fs::remove_dir_all(m2.join("com").join("socketfixture")).unwrap();
            m2
        };

        // Unguarded: wired where no mirror is configured, then built
        // behind the mirror.
        let wired = b.root.join("wired");
        fixture::write_project(&wired, Shape::Selected, &b.server);
        let (code, env, stderr) = b.scan(&wired);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        let out = mvn.copy_dependencies(&wired, &cold("unguarded"), &corp, "target/after");
        assert!(
            !ok(&out) && dump(&out).contains(&b.suffixed),
            "the mirror cannot serve the patched version:\n{}",
            dump(&out)
        );

        // Guarded: the scan reads the settings Maven would be started with.
        let (code, env, stderr) = b.scan_with(&proj, &[("MAVEN_ARGS", &maven_args(&corp))]);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 0, "{env}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let detail = warning(&env, "redirect_maven_mirror_captures_repository")
            .unwrap_or_else(|| panic!("the scan says why: {env}"))["detail"]
            .as_str()
            .unwrap()
            .to_string();
        for names in [
            "`central`",
            "<mirrorOf>*</mirrorOf>",
            corp.to_str().unwrap(),
            &format!("<mirrorOf>*,!{id}</mirrorOf>"),
            "scan --mode vendored",
            "Only this machine's settings were read",
        ] {
            assert!(detail.contains(names), "{names}: {detail}");
        }
        assert_eq!(
            fixture::snapshot(&proj),
            pristine,
            "the project is left untouched: {env}"
        );
        assert_eq!(
            fixture::resolve_warm(&mvn, &proj, &cold("guarded"), &corp, "target/guarded", &[]),
            before,
            "and builds behind the mirror as it did"
        );

        // The first way forward: the mirror leaves the repository out.
        // (The Socket repository is itself mirrored onto the test's
        // server, under its own id, which is what a mirror written for
        // that one repository looks like.)
        let excluding = b.root.join("settings-corp-excluding.xml");
        let socket_url = format!("{}{}", b.server.uri(), PATCH.repo_path());
        write_settings_with_ids(
            &excluding,
            &[
                ("central", &format!("*,!{id}"), &manager),
                (&id, &id, &socket_url),
            ],
        );
        let (code, env, stderr) = b.scan_with(&proj, &[("MAVEN_ARGS", &maven_args(&excluding))]);
        assert_eq!(code, Some(0), "{env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert!(
            warning(&env, "redirect_maven_mirror_captures_repository").is_none(),
            "{env}"
        );
        let after = fixture::resolve_warm(
            &mvn,
            &proj,
            &cold("excluding"),
            &excluding,
            "target/excluded",
            &[],
        );
        b.assert_only_the_victim_is_patched("behind the excluding mirror", &before, &after);
    }
}
