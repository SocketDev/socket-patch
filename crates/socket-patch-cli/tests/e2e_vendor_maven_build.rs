//! Real-Maven vendored-mode (`vendor`) host capstone, ending in
//! manifest-less VEX — the host twin of the docker `docker_e2e_vendor_maven`
//! (which pins the image's Debian Maven); this one runs whichever Maven the
//! `SOCKET_PATCH_MAVEN_E2E_*` gates select, so every Maven line in the
//! version matrix proves the same chain:
//!
//!   1. A consumer depending on `commons-text:1.10.0` (parent pom + the
//!      commons-lang3 transitive) is resolved from Maven Central into a
//!      per-test local repository — the ACTUAL registry bytes.
//!   2. A marker patch on the cached jar's `META-INF/NOTICE.txt` is staged
//!      (manifest + blob, real git-sha256 before/after hashes), and
//!      `vendor --json --offline --vex` (the real binary) rebuilds the jar
//!      into the committed maven2 tree `.socket/vendor/maven/<uuid>/…`,
//!      inserts the `socket-patch-vendor-<uuid>` file:// `<repository>`, and
//!      attests in-run `(vendored)`.
//!   3. FRESH CHECKOUT: only `pom.xml` + `.socket/` travel (the manifest and
//!      blobs deleted — the detached / depscan-PR shape), commons-text is
//!      purged from the local repository, and Maven resolves the patched jar
//!      from the file:// repository: byte-identical to the committed jar,
//!      NOTICE patched, the transitive declared by the vendored upstream pom.
//!   4. MANIFEST-LESS VEX over the fresh checkout (`vex_e2e_common`):
//!      * the ledger present → attested online and `--offline`;
//!      * the ledgers deleted, online → attested from the pom wiring + the
//!        committed artifact + the API record; `--offline` →
//!        `record_unavailable`, ZERO requests;
//!      * embedded `vendor --vex` and `apply --vex` with no manifest attest
//!        the same;
//!      * a tampered committed member → `vendor_hash_mismatch`;
//!      * the pom reverted to the registry version (ledger + artifact left
//!        behind) → `vendor_unwired`, with and without `--no-verify`; Maven
//!        then resolves Central's pristine jar and nothing attests.
//!   5. TAMPER probe: a mutated committed jar with its stale `.sha1` is
//!      never consumed (`checksumPolicy=fail`).
//!   6. The source project's `vendor --revert` byte-restores `pom.xml`, and
//!      nothing is left to attest.
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

const SUITE: &str = "e2e_vendor_maven_build";
const UUID: &str = "5e6f7081-92a3-4b4c-8d5e-6f708192a3b4";
const GHSA: &str = "GHSA-vendor-maven-real";
const CVE: &str = "CVE-2026-7202";
const PRODUCT: &str = "pkg:maven/com.example/app@1.0.0";

fn vulns() -> [(&'static str, &'static [&'static str]); 1] {
    [(GHSA, &[CVE])]
}

fn leaf_rel() -> String {
    format!(".socket/vendor/maven/{UUID}/{GROUP_PATH}/{ARTIFACT}/{VERSION}")
}

fn jar_rel() -> String {
    format!("{}/{ARTIFACT}-{VERSION}.jar", leaf_rel())
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

/// What `get` saves for an agent-mode patch: the manifest record + the
/// after-hash blob (so `vendor --offline` needs no network).
fn stage_manifest(proj: &Path, member_before: &[u8], member_after: &[u8]) {
    let record = serde_json::json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { MEMBER: {
            "beforeHash": git_sha256(member_before),
            "afterHash": git_sha256(member_after),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "maven vendored capstone",
        "license": "MIT",
        "tier": "free",
    });
    let manifest = serde_json::json!({ "patches": { purl(): record } });
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        proj.join(".socket/blobs").join(git_sha256(member_after)),
        member_after,
    )
    .unwrap();
}

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

#[test]
#[ignore = "real Maven + Maven Central (fixture); run with --ignored"]
fn maven_vendor_fresh_checkout_install_and_manifestless_vex() {
    let Some(mvn) = Mvn::detect(SUITE) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().canonicalize().unwrap();
    let m2 = root.join("m2");
    let proj = root.join("proj");
    let settings = root.join("settings.xml");
    write_settings(&settings, &[]);

    // 1. The ACTUAL registry bytes.
    let Some((jar, _pom)) = warm_fixture(SUITE, &mvn, &proj, &m2, &settings) else {
        return;
    };
    let pristine_pom = std::fs::read(proj.join("pom.xml")).unwrap();

    // 2. Stage the patch, then the real writer.
    let (orig, patched) = patched_member(&jar, UUID);
    stage_manifest(&proj, &orig, &patched);
    let (code, env, stderr) = socket(
        &proj,
        &m2,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
            "--vex",
            "embedded.vex.json",
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(code, Some(0), "vendor --vex: {env}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    let embedded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("embedded.vex.json")).unwrap()).unwrap();
    assert_attested(&embedded, &purl(), UUID, Marker::Vendored, &vulns());
    let vendored_jar = std::fs::read(proj.join(jar_rel())).unwrap();
    assert_jar_patched(&vendored_jar, &patched, "vendored jar");
    assert_ne!(vendored_jar, jar, "the committed jar is not Central's jar");
    let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
    assert!(
        wired.contains(&format!("<id>socket-patch-vendor-{UUID}</id>"))
            && wired.contains(&format!(
                "file://${{project.basedir}}/.socket/vendor/maven/{UUID}"
            ))
            && wired.contains("<checksumPolicy>fail</checksumPolicy>"),
        "vendored repository wiring:\n{wired}"
    );
    assert!(proj.join(".socket/vendor/state.json").is_file());

    // 3. Fresh checkout (no manifest, no blobs) + real resolve.
    let fresh = root.join("fresh");
    fresh_checkout(&proj, &fresh);
    strip_manifest(&fresh);
    std::fs::remove_dir_all(fresh.join(".socket/blobs")).unwrap();
    let _ = std::fs::remove_file(fresh.join("embedded.vex.json"));
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/dep");
    assert!(ok(&out), "fresh resolve failed:\n{}", dump(&out));
    let resolved =
        std::fs::read(fresh.join(format!("target/dep/{ARTIFACT}-{VERSION}.jar"))).unwrap();
    assert_eq!(
        resolved, vendored_jar,
        "Maven must consume the committed file:// jar, not Central's"
    );
    assert!(
        fresh.join(format!("target/dep/{TRANSITIVE_JAR}")).is_file(),
        "the vendored upstream pom's transitive must resolve"
    );
    std::fs::remove_dir_all(fresh.join("target")).unwrap();

    // 4. MANIFEST-LESS VEX.
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(UUID, &purl(), &[(MEMBER, &git_sha256(&patched))], &vulns()),
    )]);
    let run = vex_run(&m2);

    // Ledger present: online and offline.
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Vendored, &vulns());
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
    assert_attested(out.doc(), &purl(), UUID, Marker::Vendored, &vulns());
    quiet.assert_no_requests();

    // Ledgers gone: pom wiring + committed artifact + the API record.
    let ledger = std::fs::read(fresh.join(".socket/vendor/state.json")).unwrap();
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
    assert_attested(out.doc(), &purl(), UUID, Marker::Vendored, &vulns());
    assert!(
        api.view_requests(UUID) > before,
        "the record came from the API"
    );

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

    // Embedded, no manifest: `vendor --vex` and `apply --vex`.
    for via in [VexVia::Vendor, VexVia::Apply] {
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                via,
                proxy_url: Some(api.uri()),
                ..run.clone()
            },
        );
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        assert_attested(out.doc(), &purl(), UUID, Marker::Vendored, &vulns());
    }

    // A tampered committed member, RE-SIGNED (its `.sha1` updated): Maven
    // consumes it (the transport check passes), but the record's afterHash
    // no longer holds — omitted.
    let committed = fresh.join(jar_rel());
    let sidecar = fresh.join(format!("{}.sha1", jar_rel()));
    let good_sidecar = std::fs::read(&sidecar).unwrap();
    let tampered = jar_with_member(&vendored_jar, MEMBER, b"tampered\n");
    std::fs::write(&committed, &tampered).unwrap();
    std::fs::write(&sidecar, sha1_hex(&tampered)).unwrap();
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/resigned");
    assert!(ok(&out), "{}", dump(&out));
    assert_eq!(
        std::fs::read(fresh.join(format!("target/resigned/{ARTIFACT}-{VERSION}.jar"))).unwrap(),
        tampered,
        "a re-signed committed jar is what Maven builds"
    );
    let _ = std::fs::remove_dir_all(fresh.join("target"));
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, &purl(), "vendor_hash_mismatch");

    // 5. TAMPER probe: the mutated jar with its ORIGINAL (now stale)
    // `.sha1` is never what the build consumes — and never attested.
    std::fs::write(&sidecar, &good_sidecar).unwrap();
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/tamper");
    let consumed = std::fs::read(fresh.join(format!("target/tamper/{ARTIFACT}-{VERSION}.jar")));
    match consumed {
        // Maven moved on to the next repository (Central) after the
        // checksum failure: the build gets the PRISTINE registry jar.
        Ok(bytes) => {
            eprintln!(
                "TAMPER (Maven {}): checksum-rejected file:// copy, fell back to Central",
                mvn.version
            );
            assert!(ok(&out), "{}", dump(&out));
            assert_eq!(
                bytes,
                jar,
                "a tampered committed jar must never be consumed:\n{}",
                dump(&out)
            );
            assert!(
                dump(&out).to_ascii_lowercase().contains("checksum"),
                "the file:// copy was rejected on its checksum:\n{}",
                dump(&out)
            );
        }
        Err(_) => {
            eprintln!(
                "TAMPER (Maven {}): resolve failed on the checksum",
                mvn.version
            );
            assert!(
                !ok(&out) && dump(&out).to_ascii_lowercase().contains("checksum"),
                "a checksum failure:\n{}",
                dump(&out)
            );
        }
    }
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(2), "stale sidecar = no reference: {out}");
    assert_absent(out.doc.as_ref(), &purl());
    std::fs::write(&committed, &vendored_jar).unwrap();
    let _ = std::fs::remove_dir_all(fresh.join("target"));

    // Sidecar-only damage: the committed jar is intact (its members still
    // hash-verify against the record) but its `.sha1` — the checksum
    // `checksumPolicy=fail` validates — no longer matches (or is gone, e.g.
    // a `*.sha1` gitignore). Maven rejects the file:// copy and builds
    // Central's PRISTINE jar, so the vendored wiring is not what runs and
    // nothing may be attested — with or without the ledger.
    for (label, damage) in [("stale", Some("0".repeat(40))), ("missing", None)] {
        match &damage {
            Some(text) => std::fs::write(&sidecar, text).unwrap(),
            None => std::fs::remove_file(&sidecar).unwrap(),
        }
        purge(&m2);
        let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/sidecar");
        if let Ok(bytes) =
            std::fs::read(fresh.join(format!("target/sidecar/{ARTIFACT}-{VERSION}.jar")))
        {
            assert_eq!(
                bytes,
                jar,
                "{label} sidecar: Maven must not consume the file:// jar:\n{}",
                dump(&out)
            );
        }
        let _ = std::fs::remove_dir_all(fresh.join("target"));
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                proxy_url: Some(api.uri()),
                ..run.clone()
            },
        );
        assert_ne!(out.code, Some(0), "{label} sidecar must not attest: {out}");
        assert_absent(out.doc.as_ref(), &purl());
        std::fs::write(fresh.join(".socket/vendor/state.json"), &ledger).unwrap();
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                offline: true,
                proxy_url: Some(PatchApi::empty().uri()),
                ..run.clone()
            },
        );
        assert_eq!(out.code, Some(1), "{label} sidecar + ledger: {out}");
        assert_not_attested(&out.envelope, &purl(), "vendor_unwired");
        strip_ledgers(&fresh);
    }
    std::fs::write(&sidecar, &good_sidecar).unwrap();

    // The POM's sidecar is not load-bearing for consumption: a stale
    // `<a>-<v>.pom.sha1` sends only the descriptor to the next repository
    // (Central serves the same upstream pom the vendor tree copied
    // verbatim); the JAR still resolves from the file:// repository, so
    // the patch still runs and still attests.
    let pom_sidecar = fresh.join(format!("{}/{ARTIFACT}-{VERSION}.pom.sha1", leaf_rel()));
    let good_pom_sidecar = std::fs::read(&pom_sidecar).unwrap();
    std::fs::write(&pom_sidecar, "0".repeat(40)).unwrap();
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/pomsidecar");
    assert!(ok(&out), "{}", dump(&out));
    let consumed =
        std::fs::read(fresh.join(format!("target/pomsidecar/{ARTIFACT}-{VERSION}.jar"))).unwrap();
    eprintln!(
        "POM SIDECAR (Maven {}): consumed the {} jar",
        mvn.version,
        if consumed == vendored_jar {
            "vendored"
        } else {
            "registry"
        }
    );
    assert_eq!(
        consumed,
        vendored_jar,
        "a stale pom sidecar must not divert the jar:\n{}",
        dump(&out)
    );
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), &purl(), UUID, Marker::Vendored, &vulns());
    std::fs::write(&pom_sidecar, &good_pom_sidecar).unwrap();
    let _ = std::fs::remove_dir_all(fresh.join("target"));

    // Reverted to the registry version, ledger + artifact left behind:
    // dead, with and without --no-verify.
    std::fs::write(fresh.join("pom.xml"), &pristine_pom).unwrap();
    std::fs::write(fresh.join(".socket/vendor/state.json"), &ledger).unwrap();
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
        assert_not_attested(&out.envelope, &purl(), "vendor_unwired");
        assert_absent(out.doc.as_ref(), &purl());
    }
    // Maven now builds Central's pristine jar; without the ledger nothing
    // names a patch at all.
    purge(&m2);
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/reverted");
    assert!(ok(&out), "{}", dump(&out));
    assert_eq!(
        std::fs::read(fresh.join(format!("target/reverted/{ARTIFACT}-{VERSION}.jar"))).unwrap(),
        jar,
        "the reverted pom resolves Central's pristine jar"
    );
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

    // 6. The source project's real revert.
    let (code, env, stderr) = socket(
        &proj,
        &m2,
        &[
            "vendor",
            "--revert",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "vendor --revert: {env}\n{stderr}");
    assert_eq!(
        std::fs::read(proj.join("pom.xml")).unwrap(),
        pristine_pom,
        "revert byte-restores pom.xml"
    );
    assert!(!proj.join(".socket/vendor").exists());
    strip_manifest(&proj);
    let out = run_vex(
        &binary(),
        &proj,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(2), "{out}");
}
