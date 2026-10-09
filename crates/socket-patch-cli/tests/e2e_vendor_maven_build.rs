//! Real-Maven vendored-mode (`vendor`) host capstone for a single-module
//! project, ending in manifest-less VEX — the host twin of the docker
//! `docker_e2e_vendor_maven` (which pins the image's Debian Maven); this one
//! runs whichever Maven the `SOCKET_PATCH_MAVEN_E2E_*` gates select, so
//! every Maven line in the version matrix proves the same chain:
//!
//!   1. A consumer depending on `commons-text:1.10.0` (parent pom + the
//!      commons-lang3 transitive) is resolved from Maven Central into a
//!      per-test local repository — the ACTUAL registry bytes.
//!   2. A marker patch on the cached jar's `META-INF/NOTICE.txt` is staged
//!      (manifest + blob, real git-sha256 before/after hashes), and
//!      `vendor --json --vex` (the real binary) plans the single-module pom
//!      as a reactor of one (#973): the suffixed tree
//!      `.socket/vendor/maven2/<g>/<a>/<v>-socket.<hex8>/`, the pinned
//!      `<version>`, `.mvn/maven.config` and the fallback
//!      `socket-patch-vendor` file repository. With no Maven Wrapper the run
//!      carries both wrapper-less `vendor_jvm_degraded` warnings
//!      (`maven_f_outside_root`, `maven_mirror_of_all`), and attests in-run
//!      `(vendored)`.
//!   3. FRESH CHECKOUT: only `pom.xml`, `.mvn/` and `.socket/` travel (the
//!      manifest and blobs deleted). Maven builds against the WARM local
//!      repository (Central's pristine 1.10.0 still cached: it cannot shadow
//!      the suffixed version) and again behind a `mirrorOf external:*`
//!      mirror: the resolved jar is the committed one, NOTICE patched, the
//!      transitive declared by the suffixed upstream pom.
//!   4. MANIFEST-LESS VEX over the fresh checkout (`vex_e2e_common`):
//!      * the ledger present → attested online and `--offline`, and by the
//!        embedded `vendor --vex` and `apply --vex` with no manifest;
//!      * the ledgers deleted → nothing attests (a planner pin is never
//!        attributed without its ledger);
//!      * a tampered committed member, re-signed or with its stale `.sha1`
//!        → never attested. Maven before 3.9.2 rejects the stale-`.sha1`
//!        copy on the fallback repository's `checksumPolicy=fail`; 3.9.2+
//!        builds it from the unchecked repository tail;
//!      * the pom reverted to the registry version (ledger + tree left
//!        behind) → `vendor_unwired`, with and without `--no-verify`, and
//!        Maven resolves Central's pristine jar.
//!   5. The source project's `vendor --revert` restores every byte, and
//!      nothing is left to attest.
//!
//! Gated like the other real-toolchain capstones: `#[ignore]` (network to
//! Maven Central for the fixture), toolchain selection and the
//! `SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}` gates in
//! `maven_build_common`.

#[path = "maven_build_common/mod.rs"]
mod maven_build_common;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;
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

/// The suffixed version the planner pins: `<base>-socket.<uuid hex8>`.
const SV: &str = "1.10.0-socket.5e6f7081";

fn tree_rel() -> String {
    format!(".socket/vendor/maven2/{GROUP_PATH}/{ARTIFACT}/{SV}")
}

fn jar_rel() -> String {
    format!("{}/{ARTIFACT}-{SV}.jar", tree_rel())
}

/// Every file under `dir` (relative, forward slashes) with its bytes.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy();
                out.insert(rel.replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
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
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        cwd,
        args,
        &[("MAVEN_REPO_LOCAL", m2.to_str().unwrap())],
    );
    let out = cmd
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
/// after-hash blob (input to the artifact fixture service).
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

/// The commons-text jar Maven copied into `<cwd>/<out_rel>`, and its name.
fn copied_jar(cwd: &Path, out_rel: &str) -> (String, Vec<u8>) {
    let dir = cwd.join(out_rel);
    let hits: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{ARTIFACT}-")))
        .collect();
    assert_eq!(hits.len(), 1, "{}: {hits:?}", dir.display());
    let bytes = std::fs::read(dir.join(&hits[0])).unwrap();
    (hits[0].clone(), bytes)
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
    let Some((jar, upstream_pom)) = warm_fixture(SUITE, &mvn, &proj, &m2, &settings) else {
        return;
    };
    let pristine_pom = std::fs::read(proj.join("pom.xml")).unwrap();

    // 2. Stage the patch, then the real writer.
    let (orig, patched) = patched_member(&jar, UUID);
    stage_manifest(&proj, &orig, &patched);
    let before = snapshot(&proj);
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
    // No Maven Wrapper: both wrapper-less warnings, whatever Maven runs.
    let text = env.to_string();
    for reason in ["maven_f_outside_root", "maven_mirror_of_all"] {
        assert!(
            text.contains("vendor_jvm_degraded") && text.contains(&format!("reason: {reason}: ")),
            "{reason}: {env}"
        );
    }
    assert!(!text.contains("vendor_maven_local_cache_shadow"), "{env}");
    let embedded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("embedded.vex.json")).unwrap()).unwrap();
    assert_attested(&embedded, &purl(), UUID, Marker::Vendored, &vulns());
    std::fs::remove_file(proj.join("embedded.vex.json")).unwrap();

    let vendored_jar = std::fs::read(proj.join(jar_rel())).unwrap();
    assert_jar_patched(&vendored_jar, &patched, "vendored jar");
    assert_eq!(
        std::fs::read_to_string(proj.join(format!("{}.sha1", jar_rel()))).unwrap(),
        sha1_hex(&vendored_jar)
    );
    let tree_pom =
        std::fs::read_to_string(proj.join(format!("{}/{ARTIFACT}-{SV}.pom", tree_rel()))).unwrap();
    assert_eq!(
        tree_pom.replace(SV, VERSION),
        String::from_utf8_lossy(&upstream_pom),
        "the suffixed pom differs from upstream only in its version"
    );
    let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
    for needle in [
        format!("<version>{SV}</version>"),
        "<id>socket-patch-vendor</id>".to_string(),
        "<url>file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2</url>".to_string(),
        "<checksumPolicy>fail</checksumPolicy>".to_string(),
    ] {
        assert!(wired.contains(&needle), "pom.xml lacks {needle}:\n{wired}");
    }
    assert!(!wired.contains(".socket/vendor/maven/"), "{wired}");
    assert_eq!(
        std::fs::read_to_string(proj.join(".mvn/maven.config")).unwrap(),
        "-Daether.offline.protocols=file\n\
         -Dmaven.repo.local.tail=${session.rootDirectory}/.socket/vendor/maven2\n"
    );
    assert!(!proj.join(".socket/vendor/maven").exists());
    assert!(proj.join(".socket/vendor/state.json").is_file());

    // An in-sync re-run writes nothing.
    let vendored = snapshot(&proj);
    let (code, env, stderr) = socket(
        &proj,
        &m2,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "re-vendor: {env}\n{stderr}");
    assert_eq!(
        snapshot(&proj),
        vendored,
        "an in-sync re-run writes nothing"
    );

    // 3. Fresh checkout (no manifest, no blobs) + real resolve against the
    // WARM local repository: Central's 1.10.0 cannot shadow the pin.
    let fresh = root.join("fresh");
    fresh_checkout(&proj, &fresh);
    strip_manifest(&fresh);
    std::fs::remove_dir_all(fresh.join(".socket/blobs")).unwrap();
    assert!(
        repo_dir(&m2, VERSION)
            .join(format!("{ARTIFACT}-{VERSION}.jar"))
            .is_file(),
        "the local repository stays warm"
    );
    let mirrored = root.join("mirrored-settings.xml");
    write_settings(
        &mirrored,
        &[("external:*", "https://repo.maven.apache.org/maven2")],
    );
    for (label, settings) in [("warm", &settings), ("mirrorOf external:*", &mirrored)] {
        let out = mvn.copy_dependencies(&fresh, &m2, settings, "target/dep");
        assert!(ok(&out), "{label}: fresh resolve failed:\n{}", dump(&out));
        let (name, resolved) = copied_jar(&fresh, "target/dep");
        assert_eq!(name, format!("{ARTIFACT}-{SV}.jar"), "{label}");
        assert_eq!(
            resolved, vendored_jar,
            "{label}: Maven must consume the committed jar, not Central's"
        );
        assert!(
            fresh.join(format!("target/dep/{TRANSITIVE_JAR}")).is_file(),
            "{label}: the suffixed upstream pom's transitive must resolve"
        );
        std::fs::remove_dir_all(fresh.join("target")).unwrap();
    }

    // 4. MANIFEST-LESS VEX.
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(UUID, &purl(), &[(MEMBER, &git_sha256(&patched))], &vulns()),
    )]);
    let run = vex_run(&m2);

    // Ledger present: online, offline, and embedded with no manifest.
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

    // Ledgers gone: a planner pin is never attributed without its ledger.
    let ledger = std::fs::read(fresh.join(".socket/vendor/state.json")).unwrap();
    strip_ledgers(&fresh);
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_ne!(out.code, Some(0), "{out}");
    assert_absent(out.doc.as_ref(), &purl());
    std::fs::write(fresh.join(".socket/vendor/state.json"), &ledger).unwrap();

    // A tampered committed member, RE-SIGNED (its `.sha1` updated): what
    // the build may consume no longer carries the record's afterHash, so
    // it is never attested.
    let committed = fresh.join(jar_rel());
    let sidecar = fresh.join(format!("{}.sha1", jar_rel()));
    let good_sidecar = std::fs::read(&sidecar).unwrap();
    let tampered = jar_with_member(&vendored_jar, MEMBER, b"tampered\n");
    std::fs::write(&committed, &tampered).unwrap();
    std::fs::write(&sidecar, sha1_hex(&tampered)).unwrap();
    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            proxy_url: Some(api.uri()),
            ..run.clone()
        },
    );
    assert_ne!(out.code, Some(0), "a tampered tree must not attest: {out}");
    assert_absent(out.doc.as_ref(), &purl());

    // TAMPER probe: the mutated jar with its ORIGINAL (now stale) `.sha1`.
    // Before 3.9.2 Maven reads the fallback `checksumPolicy=fail` file
    // repository, so the checksum rejects the copy. 3.9.2+ reads the
    // `maven.repo.local.tail` tree, a local repository Maven does not
    // checksum, so the tampered jar is what builds; there the gate is the
    // committed tree's review and VEX, which never attests it (below).
    // A COLD re-resolve: step 3 cached the suffixed artifact in the local
    // repository, which Maven serves without re-reading (or re-checksumming)
    // any remote, so the cached copy is dropped first. Central's pristine
    // 1.10.0 stays warm (it cannot shadow the suffixed version).
    std::fs::write(&sidecar, &good_sidecar).unwrap();
    let cached = repo_dir(&m2, SV);
    if cached.exists() {
        std::fs::remove_dir_all(&cached).unwrap();
    }
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/tamper");
    if mvn.numeric() >= vec![3, 9, 2] {
        assert!(ok(&out), "{}", dump(&out));
        assert_eq!(
            copied_jar(&fresh, "target/tamper"),
            (format!("{ARTIFACT}-{SV}.jar"), tampered.clone()),
            "Maven {} reads the unchecked repository tail",
            mvn.version
        );
    } else {
        assert!(
            !ok(&out) && dump(&out).to_ascii_lowercase().contains("checksum"),
            "Maven {}: the fallback repository rejects the stale checksum:\n{}",
            mvn.version,
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
    assert_ne!(out.code, Some(0), "a tampered tree must not attest: {out}");
    assert_absent(out.doc.as_ref(), &purl());
    std::fs::write(&committed, &vendored_jar).unwrap();

    // Reverted to the registry version, ledger + tree left behind: dead,
    // with and without --no-verify, and Maven builds Central's jar.
    std::fs::write(fresh.join("pom.xml"), &pristine_pom).unwrap();
    std::fs::remove_dir_all(fresh.join(".mvn")).unwrap();
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
    let out = mvn.copy_dependencies(&fresh, &m2, &settings, "target/reverted");
    assert!(ok(&out), "{}", dump(&out));
    assert_eq!(
        copied_jar(&fresh, "target/reverted"),
        (format!("{ARTIFACT}-{VERSION}.jar"), jar.clone()),
        "the reverted pom resolves Central's pristine jar"
    );

    // 5. The source project's real revert.
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
    assert_eq!(snapshot(&proj), before, "revert restores every byte");
    assert!(!proj.join(".mvn").exists());
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
