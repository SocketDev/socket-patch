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

#[path = "hosted_maven_common/mod.rs"]
mod hosted_maven_common;
#[path = "maven_build_common/mod.rs"]
mod maven_build_common;
#[path = "maven_mediation_common/mod.rs"]
mod maven_mediation_common;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::path::{Path, PathBuf};

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

/// `socket-patch <args>` in the hermetic environment and the per-test
/// local repository as the crawler's maven repo.
fn socket(cwd: &Path, m2: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        cwd,
        args,
        &[("MAVEN_REPO_LOCAL", m2.to_str().unwrap())],
    );
    let out = cmd
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

/// What `get` saves for an agent-mode patch: the manifest record + the
/// after-hash blob (input to the artifact fixture service).
fn stage_manifest(proj: &Path, member_before: &[u8], member_after: &[u8]) {
    stage_manifest_of(proj, &purl(), MEMBER, member_before, member_after);
}

/// [`stage_manifest`] for the jar member `member` of `purl`.
fn stage_manifest_of(
    proj: &Path,
    purl: &str,
    member: &str,
    member_before: &[u8],
    member_after: &[u8],
) {
    let record = serde_json::json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { member: {
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
    let manifest = serde_json::json!({ "patches": { purl: record } });
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
    // The mirror keeps the id `central` so the warm plugin closure (cached
    // under that id) is reused instead of re-fetched from Central (CI run
    // 37909555148).
    let mirrored = root.join("mirrored-settings.xml");
    write_settings_with_ids(
        &mirrored,
        &[(
            "central",
            "external:*",
            "https://repo.maven.apache.org/maven2",
        )],
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

/// The log4j shape, on the real artifact: `log4j-core:2.17.1` has no
/// `<version>` of its own and names `log4j-api` without one; both come from
/// its parent pom, which manages every sibling at `${project.version}`.
/// Maven interpolates a pom after merging its parents into it, so in a pom
/// that only had its own version suffixed that reference named
/// `log4j-api:2.17.1-socket.<hex8>`, which nothing serves: `vendor` and
/// `vendor --check` reported success and the build failed. The vendored
/// pom must resolve what the upstream pom does, so a fresh checkout builds
/// with the patched jar and the sibling at its base version.
#[test]
#[ignore = "real Maven + Maven Central (fixture); run with --ignored"]
fn maven_vendor_keeps_a_sibling_the_parent_manages_at_the_base_version() {
    const G: &str = "org.apache.logging.log4j";
    const A: &str = "log4j-core";
    const V: &str = "2.17.1";
    const SIBLING: &str = "log4j-api-2.17.1.jar";
    const NOTICE: &str = "META-INF/NOTICE";
    let sv = format!("{V}-socket.5e6f7081");
    let Some(mvn) = Mvn::detect(SUITE) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().canonicalize().unwrap();
    let (m2, proj) = (root.join("m2"), root.join("proj"));
    let settings = root.join("settings.xml");
    write_settings(&settings, &[]);
    let copy_dependencies = |cwd: &Path, settings: &Path, extra: &[&str]| {
        let _ = std::fs::remove_dir_all(cwd.join("target"));
        let goal = format!("{DEPENDENCY_PLUGIN}:copy-dependencies");
        let mut args = vec![goal.as_str(), "-DoutputDirectory=target/dep"];
        args.extend_from_slice(extra);
        mvn.run(cwd, &m2, settings, &args)
    };
    let copied = |cwd: &Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(cwd.join("target/dep"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };

    // 1. The ACTUAL registry bytes: the jar, its pom and the parent chain.
    std::fs::create_dir_all(&proj).unwrap();
    let pom = consumer_pom(V).replace(GROUP, G).replace(ARTIFACT, A);
    std::fs::write(proj.join("pom.xml"), &pom).unwrap();
    let out = with_central_fallback(SUITE, "log4j warm-up", &settings, |s, extra| {
        copy_dependencies(&proj, s, extra)
    });
    if !ok(&out) {
        skip(
            SUITE,
            &format!(
                "log4j warm-up against Maven Central failed:\n{}",
                dump(&out)
            ),
        );
        return;
    }
    assert_eq!(
        copied(&proj),
        [SIBLING.to_string(), format!("{A}-{V}.jar")],
        "the pristine build resolves log4j-core and its sibling"
    );
    std::fs::remove_dir_all(proj.join("target")).unwrap();
    let cached = m2.join(G.replace('.', "/")).join(A).join(V);
    let jar = std::fs::read(cached.join(format!("{A}-{V}.jar"))).unwrap();
    let upstream_pom = std::fs::read_to_string(cached.join(format!("{A}-{V}.pom"))).unwrap();
    assert!(
        upstream_pom.contains("<parent>")
            && upstream_pom.contains("<artifactId>log4j-api</artifactId>"),
        "fixture: log4j-core names its sibling and inherits from a parent"
    );

    // 2. A marker patch, then the real writer.
    let orig = jar_member(&jar, NOTICE).expect("NOTICE in the upstream jar");
    let mut patched = orig.clone();
    patched.extend_from_slice(format!("\n{MARKER} log4j\n").as_bytes());
    stage_manifest_of(
        &proj,
        &format!("pkg:maven/{G}/{A}@{V}"),
        NOTICE,
        &orig,
        &patched,
    );
    let cwd = proj.to_str().unwrap();
    let (code, env, stderr) = socket(&proj, &m2, &["vendor", "--json", "--offline", "--cwd", cwd]);
    assert_eq!(code, Some(0), "vendor: {env}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let tree = proj.join(format!(
        ".socket/vendor/maven2/{}/{A}/{sv}",
        G.replace('.', "/")
    ));
    let tree_pom = std::fs::read_to_string(tree.join(format!("{A}-{sv}.pom"))).unwrap();
    assert!(
        tree_pom.contains("socket-patch:inherited:begin")
            && !tree_pom.contains("${project.version}"),
        "the suffixed pom declares what it inherited through the pom's version:\n{tree_pom}"
    );

    // 3. `--check` agrees, and a fresh checkout builds: the patched jar,
    // and the sibling at the version upstream resolves.
    let (code, env, stderr) = socket(&proj, &m2, &["vendor", "--check", "--json", "--cwd", cwd]);
    assert_eq!(code, Some(0), "vendor --check: {env}\n{stderr}");
    let fresh = root.join("fresh");
    fresh_checkout(&proj, &fresh);
    let out = copy_dependencies(&fresh, &settings, &[]);
    assert!(ok(&out), "fresh resolve failed:\n{}", dump(&out));
    assert_eq!(
        copied(&fresh),
        [SIBLING.to_string(), format!("{A}-{sv}.jar")],
        "Maven resolves the vendored jar and the sibling at its base version"
    );
    let resolved = std::fs::read(fresh.join(format!("target/dep/{A}-{sv}.jar"))).unwrap();
    assert_eq!(
        jar_member(&resolved, NOTICE).as_deref(),
        Some(patched.as_slice()),
        "Maven consumes the committed, patched jar"
    );
}

// ── a pin follows the version Maven selects ─────────────────────────────

mod mediation {
    use super::hosted_maven_common::Server;
    use super::maven_mediation_common::{self as fixture, Shape};
    use super::*;

    const UUID: &str = "708192a3-b4c5-4d6e-8f70-8192a3b4c5d6";
    const ORG: &str = "test-org";

    /// The base victim's version as vendoring pins it.
    fn suffixed() -> String {
        format!("{}-socket.{}", fixture::BASE, &UUID[..8])
    }

    /// What `get` saves for the patch of the base victim: the manifest
    /// record and the after-hash blob.
    fn stage(proj: &Path) {
        let (before, after) = (
            fixture::pristine_member(fixture::VICTIM, fixture::BASE),
            fixture::patched_member(),
        );
        let record = serde_json::json!({
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { fixture::MEMBER: {
                "beforeHash": git_sha256(&before),
                "afterHash": git_sha256(&after),
            } },
            "vulnerabilities": { "GHSA-mediation-maven-vendored": {
                "cves": ["CVE-2026-7204"], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "maven mediation capstone",
            "license": "MIT",
            "tier": "free",
        });
        let manifest = serde_json::json!({ "patches": { fixture::purl(): record } });
        std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
        std::fs::write(
            proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(proj.join(".socket/blobs").join(git_sha256(&after)), after).unwrap();
    }

    /// The committed wiring is the record of where a patch is pinned: it
    /// checks clean and a re-run leaves it alone on any machine, whatever
    /// that machine's local repository holds. A project whose parent pom
    /// comes from a repository is vendored on a machine that never
    /// resolved it (what Maven selects cannot be told there, so the
    /// declaration is rewritten and no pin is written). On a machine that
    /// did resolve it, `vendor --check` passes, a second `vendor` changes
    /// no byte, and Maven builds the patched jar.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_vendored_wiring_checks_clean_and_stays_put_on_any_machine() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().canonicalize().unwrap();
        let (warm, cold) = (root.join("m2-warm"), root.join("m2-cold"));
        let settings = root.join("settings.xml");
        write_settings(&settings, &[]);
        let server = Server::start();
        fixture::publish(&server);
        let proj = root.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("pom.xml"), fixture::parented_pom(&server)).unwrap();
        let Some(before) = fixture::resolve(SUITE, &mvn, &proj, &warm, &settings, "target/before")
        else {
            return;
        };
        assert!(before.contains_key(&fixture::victim_jar_name(fixture::BASE)));
        // The other machine holds the installed victim and nothing else of
        // this build: not the parent pom its selection hangs on.
        let installed = fixture::victim_dir(&cold, fixture::BASE);
        std::fs::create_dir_all(&installed).unwrap();
        for entry in std::fs::read_dir(fixture::victim_dir(&warm, fixture::BASE)).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), installed.join(entry.file_name())).unwrap();
        }
        let vendor = |m2: &Path, args: &[&str]| {
            let mut all = vec!["vendor"];
            all.extend_from_slice(args);
            all.extend_from_slice(&["--json", "--cwd", proj.to_str().unwrap()]);
            socket(&proj, m2, &all)
        };

        stage(&proj);
        let (code, env, stderr) = vendor(&cold, &["--offline"]);
        assert_eq!(code, Some(0), "vendor on the cold machine: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        let sv = suffixed();
        let pom = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
        assert!(pom.contains(&format!("<version>{sv}</version>")), "{pom}");
        assert!(
            !pom.contains("<!-- socket-patch 7"),
            "nothing could be told of the build there, so no pin:\n{pom}"
        );
        let committed = fixture::snapshot(&proj);

        // The machine that resolved the project sees the same checkout.
        let (code, env, stderr) = vendor(&warm, &["--check"]);
        assert_eq!(
            code,
            Some(0),
            "vendor --check on the warm machine: {env}\n{stderr}"
        );
        assert_eq!(fixture::snapshot(&proj), committed, "{env}");
        let (code, env, stderr) = vendor(&warm, &["--offline"]);
        assert_eq!(code, Some(0), "vendor on the warm machine: {env}\n{stderr}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        assert_eq!(
            fixture::snapshot(&proj),
            committed,
            "a re-run must not rewrite a committed pom: {env}"
        );
        let after = fixture::resolve_warm(&mvn, &proj, &warm, &settings, "target/after", &[]);
        assert_eq!(
            fixture::unsuffixed(after.keys()),
            before.keys().cloned().collect()
        );
        assert_eq!(
            after
                .get(&fixture::victim_jar_name(&sv))
                .and_then(|jar| jar_member(jar, fixture::MEMBER)),
            Some(fixture::patched_member())
        );
    }

    /// A pin must not outlive the selection it was written for. A project
    /// is vendored while Maven selects the base version two levels down;
    /// then it gains a dependency that brings a newer version in nearer
    /// the root. The pin would keep forcing the old version, so the next
    /// run takes it out, says so, and Maven resolves the version it
    /// selects.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_vendored_pin_is_removed_when_the_build_selects_another_version() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().canonicalize().unwrap();
        let m2 = root.join("m2");
        let settings = root.join("settings.xml");
        write_settings(&settings, &[]);
        let server = Server::start();
        fixture::publish(&server);
        let proj = root.join("proj");
        fixture::write_project(&proj, Shape::Selected, &server);
        if fixture::resolve(SUITE, &mvn, &proj, &m2, &settings, "target/before").is_none() {
            return;
        }
        let vendor = |args: &[&str]| {
            let mut all = vec!["vendor"];
            all.extend_from_slice(args);
            all.extend_from_slice(&["--json", "--cwd", proj.to_str().unwrap()]);
            socket(&proj, &m2, &all)
        };
        stage(&proj);
        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "vendor: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        let sv = suffixed();
        let pinned = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
        assert!(
            pinned.contains(&format!("<version>{sv}</version>")),
            "{pinned}"
        );

        // The build moves on: lib-new brings the newer victim in nearer.
        // (The project's own `<dependencies>`, not the pin's section.)
        let with_lib_new = |pom: &str| {
            pom.replace(
                "\n  <dependencies>\n",
                &format!(
                    "\n  <dependencies>\n{}",
                    fixture::dependency("lib-new", "1.0", "")
                ),
            )
        };
        let moved = with_lib_new(&pinned);
        assert_ne!(moved, pinned);
        std::fs::write(proj.join("pom.xml"), &moved).unwrap();
        let forced = fixture::resolve_warm(&mvn, &proj, &m2, &settings, "target/forced", &[]);
        assert!(
            forced.contains_key(&fixture::victim_jar_name(&sv)),
            "the stale pin forces the old version: {:?}",
            forced.keys()
        );

        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "vendor after the change: {env}\n{stderr}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let skip = skip_of(&env).unwrap_or_else(|| panic!("no skip: {env}"));
        assert_eq!(
            skip["errorCode"], "vendor_maven_version_not_selected",
            "{env}"
        );
        let reason = skip["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains(&format!("{} {}", fixture::VICTIM, fixture::NEWER))
                && reason.contains("was removed"),
            "{reason}"
        );
        let unpinned = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
        assert!(!unpinned.contains(&sv), "the pin is gone:\n{unpinned}");
        let after = fixture::resolve_warm(&mvn, &proj, &m2, &settings, "target/after", &[]);
        assert!(
            after.contains_key(&fixture::victim_jar_name(fixture::NEWER))
                && !after.keys().any(|name| name.contains("-socket.")),
            "Maven resolves what it selects: {:?}",
            after.keys()
        );
        // A second run has nothing left to take out, and the revert of the
        // leftover entry restores the project as the user now has it.
        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "second run: {env}\n{stderr}");
        assert_eq!(
            std::fs::read_to_string(proj.join("pom.xml")).unwrap(),
            unpinned
        );
        let (code, env, stderr) = vendor(&["--revert"]);
        assert_eq!(code, Some(0), "revert: {env}\n{stderr}");
        let expected = with_lib_new(&fixture::project_pom(Shape::Selected, &server));
        assert_eq!(
            std::fs::read_to_string(proj.join("pom.xml")).unwrap(),
            expected,
            "the revert leaves the user's pom, byte for byte: {env}"
        );
    }

    fn skip_of<'e>(env: &'e serde_json::Value) -> Option<&'e serde_json::Value> {
        env["events"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["action"] == "skipped")
    }

    /// Vendoring never changes which version of an artifact a Maven build
    /// resolves, and agent mode never fails on a version Maven did not
    /// download. For each shape of the bug the patch of the base version is
    /// skipped with `vendor_maven_version_not_selected` (exit 0, the
    /// selected version named), the project is byte for byte what it was,
    /// and Maven resolves the jars it resolved before. Where the base
    /// version is the one selected, two levels down, it is vendored and
    /// Maven resolves the patched jar in its place.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_vendored_pins_follow_the_version_maven_selects() {
        let Some(mvn) = Mvn::detect(SUITE) else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().canonicalize().unwrap();
        let m2 = root.join("m2");
        let settings = root.join("settings.xml");
        write_settings(&settings, &[]);
        let server = Server::start();
        fixture::publish(&server);
        let vendor = |proj: &Path| {
            socket(
                proj,
                &m2,
                &[
                    "vendor",
                    "--json",
                    "--offline",
                    "--cwd",
                    proj.to_str().unwrap(),
                ],
            )
        };

        let unselected = |shape: Shape| -> Option<()> {
            let proj = root.join(shape.name());
            fixture::write_project(&proj, shape, &server);
            let before = fixture::resolve(SUITE, &mvn, &proj, &m2, &settings, "target/before")?;
            assert!(
                before.contains_key(&fixture::victim_jar_name(shape.selects())),
                "{shape:?}: Maven selects {}: {:?}",
                shape.selects(),
                before.keys()
            );
            stage(&proj);
            let pristine = fixture::snapshot(&proj);
            let (code, env, stderr) = vendor(&proj);
            assert_eq!(code, Some(0), "{shape:?}: {env}\n{stderr}");
            assert_eq!(env["status"], "success", "{shape:?}: {env}");
            assert_eq!(env["summary"]["applied"], 0, "{shape:?}: {env}");
            assert_eq!(env["summary"]["failed"], 0, "{shape:?}: {env}");
            assert_eq!(
                fixture::snapshot(&proj),
                pristine,
                "{shape:?}: vendoring must write nothing: {env}"
            );
            let skip = skip_of(&env).unwrap_or_else(|| panic!("{shape:?}: no skip: {env}"));
            // Without the base version's pom in the local repository the
            // package is not installed at all, which is a skip of its own.
            let base_pom = fixture::victim_dir(&m2, fixture::BASE).join(format!(
                "{}-{}.pom",
                fixture::VICTIM,
                fixture::BASE
            ));
            if base_pom.is_file() {
                assert_eq!(
                    skip["errorCode"], "vendor_maven_version_not_selected",
                    "{shape:?}: {env}"
                );
                let reason = skip["reason"].as_str().unwrap_or_default();
                assert!(
                    reason.contains(&format!(
                        "Maven selects {}:{} {}",
                        fixture::GROUP,
                        fixture::VICTIM,
                        shape.selects()
                    )),
                    "{shape:?}: the skip names the selected version: {reason}"
                );
            }
            let after = fixture::resolve_warm(&mvn, &proj, &m2, &settings, "target/after", &[]);
            assert_eq!(
                after, before,
                "{shape:?}: Maven resolves what it resolved before"
            );
            Some(())
        };

        // The first shape runs against a local repository that holds
        // nothing else: Maven read the pom of the base version, which lost,
        // and never fetched its jar (the table's V5).
        if unselected(Shape::NearerNewer).is_none() {
            return;
        }
        let base_dir = fixture::victim_dir(&m2, fixture::BASE);
        let base_jar = base_dir.join(fixture::victim_jar_name(fixture::BASE));
        assert!(!base_jar.exists(), "Maven never fetched the losing jar");

        // Agent mode patches jars where they lie: a version with no jar is
        // not a package it can patch, and not a failure either.
        if base_dir.is_dir() {
            let proj = root.join(Shape::NearerNewer.name());
            std::fs::remove_dir_all(proj.join(".socket")).unwrap();
            let patched_jar = fixture::patched_victim_jar();
            let view = patch_view(
                UUID,
                &fixture::purl(),
                &[(fixture::MEMBER, &git_sha256(&fixture::patched_member()))],
                &[("GHSA-mediation-maven-vendored", &["CVE-2026-7204"])],
            );
            let patch = hosted_maven_common::Hosted {
                org: ORG,
                uuid: UUID,
                hex8: "708192a3",
                token: "44444444-5555-4666-8777-888888888888",
                ghsa: "GHSA-mediation-maven-vendored",
                cve: "CVE-2026-7204",
                group: fixture::GROUP,
                artifact: fixture::VICTIM,
                version: fixture::BASE,
                title: "maven mediation capstone",
            };
            hosted_maven_common::mount_api(&server, &patch, &patched_jar, b"<project/>", &view);
            fixture::answer_lookups_only_for(&server, ORG, &fixture::purl()["pkg:maven/".len()..]);
            let repository = fixture::snapshot(&m2);
            let pristine = std::fs::read(proj.join("pom.xml")).unwrap();
            let (code, env, stderr) = socket(
                &proj,
                &m2,
                &[
                    "scan",
                    "--mode",
                    "agent",
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
            assert_eq!(code, Some(0), "agent scan: {env}\n{stderr}");
            assert_eq!(env["status"], "success", "{env}");
            assert_eq!(env["summary"]["failed"], 0, "{env}");
            assert!(
                !stderr.contains("not found on disk") && !stderr.contains("no matching variant"),
                "a version with no jar is not a failed patch: {stderr}"
            );
            assert_eq!(
                fixture::snapshot(&m2),
                repository,
                "the local repository is untouched"
            );
            assert_eq!(std::fs::read(proj.join("pom.xml")).unwrap(), pristine);
            let _ = std::fs::remove_dir_all(proj.join(".socket"));
        }

        for shape in [Shape::NearerOlder, Shape::DirectOther, Shape::Excluded] {
            unselected(shape).expect("the local repository is warm");
        }

        // The base version is the one selected: the patched build takes its
        // place, and nothing else moves.
        let proj = root.join(Shape::Selected.name());
        fixture::write_project(&proj, Shape::Selected, &server);
        let before = fixture::resolve(SUITE, &mvn, &proj, &m2, &settings, "target/before")
            .expect("the local repository is warm");
        assert!(before.contains_key(&fixture::victim_jar_name(fixture::BASE)));
        stage(&proj);
        let pristine = fixture::snapshot(&proj);
        let (code, env, stderr) = vendor(&proj);
        assert_eq!(code, Some(0), "selected: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let sv = suffixed();
        let wired = std::fs::read_to_string(proj.join("pom.xml")).unwrap();
        assert!(
            wired.contains(&format!("<version>{sv}</version>")),
            "the pinned pom:\n{wired}"
        );
        let after = fixture::resolve_warm(&mvn, &proj, &m2, &settings, "target/after", &[]);
        assert_eq!(
            fixture::unsuffixed(after.keys()),
            before.keys().cloned().collect(),
            "the same artifacts, the victim in its patched build"
        );
        let resolved = after
            .get(&fixture::victim_jar_name(&sv))
            .unwrap_or_else(|| panic!("Maven resolves the vendored jar: {:?}", after.keys()));
        assert_eq!(
            jar_member(resolved, fixture::MEMBER),
            Some(fixture::patched_member()),
            "the resolved jar is the patched one"
        );
        for (name, bytes) in &before {
            if *name != fixture::victim_jar_name(fixture::BASE) {
                assert_eq!(after.get(name), Some(bytes), "{name} is untouched");
            }
        }
        // A second run is in sync, and the revert restores every byte.
        let vendored = fixture::snapshot(&proj);
        let (code, env, stderr) = vendor(&proj);
        assert_eq!(code, Some(0), "re-vendor: {env}\n{stderr}");
        assert_eq!(
            fixture::snapshot(&proj),
            vendored,
            "a second run is a no-op: {env}"
        );
        let (code, env, stderr) = socket(
            &proj,
            &m2,
            &[
                "vendor",
                "--revert",
                "--json",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        );
        assert_eq!(code, Some(0), "revert: {env}\n{stderr}");
        assert_eq!(
            fixture::snapshot(&proj),
            pristine,
            "the revert restores every byte"
        );

        // The base version now sits in the local repository, jar and all,
        // and no pom of this project names it: a range selects another.
        unselected(Shape::Ranged).expect("the local repository is warm");
    }
}
