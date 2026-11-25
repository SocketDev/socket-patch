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
//! Another test pins which local repository a build uses when the
//! project's `.mvn/maven.config` names one (`-Dmaven.repo.local`): real
//! Maven resolves into it rather than the one `MAVEN_OPTS` names, the
//! command line (`MAVEN_ARGS`, Maven 3.9+) overrides it, and socket-patch
//! given the same environment patches the artifact in that same repository.
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

use std::collections::BTreeMap;
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

    /// What `get` saves for the patch of the base victim.
    fn stage(proj: &Path) {
        stage_all(proj, &[(fixture::BASE, UUID)]);
    }

    /// A second patch, for the newer victim.
    const NEWER_UUID: &str = "8192a3b4-c5d6-4e7f-9081-92a3b4c5d6e7";

    /// The manifest record `get` saves for a patch of the victim at
    /// `version`, with its after-hash blob.
    fn stage_all(proj: &Path, patches: &[(&str, &str)]) {
        let mut records = serde_json::Map::new();
        std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
        for (version, uuid) in patches {
            let (before, after) = (
                fixture::pristine_member(fixture::VICTIM, version),
                fixture::patched_member_of(version),
            );
            records.insert(
                fixture::purl_of(version),
                serde_json::json!({
                    "uuid": uuid,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": { fixture::MEMBER: {
                        "beforeHash": git_sha256(&before),
                        "afterHash": git_sha256(&after),
                    } },
                    "vulnerabilities": { "GHSA-mediation-maven-vendored": {
                        "cves": ["CVE-2026-7204"], "summary": "s", "severity": "high",
                        "description": "d"
                    } },
                    "description": "maven mediation capstone",
                    "license": "MIT",
                    "tier": "free",
                }),
            );
            std::fs::write(proj.join(".socket/blobs").join(git_sha256(&after)), after).unwrap();
        }
        std::fs::write(
            proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": records })).unwrap(),
        )
        .unwrap();
    }

    /// The table's V3: in a reactor each module keeps the version it
    /// selects. A patch of the base version is pinned in the modules that
    /// select it (one through other artifacts, one by its own
    /// declaration) and never in the parent they share with a module that
    /// resolves a newer version, which Maven resolves exactly as before. A
    /// patch of that newer version is then pinned in its module beside the
    /// first, and the revert restores every pom.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_vendored_reactor_pins_each_module_at_the_version_it_selects() {
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
        let proj = root.join("reactor");
        fixture::write_reactor(&proj, &server);
        let poms = ["pom.xml", "a/pom.xml", "b/pom.xml", "c/pom.xml"];
        let read_poms = |proj: &Path| -> Vec<Vec<u8>> {
            poms.iter()
                .map(|rel| std::fs::read(proj.join(rel)).unwrap())
                .collect()
        };
        let pristine = read_poms(&proj);
        let vendor = |args: &[&str]| {
            let mut all = vec!["vendor"];
            all.extend_from_slice(args);
            all.extend_from_slice(&["--json", "--cwd", proj.to_str().unwrap()]);
            socket(&proj, &m2, &all)
        };
        let Some(before) =
            fixture::resolve_reactor(SUITE, &mvn, &proj, &m2, &settings, "target/before")
        else {
            return;
        };
        for (module, selects, ..) in fixture::REACTOR_MODULES {
            assert!(
                before[module].contains_key(&fixture::victim_jar_name(selects)),
                "{module} selects {selects}: {:?}",
                before[module].keys()
            );
        }
        let base_sv = suffixed();
        let newer_sv = format!("{}-socket.{}", fixture::NEWER, &NEWER_UUID[..8]);
        let resolved = |out_rel: &str| {
            fixture::resolve_reactor(SUITE, &mvn, &proj, &m2, &settings, out_rel)
                .expect("the local repository is warm")
        };
        // What each module must resolve once `patched` versions are
        // vendored: the same artifacts, the patched ones in their patched
        // build, everything else byte for byte.
        let assert_follows = |after: &BTreeMap<String, BTreeMap<String, Vec<u8>>>,
                              patched: &[(&str, &str)]| {
            for (module, selects, ..) in fixture::REACTOR_MODULES {
                let (was, now) = (&before[module], &after[module]);
                assert_eq!(
                    fixture::unsuffixed(now.keys()),
                    was.keys().cloned().collect(),
                    "{module} resolves the artifacts it resolved before"
                );
                let pristine_name = fixture::victim_jar_name(selects);
                match patched.iter().find(|(version, _)| *version == selects) {
                    Some((version, sv)) => {
                        let jar = now.get(&fixture::victim_jar_name(sv)).unwrap_or_else(|| {
                            panic!("{module} resolves the patched {version}: {:?}", now.keys())
                        });
                        assert_eq!(
                            jar_member(jar, fixture::MEMBER),
                            Some(fixture::patched_member_of(version)),
                            "{module}: the patched jar"
                        );
                    }
                    None => assert_eq!(
                        now.get(&pristine_name),
                        was.get(&pristine_name),
                        "{module} keeps the pristine {selects}"
                    ),
                }
                for (name, bytes) in was {
                    if *name != pristine_name {
                        assert_eq!(now.get(name), Some(bytes), "{module}: {name} is untouched");
                    }
                }
            }
        };

        // The patch of the base version: pinned in `a` and `c`, never in
        // the parent, and `b` is left exactly as it was.
        stage_all(&proj, &[(fixture::BASE, UUID)]);
        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "vendor: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let after = read_poms(&proj);
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        assert!(
            !text(&after[0]).contains("-socket."),
            "the parent takes no pin:\n{}",
            text(&after[0])
        );
        assert!(
            text(&after[1]).contains(&format!("<version>{base_sv}</version>")),
            "{}",
            text(&after[1])
        );
        assert_eq!(after[2], pristine[2], "b/pom.xml is untouched");
        assert!(
            text(&after[3]).contains(&format!("<version>{base_sv}</version>")),
            "{}",
            text(&after[3])
        );
        assert_follows(&resolved("target/after-base"), &[(fixture::BASE, &base_sv)]);

        // The patch of the version `b` selects joins it.
        stage_all(
            &proj,
            &[(fixture::BASE, UUID), (fixture::NEWER, NEWER_UUID)],
        );
        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "second vendor: {env}\n{stderr}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let both = read_poms(&proj);
        assert!(!text(&both[0]).contains("-socket."), "{}", text(&both[0]));
        assert_eq!(both[1], after[1], "a/pom.xml keeps its pin");
        assert!(
            text(&both[2]).contains(&format!("<version>{newer_sv}</version>")),
            "{}",
            text(&both[2])
        );
        assert!(!text(&both[2]).contains(&base_sv));
        assert_eq!(both[3], after[3], "c/pom.xml keeps its pin");
        assert_follows(
            &resolved("target/after-both"),
            &[(fixture::BASE, &base_sv), (fixture::NEWER, &newer_sv)],
        );

        // In sync, checked, and reverted byte for byte.
        let wired = fixture::snapshot(&proj);
        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "re-vendor: {env}\n{stderr}");
        assert_eq!(
            fixture::snapshot(&proj),
            wired,
            "a third run is a no-op: {env}"
        );
        let (code, env, stderr) = vendor(&["--check"]);
        assert_eq!(code, Some(0), "vendor --check: {env}\n{stderr}");
        let (code, env, stderr) = vendor(&["--revert"]);
        assert_eq!(code, Some(0), "revert: {env}\n{stderr}");
        assert_eq!(read_poms(&proj), pristine, "the revert restores every pom");
        assert!(!proj.join(".socket/vendor/maven2").exists(), "{env}");
        assert_no_vendor_residue_in_mvn(&mvn, &proj, &env);
    }

    /// Nothing the vendor run wrote is left under `.mvn`. Maven 4 keeps
    /// its project-local repository in `.mvn/target/`: that is the
    /// build's, the revert leaves it, and it is the only entry allowed
    /// (#2158). Maven 3 writes nothing there, so `.mvn` itself must go.
    fn assert_no_vendor_residue_in_mvn(mvn: &Mvn, proj: &Path, env: &serde_json::Value) {
        let dot_mvn = proj.join(".mvn");
        if mvn.major() < 4 {
            assert!(!dot_mvn.exists(), "{env}");
            return;
        }
        let left: Vec<_> = match std::fs::read_dir(&dot_mvn) {
            Ok(entries) => entries
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name != "target")
                .collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => panic!("{}: {err}", dot_mvn.display()),
        };
        assert!(left.is_empty(), ".mvn still holds {left:?}: {env}");
    }

    /// A pin in a shared parent must go once a module below it resolves
    /// another version, even while a sibling's selection cannot be told,
    /// and the revert must restore every pom byte for byte. A reactor
    /// whose modules all select the base version is vendored (one pin, in
    /// the parent). Then `b` moves to a newer version and `a` gains a
    /// dependency this machine never resolved. The next run takes the pin
    /// out of the parent (it would hold `b` back), keeps the module that
    /// still certainly selects the base version patched, and Maven builds
    /// `b` on the version it selects. `vendor --revert` then leaves each
    /// pom exactly as the user has it: no empty management block where
    /// the pin was.
    #[test]
    #[ignore = "real Maven + Maven Central (dependency plugin); run with --ignored"]
    fn maven_vendored_parent_pin_goes_when_a_module_moves_on_and_reverts_clean() {
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
        let proj = root.join("reactor");
        fixture::write_reactor(&proj, &server);
        let poms = ["pom.xml", "a/pom.xml", "b/pom.xml", "c/pom.xml"];
        let read_poms = |proj: &Path| -> Vec<String> {
            poms.iter()
                .map(|rel| std::fs::read_to_string(proj.join(rel)).unwrap())
                .collect()
        };
        // Every module on the base version: `b` through lib-deep, like `a`.
        let b_on_newer = std::fs::read_to_string(proj.join("b/pom.xml")).unwrap();
        std::fs::write(
            proj.join("b/pom.xml"),
            fixture::module_pom("b", "lib-deep", "1.0"),
        )
        .unwrap();
        if fixture::resolve_reactor(SUITE, &mvn, &proj, &m2, &settings, "target/before").is_none() {
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
        let pinned = read_poms(&proj);
        assert!(
            pinned[0].contains(&format!("<version>{sv}</version>")),
            "every module selects the base version, so the parent is pinned:\n{}",
            pinned[0]
        );

        // The build moves on.
        std::fs::write(proj.join("b/pom.xml"), &b_on_newer).unwrap();
        let a_with_unread = pinned[1].replace(
            "\n  <dependencies>\n",
            &format!(
                "\n  <dependencies>\n{}",
                fixture::dependency("lib-range", "1.0", "")
            ),
        );
        assert_ne!(a_with_unread, pinned[1]);
        std::fs::write(proj.join("a/pom.xml"), &a_with_unread).unwrap();
        let users = read_poms(&proj);
        // Maven has built `b` since (and nothing else): what `b` selects
        // can be told, what `a` selects cannot. The pin still forces the
        // old version on `b`.
        let goal = format!("{DEPENDENCY_PLUGIN}:copy-dependencies");
        let out = mvn.run(
            &proj,
            &m2,
            &settings,
            &[&goal, "-DoutputDirectory=target/forced", "-pl", "b"],
        );
        assert!(ok(&out), "{}", dump(&out));
        assert!(
            proj.join("b/target/forced")
                .join(fixture::victim_jar_name(&sv))
                .is_file(),
            "the parent's pin holds b on the old version"
        );
        std::fs::remove_dir_all(proj.join("b/target")).unwrap();

        let (code, env, stderr) = vendor(&["--offline"]);
        assert_eq!(code, Some(0), "vendor after the change: {env}\n{stderr}");
        assert_eq!(env["summary"]["failed"], 0, "{env}");
        let after = read_poms(&proj);
        assert!(
            !after[0].contains(&sv),
            "the parent's pin would hold b back, so it goes:\n{}",
            after[0]
        );
        assert_eq!(
            after[1], users[1],
            "a cannot be told: no pin is written for it"
        );
        assert_eq!(after[2], users[2], "b is untouched");
        assert!(
            after[3].contains(&format!("<version>{sv}</version>")),
            "c still selects the base version:\n{}",
            after[3]
        );
        let built = fixture::resolve_reactor(SUITE, &mvn, &proj, &m2, &settings, "target/after")
            .expect("the local repository is warm");
        assert!(
            built["b"].contains_key(&fixture::victim_jar_name(fixture::NEWER))
                && !built["b"].keys().any(|name| name.contains("-socket.")),
            "b builds on the version Maven selects for it: {:?}",
            built["b"].keys()
        );
        assert_eq!(
            built["c"]
                .get(&fixture::victim_jar_name(&sv))
                .and_then(|jar| jar_member(jar, fixture::MEMBER)),
            Some(fixture::patched_member())
        );

        let (code, env, stderr) = vendor(&["--revert"]);
        assert_eq!(code, Some(0), "revert: {env}\n{stderr}");
        let reverted = read_poms(&proj);
        let pristine_root = {
            let fresh = root.join("fresh");
            fixture::write_reactor(&fresh, &server);
            std::fs::read_to_string(fresh.join("pom.xml")).unwrap()
        };
        assert_eq!(
            reverted[0], pristine_root,
            "the parent pom, byte for byte: {env}"
        );
        assert_eq!(
            reverted[1],
            users[1].replace(&sv, fixture::BASE),
            "a/pom.xml"
        );
        assert_eq!(reverted[2], users[2], "b/pom.xml");
        assert_eq!(
            reverted[3],
            fixture::module_pom("c", fixture::VICTIM, fixture::BASE),
            "c/pom.xml"
        );
        assert_no_vendor_residue_in_mvn(&mvn, &proj, &env);
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

/// Every file under `from`, copied to the same place under `to`.
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

/// The local repository of a build is the one Maven itself takes: the
/// project's `.mvn/maven.config` (`-Dmaven.repo.local`) over `MAVEN_OPTS`,
/// and the command line (`MAVEN_ARGS`, which Maven 3.9+ reads) over the
/// config. Maven is asked first, with no repository on its command line;
/// socket-patch, in the same environment and with no `MAVEN_REPO_LOCAL`,
/// then patches and restores the artifact in that same repository.
#[test]
#[ignore = "real Maven + Maven Central (fixture); run with --ignored"]
fn maven_config_local_repository_is_the_one_maven_and_socket_patch_use() {
    let Some(mvn) = Mvn::detect(SUITE) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().canonicalize().unwrap();
    let proj = root.join("proj");
    let home = root.join("home");
    let [from_config, from_opts, from_args] =
        ["repo-config", "repo-opts", "repo-args"].map(|name| root.join(name));
    let settings = root.join("settings.xml");
    write_settings(&settings, &[]);
    std::fs::create_dir_all(proj.join(".mvn")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(proj.join("pom.xml"), consumer_pom(VERSION)).unwrap();
    std::fs::write(
        proj.join(".mvn/maven.config"),
        format!("-Dmaven.repo.local={}\n", from_config.display()),
    )
    .unwrap();
    // The JVM's own properties. `user.home` keeps a Maven that took none of
    // these repositories out of the real `~/.m2`.
    let opts = format!(
        "-Duser.home={} -Dmaven.repo.local={}",
        home.display(),
        from_opts.display()
    );
    let goal = format!("{DEPENDENCY_PLUGIN}:copy-dependencies");
    let resolve = |settings: &Path, extra: &[&str], maven_args: Option<&str>| {
        let _ = std::fs::remove_dir_all(proj.join("target"));
        let mut args = vec![goal.as_str(), "-DoutputDirectory=target/deps"];
        args.extend_from_slice(extra);
        mvn.run_unpinned(&proj, settings, &args, |cmd| {
            cmd.env("MAVEN_OPTS", &opts);
            if let Some(value) = maven_args {
                cmd.env("MAVEN_ARGS", value);
            }
        })
    };
    let pom_leaf = format!("{ARTIFACT}-{VERSION}.pom");
    let cached = |repo: &Path| repo_dir(repo, VERSION).join(&pom_leaf);

    // 1. Maven: the config's repository, not the one MAVEN_OPTS names.
    let out = with_central_fallback(SUITE, "maven.config resolution", &settings, |s, extra| {
        resolve(s, extra, None)
    });
    if !ok(&out) {
        skip(
            SUITE,
            &format!("resolving against Maven Central failed:\n{}", dump(&out)),
        );
        return;
    }
    assert!(
        cached(&from_config).is_file(),
        "Maven {} did not resolve into the repository .mvn/maven.config names:\n{}",
        mvn.version,
        dump(&out)
    );
    assert!(
        !from_opts.exists() && !home.join(".m2/repository").exists(),
        "Maven {} used another repository as well",
        mvn.version
    );

    // 2. socket-patch: the same repository.
    let pristine = std::fs::read(cached(&from_config)).unwrap();
    let patched = [
        pristine.as_slice(),
        b"<!-- socket-patch maven.config e2e -->\n",
    ]
    .concat();
    stage_manifest_of(
        &proj,
        &purl(),
        &format!("package/{pom_leaf}"),
        &pristine,
        &patched,
    );
    std::fs::write(
        proj.join(".socket/blobs").join(git_sha256(&pristine)),
        &pristine,
    )
    .unwrap();
    // `--preserve-state`: a rollback otherwise drops the record it restored.
    let agent = |command: &str, maven_args: Option<&str>| {
        let mut cmd = hermetic::command(&binary());
        hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
        prebuilt_common::jvm_env::isolate_cli(&mut cmd);
        if command == "rollback" {
            cmd.args(["rollback", "--preserve-state"]);
        } else {
            cmd.arg(command);
        }
        cmd.args(["--json", "--offline", "--cwd"])
            .arg(&proj)
            .env("MAVEN_OPTS", &opts)
            .env_remove("MAVEN_REPO_LOCAL")
            .env_remove("M2_HOME");
        if let Some(value) = maven_args {
            cmd.env("MAVEN_ARGS", value);
        }
        let out = cmd.output().expect("run socket-patch");
        assert!(out.status.success(), "{command}: {}", dump(&out));
    };
    agent("apply", None);
    assert_eq!(std::fs::read(cached(&from_config)).unwrap(), patched);
    agent("rollback", None);
    assert_eq!(std::fs::read(cached(&from_config)).unwrap(), pristine);

    // 3. The command line is merged over the config. Maven before 3.9 does
    //    not read MAVEN_ARGS.
    if mvn.numeric() < vec![3, 9, 0] {
        println!(
            "{SUITE}: Maven {} does not read MAVEN_ARGS; the command-line leg is skipped",
            mvn.version
        );
        return;
    }
    copy_tree(&from_config, &from_args);
    std::fs::remove_dir_all(repo_dir(&from_config, VERSION)).unwrap();
    let args_value = format!("-Dmaven.repo.local={}", from_args.display());
    // Offline, only the repository that still holds the artifact resolves.
    let out = resolve(&settings, &["-o"], Some(&args_value));
    assert!(
        ok(&out),
        "Maven {} did not take the repository MAVEN_ARGS names over the config's:\n{}",
        mvn.version,
        dump(&out)
    );
    agent("apply", Some(&args_value));
    assert_eq!(std::fs::read(cached(&from_args)).unwrap(), patched);
    agent("rollback", Some(&args_value));
    assert_eq!(std::fs::read(cached(&from_args)).unwrap(), pristine);
}
