//! Hermetic CLI tests: `vex` (and the scope check of `get`) under a Bazel
//! workspace (design 7, hazards HZ-02 and HZ-15).
//!
//! A Bazel ruleset fetches a package from the lock its declaration names,
//! so `vex` makes a statement only on a proof that the Bazel build consumes
//! the patch. Every lane is disabled in this build, so no proof exists yet:
//! what these cases pin is that each way a statement used to over-attest is
//! now withheld with a `vex_bazel_*` code, that `--no-verify` brings none of
//! them back, and that the same files with the workspace file gone attest
//! as they always did. The fixture workspace is the rules_jvm_external one,
//! whose `maven_install.json` resolves `slf4j-api` 1.7.36 unpatched.
//!
//! The verdicts that need a lane (a pin the build consumes, an in-run
//! grant, an agent or a vendored lane's pin of a manifest record) are unit
//! tests over a toy lane table, in `socket_patch_core::vex::discover::bazel`
//! and in the CLI's `bazel_gate::vex`: the built binary has no toy lane.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_core::bazel::codes::Code;

#[allow(clippy::duplicate_mod)]
#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::{self, envelope_error_code, git_sha256, parse_json_envelope};
use vex_e2e_common::{
    assert_attested, assert_omitted, patch_view, run_vex, Marker, PatchApi, VexOutcome, VexRun,
};

const SLF4J: &str = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
/// The patch the committed pom redirect fixture pins `slf4j-api` to.
const POM_PIN: &str = "77777777-7777-7777-7777-777777777777";
const UUID: &str = "9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a90";
const VULNS: &[(&str, &[&str])] = &[("GHSA-test-aaaa-bbbb", &["CVE-2024-0001"])];
const PRISTINE: &[u8] = b"<project><artifactId>slf4j-api</artifactId></project>\n";
const PATCHED: &[u8] = b"<project><artifactId>slf4j-api</artifactId><!-- fix --></project>\n";

fn put(root: &Path, rel: &str, bytes: impl AsRef<[u8]>) {
    let file = rel
        .split('/')
        .fold(root.to_path_buf(), |at, part| at.join(part));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, bytes).unwrap();
}

/// A copy of the rules_jvm_external fixture workspace as a git checkout of
/// its own, and empty stand-ins for the JVM caches of the machine.
struct Workspace {
    tmp: tempfile::TempDir,
    root: PathBuf,
    caches: PathBuf,
}

fn workspace() -> Workspace {
    let tmp = tempfile::tempdir().unwrap();
    let top = tmp.path().canonicalize().unwrap();
    let (root, caches) = (top.join("ws"), top.join("caches"));
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel/light");
    common::fs_tree::copy_tree(&fixtures.join("rules_jvm_external/bzlmod/e9"), &root);
    put(&root, ".git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(caches.join("m2")).unwrap();
    Workspace { tmp, root, caches }
}

/// A manifest of agent mode that records one patch of `purl`, with the
/// vulnerability a statement needs.
fn record(project: &Path, purl: &str, file: &str) {
    let vulns: serde_json::Map<String, Value> = VULNS
        .iter()
        .map(|(id, cves)| {
            let body =
                json!({"cves": cves, "summary": "s", "severity": "high", "description": "d"});
            (id.to_string(), body)
        })
        .collect();
    let files =
        json!({file: {"beforeHash": git_sha256(PRISTINE), "afterHash": git_sha256(PATCHED)}});
    let patch = json!({
        "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z", "files": files,
        "vulnerabilities": vulns, "description": "d", "license": "MIT", "tier": "free",
    });
    let manifest = json!({ "patches": { purl: patch } });
    put(project, ".socket/manifest.json", manifest.to_string());
}

/// `vex --cwd project`, its document written outside the workspace and the
/// JVM caches of the machine out of reach.
fn vex(ws: &Workspace, project: &Path, run: VexRun) -> VexOutcome {
    let run = VexRun {
        output: Some(ws.tmp.path().join("out.vex.json")),
        ..run
    };
    let run = run
        .env("MAVEN_REPO_LOCAL", ws.caches.join("m2"))
        .env("GRADLE_USER_HOME", ws.caches.join("gradle"))
        .env("HOME", &ws.caches)
        .env("USERPROFILE", &ws.caches);
    run_vex(&common::binary(), project, &run)
}

/// The detail of the run warning with `code`.
fn warning<'a>(out: &'a VexOutcome, code: &str) -> &'a str {
    let warnings = out.envelope["warnings"].as_array();
    let found = warnings.into_iter().flatten().find(|w| w["code"] == code);
    let detail = found.and_then(|w| w["detail"].as_str());
    detail.unwrap_or_else(|| panic!("no `{code}` warning:\n{out}"))
}

/// Over-attestation from a lock Bazel does not read (the hosted basis): a
/// `pom.xml` pinned to a hosted patch, beside a `maven_install.json` that
/// still resolves the release from Maven Central. The Bazel build fetches
/// the unpatched jar, so no statement is made, with or without
/// `--no-verify`. Without the workspace file the same pin attests.
#[test]
fn a_pom_pin_beside_an_unpatched_maven_install_json_is_not_attested() {
    let ws = workspace();
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core");
    let pom = core.join("tests/fixtures/redirect/maven/pom/basic/expected/pom.xml");
    put(&ws.root, "pom.xml", std::fs::read(pom).unwrap());
    let files = [("package/slf4j-api-1.7.36.pom", &git_sha256(PATCHED)[..])];
    let view = patch_view(POM_PIN, SLF4J, &files, VULNS);
    let api = PatchApi::start(vec![(POM_PIN.to_string(), view)]);
    let code = Code::VexNotConsumed.as_str();
    for no_verify in [false, true] {
        let run = VexRun {
            no_verify,
            ..VexRun::online(&api)
        };
        let out = vex(&ws, &ws.root, run);
        assert_omitted(&out, SLF4J, code, &format!("--no-verify {no_verify}"));
        let said = warning(&out, code);
        assert!(said.contains("`pom.xml` is a file no hub reads"), "{said}");
    }

    std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
    let out = vex(&ws, &ws.root, VexRun::online(&api));
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), SLF4J, POM_PIN, Marker::Redirected, VULNS);
}

/// Over-attestation from a host tree (the installed basis): `service-a`
/// keeps a `pom.xml`, the patch is applied in the local Maven repository,
/// and the hub at the workspace root builds `//service-a/...` from its own
/// `maven_install.json`, which resolves the release with no pin. No hub
/// governs `service-a`, so only the workspace-wide check withholds it.
#[test]
fn a_patched_local_repository_does_not_attest_beside_a_root_maven_install_json() {
    let ws = workspace();
    let project = ws.root.join("service-a");
    let dependency = "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>\
                      <version>1.7.36</version></dependency>";
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.x</groupId>\
         <artifactId>service-a</artifactId><version>1</version>\
         <dependencies>{dependency}</dependencies></project>\n"
    );
    put(&project, "pom.xml", pom);
    record(&project, SLF4J, "package/slf4j-api-1.7.36.pom");
    let installed = "m2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.pom";
    put(&ws.caches, installed, PATCHED);
    let code = Code::VexNotConsumed.as_str();
    for no_verify in [false, true] {
        let run = VexRun {
            no_verify,
            ..VexRun::offline()
        };
        let out = vex(&ws, &project, run);
        assert_omitted(&out, SLF4J, code, &format!("--no-verify {no_verify}"));
        let said = warning(&out, code);
        assert!(said.contains("hub `maven` resolves"), "{said}");
    }

    // The fixture is the hazard: the same project in no Bazel workspace
    // is attested from the patched repository, as it always was.
    std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
    let out = vex(&ws, &project, VexRun::offline());
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), SLF4J, UUID, Marker::Applied, VULNS);
}

/// Owner decision O16: nothing in a tree Bazel owns is attested or
/// patched. `vex` and `get` are refused there, whether a flag named the
/// tree or the command was started inside it, before a manifest is read or
/// the API is asked: no document, no request, no file touched.
#[test]
fn vex_and_get_are_refused_in_a_tree_bazel_owns() {
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    let tmp = tempfile::tempdir().unwrap();
    let top = tmp.path().canonicalize().unwrap();
    let (ws, base) = (top.join("ws"), top.join("base"));
    put(&ws, "MODULE.bazel", "");
    put(&base, "DO_NOT_BUILD_HERE", ws.to_string_lossy().as_bytes());
    // A fetched repository that somebody patched in place: outside an
    // output base this is a project `vex` attests.
    let tree = base.join("external").join("npm");
    put(
        &tree,
        "package.json",
        r#"{"name": "app", "version": "1.0.0"}"#,
    );
    let package = r#"{"name": "left-pad", "version": "1.3.0"}"#;
    put(&tree, "node_modules/left-pad/package.json", package);
    put(&tree, "node_modules/left-pad/index.js", PATCHED);
    record(&tree, PURL, "package/index.js");

    let api = PatchApi::empty();
    let (doc, uri) = (ws.join("vex.json"), api.uri());
    let (doc_arg, tree_arg) = (doc.to_string_lossy(), tree.to_string_lossy());
    let vex = ["vex", "--json", "--offline", "--output", &doc_arg];
    let get = ["get", PURL, "--json", "--yes", "--api-url", &uri];
    let get = [
        &get[..],
        &["--api-token", "fake-token", "--org", "test-org"],
    ]
    .concat();
    let before = snapshot(&top);
    for command in [&vex[..], &get[..]] {
        for named in [true, false] {
            let scope: &[&str] = if named { &["--cwd", &tree_arg] } else { &[] };
            let cwd = if named { &ws } else { &tree };
            let args = [command, scope].concat();
            let (code, stdout, stderr) = common::run_with_env(cwd, &args, &[]);
            let what = format!("{args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");
            assert_eq!(code, 1, "{what}");
            let envelope = parse_json_envelope(&stdout);
            let refused = Code::AgentOutputTree.as_str();
            assert_eq!(envelope_error_code(&envelope), Some(refused), "{what}");
            assert_eq!(envelope["command"], command[0], "{what}");
        }
    }
    api.assert_no_requests();
    assert_same_tree(&before, &snapshot(&top));

    // The marker, not the path, makes it Bazel's: with it gone the same
    // tree is a project, and its patched copy is attested.
    std::fs::remove_file(base.join("DO_NOT_BUILD_HERE")).unwrap();
    let args = [
        &vex[..],
        &["--cwd", &tree_arg, "--product", "pkg:npm/app@1.0.0"],
    ]
    .concat();
    let (code, stdout, stderr) = common::run_with_env(&ws, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let written: Value = serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
    assert_attested(&written, PURL, UUID, Marker::Applied, VULNS);
}
