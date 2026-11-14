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
//! Three more cases are about where the rule stops and where it does not:
//! a run on the global installs is not judged against the workspace at
//! `--cwd`; a vendor ledger entry that says the owned index of a Bazel root
//! wires its artifact is not attested from the artifact alone; and nothing
//! in a tree Bazel owns is attested, however the run got there.
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
    assert_attested, assert_omitted, patch_view, run_vex, write_hosted_npm_lock, Marker, PatchApi,
    VexOutcome, VexRun,
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

/// A run on the global installs (`--global-prefix`) attests another tree
/// than the project's, which the workspace at `--cwd` does not build. It is
/// not judged against that workspace: the statement is made as it is with
/// no workspace file, and no code of the Bazel checks appears. The same
/// record in a project run of the same workspace is withheld, which is
/// what shows the hub governs it.
#[test]
fn a_run_on_the_global_installs_is_not_judged_against_the_workspace() {
    const PURL: &str = "pkg:pypi/examplepkg@1.2.3";
    let tmp = tempfile::tempdir().unwrap();
    let top = tmp.path().canonicalize().unwrap();
    let (root, site) = (top.join("ws"), top.join("site-packages"));
    put(&root, ".git/HEAD", "ref: refs/heads/main\n");
    let hub = "bazel_dep(name = \"rules_python\", version = \"1.0.0\")\n\
               pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
               pip.parse(hub_name = \"pip\", python_version = \"3.11\", \
               requirements_lock = \"//:requirements_lock.txt\")\n\
               use_repo(pip, \"pip\")\n";
    put(&root, "MODULE.bazel", hub);
    let lock = format!(
        "examplepkg==1.2.3 \\\n    --hash=sha256:{}\n",
        "1".repeat(64)
    );
    put(&root, "requirements_lock.txt", lock);
    let metadata = "Metadata-Version: 2.1\nName: examplepkg\nVersion: 1.2.3\n\n";
    put(&site, "examplepkg-1.2.3.dist-info/METADATA", metadata);
    put(&site, "mod.py", PATCHED);
    record(&root, PURL, "package/mod.py");

    let run = |global: bool| {
        let run = VexRun {
            output: Some(top.join("out.vex.json")),
            ..VexRun::offline()
        };
        let run = run.arg("--ecosystems").arg("pypi");
        let run = match global {
            true => run.arg("--global-prefix").arg(site.to_string_lossy()),
            false => run,
        };
        run_vex(&common::binary(), &root, &run)
    };
    // Every code of the Bazel checks the envelope carries: a warning's,
    // and the reason of a skipped event.
    fn bazel_codes(out: &VexOutcome) -> Vec<String> {
        let mut found = Vec::new();
        for (list, member) in [("warnings", "code"), ("events", "errorCode")] {
            let entries = out.envelope[list].as_array();
            let codes = entries.into_iter().flatten();
            let codes = codes.filter_map(|entry| entry[member].as_str());
            found.extend(
                codes
                    .filter(|code| code.contains("bazel"))
                    .map(String::from),
            );
        }
        found
    }

    let out = run(true);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Applied, VULNS);
    assert_eq!(bazel_codes(&out), Vec::<String>::new(), "{out}");

    // The project run of the same workspace: the pip hub builds the
    // package from its lock, and a patched tree says nothing of that.
    let out = run(false);
    let code = Code::VexNotConsumed.as_str();
    assert_omitted(&out, PURL, code, "a project run under the pip hub");
    let said = bazel_codes(&out);
    assert!(said.len() >= 2 && said.iter().all(|c| c == code), "{out}");

    // And with no workspace the global run says what it said under one.
    std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
    let out = run(true);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Applied, VULNS);
}

/// A vendor ledger entry that says the owned index of a Bazel root wires
/// its artifact, as `scan --mode vendored` or a route of `apply` records
/// one. Nothing in this build can prove that the Bazel build consumes the
/// pin, so the artifact is not attested from its own bytes: with or
/// without a manifest record, routed or not, under `--no-verify`, and
/// with the workspace file gone. (The statement such an entry does make,
/// on a vendored lane's pin, is a unit test over a toy lane table in the
/// CLI's `bazel_gate::vex`.)
#[test]
fn an_index_wired_vendor_entry_is_not_attested_from_its_artifact_alone() {
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.0.0";
    let hub = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
               go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
               go_deps.from_file(go_mod = \"//:go.mod\")\n\
               use_repo(go_deps, \"com_github_foo_bar\")\n";
    let go_mod = "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n";
    let artifact = format!(".socket/vendor/golang/{UUID}/bar");
    let files = json!({"package/bar.go": {
        "beforeHash": git_sha256(PRISTINE), "afterHash": git_sha256(PATCHED),
    }});
    let vuln =
        json!({"cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d"});
    let patch = json!({
        "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z", "files": files,
        "vulnerabilities": {"GHSA-test-aaaa-bbbb": vuln},
        "description": "d", "license": "MIT", "tier": "free",
    });
    let fixture = |routed: bool, manifest: bool| {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("ws");
        put(&root, ".git/HEAD", "ref: refs/heads/main\n");
        put(&root, ".bazelversion", "9.3.2\n");
        put(&root, "MODULE.bazel", hub);
        put(&root, "go.mod", go_mod);
        put(&root, "go.sum", "");
        put(&root, &format!("{artifact}/bar.go"), PATCHED);
        let mut said = json!({"projectRel": ""});
        if routed {
            said["routed"] = json!(true);
        }
        let wiring = json!({
            "file": ".socket/bazel/index.json", "kind": "bazel_index", "action": "added",
            "key": UUID, "new": said,
        });
        let entry = json!({
            "ecosystem": "golang", "basePurl": PURL, "uuid": UUID,
            "artifact": {"path": artifact, "sha256": "c".repeat(64)},
            "wiring": [wiring], "record": patch,
        });
        let state = json!({"version": 1, "entries": {PURL: entry}});
        put(&root, ".socket/vendor/state.json", state.to_string());
        if manifest {
            let manifest = json!({"patches": {PURL: patch}});
            put(&root, ".socket/manifest.json", manifest.to_string());
        }
        (tmp, root)
    };
    let vex = |tmp: &tempfile::TempDir, root: &Path, no_verify: bool| {
        let run = VexRun {
            output: Some(tmp.path().join("out.vex.json")),
            no_verify,
            ..VexRun::offline()
        };
        let home = tmp.path().join("home");
        let run = run
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("GOMODCACHE", home.join("gomodcache"));
        run_vex(&common::binary(), root, &run)
    };
    for (routed, manifest) in [(false, false), (false, true), (true, false), (true, true)] {
        let what = format!("routed {routed}, manifest record {manifest}");
        let (tmp, root) = fixture(routed, manifest);
        for no_verify in [false, true] {
            let out = vex(&tmp, &root, no_verify);
            assert_omitted(&out, PURL, "vendor_unwired", &what);
            let said = warning(&out, "vex_claim_unwired");
            assert!(said.contains("the owned index of a Bazel root"), "{said}");
            assert!(said.contains("no enabled lane can tell"), "{said}");
        }
        std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
        let out = vex(&tmp, &root, false);
        assert_omitted(&out, PURL, "vendor_unwired", &what);
        let said = warning(&out, "vex_claim_unwired");
        assert!(said.contains("no Bazel workspace"), "{said}");
    }
}

/// Owner decision O16: nothing in a tree Bazel owns is attested or
/// patched. `vex` and `get` are refused there, whether a flag named the
/// tree, the command was started inside it, or `--manifest-path` moved
/// the run to it from outside, before a manifest is read or the API is
/// asked: no document, no request, no file touched.
#[test]
fn vex_and_get_are_refused_in_a_tree_bazel_owns() {
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    /// The patch a lockfile of the second tree pins `left-pad` to.
    const HOSTED: &str = "5d2c8e1a-3b4f-4c6d-9e7a-1f0b2c3d4e5f";
    const TOKEN: &str = "sktsec_test_token_for_vex_e2e";
    const ORG: [&str; 4] = ["--api-token", TOKEN, "--org", "test-org"];
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
    // A second one whose lockfile resolves the package from a hosted
    // patch, with no record of it anywhere on this machine: outside an
    // output base `vex` asks the API for the record, so a refusal that
    // came after planning would show as a request.
    let hosted = base.join("external").join("hosted");
    put(
        &hosted,
        "package.json",
        r#"{"name": "app", "version": "1.0.0"}"#,
    );
    assert_eq!(
        write_hosted_npm_lock(&hosted, "left-pad", "1.3.0", HOSTED),
        PURL
    );

    let files = [("package/index.js", &git_sha256(PATCHED)[..])];
    let view = patch_view(HOSTED, PURL, &files, VULNS);
    let api = PatchApi::start(vec![(HOSTED.to_string(), view)]);
    let (doc, uri) = (ws.join("vex.json"), api.uri());
    let (doc_arg, tree_arg) = (doc.to_string_lossy(), tree.to_string_lossy());
    let hosted_arg = hosted.to_string_lossy();
    let manifest = tree.join(".socket").join("manifest.json");
    let hosted_manifest = hosted.join(".socket").join("manifest.json");
    let (manifest_arg, hosted_manifest_arg) = (
        manifest.to_string_lossy(),
        hosted_manifest.to_string_lossy(),
    );
    let vex = ["vex", "--json", "--offline", "--output", &doc_arg];
    let online = ["vex", "--json", "--output", &doc_arg, "--api-url", &uri];
    let online = [&online[..], &ORG].concat();
    let get = ["get", PURL, "--json", "--yes", "--api-url", &uri];
    let get = [&get[..], &ORG].concat();
    // How the tree becomes the scope of the run, each from a directory
    // that makes it so: named by `--cwd`, the working directory itself,
    // and the project of a manifest that `--manifest-path` names.
    let forms = |tree: &Path, tree_arg: &str, manifest_arg: &str| {
        let named = vec!["--cwd".to_string(), tree_arg.to_string()];
        let moved = vec!["--manifest-path".to_string(), manifest_arg.to_string()];
        [
            (ws.clone(), named),
            (tree.to_path_buf(), Vec::new()),
            (ws.clone(), moved),
        ]
    };
    let runs = [
        (&vex[..], forms(&tree, &tree_arg, &manifest_arg)),
        (&get[..], forms(&tree, &tree_arg, &manifest_arg)),
        (
            &online[..],
            forms(&hosted, &hosted_arg, &hosted_manifest_arg),
        ),
    ];
    let before = snapshot(&top);
    for (command, forms) in &runs {
        for (cwd, scope) in forms {
            let scope = scope.iter().map(|arg| &arg[..]);
            let args: Vec<&str> = command.iter().copied().chain(scope).collect();
            let (code, stdout, stderr) = common::run_with_env(cwd, &args, &[]);
            let what = format!("{args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");
            assert_eq!(code, 1, "{what}");
            let envelope = parse_json_envelope(&stdout);
            let refused = Code::AgentOutputTree.as_str();
            assert_eq!(envelope_error_code(&envelope), Some(refused), "{what}");
            assert_eq!(envelope["command"], command[0], "{what}");
            assert!(!doc.exists(), "a document was written: {what}");
        }
    }
    api.assert_no_requests();
    assert_same_tree(&before, &snapshot(&top));

    // The marker, not the path, makes it Bazel's: with it gone the same
    // tree is a project, and its patched copy is attested.
    std::fs::remove_file(base.join("DO_NOT_BUILD_HERE")).unwrap();
    let product = ["--product", "pkg:npm/app@1.0.0"];
    let args = [&vex[..], &["--cwd", &tree_arg], &product].concat();
    let (code, stdout, stderr) = common::run_with_env(&ws, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let written: Value = serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
    assert_attested(&written, PURL, UUID, Marker::Applied, VULNS);
    // So is it through its manifest, from the workspace.
    std::fs::remove_file(&doc).unwrap();
    let args = [&vex[..], &["--manifest-path", &manifest_arg], &product].concat();
    let (code, stdout, stderr) = common::run_with_env(&ws, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let written: Value = serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
    assert_attested(&written, PURL, UUID, Marker::Applied, VULNS);
    api.assert_no_requests();

    // And the second tree is where the zero above bites: the same online
    // run asks the API for the record of the pin, and attests from it.
    std::fs::remove_file(&doc).unwrap();
    let args = [&online[..], &["--cwd", &hosted_arg], &product].concat();
    let (code, stdout, stderr) = common::run_with_env(&ws, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(api.view_requests(HOSTED) >= 1, "{:?}", api.requests());
    let written: Value = serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
    assert_attested(&written, PURL, HOSTED, Marker::Redirected, VULNS);
}
