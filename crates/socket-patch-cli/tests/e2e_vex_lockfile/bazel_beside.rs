//! `vex` for a project that Bazel does not build, in a checkout where Bazel
//! builds something else.
//!
//! `web/` is a plain pnpm project. The root of its checkout is a Bazel
//! workspace that builds Java and nothing of `web/`: its one hub is
//! `maven.install` of rules_jvm_external in a `MODULE.bazel`, or
//! `maven_install` in a `WORKSPACE`, and no Bazel file names the project's
//! lock. So what `socket-patch` patched there is what the project's own
//! package manager installs, as in a checkout without Bazel, and `vex` must
//! say what it says there: the exit code, both streams and the document of
//! each form are those of that checkout, byte for byte (but for the path of
//! the checkout and the time; each form is told the id of its document).
//!
//! These two tests are the fixed point for every change to what `vex` says
//! in a Bazel workspace. A change that makes one of them fail, or that
//! needs an edit to this file, has changed the answer for a project Bazel
//! does not build. A change that makes `vex` read a Bazel file adds a test
//! of its own for the case it touches.

use std::path::{Path, PathBuf};

use crate::vex_e2e_common;
use vex_e2e_common::*;

const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "6d2f8b1c-4e7a-4c3d-9b5e-0a1f2e3d4c5b";
const VULNS: &[(&str, &[&str])] = &[("GHSA-bzl-besd-0001", &["CVE-2026-6161"])];
/// The entry file of the package, before the patch and with it.
const UPSTREAM: &str = "module.exports = (s) => s;\n";
const PATCHED: &str = "/* patched */\nmodule.exports = (s) => s;\n";
/// The sum of a tarball, as a lock spells it.
const INTEGRITY: &str = "sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==";
/// The id every form is told to give its document (`--doc-id`, and
/// `--vex-doc-id` for `apply`), where `vex` would make a new one per run.
const DOCUMENT: &str = "urn:uuid:0b6c7d2e-5a41-4f38-8e9d-1c2b3a4f5e6d";

/// A root `MODULE.bazel` whose one hub is Maven's, and the package of the
/// root that it builds.
const JAVA_MODULE: &str = r#"module(name = "shop", version = "0.0.0")

bazel_dep(name = "rules_jvm_external", version = "6.7")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(artifacts = ["com.google.guava:guava:33.4.0-jre"])
use_repo(maven, "maven")
"#;
const JAVA_BUILD: &str = r#"java_library(
    name = "server",
    srcs = glob(["server/**/*.java"]),
    deps = ["@maven//:com_google_guava_guava"],
)
"#;

/// A root `WORKSPACE` whose one hub is Maven's.
const JAVA_WORKSPACE: &str = r#"workspace(name = "shop")

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = ["com.google.guava:guava:33.4.0-jre"],
    repositories = ["https://repo1.maven.org/maven2"],
)
"#;

/// What is at the root of each checkout, and its files: no Bazel, then the
/// two workspaces that build Java.
const AROUND: [(&str, &[(&str, &str)]); 3] = [
    ("no Bazel", &[]),
    (
        "a Java MODULE.bazel",
        &[("MODULE.bazel", JAVA_MODULE), ("BUILD.bazel", JAVA_BUILD)],
    ),
    ("a Java WORKSPACE", &[("WORKSPACE", JAVA_WORKSPACE)]),
];

/// The files of the pnpm project: its `package.json`, and a lock as pnpm 9
/// and later write it, which holds `resolution` for the one package.
fn project(resolution: &str) -> Vec<(String, String)> {
    let package = r#"{"name": "web", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    let lock = format!(
        "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  \
         excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n      \
         left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  \
         left-pad@1.3.0:\n    resolution: {{{resolution}}}\n\nsnapshots:\n\n  \
         left-pad@1.3.0: {{}}\n"
    );
    let files = [
        ("package.json", package.to_string()),
        ("pnpm-lock.yaml", lock),
    ];
    files.map(|(rel, text)| (rel.to_string(), text)).to_vec()
}

/// What a run said: its exit code, its stdout, its stderr and its
/// document, with what differs from one checkout and one run to the next
/// in fixed words: the path of the checkout and the time.
fn settled(out: &VexOutcome, checkout: &Path) -> (Option<i32>, String, String, String) {
    let document = std::fs::read_to_string(&out.output).unwrap_or_default();
    // The path as the test names it and as the system resolves it, each as
    // plain text and as a JSON string spells it.
    let resolved = checkout.canonicalize().expect("the checkout");
    let mut paths = Vec::new();
    for path in [resolved.as_path(), checkout] {
        let plain = path.to_string_lossy().into_owned();
        let quoted = serde_json::to_string(&plain).expect("a JSON string");
        paths.extend([quoted[1..quoted.len() - 1].to_string(), plain]);
    }
    let time = regex::Regex::new(r#""timestamp": "[^"]*""#).expect("a time");
    let fixed = |text: &str| {
        let text = paths.iter().fold(text.to_string(), |text, path| {
            text.replace(path.as_str(), "<checkout>")
        });
        time.replace_all(&text, r#""timestamp": "<now>""#)
            .into_owned()
    };
    let streams = [&out.stdout, &out.stderr, &document].map(|text| fixed(text));
    let [stdout, stderr, document] = streams;
    (out.code, stdout, stderr, document)
}

/// `vex` as JSON and as a person reads it, and `apply --vex`, each as `run`
/// says, in a checkout with the project's `files` in `web/` and each set of
/// Bazel files at its root. Without Bazel a form attests the package
/// through the patch, as `marker` says; beside each workspace it says what
/// it said there.
fn says_the_same_beside_bazel(files: &[(String, String)], run: VexRun, marker: Marker) {
    let told = |run: VexRun, option: &str| run.arg(option).arg(DOCUMENT);
    let person = VexRun {
        human: true,
        ..run.clone()
    };
    let forms = [
        told(run.clone(), "--doc-id"),
        told(person, "--doc-id"),
        told(run.via(VexVia::Apply), "--vex-doc-id"),
    ];
    let mut without_bazel = Vec::new();
    for (around, bazel) in AROUND {
        let root = tempfile::tempdir().expect("a temp root");
        let web = root.path().join("web");
        let write = |path: PathBuf, text: &str| {
            std::fs::create_dir_all(path.parent().expect("a file path")).expect("a directory");
            std::fs::write(path, text).expect("a file of the checkout");
        };
        write(root.path().join(".git/HEAD"), "ref: refs/heads/main\n");
        for (rel, text) in bazel {
            write(root.path().join(rel), text);
        }
        for (rel, text) in files {
            write(web.join(rel), text);
        }
        for (n, form) in forms.iter().enumerate() {
            // Each form writes the same path: the document compared is its own.
            let _ = std::fs::remove_file(web.join(DEFAULT_OUTPUT));
            let out = run_vex(&binary(), &web, form);
            let said = settled(&out, root.path());
            if bazel.is_empty() {
                assert_eq!(out.code, Some(0), "form {n}: {out}");
                assert_attested(out.doc(), PURL, UUID, marker, VULNS);
                without_bazel.push(said);
            } else {
                assert_eq!(said, without_bazel[n], "{around}, form {n}: {out}");
            }
        }
    }
}

/// Hosted mode: the lock names the patched tarball on the patch host, and
/// the record comes from the API.
#[test]
fn a_hosted_pin_beside_a_java_bazel_build_attests_as_without_bazel() {
    let files = [("package/index.js", &*git_sha256(PATCHED.as_bytes()))];
    let api = PatchApi::start(vec![(UUID.into(), patch_view(UUID, PURL, &files, VULNS))]);
    let pin = format!(
        "integrity: {INTEGRITY}, tarball: \
         https://patch.socket.dev/patch/npm/left-pad/1.3.0/{HOSTED_TOKEN}/{UUID}/left-pad-1.3.0.tgz"
    );
    says_the_same_beside_bazel(&project(&pin), VexRun::online(&api), Marker::Redirected);
}

/// Agent mode: the installed copy holds the patch, which the manifest
/// records with its blob, and the run is offline.
#[test]
fn an_installed_patch_beside_a_java_bazel_build_attests_as_without_bazel() {
    let (ghsa, cves) = VULNS[0];
    let patched = git_sha256(PATCHED.as_bytes());
    let manifest = serde_json::json!({ "patches": { PURL: {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": git_sha256(UPSTREAM.as_bytes()),
            "afterHash": patched,
        }},
        "vulnerabilities": { ghsa: {
            "cves": cves, "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "a patch",
        "license": "MIT",
        "tier": "free",
    }}});
    let mut files = project(&format!("integrity: {INTEGRITY}"));
    let installed = r#"{"name": "left-pad", "version": "1.3.0"}"#;
    files.extend([
        (
            "node_modules/left-pad/package.json".into(),
            installed.into(),
        ),
        ("node_modules/left-pad/index.js".into(), PATCHED.into()),
        (format!(".socket/blobs/{patched}"), PATCHED.into()),
        (".socket/manifest.json".into(), manifest.to_string()),
    ]);
    says_the_same_beside_bazel(&files, VexRun::offline(), Marker::Applied);
}
