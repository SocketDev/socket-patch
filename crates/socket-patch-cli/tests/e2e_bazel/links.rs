//! Hermetic CLI tests: a workspace glob never takes one of Bazel's own
//! trees for a workspace member (hazard HZ-17, the link part).
//!
//! Before a patch is wired, and before one is attested, socket-patch reads
//! the project's own patch declarations in every workspace member. A
//! member it cannot inspect withholds every npm package. Bazel puts trees
//! that mirror the project's manifests where a wide pattern reaches them:
//! four links in the workspace root (under any `--symlink_prefix`), an
//! output base inside the checkout, a vendor directory. With those present
//! the patterns `*`, `**` and `.` used to end every later `scan` in
//! `user_patch_conflict` and every `vex` in an omitted package (probes B4,
//! C8, rules-js B1), and `.` is the pattern of the `pnpm-workspace.yaml`
//! that hosted and vendored mode write themselves.
//!
//! Each case fabricates the Bazel side of the rules_js fixture workspace
//! (no Bazel runs) and runs the real binary against a fake Socket API: a
//! hosted `scan`, the `scan` after it, and `vex`. Every npm package has to
//! be wired and attested each time. Then the marker that makes the tree
//! Bazel's is deleted and the same commands must withhold every package
//! again: the fixture is the hazard, and the marker, not a name, lifts it.
//!
//! The link cases are Unix only (a test cannot make a junction without
//! spawning `cmd`); the vendor-directory case runs everywhere.

use std::path::{Path, PathBuf};

use serde_json::Value;
use wiremock::MockServer;

#[allow(clippy::duplicate_mod)]
#[path = "../hosted_memory_common/mod.rs"]
mod hosted_memory_common;
#[allow(clippy::duplicate_mod)]
#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use crate::bazel_common::{assert_same_tree, assert_write_policy, snapshot, WriteClass};
use crate::common::{self, envelope};
use hosted_memory_common::{mount_api, Patch, ORG};
use vex_e2e_common::{assert_attested, assert_not_attested, run_vex, Marker, VexOutcome, VexRun};

/// The two registry packages of the fixture lock: purl, tarball path on
/// the patch host, and the patch the fake API offers. One is scoped.
const PACKAGES: [(&str, &str, &str); 2] = [
    (
        "pkg:npm/@tootallnate/once@2.0.0",
        "@tootallnate/once/2.0.0/TOKEN/0b5e1c1e-0000-4000-8000-0000000000a2/once-2.0.0.tgz",
        "0b5e1c1e-0000-4000-8000-0000000000a2",
    ),
    (
        "pkg:npm/left-pad@1.3.0",
        "left-pad/1.3.0/TOKEN/0b5e1c1e-0000-4000-8000-0000000000a1/left-pad-1.3.0.tgz",
        "0b5e1c1e-0000-4000-8000-0000000000a1",
    ),
];
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatchedPATCHEDpatched9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0123456789AB==";
/// What the fake API's patch view names for every patch.
const VULNS: &[(&str, &[&str])] = &[("GHSA-test-aaaa-bbbb", &["CVE-2024-0001"])];

/// A copy of the rules_js fixture workspace (`MODULE.bazel`, a pnpm lock
/// 9.0 in the root package) as its own git checkout, with a workspace
/// member `app` and, when given, a `pnpm-workspace.yaml` listing `pattern`.
struct Workspace {
    tmp: tempfile::TempDir,
    root: PathBuf,
}

fn workspace(pattern: Option<&str>) -> Workspace {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel/light/rules_js/bzlmod/e9");
    common::fs_tree::copy_tree(&fixture, &root);
    write(&root, ".git/HEAD", "ref: refs/heads/main\n");
    write(&root, "app/package.json", "{\"name\": \"app\"}\n");
    if let Some(pattern) = pattern {
        let text = format!("packages:\n  - '{pattern}'\n");
        write(&root, "pnpm-workspace.yaml", &text);
    }
    Workspace { tmp, root }
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// An output base as a build leaves it (probes B4, C7, C8): the marker
/// with the workspace path, `external` with a fetched repository, and an
/// execution root that mirrors each top-level entry of the workspace as a
/// link (all but Bazel's own `bazel-*` links) and holds the manifest a
/// `js_library` copied into `bazel-out`.
#[cfg(unix)]
fn output_base(base: &Path, ws: &Path) {
    let execroot = base.join("execroot/_main");
    write(base, "DO_NOT_BUILD_HERE", &ws.to_string_lossy());
    write(
        base,
        "external/npm__left-pad__1.3.0/package/package.json",
        "{}",
    );
    write(&execroot, "bazel-out/k8-fastbuild/bin/package.json", "{}");
    for entry in std::fs::read_dir(ws).unwrap() {
        let name = entry.unwrap().file_name();
        if !name.to_string_lossy().starts_with("bazel-") {
            std::os::unix::fs::symlink(ws.join(&name), execroot.join(&name)).unwrap();
        }
    }
}

/// The four convenience links into `base`, `<prefix>bin` and so on. The
/// one to the execution root is named after the workspace directory.
#[cfg(unix)]
fn convenience_links(ws: &Path, base: &Path, prefix: &str) {
    let out = base.join("execroot/_main/bazel-out");
    for (name, target) in [
        ("bin", out.join("k8-fastbuild/bin")),
        ("out", out.clone()),
        ("testlogs", out.join("k8-fastbuild/testlogs")),
        ("ws", base.join("execroot/_main")),
    ] {
        let link = ws.join(format!("{prefix}{name}"));
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, link).unwrap();
    }
}

/// The fake Socket API: one free patch per package of [`PACKAGES`], hosted
/// on the fake itself, so no run can leave the machine.
async fn socket_api() -> MockServer {
    let server = MockServer::start().await;
    let patch = |(purl, path, uuid): &(&str, &str, &str)| {
        let path = path.replace("TOKEN", TOKEN);
        let url = format!("{}/patch/npm/{path}", server.uri());
        let tarball = serde_json::json!({
            "kind": "tarball", "url": url, "integrity": {"sha512": SRI},
        });
        Patch {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            reference: serde_json::json!({
                "status": "granted", "url": url, "purl": null,
                "artifacts": [tarball], "registryOverride": null,
            }),
        }
    };
    mount_api(&server, &PACKAGES.iter().map(patch).collect::<Vec<_>>()).await;
    server
}

/// `scan --mode hosted --json --yes`, with no tool on `PATH`.
fn scan(ws: &Workspace, api: &MockServer) -> Value {
    let (cwd, url) = (ws.root.to_string_lossy(), api.uri());
    let mut args = vec!["scan", "--mode", "hosted", "--json", "--yes", "--cwd", &cwd];
    args.extend(["--org", ORG, "--api-token", "fake-token", "--api-url", &url]);
    let (code, stdout, stderr) = common::run_with_env(&ws.root, &args, &[("PATH", "")]);
    assert_eq!(code, 0, "scan failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
    envelope::parse_json_envelope(&stdout)
}

/// `vex`, with its document written outside the workspace.
fn vex(ws: &Workspace, api: &MockServer) -> VexOutcome {
    let run = VexRun {
        api_url: Some(api.uri()),
        api_token: Some("fake-token".into()),
        org: Some(ORG.into()),
        patch_server_url: Some(api.uri()),
        output: Some(ws.tmp.path().join("out.vex.json")),
        ..VexRun::default()
    };
    run_vex(&common::binary(), &ws.root, &run.env("PATH", ""))
}

/// The hosted pins a scan reports, in purl order.
fn pins(scan: &Value) -> Vec<(String, String)> {
    let mut pins = envelope::hosted_pins(scan);
    pins.sort();
    pins
}

/// A hosted `scan`, the `scan` after it and `vex` each see every npm
/// package: both are wired, nothing is withheld, both are attested. The
/// first run changes the lock and the pnpm side file and nothing else; the
/// second, with the side file now in place, changes nothing.
fn assert_every_package_seen(ws: &Workspace, api: &MockServer, what: &str) {
    let all: Vec<_> = PACKAGES
        .map(|(purl, _, uuid)| (purl.to_string(), uuid.to_string()))
        .into();
    let before = snapshot(&ws.root);
    let first = scan(ws, api);
    let wired = snapshot(&ws.root);
    assert_eq!(pins(&first), all, "{what}: first scan\n{first:#}");
    let lock = |file: &str| (file.to_string(), WriteClass::NativeLock);
    assert_eq!(
        assert_write_policy(&before, &wired),
        [lock("pnpm-lock.yaml"), lock("pnpm-workspace.yaml")],
        "{what}"
    );
    let second = scan(ws, api);
    assert_eq!(pins(&second), all, "{what}: second scan\n{second:#}");
    for run in [&first, &second] {
        let codes = envelope::all_codes(run);
        assert!(
            !codes.iter().any(|c| c == "user_patch_conflict"),
            "{what}: {run:#}"
        );
    }
    assert_same_tree(&wired, &snapshot(&ws.root));
    let out = vex(ws, api);
    assert_eq!(out.code, Some(0), "{what}: {out}");
    for (purl, _, uuid) in PACKAGES {
        assert_attested(out.doc(), purl, uuid, Marker::Redirected, VULNS);
    }
}

/// The control: with the marker gone the same tree withholds every npm
/// package, as every Bazel workspace did before, and writes nothing.
fn assert_every_package_withheld(ws: &Workspace, api: &MockServer, what: &str) {
    let before = snapshot(&ws.root);
    let run = scan(ws, api);
    assert_eq!(pins(&run), [], "{what}: {run:#}");
    for (purl, ..) in PACKAGES {
        let withheld = envelope::has_event(&run, "skipped", "user_patch_conflict", purl);
        assert!(withheld, "{what}: {purl}\n{run:#}");
    }
    assert_same_tree(&before, &snapshot(&ws.root));
    let out = vex(ws, api);
    assert_eq!(out.code, Some(1), "{what}: {out}");
    for (purl, ..) in PACKAGES {
        assert_not_attested(&out.envelope, purl, "vex_npm_patched_dependency");
    }
}

/// The links and the output base of a built workspace, one shape per row.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn bazel_links_and_output_bases_are_not_workspace_members() {
    let api = socket_api().await;
    for (pattern, prefix, in_tree) in [
        // Probe B4: the default links, under each pattern that reaches
        // the workspace root.
        (Some("*"), "bazel-", false),
        (Some("**"), "bazel-", false),
        // Probe rules-js B1: `.`, and no `pnpm-workspace.yaml` at all,
        // where the first hosted run writes one whose `packages:` is `.`
        // and so sets the trap for the next run itself.
        (Some("."), "bazel-", false),
        (None, "bazel-", false),
        // Probe B4: `--symlink_prefix=dist/` moves the links into a
        // directory, where no name tells them from the user's own.
        (Some("**"), "dist/", false),
        // Probe C8, `--output_base=<workspace>/out`: a real directory
        // whose execution root links back to the member `app`. Inferred
        // from C8 and B4 and never run on real Bazel: this row is the
        // first evidence for it.
        (Some("**"), "bazel-", true),
    ] {
        let what = format!("packages: {pattern:?}, {prefix}*, in-tree base: {in_tree}");
        let ws = workspace(pattern);
        let base = if in_tree {
            ws.root.join("out")
        } else {
            ws.tmp.path().join("user_root/0a1b2c")
        };
        std::fs::create_dir_all(&base).unwrap();
        output_base(&base, &ws.root);
        convenience_links(&ws.root, &base, prefix);
        assert_every_package_seen(&ws, &api, &what);
        if pattern.is_none() {
            let written = std::fs::read_to_string(ws.root.join("pnpm-workspace.yaml")).unwrap();
            assert!(written.contains("packages:\n  - '.'\n"), "{written}");
        }
        std::fs::remove_file(base.join("DO_NOT_BUILD_HERE")).unwrap();
        assert_every_package_withheld(&ws, &api, &what);
    }
}

/// A committed `bazel vendor` directory holds every fetched repository,
/// test fixtures included: one malformed `package.json` among them used
/// to protect every npm package. Under either marker Bazel writes (7.1.2
/// to 7.2.1 write only `.vendorignore`, probe C11).
#[tokio::test(flavor = "multi_thread")]
async fn a_bazel_vendor_directory_is_not_walked() {
    let api = socket_api().await;
    for marker in ["VENDOR.bazel", ".vendorignore"] {
        let ws = workspace(Some("**"));
        let vendored = "third_party/bazel/npm__resolve__1.22.8/package";
        write(&ws.root, &format!("{vendored}/package.json"), "{}\n");
        write(
            &ws.root,
            &format!("{vendored}/test/malformed/package.json"),
            "{",
        );
        write(&ws.root, &format!("third_party/bazel/{marker}"), "");
        assert_every_package_seen(&ws, &api, marker);
        std::fs::remove_file(ws.root.join("third_party/bazel").join(marker)).unwrap();
        assert_every_package_withheld(&ws, &api, marker);
    }
}
