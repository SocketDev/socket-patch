//! Real-vlt vendored capstone (suite `vendored`, DESIGN §8.3).
//!
//! Every leg installs a project with the REAL vlt under test, vendors a
//! patch into the D19 layout (`.socket/vendor/npm/<uuid>/<leaf>/
//! node_modules/<name>/`) through the real `socket-patch`, and lets vlt
//! install the committed payload from a fresh checkout. Each leg is
//! `vlt_pinned_matrix_vendored_<leg>` and prints one `VLT-LEG` line; the
//! era skips are the `vendored` rows of `vlt-leg-manifest.json`.
//!
//! Run: `SOCKET_PATCH_VLT_E2E_JS=<vlt.js> cargo test -p socket-patch-cli
//! --test e2e_vendor_vlt_build -- --include-ignored vlt_pinned_matrix`.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

#[path = "vlt_e2e_common/mod.rs"]
mod vlt_e2e_common;
#[path = "vex_e2e_common/vlt.rs"]
mod vlt_vex;

use vlt_e2e_common::fixture::*;
use vlt_e2e_common::*;

const SUITE: &str = "vendored";
const DEBUG: (&str, &str) = ("debug", "4.3.4");
const MS2: (&str, &str) = ("ms", "2.1.2");
const SEMVER: (&str, &str) = ("semver", "7.6.0");
const UUID_DEBUG: &str = "f6f6f6f6-6666-4666-8666-666666666666";
const UUID_SEMVER: &str = "a7a7a7a7-7777-4777-8777-777777777777";

/// Start a vendored leg; A0 locks (no `lockfileVersion`) are refused by
/// vendored mode, so every leg but `absent_version_refused` skips there.
fn vendored_leg(name: &'static str) -> Option<Leg> {
    let leg = Leg::start(SUITE, name)?;
    if leg.era() == VltEra::A0 {
        leg.skip("a0-vendored-unsupported");
        return None;
    }
    Some(leg)
}

fn rel(t: &PatchTarget) -> String {
    let (scope, bare) = match t.name.split_once('/') {
        Some((scope, bare)) => (format!("{scope}/"), bare),
        None => (String::new(), t.name.as_str()),
    };
    format!(
        ".socket/vendor/npm/{}/{scope}{bare}-{}/node_modules/{}",
        t.uuid, t.version, t.name
    )
}

fn uuid_dir(proj: &Path, t: &PatchTarget) -> PathBuf {
    proj.join(format!(".socket/vendor/npm/{}", t.uuid))
}

/// Every object in `doc` (at any depth) carrying an `errorCode`.
fn coded(doc: &Value) -> Vec<&Value> {
    fn walk<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
        match v {
            Value::Object(m) => {
                if m.contains_key("errorCode") {
                    out.push(v);
                }
                m.values().for_each(|c| walk(c, out));
            }
            Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(doc, &mut out);
    out
}

fn event_codes(doc: &Value) -> Vec<String> {
    coded(doc)
        .iter()
        .filter_map(|e| e["errorCode"].as_str().map(str::to_string))
        .collect()
}

fn failed_code(doc: &Value, purl: &str) -> Option<String> {
    coded(doc)
        .into_iter()
        .find(|e| e["purl"] == purl && (e["action"] == "failed" || e.get("error").is_some()))
        .and_then(|e| e["errorCode"].as_str().map(str::to_string))
}

/// `scan --mode vendored --vendor-source build` (the local build from the
/// installed store copy).
fn vendor_scan(fx: &Fixture) -> Value {
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "scan --mode vendored: {out}");
    out.json()
}

fn vendor_revert(proj: &Path) -> SocketOut {
    let cwd = proj.to_str().unwrap().to_string();
    socket(
        proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            &cwd,
        ],
        &[],
    )
}

fn repair(fx: &Fixture) -> SocketOut {
    socket_api(&fx.proj, &fx.svc, &["repair"], &[])
}

/// The committed wiring for `t`: the importer spec, the lock's `file` node
/// and the payload (with `devDependencies` stripped from package.json).
fn assert_vendored(fx: &Fixture, t: &PatchTarget, importer: &str) {
    let r = rel(t);
    let lock = read_lock(&fx.proj);
    let file_node = lock["nodes"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(id, _)| id.starts_with("file") && lock["nodes"][*id][3] == r)
        .map(|(id, _)| id.clone());
    assert!(file_node.is_some(), "a file node for {r}: {lock:#}");
    let pkg: Value = serde_json::from_slice(
        &std::fs::read(fx.proj.join(importer).join("package.json")).unwrap(),
    )
    .unwrap();
    let spec = ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .find_map(|f| {
            pkg[*f].as_object().and_then(|m| {
                m.values()
                    .find(|v| v.as_str().is_some_and(|s| s.starts_with("file:")))
                    .cloned()
            })
        })
        .unwrap_or_else(|| panic!("a file: spec in {importer}/package.json: {pkg:#}"));
    assert!(spec.as_str().unwrap().ends_with(&r), "{spec}");
    let payload = package_files(&fx.proj.join(&r));
    for (file, after) in t.patched_files() {
        if file == "package.json" {
            let got: Value = serde_json::from_slice(&payload[&file]).unwrap();
            assert!(
                got.get("devDependencies").is_none(),
                "devDependencies stripped"
            );
            continue;
        }
        assert_eq!(payload.get(&file), Some(&after), "{r}/{file}");
    }
}

/// A fresh checkout's locked install and frozen install land the patched
/// payload with the lock byte-stable.
fn assert_fresh_vendored(fx: &Fixture, t: &PatchTarget, name: &str) -> PathBuf {
    let co = fx.checkout(name);
    assert_ci_byte_stable(&fx.leg, &co, &VltRun::profile(name), false);
    assert_eq!(state(&co, t), State::Patched, "{} after ci", t.name);
    let frozen = fx.leg.frozen_args();
    std::fs::remove_dir_all(co.join("node_modules")).unwrap();
    let before = lock_bytes(&co);
    fx.vlt_ok_profile(&co, &frozen, &format!("{name}-frozen"));
    assert_eq!(state(&co, t), State::Patched, "{} after {frozen:?}", t.name);
    assert_eq!(lock_bytes(&co), before, "frozen keeps the lock");
    co
}

async fn left_pad_fixture(leg: Leg) -> Fixture {
    Fixture::build(leg, Shape::with_bystander().warm()).await
}

fn standalone_vex_outcome(fx: &Fixture, dir: &Path) -> (SocketOut, bool) {
    let _ = std::fs::remove_file(dir.join("out.vex.json"));
    let uri = fx.svc.uri();
    let out = socket_api(
        dir,
        &fx.svc,
        &["vex"],
        &[
            "--output",
            "out.vex.json",
            "--product",
            PRODUCT,
            "--patch-server-url",
            &uri,
        ],
    );
    let attested = vex_doc_attests(&dir.join("out.vex.json"), fx.t());
    (out, attested)
}

// ── drivers ───────────────────────────────────────────────────────────────

/// `scan --mode vendored`: the payload is committed in the D19 layout, the
/// importer and the lock point at it, and a fresh checkout's `vlt ci` and
/// frozen install land the patched bytes with the lock byte-stable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_scan_fresh_ci() {
    let Some(leg) = vendored_leg("scan_fresh_ci") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    let doc = vendor_scan(&fx);
    assert!(!event_codes(&doc)
        .iter()
        .any(|c| c == "vendor_prebuilt_downloaded"));
    assert_vendored(&fx, fx.t(), "");
    assert_eq!(
        read(&uuid_dir(&fx.proj, fx.t()).join(".gitignore")),
        "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n"
    );
    assert_eq!(
        read(&uuid_dir(&fx.proj, fx.t()).join(".gitattributes")),
        "* -text\n"
    );
    assert_fresh_vendored(&fx, fx.t(), "fresh-scan");
    fx.leg.ran();
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

async fn get_vendored(name: &'static str, source: &str) {
    let Some(leg) = vendored_leg(name) else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["get", UUID, "--mode", "vendored"],
        &["--vendor-source", source],
    );
    assert_eq!(out.code, 0, "{out}");
    let doc = out.json();
    let served = event_codes(&doc)
        .iter()
        .any(|c| c == "vendor_prebuilt_downloaded");
    assert_eq!(served, source == "service", "{doc:#}");
    assert_vendored(&fx, fx.t(), "");
    assert_fresh_vendored(&fx, fx.t(), "fresh-get");
    fx.leg.ran();
}

/// `get <uuid> --mode vendored --vendor-source build`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_get_build_fresh_ci() {
    get_vendored("get_build_fresh_ci", "build").await;
}

/// `get <uuid> --mode vendored --vendor-source service`: the service's
/// archive is extracted into the D19 layout.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_get_service_fresh_ci() {
    get_vendored("get_service_fresh_ci", "service").await;
}

/// A direct vendored dependency survives a no-op install, an add, an
/// uninstall and an update (p-vendored §2).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_durability() {
    let Some(leg) = vendored_leg("durability") else {
        return;
    };
    let mut shape = Shape::with_bystander().warm();
    shape.pins.push(SCOPED);
    let fx = Fixture::build(leg, shape).await;
    vendor_scan(&fx);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let mut steps: Vec<Vec<&str>> = vec![
        vec!["install"],
        vec!["install", "@isaacs/string-locale-compare@1.1.0"],
        vec!["uninstall", "@isaacs/string-locale-compare"],
    ];
    if fx.leg.at_least(VLT_UPDATE_FROM) {
        steps.push(vec!["update"]);
    }
    for step in steps {
        fx.vlt_ok(&fx.proj, &step);
        assert_eq!(state(&fx.proj, fx.t()), State::Patched, "after {step:?}");
        assert_vendored(&fx, fx.t(), "");
    }
    fx.leg.ran();
}

// ── self-referencing packages (D19) ───────────────────────────────────────

const SELFREF: (&str, &str) = ("vlt-e2e-selfref", "1.0.0");
const UUID_SELFREF: &str = "b8b8b8b8-8888-4888-8888-888888888888";

fn selfref_shape(importer_pkg: (&str, String)) -> Shape {
    Shape {
        deps: vec![],
        pins: vec![],
        synthetic: vec![selfref_pkg()],
        targets: vec![(SELFREF.0, SELFREF.1, UUID_SELFREF, "lib/impl.js")],
        files: vec![(importer_pkg.0.to_string(), importer_pkg.1)],
        warm: true,
        ..Shape::left_pad()
    }
}

/// `require('<module>')` from `dir` (the package requires its own name)
/// loads the patched `lib/impl.js`.
fn assert_selfref(dir: &Path, module: &str, t: &PatchTarget) {
    let script = format!(
        "require('{module}');\
         const f=require('fs').readFileSync(require.resolve('{module}/lib/impl'),'utf8');\
         console.log(f.startsWith('/* SOCKET-PATCHED */')?'PATCHED':'PRISTINE')"
    );
    let out = std::process::Command::new("node")
        .arg("-e")
        .arg(&script)
        .current_dir(dir)
        .output()
        .unwrap();
    assert_ok(
        &out,
        &format!("self-reference of {} from {}", t.name, dir.display()),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "PATCHED");
}

/// A workspace member's direct dependency on a package that requires its
/// own name is vendored (the member gets `file:../../.socket/…`), and the
/// self-reference resolves after a fresh `vlt ci`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_workspace_member_selfref() {
    let Some(leg) = vendored_leg("workspace_member_selfref") else {
        return;
    };
    if !hermetic_registry(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    let mut shape = selfref_shape(("packages/a/package.json", package_json("a", &[SELFREF])));
    shape.vlt_json.workspaces = Some(json!("packages/*"));
    let fx = Fixture::build(leg, shape).await;
    let t = fx.t().clone();
    vendor_scan(&fx);
    assert_vendored(&fx, &t, "packages/a");
    let pkg = read(&fx.proj.join("packages/a/package.json"));
    assert!(pkg.contains(&format!("file:../../{}", rel(&t))), "{pkg}");
    let co = fx.checkout("fresh-member");
    assert_ci_byte_stable(&fx.leg, &co, &VltRun::profile("fresh-member"), false);
    assert_selfref(&co.join("packages/a"), SELFREF.0, &t);
    fx.leg.ran();
}

/// An npm-alias importer edge (`sr: npm:vlt-e2e-selfref@1.0.0`):
/// the package.json key stays the alias and the self-reference resolves
/// (`npm:` specs follow `registries.npm`, pointed at the harness registry
/// on every era).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_alias_selfref() {
    let Some(leg) = vendored_leg("alias_selfref") else {
        return;
    };
    if !hermetic_registry(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    if npm_alias_to_public_npm(leg.version()) {
        return leg.skip("npm-alias-non-hermetic");
    }
    let mut shape = selfref_shape(("README.md", "alias\n".into()))
        .vlt_json_fn(|v, r| with_registries(v, r, json!({ "npm": r }), &[]));
    shape.deps = vec![("sr", "npm:vlt-e2e-selfref@1.0.0")];
    let fx = Fixture::build(leg, shape).await;
    let t = fx.t().clone();
    vendor_scan(&fx);
    let pkg: Value = serde_json::from_str(&read(&fx.proj.join("package.json"))).unwrap();
    assert!(
        pkg["dependencies"]["sr"]
            .as_str()
            .is_some_and(|s| s.ends_with(&rel(&t))),
        "{pkg:#}"
    );
    let co = fx.checkout("fresh-alias");
    assert_ci_byte_stable(&fx.leg, &co, &VltRun::profile("fresh-alias"), true);
    assert_selfref(&co, "sr", &t);
    fx.leg.ran();
}

/// A dependency with dependencies: vlt creates the link dir inside the
/// vendored package (socket-patch never reads or commits it) and `git
/// status` stays clean.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_dep_with_deps() {
    let Some(leg) = vendored_leg("dep_with_deps") else {
        return;
    };
    let shape = Shape {
        deps: vec![DEBUG],
        pins: vec![DEBUG, MS2],
        targets: vec![(DEBUG.0, DEBUG.1, UUID_DEBUG, "src/index.js")],
        warm: true,
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    let t = fx.t().clone();
    git_ok(&fx.proj, &["init", "-q"]);
    write(&fx.proj.join(".gitignore"), "node_modules\n.VLT.DELETE.*\n");
    vendor_scan(&fx);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    assert_eq!(state(&fx.proj, &t), State::Patched);
    let inner = fx.proj.join(rel(&t)).join("node_modules");
    assert!(inner.join("ms").exists(), "vlt links ms inside the payload");
    git_ok(&fx.proj, &["add", "-A"]);
    git_ok(&fx.proj, &["commit", "-q", "-m", "vendored"]);
    fx.vlt_ok(&fx.proj, &["install"]);
    let status = git_ok(&fx.proj, &["status", "--porcelain"]);
    assert_eq!(status, "", "the link dir stays out of git");
    let tracked = git_ok(&fx.proj, &["ls-files"]);
    assert!(
        !tracked.contains(&format!("{}/node_modules/", rel(&t))),
        "{tracked}"
    );
    let co = fx.leg.root.join("clone");
    git_ok(
        &fx.leg.root,
        &[
            "clone",
            "-q",
            fx.proj.to_str().unwrap(),
            co.to_str().unwrap(),
        ],
    );
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "clone");
    assert_eq!(state(&co, &t), State::Patched);
    assert!(installed(&co, "debug", "package.json").is_some());
    fx.leg.ran();
}

/// A root `.gitignore` that ignores what packages publish: the payload is
/// committed anyway (`<uuid>/.gitignore` re-includes it) and a fresh clone
/// installs the patch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_hostile_gitignore() {
    let Some(leg) = vendored_leg("hostile_gitignore") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    git_ok(&fx.proj, &["init", "-q"]);
    write(
        &fx.proj.join(".gitignore"),
        "node_modules\n.VLT.DELETE.*\ndist/\n*.map\n*.js\n",
    );
    vendor_scan(&fx);
    git_ok(&fx.proj, &["add", "-A"]);
    git_ok(&fx.proj, &["commit", "-q", "-m", "vendored"]);
    let tracked = git_ok(&fx.proj, &["ls-files"]);
    assert!(
        tracked.contains(&format!("{}/index.js", rel(fx.t()))),
        "{tracked}"
    );
    let co = fx.leg.root.join("clone");
    git_ok(
        &fx.leg.root,
        &[
            "clone",
            "-q",
            fx.proj.to_str().unwrap(),
            co.to_str().unwrap(),
        ],
    );
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "clone");
    assert_eq!(state(&co, fx.t()), State::Patched);
    fx.leg.ran();
}

/// A `core.autocrlf=true` clone keeps the payload byte-exact
/// (`<uuid>/.gitattributes` is `* -text`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_autocrlf_checkout() {
    let Some(leg) = vendored_leg("autocrlf_checkout") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    git_ok(&fx.proj, &["init", "-q"]);
    write(&fx.proj.join(".gitignore"), "node_modules\n.VLT.DELETE.*\n");
    vendor_scan(&fx);
    git_ok(&fx.proj, &["add", "-A"]);
    git_ok(&fx.proj, &["commit", "-q", "-m", "vendored"]);
    let co = fx.leg.root.join("crlf");
    git_ok(
        &fx.leg.root,
        &[
            "-c",
            "core.autocrlf=true",
            "clone",
            "-q",
            fx.proj.to_str().unwrap(),
            co.to_str().unwrap(),
        ],
    );
    let payload = package_files(&co.join(rel(fx.t())));
    assert_eq!(payload.get(&fx.t().file), Some(&fx.t().after), "byte-exact");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "crlf");
    assert_eq!(state(&co, fx.t()), State::Patched);
    let (out, attested) = standalone_vex_outcome(&fx, &co);
    assert!(attested, "the autocrlf checkout verifies: {out}");
    fx.leg.ran();
}

/// A bin-bearing package (semver): the bin is linked from the vendored
/// payload after a fresh `vlt ci`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_bin_bearing() {
    let Some(leg) = vendored_leg("bin_bearing") else {
        return;
    };
    let shape = Shape {
        deps: vec![SEMVER],
        pins: vec![SEMVER, ("lru-cache", "6.0.0"), ("yallist", "4.0.0")],
        targets: vec![(SEMVER.0, SEMVER.1, UUID_SEMVER, "index.js")],
        warm: true,
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    vendor_scan(&fx);
    let co = assert_fresh_vendored(&fx, fx.t(), "fresh-bin");
    let bin = co.join("node_modules/.bin/semver");
    assert!(
        bin.exists() || co.join("node_modules/.bin/semver.cmd").exists(),
        "the bin is linked"
    );
    let out = std::process::Command::new("node")
        .arg(co.join("node_modules/semver/bin/semver.js"))
        .arg("1.2.3")
        .output()
        .unwrap();
    assert_ok(&out, "semver bin");
    fx.leg.ran();
}

/// A patch that also touches package.json of a package with
/// devDependencies: vendoring verifies it under the vlt manifest exemption
/// and VEX attests it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_package_json_devdeps_patch() {
    let Some(leg) = vendored_leg("package_json_devdeps_patch") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    let t = fx.t().clone();
    let pkg = String::from_utf8(t.base["package.json"].clone()).unwrap();
    let after = pkg
        .replacen('{', "{\n  \"socketPatched\": true,", 1)
        .into_bytes();
    let t2 = t.clone().also_patch("package.json", after);
    let svc = PatchService::start(vec![t2.clone()]).await;
    let out = socket_api(
        &fx.proj,
        &svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "{out}");
    let payload = package_files(&fx.proj.join(rel(&t2)));
    let got: Value = serde_json::from_slice(&payload["package.json"]).unwrap();
    assert_eq!(got["socketPatched"], true);
    assert!(got.get("devDependencies").is_none());
    let co = fx.checkout("fresh-pkgjson");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "fresh-pkgjson");
    assert_eq!(state(&co, &t2), State::Patched);
    let uri = svc.uri();
    let out = socket_api(
        &co,
        &svc,
        &["vex"],
        &[
            "--output",
            "out.vex.json",
            "--product",
            PRODUCT,
            "--patch-server-url",
            &uri,
        ],
    );
    assert!(vex_doc_attests(&co.join("out.vex.json"), &t2), "{out}");
    fx.leg.ran();
}

// ── repair, idempotency, revert ───────────────────────────────────────────

/// The committed payload deleted outright: `repair` rebuilds it from the
/// installed copy, and a fresh checkout installs the patch again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_repair_rebuilds() {
    let Some(leg) = vendored_leg("repair_rebuilds") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    let lock = lock_bytes(&fx.proj);
    let committed = package_files(&fx.proj.join(rel(fx.t())));
    std::fs::remove_dir_all(fx.proj.join(rel(fx.t()))).unwrap();
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let out = repair(&fx);
    assert_eq!(out.code, 0, "{out}");
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "repair");
    assert_eq!(package_files(&fx.proj.join(rel(fx.t()))), committed);
    assert_eq!(lock_bytes(&fx.proj), lock, "repair keeps the lock");
    assert_fresh_vendored(&fx, fx.t(), "fresh-repair");
    fx.leg.ran();
}

/// `vendor --revert` twice and `repair` twice: the reruns change nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_idempotency() {
    let Some(leg) = vendored_leg("idempotency") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    let out = repair(&fx);
    assert_eq!(out.code, 0, "{out}");
    let files = package_files(&fx.proj.join(".socket"));
    let lock = lock_bytes(&fx.proj);
    let out = repair(&fx);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(
        package_files(&fx.proj.join(".socket")),
        files,
        "repair rerun"
    );
    assert_eq!(lock_bytes(&fx.proj), lock);
    let out = vendor_revert(&fx.proj);
    assert_eq!(out.code, 0, "{out}");
    let lock = lock_bytes(&fx.proj);
    let pkg = std::fs::read(fx.proj.join("package.json")).unwrap();
    let out = vendor_revert(&fx.proj);
    assert!(out.code == 0 || out.code == 1, "{out}");
    assert_eq!(lock_bytes(&fx.proj), lock, "revert rerun");
    assert_eq!(std::fs::read(fx.proj.join("package.json")).unwrap(), pkg);
    fx.leg.ran();
}

/// `vendor --revert` restores the lock and package.json byte-for-byte and
/// removes the payload; `vlt ci` then installs the registry bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_revert_byte_exact() {
    let Some(leg) = vendored_leg("revert_byte_exact") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    let pkg_before = std::fs::read(fx.proj.join("package.json")).unwrap();
    vendor_scan(&fx);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    let snap = fx.snapshot(&fx.proj, &[]);
    let out = vendor_revert(&fx.proj);
    assert_eq!(out.code, 0, "{out}");
    snap.assert_same(&fx.snapshot(&fx.proj, &[]), "vendor --revert");
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(&fx.proj)),
        String::from_utf8_lossy(&fx.lock_before)
    );
    assert_eq!(
        std::fs::read(fx.proj.join("package.json")).unwrap(),
        pkg_before
    );
    assert!(!uuid_dir(&fx.proj, fx.t()).exists(), "payload removed");
    let co = fx.checkout("after-revert");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "after-revert");
    assert_eq!(state(&co, fx.t()), State::Pristine);
    fx.leg.ran();
}

/// Re-saves after vendoring (`vlt install <new>`, `vlt uninstall
/// <other>`, a CRLF lock): `vendor --revert` re-places the registry
/// entries among vlt's and a following `vlt ci` keeps the lock
/// byte-identical.
async fn resave_revert(name: &'static str, step: &'static str, crlf: bool) {
    let Some(leg) = vendored_leg(name) else {
        return;
    };
    let mut shape = Shape::with_bystander().warm();
    shape.pins.push(SCOPED);
    let fx = Fixture::build(leg, shape).await;
    if crlf {
        std::fs::write(fx.proj.join(VLT_LOCK), to_crlf(&fx.lock_before)).unwrap();
    }
    vendor_scan(&fx);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    match step {
        "install" => {
            fx.vlt_ok(
                &fx.proj,
                &["install", "@isaacs/string-locale-compare@1.1.0"],
            );
        }
        _ => {
            fx.vlt_ok(&fx.proj, &["uninstall", MS.0]);
        }
    }
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let out = vendor_revert(&fx.proj);
    assert_eq!(out.code, 0, "{out}");
    let lock = read_lock(&fx.proj);
    assert_eq!(
        node_ids(&lock, LP.0, LP.1).len(),
        1,
        "registry node back: {lock:#}"
    );
    assert!(
        !lock.to_string().contains(".socket/vendor"),
        "no vendored wiring left: {lock:#}"
    );
    if fx.leg.at_least(HAS_CI_FROM) {
        assert_ci_byte_stable(&fx.leg, &fx.proj, &fx.run, false);
        assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    }
    fx.leg.ran();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_resave_install_revert() {
    resave_revert("resave_install_revert", "install", false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_resave_uninstall_revert() {
    resave_revert("resave_uninstall_revert", "uninstall", false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_resave_crlf_revert() {
    resave_revert("resave_crlf_revert", "install", true).await;
}

// ── tamper (T33) ──────────────────────────────────────────────────────────

/// Vendor, install, tamper with the committed state, then: standalone VEX
/// no longer attests the patch.
async fn tamper(name: &'static str, how: fn(&Fixture, &Path)) {
    let Some(leg) = vendored_leg(name) else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    let (out, attested) = standalone_vex_outcome(&fx, &fx.proj);
    assert!(attested, "attested before the tamper: {out}");
    let payload = fx.proj.join(rel(fx.t()));
    how(&fx, &payload);
    let (out, attested) = standalone_vex_outcome(&fx, &fx.proj);
    assert!(!attested, "{name}: VEX must not attest: {out}");
    fx.leg.ran();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_planted_file() {
    tamper("tamper_planted_file", |_, p| {
        write(&p.join("planted.js"), "module.exports = 'planted'\n")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_file_content() {
    tamper("tamper_file_content", |fx, p| {
        let mut b = fx.t().after.clone();
        b.extend_from_slice(b"\n// tampered\n");
        write(&p.join(&fx.t().file), b)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_payload_package_json() {
    tamper("tamper_payload_package_json", |fx, p| {
        write(&p.join("package.json"), &fx.t().base["package.json"])
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_symlink_outside() {
    tamper("tamper_symlink_outside", |fx, p| {
        let target = fx.proj.join("package.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, p.join("evil.js")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, p.join("evil.js")).unwrap();
    })
    .await;
}

/// A deleted `<uuid>/.gitignore` is repaired, not a mismatch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_deleted_gitignore() {
    let Some(leg) = vendored_leg("tamper_deleted_gitignore") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    let gi = uuid_dir(&fx.proj, fx.t()).join(".gitignore");
    let body = std::fs::read(&gi).unwrap();
    std::fs::remove_file(&gi).unwrap();
    let out = repair(&fx);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(std::fs::read(&gi).unwrap(), body, "repair restores it");
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    let (out, attested) = standalone_vex_outcome(&fx, &fx.proj);
    assert!(attested, "{out}");
    fx.leg.ran();
}

/// A hand-edited file-node path in the lock: revert reports the drift and
/// keeps the payload, writing nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_tamper_lock_file_node_path() {
    let Some(leg) = vendored_leg("tamper_lock_file_node_path") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    let r = rel(fx.t());
    let text = String::from_utf8(lock_bytes(&fx.proj)).unwrap();
    let edited = text.replacen(&format!("\"{r}\"]"), &format!("\"{r}/x\"]"), 1);
    assert_ne!(edited, text, "the file node carries the path");
    std::fs::write(fx.proj.join(VLT_LOCK), &edited).unwrap();
    let out = vendor_revert(&fx.proj);
    let doc = out.json();
    assert!(
        event_codes(&doc)
            .iter()
            .any(|c| c == "vendor_lock_entry_drifted"),
        "{out}"
    );
    assert_eq!(String::from_utf8(lock_bytes(&fx.proj)).unwrap(), edited);
    assert!(fx.proj.join(&r).exists(), "the payload is kept");
    let (out, attested) = standalone_vex_outcome(&fx, &fx.proj);
    assert!(!attested, "{out}");
    fx.leg.ran();
}

// ── refusals and era legs ─────────────────────────────────────────────────

/// A transitive-only target is refused (`vendor_vlt_transitive_unsupported`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_transitive_refused() {
    let Some(leg) = vendored_leg("transitive_refused") else {
        return;
    };
    let shape = Shape {
        deps: vec![DEBUG],
        pins: vec![DEBUG, MS2],
        targets: vec![(MS2.0, MS2.1, UUID_MS, "index.js")],
        warm: true,
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    let doc = out.json();
    assert_eq!(
        failed_code(&doc, &fx.t().purl()).as_deref(),
        Some("vendor_vlt_transitive_unsupported"),
        "{out}"
    );
    assert_eq!(lock_bytes(&fx.proj), fx.lock_before, "no write");
    fx.leg.ran();
}

/// An era-A lock (0.0.0-19 … rc.8) with `··` ids (the default registry,
/// public npm) vendors with `vendor_vlt_legacy_lockfile`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_legacy_lockfile_warning() {
    let Some(leg) = vendored_leg("legacy_lockfile_warning") else {
        return;
    };
    if leg.era() != VltEra::A {
        return leg.skip("not-legacy-lockfile");
    }
    let mut shape = Shape::with_bystander().warm();
    shape.vlt_json.no_registry = true;
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    assert!(
        node_id(&lock, LP.0, LP.1).starts_with("··"),
        "the default registry writes `··` ids: {lock:#}"
    );
    let doc = vendor_scan(&fx);
    assert!(
        doc.to_string().contains("vendor_vlt_legacy_lockfile"),
        "{doc:#}"
    );
    assert_fresh_vendored(&fx, fx.t(), "fresh-legacy");
    fx.leg.ran();
}

/// An A0 lock (no `lockfileVersion`, ≤ 0.0.0-18) is refused
/// (`vendor_lockfile_version_unsupported`) with no writes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_absent_version_refused() {
    let Some(leg) = Leg::start(SUITE, "absent_version_refused") else {
        return;
    };
    if leg.era() != VltEra::A0 {
        return leg.skip("lockfile-version-present");
    }
    let fx = left_pad_fixture(leg).await;
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    let doc = out.json();
    assert_eq!(
        failed_code(&doc, &fx.t().purl()).as_deref(),
        Some("vendor_lockfile_version_unsupported"),
        "{out}"
    );
    assert_eq!(lock_bytes(&fx.proj), fx.lock_before, "no write");
    assert!(!fx.proj.join(".socket/vendor/npm").exists());
    fx.leg.ran();
}

/// The lock deleted, then `vlt install`: 0.0.0-31 … rc.5 cannot resolve
/// a lockless `file:` directory (non-zero exit); every other release
/// installs the patched payload.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_lockless_reinstall() {
    let Some(leg) = vendored_leg("lockless_reinstall") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    vendor_scan(&fx);
    let co = fx.checkout("lockless");
    std::fs::remove_file(co.join(VLT_LOCK)).unwrap();
    let out = fx.vlt_profile(&co, &["install"], "lockless");
    if !lockless_file_dir_broken(fx.leg.version()) {
        assert_ok(&out, "lockless install");
        assert_eq!(state(&co, fx.t()), State::Patched);
    } else {
        assert!(!out.status.success(), "{}", out_text(&out));
    }
    fx.leg.ran();
}

/// The manifest-less VEX tail on the vendored project.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_vendored_manifestless_vex() {
    let Some(leg) = vendored_leg("manifestless_vex") else {
        return;
    };
    let fx = left_pad_fixture(leg).await;
    let pkg_before = std::fs::read(fx.proj.join("package.json")).unwrap();
    vendor_scan(&fx);
    let t = fx.t().clone();
    let cve = [t.cve.as_str()];
    let vulns = vec![(t.ghsa.as_str(), &cve[..])];
    let case = vlt_vex::VltVexCase {
        tag: "vendored",
        mode: vlt_vex::VltMode::Vendored,
        purl: &t.purl(),
        uuid: &t.uuid,
        files: t.vex_files(),
        vulns: &vulns,
        registry_lock: fx.lock_before.clone(),
        registry_manifests: vec![("package.json".into(), pkg_before)],
        patch_server_url: Some(fx.svc.uri()),
    };
    let leg = &fx.leg;
    vlt_vex::run_vlt_vex_matrix(&fx.proj, &leg.root, &case, |co| {
        let out = leg.vlt_with(co, &leg.locked_install_args(), &VltRun::profile("vex"));
        assert_ok(&out, "vex checkout locked install");
        assert_eq!(state(co, &t), State::Patched);
    });
    fx.leg.ran();
}
