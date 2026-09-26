//! Real-vlt agent mode and setup (suites `agent` and `setup`, DESIGN §5,
//! §8.3).
//!
//! Agent legs patch a REAL vlt tree in place (importer links, the `.vlt`
//! store, transitive, scoped, alias and peer copies) and pin how long the
//! patch persists across vlt commands (T23). Setup legs wire the root
//! `postinstall` hook and run vlt with a leg-private `npx` shim that execs
//! the socket-patch under test, counting hook invocations (T17/T18/T22).
//! Each leg is `vlt_pinned_matrix_<suite>_<leg>` and prints one `VLT-LEG`
//! line.

use std::path::Path;

use serde_json::{json, Value};

#[path = "vlt_e2e_common/mod.rs"]
mod vlt_e2e_common;

use vlt_e2e_common::fixture::*;
use vlt_e2e_common::*;

const DEBUG: (&str, &str) = ("debug", "4.3.4");
const MS2: (&str, &str) = ("ms", "2.1.2");
const USX: (&str, &str) = ("use-sync-external-store", "1.2.0");
const UUID_MS2: &str = "c9c9c9c9-9999-4999-8999-999999999999";
const HOOK: &str = "npx @socketsecurity/socket-patch apply --silent --ecosystems npm";

fn agent_leg(name: &'static str) -> Option<Leg> {
    Leg::start("agent", name)
}

fn setup_leg(name: &'static str) -> Option<Leg> {
    Leg::start("setup", name)
}

fn cwd(dir: &Path) -> String {
    dir.to_str().unwrap().to_string()
}

/// `<cmd> --json --yes --offline --cwd <dir>` plus `extra`.
fn offline(dir: &Path, cmd: &[&str], extra: &[&str]) -> SocketOut {
    let c = cwd(dir);
    let mut args: Vec<&str> = cmd.to_vec();
    args.extend(["--json", "--yes", "--offline", "--cwd", &c]);
    args.extend_from_slice(extra);
    socket(dir, &args, &[])
}

/// A tree with every copy shape: left-pad (direct), ms@2.1.2 (only
/// transitive, via debug), a scoped package, an `npm:` alias (`mm` →
/// ms@2.1.3) and a peer-resolved package.
fn zoo_shape() -> Shape {
    let pins = vec![
        LP,
        DEBUG,
        MS2,
        MS,
        SCOPED,
        USX,
        ("react", "18.2.0"),
        ("loose-envify", "1.4.0"),
        ("js-tokens", "4.0.0"),
    ];
    Shape {
        deps: vec![
            LP,
            DEBUG,
            SCOPED,
            ("mm", "npm:ms@2.1.3"),
            USX,
            ("react", "18.2.0"),
        ],
        pins,
        targets: vec![
            (LP.0, LP.1, UUID, "index.js"),
            (MS2.0, MS2.1, UUID_MS2, "index.js"),
            (MS.0, MS.1, UUID_MS, "index.js"),
            (SCOPED.0, SCOPED.1, UUID_SCOPED, "index.js"),
            (USX.0, USX.1, UUID_USX, "index.js"),
        ],
        warm: true,
        ..Shape::left_pad()
    }
    .vlt_json_fn(|v, r| with_registries(v, r, json!({ "npm": r }), &[]))
}

/// Every installed copy of `t` (every store entry of `name@version`, and
/// the importer link when it resolves there) is in `want`.
fn assert_every_copy(proj: &Path, t: &PatchTarget, want: State) {
    let lock = read_lock(proj);
    let ids = node_ids(&lock, &t.name, &t.version);
    assert!(!ids.is_empty(), "{} in the lock", t.name);
    for id in ids {
        let dir = store_pkg(proj, &id, &t.name);
        if dir.exists() {
            assert_eq!(state_at(&dir, t), want, "{id}");
        }
    }
}

fn agent_scan(fx: &Fixture) -> SocketOut {
    socket_api(&fx.proj, &fx.svc, &["scan", "--mode", "agent"], &[])
}

// ── agent commands ────────────────────────────────────────────────────────

/// `scan --mode agent` patches every copy: the direct importer, the
/// transitive-only store copy, the scoped package, the alias and the peer
/// instance; `list` shows them; `rollback` restores every copy.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_scan_apply_rollback_list() {
    let Some(leg) = agent_leg("scan_apply_rollback_list") else {
        return;
    };
    if !hermetic_registry(leg.version()) || npm_alias_to_public_npm(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    let fx = Fixture::build(leg, zoo_shape()).await;
    let out = agent_scan(&fx);
    assert_eq!(out.code, 0, "{out}");
    for t in &fx.svc.targets {
        assert_every_copy(&fx.proj, t, State::Patched);
    }
    assert_eq!(state(&fx.proj, fx.svc.target(LP.0)), State::Patched);
    let mm = importer_dir(&fx.proj, "", "mm");
    assert_eq!(
        state_at(&mm, &fx.svc.targets[2]),
        State::Patched,
        "the alias"
    );
    let out = offline(&fx.proj, &["list"], &[]);
    assert_eq!(out.code, 0, "{out}");
    for t in &fx.svc.targets {
        assert!(out.stdout.contains(&t.uuid), "list shows {}: {out}", t.name);
    }
    let out = socket_api(&fx.proj, &fx.svc, &["rollback"], &[]);
    assert_eq!(out.code, 0, "{out}");
    for t in &fx.svc.targets {
        assert_every_copy(&fx.proj, t, State::Pristine);
    }
    fx.leg.ran();
}

/// `get <uuid>` (agent) patches the installed copy; `remove <purl>` rolls
/// it back and drops it from the manifest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_get_and_remove() {
    let Some(leg) = agent_leg("get_and_remove") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = socket_api(&fx.proj, &fx.svc, &["get", UUID], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let purl = fx.t().purl();
    let out = socket_api(&fx.proj, &fx.svc, &["remove", &purl], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    let manifest = std::fs::read_to_string(fx.proj.join(".socket/manifest.json")).unwrap();
    assert!(!manifest.contains(UUID), "{manifest}");
    fx.leg.ran();
}

/// `vlt install`, then `apply` from a staged manifest patches the file.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_install_then_apply_patches_file() {
    let Some(leg) = agent_leg("install_then_apply_patches_file") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad().warm()).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = offline(&fx.proj, &["apply"], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    assert_every_copy(&fx.proj, fx.t(), State::Patched);
    fx.leg.ran();
}

/// A transitive-only dependency (ms via debug, no importer link) is
/// patched in the `.vlt` store.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_transitive_only_dep_apply_patches_store() {
    let Some(leg) = agent_leg("transitive_only_dep_apply_patches_store") else {
        return;
    };
    let shape = Shape {
        deps: vec![DEBUG],
        pins: vec![DEBUG, MS2],
        targets: vec![(MS2.0, MS2.1, UUID_MS2, "index.js")],
        warm: true,
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    assert!(
        !fx.proj.join("node_modules/ms").exists(),
        "no importer link"
    );
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = offline(&fx.proj, &["apply"], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_every_copy(&fx.proj, fx.t(), State::Patched);
    let out = std::process::Command::new("node")
        .arg("-e")
        .arg("const f=require('fs').readFileSync(require.resolve('ms',{paths:[require.resolve('debug')]}),'utf8');console.log(f.startsWith('/* SOCKET-PATCHED */'))")
        .current_dir(&fx.proj)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "true",
        "debug loads the patch"
    );
    fx.leg.ran();
}

/// The agent `scan` lockfile supplement: a package in `vlt-lock.json` but
/// not installed is still reported (`lockfileOnlyPackages`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_lockfile_supplement() {
    let Some(leg) = agent_leg("lockfile_supplement") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    let out = socket_api(&fx.proj, &fx.svc, &["scan"], &[]);
    assert_eq!(out.code, 0, "{out}");
    let doc = out.json();
    assert!(
        doc["lockfileOnlyPackages"].as_u64().unwrap_or(0) >= 1,
        "{doc:#}"
    );
    assert!(
        out.stdout.contains(&fx.t().uuid),
        "the lock-only package has its patch: {doc:#}"
    );
    fx.leg.ran();
}

/// `vlt install @socketsecurity/socket-patch` (the npm launcher and its
/// os/cpu/libc-filtered platform packages, built from this repo's `npm/`
/// with the binary under test): the linked bin runs the binary.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_launcher() {
    let Some(leg) = agent_leg("launcher") else {
        return;
    };
    if !hermetic_registry(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    let (pkgs, host) = launcher_packages();
    let reg = Registry::start_with(&[], pkgs).await;
    let proj = leg.dir("launcher");
    let launcher = launcher_version();
    write(
        &proj.join("package.json"),
        package_json(
            "vlt-e2e-launcher",
            &[("@socketsecurity/socket-patch", &launcher)],
        ),
    );
    write_vlt_json(&proj, leg.version(), &reg.url(), &VltJson::default());
    leg.vlt_ok(&proj, &["install"]);
    let platform_dir = proj.join("node_modules/.vlt");
    let installed: Vec<String> = std::fs::read_dir(&platform_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("socket-patch-"))
        .collect();
    assert!(
        installed.iter().any(|n| n.contains(&host)),
        "the host platform package is installed: {installed:?}"
    );
    let bin = proj.join("node_modules/@socketsecurity/socket-patch/bin/socket-patch");
    let out = std::process::Command::new("node")
        .arg(&bin)
        .arg("--version")
        .output()
        .unwrap();
    assert_ok(&out, "the launcher");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")),
        "{}",
        out_text(&out)
    );
    leg.ran();
}

fn launcher_version() -> String {
    let pkg: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../npm/socket-patch/package.json"),
        )
        .unwrap(),
    )
    .unwrap();
    pkg["version"].as_str().unwrap().to_string()
}

/// The launcher and every platform package (the host's carries the
/// binary under test); returns the host package's suffix.
fn launcher_packages() -> (Vec<CachedPkg>, String) {
    let npm = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../npm");
    let read = |p: &Path| -> Value { serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap() };
    let mut launcher = read(&npm.join("socket-patch/package.json"));
    for k in ["scripts", "dependencies", "exports", "devDependencies"] {
        launcher.as_object_mut().unwrap().remove(k);
    }
    let bin = std::fs::read(npm.join("socket-patch/bin/socket-patch")).unwrap();
    let mut pkgs = vec![synthetic_pkg_exec(
        launcher.clone(),
        &[("bin/socket-patch", &bin)],
        &["bin/socket-patch"],
    )];
    let host = host_platform();
    let exe = if cfg!(windows) {
        "socket-patch.exe"
    } else {
        "socket-patch"
    };
    let binary = std::fs::read(socket_bin()).unwrap();
    for name in launcher["optionalDependencies"].as_object().unwrap().keys() {
        let dir = npm.join(name.trim_start_matches("@socketsecurity/"));
        let manifest = read(&dir.join("package.json"));
        let files: Vec<(&str, &[u8])> = if name.ends_with(&host) {
            vec![(exe, &binary)]
        } else {
            vec![]
        };
        pkgs.push(synthetic_pkg_exec(manifest, &files, &[exe]));
    }
    (pkgs, host)
}

fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        o => o,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        a => a,
    };
    let libc = if cfg!(target_os = "linux") {
        if cfg!(target_env = "musl") {
            "-musl"
        } else {
            "-gnu"
        }
    } else {
        ""
    };
    format!("socket-patch-{os}-{arch}{libc}")
}

// ── persistence (T23) ─────────────────────────────────────────────────────

async fn applied(leg: Leg) -> Fixture {
    let mut shape = Shape::with_bystander().warm();
    shape.pins.push(SCOPED);
    let fx = Fixture::build(leg, shape).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = offline(&fx.proj, &["apply"], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx
}

/// After agent apply the patch survives a no-op install, `install <new>`,
/// `uninstall`, a frozen install with node_modules present, `vlt update`,
/// `install --force` (from rc.28) and a deleted hidden lock. 0.0.0-14
/// re-extracts the installed copy on every install instead (pinned).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_persistence_survives() {
    let Some(leg) = agent_leg("persistence_survives") else {
        return;
    };
    let fx = applied(leg).await;
    let mut steps: Vec<Vec<&str>> = vec![
        vec!["install"],
        vec!["install", "@isaacs/string-locale-compare@1.1.0"],
        vec!["uninstall", "@isaacs/string-locale-compare"],
    ];
    if fx.leg.at_least(HAS_CI_FROM) {
        steps.push(vec!["install", "--frozen-lockfile"]);
    }
    if fx.leg.at_least(VLT_UPDATE_FROM) {
        steps.push(vec!["update"]);
    }
    if fx.leg.at_least(INSTALL_FORCE_FROM) {
        steps.push(vec!["install", "--force"]);
    }
    let reextracts = plain_install_refreshes_stale(fx.leg.version());
    let want = if reextracts {
        State::Pristine
    } else {
        State::Patched
    };
    let reapply = |fx: &Fixture| {
        if reextracts {
            let out = offline(&fx.proj, &["apply"], &[]);
            assert_eq!(out.code, 0, "{out}");
        }
    };
    for step in steps {
        fx.vlt_ok(&fx.proj, &step);
        assert_eq!(state(&fx.proj, fx.t()), want, "after {step:?}");
        reapply(&fx);
    }
    let _ = std::fs::remove_file(fx.proj.join(HIDDEN_LOCK));
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), want, "after a deleted hidden lock");
    fx.leg.ran();
}

/// `vlt ci` (or `rm -rf node_modules` + install) restores pristine bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_persistence_reverted_by_reinstall() {
    let Some(leg) = agent_leg("persistence_reverted_by_reinstall") else {
        return;
    };
    let fx = applied(leg).await;
    if fx.leg.at_least(HAS_CI_FROM) {
        fx.vlt_ok(&fx.proj, &["ci"]);
        assert_eq!(state(&fx.proj, fx.t()), State::Pristine, "vlt ci");
        let out = offline(&fx.proj, &["apply"], &[]);
        assert_eq!(out.code, 0, "{out}");
        assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    }
    remove_tree(&fx.proj);
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(
        state(&fx.proj, fx.t()),
        State::Pristine,
        "rm -rf node_modules"
    );
    fx.leg.ran();
}

/// `apply` rerun is idempotent, `rollback` rerun is a no-op, and `vex`
/// (the setup hook wired) attests the agent-patched store copy but not
/// after a `vlt ci` that ran without the hook.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_agent_reruns_and_vex() {
    let Some(leg) = agent_leg("reruns_and_vex") else {
        return;
    };
    let fx = applied(leg).await;
    let files = package_files(&fx.proj.join(".socket"));
    let out = offline(&fx.proj, &["apply"], &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(
        package_files(&fx.proj.join(".socket")),
        files,
        "apply rerun"
    );
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    let vex = |fx: &Fixture| {
        let _ = std::fs::remove_file(fx.proj.join("out.vex.json"));
        let out = offline(
            &fx.proj,
            &["vex"],
            &["--output", "out.vex.json", "--product", PRODUCT],
        );
        (vex_doc_attests(&fx.proj.join("out.vex.json"), fx.t()), out)
    };
    let (attested, out) = vex(&fx);
    assert!(attested, "{out}");
    if fx.leg.at_least(HAS_CI_FROM) {
        let out = setup(&fx.proj, &fx, &["--remove"]);
        assert_eq!(out.code, 0, "{out}");
        fx.vlt_ok(&fx.proj, &["ci"]);
        let out = setup(&fx.proj, &fx, &[]);
        assert_eq!(out.code, 0, "{out}");
        let (attested, out) = vex(&fx);
        assert!(!attested, "pristine after vlt ci without the hook: {out}");
        let out = offline(&fx.proj, &["apply"], &[]);
        assert_eq!(out.code, 0, "{out}");
    }
    let out = offline(&fx.proj, &["rollback"], &[]);
    assert_eq!(out.code, 0, "{out}");
    let snapshot = package_files(&importer_dir(&fx.proj, "", LP.0).canonicalize().unwrap());
    let out = offline(&fx.proj, &["rollback"], &[]);
    assert!(out.code == 0 || out.code == 1, "{out}");
    assert_eq!(
        package_files(&importer_dir(&fx.proj, "", LP.0).canonicalize().unwrap()),
        snapshot,
        "rollback rerun"
    );
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    fx.leg.ran();
}

// ── setup ─────────────────────────────────────────────────────────────────

fn setup(dir: &Path, fx: &Fixture, extra: &[&str]) -> SocketOut {
    let bin = fx.leg.shim_dir();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut parts = vec![bin];
    parts.extend(std::env::split_paths(&path));
    let joined = std::env::join_paths(parts).unwrap();
    let c = cwd(dir);
    let mut args = vec!["setup", "--json", "--yes", "--cwd", &c];
    args.extend_from_slice(extra);
    socket(dir, &args, &[("PATH", joined.to_str().unwrap())])
}

fn with_hook_env(fx: &Fixture) -> VltRun {
    let mut run = fx.run.clone().with_shims();
    run.env.push(("SOCKET_NO_CONFIG".into(), "1".into()));
    run.env.push(("SOCKET_NO_UPDATE_CHECK".into(), "1".into()));
    run.env
        .push(("SOCKET_TELEMETRY_DISABLED".into(), "1".into()));
    run.env.push(("SOCKET_OFFLINE".into(), "1".into()));
    run
}

fn hook_count(fx: &Fixture) -> usize {
    fx.leg
        .npx_log()
        .iter()
        .filter(|l| l.contains("apply"))
        .count()
}

/// With the hook wired: every diff-bearing reify (fresh install, `install
/// <x>`, `ci`) runs it exactly once from rc.13, and the patched bytes land
/// in `.vlt/<DepID>/node_modules/<name>`; a no-op install runs nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_hook_fires_per_reify() {
    let Some(leg) = setup_leg("hook_fires_per_reify") else {
        return;
    };
    if !leg.at_least(ROOT_POSTINSTALL_FROM) {
        return leg.skip("root-postinstall-not-run");
    }
    let mut shape = Shape::with_bystander();
    shape.pins.push(SCOPED);
    let fx = Fixture::build(leg, shape).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    let pkg = std::fs::read_to_string(fx.proj.join("package.json")).unwrap();
    assert!(pkg.contains(HOOK), "{pkg}");
    let run = with_hook_env(&fx);
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &run);
    assert_eq!(hook_count(&fx), 1, "fresh install: {:?}", fx.leg.npx_log());
    assert_every_copy(&fx.proj, fx.t(), State::Patched);
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &run);
    assert_eq!(hook_count(&fx), 1, "a no-op install runs no hook");
    fx.leg.vlt_ok_with(
        &fx.proj,
        &["install", "@isaacs/string-locale-compare@1.1.0"],
        &run,
    );
    assert_eq!(hook_count(&fx), 2, "install <x>");
    fx.leg.vlt_ok_with(&fx.proj, &["ci"], &run);
    assert_eq!(hook_count(&fx), 3, "ci");
    assert_every_copy(&fx.proj, fx.t(), State::Patched);
    fx.leg.ran();
}

/// `vlt_root_scripts_not_run`: definite through the `vlt` shim before
/// rc.13, absent from rc.13.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_root_scripts_advisory() {
    let Some(leg) = setup_leg("root_scripts_advisory") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    let warned = out.stdout.contains("vlt_root_scripts_not_run");
    if fx.leg.at_least(ROOT_POSTINSTALL_FROM) {
        assert!(!warned, "{out}");
    } else {
        assert!(warned, "{out}");
        assert!(
            out.stdout
                .contains(&format!("(`vlt --version` reports {})", fx.leg.tc.raw)),
            "the definite wording: {out}"
        );
    }
    fx.leg.ran();
}

/// A workspace gets the hook at the root only, and a member-dir `vlt ci`
/// runs the root hook once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_workspace_root_only() {
    let Some(leg) = setup_leg("workspace_root_only") else {
        return;
    };
    if !leg.at_least(ROOT_POSTINSTALL_FROM) {
        return leg.skip("root-postinstall-not-run");
    }
    let mut shape = Shape::left_pad();
    shape.deps = vec![];
    shape.vlt_json.workspaces = Some(json!("packages/*"));
    shape.files = vec![("packages/a/package.json".into(), package_json("a", &[LP]))];
    let fx = Fixture::build(leg, shape).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let member = std::fs::read_to_string(fx.proj.join("packages/a/package.json")).unwrap();
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert!(std::fs::read_to_string(fx.proj.join("package.json"))
        .unwrap()
        .contains(HOOK));
    assert_eq!(
        std::fs::read_to_string(fx.proj.join("packages/a/package.json")).unwrap(),
        member,
        "the member is untouched"
    );
    let run = with_hook_env(&fx);
    fx.leg
        .vlt_ok_with(&fx.proj.join("packages/a"), &["ci"], &run);
    assert_eq!(hook_count(&fx), 1, "{:?}", fx.leg.npx_log());
    assert_eq!(
        state_at(&importer_dir(&fx.proj, "packages/a", LP.0), fx.t()),
        State::Patched
    );
    fx.leg.ran();
}

/// `setup` twice adds no duplicate hook.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_twice_no_duplicate() {
    let Some(leg) = setup_leg("twice_no_duplicate") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    let once = std::fs::read(fx.proj.join("package.json")).unwrap();
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(std::fs::read(fx.proj.join("package.json")).unwrap(), once);
    let pkg: Value = serde_json::from_slice(&once).unwrap();
    assert_eq!(pkg["scripts"]["postinstall"], HOOK, "{pkg:#}");
    fx.leg.ran();
}

/// With the hook present: a project with no patches installs cleanly;
/// with the patch API unreachable and the blobs not local, the hook's
/// `apply --silent` exits with the contract's `sources_download_failed`
/// code and vlt rolls the install back (a non-zero root script aborts it).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_hook_failure() {
    let Some(leg) = setup_leg("hook_failure") else {
        return;
    };
    if !leg.at_least(ROOT_POSTINSTALL_FROM) {
        return leg.skip("root-postinstall-not-run");
    }
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    let run = with_hook_env(&fx);
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &run);
    assert_eq!(hook_count(&fx), 1, "the empty hook ran");
    stage_manifest(&fx.proj, &[fx.t()]);
    std::fs::remove_dir_all(fx.proj.join(".socket/blobs")).unwrap();
    let dead = "http://127.0.0.1:9";
    let mut cmd = socket_cmd();
    let c = cwd(&fx.proj);
    cmd.args([
        "apply",
        "--silent",
        "--json",
        "--ecosystems",
        "npm",
        "--cwd",
        &c,
    ])
    .env("SOCKET_PROXY_URL", dead)
    .env("SOCKET_API_URL", dead);
    let direct = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&direct.stdout).into_owned();
    assert!(
        text.contains("sources_download_failed") && text.contains("partialFailure"),
        "the contract's warning: {text}"
    );
    assert_eq!(
        direct.status.code(),
        Some(1),
        "partialFailure exits 1: {}",
        out_text(&direct)
    );
    remove_tree(&fx.proj);
    let mut run = with_hook_env(&fx);
    run.env.retain(|(k, _)| k != "SOCKET_OFFLINE");
    run.env.push(("SOCKET_PROXY_URL".into(), dead.into()));
    run.env.push(("SOCKET_API_URL".into(), dead.into()));
    let out = fx.leg.vlt_with(&fx.proj, &["install"], &run);
    assert_eq!(hook_count(&fx), 2, "the failing hook ran");
    assert!(
        !out.status.success(),
        "the failing hook aborts the install: {}",
        out_text(&out)
    );
    fx.leg.ran();
}

/// Windows from 1.0.5 (the rollback EBUSY fix): a failing hook's abort
/// leaves no `.VLT.DELETE.*` staging dir the next crawl could misread.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_setup_hook_abort_leaves_no_staging() {
    let Some(leg) = setup_leg("hook_abort_leaves_no_staging") else {
        return;
    };
    if !cfg!(windows) {
        return leg.skip("windows-only");
    }
    if !leg.at_least(REGISTRIES_NPM_REQUIRED_FROM) {
        return leg.skip("pre-ebusy-fix");
    }
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    let out = setup(&fx.proj, &fx, &[]);
    assert_eq!(out.code, 0, "{out}");
    stage_manifest(&fx.proj, &[fx.t()]);
    std::fs::remove_dir_all(fx.proj.join(".socket/blobs")).unwrap();
    let dead = "http://127.0.0.1:9";
    let mut run = with_hook_env(&fx);
    run.env.retain(|(k, _)| k != "SOCKET_OFFLINE");
    run.env.push(("SOCKET_PROXY_URL".into(), dead.into()));
    run.env.push(("SOCKET_API_URL".into(), dead.into()));
    let out = fx.leg.vlt_with(&fx.proj, &["install"], &run);
    assert!(
        !out.status.success(),
        "the failing hook aborts: {}",
        out_text(&out)
    );
    let store = fx.proj.join("node_modules/.vlt");
    let staging: Vec<String> = std::fs::read_dir(&store)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".VLT.DELETE"))
                .collect()
        })
        .unwrap_or_default();
    assert!(staging.is_empty(), "{staging:?}");
    let out = socket_api(&fx.proj, &fx.svc, &["scan"], &[]);
    assert!(!out.stdout.contains(".VLT.DELETE"), "{out}");
    fx.leg.ran();
}
