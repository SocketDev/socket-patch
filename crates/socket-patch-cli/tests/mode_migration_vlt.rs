//! Real-vlt mode migrations (suite `migration`, DESIGN §8.3, §4.10).
//!
//! Hosted ⇄ vendored takeovers (both drivers), dry-run parity, scoped and
//! unscoped unwinds, agent-mode interplay (r-tests T21), package-manager
//! switches (T37) and the vlt upgrade (T19, `SOCKET_PATCH_VLT_E2E_UPGRADE_JS`)
//! against the REAL vlt under test, every terminal state proven by a fresh
//! checkout's locked install. Each leg is `vlt_pinned_matrix_migration_<leg>`
//! and prints one `VLT-LEG` line.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

#[path = "vlt_e2e_common/mod.rs"]
mod vlt_e2e_common;

use vlt_e2e_common::fixture::*;
use vlt_e2e_common::*;

const SUITE: &str = "migration";

fn migration_leg(name: &'static str) -> Option<Leg> {
    let leg = Leg::start(SUITE, name)?;
    if leg.era() == VltEra::A0 {
        leg.skip("a0-vendored-unsupported");
        return None;
    }
    Some(leg)
}

/// Every object in `doc` carrying an `errorCode`, at any depth.
fn codes(doc: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if let Some(c) = m.get("errorCode").and_then(Value::as_str) {
                    out.push(c.to_string());
                }
                if let Some(c) = m.get("code").and_then(Value::as_str) {
                    out.push(c.to_string());
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

fn has_code(doc: &Value, code: &str) -> bool {
    codes(doc).iter().any(|c| c == code)
}

/// Every committable byte of `proj` (no installed trees).
fn project_bytes(proj: &Path) -> BTreeMap<String, Vec<u8>> {
    let co = proj.with_extension("snapshot");
    fresh_checkout(proj, &co);
    let files = vlt_vex_free_walk(&co);
    std::fs::remove_dir_all(&co).unwrap();
    files
}

fn vlt_vex_free_walk(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                walk(base, &p, out);
            } else {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn cwd_args(proj: &Path) -> String {
    proj.to_str().unwrap().to_string()
}

fn vendor_cmd(proj: &Path, extra: &[&str]) -> SocketOut {
    let cwd = cwd_args(proj);
    let mut args = vec!["vendor", "--json", "--yes", "--offline", "--cwd", &cwd];
    args.extend_from_slice(extra);
    socket(proj, &args, &[])
}

fn vendored_scan(fx: &Fixture, dir: &Path, extra: &[&str]) -> SocketOut {
    let mut args = vec!["--vendor-source", "build"];
    args.extend_from_slice(extra);
    socket_api(dir, &fx.svc, &["scan", "--mode", "vendored"], &args)
}

fn hosted_scan(fx: &Fixture, dir: &Path, extra: &[&str]) -> SocketOut {
    socket_api(dir, &fx.svc, &["scan", "--mode", "hosted"], extra)
}

fn agent(dir: &Path, cmd: &str, extra: &[&str]) -> SocketOut {
    let cwd = cwd_args(dir);
    let mut args = vec![cmd, "--json", "--yes", "--offline", "--cwd", &cwd];
    args.extend_from_slice(extra);
    socket(dir, &args, &[])
}

fn copy_project(fx: &Fixture, from: &Path, name: &str) -> std::path::PathBuf {
    let to = fx.leg.dir(name);
    std::fs::remove_dir_all(&to).unwrap();
    fresh_checkout(from, &to);
    fx.vlt_ok_profile(&to, &fx.leg.locked_install_args(), name);
    to
}

fn assert_pure_hosted(fx: &Fixture, dir: &Path, t: &PatchTarget) {
    assert_pinned(dir, &fx.svc, t);
    assert!(
        !String::from_utf8(lock_bytes(dir))
            .unwrap()
            .contains(".socket/vendor"),
        "no vendored wiring left"
    );
    assert!(
        !dir.join(format!(".socket/vendor/npm/{}", t.uuid)).exists(),
        "no vendored artifact left"
    );
    let ledger: Value = serde_json::from_slice(
        &std::fs::read(dir.join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    let before: Value = serde_json::from_slice(&fx.lock_before).unwrap();
    let id = node_id(&before, &t.name, &t.version);
    let original = ledger["edits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["kind"] == "redirect_vlt_lock_node"
                && e["original"]
                    .as_str()
                    .is_some_and(|o| o.starts_with(&format!("\"{id}\"")))
        })
        .and_then(|e| e["original"].as_str())
        .unwrap_or_else(|| panic!("a ledger edit for {id}: {ledger:#}"))
        .to_string();
    let pristine = node_line(&String::from_utf8_lossy(&fx.lock_before), &id)
        .unwrap()
        .trim()
        .trim_end_matches(',')
        .to_string();
    assert_eq!(
        original, pristine,
        "the ledger original is the pristine registry line"
    );
}

fn assert_pure_vendored(dir: &Path, t: &PatchTarget) {
    let text = String::from_utf8(lock_bytes(dir)).unwrap();
    assert!(
        text.contains(&format!(".socket/vendor/npm/{}/", t.uuid)),
        "the lock is vendored: {text}"
    );
    let lock = read_lock(dir);
    assert!(
        node_ids(&lock, &t.name, &t.version).is_empty(),
        "no registry node left for {}: {lock:#}",
        t.name
    );
    assert!(
        !text.contains(&t.artifact_path()),
        "no hosted URL left: {text}"
    );
    assert!(
        !dir.join(".socket/vendor/redirect-state.json").exists()
            || !std::fs::read_to_string(dir.join(".socket/vendor/redirect-state.json"))
                .unwrap()
                .contains(&t.purl()),
        "the redirect record is gone"
    );
}

/// A fresh checkout's locked install lands `want` for `t`.
fn assert_fresh(fx: &Fixture, dir: &Path, t: &PatchTarget, want: State, name: &str) {
    let co = fx.leg.root.join(format!("fresh-{name}"));
    fresh_checkout(dir, &co);
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), name);
    assert_eq!(state(&co, t), want, "{name}: {}", t.name);
}

fn assert_unscoped_rollback_pristine(fx: &Fixture, dir: &Path, name: &str) {
    let out = rollback(dir, &[]);
    assert_eq!(out.code, 0, "{name}: {out}");
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(dir)),
        String::from_utf8_lossy(&fx.lock_before),
        "{name}: the pristine lock"
    );
    assert!(
        !dir.join(".socket/vendor/npm").exists(),
        "{name}: no artifacts"
    );
    assert!(
        !dir.join(".socket/vendor/state.json").exists(),
        "{name}: no vendor ledger"
    );
    assert!(
        !dir.join(".socket/vendor/redirect-state.json").exists(),
        "{name}: no redirect ledger"
    );
    for t in &fx.svc.targets {
        assert_fresh(fx, dir, t, State::Pristine, &format!("{name}-{}", t.bare()));
    }
}

async fn two_target_fixture(leg: Leg) -> Fixture {
    let shape = Shape {
        deps: vec![LP, MS],
        pins: vec![LP, MS],
        targets: vec![
            (LP.0, LP.1, UUID, "index.js"),
            (MS.0, MS.1, UUID_MS, "index.js"),
        ],
        warm: true,
        ..Shape::left_pad()
    };
    Fixture::build(leg, shape).await
}

// ── 1–2. takeovers ────────────────────────────────────────────────────────

/// Vendored → hosted: the vendored entry, artifact and wiring go, the
/// ledger original is the pristine registry line, a fresh checkout is
/// patched; the unscoped rollback restores the pristine lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_vendored_then_hosted() {
    let Some(leg) = migration_leg("vendored_then_hosted") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = vendored_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert!(
        has_code(&out.json(), "redirect_takeover_reverted_vendored"),
        "{out}"
    );
    assert_pure_hosted(&fx, &fx.proj, fx.t());
    assert!(!fx.proj.join(".socket/vendor/state.json").exists());
    assert_fresh(&fx, &fx.proj, fx.t(), State::Patched, "hosted");
    assert_unscoped_rollback_pristine(&fx, &fx.proj, "rollback");
    fx.leg.ran();
}

/// Hosted → vendored through `scan --mode vendored` and through `vendor`
/// (a staged manifest): the redirect record goes, the lock is vendored,
/// fresh checkouts are patched, and `vendor --revert` restores the
/// pristine lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_hosted_then_vendored() {
    let Some(leg) = migration_leg("hosted_then_vendored") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    for driver in ["scan", "vendor"] {
        let dir = copy_project(&fx, &fx.proj, &format!("drv-{driver}"));
        let out = if driver == "scan" {
            vendored_scan(&fx, &dir, &[])
        } else {
            stage_manifest(&dir, &[fx.t()]);
            vendor_cmd(&dir, &[])
        };
        assert_eq!(out.code, 0, "{driver}: {out}");
        assert!(
            has_code(&out.json(), "vendor_takeover_reverted_redirect"),
            "{driver}: {out}"
        );
        assert_pure_vendored(&dir, fx.t());
        assert_fresh(
            &fx,
            &dir,
            fx.t(),
            State::Patched,
            &format!("{driver}-vendored"),
        );
        let out = vendor_revert_all(&dir);
        assert_eq!(out.code, 0, "{driver}: {out}");
        assert_eq!(
            String::from_utf8_lossy(&lock_bytes(&dir)),
            String::from_utf8_lossy(&fx.lock_before),
            "{driver}: revert restores the pristine lock"
        );
    }
    fx.leg.ran();
}

fn vendor_revert_all(dir: &Path) -> SocketOut {
    vendor_cmd(dir, &["--revert"])
}

// ── 3. dry-run parity ─────────────────────────────────────────────────────

/// Over a live hosted redirect `vendor --dry-run` previews the takeover
/// and `scan --mode vendored --dry-run` says `would_vendor`; over a live
/// vendored state `scan --mode hosted --dry-run` previews
/// `redirect_would_revert_vendored`. No preview writes a byte, and the wet
/// runs then do what was previewed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_dry_run_parity() {
    let Some(leg) = migration_leg("dry_run_parity") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    stage_manifest(&fx.proj, &[fx.t()]);
    let before = project_bytes(&fx.proj);
    let out = vendor_cmd(&fx.proj, &["--dry-run"]);
    assert_eq!(out.code, 0, "{out}");
    assert!(
        has_code(&out.json(), "vendor_would_revert_redirect"),
        "{out}"
    );
    assert!(!out.stdout.contains("vendor_lock_entry_not_found"), "{out}");
    let out = vendored_scan(&fx, &fx.proj, &["--dry-run"]);
    assert_eq!(out.code, 0, "{out}");
    let doc = out.json();
    let preview = doc["vendor"]["patches"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["purl"] == fx.t().purl()))
        .cloned()
        .unwrap_or_else(|| panic!("a preview for {}: {doc:#}", fx.t().purl()));
    assert_eq!(preview["action"], "would_vendor", "{doc:#}");
    assert!(!out.stdout.contains("would_refuse"), "{out}");
    assert_eq!(
        project_bytes(&fx.proj),
        before,
        "the previews write nothing"
    );
    let out = vendor_cmd(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert!(
        has_code(&out.json(), "vendor_takeover_reverted_redirect"),
        "{out}"
    );
    assert_pure_vendored(&fx.proj, fx.t());
    let before = project_bytes(&fx.proj);
    let out = hosted_scan(&fx, &fx.proj, &["--dry-run"]);
    assert_eq!(out.code, 0, "{out}");
    let doc = out.json();
    assert!(has_code(&doc, "redirect_would_revert_vendored"), "{doc:#}");
    assert!(
        !has_code(&doc, "redirect_vendored_revert_failed"),
        "{doc:#}"
    );
    assert_eq!(
        project_bytes(&fx.proj),
        before,
        "the hosted preview writes nothing"
    );
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_pure_hosted(&fx, &fx.proj, fx.t());
    fx.leg.ran();
}

// ── 4–5. scoped and unscoped unwinds ──────────────────────────────────────

/// Two hosted records; `rollback <purl-a>` and, on a copy, `remove
/// <purl-a>` unwind only a; a fresh checkout lands a's registry bytes and
/// b's patch; the unscoped rollback then restores the pristine lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_scoped_unwind_one_of_two() {
    let Some(leg) = migration_leg("scoped_unwind_one_of_two") else {
        return;
    };
    let fx = two_target_fixture(leg).await;
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    let a = fx.svc.target(LP.0).clone();
    let b = fx.svc.target(MS.0).clone();
    assert_pinned(&fx.proj, &fx.svc, &a);
    assert_pinned(&fx.proj, &fx.svc, &b);
    let copy = copy_project(&fx, &fx.proj, "remove-copy");
    let out = rollback(&fx.proj, &[&a.purl()]);
    assert_eq!(out.code, 0, "{out}");
    let cwd = cwd_args(&copy);
    let purl = a.purl();
    let out = socket(
        &copy,
        &[
            "remove",
            &purl,
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            &cwd,
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{out}");
    for dir in [&fx.proj, &copy] {
        assert_not_pinned(dir, &a);
        assert_pinned(dir, &fx.svc, &b);
        let ledger =
            std::fs::read_to_string(dir.join(".socket/vendor/redirect-state.json")).unwrap();
        assert!(
            !ledger.contains(&a.purl()) && ledger.contains(&b.purl()),
            "{ledger}"
        );
        assert_fresh(&fx, dir, &a, State::Pristine, "a-unwound");
        assert_fresh(&fx, dir, &b, State::Patched, "b-kept");
    }
    assert_unscoped_rollback_pristine(&fx, &fx.proj, "after-scoped");
    fx.leg.ran();
}

/// A mixed state (left-pad vendored, ms hosted): the unscoped rollback
/// restores the pristine lock and leaves no artifacts or ledgers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_rollback_from_mixed() {
    let Some(leg) = migration_leg("rollback_from_mixed") else {
        return;
    };
    let fx = two_target_fixture(leg).await;
    let a = fx.svc.target(LP.0).clone();
    let b = fx.svc.target(MS.0).clone();
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["get", &a.uuid, "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "{out}");
    assert_pure_vendored(&fx.proj, &a);
    assert_pinned(&fx.proj, &fx.svc, &b);
    assert_fresh(&fx, &fx.proj, &a, State::Patched, "mixed-a");
    assert_fresh(&fx, &fx.proj, &b, State::Patched, "mixed-b");
    assert_unscoped_rollback_pristine(&fx, &fx.proj, "mixed");
    fx.leg.ran();
}

// ── 6–9. agent interplay (T21) ────────────────────────────────────────────

/// 6: agent `apply` over a vendored package yields: the committed payload
/// and the installed copy are left alone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_agent_apply_yields_to_vendored() {
    let Some(leg) = migration_leg("agent_apply_yields_to_vendored") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = vendored_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    stage_manifest(&fx.proj, &[fx.t()]);
    let before = project_bytes(&fx.proj);
    let out = agent(&fx.proj, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let after = project_bytes(&fx.proj);
    for (k, v) in &before {
        if k.starts_with(".socket/vendor/npm/") {
            assert_eq!(after.get(k), Some(v), "{k} untouched");
        }
    }
    fx.leg.ran();
}

/// 7: agent `apply` after a hosted install finds the store copy already
/// patched.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_agent_apply_after_hosted() {
    let Some(leg) = migration_leg("agent_apply_after_hosted") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let out = hosted_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = agent(&fx.proj, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    let text = out.stdout.to_lowercase();
    assert!(text.contains("already"), "already patched: {out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// 8: a hosted scan over an agent-patched warm tree keeps the tree (heal
/// rule (c) sees the afterHash pass): nothing is invalidated.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_hosted_scan_keeps_agent_patched_tree() {
    let Some(leg) = migration_leg("hosted_scan_keeps_agent_patched_tree") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = agent(&fx.proj, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let _ = std::fs::remove_file(fx.proj.join(HIDDEN_LOCK));
    let ids = fx.store_ids(fx.t());
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_nothing_stale());
    for id in &ids {
        assert!(store_entry(&fx.proj, id).exists(), "{id} kept");
    }
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// 9: agent rollback after a hosted and after a vendored takeover of an
/// agent-patched tree, and `remove` across agent + hosted + vendored
/// state: the pristine lock comes back and no state is left. After the
/// vendored takeover the rollback reports `reinstall_required`: a plain
/// `vlt install` keeps the agent-patched store copy (vlt trusts its hidden
/// lock) and the locked install restores the registry bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_agent_rollback_after_takeovers() {
    let Some(leg) = migration_leg("agent_rollback_after_takeovers") else {
        return;
    };
    let fx = two_target_fixture(leg).await;
    let a = fx.svc.target(LP.0).clone();
    let b = fx.svc.target(MS.0).clone();
    stage_manifest(&fx.proj, &[&a, &b]);
    let out = agent(&fx.proj, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, &a), State::Patched);
    for mode in ["hosted", "vendored"] {
        let dir = fx.leg.dir(&format!("agent-{mode}"));
        std::fs::remove_dir_all(&dir).unwrap();
        fresh_checkout(&fx.proj, &dir);
        fx.vlt_ok_profile(&dir, &fx.leg.locked_install_args(), mode);
        let out = agent(&dir, "apply", &[]);
        assert_eq!(out.code, 0, "{out}");
        let out = if mode == "hosted" {
            hosted_scan(&fx, &dir, &[])
        } else {
            vendored_scan(&fx, &dir, &[])
        };
        assert_eq!(out.code, 0, "{mode}: {out}");
        let out = rollback(&dir, &[]);
        assert_eq!(out.code, 0, "{mode} rollback: {out}");
        assert_eq!(
            String::from_utf8_lossy(&lock_bytes(&dir)),
            String::from_utf8_lossy(&fx.lock_before),
            "{mode}: the pristine lock"
        );
        if mode == "vendored" {
            assert!(has_code(&out.json(), "reinstall_required"), "{out}");
            fx.vlt_ok_profile(&dir, &["install"], mode);
            assert_eq!(
                state(&dir, &a),
                State::Patched,
                "vlt install keeps the agent-patched store copy the takeover left"
            );
        }
        fx.vlt_ok_profile(&dir, &fx.leg.locked_install_args(), mode);
        for t in [&a, &b] {
            assert_eq!(state(&dir, t), State::Pristine, "{mode}: {}", t.name);
        }
    }
    let dir = fx.leg.dir("remove-all");
    std::fs::remove_dir_all(&dir).unwrap();
    fresh_checkout(&fx.proj, &dir);
    fx.vlt_ok_profile(&dir, &fx.leg.locked_install_args(), "remove-all");
    let out = agent(&dir, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    let out = hosted_scan(&fx, &dir, &[]);
    assert_eq!(out.code, 0, "{out}");
    let out = socket_api(
        &dir,
        &fx.svc,
        &["get", &b.uuid, "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "{out}");
    for t in [&a, &b] {
        let cwd = cwd_args(&dir);
        let purl = t.purl();
        let out = socket(
            &dir,
            &[
                "remove",
                &purl,
                "--json",
                "--yes",
                "--offline",
                "--cwd",
                &cwd,
            ],
            &[],
        );
        assert_eq!(out.code, 0, "remove {}: {out}", t.name);
    }
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(&dir)),
        String::from_utf8_lossy(&fx.lock_before)
    );
    assert!(!dir.join(".socket/vendor/npm").exists());
    fx.leg.ran();
}

// ── PM switches (T37) ─────────────────────────────────────────────────────

/// npm hosted, then vlt joins (`vlt install` writes vlt-lock.json): the
/// rescan rewrites both locks, and vlt confirms only once vlt install
/// state exists (`vlt_drives`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_pm_switch_npm_to_vlt() {
    let Some(leg) = migration_leg("pm_switch_npm_to_vlt") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let dir = fx.leg.dir("npm");
    write(
        &dir.join("package.json"),
        package_json("vlt-e2e-app", &[LP]),
    );
    write(&dir.join(".npmrc"), format!("registry={}\n", fx.reg.url()));
    write_vlt_json(&dir, fx.leg.version(), &fx.reg.url(), &VltJson::default());
    let npm = npm_run(
        &dir,
        &["install", "--ignore-scripts", "--no-audit", "--no-fund"],
    );
    assert_ok(&npm, "npm install");
    let out = hosted_scan(&fx, &dir, &[]);
    assert_eq!(out.code, 0, "{out}");
    let plock = std::fs::read_to_string(dir.join("package-lock.json")).unwrap();
    assert!(plock.contains("/patch/npm/"), "{plock}");
    std::fs::remove_dir_all(dir.join("node_modules")).unwrap();
    fx.vlt_ok(&dir, &["install"]);
    assert!(dir.join(VLT_LOCK).exists());
    let out = hosted_scan(&fx, &dir, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_pinned(&dir, &fx.svc, fx.t());
    assert!(std::fs::read_to_string(dir.join("package-lock.json"))
        .unwrap()
        .contains("/patch/npm/"));
    assert!(
        !has_code(&out.json(), "redirect_vlt_sibling_lockfiles"),
        "vlt drives: {out}"
    );
    fx.leg.ran();
}

fn npm_run(dir: &Path, args: &[&str]) -> std::process::Output {
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let mut cmd = std::process::Command::new(npm);
    cmd.args(args).current_dir(dir);
    cache_env::scrub_ambient_vlt_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.output().expect("spawn npm")
}

/// vlt → npm (`vlt-lock.json` deleted): the rollback refuses the vlt edits
/// ("vlt-lock.json no longer exists") and keeps the ledger, writing no
/// lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_pm_switch_vlt_to_npm() {
    let Some(leg) = migration_leg("pm_switch_vlt_to_npm") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    std::fs::remove_file(fx.proj.join(VLT_LOCK)).unwrap();
    let ledger = std::fs::read(fx.proj.join(".socket/vendor/redirect-state.json")).unwrap();
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 1, "{out}");
    assert!(
        out.stdout.contains("vlt-lock.json no longer exists"),
        "{out}"
    );
    assert!(!fx.proj.join(VLT_LOCK).exists(), "nothing recreated");
    assert_eq!(
        std::fs::read(fx.proj.join(".socket/vendor/redirect-state.json")).unwrap(),
        ledger,
        "the ledger is kept"
    );
    fx.leg.ran();
}

/// A `flavor:"npm"` vendored entry, then a `vlt-lock.json` appears: the
/// re-vendor refuses with `vendor_flavor_changed`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_flavor_changed() {
    let Some(leg) = migration_leg("flavor_changed") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let dir = fx.leg.dir("npm-vendored");
    write(
        &dir.join("package.json"),
        package_json("vlt-e2e-app", &[LP]),
    );
    write(&dir.join(".npmrc"), format!("registry={}\n", fx.reg.url()));
    let npm = npm_run(
        &dir,
        &["install", "--ignore-scripts", "--no-audit", "--no-fund"],
    );
    assert_ok(&npm, "npm install");
    stage_manifest(&dir, &[fx.t()]);
    let out = vendor_cmd(&dir, &[]);
    assert_eq!(out.code, 0, "{out}");
    let ledger = std::fs::read_to_string(dir.join(".socket/vendor/state.json")).unwrap();
    assert!(ledger.contains("\"npm\""), "{ledger}");
    write_vlt_json(&dir, fx.leg.version(), &fx.reg.url(), &VltJson::default());
    std::fs::remove_dir_all(dir.join("node_modules")).unwrap();
    fx.vlt_ok(&dir, &["install"]);
    let out = vendor_cmd(&dir, &["--force"]);
    assert!(has_code(&out.json(), "vendor_flavor_changed"), "{out}");
    fx.leg.ran();
}

// ── vlt upgrade (T19) ─────────────────────────────────────────────────────

fn upgrade() -> Option<Toolchain> {
    match upgrade_toolchain() {
        Ok(Some(tc)) => Some(tc),
        Ok(None) => None,
        Err(e) => panic!("{e}"),
    }
}

/// rc.14 hosted, then the upgraded vlt refuses the v0 lock; the lock is
/// re-created, the rescan re-pins under the tilde DepID (superseding the
/// recorded legacy edit), rollback is clean and VEX attests after the
/// rescan.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_upgrade_hosted() {
    let Some(leg) = migration_leg("upgrade_hosted") else {
        return;
    };
    let Some(up) = upgrade() else {
        return leg.skip("no-upgrade-vlt");
    };
    if leg.era().lockfile_version() != Some(0) || up.version < LOCKFILE_VERSION_CHECKED_FROM {
        return leg.skip("no-grammar-upgrade");
    }
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    let upr = VltRun::profile("up").with_tc(&up);
    write_vlt_json(&fx.proj, up.version, &fx.reg.url(), &VltJson::default());
    let out = fx.leg.vlt_with(&fx.proj, &["ci"], &upr);
    assert!(
        !out.status.success(),
        "the upgraded vlt refuses v0: {}",
        out_text(&out)
    );
    std::fs::remove_file(fx.proj.join(VLT_LOCK)).unwrap();
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &upr);
    let lock = read_lock(&fx.proj);
    assert_eq!(lock["lockfileVersion"], 1, "{lock:#}");
    let relocked = lock_bytes(&fx.proj);
    remove_tree(&fx.proj);
    let doc = fx.scan(&["--vex", "out.vex.json", "--vex-product", PRODUCT]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    assert!(
        fx.vex_attested(fx.t()),
        "attested after the rescan: {doc:#}"
    );
    let ledger =
        std::fs::read_to_string(fx.proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        !ledger.contains('·'),
        "the legacy edit is superseded: {ledger}"
    );
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(
        lock_bytes(&fx.proj),
        relocked,
        "rollback to the re-created lock"
    );
    fx.leg.ran();
}

/// rc.14 vendored, the same upgrade: `vendor --revert` reports the
/// cross-grammar drift and writes nothing; following the remedy, the next
/// revert is identity-already-reverted and removes the artifact.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_migration_upgrade_vendored() {
    let Some(leg) = migration_leg("upgrade_vendored") else {
        return;
    };
    let Some(up) = upgrade() else {
        return leg.skip("no-upgrade-vlt");
    };
    if leg.era().lockfile_version() != Some(0) || up.version < LOCKFILE_VERSION_CHECKED_FROM {
        return leg.skip("no-grammar-upgrade");
    }
    let fx = Fixture::build(leg, Shape::left_pad().warm()).await;
    let pkg_before = std::fs::read_to_string(fx.proj.join("package.json")).unwrap();
    let out = vendored_scan(&fx, &fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    let upr = VltRun::profile("up").with_tc(&up);
    write_vlt_json(&fx.proj, up.version, &fx.reg.url(), &VltJson::default());
    std::fs::remove_file(fx.proj.join(VLT_LOCK)).unwrap();
    remove_tree(&fx.proj);
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &upr);
    let before = project_bytes(&fx.proj);
    let out = vendor_revert_all(&fx.proj);
    assert!(
        out.stdout
            .contains("re-created by a different vlt lockfile grammar"),
        "{out}"
    );
    assert_eq!(project_bytes(&fx.proj), before, "no writes");
    write(&fx.proj.join("package.json"), &pkg_before);
    fx.leg.vlt_ok_with(&fx.proj, &["install"], &upr);
    let out = vendor_revert_all(&fx.proj);
    assert_eq!(out.code, 0, "{out}");
    assert!(!fx.proj.join(".socket/vendor/npm").exists(), "{out}");
    fx.leg.ran();
}
