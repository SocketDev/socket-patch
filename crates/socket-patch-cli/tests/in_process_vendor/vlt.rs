//! vlt vendored legs (DESIGN §4, §8.2): `vendor` through the scrubbed
//! binary against the real-vlt captures (byte oracles for the wired lock
//! and package.json files), the synthetic shapes the captures lack, every
//! lock-, manifest- and ledger-decidable refusal, the patch-service fast
//! path, the committed-dir auto-fetch, and the revert inverses.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::vlt_vendor::*;

// ── the real-vlt captures ────────────────────────────────────────────────

/// Vendor one capture case: a refusal case must fail with its code and
/// leave the project untouched; a wired case must write exactly the lock
/// and package.json files real vlt kept stable through `vlt ci`, re-run
/// in sync, and revert byte-exact.
fn run_capture_case(vlt: &str, name: &str) {
    let case = cases(vlt)
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no capture case {vlt}/{name}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    capture_project(root, &case);
    let tracked = ["vlt-lock.json", "package.json", "packages/a/package.json"];
    let before: Vec<Option<Vec<u8>>> = tracked
        .iter()
        .map(|f| std::fs::read(root.join(f)).ok())
        .collect();
    let what = format!("{vlt}/{name}");

    let (code, env, stderr) = vendor(root, &[]);
    if let Some(refusal) = &case.refusal {
        assert_eq!(code, 1, "[{what}] {env:#}\n{stderr}");
        assert_eq!(failure(&env, &case.purl).0, *refusal, "[{what}] {env:#}");
        for (f, b) in tracked.iter().zip(&before) {
            assert_eq!(
                &std::fs::read(root.join(f)).ok(),
                b,
                "[{what}] {f} untouched"
            );
        }
        assert!(
            !root.join(".socket/vendor/npm").exists(),
            "[{what}] nothing staged"
        );
        return;
    }
    assert_eq!(code, 0, "[{what}] {env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "[{what}] {env:#}");
    let (pkg_name, pkg_version) = case.coords();
    let rel = rel_dir(FIXTURE_UUID, &pkg_name, &pkg_version);
    let churn = std::fs::read_to_string(case.dir().join("case.json"))
        .unwrap()
        .contains("\"ciChurn\": [\n    [");
    if !churn {
        for f in tracked {
            let expected = case.dir().join("expected").join(f);
            if let Ok(want) = std::fs::read(&expected) {
                assert_eq!(
                    String::from_utf8_lossy(&std::fs::read(root.join(f)).unwrap()),
                    String::from_utf8_lossy(&want),
                    "[{what}] {f} must be the bytes real vlt keeps stable"
                );
            }
        }
    }
    let entry = ledger_entry(root, &case.purl);
    assert_eq!(entry["flavor"], "vlt", "[{what}] {entry:#}");
    assert_eq!(entry["artifact"]["path"], rel, "[{what}] {entry:#}");
    assert!(
        entry["artifact"]["fileInventory"]["index.js"].is_string(),
        "[{what}] {entry:#}"
    );
    assert_eq!(read(root, &format!("{rel}/index.js")).as_bytes(), PATCHED);
    let uuid = uuid_dir(root, FIXTURE_UUID);
    assert_eq!(
        read(
            root,
            &format!(".socket/vendor/npm/{FIXTURE_UUID}/.gitignore")
        ),
        UUID_GITIGNORE
    );
    assert_eq!(
        std::fs::read_to_string(uuid.join(".gitattributes")).unwrap(),
        UUID_GITATTRIBUTES
    );
    let wired: Vec<Option<Vec<u8>>> = tracked
        .iter()
        .map(|f| std::fs::read(root.join(f)).ok())
        .collect();

    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "[{what}] rerun: {env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"already_vendored".to_string()),
        "[{what}] {env:#}"
    );
    for (f, w) in tracked.iter().zip(&wired) {
        assert_eq!(
            &std::fs::read(root.join(f)).ok(),
            w,
            "[{what}] rerun kept {f}"
        );
    }

    let cwd = root.to_str().unwrap();
    let (code, env, stderr) = socket(root, &["vendor", "--revert", "--json", "--cwd", cwd], &[]);
    assert_eq!(code, 0, "[{what}] revert: {env:#}\n{stderr}");
    for (f, b) in tracked.iter().zip(&before) {
        assert_eq!(
            std::fs::read(root.join(f))
                .ok()
                .map(|b| String::from_utf8_lossy(&b).to_string()),
            b.as_ref().map(|b| String::from_utf8_lossy(b).to_string()),
            "[{what}] revert restores {f} byte for byte"
        );
    }
    assert!(!uuid.exists(), "[{what}] revert removes the artifact");
}

#[test]
fn vendor_vlt_every_capture_case() {
    for vlt in CAPTURED {
        for case in cases(vlt) {
            run_capture_case(vlt, &case.name);
            eprintln!("vendor vlt capture {vlt}/{}: OK", case.name);
        }
    }
}

#[test]
fn vendor_vlt_direct_v1() {
    run_capture_case("1.2.0", "left-pad");
}

#[test]
fn vendor_vlt_direct_v0() {
    run_capture_case("1.0.0-rc.14", "left-pad");
}

#[test]
fn vendor_vlt_workspace_member() {
    run_capture_case("1.2.0", "member-only");
}

#[test]
fn vendor_vlt_alias_edge() {
    run_capture_case("1.2.0", "alias");
}

#[test]
fn vendor_vlt_scoped() {
    run_capture_case("1.2.0", "scoped");
}

#[test]
fn vendor_vlt_dev_edge() {
    run_capture_case("1.2.0", "dev-edge");
}

#[test]
fn vendor_vlt_optional_edge() {
    run_capture_case("1.2.0", "optional-edge");
}

#[test]
fn vendor_vlt_with_deps_rekeys_edges() {
    run_capture_case("1.2.0", "supports-color");
    run_capture_case("1.0.10", "semver");
}

#[test]
fn vendor_vlt_refuses_transitive() {
    run_capture_case("1.2.0", "transitive");
}

/// A node whose only extra is one peer context (the root from vlt 1.0.8, a
/// workspace member from rc.15) is vendored without the extra, exactly as
/// real vlt keeps it through `vlt ci`, and reverts to the extra-bearing
/// DepID.
#[test]
fn vendor_vlt_single_peer_context_drops_extra() {
    for (vlt, case) in [
        ("1.2.0", "peer"),
        ("1.2.0", "peer-member"),
        ("1.0.10", "alias-selfref-peer"),
        ("1.0.4", "peer-member"),
        ("1.0.0-rc.32", "peer-member"),
    ] {
        let lock = std::fs::read_to_string(
            fixtures()
                .join(vlt)
                .join("projects")
                .join(
                    &cases(vlt)
                        .into_iter()
                        .find(|c| c.name == case)
                        .unwrap()
                        .project,
                )
                .join(VLT_LOCK),
        )
        .unwrap();
        assert!(
            lock.contains("use-sync-external-store@1.2.0~peer."),
            "{vlt}/{case}: the capture carries a peer extra"
        );
        run_capture_case(vlt, case);
    }
}

/// Several instances of one name@version, or a modifier extra, stay
/// refused before any write.
#[test]
fn vendor_vlt_refuses_peer_and_modifier_variants() {
    let two = Lock::v1(
        &[
            &reg_node("~npm~left-pad@1.3.0~peer.1"),
            &reg_node("~npm~left-pad@1.3.0~peer.2"),
        ],
        &[
            "\"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0~peer.1\"",
            "\"workspace~packages+a left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0~peer.2\"",
        ],
    );
    let detail = refused_with(&two.render(), ROOT_PKG, "vendor_lock_entry_unsupported");
    assert!(
        detail.contains("2 instances") && detail.contains("peer/modifier variants"),
        "{detail}"
    );
    let modifier = "~npm~left-pad@1.3.0~_croot_s_g_s#left-pad";
    let lock = Lock::v1(
        &[&reg_node(modifier)],
        &[&format!("\"file~_d left-pad\": \"prod 1.3.0 {modifier}\"")],
    );
    let detail = refused_with(&lock.render(), ROOT_PKG, "vendor_lock_entry_unsupported");
    assert!(
        detail.contains(&format!("a modifier variant instance ({modifier})")),
        "{detail}"
    );
}

/// `vendor_vlt_reinstall_required`: a rewired optional dependency always
/// gets the `vlt ci` advisory; an in-sync rerun gets it again only while
/// node_modules still links the installed upstream copy.
#[test]
fn vendor_vlt_optional_edge_asks_for_vlt_ci() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lock = Lock::v1(
        &[&reg_node("~npm~left-pad@1.3.0")],
        &["\"file~_d left-pad\": \"optional 1.3.0 ~npm~left-pad@1.3.0\""],
    );
    let pkg = ROOT_PKG.replace("\"dependencies\"", "\"optionalDependencies\"");
    project(root, &lock, &pkg, "~npm~left-pad@1.3.0");
    let store = store_dir(root, "~npm~left-pad@1.3.0", NAME);
    link_dir(&store, &root.join("node_modules").join(NAME));
    let advisory = |env: &Value| -> Vec<String> {
        events(env)
            .iter()
            .filter(|e| e["errorCode"] == "vendor_vlt_reinstall_required")
            .map(|e| e.to_string())
            .collect()
    };
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let got = advisory(&env);
    assert_eq!(got.len(), 1, "{env:#}");
    assert!(
        got[0].contains("left-pad@1.3.0 is an optional dependency")
            && got[0].contains("run `vlt ci` (or delete node_modules and run `vlt install`)")
            && got[0].contains("before 1.0.5"),
        "{}",
        got[0]
    );
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        codes(&env).contains(&"already_vendored".to_string()),
        "{env:#}"
    );
    assert_eq!(
        advisory(&env).len(),
        1,
        "the upstream copy is still linked: {env:#}"
    );
    unlink_dir(&root.join("node_modules").join(NAME));
    link_dir(
        &root.join(rel_dir(UUID, NAME, VERSION)),
        &root.join("node_modules").join(NAME),
    );
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        advisory(&env).is_empty(),
        "linked to the vendored copy: {env:#}"
    );
}

/// A prod dependency whose link still resolves into vlt's store gets the
/// reinstall advisory; one without a stale link gets none.
#[test]
fn vendor_vlt_stale_prod_link_asks_for_a_reinstall() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    let (code, env, _) = vendor(tmp.path(), &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        !codes(&env).contains(&"vendor_vlt_reinstall_required".to_string()),
        "{env:#}"
    );

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let store = store_dir(root, "~npm~left-pad@1.3.0", NAME);
    link_dir(&store, &root.join("node_modules").join(NAME));
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let detail = events(&env)
        .into_iter()
        .find(|e| e["errorCode"] == "vendor_vlt_reinstall_required")
        .unwrap_or_else(|| panic!("{env:#}"))
        .to_string();
    assert!(
        detail.contains(
            "node_modules/left-pad still links left-pad@1.3.0 to its installed upstream copy; \
             run `vlt install` (or `vlt ci`) to link the vendored copy"
        ),
        "{detail}"
    );
}

// ── synthetic shapes ─────────────────────────────────────────────────────

fn revert(root: &Path) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    socket(root, &["vendor", "--revert", "--json", "--cwd", &cwd], &[])
}

/// Vendor `root`, then revert it and require the original lock and
/// package.json back byte for byte. Returns the wired lock.
fn vendor_and_revert(root: &Path) -> String {
    let lock = read(root, VLT_LOCK);
    let pkg = read(root, "package.json");
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    let wired = read(root, VLT_LOCK);
    let (code, env, stderr) = revert(root);
    assert_eq!(code, 0, "revert: {env:#}\n{stderr}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert_eq!(read(root, "package.json"), pkg);
    assert!(!uuid_dir(root, UUID).exists());
    wired
}

fn file_spec() -> String {
    format!("file:./{}", rel_dir(UUID, NAME, VERSION))
}

#[test]
fn vendor_vlt_barespec_with_spaces() {
    let tmp = tempfile::tempdir().unwrap();
    let lock = Lock::v1(
        &[&reg_node("~npm~left-pad@1.3.0")],
        &["\"file~_d left-pad\": \"prod >=1 <2 ~npm~left-pad@1.3.0\""],
    );
    project(
        tmp.path(),
        &lock,
        &ROOT_PKG.replace("\"1.3.0\"", "\">=1 <2\""),
        "~npm~left-pad@1.3.0",
    );
    let wired = vendor_and_revert(tmp.path());
    let rel = rel_dir(UUID, NAME, VERSION);
    assert!(
        wired.contains(&format!(
            "\"file~_d left-pad\": \"prod {} {}\"",
            file_spec(),
            file_id_v1(&rel)
        )),
        "{wired}"
    );
}

#[test]
fn vendor_vlt_crlf_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let mut lock = direct_lock();
    lock.crlf = true;
    project(tmp.path(), &lock, ROOT_PKG, "~npm~left-pad@1.3.0");
    let wired = vendor_and_revert(tmp.path());
    assert!(
        wired
            .split('\n')
            .filter(|l| !l.is_empty())
            .all(|l| l.ends_with('\r')),
        "every line keeps its CR: {wired:?}"
    );
    assert!(wired.contains(&file_spec()), "{wired}");
}

#[test]
fn vendor_vlt_peer_range_left_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = "{\n  \"name\": \"lib\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  },\n  \"peerDependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n";
    project(tmp.path(), &direct_lock(), pkg, "~npm~left-pad@1.3.0");
    let (code, env, stderr) = vendor(tmp.path(), &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let after = read(tmp.path(), "package.json");
    assert_eq!(
        after,
        pkg.replace(
            "\"left-pad\": \"1.3.0\"",
            &format!("\"left-pad\": \"{}\"", file_spec())
        ),
        "only the dependencies spec moves"
    );
}

#[test]
fn vendor_vlt_legacy_lockfile_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let lock = Lock::v0(
        &[&reg_node("··left-pad@1.3.0")],
        &["\"file·. left-pad\": \"prod 1.3.0 ··left-pad@1.3.0\""],
    );
    project(tmp.path(), &lock, ROOT_PKG, "··left-pad@1.3.0");
    let (code, env, stderr) = vendor(tmp.path(), &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_vlt_legacy_lockfile".to_string()),
        "{env:#}"
    );
    let wired = read(tmp.path(), VLT_LOCK);
    assert!(
        wired.contains(&format!(
            "\"file·.socket§vendor§npm§{UUID}§left-pad-1.3.0§node_modules§left-pad\""
        )),
        "the legacy grammar is kept: {wired}"
    );
}

#[test]
fn vendor_vlt_package_json_patch_with_devdeps_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let before_pkg = "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\",\n  \"devDependencies\": {\n    \"tap\": \"^16\"\n  }\n}\n";
    let after_pkg = "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\",\n  \"main\": \"index.js\",\n  \"devDependencies\": {\n    \"tap\": \"^16\"\n  }\n}\n";
    project(root, &direct_lock(), ROOT_PKG, "~npm~left-pad@1.3.0");
    install_store(
        root,
        "~npm~left-pad@1.3.0",
        NAME,
        VERSION,
        PRISTINE,
        Some(before_pkg),
    );
    stage_patch(
        root,
        &[PURL],
        UUID,
        &[(
            "package/package.json",
            before_pkg.as_bytes(),
            after_pkg.as_bytes(),
        )],
    );
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_dep_manifest_stale".to_string()),
        "{env:#}"
    );
    let rel = rel_dir(UUID, NAME, VERSION);
    let committed = read(root, &format!("{rel}/package.json"));
    assert_eq!(
        committed,
        "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\",\n  \"main\": \"index.js\"\n}\n",
        "the committed manifest drops devDependencies"
    );

    // Every verifier applies the vlt manifest exemption: repair sees a
    // healthy artifact (no Corrupt → rebuild loop), and so does a re-run.
    let cwd = root.to_str().unwrap();
    let (code, env, stderr) = socket(root, &["repair", "--json", "--offline", "--cwd", cwd], &[]);
    assert_eq!(code, 0, "repair: {env:#}\n{stderr}");
    assert!(
        !env.to_string().contains("vendor_artifact_corrupt"),
        "repair must not judge the stripped manifest corrupt: {env:#}"
    );
    assert_eq!(read(root, &format!("{rel}/package.json")), committed);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        codes(&env).contains(&"already_vendored".to_string()),
        "{env:#}"
    );

    // A tampered committed manifest is caught.
    std::fs::write(root.join(&rel).join("package.json"), after_pkg).unwrap();
    let (code, env, _) = socket(
        root,
        &["repair", "--json", "--offline", "--dry-run", "--cwd", cwd],
        &[],
    );
    assert_eq!(code, 0, "{env:#}");
    assert!(env.to_string().contains("wouldRebuild"), "{env:#}");
}

// ── refusals ─────────────────────────────────────────────────────────────

/// Vendor must refuse `root` with `code` and write nothing.
fn assert_refused(root: &Path, code: &str) -> String {
    let before = snapshot(root);
    let (exit, env, stderr) = vendor(root, &[]);
    assert_eq!(exit, 1, "{env:#}\n{stderr}");
    let (got, detail) = failure(&env, PURL);
    assert_eq!(got, code, "{detail}\n{env:#}");
    assert_eq!(snapshot(root), before, "a refusal writes nothing");
    detail
}

fn refused_with(lock: &str, pkg: &str, code: &str) -> String {
    let tmp = tempfile::tempdir().unwrap();
    project(tmp.path(), &direct_lock(), pkg, "~npm~left-pad@1.3.0");
    std::fs::write(tmp.path().join(VLT_LOCK), lock).unwrap();
    assert_refused(tmp.path(), code)
}

#[test]
fn vendor_vlt_refuses_importer_peer_edge() {
    let lock = direct_lock()
        .render()
        .replace("\"prod 1.3.0", "\"peer 1.3.0");
    let pkg = "{\"peerDependencies\":{\"left-pad\":\"1.3.0\"}}";
    let detail = refused_with(&lock, pkg, "vendor_lock_entry_unsupported");
    assert!(detail.contains("peer"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_foreign_registry() {
    let mut lock = Lock::v1(
        &[&reg_node("~acme~left-pad@1.3.0")],
        &["\"file~_d left-pad\": \"prod acme:left-pad@1.3.0 ~acme~left-pad@1.3.0\""],
    );
    lock.options = "{\"registries\": {\"acme\": \"https://npm.acme.example/\"}}".into();
    let tmp = tempfile::tempdir().unwrap();
    project(
        tmp.path(),
        &lock,
        &ROOT_PKG.replace("\"1.3.0\"", "\"acme:left-pad@1.3.0\""),
        "~acme~left-pad@1.3.0",
    );
    let detail = assert_refused(tmp.path(), "vendor_lock_entry_unsupported");
    assert!(detail.contains("default registry"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_multi_field_declaration() {
    let pkg =
        "{\"dependencies\":{\"left-pad\":\"1.3.0\"},\"devDependencies\":{\"left-pad\":\"1.3.0\"}}";
    let detail = refused_with(
        &direct_lock().render(),
        pkg,
        "vendor_lock_entry_unsupported",
    );
    assert!(detail.contains("multiple dependency fields"), "{detail}");
}

#[test]
fn vendor_vlt_out_of_sync() {
    refused_with(
        &direct_lock().render(),
        &ROOT_PKG.replace("\"1.3.0\"", "\"^1.3.0\""),
        "vendor_vlt_lock_out_of_sync",
    );
}

#[test]
fn vendor_vlt_refuses_absent_version() {
    let mut lock = direct_lock();
    lock.version = None;
    let detail = refused_with(
        &lock.render(),
        ROOT_PKG,
        "vendor_lockfile_version_unsupported",
    );
    assert!(detail.contains("no lockfileVersion"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_v2() {
    let mut lock = direct_lock();
    lock.version = Some(2);
    let detail = refused_with(
        &lock.render(),
        ROOT_PKG,
        "vendor_lockfile_version_unsupported",
    );
    assert!(detail.contains("lockfileVersion 2"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_bom() {
    let lock = format!("\u{feff}{}", direct_lock().render());
    refused_with(&lock, ROOT_PKG, "vendor_lockfile_version_unsupported");
}

#[test]
fn vendor_vlt_refuses_unparseable() {
    refused_with(
        "{ \"lockfileVersion\": 1,",
        ROOT_PKG,
        "vendor_lockfile_version_unsupported",
    );
}

#[test]
fn vendor_vlt_refuses_non_canonical() {
    let pretty = serde_json::to_string_pretty(
        &serde_json::from_str::<Value>(&direct_lock().render()).unwrap(),
    )
    .unwrap();
    let detail = refused_with(&pretty, ROOT_PKG, "vendor_lockfile_version_unsupported");
    assert!(detail.contains("canonical layout"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_duplicate_devdependencies() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    install_store(
        tmp.path(),
        "~npm~left-pad@1.3.0",
        NAME,
        VERSION,
        PRISTINE,
        Some("{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"devDependencies\":{},\"devDependencies\":{}}"),
    );
    let detail = assert_refused(tmp.path(), "vendor_lock_entry_unsupported");
    assert!(detail.contains("duplicate devDependencies"), "{detail}");
}

#[test]
fn vendor_vlt_refuses_bundled_deps() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    install_store(
        tmp.path(),
        "~npm~left-pad@1.3.0",
        NAME,
        VERSION,
        PRISTINE,
        Some("{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"bundleDependencies\":[\"x\"]}"),
    );
    assert_refused(tmp.path(), "vendor_bundled_deps_unsupported");
}

#[test]
fn vendor_vlt_refuses_flavor_changed() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    let state = json!({
        "version": 1,
        "entries": { PURL: {
            "ecosystem": "npm",
            "basePurl": PURL,
            "uuid": UUID,
            "artifact": { "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz") },
            "wiring": [],
            "flavor": "pnpm",
        }}
    });
    std::fs::create_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::write(
        tmp.path().join(".socket/vendor/state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    let detail = assert_refused(tmp.path(), "vendor_flavor_changed");
    assert!(
        detail.contains("`pnpm`") && detail.contains("`vlt`"),
        "{detail}"
    );
}

#[test]
fn vendor_vlt_refuses_gitignored_payload() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    if !git_init(tmp.path()) {
        eprintln!("git not available; skipping");
        return;
    }
    std::fs::write(tmp.path().join(".gitignore"), ".socket/\n").unwrap();
    let detail = assert_refused(tmp.path(), "vendor_artifact_gitignored");
    assert!(detail.contains(".gitignore:1:.socket/"), "{detail}");
    let cwd = tmp.path().to_str().unwrap();
    let (code, env, _) = socket(
        tmp.path(),
        &["vendor", "--json", "--offline", "--dry-run", "--cwd", cwd],
        &[],
    );
    assert_eq!(code, 1, "the dry run previews the refusal: {env:#}");
    assert_eq!(failure(&env, PURL).0, "vendor_artifact_gitignored");
}

#[test]
fn vendor_vlt_payload_tracked_under_hostile_root_gitignore() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let store = store_dir(root, "~npm~left-pad@1.3.0", NAME);
    std::fs::create_dir_all(store.join("dist")).unwrap();
    std::fs::write(store.join("dist/index.js"), "x\n").unwrap();
    std::fs::write(store.join("dist/index.js.map"), "{}\n").unwrap();
    if !git_init(root) {
        eprintln!("git not available; skipping");
        return;
    }
    std::fs::write(root.join(".gitignore"), "node_modules\ndist/\n*.map\n").unwrap();
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let rel = rel_dir(UUID, NAME, VERSION);
    assert!(root.join(&rel).join("dist/index.js.map").is_file());
    let out = std::process::Command::new(git().unwrap())
        .args(["check-ignore", "--no-index", "--stdin"])
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().unwrap();
            for f in [
                "index.js",
                "package.json",
                "dist/index.js",
                "dist/index.js.map",
            ] {
                writeln!(stdin, "{rel}/{f}")?;
            }
            drop(stdin);
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "git commits every payload file"
    );
}

// ── committed dir artifact, reuse, re-vendor ─────────────────────────────

#[test]
fn vendor_vlt_reuse_is_churn_free() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    let lock = read(root, VLT_LOCK);
    let artifact = snapshot(&uuid_dir(root, UUID));
    let state = read(root, ".socket/vendor/state.json");
    std::fs::remove_file(uuid_dir(root, UUID).join(".gitignore")).unwrap();
    for run in 0..2 {
        let (code, env, _) = vendor(root, &[]);
        assert_eq!(code, 0, "[{run}] {env:#}");
        assert_eq!(env["summary"]["applied"], 0, "[{run}] {env:#}");
        assert!(
            codes(&env).contains(&"already_vendored".to_string()),
            "[{run}] {env:#}"
        );
        assert_eq!(read(root, VLT_LOCK), lock);
        assert_eq!(
            snapshot(&uuid_dir(root, UUID)),
            artifact,
            "[{run}] the gitignore is restored"
        );
        assert_eq!(read(root, ".socket/vendor/state.json"), state);
    }
}

#[test]
fn vendor_vlt_auto_fetch_stages_the_committed_dir_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    let lock = read(root, VLT_LOCK);
    // A fresh clone: nothing installed, the committed dir artifact only.
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"already_vendored".to_string()),
        "{env:#}"
    );
    assert!(
        !codes(&env).contains(&"package_not_installed".to_string()),
        "{env:#}"
    );
    assert_eq!(read(root, VLT_LOCK), lock);

    // vlt links the vendored dir itself into node_modules; that link is
    // never taken as a pristine source (the committed rung verifies it).
    let rel = rel_dir(UUID, NAME, VERSION);
    let link = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(root.join("node_modules")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join(&rel), &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(root.join(&rel), &link).unwrap();
    std::fs::write(root.join(&rel).join("extra.js"), "tampered\n").unwrap();
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 1, "{env:#}");
    let (got, detail) = failure(&env, PURL);
    assert_eq!(got, "vendor_fetch_failed", "{env:#}");
    assert!(detail.contains("socket-patch repair"), "{detail}");
    assert_eq!(read(root, VLT_LOCK), lock);
}

#[test]
fn vendor_vlt_revendor_new_uuid() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let pkg = read(root, "package.json");
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    stage_patch(root, &[PURL], UUID2, &[]);
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        !uuid_dir(root, UUID).exists(),
        "the old uuid dir is removed"
    );
    let rel2 = rel_dir(UUID2, NAME, VERSION);
    assert!(root.join(&rel2).join("index.js").is_file());
    let wired = read(root, VLT_LOCK);
    assert!(
        wired.contains(&file_id_v1(&rel2)) && !wired.contains(UUID),
        "{wired}"
    );
    assert_eq!(
        read(root, "package.json"),
        pkg.replace("\"1.3.0\"", &format!("\"file:./{rel2}\""))
    );
    let entry = ledger_entry(root, PURL);
    assert_eq!(entry["uuid"], UUID2, "{entry:#}");
    let node = entry["wiring"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "vlt_lock_node")
        .unwrap()
        .clone();
    assert_eq!(node["key"], "~npm~left-pad@1.3.0", "{node:#}");
    let (code, env, _) = revert(root);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert_eq!(read(root, "package.json"), pkg);
}

/// vlt's post-install layout: `node_modules/<name>` links the committed
/// dir of `uuid`, and the store copy is gone.
fn link_dir(target: &Path, link: &Path) {
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link).unwrap();
}

fn unlink_dir(link: &Path) {
    std::fs::remove_file(link)
        .or_else(|_| std::fs::remove_dir(link))
        .unwrap();
}

fn link_vendored_dir(root: &Path, uuid: &str) {
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();
    std::fs::create_dir_all(root.join("node_modules")).unwrap();
    let target = Path::new("..").join(rel_dir(uuid, NAME, VERSION));
    let link = root.join("node_modules").join(NAME);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(root.join(rel_dir(uuid, NAME, VERSION)), &link).unwrap();
}

#[test]
fn vendor_vlt_linked_install_without_a_ledger_entry_points_at_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    link_vendored_dir(root, UUID);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        codes(&env).contains(&"already_vendored".to_string()),
        "{env:#}"
    );
    let lock = read(root, VLT_LOCK);
    std::fs::remove_file(root.join(".socket/vendor/state.json")).unwrap();
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 1, "{env:#}");
    let (got, detail) = failure(&env, PURL);
    assert_eq!(got, "vendor_ledger_entry_missing", "{env:#}");
    assert_eq!(
        detail,
        format!(
            "installed from the vendored artifact .socket/vendor/npm/{UUID}/, but the vendor \
             ledger has no entry for it; run `socket-patch repair` to restore the entry"
        )
    );
    assert!(
        !codes(&env).contains(&"package_not_installed".to_string()),
        "{env:#}"
    );
    assert_eq!(read(root, VLT_LOCK), lock);

    let cwd = root.to_str().unwrap().to_string();
    let (code, env, _) = socket(root, &["repair", "--json", "--offline", "--cwd", &cwd], &[]);
    assert_eq!(code, 0, "{env:#}");
    let entry = ledger_entry(root, PURL);
    assert_eq!(entry["flavor"], "vlt", "{env:#}");
    assert_eq!(entry["uuid"], UUID, "{env:#}");
    // The reconstructed entry has no inventory: the rerun says so instead
    // of claiming nothing is installed.
    assert!(entry["artifact"]["fileInventory"].is_null(), "{entry:#}");
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 1, "{env:#}");
    let skip = events(&env)
        .into_iter()
        .find(|e| e["errorCode"] == "package_not_installed")
        .unwrap_or_else(|| panic!("{env:#}"));
    assert_eq!(
        skip["reason"],
        format!(
            "the only installed copy is the vendored artifact .socket/vendor/npm/{UUID}/, which \
             is not a pristine source, and its ledger entry records no file inventory to stage \
             the committed artifact against"
        )
    );
    assert_eq!(read(root, VLT_LOCK), lock);
}

const EXTRA: (&str, &[u8], &[u8]) = ("package/extra.js", b"orig\n", b"v1-only\n");

/// A project vendored at [`UUID`] by a patch that also changes
/// `extra.js`, then linked the way `vlt install` links it, with a
/// superseding [`UUID2`] patch that leaves `extra.js` alone.
fn superseded_linked_project(root: &Path, lock: &Lock) {
    project(root, lock, ROOT_PKG, "~npm~left-pad@1.3.0");
    std::fs::write(
        store_dir(root, "~npm~left-pad@1.3.0", NAME).join("extra.js"),
        EXTRA.1,
    )
    .unwrap();
    stage_patch(root, &[PURL], UUID, &[EXTRA]);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(
        read(root, &format!("{}/extra.js", rel_dir(UUID, NAME, VERSION))).as_bytes(),
        EXTRA.2
    );
    link_vendored_dir(root, UUID);
    stage_patch(root, &[PURL], UUID2, &[]);
}

#[test]
fn vendor_vlt_revendor_new_uuid_never_builds_from_the_old_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    superseded_linked_project(root, &direct_lock());
    let lock = read(root, VLT_LOCK);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 1, "{env:#}");
    let skip = events(&env)
        .into_iter()
        .find(|e| e["errorCode"] == "package_not_installed")
        .unwrap_or_else(|| panic!("{env:#}"));
    assert_eq!(
        skip["reason"],
        format!(
            "the only installed copy is the vendored artifact .socket/vendor/npm/{UUID}/ of \
             patch {UUID}, which is not a pristine source for this patch; --offline prevents \
             fetching the pristine artifact from the registry"
        ),
        "{env:#}"
    );
    assert!(!uuid_dir(root, UUID2).exists(), "{env:#}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert_eq!(ledger_entry(root, PURL)["uuid"], UUID);
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_revendor_new_uuid_fetches_the_pristine_package() {
    let server = MockServer::start().await;
    let pristine = tarball(
        &[
            (
                "package/package.json",
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}\n",
            ),
            ("package/index.js", PRISTINE),
            ("package/extra.js", EXTRA.1),
        ],
        &[],
    );
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(pristine.clone()))
        .mount(&server)
        .await;
    let url = format!("{}/left-pad/-/left-pad-1.3.0.tgz", server.uri());
    let lock = Lock::v1(
        &[&format!(
            "\"~npm~left-pad@1.3.0\": [0,\"{NAME}\",\"{}\",\"{url}\"]",
            sri(&pristine)
        )],
        &["\"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0\""],
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    superseded_linked_project(root, &lock);
    let cwd = root.to_str().unwrap().to_string();
    let (code, env, stderr) = socket(
        root,
        &[
            "vendor",
            "--json",
            "--vendor-source",
            "build",
            "--cwd",
            &cwd,
        ],
        &[],
    );
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_fetched_missing".to_string()),
        "{env:#}"
    );
    let rel2 = rel_dir(UUID2, NAME, VERSION);
    assert_eq!(read(root, &format!("{rel2}/index.js")).as_bytes(), PATCHED);
    assert_eq!(
        read(root, &format!("{rel2}/extra.js")).as_bytes(),
        EXTRA.1,
        "the old patch's extra.js never reaches the new artifact"
    );
    assert!(!uuid_dir(root, UUID).exists());
    assert_eq!(ledger_entry(root, PURL)["uuid"], UUID2);
}

// ── revert inverses ──────────────────────────────────────────────────────

#[test]
fn vendor_vlt_revert_byte_exact() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    vendor_and_revert(tmp.path());
    let tmp = tempfile::tempdir().unwrap();
    project(
        tmp.path(),
        &direct_lock_v0(),
        ROOT_PKG,
        "·npm·left-pad@1.3.0",
    );
    vendor_and_revert(tmp.path());
}

#[test]
fn vendor_vlt_revert_after_outgoing_peer_value_rewrite() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lock = Lock::v1(
        &[
            &reg_node("~npm~left-pad@1.3.0"),
            "\"~npm~react@18.2.0\": [0,\"react\",\"sha512-R==\"]",
        ],
        &[
            "\"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0\"",
            "\"file~_d react\": \"prod 18.2.0 ~npm~react@18.2.0\"",
            "\"~npm~left-pad@1.3.0 react\": \"peer ^16 || ^18 ~npm~react@18.2.0\"",
        ],
    );
    let pkg = "{\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\",\n    \"react\": \"18.2.0\"\n  }\n}\n";
    project(root, &lock, pkg, "~npm~left-pad@1.3.0");
    let original = read(root, VLT_LOCK);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    let wired = read(root, VLT_LOCK);
    let file_id = file_id_v1(&rel_dir(UUID, NAME, VERSION));
    assert!(
        wired.contains(&format!("\"{file_id} react\": \"peer ^16 || ^18")),
        "{wired}"
    );
    // vlt rc.14 rewrites a `file:` dependency's peer spec on `ci`.
    std::fs::write(
        root.join(VLT_LOCK),
        wired.replace("\"peer ^16 || ^18 ~npm~react", "\"peer 18.2.0 ~npm~react"),
    )
    .unwrap();
    let (code, env, stderr) = revert(root);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(
        read(root, VLT_LOCK),
        original.replace("\"peer ^16 || ^18 ~npm~react", "\"peer 18.2.0 ~npm~react"),
        "the re-key restores the key and keeps vlt's current value"
    );
    assert_eq!(read(root, "package.json"), pkg);
}

#[test]
fn vendor_vlt_revert_identity_already_reverted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let pkg = read(root, "package.json");
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    // The user put the registry dependency back and re-locked by hand.
    let relocked = lock.clone();
    std::fs::write(root.join(VLT_LOCK), &relocked).unwrap();
    std::fs::write(root.join("package.json"), &pkg).unwrap();
    let (code, env, stderr) = revert(root);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(read(root, VLT_LOCK), relocked);
    assert_eq!(read(root, "package.json"), pkg);
    assert!(
        !uuid_dir(root, UUID).exists(),
        "only the artifact removal remained"
    );
}

#[test]
fn vendor_vlt_revert_cross_grammar_drift_detail() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project(root, &direct_lock_v0(), ROOT_PKG, "·npm·left-pad@1.3.0");
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    let wired_pkg = read(root, "package.json");
    // A vlt upgrade rejected the v0 lock; the user deleted and re-created it
    // (tilde ids, the `file:` spec kept from package.json).
    let rel = rel_dir(UUID, NAME, VERSION);
    let file_id = file_id_v1(&rel);
    let relocked = Lock::v1(
        &[&format!("\"{file_id}\": [0,\"left-pad\",null,\"{rel}\"]")],
        &[&format!(
            "\"file~_d left-pad\": \"prod file:./{rel} {file_id}\""
        )],
    )
    .render();
    std::fs::write(root.join(VLT_LOCK), &relocked).unwrap();
    let (code, env, stderr) = revert(root);
    assert_eq!(code, 0, "a drift is kept, not failed: {env:#}\n{stderr}");
    let drift = events(&env)
        .into_iter()
        .find(|e| e["errorCode"] == "vendor_lock_entry_drifted")
        .unwrap_or_else(|| panic!("{env:#}"));
    assert_eq!(
        drift["reason"],
        "vlt-lock.json was re-created by a different vlt lockfile grammar; set left-pad in \
         package.json back to 1.3.0, run `vlt install`, then re-run `socket-patch vendor \
         --revert` to remove the artifact"
    );
    assert!(uuid_dir(root, UUID).exists(), "a drift keeps the artifact");
    assert_eq!(read(root, VLT_LOCK), relocked, "no writes on drift");
    assert_eq!(read(root, "package.json"), wired_pkg);

    // Following the detail: the spec back, `vlt install`, then the re-run.
    std::fs::write(root.join("package.json"), ROOT_PKG).unwrap();
    std::fs::write(root.join(VLT_LOCK), direct_lock().render()).unwrap();
    let (code, env, stderr) = revert(root);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(!uuid_dir(root, UUID).exists());
    assert_eq!(read(root, VLT_LOCK), direct_lock().render());
}

// ── the patch service ────────────────────────────────────────────────────

const PACKAGE_PATH: &str = "/v0/orgs/acme/patches/package";

fn sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// A prebuilt tarball: `entries` of `(path, bytes)` plus optional raw
/// headers (`(path, entry type, link target)`).
fn tarball(entries: &[(&str, &[u8])], special: &[(&str, tar::EntryType, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    for (name, kind, target) in special {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(*kind);
        header.set_size(0);
        header.set_mode(0o644);
        if !target.is_empty() {
            header.set_link_name(target).unwrap();
        }
        header.set_path(name).ok();
        if header.path().is_err() || name.contains("..") {
            let bytes = name.as_bytes();
            header.as_old_mut().name[..bytes.len()].copy_from_slice(bytes);
        }
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn prebuilt(first: &str) -> Vec<u8> {
    tarball(
        &[
            (
                &format!("{first}/package.json"),
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}\n",
            ),
            (&format!("{first}/index.js"), PATCHED),
            (&format!("{first}/README.md"), b"from the service\n"),
        ],
        &[],
    )
}

async fn mount_grant(server: &MockServer, bytes: &[u8], sha512: &str) {
    let serve = format!("/serve/{UUID}/left-pad-1.3.0.tgz");
    let url = format!("{}{serve}", server.uri());
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: { "status": "granted", "url": url,
                "artifacts": [{ "kind": "tarball", "url": url,
                                "integrity": { "sha512": sha512 } }] } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(serve))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(server)
        .await;
}

async fn mount_status(server: &MockServer, status: u16, body: Value) {
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn vendor_via_service(root: &Path, uri: &str, extra: &[&str]) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let mut args = vec![
        "vendor",
        "--json",
        "--cwd",
        &cwd,
        "--api-url",
        uri,
        "--vendor-url",
        uri,
        "--api-token",
        "sktsec_placeholder_value_for_tests_api",
        "--org",
        "acme",
        "--lock-timeout",
        "5",
    ];
    args.extend_from_slice(extra);
    socket(root, &args, &[])
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_service_dir_extract() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let server = MockServer::start().await;
    let bytes = prebuilt("left-pad");
    mount_grant(&server, &bytes, &sri(&bytes)).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri(), &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_prebuilt_downloaded".to_string()),
        "{env:#}"
    );
    let rel = rel_dir(UUID, NAME, VERSION);
    assert_eq!(
        read(root, &format!("{rel}/README.md")),
        "from the service\n",
        "the first path component is stripped whatever it is called"
    );
    assert_eq!(read(root, &format!("{rel}/index.js")).as_bytes(), PATCHED);
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_service_integrity_mismatch_hard_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let server = MockServer::start().await;
    let bytes = prebuilt("package");
    mount_grant(&server, &bytes, &sri(b"something else")).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri(), &[]);
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert!(env.to_string().contains("integrity"), "{env:#}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert!(!uuid_dir(root, UUID).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_service_policy_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let server = MockServer::start().await;
    mount_status(&server, 503, json!({"error": "down"})).await;
    let (code, env, stderr) =
        vendor_via_service(root, &server.uri(), &["--vendor-source", "service"]);
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert!(!uuid_dir(root, UUID).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_service_auto_falls_back_to_build() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let server = MockServer::start().await;
    mount_status(&server, 503, json!({"error": "down"})).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri(), &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_prebuilt_unavailable".to_string()),
        "{env:#}"
    );
    let rel = rel_dir(UUID, NAME, VERSION);
    assert_eq!(read(root, &format!("{rel}/index.js")).as_bytes(), PATCHED);
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_service_pending_falls_back_to_build() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let server = MockServer::start().await;
    mount_status(
        &server,
        200,
        json!({ "results": { UUID: { "status": "pending_build" } } }),
    )
    .await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri(), &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        codes(&env).contains(&"vendor_prebuilt_pending".to_string()),
        "{env:#}"
    );
}

async fn assert_archive_refused(special: (&str, tar::EntryType, &str)) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let server = MockServer::start().await;
    let bytes = tarball(
        &[
            (
                "package/package.json",
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}\n",
            ),
            ("package/index.js", PATCHED),
        ],
        &[special],
    );
    mount_grant(&server, &bytes, &sri(&bytes)).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri(), &[]);
    assert_eq!(code, 1, "{:?}: {env:#}\n{stderr}", special.0);
    assert!(env.to_string().contains("unsafe"), "{env:#}");
    assert_eq!(read(root, VLT_LOCK), lock);
    assert!(!uuid_dir(root, UUID).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_archive_symlink_refused() {
    assert_archive_refused(("package/link.js", tar::EntryType::Symlink, "index.js")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_archive_hardlink_refused() {
    assert_archive_refused(("package/hard.js", tar::EntryType::Link, "package/index.js")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_archive_device_refused() {
    assert_archive_refused(("package/dev", tar::EntryType::Char, "")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_vlt_archive_escape_refused() {
    assert_archive_refused(("package/../../escape.js", tar::EntryType::Regular, "")).await;
}

// ── hints ────────────────────────────────────────────────────────────────

#[test]
fn vendor_vlt_human_hints_name_vlt_files_and_install() {
    let tmp = tempfile::tempdir().unwrap();
    direct_project(tmp.path());
    let cwd = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = socket_human(tmp.path(), &["vendor", "--offline", "--cwd", cwd]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("vlt-lock.json and .socket/vendor/") && stdout.contains("CI: `vlt ci`"),
        "{stdout}"
    );
    assert!(stdout.contains("Run `vlt install`"), "{stdout}");
    let (code, stdout, stderr) = socket_human(tmp.path(), &["vendor", "--revert", "--cwd", cwd]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("Run `vlt install`"), "{stdout}");
}

/// From a workspace member's directory no root lock is visible: vendor
/// refuses with the missing-lockfile code and writes no package-lock.
#[test]
fn vendor_vlt_workspace_member_cwd_sees_no_root_lock() {
    let case = cases("1.2.0")
        .into_iter()
        .find(|c| c.name == "member-only")
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    capture_project(tmp.path(), &case);
    let member = tmp.path().join("packages/a");
    let before = snapshot(tmp.path());
    stage_patch(&member, &[&case.purl], FIXTURE_UUID, &[]);
    let cwd = member.to_str().unwrap();
    let (_, env, _) = socket(
        &member,
        &["vendor", "--json", "--offline", "--cwd", cwd],
        &[],
    );
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert!(!member.join("package-lock.json").exists());
    assert!(!member.join("vlt-lock.json").exists());
    let after = snapshot(tmp.path());
    let changed: Vec<&String> = after
        .keys()
        .filter(|k| before.get(*k) != after.get(*k))
        .filter(|k| !k.starts_with("packages/a/.socket"))
        .collect();
    assert!(changed.is_empty(), "{changed:?}");
}

/// The lock is written last; when that write fails the package.json files
/// already rewritten go back and the staged artifact is unwound. An
/// immutable file (`chflags uchg`) is the one hermetic way to fail only
/// the lock's rename.
#[cfg(target_os = "macos")]
#[test]
fn vendor_vlt_lock_write_failure_unwinds_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    direct_project(root);
    let lock = read(root, VLT_LOCK);
    let chflags = |flag: &str| {
        std::process::Command::new("chflags")
            .arg(flag)
            .arg(root.join(VLT_LOCK))
            .status()
            .is_ok_and(|s| s.success())
    };
    if !chflags("uchg") {
        eprintln!("chflags unavailable; skipping");
        return;
    }
    let (code, env, stderr) = vendor(root, &[]);
    assert!(chflags("nouchg"));
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert!(
        env.to_string().contains("package.json files restored"),
        "{env:#}"
    );
    assert_eq!(read(root, "package.json"), ROOT_PKG);
    assert_eq!(read(root, VLT_LOCK), lock);
    assert!(
        !uuid_dir(root, UUID).exists(),
        "the staged artifact is unwound"
    );
}
