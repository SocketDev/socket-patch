//! The hosted inventory keeps contested wiring: a hosted lock another lock
//! contradicts is not an attributable pin, but it is still hosted state
//! management commands must refuse around.

use socket_patch_core::patch::redirect::upstream::HostedInventory;

const PATCH: &str = "11111111-1111-4111-8111-111111111111";
const GRANT: &str = "22222222-2222-4222-8222-222222222222";

fn lock(resolved: &str, integrity: &str) -> String {
    format!(
        r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"app","version":"1.0.0","dependencies":{{"left-pad":"1.3.0"}}}},"node_modules/left-pad":{{"version":"1.3.0","resolved":"{resolved}","integrity":"{integrity}"}}}}}}"#
    )
}

fn hosted_url() -> String {
    format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/{PATCH}/left-pad-1.3.0.tgz")
}

fn write_project(root: &std::path::Path, shrinkwrap_hosted: bool, lock_hosted: bool) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    let upstream = lock(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-upstream==",
    );
    let hosted = lock(&hosted_url(), "sha512-patched==");
    std::fs::write(
        root.join("package-lock.json"),
        if lock_hosted { &hosted } else { &upstream },
    )
    .unwrap();
    if shrinkwrap_hosted {
        std::fs::write(root.join("npm-shrinkwrap.json"), &hosted).unwrap();
    }
}

async fn inventory(root: &std::path::Path) -> HostedInventory {
    HostedInventory::of(&socket_patch_core::vex::discover_patched_refs(root).await)
}

#[tokio::test]
async fn contradicted_hosted_lock_is_contested_not_absent() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), true, false);
    let inv = inventory(tmp.path()).await;
    assert!(inv.pins.is_empty(), "no attributable pin: {inv:?}");
    assert!(!inv.is_empty(), "contested wiring is hosted state: {inv:?}");
    let refusal = inv.contested_refusal().expect("a refusal");
    assert!(refusal.contains("npm-shrinkwrap.json"), "{refusal}");
    assert!(refusal.contains("git checkout -- npm-shrinkwrap.json"), "{refusal}");
    assert!(refusal.contains("patched_ref_unattributable"), "{refusal}");
    assert!(!refusal.contains(GRANT), "the grant token is not a patch: {refusal}");
}

#[tokio::test]
async fn attributable_pin_is_not_contested() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), false, true);
    let inv = inventory(tmp.path()).await;
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    assert_eq!(inv.pins[0].uuid, PATCH);
    assert!(inv.contested.is_empty(), "{inv:?}");
    assert!(inv.contested_refusal().is_none());
}

#[tokio::test]
async fn registry_only_project_has_no_hosted_state() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), false, false);
    assert!(inventory(tmp.path()).await.is_empty());
}
