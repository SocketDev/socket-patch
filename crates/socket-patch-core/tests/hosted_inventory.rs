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
    assert!(
        refusal.contains("git checkout -- npm-shrinkwrap.json"),
        "{refusal}"
    );
    assert!(refusal.contains("patched_ref_unattributable"), "{refusal}");
    assert!(
        !refusal.contains(GRANT),
        "the grant token is not a patch: {refusal}"
    );
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

// ── attributed pins' grant tokens ────────────────────────────────────────
// With no ledger, the lock content alone attributes a hosted pin, and the
// discovery sweep also recognizes the grant token of the pin's URL. That
// token is the pin's own, not unattributed wiring, wherever the file names
// the pin's patch too; any other unpinned patch uuid stays contested.

const OTHER_PATCH: &str = "33333333-3333-4333-8333-333333333333";
const SHA512: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

fn vlt_lock(nodes: &[(&str, &str)]) -> String {
    // No `lockfileVersion`: a lock some vlt release discards, so its hosted
    // pins are refs withheld from the lock basis (a flagged pin file).
    let nodes: Vec<String> = nodes
        .iter()
        .map(|(id, url)| format!("    \"{id}\": [0,\"left-pad\",\"{SHA512}\",\"{url}\"]"))
        .collect();
    format!(
        "{{\n  \"options\": {{}},\n  \"nodes\": {{\n{}\n  }},\n  \"edges\": {{}}\n}}\n",
        nodes.join(",\n")
    )
}

#[tokio::test]
async fn vlt_pin_withheld_from_the_lock_basis_is_not_contested() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        vlt_lock(&[("·npm·left-pad@1.3.0", &hosted_url())]),
    )
    .unwrap();
    let inv = inventory(tmp.path()).await;
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    assert_eq!(inv.pins[0].uuid, PATCH);
    assert!(inv.contested.is_empty(), "{inv:?}");
}

#[tokio::test]
async fn vlt_flagged_lock_naming_another_patch_is_still_contested() {
    let tmp = tempfile::tempdir().unwrap();
    // Same grant token, but a second node wires a patch no ref attributes
    // (its leaf names another package version, so it is diagnosed).
    let bogus = format!(
        "https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/{OTHER_PATCH}/left-pad-9.9.9.tgz"
    );
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        vlt_lock(&[
            ("·npm·left-pad@1.3.0", &hosted_url()),
            ("·npm·left-pad@1.3.0·peer", &bogus),
        ]),
    )
    .unwrap();
    let inv = inventory(tmp.path()).await;
    let contested: Vec<&str> = inv.contested.iter().map(|c| c.uuid.as_str()).collect();
    assert!(contested.contains(&OTHER_PATCH), "{inv:?}");
    assert!(!contested.contains(&GRANT), "{inv:?}");
    assert!(inv.contested_refusal().is_some());
}

fn uv_url(patch: &str) -> String {
    format!(
        "https://patch.socket.dev/patch/pypi/six/1.17.0/{GRANT}/{patch}/six-1.17.0-py2.py3-none-any.whl"
    )
}

fn write_uv_project(root: &std::path::Path, pyproject_patch: &str, extra_source: Option<&str>) {
    let url = uv_url(PATCH);
    let hash = "a".repeat(64);
    std::fs::write(
        root.join("uv.lock"),
        format!(
            "version = 1\nrequires-python = \">=3.8\"\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\n\
             dependencies = [{{ name = \"six\" }}]\n\n\
             [[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsource = {{ url = \"{url}\" }}\n\
             wheels = [{{ url = \"{url}\", hash = \"sha256:{hash}\" }}]\n"
        ),
    )
    .unwrap();
    let extra = extra_source
        .map(|u| format!("other = {{ url = \"{u}\" }}\n"))
        .unwrap_or_default();
    std::fs::write(
        root.join("pyproject.toml"),
        format!(
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = []\n\n\
             [tool.uv]\noverride-dependencies = [\"six==1.17.0\"]\n\n\
             [tool.uv.sources]\nsix = {{ url = \"{}\" }}\n{extra}",
            uv_url(pyproject_patch)
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn uv_transitive_override_pin_is_not_contested_by_its_pyproject() {
    let tmp = tempfile::tempdir().unwrap();
    write_uv_project(tmp.path(), PATCH, None);
    let inv = inventory(tmp.path()).await;
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    assert_eq!(inv.pins[0].uuid, PATCH);
    assert_eq!(inv.pins[0].files, vec!["uv.lock".to_string()]);
    assert!(inv.contested.is_empty(), "{inv:?}");
}

#[tokio::test]
async fn uv_pyproject_naming_an_unpinned_patch_is_still_contested() {
    let tmp = tempfile::tempdir().unwrap();
    // pyproject.toml also routes another package to a patch no lock pins,
    // under the same grant token.
    let other = format!(
        "https://patch.socket.dev/patch/pypi/other/1.0.0/{GRANT}/{OTHER_PATCH}/other-1.0.0-py3-none-any.whl"
    );
    write_uv_project(tmp.path(), PATCH, Some(&other));
    let inv = inventory(tmp.path()).await;
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    let contested: Vec<&str> = inv.contested.iter().map(|c| c.uuid.as_str()).collect();
    assert_eq!(contested, vec![OTHER_PATCH], "{inv:?}");
    let refusal = inv.contested_refusal().expect("a refusal");
    assert!(refusal.contains("pyproject.toml"), "{refusal}");
}

#[tokio::test]
async fn half_reverted_uv_pair_is_still_contested() {
    let tmp = tempfile::tempdir().unwrap();
    // The lock and its pyproject name different patches: nothing is
    // attributable, so the token is no pin's and both stay contested.
    write_uv_project(tmp.path(), OTHER_PATCH, None);
    let inv = inventory(tmp.path()).await;
    assert!(inv.pins.is_empty(), "{inv:?}");
    assert!(inv.contested_refusal().is_some(), "{inv:?}");
}

/// A lockless NuGet pin (an exclusive Socket source mapping, no
/// `packages.lock.json`: `rewrite_nuget`'s output for most projects) is
/// contested wiring nothing can attribute to a version. Its refusal names
/// the remedy that makes it attributable — create the lockfile — never a
/// hosted re-scan, which would only write the same pin again (B13).
#[tokio::test]
async fn lockless_nuget_pin_refusal_names_the_lockfile_remedy() {
    let tmp = tempfile::tempdir().unwrap();
    let key = format!("socket-patch-{PATCH}");
    let index = format!("https://patch.socket.dev/patch-registry/nuget/{GRANT}/{PATCH}/index.json");
    std::fs::write(
        tmp.path().join("nuget.config"),
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
             <add key=\"{key}\" value=\"{index}\" />\n  </packageSources>\n  \
             <packageSourceMapping>\n    <packageSource key=\"{key}\">\n      \
             <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  \
             </packageSourceMapping>\n</configuration>\n"
        ),
    )
    .unwrap();
    let inv = inventory(tmp.path()).await;
    assert!(inv.pins.is_empty(), "{inv:?}");
    let lockless: Vec<_> = inv
        .contested
        .iter()
        .filter(|c| !c.lockless.is_empty())
        .collect();
    assert_eq!(lockless.len(), 1, "{inv:?}");
    assert!(lockless[0].lockless.contains("nuget"), "{inv:?}");
    let refusal = inv.contested_refusal().expect("a refusal");
    assert!(refusal.contains("no lockfile records"), "{refusal}");
    assert!(
        refusal.contains("dotnet restore --use-lock-file"),
        "{refusal}"
    );
    assert!(
        refusal.contains("git checkout -- nuget.config"),
        "{refusal}"
    );
    assert!(
        !refusal.contains("re-run `socket-patch scan --mode hosted`"),
        "a hosted re-scan cannot attribute a lockless pin: {refusal}"
    );
}
