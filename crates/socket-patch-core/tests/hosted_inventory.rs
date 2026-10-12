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

// ── pins withheld from VEX by an unreachable unpatched copy (#828) ───────
// The hosted rewriters rewire every entry they can and skip a copy no
// rewire reaches (an npm bundled copy, a yarn classic git block). Discovery
// does not attest that pin, but it is still the rewriter's own wiring of
// one package version: management commands restore it, never refuse it.

#[tokio::test]
async fn npm_pin_beside_a_bundled_copy_is_an_attributable_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0","bund":"file:bund-1.0.0.tgz"}}"#,
    )
    .unwrap();
    let mut lock: serde_json::Value =
        serde_json::from_str(&lock(&hosted_url(), "sha512-patched==")).unwrap();
    let packages = lock["packages"].as_object_mut().unwrap();
    packages.insert(
        "node_modules/bund".into(),
        serde_json::json!({ "version": "1.0.0", "resolved": "file:bund-1.0.0.tgz" }),
    );
    packages.insert(
        "node_modules/bund/node_modules/left-pad".into(),
        serde_json::json!({
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-upstream==",
            "inBundle": true,
        }),
    );
    std::fs::write(root.join("package-lock.json"), lock.to_string()).unwrap();

    let discovery = socket_patch_core::vex::discover_patched_refs(root).await;
    assert!(discovery.refs.is_empty(), "never attested: {discovery:#?}");
    let inv = HostedInventory::of(&discovery);
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    assert_eq!(inv.pins[0].purl, "pkg:npm/left-pad@1.3.0");
    assert_eq!(inv.pins[0].uuid, PATCH);
    assert_eq!(inv.pins[0].files, vec!["package-lock.json".to_string()]);
    assert!(inv.contested_refusal().is_none(), "{inv:?}");
}

#[tokio::test]
async fn yarn_classic_pin_beside_a_git_copy_is_an_attributable_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let url = hosted_url();
    std::fs::write(
        root.join("yarn.lock"),
        format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\n\
             \"left-pad@git+https://github.com/stevemao/left-pad.git#v1.3.0\":\n  \
             version \"1.3.0\"\n  \
             resolved \"git+https://github.com/stevemao/left-pad.git#5e5f1a6e23f6fa2bd1e4a3d0c2bb1c0e1bb0f00a\"\n\n\
             left-pad@^1.3.0:\n  \
             version \"1.3.0\"\n  \
             resolved \"{url}\"\n  \
             integrity sha512-patched==\n"
        ),
    )
    .unwrap();

    let discovery = socket_patch_core::vex::discover_patched_refs(root).await;
    assert!(discovery.refs.is_empty(), "never attested: {discovery:#?}");
    let inv = HostedInventory::of(&discovery);
    assert_eq!(inv.pins.len(), 1, "{inv:?}");
    assert_eq!(inv.pins[0].purl, "pkg:npm/left-pad@1.3.0");
    assert_eq!(inv.pins[0].files, vec!["yarn.lock".to_string()]);
    assert!(inv.contested_refusal().is_none(), "{inv:?}");
}

/// The twin over a copy beneath a `hasShrinkwrap` package (#753): npm 7–11
/// install it from that package's own npm-shrinkwrap.json, so the hosted
/// rewriter skips it (`redirect_npm_shrinkwrapped_instance_skipped`), and
/// over a nested git copy (#326). The hoisted pin is still the rewriter's
/// own wiring.
#[tokio::test]
async fn npm_pin_beside_a_shrinkwrapped_or_git_copy_is_an_attributable_pin() {
    let shrinkwrapped = (
        serde_json::json!({
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/@bh/sw/-/sw-1.0.0.tgz",
            "integrity": "sha512-sw==",
            "hasShrinkwrap": true,
        }),
        serde_json::json!({
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-upstream==",
        }),
    );
    let git = (
        serde_json::json!({
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/@bh/sw/-/sw-1.0.0.tgz",
            "integrity": "sha512-sw==",
            "dependencies": { "left-pad": "stevemao/left-pad#v1.3.0" },
        }),
        serde_json::json!({
            "version": "1.3.0",
            "resolved": "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba",
        }),
    );
    for (case, (parent, child)) in [("hasShrinkwrap", shrinkwrapped), ("git", git)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0","@bh/sw":"1.0.0"}}"#,
        )
        .unwrap();
        let mut lock: serde_json::Value =
            serde_json::from_str(&lock(&hosted_url(), "sha512-patched==")).unwrap();
        let packages = lock["packages"].as_object_mut().unwrap();
        packages.insert("node_modules/@bh/sw".into(), parent);
        packages.insert("node_modules/@bh/sw/node_modules/left-pad".into(), child);
        std::fs::write(root.join("package-lock.json"), lock.to_string()).unwrap();

        let discovery = socket_patch_core::vex::discover_patched_refs(root).await;
        assert!(
            discovery.refs.is_empty(),
            "{case}: never attested: {discovery:#?}"
        );
        let inv = HostedInventory::of(&discovery);
        assert_eq!(inv.pins.len(), 1, "{case}: {inv:?}");
        assert_eq!(inv.pins[0].purl, "pkg:npm/left-pad@1.3.0");
        assert_eq!(inv.pins[0].uuid, PATCH);
        assert!(inv.contested_refusal().is_none(), "{case}: {inv:?}");
    }
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

// ── #1203: a berry `resolutions` pin `yarn remove` left behind ───────────
// A hosted yarn berry pin lives in two places: the root package.json
// `resolutions` selector and the lock entry keyed by the hosted URL. `yarn
// remove` (or `yarn up` to an unpatched version) deletes the lock entry but
// never touches `resolutions`, so the selector routes nothing any more. It
// is Socket's own leftover wiring, not contested state: the management
// commands list around it and `rollback` / `remove` retire it.

const MS_PATCH: &str = "44444444-4444-4444-8444-444444444444";

fn berry_hosted_url(name: &str, version: &str, patch: &str) -> String {
    format!(
        "https://patch.socket.dev/patch/npm/{name}/{version}/{GRANT}/{patch}/{name}-{version}.tgz"
    )
}

fn berry_lock(entries: &[(&str, &str, &str)]) -> String {
    let mut text = String::from(
        "# This file is generated by running \"yarn install\" inside your project.\n\
         # Manual changes might be lost - proceed with caution!\n\n\
         __metadata:\n  version: 8\n  cacheKey: 10c0\n",
    );
    for (name, version, url) in entries {
        text.push_str(&format!(
            "\n\"{name}@{url}\":\n  version: {version}\n  resolution: \"{name}@{url}\"\n  \
             checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
            "a".repeat(128)
        ));
    }
    let deps: Vec<String> = entries
        .iter()
        .map(|(name, version, _)| format!("    {name}: \"npm:{version}\"\n"))
        .collect();
    text.push_str(&format!(
        "\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n{}  \
         languageName: unknown\n  linkType: soft\n",
        if deps.is_empty() {
            String::new()
        } else {
            format!("  dependencies:\n{}", deps.concat())
        }
    ));
    text
}

/// A berry project hosted-pinned to left-pad and ms, after `yarn remove
/// left-pad` (`ms_pinned`: ms is still pinned, else it was removed too).
fn write_berry_removed(root: &std::path::Path, ms_pinned: bool) {
    let lp = berry_hosted_url("left-pad", "1.3.0", PATCH);
    let ms = berry_hosted_url("ms", "2.1.3", MS_PATCH);
    let mut resolutions = serde_json::Map::new();
    resolutions.insert("left-pad@npm:1.3.0".into(), lp.clone().into());
    resolutions.insert("ms@npm:2.1.3".into(), ms.clone().into());
    let mut pkg = serde_json::json!({"name": "app", "version": "1.0.0", "private": true});
    if ms_pinned {
        pkg["dependencies"] = serde_json::json!({"ms": "2.1.3"});
    } else {
        resolutions.remove("ms@npm:2.1.3");
    }
    pkg["resolutions"] = resolutions.into();
    std::fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&pkg).unwrap() + "\n",
    )
    .unwrap();
    let entries: Vec<(&str, &str, &str)> = if ms_pinned {
        vec![("ms", "2.1.3", ms.as_str())]
    } else {
        Vec::new()
    };
    std::fs::write(root.join("yarn.lock"), berry_lock(&entries)).unwrap();
    std::fs::write(root.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
}

#[tokio::test]
async fn berry_selector_left_by_yarn_remove_is_stale_not_contested() {
    for ms_pinned in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        write_berry_removed(tmp.path(), ms_pinned);
        let inv = inventory(tmp.path()).await;
        assert!(
            inv.contested.is_empty(),
            "ms_pinned={ms_pinned}: a leftover selector is not contested: {inv:?}"
        );
        assert!(inv.contested_refusal().is_none());
        let pinned: Vec<&str> = inv.pins.iter().map(|p| p.uuid.as_str()).collect();
        assert_eq!(
            pinned,
            if ms_pinned { vec![MS_PATCH] } else { vec![] },
            "{inv:?}"
        );
        assert_eq!(inv.stale.len(), 1, "{inv:?}");
        assert_eq!(inv.stale[0].purl, "pkg:npm/left-pad@1.3.0");
        assert_eq!(inv.stale[0].uuid, PATCH);
        assert_eq!(inv.stale[0].files, vec!["package.json".to_string()]);
        assert!(!inv.is_empty(), "the leftover selector is hosted state");
    }
}

#[tokio::test]
async fn berry_selector_is_only_retired_against_a_berry_lock() {
    // No yarn.lock: nothing says whether yarn would route the selector
    // (the project may never have been installed), so it is not retired.
    let tmp = tempfile::tempdir().unwrap();
    write_berry_removed(tmp.path(), false);
    std::fs::remove_file(tmp.path().join("yarn.lock")).unwrap();
    let inv = inventory(tmp.path()).await;
    assert!(inv.stale.is_empty(), "{inv:?}");
    // A lock that still resolves the descriptor elsewhere disagrees with
    // the manifest: contested, never retired.
    write_berry_removed(tmp.path(), false);
    std::fs::write(
        tmp.path().join("yarn.lock"),
        berry_lock(&[]).replace(
            "\n\"app@workspace:.\"",
            &format!(
                "\n\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
                 checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n\n\"app@workspace:.\"",
                "b".repeat(128)
            ),
        ),
    )
    .unwrap();
    let inv = inventory(tmp.path()).await;
    assert!(inv.stale.is_empty(), "{inv:?}");
    assert!(inv.contested_refusal().is_some(), "{inv:?}");
}

#[tokio::test]
async fn restore_retires_a_leftover_berry_selector() {
    use socket_patch_core::patch::redirect::upstream::{
        restore_upstream, PinStatus, RestoreOptions,
    };
    for ms_pinned in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        write_berry_removed(tmp.path(), ms_pinned);
        let lock_before = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
        let inv = inventory(tmp.path()).await;
        // Offline: retiring a selector needs no registry lookup.
        let opts = RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let outcome = restore_upstream(tmp.path(), &inv.stale, &opts).await;
        assert_eq!(outcome.pins.len(), 1);
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert_eq!(outcome.reverted_files, vec!["package.json".to_string()]);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|(code, detail)| *code == "hosted_resolution_orphaned"
                    && detail.contains("left-pad@npm:1.3.0")),
            "{:?}",
            outcome.warnings
        );
        let pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(tmp.path().join("package.json")).unwrap(),
        )
        .unwrap();
        if ms_pinned {
            let res = pkg["resolutions"].as_object().unwrap();
            assert!(!res.contains_key("left-pad@npm:1.3.0"), "{pkg}");
            assert!(res.contains_key("ms@npm:2.1.3"), "{pkg}");
        } else {
            assert!(pkg.get("resolutions").is_none(), "{pkg}");
        }
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
            lock_before,
            "the lock is not touched"
        );
        let after = inventory(tmp.path()).await;
        assert!(
            after.stale.is_empty() && after.contested.is_empty(),
            "{after:?}"
        );
    }
}

// ── #1445: a uv override pin `uv remove` / `uv lock -P` left behind ──────
// Hosted uv wires a TRANSITIVE package with an `override-dependencies`
// entry (under the rewrite's ownership comment) plus a `[tool.uv.sources]`
// URL, which uv.lock records under `[manifest] overrides`. Once the parent
// stops depending on it (`uv remove <parent>`, `uv lock --upgrade-package
// <parent>`), uv drops its `[[package]]` but never edits the override or
// the source, so both lines (and the manifest record) are left behind.
// That is Socket's own leftover pin, not contested state.

const SIX_PATCH: &str = "66666666-6666-4666-8666-666666666666";

fn six_hosted_url() -> String {
    format!(
        "https://patch.socket.dev/patch/pypi/six/1.16.0/{GRANT}/{SIX_PATCH}/six-1.16.0-py2.py3-none-any.whl"
    )
}

/// The pristine project: `isodate` is the only declared dependency.
const UV_ORPHAN_PYPROJECT_PRISTINE: &str = "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n\
     requires-python = \">=3.9\"\ndependencies = [\"isodate>=0.6\"]\n";

/// The uv.lock real uv (0.11) writes for the leftover wiring after `uv lock
/// --upgrade-package isodate` (0.7.2 no longer depends on six), with the
/// `[manifest]` block `manifest` (`None`: no manifest record).
fn uv_orphan_lock(manifest: Option<&str>) -> String {
    let manifest = manifest.map(|m| format!("{m}\n\n")).unwrap_or_default();
    format!(
        "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n{manifest}\
         [[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\n\
         dependencies = [\n    {{ name = \"isodate\" }},\n]\n\n\
         [package.metadata]\nrequires-dist = [{{ name = \"isodate\", specifier = \">=0.6\" }}]\n\n\
         [[package]]\nname = \"isodate\"\nversion = \"0.7.2\"\n\
         source = {{ registry = \"https://pypi.org/simple\" }}\n\
         sdist = {{ url = \"https://files.pythonhosted.org/packages/54/4d/e940025e2ce31a8ce1202635910747e5a87cc3a6a6bb2d00973375014749/isodate-0.7.2.tar.gz\", hash = \"sha256:4cd1aa0f43ca76f4a6c6c0292a85f40b35ec2e43e315b59f06e6d32171a953e6\", size = 29705, upload-time = \"2024-10-08T23:04:11.5Z\" }}\n\
         wheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/15/aa/0aca39a37d3c7eb941ba736ede56d689e7be91cab5d9ca846bde3999eba6/isodate-0.7.2-py3-none-any.whl\", hash = \"sha256:28009937d8031054830160fce6d409ed342816b543597cece116d966c6d99e15\", size = 22320, upload-time = \"2024-10-08T23:04:09.501Z\" }},\n]\n"
    )
}

/// A uv project whose hosted six pin (a transitive of isodate 0.6.1) was
/// left behind by `uv lock --upgrade-package isodate`. `marked`: the
/// override carries the hosted rewrite's ownership comment (else it is the
/// user's own pin).
fn write_uv_override_left_by_relock(root: &std::path::Path, marked: bool) {
    let mark = if marked {
        "    # socket-patch hosted: pins a patched transitive dependency; rollback removes it\n"
    } else {
        ""
    };
    std::fs::write(
        root.join("pyproject.toml"),
        format!(
            "{UV_ORPHAN_PYPROJECT_PRISTINE}\n[tool.uv]\noverride-dependencies = [\n{mark}    \
             \"six==1.16.0\",\n]\n\n[tool.uv.sources]\nsix = {{ url = \"{}\" }}\n",
            six_hosted_url()
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("uv.lock"),
        uv_orphan_lock(Some(&format!(
            "[manifest]\noverrides = [{{ name = \"six\", url = \"{}\" }}]",
            six_hosted_url()
        ))),
    )
    .unwrap();
}

#[tokio::test]
async fn uv_override_left_by_relock_is_stale_not_contested() {
    let tmp = tempfile::tempdir().unwrap();
    write_uv_override_left_by_relock(tmp.path(), true);
    let inv = inventory(tmp.path()).await;
    assert!(
        inv.contested.is_empty(),
        "a leftover override pin is not contested: {inv:?}"
    );
    assert!(inv.contested_refusal().is_none());
    assert!(inv.pins.is_empty(), "{inv:?}");
    assert_eq!(inv.stale.len(), 1, "{inv:?}");
    assert_eq!(inv.stale[0].purl, "pkg:pypi/six@1.16.0");
    assert_eq!(inv.stale[0].uuid, SIX_PATCH);
    assert_eq!(inv.stale[0].files, vec!["uv.lock".to_string()]);
    assert!(!inv.is_empty(), "the leftover override is hosted state");
}

#[tokio::test]
async fn uv_override_left_beside_a_live_hosted_pin_is_stale() {
    // Another package is still hosted-pinned in the same lock: that one is a
    // pin, the leftover six override is stale, and nothing is contested.
    let tmp = tempfile::tempdir().unwrap();
    write_uv_project(tmp.path(), PATCH, None);
    let pyproject = std::fs::read_to_string(tmp.path().join("pyproject.toml")).unwrap();
    // The live pin is six 1.17.0; the leftover is `other` 1.0.0.
    let other = format!(
        "https://patch.socket.dev/patch/pypi/other/1.0.0/{GRANT}/{SIX_PATCH}/other-1.0.0-py3-none-any.whl"
    );
    let pyproject = pyproject
        .replace(
            "override-dependencies = [\"six==1.17.0\"]",
            "override-dependencies = [\"six==1.17.0\",\n    \
             # socket-patch hosted: pins a patched transitive dependency; rollback removes it\n    \
             \"other==1.0.0\",\n]",
        )
        + &format!("other = {{ url = \"{other}\" }}\n");
    std::fs::write(tmp.path().join("pyproject.toml"), pyproject).unwrap();
    let lock = std::fs::read_to_string(tmp.path().join("uv.lock")).unwrap();
    let lock = lock.replacen(
        "\n\n[[package]]",
        &format!("\n\n[manifest]\noverrides = [{{ name = \"other\", url = \"{other}\" }}]\n\n[[package]]"),
        1,
    );
    std::fs::write(tmp.path().join("uv.lock"), lock).unwrap();
    let inv = inventory(tmp.path()).await;
    assert!(inv.contested.is_empty(), "{inv:?}");
    let pinned: Vec<&str> = inv.pins.iter().map(|p| p.uuid.as_str()).collect();
    assert_eq!(pinned, vec![PATCH], "{inv:?}");
    assert_eq!(inv.stale.len(), 1, "{inv:?}");
    assert_eq!(inv.stale[0].purl, "pkg:pypi/other@1.0.0");
    assert_eq!(inv.stale[0].uuid, SIX_PATCH);
}

#[tokio::test]
async fn users_own_uv_override_left_by_relock_stays_contested() {
    // Without the hosted rewrite's ownership comment the override is the
    // user's own pin: nothing says the wiring is Socket's to retire.
    let tmp = tempfile::tempdir().unwrap();
    write_uv_override_left_by_relock(tmp.path(), false);
    let inv = inventory(tmp.path()).await;
    assert!(inv.stale.is_empty(), "{inv:?}");
    assert!(inv.contested_refusal().is_some(), "{inv:?}");
}

#[tokio::test]
async fn uv_override_still_in_the_lock_is_not_stale() {
    // The lock still resolves six from the registry while the metadata
    // routes it to the hosted wheel: the pair disagrees (half reverted),
    // which stays contested.
    let tmp = tempfile::tempdir().unwrap();
    write_uv_override_left_by_relock(tmp.path(), true);
    let lock = std::fs::read_to_string(tmp.path().join("uv.lock")).unwrap();
    std::fs::write(
        tmp.path().join("uv.lock"),
        lock + "\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\
                source = { registry = \"https://pypi.org/simple\" }\n",
    )
    .unwrap();
    let inv = inventory(tmp.path()).await;
    assert!(inv.stale.is_empty(), "{inv:?}");
    assert!(inv.contested_refusal().is_some(), "{inv:?}");
}

#[tokio::test]
async fn restore_retires_a_leftover_uv_override() {
    use socket_patch_core::patch::redirect::upstream::{
        restore_upstream, PinStatus, RestoreOptions,
    };
    let tmp = tempfile::tempdir().unwrap();
    write_uv_override_left_by_relock(tmp.path(), true);
    let inv = inventory(tmp.path()).await;
    // Offline: retiring a leftover needs no registry lookup.
    let opts = RestoreOptions {
        offline: true,
        ..Default::default()
    };
    let outcome = restore_upstream(tmp.path(), &inv.stale, &opts).await;
    assert_eq!(outcome.pins.len(), 1);
    assert_eq!(
        outcome.pins[0].status,
        PinStatus::Restored,
        "{:?}",
        outcome.pins
    );
    assert_eq!(
        outcome.reverted_files,
        vec!["pyproject.toml".to_string(), "uv.lock".to_string()]
    );
    assert!(
        outcome
            .warnings
            .iter()
            .any(|(code, detail)| *code == "hosted_resolution_orphaned"
                && detail.contains("six==1.16.0")),
        "{:?}",
        outcome.warnings
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pyproject.toml")).unwrap(),
        UV_ORPHAN_PYPROJECT_PRISTINE,
        "the override and the source go, and the emptied [tool.uv] with them"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("uv.lock")).unwrap(),
        uv_orphan_lock(None),
        "the `[manifest] overrides` record goes, as `uv lock` would drop it"
    );
    let after = inventory(tmp.path()).await;
    assert!(after.is_empty(), "{after:?}");
}
