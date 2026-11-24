//! Cleanup of hosted mode's pnpm registry route once a patch is no longer
//! needed: `scan` and `repair` take out every entry of the route that no
//! lockfile uses any more.
//!
//! A registry entry is the registry of a patch (its `namedRegistries`
//! line), the `overrides` entry of pnpm-workspace.yaml that routes the
//! release to it, and that override's record in a lock's `overrides:`
//! section. Each test lays down the
//! project an earlier hosted scan routed and the change that made an entry
//! unused, then compares the files byte for byte:
//!
//! - a hosted `scan`, with no extra flag, after the dependency was removed,
//!   was upgraded past the patched release, or had its patch withdrawn, and
//!   once no patch is hosted at all;
//! - `repair --offline`, from the files alone, for the same projects where
//!   that can be told without the patch service;
//! - `scan --prune`, in hosted mode and with no mode;
//! - a dry run of each, which lists the same entries and writes nothing.
//!
//! The real-pnpm leg (`e2e_redirect_pnpm_build.rs`) runs the same changes
//! through pnpm itself and installs the cleaned project frozen.

#[path = "common/hermetic.rs"]
mod hermetic;

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const HOST: &str = "https://patch.test";
const PATCHED: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM: &str = "sha512-UPSTREAMupstream==";

/// A patched release, the grant its tarball is served under and the name
/// of its registry (`socket-` and the first eight digits of the patch
/// UUID).
struct Patch {
    name: &'static str,
    version: &'static str,
    uuid: &'static str,
    token: &'static str,
    alias: &'static str,
}

const KEPT: Patch = Patch {
    name: "kept-pkg",
    version: "1.0.0",
    uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    token: "11111111-1111-4111-8111-111111111111",
    alias: "socket-aaaaaaaa",
};
const GONE: Patch = Patch {
    name: "gone-pkg",
    version: "2.0.0",
    uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    token: "22222222-2222-4222-8222-222222222222",
    alias: "socket-bbbbbbbb",
};

impl Patch {
    fn purl(&self) -> String {
        format!("pkg:npm/{}@{}", self.name, self.version)
    }

    fn release(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// The registry's address: the directory the patch is served from.
    fn address(&self) -> String {
        let Patch {
            name,
            version,
            uuid,
            token,
            ..
        } = self;
        format!("{HOST}/patch/npm/{name}/{version}/{token}/{uuid}/")
    }

    fn url(&self) -> String {
        format!("{}{}-{}.tgz", self.address(), self.name, self.version)
    }

    /// The lock's record of the override that routes the release.
    fn recorded(&self) -> String {
        format!("{}: {}:{}", self.release(), self.alias, self.version)
    }

    /// The release as a lock holds it once routed.
    fn routed(&self) -> Dep {
        Dep {
            name: self.name,
            version: self.version,
            routed: Some((self.alias, self.url())),
        }
    }

    /// The release on the public registry.
    fn upstream(&self) -> Dep {
        Dep::plain(self.name, self.version)
    }
}

/// One dependency of a [`lock`]: routed through a registry when it has
/// one (`(registry name, tarball)`).
struct Dep {
    name: &'static str,
    version: &'static str,
    routed: Option<(&'static str, String)>,
}

impl Dep {
    fn plain(name: &'static str, version: &'static str) -> Dep {
        Dep {
            name,
            version,
            routed: None,
        }
    }

    fn spelled(&self) -> String {
        match &self.routed {
            Some((alias, _)) => format!("{alias}:{}", self.version),
            None => self.version.to_string(),
        }
    }
}

/// A lockfileVersion 9 lock recording `overrides` (`key: value`), its `.`
/// importer depending on `deps`, laid out as pnpm writes one.
fn lock(overrides: &[String], deps: &[Dep]) -> String {
    let mut text = "lockfileVersion: '9.0'\n\n".to_string();
    if !overrides.is_empty() {
        text.push_str("overrides:\n");
        for entry in overrides {
            text.push_str(&format!("  {entry}\n"));
        }
        text.push('\n');
    }
    if deps.is_empty() {
        text.push_str("importers:\n\n  .: {}\n");
        return text;
    }
    text.push_str("importers:\n\n  .:\n    dependencies:\n");
    for dep in deps {
        let spelled = dep.spelled();
        text.push_str(&format!(
            "      {}:\n        specifier: {spelled}\n        version: {spelled}\n",
            dep.name
        ));
    }
    text.push_str("\npackages:\n");
    for dep in deps {
        let resolution = match &dep.routed {
            Some((_, url)) => format!("{{integrity: {PATCHED}, tarball: {url}}}"),
            None => format!("{{integrity: {UPSTREAM}}}"),
        };
        text.push_str(&format!(
            "\n  {}@{}:\n    resolution: {resolution}\n",
            dep.name,
            dep.spelled()
        ));
    }
    text.push_str("\nsnapshots:\n");
    for dep in deps {
        text.push_str(&format!("\n  {}@{}: {{}}\n", dep.name, dep.spelled()));
    }
    text
}

/// The two maps of the route for `patches`, as hosted mode writes them:
/// the registries in name order, the overrides in key order.
fn maps(patches: &[&Patch]) -> String {
    let mut registries: Vec<String> = patches
        .iter()
        .map(|p| format!("  {}: {}\n", p.alias, p.address()))
        .collect();
    registries.sort();
    let mut overrides: Vec<String> = patches
        .iter()
        .map(|p| format!("  '{}': '{}:{}'\n", p.release(), p.alias, p.version))
        .collect();
    overrides.sort();
    format!(
        "namedRegistries:\n{}overrides:\n{}",
        registries.concat(),
        overrides.concat()
    )
}

/// The file a routed scan creates for `patches`.
fn created(patches: &[&Patch]) -> String {
    format!("packages:\n  - '.'\n{}", maps(patches))
}

/// A project pinned to a pnpm the registry route is taken for, depending
/// on `deps` (each installed, so the scan crawls it), with `workspace` and
/// `lock_text` as an earlier run and the user's change left them.
fn write_project(root: &Path, deps: &[Dep], workspace: Option<&str>, lock_text: &str) {
    let dependencies: serde_json::Map<String, Value> = deps
        .iter()
        .map(|dep| (dep.name.to_string(), json!(dep.version)))
        .collect();
    let manifest = json!({
        "name": "consumer",
        "version": "0.0.0",
        "packageManager": "pnpm@12.22.0",
        "dependencies": dependencies,
    });
    std::fs::write(root.join("package.json"), manifest.to_string()).unwrap();
    for dep in deps {
        let dir = root.join("node_modules").join(dep.name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            json!({ "name": dep.name, "version": dep.version }).to_string(),
        )
        .unwrap();
    }
    if let Some(workspace) = workspace {
        std::fs::write(root.join("pnpm-workspace.yaml"), workspace).unwrap();
    }
    std::fs::write(root.join("pnpm-lock.yaml"), lock_text).unwrap();
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

/// The patch API: the search offers `offered`, the reference endpoint
/// grants each of them with its registry address and answers `withdrawn`
/// for the rest, and the npm registry serves the upstream release of
/// every patch (for a restore).
async fn mock_api(server: &MockServer, offered: &[&Patch], withdrawn: &[&Patch]) {
    let packages: Vec<Value> = offered
        .iter()
        .map(|p| {
            json!({
                "purl": p.purl(),
                "patches": [{
                    "uuid": p.uuid, "purl": p.purl(), "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "registry cleanup fixture"
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    for p in offered {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{}.*$",
                p.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": p.uuid, "purl": p.purl(),
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
    }
    let mut results = serde_json::Map::new();
    for p in offered {
        results.insert(
            p.uuid.to_string(),
            json!({
                "status": "granted",
                "url": p.url(),
                "purl": p.purl(),
                "artifacts": [{
                    "kind": "tarball",
                    "url": p.url(),
                    "integrity": { "sha512": PATCHED }
                }],
                "registryOverride": null,
                "npmRegistryUrl": p.address(),
            }),
        );
    }
    for p in withdrawn {
        results.insert(p.uuid.to_string(), json!({ "status": "withdrawn" }));
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .mount(server)
        .await;
    for p in [&KEPT, &GONE] {
        let Patch { name, version, .. } = p;
        Mock::given(method("GET"))
            .and(path(format!("/npm-registry/{name}/{version}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": name,
                "version": version,
                "dist": {
                    "tarball": format!("{}/npm-registry/{name}/-/{name}-{version}.tgz", server.uri()),
                    "integrity": UPSTREAM,
                }
            })))
            .mount(server)
            .await;
    }
}

/// Run the CLI and parse its `--json` envelope.
fn run_json(cmd: &mut std::process::Command) -> (Option<i32>, Value) {
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (out.status.code(), doc)
}

/// `scan [extra] --yes` against `server`, with the fixtures' patch server
/// named to the run.
fn scan_command(cwd: &Path, server: &MockServer, extra: &[&str]) -> std::process::Command {
    scan_command_told(cwd, server, extra, Some(HOST))
}

/// [`scan_command`] for a run told of `patch_server`, or of none.
fn scan_command_told(
    cwd: &Path,
    server: &MockServer,
    extra: &[&str],
    patch_server: Option<&str>,
) -> std::process::Command {
    let mut cmd = hermetic::binary_command();
    for prefix in ["npm_config_", "pnpm_config_"] {
        for key in [
            "lockfile",
            "package_lock",
            "git_branch_lockfile",
            "registry",
        ] {
            cmd.env_remove(format!("{prefix}{key}"));
        }
    }
    cmd.env_remove("NPM_CONFIG_REGISTRY").env(
        "SOCKET_NPM_REGISTRY",
        format!("{}/npm-registry", server.uri()),
    );
    cmd.arg("scan").args(extra).arg("--yes");
    if let Some(url) = patch_server {
        cmd.args(["--patch-server-url", url]);
    }
    cmd.args([
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        &server.uri(),
        "--org",
        ORG,
        "--api-token",
        "fake",
    ]);
    cmd
}

/// `scan --mode hosted --json [extra]`.
fn scan_hosted(cwd: &Path, server: &MockServer, extra: &[&str]) -> (Option<i32>, Value) {
    let mut args = vec!["--mode", "hosted", "--json"];
    args.extend_from_slice(extra);
    run_json(&mut scan_command(cwd, server, &args))
}

/// `repair [extra]` with no patch service to reach: the API address is a
/// closed port, so a run that asked it anything would fail.
fn repair_command(cwd: &Path, extra: &[&str]) -> std::process::Command {
    repair_command_told(cwd, extra, Some(HOST))
}

/// [`repair_command`] for a run told of `patch_server`, or of none.
fn repair_command_told(
    cwd: &Path,
    extra: &[&str],
    patch_server: Option<&str>,
) -> std::process::Command {
    let mut cmd = hermetic::binary_command();
    cmd.arg("repair").args(extra);
    if let Some(url) = patch_server {
        cmd.args(["--patch-server-url", url]);
    }
    cmd.args([
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        "http://127.0.0.1:9",
    ]);
    cmd
}

/// `repair --offline --json [extra]`.
fn repair_offline(cwd: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let mut args = vec!["--offline", "--json"];
    args.extend_from_slice(extra);
    run_json(&mut repair_command(cwd, &args))
}

/// `(file, entry, key)` of each registry entry the envelope reports as
/// taken out by `action` (`removed`, or `verified` on a dry run), sorted.
/// An event carries the entry's value only where it names no grant.
fn entries(doc: &Value, action: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = doc["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events: {doc}"))
        .iter()
        .filter(|e| e["errorCode"] == "registry_entry_unused")
        .map(|e| {
            assert_eq!(e["action"], action, "{e}");
            assert_eq!(e["details"]["mode"], "hosted", "{e}");
            assert!(e.get("purl").is_none(), "an artifact-level event: {e}");
            let text = |key: &str| e["details"][key].as_str().unwrap_or_default().to_string();
            (text("file"), text("entry"), text("key"))
        })
        .collect();
    out.sort();
    for event in doc["events"].as_array().into_iter().flatten() {
        if event["errorCode"] != "registry_entry_unused" {
            continue;
        }
        let json = event.to_string();
        for patch in [&KEPT, &GONE] {
            assert!(
                !json.contains(patch.token),
                "a registry's address carries the grant token and is not reported: {event}"
            );
        }
    }
    out
}

fn entry(file: &str, kind: &str, key: &str) -> (String, String, String) {
    (file.to_string(), kind.to_string(), key.to_string())
}

/// The entries `GONE` leaves unused beside a still routed `KEPT`.
fn gone_entries() -> Vec<(String, String, String)> {
    vec![
        entry("pnpm-lock.yaml", "lockOverride", "gone-pkg@2.0.0"),
        entry("pnpm-workspace.yaml", "override", "gone-pkg@2.0.0"),
        entry("pnpm-workspace.yaml", "registry", GONE.alias),
    ]
}

/// The entries of a route no lock uses at all.
fn all_entries() -> Vec<(String, String, String)> {
    vec![
        entry("pnpm-lock.yaml", "lockOverride", "gone-pkg@2.0.0"),
        entry("pnpm-lock.yaml", "lockOverride", "kept-pkg@1.0.0"),
        entry("pnpm-workspace.yaml", "override", "gone-pkg@2.0.0"),
        entry("pnpm-workspace.yaml", "override", "kept-pkg@1.0.0"),
        entry("pnpm-workspace.yaml", "registry", KEPT.alias),
        entry("pnpm-workspace.yaml", "registry", GONE.alias),
    ]
}

fn both_recorded() -> Vec<String> {
    vec![GONE.recorded(), KEPT.recorded()]
}

/// How `GONE` left the project: `(what the lock holds now, case name)`.
fn departures() -> Vec<(Vec<Dep>, &'static str)> {
    vec![
        // (a) The dependency was removed.
        (vec![KEPT.routed()], "removed"),
        // (b) It was upgraded past the patched release.
        (
            vec![Dep::plain("gone-pkg", "2.1.0"), KEPT.routed()],
            "upgraded",
        ),
    ]
}

/// What the lock holds once `GONE` left, restated for an expectation.
fn after_departure(case: &str) -> Vec<Dep> {
    departures()
        .into_iter()
        .find(|(_, name)| *name == case)
        .map(|(deps, _)| deps)
        .expect("a departure")
}

/// The project after `GONE` left it (`case`): pnpm rewrote the lock without
/// the release and still records the override it was configured with; the
/// workspace file is as the routed scan wrote it.
fn departed_project(root: &Path, case: &str) -> (String, String) {
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &after_departure(case));
    write_project(root, &after_departure(case), Some(&workspace), &lock_text);
    (workspace, lock_text)
}

fn assert_unchanged(root: &Path, workspace: &str, lock_text: &str, why: &str) {
    assert_eq!(
        read(root, "pnpm-workspace.yaml").as_deref(),
        Some(workspace),
        "{why}"
    );
    assert_eq!(
        read(root, "pnpm-lock.yaml").as_deref(),
        Some(lock_text),
        "{why}"
    );
}

/// `GONE`'s entries are out and `KEPT` is routed as before.
fn assert_gone_cleaned(root: &Path, case: &str) {
    assert_eq!(
        read(root, "pnpm-workspace.yaml").unwrap(),
        created(&[&KEPT]),
        "{case}: the override and the registry of the departed release go"
    );
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        lock(&[KEPT.recorded()], &after_departure(case)),
        "{case}: the lock's record follows the file"
    );
}

// ── scan, hosted mode, no extra flag ─────────────────────────────────────

/// (1, 5a, 5b, 5g) A hosted scan with no extra flag reconciles the route:
/// once a dependency was removed, or upgraded past the patched release,
/// its override leaves pnpm-workspace.yaml and the lock's record together
/// and its registry goes with it, while the release still
/// patched stays routed. The envelope lists each entry; a dry run lists
/// the same and writes nothing; a second scan finds nothing to do. No `gc`
/// is reported without `--prune`.
#[tokio::test]
async fn scan_takes_out_what_a_departed_dependency_left() {
    for (_, case) in departures() {
        let server = MockServer::start().await;
        mock_api(&server, &[&KEPT], &[]).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (workspace, lock_text) = departed_project(root, case);

        let (code, doc) = scan_hosted(root, &server, &["--dry-run"]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(entries(&doc, "verified"), gone_entries(), "{case}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

        let (code, doc) = scan_hosted(root, &server, &[]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(entries(&doc, "removed"), gone_entries(), "{case}: {doc}");
        assert_gone_cleaned(root, case);
        assert!(doc.get("gc").is_none(), "no --prune, no `gc`: {doc}");
        let rewritten = doc["redirect"]["rewrittenFiles"].as_array().unwrap();
        for file in ["pnpm-lock.yaml", "pnpm-workspace.yaml"] {
            assert!(rewritten.iter().any(|f| f == file), "{case} {file}: {doc}");
        }
        assert!(!root.join(".socket").exists(), "{case}: no residue");

        let (code, doc) = scan_hosted(root, &server, &[]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(entries(&doc, "removed"), [], "{case}: {doc}");
        assert_gone_cleaned(root, case);
    }
}

/// (1, 5c, 5g) A withdrawn patch: the scan puts the release back on the
/// public registry (its lock key plain again, the upstream resolution, the
/// importer's specifier from package.json) and takes its override, the
/// lock's record of it and its registry out in the same run.
/// The patch still served stays routed. A dry run writes nothing.
#[tokio::test]
async fn scan_takes_out_the_entries_of_a_withdrawn_patch() {
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT], &[&GONE]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    write_project(
        root,
        &[GONE.upstream(), KEPT.upstream()],
        Some(&workspace),
        &lock_text,
    );

    let (code, doc) = scan_hosted(root, &server, &["--dry-run"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

    let (code, doc) = scan_hosted(root, &server, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(
        read(root, "pnpm-workspace.yaml").unwrap(),
        created(&[&KEPT])
    );
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        lock(&[KEPT.recorded()], &[GONE.upstream(), KEPT.routed()])
    );
    let restored = doc["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "rolledBack")
        .unwrap_or_else(|| panic!("the restored pin is reported: {doc}"));
    assert_eq!(restored["purl"], GONE.purl(), "{doc}");
    assert_eq!(restored["errorCode"], "patch_withdrawn", "{doc}");
    assert!(!root.join(".socket").exists(), "no residue");
}

/// (1, 5d, 5g) Once no patch is hosted any more a scan leaves no alias, no
/// override of ours and no registry key: after every patched dependency
/// was upgraded, after every patch was withdrawn, and in a project left
/// with no dependency at all. A file of the user's is back to their bytes,
/// and the file a routed scan created is deleted in the same run, in every
/// one of those cases: also when the last routed package left the lock
/// while other, unpatched packages are still crawled, where the rewrite
/// can only write the file back as a bare `packages` list and the scan
/// removes it once the writes have landed.
#[tokio::test]
async fn scan_leaves_nothing_of_the_route_once_no_patch_is_hosted() {
    const USER: &str = "packages:\n  - 'apps/*'\noverrides:\n  lodash: ^4.17.21\n";
    let users_file = format!(
        "{USER}  'gone-pkg@2.0.0': '{}:2.0.0'\n  'kept-pkg@1.0.0': '{}:1.0.0'\n\
         namedRegistries:\n  {}: {}\n  {}: {}\n",
        GONE.alias,
        KEPT.alias,
        KEPT.alias,
        KEPT.address(),
        GONE.alias,
        GONE.address()
    );
    let users_recorded = || -> Vec<String> {
        std::iter::once("lodash: ^4.17.21".to_string())
            .chain(both_recorded())
            .collect()
    };

    // Every patched dependency was upgraded to a release with no patch.
    for (workspace, recorded, left, left_recorded) in [
        (created(&[&KEPT, &GONE]), both_recorded(), None, vec![]),
        (
            users_file.clone(),
            users_recorded(),
            Some(USER),
            vec!["lodash: ^4.17.21".to_string()],
        ),
    ] {
        let server = MockServer::start().await;
        mock_api(&server, &[], &[]).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let upgraded = || {
            vec![
                Dep::plain("gone-pkg", "2.1.0"),
                Dep::plain("kept-pkg", "1.0.1"),
            ]
        };
        let lock_text = lock(&recorded, &upgraded());
        write_project(root, &upgraded(), Some(&workspace), &lock_text);

        let (code, doc) = scan_hosted(root, &server, &["--dry-run"]);
        assert_eq!(code, Some(0), "{doc}");
        assert_eq!(entries(&doc, "verified"), all_entries(), "{doc}");
        assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

        let (code, doc) = scan_hosted(root, &server, &[]);
        assert_eq!(code, Some(0), "{doc}");
        assert_eq!(entries(&doc, "removed"), all_entries(), "{doc}");
        assert_eq!(
            read(root, "pnpm-workspace.yaml").as_deref(),
            left,
            "the created file is gone, the user's is their bytes: {doc}"
        );
        assert_eq!(
            read(root, "pnpm-lock.yaml").unwrap(),
            lock(&left_recorded, &upgraded())
        );
        assert!(
            doc["warnings"]
                .as_array()
                .is_none_or(|ws| ws.iter().all(|w| w["code"] != "registry_cleanup_failed")),
            "{doc}"
        );
        // Nothing left to do, and nothing comes back.
        let (code, doc) = scan_hosted(root, &server, &[]);
        assert_eq!(code, Some(0), "{doc}");
        assert_eq!(entries(&doc, "removed"), [], "{doc}");
        assert_eq!(read(root, "pnpm-workspace.yaml").as_deref(), left);
    }

    // Every patch was withdrawn: both pins are restored, and the file the
    // route created goes with the last of them.
    let server = MockServer::start().await;
    mock_api(&server, &[], &[&KEPT, &GONE]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    let installed = || vec![GONE.upstream(), KEPT.upstream()];
    write_project(root, &installed(), Some(&workspace), &lock_text);
    let (code, doc) = scan_hosted(root, &server, &["--dry-run"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");
    let (code, doc) = scan_hosted(root, &server, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(read(root, "pnpm-workspace.yaml"), None, "{doc}");
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        lock(&[], &installed())
    );

    // The project's last dependency was removed: the scan crawls nothing,
    // and still takes the route out, from the lockfile alone.
    let server = MockServer::start().await;
    mock_api(&server, &[], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lock_text = lock(&both_recorded(), &[]);
    write_project(root, &[], Some(&workspace), &lock_text);
    let (code, doc) = scan_hosted(root, &server, &["--dry-run"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "verified"), all_entries(), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");
    let (code, doc) = scan_hosted(root, &server, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), all_entries(), "{doc}");
    assert_eq!(read(root, "pnpm-workspace.yaml"), None, "{doc}");
    assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), lock(&[], &[]));
    assert_eq!(
        doc["redirect"]["rewrittenFiles"],
        json!(["pnpm-lock.yaml", "pnpm-workspace.yaml"]),
        "{doc}"
    );
    assert!(!root.join(".socket").exists(), "no residue");
}

// ── scan --prune ─────────────────────────────────────────────────────────

/// (2, 5f, 5g) `--prune` in hosted mode: the hosted scan has already taken
/// the unused registry entries out, and with the flag the envelope's `gc`
/// counts them. The warning no longer says the flag has no effect: it says
/// which state the flag does not sweep in this mode, and that the registry
/// entries go on every hosted run. A dry run counts what would go.
#[tokio::test]
async fn hosted_prune_reports_the_registry_entries_it_removed() {
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    let gc = |removed: u64| {
        json!({
            "removedBlobs": 0,
            "removedDiffArchives": 0,
            "removedPackageArchives": 0,
            "bytesFreed": 0,
            "removedRegistryEntries": removed,
        })
    };
    let prune_warning = |doc: &Value| -> String {
        doc["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "redirect_prune_ignored")
            .and_then(|w| w["detail"].as_str())
            .unwrap_or_else(|| panic!("redirect_prune_ignored: {doc}"))
            .to_string()
    };

    let (code, doc) = scan_hosted(root, &server, &["--prune", "--dry-run"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "verified"), gone_entries(), "{doc}");
    assert_eq!(doc["gc"], gc(3), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

    let (code, doc) = scan_hosted(root, &server, &["--prune"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_eq!(doc["gc"], gc(3), "{doc}");
    assert_gone_cleaned(root, "removed");
    let detail = prune_warning(&doc);
    assert!(
        detail.contains("sweeps no `.socket/` state")
            && detail.contains("already removes the pnpm registry entries")
            && !detail.contains("no effect"),
        "{detail}"
    );

    // Nothing left to remove: the count says so.
    let (code, doc) = scan_hosted(root, &server, &["--prune"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(doc["gc"], gc(0), "{doc}");
    assert_gone_cleaned(root, "removed");
}

/// (2, 5f, 5g) `scan --prune` with no `--mode` is the report-only scan plus
/// the GC pass. In a project whose patches are hosted that pass has no
/// `.socket/` state to sweep, and takes the unused registry entries out
/// from the lockfiles alone, reported in `gc` like its other sweeps.
#[tokio::test]
async fn prune_with_no_mode_removes_unused_registry_entries() {
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "upgraded");

    let (code, doc) = run_json(&mut scan_command(
        root,
        &server,
        &["--prune", "--json", "--dry-run"],
    ));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "verified"), gone_entries(), "{doc}");
    assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

    let (code, doc) = run_json(&mut scan_command(root, &server, &["--prune", "--json"]));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{doc}");
    assert_eq!(doc["gc"]["removedBlobs"], 0, "{doc}");
    assert_gone_cleaned(root, "upgraded");
    assert!(
        doc.get("redirect").is_none(),
        "not a hosted run: the lock entries were left to the GC pass: {doc}"
    );
    assert!(!root.join(".socket").exists(), "no residue");
}

// ── repair ───────────────────────────────────────────────────────────────

/// (3, 5e, 5g) `repair`'s cleanup phase takes the unused registry entries
/// out with no patch service to ask (`--offline`, and an API address
/// nothing listens on): a dependency that was removed or upgraded, in a
/// project whose only patch state is hosted. The envelope lists each entry
/// beside the usual hosted-only note and counts them in `gc`; a dry run
/// lists the same and writes nothing; `.socket/` is never left behind.
#[tokio::test]
async fn repair_takes_out_what_a_departed_dependency_left() {
    for (_, case) in departures() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (workspace, lock_text) = departed_project(root, case);

        let (code, doc) = repair_offline(root, &["--dry-run"]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(entries(&doc, "verified"), gone_entries(), "{case}: {doc}");
        assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{case}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");
        assert!(
            !root.join(".socket").exists(),
            "{case}: a preview locks nothing"
        );

        let (code, doc) = repair_offline(root, &[]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(doc["status"], "success", "{case}: {doc}");
        assert_eq!(entries(&doc, "removed"), gone_entries(), "{case}: {doc}");
        assert_eq!(
            doc["gc"],
            json!({
                "removedBlobs": 0,
                "removedDiffArchives": 0,
                "removedPackageArchives": 0,
                "bytesFreed": 0,
                "removedRegistryEntries": 3,
            }),
            "{case}: {doc}"
        );
        assert_eq!(
            doc["summary"]["removed"], 0,
            "entries are not patches: {doc}"
        );
        assert!(
            doc["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "skipped" && e["errorCode"] == "redirect_only_project"),
            "{case}: the hosted-only note stays: {doc}"
        );
        assert_gone_cleaned(root, case);
        assert!(!root.join(".socket").exists(), "{case}: no residue");

        // Nothing more to take out, and nothing is locked for it.
        let (code, doc) = repair_offline(root, &[]);
        assert_eq!(code, Some(0), "{case}: {doc}");
        assert_eq!(entries(&doc, "removed"), [], "{case}: {doc}");
        assert_eq!(doc["gc"]["removedRegistryEntries"], 0, "{case}: {doc}");
        assert_gone_cleaned(root, case);
    }
}

/// (3, 5d through repair, 5g) With no release routed any more `repair`
/// leaves nothing of the route: the file a routed scan created is deleted,
/// a file of the user's is back to their bytes, and the lock's
/// `overrides:` records go, exactly what a hosted scan leaves. That
/// holds for a project with no hosted pin left at all, which `repair` used
/// to answer with `manifest_not_found`.
#[tokio::test]
async fn repair_leaves_nothing_of_a_route_no_lock_uses() {
    const USER: &str = "packages:\n  - 'apps/*'\ncatalog:\n  react: ^19.0.0\n";
    for user in [None, Some(USER)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let workspace = match user {
            None => created(&[&KEPT, &GONE]),
            Some(user) => format!("{user}{}", maps(&[&KEPT, &GONE])),
        };
        let upgraded = || {
            vec![
                Dep::plain("gone-pkg", "2.1.0"),
                Dep::plain("kept-pkg", "1.0.1"),
            ]
        };
        let lock_text = lock(&both_recorded(), &upgraded());
        write_project(root, &upgraded(), Some(&workspace), &lock_text);

        let (code, doc) = repair_offline(root, &["--dry-run"]);
        assert_eq!(code, Some(0), "{user:?}: {doc}");
        assert_eq!(entries(&doc, "verified"), all_entries(), "{user:?}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

        let (code, doc) = repair_offline(root, &[]);
        assert_eq!(code, Some(0), "{user:?}: {doc}");
        assert_eq!(entries(&doc, "removed"), all_entries(), "{user:?}: {doc}");
        assert_eq!(doc["gc"]["removedRegistryEntries"], 6, "{user:?}: {doc}");
        assert_eq!(read(root, "pnpm-workspace.yaml").as_deref(), user);
        let cleaned = lock(&[], &upgraded());
        assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), cleaned);
        assert!(
            !cleaned.contains("socket"),
            "no alias, override or key is left"
        );
        assert!(!root.join(".socket").exists(), "{user:?}: no residue");
    }
}

/// (3) What `repair` must not touch. A release a lock still routes keeps
/// everything it needs: `repair` asks no patch service, so a patch that
/// was withdrawn is the next scan's to restore. The user's own registry
/// under our name, and their overrides, stay byte for byte. And
/// `--download-only`, which skips the cleanup phase, skips this too.
#[tokio::test]
async fn repair_keeps_what_is_used_and_what_is_the_users() {
    // Both releases still routed.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    write_project(
        root,
        &[GONE.upstream(), KEPT.upstream()],
        Some(&workspace),
        &lock_text,
    );
    let (code, doc) = repair_offline(root, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), [], "{doc}");
    assert_eq!(doc["gc"]["removedRegistryEntries"], 0, "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "every entry is in use");

    // A registry of the user's under the very name ours would take,
    // somewhere else, and an override of it.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let users =
        "packages:\n  - '.'\nnamedRegistries:\n  socket-bbbbbbbb: https://npm.work.example/\n\
                 overrides:\n  'gone-pkg@2.0.0': 'socket-bbbbbbbb:2.0.0'\n";
    let lock_text = lock(&[GONE.recorded()], &[Dep::plain("gone-pkg", "2.1.0")]);
    write_project(
        root,
        &[Dep::plain("gone-pkg", "2.1.0")],
        Some(users),
        &lock_text,
    );
    let (code, doc) = repair_offline(root, &[]);
    assert_eq!(entries(&doc, "removed"), [], "{code:?}: {doc}");
    assert_unchanged(root, users, &lock_text, "the user's entries stay");

    // `--download-only` skips the cleanup phase.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    let (code, doc) = run_json(&mut repair_command(root, &["--download-only", "--json"]));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), [], "{doc}");
    assert!(doc.get("gc").is_none(), "no cleanup phase, no `gc`: {doc}");
    assert_unchanged(
        root,
        &workspace,
        &lock_text,
        "--download-only cleans nothing",
    );
}

/// (3) A project with agent-mode state beside its hosted patches: the
/// registry cleanup is part of the same cleanup phase as the `.socket/`
/// sweeps, and counted in the same `gc`.
#[tokio::test]
async fn repair_cleans_the_route_beside_a_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    departed_project(root, "removed");
    std::fs::create_dir_all(root.join(".socket")).unwrap();
    std::fs::write(root.join(".socket/manifest.json"), r#"{"patches": {}}"#).unwrap();

    let (code, doc) = repair_offline(root, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_eq!(
        doc["gc"],
        json!({
            "removedBlobs": 0,
            "removedDiffArchives": 0,
            "removedPackageArchives": 0,
            "bytesFreed": 0,
            "removedRegistryEntries": 3,
        }),
        "{doc}"
    );
    assert_gone_cleaned(root, "removed");
}

// ── a run granted only part of the project's patches ─────────────────────

/// A scan the patch service grants only some of the routed patches (a
/// scan of one subtree, a search that lists fewer patches than the lock
/// pins) leaves the others routed: nothing is rewritten, the project
/// stays off `trustLockfile`, and no registry entry is reported removed.
/// The release it was not granted keeps the registry the files already
/// route it through.
#[tokio::test]
async fn a_scan_granted_part_of_the_patches_leaves_the_rest_routed() {
    let server = MockServer::start().await;
    // Only GONE's patch is offered and granted; KEPT's is not mentioned.
    mock_api(&server, &[&GONE], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    write_project(
        root,
        &[GONE.upstream(), KEPT.upstream()],
        Some(&workspace),
        &lock_text,
    );

    for extra in [&["--dry-run"][..], &[]] {
        let (code, doc) = scan_hosted(root, &server, extra);
        assert_eq!(code, Some(0), "{extra:?}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "both releases stay routed");
        assert_eq!(
            doc["events"].as_array().map_or(0, |events| {
                events
                    .iter()
                    .filter(|e| e["errorCode"] == "registry_entry_unused")
                    .count()
            }),
            0,
            "{extra:?}: {doc}"
        );
        let said = doc["warnings"].to_string();
        assert!(
            !said.contains("no registry address") && !said.contains("rely on `trustLockfile`"),
            "{extra:?}: {doc}"
        );
        assert!(
            doc["redirect"]["rewrittenFiles"]
                .as_array()
                .is_none_or(|files| files.is_empty()),
            "{extra:?}: {doc}"
        );
    }
}

/// A hosted scan that selects no patch tidies the route only when it can
/// take the apply lock. In a checkout it cannot write (the lock's
/// directory cannot be created) the scan still succeeds, changes nothing
/// and reports nothing removed: the entries wait for the next scan. A run
/// with nothing else to do is not failed for housekeeping.
#[cfg(unix)]
#[tokio::test]
async fn a_scan_that_cannot_take_the_lock_leaves_the_route_for_the_next_scan() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mock_api(&server, &[], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    let writable = std::fs::metadata(root).unwrap().permissions();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Not a check a privileged user can make: nothing is read-only to it.
    let read_only = std::fs::create_dir(root.join(".probe")).is_err();
    let ran = read_only.then(|| scan_hosted(root, &server, &[]));
    std::fs::set_permissions(root, writable).unwrap();
    let Some((code, doc)) = ran else {
        let _ = std::fs::remove_dir(root.join(".probe"));
        return;
    };
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), [], "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "nothing is written");

    // The next scan, with the lock to be had, takes the entries out.
    let (code, doc) = scan_hosted(root, &server, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
}

// ── a patch server the run was not told of ───────────────────────────────

/// What a cleanup command says of the fixtures' two registries when it was
/// not told that [`HOST`] is a patch server.
const PASSED_OVER: &str = "2 pnpm registries of hosted patches on https://patch.test were left \
     alone: this run was not given that host as a patch server, so it cannot tell those \
     registries from the project's own; pass `--patch-server-url https://patch.test` (or set \
     SOCKET_PATCH_SERVER_URL) to let this command tidy what no lockfile uses of them";

/// The details of the envelope's `registry_cleanup_unknown_host` warnings.
fn passed_over(doc: &Value) -> Vec<String> {
    doc["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "registry_cleanup_unknown_host")
        .map(|w| w["detail"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The commands that tidy a route from the files alone know a patch server
/// only when it is Socket's or the run was told of it. A route on any
/// other host is left alone, as a registry of the project's own would be,
/// and the command says so instead of doing nothing without a word: which
/// host (its origin, never the address, which holds the grant's token),
/// how many registries, and the setting that lets it tidy them. `--json`
/// carries it as a `registry_cleanup_unknown_host` warning and a person
/// reads one line, from `repair`, from the `--prune` pass and from a
/// hosted scan that crawled no package. Told of the host, the same
/// command tidies the project and has nothing to say.
#[tokio::test]
async fn cleanup_says_when_it_leaves_a_route_on_an_unknown_host_alone() {
    // What a run printed, both streams, which never hold a grant's token.
    let printed = |cmd: &mut std::process::Command| {
        let out = cmd.output().expect("run socket-patch");
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        );
        for patch in [&KEPT, &GONE] {
            assert!(
                !stdout.contains(patch.token) && !stderr.contains(patch.token),
                "{stdout}\n{stderr}"
            );
        }
        (out.status.code(), stdout, stderr)
    };
    let server = MockServer::start().await;
    mock_api(&server, &[], &[]).await;

    // `repair`, dry and wet: nothing is removed, and it says why.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    for extra in [
        &["--offline", "--json", "--dry-run"][..],
        &["--offline", "--json"],
    ] {
        let (code, stdout, _) = printed(&mut repair_command_told(root, extra, None));
        let doc: Value = serde_json::from_str(&stdout).expect("the JSON envelope");
        assert_eq!(code, Some(0), "{extra:?}: {doc}");
        assert_eq!(passed_over(&doc), [PASSED_OVER], "{extra:?}: {doc}");
        assert_eq!(doc["events"].as_array().map_or(0, Vec::len), 1, "{doc}");
        assert_unchanged(root, &workspace, &lock_text, "the route is left alone");
    }
    let (code, stdout, stderr) = printed(&mut repair_command_told(root, &["--offline"], None));
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert_eq!(stderr, format!("Warning: {PASSED_OVER}\n"));
    assert!(
        stdout.contains("Hosted patches need no local repair"),
        "{stdout}"
    );

    // The `--prune` pass of a scan in no mode.
    let prune = |extra: &[&str]| {
        let mut args = vec!["--prune"];
        args.extend_from_slice(extra);
        scan_command_told(root, &server, &args, None)
    };
    let (code, stdout, _) = printed(&mut prune(&["--json"]));
    let doc: Value = serde_json::from_str(&stdout).expect("the JSON envelope");
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(passed_over(&doc), [PASSED_OVER], "{doc}");
    assert_eq!(doc["gc"]["removedRegistryEntries"], 0, "{doc}");
    let (code, stdout, stderr) = printed(&mut prune(&[]));
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!("GC: {PASSED_OVER}.\n")),
        "{stdout}\n{stderr}"
    );
    assert_unchanged(root, &workspace, &lock_text, "the route is left alone");

    // A hosted scan that crawls no package: its rewrite never runs, so
    // the same tidying from the files does, and says the same.
    let bare = tempfile::tempdir().unwrap();
    let no_deps_lock = lock(&both_recorded(), &[]);
    write_project(bare.path(), &[], Some(&workspace), &no_deps_lock);
    let (code, stdout, _) = printed(&mut scan_command_told(
        bare.path(),
        &server,
        &["--mode", "hosted", "--json"],
        None,
    ));
    let doc: Value = serde_json::from_str(&stdout).expect("the JSON envelope");
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(passed_over(&doc), [PASSED_OVER], "{doc}");
    assert_unchanged(bare.path(), &workspace, &no_deps_lock, "left alone");

    // Told of the host through the environment, `repair` tidies the
    // project and passes nothing over.
    let mut told = repair_command_told(root, &["--offline", "--json"], None);
    let (code, doc) = run_json(told.env("SOCKET_PATCH_SERVER_URL", HOST));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_eq!(passed_over(&doc), [] as [&str; 0], "{doc}");
    assert_gone_cleaned(root, "removed");
}

// ── a patch mirror ───────────────────────────────────────────────────────

/// The path of the patch mirror's base on the mock server.
const MIRROR_PREFIX: &str = "/artifactory/socket-patch";

/// Where the mirror at `base` serves `patch`'s tarball: the patch server's
/// own path under the base.
fn mirrored_url(base: &str, patch: &Patch) -> String {
    format!(
        "{base}{}",
        patch.url().strip_prefix(HOST).expect("a served URL")
    )
}

/// A hosted scan given a patch mirror (`--patch-mirror-url`) over a project
/// an earlier run routed. The pins move onto the mirror, which serves no
/// registry a mirrored tarball could be verified against, so the route
/// goes in the same run: both registries (still recognised as the patch
/// server's, with the mirror configured), both overrides, the lock's
/// records and its registry keys. What is left is the project a mirror
/// run makes on `trustLockfile`, the run says it was the mirror that kept
/// the project off the route, and a dry run writes nothing.
#[tokio::test]
async fn a_patch_mirror_takes_a_routed_project_off_the_route() {
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT, &GONE], &[]).await;
    // The mirror serves both patches.
    Mock::given(method("HEAD"))
        .and(path_regex(format!("^{MIRROR_PREFIX}/patch/npm/.+\\.tgz$")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let base = format!("{}{MIRROR_PREFIX}", server.uri());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    write_project(
        root,
        &[GONE.upstream(), KEPT.upstream()],
        Some(&workspace),
        &lock_text,
    );
    let mirror = ["--patch-mirror-url", base.as_str()];

    let (code, doc) = scan_hosted(root, &server, &[mirror[0], mirror[1], "--dry-run"]);
    assert_eq!(code, Some(0), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");

    let (code, doc) = scan_hosted(root, &server, &mirror);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(
        read(root, "pnpm-workspace.yaml").as_deref(),
        Some("packages:\n  - '.'\ntrustLockfile: true\n"),
        "{doc}"
    );
    let mut on_the_mirror = lock(&[], &[GONE.upstream(), KEPT.upstream()]);
    for patch in [&GONE, &KEPT] {
        let entry = format!("\n  {}:\n    resolution: ", patch.release());
        on_the_mirror = on_the_mirror.replacen(
            &format!("{entry}{{integrity: {UPSTREAM}}}"),
            &format!(
                "{entry}{{integrity: {PATCHED}, tarball: {}}}",
                mirrored_url(&base, patch)
            ),
            1,
        );
    }
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        on_the_mirror,
        "{doc}"
    );
    let removed = entries(&doc, "removed");
    for gone in all_entries() {
        assert!(removed.contains(&gone), "{gone:?}: {doc}");
    }
    let applied = doc["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["action"] == "applied" && e["details"]["mode"] == "hosted")
        .count();
    assert_eq!(applied, 2, "both pins are confirmed on the mirror: {doc}");
    let said = doc["warnings"].to_string();
    assert!(
        said.contains("the patch mirror serves no registry for gone-pkg@2.0.0, kept-pkg@1.0.0")
            && !said.contains("gave no registry address"),
        "{doc}"
    );

    // Nothing is left to move or to tidy.
    let (code, doc) = scan_hosted(root, &server, &mirror);
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), [], "{doc}");
    assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), on_the_mirror);
    assert!(
        doc["redirect"]["rewrittenFiles"]
            .as_array()
            .is_none_or(|files| files.is_empty()),
        "{doc}"
    );
}

/// With a patch mirror configured for the machine (`SOCKET_PATCH_MIRROR_URL`)
/// the commands that tidy a route from the files alone still know it: its
/// registries are on the patch server, not under the mirror's base, and
/// the entries a departed dependency left go as without the mirror, from
/// `repair --offline` and from `scan --prune`.
#[tokio::test]
async fn cleanup_knows_a_route_with_a_patch_mirror_configured() {
    const MIRROR: (&str, &str) = (
        "SOCKET_PATCH_MIRROR_URL",
        "https://repo.example/artifactory/socket-patch",
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    let mut dry = repair_command(root, &["--offline", "--json", "--dry-run"]);
    let (code, doc) = run_json(dry.env(MIRROR.0, MIRROR.1));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "verified"), gone_entries(), "{doc}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");
    let mut wet = repair_command(root, &["--offline", "--json"]);
    let (code, doc) = run_json(wet.env(MIRROR.0, MIRROR.1));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_gone_cleaned(root, "removed");

    let server = MockServer::start().await;
    mock_api(&server, &[], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    departed_project(root, "removed");
    let mut prune = scan_command(root, &server, &["--prune", "--json"]);
    let (code, doc) = run_json(prune.env(MIRROR.0, MIRROR.1));
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(entries(&doc, "removed"), gone_entries(), "{doc}");
    assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{doc}");
    assert_gone_cleaned(root, "removed");
}

// ── leaving hosted mode for agent mode ───────────────────────────────────

/// A routed project scanned in agent mode keeps its route. An agent run
/// patches installed files and unwinds no hosted lockfile wiring, so the
/// lock still installs both releases through the registry and every entry
/// is in use: nothing is removed, with or without `--prune`, and the run
/// says the hosted wiring is still live (`hosted_wiring_retained`) and how
/// to leave it. `rollback` / `remove` (above) are what take a pin and its
/// route out together.
#[tokio::test]
async fn agent_mode_leaves_the_route_of_live_hosted_pins() {
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT, &GONE], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace = created(&[&KEPT, &GONE]);
    let lock_text = lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]);
    write_project(
        root,
        &[GONE.upstream(), KEPT.upstream()],
        Some(&workspace),
        &lock_text,
    );

    for extra in [
        &["--mode", "agent", "--json", "--dry-run"][..],
        &["--mode", "agent", "--prune", "--json", "--dry-run"],
        &["--sync", "--json", "--dry-run"],
    ] {
        let (code, doc) = run_json(&mut scan_command(root, &server, extra));
        assert_eq!(code, Some(0), "{extra:?}: {doc}");
        assert_eq!(entries(&doc, "verified"), [], "{extra:?}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "every entry is in use");
        let retained = doc["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "hosted_wiring_retained")
            .and_then(|w| w["detail"].as_str())
            .unwrap_or_else(|| panic!("{extra:?}: hosted_wiring_retained: {doc}"));
        for patch in [&KEPT, &GONE] {
            assert!(retained.contains(&patch.purl()), "{extra:?}: {retained}");
        }
        assert!(
            retained.contains("socket-patch rollback") && retained.contains("scan --mode vendored"),
            "{retained}"
        );
        if extra.contains(&"--prune") || extra.contains(&"--sync") {
            assert_eq!(doc["gc"]["removedRegistryEntries"], 0, "{extra:?}: {doc}");
        }
    }
}

// ── remove and rollback ──────────────────────────────────────────────────

/// `remove <purl>` / `rollback <purl>` with the npm registry at `server`.
fn unwind(
    cwd: &Path,
    server: &MockServer,
    command: &str,
    targets: &[&str],
) -> (Option<i32>, Value) {
    let mut cmd = hermetic::binary_command();
    cmd.env_remove("npm_config_registry")
        .env_remove("NPM_CONFIG_REGISTRY")
        .env(
            "SOCKET_NPM_REGISTRY",
            format!("{}/npm-registry", server.uri()),
        )
        .arg(command)
        .args(targets)
        .args([
            "--json",
            "--yes",
            "--patch-server-url",
            HOST,
            "--cwd",
            cwd.to_str().unwrap(),
        ]);
    run_json(&mut cmd)
}

/// The user ran `remove` (or `rollback`) on one patched package: its
/// release is back on the public registry, and its override, the lock's
/// record of it and its registry go in the same
/// run, with no scan in between. The other package stays routed. Taking
/// that one out too leaves the pristine lock and no workspace file.
#[tokio::test]
async fn remove_and_rollback_take_a_package_and_its_registry_out() {
    for command in ["remove", "rollback"] {
        let server = MockServer::start().await;
        mock_api(&server, &[], &[]).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_project(
            root,
            &[GONE.upstream(), KEPT.upstream()],
            Some(&created(&[&KEPT, &GONE])),
            &lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]),
        );

        let (code, doc) = unwind(root, &server, command, &[&GONE.purl()]);
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(
            read(root, "pnpm-workspace.yaml").unwrap(),
            created(&[&KEPT]),
            "{command}: the override and the registry go with the package"
        );
        assert_eq!(
            read(root, "pnpm-lock.yaml").unwrap(),
            lock(&[KEPT.recorded()], &[GONE.upstream(), KEPT.routed()]),
            "{command}"
        );

        let (code, doc) = unwind(root, &server, command, &[&KEPT.purl()]);
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(read(root, "pnpm-workspace.yaml"), None, "{command}: {doc}");
        assert_eq!(
            read(root, "pnpm-lock.yaml").unwrap(),
            lock(&[], &[GONE.upstream(), KEPT.upstream()]),
            "{command}"
        );
    }
}

// ── members' own locks ───────────────────────────────────────────────────

/// A file of the golden project `member-locks`, a workspace that keeps one
/// lock per member (`sharedWorkspaceLockfile: false`): under `project/` as
/// pnpm locked it, under `expected/` as the scan routed it.
fn member_golden(rel: &str) -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/pnpm-registry-overrides/member-locks");
    std::fs::read_to_string(dir.join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
        .replace("\r\n", "\n")
}

const MEMBER_FILES: [&str; 7] = [
    "package.json",
    "pnpm-workspace.yaml",
    "pnpm-lock.yaml",
    "packages/a/package.json",
    "packages/a/pnpm-lock.yaml",
    "packages/b/package.json",
    "packages/b/pnpm-lock.yaml",
];

/// That workspace with the route taken out by hand everywhere but in
/// `routed`, which are as the scan wrote them.
fn member_project(root: &Path, routed: &[&str]) {
    for rel in MEMBER_FILES {
        let from = match routed.contains(&rel) {
            true => "expected",
            false => "project",
        };
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, member_golden(&format!("{from}/{rel}"))).unwrap();
    }
}

/// What is left of a route can be in a member's own lock alone, with the
/// root pnpm-workspace.yaml and the root lock holding nothing of it. The
/// commands that tidy a route look there too: `repair`, `scan --prune` and
/// a hosted scan that crawls no package each take out a lock's record of an
/// override that no lock of the workspace uses any more, and the project is
/// then the one pnpm locked, byte for byte. A release a member's lock
/// still routes is no leftover: none of the three restores a pin, so its
/// key and its record stay as they are.
#[tokio::test]
async fn cleanup_finds_what_a_route_left_in_a_members_own_lock() {
    const A: &str = "packages/a/pnpm-lock.yaml";
    const B: &str = "packages/b/pnpm-lock.yaml";
    let server = MockServer::start().await;
    mock_api(&server, &[], &[]).await;
    let run = |command: &str, root: &Path| match command {
        "repair" => repair_offline(root, &[]),
        "scan --prune" => run_json(&mut scan_command(root, &server, &["--prune", "--json"])),
        _ => scan_hosted(root, &server, &[]),
    };
    for command in ["repair", "scan --prune", "scan --mode hosted"] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        member_project(root, &[B]);
        let (code, doc) = run(command, root);
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(
            entries(&doc, "removed"),
            [entry(B, "lockOverride", "leaf@1.0.0")],
            "{command}: {doc}"
        );
        for rel in MEMBER_FILES {
            assert_eq!(
                read(root, rel).unwrap(),
                member_golden(&format!("project/{rel}")),
                "{command}: {rel}"
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        member_project(root, &[A]);
        let (code, doc) = run(command, root);
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(entries(&doc, "removed"), [], "{command}: {doc}");
        for rel in MEMBER_FILES {
            let from = if rel == A { "expected" } else { "project" };
            assert_eq!(
                read(root, rel).unwrap(),
                member_golden(&format!("{from}/{rel}")),
                "{command}: {rel}"
            );
        }
    }
}

// ── a Bazel workspace ────────────────────────────────────────────────────

/// A rules_js hub that keeps the project's pnpm lock up to date with a
/// pnpm 11 that does not see pnpm-workspace.yaml: hosted mode pins nothing
/// in that lock (`redirect_pnpm_bazel_workspace_hidden`).
const HIDING_HUB: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True)\n\
    pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
    pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n";

/// A project routed before its Bazel workspace got such a hub. A hosted
/// scan leaves the lock to the hub, so it takes nothing of the route out
/// either: the workspace file and the lock stay as they were, in step with
/// each other, and the warning says why nothing was rewritten. The
/// commands that settle a route from the lockfiles alone pin nothing, and
/// work as without the hub, the file and the lock's record together:
/// `repair`, `scan --prune` with no mode, `remove` and `rollback`.
#[tokio::test]
async fn cleanup_in_a_bazel_workspace_whose_hub_hides_the_workspace_file() {
    let hub = |root: &Path| std::fs::write(root.join("MODULE.bazel"), HIDING_HUB).unwrap();
    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT], &[]).await;

    for extra in [&[][..], &["--prune"]] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (workspace, lock_text) = departed_project(root, "removed");
        hub(root);
        let (code, doc) = scan_hosted(root, &server, extra);
        assert_eq!(code, Some(0), "{extra:?}: {doc}");
        let warned = doc["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "redirect_pnpm_bazel_workspace_hidden");
        assert!(warned, "{extra:?}: {doc}");
        assert_eq!(entries(&doc, "removed"), [], "{extra:?}: {doc}");
        assert_unchanged(root, &workspace, &lock_text, "the lock is left to the hub");
    }

    for command in ["repair", "scan --prune"] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        departed_project(root, "removed");
        hub(root);
        let (code, doc) = match command {
            "repair" => repair_offline(root, &[]),
            _ => run_json(&mut scan_command(root, &server, &["--prune", "--json"])),
        };
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(entries(&doc, "removed"), gone_entries(), "{command}: {doc}");
        assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{command}: {doc}");
        assert_gone_cleaned(root, "removed");
    }

    let registry = MockServer::start().await;
    mock_api(&registry, &[], &[]).await;
    for command in ["remove", "rollback"] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_project(
            root,
            &[GONE.upstream(), KEPT.upstream()],
            Some(&created(&[&KEPT, &GONE])),
            &lock(&both_recorded(), &[GONE.routed(), KEPT.routed()]),
        );
        hub(root);
        let (code, doc) = unwind(root, &registry, command, &[&GONE.purl()]);
        assert_eq!(code, Some(0), "{command}: {doc}");
        assert_eq!(
            read(root, "pnpm-workspace.yaml").unwrap(),
            created(&[&KEPT]),
            "{command}: the override and the registry go with the package"
        );
        assert_eq!(
            read(root, "pnpm-lock.yaml").unwrap(),
            lock(&[KEPT.recorded()], &[GONE.upstream(), KEPT.routed()]),
            "{command}"
        );
    }
}

/// A hub that keeps the lock up to date with a pnpm 11 and lists the
/// project's pnpm-workspace.yaml as `data`. The file is the one a routed
/// scan created, so it holds nothing but what hosted mode writes, and a
/// run that takes the last of the route out would delete it under the
/// call that names it.
const LISTING_HUB: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\", \
    data = [\"//:pnpm-workspace.yaml\"], update_pnpm_lock = True)\n\
    pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
    pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n";

/// What a hosted scan does with a lock that it leaves to a Bazel hub does
/// not depend on what the scan was granted. With a patch for a package of
/// the lock, with none, and with nothing crawled at all, it rewrites
/// neither the lock nor pnpm-workspace.yaml, and says why. Before, only
/// the first left the files: the other two took the unused entries out, and
/// with the last of them the file that the hub's `data` names.
#[tokio::test]
async fn a_hosted_scan_leaves_a_lock_to_its_bazel_hub_whatever_it_is_granted() {
    let granting = MockServer::start().await;
    mock_api(&granting, &[&KEPT], &[]).await;
    let empty = MockServer::start().await;
    mock_api(&empty, &[], &[]).await;
    let hidden = |doc: &Value| {
        doc["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "redirect_pnpm_bazel_workspace_hidden")
    };
    for hub in [HIDING_HUB, LISTING_HUB] {
        for (granted, server, installed) in [
            ("a patch", &granting, true),
            ("no patch", &empty, true),
            ("nothing crawled", &empty, false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let (workspace, lock_text) = departed_project(root, "removed");
            if !installed {
                std::fs::remove_dir_all(root.join("node_modules")).unwrap();
            }
            std::fs::write(root.join("MODULE.bazel"), hub).unwrap();
            let (code, doc) = scan_hosted(root, server, &[]);
            assert_eq!(code, Some(0), "{granted}: {doc}");
            assert_eq!(entries(&doc, "removed"), [], "{granted}: {doc}");
            assert_unchanged(root, &workspace, &lock_text, granted);
            assert!(hidden(&doc), "{granted}: {doc}");
        }
    }
}

// ── what a person is told ────────────────────────────────────────────────

/// (4) Without `--json` each removal is a line, in `repair` and in a
/// hosted scan, and a dry run says what would go. A registry's address,
/// which carries its grant's token, is not printed.
#[tokio::test]
async fn the_removed_entries_are_listed_for_a_person() {
    let listed = |verb: &str| {
        format!(
            "{verb} 3 pnpm registry entries that no lockfile uses any more:\n  \
             - overrides entry `gone-pkg@2.0.0` of pnpm-lock.yaml\n  \
             - namedRegistries entry `socket-bbbbbbbb` of pnpm-workspace.yaml\n  \
             - overrides entry `gone-pkg@2.0.0` of pnpm-workspace.yaml\n"
        )
    };
    let output = |cmd: &mut std::process::Command| {
        let out = cmd.output().expect("run socket-patch");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for patch in [&KEPT, &GONE] {
            assert!(!text.contains(patch.token), "{text}");
        }
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (workspace, lock_text) = departed_project(root, "removed");
    let (code, stdout) = output(&mut repair_command(root, &["--offline", "--dry-run"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains(&listed("Would remove")), "{stdout}");
    assert_unchanged(root, &workspace, &lock_text, "a dry run writes nothing");
    let (code, stdout) = output(&mut repair_command(root, &["--offline"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains(&listed("Removed")), "{stdout}");
    assert!(
        stdout.contains("Hosted patches need no local repair"),
        "{stdout}"
    );
    assert_gone_cleaned(root, "removed");

    let server = MockServer::start().await;
    mock_api(&server, &[&KEPT], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    departed_project(root, "removed");
    let (code, stdout) = output(&mut scan_command(root, &server, &["--mode", "hosted"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.contains("Removed 3 pnpm registry entries"),
        "{stdout}"
    );
    assert_gone_cleaned(root, "removed");
}
