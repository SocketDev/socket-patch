//! [`sweep_pnpm_registry_route`]: what `repair` and a `--prune` pass take
//! out of a pnpm project's registry route from its files alone.

use std::path::Path;

use super::{sweep_pnpm_registry_route, RestoreOptions, RouteSweep};
use crate::hosted::guidance::pnpm_registry_entries_removed;

const HOST: &str = "https://patch.test";
const TOKEN: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
/// The patches of the fixtures' packages, each with the name its registry
/// takes (`socket-` and the first eight digits of the patch UUID).
const LEAF_UUID: &str = "11111111-1111-4111-8111-111111111111";
const LEAF_ALIAS: &str = "socket-11111111";
const MID_UUID: &str = "22222222-2222-4222-8222-222222222222";
const MID_ALIAS: &str = "socket-22222222";

/// The directory the patch `uuid` of `name@version` is served from: its
/// registry's address.
fn address(name: &str, version: &str, uuid: &str) -> String {
    format!("{HOST}/patch/npm/{name}/{version}/{TOKEN}/{uuid}/")
}

/// One dependency of a [`lock`]: `Some((registry, patch uuid))` when
/// routed through a registry.
struct Dep(
    &'static str,
    &'static str,
    Option<(&'static str, &'static str)>,
);

impl Dep {
    fn version(&self) -> String {
        match self.2 {
            Some((alias, _)) => format!("{alias}:{}", self.1),
            None => self.1.to_string(),
        }
    }

    fn resolution(&self) -> String {
        let Dep(name, version, routed) = self;
        match routed {
            Some((_, uuid)) => format!(
                "{{integrity: sha512-PATCHED==, tarball: {}{name}-{version}.tgz}}",
                address(name, version, uuid)
            ),
            None => "{integrity: sha512-UPSTREAM==}".to_string(),
        }
    }
}

const LEAF_ROUTED: Dep = Dep("leaf", "1.0.0", Some((LEAF_ALIAS, LEAF_UUID)));
const MID_ROUTED: Dep = Dep("mid", "2.0.0", Some((MID_ALIAS, MID_UUID)));

/// A lockfileVersion 9 lock recording `overrides` (`key: value`), its `.`
/// importer depending on `deps`, laid out as pnpm writes one.
fn lock(overrides: &[&str], deps: &[Dep]) -> String {
    let mut text = "lockfileVersion: '9.0'\n\n".to_string();
    if !overrides.is_empty() {
        text.push_str("overrides:\n");
        for entry in overrides {
            text.push_str(&format!("  {entry}\n"));
        }
        text.push('\n');
    }
    text.push_str("importers:\n\n  .:\n    dependencies:\n");
    for dep in deps {
        let version = dep.version();
        text.push_str(&format!(
            "      {}:\n        specifier: {version}\n        version: {version}\n",
            dep.0
        ));
    }
    text.push_str("\npackages:\n");
    for dep in deps {
        text.push_str(&format!(
            "\n  {}@{}:\n    resolution: {}\n",
            dep.0,
            dep.version(),
            dep.resolution()
        ));
    }
    text.push_str("\nsnapshots:\n");
    for dep in deps {
        text.push_str(&format!("\n  {}@{}: {{}}\n", dep.0, dep.version()));
    }
    text
}

/// The lock's records of the overrides that route the two releases.
const LEAF: &str = "leaf@1.0.0: socket-11111111:1.0.0";
const MID: &str = "mid@2.0.0: socket-22222222:2.0.0";

/// The registry lines of the two patches, as the workspace file holds them.
fn leaf_registry() -> String {
    format!("  {LEAF_ALIAS}: {}", address("leaf", "1.0.0", LEAF_UUID))
}

fn mid_registry() -> String {
    format!("  {MID_ALIAS}: {}", address("mid", "2.0.0", MID_UUID))
}

/// The two maps of the route for `registries` (their lines) and
/// `overrides`, as hosted mode writes them.
fn maps(registries: &[String], overrides: &[&str]) -> String {
    let mut text = format!("namedRegistries:\n{}\noverrides:\n", registries.join("\n"));
    for entry in overrides {
        let (key, value) = entry.split_once(": ").expect("key: value");
        text.push_str(&format!("  '{key}': '{value}'\n"));
    }
    text
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("a parent")).unwrap();
    std::fs::write(path, text).unwrap();
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

async fn sweep(root: &Path, dry_run: bool) -> RouteSweep {
    sweep_from(root, dry_run, vec![HOST.to_string()]).await
}

/// [`sweep`] for a run configured with `origins`.
async fn sweep_from(root: &Path, dry_run: bool, origins: Vec<String>) -> RouteSweep {
    let opts = RestoreOptions {
        dry_run,
        offline: true,
        patch_server_origins: origins,
        bun_lockb: false,
    };
    sweep_pnpm_registry_route(root, &opts).await
}

/// `(file, entry, key)` of every entry a sweep took out.
fn removed(swept: &RouteSweep) -> Vec<(String, &'static str, String)> {
    assert_eq!(swept.unread, None);
    assert_eq!(swept.flush_error, None);
    pnpm_registry_entries_removed(&swept.edits)
        .into_iter()
        .map(|entry| (entry.file, entry.kind.as_str(), entry.key))
        .collect()
}

fn entry(file: &str, kind: &'static str, key: &str) -> (String, &'static str, String) {
    (file.to_string(), kind, key.to_string())
}

/// A dependency that left the lock (removed, or upgraded past the patched
/// release) takes its entries with it: its override from the workspace
/// file and from the lock's record, and its registry, which no lock key
/// names any more. The release still routed keeps its own. A dry run
/// names the same entries and writes nothing; a second sweep finds
/// nothing.
#[tokio::test]
async fn a_dependency_that_left_the_lock_takes_its_entries() {
    for gone in [
        // Removed from the project.
        vec![LEAF_ROUTED],
        // Upgraded to a release the registry does not serve.
        vec![LEAF_ROUTED, Dep("mid", "2.1.0", None)],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let workspace = format!(
            "packages:\n  - 'apps/*'\ncatalog:\n  react: ^19.0.0\n{}",
            maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
        );
        write(root, "pnpm-workspace.yaml", &workspace);
        let before = lock(&[LEAF, MID], &gone);
        write(root, "pnpm-lock.yaml", &before);

        let want = [
            entry("pnpm-lock.yaml", "lockOverride", "mid@2.0.0"),
            entry("pnpm-workspace.yaml", "registry", MID_ALIAS),
            entry("pnpm-workspace.yaml", "override", "mid@2.0.0"),
        ];
        let dry = sweep(root, true).await;
        assert_eq!(removed(&dry), want);
        assert_eq!(dry.files, ["pnpm-lock.yaml", "pnpm-workspace.yaml"]);
        assert_eq!(
            read(root, "pnpm-lock.yaml").as_deref(),
            Some(before.as_str())
        );
        assert_eq!(
            read(root, "pnpm-workspace.yaml").as_deref(),
            Some(workspace.as_str()),
            "a dry run writes nothing"
        );

        let wet = sweep(root, false).await;
        assert_eq!(removed(&wet), want);
        assert_eq!(
            read(root, "pnpm-workspace.yaml").unwrap(),
            format!(
                "packages:\n  - 'apps/*'\ncatalog:\n  react: ^19.0.0\n{}",
                maps(&[leaf_registry()], &[LEAF])
            )
        );
        assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), lock(&[LEAF], &gone));

        let again = sweep(root, false).await;
        assert_eq!(removed(&again), []);
        assert!(again.files.is_empty());
    }
}

/// A rules_js hub of a Bazel workspace that keeps the lock up to date with
/// a pnpm 11 that does not see pnpm-workspace.yaml: hosted mode pins
/// nothing in that lock ([`crate::bazel::pnpm::hidden`]).
const HIDING_HUB: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True)\n\
    pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
    pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n";

/// The sweep reads the lockfiles alone and pins nothing, so a Bazel hub
/// that hosted mode leaves the lock to changes nothing about it: in a
/// project routed before the hub was there, what a departed dependency
/// left goes from the workspace file and from the lock's record together,
/// exactly as in the same project without its `MODULE.bazel`.
#[tokio::test]
async fn a_bazel_hub_changes_nothing_about_the_sweep() {
    let project = |hub: bool| {
        let dir = tempfile::tempdir().unwrap();
        let workspace = format!(
            "packages:\n  - 'apps/*'\n{}",
            maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
        );
        write(dir.path(), "pnpm-workspace.yaml", &workspace);
        write(
            dir.path(),
            "pnpm-lock.yaml",
            &lock(&[LEAF, MID], &[LEAF_ROUTED]),
        );
        if hub {
            write(dir.path(), "MODULE.bazel", HIDING_HUB);
        }
        dir
    };
    let (plain, hubbed) = (project(false), project(true));
    let view = crate::vendor::lock_inventory::ProjectView::Disk(hubbed.path());
    assert!(
        crate::bazel::pnpm::hidden(&view).await.is_some(),
        "the hub is one hosted mode leaves the lock to"
    );
    for dry_run in [true, false] {
        let without = sweep(plain.path(), dry_run).await;
        let with = sweep(hubbed.path(), dry_run).await;
        assert_eq!(removed(&with), removed(&without), "dry run: {dry_run}");
        assert_eq!(removed(&with).len(), 3, "dry run: {dry_run}");
        assert_eq!(with.files, without.files);
        for rel in ["pnpm-workspace.yaml", "pnpm-lock.yaml"] {
            assert_eq!(read(hubbed.path(), rel), read(plain.path(), rel), "{rel}");
        }
    }
    assert_eq!(
        read(hubbed.path(), "pnpm-workspace.yaml").unwrap(),
        format!(
            "packages:\n  - 'apps/*'\n{}",
            maps(&[leaf_registry()], &[LEAF])
        )
    );
    assert_eq!(
        read(hubbed.path(), "pnpm-lock.yaml").unwrap(),
        lock(&[LEAF], &[LEAF_ROUTED])
    );
}

/// With no release routed any more nothing of the route is left: every
/// registry, every override of ours and the locks' records go. A file
/// hosted mode created is deleted; a file of the user's is back to their
/// bytes, their own registry and overrides untouched.
#[tokio::test]
async fn nothing_routed_leaves_nothing_of_the_route() {
    const USER: &str =
        "packages:\n  - 'apps/*'\nnamedRegistries:\n  work: https://npm.work.example/\n\
                        overrides:\n  lodash: ^4.17.21\n";
    for user in [None, Some(USER)] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let workspace = match user {
            None => format!(
                "packages:\n  - '.'\n{}",
                maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
            ),
            Some(_) => format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n  work: https://npm.work.example/\n{}\n{}\n\
                 overrides:\n  lodash: ^4.17.21\n  'leaf@1.0.0': 'socket-11111111:1.0.0'\n  \
                 'mid@2.0.0': 'socket-22222222:2.0.0'\n",
                leaf_registry(),
                mid_registry()
            ),
        };
        write(root, "pnpm-workspace.yaml", &workspace);
        let users: &[&str] = match user {
            None => &[],
            Some(_) => &["lodash: ^4.17.21"],
        };
        let recorded: Vec<&str> = users.iter().copied().chain([LEAF, MID]).collect();
        let deps = [Dep("leaf", "1.1.0", None)];
        write(root, "pnpm-lock.yaml", &lock(&recorded, &deps));

        let dry = sweep(root, true).await;
        let want = [
            entry("pnpm-lock.yaml", "lockOverride", "leaf@1.0.0"),
            entry("pnpm-lock.yaml", "lockOverride", "mid@2.0.0"),
            entry("pnpm-workspace.yaml", "registry", LEAF_ALIAS),
            entry("pnpm-workspace.yaml", "registry", MID_ALIAS),
            entry("pnpm-workspace.yaml", "override", "leaf@1.0.0"),
            entry("pnpm-workspace.yaml", "override", "mid@2.0.0"),
        ];
        assert_eq!(removed(&dry), want, "{user:?}");
        assert_eq!(
            read(root, "pnpm-workspace.yaml").as_deref(),
            Some(workspace.as_str())
        );

        let wet = sweep(root, false).await;
        assert_eq!(removed(&wet), want, "{user:?}");
        assert_eq!(
            read(root, "pnpm-workspace.yaml").as_deref(),
            user,
            "created: deleted; the user's: their bytes"
        );
        assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), lock(users, &deps));
        assert_eq!(removed(&sweep(root, false).await), []);
    }
}

/// With several locks governed by the one workspace file, an entry goes
/// only when none of them uses it: pnpm records the file's overrides in
/// every lock, and a release routed by any lock keeps its override in all
/// of them, and its registry.
#[tokio::test]
async fn an_entry_goes_only_when_no_governed_lock_uses_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let user = "packages:\n  - packages/*\nsharedWorkspaceLockfile: false\n";
    let workspace = format!(
        "{user}{}",
        maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
    );
    write(root, "pnpm-workspace.yaml", &workspace);
    write(
        root,
        "package.json",
        r#"{"name": "root", "version": "1.0.0"}"#,
    );
    write(
        root,
        "packages/a/package.json",
        r#"{"name": "a", "version": "1.0.0"}"#,
    );
    // The root lock routes leaf; the member's own lock routes mid.
    let root_lock = lock(&[LEAF, MID], &[LEAF_ROUTED]);
    let member_lock = lock(&[LEAF, MID], &[MID_ROUTED]);
    write(root, "pnpm-lock.yaml", &root_lock);
    write(root, "packages/a/pnpm-lock.yaml", &member_lock);
    let swept = sweep(root, false).await;
    assert_eq!(
        removed(&swept),
        [],
        "each entry is used by one of the locks"
    );
    assert!(swept.files.is_empty());
    assert_eq!(read(root, "pnpm-workspace.yaml").unwrap(), workspace);

    // The member drops mid: no lock routes it, so it goes from the file
    // and from both locks' records.
    write(
        root,
        "packages/a/pnpm-lock.yaml",
        &lock(&[LEAF, MID], &[Dep("mid", "2.1.0", None)]),
    );
    let swept = sweep(root, false).await;
    assert_eq!(
        removed(&swept),
        [
            entry("pnpm-lock.yaml", "lockOverride", "mid@2.0.0"),
            entry("packages/a/pnpm-lock.yaml", "lockOverride", "mid@2.0.0"),
            entry("pnpm-workspace.yaml", "registry", MID_ALIAS),
            entry("pnpm-workspace.yaml", "override", "mid@2.0.0"),
        ]
    );
    assert_eq!(
        read(root, "pnpm-workspace.yaml").unwrap(),
        format!("{user}{}", maps(&[leaf_registry()], &[LEAF]))
    );
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        lock(&[LEAF], &[LEAF_ROUTED])
    );
    assert_eq!(
        read(root, "packages/a/pnpm-lock.yaml").unwrap(),
        lock(&[LEAF], &[Dep("mid", "2.1.0", None)])
    );
}

/// What is not hosted mode's stays byte for byte: a registry the user
/// declared under a name of ours somewhere else, with the overrides that
/// use it; a registry of the route's shape on a host this run does not
/// know for a patch server; and a plain `socket` registry of theirs.
/// Only the second may be hosted mode's after all (a patch server the
/// run was not told of), so the sweep names its host and how many
/// registries it passed over there; of the others it says nothing.
#[tokio::test]
async fn the_users_entries_are_never_touched() {
    for (workspace, record, passed_over) in [
        (
            "packages:\n  - '.'\nnamedRegistries:\n  socket-11111111: https://npm.work.example/\n\
             overrides:\n  'leaf@1.0.0': 'socket-11111111:1.0.0'\n"
                .to_string(),
            LEAF,
            vec![],
        ),
        (
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n  socket-11111111: \
                 https://mirror.example/patch/npm/leaf/1.0.0/{TOKEN}/{LEAF_UUID}/\n\
                 overrides:\n  'leaf@1.0.0': 'socket-11111111:1.0.0'\n"
            ),
            LEAF,
            vec![("https://mirror.example".to_string(), 1)],
        ),
        (
            "packages:\n  - '.'\nnamedRegistries:\n  socket: https://npm.work.example/\n\
             overrides:\n  'leaf@1.0.0': 'socket:1.0.0'\n"
                .to_string(),
            "leaf@1.0.0: socket:1.0.0",
            vec![],
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "pnpm-workspace.yaml", &workspace);
        let text = lock(&[record], &[Dep("leaf", "1.1.0", None)]);
        write(root, "pnpm-lock.yaml", &text);
        let swept = sweep(root, false).await;
        assert_eq!(removed(&swept), [], "{workspace}");
        assert!(swept.files.is_empty());
        assert_eq!(swept.unknown_hosts, passed_over, "{workspace}");
        assert_eq!(read(root, "pnpm-workspace.yaml").unwrap(), workspace);
        assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), text);
    }
}

/// The same project swept twice: by a run that knows its patch server,
/// which tidies it and passes nothing over, and by a run that does not,
/// which removes nothing and says which host holds how many registries.
#[tokio::test]
async fn a_route_on_a_host_the_run_was_not_told_of_is_passed_over_and_named() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let workspace = format!(
        "packages:\n  - '.'\n{}",
        maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
    );
    write(root, "pnpm-workspace.yaml", &workspace);
    // Neither release is in the lock any more.
    let text = lock(&[LEAF, MID], &[Dep("other", "1.0.0", None)]);
    write(root, "pnpm-lock.yaml", &text);

    for dry_run in [true, false] {
        let untold = sweep_from(root, dry_run, Vec::new()).await;
        assert_eq!(removed(&untold), [], "dry_run={dry_run}");
        assert!(untold.files.is_empty());
        assert_eq!(untold.unknown_hosts, [(HOST.to_string(), 2)]);
        assert_eq!(read(root, "pnpm-workspace.yaml").unwrap(), workspace);
        assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), text);
    }

    let told = sweep(root, false).await;
    assert_eq!(removed(&told).len(), 6, "{:?}", told.edits);
    assert_eq!(told.unknown_hosts, []);
    assert_eq!(read(root, "pnpm-workspace.yaml"), None);
}

/// A lock's record of an override outlives a deleted workspace file: it
/// goes all the same. And a project with no pnpm files at all is left
/// alone without a word.
#[tokio::test]
async fn a_lock_record_goes_without_a_workspace_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let deps = [Dep("leaf", "1.1.0", None)];
    write(root, "pnpm-lock.yaml", &lock(&[LEAF], &deps));
    let swept = sweep(root, false).await;
    assert_eq!(
        removed(&swept),
        [entry("pnpm-lock.yaml", "lockOverride", "leaf@1.0.0")]
    );
    assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), lock(&[], &deps));
    assert_eq!(read(root, "pnpm-workspace.yaml"), None);

    let bare = tempfile::tempdir().unwrap();
    let swept = sweep(bare.path(), false).await;
    assert_eq!(removed(&swept), []);
    assert!(swept.files.is_empty());
}

/// A lockfileVersion 9 lock the edits cannot read (mixed line endings)
/// that names a registry of ours may still route anything: nothing goes.
#[tokio::test]
async fn a_lock_that_cannot_be_read_keeps_everything() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let workspace = format!(
        "packages:\n  - '.'\n{}",
        maps(&[leaf_registry(), mid_registry()], &[LEAF, MID])
    );
    write(root, "pnpm-workspace.yaml", &workspace);
    let mixed = lock(&[LEAF, MID], &[LEAF_ROUTED]).replacen("importers:\n", "importers:\r\n", 1);
    write(root, "pnpm-lock.yaml", &mixed);
    let swept = sweep(root, false).await;
    assert_eq!(removed(&swept), []);
    assert_eq!(read(root, "pnpm-workspace.yaml").unwrap(), workspace);
    assert_eq!(read(root, "pnpm-lock.yaml").unwrap(), mixed);
}

/// A patch mirror among the run's origins (`--patch-mirror-url`) changes
/// nothing of what is the CLI's: a route's registries are on the patch
/// server, and their entries go as without the mirror. A registry of the
/// same shape declared on the mirror's host is on no patch server (a
/// mirror's entry holds its base, never its host), so it and its override
/// are the user's.
#[tokio::test]
async fn a_route_is_told_from_the_users_with_a_patch_mirror_configured() {
    const MIRROR: &str = "https://repo.example/artifactory/socket-patch";
    const THEIRS_UUID: &str = "33333333-3333-4333-8333-333333333333";
    let theirs =
        format!("  socket-33333333: {MIRROR}/patch/npm/other/3.0.0/{TOKEN}/{THEIRS_UUID}/");
    const THEIR_OVERRIDE: &str = "other@3.0.0: socket-33333333:3.0.0";
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "pnpm-workspace.yaml",
        &format!(
            "packages:\n  - 'apps/*'\n{}",
            maps(
                &[theirs.clone(), leaf_registry(), mid_registry()],
                &[THEIR_OVERRIDE, LEAF, MID]
            )
        ),
    );
    // mid left the lock.
    write(
        root,
        "pnpm-lock.yaml",
        &lock(&[THEIR_OVERRIDE, LEAF, MID], &[LEAF_ROUTED]),
    );

    let origins = vec![HOST.to_string(), crate::origin::mirror_entry(MIRROR)];
    let wet = sweep_from(root, false, origins).await;
    assert_eq!(
        removed(&wet),
        [
            entry("pnpm-lock.yaml", "lockOverride", "mid@2.0.0"),
            entry("pnpm-workspace.yaml", "registry", MID_ALIAS),
            entry("pnpm-workspace.yaml", "override", "mid@2.0.0"),
        ]
    );
    assert_eq!(
        read(root, "pnpm-workspace.yaml").unwrap(),
        format!(
            "packages:\n  - 'apps/*'\n{}",
            maps(&[theirs, leaf_registry()], &[THEIR_OVERRIDE, LEAF])
        )
    );
    assert_eq!(
        read(root, "pnpm-lock.yaml").unwrap(),
        lock(&[THEIR_OVERRIDE, LEAF], &[LEAF_ROUTED])
    );
    // The one under the mirror's base is passed over, and named by host.
    assert_eq!(wet.unknown_hosts, [("https://repo.example".to_string(), 1)]);
}
