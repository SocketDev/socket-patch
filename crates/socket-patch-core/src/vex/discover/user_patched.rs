//! npm-family packages the project patches itself with pnpm, yarn or
//! patch-package.
//!
//! pnpm's `patchedDependencies` (in `package.json`'s `pnpm` field, in
//! `pnpm-workspace.yaml`, and recorded in every pnpm lock's own
//! `patchedDependencies` map and `(patch_hash=…)` key suffixes), a yarn
//! berry `patch:` descriptor (in `package.json`, and resolved in
//! `yarn.lock`), and a patch-package patch (`patches/<name>+<version>.patch`,
//! or a `--patch-dir` a script names) are each applied by the package
//! manager, or its postinstall, on top of whatever tarball the lock names:
//! a Socket pin of such a package installs the Socket patch with the
//! user's diff stacked on it (or fails the install when the diff no longer
//! applies), never the Socket patch alone. Yarn classic has no patch
//! protocol, and neither has vlt (its `vlt.json` `modifiers` rewrite
//! dependency specs, never package contents), so a yarn classic or vlt
//! project patches a dependency only through patch-package, which is read
//! for every npm-family lock alike.
//!
//! So a ref of such a package is marked
//! [`UnattestedKind::UserPatchedDependency`]: it stays a ref (`rollback` /
//! `remove` / `list` still find a pin an earlier run, or an
//! `--allow-patch-conflicts` run, wrote), and only `vex` omits it, whatever
//! wiring the ref is and whether or not the run that wrote it had consent.
//! The evidence is [`UserPatchIndex::npm_family_in`], the parse rules of the
//! CLI's consent gate that keeps hosted and vendored mode from wiring these
//! packages, and the one the in-memory hosted engine withholds them by, so
//! the three never disagree. npm's and Bun's own `patchedDependencies`
//! are judged per resolution by their extractors instead (#711, #367).

use super::{CopyTarget, DiscoverCtx, Discovery, UnattestedKind, UnwiredCopy};
use crate::patch::user_patches::UserPatchIndex;

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    if !out.refs.iter().any(|r| r.purl.starts_with("pkg:npm/")) {
        return;
    }
    let mut lock_files: Vec<String> = out
        .refs
        .iter()
        .filter(|r| r.purl.starts_with("pkg:npm/"))
        .map(|r| r.source_file.to_string_lossy().replace('\\', "/"))
        .filter(|f| is_patch_lock(f))
        .collect();
    lock_files.extend(["pnpm-lock.yaml".to_string(), "yarn.lock".to_string()]);
    lock_files.sort();
    lock_files.dedup();
    let mut locks: Vec<(String, String)> = Vec::new();
    let mut unreadable: Vec<(String, std::io::Error)> = Vec::new();
    for rel in lock_files {
        // An unreadable lock protects every npm package, as in the hosted
        // engine and the disk scan, so the three never disagree.
        match ctx.view.read_text(&rel).await {
            Ok(text) => locks.push((rel, text)),
            Err(_)
                if matches!(
                    ctx.view,
                    crate::vendor::lock_inventory::ProjectView::Memory(_)
                ) && ctx.view.is_symlink(&rel) => {}
            Err(e) => unreadable.push((rel, e)),
        }
    }
    let locks: Vec<(&str, &str)> = locks
        .iter()
        .map(|(rel, text)| (rel.as_str(), text.as_str()))
        .collect();
    let mut index = UserPatchIndex::npm_family_in(&ctx.view, &locks).await;
    for (rel, e) in &unreadable {
        index.unreadable_lock(rel, e);
    }
    if index.is_empty() {
        return;
    }
    // Each mark is an `UnwiredCopy` for exactly that ref, as the npm and
    // Bun extractors' (`npm::mark_user_patched`): it lands only on a ref
    // that survives every contest, and a ref one of those already covers
    // keeps that first reason.
    let marks: Vec<UnwiredCopy> = out
        .refs
        .iter()
        .filter(|r| r.purl.starts_with("pkg:npm/"))
        .filter_map(|r| {
            let sources = index.conflicts(&r.purl);
            if sources.is_empty() {
                return None;
            }
            let detail = format!(
                "{} declares a patch the project applies to this package itself (pnpm \
                 `patchedDependencies`, a yarn `patch:` descriptor, or a patch-package patch); \
                 the package manager applies it on top of whatever tarball the lock names, so \
                 the install never runs the Socket patch alone, and hosted and vendored mode \
                 leave the package alone without `--allow-patch-conflicts`",
                sources.join(", ")
            );
            Some(UnwiredCopy {
                scope: Some(r.source_file.clone()),
                target: CopyTarget::Ref {
                    purl: r.purl.clone(),
                    uuid: r.uuid.clone(),
                },
                file: r.source_file.clone(),
                detail,
                kind: UnattestedKind::UserPatchedDependency,
            })
        })
        .collect();
    for mark in marks {
        out.unwired_copy(mark);
    }
}

/// A lock whose own records can declare a user patch: a pnpm lock (root,
/// Rush or a member's) or a yarn lock.
fn is_patch_lock(rel: &str) -> bool {
    matches!(
        rel.rsplit('/').next(),
        Some("pnpm-lock.yaml" | "shrinkwrap.yaml" | "yarn.lock")
    )
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;

    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";

    /// The `(purl, uuid)` of every ref marked user-patched.
    fn marked(out: &Discovery) -> Vec<(String, String)> {
        out.unattested
            .iter()
            .filter(|u| u.kind == UnattestedKind::UserPatchedDependency)
            .map(|u| (u.purl.clone(), u.uuid.clone()))
            .collect()
    }

    /// Every ref of `out` (at least one) is marked, and only once.
    fn all_marked(out: &Discovery, what: &str) {
        assert!(!out.refs.is_empty(), "{what}: no refs");
        let mut want: Vec<(String, String)> = out
            .refs
            .iter()
            .map(|r| (r.purl.clone(), r.uuid.clone()))
            .collect();
        want.sort();
        want.dedup();
        assert_eq!(marked(out), want, "{what}: {:#?}", out.unattested);
    }

    fn none_marked(out: &Discovery, what: &str) {
        assert!(!out.refs.is_empty(), "{what}: no refs");
        assert_eq!(marked(out), [], "{what}: {:#?}", out.unattested);
    }

    /// REGRESSION: a pnpm pin of a package the project patches itself with
    /// pnpm's `patchedDependencies` was attested, though pnpm applies the
    /// user's diff on top of the pinned tarball. Every place pnpm reads or
    /// records the patch counts: `pnpm-workspace.yaml` (pnpm 10+),
    /// `package.json`'s `pnpm` field, the lock's own `patchedDependencies`
    /// map, and a `(patch_hash=…)` snapshot key; another version's key and
    /// npm's top-level `patchedDependencies` (which pnpm never reads) do
    /// not.
    #[tokio::test]
    async fn pnpm_patched_dependencies_mark_the_pin() {
        let fixture = "redirect/npm/pnpm/basic/expected";
        let p = Project::new();
        p.copy_fixture(fixture);
        none_marked(&p.discover().await, "control");
        let lock = std::fs::read_to_string(p.root().join("pnpm-lock.yaml")).unwrap();
        let with_map = lock.replacen(
            "\nimporters:",
            "\npatchedDependencies:\n  left-pad@1.3.0:\n    hash: abc123\n    path: patches/left-pad@1.3.0.patch\n\nimporters:",
            1,
        );
        let with_hash = lock.replacen(
            "  left-pad@1.3.0: {}",
            "  left-pad@1.3.0(patch_hash=abc123): {}",
            1,
        );
        assert!(
            with_map != lock && with_hash != lock,
            "the lock edits apply"
        );

        for (file, text, hit) in [
            (
                "pnpm-workspace.yaml",
                "packages:\n  - '.'\npatchedDependencies:\n  left-pad@1.3.0: patches/left-pad@1.3.0.patch\n",
                true,
            ),
            (
                "pnpm-workspace.yaml",
                "patchedDependencies:\n  left-pad: patches/left-pad.patch\n",
                true,
            ),
            (
                "pnpm-workspace.yaml",
                "patchedDependencies:\n  left-pad@^1.0.0: patches/left-pad.patch\n",
                true,
            ),
            (
                "pnpm-workspace.yaml",
                "patchedDependencies:\n  left-pad@1.2.0: patches/left-pad.patch\n",
                false,
            ),
            (
                "package.json",
                r#"{"pnpm":{"patchedDependencies":{"left-pad@1.3.0":"patches/left-pad.patch"}}}"#,
                true,
            ),
            (
                "package.json",
                r#"{"patchedDependencies":{"left-pad@1.3.0":"patches/left-pad.patch"}}"#,
                false,
            ),
            ("pnpm-lock.yaml", with_map.as_str(), true),
            ("pnpm-lock.yaml", with_hash.as_str(), true),
        ] {
            let p = Project::new();
            p.copy_fixture(fixture);
            p.write(file, text);
            let out = p.discover().await;
            if hit {
                all_marked(&out, text);
                let detail = &out.unattested[0].detail;
                assert!(detail.contains(file), "{detail}");
            } else {
                none_marked(&out, text);
            }
        }
    }

    /// REGRESSION: a yarn berry pin of a package the project patches with a
    /// `patch:` descriptor (`yarn patch`) was attested. The descriptor in
    /// `package.json` and the `patch:` locator `yarn.lock` resolves both
    /// count, including one wrapping the hosted tarball itself (a `yarn
    /// patch` made after the rewire, #962): yarn applies the user's diff on
    /// top of it. Yarn's builtin compatibility patches do not.
    #[tokio::test]
    async fn yarn_berry_patch_descriptors_mark_the_pin() {
        let fixture = "redirect/npm/yarn-berry/basic/expected";
        let p = Project::new();
        p.copy_fixture(fixture);
        none_marked(&p.discover().await, "control");
        let manifest = std::fs::read_to_string(p.root().join("package.json")).unwrap();
        let lock = std::fs::read_to_string(p.root().join("yarn.lock")).unwrap();
        let url = "https://patch.socket.dev/patch/npm/11111111-1111-1111-1111-111111111111/77777777-7777-7777-7777-777777777777/left-pad-1.3.0.tgz";
        let patched_entry = |patch: &str| {
            format!(
                "\n\"left-pad@patch:left-pad@npm%3A1.3.0#{patch}\":\n  version: 1.3.0\n  resolution: \"left-pad@patch:left-pad@npm%3A1.3.0#{patch}::version=1.3.0&hash=abc123\"\n  languageName: node\n  linkType: hard\n"
            )
        };
        let wrapping = manifest.replacen(
            "\"left-pad\": \"^1.3.0\"",
            &format!(
                "\"left-pad\": \"patch:left-pad@{}#./.yarn/patches/left-pad.patch\"",
                url.replace(':', "%3A")
            ),
            1,
        );
        assert_ne!(wrapping, manifest, "the manifest edit applies");
        for (file, text, hit) in [
            ("package.json", wrapping, true),
            (
                "yarn.lock",
                format!(
                    "{lock}{}",
                    patched_entry("./.yarn/patches/left-pad-npm-1.3.0-abc.patch")
                ),
                true,
            ),
            (
                "yarn.lock",
                format!(
                    "{lock}{}",
                    patched_entry("optional!builtin<compat/left-pad>")
                ),
                false,
            ),
        ] {
            let p = Project::new();
            p.copy_fixture(fixture);
            p.write(file, &text);
            let out = p.discover().await;
            if hit {
                all_marked(&out, &text);
            } else {
                none_marked(&out, &text);
            }
        }
    }

    /// REGRESSION: yarn classic and vlt have no patch mechanism of their
    /// own, so a project patches a dependency there with patch-package, a
    /// postinstall that applies `patches/<name>+<version>.patch` (or a
    /// `--patch-dir` a script names) over the installed copy. A pin of such
    /// a package (hosted or vendored) was attested; npm-lock pins likewise.
    /// Another version's patch file does not count.
    #[tokio::test]
    async fn patch_package_patches_mark_yarn_classic_vlt_and_npm_pins() {
        for fixture in [
            "redirect/npm/yarn-classic/basic/expected",
            "redirect/npm/vlt/basic/expected",
            "redirect/npm/vlt/vendored-entry/input",
            "redirect/npm/package-lock-v3/basic/expected",
        ] {
            let p = Project::new();
            p.copy_fixture(fixture);
            none_marked(&p.discover().await, fixture);

            p.write("patches/left-pad+1.2.0.patch", "diff\n");
            none_marked(&p.discover().await, fixture);

            p.write("patches/left-pad+1.3.0.patch", "diff\n");
            let out = p.discover().await;
            all_marked(&out, fixture);
            assert!(
                out.unattested[0]
                    .detail
                    .contains("patches/left-pad+1.3.0.patch"),
                "{}",
                out.unattested[0].detail
            );

            // A custom directory a patch-package script names.
            let p = Project::new();
            p.copy_fixture(fixture);
            p.write(
                "package.json",
                r#"{"scripts":{"postinstall":"patch-package --patch-dir fixes"}}"#,
            );
            p.write("fixes/left-pad+1.3.0.patch", "diff\n");
            all_marked(&p.discover().await, fixture);
        }
    }

    /// Every file under `root` but the repository marker, as an in-memory
    /// project.
    fn memory_copy(root: &std::path::Path) -> crate::vendor::lock_inventory::MemoryProject {
        use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};
        let mut project = MemoryProject::new();
        for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
            let rel = entry.path().strip_prefix(root).unwrap();
            if !entry.file_type().is_file() || rel.starts_with(".git") {
                continue;
            }
            let text = std::fs::read_to_string(entry.path()).unwrap();
            let rel = rel.to_string_lossy().replace('\\', "/");
            project.insert(rel, MemoryEntry::Text(text.into()));
        }
        project
    }

    /// Discovery reads a workspace member's user patches as the CLI's
    /// consent gate does (the very same walk): a member's
    /// `pnpm.patchedDependencies`, its yarn `patch:` descriptors and its own
    /// `patches/` folder, members named by `package.json` `workspaces` or
    /// `pnpm-workspace.yaml` `packages`, on disk and in memory alike. A
    /// member beyond the git repository root is never read: it protects
    /// every npm package instead, for the gate and discovery alike.
    #[tokio::test]
    async fn workspace_member_patches_agree_with_the_consent_gate() {
        use crate::patch::user_patches::UserPatchIndex;
        use crate::vendor::lock_inventory::ProjectView;

        let berry =
            r#"{"name":"a","resolutions":{"left-pad":"patch:left-pad@npm%3A1.3.0#./p.patch"}}"#;
        let cases: &[(&str, &str, &[(&str, &str)])] = &[
            (
                "package.json workspaces, pnpm field",
                r#"{"workspaces":["packages/*"]}"#,
                &[(
                    "packages/a/package.json",
                    r#"{"name":"a","pnpm":{"patchedDependencies":{"left-pad@1.3.0":"x.patch"}}}"#,
                )],
            ),
            (
                "package.json workspaces, member patches/",
                r#"{"workspaces":{"packages":["packages/**"]}}"#,
                &[
                    ("packages/nested/a/package.json", r#"{"name":"a"}"#),
                    ("packages/nested/a/patches/left-pad+1.3.0.patch", "diff\n"),
                ],
            ),
            (
                "pnpm-workspace.yaml packages, yarn patch:",
                r#"{"name":"root"}"#,
                &[
                    ("pnpm-workspace.yaml", "packages:\n  - 'tools/*'\n"),
                    ("tools/a/package.json", berry),
                ],
            ),
        ];
        for (what, manifest, files) in cases {
            let p = Project::new();
            p.copy_fixture("redirect/npm/pnpm/basic/expected");
            p.write(".git/HEAD", "ref: refs/heads/main\n");
            p.write("package.json", manifest);
            let gate = UserPatchIndex::discover(p.root()).await;
            assert!(gate.conflicts(LEFT_PAD).is_empty(), "{what}: control");
            for (path, text) in *files {
                p.write(path, text);
            }
            let gate = UserPatchIndex::discover(p.root()).await;
            assert!(!gate.conflicts(LEFT_PAD).is_empty(), "{what}: gate");
            assert!(gate.conflicts("pkg:npm/other@1.0.0").is_empty(), "{what}");

            let out = p.discover().await;
            all_marked(&out, what);
            let member = files[files.len() - 1].0.rsplit_once('/').unwrap().0;
            assert!(
                out.unattested[0].detail.contains(member),
                "{what}: {}",
                out.unattested[0].detail
            );

            let memory = memory_copy(p.root());
            let out = discover_patched_refs_view(
                ProjectView::Memory(&memory),
                &DiscoverOptions::default(),
            )
            .await;
            all_marked(&out, what);
        }

        // Beyond the repository root: never read, every package protected.
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(outer.path().join("shared/a/patches")).unwrap();
        std::fs::write(outer.path().join("shared/a/package.json"), "{}").unwrap();
        std::fs::write(
            outer.path().join("shared/a/patches/left-pad+1.3.0.patch"),
            "diff\n",
        )
        .unwrap();
        for entry in std::fs::read_dir(fixture_path("redirect/npm/pnpm/basic/expected")).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), repo.join(entry.file_name())).unwrap();
        }
        std::fs::write(
            repo.join("package.json"),
            r#"{"workspaces":["../shared/*"]}"#,
        )
        .unwrap();
        let gate = UserPatchIndex::discover(&repo).await;
        let sources = gate.conflicts("pkg:npm/other@1.0.0");
        assert!(
            sources
                .iter()
                .any(|s| s.contains("outside the git repository")),
            "{sources:?}"
        );
        assert!(!sources.iter().any(|s| s.contains(".patch")), "{sources:?}");
        let out = discover_patched_refs_with(&repo, &DiscoverOptions::default()).await;
        all_marked(&out, "outside the repository");
        assert!(
            out.unattested[0]
                .detail
                .contains("outside the git repository"),
            "{}",
            out.unattested[0].detail
        );
    }

    /// A user-patched pnpm ref another lock contests is dropped by the
    /// cross-lock contest and leaves no mark behind: the mark targets that
    /// ref alone ([`CopyTarget::Ref`]) and lands only on contest survivors.
    #[tokio::test]
    async fn a_contested_user_patched_ref_leaves_no_mark() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/pnpm/basic/expected");
        p.write(
            "pnpm-workspace.yaml",
            "patchedDependencies:\n  left-pad@1.3.0: patches/left-pad.patch\n",
        );
        all_marked(&p.discover().await, "control");
        p.write(
            "package-lock.json",
            r#"{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-UP=="}}}"#,
        );
        let out = p.discover().await;
        assert!(
            out.refs.iter().all(|r| r.purl != LEFT_PAD),
            "the contest drops the ref: {:#?}",
            out.refs
        );
        assert!(out.unattested.is_empty(), "{:#?}", out.unattested);
    }

    /// The pins of other packages stay attested.
    #[tokio::test]
    async fn other_packages_are_not_marked() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/pnpm/basic/expected");
        p.write(
            "pnpm-workspace.yaml",
            "patchedDependencies:\n  is-number@7.0.0: patches/is-number.patch\n",
        );
        p.write("patches/is-number+7.0.0.patch", "diff\n");
        let out = p.discover().await;
        assert!(out.refs.iter().any(|r| r.purl == LEFT_PAD));
        none_marked(&out, "other package");
    }
}
