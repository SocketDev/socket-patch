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

use super::{DiscoverCtx, Discovery, UnattestedKind};
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
    for rel in lock_files {
        if let Some(text) = ctx.read_advisory_text(&rel).await {
            locks.push((rel, text));
        }
    }
    let locks: Vec<(&str, &str)> = locks
        .iter()
        .map(|(rel, text)| (rel.as_str(), text.as_str()))
        .collect();
    let index = UserPatchIndex::npm_family_in(&ctx.view, &locks).await;
    if index.is_empty() {
        return;
    }
    let marks: Vec<(String, String, String, String)> = out
        .refs
        .iter()
        .filter(|r| r.purl.starts_with("pkg:npm/"))
        .filter(|r| {
            !out.unattested.iter().any(|u| {
                u.kind == UnattestedKind::UserPatchedDependency
                    && u.purl == r.purl
                    && u.uuid == r.uuid
            })
        })
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
            Some((
                r.purl.clone(),
                r.uuid.clone(),
                r.source_file.to_string_lossy().into_owned(),
                detail,
            ))
        })
        .collect();
    for (purl, uuid, file, detail) in marks {
        out.unattested(
            &purl,
            &uuid,
            &file,
            detail,
            UnattestedKind::UserPatchedDependency,
        );
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
